package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	paymentsv1 "authz-system/api"
	"authz-system/internal/authz"
	"authz-system/internal/authz/kafkaadapter"
	"authz-system/internal/authz/natsadapter"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/segmentio/kafka-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const kafkaDefaultTopic = "payments.requested"

const natsDefaultSubject = "payments.requested"

type paymentsServer struct {
	paymentsv1.UnimplementedPaymentsServer
}

func (s *paymentsServer) Charge(ctx context.Context, req *paymentsv1.ChargeRequest) (*paymentsv1.ChargeReply, error) {
	return &paymentsv1.ChargeReply{Status: "charged"}, nil
}

func (s *paymentsServer) Refund(ctx context.Context, req *paymentsv1.RefundRequest) (*paymentsv1.RefundReply, error) {
	return &paymentsv1.RefundReply{Status: "refunded"}, nil
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing env %s", k)
	}
	return v
}

func envDefault(k, fallback string) string {
	v := os.Getenv(k)
	if v == "" {
		return fallback
	}
	return v
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func mustServerTLSConfig(certFile, keyFile, caFile string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("load cert/key: %v", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("read ca: %v", err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caPEM); !ok {
		log.Fatalf("append ca failed")
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	return tlsCfg
}

func mustServerCreds(certFile, keyFile, caFile string) credentials.TransportCredentials {
	return credentials.NewTLS(mustServerTLSConfig(certFile, keyFile, caFile))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func runKafkaConsumer(cfg authz.Config) {
	adapter, err := kafkaadapter.New(cfg)
	if err != nil {
		log.Fatalf("kafka authz adapter: %v", err)
	}

	topic := envDefault("KAFKA_TOPIC_PAYMENT_REQUESTED", kafkaDefaultTopic)
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  splitCSV(envDefault("KAFKA_BROKERS", "kafka:9092")),
		Topic:    topic,
		GroupID:  envDefault("KAFKA_GROUP_ID", "payments-demo"),
		MinBytes: 1,
		MaxBytes: 1 << 20,
		MaxWait:  500 * time.Millisecond,
	})
	defer reader.Close()

	log.Printf("payments Kafka consumer listening topic=%s group=%s", topic, envDefault("KAFKA_GROUP_ID", "payments-demo"))
	for {
		ctx := context.Background()
		msg, err := reader.FetchMessage(ctx)
		if err != nil {
			log.Printf("kafka fetch error: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}

		if err := adapter.AuthorizeConsume(ctx, msg); err != nil {
			log.Printf("KAFKA CONSUME DENY: topic=%s partition=%d offset=%d error=%v", msg.Topic, msg.Partition, msg.Offset, err)
			_ = reader.CommitMessages(ctx, msg)
			continue
		}

		source, _ := kafkaadapter.ServiceNameFromHeaders(msg.Headers)
		messageType, _ := kafkaadapter.MessageTypeFromHeaders(msg.Headers)
		log.Printf("KAFKA CONSUME OK: source=%s topic=%s message_type=%s offset=%d value=%s", source, msg.Topic, messageType, msg.Offset, strings.TrimSpace(string(msg.Value)))
		if err := reader.CommitMessages(ctx, msg); err != nil {
			log.Printf("kafka commit error: %v", err)
		}
	}
}

func runNATSSubscriber(cfg authz.Config) {
	adapter, err := natsadapter.New(cfg)
	if err != nil {
		log.Fatalf("nats authz adapter: %v", err)
	}

	conn, err := nats.Connect(
		envDefault("NATS_URL", "nats://nats:4222"),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(20),
		nats.ReconnectWait(500*time.Millisecond),
	)
	if err != nil {
		log.Fatalf("nats connect: %v", err)
	}
	defer conn.Close()

	subject := envDefault("NATS_SUBJECT_PAYMENT_REQUESTED", natsDefaultSubject)
	sub, err := conn.SubscribeSync(subject)
	if err != nil {
		log.Fatalf("nats subscribe subject=%s: %v", subject, err)
	}
	defer sub.Unsubscribe()

	if err := conn.Flush(); err != nil {
		log.Fatalf("nats flush subscription: %v", err)
	}

	log.Printf("payments NATS subscriber listening subject=%s", subject)
	for {
		msg, err := sub.NextMsg(500 * time.Millisecond)
		if errors.Is(err, nats.ErrTimeout) {
			continue
		}
		if err != nil {
			log.Printf("nats receive error: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}

		ctx := context.Background()
		if err := adapter.AuthorizeConsume(ctx, msg); err != nil {
			log.Printf("NATS CONSUME DENY: subject=%s error=%v", msg.Subject, err)
			continue
		}

		source, _ := natsadapter.ServiceNameFromHeaders(msg.Header)
		messageType, _ := natsadapter.MessageTypeFromHeaders(msg.Header)
		log.Printf("NATS CONSUME OK: source=%s subject=%s message_type=%s value=%s", source, msg.Subject, messageType, strings.TrimSpace(string(msg.Data)))
	}
}

func main() {
	serviceName := mustEnv("SERVICE_NAME")
	policyURL := mustEnv("POLICY_URL")

	certFile := mustEnv("CERT_FILE")
	keyFile := mustEnv("KEY_FILE")
	caFile := mustEnv("CA_FILE")

	policyCert := mustEnv("POLICY_CERT_FILE")
	policyKey := mustEnv("POLICY_KEY_FILE")
	policyCA := mustEnv("POLICY_CA_FILE")

	// metrics endpoint
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		log.Println("payments metrics on :9090")
		log.Fatal(http.ListenAndServe(":9090", mux))
	}()

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	cfg := authz.Config{
		TargetService: serviceName,
		PolicyURL:     policyURL,
		FailOpen:      false,
		Timeout:       250 * time.Millisecond,
		CacheTTL:      2 * time.Second,
		PolicyClientTLS: authz.TLSFiles{
			CertFile: policyCert,
			KeyFile:  policyKey,
			CAFile:   policyCA,
		},
	}

	go runKafkaConsumer(cfg)
	go runNATSSubscriber(cfg)

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /payments/charge", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"status": "charged"})
		})
		mux.HandleFunc("POST /payments/refund", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"status": "refunded"})
		})

		srv := &http.Server{
			Addr:      ":8080",
			Handler:   authz.NewHTTPMiddleware(cfg)(mux),
			TLSConfig: mustServerTLSConfig(certFile, keyFile, caFile),
		}
		log.Println("payments REST listening on :8080 (mTLS + authz)")
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}()

	s := grpc.NewServer(
		grpc.Creds(mustServerCreds(certFile, keyFile, caFile)),
		grpc.UnaryInterceptor(authz.NewUnaryInterceptor(cfg)),
		grpc.StreamInterceptor(authz.NewStreamInterceptor(cfg)),
	)

	paymentsv1.RegisterPaymentsServer(s, &paymentsServer{})

	log.Println("payments listening on :50051 (mTLS + authz)")
	log.Fatal(s.Serve(lis))
}
