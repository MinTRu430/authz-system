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
	"strconv"
	"strings"
	"time"

	paymentsv1 "authz-system/api"
	"authz-system/internal/authz"
	"authz-system/internal/authz/brokerreliability"
	"authz-system/internal/authz/brokersign"
	"authz-system/internal/authz/grpcadapter"
	"authz-system/internal/authz/httpadapter"
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

func durationEnvDefault(k string, fallback time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("invalid duration env %s=%q: %v", k, v, err)
	}
	return d
}

func boolEnvDefault(k string, fallback bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		log.Fatalf("invalid bool env %s=%q: %v", k, v, err)
	}
	return b
}

func intEnvDefault(k string, fallback int) int {
	v := os.Getenv(k)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("invalid int env %s=%q: %v", k, v, err)
	}
	return n
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

func policyEndpointConfig() (string, []string) {
	policyURL := os.Getenv("POLICY_URL")
	policyURLs := splitCSV(os.Getenv("POLICY_URLS"))
	if policyURL == "" && len(policyURLs) == 0 {
		log.Fatal("missing env POLICY_URL or POLICY_URLS")
	}
	return policyURL, policyURLs
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
	brokers := splitCSV(envDefault("KAFKA_BROKERS", "kafka:9092"))
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  brokers,
		Topic:    topic,
		GroupID:  envDefault("KAFKA_GROUP_ID", "payments-demo"),
		MinBytes: 1,
		MaxBytes: 1 << 20,
		MaxWait:  500 * time.Millisecond,
	})
	defer reader.Close()
	dlqWriter := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Balancer:     &kafka.LeastBytes{},
		BatchSize:    1,
		BatchTimeout: 10 * time.Millisecond,
	}
	defer dlqWriter.Close()

	reliability := brokerReliabilityConfig(cfg)

	log.Printf("payments Kafka consumer listening topic=%s group=%s", topic, envDefault("KAFKA_GROUP_ID", "payments-demo"))
	for {
		ctx := context.Background()
		msg, err := reader.FetchMessage(ctx)
		if err != nil {
			log.Printf("kafka fetch error: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}

		if _, err := processKafkaMessage(ctx, adapter, reliability, dlqWriter, msg); err != nil {
			log.Printf("KAFKA CONSUME ERROR: topic=%s partition=%d offset=%d error=%v", msg.Topic, msg.Partition, msg.Offset, err)
			continue
		}
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
	reliability := brokerReliabilityConfig(cfg)
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
		if _, err := processNATSMessage(ctx, adapter, reliability, conn, msg); err != nil {
			log.Printf("NATS CONSUME ERROR: subject=%s error=%v", msg.Subject, err)
			continue
		}
	}
}

func processKafkaMessage(ctx context.Context, adapter *kafkaadapter.Adapter, cfg brokerreliability.Config, dlqWriter *kafka.Writer, msg kafka.Message) (brokerreliability.Outcome, error) {
	source, _ := kafkaadapter.ServiceNameFromHeaders(msg.Headers)
	messageType, _ := kafkaadapter.MessageTypeFromHeaders(msg.Headers)
	reliabilityMessage := brokerreliability.Message{
		Broker:           kafkaadapter.BrokerNameKafka,
		Resource:         msg.Topic,
		OriginalResource: msg.Topic,
		Source:           source,
		MessageType:      messageType,
		Payload:          msg.Value,
		Headers:          kafkaHeadersMap(msg.Headers),
	}
	return brokerreliability.Process(ctx, cfg, reliabilityMessage, func(ctx context.Context) error {
		return adapter.AuthorizeConsume(ctx, msg)
	}, func(context.Context) error {
		log.Printf("KAFKA CONSUME OK: source=%s topic=%s message_type=%s offset=%d value=%s", source, msg.Topic, messageType, msg.Offset, strings.TrimSpace(string(msg.Value)))
		return nil
	}, func(ctx context.Context, env brokerreliability.Envelope) error {
		return publishKafkaDLQ(ctx, dlqWriter, cfg, env)
	})
}

func publishKafkaDLQ(ctx context.Context, writer *kafka.Writer, cfg brokerreliability.Config, env brokerreliability.Envelope) error {
	payload, err := brokerreliability.MarshalEnvelope(env)
	if err != nil {
		return err
	}
	topic := brokerreliability.BuildDLQResource(cfg.DLQPrefix, env.OriginalResource)
	if err := writer.WriteMessages(ctx, kafka.Message{
		Topic: topic,
		Key:   []byte(env.Reason),
		Value: payload,
	}); err != nil {
		return err
	}
	log.Printf("KAFKA DLQ OK: topic=%s reason=%s source=%s message_type=%s", topic, env.Reason, env.Source, env.MessageType)
	return nil
}

func processNATSMessage(ctx context.Context, adapter *natsadapter.Adapter, cfg brokerreliability.Config, conn *nats.Conn, msg *nats.Msg) (brokerreliability.Outcome, error) {
	source, _ := natsadapter.ServiceNameFromHeaders(msg.Header)
	messageType, _ := natsadapter.MessageTypeFromHeaders(msg.Header)
	reliabilityMessage := brokerreliability.Message{
		Broker:           natsadapter.BrokerNameNATS,
		Resource:         msg.Subject,
		OriginalResource: msg.Subject,
		Source:           source,
		MessageType:      messageType,
		Payload:          msg.Data,
		Headers:          natsHeadersMap(msg.Header),
	}
	return brokerreliability.Process(ctx, cfg, reliabilityMessage, func(ctx context.Context) error {
		return adapter.AuthorizeConsume(ctx, msg)
	}, func(context.Context) error {
		log.Printf("NATS CONSUME OK: source=%s subject=%s message_type=%s value=%s", source, msg.Subject, messageType, strings.TrimSpace(string(msg.Data)))
		return nil
	}, func(ctx context.Context, env brokerreliability.Envelope) error {
		return publishNATSDLQ(ctx, conn, cfg, env)
	})
}

func publishNATSDLQ(ctx context.Context, conn *nats.Conn, cfg brokerreliability.Config, env brokerreliability.Envelope) error {
	payload, err := brokerreliability.MarshalEnvelope(env)
	if err != nil {
		return err
	}
	subject := brokerreliability.BuildDLQResource(cfg.DLQPrefix, env.OriginalResource)
	if err := conn.Publish(subject, payload); err != nil {
		return err
	}
	flushCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := conn.FlushWithContext(flushCtx); err != nil {
		return err
	}
	log.Printf("NATS DLQ OK: subject=%s reason=%s source=%s message_type=%s", subject, env.Reason, env.Source, env.MessageType)
	return nil
}

func kafkaHeadersMap(headers []kafka.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for _, h := range headers {
		out[h.Key] = string(h.Value)
	}
	return out
}

func natsHeadersMap(headers nats.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for key, values := range headers {
		if len(values) > 0 {
			out[key] = values[0]
		}
	}
	return out
}

func brokerReliabilityConfig(cfg authz.Config) brokerreliability.Config {
	return brokerreliability.Config{
		DLQEnabled:                 cfg.BrokerDLQEnabled,
		DLQPrefix:                  cfg.BrokerDLQPrefix,
		MaxRetries:                 cfg.BrokerMaxRetries,
		RetryBackoff:               cfg.BrokerRetryBackoff,
		DeadLetterOnDeny:           cfg.BrokerDeadLetterOnDeny,
		DeadLetterOnSignatureError: cfg.BrokerDeadLetterOnSignatureError,
	}
}

func main() {
	serviceName := mustEnv("SERVICE_NAME")
	shutdownTracing, err := authz.InitTracingFromEnv(context.Background(), serviceName)
	if err != nil {
		log.Fatalf("init tracing: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(ctx)
	}()

	policyURL, policyURLs := policyEndpointConfig()

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
		PolicyURLs:    policyURLs,
		FailOpen:      false,
		Timeout:       250 * time.Millisecond,
		CacheTTL:      2 * time.Second,
		PolicyClientTLS: authz.TLSFiles{
			CertFile: policyCert,
			KeyFile:  policyKey,
			CAFile:   policyCA,
		},
		BrokerSigningMode:                envDefault("AUTHZ_MESSAGE_SIGNING_MODE", brokersign.ModeRequired),
		BrokerSigningSecret:              os.Getenv("AUTHZ_MESSAGE_SIGNING_SECRET"),
		BrokerVerificationSecrets:        os.Getenv("AUTHZ_MESSAGE_VERIFICATION_SECRETS"),
		BrokerMessageMaxAge:              durationEnvDefault("AUTHZ_MESSAGE_MAX_AGE", brokersign.DefaultMaxAge),
		BrokerMessageFutureSkew:          durationEnvDefault("AUTHZ_MESSAGE_FUTURE_SKEW", brokersign.DefaultFutureSkew),
		BrokerDLQEnabled:                 boolEnvDefault("BROKER_DLQ_ENABLED", true),
		BrokerDLQPrefix:                  envDefault("BROKER_DLQ_PREFIX", brokerreliability.DefaultDLQPrefix),
		BrokerMaxRetries:                 intEnvDefault("BROKER_MAX_RETRIES", brokerreliability.DefaultMaxRetries),
		BrokerRetryBackoff:               durationEnvDefault("BROKER_RETRY_BACKOFF", brokerreliability.DefaultRetryBackoff),
		BrokerDeadLetterOnDeny:           boolEnvDefault("BROKER_DEAD_LETTER_ON_DENY", true),
		BrokerDeadLetterOnSignatureError: boolEnvDefault("BROKER_DEAD_LETTER_ON_SIGNATURE_ERROR", true),
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
			Handler:   httpadapter.NewMiddleware(cfg)(mux),
			TLSConfig: mustServerTLSConfig(certFile, keyFile, caFile),
		}
		log.Println("payments REST listening on :8080 (mTLS + authz)")
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}()

	s := grpc.NewServer(
		grpc.Creds(mustServerCreds(certFile, keyFile, caFile)),
		grpc.UnaryInterceptor(grpcadapter.NewUnaryInterceptor(cfg)),
		grpc.StreamInterceptor(grpcadapter.NewStreamInterceptor(cfg)),
	)

	paymentsv1.RegisterPaymentsServer(s, &paymentsServer{})

	log.Println("payments listening on :50051 (mTLS + authz)")
	log.Fatal(s.Serve(lis))
}
