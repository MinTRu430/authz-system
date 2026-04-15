package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	paymentsv1 "authz-system/api"
	"authz-system/internal/authz"
	"authz-system/internal/authz/kafkaadapter"
	"authz-system/internal/authz/natsadapter"

	"github.com/nats-io/nats.go"
	"github.com/segmentio/kafka-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	kafkaRequestedTopic     = "payments.requested"
	kafkaRequestedType      = "payment.requested.v1"
	kafkaForcedRefundTopic  = "payments.refund.forced"
	kafkaForcedRefundType   = "payment.refund.forced.v1"
	kafkaDefaultTarget      = "payments"
	kafkaDefaultServiceName = "orders"

	natsRequestedSubject    = "payments.requested"
	natsRequestedType       = "payment.requested.v1"
	natsForcedRefundSubject = "payments.refund.forced"
	natsForcedRefundType    = "payment.refund.forced.v1"
	natsDefaultTarget       = "payments"
	natsDefaultServiceName  = "orders"
)

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

func mustClientTLSConfig(certFile, keyFile, caFile, serverName string) *tls.Config {
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
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName, // "payments"
	}
}

func mustClientCreds(certFile, keyFile, caFile, serverName string) credentials.TransportCredentials {
	return credentials.NewTLS(mustClientTLSConfig(certFile, keyFile, caFile, serverName))
}

func callREST(cmd string) {
	var path, label string
	switch cmd {
	case "rest-charge":
		path, label = "/payments/charge", "REST Charge"
	case "rest-refund":
		path, label = "/payments/refund", "REST Refund"
	default:
		log.Fatalf("unknown REST command %s", cmd)
	}

	tlsConfig := mustClientTLSConfig(
		mustEnv("CERT_FILE"),
		mustEnv("KEY_FILE"),
		mustEnv("CA_FILE"),
		"payments",
	)
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	baseURL := strings.TrimRight(envDefault("PAYMENTS_REST_URL", "https://payments:8080"), "/")
	req, err := http.NewRequest(http.MethodPost, baseURL+path, bytes.NewReader([]byte("{}")))
	if err != nil {
		log.Fatalf("%s request error: %v", label, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("%s error: %v", label, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Fatalf("%s error: status=%d body=%s", label, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	fmt.Printf("%s OK: %s\n", label, strings.TrimSpace(string(body)))
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

func kafkaAuthzConfig() authz.Config {
	certFile := mustEnv("CERT_FILE")
	keyFile := mustEnv("KEY_FILE")
	caFile := mustEnv("CA_FILE")

	return authz.Config{
		TargetService: envDefault("KAFKA_TARGET_SERVICE", kafkaDefaultTarget),
		PolicyURL:     mustEnv("POLICY_URL"),
		FailOpen:      false,
		Timeout:       250 * time.Millisecond,
		CacheTTL:      2 * time.Second,
		PolicyClientTLS: authz.TLSFiles{
			CertFile: envDefault("POLICY_CERT_FILE", certFile),
			KeyFile:  envDefault("POLICY_KEY_FILE", keyFile),
			CAFile:   envDefault("POLICY_CA_FILE", caFile),
		},
	}
}

func natsAuthzConfig() authz.Config {
	certFile := mustEnv("CERT_FILE")
	keyFile := mustEnv("KEY_FILE")
	caFile := mustEnv("CA_FILE")

	return authz.Config{
		TargetService: envDefault("NATS_TARGET_SERVICE", natsDefaultTarget),
		PolicyURL:     mustEnv("POLICY_URL"),
		FailOpen:      false,
		Timeout:       250 * time.Millisecond,
		CacheTTL:      2 * time.Second,
		PolicyClientTLS: authz.TLSFiles{
			CertFile: envDefault("POLICY_CERT_FILE", certFile),
			KeyFile:  envDefault("POLICY_KEY_FILE", keyFile),
			CAFile:   envDefault("POLICY_CA_FILE", caFile),
		},
	}
}

func callKafka(cmd string) {
	var topic, messageType, label string
	useAuthz := true

	switch cmd {
	case "kafka-publish":
		topic = envDefault("KAFKA_TOPIC_PAYMENT_REQUESTED", kafkaRequestedTopic)
		messageType = kafkaRequestedType
		label = "Kafka Publish"
	case "kafka-publish-deny":
		topic = kafkaForcedRefundTopic
		messageType = kafkaForcedRefundType
		label = "Kafka Publish Deny"
	case "kafka-publish-raw":
		topic = envDefault("KAFKA_TOPIC_PAYMENT_REQUESTED", kafkaRequestedTopic)
		messageType = kafkaRequestedType
		label = "Kafka Raw Publish"
		useAuthz = false
	default:
		log.Fatalf("unknown Kafka command %s", cmd)
	}

	writer := &kafka.Writer{
		Addr:     kafka.TCP(splitCSV(envDefault("KAFKA_BROKERS", "kafka:9092"))...),
		Topic:    topic,
		Balancer: &kafka.LeastBytes{},
	}
	defer writer.Close()

	sourceService := envDefault("SERVICE_NAME", kafkaDefaultServiceName)
	msg := kafka.Message{
		Key:   []byte(fmt.Sprintf("%s-%d", messageType, time.Now().UnixNano())),
		Value: []byte(fmt.Sprintf(`{"order_id":"o-1","amount":100,"message_type":%q}`, messageType)),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if useAuthz {
		adapter, err := kafkaadapter.New(kafkaAuthzConfig())
		if err != nil {
			log.Fatalf("%s adapter error: %v", label, err)
		}
		if err := adapter.Publish(ctx, writer, msg, sourceService, messageType); err != nil {
			log.Fatalf("%s error: %v", label, err)
		}
	} else {
		msg.Headers = []kafka.Header{
			{Key: kafkaadapter.HeaderServiceName, Value: []byte(sourceService)},
			{Key: kafkaadapter.HeaderMessageType, Value: []byte(messageType)},
		}
		if err := writer.WriteMessages(ctx, msg); err != nil {
			log.Fatalf("%s error: %v", label, err)
		}
	}

	fmt.Printf("%s OK: topic=%s message_type=%s\n", label, topic, messageType)
}

func callNATS(cmd string) {
	var subject, messageType, label string
	useAuthz := true

	switch cmd {
	case "nats-publish":
		subject = envDefault("NATS_SUBJECT_PAYMENT_REQUESTED", natsRequestedSubject)
		messageType = natsRequestedType
		label = "NATS Publish"
	case "nats-publish-deny":
		subject = natsForcedRefundSubject
		messageType = natsForcedRefundType
		label = "NATS Publish Deny"
	case "nats-publish-raw":
		subject = envDefault("NATS_SUBJECT_PAYMENT_REQUESTED", natsRequestedSubject)
		messageType = natsRequestedType
		label = "NATS Raw Publish"
		useAuthz = false
	default:
		log.Fatalf("unknown NATS command %s", cmd)
	}

	conn, err := nats.Connect(envDefault("NATS_URL", "nats://nats:4222"))
	if err != nil {
		log.Fatalf("%s connect error: %v", label, err)
	}
	defer conn.Close()

	sourceService := envDefault("SERVICE_NAME", natsDefaultServiceName)
	payload := []byte(fmt.Sprintf(`{"order_id":"o-1","amount":100,"message_type":%q}`, messageType))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if useAuthz {
		adapter, err := natsadapter.New(natsAuthzConfig())
		if err != nil {
			log.Fatalf("%s adapter error: %v", label, err)
		}
		if err := adapter.Publish(ctx, conn, subject, payload, sourceService, messageType); err != nil {
			log.Fatalf("%s error: %v", label, err)
		}
	} else {
		msg := &nats.Msg{
			Subject: subject,
			Header: nats.Header{
				natsadapter.HeaderServiceName: []string{sourceService},
				natsadapter.HeaderMessageType: []string{messageType},
			},
			Data: payload,
		}
		if err := conn.PublishMsg(msg); err != nil {
			log.Fatalf("%s error: %v", label, err)
		}
	}

	if err := conn.FlushWithContext(ctx); err != nil {
		log.Fatalf("%s flush error: %v", label, err)
	}
	fmt.Printf("%s OK: subject=%s message_type=%s\n", label, subject, messageType)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: orders charge|refund|rest-charge|rest-refund|kafka-publish|kafka-publish-deny|kafka-publish-raw|nats-publish|nats-publish-deny|nats-publish-raw")
		os.Exit(2)
	}
	cmd := os.Args[1]

	if cmd == "rest-charge" || cmd == "rest-refund" {
		callREST(cmd)
		return
	}
	if cmd == "kafka-publish" || cmd == "kafka-publish-deny" || cmd == "kafka-publish-raw" {
		callKafka(cmd)
		return
	}
	if cmd == "nats-publish" || cmd == "nats-publish-deny" || cmd == "nats-publish-raw" {
		callNATS(cmd)
		return
	}

	creds := mustClientCreds(
		mustEnv("CERT_FILE"),
		mustEnv("KEY_FILE"),
		mustEnv("CA_FILE"),
		"payments",
	)

	conn, err := grpc.Dial("payments:50051", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	c := paymentsv1.NewPaymentsClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	switch cmd {
	case "charge":
		resp, err := c.Charge(ctx, &paymentsv1.ChargeRequest{OrderId: "o-1", Amount: 100})
		if err != nil {
			log.Fatalf("Charge error: %v", err)
		}
		fmt.Println("Charge OK:", resp.Status)
	case "refund":
		resp, err := c.Refund(ctx, &paymentsv1.RefundRequest{PaymentId: "p-1", Amount: 50})
		if err != nil {
			log.Fatalf("Refund error: %v", err)
		}
		fmt.Println("Refund OK:", resp.Status)
	default:
		fmt.Println("usage: orders charge|refund|rest-charge|rest-refund|kafka-publish|kafka-publish-deny|kafka-publish-raw|nats-publish|nats-publish-deny|nats-publish-raw")
		os.Exit(2)
	}
}
