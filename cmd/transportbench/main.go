package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	paymentsv1 "authz-system/api"
	"authz-system/internal/authz"
	"authz-system/internal/authz/kafkaadapter"
	"authz-system/internal/authz/natsadapter"

	"github.com/nats-io/nats.go"
	"github.com/segmentio/kafka-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const (
	messageTypeRequested    = "payment.requested.v1"
	messageTypeForcedRefund = "payment.refund.forced.v1"
	resourceRequested       = "payments.requested"
	resourceForcedRefund    = "payments.refund.forced"
)

type benchResult struct {
	latency time.Duration
	ok      bool
	err     error
}

type runResult struct {
	items   []benchResult
	elapsed time.Duration
}

type benchClient interface {
	Close() error
	Do(context.Context, int) error
}

func main() {
	var (
		transport = flag.String("transport", "grpc", "grpc|rest|kafka|nats")
		scenario  = flag.String("scenario", "allow", "allow|deny")
		n         = flag.Int("n", 200, "measured operations")
		c         = flag.Int("c", 10, "concurrency")
		warmup    = flag.Int("warmup", 20, "warmup operations, not included")
		timeout   = flag.Duration("timeout", 3*time.Second, "per-operation timeout")
	)
	flag.Parse()

	if *scenario != "allow" && *scenario != "deny" {
		log.Fatalf("invalid -scenario=%s", *scenario)
	}
	if *n <= 0 || *c <= 0 {
		log.Fatalf("invalid -n or -c")
	}

	client, err := newBenchClient(*transport, *scenario)
	if err != nil {
		log.Fatalf("create client: %v", err)
	}
	defer client.Close()

	fmt.Printf("[*] transportbench transport=%s scenario=%s n=%d c=%d warmup=%d timeout=%s\n",
		*transport, *scenario, *n, *c, *warmup, timeout.String())

	if *warmup > 0 {
		run(client, *warmup, *c, *timeout)
	}

	results := run(client, *n, *c, *timeout)
	printSummary(*transport, *scenario, *n, *c, results)
}

func newBenchClient(transport, scenario string) (benchClient, error) {
	switch transport {
	case "grpc":
		return newGRPCBenchClient(scenario)
	case "rest", "http":
		return newRESTBenchClient(scenario)
	case "kafka":
		return newKafkaBenchClient(scenario)
	case "nats":
		return newNATSBenchClient(scenario)
	default:
		return nil, fmt.Errorf("unknown transport %q", transport)
	}
}

func run(client benchClient, n int, c int, timeout time.Duration) runResult {
	jobs := make(chan int, c)
	out := make(chan benchResult, c)

	var wg sync.WaitGroup
	wg.Add(c)
	for i := 0; i < c; i++ {
		go func() {
			defer wg.Done()
			for seq := range jobs {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				start := time.Now()
				err := client.Do(ctx, seq)
				elapsed := time.Since(start)
				cancel()

				out <- benchResult{latency: elapsed, ok: err == nil, err: err}
			}
		}()
	}

	start := time.Now()
	go func() {
		for i := 0; i < n; i++ {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		close(out)
	}()

	results := make([]benchResult, 0, n)
	for r := range out {
		results = append(results, r)
	}
	return runResult{items: results, elapsed: time.Since(start)}
}

type grpcBenchClient struct {
	client   paymentsv1.PaymentsClient
	conn     *grpc.ClientConn
	scenario string
}

func newGRPCBenchClient(scenario string) (*grpcBenchClient, error) {
	creds, err := clientCreds("payments")
	if err != nil {
		return nil, err
	}
	conn, err := grpc.Dial(
		envDefault("PAYMENTS_GRPC_ADDR", "payments:50051"),
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
	)
	if err != nil {
		return nil, err
	}
	return &grpcBenchClient{client: paymentsv1.NewPaymentsClient(conn), conn: conn, scenario: scenario}, nil
}

func (c *grpcBenchClient) Close() error {
	return c.conn.Close()
}

func (c *grpcBenchClient) Do(ctx context.Context, seq int) error {
	switch c.scenario {
	case "allow":
		_, err := c.client.Charge(ctx, &paymentsv1.ChargeRequest{OrderId: fmt.Sprintf("o-%d", seq), Amount: 100})
		return err
	case "deny":
		_, err := c.client.Refund(ctx, &paymentsv1.RefundRequest{PaymentId: fmt.Sprintf("p-%d", seq), Amount: 50})
		if status.Code(err) == codes.PermissionDenied {
			return nil
		}
		return err
	default:
		return fmt.Errorf("unknown scenario %q", c.scenario)
	}
}

type restBenchClient struct {
	client   *http.Client
	baseURL  string
	scenario string
}

func newRESTBenchClient(scenario string) (*restBenchClient, error) {
	tlsConfig, err := tlsConfig("payments")
	if err != nil {
		return nil, err
	}
	return &restBenchClient{
		client: &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		baseURL:  strings.TrimRight(envDefault("PAYMENTS_REST_URL", "https://payments:8080"), "/"),
		scenario: scenario,
	}, nil
}

func (c *restBenchClient) Close() error {
	c.client.CloseIdleConnections()
	return nil
}

func (c *restBenchClient) Do(ctx context.Context, seq int) error {
	path := "/payments/charge"
	expectDeny := false
	if c.scenario == "deny" {
		path = "/payments/refund"
		expectDeny = true
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader([]byte("{}")))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	if expectDeny && resp.StatusCode == http.StatusForbidden {
		return nil
	}
	if !expectDeny && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
}

type kafkaBenchClient struct {
	adapter     *kafkaadapter.Adapter
	writer      *kafka.Writer
	source      string
	scenario    string
	messageType string
}

func newKafkaBenchClient(scenario string) (*kafkaBenchClient, error) {
	adapter, err := kafkaadapter.New(brokerAuthzConfig("KAFKA_TARGET_SERVICE"))
	if err != nil {
		return nil, err
	}

	topic, messageType := kafkaResourceForScenario(scenario)
	writer := &kafka.Writer{
		Addr:         kafka.TCP(splitCSV(envDefault("KAFKA_BROKERS", "kafka:9092"))...),
		Topic:        topic,
		Balancer:     &kafka.LeastBytes{},
		BatchSize:    1,
		BatchTimeout: 10 * time.Millisecond,
	}
	return &kafkaBenchClient{
		adapter:     adapter,
		writer:      writer,
		source:      envDefault("SERVICE_NAME", "orders"),
		scenario:    scenario,
		messageType: messageType,
	}, nil
}

func (c *kafkaBenchClient) Close() error {
	return c.writer.Close()
}

func (c *kafkaBenchClient) Do(ctx context.Context, seq int) error {
	msg := kafka.Message{
		Key:   []byte(fmt.Sprintf("%s-%d", c.messageType, seq)),
		Value: []byte(fmt.Sprintf(`{"order_id":"o-%d","amount":100,"message_type":%q}`, seq, c.messageType)),
	}
	err := c.adapter.Publish(ctx, c.writer, msg, c.source, c.messageType)
	if c.scenario == "deny" {
		if errors.Is(err, authz.ErrDenied) {
			return nil
		}
		if err == nil {
			return errors.New("expected deny, got allow")
		}
	}
	return err
}

type natsBenchClient struct {
	adapter     *natsadapter.Adapter
	conn        *nats.Conn
	source      string
	subject     string
	scenario    string
	messageType string
}

func newNATSBenchClient(scenario string) (*natsBenchClient, error) {
	adapter, err := natsadapter.New(brokerAuthzConfig("NATS_TARGET_SERVICE"))
	if err != nil {
		return nil, err
	}

	subject, messageType := natsResourceForScenario(scenario)
	conn, err := nats.Connect(envDefault("NATS_URL", "nats://nats:4222"), nats.Timeout(2*time.Second))
	if err != nil {
		return nil, err
	}
	return &natsBenchClient{
		adapter:     adapter,
		conn:        conn,
		source:      envDefault("SERVICE_NAME", "orders"),
		subject:     subject,
		scenario:    scenario,
		messageType: messageType,
	}, nil
}

func (c *natsBenchClient) Close() error {
	c.conn.Close()
	return nil
}

func (c *natsBenchClient) Do(ctx context.Context, seq int) error {
	payload := []byte(fmt.Sprintf(`{"order_id":"o-%d","amount":100,"message_type":%q}`, seq, c.messageType))
	err := c.adapter.Publish(ctx, c.conn, c.subject, payload, c.source, c.messageType)
	if c.scenario == "deny" {
		if errors.Is(err, authz.ErrDenied) {
			return nil
		}
		if err == nil {
			return errors.New("expected deny, got allow")
		}
	}
	if err != nil {
		return err
	}
	return c.conn.FlushWithContext(ctx)
}

func kafkaResourceForScenario(scenario string) (string, string) {
	if scenario == "deny" {
		return resourceForcedRefund, messageTypeForcedRefund
	}
	return envDefault("KAFKA_TOPIC_PAYMENT_REQUESTED", resourceRequested), messageTypeRequested
}

func natsResourceForScenario(scenario string) (string, string) {
	if scenario == "deny" {
		return resourceForcedRefund, messageTypeForcedRefund
	}
	return envDefault("NATS_SUBJECT_PAYMENT_REQUESTED", resourceRequested), messageTypeRequested
}

func brokerAuthzConfig(targetEnv string) authz.Config {
	return authz.Config{
		TargetService: envDefault(targetEnv, "payments"),
		PolicyURL:     mustEnv("POLICY_URL"),
		FailOpen:      false,
		Timeout:       250 * time.Millisecond,
		CacheTTL:      2 * time.Second,
		PolicyClientTLS: authz.TLSFiles{
			CertFile: envDefault("POLICY_CERT_FILE", mustEnv("CERT_FILE")),
			KeyFile:  envDefault("POLICY_KEY_FILE", mustEnv("KEY_FILE")),
			CAFile:   envDefault("POLICY_CA_FILE", mustEnv("CA_FILE")),
		},
	}
}

func printSummary(transport, scenario string, n int, c int, results runResult) {
	var ok, fail uint64
	var firstErr error
	latencies := make([]time.Duration, 0, len(results.items))
	var total time.Duration
	for _, r := range results.items {
		latencies = append(latencies, r.latency)
		total += r.latency
		if r.ok {
			ok++
		} else {
			fail++
			if firstErr == nil {
				firstErr = r.err
			}
		}
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	min := time.Duration(0)
	max := time.Duration(0)
	avg := time.Duration(0)
	if len(latencies) > 0 {
		min = latencies[0]
		max = latencies[len(latencies)-1]
		avg = total / time.Duration(len(latencies))
	}

	rps := 0.0
	if results.elapsed > 0 {
		rps = float64(len(results.items)) / results.elapsed.Seconds()
	}

	fmt.Println()
	fmt.Printf("=== RESULTS (%s/%s) ===\n", transport, scenario)
	fmt.Printf("Requests: %d  Concurrency: %d\n", n, c)
	fmt.Printf("OK: %d  FAIL: %d\n", ok, fail)
	if firstErr != nil {
		fmt.Printf("First error: %v\n", firstErr)
	}
	fmt.Printf("Estimated RPS: %.1f\n", rps)
	fmt.Println("Latency:")
	fmt.Printf("  min: %s\n", min)
	fmt.Printf("  avg: %s\n", avg)
	fmt.Printf("  p50: %s\n", percentile(latencies, 0.50))
	fmt.Printf("  p95: %s\n", percentile(latencies, 0.95))
	fmt.Printf("  p99: %s\n", percentile(latencies, 0.99))
	fmt.Printf("  max: %s\n", max)
	fmt.Printf("CSV: transport,scenario,n,c,ok,fail,rps,min_ms,avg_ms,p50_ms,p95_ms,p99_ms,max_ms\n")
	fmt.Printf("CSV: %s,%s,%d,%d,%d,%d,%.1f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
		transport, scenario, n, c, ok, fail, rps,
		ms(min), ms(avg), ms(percentile(latencies, 0.50)), ms(percentile(latencies, 0.95)), ms(percentile(latencies, 0.99)), ms(max))
}

func percentile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(q*float64(len(sorted)) + 0.999999)
	if idx < 1 {
		idx = 1
	}
	if idx > len(sorted) {
		idx = len(sorted)
	}
	return sorted[idx-1]
}

func ms(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func clientCreds(serverName string) (credentials.TransportCredentials, error) {
	cfg, err := tlsConfig(serverName)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(cfg), nil
}

func tlsConfig(serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(mustEnv("CERT_FILE"), mustEnv("KEY_FILE"))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(mustEnv("CA_FILE"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caPEM); !ok {
		return nil, errors.New("append CA failed")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
	}, nil
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
