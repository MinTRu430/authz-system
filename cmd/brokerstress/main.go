package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"authz-system/internal/authz"
	"authz-system/internal/authz/brokersign"
	"authz-system/internal/authz/kafkaadapter"
	"authz-system/internal/authz/natsadapter"

	"github.com/nats-io/nats.go"
	"github.com/segmentio/kafka-go"
)

const (
	modePublish = "publish"
	modeE2E     = "e2e"
	modeConsume = "consume"

	scenarioValid            = "valid"
	scenarioInvalidSignature = "invalid-signature"
	scenarioDenied           = "denied"

	expectAuto             = "auto"
	expectAllowed          = "allowed"
	expectBlocked          = "blocked"
	expectDenied           = "denied"
	expectInvalidSignature = "invalid-signature"
	expectAny              = "any"

	outcomeAllowed          = "allowed"
	outcomeBlocked          = "blocked"
	outcomeDenied           = "denied"
	outcomeInvalidSignature = "invalid_signature"
	outcomeError            = "error"

	requestedResource  = "payments.requested"
	requestedType      = "payment.requested.v1"
	deniedResource     = "payments.refund.forced"
	deniedMessageType  = "payment.refund.forced.v1"
	defaultCacheTTL    = 2 * time.Second
	defaultOperationTO = 10 * time.Second
)

type runConfig struct {
	broker      string
	mode        string
	scenario    string
	expect      string
	n           int
	concurrency int
	timeout     time.Duration
	cacheTTL    time.Duration
	pace        time.Duration
}

type messagePayload struct {
	RunID       string `json:"run_id"`
	MessageID   string `json:"message_id"`
	OrderID     string `json:"order_id"`
	Amount      int    `json:"amount"`
	MessageType string `json:"message_type"`
}

type consumeResult struct {
	err     error
	handled bool
}

type operationResult struct {
	latency time.Duration
	outcome string
	success bool
	err     error
}

type summary struct {
	Timestamp        string  `json:"timestamp"`
	Broker           string  `json:"broker"`
	Mode             string  `json:"mode"`
	Scenario         string  `json:"scenario"`
	Expect           string  `json:"expect"`
	CacheTTL         string  `json:"cache_ttl"`
	Total            int     `json:"total"`
	Concurrency      int     `json:"concurrency"`
	Success          int     `json:"success"`
	Errors           int     `json:"errors"`
	Allowed          int     `json:"allowed"`
	Blocked          int     `json:"blocked"`
	Denied           int     `json:"denied"`
	InvalidSignature int     `json:"invalid_signature"`
	HandlerCalls     int64   `json:"handler_calls"`
	ElapsedSeconds   float64 `json:"elapsed_seconds"`
	Throughput       float64 `json:"throughput"`
	AvgMS            float64 `json:"avg_ms"`
	P50MS            float64 `json:"p50_ms"`
	P95MS            float64 `json:"p95_ms"`
	P99MS            float64 `json:"p99_ms"`
	MaxMS            float64 `json:"max_ms"`
	FirstError       string  `json:"first_error,omitempty"`
}

type benchmark struct {
	cfg         runConfig
	runID       string
	source      string
	resource    string
	messageType string

	pending      sync.Map
	handlerCalls atomic.Int64
	consumerSem  chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	kafkaPublisher *kafkaadapter.Adapter
	kafkaConsumer  *kafkaadapter.Adapter
	kafkaWriter    *kafka.Writer
	kafkaReader    *kafka.Reader

	natsPublisher *natsadapter.Adapter
	natsConsumer  *natsadapter.Adapter
	natsConn      *nats.Conn
	natsSub       *nats.Subscription
	natsMessages  chan *nats.Msg
}

func main() {
	cfg := parseFlags()
	b, err := newBenchmark(cfg)
	if err != nil {
		log.Fatalf("create broker benchmark: %v", err)
	}
	defer b.Close()

	if cfg.mode != modePublish {
		if err := b.startConsumer(); err != nil {
			log.Fatalf("start consumer: %v", err)
		}
	}

	fmt.Printf("[*] brokerstress broker=%s mode=%s scenario=%s expect=%s n=%d c=%d cache=%s timeout=%s\n",
		cfg.broker, cfg.mode, cfg.scenario, cfg.expect, cfg.n, cfg.concurrency, cfg.cacheTTL, cfg.timeout)

	start := time.Now()
	results := runOperations(cfg, b.execute)
	elapsed := time.Since(start)
	report := buildSummary(cfg, results, elapsed, b.handlerCalls.Load())
	printSummary(report)

	if report.Errors > 0 {
		os.Exit(1)
	}
}

func parseFlags() runConfig {
	var cfg runConfig
	flag.StringVar(&cfg.broker, "broker", "kafka", "kafka|nats")
	flag.StringVar(&cfg.mode, "mode", modePublish, "publish|e2e|consume")
	flag.StringVar(&cfg.scenario, "scenario", scenarioValid, "valid|invalid-signature|denied")
	flag.StringVar(&cfg.expect, "expect", expectAuto, "auto|allowed|blocked|denied|invalid-signature|any")
	flag.IntVar(&cfg.n, "n", 50000, "number of operations")
	flag.IntVar(&cfg.concurrency, "c", 10, "operation and consumer concurrency")
	flag.DurationVar(&cfg.timeout, "timeout", defaultOperationTO, "per-operation timeout")
	flag.DurationVar(&cfg.cacheTTL, "cache-ttl", defaultCacheTTL, "authorization cache TTL; 0 disables cache")
	flag.DurationVar(&cfg.pace, "pace", 0, "optional delay after each operation")
	flag.Parse()

	cfg.broker = strings.ToLower(strings.TrimSpace(cfg.broker))
	cfg.mode = strings.ToLower(strings.TrimSpace(cfg.mode))
	cfg.scenario = strings.ToLower(strings.TrimSpace(cfg.scenario))
	cfg.expect = strings.ToLower(strings.TrimSpace(cfg.expect))

	if cfg.broker != kafkaadapter.BrokerNameKafka && cfg.broker != natsadapter.BrokerNameNATS {
		log.Fatalf("invalid -broker=%q", cfg.broker)
	}
	if cfg.mode != modePublish && cfg.mode != modeE2E && cfg.mode != modeConsume {
		log.Fatalf("invalid -mode=%q", cfg.mode)
	}
	if cfg.scenario != scenarioValid && cfg.scenario != scenarioInvalidSignature && cfg.scenario != scenarioDenied {
		log.Fatalf("invalid -scenario=%q", cfg.scenario)
	}
	if cfg.mode == modeE2E && cfg.scenario != scenarioValid {
		log.Fatal("e2e mode currently requires -scenario=valid")
	}
	if cfg.mode == modePublish && cfg.scenario == scenarioInvalidSignature {
		log.Fatal("publish mode does not use invalid-signature; use consume mode")
	}
	if cfg.n <= 0 || cfg.concurrency <= 0 {
		log.Fatal("-n and -c must be positive")
	}
	if cfg.timeout <= 0 || cfg.cacheTTL < 0 || cfg.pace < 0 {
		log.Fatal("timeouts must be non-negative and operation timeout must be positive")
	}
	if cfg.expect == expectAuto {
		cfg.expect = expectedOutcome(cfg.scenario)
	}
	switch cfg.expect {
	case expectAllowed, expectBlocked, expectDenied, expectInvalidSignature, expectAny:
	default:
		log.Fatalf("invalid -expect=%q", cfg.expect)
	}
	return cfg
}

func newBenchmark(cfg runConfig) (*benchmark, error) {
	ctx, cancel := context.WithCancel(context.Background())
	resource, messageType := scenarioResource(cfg.scenario)
	b := &benchmark{
		cfg:         cfg,
		runID:       fmt.Sprintf("%d", time.Now().UnixNano()),
		source:      envDefault("SERVICE_NAME", "orders"),
		resource:    resource,
		messageType: messageType,
		consumerSem: make(chan struct{}, cfg.concurrency),
		ctx:         ctx,
		cancel:      cancel,
	}

	authzCfg := brokerAuthzConfig(cfg.cacheTTL)
	switch cfg.broker {
	case kafkaadapter.BrokerNameKafka:
		publisher, err := kafkaadapter.New(authzCfg)
		if err != nil {
			return nil, err
		}
		consumer, err := kafkaadapter.New(authzCfg)
		if err != nil {
			return nil, err
		}
		b.kafkaPublisher = publisher
		b.kafkaConsumer = consumer
		b.kafkaWriter = &kafka.Writer{
			Addr:         kafka.TCP(splitCSV(envDefault("KAFKA_BROKERS", "kafka:9092"))...),
			Balancer:     &kafka.LeastBytes{},
			BatchSize:    100,
			BatchTimeout: 5 * time.Millisecond,
			Async:        false,
		}
	case natsadapter.BrokerNameNATS:
		publisher, err := natsadapter.New(authzCfg)
		if err != nil {
			return nil, err
		}
		consumer, err := natsadapter.New(authzCfg)
		if err != nil {
			return nil, err
		}
		conn, err := nats.Connect(
			envDefault("NATS_URL", "nats://nats:4222"),
			nats.Timeout(3*time.Second),
			nats.ReconnectWait(250*time.Millisecond),
			nats.MaxReconnects(20),
		)
		if err != nil {
			return nil, err
		}
		b.natsPublisher = publisher
		b.natsConsumer = consumer
		b.natsConn = conn
	}
	return b, nil
}

func (b *benchmark) startConsumer() error {
	switch b.cfg.broker {
	case kafkaadapter.BrokerNameKafka:
		return b.startKafkaConsumer()
	case natsadapter.BrokerNameNATS:
		return b.startNATSConsumer()
	default:
		return fmt.Errorf("unsupported broker %q", b.cfg.broker)
	}
}

func (b *benchmark) startKafkaConsumer() error {
	brokers := splitCSV(envDefault("KAFKA_BROKERS", "kafka:9092"))
	if len(brokers) == 0 {
		return errors.New("KAFKA_BROKERS is empty")
	}

	leader, err := kafka.DialLeader(b.ctx, "tcp", brokers[0], b.resource, 0)
	if err != nil {
		return fmt.Errorf("dial Kafka leader: %w", err)
	}
	offset, err := leader.ReadLastOffset()
	_ = leader.Close()
	if err != nil {
		return fmt.Errorf("read Kafka end offset: %w", err)
	}

	b.kafkaReader = kafka.NewReader(kafka.ReaderConfig{
		Brokers:   brokers,
		Topic:     b.resource,
		Partition: 0,
		MinBytes:  1,
		MaxBytes:  10 << 20,
		MaxWait:   100 * time.Millisecond,
	})
	if err := b.kafkaReader.SetOffset(offset); err != nil {
		return fmt.Errorf("set Kafka offset: %w", err)
	}

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			msg, err := b.kafkaReader.FetchMessage(b.ctx)
			if err != nil {
				if b.ctx.Err() != nil {
					return
				}
				continue
			}
			if !b.isOwnPayload(msg.Value) {
				continue
			}
			b.consumerSem <- struct{}{}
			b.wg.Add(1)
			go func(message kafka.Message) {
				defer b.wg.Done()
				defer func() { <-b.consumerSem }()
				b.processKafkaMessage(message)
			}(msg)
		}
	}()
	return nil
}

func (b *benchmark) startNATSConsumer() error {
	bufferSize := b.cfg.n
	if bufferSize > 100000 {
		bufferSize = 100000
	}
	b.natsMessages = make(chan *nats.Msg, bufferSize)
	sub, err := b.natsConn.ChanSubscribe(b.resource, b.natsMessages)
	if err != nil {
		return err
	}
	b.natsSub = sub
	if err := b.natsConn.Flush(); err != nil {
		return err
	}

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			select {
			case <-b.ctx.Done():
				return
			case msg := <-b.natsMessages:
				if msg == nil || !b.isOwnPayload(msg.Data) {
					continue
				}
				b.consumerSem <- struct{}{}
				b.wg.Add(1)
				go func(message *nats.Msg) {
					defer b.wg.Done()
					defer func() { <-b.consumerSem }()
					b.processNATSMessage(message)
				}(msg)
			}
		}
	}()
	return nil
}

func (b *benchmark) execute(ctx context.Context, seq int) (string, error) {
	if b.cfg.pace > 0 {
		defer time.Sleep(b.cfg.pace)
	}

	payload, messageID, err := b.makePayload(seq)
	if err != nil {
		return outcomeError, err
	}

	if b.cfg.mode == modePublish {
		return b.publishAuthorized(ctx, payload, seq)
	}

	resultCh := make(chan consumeResult, 1)
	b.pending.Store(messageID, resultCh)
	defer b.pending.Delete(messageID)

	switch b.cfg.mode {
	case modeE2E:
		_, err = b.publishAuthorized(ctx, payload, seq)
	case modeConsume:
		err = b.publishDirect(ctx, payload, seq)
	default:
		err = fmt.Errorf("unsupported mode %q", b.cfg.mode)
	}
	if err != nil {
		return classifyError(err), err
	}

	select {
	case result := <-resultCh:
		if result.err != nil {
			return classifyError(result.err), result.err
		}
		if !result.handled {
			return outcomeError, errors.New("message completed without handler")
		}
		return outcomeAllowed, nil
	case <-ctx.Done():
		return outcomeError, ctx.Err()
	}
}

func (b *benchmark) publishAuthorized(ctx context.Context, payload []byte, seq int) (string, error) {
	var err error
	switch b.cfg.broker {
	case kafkaadapter.BrokerNameKafka:
		err = b.kafkaPublisher.Publish(ctx, b.kafkaWriter, kafka.Message{
			Topic: b.resource,
			Key:   []byte(fmt.Sprintf("%s-%d", b.runID, seq)),
			Value: payload,
		}, b.source, b.messageType)
	case natsadapter.BrokerNameNATS:
		err = b.natsPublisher.Publish(ctx, b.natsConn, b.resource, payload, b.source, b.messageType)
		if err == nil {
			err = b.natsConn.FlushWithContext(ctx)
		}
	}
	if err != nil {
		return classifyError(err), err
	}
	return outcomeAllowed, nil
}

func (b *benchmark) publishDirect(ctx context.Context, payload []byte, seq int) error {
	switch b.cfg.broker {
	case kafkaadapter.BrokerNameKafka:
		headers, err := b.kafkaPublisher.SignHeaders(nil, b.resource, payload, b.source, b.messageType)
		if err != nil {
			return err
		}
		if b.cfg.scenario == scenarioInvalidSignature {
			headers = tamperKafkaSignature(headers)
		}
		return b.kafkaWriter.WriteMessages(ctx, kafka.Message{
			Topic:   b.resource,
			Key:     []byte(fmt.Sprintf("%s-%d", b.runID, seq)),
			Value:   payload,
			Headers: headers,
		})
	case natsadapter.BrokerNameNATS:
		headers, err := b.natsPublisher.SignHeaders(nil, b.resource, payload, b.source, b.messageType)
		if err != nil {
			return err
		}
		if b.cfg.scenario == scenarioInvalidSignature {
			headers.Set(natsadapter.HeaderSignature, "invalid")
		}
		if err := b.natsConn.PublishMsg(&nats.Msg{
			Subject: b.resource,
			Header:  headers,
			Data:    payload,
		}); err != nil {
			return err
		}
		return b.natsConn.FlushWithContext(ctx)
	default:
		return fmt.Errorf("unsupported broker %q", b.cfg.broker)
	}
}

func (b *benchmark) processKafkaMessage(msg kafka.Message) {
	ctx, cancel := context.WithTimeout(b.ctx, b.cfg.timeout)
	defer cancel()

	err := b.kafkaConsumer.AuthorizeConsume(ctx, msg)
	handled := false
	if err == nil {
		handled = true
		b.handlerCalls.Add(1)
	}
	b.complete(msg.Value, consumeResult{err: err, handled: handled})
}

func (b *benchmark) processNATSMessage(msg *nats.Msg) {
	ctx, cancel := context.WithTimeout(b.ctx, b.cfg.timeout)
	defer cancel()

	err := b.natsConsumer.AuthorizeConsume(ctx, msg)
	handled := false
	if err == nil {
		handled = true
		b.handlerCalls.Add(1)
	}
	b.complete(msg.Data, consumeResult{err: err, handled: handled})
}

func (b *benchmark) complete(data []byte, result consumeResult) {
	var payload messagePayload
	if err := json.Unmarshal(data, &payload); err != nil || payload.RunID != b.runID {
		return
	}
	value, ok := b.pending.LoadAndDelete(payload.MessageID)
	if !ok {
		return
	}
	ch := value.(chan consumeResult)
	ch <- result
}

func (b *benchmark) isOwnPayload(data []byte) bool {
	var payload messagePayload
	return json.Unmarshal(data, &payload) == nil && payload.RunID == b.runID
}

func (b *benchmark) makePayload(seq int) ([]byte, string, error) {
	messageID := fmt.Sprintf("%s-%d", b.runID, seq)
	payload, err := json.Marshal(messagePayload{
		RunID:       b.runID,
		MessageID:   messageID,
		OrderID:     fmt.Sprintf("stress-%d", seq),
		Amount:      100,
		MessageType: b.messageType,
	})
	return payload, messageID, err
}

func (b *benchmark) Close() {
	b.cancel()
	if b.kafkaReader != nil {
		_ = b.kafkaReader.Close()
	}
	if b.natsSub != nil {
		_ = b.natsSub.Unsubscribe()
	}
	b.wg.Wait()
	if b.kafkaWriter != nil {
		_ = b.kafkaWriter.Close()
	}
	if b.natsConn != nil {
		b.natsConn.Close()
	}
}

func runOperations(cfg runConfig, operation func(context.Context, int) (string, error)) []operationResult {
	jobs := make(chan int, cfg.concurrency)
	results := make(chan operationResult, cfg.concurrency)
	var wg sync.WaitGroup

	for worker := 0; worker < cfg.concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := range jobs {
				ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
				start := time.Now()
				outcome, err := operation(ctx, seq)
				elapsed := time.Since(start)
				cancel()
				results <- operationResult{
					latency: elapsed,
					outcome: outcome,
					success: matchesExpectation(cfg.expect, outcome),
					err:     err,
				}
			}
		}()
	}

	go func() {
		for seq := 0; seq < cfg.n; seq++ {
			jobs <- seq
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	out := make([]operationResult, 0, cfg.n)
	for result := range results {
		out = append(out, result)
	}
	return out
}

func buildSummary(cfg runConfig, results []operationResult, elapsed time.Duration, handlerCalls int64) summary {
	report := summary{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Broker:         cfg.broker,
		Mode:           cfg.mode,
		Scenario:       cfg.scenario,
		Expect:         cfg.expect,
		CacheTTL:       cfg.cacheTTL.String(),
		Total:          len(results),
		Concurrency:    cfg.concurrency,
		HandlerCalls:   handlerCalls,
		ElapsedSeconds: elapsed.Seconds(),
	}

	latencies := make([]time.Duration, 0, len(results))
	var totalLatency time.Duration
	for _, result := range results {
		latencies = append(latencies, result.latency)
		totalLatency += result.latency
		if result.success {
			report.Success++
		} else {
			report.Errors++
			if report.FirstError == "" && result.err != nil {
				report.FirstError = result.err.Error()
			}
		}
		switch result.outcome {
		case outcomeAllowed:
			report.Allowed++
		case outcomeBlocked:
			report.Blocked++
		case outcomeDenied:
			report.Denied++
		case outcomeInvalidSignature:
			report.InvalidSignature++
		}
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	if len(latencies) > 0 {
		report.AvgMS = milliseconds(totalLatency / time.Duration(len(latencies)))
		report.P50MS = milliseconds(percentile(latencies, 0.50))
		report.P95MS = milliseconds(percentile(latencies, 0.95))
		report.P99MS = milliseconds(percentile(latencies, 0.99))
		report.MaxMS = milliseconds(latencies[len(latencies)-1])
	}
	if elapsed > 0 {
		report.Throughput = float64(len(results)) / elapsed.Seconds()
	}
	return report
}

func printSummary(report summary) {
	fmt.Println()
	fmt.Printf("=== BROKER STRESS RESULTS (%s/%s/%s) ===\n", report.Broker, report.Mode, report.Scenario)
	fmt.Printf("Total: %d  Concurrency: %d  Cache: %s\n", report.Total, report.Concurrency, report.CacheTTL)
	fmt.Printf("Success: %d  Errors: %d  Handler calls: %d\n", report.Success, report.Errors, report.HandlerCalls)
	fmt.Printf("Allowed: %d  Blocked: %d  Denied: %d  Invalid signature: %d\n",
		report.Allowed, report.Blocked, report.Denied, report.InvalidSignature)
	fmt.Printf("Throughput: %.1f ops/s\n", report.Throughput)
	fmt.Printf("Latency: avg=%.3fms p50=%.3fms p95=%.3fms p99=%.3fms max=%.3fms\n",
		report.AvgMS, report.P50MS, report.P95MS, report.P99MS, report.MaxMS)
	if report.FirstError != "" {
		fmt.Printf("First error: %s\n", report.FirstError)
	}

	encoded, _ := json.Marshal(report)
	fmt.Printf("JSON: %s\n", encoded)
	fmt.Printf("MARKDOWN: | %s | %s | %s | %s | %d | %d | %s | %d | %d | %d | %d | %d | %d | %.1f | %.3f | %.3f | %.3f | %.3f | %d |\n",
		report.Broker, report.Mode, report.Scenario, report.CacheTTL,
		report.Total, report.Concurrency, report.Expect, report.Success, report.Errors,
		report.Allowed, report.Blocked, report.Denied, report.InvalidSignature,
		report.Throughput, report.AvgMS, report.P50MS, report.P95MS, report.P99MS, report.HandlerCalls)
}

func expectedOutcome(scenario string) string {
	switch scenario {
	case scenarioInvalidSignature:
		return expectInvalidSignature
	case scenarioDenied:
		return expectDenied
	default:
		return expectAllowed
	}
}

func matchesExpectation(expect, outcome string) bool {
	if expect == expectAny {
		return outcome != outcomeError
	}
	return expect == outcome || (expect == expectInvalidSignature && outcome == outcomeInvalidSignature)
}

func classifyError(err error) string {
	if err == nil {
		return outcomeAllowed
	}
	switch {
	case errors.Is(err, authz.ErrFailClosed), errors.Is(err, authz.ErrPolicyUnavailable):
		return outcomeBlocked
	case errors.Is(err, authz.ErrDenied):
		return outcomeDenied
	}
	if reason := brokersign.FailureReason(err); reason != "" && reason != "unknown" {
		return outcomeInvalidSignature
	}
	return outcomeError
}

func scenarioResource(scenario string) (string, string) {
	if scenario == scenarioDenied {
		return deniedResource, deniedMessageType
	}
	return requestedResource, requestedType
}

func percentile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := int(q*float64(len(sorted)) + 0.999999)
	if index < 1 {
		index = 1
	}
	if index > len(sorted) {
		index = len(sorted)
	}
	return sorted[index-1]
}

func milliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}

func tamperKafkaSignature(headers []kafka.Header) []kafka.Header {
	for i := range headers {
		if headers[i].Key == kafkaadapter.HeaderSignature {
			headers[i].Value = []byte("invalid")
			return headers
		}
	}
	return append(headers, kafka.Header{Key: kafkaadapter.HeaderSignature, Value: []byte("invalid")})
}

func brokerAuthzConfig(cacheTTL time.Duration) authz.Config {
	policyURL := os.Getenv("POLICY_URL")
	policyURLs := splitCSV(os.Getenv("POLICY_URLS"))
	if policyURL == "" && len(policyURLs) == 0 {
		log.Fatal("missing env POLICY_URL or POLICY_URLS")
	}
	return authz.Config{
		TargetService: "payments",
		PolicyURL:     policyURL,
		PolicyURLs:    policyURLs,
		FailOpen:      false,
		Timeout:       500 * time.Millisecond,
		CacheTTL:      cacheTTL,
		PolicyClientTLS: authz.TLSFiles{
			CertFile: envDefault("POLICY_CERT_FILE", mustEnv("CERT_FILE")),
			KeyFile:  envDefault("POLICY_KEY_FILE", mustEnv("KEY_FILE")),
			CAFile:   envDefault("POLICY_CA_FILE", mustEnv("CA_FILE")),
		},
		BrokerSigningMode:         envDefault("AUTHZ_MESSAGE_SIGNING_MODE", brokersign.ModeRequired),
		BrokerSigningSecret:       os.Getenv("AUTHZ_MESSAGE_SIGNING_SECRET"),
		BrokerVerificationSecrets: os.Getenv("AUTHZ_MESSAGE_VERIFICATION_SECRETS"),
		BrokerMessageMaxAge:       durationEnvDefault("AUTHZ_MESSAGE_MAX_AGE", brokersign.DefaultMaxAge),
		BrokerMessageFutureSkew:   durationEnvDefault("AUTHZ_MESSAGE_FUTURE_SKEW", brokersign.DefaultFutureSkew),
	}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func mustEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("missing env %s", key)
	}
	return value
}

func envDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func durationEnvDefault(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		log.Fatalf("invalid duration env %s=%q: %v", key, value, err)
	}
	return duration
}
