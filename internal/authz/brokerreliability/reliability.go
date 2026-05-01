package brokerreliability

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"authz-system/internal/authz"
	"authz-system/internal/authz/brokersign"

	"go.opentelemetry.io/otel/attribute"
)

const (
	ReasonMissingSignature     = "missing_signature"
	ReasonUnsupportedVersion   = "unsupported_version"
	ReasonMalformedTimestamp   = "malformed_timestamp"
	ReasonExpiredTimestamp     = "expired_timestamp"
	ReasonFutureTimestamp      = "future_timestamp"
	ReasonPayloadHashMismatch  = "payload_hash_mismatch"
	ReasonUnknownServiceSecret = "unknown_service_secret"
	ReasonInvalidSignature     = "invalid_signature"
	ReasonMalformedHeaders     = "malformed_headers"
	ReasonDenied               = "denied"
	ReasonPolicyUnavailable    = "policy_unavailable"
	ReasonHandlerError         = "handler_error"
	ReasonBrokerError          = "broker_error"
	ResultProcessed            = "processed"
	ResultDeadLettered         = "deadlettered"
	ResultDropped              = "dropped"
	ResultError                = "error"
	DefaultDLQPrefix           = "authz.dlq"
	DefaultMaxRetries          = 3
	DefaultRetryBackoff        = 500 * time.Millisecond
)

type Config struct {
	DLQEnabled                 bool
	DLQPrefix                  string
	MaxRetries                 int
	RetryBackoff               time.Duration
	DeadLetterOnDeny           bool
	DeadLetterOnSignatureError bool
}

type Message struct {
	Broker           string
	Resource         string
	OriginalResource string
	Source           string
	MessageType      string
	Payload          []byte
	Headers          map[string]string
}

type Envelope struct {
	Broker           string            `json:"broker"`
	Resource         string            `json:"resource"`
	OriginalResource string            `json:"original_resource"`
	Source           string            `json:"source,omitempty"`
	MessageType      string            `json:"message_type,omitempty"`
	Reason           string            `json:"reason"`
	Error            string            `json:"error"`
	Timestamp        string            `json:"timestamp"`
	PayloadBase64    string            `json:"payload_base64"`
	Headers          map[string]string `json:"headers,omitempty"`
}

type Classification struct {
	Reason    string
	Terminal  bool
	Transient bool
}

type Outcome struct {
	Result       string
	Reason       string
	Retried      int
	DeadLettered bool
}

type DLQPublisher func(context.Context, Envelope) error
type Step func(context.Context) error

func Defaults(cfg Config) Config {
	if cfg.DLQPrefix == "" {
		cfg.DLQPrefix = DefaultDLQPrefix
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = DefaultMaxRetries
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = DefaultRetryBackoff
	}
	return cfg
}

func BuildDLQResource(prefix, resource string) string {
	if prefix == "" {
		prefix = DefaultDLQPrefix
	}
	prefix = strings.TrimSuffix(prefix, ".")
	resource = strings.TrimPrefix(resource, ".")
	if resource == "" {
		return prefix
	}
	return prefix + "." + resource
}

func Classify(err error) Classification {
	switch {
	case err == nil:
		return Classification{}
	case errors.Is(err, brokersign.ErrMissingSignature):
		return terminal(ReasonMissingSignature)
	case errors.Is(err, brokersign.ErrUnsupportedVersion):
		return terminal(ReasonUnsupportedVersion)
	case errors.Is(err, brokersign.ErrMalformedTimestamp):
		return terminal(ReasonMalformedTimestamp)
	case errors.Is(err, brokersign.ErrExpiredTimestamp):
		return terminal(ReasonExpiredTimestamp)
	case errors.Is(err, brokersign.ErrFutureTimestamp):
		return terminal(ReasonFutureTimestamp)
	case errors.Is(err, brokersign.ErrPayloadHashMismatch):
		return terminal(ReasonPayloadHashMismatch)
	case errors.Is(err, brokersign.ErrUnknownServiceSecret):
		return terminal(ReasonUnknownServiceSecret)
	case errors.Is(err, brokersign.ErrInvalidSignature):
		return terminal(ReasonInvalidSignature)
	case errors.Is(err, authz.ErrDenied):
		return terminal(ReasonDenied)
	case errors.Is(err, authz.ErrFailClosed), errors.Is(err, authz.ErrPolicyUnavailable):
		return transient(ReasonPolicyUnavailable)
	case isMalformedHeaderError(err):
		return terminal(ReasonMalformedHeaders)
	default:
		return transient(ReasonBrokerError)
	}
}

func Process(ctx context.Context, cfg Config, msg Message, authorize Step, handle Step, publishDLQ DLQPublisher) (Outcome, error) {
	cfg = Defaults(cfg)

	authOutcome, err := runWithRetry(ctx, cfg, msg.Broker, authorize)
	if err != nil {
		class := Classify(err)
		if class.Terminal {
			return handleTerminal(ctx, cfg, msg, class.Reason, err, publishDLQ)
		}
		return deadLetter(ctx, cfg, msg, class.Reason, err, publishDLQ)
	}

	if handle == nil {
		authz.RecordBrokerMessageProcessing(msg.Broker, ResultProcessed)
		return Outcome{Result: ResultProcessed, Retried: authOutcome.Retried}, nil
	}

	handlerOutcome, err := retryHandler(ctx, cfg, msg.Broker, handle)
	if err != nil {
		return deadLetter(ctx, cfg, msg, ReasonHandlerError, err, publishDLQ)
	}
	retried := authOutcome.Retried + handlerOutcome.Retried
	authz.RecordBrokerMessageProcessing(msg.Broker, ResultProcessed)
	return Outcome{Result: ResultProcessed, Retried: retried}, nil
}

func NewEnvelope(msg Message, reason string, err error, now time.Time) Envelope {
	original := msg.OriginalResource
	if original == "" {
		original = msg.Resource
	}
	return Envelope{
		Broker:           msg.Broker,
		Resource:         msg.Resource,
		OriginalResource: original,
		Source:           msg.Source,
		MessageType:      msg.MessageType,
		Reason:           reason,
		Error:            errorString(err),
		Timestamp:        now.UTC().Format(time.RFC3339),
		PayloadBase64:    base64.StdEncoding.EncodeToString(msg.Payload),
		Headers:          AllowlistHeaders(msg.Headers),
	}
}

func MarshalEnvelope(env Envelope) ([]byte, error) {
	return json.Marshal(env)
}

func AllowlistHeaders(headers map[string]string) map[string]string {
	allowed := map[string]struct{}{
		brokersign.HeaderServiceName:      {},
		brokersign.HeaderMessageType:      {},
		brokersign.HeaderSignatureVersion: {},
		brokersign.HeaderTimestamp:        {},
		brokersign.HeaderPayloadSHA256:    {},
		brokersign.HeaderSignature:        {},
	}
	out := make(map[string]string, len(allowed))
	for key, value := range headers {
		if _, ok := allowed[key]; ok {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func runWithRetry(ctx context.Context, cfg Config, broker string, step Step) (Outcome, error) {
	if step == nil {
		return Outcome{}, nil
	}
	var retried int
	for {
		err := step(ctx)
		if err == nil {
			return Outcome{Retried: retried}, nil
		}
		class := Classify(err)
		if class.Terminal {
			return Outcome{Reason: class.Reason, Retried: retried}, err
		}
		if retried >= cfg.MaxRetries {
			return Outcome{Reason: class.Reason, Retried: retried}, err
		}
		retried++
		_, span := authz.StartSpan(ctx, "broker.consume.retry",
			append(authz.BrokerTraceAttrs(broker, "consume"),
				attribute.String("broker.retry_reason", class.Reason),
				attribute.Int("broker.retry_count", retried),
			)...,
		)
		authz.EndSpanWithResult(span, "retry", nil)
		span.End()
		authz.RecordBrokerMessageRetried(broker, class.Reason)
		if err := sleep(ctx, cfg.RetryBackoff); err != nil {
			return Outcome{Reason: class.Reason, Retried: retried}, err
		}
	}
}

func retryHandler(ctx context.Context, cfg Config, broker string, step Step) (Outcome, error) {
	var retried int
	for {
		err := step(ctx)
		if err == nil {
			return Outcome{Retried: retried}, nil
		}
		if retried >= cfg.MaxRetries {
			return Outcome{Reason: ReasonHandlerError, Retried: retried}, err
		}
		retried++
		_, span := authz.StartSpan(ctx, "broker.consume.retry",
			append(authz.BrokerTraceAttrs(broker, "consume"),
				attribute.String("broker.retry_reason", ReasonHandlerError),
				attribute.Int("broker.retry_count", retried),
			)...,
		)
		authz.EndSpanWithResult(span, "retry", nil)
		span.End()
		authz.RecordBrokerMessageRetried(broker, ReasonHandlerError)
		if err := sleep(ctx, cfg.RetryBackoff); err != nil {
			return Outcome{Reason: ReasonHandlerError, Retried: retried}, err
		}
	}
}

func handleTerminal(ctx context.Context, cfg Config, msg Message, reason string, err error, publishDLQ DLQPublisher) (Outcome, error) {
	if reason == ReasonDenied && !cfg.DeadLetterOnDeny {
		authz.RecordBrokerMessageProcessing(msg.Broker, ResultDropped)
		return Outcome{Result: ResultDropped, Reason: reason}, nil
	}
	if isSignatureReason(reason) && !cfg.DeadLetterOnSignatureError {
		authz.RecordBrokerMessageProcessing(msg.Broker, ResultDropped)
		return Outcome{Result: ResultDropped, Reason: reason}, nil
	}
	return deadLetter(ctx, cfg, msg, reason, err, publishDLQ)
}

func deadLetter(ctx context.Context, cfg Config, msg Message, reason string, err error, publishDLQ DLQPublisher) (Outcome, error) {
	_, span := authz.StartSpan(ctx, "broker.consume.dead_letter",
		append(authz.BrokerTraceAttrs(msg.Broker, "consume"),
			attribute.Bool("broker.dlq", cfg.DLQEnabled),
			attribute.String("broker.dlq_reason", reason),
		)...,
	)
	defer span.End()

	authz.RecordBrokerConsumeError(msg.Broker, reason)
	if !cfg.DLQEnabled {
		authz.RecordBrokerMessageProcessing(msg.Broker, ResultDropped)
		authz.EndSpanWithResult(span, ResultDropped, nil)
		return Outcome{Result: ResultDropped, Reason: reason}, nil
	}
	if publishDLQ == nil {
		authz.RecordBrokerMessageProcessing(msg.Broker, ResultError)
		authz.EndSpanWithResult(span, ResultError, errors.New("broker DLQ publisher is nil"))
		return Outcome{Result: ResultError, Reason: reason}, errors.New("broker DLQ publisher is nil")
	}
	env := NewEnvelope(msg, reason, err, time.Now())
	if publishErr := publishDLQ(ctx, env); publishErr != nil {
		authz.RecordBrokerDLQPublishError(msg.Broker)
		authz.RecordBrokerMessageProcessing(msg.Broker, ResultError)
		authz.EndSpanWithResult(span, ResultError, publishErr)
		return Outcome{Result: ResultError, Reason: reason}, publishErr
	}
	authz.RecordBrokerMessageDeadLettered(msg.Broker, reason)
	authz.RecordBrokerMessageProcessing(msg.Broker, ResultDeadLettered)
	authz.EndSpanWithResult(span, ResultDeadLettered, nil)
	return Outcome{Result: ResultDeadLettered, Reason: reason, DeadLettered: true}, nil
}

func terminal(reason string) Classification {
	return Classification{Reason: reason, Terminal: true}
}

func transient(reason string) Classification {
	return Classification{Reason: reason, Transient: true}
}

func isSignatureReason(reason string) bool {
	switch reason {
	case ReasonMissingSignature, ReasonUnsupportedVersion, ReasonMalformedTimestamp, ReasonExpiredTimestamp, ReasonFutureTimestamp, ReasonPayloadHashMismatch, ReasonUnknownServiceSecret, ReasonInvalidSignature:
		return true
	default:
		return false
	}
}

func isMalformedHeaderError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "missing x-service-name") ||
		strings.Contains(msg, "missing x-message-type") ||
		strings.Contains(msg, "topic is empty") ||
		strings.Contains(msg, "subject is empty")
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
