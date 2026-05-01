package kafkaadapter

import (
	"context"
	"errors"

	"authz-system/internal/authz"
	"authz-system/internal/authz/brokersign"

	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel/attribute"
)

const (
	BrokerNameKafka        = "kafka"
	HeaderServiceName      = "X-Service-Name"
	HeaderMessageType      = "X-Message-Type"
	HeaderSignatureVersion = brokersign.HeaderSignatureVersion
	HeaderTimestamp        = brokersign.HeaderTimestamp
	HeaderPayloadSHA256    = brokersign.HeaderPayloadSHA256
	HeaderSignature        = brokersign.HeaderSignature
	DefaultTargetService   = "payments"
	DefaultRequestedTopic  = "payments.requested"
)

var (
	ErrMissingServiceName = errors.New("kafka message missing X-Service-Name header")
	ErrMissingMessageType = errors.New("kafka message missing X-Message-Type header")
	ErrMissingTopic       = errors.New("kafka message topic is empty")
)

type Adapter struct {
	targetService string
	broker        authz.BrokerAuthzAdapter
	signingMode   string
	signer        *brokersign.Signer
	verifier      *brokersign.Verifier
}

func New(cfg authz.Config) (*Adapter, error) {
	broker, err := authz.NewGenericBrokerAdapter(cfg)
	if err != nil {
		return nil, err
	}
	target := cfg.TargetService
	if target == "" {
		target = DefaultTargetService
	}
	adapter := &Adapter{targetService: target, broker: broker}
	if err := adapter.configureSigning(cfg); err != nil {
		return nil, err
	}
	return adapter, nil
}

func NewWithBrokerAuthzAdapter(targetService string, broker authz.BrokerAuthzAdapter) *Adapter {
	if targetService == "" {
		targetService = DefaultTargetService
	}
	return &Adapter{targetService: targetService, broker: broker, signingMode: brokersign.ModeDisabled}
}

func (a *Adapter) Publish(ctx context.Context, writer *kafka.Writer, msg kafka.Message, sourceService, messageType string) error {
	topic := topicForMessage(writer, msg)
	if topic == "" {
		return ErrMissingTopic
	}

	ctx, span := authz.StartSpan(ctx, "broker.publish.authorize", authz.BrokerTraceAttrs(BrokerNameKafka, "publish")...)
	interaction := authz.BrokerInteraction{
		SourceService: sourceService,
		TargetService: a.targetService,
		Broker:        BrokerNameKafka,
		Resource:      topic,
		MessageType:   messageType,
	}
	if _, err := a.broker.AuthorizePublish(ctx, interaction); err != nil {
		authz.EndSpanWithResult(span, brokerAuthzTraceResult(err), brokerAuthzTraceError(err))
		span.End()
		return err
	}
	authz.EndSpanWithResult(span, "allow", nil)
	span.End()

	if writer == nil || writer.Topic == "" {
		msg.Topic = topic
	} else {
		msg.Topic = ""
	}
	headers, err := a.SignHeaders(msg.Headers, topic, msg.Value, sourceService, messageType)
	if err != nil {
		return err
	}
	msg.Headers = headers
	return writer.WriteMessages(ctx, msg)
}

func (a *Adapter) AuthorizeConsume(ctx context.Context, msg kafka.Message) error {
	topic := msg.Topic
	if topic == "" {
		return ErrMissingTopic
	}
	sourceService, err := ServiceNameFromHeaders(msg.Headers)
	if err != nil {
		return err
	}
	messageType, err := MessageTypeFromHeaders(msg.Headers)
	if err != nil {
		return err
	}
	ctx, verifySpan := authz.StartSpan(ctx, "broker.consume.verify_signature", authz.BrokerTraceAttrs(BrokerNameKafka, "consume")...)
	if err := a.verifySignature(topic, msg.Value, sourceService, messageType, msg.Headers); err != nil {
		verifySpan.SetAttributes(attribute.String("broker.signature_result", brokersign.FailureReason(err)))
		authz.EndSpanWithResult(verifySpan, "fail", err)
		verifySpan.End()
		return err
	}
	verifySpan.SetAttributes(attribute.String("broker.signature_result", "ok"))
	authz.EndSpanWithResult(verifySpan, "ok", nil)
	verifySpan.End()

	interaction := authz.BrokerInteraction{
		SourceService: sourceService,
		TargetService: a.targetService,
		Broker:        BrokerNameKafka,
		Resource:      topic,
		MessageType:   messageType,
	}
	ctx, authSpan := authz.StartSpan(ctx, "broker.consume.authorize", authz.BrokerTraceAttrs(BrokerNameKafka, "consume")...)
	_, err = a.broker.AuthorizeConsume(ctx, interaction)
	authz.EndSpanWithResult(authSpan, brokerAuthzTraceResult(err), brokerAuthzTraceError(err))
	authSpan.End()
	return err
}

func (a *Adapter) SignHeaders(headers []kafka.Header, resource string, payload []byte, sourceService, messageType string) ([]kafka.Header, error) {
	headers = upsertHeader(headers, HeaderServiceName, sourceService)
	headers = upsertHeader(headers, HeaderMessageType, messageType)
	if !a.signingRequired() {
		return headers, nil
	}
	if a.signer == nil {
		return nil, brokersign.ErrMissingSigningSecret
	}
	signed, err := a.signer.Sign(brokersign.SignInput{
		Broker:      BrokerNameKafka,
		Resource:    resource,
		Source:      sourceService,
		MessageType: messageType,
		Payload:     payload,
	})
	if err != nil {
		return nil, err
	}
	for key, value := range signed {
		headers = upsertHeader(headers, key, value)
	}
	authz.RecordMessageSigned(BrokerNameKafka)
	return headers, nil
}

func ServiceNameFromHeaders(headers []kafka.Header) (string, error) {
	v := headerValue(headers, HeaderServiceName)
	if v == "" {
		return "", ErrMissingServiceName
	}
	return v, nil
}

func MessageTypeFromHeaders(headers []kafka.Header) (string, error) {
	v := headerValue(headers, HeaderMessageType)
	if v == "" {
		return "", ErrMissingMessageType
	}
	return v, nil
}

func upsertHeader(headers []kafka.Header, key, value string) []kafka.Header {
	for i := range headers {
		if headers[i].Key == key {
			headers[i].Value = []byte(value)
			return headers
		}
	}
	return append(headers, kafka.Header{Key: key, Value: []byte(value)})
}

func headerValue(headers []kafka.Header, key string) string {
	for _, h := range headers {
		if h.Key == key {
			return string(h.Value)
		}
	}
	return ""
}

func topicForMessage(writer *kafka.Writer, msg kafka.Message) string {
	if msg.Topic != "" {
		return msg.Topic
	}
	if writer != nil {
		return writer.Topic
	}
	return ""
}

func (a *Adapter) configureSigning(cfg authz.Config) error {
	mode, err := brokersign.NormalizeMode(cfg.BrokerSigningMode)
	if err != nil {
		return err
	}
	a.signingMode = mode
	if mode == brokersign.ModeDisabled {
		return nil
	}
	if cfg.BrokerSigningSecret != "" {
		secret, err := brokersign.ParseSecret(cfg.BrokerSigningSecret)
		if err != nil {
			return err
		}
		a.signer, err = brokersign.NewSigner(brokersign.SignerConfig{Secret: secret})
		if err != nil {
			return err
		}
	}
	if cfg.BrokerVerificationSecrets != "" {
		secrets, err := brokersign.ParseVerificationSecrets(cfg.BrokerVerificationSecrets)
		if err != nil {
			return err
		}
		a.verifier, err = brokersign.NewVerifier(brokersign.VerifierConfig{
			Secrets:    secrets,
			MaxAge:     cfg.BrokerMessageMaxAge,
			FutureSkew: cfg.BrokerMessageFutureSkew,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) signingRequired() bool {
	return a.signingMode != brokersign.ModeDisabled
}

func (a *Adapter) verifySignature(resource string, payload []byte, sourceService, messageType string, headers []kafka.Header) error {
	if !a.signingRequired() {
		return nil
	}
	if a.verifier == nil {
		err := brokersign.ErrMissingVerificationKeys
		authz.RecordMessageSignatureCheck(BrokerNameKafka, "fail")
		authz.RecordMessageSignatureFailure(BrokerNameKafka, brokersign.FailureReason(err))
		return err
	}
	err := a.verifier.Verify(brokersign.VerifyInput{
		Broker:      BrokerNameKafka,
		Resource:    resource,
		Source:      sourceService,
		MessageType: messageType,
		Payload:     payload,
		Headers:     kafkaHeadersMap(headers),
	})
	if err != nil {
		authz.RecordMessageSignatureCheck(BrokerNameKafka, "fail")
		authz.RecordMessageSignatureFailure(BrokerNameKafka, brokersign.FailureReason(err))
		return err
	}
	authz.RecordMessageSignatureCheck(BrokerNameKafka, "ok")
	return nil
}

func kafkaHeadersMap(headers []kafka.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for _, h := range headers {
		out[h.Key] = string(h.Value)
	}
	return out
}

func brokerAuthzTraceResult(err error) string {
	switch {
	case err == nil:
		return "allow"
	case errors.Is(err, authz.ErrDenied):
		return "deny"
	case errors.Is(err, authz.ErrFailClosed), errors.Is(err, authz.ErrPolicyUnavailable):
		return "unavailable"
	default:
		return "error"
	}
}

func brokerAuthzTraceError(err error) error {
	if errors.Is(err, authz.ErrDenied) {
		return nil
	}
	return err
}
