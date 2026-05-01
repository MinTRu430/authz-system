package natsadapter

import (
	"context"
	"errors"

	"authz-system/internal/authz"
	"authz-system/internal/authz/brokersign"

	"github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel/attribute"
)

const (
	BrokerNameNATS         = "nats"
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
	ErrMissingServiceName = errors.New("nats message missing X-Service-Name header")
	ErrMissingMessageType = errors.New("nats message missing X-Message-Type header")
	ErrMissingSubject     = errors.New("nats message subject is empty")
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

func (a *Adapter) Publish(ctx context.Context, conn *nats.Conn, subject string, data []byte, sourceService, messageType string) error {
	if subject == "" {
		return ErrMissingSubject
	}

	ctx, span := authz.StartSpan(ctx, "broker.publish.authorize", authz.BrokerTraceAttrs(BrokerNameNATS, "publish")...)
	interaction := authz.BrokerInteraction{
		SourceService: sourceService,
		TargetService: a.targetService,
		Broker:        BrokerNameNATS,
		Resource:      subject,
		MessageType:   messageType,
	}
	if _, err := a.broker.AuthorizePublish(ctx, interaction); err != nil {
		authz.EndSpanWithResult(span, brokerAuthzTraceResult(err), brokerAuthzTraceError(err))
		span.End()
		return err
	}
	authz.EndSpanWithResult(span, "allow", nil)
	span.End()

	headers, err := a.SignHeaders(nil, subject, data, sourceService, messageType)
	if err != nil {
		return err
	}
	msg := &nats.Msg{Subject: subject, Header: headers, Data: data}
	return conn.PublishMsg(msg)
}

func (a *Adapter) AuthorizeConsume(ctx context.Context, msg *nats.Msg) error {
	if msg == nil || msg.Subject == "" {
		return ErrMissingSubject
	}
	sourceService, err := ServiceNameFromHeaders(msg.Header)
	if err != nil {
		return err
	}
	messageType, err := MessageTypeFromHeaders(msg.Header)
	if err != nil {
		return err
	}
	ctx, verifySpan := authz.StartSpan(ctx, "broker.consume.verify_signature", authz.BrokerTraceAttrs(BrokerNameNATS, "consume")...)
	if err := a.verifySignature(msg.Subject, msg.Data, sourceService, messageType, msg.Header); err != nil {
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
		Broker:        BrokerNameNATS,
		Resource:      msg.Subject,
		MessageType:   messageType,
	}
	ctx, authSpan := authz.StartSpan(ctx, "broker.consume.authorize", authz.BrokerTraceAttrs(BrokerNameNATS, "consume")...)
	_, err = a.broker.AuthorizeConsume(ctx, interaction)
	authz.EndSpanWithResult(authSpan, brokerAuthzTraceResult(err), brokerAuthzTraceError(err))
	authSpan.End()
	return err
}

func (a *Adapter) SignHeaders(headers nats.Header, resource string, payload []byte, sourceService, messageType string) (nats.Header, error) {
	if headers == nil {
		headers = nats.Header{}
	}
	headers.Set(HeaderServiceName, sourceService)
	headers.Set(HeaderMessageType, messageType)
	if !a.signingRequired() {
		return headers, nil
	}
	if a.signer == nil {
		return nil, brokersign.ErrMissingSigningSecret
	}
	signed, err := a.signer.Sign(brokersign.SignInput{
		Broker:      BrokerNameNATS,
		Resource:    resource,
		Source:      sourceService,
		MessageType: messageType,
		Payload:     payload,
	})
	if err != nil {
		return nil, err
	}
	for key, value := range signed {
		headers.Set(key, value)
	}
	authz.RecordMessageSigned(BrokerNameNATS)
	return headers, nil
}

func ServiceNameFromHeaders(headers nats.Header) (string, error) {
	v := headers.Get(HeaderServiceName)
	if v == "" {
		return "", ErrMissingServiceName
	}
	return v, nil
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

func (a *Adapter) verifySignature(resource string, payload []byte, sourceService, messageType string, headers nats.Header) error {
	if !a.signingRequired() {
		return nil
	}
	if a.verifier == nil {
		err := brokersign.ErrMissingVerificationKeys
		authz.RecordMessageSignatureCheck(BrokerNameNATS, "fail")
		authz.RecordMessageSignatureFailure(BrokerNameNATS, brokersign.FailureReason(err))
		return err
	}
	err := a.verifier.Verify(brokersign.VerifyInput{
		Broker:      BrokerNameNATS,
		Resource:    resource,
		Source:      sourceService,
		MessageType: messageType,
		Payload:     payload,
		Headers:     natsHeadersMap(headers),
	})
	if err != nil {
		authz.RecordMessageSignatureCheck(BrokerNameNATS, "fail")
		authz.RecordMessageSignatureFailure(BrokerNameNATS, brokersign.FailureReason(err))
		return err
	}
	authz.RecordMessageSignatureCheck(BrokerNameNATS, "ok")
	return nil
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

func MessageTypeFromHeaders(headers nats.Header) (string, error) {
	v := headers.Get(HeaderMessageType)
	if v == "" {
		return "", ErrMissingMessageType
	}
	return v, nil
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
