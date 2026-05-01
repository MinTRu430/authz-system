package kafkaadapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"authz-system/internal/authz"
	"authz-system/internal/authz/brokersign"

	"github.com/segmentio/kafka-go"
)

type fakeBrokerAuthzAdapter struct {
	publish      authz.BrokerInteraction
	consume      authz.BrokerInteraction
	publishCalls int
	consumeCalls int
}

func (f *fakeBrokerAuthzAdapter) NormalizePublish(interaction authz.BrokerInteraction) authz.AuthzRequest {
	return authz.NewBrokerAuthzRequest(interaction, authz.BrokerOperationPublish)
}

func (f *fakeBrokerAuthzAdapter) NormalizeConsume(interaction authz.BrokerInteraction) authz.AuthzRequest {
	return authz.NewBrokerAuthzRequest(interaction, authz.BrokerOperationConsume)
}

func (f *fakeBrokerAuthzAdapter) AuthorizePublish(_ context.Context, interaction authz.BrokerInteraction) (authz.CheckResponse, error) {
	f.publishCalls++
	f.publish = interaction
	return authz.CheckResponse{Allow: true}, nil
}

func (f *fakeBrokerAuthzAdapter) AuthorizeConsume(_ context.Context, interaction authz.BrokerInteraction) (authz.CheckResponse, error) {
	f.consumeCalls++
	f.consume = interaction
	return authz.CheckResponse{Allow: true}, nil
}

func TestAuthorizeConsumeBuildsBrokerInteractionFromHeaders(t *testing.T) {
	fake := &fakeBrokerAuthzAdapter{}
	adapter := NewWithBrokerAuthzAdapter("payments", fake)

	msg := kafka.Message{
		Topic: "payments.requested",
		Headers: []kafka.Header{
			{Key: HeaderServiceName, Value: []byte("orders")},
			{Key: HeaderMessageType, Value: []byte("payment.requested.v1")},
		},
	}

	if err := adapter.AuthorizeConsume(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if fake.consume.SourceService != "orders" {
		t.Fatalf("source = %q, want orders", fake.consume.SourceService)
	}
	if fake.consume.TargetService != "payments" {
		t.Fatalf("target = %q, want payments", fake.consume.TargetService)
	}
	if fake.consume.Broker != BrokerNameKafka {
		t.Fatalf("broker = %q, want kafka", fake.consume.Broker)
	}
	if fake.consume.Resource != "payments.requested" {
		t.Fatalf("resource = %q", fake.consume.Resource)
	}
	if fake.consume.MessageType != "payment.requested.v1" {
		t.Fatalf("message_type = %q", fake.consume.MessageType)
	}
}

func TestAuthorizeConsumeRequiresMessageTypeHeader(t *testing.T) {
	fake := &fakeBrokerAuthzAdapter{}
	adapter := NewWithBrokerAuthzAdapter("payments", fake)

	err := adapter.AuthorizeConsume(context.Background(), kafka.Message{
		Topic:   "payments.requested",
		Headers: []kafka.Header{{Key: HeaderServiceName, Value: []byte("orders")}},
	})
	if err != ErrMissingMessageType {
		t.Fatalf("err = %v, want ErrMissingMessageType", err)
	}
}

func TestSignHeadersAddsSignatureHeaders(t *testing.T) {
	adapter := newSignedTestAdapter(t, &fakeBrokerAuthzAdapter{})
	payload := []byte(`{"order_id":"o-1"}`)

	headers, err := adapter.SignHeaders(nil, "payments.requested", payload, "orders", "payment.requested.v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := headerValue(headers, HeaderServiceName); got != "orders" {
		t.Fatalf("service header = %q", got)
	}
	if got := headerValue(headers, HeaderMessageType); got != "payment.requested.v1" {
		t.Fatalf("message type header = %q", got)
	}
	for _, key := range []string{HeaderSignatureVersion, HeaderTimestamp, HeaderPayloadSHA256, HeaderSignature} {
		if got := headerValue(headers, key); got == "" {
			t.Fatalf("missing signed header %s", key)
		}
	}

	err = adapter.verifier.Verify(brokersign.VerifyInput{
		Broker:      BrokerNameKafka,
		Resource:    "payments.requested",
		Source:      "orders",
		MessageType: "payment.requested.v1",
		Payload:     payload,
		Headers:     kafkaHeadersMap(headers),
	})
	if err != nil {
		t.Fatalf("Verify error = %v, want nil", err)
	}
}

func TestAuthorizeConsumeValidSignedMessageProceedsToAuthz(t *testing.T) {
	fake := &fakeBrokerAuthzAdapter{}
	adapter := newSignedTestAdapter(t, fake)
	payload := []byte(`{"order_id":"o-1"}`)
	headers, err := adapter.SignHeaders(nil, "payments.requested", payload, "orders", "payment.requested.v1")
	if err != nil {
		t.Fatal(err)
	}

	err = adapter.AuthorizeConsume(context.Background(), kafka.Message{
		Topic:   "payments.requested",
		Value:   payload,
		Headers: headers,
	})
	if err != nil {
		t.Fatalf("AuthorizeConsume error = %v, want nil", err)
	}
	if fake.consumeCalls != 1 {
		t.Fatalf("consume calls = %d, want 1", fake.consumeCalls)
	}
}

func TestAuthorizeConsumeInvalidSignatureDoesNotCallAuthz(t *testing.T) {
	fake := &fakeBrokerAuthzAdapter{}
	adapter := newSignedTestAdapter(t, fake)
	payload := []byte(`{"order_id":"o-1"}`)
	headers, err := adapter.SignHeaders(nil, "payments.requested", payload, "orders", "payment.requested.v1")
	if err != nil {
		t.Fatal(err)
	}
	headers = upsertHeader(headers, HeaderSignature, "invalid")

	err = adapter.AuthorizeConsume(context.Background(), kafka.Message{
		Topic:   "payments.requested",
		Value:   payload,
		Headers: headers,
	})
	if !errors.Is(err, brokersign.ErrInvalidSignature) {
		t.Fatalf("AuthorizeConsume error = %v, want ErrInvalidSignature", err)
	}
	if fake.consumeCalls != 0 {
		t.Fatalf("consume calls = %d, want 0", fake.consumeCalls)
	}
}

func TestAuthorizeConsumeMissingSignatureDoesNotCallAuthz(t *testing.T) {
	fake := &fakeBrokerAuthzAdapter{}
	adapter := newSignedTestAdapter(t, fake)
	payload := []byte(`{"order_id":"o-1"}`)

	err := adapter.AuthorizeConsume(context.Background(), kafka.Message{
		Topic: "payments.requested",
		Value: payload,
		Headers: []kafka.Header{
			{Key: HeaderServiceName, Value: []byte("orders")},
			{Key: HeaderMessageType, Value: []byte("payment.requested.v1")},
		},
	})
	if !errors.Is(err, brokersign.ErrMissingSignature) {
		t.Fatalf("AuthorizeConsume error = %v, want ErrMissingSignature for unsigned message", err)
	}
	if fake.consumeCalls != 0 {
		t.Fatalf("consume calls = %d, want 0", fake.consumeCalls)
	}
}

func newSignedTestAdapter(t *testing.T, fake *fakeBrokerAuthzAdapter) *Adapter {
	t.Helper()
	now := time.Unix(1_700_000_000, 0)
	signer, err := brokersign.NewSigner(brokersign.SignerConfig{
		Secret: []byte("orders-secret"),
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := brokersign.NewVerifier(brokersign.VerifierConfig{
		Secrets: map[string][]byte{"orders": []byte("orders-secret")},
		Now:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Adapter{
		targetService: "payments",
		broker:        fake,
		signingMode:   brokersign.ModeRequired,
		signer:        signer,
		verifier:      verifier,
	}
}
