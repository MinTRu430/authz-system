package kafkaadapter

import (
	"context"
	"testing"

	"authz-system/internal/authz"

	"github.com/segmentio/kafka-go"
)

type fakeBrokerAuthzAdapter struct {
	publish authz.BrokerInteraction
	consume authz.BrokerInteraction
}

func (f *fakeBrokerAuthzAdapter) NormalizePublish(interaction authz.BrokerInteraction) authz.AuthzRequest {
	return authz.NewBrokerAuthzRequest(interaction, authz.BrokerOperationPublish)
}

func (f *fakeBrokerAuthzAdapter) NormalizeConsume(interaction authz.BrokerInteraction) authz.AuthzRequest {
	return authz.NewBrokerAuthzRequest(interaction, authz.BrokerOperationConsume)
}

func (f *fakeBrokerAuthzAdapter) AuthorizePublish(_ context.Context, interaction authz.BrokerInteraction) (authz.CheckResponse, error) {
	f.publish = interaction
	return authz.CheckResponse{Allow: true}, nil
}

func (f *fakeBrokerAuthzAdapter) AuthorizeConsume(_ context.Context, interaction authz.BrokerInteraction) (authz.CheckResponse, error) {
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
