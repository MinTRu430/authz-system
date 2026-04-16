package authz

import (
	"testing"
	"time"
)

func TestNewBrokerAuthzRequestPublish(t *testing.T) {
	req := NewBrokerAuthzRequest(BrokerInteraction{
		SourceService: "orders",
		TargetService: "payments",
		Broker:        "kafka",
		Resource:      "payments.charge.requested",
		MessageType:   "PaymentChargeRequested",
	}, BrokerOperationPublish)

	if req.Transport != TransportBroker {
		t.Fatalf("transport = %q, want broker", req.Transport)
	}
	if req.Operation != "publish" {
		t.Fatalf("operation = %q, want publish", req.Operation)
	}
	if req.Broker != "kafka" {
		t.Fatalf("broker = %q, want kafka", req.Broker)
	}
	if req.Resource != "payments.charge.requested" {
		t.Fatalf("resource = %q", req.Resource)
	}
	if req.MessageType != "PaymentChargeRequested" {
		t.Fatalf("message_type = %q", req.MessageType)
	}
}

func TestDecidePolicySupportsBrokerRules(t *testing.T) {
	rules := NormalizePolicyRules([]PolicyRule{
		{
			ID:          "B1",
			Source:      "orders",
			Target:      "payments",
			Transport:   TransportBroker,
			Broker:      "nats",
			Operation:   "publish",
			Resource:    "payments.charge.requested",
			MessageType: "PaymentChargeRequested",
			Effect:      "allow",
		},
		{
			ID:        "D1",
			Source:    "*",
			Target:    "*",
			Transport: "*",
			Operation: "*",
			Resource:  "*",
			Effect:    "deny",
		},
	})

	req := NewBrokerAuthzRequest(BrokerInteraction{
		SourceService: "orders",
		TargetService: "payments",
		Broker:        "nats",
		Resource:      "payments.charge.requested",
		MessageType:   "PaymentChargeRequested",
	}, BrokerOperationPublish)

	resp := DecidePolicy(rules, "v1", req)
	if !resp.Allow {
		t.Fatalf("allow = false, reason=%q", resp.Reason)
	}
	if resp.RuleID != "B1" {
		t.Fatalf("rule_id = %q, want B1", resp.RuleID)
	}
}

func TestBrokerRuleDoesNotMatchDifferentMessageType(t *testing.T) {
	rules := NormalizePolicyRules([]PolicyRule{
		{
			ID:          "B1",
			Source:      "orders",
			Target:      "payments",
			Transport:   TransportBroker,
			Broker:      "kafka",
			Operation:   "publish",
			Resource:    "payments.events",
			MessageType: "PaymentChargeRequested",
			Effect:      "allow",
		},
	})

	req := NewBrokerAuthzRequest(BrokerInteraction{
		SourceService: "orders",
		TargetService: "payments",
		Broker:        "kafka",
		Resource:      "payments.events",
		MessageType:   "PaymentRefundRequested",
	}, BrokerOperationPublish)

	resp := DecidePolicy(rules, "v1", req)
	if resp.Allow {
		t.Fatalf("allow = true, want default deny")
	}
}

func TestBrokerRuleDoesNotMatchDifferentBroker(t *testing.T) {
	rules := NormalizePolicyRules([]PolicyRule{
		{
			ID:          "B1",
			Source:      "orders",
			Target:      "payments",
			Transport:   TransportBroker,
			Broker:      "kafka",
			Operation:   "publish",
			Resource:    "payments.events",
			MessageType: "PaymentChargeRequested",
			Effect:      "allow",
		},
	})

	req := NewBrokerAuthzRequest(BrokerInteraction{
		SourceService: "orders",
		TargetService: "payments",
		Broker:        "nats",
		Resource:      "payments.events",
		MessageType:   "PaymentChargeRequested",
	}, BrokerOperationPublish)

	resp := DecidePolicy(rules, "v1", req)
	if resp.Allow {
		t.Fatalf("allow = true, want default deny")
	}
}

func TestDecisionCacheKeyIncludesBrokerAndMessageType(t *testing.T) {
	cache := NewDecisionCache(time.Second)
	charge := NewBrokerAuthzRequest(BrokerInteraction{
		SourceService: "orders",
		TargetService: "payments",
		Broker:        "kafka",
		Resource:      "payments.events",
		MessageType:   "PaymentChargeRequested",
	}, BrokerOperationPublish)
	refund := NewBrokerAuthzRequest(BrokerInteraction{
		SourceService: "orders",
		TargetService: "payments",
		Broker:        "kafka",
		Resource:      "payments.events",
		MessageType:   "PaymentRefundRequested",
	}, BrokerOperationPublish)
	natsCharge := NewBrokerAuthzRequest(BrokerInteraction{
		SourceService: "orders",
		TargetService: "payments",
		Broker:        "nats",
		Resource:      "payments.events",
		MessageType:   "PaymentChargeRequested",
	}, BrokerOperationPublish)

	cache.Put(charge, CheckResponse{Allow: true, RuleID: "B1"})

	if _, ok := cache.Get(refund); ok {
		t.Fatal("refund event unexpectedly hit charge event cache entry")
	}
	if _, ok := cache.Get(natsCharge); ok {
		t.Fatal("NATS event unexpectedly hit Kafka cache entry")
	}
	if resp, ok := cache.Get(charge); !ok || !resp.Allow {
		t.Fatalf("charge event cache entry missing: ok=%v resp=%+v", ok, resp)
	}
}
