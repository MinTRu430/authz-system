package authz

import (
	"testing"
	"time"
)

func TestAuthzRequestNormalizeLegacyGRPC(t *testing.T) {
	req := AuthzRequest{
		SourceService: "orders",
		TargetService: "payments",
		RPCMethod:     "/payments.v1.Payments/Charge",
	}.Normalize()

	if req.Source != "orders" {
		t.Fatalf("source = %q, want orders", req.Source)
	}
	if req.Target != "payments" {
		t.Fatalf("target = %q, want payments", req.Target)
	}
	if req.Transport != TransportGRPC {
		t.Fatalf("transport = %q, want grpc", req.Transport)
	}
	if req.Operation != "/payments.v1.Payments/Charge" {
		t.Fatalf("operation = %q", req.Operation)
	}
	if req.Resource != "*" {
		t.Fatalf("resource = %q, want *", req.Resource)
	}
}

func TestDecidePolicySupportsNewRuleFormat(t *testing.T) {
	rules := NormalizePolicyRules([]PolicyRule{
		{
			ID:        "REST1",
			Source:    "orders",
			Target:    "payments",
			Transport: TransportREST,
			Operation: "POST",
			Resource:  "/payments/charge",
			Effect:    "allow",
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

	resp := DecidePolicy(rules, "v1", NewAuthzRequest("orders", "payments", TransportREST, "POST", "/payments/charge"))
	if !resp.Allow {
		t.Fatalf("allow = false, reason=%q", resp.Reason)
	}
	if resp.RuleID != "REST1" {
		t.Fatalf("rule_id = %q, want REST1", resp.RuleID)
	}
}

func TestDecidePolicySupportsLegacyRPCRules(t *testing.T) {
	rules := NormalizePolicyRules([]PolicyRule{
		{ID: "R1", Source: "orders", Target: "payments", RPC: "/payments.v1.Payments/Charge", Effect: "allow"},
		{ID: "R3", Source: "*", Target: "*", RPC: "*", Effect: "deny"},
	})

	req := NewGRPCAuthzRequest("orders", "payments", "/payments.v1.Payments/Charge")
	resp := DecidePolicy(rules, "v1", req)
	if !resp.Allow {
		t.Fatalf("allow = false, reason=%q", resp.Reason)
	}
	if resp.RuleID != "R1" {
		t.Fatalf("rule_id = %q, want R1", resp.RuleID)
	}
}

func TestDecisionCacheKeyIncludesTransportOperationResource(t *testing.T) {
	cache := NewDecisionCache(time.Second)
	grpcReq := NewGRPCAuthzRequest("orders", "payments", "/payments.v1.Payments/Charge")
	restReq := NewAuthzRequest("orders", "payments", TransportREST, "POST", "/payments/charge")

	cache.Put(grpcReq, CheckResponse{Allow: true, RuleID: "R1"})

	if _, ok := cache.Get(restReq); ok {
		t.Fatal("REST request unexpectedly hit gRPC cache entry")
	}

	if resp, ok := cache.Get(grpcReq); !ok || !resp.Allow {
		t.Fatalf("gRPC cache entry missing: ok=%v resp=%+v", ok, resp)
	}
}
