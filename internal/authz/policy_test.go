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

func TestDecidePolicyMatchesExplicitDenyRule(t *testing.T) {
	rules := NormalizePolicyRules([]PolicyRule{
		{
			ID:        "REST_DENY",
			Source:    "orders",
			Target:    "payments",
			Transport: TransportHTTP,
			Operation: "POST",
			Resource:  "/payments/refund",
			Effect:    "deny",
		},
		{
			ID:        "DEFAULT",
			Source:    "*",
			Target:    "*",
			Transport: "*",
			Operation: "*",
			Resource:  "*",
			Effect:    "deny",
		},
	})

	resp := DecidePolicy(rules, "v1", NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/refund"))
	if resp.Allow {
		t.Fatalf("allow = true, want deny")
	}
	if resp.RuleID != "REST_DENY" {
		t.Fatalf("rule_id = %q, want REST_DENY", resp.RuleID)
	}
	if resp.Reason != "matched deny rule" {
		t.Fatalf("reason = %q, want matched deny rule", resp.Reason)
	}
}

func TestDecidePolicyDefaultDenyWhenNoRuleMatches(t *testing.T) {
	rules := NormalizePolicyRules([]PolicyRule{
		{
			ID:        "REST1",
			Source:    "orders",
			Target:    "payments",
			Transport: TransportHTTP,
			Operation: "POST",
			Resource:  "/payments/charge",
			Effect:    "allow",
		},
	})

	resp := DecidePolicy(rules, "v1", NewAuthzRequest("orders", "payments", TransportHTTP, "GET", "/payments/charge"))
	if resp.Allow {
		t.Fatalf("allow = true, want default deny")
	}
	if resp.RuleID != "" {
		t.Fatalf("rule_id = %q, want empty default deny rule", resp.RuleID)
	}
	if resp.Reason != "default deny" {
		t.Fatalf("reason = %q, want default deny", resp.Reason)
	}
}

func TestDecidePolicyRequiresTransportOperationAndResourceMatch(t *testing.T) {
	rules := NormalizePolicyRules([]PolicyRule{
		{
			ID:        "REST1",
			Source:    "orders",
			Target:    "payments",
			Transport: TransportHTTP,
			Operation: "POST",
			Resource:  "/payments/charge",
			Effect:    "allow",
		},
	})

	cases := []struct {
		name string
		req  AuthzRequest
	}{
		{
			name: "different transport",
			req:  NewGRPCAuthzRequest("orders", "payments", "/payments.v1.Payments/Charge"),
		},
		{
			name: "different operation",
			req:  NewAuthzRequest("orders", "payments", TransportHTTP, "GET", "/payments/charge"),
		},
		{
			name: "different resource",
			req:  NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/refund"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := DecidePolicy(rules, "v1", tc.req)
			if resp.Allow {
				t.Fatalf("allow = true, want default deny")
			}
			if resp.RuleID != "" {
				t.Fatalf("rule_id = %q, want empty default deny rule", resp.RuleID)
			}
		})
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

func TestDecisionCacheHitMissAndExpiration(t *testing.T) {
	cache := NewDecisionCache(10 * time.Millisecond)
	req := NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge")

	if _, ok := cache.Get(req); ok {
		t.Fatal("empty cache unexpectedly returned a hit")
	}

	cache.Put(req, CheckResponse{Allow: true, RuleID: "R_HTTP_1"})
	if resp, ok := cache.Get(req); !ok || !resp.Allow || resp.RuleID != "R_HTTP_1" {
		t.Fatalf("cache hit mismatch: ok=%v resp=%+v", ok, resp)
	}

	time.Sleep(25 * time.Millisecond)
	if _, ok := cache.Get(req); ok {
		t.Fatal("expired cache entry unexpectedly returned a hit")
	}
}

func TestDecisionCacheKeyIncludesOperationAndResource(t *testing.T) {
	cache := NewDecisionCache(time.Second)
	charge := NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge")
	refund := NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/refund")
	getCharge := NewAuthzRequest("orders", "payments", TransportHTTP, "GET", "/payments/charge")

	cache.Put(charge, CheckResponse{Allow: true, RuleID: "R_HTTP_1"})

	if _, ok := cache.Get(refund); ok {
		t.Fatal("refund request unexpectedly hit charge cache entry")
	}
	if _, ok := cache.Get(getCharge); ok {
		t.Fatal("GET request unexpectedly hit POST cache entry")
	}
	if resp, ok := cache.Get(charge); !ok || resp.RuleID != "R_HTTP_1" {
		t.Fatalf("charge cache entry missing: ok=%v resp=%+v", ok, resp)
	}
}
