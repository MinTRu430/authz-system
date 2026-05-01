package authz

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
)

func TestCompiledPolicyMatchesLinearTable(t *testing.T) {
	cases := []struct {
		name       string
		rules      []PolicyRule
		req        AuthzRequest
		wantAllow  bool
		wantRuleID string
		wantReason string
	}{
		{
			name: "exact allow",
			rules: []PolicyRule{
				{ID: "R1", Source: "orders", Target: "payments", Transport: TransportHTTP, Operation: "POST", Resource: "/payments/charge", Effect: "allow"},
			},
			req:        NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge"),
			wantAllow:  true,
			wantRuleID: "R1",
			wantReason: "matched allow rule",
		},
		{
			name: "exact deny",
			rules: []PolicyRule{
				{ID: "R1", Source: "orders", Target: "payments", Transport: TransportHTTP, Operation: "POST", Resource: "/payments/refund", Effect: "deny"},
			},
			req:        NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/refund"),
			wantAllow:  false,
			wantRuleID: "R1",
			wantReason: "matched deny rule",
		},
		{
			name: "wildcard source",
			rules: []PolicyRule{
				{ID: "R1", Source: "*", Target: "payments", Transport: TransportHTTP, Operation: "POST", Resource: "/payments/charge", Effect: "allow"},
			},
			req:        NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge"),
			wantAllow:  true,
			wantRuleID: "R1",
			wantReason: "matched allow rule",
		},
		{
			name: "wildcard target",
			rules: []PolicyRule{
				{ID: "R1", Source: "orders", Target: "*", Transport: TransportHTTP, Operation: "POST", Resource: "/payments/charge", Effect: "allow"},
			},
			req:        NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge"),
			wantAllow:  true,
			wantRuleID: "R1",
			wantReason: "matched allow rule",
		},
		{
			name: "wildcard transport",
			rules: []PolicyRule{
				{ID: "R1", Source: "orders", Target: "payments", Transport: "*", Operation: "POST", Resource: "/payments/charge", Effect: "allow"},
			},
			req:        NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge"),
			wantAllow:  true,
			wantRuleID: "R1",
			wantReason: "matched allow rule",
		},
		{
			name: "wildcard broker",
			rules: []PolicyRule{
				{ID: "R1", Source: "orders", Target: "payments", Transport: TransportBroker, Broker: "*", Operation: "publish", Resource: "payments.requested", MessageType: "payment.requested.v1", Effect: "allow"},
			},
			req:        NewBrokerAuthzRequest(BrokerInteraction{SourceService: "orders", TargetService: "payments", Broker: "kafka", Resource: "payments.requested", MessageType: "payment.requested.v1"}, BrokerOperationPublish),
			wantAllow:  true,
			wantRuleID: "R1",
			wantReason: "matched allow rule",
		},
		{
			name: "wildcard operation",
			rules: []PolicyRule{
				{ID: "R1", Source: "orders", Target: "payments", Transport: TransportHTTP, Operation: "*", Resource: "/payments/charge", Effect: "allow"},
			},
			req:        NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge"),
			wantAllow:  true,
			wantRuleID: "R1",
			wantReason: "matched allow rule",
		},
		{
			name: "wildcard resource",
			rules: []PolicyRule{
				{ID: "R1", Source: "orders", Target: "payments", Transport: TransportHTTP, Operation: "POST", Resource: "*", Effect: "allow"},
			},
			req:        NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge"),
			wantAllow:  true,
			wantRuleID: "R1",
			wantReason: "matched allow rule",
		},
		{
			name: "wildcard message type",
			rules: []PolicyRule{
				{ID: "R1", Source: "orders", Target: "payments", Transport: TransportBroker, Broker: "nats", Operation: "publish", Resource: "payments.requested", MessageType: "*", Effect: "allow"},
			},
			req:        NewBrokerAuthzRequest(BrokerInteraction{SourceService: "orders", TargetService: "payments", Broker: "nats", Resource: "payments.requested", MessageType: "payment.requested.v1"}, BrokerOperationPublish),
			wantAllow:  true,
			wantRuleID: "R1",
			wantReason: "matched allow rule",
		},
		{
			name: "explicit deny by default",
			rules: []PolicyRule{
				{ID: "DEFAULT", Source: "*", Target: "*", Transport: "*", Operation: "*", Resource: "*", Broker: "*", MessageType: "*", Effect: "deny"},
			},
			req:        NewAuthzRequest("orders", "payments", TransportHTTP, "GET", "/unknown"),
			wantAllow:  false,
			wantRuleID: "DEFAULT",
			wantReason: "matched deny rule",
		},
		{
			name: "synthetic default deny",
			rules: []PolicyRule{
				{ID: "R1", Source: "orders", Target: "payments", Transport: TransportHTTP, Operation: "POST", Resource: "/payments/charge", Effect: "allow"},
			},
			req:        NewAuthzRequest("orders", "payments", TransportHTTP, "GET", "/unknown"),
			wantAllow:  false,
			wantRuleID: "",
			wantReason: "default deny",
		},
		{
			name: "early wildcard deny before later specific allow",
			rules: []PolicyRule{
				{ID: "D1", Source: "*", Target: "payments", Transport: TransportHTTP, Operation: "POST", Resource: "/payments/charge", Effect: "deny"},
				{ID: "A1", Source: "orders", Target: "payments", Transport: TransportHTTP, Operation: "POST", Resource: "/payments/charge", Effect: "allow"},
			},
			req:        NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge"),
			wantAllow:  false,
			wantRuleID: "D1",
			wantReason: "matched deny rule",
		},
		{
			name: "early allow before later deny",
			rules: []PolicyRule{
				{ID: "A1", Source: "orders", Target: "payments", Transport: TransportHTTP, Operation: "POST", Resource: "/payments/charge", Effect: "allow"},
				{ID: "D1", Source: "*", Target: "payments", Transport: TransportHTTP, Operation: "POST", Resource: "/payments/charge", Effect: "deny"},
			},
			req:        NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge"),
			wantAllow:  true,
			wantRuleID: "A1",
			wantReason: "matched allow rule",
		},
		{
			name: "legacy rpc rule",
			rules: []PolicyRule{
				{ID: "R1", Source: "orders", Target: "payments", RPC: "/payments.v1.Payments/Charge", Effect: "allow"},
			},
			req:        NewGRPCAuthzRequest("orders", "payments", "/payments.v1.Payments/Charge"),
			wantAllow:  true,
			wantRuleID: "R1",
			wantReason: "matched allow rule",
		},
		{
			name: "mixed grpc http kafka nats rules",
			rules: []PolicyRule{
				{ID: "G1", Source: "orders", Target: "payments", RPC: "/payments.v1.Payments/Charge", Effect: "allow"},
				{ID: "H1", Source: "orders", Target: "payments", Transport: TransportHTTP, Operation: "POST", Resource: "/payments/charge", Effect: "allow"},
				{ID: "K1", Source: "orders", Target: "payments", Transport: TransportBroker, Broker: "kafka", Operation: "publish", Resource: "payments.requested", MessageType: "payment.requested.v1", Effect: "allow"},
				{ID: "N1", Source: "orders", Target: "payments", Transport: TransportBroker, Broker: "nats", Operation: "publish", Resource: "payments.requested", MessageType: "payment.requested.v1", Effect: "allow"},
			},
			req:        NewBrokerAuthzRequest(BrokerInteraction{SourceService: "orders", TargetService: "payments", Broker: "nats", Resource: "payments.requested", MessageType: "payment.requested.v1"}, BrokerOperationPublish),
			wantAllow:  true,
			wantRuleID: "N1",
			wantReason: "matched allow rule",
		},
		{
			name: "broker mismatch kafka vs nats",
			rules: []PolicyRule{
				{ID: "K1", Source: "orders", Target: "payments", Transport: TransportBroker, Broker: "kafka", Operation: "publish", Resource: "payments.requested", MessageType: "payment.requested.v1", Effect: "allow"},
			},
			req:        NewBrokerAuthzRequest(BrokerInteraction{SourceService: "orders", TargetService: "payments", Broker: "nats", Resource: "payments.requested", MessageType: "payment.requested.v1"}, BrokerOperationPublish),
			wantAllow:  false,
			wantRuleID: "",
			wantReason: "default deny",
		},
		{
			name: "rest normalizes to http",
			rules: []PolicyRule{
				{ID: "H1", Source: "orders", Target: "payments", Transport: TransportHTTP, Operation: "POST", Resource: "/payments/charge", Effect: "allow"},
			},
			req:        NewAuthzRequest("orders", "payments", TransportREST, "POST", "/payments/charge"),
			wantAllow:  true,
			wantRuleID: "H1",
			wantReason: "matched allow rule",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := assertCompiledMatchesLinear(t, tc.rules, tc.req)
			if got.Allow != tc.wantAllow || got.RuleID != tc.wantRuleID || got.Reason != tc.wantReason {
				t.Fatalf("indexed decision = %+v, want allow=%v rule_id=%q reason=%q", got, tc.wantAllow, tc.wantRuleID, tc.wantReason)
			}
		})
	}
}

func TestCompiledPolicyStats(t *testing.T) {
	compiled := CompilePolicyRules([]PolicyRule{
		{ID: "R1", Source: "orders", Target: "payments", Transport: TransportHTTP, Operation: "POST", Resource: "/payments/charge", Effect: "allow"},
		{ID: "R2", Source: "orders", Target: "payments", Transport: TransportHTTP, Operation: "POST", Resource: "/payments/charge", Effect: "deny"},
		{ID: "R3", Source: "*", Target: "*", Transport: "*", Operation: "*", Resource: "*", Broker: "*", MessageType: "*", Effect: "deny"},
	})

	stats := compiled.Stats()
	if stats.Rules != 3 {
		t.Fatalf("rules = %d, want 3", stats.Rules)
	}
	if stats.Buckets != 2 {
		t.Fatalf("buckets = %d, want 2", stats.Buckets)
	}
}

func TestCompiledPolicyMatchesLinearRandomized(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	for iter := 0; iter < 200; iter++ {
		rules := randomPolicyRules(rng, 1+rng.Intn(40))
		compiled := CompilePolicyRules(rules)
		normalized := NormalizePolicyRules(rules)

		for i := 0; i < 40; i++ {
			req := randomAuthzRequest(rng)
			indexed := compiled.Decide("v-random", req)
			linear := DecidePolicy(normalized, "v-random", req)
			if !reflect.DeepEqual(indexed, linear) {
				t.Fatalf("iter=%d req=%+v\nindexed=%+v\nlinear=%+v\nrules=%+v", iter, req, indexed, linear, normalized)
			}
		}
	}
}

func assertCompiledMatchesLinear(t *testing.T, rules []PolicyRule, req AuthzRequest) CheckResponse {
	t.Helper()

	compiled := CompilePolicyRules(rules)
	normalized := NormalizePolicyRules(rules)
	indexed := compiled.Decide("v1", req)
	linear := DecidePolicy(normalized, "v1", req)
	if !reflect.DeepEqual(indexed, linear) {
		t.Fatalf("indexed decision = %+v, linear decision = %+v", indexed, linear)
	}
	return indexed
}

func randomPolicyRules(rng *rand.Rand, n int) []PolicyRule {
	rules := make([]PolicyRule, 0, n)
	for i := 0; i < n; i++ {
		rule := PolicyRule{
			ID:          fmt.Sprintf("R%d", i),
			Source:      pick(rng, []string{"orders", "payments", "inventory", "*", ""}),
			Target:      pick(rng, []string{"payments", "orders", "ledger", "*", ""}),
			Transport:   Transport(pick(rng, []string{"grpc", "http", "rest", "broker", "*", ""})),
			Operation:   pick(rng, []string{"/payments.v1.Payments/Charge", "/payments.v1.Payments/Refund", "POST", "GET", "publish", "consume", "*", ""}),
			Resource:    pick(rng, []string{"*", "", "/payments/charge", "/payments/refund", "payments.requested", "payments.refund.forced"}),
			Broker:      pick(rng, []string{"*", "", "kafka", "nats"}),
			MessageType: pick(rng, []string{"*", "", "payment.requested.v1", "payment.refund.forced.v1"}),
			Effect:      pick(rng, []string{"allow", "deny", "ALLOW", "DENY", ""}),
		}
		if rng.Intn(10) == 0 {
			rule.Transport = ""
			rule.Operation = ""
			rule.Resource = ""
			rule.RPC = pick(rng, []string{"/payments.v1.Payments/Charge", "/payments.v1.Payments/Refund", "*"})
		}
		rules = append(rules, rule)
	}
	return rules
}

func randomAuthzRequest(rng *rand.Rand) AuthzRequest {
	if rng.Intn(10) == 0 {
		return AuthzRequest{
			SourceService: pick(rng, []string{"orders", "payments", "inventory", ""}),
			TargetService: pick(rng, []string{"payments", "orders", "ledger", ""}),
			RPCMethod:     pick(rng, []string{"/payments.v1.Payments/Charge", "/payments.v1.Payments/Refund", ""}),
		}
	}

	return AuthzRequest{
		Source:      pick(rng, []string{"orders", "payments", "inventory", ""}),
		Target:      pick(rng, []string{"payments", "orders", "ledger", ""}),
		Transport:   Transport(pick(rng, []string{"grpc", "http", "rest", "broker", ""})),
		Operation:   pick(rng, []string{"/payments.v1.Payments/Charge", "/payments.v1.Payments/Refund", "POST", "GET", "publish", "consume", ""}),
		Resource:    pick(rng, []string{"", "/payments/charge", "/payments/refund", "payments.requested", "payments.refund.forced"}),
		Broker:      pick(rng, []string{"", "kafka", "nats"}),
		MessageType: pick(rng, []string{"", "payment.requested.v1", "payment.refund.forced.v1"}),
	}
}

func pick(rng *rand.Rand, values []string) string {
	return values[rng.Intn(len(values))]
}
