package authz

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestMultiPolicyClientFirstUnavailableSecondAllow(t *testing.T) {
	firstTransport := roundTripError(errors.New("connection refused"))
	secondTransport := newPolicyRoundTripper(CheckResponse{Allow: true, Reason: "matched allow rule", RuleID: "R_ALLOW"})
	client := newTestMultiPolicyClient(
		newTestPolicyClient("http://policy-1.test", firstTransport),
		newTestPolicyClient("http://policy-2.test", secondTransport),
	)

	resp, err := client.Check(context.Background(), NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge"))
	if err != nil {
		t.Fatalf("Check error = %v, want nil", err)
	}
	if !resp.Allow || resp.RuleID != "R_ALLOW" {
		t.Fatalf("response = %+v, want second endpoint allow", resp)
	}
	if got := firstTransport.calls.Load(); got != 1 {
		t.Fatalf("first endpoint calls = %d, want 1", got)
	}
	if got := secondTransport.calls.Load(); got != 1 {
		t.Fatalf("second endpoint calls = %d, want 1", got)
	}
}

func TestMultiPolicyClientFirstUnavailableSecondDeny(t *testing.T) {
	firstTransport := roundTripError(errors.New("connection refused"))
	secondTransport := newPolicyRoundTripper(CheckResponse{Allow: false, Reason: "matched deny rule", RuleID: "R_DENY"})
	client := newTestMultiPolicyClient(
		newTestPolicyClient("http://policy-1.test", firstTransport),
		newTestPolicyClient("http://policy-2.test", secondTransport),
	)

	resp, err := client.Check(context.Background(), NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/refund"))
	if err != nil {
		t.Fatalf("Check error = %v, want nil deny decision", err)
	}
	if resp.Allow || resp.RuleID != "R_DENY" {
		t.Fatalf("response = %+v, want second endpoint deny", resp)
	}
}

func TestMultiPolicyClientAllUnavailable(t *testing.T) {
	client := newTestMultiPolicyClient(
		newTestPolicyClient("http://policy-1.test", roundTripError(errors.New("connection refused"))),
		newTestPolicyClient("http://policy-2.test", roundTripError(errors.New("connection refused"))),
	)

	_, err := client.Check(context.Background(), NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge"))
	if !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("Check error = %v, want ErrPolicyUnavailable", err)
	}
}

func TestMultiPolicyClientEnsureAvailableSucceedsIfOneHealthy(t *testing.T) {
	firstTransport := newPolicyRoundTripper(CheckResponse{})
	firstTransport.healthStatus = http.StatusServiceUnavailable
	secondTransport := newPolicyRoundTripper(CheckResponse{})
	client := newTestMultiPolicyClient(
		newTestPolicyClient("http://policy-1.test", firstTransport),
		newTestPolicyClient("http://policy-2.test", secondTransport),
	)

	if err := client.EnsureAvailable(context.Background()); err != nil {
		t.Fatalf("EnsureAvailable error = %v, want nil", err)
	}
	if got := firstTransport.healthCalls.Load(); got != 1 {
		t.Fatalf("first health calls = %d, want 1", got)
	}
	if got := secondTransport.healthCalls.Load(); got != 1 {
		t.Fatalf("second health calls = %d, want 1", got)
	}
}

func TestMultiPolicyClientEnsureAvailableFailsIfAllUnhealthy(t *testing.T) {
	firstTransport := newPolicyRoundTripper(CheckResponse{})
	firstTransport.healthStatus = http.StatusServiceUnavailable
	secondTransport := newPolicyRoundTripper(CheckResponse{})
	secondTransport.healthStatus = http.StatusServiceUnavailable
	client := newTestMultiPolicyClient(
		newTestPolicyClient("http://policy-1.test", firstTransport),
		newTestPolicyClient("http://policy-2.test", secondTransport),
	)

	err := client.EnsureAvailable(context.Background())
	if !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("EnsureAvailable error = %v, want ErrPolicyUnavailable", err)
	}
}

func TestMultiPolicyClientPerEndpointBreakerIsIsolated(t *testing.T) {
	firstTransport := roundTripError(errors.New("connection refused"))
	secondTransport := newPolicyRoundTripper(CheckResponse{Allow: true, Reason: "matched allow rule", RuleID: "R_ALLOW"})
	first := newTestPolicyClient("http://policy-1.test", firstTransport)
	second := newTestPolicyClient("http://policy-2.test", secondTransport)
	first.downFor = time.Second
	second.downFor = time.Second

	base := time.Unix(500, 0)
	first.now = func() time.Time { return base }
	second.now = func() time.Time { return base }

	client := newTestMultiPolicyClient(first, second)
	resp, err := client.Check(context.Background(), NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge"))
	if err != nil {
		t.Fatalf("Check error = %v, want nil", err)
	}
	if !resp.Allow || resp.RuleID != "R_ALLOW" {
		t.Fatalf("response = %+v, want second endpoint allow", resp)
	}
	if !first.IsDown() {
		t.Fatal("first endpoint is not in unavailable backoff")
	}
	if second.IsDown() {
		t.Fatal("second endpoint unexpectedly entered unavailable backoff")
	}

	_, err = client.Check(context.Background(), NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge"))
	if err != nil {
		t.Fatalf("second Check error = %v, want nil", err)
	}
	if !first.IsDown() {
		t.Fatal("successful second endpoint reset first endpoint breaker")
	}
}

func TestMultiPolicyClientDenyFromHealthyEndpointIsFinal(t *testing.T) {
	firstTransport := newPolicyRoundTripper(CheckResponse{Allow: false, Reason: "matched deny rule", RuleID: "R_DENY"})
	secondTransport := newPolicyRoundTripper(CheckResponse{Allow: true, Reason: "matched allow rule", RuleID: "R_ALLOW"})
	client := newTestMultiPolicyClient(
		newTestPolicyClient("http://policy-1.test", firstTransport),
		newTestPolicyClient("http://policy-2.test", secondTransport),
	)

	resp, err := client.Check(context.Background(), NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/refund"))
	if err != nil {
		t.Fatalf("Check error = %v, want nil deny decision", err)
	}
	if resp.Allow || resp.RuleID != "R_DENY" {
		t.Fatalf("response = %+v, want first endpoint deny", resp)
	}
	if got := secondTransport.calls.Load(); got != 0 {
		t.Fatalf("second endpoint calls = %d, want 0 because deny is final", got)
	}
}

func TestPolicyURLBackwardCompatibility(t *testing.T) {
	urls := normalizePolicyURLs(nil, "http://policy.test/")
	if len(urls) != 1 || urls[0] != "http://policy.test" {
		t.Fatalf("urls = %+v, want single trimmed PolicyURL", urls)
	}

	urls = normalizePolicyURLs([]string{"http://policy-1.test, http://policy-2.test/"}, "http://policy.test")
	if len(urls) != 2 || urls[0] != "http://policy-1.test" || urls[1] != "http://policy-2.test" {
		t.Fatalf("urls = %+v, want PolicyURLs to take precedence", urls)
	}
}

func newTestMultiPolicyClient(endpoints ...*PolicyClient) *MultiPolicyClient {
	return &MultiPolicyClient{endpoints: endpoints}
}
