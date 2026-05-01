package authz

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestPolicyClientHealthOK(t *testing.T) {
	transport := newPolicyRoundTripper(CheckResponse{})
	client := newTestPolicyClient("http://policy.test", transport)

	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("Health error = %v, want nil", err)
	}
	if got := transport.healthCalls.Load(); got != 1 {
		t.Fatalf("health calls = %d, want 1", got)
	}
}

func TestPolicyClientHealthUnavailableStatus(t *testing.T) {
	transport := newPolicyRoundTripper(CheckResponse{})
	transport.healthStatus = http.StatusServiceUnavailable
	client := newTestPolicyClient("http://policy.test", transport)

	err := client.Health(context.Background())
	if !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("Health error = %v, want ErrPolicyUnavailable", err)
	}
	if got := transport.healthCalls.Load(); got != 1 {
		t.Fatalf("health calls = %d, want 1", got)
	}
}

func TestPolicyClientHealthTransportError(t *testing.T) {
	transport := newPolicyRoundTripper(CheckResponse{})
	transport.healthErr = errors.New("connection refused")
	client := newTestPolicyClient("http://policy.test", transport)

	err := client.Health(context.Background())
	if !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("Health error = %v, want ErrPolicyUnavailable", err)
	}
	if got := transport.healthCalls.Load(); got != 1 {
		t.Fatalf("health calls = %d, want 1", got)
	}
}

func TestPolicyClientEnsureAvailableCachesHealthyState(t *testing.T) {
	transport := newPolicyRoundTripper(CheckResponse{})
	client := newTestPolicyClient("http://policy.test", transport)
	client.healthPositiveTTL = time.Minute

	if err := client.EnsureAvailable(context.Background()); err != nil {
		t.Fatalf("EnsureAvailable error = %v, want nil", err)
	}
	if err := client.EnsureAvailable(context.Background()); err != nil {
		t.Fatalf("cached EnsureAvailable error = %v, want nil", err)
	}
	if got := transport.healthCalls.Load(); got != 1 {
		t.Fatalf("health calls = %d, want 1 because healthy state is cached", got)
	}
}

func TestPolicyClientEnsureAvailableBackoffAndRecovery(t *testing.T) {
	transport := newPolicyRoundTripper(CheckResponse{})
	transport.healthStatus = http.StatusServiceUnavailable
	client := newTestPolicyClient("http://policy.test", transport)
	client.healthPositiveTTL = time.Second
	client.downFor = time.Second

	base := time.Unix(200, 0)
	now := base
	client.now = func() time.Time { return now }

	if err := client.EnsureAvailable(context.Background()); !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("first EnsureAvailable error = %v, want ErrPolicyUnavailable", err)
	}
	if got := transport.healthCalls.Load(); got != 1 {
		t.Fatalf("health calls = %d, want first health call", got)
	}

	transport.healthStatus = http.StatusOK
	now = base.Add(500 * time.Millisecond)
	if err := client.EnsureAvailable(context.Background()); !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("backoff EnsureAvailable error = %v, want ErrPolicyUnavailable", err)
	}
	if got := transport.healthCalls.Load(); got != 1 {
		t.Fatalf("health calls = %d, want no retry before backoff expires", got)
	}

	now = base.Add(1100 * time.Millisecond)
	if err := client.EnsureAvailable(context.Background()); err != nil {
		t.Fatalf("recovery EnsureAvailable error = %v, want nil", err)
	}
	if got := transport.healthCalls.Load(); got != 2 {
		t.Fatalf("health calls = %d, want recovery health call after backoff", got)
	}

	now = base.Add(1500 * time.Millisecond)
	if err := client.EnsureAvailable(context.Background()); err != nil {
		t.Fatalf("cached recovery EnsureAvailable error = %v, want nil", err)
	}
	if got := transport.healthCalls.Load(); got != 2 {
		t.Fatalf("health calls = %d, want recovered healthy state cached", got)
	}
}

func TestPolicyClientCheckSuccessMarksHealthy(t *testing.T) {
	transport := newPolicyRoundTripper(CheckResponse{Allow: true, Reason: "matched allow rule", RuleID: "R1"})
	client := newTestPolicyClient("http://policy.test", transport)
	client.healthPositiveTTL = time.Minute

	if _, err := client.Check(context.Background(), NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge")); err != nil {
		t.Fatalf("Check error = %v, want nil", err)
	}
	if client.availabilityState.Load() != policyAvailabilityHealthy {
		t.Fatalf("availability state = %d, want healthy", client.availabilityState.Load())
	}
	if client.IsDown() {
		t.Fatal("client is down after successful check")
	}
}

func TestPolicyClientCheckTransportErrorMarksUnavailable(t *testing.T) {
	transport := newPolicyRoundTripper(CheckResponse{Allow: true})
	transport.err = errors.New("connection refused")
	client := newTestPolicyClient("http://policy.test", transport)
	client.downFor = time.Second

	base := time.Unix(300, 0)
	now := base
	client.now = func() time.Time { return now }

	_, err := client.Check(context.Background(), NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge"))
	if !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("Check error = %v, want ErrPolicyUnavailable", err)
	}

	transport.err = nil
	transport.healthStatus = http.StatusOK
	now = base.Add(500 * time.Millisecond)
	if err := client.EnsureAvailable(context.Background()); !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("EnsureAvailable error = %v, want ErrPolicyUnavailable before backoff expires", err)
	}
	if got := transport.healthCalls.Load(); got != 0 {
		t.Fatalf("health calls = %d, want no health call before backoff expires", got)
	}
}

func newTestPolicyClient(policyURL string, transport http.RoundTripper) *PolicyClient {
	return &PolicyClient{
		BaseURL: policyURL,
		HTTP: &http.Client{
			Timeout:   50 * time.Millisecond,
			Transport: transport,
		},
		downFor:           50 * time.Millisecond,
		healthPositiveTTL: 50 * time.Millisecond,
	}
}
