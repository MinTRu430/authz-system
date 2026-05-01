package authz

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthorizerFailClosedWhenPolicyServerUnavailable(t *testing.T) {
	a := newTestAuthorizer("http://policy.test", false, 0, roundTripError(errors.New("connection refused")))
	req := NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge")

	resp, err := a.Authorize(context.Background(), req)
	if !errors.Is(err, ErrFailClosed) {
		t.Fatalf("err = %v, want ErrFailClosed", err)
	}
	if resp.Allow {
		t.Fatalf("allow = true, want fail-closed deny")
	}
}

func TestAuthorizerFailOpenAllowsUnavailablePolicyServerOnlyWhenConfigured(t *testing.T) {
	a := newTestAuthorizer("http://policy.test", true, 0, roundTripError(errors.New("connection refused")))
	req := NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge")

	resp, err := a.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize error = %v, want nil in fail-open mode", err)
	}
	if !resp.Allow {
		t.Fatalf("allow = false, want fail-open allow")
	}
	if resp.Reason != "fail-open: policy-server unavailable" {
		t.Fatalf("reason = %q, want fail-open unavailable reason", resp.Reason)
	}
}

func TestAuthorizerDeniesPolicyDenyDecision(t *testing.T) {
	transport := newPolicyRoundTripper(CheckResponse{
		Allow:  false,
		Reason: "matched deny rule",
		RuleID: "R_DENY",
	})

	a := newTestAuthorizer("http://policy.test", false, time.Minute, transport)
	req := NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/refund")

	resp, err := a.Authorize(context.Background(), req)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
	if resp.Allow {
		t.Fatalf("allow = true, want deny")
	}
	if resp.RuleID != "R_DENY" {
		t.Fatalf("rule_id = %q, want R_DENY", resp.RuleID)
	}
}

func TestAuthorizerFailClosedOnAllowCacheHitWhenPolicyServerUnavailable(t *testing.T) {
	transport := newPolicyRoundTripper(CheckResponse{
		Allow:  true,
		Reason: "matched allow rule",
		RuleID: "R_ALLOW",
	})

	a := newTestAuthorizer("http://policy.test", false, time.Minute, transport)
	a.healthTimeout = 25 * time.Millisecond
	client := testPolicyClient(t, a)
	client.healthPositiveTTL = 50 * time.Millisecond
	base := time.Unix(100, 0)
	now := base
	client.now = func() time.Time { return now }
	req := NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge")

	resp, err := a.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("first Authorize error = %v, want nil", err)
	}
	if !resp.Allow || resp.RuleID != "R_ALLOW" {
		t.Fatalf("first response = %+v, want cached allow", resp)
	}
	if got := transport.calls.Load(); got != 1 {
		t.Fatalf("policy checks = %d, want 1 before cache hit", got)
	}

	transport.healthStatus = http.StatusServiceUnavailable
	now = base.Add(100 * time.Millisecond)
	resp, err = a.Authorize(context.Background(), req)
	if !errors.Is(err, ErrFailClosed) {
		t.Fatalf("cache-hit err = %v, want ErrFailClosed", err)
	}
	if !resp.Allow || resp.RuleID != "R_ALLOW" {
		t.Fatalf("cache-hit response = %+v, want cached allow response returned with fail-closed error", resp)
	}
	if got := transport.calls.Load(); got != 1 {
		t.Fatalf("policy checks = %d, want no second /v1/check call on cache hit", got)
	}
	if got := transport.healthCalls.Load(); got != 1 {
		t.Fatalf("health checks = %d, want 1 on allow cache hit", got)
	}
}

func TestAuthorizerAllowCacheHitUsesCachedHealthState(t *testing.T) {
	transport := newPolicyRoundTripper(CheckResponse{
		Allow:  true,
		Reason: "matched allow rule",
		RuleID: "R_ALLOW",
	})

	a := newTestAuthorizer("http://policy.test", false, time.Minute, transport)
	testPolicyClient(t, a).healthPositiveTTL = time.Minute
	req := NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/charge")

	if _, err := a.Authorize(context.Background(), req); err != nil {
		t.Fatalf("first Authorize error = %v, want nil", err)
	}

	for i := 0; i < 3; i++ {
		resp, err := a.Authorize(context.Background(), req)
		if err != nil {
			t.Fatalf("cache-hit Authorize[%d] error = %v, want nil", i, err)
		}
		if !resp.Allow || resp.RuleID != "R_ALLOW" {
			t.Fatalf("cache-hit response[%d] = %+v, want cached allow", i, resp)
		}
	}
	if got := transport.calls.Load(); got != 1 {
		t.Fatalf("policy checks = %d, want one /v1/check", got)
	}
	if got := transport.healthCalls.Load(); got != 1 {
		t.Fatalf("health checks = %d, want one health call to seed cached healthy state", got)
	}
}

func TestAuthorizerDenyCacheHitDoesNotRequirePolicyHealthCheck(t *testing.T) {
	transport := newPolicyRoundTripper(CheckResponse{
		Allow:  false,
		Reason: "matched deny rule",
		RuleID: "R_DENY",
	})
	transport.healthStatus = http.StatusServiceUnavailable

	a := newTestAuthorizer("http://policy.test", false, time.Minute, transport)
	req := NewAuthzRequest("orders", "payments", TransportHTTP, "POST", "/payments/refund")

	_, err := a.Authorize(context.Background(), req)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("first Authorize err = %v, want ErrDenied", err)
	}
	if got := transport.calls.Load(); got != 1 {
		t.Fatalf("policy checks = %d, want 1 before deny cache hit", got)
	}

	resp, err := a.Authorize(context.Background(), req)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("cache-hit err = %v, want ErrDenied", err)
	}
	if resp.Allow {
		t.Fatalf("allow = true, want cached deny")
	}
	if got := transport.calls.Load(); got != 1 {
		t.Fatalf("policy checks = %d, want no second /v1/check call on deny cache hit", got)
	}
	if got := transport.healthCalls.Load(); got != 0 {
		t.Fatalf("health checks = %d, want none on deny cache hit", got)
	}
}

type policyRoundTripper struct {
	decision     CheckResponse
	err          error
	healthStatus int
	healthErr    error
	calls        atomic.Int64
	healthCalls  atomic.Int64
}

func newPolicyRoundTripper(decision CheckResponse) *policyRoundTripper {
	return &policyRoundTripper{decision: decision, healthStatus: http.StatusOK}
}

func roundTripError(err error) *policyRoundTripper {
	return &policyRoundTripper{err: err}
}

func (rt *policyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet && req.URL.Path == "/v1/health" {
		rt.healthCalls.Add(1)
		if rt.healthErr != nil {
			return nil, rt.healthErr
		}
		status := rt.healthStatus
		if status == 0 {
			status = http.StatusOK
		}
		return responseWithStatus(status, http.StatusText(status)), nil
	}

	rt.calls.Add(1)
	if rt.err != nil {
		return nil, rt.err
	}
	if req.Method != http.MethodPost {
		return responseWithStatus(http.StatusMethodNotAllowed, "method not allowed"), nil
	}
	if req.URL.Path != "/v1/check" {
		return responseWithStatus(http.StatusNotFound, "not found"), nil
	}
	var authReq AuthzRequest
	if err := json.NewDecoder(req.Body).Decode(&authReq); err != nil {
		return responseWithStatus(http.StatusBadRequest, "bad request"), nil
	}
	return responseWithJSON(rt.decision), nil
}

func responseWithJSON(resp CheckResponse) *http.Response {
	var b strings.Builder
	_ = json.NewEncoder(&b).Encode(resp)
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(b.String())),
	}
}

func responseWithStatus(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func newTestAuthorizer(policyURL string, failOpen bool, cacheTTL time.Duration, transport http.RoundTripper) *Authorizer {
	var cache *DecisionCache
	if cacheTTL > 0 {
		cache = NewDecisionCache(cacheTTL)
	}
	a := &Authorizer{
		failOpen: failOpen,
		client: &PolicyClient{
			BaseURL: policyURL,
			HTTP: &http.Client{
				Timeout:   50 * time.Millisecond,
				Transport: transport,
			},
			downFor:           50 * time.Millisecond,
			healthPositiveTTL: 50 * time.Millisecond,
		},
		cache:         cache,
		healthTimeout: 25 * time.Millisecond,
	}
	return a
}

func testPolicyClient(t *testing.T, a *Authorizer) *PolicyClient {
	t.Helper()
	client, ok := a.client.(*PolicyClient)
	if !ok {
		t.Fatalf("authorizer client type = %T, want *PolicyClient", a.client)
	}
	return client
}
