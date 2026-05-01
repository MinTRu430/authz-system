package authz

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

type TLSFiles struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

var ErrPolicyUnavailable = errors.New("policy-server unavailable")

type PolicyDecisionClient interface {
	Check(ctx context.Context, req CheckRequest) (CheckResponse, error)
	EnsureAvailable(ctx context.Context) error
}

const (
	defaultPolicyHealthPositiveTTL  = 2 * time.Second
	defaultPolicyUnavailableBackoff = 2 * time.Second

	policyAvailabilityUnknown int32 = iota
	policyAvailabilityHealthy
	policyAvailabilityUnavailable
)

type PolicyClient struct {
	BaseURL string
	HTTP    *http.Client

	downUntil         atomic.Int64
	healthOKUntil     atomic.Int64
	availabilityState atomic.Int32

	downFor           time.Duration
	healthPositiveTTL time.Duration
	now               func() time.Time
	metricsEndpoint   string
}

func NewPolicyClient(baseURL string, timeout time.Duration, tlsFiles TLSFiles) (*PolicyClient, error) {
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}
	tr, err := buildMTLSTransport(tlsFiles)
	if err != nil {
		return nil, err
	}
	return &PolicyClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP: &http.Client{
			Timeout:   timeout,
			Transport: tr,
		},
		downFor:           defaultPolicyUnavailableBackoff,
		healthPositiveTTL: defaultPolicyHealthPositiveTTL,
		metricsEndpoint:   "0",
	}, nil
}

func buildMTLSTransport(f TLSFiles) (*http.Transport, error) {
	if f.CertFile == "" || f.KeyFile == "" || f.CAFile == "" {
		return nil, errors.New("TLSFiles required")
	}
	cert, err := tls.LoadX509KeyPair(f.CertFile, f.KeyFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(f.CAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caPEM); !ok {
		return nil, errors.New("append CA failed")
	}
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
		},
	}, nil
}

func (c *PolicyClient) isDown(now time.Time) bool {
	until := c.downUntil.Load()
	return until != 0 && now.UnixNano() < until
}

func (c *PolicyClient) IsDown() bool {
	return c.isDown(c.clockNow())
}

func (c *PolicyClient) configureAvailability(healthTTL, unavailableBackoff time.Duration) {
	if healthTTL > 0 {
		c.healthPositiveTTL = healthTTL
	}
	if unavailableBackoff > 0 {
		c.downFor = unavailableBackoff
	}
}

func (c *PolicyClient) setMetricsEndpoint(endpoint string) {
	c.metricsEndpoint = metricEndpoint(endpoint)
}

func (c *PolicyClient) metricEndpoint() string {
	return metricEndpoint(c.metricsEndpoint)
}

func (c *PolicyClient) clockNow() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *PolicyClient) healthTTL() time.Duration {
	if c.healthPositiveTTL <= 0 {
		return defaultPolicyHealthPositiveTTL
	}
	return c.healthPositiveTTL
}

func (c *PolicyClient) unavailableBackoff() time.Duration {
	if c.downFor <= 0 {
		return defaultPolicyUnavailableBackoff
	}
	return c.downFor
}

func (c *PolicyClient) hasFreshHealth(now time.Time) bool {
	until := c.healthOKUntil.Load()
	return until != 0 && now.UnixNano() < until
}

func (c *PolicyClient) markAvailable(now time.Time) {
	c.downUntil.Store(0)
	c.healthOKUntil.Store(now.Add(c.healthTTL()).UnixNano())
	c.markHealthyState()
}

func (c *PolicyClient) markCheckAvailable() {
	c.downUntil.Store(0)
	c.markHealthyState()
}

func (c *PolicyClient) markHealthyState() {
	if c.availabilityState.Swap(policyAvailabilityHealthy) != policyAvailabilityHealthy {
		recordPolicyCircuitTransition("healthy")
	}
	recordPolicyAvailabilityState(1)
	recordPolicyEndpointAvailabilityState(c.metricEndpoint(), 1)
}

func (c *PolicyClient) markUnavailable(now time.Time) {
	c.healthOKUntil.Store(0)
	c.downUntil.Store(now.Add(c.unavailableBackoff()).UnixNano())
	if c.availabilityState.Swap(policyAvailabilityUnavailable) != policyAvailabilityUnavailable {
		recordPolicyCircuitTransition("unavailable")
	}
	recordPolicyAvailabilityState(0)
	recordPolicyEndpointAvailabilityState(c.metricEndpoint(), 0)
}

func isTransportErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "TLS handshake timeout") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "no such host") {
		return true
	}
	return false
}

func (c *PolicyClient) Health(ctx context.Context) error {
	ctx, span := StartSpan(ctx, "authz.policy.health", attribute.String("authz.policy_endpoint_index", c.metricEndpoint()))
	result := "error"
	var spanErr error
	defer func() {
		EndSpanWithResult(span, result, spanErr)
		span.End()
	}()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/health", nil)
	if err != nil {
		recordPolicyHealth("fail")
		recordPolicyEndpointHealth(c.metricEndpoint(), "error")
		c.markUnavailable(c.clockNow())
		spanErr = err
		return err
	}
	InjectHTTP(ctx, httpReq.Header)

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		recordPolicyHealth("fail")
		recordPolicyEndpointHealth(c.metricEndpoint(), "unavailable")
		if isTransportErr(err) {
			c.markUnavailable(c.clockNow())
			result = "unavailable"
			spanErr = ErrPolicyUnavailable
			return ErrPolicyUnavailable
		}
		c.markUnavailable(c.clockNow())
		spanErr = err
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		recordPolicyHealth("fail")
		recordPolicyEndpointHealth(c.metricEndpoint(), "unavailable")
		c.markUnavailable(c.clockNow())
		result = "unavailable"
		spanErr = ErrPolicyUnavailable
		return ErrPolicyUnavailable
	}

	recordPolicyHealth("ok")
	recordPolicyEndpointHealth(c.metricEndpoint(), "ok")
	c.markAvailable(c.clockNow())
	result = "ok"
	return nil
}

func (c *PolicyClient) EnsureAvailable(ctx context.Context) error {
	now := c.clockNow()
	if c.hasFreshHealth(now) {
		return nil
	}
	if c.isDown(now) {
		return ErrPolicyUnavailable
	}
	return c.Health(ctx)
}

func (c *PolicyClient) Check(ctx context.Context, req CheckRequest) (CheckResponse, error) {
	req = req.Normalize()
	attrs := append(SafeAuthzAttrs(req), attribute.String("authz.policy_endpoint_index", c.metricEndpoint()))
	ctx, span := StartSpan(ctx, "authz.policy.check", attrs...)
	result := "error"
	var spanErr error
	defer func() {
		EndSpanWithResult(span, result, spanErr)
		span.End()
	}()

	now := c.clockNow()
	if c.isDown(now) {
		recordPolicyEndpointRequest(c.metricEndpoint(), "unavailable")
		result = "unavailable"
		spanErr = ErrPolicyUnavailable
		return CheckResponse{}, ErrPolicyUnavailable
	}

	body, err := json.Marshal(req)
	if err != nil {
		recordPolicyEndpointRequest(c.metricEndpoint(), "error")
		spanErr = err
		return CheckResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/check", bytes.NewReader(body))
	if err != nil {
		recordPolicyEndpointRequest(c.metricEndpoint(), "error")
		spanErr = err
		return CheckResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	InjectHTTP(ctx, httpReq.Header)

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		if isTransportErr(err) {
			c.markUnavailable(c.clockNow())
			recordPolicyEndpointRequest(c.metricEndpoint(), "unavailable")
			result = "unavailable"
			spanErr = ErrPolicyUnavailable
			return CheckResponse{}, ErrPolicyUnavailable
		}
		recordPolicyEndpointRequest(c.metricEndpoint(), "error")
		spanErr = err
		return CheckResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 {
			c.markUnavailable(c.clockNow())
			recordPolicyEndpointRequest(c.metricEndpoint(), "unavailable")
			result = "unavailable"
			spanErr = ErrPolicyUnavailable
			return CheckResponse{}, ErrPolicyUnavailable
		}
		recordPolicyEndpointRequest(c.metricEndpoint(), "error")
		spanErr = errors.New("policy status")
		return CheckResponse{}, errors.New("policy status: " + resp.Status)
	}

	var out CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		c.markUnavailable(c.clockNow())
		recordPolicyEndpointRequest(c.metricEndpoint(), "unavailable")
		result = "unavailable"
		spanErr = ErrPolicyUnavailable
		return CheckResponse{}, ErrPolicyUnavailable
	}
	c.markCheckAvailable()
	recordPolicyEndpointRequest(c.metricEndpoint(), decisionResult(out))
	result = decisionResult(out)
	return out, nil
}
