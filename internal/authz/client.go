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
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type TLSFiles struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

var ErrPolicyUnavailable = errors.New("policy-server unavailable")

type PolicyClient struct {
	BaseURL string
	HTTP    *http.Client

	downUntil atomic.Int64
	downFor   time.Duration
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
		BaseURL: baseURL,
		HTTP: &http.Client{
			Timeout:   timeout,
			Transport: tr,
		},
		downFor: 3 * time.Second,
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

func (c *PolicyClient) markDown(now time.Time) {
	c.downUntil.Store(now.Add(c.downFor).UnixNano())
}

func (c *PolicyClient) IsDown() bool {
	return c.isDown(time.Now())
}

// Probe проверяет доступность policy-server на уровне TCP (быстро, без HTTP).
// Используется, чтобы не допустить "fail-open through cache".
func (c *PolicyClient) Probe(timeout time.Duration) bool {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return false
	}
	host := u.Host
	if host == "" {
		return false
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", host)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
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

func (c *PolicyClient) Check(ctx context.Context, req CheckRequest) (CheckResponse, error) {
	now := time.Now()
	if c.isDown(now) {
		return CheckResponse{}, ErrPolicyUnavailable
	}

	body, err := json.Marshal(req)
	if err != nil {
		return CheckResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/check", bytes.NewReader(body))
	if err != nil {
		return CheckResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		if isTransportErr(err) {
			c.markDown(now)
			return CheckResponse{}, ErrPolicyUnavailable
		}
		return CheckResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 {
			c.markDown(now)
			return CheckResponse{}, ErrPolicyUnavailable
		}
		return CheckResponse{}, errors.New("policy status: " + resp.Status)
	}

	var out CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		c.markDown(now)
		return CheckResponse{}, ErrPolicyUnavailable
	}
	return out, nil
}
