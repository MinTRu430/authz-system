package authz

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"
)

type TLSFiles struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

type PolicyClient struct {
	BaseURL string
	HTTP    *http.Client
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

func (c *PolicyClient) Check(ctx context.Context, req CheckRequest) (CheckResponse, error) {
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
		return CheckResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return CheckResponse{}, errors.New("policy status: " + resp.Status)
	}

	var out CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return CheckResponse{}, err
	}
	return out, nil
}
