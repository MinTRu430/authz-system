package authz

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type MultiPolicyClient struct {
	endpoints []*PolicyClient
	next      atomic.Uint64
}

func NewMultiPolicyClient(baseURLs []string, timeout time.Duration, tlsFiles TLSFiles) (*MultiPolicyClient, error) {
	urls := normalizePolicyURLs(baseURLs, "")
	if len(urls) == 0 {
		return nil, errors.New("PolicyURLs required")
	}

	endpoints := make([]*PolicyClient, 0, len(urls))
	for i, baseURL := range urls {
		client, err := NewPolicyClient(baseURL, timeout, tlsFiles)
		if err != nil {
			return nil, err
		}
		client.setMetricsEndpoint(endpointLabel(i))
		endpoints = append(endpoints, client)
	}

	return &MultiPolicyClient{endpoints: endpoints}, nil
}

func newPolicyDecisionClient(cfg Config) (PolicyDecisionClient, error) {
	urls := normalizePolicyURLs(cfg.PolicyURLs, cfg.PolicyURL)
	if len(urls) == 0 {
		return nil, errors.New("PolicyURL or PolicyURLs required")
	}

	if len(urls) == 1 {
		client, err := NewPolicyClient(urls[0], cfg.Timeout, cfg.PolicyClientTLS)
		if err != nil {
			return nil, err
		}
		client.configureAvailability(cfg.PolicyHealthPositiveTTL, cfg.PolicyUnavailableBackoff)
		return client, nil
	}

	client, err := NewMultiPolicyClient(urls, cfg.Timeout, cfg.PolicyClientTLS)
	if err != nil {
		return nil, err
	}
	client.configureAvailability(cfg.PolicyHealthPositiveTTL, cfg.PolicyUnavailableBackoff)
	return client, nil
}

func normalizePolicyURLs(policyURLs []string, policyURL string) []string {
	source := policyURLs
	if len(source) == 0 && policyURL != "" {
		source = []string{policyURL}
	}

	out := make([]string, 0, len(source))
	seen := make(map[string]struct{}, len(source))
	for _, raw := range source {
		for _, part := range strings.Split(raw, ",") {
			url := strings.TrimRight(strings.TrimSpace(part), "/")
			if url == "" {
				continue
			}
			if _, ok := seen[url]; ok {
				continue
			}
			seen[url] = struct{}{}
			out = append(out, url)
		}
	}
	return out
}

func (c *MultiPolicyClient) configureAvailability(healthTTL, unavailableBackoff time.Duration) {
	for _, endpoint := range c.endpoints {
		endpoint.configureAvailability(healthTTL, unavailableBackoff)
	}
}

func (c *MultiPolicyClient) Check(ctx context.Context, req CheckRequest) (CheckResponse, error) {
	if len(c.endpoints) == 0 {
		return CheckResponse{}, ErrPolicyUnavailable
	}

	start := c.startIndex()
	var unavailable bool
	for i := 0; i < len(c.endpoints); i++ {
		idx := (start + i) % len(c.endpoints)
		resp, err := c.endpoints[idx].Check(ctx, req)
		if err == nil {
			return resp, nil
		}
		if errors.Is(err, ErrPolicyUnavailable) {
			unavailable = true
			if i < len(c.endpoints)-1 {
				recordPolicyFailover()
			}
			continue
		}
		return CheckResponse{}, err
	}

	if unavailable {
		return CheckResponse{}, ErrPolicyUnavailable
	}
	return CheckResponse{}, ErrPolicyUnavailable
}

func (c *MultiPolicyClient) EnsureAvailable(ctx context.Context) error {
	if len(c.endpoints) == 0 {
		return ErrPolicyUnavailable
	}

	start := c.startIndex()
	var unavailable bool
	for i := 0; i < len(c.endpoints); i++ {
		idx := (start + i) % len(c.endpoints)
		err := c.endpoints[idx].EnsureAvailable(ctx)
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrPolicyUnavailable) {
			unavailable = true
			if i < len(c.endpoints)-1 {
				recordPolicyFailover()
			}
			continue
		}
		return err
	}

	if unavailable {
		return ErrPolicyUnavailable
	}
	return ErrPolicyUnavailable
}

func (c *MultiPolicyClient) startIndex() int {
	return int(c.next.Add(1)-1) % len(c.endpoints)
}

func endpointLabel(idx int) string {
	return strconv.Itoa(idx)
}

func decisionResult(resp CheckResponse) string {
	if resp.Allow {
		return "allow"
	}
	return "deny"
}
