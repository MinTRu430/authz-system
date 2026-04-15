package authz

import (
	"context"
	"errors"
	"time"
)

var (
	ErrDenied     = errors.New("authz denied")
	ErrFailClosed = errors.New("authz fail-closed")
)

type AuthorizeError struct {
	Kind     error
	Response CheckResponse
	Cause    error
	Message  string
}

func (e *AuthorizeError) Error() string {
	return e.Message
}

func (e *AuthorizeError) Unwrap() error {
	return e.Cause
}

func (e *AuthorizeError) Is(target error) bool {
	return target == e.Kind
}

type Authorizer struct {
	failOpen     bool
	client       *PolicyClient
	cache        *DecisionCache
	probeTimeout time.Duration
}

func NewAuthorizer(cfg Config) (*Authorizer, error) {
	RegisterMetrics()

	client, err := NewPolicyClient(cfg.PolicyURL, cfg.Timeout, cfg.PolicyClientTLS)
	if err != nil {
		return nil, err
	}

	var cache *DecisionCache
	if cfg.CacheTTL > 0 {
		cache = NewDecisionCache(cfg.CacheTTL)
	}

	return &Authorizer{
		failOpen:     cfg.FailOpen,
		client:       client,
		cache:        cache,
		probeTimeout: 150 * time.Millisecond,
	}, nil
}

func (a *Authorizer) Authorize(ctx context.Context, req AuthzRequest) (CheckResponse, error) {
	req = req.Normalize()

	if a.cache != nil {
		if resp, ok := a.cache.Get(req); ok {
			recordAuthzCache("hit", req)

			// STRICT FAIL-CLOSED (anti fail-open-through-cache):
			// На allow cache-hit дополнительно проверяем, что policy-server доступен.
			// Если недоступен и FailOpen=false -> deny.
			if resp.Allow && !a.failOpen {
				if !a.client.Probe(a.probeTimeout) {
					recordAuthzCheck("unavailable", req)
					FailClosedInc()
					return resp, &AuthorizeError{
						Kind:     ErrFailClosed,
						Response: resp,
						Message:  "fail-closed: policy-server unavailable",
					}
				}
			}

			if !resp.Allow {
				recordAuthzCheck("deny", req)
				return resp, &AuthorizeError{
					Kind:     ErrDenied,
					Response: resp,
					Message:  "denied: " + resp.Reason,
				}
			}

			recordAuthzCheck("allow", req)
			return resp, nil
		}
		recordAuthzCache("miss", req)
	}

	start := time.Now()
	dec, err := a.client.Check(ctx, req)
	observeAuthzPolicyLatency(req, time.Since(start))

	if err != nil {
		recordAuthzCheck("unavailable", req)
		if a.failOpen {
			return CheckResponse{Allow: true, Reason: "fail-open: policy-server unavailable"}, nil
		}

		FailClosedInc()
		if errors.Is(err, ErrPolicyUnavailable) {
			return CheckResponse{}, &AuthorizeError{
				Kind:    ErrFailClosed,
				Cause:   err,
				Message: "fail-closed: policy-server unavailable",
			}
		}

		return CheckResponse{}, &AuthorizeError{
			Kind:    ErrFailClosed,
			Cause:   err,
			Message: "fail-closed: policy error: " + err.Error(),
		}
	}

	if a.cache != nil {
		a.cache.Put(req, dec)
	}

	if !dec.Allow {
		recordAuthzCheck("deny", req)
		return dec, &AuthorizeError{
			Kind:     ErrDenied,
			Response: dec,
			Message:  "denied: " + dec.Reason,
		}
	}

	recordAuthzCheck("allow", req)
	return dec, nil
}
