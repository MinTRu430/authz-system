package authz

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/attribute"
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
	failOpen      bool
	client        PolicyDecisionClient
	cache         *DecisionCache
	healthTimeout time.Duration
}

func NewAuthorizer(cfg Config) (*Authorizer, error) {
	RegisterMetrics()

	client, err := newPolicyDecisionClient(cfg)
	if err != nil {
		return nil, err
	}

	var cache *DecisionCache
	if cfg.CacheTTL > 0 {
		cache = NewDecisionCache(cfg.CacheTTL)
	}
	healthTimeout := cfg.PolicyHealthTimeout
	if healthTimeout <= 0 {
		healthTimeout = 150 * time.Millisecond
	}

	return &Authorizer{
		failOpen:      cfg.FailOpen,
		client:        client,
		cache:         cache,
		healthTimeout: healthTimeout,
	}, nil
}

func (a *Authorizer) Authorize(ctx context.Context, req AuthzRequest) (CheckResponse, error) {
	req = req.Normalize()
	attrs := SafeAuthzAttrs(req)
	ctx, span := StartSpan(ctx, "authz.authorize", attrs...)
	result := "error"
	var spanErr error
	defer func() {
		EndSpanWithResult(span, result, spanErr)
		span.End()
	}()

	if a.cache != nil {
		_, cacheSpan := StartSpan(ctx, "authz.cache.get", attrs...)
		resp, ok := a.cache.Get(req)
		cacheSpan.SetAttributes(attribute.Bool("authz.cache_hit", ok))
		EndSpanWithResult(cacheSpan, cacheResult(ok), nil)
		cacheSpan.End()

		if ok {
			recordAuthzCache("hit", req)
			span.SetAttributes(attribute.Bool("authz.cache_hit", true))

			// STRICT FAIL-CLOSED (anti fail-open-through-cache):
			// На allow cache-hit дополнительно проверяем, что policy-server доступен.
			// Если недоступен и FailOpen=false -> deny.
			if resp.Allow && !a.failOpen {
				healthTimeout := a.healthTimeout
				if healthTimeout <= 0 {
					healthTimeout = 150 * time.Millisecond
				}
				healthCtx, cancel := context.WithTimeout(ctx, healthTimeout)
				err := a.client.EnsureAvailable(healthCtx)
				cancel()
				if err != nil {
					recordAuthzCheck("unavailable", req)
					FailClosedInc()
					result = "unavailable"
					spanErr = ErrFailClosed
					span.SetAttributes(attribute.Bool("authz.fail_closed", true))
					_, failSpan := StartSpan(ctx, "authz.fail_closed", attrs...)
					failSpan.SetAttributes(attribute.Bool("authz.fail_closed", true))
					EndSpanWithResult(failSpan, "unavailable", ErrFailClosed)
					failSpan.End()
					return resp, &AuthorizeError{
						Kind:     ErrFailClosed,
						Response: resp,
						Cause:    err,
						Message:  "fail-closed: policy-server unavailable",
					}
				}
			}

			if !resp.Allow {
				recordAuthzCheck("deny", req)
				result = "deny"
				return resp, &AuthorizeError{
					Kind:     ErrDenied,
					Response: resp,
					Message:  "denied: " + resp.Reason,
				}
			}

			recordAuthzCheck("allow", req)
			result = "allow"
			return resp, nil
		}
		recordAuthzCache("miss", req)
		span.SetAttributes(attribute.Bool("authz.cache_hit", false))
	}

	start := time.Now()
	dec, err := a.client.Check(ctx, req)
	observeAuthzPolicyLatency(req, time.Since(start))

	if err != nil {
		recordAuthzCheck("unavailable", req)
		if a.failOpen {
			result = "allow"
			return CheckResponse{Allow: true, Reason: "fail-open: policy-server unavailable"}, nil
		}

		FailClosedInc()
		result = "unavailable"
		spanErr = ErrFailClosed
		span.SetAttributes(attribute.Bool("authz.fail_closed", true))
		_, failSpan := StartSpan(ctx, "authz.fail_closed", attrs...)
		failSpan.SetAttributes(attribute.Bool("authz.fail_closed", true))
		EndSpanWithResult(failSpan, "unavailable", ErrFailClosed)
		failSpan.End()
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
		result = "deny"
		return dec, &AuthorizeError{
			Kind:     ErrDenied,
			Response: dec,
			Message:  "denied: " + dec.Reason,
		}
	}

	recordAuthzCheck("allow", req)
	result = "allow"
	return dec, nil
}

func cacheResult(hit bool) string {
	if hit {
		return "hit"
	}
	return "miss"
}
