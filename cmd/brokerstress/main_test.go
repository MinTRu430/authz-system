package main

import (
	"errors"
	"testing"
	"time"

	"authz-system/internal/authz"
	"authz-system/internal/authz/brokersign"
)

func TestPercentile(t *testing.T) {
	values := []time.Duration{
		time.Millisecond,
		2 * time.Millisecond,
		3 * time.Millisecond,
		4 * time.Millisecond,
		5 * time.Millisecond,
	}
	if got := percentile(values, 0.50); got != 3*time.Millisecond {
		t.Fatalf("p50 = %s, want 3ms", got)
	}
	if got := percentile(values, 0.95); got != 5*time.Millisecond {
		t.Fatalf("p95 = %s, want 5ms", got)
	}
}

func TestMatchesExpectation(t *testing.T) {
	tests := []struct {
		expect  string
		outcome string
		want    bool
	}{
		{expectAllowed, outcomeAllowed, true},
		{expectBlocked, outcomeBlocked, true},
		{expectDenied, outcomeDenied, true},
		{expectInvalidSignature, outcomeInvalidSignature, true},
		{expectAny, outcomeBlocked, true},
		{expectAny, outcomeError, false},
		{expectAllowed, outcomeDenied, false},
	}
	for _, test := range tests {
		if got := matchesExpectation(test.expect, test.outcome); got != test.want {
			t.Errorf("matchesExpectation(%q, %q) = %v, want %v", test.expect, test.outcome, got, test.want)
		}
	}
}

func TestClassifyError(t *testing.T) {
	if got := classifyError(nil); got != outcomeAllowed {
		t.Fatalf("nil error outcome = %q", got)
	}
	if got := classifyError(authz.ErrDenied); got != outcomeDenied {
		t.Fatalf("denied outcome = %q", got)
	}
	if got := classifyError(authz.ErrFailClosed); got != outcomeBlocked {
		t.Fatalf("fail-closed outcome = %q", got)
	}
	if got := classifyError(brokersign.ErrInvalidSignature); got != outcomeInvalidSignature {
		t.Fatalf("signature outcome = %q", got)
	}
	if got := classifyError(errors.New("boom")); got != outcomeError {
		t.Fatalf("generic error outcome = %q", got)
	}
}

func TestBuildSummaryCountsHandlerCalls(t *testing.T) {
	cfg := runConfig{
		broker:      "kafka",
		mode:        modeConsume,
		scenario:    scenarioInvalidSignature,
		expect:      expectInvalidSignature,
		n:           2,
		concurrency: 1,
		cacheTTL:    time.Second,
	}
	results := []operationResult{
		{latency: time.Millisecond, outcome: outcomeInvalidSignature, success: true},
		{latency: 2 * time.Millisecond, outcome: outcomeInvalidSignature, success: true},
	}
	report := buildSummary(cfg, results, 2*time.Millisecond, 0)
	if report.Success != 2 || report.Errors != 0 || report.InvalidSignature != 2 {
		t.Fatalf("unexpected summary: %+v", report)
	}
	if report.HandlerCalls != 0 {
		t.Fatalf("handler calls = %d, want 0", report.HandlerCalls)
	}
}
