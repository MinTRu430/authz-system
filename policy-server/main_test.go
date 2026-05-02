package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authz-system/internal/authz"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestHealthEndpointOKWhenPolicyLoaded(t *testing.T) {
	policyFile := filepath.Join(t.TempDir(), "policies.yaml")
	policy := strings.Join([]string{
		"- id: R1",
		"  source: orders",
		"  target: payments",
		"  transport: http",
		"  operation: POST",
		"  resource: /payments/charge",
		"  effect: allow",
		"",
	}, "\n")
	if err := os.WriteFile(policyFile, []byte(policy), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	store := &Store{}
	if err := store.ReloadFromFile(policyFile); err != nil {
		t.Fatalf("reload policy: %v", err)
	}

	rr := httptest.NewRecorder()
	store.HealthHandler(rr, httptest.NewRequest(http.MethodGet, "/v1/health", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"status":"ok"`) {
		t.Fatalf("body = %s, want status ok", rr.Body.String())
	}
	for _, want := range []string{`"content_hash":`, `"policy_source":"file"`, `"sync_status":"ok"`} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("body = %s, want %s", rr.Body.String(), want)
		}
	}
}

func TestHealthEndpointUnavailableWithoutPolicy(t *testing.T) {
	store := &Store{}

	rr := httptest.NewRecorder()
	store.HealthHandler(rr, httptest.NewRequest(http.MethodGet, "/v1/health", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"status":"unhealthy"`) {
		t.Fatalf("body = %s, want unhealthy status", rr.Body.String())
	}
}

func TestHealthEndpointRejectsNonGET(t *testing.T) {
	store := &Store{}

	rr := httptest.NewRecorder()
	store.HealthHandler(rr, httptest.NewRequest(http.MethodPost, "/v1/health", nil))

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
}

func TestPolicyServerMetricsRegister(t *testing.T) {
	reg := prometheus.NewRegistry()
	registerPolicyMetrics(reg)

	names := gatherMetricNames(t, reg)
	for _, name := range []string{
		"policy_reload_total",
		"policy_reload_duration_seconds",
		"policy_check_requests_total",
		"policy_check_duration_seconds",
		"policy_match_latency_seconds",
		"policy_rules_total",
		"policy_index_buckets_total",
		"policy_store_sync_total",
		"policy_store_sync_duration_seconds",
		"policy_store_db_errors_total",
		"policy_store_last_sync_timestamp_seconds",
		"policy_replica_in_sync",
	} {
		if !names[name] {
			t.Fatalf("metric %s was not registered", name)
		}
	}
}

func TestReloadMetricsRecordSuccessAndFailure(t *testing.T) {
	reg := prometheus.NewRegistry()
	registerPolicyMetrics(reg)

	store := &Store{}
	okBefore := metricValue(t, reg, "policy_reload_total", map[string]string{"result": "ok"})
	errBefore := metricValue(t, reg, "policy_reload_total", map[string]string{"result": "error"})
	durationBefore := histogramCount(t, reg, "policy_reload_duration_seconds")

	if err := store.ReloadFromFile(writeTestPolicy(t)); err != nil {
		t.Fatalf("reload policy: %v", err)
	}
	if err := store.ReloadFromFile(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("reload missing policy error = nil, want error")
	}

	if got := metricValue(t, reg, "policy_reload_total", map[string]string{"result": "ok"}) - okBefore; got != 1 {
		t.Fatalf("policy_reload_total ok delta = %v, want 1", got)
	}
	if got := metricValue(t, reg, "policy_reload_total", map[string]string{"result": "error"}) - errBefore; got != 1 {
		t.Fatalf("policy_reload_total error delta = %v, want 1", got)
	}
	if got := histogramCount(t, reg, "policy_reload_duration_seconds") - durationBefore; got != 2 {
		t.Fatalf("policy_reload_duration_seconds count delta = %v, want 2", got)
	}
}

func TestCheckMetricsRecordAllowAndDeny(t *testing.T) {
	reg := prometheus.NewRegistry()
	registerPolicyMetrics(reg)

	store := &Store{}
	if err := store.ReloadFromFile(writeTestPolicy(t)); err != nil {
		t.Fatalf("reload policy: %v", err)
	}

	allowBefore := metricValue(t, reg, "policy_check_requests_total", map[string]string{"result": "allow"})
	denyBefore := metricValue(t, reg, "policy_check_requests_total", map[string]string{"result": "deny"})
	durationBefore := histogramCount(t, reg, "policy_check_duration_seconds")

	doCheck(t, store, authz.NewAuthzRequest("orders", "payments", authz.TransportHTTP, "POST", "/payments/charge"))
	doCheck(t, store, authz.NewAuthzRequest("orders", "payments", authz.TransportHTTP, "POST", "/payments/refund"))

	if got := metricValue(t, reg, "policy_check_requests_total", map[string]string{"result": "allow"}) - allowBefore; got != 1 {
		t.Fatalf("policy_check_requests_total allow delta = %v, want 1", got)
	}
	if got := metricValue(t, reg, "policy_check_requests_total", map[string]string{"result": "deny"}) - denyBefore; got != 1 {
		t.Fatalf("policy_check_requests_total deny delta = %v, want 1", got)
	}
	if got := histogramCount(t, reg, "policy_check_duration_seconds") - durationBefore; got != 2 {
		t.Fatalf("policy_check_duration_seconds count delta = %v, want 2", got)
	}
}

func TestCheckHandlerCreatesTracingSpans(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	otel.SetTracerProvider(tp)
	defer func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(noop.NewTracerProvider())
	}()

	store := &Store{}
	if err := store.ReloadFromFile(writeTestPolicy(t)); err != nil {
		t.Fatalf("reload policy: %v", err)
	}

	doCheck(t, store, authz.NewAuthzRequest("orders", "payments", authz.TransportHTTP, "POST", "/payments/charge"))

	names := make(map[string]bool)
	for _, span := range exporter.GetSpans() {
		names[span.Name] = true
	}
	for _, name := range []string{"policy_server.check", "policy_server.match"} {
		if !names[name] {
			t.Fatalf("span %s not found in %+v", name, names)
		}
	}
}

func writeTestPolicy(t *testing.T) string {
	t.Helper()
	policyFile := filepath.Join(t.TempDir(), "policies.yaml")
	policy := strings.Join([]string{
		"- id: R1",
		"  source: orders",
		"  target: payments",
		"  transport: http",
		"  operation: POST",
		"  resource: /payments/charge",
		"  effect: allow",
		"- id: R2",
		"  source: '*'",
		"  target: '*'",
		"  transport: '*'",
		"  operation: '*'",
		"  resource: '*'",
		"  effect: deny",
		"",
	}, "\n")
	if err := os.WriteFile(policyFile, []byte(policy), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return policyFile
}

func doCheck(t *testing.T, store *Store, req authz.AuthzRequest) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal check request: %v", err)
	}
	rr := httptest.NewRecorder()
	store.CheckHandler(rr, httptest.NewRequest(http.MethodPost, "/v1/check", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("check status = %d, want 200, body=%s", rr.Code, rr.Body.String())
	}
}

func gatherMetricNames(t *testing.T, reg *prometheus.Registry) map[string]bool {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	out := make(map[string]bool, len(families))
	for _, family := range families {
		out[family.GetName()] = true
	}
	return out
}

func metricValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	metric := findMetric(t, reg, name, labels)
	if metric == nil {
		return 0
	}
	if metric.Counter != nil {
		return metric.Counter.GetValue()
	}
	if metric.Gauge != nil {
		return metric.Gauge.GetValue()
	}
	t.Fatalf("metric %s has unsupported type", name)
	return 0
}

func histogramCount(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	metric := findMetric(t, reg, name, nil)
	if metric == nil || metric.Histogram == nil {
		return 0
	}
	return float64(metric.Histogram.GetSampleCount())
}

func findMetric(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) *dto.Metric {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			if labelsMatch(metric, labels) {
				return metric
			}
		}
	}
	return nil
}

func labelsMatch(metric *dto.Metric, labels map[string]string) bool {
	if len(labels) == 0 {
		return true
	}
	got := make(map[string]string, len(metric.Label))
	for _, pair := range metric.Label {
		got[pair.GetName()] = pair.GetValue()
	}
	for name, want := range labels {
		if got[name] != want {
			return false
		}
	}
	return true
}
