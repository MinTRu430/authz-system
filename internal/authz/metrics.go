package authz

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	authzChecksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_checks_total", Help: "Total authz checks"},
		[]string{"result", "transport"}, // allow|deny|unauthenticated|unavailable, grpc|http|broker
	)
	authzCacheTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_cache_total", Help: "Authz cache hit/miss"},
		[]string{"type", "transport"}, // hit|miss, grpc|http|broker
	)
	authzPolicyLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: "authz_policy_check_latency_seconds", Help: "Policy check latency seconds"},
		[]string{"transport"},
	)

	// NEW: fail-closed counter for эксплуатационного анализа
	authzFailClosedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "authz_fail_closed_total",
			Help: "Total requests denied due to fail-closed mode (policy-server unavailable)",
		},
	)

	registerMetricsOnce sync.Once
)

func RegisterMetrics() {
	registerMetricsOnce.Do(func() {
		prometheus.MustRegister(authzChecksTotal, authzCacheTotal, authzPolicyLatency, authzFailClosedTotal)
	})
}

func FailClosedInc() {
	authzFailClosedTotal.Inc()
}

func recordAuthzCheck(result string, req AuthzRequest) {
	authzChecksTotal.WithLabelValues(result, metricTransport(req)).Inc()
}

func recordAuthzCache(kind string, req AuthzRequest) {
	authzCacheTotal.WithLabelValues(kind, metricTransport(req)).Inc()
}

func observeAuthzPolicyLatency(req AuthzRequest, d time.Duration) {
	authzPolicyLatency.WithLabelValues(metricTransport(req)).Observe(d.Seconds())
}

func metricTransport(req AuthzRequest) string {
	req = req.Normalize()
	if req.Transport == "" {
		return "unknown"
	}
	return string(req.Transport)
}
