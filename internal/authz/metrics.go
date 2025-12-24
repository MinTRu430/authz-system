package authz

import "github.com/prometheus/client_golang/prometheus"

var (
	authzChecksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_checks_total", Help: "Total authz checks"},
		[]string{"result"}, // allow|deny|unauthenticated|unavailable
	)
	authzCacheTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_cache_total", Help: "Authz cache hit/miss"},
		[]string{"type"}, // hit|miss
	)
	authzPolicyLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{Name: "authz_policy_check_latency_seconds", Help: "Policy check latency seconds"},
	)
	registered = false
)

func RegisterMetrics() {
	if registered {
		return
	}
	prometheus.MustRegister(authzChecksTotal, authzCacheTotal, authzPolicyLatency)
	registered = true
}
