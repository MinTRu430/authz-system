package authz

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	authzChecksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_checks_total", Help: "Total authz checks"},
		[]string{"result", "transport", "broker"},
	)
	authzProtectedOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_protected_operations_total", Help: "Total protected operations observed by authz adapters"},
		[]string{"transport", "broker", "result"},
	)
	authzCacheTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_cache_total", Help: "Authz cache hit/miss"},
		[]string{"type", "transport", "broker"},
	)
	authzPolicyLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: "authz_policy_check_latency_seconds", Help: "Policy check latency seconds"},
		[]string{"transport", "broker"},
	)
	authzPolicyHealthChecksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_policy_health_checks_total", Help: "Application-level policy-server health checks"},
		[]string{"result"},
	)
	authzPolicyAvailabilityState = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "authz_policy_availability_state", Help: "Policy-server availability state: 1 healthy, 0 unavailable"},
	)
	authzPolicyCircuitTransitionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_policy_circuit_transitions_total", Help: "Policy-server availability circuit transitions"},
		[]string{"state"},
	)
	authzPolicyFailoverTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "authz_policy_failover_total", Help: "Policy endpoint failover attempts"},
	)
	authzPolicyEndpointRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_policy_endpoint_requests_total", Help: "Policy endpoint check requests"},
		[]string{"endpoint", "result"},
	)
	authzPolicyEndpointHealthTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_policy_endpoint_health_total", Help: "Policy endpoint health checks"},
		[]string{"endpoint", "result"},
	)
	authzPolicyEndpointAvailabilityState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "authz_policy_endpoint_availability_state", Help: "Policy endpoint availability state: 1 healthy, 0 unavailable"},
		[]string{"endpoint"},
	)
	authzMessageSignedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_message_signed_total", Help: "Broker messages signed by authz adapters"},
		[]string{"broker"},
	)
	authzMessageSignatureChecksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_message_signature_checks_total", Help: "Broker message signature verification checks"},
		[]string{"broker", "result"},
	)
	authzMessageSignatureFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_message_signature_failures_total", Help: "Broker message signature verification failures"},
		[]string{"broker", "reason"},
	)
	authzBrokerMessageProcessingTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_broker_message_processing_total", Help: "Broker message processing outcomes"},
		[]string{"broker", "result"},
	)
	authzBrokerMessagesRetriedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_broker_messages_retried_total", Help: "Broker message processing retries"},
		[]string{"broker", "reason"},
	)
	authzBrokerMessagesDeadLetteredTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_broker_messages_deadlettered_total", Help: "Broker messages sent to dead-letter resources"},
		[]string{"broker", "reason"},
	)
	authzBrokerDLQPublishErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_broker_dlq_publish_errors_total", Help: "Broker dead-letter publish errors"},
		[]string{"broker"},
	)
	authzBrokerConsumeErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authz_broker_consume_errors_total", Help: "Broker consume errors"},
		[]string{"broker", "reason"},
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
		prometheus.MustRegister(
			authzChecksTotal,
			authzProtectedOperationsTotal,
			authzCacheTotal,
			authzPolicyLatency,
			authzPolicyHealthChecksTotal,
			authzPolicyAvailabilityState,
			authzPolicyCircuitTransitionsTotal,
			authzPolicyFailoverTotal,
			authzPolicyEndpointRequestsTotal,
			authzPolicyEndpointHealthTotal,
			authzPolicyEndpointAvailabilityState,
			authzMessageSignedTotal,
			authzMessageSignatureChecksTotal,
			authzMessageSignatureFailuresTotal,
			authzBrokerMessageProcessingTotal,
			authzBrokerMessagesRetriedTotal,
			authzBrokerMessagesDeadLetteredTotal,
			authzBrokerDLQPublishErrorsTotal,
			authzBrokerConsumeErrorsTotal,
			authzFailClosedTotal,
		)
	})
}

func FailClosedInc() {
	authzFailClosedTotal.Inc()
}

func RecordAuthzCheck(result string, req AuthzRequest) {
	recordAuthzCheck(result, req)
}

func recordAuthzCheck(result string, req AuthzRequest) {
	transport := metricTransport(req)
	broker := metricBroker(req)
	authzChecksTotal.WithLabelValues(result, transport, broker).Inc()
	authzProtectedOperationsTotal.WithLabelValues(transport, broker, result).Inc()
}

func recordAuthzCache(kind string, req AuthzRequest) {
	authzCacheTotal.WithLabelValues(kind, metricTransport(req), metricBroker(req)).Inc()
}

func observeAuthzPolicyLatency(req AuthzRequest, d time.Duration) {
	authzPolicyLatency.WithLabelValues(metricTransport(req), metricBroker(req)).Observe(d.Seconds())
}

func recordPolicyHealth(result string) {
	authzPolicyHealthChecksTotal.WithLabelValues(result).Inc()
}

func recordPolicyAvailabilityState(value float64) {
	authzPolicyAvailabilityState.Set(value)
}

func recordPolicyCircuitTransition(state string) {
	authzPolicyCircuitTransitionsTotal.WithLabelValues(state).Inc()
}

func recordPolicyFailover() {
	authzPolicyFailoverTotal.Inc()
}

func recordPolicyEndpointRequest(endpoint, result string) {
	authzPolicyEndpointRequestsTotal.WithLabelValues(endpoint, result).Inc()
}

func recordPolicyEndpointHealth(endpoint, result string) {
	authzPolicyEndpointHealthTotal.WithLabelValues(endpoint, result).Inc()
}

func recordPolicyEndpointAvailabilityState(endpoint string, value float64) {
	authzPolicyEndpointAvailabilityState.WithLabelValues(metricEndpoint(endpoint)).Set(value)
}

func RecordMessageSigned(broker string) {
	authzMessageSignedTotal.WithLabelValues(metricBrokerName(broker)).Inc()
}

func RecordMessageSignatureCheck(broker, result string) {
	authzMessageSignatureChecksTotal.WithLabelValues(metricBrokerName(broker), result).Inc()
}

func RecordMessageSignatureFailure(broker, reason string) {
	authzMessageSignatureFailuresTotal.WithLabelValues(metricBrokerName(broker), reason).Inc()
}

func RecordBrokerMessageProcessing(broker, result string) {
	authzBrokerMessageProcessingTotal.WithLabelValues(metricBrokerName(broker), result).Inc()
}

func RecordBrokerMessageRetried(broker, reason string) {
	authzBrokerMessagesRetriedTotal.WithLabelValues(metricBrokerName(broker), reason).Inc()
}

func RecordBrokerMessageDeadLettered(broker, reason string) {
	authzBrokerMessagesDeadLetteredTotal.WithLabelValues(metricBrokerName(broker), reason).Inc()
}

func RecordBrokerDLQPublishError(broker string) {
	authzBrokerDLQPublishErrorsTotal.WithLabelValues(metricBrokerName(broker)).Inc()
}

func RecordBrokerConsumeError(broker, reason string) {
	authzBrokerConsumeErrorsTotal.WithLabelValues(metricBrokerName(broker), reason).Inc()
}

func metricTransport(req AuthzRequest) string {
	req = req.Normalize()
	if req.Transport == "" {
		return "unknown"
	}
	return string(req.Transport)
}

func metricBroker(req AuthzRequest) string {
	req = req.Normalize()
	if req.Transport != TransportBroker || req.Broker == "" || req.Broker == "*" {
		return "none"
	}
	return req.Broker
}

func metricBrokerName(broker string) string {
	if broker == "" || broker == "*" {
		return "none"
	}
	return broker
}

func metricEndpoint(endpoint string) string {
	if endpoint == "" {
		return "0"
	}
	return endpoint
}
