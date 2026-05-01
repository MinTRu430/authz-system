package authz

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestTracingDisabledDoesNotFail(t *testing.T) {
	shutdown, err := InitTracing(context.Background(), TracingConfig{Enabled: false, ServiceName: "test"})
	if err != nil {
		t.Fatalf("InitTracing disabled error = %v, want nil", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown disabled tracing error = %v, want nil", err)
	}
}

func TestTracingConfigFromEnv(t *testing.T) {
	t.Setenv("OTEL_ENABLED", "true")
	t.Setenv("OTEL_SERVICE_NAME", "payments")
	t.Setenv("OTEL_EXPORTER", "stdout")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector:4317")

	cfg := TracingConfigFromEnv("fallback")
	if !cfg.Enabled || cfg.ServiceName != "payments" || cfg.Exporter != "stdout" || cfg.OTLPEndpoint != "otel-collector:4317" {
		t.Fatalf("TracingConfigFromEnv = %+v", cfg)
	}
}

func TestStartSpanRecordsOnlySafeAuthzAttributes(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	otel.SetTracerProvider(tp)
	defer func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(noop.NewTracerProvider())
	}()

	req := AuthzRequest{
		Source:      "orders",
		Target:      "payments",
		Transport:   TransportBroker,
		Operation:   "publish",
		Resource:    "payments.requested",
		Broker:      "kafka",
		MessageType: "payment.requested.v1",
	}
	_, span := StartSpan(context.Background(), "authz.test", append(SafeAuthzAttrs(req), attribute.Bool("authz.cache_hit", true))...)
	EndSpanWithResult(span, "allow", nil)
	span.End()

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans = %d, want 1", len(spans))
	}
	attrs := spanAttributes(spans[0].Attributes)
	if attrs["authz.transport"] != "broker" || attrs["authz.broker"] != "kafka" || attrs["authz.cache_hit"] != "true" {
		t.Fatalf("safe attrs = %+v", attrs)
	}
	for _, forbidden := range []string{"authz.source", "authz.target", "authz.resource", "authz.message_type", "authz.signature", "payload"} {
		if _, ok := attrs[forbidden]; ok {
			t.Fatalf("unexpected sensitive attribute %q in %+v", forbidden, attrs)
		}
	}
}

func spanAttributes(attrs []attribute.KeyValue) map[string]string {
	out := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		out[string(attr.Key)] = attr.Value.Emit()
	}
	return out
}
