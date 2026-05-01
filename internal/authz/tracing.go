package authz

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName            = "authz-system"
	tracingExporterNone   = "none"
	tracingExporterOTLP   = "otlp"
	tracingExporterStdout = "stdout"
)

type TracingConfig struct {
	Enabled      bool
	ServiceName  string
	Exporter     string
	OTLPEndpoint string
}

func TracingConfigFromEnv(defaultServiceName string) TracingConfig {
	enabled := boolEnv("OTEL_ENABLED", false)
	serviceName := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME"))
	if serviceName == "" {
		serviceName = defaultServiceName
	}
	exporter := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_EXPORTER")))
	if exporter == "" {
		exporter = tracingExporterStdout
	}
	return TracingConfig{
		Enabled:      enabled,
		ServiceName:  serviceName,
		Exporter:     exporter,
		OTLPEndpoint: strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")),
	}
}

func InitTracingFromEnv(ctx context.Context, defaultServiceName string) (func(context.Context) error, error) {
	return InitTracing(ctx, TracingConfigFromEnv(defaultServiceName))
}

func InitTracing(ctx context.Context, cfg TracingConfig) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(defaultTextMapPropagator())
	if !cfg.Enabled || strings.EqualFold(cfg.Exporter, tracingExporterNone) {
		return func(context.Context) error { return nil }, nil
	}

	if cfg.ServiceName == "" {
		cfg.ServiceName = "authz-service"
	}

	exporter, err := newSpanExporter(ctx, cfg)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(ctx, resource.WithAttributes(attribute.String("service.name", cfg.ServiceName)))
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

func newSpanExporter(ctx context.Context, cfg TracingConfig) (sdktrace.SpanExporter, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Exporter)) {
	case "", tracingExporterStdout:
		return stdouttrace.New(stdouttrace.WithPrettyPrint())
	case tracingExporterOTLP:
		opts := []otlptracegrpc.Option{}
		if cfg.OTLPEndpoint != "" {
			opts = append(opts, otlptracegrpc.WithEndpoint(cfg.OTLPEndpoint))
		}
		if boolEnv("OTEL_EXPORTER_OTLP_INSECURE", true) {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		return otlptrace.New(ctx, otlptracegrpc.NewClient(opts...))
	default:
		return nil, errors.New("unsupported OTEL_EXPORTER: " + cfg.Exporter)
	}
}

func defaultTextMapPropagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
}

func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return otel.Tracer(tracerName).Start(ctx, name, trace.WithAttributes(attrs...))
}

func EndSpanWithResult(span trace.Span, result string, err error) {
	if result != "" {
		span.SetAttributes(attribute.String("authz.result", result))
	}
	if err != nil {
		span.SetStatus(codes.Error, safeErrorKind(err))
		return
	}
	span.SetStatus(codes.Ok, "")
}

func SafeAuthzAttrs(req AuthzRequest) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("authz.transport", metricTransport(req)),
		attribute.String("authz.broker", metricBroker(req)),
	}
}

func BrokerTraceAttrs(broker, operation string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("broker.name", metricBrokerName(broker)),
		attribute.String("broker.operation", operation),
	}
}

func InjectHTTP(ctx context.Context, header http.Header) {
	if header == nil {
		return
	}
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(header))
}

func ExtractHTTP(ctx context.Context, header http.Header) context.Context {
	if header == nil {
		return ctx
	}
	return otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(header))
}

func InjectTextMap(ctx context.Context, carrier propagation.TextMapCarrier) {
	if carrier == nil {
		return
	}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
}

func ExtractTextMap(ctx context.Context, carrier propagation.TextMapCarrier) context.Context {
	if carrier == nil {
		return ctx
	}
	return otel.GetTextMapPropagator().Extract(ctx, carrier)
}

func safeErrorKind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrDenied):
		return "denied"
	case errors.Is(err, ErrFailClosed), errors.Is(err, ErrPolicyUnavailable):
		return "policy_unavailable"
	default:
		return "error"
	}
}

func boolEnv(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}
