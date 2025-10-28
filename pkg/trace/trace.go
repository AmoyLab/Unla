package trace

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// testable indirections for constructors
var (
	newResource      = resource.New
	newOTLPTraceHTTP = otlptracehttp.New
	newOTLPTraceGRPC = otlptracegrpc.New
)

// Config represents OpenTelemetry/Jaeger tracing configuration
type Config struct {
	Enabled     bool              `yaml:"enabled"`
	ServiceName string            `yaml:"service_name"`
	Endpoint    string            `yaml:"endpoint"`     // e.g. localhost:4317 or http://localhost:4318
	Protocol    string            `yaml:"protocol"`     // grpc or http
	Insecure    bool              `yaml:"insecure"`     // allow insecure connection
	SamplerRate float64           `yaml:"sampler_rate"` // 0.0~1.0
	Environment string            `yaml:"environment"`  // env tag: dev/staging/prod
	Headers     map[string]string `yaml:"headers"`
	Capture     CaptureConfig     `yaml:"capture"`
}

// CaptureConfig controls extra trace capture behavior
type CaptureConfig struct {
	DownstreamError struct {
		Enabled       bool `yaml:"enabled"`
		MaxBodyLength int  `yaml:"max_body_length"`
	} `yaml:"downstream_error"`
	DownstreamRequest struct {
		Enabled        bool      `yaml:"enabled"`
		IncludeFields  StringMap `yaml:"include_fields"`
		MaxFieldLength int       `yaml:"max_field_length"`
		BodyEnabled    bool      `yaml:"body_enabled"`
		BodyMaxLength  int       `yaml:"body_max_length"`
	} `yaml:"downstream_request"`
}

// StringMap is a generic map[string]string type that supports:
// 1. YAML maps
// 2. JSON strings
// 3. CSV strings like "k1=v1,k2=v2"
type StringMap map[string]string

func (m *StringMap) UnmarshalYAML(value *yaml.Node) error {

	// 1. Try to decode as plain string
	var raw string
	if err := value.Decode(&raw); err == nil {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			*m = make(map[string]string)
			return nil
		}

		// 2. Try JSON string
		if strings.HasPrefix(raw, "{") {
			var tmp map[string]string
			if err := json.Unmarshal([]byte(raw), &tmp); err == nil {
				*m = tmp
				return nil
			} else {
			}
		}

		// 3. Try CSV format: key1=value1,key2=value2
		tmp := make(map[string]string)
		pairs := strings.Split(raw, ",")
		for _, p := range pairs {
			kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
			if len(kv) == 2 {
				tmp[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			} else {
			}
		}
		*m = tmp
		return nil
	}

	// 4. Fallback: decode as YAML map and convert values to string
	tmp := make(map[string]interface{})
	if err := value.Decode(&tmp); err != nil {
		return err
	}
	res := make(map[string]string, len(tmp))
	for k, v := range tmp {
		res[k] = fmt.Sprintf("%v", v)
	}
	*m = res
	return nil
}

// InitTracing initializes OpenTelemetry tracing and returns a shutdown func
func InitTracing(ctx context.Context, cfg *Config, lg *zap.Logger) (func(context.Context) error, error) {
	// Defaults
	serviceName := cfg.ServiceName
	protocol := cfg.Protocol
	if protocol == "" {
		protocol = "grpc"
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		if protocol == "http" {
			endpoint = "http://localhost:4318"
		} else {
			endpoint = "localhost:4317"
		}
	}

	// Normalize endpoint: strip http/https scheme if present, since exporters
	// expect plain host[:port] and infer scheme from options (e.g. Insecure).
	if protocol == "grpc" {
		endpoint = strings.TrimPrefix(endpoint, "http://")
		endpoint = strings.TrimPrefix(endpoint, "https://")
		endpoint = strings.TrimSuffix(endpoint, "/")
	}

	// Resource with service metadata
	res, err := newResource(ctx,
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.DeploymentEnvironment(cfg.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create resource: %w", err)
	}

	// Exporter
	var exp *otlptrace.Exporter
	switch protocol {
	case "http":
		opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
		if cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
		}
		exp, err = newOTLPTraceHTTP(ctx, opts...)
	default: // grpc
		opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(endpoint)}
		if cfg.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(cfg.Headers))
		}
		exp, err = newOTLPTraceGRPC(ctx, opts...)
	}
	if err != nil {
		return nil, fmt.Errorf("create exporter: %w", err)
	}

	// Sampler
	rate := cfg.SamplerRate
	if rate < 0 {
		rate = 0
	}
	if rate > 1 {
		rate = 1
	}
	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(rate))

	// Tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	lg.Debug("OpenTelemetry tracer initialized",
		zap.String("endpoint", endpoint),
		zap.String("protocol", protocol),
		zap.Float64("sampler_rate", rate),
	)

	return tp.Shutdown, nil
}

// Builder is a small wrapper to access a named tracer with fluent helpers
type Builder struct {
	tracer trace.Tracer
}

// Tracer creates a Builder for a named tracer
func Tracer(name string) *Builder {
	return &Builder{tracer: otel.Tracer(name)}
}

// SpanScope holds span and context, with fluent helpers
type SpanScope struct {
	Ctx  context.Context
	Span trace.Span
}

// Start starts a new span and returns a scope
func (b *Builder) Start(ctx context.Context, spanName string, opts ...trace.SpanStartOption) *SpanScope {
	nctx, sp := b.tracer.Start(ctx, spanName, opts...)
	return &SpanScope{Ctx: nctx, Span: sp}
}

// WithAttrs sets attributes on the span and returns the scope for chaining
func (s *SpanScope) WithAttrs(attrs ...attribute.KeyValue) *SpanScope {
	if s != nil && s.Span != nil {
		s.Span.SetAttributes(attrs...)
	}
	return s
}

// End ends the span if present
func (s *SpanScope) End() {
	if s != nil && s.Span != nil {
		s.Span.End()
	}
}
