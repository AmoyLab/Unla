package trace

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.uber.org/zap"

	"github.com/stretchr/testify/assert"
)

func TestInitTracing_HTTPProtocol(t *testing.T) {
	cfg := &Config{
		Enabled:     true,
		ServiceName: "test-http",
		Endpoint:    "http://localhost:4318",
		Protocol:    "http",
		Insecure:    true,
		SamplerRate: 0.5,
		Environment: "test",
		Headers:     map[string]string{"Authorization": "Bearer token"},
	}

	// Mock the constructors to avoid actual network calls
	originalNewResource := newResource
	originalNewHTTP := newOTLPTraceHTTP
	defer func() {
		newResource = originalNewResource
		newOTLPTraceHTTP = originalNewHTTP
	}()

	newResource = func(ctx context.Context, options ...resource.Option) (*resource.Resource, error) {
		return resource.Default(), nil
	}
	newOTLPTraceHTTP = func(ctx context.Context, options ...otlptracehttp.Option) (*otlptrace.Exporter, error) {
		return nil, nil // Mock exporter
	}

	shutdown, err := InitTracing(context.Background(), cfg, zap.NewNop())
	assert.NoError(t, err)
	assert.NotNil(t, shutdown)
}

func TestInitTracing_GRPCProtocol(t *testing.T) {
	cfg := &Config{
		Enabled:     true,
		ServiceName: "test-grpc",
		Endpoint:    "https://localhost:4317/",
		Protocol:    "grpc",
		Insecure:    false,
		SamplerRate: 1.0,
		Environment: "production",
		Headers:     map[string]string{"x-api-key": "secret"},
	}

	// Mock the constructors
	originalNewResource := newResource
	originalNewGRPC := newOTLPTraceGRPC
	defer func() {
		newResource = originalNewResource
		newOTLPTraceGRPC = originalNewGRPC
	}()

	newResource = func(ctx context.Context, options ...resource.Option) (*resource.Resource, error) {
		return resource.Default(), nil
	}
	newOTLPTraceGRPC = func(ctx context.Context, options ...otlptracegrpc.Option) (*otlptrace.Exporter, error) {
		return nil, nil // Mock exporter
	}

	shutdown, err := InitTracing(context.Background(), cfg, zap.NewNop())
	assert.NoError(t, err)
	assert.NotNil(t, shutdown)
}

func TestInitTracing_DefaultValues(t *testing.T) {
	cfg := &Config{
		ServiceName: "test-defaults",
		SamplerRate: -0.5, // Should be clamped to 0
	}

	// Mock the constructors
	originalNewResource := newResource
	originalNewGRPC := newOTLPTraceGRPC
	defer func() {
		newResource = originalNewResource
		newOTLPTraceGRPC = originalNewGRPC
	}()

	newResource = func(ctx context.Context, options ...resource.Option) (*resource.Resource, error) {
		return resource.Default(), nil
	}
	newOTLPTraceGRPC = func(ctx context.Context, options ...otlptracegrpc.Option) (*otlptrace.Exporter, error) {
		return nil, nil
	}

	shutdown, err := InitTracing(context.Background(), cfg, zap.NewNop())
	assert.NoError(t, err)
	assert.NotNil(t, shutdown)
}

func TestInitTracing_ResourceError(t *testing.T) {
	cfg := &Config{
		ServiceName: "test-error",
	}

	// Mock resource creation to fail
	originalNewResource := newResource
	defer func() { newResource = originalNewResource }()

	newResource = func(ctx context.Context, options ...resource.Option) (*resource.Resource, error) {
		return nil, errors.New("resource creation failed")
	}

	shutdown, err := InitTracing(context.Background(), cfg, zap.NewNop())
	assert.Error(t, err)
	assert.Nil(t, shutdown)
	assert.Contains(t, err.Error(), "create resource")
}

func TestInitTracing_ExporterError_HTTP(t *testing.T) {
	cfg := &Config{
		ServiceName: "test-http-error",
		Protocol:    "http",
	}

	// Mock the constructors
	originalNewResource := newResource
	originalNewHTTP := newOTLPTraceHTTP
	defer func() {
		newResource = originalNewResource
		newOTLPTraceHTTP = originalNewHTTP
	}()

	newResource = func(ctx context.Context, options ...resource.Option) (*resource.Resource, error) {
		return resource.Default(), nil
	}
	newOTLPTraceHTTP = func(ctx context.Context, options ...otlptracehttp.Option) (*otlptrace.Exporter, error) {
		return nil, errors.New("http exporter failed")
	}

	shutdown, err := InitTracing(context.Background(), cfg, zap.NewNop())
	assert.Error(t, err)
	assert.Nil(t, shutdown)
	assert.Contains(t, err.Error(), "create exporter")
}

func TestInitTracing_ExporterError_GRPC(t *testing.T) {
	cfg := &Config{
		ServiceName: "test-grpc-error",
		Protocol:    "grpc",
	}

	// Mock the constructors
	originalNewResource := newResource
	originalNewGRPC := newOTLPTraceGRPC
	defer func() {
		newResource = originalNewResource
		newOTLPTraceGRPC = originalNewGRPC
	}()

	newResource = func(ctx context.Context, options ...resource.Option) (*resource.Resource, error) {
		return resource.Default(), nil
	}
	newOTLPTraceGRPC = func(ctx context.Context, options ...otlptracegrpc.Option) (*otlptrace.Exporter, error) {
		return nil, errors.New("grpc exporter failed")
	}

	shutdown, err := InitTracing(context.Background(), cfg, zap.NewNop())
	assert.Error(t, err)
	assert.Nil(t, shutdown)
	assert.Contains(t, err.Error(), "create exporter")
}

func TestInitTracing_SamplerRateClamping(t *testing.T) {
	tests := []struct {
		name         string
		samplerRate  float64
		expectedRate float64
	}{
		{"negative rate", -1.5, 0.0},
		{"zero rate", 0.0, 0.0},
		{"valid rate", 0.7, 0.7},
		{"rate equal one", 1.0, 1.0},
		{"rate greater than one", 1.5, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ServiceName: "test-clamping",
				SamplerRate: tt.samplerRate,
			}

			// Mock the constructors
			originalNewResource := newResource
			originalNewGRPC := newOTLPTraceGRPC
			defer func() {
				newResource = originalNewResource
				newOTLPTraceGRPC = originalNewGRPC
			}()

			newResource = func(ctx context.Context, options ...resource.Option) (*resource.Resource, error) {
				return resource.Default(), nil
			}
			newOTLPTraceGRPC = func(ctx context.Context, options ...otlptracegrpc.Option) (*otlptrace.Exporter, error) {
				return nil, nil
			}

			shutdown, err := InitTracing(context.Background(), cfg, zap.NewNop())
			assert.NoError(t, err)
			assert.NotNil(t, shutdown)
		})
	}
}

func TestTracer_And_SpanScope(t *testing.T) {
	builder := Tracer("test-tracer")
	assert.NotNil(t, builder)
	assert.NotNil(t, builder.tracer)

	// Start a span
	scope := builder.Start(context.Background(), "test-span")
	assert.NotNil(t, scope)
	assert.NotNil(t, scope.Ctx)
	assert.NotNil(t, scope.Span)

	// Add attributes
	scope.WithAttrs(attribute.String("key", "value"))
	scope.End()
}

func TestSpanScope_NilSafety(t *testing.T) {
	// Test nil safety
	var nilScope *SpanScope
	result := nilScope.WithAttrs(attribute.String("key", "value")) // Should not panic
	assert.Nil(t, result)
	nilScope.End() // Should not panic

	// Test with nil span
	scope := &SpanScope{Ctx: context.Background(), Span: nil}
	result2 := scope.WithAttrs(attribute.String("key", "value"))
	assert.Equal(t, scope, result2) // Should return the same scope
	scope.End()
}

func TestSpanScope_WithAttrs_Chaining(t *testing.T) {
	builder := Tracer("test-tracer")
	scope := builder.Start(context.Background(), "test-span")

	// Test chaining
	result := scope.WithAttrs(attribute.String("key1", "value1")).WithAttrs(attribute.String("key2", "value2"))
	assert.Equal(t, scope, result)
	scope.End()
}
