package trace

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// helper structure for YAML decoding of StringMap
type cfgWithMap struct {
	M StringMap `yaml:"m"`
}

func TestStringMapUnmarshalYAML_VariousFormats(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		var c cfgWithMap
		err := yaml.Unmarshal([]byte("m: ''\n"), &c)
		require.NoError(t, err)
		require.NotNil(t, c.M)
		require.Len(t, c.M, 0)
	})

	t.Run("yaml sequence -> error", func(t *testing.T) {
		var c cfgWithMap
		err := yaml.Unmarshal([]byte("m:\n  - 1\n  - 2\n"), &c)
		require.Error(t, err)
	})

	// covers: JSON-looking string that isn't valid JSON, then CSV token without '='
	// exercises the error path after JSON unmarshal attempt and the len!=2 branch
	t.Run("json-like but invalid -> csv ignore bad", func(t *testing.T) {
		var c cfgWithMap
		// starts with '{' so JSON branch is attempted and fails; then CSV parsing runs
		// with a token lacking '=' which should be ignored
		err := yaml.Unmarshal([]byte("m: '{not json}, badtoken, k=v'\n"), &c)
		require.NoError(t, err)
		require.Equal(t, StringMap{"k": "v"}, c.M)
	})

	t.Run("json string", func(t *testing.T) {
		var c cfgWithMap
		err := yaml.Unmarshal([]byte("m: '{\"k1\":\"v1\",\"k2\":\"v2\"}'\n"), &c)
		require.NoError(t, err)
		require.Equal(t, StringMap{"k1": "v1", "k2": "v2"}, c.M)
	})

	t.Run("csv string", func(t *testing.T) {
		var c cfgWithMap
		err := yaml.Unmarshal([]byte("m: 'a=1, b=2, c = 3'\n"), &c)
		require.NoError(t, err)
		require.Equal(t, StringMap{"a": "1", "b": "2", "c": "3"}, c.M)
	})

	t.Run("yaml map", func(t *testing.T) {
		var c cfgWithMap
		err := yaml.Unmarshal([]byte("m:\n  x: 10\n  y: true\n  z: val\n"), &c)
		require.NoError(t, err)
		// values are stringified by UnmarshalYAML
		require.Equal(t, StringMap{"x": "10", "y": "true", "z": "val"}, c.M)
	})
}

func TestInitTracing_HTTP_NoopUsage(t *testing.T) {
	// Use HTTP protocol to avoid opening a gRPC connection in tests.
	cfg := &Config{
		Enabled:     true,
		ServiceName: "unla-test",
		Protocol:    "http",
		// leave Endpoint empty to exercise default path (http://localhost:4318)
		Insecure:    true,
		SamplerRate: 2.5, // will be clamped to 1.0
		Environment: "dev",
		Headers:     map[string]string{"x-test": "1"},
	}

	shutdown, err := InitTracing(context.Background(), cfg, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, shutdown)

	// Do not create spans here to avoid any export attempts.
	// Ensure global propagator/provider are set and then shutdown cleanly.
	_ = otel.GetTextMapPropagator()

	// Shutdown should not error when no spans were exported.
	require.NoError(t, shutdown(context.Background()))
}

func TestInitTracing_GRPC_Normalization_And_Shutdown(t *testing.T) {
	// Use gRPC protocol with endpoint containing scheme and trailing slash to
	// exercise the normalization logic. We set Insecure to true to avoid TLS.
	cfg := &Config{
		Enabled:     true,
		ServiceName: "unla-test",
		Protocol:    "grpc",
		Endpoint:    "http://localhost:4317/", // will be trimmed to localhost:4317
		Insecure:    true,
		SamplerRate: -1,                             // clamp to 0
		Headers:     map[string]string{"auth": "t"}, // cover grpc headers path
	}

	shutdown, err := InitTracing(context.Background(), cfg, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, shutdown)

	// Immediately shutdown; we don't export any spans to avoid network activity
	require.NoError(t, shutdown(context.Background()))
}

func TestInitTracing_GRPC_DefaultEndpoint_And_Shutdown(t *testing.T) {
	// Empty endpoint with grpc protocol should default to localhost:4317
	cfg := &Config{
		Enabled:     true,
		ServiceName: "unla-test",
		Protocol:    "grpc",
		Endpoint:    "",
		Insecure:    true,
	}

	shutdown, err := InitTracing(context.Background(), cfg, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	require.NoError(t, shutdown(context.Background()))
}

func TestInitTracing_DefaultProtocol_Empty_UsesGRPC(t *testing.T) {
	// Empty protocol should default to grpc and empty endpoint defaults too
	cfg := &Config{
		Enabled:     true,
		ServiceName: "unla-test",
		Protocol:    "",
		Endpoint:    "",
		Insecure:    true,
	}

	shutdown, err := InitTracing(context.Background(), cfg, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	require.NoError(t, shutdown(context.Background()))
}

func TestInitTracing_ResourceError_IsReturned(t *testing.T) {
	// Override newResource to simulate a construction error
	prev := newResource
	newResource = func(ctx context.Context, opts ...resource.Option) (*resource.Resource, error) {
		return nil, fmt.Errorf("boom")
	}
	t.Cleanup(func() { newResource = prev })

	cfg := &Config{ServiceName: "svc", Protocol: "http"}
	shutdown, err := InitTracing(context.Background(), cfg, zap.NewNop())
	require.Error(t, err)
	require.Nil(t, shutdown)
}

func TestInitTracing_ExporterError_IsReturned(t *testing.T) {
	// Override HTTP exporter constructor to simulate an error
	prev := newOTLPTraceHTTP
	newOTLPTraceHTTP = func(ctx context.Context, options ...otlptracehttp.Option) (*otlptrace.Exporter, error) {
		return nil, fmt.Errorf("no exporter")
	}
	t.Cleanup(func() { newOTLPTraceHTTP = prev })

	cfg := &Config{ServiceName: "svc", Protocol: "http"}
	shutdown, err := InitTracing(context.Background(), cfg, zap.NewNop())
	require.Error(t, err)
	require.Nil(t, shutdown)
}

func TestBuilder_Start_WithAttrs_End_WithInMemoryProvider(t *testing.T) {
	// Set up an in-memory recorder to validate span creation and attributes.
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(sr),
		sdktrace.WithResource(resource.Empty()),
	)
	// Save the previous provider and restore after test to avoid global leakage.
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})

	b := Tracer("trace-test")
	scope := b.Start(context.Background(), "op")
	require.NotNil(t, scope)
	scope = scope.WithAttrs(attribute.String("k", "v"))
	require.NotNil(t, scope)
	scope.End()

	// Validate one span recorded with the attribute.
	spans := sr.Ended()
	require.Len(t, spans, 1)

	attrs := spans[0].Attributes()
	// Find our attribute
	found := false
	for _, a := range attrs {
		if a.Key == "k" && a.Value.AsString() == "v" {
			found = true
			break
		}
	}
	require.True(t, found, "expected attribute k=v to be set on span")
}
