package core

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

type marshalingTraceClient struct{}

func (*marshalingTraceClient) Start(context.Context) error { return nil }
func (*marshalingTraceClient) Stop(context.Context) error  { return nil }
func (*marshalingTraceClient) UploadTraces(_ context.Context, spans []*tracepb.ResourceSpans) error {
	_, err := proto.Marshal(&collector.ExportTraceServiceRequest{ResourceSpans: spans})
	return err
}

func recordTraceSpans(t *testing.T) (*sdktrace.TracerProvider, *tracetest.SpanRecorder) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		require.NoError(t, provider.Shutdown(context.Background()))
	})
	return provider, recorder
}

func requireOTLPExport(t *testing.T, spans []sdktrace.ReadOnlySpan) {
	t.Helper()
	require.NotEmpty(t, spans)
	exporter, err := otlptrace.New(context.Background(), &marshalingTraceClient{})
	require.NoError(t, err)
	defer func() { require.NoError(t, exporter.Shutdown(context.Background())) }()
	require.NoError(t, exporter.ExportSpans(context.Background(), spans))
}

func TestExecuteHTTPToolTraceUTF8(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		limit            int
	}{
		{"Chinese byte boundary", strings.Repeat("中", 100), strings.Repeat("中", 85), 256},
		{"emoji byte boundary", "a" + strings.Repeat("😀", 80), "a" + strings.Repeat("😀", 63), 256},
		{"invalid bytes", "a\xff\xfeb", "a�b", 256},
		{"unlimited invalid bytes", "a\xffb", "a�b", 0},
		{"negative limit", "a\xffb", "a�b", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, recorder := recordTraceSpans(t)
			received := make(chan string, 1)
			downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				received <- string(body)
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer downstream.Close()

			server := &Server{logger: zap.NewNop(), toolRespHandler: CreateResponseHandlerChain()}
			capture := &server.traceCapture
			capture.DownstreamRequest.Enabled = true
			capture.DownstreamRequest.IncludeFields = map[string]string{"text": "{{.Args.text}}"}
			capture.DownstreamRequest.MaxFieldLength = tc.limit
			capture.DownstreamRequest.BodyEnabled = true
			capture.DownstreamRequest.BodyMaxLength = tc.limit
			capture.DownstreamError.Enabled = true
			capture.DownstreamError.MaxBodyLength = tc.limit
			capture.DownstreamResponse.Enabled = true
			capture.DownstreamResponse.MaxBodyLength = tc.limit
			tool := &config.ToolConfig{
				Name: "text", Method: http.MethodPost, Endpoint: downstream.URL,
				RequestBody: "{{.Args.text}}",
			}
			c, _ := newGin()
			conn := &fakeConnExec{meta: &session.Meta{ID: "sid", Request: &session.RequestInfo{Headers: map[string]string{}}}}
			result, err := server.executeHTTPTool(c, conn, tool, map[string]any{"text": tc.body}, nil)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tc.body, <-received)
			require.Len(t, result.Content, 1)
			content, ok := result.Content[0].(*mcp.TextContent)
			require.True(t, ok)
			assert.Equal(t, tc.body, content.Text)
			assert.True(t, result.IsError)

			spans := recorder.Ended()
			requireOTLPExport(t, spans)
			found := false
			for _, span := range spans {
				if span.Name() != cnst.SpanHTTPToolExecute {
					continue
				}
				found = true
				attrs := map[string]string{}
				for _, attr := range span.Attributes() {
					attrs[string(attr.Key)] = attr.Value.AsString()
				}
				for _, key := range []string{cnst.AttrDownstreamArgPrefix + "text", cnst.AttrDownstreamReqBody, cnst.AttrHTTPErrorPreview, cnst.AttrHTTPRespBody} {
					value, exists := attrs[key]
					require.True(t, exists, "missing attribute %s", key)
					assert.Equal(t, tc.want, value, key)
				}
			}
			require.True(t, found, "tool execution span missing")
		})
	}
}

func TestToolErrorTraceUTF8(t *testing.T) {
	for _, tc := range []struct{ name, message, want string }{
		{"Chinese byte boundary", "x" + strings.Repeat("中", 60), "x" + strings.Repeat("中", 39)},
		{"emoji byte boundary", "x" + strings.Repeat("😀", 60), "x" + strings.Repeat("😀", 29)},
		{"invalid bytes", "error: \xff", "error: �"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, recorder := recordTraceSpans(t)
			c, w := newGin()
			ctx, span := provider.Tracer("test").Start(c.Request.Context(), "tool error")
			c.Request = c.Request.WithContext(ctx)
			server := &Server{logger: zap.NewNop()}
			conn := &fakeConn{meta: &session.Meta{ID: "sid"}}
			server.sendToolExecutionError(c, conn, mcp.JSONRPCRequest{Id: 1, Method: mcp.ToolsCall}, errors.New(tc.message), nil, false)
			span.End()
			assert.Equal(t, http.StatusOK, w.Code)
			spans := recorder.Ended()
			require.Len(t, spans, 1)
			requireOTLPExport(t, spans)
			assert.Equal(t, tc.want, spans[0].Status().Description)
		})
	}
}

func TestProtocolErrorTraceUTF8(t *testing.T) {
	provider, recorder := recordTraceSpans(t)
	c, w := newGin()
	ctx, span := provider.Tracer("test").Start(c.Request.Context(), "protocol error")
	c.Request = c.Request.WithContext(ctx)
	server := &Server{logger: zap.NewNop()}
	server.sendProtocolError(c, 1, "invalid \xff", http.StatusBadRequest, mcp.ErrorCodeInvalidRequest)
	span.End()
	assert.Equal(t, http.StatusBadRequest, w.Code)
	spans := recorder.Ended()
	require.Len(t, spans, 1)
	requireOTLPExport(t, spans)
	assert.Equal(t, "invalid �", spans[0].Status().Description)
}

func TestTraceText(t *testing.T) {
	for _, tc := range []struct {
		name, text, want string
		limit            int
	}{
		{"empty", "", "", 1},
		{"ASCII", "abcdef", "abc", 3},
		{"exact boundary", "中", "中", 3},
		{"partial Chinese", "中文", "中", 4},
		{"no complete character", "中", "", 2},
		{"partial emoji", "a😀b", "a", 4},
		{"complete emoji", "a😀b", "a😀", 5},
		{"replacement byte budget", "a\xffb", "a", 3},
		{"replacement fits", "a\xffb", "a�", 4},
		{"valid replacement character", "�", "�", 3},
		{"invalid prefix", "\xffabc", "�abc", 0},
		{"invalid suffix", "abc\xff", "abc�", -1},
		{"incomplete input", "\xe4\xb8", "�", 0},
		{"unlimited Unicode", "中文😀", "中文😀", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := traceText(tc.text, tc.limit)
			assert.Equal(t, tc.want, got)
			assert.True(t, utf8.ValidString(got))
			if tc.limit > 0 {
				assert.LessOrEqual(t, len(got), tc.limit)
			}
		})
	}
}
