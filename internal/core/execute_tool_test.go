package core

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/andybalholm/brotli"
	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type fakeConnExec struct{ meta *session.Meta }

func (f *fakeConnExec) EventQueue() <-chan *session.Message                  { return nil }
func (f *fakeConnExec) Send(ctx context.Context, msg *session.Message) error { return nil }
func (f *fakeConnExec) Close(ctx context.Context) error                      { return nil }
func (f *fakeConnExec) Meta() *session.Meta                                  { return f.meta }

func TestExecuteHTTPTool_Success(t *testing.T) {
	// downstream returns JSON
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hello":"world"}`))
	}))
	defer srv.Close()

	allowlist, _ := parseInternalNetworkAllowlist([]string{"127.0.0.0/8", "::1/128"})
	s := &Server{logger: zap.NewNop(), toolRespHandler: CreateResponseHandlerChain(), internalNetACL: allowlist}
	tool := &config.ToolConfig{
		Name:         "t",
		Method:       http.MethodGet,
		Endpoint:     srv.URL,
		ResponseBody: "{{.Response.Body}}",
		Meta: map[string]any{
			"contains_pii": true,
			"data_level":   "sensitive",
		},
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	conn := &fakeConnExec{meta: &session.Meta{ID: "sid", Request: &session.RequestInfo{Headers: map[string]string{"X-Req": "v"}}}}
	c, _ := gin.CreateTestContext(nil)
	c.Request = req
	res, err := s.executeHTTPTool(c, conn, tool, map[string]any{}, map[string]string{})
	assert.NoError(t, err)
	if assert.NotNil(t, res) {
		assert.Equal(t, map[string]any{
			"contains_pii": true,
			"data_level":   "sensitive",
		}, res.Meta)
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			assert.Equal(t, `{"hello":"world"}`, tc.Text)
		} else {
			t.Fatalf("unexpected content type")
		}
	}
}

func TestExecuteHTTPTool_DownstreamErrorResultIncludesMeta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid user"}`))
	}))
	defer srv.Close()

	allowlist, _ := parseInternalNetworkAllowlist([]string{"127.0.0.0/8", "::1/128"})
	s := &Server{logger: zap.NewNop(), toolRespHandler: CreateResponseHandlerChain(), internalNetACL: allowlist}
	tool := &config.ToolConfig{
		Name:         "sensitive",
		Method:       http.MethodGet,
		Endpoint:     srv.URL,
		ResponseBody: "{{.Response.Body}}",
		Meta: map[string]any{
			"contains_pii": true,
		},
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	conn := &fakeConnExec{meta: &session.Meta{ID: "sid", Request: &session.RequestInfo{Headers: map[string]string{}}}}
	c, _ := gin.CreateTestContext(nil)
	c.Request = req

	res, err := s.executeHTTPTool(c, conn, tool, map[string]any{}, map[string]string{})

	assert.NoError(t, err)
	if assert.NotNil(t, res) {
		assert.True(t, res.IsError)
		assert.Equal(t, map[string]any{"contains_pii": true}, res.Meta)
	}
}

func TestExecuteHTTPTool_ForwardHeadersAndRequestError(t *testing.T) {
	s := &Server{logger: zap.NewNop(), toolRespHandler: CreateResponseHandlerChain(), forwardConfig: config.ForwardConfig{Enabled: true}}
	s.forwardConfig.McpArg.KeyForHeader = "_hdr"
	tool := &config.ToolConfig{
		Name:         "t",
		Method:       http.MethodGet,
		Endpoint:     "http://127.0.0.1:0", // invalid port triggers dial error
		ResponseBody: "{{.Response.Body}}",
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example", nil)
	conn := &fakeConnExec{meta: &session.Meta{ID: "sid", Request: &session.RequestInfo{Headers: map[string]string{}}}}
	c, _ := gin.CreateTestContext(nil)
	c.Request = req

	args := map[string]any{
		"_hdr": map[string]any{"X-A": "B"},
	}

	res, err := s.executeHTTPTool(c, conn, tool, args, map[string]string{})
	assert.Error(t, err)
	assert.Nil(t, res)
}

func TestExecuteHTTPTool_GzipResponse(t *testing.T) {
	// downstream returns gzip-compressed JSON
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write([]byte(`{"hello":"gzip"}`))
		_ = gz.Close()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	allowlist, _ := parseInternalNetworkAllowlist([]string{"127.0.0.0/8", "::1/128"})
	s := &Server{logger: zap.NewNop(), toolRespHandler: CreateResponseHandlerChain(), internalNetACL: allowlist}
	tool := &config.ToolConfig{
		Name:         "t",
		Method:       http.MethodGet,
		Endpoint:     srv.URL,
		Headers:      map[string]string{"Accept-Encoding": "gzip"},
		ResponseBody: "{{.Response.Body}}",
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	conn := &fakeConnExec{meta: &session.Meta{ID: "sid", Request: &session.RequestInfo{Headers: map[string]string{"X-Req": "v"}}}}
	c, _ := gin.CreateTestContext(nil)
	c.Request = req

	res, err := s.executeHTTPTool(c, conn, tool, map[string]any{}, map[string]string{})
	assert.NoError(t, err)
	if assert.NotNil(t, res) {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			assert.Equal(t, `{"hello":"gzip"}`, tc.Text)
		} else {
			t.Fatalf("unexpected content type")
		}
	}
}

func TestReadDecodedResponseBody_GzipInvalidData(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{"Content-Encoding": []string{"gzip"}},
		Body:   io.NopCloser(bytes.NewBufferString("not-gzip-data")),
	}

	_, err := readDecodedResponseBody(resp)
	assert.Error(t, err)
}

func TestExecuteHTTPTool_BrotliResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		br := brotli.NewWriter(&buf)
		_, _ = br.Write([]byte(`{"hello":"brotli"}`))
		_ = br.Close()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	allowlist, _ := parseInternalNetworkAllowlist([]string{"127.0.0.0/8", "::1/128"})
	s := &Server{logger: zap.NewNop(), toolRespHandler: CreateResponseHandlerChain(), internalNetACL: allowlist}
	tool := &config.ToolConfig{Name: "t", Method: http.MethodGet, Endpoint: srv.URL, ResponseBody: "{{.Response.Body}}"}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	conn := &fakeConnExec{meta: &session.Meta{ID: "sid", Request: &session.RequestInfo{Headers: map[string]string{}}}}
	c, _ := gin.CreateTestContext(nil)
	c.Request = req

	res, err := s.executeHTTPTool(c, conn, tool, map[string]any{}, map[string]string{})
	assert.NoError(t, err)
	if assert.NotNil(t, res) {
		tc, ok := res.Content[0].(*mcp.TextContent)
		if !ok {
			t.Fatalf("unexpected content type")
		}
		assert.Equal(t, `{"hello":"brotli"}`, tc.Text)
	}
}

func TestExecuteHTTPTool_ZstdResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw, err := zstd.NewWriter(&buf)
		assert.NoError(t, err)
		_, _ = zw.Write([]byte(`{"hello":"zstd"}`))
		zw.Close()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "zstd")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	allowlist, _ := parseInternalNetworkAllowlist([]string{"127.0.0.0/8", "::1/128"})
	s := &Server{logger: zap.NewNop(), toolRespHandler: CreateResponseHandlerChain(), internalNetACL: allowlist}
	tool := &config.ToolConfig{Name: "t", Method: http.MethodGet, Endpoint: srv.URL, ResponseBody: "{{.Response.Body}}"}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	conn := &fakeConnExec{meta: &session.Meta{ID: "sid", Request: &session.RequestInfo{Headers: map[string]string{}}}}
	c, _ := gin.CreateTestContext(nil)
	c.Request = req

	res, err := s.executeHTTPTool(c, conn, tool, map[string]any{}, map[string]string{})
	assert.NoError(t, err)
	if assert.NotNil(t, res) {
		tc, ok := res.Content[0].(*mcp.TextContent)
		if !ok {
			t.Fatalf("unexpected content type")
		}
		assert.Equal(t, `{"hello":"zstd"}`, tc.Text)
	}
}

func TestExecuteHTTPTool_DeflateResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		_, _ = zw.Write([]byte(`{"hello":"deflate"}`))
		_ = zw.Close()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "deflate")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	allowlist, _ := parseInternalNetworkAllowlist([]string{"127.0.0.0/8", "::1/128"})
	s := &Server{logger: zap.NewNop(), toolRespHandler: CreateResponseHandlerChain(), internalNetACL: allowlist}
	tool := &config.ToolConfig{Name: "t", Method: http.MethodGet, Endpoint: srv.URL, ResponseBody: "{{.Response.Body}}"}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	conn := &fakeConnExec{meta: &session.Meta{ID: "sid", Request: &session.RequestInfo{Headers: map[string]string{}}}}
	c, _ := gin.CreateTestContext(nil)
	c.Request = req

	res, err := s.executeHTTPTool(c, conn, tool, map[string]any{}, map[string]string{})
	assert.NoError(t, err)
	if assert.NotNil(t, res) {
		tc, ok := res.Content[0].(*mcp.TextContent)
		if !ok {
			t.Fatalf("unexpected content type")
		}
		assert.Equal(t, `{"hello":"deflate"}`, tc.Text)
	}
}

func TestReadDecodedResponseBody_DeflateRaw(t *testing.T) {
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	assert.NoError(t, err)
	_, _ = fw.Write([]byte(`{"hello":"raw-deflate"}`))
	_ = fw.Close()

	resp := &http.Response{
		Header: http.Header{"Content-Encoding": []string{"deflate"}},
		Body:   io.NopCloser(bytes.NewReader(buf.Bytes())),
	}

	body, err := readDecodedResponseBody(resp)
	assert.NoError(t, err)
	assert.Equal(t, `{"hello":"raw-deflate"}`, string(body))
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
