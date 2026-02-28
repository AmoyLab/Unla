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
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
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
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	conn := &fakeConnExec{meta: &session.Meta{ID: "sid", Request: &session.RequestInfo{Headers: map[string]string{"X-Req": "v"}}}}
	c, _ := gin.CreateTestContext(nil)
	c.Request = req
	res, err := s.executeHTTPTool(c, conn, tool, map[string]any{}, map[string]string{})
	assert.NoError(t, err)
	if assert.NotNil(t, res) {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			assert.Equal(t, `{"hello":"world"}`, tc.Text)
		} else {
			t.Fatalf("unexpected content type")
		}
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
