package core

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"testing"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/internal/template"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestShouldIgnoreHeader(t *testing.T) {
	s := &Server{forwardConfig: config.ForwardConfig{Enabled: true}, caseInsensitive: true, logger: zap.NewNop()}

	// allowHeaders take precedence
	s.allowHeaders = []string{"x-allow"}
	s.ignoreHeaders = []string{"x-ignore"}
	assert.True(t, s.shouldIgnoreHeader("X-Other"))
	assert.False(t, s.shouldIgnoreHeader("X-Allow"))
	assert.True(t, s.shouldIgnoreHeader("x-ignore"))

	// when allow list empty, use ignore list only
	s.allowHeaders = nil
	assert.True(t, s.shouldIgnoreHeader("x-ignore"))
	assert.False(t, s.shouldIgnoreHeader("x-zzz"))

	// when forward disabled, never ignore
	s.forwardConfig.Enabled = false
	assert.False(t, s.shouldIgnoreHeader("x-ignore"))
}

func TestProcessArguments(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	req := &http.Request{Header: http.Header{}, URL: u}
	tool := &config.ToolConfig{Args: []config.ArgConfig{
		{Name: "H1", Position: "header"},
		{Name: "q", Position: "query"},
		{Name: "f", Position: "form-data"},
	}}
	args := map[string]any{"H1": "v1", "q": "v2", "f": "v3"}
	processArguments(req, tool, args)
	assert.Equal(t, "v1", req.Header.Get("H1"))
	assert.Equal(t, "q=v2", req.URL.RawQuery)
	// form-data body present
	b, _ := io.ReadAll(req.Body)
	// Build expected multipart body prefix to avoid boundary issues
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("f", "v3")
	_ = w.Close()
	assert.Contains(t, string(b), "v3")
	assert.Contains(t, req.Header.Get("Content-Type"), "multipart/form-data; boundary=")
}

func TestPreprocessResponseData(t *testing.T) {
	input := map[string]any{
		"a": []any{1, 2},
		"b": map[string]any{"c": []any{"x"}},
		"d": "keep",
	}
	out := preprocessResponseData(input)
	// arrays become JSON strings
	assert.Equal(t, "[1,2]", out["a"])
	nested := out["b"].(map[string]any)
	assert.Equal(t, "[\"x\"]", nested["c"])
	assert.Equal(t, "keep", out["d"])
}

func TestFillDefaultArgs(t *testing.T) {
	tool := &config.ToolConfig{Args: []config.ArgConfig{{Name: "a", Default: "x"}, {Name: "b", Default: "y"}}}
	args := map[string]any{"b": "set"}
	fillDefaultArgs(tool, args)
	assert.Equal(t, "x", args["a"])
	assert.Equal(t, "set", args["b"])
}

func TestCreateHTTPClient(t *testing.T) {
	// default client when no proxy
	cli, err := createHTTPClient(nil)
	assert.NoError(t, err)
	assert.NotNil(t, cli)

	// http proxy
	cli2, err := createHTTPClient(&config.ToolConfig{Proxy: &config.ProxyConfig{Type: "http", Host: "127.0.0.1", Port: 8080}})
	assert.NoError(t, err)
	assert.NotNil(t, cli2)

	// socks5 proxy
	cli3, err := createHTTPClient(&config.ToolConfig{Proxy: &config.ProxyConfig{Type: "socks5", Host: "127.0.0.1", Port: 1080}})
	assert.NoError(t, err)
	assert.NotNil(t, cli3)

	// invalid proxy
	_, err = createHTTPClient(&config.ToolConfig{Proxy: &config.ProxyConfig{Type: "https", Host: "invalid host with space", Port: 1}})
	assert.Error(t, err)
}

func TestTransferForwardHeaders(t *testing.T) {
	s := &Server{forwardConfig: config.ForwardConfig{Enabled: true}, logger: zap.NewNop()}
	s.forwardConfig.McpArg.KeyForHeader = "_h"

	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// add without override (default false)
	args := map[string]any{"_h": map[string]any{"X": "1"}}
	s.transferForwardHeaders(args, req)
	assert.Empty(t, args["_h"]) // deleted
	assert.Equal(t, "1", req.Header.Get("X"))

	// add again with overrideExisting
	s.forwardConfig.Header.OverrideExisting = true
	args = map[string]any{"_h": map[string]any{"X": "2"}}
	s.transferForwardHeaders(args, req)
	assert.Equal(t, "2", req.Header.Get("X"))
}

func TestMergeRequestInfo(t *testing.T) {
	u, _ := url.Parse("http://example.com?a=1")
	req := &http.Request{Header: http.Header{"H": {"v"}}, URL: u}
	req.AddCookie(&http.Cookie{Name: "c", Value: "cv"})

	meta := &session.RequestInfo{Headers: map[string]string{"HX": "vx"}, Query: map[string]string{"qq": "vv"}, Cookies: map[string]string{"cx": "vx"}}
	wrapper := mergeRequestInfo(meta, req)
	assert.Equal(t, "v", wrapper.Headers["H"])
	assert.Equal(t, "vx", wrapper.Headers["HX"])
	assert.Equal(t, "1", wrapper.Query["a"])
	assert.Equal(t, "vv", wrapper.Query["qq"])
	assert.Equal(t, "cv", wrapper.Cookies["c"])
	assert.Equal(t, "vx", wrapper.Cookies["cx"])
}

func TestPrepareRequest(t *testing.T) {
	s := &Server{logger: zap.NewNop(), forwardConfig: config.ForwardConfig{Enabled: true}, caseInsensitive: true}
	// Only allow H1 from context headers
	s.allowHeaders = []string{"h1"}

	tool := &config.ToolConfig{
		Name:        "t1",
		Method:      http.MethodPost,
		Endpoint:    "http://example.com/{{ .Args.k }}",
		Headers:     map[string]string{"H1": "override", "H3": "{{ .Args.k }}"},
		RequestBody: `{"a": "{{ .Args.k }}"}`,
	}

	ctx := template.NewContext()
	ctx.Args["k"] = "V"
	ctx.Request.Headers["H1"] = "ctx1"
	ctx.Request.Headers["H2"] = "ctx2"

	req, rendered, err := s.prepareRequest(tool, ctx)
	assert.NoError(t, err)
	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "http://example.com/V", req.URL.String())

	// Only H1 forwarded from context, but overridden by tool header
	assert.Equal(t, "override", req.Header.Get("H1"))
	// H2 should be ignored due to allow list
	assert.Empty(t, req.Header.Get("H2"))
	// H3 rendered from template
	assert.Equal(t, "V", req.Header.Get("H3"))

	b, _ := io.ReadAll(req.Body)
	assert.Equal(t, `{"a": "V"}`, string(b))
	// rendered body is returned for tracing capture
	assert.Equal(t, `{"a": "V"}`, rendered)
}
