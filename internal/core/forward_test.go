package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/core/mcpproxy"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newForwardTestServer(t *testing.T, cfg config.ForwardConfig) *Server {
	t.Helper()
	s, err := NewServer(zap.NewNop(), 0, nil, nil, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	s.applyForwardConfig(cfg)
	return s
}

func TestForwardCallHeaders_PolicyGated(t *testing.T) {
	newCtx := func() *gin.Context {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/x/message", nil)
		c.Request.Header.Set("Authorization", "Bearer token")
		return c
	}

	// Forward disabled: nothing is relayed.
	s := newForwardTestServer(t, config.ForwardConfig{})
	assertNoForwardedHeaders(t, s.forwardCallHeaders(newCtx()))

	// Forward enabled with default policy: Authorization is relayed.
	s = newForwardTestServer(t, config.ForwardConfig{Enabled: true})
	ctx := s.forwardCallHeaders(newCtx())
	headers := mcpproxy.CallHeadersFromContext(ctx)
	if headers["Authorization"] != "Bearer token" {
		t.Fatalf("expected relayed Authorization, got %v", headers)
	}

	// Forward enabled but Authorization excluded via ignoreHeaders.
	ignored := config.ForwardConfig{Enabled: true}
	ignored.Header.IgnoreHeaders = "Authorization"
	s = newForwardTestServer(t, ignored)
	assertNoForwardedHeaders(t, s.forwardCallHeaders(newCtx()))

	// Forward enabled but Authorization excluded via allowHeaders.
	allowlisted := config.ForwardConfig{Enabled: true}
	allowlisted.Header.AllowHeaders = "X-Custom"
	s = newForwardTestServer(t, allowlisted)
	assertNoForwardedHeaders(t, s.forwardCallHeaders(newCtx()))
}

func assertNoForwardedHeaders(t *testing.T, ctx context.Context) {
	t.Helper()
	if headers := mcpproxy.CallHeadersFromContext(ctx); len(headers) != 0 {
		t.Fatalf("expected no forwarded headers, got %v", headers)
	}
}

func TestSessionMatchesURLPrefix(t *testing.T) {
	s, err := NewServer(zap.NewNop(), 0, nil, nil, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	newCtx := func(path string) *gin.Context {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, path, nil)
		return c
	}

	conn := &testFakeConn{meta: &session.Meta{Prefix: "/x"}}

	// Matching prefix passes.
	if !s.sessionMatchesURLPrefix(newCtx("/x/message"), conn, "message") {
		t.Fatal("expected matching prefix to pass")
	}
	// Mismatched prefix is rejected.
	if s.sessionMatchesURLPrefix(newCtx("/y/message"), conn, "message") {
		t.Fatal("expected mismatched prefix to be rejected")
	}
	// Wrong endpoint suffix is rejected.
	if s.sessionMatchesURLPrefix(newCtx("/x/other"), conn, "message") {
		t.Fatal("expected wrong endpoint to be rejected")
	}
	// Nil connection is rejected.
	if s.sessionMatchesURLPrefix(newCtx("/x/message"), nil, "message") {
		t.Fatal("expected nil connection to be rejected")
	}
}
