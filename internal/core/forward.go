package core

import (
	"context"

	"github.com/amoylab/unla/internal/core/mcpproxy"
	"github.com/gin-gonic/gin"
)

// forwardCallHeaders relays the inbound caller Authorization header to
// upstream requests for metadata methods (tools/list, resources/*) that
// carry no tool arguments, so protected upstreams can authenticate the
// caller. It is gated by the same forward configuration as tools/call and
// honors the configured header allowlist/ignorelist policy.
func (s *Server) forwardCallHeaders(c *gin.Context) context.Context {
	if !s.forwardConfig.Enabled {
		return c.Request.Context()
	}
	// Only relay an Authorization the caller explicitly carried; skip it when
	// the configured header policy excludes it.
	if s.shouldIgnoreHeader("Authorization") {
		return c.Request.Context()
	}
	if auth := c.Request.Header.Get("Authorization"); auth != "" {
		return mcpproxy.WithCallHeaders(c.Request.Context(), map[string]string{"Authorization": auth})
	}
	return c.Request.Context()
}
