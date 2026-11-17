package core

import (
	"context"

	"github.com/amoylab/unla/internal/core/mcpproxy"
	"github.com/gin-gonic/gin"
)

// forwardCallHeaders relays the inbound caller Authorization to upstream
// requests for metadata methods (tools/list, resources/*) that carry no tool
// arguments, gated by the same forward configuration as tools/call.
func (s *Server) forwardCallHeaders(c *gin.Context) context.Context {
	if !s.forwardConfig.Enabled {
		return c.Request.Context()
	}
	// 仅转发调用方显式携带的 Authorization（tools/list、resources/read 等
	// 无工具参数的方法靠它把调用方身份带给受保护的上游）。
	if auth := c.Request.Header.Get("Authorization"); auth != "" {
		return mcpproxy.WithCallHeaders(c.Request.Context(), map[string]string{"Authorization": auth})
	}
	return c.Request.Context()
}
