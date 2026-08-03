package core

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/core/state"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newStreamablePostContext(body string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/gateway/test/mcp?source=unit", bytes.NewBufferString(body))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	return c, w
}

func setModernHeaders(c *gin.Context, method string, name ...string) {
	c.Request.Header.Set(mcp.HeaderMCPProtocolVersion, mcp.ProtocolVersion20260728)
	c.Request.Header.Set(mcp.HeaderMCPMethod, method)
	if len(name) > 0 {
		c.Request.Header.Set(mcp.HeaderMCPName, name[0])
	}
}

func modernParams(extra string) string {
	if extra != "" {
		extra = "," + extra
	}
	return `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}` + extra
}

func TestModernStreamableServerDiscover(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":"discover-1","method":"server/discover","params":{` + modernParams("") + `}}`
	c, w := newStreamablePostContext(body)
	setModernHeaders(c, mcp.ServerDiscover)

	s := &Server{logger: zap.NewNop()}
	s.handlePost(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Result().Header.Get(mcp.HeaderMcpSessionID))
	assert.Contains(t, w.Result().Header.Get("Content-Type"), "application/json")

	var resp mcp.JSONRPCResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	result, ok := resp.Result.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "complete", result["resultType"])
	assert.Contains(t, result["supportedVersions"], mcp.ProtocolVersion20260728)
}

func TestModernStreamableToolsListWithoutSession(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + modernParams("") + `}}`
	c, w := newStreamablePostContext(body)
	setModernHeaders(c, mcp.ToolsList)
	c.Request.AddCookie(&http.Cookie{Name: "tenant", Value: "t1"})

	st, err := state.BuildStateFromConfig(context.Background(), []*config.MCPConfig{{
		Name:   "cfg",
		Tenant: "default",
		Routers: []config.RouterConfig{{
			Server: "svc",
			Prefix: "/gateway/test",
		}},
		Servers: []config.ServerConfig{{
			Name:         "svc",
			AllowedTools: []string{"echo"},
		}},
		Tools: []config.ToolConfig{{
			Name:        "echo",
			Description: "Echo input",
			Method:      http.MethodGet,
			Endpoint:    "http://127.0.0.1/echo",
		}},
	}}, nil, zap.NewNop())
	require.NoError(t, err)

	s := &Server{logger: zap.NewNop(), state: st}
	s.handlePost(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Result().Header.Get(mcp.HeaderMcpSessionID))

	var decoded struct {
		Result struct {
			ResultType string           `json:"resultType"`
			TTLMS      int              `json:"ttlMs"`
			CacheScope string           `json:"cacheScope"`
			Tools      []mcp.ToolSchema `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &decoded))
	assert.Equal(t, "complete", decoded.Result.ResultType)
	assert.Equal(t, 60_000, decoded.Result.TTLMS)
	assert.Equal(t, "private", decoded.Result.CacheScope)
	require.Len(t, decoded.Result.Tools, 1)
	assert.Equal(t, "echo", decoded.Result.Tools[0].Name)
}

func TestModernStreamableHeadersAreCaseInsensitive(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + modernParams("") + `}}`
	c, w := newStreamablePostContext(body)
	c.Request.Header.Set("mcp-protocol-version", mcp.ProtocolVersion20260728)
	c.Request.Header.Set("mcp-method", mcp.ServerDiscover)

	s := &Server{logger: zap.NewNop()}
	s.handlePost(c)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestModernStreamableHeaderMismatch(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + modernParams("") + `}}`
	c, w := newStreamablePostContext(body)
	c.Request.Header.Set(mcp.HeaderMCPProtocolVersion, mcp.ProtocolVersion20260728)

	s := &Server{logger: zap.NewNop()}
	s.handlePost(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp mcp.JSONRPCErrorSchema
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, mcp.ErrorCodeHeaderMismatch, resp.Error.Code)
}

func TestModernStreamableUnsupportedProtocolVersion(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`
	c, w := newStreamablePostContext(body)
	c.Request.Header.Set(mcp.HeaderMCPProtocolVersion, "1900-01-01")
	c.Request.Header.Set(mcp.HeaderMCPMethod, mcp.ToolsList)

	s := &Server{logger: zap.NewNop()}
	s.handlePost(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp mcp.JSONRPCErrorSchema
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, mcp.ErrorCodeUnsupportedProtocolVersion, resp.Error.Code)
	assert.NotNil(t, resp.Error.Data)
}

func TestLegacyStreamableInitializeStillCreatesSession(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"legacy","version":"1"}}}`
	c, w := newStreamablePostContext(body)

	s := &Server{logger: zap.NewNop(), sessions: session.NewMemoryStore(zap.NewNop())}
	s.handlePost(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Result().Header.Get(mcp.HeaderMcpSessionID))
	assert.Contains(t, w.Body.String(), "event: message")
}
