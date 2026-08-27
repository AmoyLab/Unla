package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/core/state"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type fakeConn struct {
	meta    *session.Meta
	sent    []*session.Message
	sendErr error
}

func (f *fakeConn) EventQueue() <-chan *session.Message { return nil }
func (f *fakeConn) Send(ctx context.Context, msg *session.Message) error {
	f.sent = append(f.sent, msg)
	return f.sendErr
}
func (f *fakeConn) Close(ctx context.Context) error { return nil }
func (f *fakeConn) Meta() *session.Meta             { return f.meta }

func newGin() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	c.Request = req
	return c, w
}

func TestSendProtocolError(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	c, w := newGin()
	s.sendProtocolError(c, 1, "Bad", http.StatusBadRequest, mcp.ErrorCodeInvalidRequest)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body mcp.JSONRPCErrorSchema
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, mcp.JSPNRPCVersion, body.JSONRPC)
	assert.Equal(t, 1.0, body.ID) // gin/json encodes numeric as float64 when decoding to interface{}
	assert.Equal(t, mcp.ErrorCodeInvalidRequest, body.Error.Code)
}

func TestSendSuccessResponse_HTTP(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	c, w := newGin()
	conn := &fakeConn{meta: &session.Meta{ID: "sid"}}

	req := mcp.JSONRPCRequest{Id: 2, Method: "tools/call", JSONRPC: mcp.JSPNRPCVersion}
	result := mcp.NewCallToolResultText("ok")
	result.Meta = map[string]any{"contains_pii": true}
	s.sendSuccessResponse(c, conn, req, result, false)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/event-stream", w.Result().Header.Get("Content-Type"))
	assert.Equal(t, "sid", w.Result().Header.Get(mcp.HeaderMcpSessionID))
	payload := strings.TrimSpace(strings.TrimPrefix(w.Body.String(), "event: message\ndata: "))
	var response struct {
		Result struct {
			Meta map[string]any `json:"_meta"`
		} `json:"result"`
	}
	assert.NoError(t, json.Unmarshal([]byte(payload), &response))
	assert.Equal(t, map[string]any{"contains_pii": true}, response.Result.Meta)
}

func TestSendSuccessResponse_SSE(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	c, w := newGin()
	conn := &fakeConn{meta: &session.Meta{ID: "sid"}}
	req := mcp.JSONRPCRequest{Id: 3, Method: "tools/call", JSONRPC: mcp.JSPNRPCVersion}
	result := mcp.NewCallToolResultText("ok")
	result.Meta = map[string]any{"contains_pii": true}
	s.sendSuccessResponse(c, conn, req, result, true)
	assert.Equal(t, http.StatusAccepted, w.Code)
	if assert.Len(t, conn.sent, 1) {
		assert.Equal(t, "message", conn.sent[0].Event)
		var response struct {
			Result struct {
				Meta map[string]any `json:"_meta"`
			} `json:"result"`
		}
		assert.NoError(t, json.Unmarshal(conn.sent[0].Data, &response))
		assert.Equal(t, map[string]any{"contains_pii": true}, response.Result.Meta)
	}
}

func TestSendSuccessResponse_StatelessIncludesMeta(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	c, w := newGin()
	conn := newStatelessConnection(&session.Meta{ID: "stateless", Type: streamableStatelessType})
	req := mcp.JSONRPCRequest{Id: 4, Method: mcp.ToolsCall, JSONRPC: mcp.JSPNRPCVersion}
	result := mcp.NewCallToolResultText("ok")
	result.Meta = map[string]any{"contains_pii": true}

	s.sendSuccessResponse(c, conn, req, result, false)

	assert.Equal(t, http.StatusOK, w.Code)
	var response struct {
		Result struct {
			ResultType string         `json:"resultType"`
			Meta       map[string]any `json:"_meta"`
		} `json:"result"`
	}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, "complete", response.Result.ResultType)
	assert.Equal(t, map[string]any{"contains_pii": true}, response.Result.Meta)
}

func TestSendResponseMarshalError_HTTP(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	c, w := newGin()
	conn := &fakeConn{meta: &session.Meta{ID: "sid"}}

	// Channel cannot be marshaled by encoding/json
	type bad struct{ C chan int }
	s.sendResponse(c, 4, conn, bad{C: make(chan int)}, false)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSendResponseSSESendError(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	c, w := newGin()
	conn := &fakeConn{meta: &session.Meta{ID: "sid"}, sendErr: errors.New("boom")}
	s.sendResponse(c, 5, conn, mcp.NewCallToolResultText("ok"), true)
	// Should convert to protocol error
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSendToolExecutionError_HTTP(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	c, w := newGin()
	conn := &fakeConn{meta: &session.Meta{ID: "sid"}}
	req := mcp.JSONRPCRequest{Id: 6, Method: "tools/call", JSONRPC: mcp.JSPNRPCVersion}
	s.sendToolExecutionError(c, conn, req, errors.New("x"), map[string]any{
		"contains_pii": true,
		"data_level":   "sensitive",
	}, false)
	assert.Equal(t, http.StatusOK, w.Code)

	payload := strings.TrimSpace(strings.TrimPrefix(w.Body.String(), "event: message\ndata: "))
	var response struct {
		Result struct {
			IsError bool           `json:"isError"`
			Meta    map[string]any `json:"_meta"`
		} `json:"result"`
	}
	assert.NoError(t, json.Unmarshal([]byte(payload), &response))
	assert.True(t, response.Result.IsError)
	assert.Equal(t, map[string]any{
		"contains_pii": true,
		"data_level":   "sensitive",
	}, response.Result.Meta)
}

func TestCallHTTPToolExecutionErrorIncludesConfiguredMeta(t *testing.T) {
	st, err := state.BuildStateFromConfig(context.Background(), []*config.MCPConfig{{
		Name:   "cfg",
		Tenant: "default",
		Routers: []config.RouterConfig{{
			Server: "svc",
			Prefix: "/gateway/test",
		}},
		Servers: []config.ServerConfig{{
			Name:         "svc",
			AllowedTools: []string{"sensitive"},
		}},
		Tools: []config.ToolConfig{{
			Name:         "sensitive",
			Method:       http.MethodGet,
			Endpoint:     "http://127.0.0.1:0",
			ResponseBody: "{{.Response.Body}}",
			Meta: map[string]any{
				"contains_pii": true,
				"data_level":   "sensitive",
			},
		}},
	}}, nil, zap.NewNop())
	assert.NoError(t, err)

	allowlist, invalidEntries := parseInternalNetworkAllowlist([]string{"127.0.0.0/8"})
	assert.Empty(t, invalidEntries)
	s := &Server{
		logger:          zap.NewNop(),
		state:           st,
		toolRespHandler: CreateResponseHandlerChain(),
		internalNetACL:  allowlist,
	}
	c, w := newGin()
	conn := &fakeConn{meta: &session.Meta{
		ID:      "sid",
		Prefix:  "/gateway/test",
		Request: &session.RequestInfo{Headers: map[string]string{}},
	}}
	req := mcp.JSONRPCRequest{Id: 7, Method: mcp.ToolsCall, JSONRPC: mcp.JSPNRPCVersion}

	result := s.callHTTPTool(c, req, conn, mcp.CallToolParams{
		Name:      "sensitive",
		Arguments: json.RawMessage(`{}`),
	}, false)

	assert.Nil(t, result)
	assert.Equal(t, http.StatusOK, w.Code)
	payload := strings.TrimSpace(strings.TrimPrefix(w.Body.String(), "event: message\ndata: "))
	var response struct {
		Result struct {
			IsError bool           `json:"isError"`
			Meta    map[string]any `json:"_meta"`
		} `json:"result"`
	}
	assert.NoError(t, json.Unmarshal([]byte(payload), &response))
	assert.True(t, response.Result.IsError)
	assert.Equal(t, map[string]any{
		"contains_pii": true,
		"data_level":   "sensitive",
	}, response.Result.Meta)
}

func TestSendAcceptedResponse(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	c, w := newGin()

	// Test without logger in context
	s.sendAcceptedResponse(c)
	assert.Equal(t, http.StatusAccepted, w.Code)

	// Test with logger in context
	c2, w2 := newGin()
	c2.Set("logger", zap.NewNop())
	s.sendAcceptedResponse(c2)
	assert.Equal(t, http.StatusAccepted, w2.Code)
}
