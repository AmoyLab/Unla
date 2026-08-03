package core

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// sendProtocolError sends a protocol-level error response
func (s *Server) sendProtocolError(c *gin.Context, id any, message string, statusCode int, bizCode int) {
	s.sendProtocolErrorWithData(c, id, message, statusCode, bizCode, nil)
}

func (s *Server) sendProtocolErrorWithData(c *gin.Context, id any, message string, statusCode int, bizCode int, data any) {
	logger := s.getLogger(c)
	logger.Warn("sending protocol error",
		zap.Any("id", id),
		zap.String("message", message),
		zap.Int("status_code", statusCode),
		zap.Int("error_code", bizCode),
		zap.String("remote_addr", c.Request.RemoteAddr),
	)

	// Annotate active span with a concise error reason for observability
	if span := oteltrace.SpanFromContext(c.Request.Context()); span != nil {
		span.SetStatus(codes.Error, message)
		span.SetAttributes(
			attribute.String(cnst.AttrErrorReason, message),
			attribute.Int(cnst.AttrMCPErrorCode, bizCode),
		)
	}

	response := mcp.JSONRPCErrorSchema{
		JSONRPCBaseResult: mcp.JSONRPCBaseResult{
			JSONRPC: mcp.JSPNRPCVersion,
			ID:      id,
		},
		Error: mcp.JSONRPCError{
			Code:    bizCode,
			Message: message,
			Data:    data,
		},
	}
	c.JSON(statusCode, response)
}

// sendToolExecutionError sends a tool execution error response
func (s *Server) sendToolExecutionError(c *gin.Context, conn session.Connection, req mcp.JSONRPCRequest, err error, isSSE bool) {
	logger := s.getLogger(c)
	logger.Error("tool execution error",
		zap.Any("request_id", req.Id),
		zap.String("method", req.Method),
		zap.String("session_id", conn.Meta().ID),
		zap.Error(err),
		zap.Bool("is_sse", isSSE),
	)

	// Tag current HTTP span with a brief error reason; keep it concise
	if span := oteltrace.SpanFromContext(c.Request.Context()); span != nil {
		reason := err.Error()
		if len(reason) > 120 { // avoid long logs in traces
			reason = reason[:120]
		}
		span.SetStatus(codes.Error, reason)
		span.SetAttributes(
			attribute.String(cnst.AttrErrorReason, reason),
		)
	}

	response := mcp.JSONRPCResponse{
		JSONRPCBaseResult: mcp.JSONRPCBaseResult{
			JSONRPC: mcp.JSPNRPCVersion,
			ID:      req.Id,
		},
		Result: mcp.NewCallToolResultError(fmt.Sprintf("Error: %s", err.Error())),
	}
	s.sendResponse(c, req.Id, conn, response, isSSE)
}

// sendSuccessResponse sends a successful response
func (s *Server) sendSuccessResponse(c *gin.Context, conn session.Connection, req mcp.JSONRPCRequest, result any, isSSE bool) {
	logger := s.getLogger(c)
	if logger.Core().Enabled(zap.DebugLevel) {
		logger.Debug("sending success response",
			zap.Any("request_id", req.Id),
			zap.String("method", req.Method),
			zap.String("session_id", conn.Meta().ID),
			zap.Bool("is_sse", isSSE),
		)
	}

	response := mcp.JSONRPCResponse{
		JSONRPCBaseResult: mcp.JSONRPCBaseResult{
			JSONRPC: mcp.JSPNRPCVersion,
			ID:      req.Id,
		},
		Result: modernizeResult(req.Method, result, isStreamableStateless(conn)),
	}

	s.sendResponse(c, req.Id, conn, response, isSSE)
}

// sendResponse handles sending the response through SSE or direct HTTP
func (s *Server) sendResponse(c *gin.Context, id any, conn session.Connection, response interface{}, isSSE bool) {
	logger := s.getLogger(c)
	eventData, err := json.Marshal(response)
	if err != nil {
		logger.Error("failed to marshal response",
			zap.Any("id", id),
			zap.String("session_id", conn.Meta().ID),
			zap.Error(err),
		)
		s.sendProtocolError(c, id, "Failed to marshal response", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
		return
	}

	if isStreamableStateless(conn) && !isSSE {
		c.JSON(http.StatusOK, response)
		return
	}

	if isSSE {
		if logger.Core().Enabled(zap.DebugLevel) {
			logger.Debug("sending SSE response",
				zap.Any("id", id),
				zap.String("session_id", conn.Meta().ID),
				zap.Int("data_size", len(eventData)),
			)
		}

		err = conn.Send(c.Request.Context(), &session.Message{
			Event: "message",
			Data:  eventData,
		})
		if err != nil {
			logger.Error("failed to send SSE message",
				zap.Any("id", id),
				zap.String("session_id", conn.Meta().ID),
				zap.Error(err),
			)
			s.sendProtocolError(c, id, fmt.Sprintf("failed to send SSE message: %v", err), http.StatusInternalServerError, mcp.ErrorCodeInternalError)
			return
		}
		c.String(http.StatusAccepted, mcp.Accepted)
	} else {
		if logger.Core().Enabled(zap.DebugLevel) {
			logger.Debug("sending HTTP response",
				zap.Any("id", id),
				zap.String("session_id", conn.Meta().ID),
				zap.Int("data_size", len(eventData)),
			)
		}

		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Header(mcp.HeaderMcpSessionID, conn.Meta().ID)
		c.String(http.StatusOK, fmt.Sprintf("event: message\ndata: %s\n\n", eventData))
	}
}

func modernizeResult(method string, result any, modern bool) any {
	if !modern {
		return result
	}

	if callResult, ok := result.(*mcp.CallToolResult); ok {
		callResult.ResultType = "complete"
		return callResult
	}

	data, err := json.Marshal(result)
	if err != nil {
		return result
	}

	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		fields = make(map[string]any)
	}

	if _, ok := fields["resultType"]; !ok {
		fields["resultType"] = "complete"
	}

	switch method {
	case mcp.ServerDiscover, mcp.ToolsList, mcp.PromptsList, mcp.ResourcesList, mcp.ResourcesTemplatesList, mcp.ResourcesRead:
		if _, ok := fields["ttlMs"]; !ok {
			fields["ttlMs"] = 60_000
		}
		if _, ok := fields["cacheScope"]; !ok {
			fields["cacheScope"] = "private"
		}
	}

	return fields
}

// sendAcceptedResponse sends an accepted response
func (s *Server) sendAcceptedResponse(c *gin.Context) {
	logger := s.getLogger(c)
	if logger.Core().Enabled(zap.DebugLevel) {
		logger.Debug("sending accepted response",
			zap.String("remote_addr", c.Request.RemoteAddr),
		)
	}

	c.String(http.StatusAccepted, mcp.Accepted)
}
