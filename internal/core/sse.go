package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/amoylab/unla/pkg/version"

	"go.uber.org/zap"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/pkg/mcp"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"

	apptrace "github.com/amoylab/unla/pkg/trace"
)

// handleSSE handles SSE connections
func (s *Server) handleSSE(c *gin.Context) {
	logger := s.getLogger(c)

	// Create a child span for the SSE connection lifecycle
	scope := apptrace.Tracer(cnst.TraceCore).
		Start(c.Request.Context(), cnst.SpanSSEConnect, oteltrace.WithSpanKind(oteltrace.SpanKindInternal))
	ctx := scope.Ctx
	defer scope.End()

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache, no-transform")
	c.Writer.Header().Set("Connection", "keep-alive")

	// Get the prefix from the request path
	prefix := strings.TrimSuffix(c.Request.URL.Path, "/sse")
	if prefix == "" {
		prefix = "/"
	}

	requestInfo := &session.RequestInfo{
		Headers: make(map[string]string),
		Query:   make(map[string]string),
		Cookies: make(map[string]string),
	}
	// Process request headers
	for k, v := range c.Request.Header {
		if len(v) > 0 {
			requestInfo.Headers[k] = v[0]
		}
	}
	// Process request querystring
	for k, v := range c.Request.URL.Query() {
		if len(v) > 0 {
			requestInfo.Query[k] = v[0]
		}
	}
	// Process request cookies
	for _, cookie := range c.Request.Cookies() {
		if cookie != nil && cookie.Name != "" {
			requestInfo.Cookies[cookie.Name] = cookie.Value
		}
	}

	sessionID := uuid.New().String()
	meta := &session.Meta{
		ID:        sessionID,
		CreatedAt: time.Now(),
		Prefix:    prefix,
		Type:      "sse",
		Request:   requestInfo,
		Extra:     nil,
	}

	// Annotate span with session metadata
	scope.WithAttrs(
		attribute.String(cnst.AttrMCPSessionID, sessionID),
		attribute.String(cnst.AttrMCPPrefix, prefix),
		attribute.String(cnst.AttrClientAddr, c.Request.RemoteAddr),
		attribute.String(cnst.AttrClientUserAgent, c.Request.UserAgent()),
	)

	logger.Info("establishing SSE connection",
		zap.String("session_id", sessionID),
		zap.String("prefix", prefix),
		zap.String("remote_addr", c.Request.RemoteAddr),
		zap.String("user_agent", c.Request.UserAgent()),
	)

	conn, err := s.sessions.Register(ctx, meta)
	if err != nil {
		logger.Error("failed to register SSE session",
			zap.Error(err),
			zap.String("session_id", sessionID),
			zap.String("prefix", prefix),
			zap.String("remote_addr", c.Request.RemoteAddr),
		)
		s.sendProtocolError(c, sessionID, "Failed to create SSE connection", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
		return
	}

	logger.Debug("SSE session registered successfully",
		zap.String("session_id", sessionID),
		zap.String("prefix", prefix),
	)

	// Send the initial endpoint event
	endpointURL := fmt.Sprintf("%s/message?sessionId=%s", strings.TrimSuffix(c.Request.URL.Path, "/sse"), meta.ID)
	ssePrefix := s.state.GetSSEPrefix(prefix)
	if ssePrefix != "" {
		endpointURL = fmt.Sprintf("%s/%s", ssePrefix, endpointURL)
	}
	logger.Debug("sending initial endpoint event",
		zap.String("session_id", sessionID),
		zap.String("endpoint_url", endpointURL),
	)

	_, err = fmt.Fprintf(c.Writer, "event: endpoint\ndata: %s\n\n", endpointURL)
	if err != nil {
		logger.Error("failed to send initial endpoint event",
			zap.Error(err),
			zap.String("session_id", sessionID),
			zap.String("remote_addr", c.Request.RemoteAddr),
		)
		s.sendProtocolError(c, sessionID, "Failed to initialize SSE connection", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
		return
	}
	c.Writer.Flush()

	logger.Info("SSE connection ready",
		zap.String("session_id", sessionID),
		zap.String("prefix", prefix),
		zap.String("remote_addr", c.Request.RemoteAddr),
	)

	// Main event loop
	for {
		select {
		case event := <-conn.EventQueue():
			if event == nil {
				logger.Warn("received nil event for session",
					zap.String("session_id", sessionID),
				)
			} else {
				logger.Debug("sending event to SSE client",
					zap.String("session_id", sessionID),
					zap.String("event_type", event.Event),
					zap.Int("data_size", len(event.Data)),
				)
			}

			switch event.Event {
			case "message":
				// Record an event for observability
				scope.Span.AddEvent("sse.message", oteltrace.WithAttributes(
					attribute.String("event_type", event.Event),
					attribute.Int("data_size", len(event.Data)),
				))
				_, err = fmt.Fprintf(c.Writer, "event: message\ndata: %s\n\n", event.Data)
				if err != nil {
					logger.Error("failed to send SSE message",
						zap.Error(err),
						zap.String("session_id", sessionID),
						zap.String("remote_addr", c.Request.RemoteAddr),
					)
				}
			default:
				scope.Span.AddEvent("sse.event", oteltrace.WithAttributes(
					attribute.String("event_type", event.Event),
				))
				_, err = fmt.Fprint(c.Writer, event)
				if err != nil {
					logger.Error("failed to write SSE event",
						zap.Error(err),
						zap.String("session_id", sessionID),
						zap.String("event_type", event.Event),
					)
				}
			}
			c.Writer.Flush()
		case <-ctx.Done():
			logger.Info("SSE client disconnected",
				zap.String("session_id", sessionID),
				zap.String("remote_addr", c.Request.RemoteAddr),
			)
			return
		case <-s.shutdownCh:
			logger.Info("SSE connection closing due to server shutdown",
				zap.String("session_id", sessionID),
			)
			return
		}
	}
}

// sendErrorResponse sends an error response through SSE channel and returns Accepted status
func (s *Server) sendErrorResponse(c *gin.Context, conn session.Connection, req mcp.JSONRPCRequest, errorMsg string) {
	s.logger.Error("sending error response via SSE",
		zap.Any("request_id", req.Id),
		zap.String("method", req.Method),
		zap.String("session_id", conn.Meta().ID),
		zap.String("error_message", errorMsg),
		zap.String("remote_addr", c.Request.RemoteAddr),
	)

	response := mcp.JSONRPCErrorSchema{
		JSONRPCBaseResult: mcp.JSONRPCBaseResult{
			JSONRPC: mcp.JSPNRPCVersion,
			ID:      req.Id,
		},
		Error: mcp.JSONRPCError{
			Code:    mcp.ErrorCodeInternalError,
			Message: errorMsg,
		},
	}
	eventData, err := json.Marshal(response)
	if err != nil {
		s.logger.Error("failed to marshal error response",
			zap.Error(err),
			zap.String("session_id", conn.Meta().ID),
			zap.Any("request_id", req.Id),
		)
		c.String(http.StatusAccepted, mcp.Accepted)
		return
	}
	err = conn.Send(c.Request.Context(), &session.Message{
		Event: "message",
		Data:  eventData,
	})
	if err != nil {
		s.logger.Error("failed to send error message to SSE client",
			zap.Error(err),
			zap.String("session_id", conn.Meta().ID),
			zap.Any("request_id", req.Id),
		)
		c.String(http.StatusAccepted, mcp.Accepted)
		return
	}

	s.logger.Debug("error response sent via SSE",
		zap.String("session_id", conn.Meta().ID),
		zap.Any("request_id", req.Id),
	)

	c.String(http.StatusAccepted, mcp.Accepted)
}

// handleMessage processes incoming JSON-RPC messages
func (s *Server) handleMessage(c *gin.Context) {
	s.logger.Debug("received message request",
		zap.String("method", c.Request.Method),
		zap.String("path", c.Request.URL.Path),
		zap.String("remote_addr", c.Request.RemoteAddr),
	)

	// Get the session ID from the query parameter
	sessionId := c.Query("sessionId")
	if sessionId == "" {
		s.logger.Warn("missing sessionId parameter",
			zap.String("path", c.Request.URL.Path),
			zap.String("remote_addr", c.Request.RemoteAddr),
		)
		c.String(http.StatusNotFound, "Missing sessionId parameter")
		s.sendProtocolError(c, nil, "Missing sessionId parameter", http.StatusBadRequest, mcp.ErrorCodeInvalidRequest)
		return
	}

	conn, err := s.sessions.Get(c.Request.Context(), sessionId)
	if err != nil {
		s.logger.Error("session not found",
			zap.Error(err),
			zap.String("session_id", sessionId),
			zap.String("remote_addr", c.Request.RemoteAddr),
		)
		c.String(http.StatusNotFound, "Session not found")
		return
	}

	s.logger.Debug("handling message for session",
		zap.String("session_id", sessionId),
		zap.String("prefix", conn.Meta().Prefix),
	)

	s.handlePostMessage(c, conn)
}

func (s *Server) handlePostMessage(c *gin.Context, conn session.Connection) {
	if conn == nil {
		s.logger.Error("null SSE connection",
			zap.String("remote_addr", c.Request.RemoteAddr),
		)
		c.String(http.StatusInternalServerError, "SSE connection not established")
		return
	}

	// Validate Content-Type header
	contentType := c.GetHeader("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		s.logger.Warn("invalid content type",
			zap.String("content_type", contentType),
			zap.String("session_id", conn.Meta().ID),
			zap.String("remote_addr", c.Request.RemoteAddr),
		)
		c.String(http.StatusNotAcceptable, "Unsupported Media Type: Content-Type must be application/json")
		return
	}

	// TODO: support auth

	// Parse the JSON-RPC message
	var req mcp.JSONRPCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.Error("failed to parse JSON-RPC request",
			zap.Error(err),
			zap.String("session_id", conn.Meta().ID),
			zap.String("remote_addr", c.Request.RemoteAddr),
		)
		c.String(http.StatusBadRequest, "Invalid message")
		return
	}

	s.logger.Debug("received JSON-RPC request",
		zap.String("method", req.Method),
		zap.Any("id", req.Id),
		zap.String("session_id", conn.Meta().ID),
	)

	reqStartTime := time.Now()
	if s.metrics != nil {
		s.metrics.McpReqStart(req.Method)
		defer s.metrics.McpReqDone(req.Method, reqStartTime)
	}

	switch req.Method {
	case mcp.NotificationInitialized:
		s.sendAcceptedResponse(c)
	case mcp.Initialize:
		var params mcp.InitializeRequestParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.sendProtocolError(c, req.Id, "Invalid initialize parameters", http.StatusBadRequest, mcp.ErrorCodeInvalidParams)
			return
		}

		result := mcp.InitializedResult{
			ProtocolVersion: mcp.LatestProtocolVersion,
			ServerInfo: mcp.ImplementationSchema{
				Name:    cnst.AppName,
				Version: version.Get(),
			},
			Capabilities: mcp.ServerCapabilitiesSchema{
				Logging: mcp.LoggingCapabilitySchema{},
				Tools: mcp.ToolsCapabilitySchema{
					ListChanged: true,
				},
				Prompts: mcp.PromptsCapabilitySchema{
					ListChanged: false,
				},
				Resources: mcp.ResourcesCapabilitySchema{
					Subscribe:   false,
					ListChanged: false,
				},
			},
		}
		s.sendSuccessResponse(c, conn, req, result, true)
	case mcp.Ping:
		// Handle ping request with an empty response
		s.sendSuccessResponse(c, conn, req, struct{}{}, true)
	case mcp.ToolsList:
		protoType := s.state.GetProtoType(conn.Meta().Prefix)
		if protoType == "" {
			s.sendProtocolError(c, req.Id, "Server configuration not found", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
			return
		}

		var tools []mcp.ToolSchema
		var err error
		switch protoType {
		case cnst.BackendProtoHttp:
			tools, err = s.fetchHTTPToolList(conn)
			if err != nil {
				s.sendProtocolError(c, req.Id, "Failed to fetch tools", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
				return
			}
		case cnst.BackendProtoStdio, cnst.BackendProtoSSE, cnst.BackendProtoStreamable:
			transport := s.state.GetTransport(conn.Meta().Prefix)
			if transport == nil {
				s.sendProtocolError(c, req.Id, "Failed to fetch tools", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
				return
			}

			tools, err = transport.FetchTools(c.Request.Context())
			if err != nil {
				s.sendProtocolError(c, req.Id, "Failed to fetch tools", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
				return
			}
		default:
			s.sendProtocolError(c, req.Id, "Unsupported protocol type", http.StatusBadRequest, mcp.ErrorCodeInvalidParams)
			return
		}

		toolSchemas := make([]mcp.ToolSchema, len(tools))
		for i, tool := range tools {
			toolSchemas[i] = mcp.ToolSchema{
				Name:        tool.Name,
				Description: tool.Description,
				InputSchema: tool.InputSchema,
				Annotations: tool.Annotations,
				Meta:        tool.Meta,
			}
		}

		result := mcp.ListToolsResult{
			Tools: toolSchemas,
		}
		s.sendSuccessResponse(c, conn, req, result, true)
	case mcp.ToolsCall:
		protoType := s.state.GetProtoType(conn.Meta().Prefix)
		if protoType == "" {
			s.sendProtocolError(c, req.Id, "Server configuration not found", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
			return
		}

		// Execute the tool and return the result
		var params mcp.CallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.sendProtocolError(c, req.Id, "Invalid tool call parameters", http.StatusBadRequest, mcp.ErrorCodeInvalidParams)
			return
		}

		var (
			result *mcp.CallToolResult
			err    error
		)

		status := "success"

		toolName := params.Name
		if s.metrics != nil {
			toolStartTime := time.Now()
			s.metrics.ToolExecStart(toolName)
			defer s.metrics.ToolExecDone(toolName, toolStartTime, &status)
		}

		switch protoType {
		case cnst.BackendProtoHttp:
			result = s.callHTTPTool(c, req, conn, params, true)
			if result == nil {
				status = "error"
				// Error already handled by callHTTPTool
				return
			}
		case cnst.BackendProtoStdio, cnst.BackendProtoSSE, cnst.BackendProtoStreamable:
			transport := s.state.GetTransport(conn.Meta().Prefix)
			if transport == nil {
				errMsg := "Server configuration not found"
				s.sendProtocolError(c, req.Id, errMsg, http.StatusNotFound, mcp.ErrorCodeMethodNotFound)
				status = "error"
				return
			}

			result, err = transport.CallTool(c.Request.Context(), params, mergeRequestInfo(conn.Meta().Request, c.Request))
			if err != nil {
				s.sendToolExecutionError(c, conn, req, err, true)
				status = "error"
				return
			}
		default:
			s.sendProtocolError(c, req.Id, "Unsupported protocol type", http.StatusBadRequest, mcp.ErrorCodeInvalidParams)
			status = "error"
			return
		}

		s.sendSuccessResponse(c, conn, req, result, true)

	case mcp.PromptsList:
		protoType := s.state.GetProtoType(conn.Meta().Prefix)
		if protoType == "" {
			s.sendProtocolError(c, req.Id, "Server configuration not found", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
			return
		}

		var prompts []mcp.PromptSchema
		var err error
		switch protoType {
		case cnst.BackendProtoHttp:
			prompts = s.state.GetPromptSchemas(conn.Meta().Prefix)
			if len(prompts) == 0 {
				prompts = []mcp.PromptSchema{}
			}
		case cnst.BackendProtoStdio, cnst.BackendProtoSSE, cnst.BackendProtoStreamable:
			transport := s.state.GetTransport(conn.Meta().Prefix)
			if transport == nil {
				s.sendProtocolError(c, req.Id, "Failed to fetch prompts", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
				return
			}

			prompts, err = transport.FetchPrompts(c.Request.Context())
			if err != nil {
				s.sendProtocolError(c, req.Id, "Failed to fetch prompts", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
				return
			}
		default:
			s.sendProtocolError(c, req.Id, "Unsupported protocol type", http.StatusBadRequest, mcp.ErrorCodeInvalidParams)
			return
		}

		result := struct {
			Prompts []mcp.PromptSchema `json:"prompts"`
		}{
			Prompts: prompts,
		}
		s.sendSuccessResponse(c, conn, req, result, true)
	case mcp.PromptsGet:
		protoType := s.state.GetProtoType(conn.Meta().Prefix)
		if protoType == "" {
			s.sendProtocolError(c, req.Id, "Server configuration not found", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
			return
		}

		var params struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}

		if err := json.Unmarshal(req.Params, &params); err != nil || params.Name == "" {
			s.sendProtocolError(c, req.Id, "Invalid prompt get parameters", http.StatusBadRequest, mcp.ErrorCodeInvalidParams)
			return
		}

		var prompt *mcp.PromptSchema
		var err error
		switch protoType {
		case cnst.BackendProtoHttp:
			prompts := s.state.GetPromptSchemas(conn.Meta().Prefix)
			for i := range prompts {
				if prompts[i].Name == params.Name {
					prompt = &prompts[i]
					break
				}
			}
		case cnst.BackendProtoStdio, cnst.BackendProtoSSE, cnst.BackendProtoStreamable:
			transport := s.state.GetTransport(conn.Meta().Prefix)
			if transport == nil {
				s.sendProtocolError(c, req.Id, "Failed to fetch prompt", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
				return
			}
			prompt, err = transport.FetchPrompt(c.Request.Context(), params.Name)
			if err != nil {
				s.sendProtocolError(c, req.Id, "Failed to fetch prompt", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
				return
			}
		default:
			s.sendProtocolError(c, req.Id, "Unsupported protocol type", http.StatusBadRequest, mcp.ErrorCodeInvalidParams)
			return
		}

		if prompt == nil {
			s.sendProtocolError(c, req.Id, "Prompt not found", http.StatusNotFound, mcp.ErrorCodeMethodNotFound)
			return
		}

		// Build the response with argument substitution
		var argsMap map[string]string
		if req.Params != nil {
			_ = json.Unmarshal(req.Params, &argsMap)
		}
		argsMap = params.Arguments

		resp := struct {
			Description string `json:"description"`
			Messages    []struct {
				Role    string `json:"role"`
				Content struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"messages"`
		}{
			Description: prompt.Description,
		}

		for _, msg := range prompt.PromptResponse {
			text := msg.Content.Text
			// Replace {argument} placeholders with values from argsMap
			for _, arg := range prompt.Arguments {
				if val, ok := argsMap[arg.Name]; ok {
					text = strings.ReplaceAll(text, "{"+arg.Name+"}", val)
				}
			}
			resp.Messages = append(resp.Messages, struct {
				Role    string `json:"role"`
				Content struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			}{
				Role: msg.Role,
				Content: struct {
					Type string `json:"type"`
					Text string `json:"text"`
				}{
					Type: msg.Content.Type,
					Text: text,
				},
			})
		}

		s.sendSuccessResponse(c, conn, req, resp, true)
		return

	case mcp.LoggingSetLevel:
		// Minimal stub: accept requested level and return empty object
		type params struct {
			Level string `json:"level"`
		}
		var p params
		_ = json.Unmarshal(req.Params, &p)
		s.sendSuccessResponse(c, conn, req, struct{}{}, true)
	case mcp.ResourcesList:
		s.sendSuccessResponse(c, conn, req, struct {
			Resources []struct{} `json:"resources"`
		}{Resources: []struct{}{}}, true)
	case mcp.ResourcesTemplatesList:
		s.sendSuccessResponse(c, conn, req, struct {
			ResourceTemplates []struct{} `json:"resourceTemplates"`
		}{ResourceTemplates: []struct{}{}}, true)
	case mcp.ResourcesRead:
		type params struct {
			URI string `json:"uri"`
		}
		var p params
		_ = json.Unmarshal(req.Params, &p)
		s.sendSuccessResponse(c, conn, req, struct {
			Contents []struct{} `json:"contents"`
		}{Contents: []struct{}{}}, true)
	default:
		s.sendProtocolError(c, req.Id, "Unknown method", http.StatusNotFound, mcp.ErrorCodeMethodNotFound)
	}
}
