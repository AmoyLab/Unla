package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/amoylab/unla/pkg/version"

	apptrace "github.com/amoylab/unla/pkg/trace"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// handleMCP handles MCP connections
func (s *Server) handleMCP(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodOptions:
		c.Status(http.StatusOK)
		return

	case http.MethodGet:
		s.handleGet(c)
	case http.MethodPost:
		s.handlePost(c)
		return
	case http.MethodDelete:
		s.handleDelete(c)
		return

	default:
		c.Header("Allow", "GET, POST, DELETE")
		s.sendProtocolError(c, nil, "Method not allowed", http.StatusMethodNotAllowed, mcp.ErrorCodeConnectionClosed)
		return
	}
}

// handleGet handles GET requests for SSE stream
func (s *Server) handleGet(c *gin.Context) {
	logger := s.getLogger(c)

	// Check Accept header for text/event-stream
	acceptHeader := c.GetHeader("Accept")
	if !strings.Contains(acceptHeader, "text/event-stream") {
		s.sendProtocolError(c, nil, "Not Acceptable: Client must accept text/event-stream", http.StatusNotAcceptable, mcp.ErrorCodeInvalidRequest)
		return
	}

	conn := s.getSession(c)
	if conn == nil {
		return
	}

	// TODO: replay events according to the last-event-id in request headers.

	// TODO: only support one sse stream per session, we can detect it when sub the redis topic

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache, no-transform")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set(mcp.HeaderMcpSessionID, conn.Meta().ID)
	c.Writer.Flush()

	for {
		select {
		case event := <-conn.EventQueue():
			switch event.Event {
			case "message":
				_, err := fmt.Fprintf(c.Writer, "event: message\ndata: %s\n\n", event.Data)
				if err != nil {
					logger.Error("failed to send SSE message", zap.Error(err))
				}
			}
			_, _ = fmt.Fprint(c.Writer, event)
			c.Writer.Flush()
		case <-c.Request.Context().Done():
			return
		case <-s.shutdownCh:
			return
		}
	}
}

// handlePost handles POST requests containing JSON-RPC messages
func (s *Server) handlePost(c *gin.Context) {
	// Validate Accept header
	accept := c.GetHeader("Accept")
	if !(strings.Contains(accept, "application/json") || strings.Contains(accept, "*/*")) ||
		!(strings.Contains(accept, "text/event-stream") || strings.Contains(accept, "*/*")) {
		s.sendProtocolError(c, nil,
			"Not Acceptable: Client must accept both application/json and text/event-stream",
			http.StatusNotAcceptable, mcp.ErrorCodeConnectionClosed)
		return
	}

	// Validate Content-Type header
	contentType := c.GetHeader("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		s.sendProtocolError(c, nil, "Unsupported Media Type: Content-Type must be application/json",
			http.StatusUnsupportedMediaType, mcp.ErrorCodeConnectionClosed)
		return
	}

	// TODO: support batch messages
	var req mcp.JSONRPCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.sendProtocolError(c, nil, "Invalid JSON-RPC request",
			http.StatusBadRequest, mcp.ErrorCodeParseError)
		return
	}

	sessionID := c.GetHeader(mcp.HeaderMcpSessionID)

	var (
		conn session.Connection
		err  error
	)
	if req.Method == mcp.Initialize {
		if sessionID != "" {
			// confirm if it's registered
			conn, err = s.sessions.Get(c.Request.Context(), sessionID)
			if err != nil {
				s.sendProtocolError(c, req.Id, "Failed to get session", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
				return
			}
			if conn != nil {
				s.sendProtocolError(c, req.Id, "Invalid Request: Server already initialized", http.StatusBadRequest, mcp.ErrorCodeInvalidRequest)
				return
			}
		} else {
			sessionID = uuid.New().String()
			prefix := strings.TrimSuffix(c.Request.URL.Path, "/mcp")
			if prefix == "" {
				prefix = "/"
			}

			meta := &session.Meta{
				ID:        sessionID,
				CreatedAt: time.Now(),
				Prefix:    prefix,
				Type:      "streamable",
			}
			conn, err = s.sessions.Register(c.Request.Context(), meta)
			if err != nil {
				s.sendProtocolError(c, req.Id, "Failed to create session", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
				return
			}
		}
		c.Header(mcp.HeaderMcpSessionID, sessionID)
	} else {
		conn, err = s.sessions.Get(c.Request.Context(), sessionID)
		if err != nil {
			s.sendProtocolError(c, req.Id, "Session not found",
				http.StatusNotFound, mcp.ErrorCodeRequestTimeout)
			return
		}
	}

	s.handleMCPRequest(c, req, conn)
}

// handleDelete handles DELETE requests to terminate sessions
func (s *Server) handleDelete(c *gin.Context) {
	conn := s.getSession(c)
	if conn == nil {
		return
	}

	err := s.sessions.Unregister(c.Request.Context(), conn.Meta().ID)
	if err != nil {
		s.sendProtocolError(c, conn.Meta().ID, "Failed to terminate session", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
		return
	}
	c.Status(http.StatusOK)
}

func (s *Server) handleMCPRequest(c *gin.Context, req mcp.JSONRPCRequest, conn session.Connection) {
	logger := s.getLogger(c)

	// Create a span per MCP method to group downstream work
	scope := apptrace.Tracer(cnst.TraceCore).
		Start(c.Request.Context(), cnst.SpanMCPMethodPrefix+req.Method, oteltrace.WithSpanKind(oteltrace.SpanKindInternal)).
		WithAttrs(
			attribute.String(cnst.AttrMCPSessionID, conn.Meta().ID),
			attribute.String(cnst.AttrMCPPrefix, conn.Meta().Prefix),
			attribute.String("mcp.method", req.Method),
		)
	ctx := scope.Ctx
	defer scope.End()

	// Ensure downstream operations see this span in the request context
	c.Request = c.Request.WithContext(ctx)

	reqStartTime := time.Now()
	if s.metrics != nil {
		s.metrics.McpReqStart(req.Method)
		defer s.metrics.McpReqDone(req.Method, reqStartTime)
	}

	// Process the request based on its method
	switch req.Method {
	case mcp.Initialize:
		// Handle initialization request
		var params mcp.InitializeRequestParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.sendProtocolError(c, req.Id, fmt.Sprintf("invalid initialize parameters: %v", err), http.StatusBadRequest, mcp.ErrorCodeInvalidParams)
			return
		}

		s.sendSuccessResponse(c, conn, req, mcp.InitializedResult{
			ProtocolVersion: mcp.LatestProtocolVersion,
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
			ServerInfo: mcp.ImplementationSchema{
				Name:    cnst.AppName,
				Version: version.Get(),
			},
		}, false)
		return

	case mcp.NotificationInitialized:
		c.Status(http.StatusAccepted)
		return
	case mcp.Ping:
		// Handle ping request with an empty response
		s.sendSuccessResponse(c, conn, req, struct{}{}, false)
		return
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

		s.sendSuccessResponse(c, conn, req, mcp.ListToolsResult{
			Tools: tools,
		}, false)
		return

	case mcp.ToolsCall:
		protoType := s.state.GetProtoType(conn.Meta().Prefix)
		if protoType == "" {
			s.sendProtocolError(c, req.Id, "Server configuration not found", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
			return
		}

		// Parse tool call parameters
		var params mcp.CallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.sendProtocolError(c, req.Id, fmt.Sprintf("invalid tool call parameters: %v", err), http.StatusBadRequest, mcp.ErrorCodeInvalidParams)
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
			result = s.callHTTPTool(c, req, conn, params, false)
			if result == nil {
				// Error already handled by callHTTPTool
				status = "error"
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

		s.sendSuccessResponse(c, conn, req, result, false)
		return

	case mcp.LoggingSetLevel:
		// Minimal stub: accept requested level and return empty object
		// Inspector may invoke this regardless of server support; avoid -32601
		type params struct {
			Level string `json:"level"`
		}
		var p params
		// Ignore unmarshal errors; treat as best-effort no-op
		_ = json.Unmarshal(req.Params, &p)
		s.sendSuccessResponse(c, conn, req, struct{}{}, false)
		return

	case mcp.ResourcesList:
		// Return an empty resources list by default
		s.sendSuccessResponse(c, conn, req, struct {
			Resources []struct{} `json:"resources"`
		}{Resources: []struct{}{}}, false)
		return

	case mcp.ResourcesTemplatesList:
		// Return an empty resourceTemplates list by default
		s.sendSuccessResponse(c, conn, req, struct {
			ResourceTemplates []struct{} `json:"resourceTemplates"`
		}{ResourceTemplates: []struct{}{}}, false)
		return

	case mcp.ResourcesRead:
		// Minimal stub: acknowledge read with empty contents to avoid -32601
		type params struct {
			URI string `json:"uri"`
		}
		var p params
		_ = json.Unmarshal(req.Params, &p)
		s.sendSuccessResponse(c, conn, req, struct {
			Contents []struct{} `json:"contents"`
		}{Contents: []struct{}{}}, false)
		return

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

		s.sendSuccessResponse(c, conn, req, struct {
			Prompts []mcp.PromptSchema `json:"prompts"`
		}{
			Prompts: prompts,
		}, false)
		return

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
			logger.Info("PromptsGet-prompt found", zap.String("params.Name", params.Name), zap.String("promptname", prompt.Name))
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
		argsMap := params.Arguments
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
		s.sendSuccessResponse(c, conn, req, resp, false)
		return

	default:
		s.sendProtocolError(c, req.Id, "Method not found", http.StatusNotFound, mcp.ErrorCodeMethodNotFound)
		return
	}
}

func (s *Server) getSession(c *gin.Context) session.Connection {
	sessionID := c.GetHeader(mcp.HeaderMcpSessionID)
	if sessionID == "" {
		s.sendProtocolError(c, nil, "Bad Request: Mcp-Session-Id header is required", http.StatusBadRequest, mcp.ErrorCodeConnectionClosed)
		return nil
	}
	conn, err := s.sessions.Get(c.Request.Context(), sessionID)
	if err != nil {
		s.sendProtocolError(c, nil, "Session not found", http.StatusNotFound, mcp.ErrorCodeRequestTimeout)
		return nil
	}
	return conn
}
