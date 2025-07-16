package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/proxy"

	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/pkg/mcp"

	"go.uber.org/zap"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/template"
)

// prepareRequest prepares the HTTP request with templates and arguments
func prepareRequest(tool *config.ToolConfig, tmplCtx *template.Context) (*http.Request, error) {
	// Process endpoint template
	endpoint, err := template.RenderTemplate(tool.Endpoint, tmplCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to render endpoint template: %w", err)
	}

	// Process request body template
	var reqBody io.Reader
	if tool.RequestBody != "" {
		rendered, err := template.RenderTemplate(tool.RequestBody, tmplCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render request body template: %w", err)
		}
		reqBody = strings.NewReader(rendered)
	}

	req, err := http.NewRequest(tool.Method, endpoint, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Transfer request header to downstream api request
	for k, v := range tmplCtx.Request.Headers {
		// Only transfer user-defined headers
		if !slices.Contains([]string{"accept", "accept-encoding", "accept-language", "host", "cookie",
			"connection", "user-agent", "content-length", "content-type"}, strings.ToLower(k)) {
			req.Header.Set(k, v)
		}
	}

	// Process header templates(override mcp request header if key conflicts)
	for k, v := range tool.Headers {
		rendered, err := template.RenderTemplate(v, tmplCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render header template: %w", err)
		}
		req.Header.Set(k, rendered)
	}

	return req, nil
}

// processArguments processes tool arguments and adds them to the request
func processArguments(req *http.Request, tool *config.ToolConfig, args map[string]any) {
	for _, arg := range tool.Args {
		value := fmt.Sprint(args[arg.Name])
		switch strings.ToLower(arg.Position) {
		case "header":
			req.Header.Set(arg.Name, value)
		case "query":
			q := req.URL.Query()
			q.Add(arg.Name, value)
			req.URL.RawQuery = q.Encode()
		case "form-data":
			var b bytes.Buffer
			writer := multipart.NewWriter(&b)

			if err := writer.WriteField(arg.Name, value); err != nil {
				continue
			}

			if err := writer.Close(); err != nil {
				continue
			}

			req.Body = io.NopCloser(&b)
			req.Header.Set("Content-Type", writer.FormDataContentType())
		}
	}
}

// preprocessResponseData processes response data to handle []any type
func preprocessResponseData(data map[string]any) map[string]any {
	processed := make(map[string]any)

	for k, v := range data {
		switch val := v.(type) {
		case []any:
			ss, _ := json.Marshal(val)
			processed[k] = string(ss)
		case map[string]any:
			processed[k] = preprocessResponseData(val)
		default:
			processed[k] = v
		}
	}
	return processed
}

// fillDefaultArgs fills default values for missing arguments
func fillDefaultArgs(tool *config.ToolConfig, args map[string]any) {
	for _, arg := range tool.Args {
		if _, exists := args[arg.Name]; !exists {
			args[arg.Name] = arg.Default
		}
	}
}

// createHTTPClient creates an HTTP client with proxy support if configured
func createHTTPClient(tool *config.ToolConfig) (*http.Client, error) {
	if tool != nil && tool.Proxy != nil {
		transport := &http.Transport{}

		switch tool.Proxy.Type {
		case "http", "https":
			proxyURLStr := fmt.Sprintf("%s://%s:%d", tool.Proxy.Type, tool.Proxy.Host, tool.Proxy.Port)
			proxyURL, err := url.Parse(proxyURLStr)
			if err != nil {
				return nil, fmt.Errorf("invalid %s proxy configuration: %w", tool.Proxy.Type, err)
			}
			transport.Proxy = http.ProxyURL(proxyURL)

		case "socks5":
			dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", tool.Proxy.Host, tool.Proxy.Port), nil, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
			}
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}

		return &http.Client{Transport: transport}, nil
	}

	return &http.Client{}, nil
}

// executeHTTPTool executes a tool with the given arguments
func (s *Server) executeHTTPTool(conn session.Connection, tool *config.ToolConfig, args map[string]any, request *http.Request, serverCfg map[string]string) (*mcp.CallToolResult, error) {
	// Fill default values for missing arguments
	fillDefaultArgs(tool, args)
	s.transferTransparentHeaderArgs(args, request)

	// Normalize JSON string values in arguments
	template.NormalizeJSONStringValues(args)

	// Log tool execution at info level
	s.logger.Info("executing HTTP tool",
		zap.String("tool", tool.Name),
		zap.String("method", tool.Method),
		zap.String("session_id", conn.Meta().ID),
		zap.String("remote_addr", request.RemoteAddr))

	// Prepare template context
	tmplCtx, err := template.PrepareTemplateContext(conn.Meta().Request, args, request, serverCfg)
	if err != nil {
		s.logger.Error("failed to prepare template context",
			zap.String("tool", tool.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Error(err))
		return nil, err
	}

	// Prepare HTTP request
	req, err := prepareRequest(tool, tmplCtx)
	if err != nil {
		s.logger.Error("failed to prepare HTTP request",
			zap.String("tool", tool.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Error(err))
		return nil, err
	}

	// Log request details at debug level
	s.logger.Debug("tool request details",
		zap.String("tool", tool.Name),
		zap.String("url", req.URL.String()),
		zap.String("method", req.Method),
		zap.Any("headers", req.Header))

	// Process arguments
	processArguments(req, tool, args)

	// Execute request
	cli, err := createHTTPClient(tool)
	if err != nil {
		s.logger.Error("failed to create HTTP client",
			zap.String("tool", tool.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	s.logger.Debug("sending HTTP request",
		zap.String("tool", tool.Name),
		zap.String("url", req.URL.String()),
		zap.String("session_id", conn.Meta().ID))

	resp, err := cli.Do(req)
	if err != nil {
		s.logger.Error("failed to execute HTTP request",
			zap.String("tool", tool.Name),
			zap.String("url", req.URL.String()),
			zap.String("session_id", conn.Meta().ID),
			zap.Error(err))
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for logging in case of error
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("failed to read response body",
			zap.String("tool", tool.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Int("status", resp.StatusCode),
			zap.Error(err))
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Restore response body for further processing
	resp.Body = io.NopCloser(bytes.NewBuffer(respBodyBytes))

	// Log response status
	s.logger.Debug("received HTTP response",
		zap.String("tool", tool.Name),
		zap.String("session_id", conn.Meta().ID),
		zap.String("response_body", string(respBodyBytes)),
		zap.Int("status", resp.StatusCode))

	// Process response
	callToolResult, err := s.toolRespHandler.Handle(resp, tool, tmplCtx)
	if err != nil {
		s.logger.Error("failed to process tool response",
			zap.String("tool", tool.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Int("status", resp.StatusCode),
			zap.Error(err))
		return nil, err
	}

	s.logger.Info("tool execution completed successfully",
		zap.String("tool", tool.Name),
		zap.String("session_id", conn.Meta().ID),
		zap.Int("status", resp.StatusCode))

	return callToolResult, nil
}

// transferTransparentHeaderArgs transfer transparentHeaders from args to request
func (s *Server) transferTransparentHeaderArgs(args map[string]any, request *http.Request) {
	if transparentHeaders, exists := args[s.transparentHeadersArgName]; exists {
		delete(args, s.transparentHeadersArgName)
		s.logger.Debug("transfer transparent headers",
			zap.String("transparentHeadersArgName", s.transparentHeadersArgName),
			zap.Any("transparentHeaders", transparentHeaders))
		if transparentHeaders == nil {
			return
		}
		headers, ok := transparentHeaders.(map[string]any)
		if !ok || len(headers) == 0 {
			return
		}
		for key, value := range headers {
			if v, ok := value.(string); ok {
				request.Header.Add(key, v)
			}
		}
	}
}

func (s *Server) fetchHTTPToolList(conn session.Connection) ([]mcp.ToolSchema, error) {
	s.logger.Debug("fetching HTTP tool list",
		zap.String("session_id", conn.Meta().ID),
		zap.String("prefix", conn.Meta().Prefix))

	// Get http tools for this prefix
	tools := s.state.GetToolSchemas(conn.Meta().Prefix)
	if len(tools) == 0 {
		s.logger.Warn("no tools found for prefix",
			zap.String("prefix", conn.Meta().Prefix),
			zap.String("session_id", conn.Meta().ID))
		tools = []mcp.ToolSchema{} // Return empty list if prefix not found
	}

	s.logger.Debug("fetched tool list",
		zap.String("prefix", conn.Meta().Prefix),
		zap.String("session_id", conn.Meta().ID),
		zap.Int("tool_count", len(tools)))

	return tools, nil
}

func (s *Server) callHTTPTool(c *gin.Context, req mcp.JSONRPCRequest, conn session.Connection, params mcp.CallToolParams) *mcp.CallToolResult {
	// Log tool invocation at info level
	s.logger.Info("invoking HTTP tool",
		zap.String("tool", params.Name),
		zap.String("session_id", conn.Meta().ID),
		zap.String("remote_addr", c.Request.RemoteAddr))

	// Find the tool in the precomputed map
	tool := s.state.GetTool(conn.Meta().Prefix, params.Name)
	if tool == nil {
		s.logger.Warn("tool not found",
			zap.String("tool", params.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.String("remote_addr", c.Request.RemoteAddr))
		s.sendProtocolError(c, req.Id, "Tool not found", http.StatusNotFound, mcp.ErrorCodeMethodNotFound)
		return nil
	}

	// Convert arguments to map[string]any
	var args map[string]any
	if err := json.Unmarshal(params.Arguments, &args); err != nil {
		s.logger.Error("invalid tool arguments",
			zap.String("tool", params.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Error(err))
		s.sendProtocolError(c, req.Id, "Invalid tool arguments", http.StatusBadRequest, mcp.ErrorCodeInvalidParams)
		return nil
	}

	// Log tool arguments at debug level
	if s.logger.Core().Enabled(zap.DebugLevel) {
		argsJSON, _ := json.Marshal(args)
		s.logger.Debug("tool arguments",
			zap.String("tool", params.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.ByteString("arguments", argsJSON))
	}

	// Get server configuration
	serverCfg := s.state.GetServerConfig(conn.Meta().Prefix)
	if serverCfg == nil {
		s.logger.Error("server configuration not found",
			zap.String("tool", params.Name),
			zap.String("prefix", conn.Meta().Prefix),
			zap.String("session_id", conn.Meta().ID))
		s.sendProtocolError(c, req.Id, "Server configuration not found", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
		return nil
	}

	// Execute the tool
	result, err := s.executeHTTPTool(conn, tool, args, c.Request, serverCfg.Config)
	if err != nil {
		s.logger.Error("tool execution failed",
			zap.String("tool", params.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Error(err))
		s.sendToolExecutionError(c, conn, req, err, true)
		return nil
	}

	s.logger.Info("tool invocation completed successfully",
		zap.String("tool", params.Name),
		zap.String("session_id", conn.Meta().ID))

	return result
}

// mergeRequestInfo merges request information from both session and HTTP request
func mergeRequestInfo(meta *session.RequestInfo, req *http.Request) *template.RequestWrapper {
	wrapper := &template.RequestWrapper{
		Headers: make(map[string]string),
		Query:   make(map[string]string),
		Cookies: make(map[string]string),
		Path:    make(map[string]string),
		Body:    make(map[string]any),
	}

	// Merge headers
	if meta != nil {
		for k, v := range meta.Headers {
			wrapper.Headers[k] = v
		}
	}
	if req != nil {
		for k, v := range req.Header {
			if len(v) > 0 {
				wrapper.Headers[k] = v[0]
			}
		}
	}

	// Merge query parameters
	if meta != nil {
		for k, v := range meta.Query {
			wrapper.Query[k] = v
		}
	}
	if req != nil {
		for k, v := range req.URL.Query() {
			if len(v) > 0 {
				wrapper.Query[k] = v[0]
			}
		}
	}

	// Merge cookies
	if meta != nil {
		for k, v := range meta.Cookies {
			wrapper.Cookies[k] = v
		}
	}
	if req != nil {
		for _, cookie := range req.Cookies() {
			if cookie.Name != "" {
				wrapper.Cookies[cookie.Name] = cookie.Value
			}
		}
	}

	return wrapper
}
