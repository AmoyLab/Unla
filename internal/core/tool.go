package core

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
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

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/net/proxy"

	apptrace "github.com/amoylab/unla/pkg/trace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/internal/template"
	"github.com/amoylab/unla/pkg/mcp"
)

func parseContentEncodings(contentEncoding string) []string {
	parts := strings.Split(contentEncoding, ",")
	encodings := make([]string, 0, len(parts))
	for _, part := range parts {
		encoding := strings.ToLower(strings.TrimSpace(part))
		if encoding == "" || encoding == "identity" {
			continue
		}
		encodings = append(encodings, encoding)
	}
	return encodings
}

func decodeBodyBytesByEncoding(body []byte, encoding string) ([]byte, error) {
	var (
		reader      io.Reader = bytes.NewReader(body)
		closeFn     func() error
		decodeError error
	)

	switch encoding {
	case "gzip", "x-gzip":
		gzReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		reader = gzReader
		closeFn = gzReader.Close
	case "br":
		reader = brotli.NewReader(reader)
	case "zstd":
		zstdReader, err := zstd.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to create zstd reader: %w", err)
		}
		reader = zstdReader
		closeFn = func() error {
			zstdReader.Close()
			return nil
		}
	case "deflate":
		zlibReader, err := zlib.NewReader(reader)
		if err == nil {
			reader = zlibReader
			closeFn = zlibReader.Close
			break
		}
		// Some servers send raw deflate stream for deflate token.
		flateReader := flate.NewReader(bytes.NewReader(body))
		reader = flateReader
		closeFn = flateReader.Close
	default:
		return nil, fmt.Errorf("unsupported content encoding: %s", encoding)
	}

	decoded, err := io.ReadAll(reader)
	if err != nil {
		decodeError = fmt.Errorf("failed to decode %s body: %w", encoding, err)
	}
	if closeFn != nil {
		closeErr := closeFn()
		if decodeError != nil {
			return nil, decodeError
		}
		if closeErr != nil {
			return nil, fmt.Errorf("failed to close %s decoder: %w", encoding, closeErr)
		}
	}
	if decodeError != nil {
		return nil, decodeError
	}

	return decoded, nil
}

func readDecodedResponseBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	encodings := parseContentEncodings(resp.Header.Get("Content-Encoding"))
	for i := len(encodings) - 1; i >= 0; i-- {
		body, err = decodeBodyBytesByEncoding(body, encodings[i])
		if err != nil {
			return nil, err
		}
	}
	return body, nil
}

// shouldIgnoreHeader checks if a header should be ignored based on configuration
func (s *Server) shouldIgnoreHeader(headerName string) bool {
	// If forward is disabled, don't ignore any headers (backward compatibility)
	if !s.forwardConfig.Enabled {
		return false
	}

	checkName := headerName
	if s.caseInsensitive {
		checkName = strings.ToLower(headerName)
	}

	// If allowHeaders is configured, use it exclusively (ignoreHeaders is ignored)
	if len(s.allowHeaders) > 0 {
		// Only allow headers that are in the allowHeaders list
		return !slices.Contains(s.allowHeaders, checkName)
	}

	// If allowHeaders is not configured, use ignoreHeaders
	return slices.Contains(s.ignoreHeaders, checkName)
}

// prepareRequest prepares the HTTP request with templates and arguments
func (s *Server) prepareRequest(tool *config.ToolConfig, tmplCtx *template.Context) (*http.Request, string, error) {
	// Create a context copy for endpoint rendering to support safe path arguments
	endpointCtx := *tmplCtx
	endpointCtx.Args = make(map[string]any, len(tmplCtx.Args))
	for k, v := range tmplCtx.Args {
		endpointCtx.Args[k] = v
	}

	// Apply URL path escaping for arguments defined as "path" position
	for _, arg := range tool.Args {
		if strings.ToLower(arg.Position) == "path" {
			if val, ok := endpointCtx.Args[arg.Name]; ok {
				endpointCtx.Args[arg.Name] = url.PathEscape(fmt.Sprint(val))
			}
		}
	}

	// Process endpoint template
	endpoint, err := template.RenderTemplate(tool.Endpoint, &endpointCtx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to render endpoint template: %w", err)
	}

	// Process request body template
	var reqBody io.Reader
	var renderedBody string
	if tool.RequestBody != "" {
		rendered, err := template.RenderTemplate(tool.RequestBody, tmplCtx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to render request body template: %w", err)
		}
		renderedBody = rendered
		reqBody = strings.NewReader(renderedBody)
	}

	req, err := http.NewRequest(tool.Method, endpoint, reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	// Transfer request header to downstream api request
	for k, v := range tmplCtx.Request.Headers {
		// Only transfer headers that are not in the ignore list
		if !s.shouldIgnoreHeader(k) {
			req.Header.Set(k, v)
		}
	}

	// Process header templates(override mcp request header if key conflicts)
	for k, v := range tool.Headers {
		rendered, err := template.RenderTemplate(v, tmplCtx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to render header template: %w", err)
		}
		req.Header.Set(k, rendered)
	}

	return req, renderedBody, nil
}

// processArguments processes tool arguments and adds them to the request
func processArguments(req *http.Request, tool *config.ToolConfig, args map[string]any) {
	for _, arg := range tool.Args {
		value := fmt.Sprint(args[arg.Name])
		if value == "" || value == "<nil>" {
			continue
		}
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

		return &http.Client{Transport: otelhttp.NewTransport(transport)}, nil
	}

	return &http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport)}, nil
}

// executeHTTPTool executes a tool with the given arguments
func (s *Server) executeHTTPTool(c *gin.Context, conn session.Connection, tool *config.ToolConfig,
	args map[string]any, serverCfg map[string]string) (*mcp.CallToolResult, error) {
	// Create a span to represent the tool execution lifecycle
	scope := apptrace.Tracer(cnst.TraceCore).
		Start(c.Request.Context(), cnst.SpanHTTPToolExecute, oteltrace.WithSpanKind(oteltrace.SpanKindInternal)).
		WithAttrs(
			attribute.String(cnst.AttrMCPSessionID, conn.Meta().ID),
			attribute.String(cnst.AttrMCPPrefix, conn.Meta().Prefix),
			attribute.String(cnst.AttrMCPTool, tool.Name),
		)
	ctx := scope.Ctx
	defer scope.End()

	// Get logger from Gin context (already has trace ID from middleware)
	logger := s.getLogger(c)

	// Fill default values for missing arguments
	fillDefaultArgs(tool, args)

	// Transfer forward headers from args to request HTTP headers
	s.transferForwardHeaders(args, c.Request)

	// Normalize JSON string values in arguments
	template.NormalizeJSONStringValues(args)

	// Log tool execution at info level
	logger.Info("executing HTTP tool",
		zap.String("tool", tool.Name),
		zap.String("method", tool.Method),
		zap.String("session_id", conn.Meta().ID),
		zap.String("remote_addr", c.Request.RemoteAddr))

	// Prepare template context
	tmplCtx, err := template.PrepareTemplateContext(conn.Meta().Request, args, c.Request, serverCfg)
	if err != nil {
		logger.Error("failed to prepare template context",
			zap.String("tool", tool.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Error(err))
		return nil, err
	}

	// Prepare HTTP request
	req, renderedBody, err := s.prepareRequest(tool, tmplCtx)
	if err != nil {
		logger.Error("failed to prepare HTTP request",
			zap.String("tool", tool.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Error(err))
		return nil, err
	}

	if err := s.validateToolEndpoint(ctx, req.URL); err != nil {
		logger.Warn("blocked tool endpoint",
			zap.String("tool", tool.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.String("endpoint", req.URL.String()),
			zap.Error(err))
		return nil, err
	}

	// Optionally capture selected downstream request fields via templates on span
	if s.traceCapture.DownstreamRequest.Enabled {
		include := s.traceCapture.DownstreamRequest.IncludeFields
		maxLen := s.traceCapture.DownstreamRequest.MaxFieldLength
		if len(include) > 0 {
			for k, tmpl := range include {
				rendered, err := template.RenderTemplate(tmpl, tmplCtx)
				if err != nil {
					// Skip invalid templates silently to avoid breaking requests
					continue
				}
				if maxLen > 0 && len(rendered) > maxLen {
					rendered = rendered[:maxLen]
				}
				scope.Span.SetAttributes(attribute.String(cnst.AttrDownstreamArgPrefix+k, rendered))
			}
		}
		// Optionally capture downstream request body content (rendered)
		if s.traceCapture.DownstreamRequest.BodyEnabled && renderedBody != "" {
			bMax := s.traceCapture.DownstreamRequest.BodyMaxLength
			bodyPreview := renderedBody
			if bMax > 0 && len(bodyPreview) > bMax {
				bodyPreview = bodyPreview[:bMax]
			}
			scope.Span.SetAttributes(attribute.String(cnst.AttrDownstreamReqBody, bodyPreview))
		}
	}

	// Log request details at debug level
	logger.Debug("tool request details",
		zap.String("tool", tool.Name),
		zap.String("url", req.URL.String()),
		zap.String("method", req.Method),
		zap.Any("headers", req.Header))

	// Process arguments
	processArguments(req, tool, args)

	// Execute request
	cli, err := createHTTPClient(tool)
	if err != nil {
		logger.Error("failed to create HTTP client",
			zap.String("tool", tool.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	logger.Debug("sending HTTP request",
		zap.String("tool", tool.Name),
		zap.String("url", req.URL.String()),
		zap.String("session_id", conn.Meta().ID))

	// Ensure downstream request carries current trace context
	req = req.WithContext(ctx)
	resp, err := cli.Do(req)
	if err != nil {
		logger.Error("failed to execute HTTP request",
			zap.String("tool", tool.Name),
			zap.String("url", req.URL.String()),
			zap.String("session_id", conn.Meta().ID),
			zap.Error(err))
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Read and decode response body for logging and unified downstream processing.
	respBodyBytes, err := readDecodedResponseBody(resp)
	if err != nil {
		logger.Error("failed to read response body",
			zap.String("tool", tool.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Int("status", resp.StatusCode),
			zap.Error(err))
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Restore decoded response body for further processing.
	resp.Body = io.NopCloser(bytes.NewBuffer(respBodyBytes))
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")

	// Log response status
	logger.Debug("received HTTP response",
		zap.String("tool", tool.Name),
		zap.String("session_id", conn.Meta().ID),
		zap.String("response_body", string(respBodyBytes)),
		zap.Int("status", resp.StatusCode))

	// If downstream response indicates error, annotate the span with concise details per config
	if resp.StatusCode >= 400 && s.traceCapture.DownstreamError.Enabled {
		maxLen := s.traceCapture.DownstreamError.MaxBodyLength
		preview := string(respBodyBytes)
		if maxLen > 0 && len(preview) > maxLen {
			preview = preview[:maxLen]
		}
		scope.Span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		scope.Span.SetAttributes(
			attribute.Int(cnst.AttrHTTPStatusCode, resp.StatusCode),
			attribute.String(cnst.AttrHTTPRespType, resp.Header.Get("Content-Type")),
			attribute.Int(cnst.AttrHTTPRespSize, len(respBodyBytes)),
		)
		scope.Span.SetAttributes(attribute.String(cnst.AttrHTTPErrorPreview, preview))
		scope.Span.AddEvent("http.error_response")
	}

	// Optionally capture all downstream responses (regardless of status code)
	if s.traceCapture.DownstreamResponse.Enabled {
		maxLen := s.traceCapture.DownstreamResponse.MaxBodyLength
		body := string(respBodyBytes)
		if maxLen > 0 && len(body) > maxLen {
			body = body[:maxLen]
		}
		scope.Span.SetAttributes(
			attribute.Int(cnst.AttrHTTPStatusCode, resp.StatusCode),
			attribute.String(cnst.AttrHTTPRespType, resp.Header.Get("Content-Type")),
			attribute.Int(cnst.AttrHTTPRespSize, len(respBodyBytes)),
			attribute.String(cnst.AttrHTTPRespBody, body),
		)
	}

	// Process response
	callToolResult, err := s.toolRespHandler.Handle(resp, tool, tmplCtx)
	if err != nil {
		logger.Error("failed to process tool response",
			zap.String("tool", tool.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Int("status", resp.StatusCode),
			zap.Error(err))
		return nil, err
	}

	logger.Info("tool execution completed successfully",
		zap.String("tool", tool.Name),
		zap.String("session_id", conn.Meta().ID),
		zap.Int("status", resp.StatusCode))

	return callToolResult, nil
}

// transferForwardHeaders transfer forward headers from args to request
func (s *Server) transferForwardHeaders(args map[string]any, request *http.Request) {
	// If forward is disabled, skip processing
	if !s.forwardConfig.Enabled {
		return
	}

	// Use the configured key for header from mcp_arg
	headerKey := s.forwardConfig.McpArg.KeyForHeader
	if headerKey == "" {
		return
	}

	if forwardHeaders, exists := args[headerKey]; exists {
		delete(args, headerKey)
		s.logger.Debug("transfer forward headers",
			zap.String("headerKey", headerKey),
			zap.Any("forwardHeaders", forwardHeaders))
		if forwardHeaders == nil {
			return
		}
		headers, ok := forwardHeaders.(map[string]any)
		if !ok || len(headers) == 0 {
			return
		}
		for key, value := range headers {
			if v, ok := value.(string); ok {
				if s.forwardConfig.Header.OverrideExisting {
					request.Header.Set(key, v)
				} else {
					request.Header.Add(key, v)
				}
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

func (s *Server) callHTTPTool(c *gin.Context, req mcp.JSONRPCRequest, conn session.Connection, params mcp.CallToolParams, isSSE bool) *mcp.CallToolResult {
	logger := s.getLogger(c)

	// Log tool invocation at info level
	logger.Info("invoking HTTP tool",
		zap.String("tool", params.Name),
		zap.String("session_id", conn.Meta().ID),
		zap.String("remote_addr", c.Request.RemoteAddr))

	// Find the tool in the precomputed map
	tool := s.state.GetTool(conn.Meta().Prefix, params.Name)
	if tool == nil {
		logger.Warn("tool not found",
			zap.String("tool", params.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.String("remote_addr", c.Request.RemoteAddr))
		s.sendProtocolError(c, req.Id, "Tool not found", http.StatusNotFound, mcp.ErrorCodeMethodNotFound)
		return nil
	}

	// Convert arguments to map[string]any
	var args map[string]any
	if err := json.Unmarshal(params.Arguments, &args); err != nil {
		logger.Error("invalid tool arguments",
			zap.String("tool", params.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Error(err))
		s.sendProtocolError(c, req.Id, "Invalid tool arguments", http.StatusBadRequest, mcp.ErrorCodeInvalidParams)
		return nil
	}

	// Log tool arguments at debug level
	if logger.Core().Enabled(zap.DebugLevel) {
		argsJSON, _ := json.Marshal(args)
		logger.Debug("tool arguments",
			zap.String("tool", params.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.ByteString("arguments", argsJSON))
	}

	// Get server configuration
	serverCfg := s.state.GetServerConfig(conn.Meta().Prefix)
	if serverCfg == nil {
		logger.Error("server configuration not found",
			zap.String("tool", params.Name),
			zap.String("prefix", conn.Meta().Prefix),
			zap.String("session_id", conn.Meta().ID))
		s.sendProtocolError(c, req.Id, "Server configuration not found", http.StatusInternalServerError, mcp.ErrorCodeInternalError)
		return nil
	}

	// Execute the tool
	result, err := s.executeHTTPTool(c, conn, tool, args, serverCfg.Config)
	if err != nil {
		logger.Error("tool execution failed",
			zap.String("tool", params.Name),
			zap.String("session_id", conn.Meta().ID),
			zap.Error(err))
		s.sendToolExecutionError(c, conn, req, err, isSSE)
		return nil
	}

	logger.Info("tool invocation completed successfully",
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
