package cnst

// Tracer names used across the services
const (
	// TraceCore is the tracer name for core server logic
	TraceCore = "mcp-gateway/core"
	// TraceMCPProxy is the tracer name for downstream MCP proxy/transport
	TraceMCPProxy = "mcp-gateway/mcpproxy"
)

// Common span names and prefixes
const (
	// SpanHTTPToolExecute represents executing an HTTP tool
	SpanHTTPToolExecute = "mcp.http_tool.execute"

	// SpanSSEConnect represents establishing SSE connection on server
	SpanSSEConnect = "mcp.sse.connect"

	// SpanMCPMethodPrefix prefixes spans for handling MCP methods
	SpanMCPMethodPrefix = "mcp.method."

	// Transport-specific spans
	SpanTransportStdIOFetchTools      = "mcp.transport.stdio.fetch_tools"
	SpanTransportStdIOCallTool        = "mcp.transport.stdio.call_tool"
	SpanTransportSSEFetchTools        = "mcp.transport.sse.fetch_tools"
	SpanTransportSSECallTool          = "mcp.transport.sse.call_tool"
	SpanTransportStreamableFetchTools = "mcp.transport.streamable.fetch_tools"
	SpanTransportStreamableCallTool   = "mcp.transport.streamable.call_tool"
)

// Common attribute keys
const (
	AttrTransportType       = "transport.type"
	AttrMCPTool             = "mcp.tool"
	AttrMCPSessionID        = "mcp.session_id"
	AttrMCPPrefix           = "mcp.prefix"
	AttrClientAddr          = "client.remote_addr"
	AttrClientUserAgent     = "client.user_agent"
	AttrErrorReason         = "error.reason"
	AttrMCPErrorCode        = "mcp.error_code"
	AttrHTTPStatusCode      = "http.status_code"
	AttrHTTPRespType        = "http.response.content_type"
	AttrHTTPRespSize        = "http.response.size"
	AttrHTTPErrorPreview    = "http.response.error_preview"
	AttrDownstreamArgPrefix = "downstream.arg."
	AttrDownstreamReqBody   = "downstream.request.body"
)
