package mcp

import (
	"encoding/json"
)

type (
	JSONRPCBaseResult struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
	}

	// BaseRequestParams represents the base parameters for all requests
	BaseRequestParams struct {
		// Meta information for the request
		Meta RequestMeta `json:"_meta"`
	}

	// RequestMeta represents the meta information for a request
	RequestMeta struct {
		// Progress token for tracking request progress
		// Can be string or number
		ProgressToken any `json:"progressToken"`
	}

	// JSONRPCRequest represents a JSON-RPC request that expects a response
	JSONRPCRequest struct {
		// JSONRPC version, must be "2.0"
		JSONRPC string `json:"jsonrpc"`
		// A uniquely identifying ID for a request in JSON-RPC
		Id any `json:"id"`
		// The method to be invoked
		Method string `json:"method"`
		// The parameters to be passed to the method
		Params json.RawMessage `json:"params"`
	}

	// JSONRPCResponse represents a JSON-RPC response
	JSONRPCResponse struct {
		JSONRPCBaseResult
		Result any `json:"result"`
	}

	// JSONRPCNotification represents a JSON-RPC notification
	JSONRPCNotification struct {
		JSONRPCBaseResult
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}

	// ToolSchema represents a tool definition
	ToolSchema struct {
		// The name of the tool
		Name string `json:"name"`
		// A human-readable description of the tool
		Description string `json:"description"`
		// A JSON Schema object defining the expected parameters for the tool
		InputSchema ToolInputSchema `json:"inputSchema"`
		// Annotations for the tool
		Annotations *ToolAnnotations `json:"annotations,omitempty"`
	}

	// https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2025-03-26/schema.json
	ToolAnnotations struct {
		DestructiveHint bool `json:"destructiveHint,omitempty"`
		IdempotentHint  bool `json:"idempotentHint,omitempty"`
		OpenWorldHint   bool `json:"openWorldHint,omitempty"`
		ReadOnlyHint    bool `json:"readOnlyHint,omitempty"`
		// A human-readable title for the tool.
		Title string `json:"title,omitempty"`
	}

	ToolInputSchema struct {
		Type       string         `json:"type"`
		Properties map[string]any `json:"properties"`
		Required   []string       `json:"required,omitempty"`
		Title      string         `json:"title"`
		Enum       []any          `json:"enum,omitempty"`
	}

	// ListToolsResult represents the result of a tools/list request
	ListToolsResult struct {
		Tools []ToolSchema `json:"tools"`
	}

	// CallToolParams represents parameters for a tools/call request
	CallToolParams struct {
		BaseRequestParams
		// The name of the tool to call
		Name string `json:"name"`
		// The arguments to pass to the tool
		Arguments json.RawMessage `json:"arguments"`
	}

	// CallToolRequest represents a tools/call request
	CallToolRequest struct {
		JSONRPCRequest
		Params CallToolParams `json:"params"`
	}

	// Content represents a content item in a tool call result
	Content interface {
		// GetType returns the type of the content
		GetType() string
	}

	// TextContent represents a text content item
	TextContent struct {
		// Must be "text"
		Type string `json:"type"`
		// The text content
		Text string `json:"text"`
	}

	ImageContent struct {
		// Must be "image"
		Type string `json:"type"`
		// The image data in base64 format
		Data string `json:"data"`
		// The MIME type of the image. e.g., "image/png", "image/jpeg"
		MimeType string `json:"mimeType"`
	}

	AudioContent struct {
		// Must be "audio"
		Type string `json:"type"`
		// The audio data in base64 format
		Data string `json:"data"`
		// The MIME type of the audio. e.g., "audio/wav", "audio/mpeg"
		MimeType string `json:"mimeType"`
	}

	// CallToolResult represents the result of a tools/call request
	CallToolResult struct {
		Content []Content `json:"content"`
		IsError bool      `json:"isError"`
	}

	// ImplementationSchema describes the name and version of an MCP implementation
	ImplementationSchema struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	// ClientCapabilitiesSchema represents capabilities a client may support
	ClientCapabilitiesSchema struct {
		Experimental map[string]any        `json:"experimental"`
		Sampling     map[string]any        `json:"sampling"`
		Roots        RootsCapabilitySchema `json:"roots"`
	}

	// RootsCapabilitySchema represents roots-related capabilities
	RootsCapabilitySchema struct {
		ListChanged bool `json:"listChanged"`
	}

	// InitializeRequestParams represents parameters for initialize request
	InitializeRequestParams struct {
		BaseRequestParams
		// The latest version of the Model Context Protocol that the client supports
		ProtocolVersion string `json:"protocolVersion"`
		// Client capabilities
		Capabilities ClientCapabilitiesSchema `json:"capabilities"`
		// Client implementation information
		ClientInfo ImplementationSchema `json:"clientInfo"`
	}

	// InitializeRequestSchema represents an initialize request
	InitializeRequestSchema struct {
		JSONRPCRequest
	}

	// ServerCapabilitiesSchema represents capabilities a server may support
	ServerCapabilitiesSchema struct {
		Experimental ExperimentalCapabilitySchema `json:"experimental"`
		Logging      LoggingCapabilitySchema      `json:"logging"`
		Prompts      PromptsCapabilitySchema      `json:"prompts"`
		Resources    ResourcesCapabilitySchema    `json:"resources"`
		Tools        ToolsCapabilitySchema        `json:"tools"`
	}

	ExperimentalCapabilitySchema struct {
	}

	LoggingCapabilitySchema struct {
	}

	// PromptsCapabilitySchema represents prompts-related capabilities
	PromptsCapabilitySchema struct {
		ListChanged bool `json:"listChanged"`
	}

	// ResourcesCapabilitySchema represents resources-related capabilities
	ResourcesCapabilitySchema struct {
		Subscribe   bool `json:"subscribe"`
		ListChanged bool `json:"listChanged"`
	}

	// ToolsCapabilitySchema represents tools-related capabilities
	ToolsCapabilitySchema struct {
		ListChanged bool `json:"listChanged"`
	}

	// InitializeResult represents the result of an initialize request
	InitializeResult struct {
		JSONRPCBaseResult
		Result InitializedResult `json:"result"`
	}
	InitializedResult struct {
		// The version of the Model Context Protocol that the server wants to use
		ProtocolVersion string `json:"protocolVersion"`
		// Server capabilities
		Capabilities ServerCapabilitiesSchema `json:"capabilities"`
		// Server implementation information
		ServerInfo ImplementationSchema `json:"serverInfo"`
		// Instructions describing how to use the server and its features
		Instructions string `json:"instructions"`
	}

	// InitializedNotification represents an initialized notification
	InitializedNotification struct {
		JSONRPCRequest
	}

	// PingRequest represents a ping request
	PingRequest struct {
		JSONRPCRequest
	}

	JSONRPCErrorSchema struct {
		JSONRPCBaseResult
		Error JSONRPCError `json:"error"`
	}
	// JSONRPCError represents an error in a JSON-RPC response
	JSONRPCError struct {
		// The error type that occurred
		Code int `json:"code"`
		// A short description of the error
		Message string `json:"message"`
		// Additional information about the error
		Data any `json:"data,omitempty"`
	}

	// PromptSchema and related types

	PromptSchema struct {
		Name           string                 `json:"name" yaml:"name"`
		Description    string                 `json:"description" yaml:"description"`
		Arguments      []PromptArgumentSchema `json:"arguments" yaml:"arguments"`
		PromptResponse []PromptResponseSchema `json:"promptResponse,omitempty" yaml:"promptResponse,omitempty"`
	}

	PromptArgumentSchema struct {
		Name        string `json:"name" yaml:"name"`
		Description string `json:"description" yaml:"description"`
		Required    bool   `json:"required" yaml:"required"`
	}

	PromptResponseSchema struct {
		Role    string                      `json:"role" yaml:"role"`
		Content PromptResponseContentSchema `json:"content" yaml:"content"`
	}

	PromptResponseContentSchema struct {
		Type string `json:"type" yaml:"type"`
		Text string `json:"text" yaml:"text"`
	}
)

// NewInitializeRequest creates a new initialize request
func NewInitializeRequest(id int64, params InitializeRequestParams) InitializeRequestSchema {
	paramsBytes, _ := json.Marshal(params)
	return InitializeRequestSchema{
		JSONRPCRequest: JSONRPCRequest{
			JSONRPC: JSPNRPCVersion,
			Id:      id,
			Method:  Initialize,
			Params:  paramsBytes,
		},
	}
}

// NewPingRequest creates a new ping request
func NewPingRequest(id int64) PingRequest {
	return PingRequest{
		JSONRPCRequest: JSONRPCRequest{
			JSONRPC: JSPNRPCVersion,
			Id:      id,
			Method:  Ping,
		},
	}
}

func NewJSONRPCBaseResult() JSONRPCBaseResult {
	return JSONRPCBaseResult{
		JSONRPC: JSPNRPCVersion,
		ID:      0,
	}
}

func (j JSONRPCBaseResult) WithID(id int) JSONRPCBaseResult {
	j.ID = id
	return j
}

func (t *TextContent) GetType() string {
	return TextContentType
}

func (i *ImageContent) GetType() string {
	return ImageContentType
}

func (i *AudioContent) GetType() string {
	return AudioContentType
}

// NewCallToolResult creates a new CallToolResult
// @param content the content of the result
// @param isError indicates if the result is an error
// @return *CallToolResult the CallToolResult object
func NewCallToolResult(content []Content, isError bool) *CallToolResult {
	return &CallToolResult{
		Content: content,
		IsError: isError,
	}
}

// NewCallToolResultText creates a new CallToolResult with text content
// @param text the text content
// @return *CallToolResult the CallToolResult object with the text content
func NewCallToolResultText(text string) *CallToolResult {
	return &CallToolResult{
		Content: []Content{
			&TextContent{
				Type: TextContentType,
				Text: text,
			},
		},
		IsError: false,
	}
}

// NewCallToolResultImage  creates a new CallToolResult with an image content
// @param imageData the image data in base64 format
// @param mimeType the MIME type of the image (e.g., "image/png", "image/jpeg")
// @return *CallToolResult the CallToolResult object with the image content
func NewCallToolResultImage(imageData, mimeType string) *CallToolResult {
	return &CallToolResult{
		Content: []Content{
			&ImageContent{
				Type:     ImageContentType,
				Data:     imageData,
				MimeType: mimeType,
			},
		},
		IsError: false,
	}
}

// NewCallToolResultAudio creates a new CallToolResult with an audio content
// @param audioData the audio data in base64 format
// @param mimeType the MIME type of the audio (e.g., "audio/wav", "audio/mpeg")
// @return *CallToolResult the CallToolResult object with the audio content
func NewCallToolResultAudio(audioData, mimeType string) *CallToolResult {
	return &CallToolResult{
		Content: []Content{
			&ImageContent{
				Type:     AudioContentType,
				Data:     audioData,
				MimeType: mimeType,
			},
		},
		IsError: false,
	}
}

// NewCallToolResultError creates a new CallToolResult with an error message
// @param text the error message
// @return *CallToolResult the CallToolResult object with the error message
func NewCallToolResultError(text string) *CallToolResult {
	return &CallToolResult{
		Content: []Content{
			&TextContent{
				Type: TextContentType,
				Text: text,
			},
		},
		IsError: true,
	}
}
