package mcpproxy

import (
	"context"
	"fmt"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/template"
	"github.com/amoylab/unla/pkg/mcp"
)

// TransportType represents the type of transport
type TransportType string

const (
	// TypeSSE represents SSE-based transport
	TypeSSE TransportType = "sse"
	// TypeStdio represents stdio-based transport
	TypeStdio TransportType = "stdio"
	// TypeStreamable represents streamable HTTP-based transport
	TypeStreamable TransportType = "streamable-http"
)

// Transport defines the interface for MCP transport implementations
type Transport interface {
	// FetchTools fetches the list of available tools
	FetchTools(ctx context.Context) ([]mcp.ToolSchema, error)

	// CallTool invokes a tool
	CallTool(ctx context.Context, params mcp.CallToolParams, req *template.RequestWrapper) (*mcp.CallToolResult, error)

	// Start starts the transport
	Start(ctx context.Context, tmplCtx *template.Context) error

	// Stop stops the transport
	Stop(ctx context.Context) error

	// IsRunning returns true if the transport is running
	IsRunning() bool

	// FetchPrompts fetches the list of available prompts
	FetchPrompts(ctx context.Context) ([]mcp.PromptSchema, error)
	// FetchPrompt fetches a specific prompt by name
	FetchPrompt(ctx context.Context, name string) (*mcp.PromptSchema, error)

	// ListResources fetches the list of available resources
	ListResources(ctx context.Context) ([]mcp.ResourceSchema, error)
	// ReadResource reads a resource by URI
	ReadResource(ctx context.Context, uri string) (*mcp.ReadResourceResult, error)
}

// NewTransport creates transport based on the configuration
func NewTransport(cfg config.MCPServerConfig) (Transport, error) {
	switch TransportType(cfg.Type) {
	case TypeSSE:
		return &SSETransport{cfg: cfg}, nil
	case TypeStdio:
		return &StdioTransport{cfg: cfg}, nil
	case TypeStreamable:
		return &StreamableTransport{cfg: cfg}, nil
	default:
		return nil, fmt.Errorf("unknown transport type: %s", cfg.Type)
	}
}
