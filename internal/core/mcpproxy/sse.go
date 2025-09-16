package mcpproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/amoylab/unla/internal/common/cnst"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/template"
	"github.com/amoylab/unla/pkg/mcp"
	apptrace "github.com/amoylab/unla/pkg/trace"
	"github.com/amoylab/unla/pkg/version"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// SSETransport implements Transport using Server-Sent Events
type SSETransport struct {
	client *client.Client
	cfg    config.MCPServerConfig
}

var _ Transport = (*SSETransport)(nil)

func (t *SSETransport) Start(ctx context.Context, tmplCtx *template.Context) error {
	if t.IsRunning() {
		return nil
	}

	// Create SSE transport
	sseTransport, err := transport.NewSSE(t.cfg.URL)
	if err != nil {
		return fmt.Errorf("failed to create SSE transport: %w", err)
	}

	// Start the transport
	if err := sseTransport.Start(ctx); err != nil {
		return fmt.Errorf("failed to start SSE transport: %w", err)
	}

	// Create client with the transport
	c := client.NewClient(sseTransport)

	// Initialize the client
	initRequest := mcpgo.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcpgo.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = mcpgo.Implementation{
		Name:    cnst.AppName,
		Version: version.Get(),
	}

	_, err = c.Initialize(ctx, initRequest)
	if err != nil {
		_ = sseTransport.Close()
		return fmt.Errorf("failed to initialize SSE client: %w", err)
	}

	t.client = c
	return nil
}

func (t *SSETransport) Stop(_ context.Context) error {
	if !t.IsRunning() {
		return nil
	}

	if t.client != nil {
		err := t.client.Close()
		if err != nil {
			return err
		}
		t.client = nil
	}

	return nil
}

func (t *SSETransport) IsRunning() bool {
	return t.client != nil
}

func (t *SSETransport) FetchTools(ctx context.Context) ([]mcp.ToolSchema, error) {
	scope := apptrace.Tracer(cnst.TraceMCPProxy).
		Start(ctx, cnst.SpanTransportSSEFetchTools, oteltrace.WithSpanKind(oteltrace.SpanKindClient)).
		WithAttrs(attribute.String(cnst.AttrTransportType, "sse"))
	ctx = scope.Ctx
	defer scope.End()
	if !t.IsRunning() {
		if err := t.Start(ctx, nil); err != nil {
			return nil, err
		}
	}

	// List available tools
	toolsResult, err := t.client.ListTools(ctx, mcpgo.ListToolsRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list tools: %w", err)
	}

	// Convert from mcpgo.Tool to mcp.ToolSchema
	tools := make([]mcp.ToolSchema, len(toolsResult.Tools))
	for i, schema := range toolsResult.Tools {
		// Create local mcp package ToolInputSchema
		inputSchema := mcp.ToolInputSchema{
			Type:       "object",
			Properties: make(map[string]any),
		}

		// Convert mcpgo InputSchema to local mcp format
		rawSchema, err := json.Marshal(schema.InputSchema)
		if err == nil {
			// Parse schema properties
			var schemaMap map[string]interface{}
			if err := json.Unmarshal(rawSchema, &schemaMap); err == nil {
				if properties, ok := schemaMap["properties"].(map[string]interface{}); ok {
					inputSchema.Properties = properties
				}
				if typ, ok := schemaMap["type"].(string); ok {
					inputSchema.Type = typ
				}
				if required, ok := schemaMap["required"].([]interface{}); ok {
					reqStrings := make([]string, len(required))
					for j, r := range required {
						if rStr, ok := r.(string); ok {
							reqStrings[j] = rStr
						}
					}
					inputSchema.Required = reqStrings
				}
			}
		}

		tools[i] = mcp.ToolSchema{
			Name:        schema.Name,
			Description: schema.Description,
			InputSchema: inputSchema,
		}
	}

	t.Stop(ctx)
	return tools, nil
}

func (t *SSETransport) CallTool(ctx context.Context, params mcp.CallToolParams, req *template.RequestWrapper) (*mcp.CallToolResult, error) {
	scope := apptrace.Tracer(cnst.TraceMCPProxy).
		Start(ctx, cnst.SpanTransportSSECallTool, oteltrace.WithSpanKind(oteltrace.SpanKindClient)).
		WithAttrs(
			attribute.String(cnst.AttrTransportType, "sse"),
			attribute.String(cnst.AttrMCPTool, params.Name),
		)
	ctx = scope.Ctx
	defer scope.End()
	if !t.IsRunning() {
		if err := t.Start(ctx, nil); err != nil {
			return nil, err
		}
	}

	// Convert arguments to map[string]any
	var args map[string]any
	if err := json.Unmarshal(params.Arguments, &args); err != nil {
		return nil, fmt.Errorf("invalid tool arguments: %w", err)
	}

	// Prepare template context for environment variables
	tmplCtx, err := template.AssembleTemplateContext(req, args, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare template context: %w", err)
	}

	// Process environment variables with templates
	renderedClientEnv := make(map[string]string)
	for k, v := range t.cfg.Env {
		rendered, err := template.RenderTemplate(v, tmplCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render env template: %w", err)
		}
		renderedClientEnv[k] = rendered
	}

	// Prepare tool call request parameters
	toolCallRequestParams := make(map[string]interface{})
	if err := json.Unmarshal(params.Arguments, &toolCallRequestParams); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tool arguments: %w", err)
	}

	// Call tool
	callRequest := mcpgo.CallToolRequest{}
	callRequest.Params.Name = params.Name
	callRequest.Params.Arguments = toolCallRequestParams

	mcpResult, err := t.client.CallTool(ctx, callRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to call tool: %w", err)
	}

	t.Stop(ctx)
	return convertMCPGoResult(mcpResult), nil
}

// FetchPrompts returns all prompts
func (t *SSETransport) FetchPrompts(ctx context.Context) ([]mcp.PromptSchema, error) {
	return []mcp.PromptSchema{}, nil
}

// FetchPrompt returns a specific prompt by name
func (t *SSETransport) FetchPrompt(ctx context.Context, name string) (*mcp.PromptSchema, error) {
	return nil, &HTTPError{
		StatusCode: http.StatusNotFound,
		Message:    "Prompt not found",
	}
}
