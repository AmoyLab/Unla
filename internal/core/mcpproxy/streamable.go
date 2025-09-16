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

// StreamableTransport implements Transport using Streamable HTTP
type StreamableTransport struct {
	client *client.Client
	cfg    config.MCPServerConfig
}

var _ Transport = (*StreamableTransport)(nil)

func (t *StreamableTransport) Start(ctx context.Context, tmplCtx *template.Context) error {
	if t.IsRunning() {
		return nil
	}

	// Create streamable transport
	streamableTransport, err := transport.NewStreamableHTTP(t.cfg.URL)
	if err != nil {
		return fmt.Errorf("failed to create Streamable HTTP transport: %w", err)
	}

	// Start the transport
	if err := streamableTransport.Start(ctx); err != nil {
		return fmt.Errorf("failed to start Streamable HTTP transport: %w", err)
	}

	// Create client with the transport
	c := client.NewClient(streamableTransport)

	// Initialize the client
	initRequest := mcpgo.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcpgo.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = mcpgo.Implementation{
		Name:    cnst.AppName,
		Version: version.Get(),
	}

	_, err = c.Initialize(ctx, initRequest)
	if err != nil {
		_ = streamableTransport.Close()
		return fmt.Errorf("failed to initialize streamable client: %w", err)
	}

	t.client = c
	return nil
}

func (t *StreamableTransport) Stop(_ context.Context) error {
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

func (t *StreamableTransport) IsRunning() bool {
	return t.client != nil
}

func (t *StreamableTransport) FetchTools(ctx context.Context) ([]mcp.ToolSchema, error) {
	scope := apptrace.Tracer(cnst.TraceMCPProxy).
		Start(ctx, cnst.SpanTransportStreamableFetchTools, oteltrace.WithSpanKind(oteltrace.SpanKindClient)).
		WithAttrs(attribute.String(cnst.AttrTransportType, "streamable-http"))
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

	return tools, nil
}

func (t *StreamableTransport) CallTool(ctx context.Context, params mcp.CallToolParams, req *template.RequestWrapper) (*mcp.CallToolResult, error) {
	scope := apptrace.Tracer(cnst.TraceMCPProxy).
		Start(ctx, cnst.SpanTransportStreamableCallTool, oteltrace.WithSpanKind(oteltrace.SpanKindClient)).
		WithAttrs(
			attribute.String(cnst.AttrTransportType, "streamable-http"),
			attribute.String(cnst.AttrMCPTool, params.Name),
		)
	ctx = scope.Ctx
	defer scope.End()
	if !t.IsRunning() {
		var args map[string]any
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return nil, fmt.Errorf("invalid tool arguments: %w", err)
		}
		tmplCtx, err := template.AssembleTemplateContext(req, args, nil)
		if err != nil {
			return nil, err
		}

		if err := t.Start(ctx, tmplCtx); err != nil {
			return nil, err
		}
	}
	defer func() {
		if t.cfg.Policy == cnst.PolicyOnDemand {
			_ = t.Stop(ctx)
		}
	}()

	// Prepare tool call request parameters
	toolCallRequestParams := make(map[string]interface{})
	if err := json.Unmarshal(params.Arguments, &toolCallRequestParams); err != nil {
		return nil, fmt.Errorf("failed to unmarshal arguments: %w", err)
	}

	// Call tool
	callRequest := mcpgo.CallToolRequest{}
	callRequest.Params.Name = params.Name
	callRequest.Params.Arguments = toolCallRequestParams

	res, err := t.client.CallTool(ctx, callRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to call tool: %w", err)
	}

	return convertMCPGoResult(res), nil
}

// FetchPrompts returns all prompts
func (t *StreamableTransport) FetchPrompts(ctx context.Context) ([]mcp.PromptSchema, error) {
	return []mcp.PromptSchema{}, nil
}

// FetchPrompt returns a specific prompt by name
func (t *StreamableTransport) FetchPrompt(ctx context.Context, name string) (*mcp.PromptSchema, error) {
	return nil, &HTTPError{
		StatusCode: http.StatusNotFound,
		Message:    "Prompt not found",
	}
}
