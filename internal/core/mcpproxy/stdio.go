package mcpproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/amoylab/unla/internal/template"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/pkg/mcp"
	apptrace "github.com/amoylab/unla/pkg/trace"
	"github.com/amoylab/unla/pkg/utils"
	"github.com/amoylab/unla/pkg/version"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// StdioTransport implements Transport using standard input/output
type StdioTransport struct {
	client *client.Client
	cfg    config.MCPServerConfig
}

var _ Transport = (*StdioTransport)(nil)

func (t *StdioTransport) Start(ctx context.Context, tmplCtx *template.Context) error {
	if t.IsRunning() {
		return nil
	}

	renderedClientEnv := make(map[string]string)
	for k, v := range t.cfg.Env {
		rendered, err := template.RenderTemplate(v, tmplCtx)
		if err != nil {
			return fmt.Errorf("failed to render env template: %w", err)
		}
		renderedClientEnv[k] = rendered
	}

	// Create stdio transport
	stdioTransport := transport.NewStdio(
		t.cfg.Command,
		utils.MapToEnvList(renderedClientEnv),
		t.cfg.Args...,
	)

	// Start the transport
	if err := stdioTransport.Start(ctx); err != nil {
		return fmt.Errorf("failed to start stdio transport: %w", err)
	}

	// Create client with the transport
	c := client.NewClient(stdioTransport)

	// Initialize the client
	initRequest := mcpgo.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcpgo.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = mcpgo.Implementation{
		Name:    cnst.AppName,
		Version: version.Get(),
	}
	initRequest.Params.Capabilities.Extensions = uiExtensionCapability()

	_, err := c.Initialize(ctx, initRequest)
	if err != nil {
		_ = stdioTransport.Close()
		return fmt.Errorf("failed to initialize stdio client: %w", err)
	}

	t.client = c
	return nil
}

func (t *StdioTransport) Stop(_ context.Context) error {
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

func (t *StdioTransport) IsRunning() bool {
	return t.client != nil
}

func (t *StdioTransport) FetchTools(ctx context.Context) ([]mcp.ToolSchema, error) {
	scope := apptrace.Tracer(cnst.TraceMCPProxy).
		Start(ctx, cnst.SpanTransportStdIOFetchTools, oteltrace.WithSpanKind(oteltrace.SpanKindClient)).
		WithAttrs(attribute.String(cnst.AttrTransportType, "stdio"))
	ctx = scope.Ctx
	defer scope.End()
	if !t.IsRunning() {
		if err := t.Start(ctx, template.NewContext()); err != nil {
			return nil, err
		}
	}
	defer func() {
		if t.cfg.Policy == cnst.PolicyOnDemand {
			_ = t.Stop(ctx)
		}
	}()

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
			Meta:        convertMeta(schema.Meta),
		}
	}

	return tools, nil
}

// ListResources returns all resources exposed by the upstream server
func (t *StdioTransport) ListResources(ctx context.Context) ([]mcp.ResourceSchema, error) {
	if !t.IsRunning() {
		if err := t.Start(ctx, template.NewContext()); err != nil {
			return nil, err
		}
	}
	defer func() {
		if t.cfg.Policy == cnst.PolicyOnDemand {
			_ = t.Stop(ctx)
		}
	}()

	resourcesResult, err := t.client.ListResources(ctx, mcpgo.ListResourcesRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list resources: %w", err)
	}

	resources := make([]mcp.ResourceSchema, 0, len(resourcesResult.Resources))
	for _, r := range resourcesResult.Resources {
		resources = append(resources, mcp.ResourceSchema{
			URI:         r.URI,
			Name:        r.Name,
			Description: r.Description,
			MimeType:    r.MIMEType,
			Meta:        convertMeta(r.Meta),
		})
	}
	return resources, nil
}

// ReadResource reads a resource by URI from the upstream server
func (t *StdioTransport) ReadResource(ctx context.Context, uri string) (*mcp.ReadResourceResult, error) {
	if !t.IsRunning() {
		if err := t.Start(ctx, template.NewContext()); err != nil {
			return nil, err
		}
	}
	defer func() {
		if t.cfg.Policy == cnst.PolicyOnDemand {
			_ = t.Stop(ctx)
		}
	}()

	readRequest := mcpgo.ReadResourceRequest{}
	readRequest.Params.URI = uri
	readResult, err := t.client.ReadResource(ctx, readRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to read resource: %w", err)
	}

	result := &mcp.ReadResourceResult{Meta: convertMeta(readResult.Meta)}
	for _, c := range readResult.Contents {
		if converted := convertResourceContents(c); converted != nil {
			result.Contents = append(result.Contents, converted)
		}
	}
	return result, nil
}

func (t *StdioTransport) CallTool(ctx context.Context, params mcp.CallToolParams, req *template.RequestWrapper) (*mcp.CallToolResult, error) {
	scope := apptrace.Tracer(cnst.TraceMCPProxy).
		Start(ctx, cnst.SpanTransportStdIOCallTool, oteltrace.WithSpanKind(oteltrace.SpanKindClient)).
		WithAttrs(
			attribute.String(cnst.AttrTransportType, "stdio"),
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

	toolCallRequestParams := make(map[string]any)
	if err := json.Unmarshal(params.Arguments, &toolCallRequestParams); err != nil {
		return nil, err
	}

	// Call tool
	callRequest := mcpgo.CallToolRequest{}
	callRequest.Params.Name = params.Name
	callRequest.Params.Arguments = toolCallRequestParams

	mcpResult, err := t.client.CallTool(ctx, callRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to call tool: %w", err)
	}

	return convertMCPGoResult(mcpResult), nil
}

// FetchPrompts returns all prompts
func (t *StdioTransport) FetchPrompts(ctx context.Context) ([]mcp.PromptSchema, error) {
	return []mcp.PromptSchema{}, nil
}

// FetchPrompt returns a specific prompt by name
func (t *StdioTransport) FetchPrompt(ctx context.Context, name string) (*mcp.PromptSchema, error) {
	return nil, &HTTPError{
		StatusCode: http.StatusNotFound,
		Message:    "Prompt not found",
	}
}
