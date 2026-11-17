package backend

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"
)

type ToolName string

const (
	Echo                 ToolName = "echo"
	Add                  ToolName = "add"
	LongRunningOperation ToolName = "longRunningOperation"
	SampleLLM            ToolName = "sampleLLM"
	GetTinyImage         ToolName = "getTinyImage"
)

type PromptName string

const (
	Simple  PromptName = "simple_prompt"
	Complex PromptName = "complex_prompt"
)

//go:embed image
var MCPTinyImage string

var logger *zap.Logger

func init() {
	// Initialize logger
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		panic(err)
	}
}

func NewMCPServer() *server.MCPServer {
	hooks := &server.Hooks{}

	hooks.AddBeforeAny(func(ctx context.Context, id any, method mcp.MCPMethod, message any) {
		logger.Info("beforeAny", zap.String("method", string(method)), zap.Any("id", id), zap.Any("message", message))
	})
	hooks.AddOnSuccess(func(ctx context.Context, id any, method mcp.MCPMethod, message any, result any) {
		logger.Info("onSuccess", zap.String("method", string(method)), zap.Any("id", id), zap.Any("message", message), zap.Any("result", result))
	})
	hooks.AddOnError(func(ctx context.Context, id any, method mcp.MCPMethod, message any, err error) {
		logger.Error("onError", zap.String("method", string(method)), zap.Any("id", id), zap.Any("message", message), zap.Error(err))
	})
	hooks.AddBeforeInitialize(func(ctx context.Context, id any, message *mcp.InitializeRequest) {
		logger.Info("beforeInitialize", zap.Any("id", id), zap.Any("message", message))
	})
	hooks.AddOnRequestInitialization(func(ctx context.Context, id any, message any) error {
		logger.Info("AddOnRequestInitialization", zap.Any("id", id), zap.Any("message", message))
		return nil
	})
	hooks.AddAfterInitialize(func(ctx context.Context, id any, message *mcp.InitializeRequest, result *mcp.InitializeResult) {
		logger.Info("afterInitialize", zap.Any("id", id), zap.Any("message", message), zap.Any("result", result))
	})
	hooks.AddBeforeCallTool(func(ctx context.Context, id any, message *mcp.CallToolRequest) {
		logger.Info("beforeCallTool", zap.Any("id", id), zap.Any("message", message))
	})
	hooks.AddAfterCallTool(func(ctx context.Context, id any, message *mcp.CallToolRequest, result any) {
		logger.Info("afterCallTool", zap.Any("id", id), zap.Any("message", message), zap.Any("result", result))
	})

	mcpServer := server.NewMCPServer(
		"example-servers/everything",
		"1.0.0",
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
		server.WithToolCapabilities(true),
		server.WithLogging(),
		server.WithHooks(hooks),
	)

	mcpServer.AddResource(mcp.NewResource("test://static/resource",
		"Static Resource",
		mcp.WithMIMEType("text/plain"),
	), handleReadResource)
	mcpServer.AddResourceTemplate(
		mcp.NewResourceTemplate(
			"test://dynamic/resource/{id}",
			"Dynamic Resource",
		),
		handleResourceTemplate,
	)

	resources := generateResources()
	for _, resource := range resources {
		mcpServer.AddResource(resource, handleGeneratedResource)
	}

	mcpServer.AddPrompt(mcp.NewPrompt(string(Simple),
		mcp.WithPromptDescription("A simple prompt"),
	), handleSimplePrompt)
	mcpServer.AddPrompt(mcp.NewPrompt(string(Complex),
		mcp.WithPromptDescription("A complex prompt"),
		mcp.WithArgument("temperature",
			mcp.ArgumentDescription("The temperature parameter for generation"),
			mcp.RequiredArgument(),
		),
		mcp.WithArgument("style",
			mcp.ArgumentDescription("The style to use for the response"),
			mcp.RequiredArgument(),
		),
	), handleComplexPrompt)
	mcpServer.AddTool(mcp.NewTool(string(Echo),
		mcp.WithDescription("Echoes back the input"),
		mcp.WithString("message",
			mcp.Description("Message to echo"),
			mcp.Required(),
		),
	), handleEchoTool)

	mcpServer.AddTool(
		mcp.NewTool("notify"),
		handleSendNotification,
	)

	mcpServer.AddTool(mcp.NewTool(string(Add),
		mcp.WithDescription("Adds two numbers"),
		mcp.WithNumber("a",
			mcp.Description("First number"),
			mcp.Required(),
		),
		mcp.WithNumber("b",
			mcp.Description("Second number"),
			mcp.Required(),
		),
	), handleAddTool)
	mcpServer.AddTool(mcp.NewTool(
		string(LongRunningOperation),
		mcp.WithDescription(
			"Demonstrates a long running operation with progress updates",
		),
		mcp.WithNumber("duration",
			mcp.Description("Duration of the operation in seconds"),
			mcp.DefaultNumber(10),
		),
		mcp.WithNumber("steps",
			mcp.Description("Number of steps in the operation"),
			mcp.DefaultNumber(5),
		),
	), handleLongRunningOperationTool)

	mcpServer.AddTool(mcp.NewTool(string(GetTinyImage),
		mcp.WithDescription("Returns the MCPTinyImage"),
	), handleGetTinyImageTool)

	mcpServer.AddNotificationHandler("notification", handleNotification)

	return mcpServer
}

func generateResources() []mcp.Resource {
	resources := make([]mcp.Resource, 100)
	for i := 0; i < 100; i++ {
		uri := fmt.Sprintf("test://static/resource/%d", i+1)
		if i%2 == 0 {
			resources[i] = mcp.Resource{
				URI:      uri,
				Name:     fmt.Sprintf("Resource %d", i+1),
				MIMEType: "text/plain",
			}
		} else {
			resources[i] = mcp.Resource{
				URI:      uri,
				Name:     fmt.Sprintf("Resource %d", i+1),
				MIMEType: "application/octet-stream",
			}
		}
	}
	return resources
}

func handleReadResource(
	ctx context.Context,
	request mcp.ReadResourceRequest,
) ([]mcp.ResourceContents, error) {
	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "test://static/resource",
			MIMEType: "text/plain",
			Text:     "This is a sample resource",
		},
	}, nil
}

func handleResourceTemplate(
	ctx context.Context,
	request mcp.ReadResourceRequest,
) ([]mcp.ResourceContents, error) {
	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      request.Params.URI,
			MIMEType: "text/plain",
			Text:     "This is a sample resource",
		},
	}, nil
}

func handleGeneratedResource(
	ctx context.Context,
	request mcp.ReadResourceRequest,
) ([]mcp.ResourceContents, error) {
	uri := request.Params.URI

	var resourceNumber string
	if _, err := fmt.Sscanf(uri, "test://static/resource/%s", &resourceNumber); err != nil {
		return nil, fmt.Errorf("invalid resource URI format: %w", err)
	}

	num, err := strconv.Atoi(resourceNumber)
	if err != nil {
		return nil, fmt.Errorf("invalid resource number: %w", err)
	}

	index := num - 1

	if index%2 == 0 {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      uri,
				MIMEType: "text/plain",
				Text:     fmt.Sprintf("Text content for resource %d", num),
			},
		}, nil
	} else {
		return []mcp.ResourceContents{
			mcp.BlobResourceContents{
				URI:      uri,
				MIMEType: "application/octet-stream",
				Blob:     base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("Binary content for resource %d", num))),
			},
		}, nil
	}
}

func handleSimplePrompt(
	ctx context.Context,
	request mcp.GetPromptRequest,
) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{
		Description: "A simple prompt without arguments",
		Messages: []mcp.PromptMessage{
			{
				Role: mcp.RoleUser,
				Content: mcp.TextContent{
					Type: "text",
					Text: "This is a simple prompt without arguments.",
				},
			},
		},
	}, nil
}

func handleComplexPrompt(
	ctx context.Context,
	request mcp.GetPromptRequest,
) (*mcp.GetPromptResult, error) {
	arguments := request.Params.Arguments
	return &mcp.GetPromptResult{
		Description: "A complex prompt with arguments",
		Messages: []mcp.PromptMessage{
			{
				Role: mcp.RoleUser,
				Content: mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf(
						"This is a complex prompt with arguments: temperature=%s, style=%s",
						arguments["temperature"],
						arguments["style"],
					),
				},
			},
			{
				Role: mcp.RoleAssistant,
				Content: mcp.TextContent{
					Type: "text",
					Text: "I understand. You've provided a complex prompt with temperature and style arguments. How would you like me to proceed?",
				},
			},
			{
				Role: mcp.RoleUser,
				Content: mcp.ImageContent{
					Type:     "image",
					Data:     MCPTinyImage,
					MIMEType: "image/png",
				},
			},
		},
	}, nil
}

func handleEchoTool(
	ctx context.Context,
	request mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	// Convert interface{} to json.RawMessage
	argumentsBytes, ok := request.Params.Arguments.(json.RawMessage)
	if !ok {
		return nil, fmt.Errorf("invalid arguments type")
	}

	var arguments map[string]interface{}
	if err := json.Unmarshal(argumentsBytes, &arguments); err != nil {
		return nil, fmt.Errorf("failed to unmarshal arguments: %w", err)
	}

	message, ok := arguments["message"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid message argument")
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf("Echo: %s", message),
			},
		},
	}, nil
}

func handleAddTool(
	ctx context.Context,
	request mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	// Convert interface{} to json.RawMessage
	argumentsBytes, ok := request.Params.Arguments.(json.RawMessage)
	if !ok {
		return nil, fmt.Errorf("invalid arguments type")
	}

	var arguments map[string]interface{}
	if err := json.Unmarshal(argumentsBytes, &arguments); err != nil {
		return nil, fmt.Errorf("failed to unmarshal arguments: %w", err)
	}

	a, ok1 := arguments["a"].(float64)
	b, ok2 := arguments["b"].(float64)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("invalid number arguments")
	}
	sum := a + b
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf("The sum of %f and %f is %f.", a, b, sum),
			},
		},
	}, nil
}

func handleSendNotification(
	ctx context.Context,
	request mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {

	server := server.ServerFromContext(ctx)

	err := server.SendNotificationToClient(
		ctx,
		"notifications/progress",
		map[string]any{
			"progress":      10,
			"total":         10,
			"progressToken": 0,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to send notification: %w", err)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: "notification sent successfully",
			},
		},
	}, nil
}

func handleLongRunningOperationTool(
	ctx context.Context,
	request mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	// Convert interface{} to json.RawMessage
	argumentsBytes, ok := request.Params.Arguments.(json.RawMessage)
	if !ok {
		return nil, fmt.Errorf("invalid arguments type")
	}

	var arguments map[string]interface{}
	if err := json.Unmarshal(argumentsBytes, &arguments); err != nil {
		return nil, fmt.Errorf("failed to unmarshal arguments: %w", err)
	}

	progressToken := request.Params.Meta.ProgressToken
	duration, _ := arguments["duration"].(float64)
	steps, _ := arguments["steps"].(float64)
	stepDuration := duration / steps
	server := server.ServerFromContext(ctx)

	for i := 1; i < int(steps)+1; i++ {
		time.Sleep(time.Duration(stepDuration * float64(time.Second)))
		if progressToken != nil {
			err := server.SendNotificationToClient(
				ctx,
				"notifications/progress",
				map[string]any{
					"progress":      i,
					"total":         int(steps),
					"progressToken": progressToken,
					"message":       fmt.Sprintf("Server progress %v%%", int(float64(i)*100/steps)),
				},
			)
			if err != nil {
				return nil, fmt.Errorf("failed to send notification: %w", err)
			}
		}
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf(
					"Long running operation completed. Duration: %f seconds, Steps: %d.",
					duration,
					int(steps),
				),
			},
		},
	}, nil
}

func handleGetTinyImageTool(
	ctx context.Context,
	request mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: "This is a tiny image:",
			},
			mcp.ImageContent{
				Type:     "image",
				Data:     MCPTinyImage,
				MIMEType: "image/png",
			},
			mcp.TextContent{
				Type: "text",
				Text: "The image above is the MCP tiny image.",
			},
		},
	}, nil
}

func handleNotification(
	ctx context.Context,
	notification mcp.JSONRPCNotification,
) {
	log.Printf("Received notification: %s", notification.Method)
}
