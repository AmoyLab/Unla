package backend

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
)

func TestNewMCPServer_And_GenerateResources(t *testing.T) {
	srv := NewMCPServer()
	if srv == nil {
		t.Fatal("expected server instance")
	}

	rs := generateResources()
	if len(rs) != 100 {
		t.Fatalf("expected 100 resources, got %d", len(rs))
	}
}

func TestHandleSimpleAndComplexPrompts(t *testing.T) {
	// simple
	out, err := handleSimplePrompt(context.Background(), mcp.GetPromptRequest{})
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(out.Messages), 1)

	// complex with args
	req := mcp.GetPromptRequest{Params: mcp.GetPromptParams{Arguments: map[string]string{
		"temperature": "0.7",
		"style":       "short",
	}}}
	out2, err := handleComplexPrompt(context.Background(), req)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(out2.Messages), 2)
}

func TestHandleLongRunningOperation_ZeroSteps_NoProgress(t *testing.T) {
	// Provide steps=0 to avoid progress notifications and timing
	args, _ := json.Marshal(map[string]any{"duration": 0, "steps": 0})
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: json.RawMessage(args), Meta: &mcp.Meta{}}}
	out, err := handleLongRunningOperationTool(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, out)
}
