package mcpproxy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/template"
	"github.com/amoylab/unla/pkg/mcp"
)

func TestSSETransport_EarlyFailures(t *testing.T) {
	tr := &SSETransport{cfg: config.MCPServerConfig{URL: "://bad"}}
	if tr.IsRunning() {
		t.Fatalf("unexpected running state")
	}
	if err := tr.Stop(context.Background()); err != nil {
		t.Fatalf("stop idle: %v", err)
	}
	if _, err := tr.FetchTools(context.Background()); err == nil {
		t.Fatalf("expected fetch error")
	}

	args, _ := json.Marshal(map[string]any{"k": "v"})
	_, err := tr.CallTool(context.Background(), mcp.CallToolParams{Name: "t", Arguments: args}, &template.RequestWrapper{})
	if err == nil {
		t.Fatalf("expected call tool error")
	}
}

func TestStdioTransport_EarlyFailures(t *testing.T) {
	tr := &StdioTransport{cfg: config.MCPServerConfig{Command: "__nonexistent_command__"}}
	if tr.IsRunning() {
		t.Fatalf("unexpected running state")
	}
	if err := tr.Stop(context.Background()); err != nil {
		t.Fatalf("stop idle: %v", err)
	}
	if _, err := tr.FetchTools(context.Background()); err == nil {
		t.Fatalf("expected fetch error")
	}

	args, _ := json.Marshal(map[string]any{})
	_, err := tr.CallTool(context.Background(), mcp.CallToolParams{Name: "t", Arguments: args}, &template.RequestWrapper{})
	if err == nil {
		t.Fatalf("expected call tool error")
	}
}

func TestStreamableTransport_EarlyFailures(t *testing.T) {
	tr := &StreamableTransport{cfg: config.MCPServerConfig{URL: "://bad"}}
	if tr.IsRunning() {
		t.Fatalf("unexpected running state")
	}
	if err := tr.Stop(context.Background()); err != nil {
		t.Fatalf("stop idle: %v", err)
	}
	if _, err := tr.FetchTools(context.Background()); err == nil {
		t.Fatalf("expected fetch error")
	}

	args, _ := json.Marshal(map[string]any{"k": 1})
	_, err := tr.CallTool(context.Background(), mcp.CallToolParams{Name: "t", Arguments: args}, &template.RequestWrapper{})
	if err == nil {
		t.Fatalf("expected call tool error")
	}
}
