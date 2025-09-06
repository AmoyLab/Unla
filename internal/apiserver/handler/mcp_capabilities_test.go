package handler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/amoylab/unla/internal/mcp/storage"
	"go.uber.org/zap"
)

func TestCachedCapabilities_IsExpired(t *testing.T) {
	// Test not expired
	cached := &cachedCapabilities{
		data: &mcp.CapabilitiesInfo{
			Tools: []mcp.MCPTool{},
		},
		timestamp: time.Now(),
		ttl:       5 * time.Minute,
	}
	assert.False(t, cached.isExpired())

	// Test expired
	cached = &cachedCapabilities{
		data: &mcp.CapabilitiesInfo{
			Tools: []mcp.MCPTool{},
		},
		timestamp: time.Now().Add(-10 * time.Minute),
		ttl:       5 * time.Minute,
	}
	assert.True(t, cached.isExpired())
}

func TestClearCapabilitiesCache(t *testing.T) {
	// Create handler with nil dependencies for this simple test
	logger := zap.NewNop()
	handler := NewMCP(nil, nil, nil, logger)

	// Add some cache entries
	cached1 := &cachedCapabilities{
		data:      &mcp.CapabilitiesInfo{Tools: []mcp.MCPTool{}},
		timestamp: time.Now(),
		ttl:       5 * time.Minute,
	}
	cached2 := &cachedCapabilities{
		data:      &mcp.CapabilitiesInfo{Tools: []mcp.MCPTool{}},
		timestamp: time.Now(),
		ttl:       5 * time.Minute,
	}

	handler.capabilitiesCache.Store("tenant1:server1", cached1)
	handler.capabilitiesCache.Store("tenant2:server2", cached2)

	// Test clearing specific key
	handler.clearCapabilitiesCache("tenant1:server1")
	_, exists1 := handler.capabilitiesCache.Load("tenant1:server1")
	_, exists2 := handler.capabilitiesCache.Load("tenant2:server2")
	assert.False(t, exists1)
	assert.True(t, exists2)

	// Test clearing all cache
	handler.clearCapabilitiesCache("")
	_, exists2 = handler.capabilitiesCache.Load("tenant2:server2")
	assert.False(t, exists2)
}

func TestCapabilitiesInfo_Structure(t *testing.T) {
	// Test that CapabilitiesInfo has the expected structure
	capabilities := &mcp.CapabilitiesInfo{
		Tools: []mcp.MCPTool{
			{
				Name:        "test-tool",
				Description: "A test tool",
				Enabled:     true,
				LastSynced:  time.Now().UTC().Format(time.RFC3339),
			},
		},
		Prompts: []mcp.MCPPrompt{
			{
				Name:        "test-prompt",
				Description: "A test prompt",
				LastSynced:  time.Now().UTC().Format(time.RFC3339),
			},
		},
		Resources: []mcp.MCPResource{
			{
				URI:         "test://resource",
				Name:        "test-resource",
				Description: "A test resource",
				LastSynced:  time.Now().UTC().Format(time.RFC3339),
			},
		},
		ResourceTemplates: []mcp.MCPResourceTemplate{
			{
				URITemplate: "test://template/{id}",
				Name:        "test-template",
				Description: "A test template",
				LastSynced:  time.Now().UTC().Format(time.RFC3339),
			},
		},
		LastSynced: time.Now().UTC().Format(time.RFC3339),
		ServerInfo: map[string]interface{}{
			"name":    "test-server",
			"version": "1.0.0",
		},
	}

	// Basic structure assertions
	assert.NotNil(t, capabilities.Tools)
	assert.NotNil(t, capabilities.Prompts)
	assert.NotNil(t, capabilities.Resources)
	assert.NotNil(t, capabilities.ResourceTemplates)
	assert.NotEmpty(t, capabilities.LastSynced)
	assert.NotNil(t, capabilities.ServerInfo)

	// Content assertions
	assert.Len(t, capabilities.Tools, 1)
	assert.Equal(t, "test-tool", capabilities.Tools[0].Name)
	assert.True(t, capabilities.Tools[0].Enabled)

	assert.Len(t, capabilities.Prompts, 1)
	assert.Equal(t, "test-prompt", capabilities.Prompts[0].Name)

	assert.Len(t, capabilities.Resources, 1)
	assert.Equal(t, "test://resource", capabilities.Resources[0].URI)

	assert.Len(t, capabilities.ResourceTemplates, 1)
	assert.Equal(t, "test://template/{id}", capabilities.ResourceTemplates[0].URITemplate)

	assert.Equal(t, "test-server", capabilities.ServerInfo["name"])
}

func TestHasToolChanged(t *testing.T) {
	handler := &MCP{logger: zap.NewNop()}

	// Test tool with no changes
	tool1 := mcp.MCPTool{
		Name:        "test-tool",
		Description: "Test description",
		Enabled:     true,
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"param1": map[string]interface{}{"type": "string"},
			},
		},
	}
	tool2 := tool1 // Same tool
	assert.False(t, handler.hasToolChanged(tool1, tool2))

	// Test tool with description change
	tool3 := tool1
	tool3.Description = "Different description"
	assert.True(t, handler.hasToolChanged(tool1, tool3))

	// Test tool with enabled change
	tool4 := tool1
	tool4.Enabled = false
	assert.True(t, handler.hasToolChanged(tool1, tool4))

	// Test tool with schema change
	tool5 := tool1
	tool5.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"param2": map[string]interface{}{"type": "number"},
		},
	}
	assert.True(t, handler.hasToolChanged(tool1, tool5))
}

func TestHasPromptChanged(t *testing.T) {
	handler := &MCP{logger: zap.NewNop()}

	// Test prompt with no changes
	prompt1 := mcp.MCPPrompt{
		Name:        "test-prompt",
		Description: "Test description",
		Arguments: []mcp.PromptArgumentSchema{
			{Name: "arg1", Description: "Test arg", Required: true},
		},
	}
	prompt2 := prompt1 // Same prompt
	assert.False(t, handler.hasPromptChanged(prompt1, prompt2))

	// Test prompt with description change
	prompt3 := prompt1
	prompt3.Description = "Different description"
	assert.True(t, handler.hasPromptChanged(prompt1, prompt3))

	// Test prompt with argument change
	prompt4 := prompt1
	prompt4.Arguments = []mcp.PromptArgumentSchema{
		{Name: "arg2", Description: "Different arg", Required: false},
	}
	assert.True(t, handler.hasPromptChanged(prompt1, prompt4))
}

func TestHasResourceChanged(t *testing.T) {
	handler := &MCP{logger: zap.NewNop()}

	// Test resource with no changes
	resource1 := mcp.MCPResource{
		URI:         "test://resource",
		Name:        "Test Resource",
		Description: "Test description",
		MIMEType:    "text/plain",
	}
	resource2 := resource1 // Same resource
	assert.False(t, handler.hasResourceChanged(resource1, resource2))

	// Test resource with name change
	resource3 := resource1
	resource3.Name = "Different Name"
	assert.True(t, handler.hasResourceChanged(resource1, resource3))

	// Test resource with description change
	resource4 := resource1
	resource4.Description = "Different description"
	assert.True(t, handler.hasResourceChanged(resource1, resource4))

	// Test resource with MIME type change
	resource5 := resource1
	resource5.MIMEType = "application/json"
	assert.True(t, handler.hasResourceChanged(resource1, resource5))
}

func TestHasResourceTemplateChanged(t *testing.T) {
	handler := &MCP{logger: zap.NewNop()}

	// Test template with no changes
	template1 := mcp.MCPResourceTemplate{
		URITemplate: "test://template/{id}",
		Name:        "Test Template",
		Description: "Test description",
		MIMEType:    "text/plain",
		Parameters: []mcp.ResourceTemplateParameterSchema{
			{Name: "id", Description: "Test ID", Required: true},
		},
	}
	template2 := template1 // Same template
	assert.False(t, handler.hasResourceTemplateChanged(template1, template2))

	// Test template with name change
	template3 := template1
	template3.Name = "Different Name"
	assert.True(t, handler.hasResourceTemplateChanged(template1, template3))

	// Test template with parameter change
	template4 := template1
	template4.Parameters = []mcp.ResourceTemplateParameterSchema{
		{Name: "slug", Description: "Test Slug", Required: false},
	}
	assert.True(t, handler.hasResourceTemplateChanged(template1, template4))
}

func TestSyncSummaryGetTotalChanges(t *testing.T) {
	summary := &SyncSummary{
		ToolsAdded:               2,
		ToolsUpdated:             1,
		ToolsRemoved:             0,
		PromptsAdded:             1,
		PromptsUpdated:           0,
		PromptsRemoved:           1,
		ResourcesAdded:           0,
		ResourcesUpdated:         1,
		ResourcesRemoved:         0,
		ResourceTemplatesAdded:   1,
		ResourceTemplatesUpdated: 0,
		ResourceTemplatesRemoved: 0,
	}

	total := summary.getTotalChanges()
	expected := 2 + 1 + 0 + 1 + 0 + 1 + 0 + 1 + 0 + 1 + 0 + 0 // = 7
	assert.Equal(t, expected, total)
}

func TestSyncStatusConstants(t *testing.T) {
	// Test that sync status constants are defined correctly
	assert.Equal(t, "pending", string(storage.SyncStatusPending))
	assert.Equal(t, "running", string(storage.SyncStatusRunning))
	assert.Equal(t, "success", string(storage.SyncStatusSuccess))
	assert.Equal(t, "failed", string(storage.SyncStatusFailed))
	assert.Equal(t, "partial", string(storage.SyncStatusPartial))
}