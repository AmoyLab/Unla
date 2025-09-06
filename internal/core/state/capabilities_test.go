package state

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/amoylab/unla/pkg/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewState(t *testing.T) {
	state := NewState()
	
	assert.NotNil(t, state)
	assert.NotNil(t, state.capabilities)
	assert.NotNil(t, state.version)
	assert.Equal(t, int64(0), state.GetCurrentVersion())
	assert.Equal(t, 0, state.GetCapabilitiesCount())
}

func TestSetCapabilities(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	serverName := "test-server"
	
	capabilities := &mcp.CapabilitiesInfo{
		Tools: []mcp.MCPTool{
			{
				Name:        "test-tool",
				Description: "A test tool",
				Enabled:     true,
				LastSynced:  time.Now().Format(time.RFC3339),
			},
		},
		Prompts:           []mcp.MCPPrompt{},
		Resources:         []mcp.MCPResource{},
		ResourceTemplates: []mcp.MCPResourceTemplate{},
		LastSynced:        time.Now().Format(time.RFC3339),
	}
	
	// Set capabilities
	state.SetCapabilities(tenant, serverName, capabilities)
	
	// Verify capabilities were set
	retrieved := state.GetCapabilities(tenant, serverName)
	require.NotNil(t, retrieved)
	assert.Equal(t, 1, len(retrieved.Tools))
	assert.Equal(t, "test-tool", retrieved.Tools[0].Name)
	assert.Equal(t, 1, state.GetCapabilitiesCount())
	assert.Greater(t, state.GetCurrentVersion(), int64(0))
}

func TestGetCapabilities(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	serverName := "test-server"
	
	// Test getting non-existent capabilities
	result := state.GetCapabilities(tenant, serverName)
	assert.Nil(t, result)
	
	// Set and get capabilities
	capabilities := &mcp.CapabilitiesInfo{
		Tools: []mcp.MCPTool{
			{Name: "tool1", Enabled: true},
		},
	}
	
	state.SetCapabilities(tenant, serverName, capabilities)
	retrieved := state.GetCapabilities(tenant, serverName)
	
	require.NotNil(t, retrieved)
	assert.Equal(t, 1, len(retrieved.Tools))
	assert.Equal(t, "tool1", retrieved.Tools[0].Name)
}

func TestGetCapabilitiesWithDetails(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	serverName := "test-server"
	
	capabilities := &mcp.CapabilitiesInfo{
		Tools: []mcp.MCPTool{{Name: "tool1", Enabled: true}},
	}
	
	state.SetCapabilities(tenant, serverName, capabilities)
	
	entry := state.GetCapabilitiesWithDetails(tenant, serverName)
	require.NotNil(t, entry)
	assert.NotNil(t, entry.Info)
	assert.Greater(t, entry.Version, int64(0))
	assert.True(t, time.Now().Before(entry.ExpiresAt))
	assert.Equal(t, int64(1), entry.AccessCount) // First access increments count
}

func TestCapabilitiesExpiration(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	serverName := "test-server"
	
	capabilities := &mcp.CapabilitiesInfo{
		Tools: []mcp.MCPTool{{Name: "tool1", Enabled: true}},
	}
	
	// Set capabilities with very short TTL
	state.SetCapabilitiesWithTTL(tenant, serverName, capabilities, 1*time.Millisecond)
	
	// Immediately should be available
	retrieved := state.GetCapabilities(tenant, serverName)
	assert.NotNil(t, retrieved)
	
	// Wait for expiration
	time.Sleep(10 * time.Millisecond)
	
	// Should be expired now
	expired := state.GetCapabilities(tenant, serverName)
	assert.Nil(t, expired)
}

func TestUpdateCapabilities(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	serverName := "test-server"
	
	// Initial capabilities
	capabilities := &mcp.CapabilitiesInfo{
		Tools: []mcp.MCPTool{
			{Name: "tool1", Enabled: true},
			{Name: "tool2", Enabled: false},
		},
	}
	
	state.SetCapabilities(tenant, serverName, capabilities)
	
	// Update capabilities
	updated := state.UpdateCapabilities(tenant, serverName, func(info *mcp.CapabilitiesInfo) *mcp.CapabilitiesInfo {
		newInfo := *info
		newInfo.Tools = make([]mcp.MCPTool, len(info.Tools))
		copy(newInfo.Tools, info.Tools)
		newInfo.Tools[1].Enabled = true // Enable tool2
		return &newInfo
	})
	
	assert.True(t, updated)
	
	// Verify update
	retrieved := state.GetCapabilities(tenant, serverName)
	require.NotNil(t, retrieved)
	assert.Equal(t, 2, len(retrieved.Tools))
	assert.True(t, retrieved.Tools[1].Enabled)
}

func TestUpdateToolStatus(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	serverName := "test-server"
	
	capabilities := &mcp.CapabilitiesInfo{
		Tools: []mcp.MCPTool{
			{Name: "tool1", Enabled: false},
		},
	}
	
	state.SetCapabilities(tenant, serverName, capabilities)
	
	// Update tool status
	updated := state.UpdateToolStatus(tenant, serverName, "tool1", true)
	assert.True(t, updated)
	
	// Verify update
	retrieved := state.GetCapabilities(tenant, serverName)
	require.NotNil(t, retrieved)
	assert.True(t, retrieved.Tools[0].Enabled)
}

func TestAddTool(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	serverName := "test-server"
	
	// Initial capabilities with one tool
	capabilities := &mcp.CapabilitiesInfo{
		Tools: []mcp.MCPTool{
			{Name: "tool1", Enabled: true},
		},
	}
	
	state.SetCapabilities(tenant, serverName, capabilities)
	
	// Add new tool
	newTool := mcp.MCPTool{
		Name:        "tool2",
		Description: "Second tool",
		Enabled:     true,
	}
	
	added := state.AddTool(tenant, serverName, newTool)
	assert.True(t, added)
	
	// Verify addition
	retrieved := state.GetCapabilities(tenant, serverName)
	require.NotNil(t, retrieved)
	assert.Equal(t, 2, len(retrieved.Tools))
	
	// Find the new tool
	found := false
	for _, tool := range retrieved.Tools {
		if tool.Name == "tool2" {
			assert.Equal(t, "Second tool", tool.Description)
			found = true
			break
		}
	}
	assert.True(t, found)
}

func TestRemoveTool(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	serverName := "test-server"
	
	capabilities := &mcp.CapabilitiesInfo{
		Tools: []mcp.MCPTool{
			{Name: "tool1", Enabled: true},
			{Name: "tool2", Enabled: true},
		},
	}
	
	state.SetCapabilities(tenant, serverName, capabilities)
	
	// Remove tool
	removed := state.RemoveTool(tenant, serverName, "tool1")
	assert.True(t, removed)
	
	// Verify removal
	retrieved := state.GetCapabilities(tenant, serverName)
	require.NotNil(t, retrieved)
	assert.Equal(t, 1, len(retrieved.Tools))
	assert.Equal(t, "tool2", retrieved.Tools[0].Name)
}

func TestRemoveCapabilities(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	serverName := "test-server"
	
	capabilities := &mcp.CapabilitiesInfo{
		Tools: []mcp.MCPTool{{Name: "tool1", Enabled: true}},
	}
	
	state.SetCapabilities(tenant, serverName, capabilities)
	assert.Equal(t, 1, state.GetCapabilitiesCount())
	
	// Remove capabilities
	removed := state.RemoveCapabilities(tenant, serverName)
	assert.True(t, removed)
	assert.Equal(t, 0, state.GetCapabilitiesCount())
	
	// Verify removal
	retrieved := state.GetCapabilities(tenant, serverName)
	assert.Nil(t, retrieved)
}

func TestRemoveCapabilitiesByTenant(t *testing.T) {
	state := NewState()
	
	// Add capabilities for multiple tenants
	state.SetCapabilities("tenant1", "server1", &mcp.CapabilitiesInfo{Tools: []mcp.MCPTool{{Name: "tool1"}}})
	state.SetCapabilities("tenant1", "server2", &mcp.CapabilitiesInfo{Tools: []mcp.MCPTool{{Name: "tool2"}}})
	state.SetCapabilities("tenant2", "server1", &mcp.CapabilitiesInfo{Tools: []mcp.MCPTool{{Name: "tool3"}}})
	
	assert.Equal(t, 3, state.GetCapabilitiesCount())
	
	// Remove all capabilities for tenant1
	removedCount := state.RemoveCapabilitiesByTenant("tenant1")
	assert.Equal(t, 2, removedCount)
	assert.Equal(t, 1, state.GetCapabilitiesCount())
	
	// Verify tenant2 capabilities still exist
	retrieved := state.GetCapabilities("tenant2", "server1")
	assert.NotNil(t, retrieved)
}

func TestCleanExpiredCapabilities(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	
	// Add capabilities with different TTLs
	state.SetCapabilitiesWithTTL(tenant, "server1", &mcp.CapabilitiesInfo{Tools: []mcp.MCPTool{{Name: "tool1"}}}, 1*time.Millisecond)
	state.SetCapabilitiesWithTTL(tenant, "server2", &mcp.CapabilitiesInfo{Tools: []mcp.MCPTool{{Name: "tool2"}}}, 1*time.Hour)
	
	assert.Equal(t, 2, state.GetCapabilitiesCount())
	
	// Wait for first to expire
	time.Sleep(10 * time.Millisecond)
	
	// Clean expired
	removedCount := state.CleanExpiredCapabilities()
	assert.Equal(t, 1, removedCount)
	assert.Equal(t, 1, state.GetCapabilitiesCount())
	
	// Verify only non-expired capabilities remain
	assert.Nil(t, state.GetCapabilities(tenant, "server1"))
	assert.NotNil(t, state.GetCapabilities(tenant, "server2"))
}

func TestGetAllCapabilities(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	
	// Add multiple capabilities for the same tenant
	state.SetCapabilities(tenant, "server1", &mcp.CapabilitiesInfo{Tools: []mcp.MCPTool{{Name: "tool1"}}})
	state.SetCapabilities(tenant, "server2", &mcp.CapabilitiesInfo{Tools: []mcp.MCPTool{{Name: "tool2"}}})
	state.SetCapabilities("other-tenant", "server1", &mcp.CapabilitiesInfo{Tools: []mcp.MCPTool{{Name: "tool3"}}})
	
	// Get all capabilities for the tenant
	allCaps := state.GetAllCapabilities(tenant)
	
	assert.Equal(t, 2, len(allCaps))
	assert.Contains(t, allCaps, "server1")
	assert.Contains(t, allCaps, "server2")
	assert.NotContains(t, allCaps, "other-tenant")
}

func TestGetCapabilitiesStats(t *testing.T) {
	state := NewState()
	
	// Add some test data
	state.SetCapabilities("tenant1", "server1", &mcp.CapabilitiesInfo{
		Tools:     []mcp.MCPTool{{Name: "tool1"}, {Name: "tool2"}},
		Prompts:   []mcp.MCPPrompt{{Name: "prompt1"}},
		Resources: []mcp.MCPResource{{URI: "resource1"}},
	})
	
	// Add expired capability
	state.SetCapabilitiesWithTTL("tenant1", "server2", &mcp.CapabilitiesInfo{Tools: []mcp.MCPTool{{Name: "tool3"}}}, 1*time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	
	stats := state.GetCapabilitiesStats()
	
	assert.Equal(t, 2, stats["totalEntries"])
	assert.Equal(t, 1, stats["validEntries"])
	assert.Equal(t, 1, stats["expiredEntries"])
	assert.Equal(t, 2, stats["totalTools"])
	assert.Equal(t, 1, stats["totalPrompts"])
	assert.Equal(t, 1, stats["totalResources"])
	
	tenants := stats["tenants"].(map[string]int)
	assert.Equal(t, 2, tenants["tenant1"])
}

func TestRefreshCapabilitiesTTL(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	serverName := "test-server"
	
	capabilities := &mcp.CapabilitiesInfo{Tools: []mcp.MCPTool{{Name: "tool1"}}}
	
	// Set capabilities with short TTL
	state.SetCapabilitiesWithTTL(tenant, serverName, capabilities, 50*time.Millisecond)
	
	// Wait halfway to expiration
	time.Sleep(25 * time.Millisecond)
	
	// Refresh TTL
	refreshed := state.RefreshCapabilitiesTTL(tenant, serverName, 1*time.Hour)
	assert.True(t, refreshed)
	
	// Wait past original expiration
	time.Sleep(50 * time.Millisecond)
	
	// Should still be available due to refresh
	retrieved := state.GetCapabilities(tenant, serverName)
	assert.NotNil(t, retrieved)
}

func TestConcurrentAccess(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	serverName := "test-server"
	
	capabilities := &mcp.CapabilitiesInfo{
		Tools: []mcp.MCPTool{{Name: "tool1", Enabled: false}},
	}
	
	state.SetCapabilities(tenant, serverName, capabilities)
	
	// Concurrent access test
	var wg sync.WaitGroup
	numGoroutines := 100
	
	// Concurrent readers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			retrieved := state.GetCapabilities(tenant, serverName)
			assert.NotNil(t, retrieved)
		}()
	}
	
	// Concurrent writers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			toolName := fmt.Sprintf("tool%d", i)
			state.AddTool(tenant, serverName, mcp.MCPTool{
				Name:    toolName,
				Enabled: true,
			})
		}(i)
	}
	
	wg.Wait()
	
	// Verify final state
	retrieved := state.GetCapabilities(tenant, serverName)
	require.NotNil(t, retrieved)
	assert.GreaterOrEqual(t, len(retrieved.Tools), 1) // At least the original tool
}

func TestLRUEviction(t *testing.T) {
	state := NewState()
	
	// Fill cache beyond max capacity
	for i := 0; i < MaxCapabilitiesEntries+10; i++ {
		tenant := fmt.Sprintf("tenant%d", i)
		serverName := fmt.Sprintf("server%d", i)
		capabilities := &mcp.CapabilitiesInfo{
			Tools: []mcp.MCPTool{{Name: fmt.Sprintf("tool%d", i)}},
		}
		state.SetCapabilities(tenant, serverName, capabilities)
	}
	
	// Should have triggered LRU eviction
	assert.LessOrEqual(t, state.GetCapabilitiesCount(), MaxCapabilitiesEntries)
}

func TestVersionControl(t *testing.T) {
	state := NewState()
	tenant := "test-tenant"
	serverName := "test-server"
	
	initialVersion := state.GetCurrentVersion()
	
	capabilities := &mcp.CapabilitiesInfo{Tools: []mcp.MCPTool{{Name: "tool1"}}}
	state.SetCapabilities(tenant, serverName, capabilities)
	
	// Version should have increased
	assert.Greater(t, state.GetCurrentVersion(), initialVersion)
	
	// Get entry version
	version, exists := state.GetCapabilitiesVersion(tenant, serverName)
	assert.True(t, exists)
	assert.Greater(t, version, initialVersion)
	
	// Update should increase version further
	oldVersion := version
	state.UpdateToolStatus(tenant, serverName, "tool1", true)
	
	newVersion, exists := state.GetCapabilitiesVersion(tenant, serverName)
	assert.True(t, exists)
	assert.Greater(t, newVersion, oldVersion)
}

func TestValidateCapabilitiesConsistency(t *testing.T) {
	state := NewState()
	
	// Add valid capability
	state.SetCapabilities("tenant1", "server1", &mcp.CapabilitiesInfo{
		Tools: []mcp.MCPTool{{Name: "tool1"}},
	})
	
	// Test consistency validation
	issues := state.ValidateCapabilitiesConsistency()
	assert.Empty(t, issues, "Valid capabilities should have no issues")
	
	// Manually add invalid entry to test validation
	key := makeCapabilitiesKey("tenant2", "server2")
	invalidEntry := &CapabilitiesEntry{
		Info:       nil, // This should trigger a validation issue
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		LastSynced: time.Now(),
		Version:    -1, // Invalid version
	}
	
	// Access internal state to add invalid entry for testing
	for {
		currentMap := state.capabilities.Load()
		newMap := make(map[capabilitiesKey]*CapabilitiesEntry)
		for k, v := range *currentMap {
			newMap[k] = v
		}
		newMap[key] = invalidEntry
		
		if state.capabilities.CompareAndSwap(currentMap, &newMap) {
			break
		}
	}
	
	issues = state.ValidateCapabilitiesConsistency()
	assert.NotEmpty(t, issues, "Invalid entries should trigger validation issues")
	assert.Contains(t, issues[0], "Nil capabilities info")
}