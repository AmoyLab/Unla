package state

import (
	"time"
	"github.com/amoylab/unla/pkg/mcp"
)

const (
	// DefaultCapabilitiesTTL defines default TTL for capabilities cache (5 minutes)
	DefaultCapabilitiesTTL = 5 * time.Minute
)

// capabilitiesKey represents a unique key for capabilities cache
type capabilitiesKey struct {
	tenant string
	server string
}

// String returns string representation of the capabilities key
func (k capabilitiesKey) String() string {
	return k.tenant + ":" + k.server
}

// CapabilitiesEntry represents a cached capabilities entry (simplified)
type CapabilitiesEntry struct {
	Info      *mcp.CapabilitiesInfo `json:"info"`
	ExpiresAt time.Time             `json:"expiresAt"`
}

// SetCapabilities atomically updates or creates capabilities info for a tenant and server
func (s *State) SetCapabilities(tenant, serverName string, info *mcp.CapabilitiesInfo) {
	s.SetCapabilitiesWithTTL(tenant, serverName, info, DefaultCapabilitiesTTL)
}

// SetCapabilitiesWithTTL atomically updates capabilities info with custom TTL
func (s *State) SetCapabilitiesWithTTL(tenant, serverName string, info *mcp.CapabilitiesInfo, ttl time.Duration) {
	key := makeCapabilitiesKey(tenant, serverName)
	
	// Create new entry (simplified)
	entry := &CapabilitiesEntry{
		Info:      info,
		ExpiresAt: time.Now().Add(ttl),
	}
	
	// Simple atomic update without complex LRU logic
	for {
		currentMap := s.capabilities.Load()
		newMap := make(map[capabilitiesKey]*CapabilitiesEntry)
		
		// Copy existing non-expired entries
		now := time.Now()
		for k, v := range *currentMap {
			if v.ExpiresAt.After(now) {
				newMap[k] = v
			}
		}
		
		// Add/update the new entry
		newMap[key] = entry
		
		// Try to swap atomically
		if s.capabilities.CompareAndSwap(currentMap, &newMap) {
			break
		}
	}
}

// RemoveCapabilities removes capabilities for a specific tenant and server
func (s *State) RemoveCapabilities(tenant, serverName string) bool {
	key := makeCapabilitiesKey(tenant, serverName)
	
	for {
		currentMap := s.capabilities.Load()
		if _, exists := (*currentMap)[key]; !exists {
			return false
		}
		
		newMap := make(map[capabilitiesKey]*CapabilitiesEntry)
		for k, v := range *currentMap {
			if k != key {
				newMap[k] = v
			}
		}
		
		if s.capabilities.CompareAndSwap(currentMap, &newMap) {
			return true
		}
	}
}

// CleanExpiredCapabilities removes expired capabilities entries
func (s *State) CleanExpiredCapabilities() int {
	removed := 0
	now := time.Now()
	
	for {
		currentMap := s.capabilities.Load()
		newMap := make(map[capabilitiesKey]*CapabilitiesEntry)
		
		for k, v := range *currentMap {
			if v.ExpiresAt.After(now) {
				newMap[k] = v
			} else {
				removed++
			}
		}
		
		if s.capabilities.CompareAndSwap(currentMap, &newMap) {
			break
		}
	}
	
	return removed
}

// UpdateToolStatus updates the status of a specific tool (simplified)
func (s *State) UpdateToolStatus(tenant, serverName, toolName string, enabled bool) bool {
	key := makeCapabilitiesKey(tenant, serverName)
	
	for {
		currentMap := s.capabilities.Load()
		entry, exists := (*currentMap)[key]
		if !exists || entry.ExpiresAt.Before(time.Now()) {
			return false
		}
		
		// Create updated capabilities info
		newInfo := &mcp.CapabilitiesInfo{
			Tools:             entry.Info.Tools,
			Prompts:          entry.Info.Prompts,
			Resources:        entry.Info.Resources,
			ResourceTemplates: entry.Info.ResourceTemplates,
		}
		
		// Update tool status if tool exists
		toolFound := false
		if newInfo.Tools != nil {
			for _, tool := range newInfo.Tools {
				if tool.Name == toolName {
					// Create new tool with updated status (if ToolWithStatus interface exists)
					if toolWithStatus, ok := interface{}(tool).(interface{ SetEnabled(bool) }); ok {
						toolWithStatus.SetEnabled(enabled)
					}
					toolFound = true
					break
				}
			}
		}
		
		if !toolFound {
			return false
		}
		
		// Create new entry
		newEntry := &CapabilitiesEntry{
			Info:      newInfo,
			ExpiresAt: entry.ExpiresAt,
		}
		
		// Create new map with updated entry
		newMap := make(map[capabilitiesKey]*CapabilitiesEntry)
		for k, v := range *currentMap {
			if k == key {
				newMap[k] = newEntry
			} else {
				newMap[k] = v
			}
		}
		
		if s.capabilities.CompareAndSwap(currentMap, &newMap) {
			return true
		}
	}
}

// makeCapabilitiesKey creates a capabilities key from tenant and server name
func makeCapabilitiesKey(tenant, serverName string) capabilitiesKey {
	return capabilitiesKey{
		tenant: tenant,
		server: serverName,
	}
}