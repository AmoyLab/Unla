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


// makeCapabilitiesKey creates a capabilities key from tenant and server name
func makeCapabilitiesKey(tenant, serverName string) capabilitiesKey {
	return capabilitiesKey{
		tenant: tenant,
		server: serverName,
	}
}