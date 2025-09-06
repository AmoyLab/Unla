package state

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/amoylab/unla/pkg/mcp"
)

const (
	// DefaultCapabilitiesTTL defines default TTL for capabilities cache (5 minutes)
	DefaultCapabilitiesTTL = 5 * time.Minute
	// MaxCapabilitiesEntries defines the maximum number of entries in LRU cache
	MaxCapabilitiesEntries = 1000
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

// CapabilitiesEntry represents a cached capabilities entry with metadata
type CapabilitiesEntry struct {
	Info        *mcp.CapabilitiesInfo `json:"info"`
	ExpiresAt   time.Time             `json:"expiresAt"`
	LastSynced  time.Time             `json:"lastSynced"`
	Version     int64                 `json:"version"`
	AccessCount int64                 `json:"accessCount"`
	Errors      []string              `json:"errors,omitempty"`
}

// SetCapabilities atomically updates or creates capabilities info for a tenant and server
func (s *State) SetCapabilities(tenant, serverName string, info *mcp.CapabilitiesInfo) {
	s.SetCapabilitiesWithTTL(tenant, serverName, info, DefaultCapabilitiesTTL)
}

// SetCapabilitiesWithTTL atomically updates capabilities info with custom TTL
func (s *State) SetCapabilitiesWithTTL(tenant, serverName string, info *mcp.CapabilitiesInfo, ttl time.Duration) {
	key := makeCapabilitiesKey(tenant, serverName)
	now := time.Now()
	
	// Create new entry
	entry := &CapabilitiesEntry{
		Info:        info,
		ExpiresAt:   now.Add(ttl),
		LastSynced:  now,
		Version:     s.version.Add(1),
		AccessCount: 0,
		Errors:      nil,
	}
	
	// Update capabilities atomically using copy-on-write
	for {
		currentMap := s.capabilities.Load()
		newMap := make(map[capabilitiesKey]*CapabilitiesEntry)
		
		// Copy existing entries
		for k, v := range *currentMap {
			newMap[k] = v
		}
		
		// Add/update the new entry
		newMap[key] = entry
		
		// Apply LRU eviction if necessary
		if len(newMap) > MaxCapabilitiesEntries {
			s.evictLRUEntries(newMap, MaxCapabilitiesEntries*9/10) // Keep 90% of max
		}
		
		// Try to swap atomically
		if s.capabilities.CompareAndSwap(currentMap, &newMap) {
			break
		}
		// If CAS failed, retry with updated data
	}
}

// SetCapabilitiesWithError atomically updates capabilities info with error information
func (s *State) SetCapabilitiesWithError(tenant, serverName string, info *mcp.CapabilitiesInfo, errors []string) {
	key := makeCapabilitiesKey(tenant, serverName)
	now := time.Now()
	
	// Create new entry
	entry := &CapabilitiesEntry{
		Info:        info,
		ExpiresAt:   now.Add(DefaultCapabilitiesTTL),
		LastSynced:  now,
		Version:     s.version.Add(1),
		AccessCount: 0,
		Errors:      errors,
	}
	
	// Update capabilities atomically
	for {
		currentMap := s.capabilities.Load()
		newMap := make(map[capabilitiesKey]*CapabilitiesEntry)
		
		// Copy existing entries
		for k, v := range *currentMap {
			newMap[k] = v
		}
		
		// Add/update the new entry
		newMap[key] = entry
		
		// Apply LRU eviction if necessary
		if len(newMap) > MaxCapabilitiesEntries {
			s.evictLRUEntries(newMap, MaxCapabilitiesEntries*9/10)
		}
		
		// Try to swap atomically
		if s.capabilities.CompareAndSwap(currentMap, &newMap) {
			break
		}
	}
}

// RemoveCapabilities atomically removes capabilities info for a tenant and server
func (s *State) RemoveCapabilities(tenant, serverName string) bool {
	key := makeCapabilitiesKey(tenant, serverName)
	
	for {
		currentMap := s.capabilities.Load()
		
		// Check if entry exists
		if _, exists := (*currentMap)[key]; !exists {
			return false
		}
		
		// Create new map without the entry
		newMap := make(map[capabilitiesKey]*CapabilitiesEntry)
		for k, v := range *currentMap {
			if k != key {
				newMap[k] = v
			}
		}
		
		// Try to swap atomically
		if s.capabilities.CompareAndSwap(currentMap, &newMap) {
			return true
		}
	}
}

// RemoveCapabilitiesByTenant atomically removes all capabilities for a tenant
func (s *State) RemoveCapabilitiesByTenant(tenant string) int {
	tenantPrefix := tenant + ":"
	
	for {
		currentMap := s.capabilities.Load()
		newMap := make(map[capabilitiesKey]*CapabilitiesEntry)
		removedCount := 0
		
		// Copy entries that don't belong to the tenant
		for k, v := range *currentMap {
			keyStr := k.String()
			if len(keyStr) > len(tenantPrefix) && keyStr[:len(tenantPrefix)] == tenantPrefix {
				removedCount++
			} else {
				newMap[k] = v
			}
		}
		
		// If no entries were found for this tenant, return 0
		if removedCount == 0 {
			return 0
		}
		
		// Try to swap atomically
		if s.capabilities.CompareAndSwap(currentMap, &newMap) {
			return removedCount
		}
	}
}

// evictLRUEntries removes the least recently used entries to keep the cache size under limit
func (s *State) evictLRUEntries(capMap map[capabilitiesKey]*CapabilitiesEntry, targetSize int) {
	if len(capMap) <= targetSize {
		return
	}
	
	// Create a slice of entries with their keys for sorting
	type entryWithKey struct {
		key   capabilitiesKey
		entry *CapabilitiesEntry
	}
	
	entries := make([]entryWithKey, 0, len(capMap))
	for key, entry := range capMap {
		entries = append(entries, entryWithKey{key: key, entry: entry})
	}
	
	// Sort by access count (ascending) and then by last synced time (ascending)
	// This prioritizes keeping frequently accessed and recently synced entries
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].entry.AccessCount != entries[j].entry.AccessCount {
			return entries[i].entry.AccessCount < entries[j].entry.AccessCount
		}
		return entries[i].entry.LastSynced.Before(entries[j].entry.LastSynced)
	})
	
	// Remove the least recently used entries
	entriesToRemove := len(capMap) - targetSize
	for i := 0; i < entriesToRemove; i++ {
		delete(capMap, entries[i].key)
	}
}

// CleanExpiredCapabilities removes all expired capabilities entries
func (s *State) CleanExpiredCapabilities() int {
	now := time.Now()
	
	for {
		currentMap := s.capabilities.Load()
		newMap := make(map[capabilitiesKey]*CapabilitiesEntry)
		removedCount := 0
		
		// Copy non-expired entries
		for k, v := range *currentMap {
			if now.Before(v.ExpiresAt) {
				newMap[k] = v
			} else {
				removedCount++
			}
		}
		
		// If no expired entries were found, return 0
		if removedCount == 0 {
			return 0
		}
		
		// Try to swap atomically
		if s.capabilities.CompareAndSwap(currentMap, &newMap) {
			return removedCount
		}
	}
}

// RefreshCapabilitiesTTL extends the TTL for a specific capabilities entry
func (s *State) RefreshCapabilitiesTTL(tenant, serverName string, ttl time.Duration) bool {
	key := makeCapabilitiesKey(tenant, serverName)
	
	for {
		currentMap := s.capabilities.Load()
		
		// Check if entry exists and is not expired
		existingEntry, exists := (*currentMap)[key]
		if !exists || time.Now().After(existingEntry.ExpiresAt) {
			return false
		}
		
		// Create new map with updated TTL
		newMap := make(map[capabilitiesKey]*CapabilitiesEntry)
		for k, v := range *currentMap {
			if k == key {
				// Create a copy of the entry with updated expiry time
				updatedEntry := *v
				updatedEntry.ExpiresAt = time.Now().Add(ttl)
				newMap[k] = &updatedEntry
			} else {
				newMap[k] = v
			}
		}
		
		// Try to swap atomically
		if s.capabilities.CompareAndSwap(currentMap, &newMap) {
			return true
		}
	}
}

// UpdateCapabilities performs incremental updates to capabilities info
func (s *State) UpdateCapabilities(tenant, serverName string, updateFunc func(*mcp.CapabilitiesInfo) *mcp.CapabilitiesInfo) bool {
	key := makeCapabilitiesKey(tenant, serverName)
	
	for {
		currentMap := s.capabilities.Load()
		
		// Check if entry exists and is not expired
		existingEntry, exists := (*currentMap)[key]
		if !exists || time.Now().After(existingEntry.ExpiresAt) {
			return false
		}
		
		// Apply the update function
		updatedInfo := updateFunc(existingEntry.Info)
		if updatedInfo == nil {
			return false
		}
		
		// Create new map with updated capabilities
		newMap := make(map[capabilitiesKey]*CapabilitiesEntry)
		for k, v := range *currentMap {
			if k == key {
				// Create a copy of the entry with updated capabilities
				updatedEntry := *v
				updatedEntry.Info = updatedInfo
				updatedEntry.LastSynced = time.Now()
				updatedEntry.Version = s.version.Add(1)
				newMap[k] = &updatedEntry
			} else {
				newMap[k] = v
			}
		}
		
		// Try to swap atomically
		if s.capabilities.CompareAndSwap(currentMap, &newMap) {
			return true
		}
	}
}

// UpdateToolStatus updates the enabled status and last synced time for a specific tool
func (s *State) UpdateToolStatus(tenant, serverName, toolName string, enabled bool) bool {
	return s.UpdateCapabilities(tenant, serverName, func(info *mcp.CapabilitiesInfo) *mcp.CapabilitiesInfo {
		// Create a copy of the capabilities info
		updatedInfo := &mcp.CapabilitiesInfo{
			Tools:             make([]mcp.MCPTool, len(info.Tools)),
			Prompts:           info.Prompts,
			Resources:         info.Resources,
			ResourceTemplates: info.ResourceTemplates,
			LastSynced:        time.Now(),
			ServerInfo:        info.ServerInfo,
		}
		
		// Copy tools and update the specific one
		found := false
		for i, tool := range info.Tools {
			updatedInfo.Tools[i] = tool
			if tool.Name == toolName {
				found = true
			}
		}
		
		if !found {
			return nil // Tool not found
		}
		
		return updatedInfo
	})
}

// AddTool adds a new tool to the capabilities or updates an existing one
func (s *State) AddTool(tenant, serverName string, tool mcp.MCPTool) bool {
	return s.UpdateCapabilities(tenant, serverName, func(info *mcp.CapabilitiesInfo) *mcp.CapabilitiesInfo {
		// Create a copy of the capabilities info
		updatedInfo := &mcp.CapabilitiesInfo{
			Tools:             make([]mcp.MCPTool, 0, len(info.Tools)+1),
			Prompts:           info.Prompts,
			Resources:         info.Resources,
			ResourceTemplates: info.ResourceTemplates,
			LastSynced:        time.Now(),
			ServerInfo:        info.ServerInfo,
		}
		
		// Copy existing tools and check for duplicates
		found := false
		for _, existingTool := range info.Tools {
			if existingTool.Name == tool.Name {
				// Update existing tool
				updatedInfo.Tools = append(updatedInfo.Tools, tool)
				found = true
			} else {
				updatedInfo.Tools = append(updatedInfo.Tools, existingTool)
			}
		}
		
		// Add new tool if not found
		if !found {
			updatedInfo.Tools = append(updatedInfo.Tools, tool)
		}
		
		return updatedInfo
	})
}

// RemoveTool removes a tool from the capabilities
func (s *State) RemoveTool(tenant, serverName, toolName string) bool {
	return s.UpdateCapabilities(tenant, serverName, func(info *mcp.CapabilitiesInfo) *mcp.CapabilitiesInfo {
		// Create a copy of the capabilities info
		updatedInfo := &mcp.CapabilitiesInfo{
			Tools:             make([]mcp.MCPTool, 0, len(info.Tools)),
			Prompts:           info.Prompts,
			Resources:         info.Resources,
			ResourceTemplates: info.ResourceTemplates,
			LastSynced:        time.Now(),
			ServerInfo:        info.ServerInfo,
		}
		
		// Copy tools except the one to remove
		found := false
		for _, tool := range info.Tools {
			if tool.Name != toolName {
				updatedInfo.Tools = append(updatedInfo.Tools, tool)
			} else {
				found = true
			}
		}
		
		if !found {
			return nil // Tool not found
		}
		
		return updatedInfo
	})
}

// UpdatePrompt adds or updates a prompt in the capabilities
func (s *State) UpdatePrompt(tenant, serverName string, prompt mcp.MCPPrompt) bool {
	return s.UpdateCapabilities(tenant, serverName, func(info *mcp.CapabilitiesInfo) *mcp.CapabilitiesInfo {
		// Create a copy of the capabilities info
		updatedInfo := &mcp.CapabilitiesInfo{
			Tools:             info.Tools,
			Prompts:           make([]mcp.MCPPrompt, 0, len(info.Prompts)+1),
			Resources:         info.Resources,
			ResourceTemplates: info.ResourceTemplates,
			LastSynced:        time.Now(),
			ServerInfo:        info.ServerInfo,
		}
		
		// Copy existing prompts and check for duplicates
		found := false
		for _, existingPrompt := range info.Prompts {
			if existingPrompt.Name == prompt.Name {
				// Update existing prompt
				updatedInfo.Prompts = append(updatedInfo.Prompts, prompt)
				found = true
			} else {
				updatedInfo.Prompts = append(updatedInfo.Prompts, existingPrompt)
			}
		}
		
		// Add new prompt if not found
		if !found {
			updatedInfo.Prompts = append(updatedInfo.Prompts, prompt)
		}
		
		return updatedInfo
	})
}

// UpdateResource adds or updates a resource in the capabilities
func (s *State) UpdateResource(tenant, serverName string, resource mcp.MCPResource) bool {
	return s.UpdateCapabilities(tenant, serverName, func(info *mcp.CapabilitiesInfo) *mcp.CapabilitiesInfo {
		// Create a copy of the capabilities info
		updatedInfo := &mcp.CapabilitiesInfo{
			Tools:             info.Tools,
			Prompts:           info.Prompts,
			Resources:         make([]mcp.MCPResource, 0, len(info.Resources)+1),
			ResourceTemplates: info.ResourceTemplates,
			LastSynced:        time.Now(),
			ServerInfo:        info.ServerInfo,
		}
		
		// Copy existing resources and check for duplicates
		found := false
		for _, existingResource := range info.Resources {
			if existingResource.Uri == resource.Uri {
				// Update existing resource
				updatedInfo.Resources = append(updatedInfo.Resources, resource)
				found = true
			} else {
				updatedInfo.Resources = append(updatedInfo.Resources, existingResource)
			}
		}
		
		// Add new resource if not found
		if !found {
			updatedInfo.Resources = append(updatedInfo.Resources, resource)
		}
		
		return updatedInfo
	})
}

// CleanCapabilitiesForRemovedServers removes capabilities for servers that no longer exist in the configuration
func (s *State) CleanCapabilitiesForRemovedServers(activeServers map[string]bool) int {
	removedCount := 0
	
	for {
		currentMap := s.capabilities.Load()
		newMap := make(map[capabilitiesKey]*CapabilitiesEntry)
		
		// Copy entries for servers that are still active
		for key, entry := range *currentMap {
			keyStr := key.String()
			// Extract server name from key (format: tenant:serverName)
			if colonPos := strings.Index(keyStr, ":"); colonPos > 0 && colonPos < len(keyStr)-1 {
				serverName := keyStr[colonPos+1:]
				if activeServers[serverName] {
					newMap[key] = entry
				} else {
					removedCount++
				}
			} else {
				// Keep entries with invalid format for safety
				newMap[key] = entry
			}
		}
		
		// If no entries were removed, return 0
		if removedCount == 0 {
			return 0
		}
		
		// Try to swap atomically
		if s.capabilities.CompareAndSwap(currentMap, &newMap) {
			return removedCount
		}
		// Reset counter for retry
		removedCount = 0
	}
}

// ValidateCapabilitiesConsistency checks for inconsistencies in the capabilities cache
func (s *State) ValidateCapabilitiesConsistency() []string {
	capabilityMap := s.capabilities.Load()
	issues := make([]string, 0)
	
	for key, entry := range *capabilityMap {
		keyStr := key.String()
		
		// Check key format
		if !strings.Contains(keyStr, ":") {
			issues = append(issues, fmt.Sprintf("Invalid key format: %s", keyStr))
			continue
		}
		
		// Check for nil info
		if entry.Info == nil {
			issues = append(issues, fmt.Sprintf("Nil capabilities info for key: %s", keyStr))
			continue
		}
		
		// Check expiration logic consistency
		if entry.ExpiresAt.Before(entry.LastSynced) {
			issues = append(issues, fmt.Sprintf("Expiry time before sync time for key: %s", keyStr))
		}
		
		// Check version consistency
		if entry.Version <= 0 {
			issues = append(issues, fmt.Sprintf("Invalid version for key: %s", keyStr))
		}
	}
	
	return issues
}

// makeCapabilitiesKey creates a cache key from tenant and server name
func makeCapabilitiesKey(tenant, serverName string) capabilitiesKey {
	return capabilitiesKey{
		tenant: tenant,
		server: serverName,
	}
}