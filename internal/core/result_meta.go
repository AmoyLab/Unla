package core

import "github.com/amoylab/unla/pkg/mcp"

// mergeToolResultMeta adds tool metadata to a call result without replacing
// metadata returned by the tool implementation itself.
func mergeToolResultMeta(result *mcp.CallToolResult, toolMeta map[string]any) {
	if result == nil || len(toolMeta) == 0 {
		return
	}

	if result.Meta == nil {
		result.Meta = make(map[string]any, len(toolMeta))
	}
	for key, value := range toolMeta {
		if _, exists := result.Meta[key]; !exists {
			result.Meta[key] = value
		}
	}
}
