package core

import (
	"testing"

	"github.com/amoylab/unla/pkg/mcp"
	"github.com/stretchr/testify/assert"
)

func TestMergeToolResultMetaFillsOnlyMissingKeys(t *testing.T) {
	result := mcp.NewCallToolResultText("ok")
	result.Meta = map[string]any{
		"contains_pii":  false,
		"explicit_null": nil,
		"result_only":   "result",
	}
	toolMeta := map[string]any{
		"contains_pii":  true,
		"explicit_null": "tool",
		"tool_only":     "tool",
	}

	mergeToolResultMeta(result, toolMeta)

	assert.Equal(t, map[string]any{
		"contains_pii":  false,
		"explicit_null": nil,
		"result_only":   "result",
		"tool_only":     "tool",
	}, result.Meta)
}

func TestMergeToolResultMetaCopiesToolMap(t *testing.T) {
	result := mcp.NewCallToolResultText("ok")
	toolMeta := map[string]any{"contains_pii": true}

	mergeToolResultMeta(result, toolMeta)
	toolMeta["contains_pii"] = false

	assert.Equal(t, map[string]any{"contains_pii": true}, result.Meta)
}

func TestMergeToolResultMetaIgnoresEmptyInputs(t *testing.T) {
	result := mcp.NewCallToolResultText("ok")

	assert.NotPanics(t, func() {
		mergeToolResultMeta(nil, map[string]any{"contains_pii": true})
		mergeToolResultMeta(result, nil)
		mergeToolResultMeta(result, map[string]any{})
	})
	assert.Nil(t, result.Meta)
}
