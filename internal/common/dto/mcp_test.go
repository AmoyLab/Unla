package dto

import (
	"testing"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/stretchr/testify/assert"
)

func TestFromArgConfigsAndItemsConfig(t *testing.T) {
	// Nested Items recursion and properties conversion
	nested := config.ItemsConfig{
		Type: "object",
		Properties: map[string]any{
			"child": config.ItemsConfig{Type: "array", Enum: []string{"a", "b"}},
			"raw":   "keep",
		},
		Required: []string{"child"},
	}
	cfgs := []config.ArgConfig{{
		Name: "x", Position: "query", Required: true, Type: "array",
		Description: "desc", Default: "d", Items: nested,
	}}

	// Convert
	out := FromArgConfigs(cfgs)
	if assert.Len(t, out, 1) {
		got := out[0]
		assert.Equal(t, "x", got.Name)
		assert.Equal(t, "query", got.Position)
		assert.Equal(t, true, got.Required)
		assert.Equal(t, "array", got.Type)
		assert.Equal(t, "desc", got.Description)
		assert.Equal(t, "d", got.Default)

		// Items converted
		assert.Equal(t, "object", got.Items.Type)
		// Properties map keeps non-Items values and converts Items recursively
		props := got.Items.Properties
		assert.Equal(t, "keep", props["raw"])
		child := props["child"].(ItemsConfig)
		assert.Equal(t, []string{"a", "b"}, child.Enum)
	}

	// nil case
	assert.Nil(t, FromArgConfigs(nil))
}

func TestFromMCPServerConfigsAndAuthPrompt(t *testing.T) {
	ms := []config.MCPServerConfig{{
		Type: "sse", Name: "n", Command: "cmd", Args: []string{"a"}, Env: map[string]string{"k": "v"}, URL: "u",
		Headers: map[string]string{"Authorization": "Bearer token", "X-Req": "v"},
		Policy:  "onStart", Preinstalled: true,
	}}
	out := FromMCPServerConfigs(ms)
	if assert.Len(t, out, 1) {
		assert.Equal(t, "sse", out[0].Type)
		assert.Equal(t, "n", out[0].Name)
		assert.Equal(t, "cmd", out[0].Command)
		assert.Equal(t, []string{"a"}, out[0].Args)
		assert.Equal(t, "u", out[0].URL)
		assert.Equal(t, map[string]string{"Authorization": "Bearer token", "X-Req": "v"}, out[0].Headers)
		assert.Equal(t, "onStart", out[0].Policy)
		assert.True(t, out[0].Preinstalled)
	}
	assert.Nil(t, FromMCPServerConfigs(nil))

	// Auth conversion
	a := FromAuthConfig(&config.Auth{Mode: "oauth2"})
	assert.NotNil(t, a)
	assert.Equal(t, "oauth2", a.Mode)

	// Prompt conversions
	pr := []config.PromptResponse{{Role: "system", Content: config.PromptResponseContent{Type: "text", Text: "hello"}}}
	args := []config.PromptArgument{{Name: "u", Description: "user", Required: true}}
	p := []config.PromptConfig{{Name: "p1", Description: "d", Arguments: args, PromptResponse: pr}}
	ps := FromPromptConfigs(p)
	if assert.Len(t, ps, 1) {
		assert.Equal(t, "p1", ps[0].Name)
		assert.Equal(t, "d", ps[0].Description)
		if assert.Len(t, ps[0].Arguments, 1) {
			assert.Equal(t, "u", ps[0].Arguments[0].Name)
		}
		if assert.Len(t, ps[0].PromptResponse, 1) {
			assert.Equal(t, "system", ps[0].PromptResponse[0].Role)
			assert.Equal(t, "text", ps[0].PromptResponse[0].Content.Type)
		}
	}

	assert.Nil(t, FromPromptConfigs(nil))
	assert.Nil(t, FromPromptArguments(nil))
	assert.Nil(t, FromPromptResponses(nil))
}
