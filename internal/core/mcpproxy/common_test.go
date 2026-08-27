package mcpproxy

import (
	"testing"

	"github.com/amoylab/unla/pkg/mcp"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
)

func TestConvertMCPGoResult_ContentMapping(t *testing.T) {
	res := &mcpgo.CallToolResult{IsError: false}
	res.Content = []mcpgo.Content{
		&mcpgo.TextContent{Text: "hello"},
		&mcpgo.ImageContent{Data: "IMG", MIMEType: "image/png"},
		&mcpgo.AudioContent{Data: "AUD", MIMEType: "audio/wav"},
		nil,
	}

	out := convertMCPGoResult(res)
	assert.False(t, out.IsError)
	if assert.Len(t, out.Content, 3) { // nil filtered
		// Just assert types in order
		_, ok0 := out.Content[0].(*mcp.TextContent)
		_, ok1 := out.Content[1].(*mcp.ImageContent)
		_, ok2 := out.Content[2].(*mcp.AudioContent)
		assert.True(t, ok0 && ok1 && ok2)
	}
}

func TestConvertMCPGoResult_IsError(t *testing.T) {
	res := &mcpgo.CallToolResult{IsError: true}
	out := convertMCPGoResult(res)
	assert.True(t, out.IsError)
}

func TestConvertMCPGoResult_PreservesResultMeta(t *testing.T) {
	res := &mcpgo.CallToolResult{IsError: false}
	res.Meta = map[string]any{
		"contains_pii": false,
		"request_id":   "downstream-123",
	}

	out := convertMCPGoResult(res)

	assert.Equal(t, map[string]any{
		"contains_pii": false,
		"request_id":   "downstream-123",
	}, out.Meta)
}

func TestConvertMCPGoResult_EmptyContent(t *testing.T) {
	res := &mcpgo.CallToolResult{IsError: false}
	res.Content = []mcpgo.Content{}

	out := convertMCPGoResult(res)
	assert.False(t, out.IsError)
	assert.Nil(t, out.Content)
}

func TestConvertMCPGoResult_AllNilContent(t *testing.T) {
	res := &mcpgo.CallToolResult{IsError: false}
	res.Content = []mcpgo.Content{nil, nil}

	out := convertMCPGoResult(res)
	assert.False(t, out.IsError)
	assert.Nil(t, out.Content)
}

func TestConvertMCPGoResult_TextContentDetails(t *testing.T) {
	res := &mcpgo.CallToolResult{IsError: false}
	res.Content = []mcpgo.Content{
		&mcpgo.TextContent{Text: "test message"},
	}

	out := convertMCPGoResult(res)
	assert.False(t, out.IsError)
	if assert.Len(t, out.Content, 1) {
		textContent, ok := out.Content[0].(*mcp.TextContent)
		if assert.True(t, ok) {
			assert.Equal(t, "text", textContent.Type)
			assert.Equal(t, "test message", textContent.Text)
		}
	}
}

func TestConvertMCPGoResult_ImageContentDetails(t *testing.T) {
	res := &mcpgo.CallToolResult{IsError: false}
	res.Content = []mcpgo.Content{
		&mcpgo.ImageContent{Data: "base64data", MIMEType: "image/jpeg"},
	}

	out := convertMCPGoResult(res)
	assert.False(t, out.IsError)
	if assert.Len(t, out.Content, 1) {
		imageContent, ok := out.Content[0].(*mcp.ImageContent)
		if assert.True(t, ok) {
			assert.Equal(t, "image", imageContent.Type)
			assert.Equal(t, "base64data", imageContent.Data)
			assert.Equal(t, "image/jpeg", imageContent.MimeType)
		}
	}
}

func TestConvertMCPGoResult_AudioContentDetails(t *testing.T) {
	res := &mcpgo.CallToolResult{IsError: false}
	res.Content = []mcpgo.Content{
		&mcpgo.AudioContent{Data: "base64audio", MIMEType: "audio/mp3"},
	}

	out := convertMCPGoResult(res)
	assert.False(t, out.IsError)
	if assert.Len(t, out.Content, 1) {
		audioContent, ok := out.Content[0].(*mcp.AudioContent)
		if assert.True(t, ok) {
			assert.Equal(t, "audio", audioContent.Type)
			assert.Equal(t, "base64audio", audioContent.Data)
			assert.Equal(t, "audio/mp3", audioContent.MimeType)
		}
	}
}
