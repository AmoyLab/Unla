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
	res.Meta = &mcpgo.Meta{AdditionalFields: map[string]any{
		"contains_pii": false,
		"request_id":   "downstream-123",
	}}

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

func TestConvertMCPGoResult_PreservesStructuredContent(t *testing.T) {
	res := &mcpgo.CallToolResult{}
	res.StructuredContent = map[string]any{"temperature": 21.5, "unit": "celsius"}

	out := convertMCPGoResult(res)

	assert.Equal(t, map[string]any{"temperature": 21.5, "unit": "celsius"}, out.StructuredContent)
}

func TestConvertMCPGoResult_PreservesContentMeta(t *testing.T) {
	res := &mcpgo.CallToolResult{}
	res.Content = []mcpgo.Content{
		&mcpgo.TextContent{
			Text: "hello",
			Meta: &mcpgo.Meta{AdditionalFields: map[string]any{
				"ui": map[string]any{"resourceUri": "ui://demo"},
			}},
		},
	}

	out := convertMCPGoResult(res)
	if assert.Len(t, out.Content, 1) {
		textContent, ok := out.Content[0].(*mcp.TextContent)
		if assert.True(t, ok) {
			assert.Equal(t, map[string]any{"ui": map[string]any{"resourceUri": "ui://demo"}}, textContent.Meta)
		}
	}
}

func TestConvertMCPGoResult_PreservesEmbeddedResourceMeta(t *testing.T) {
	resourceMeta := map[string]any{
		"ui": map[string]any{"csp": map[string]any{
			"connectDomains": []string{"https://api.example.com"},
		}},
	}
	res := &mcpgo.CallToolResult{}
	res.Content = []mcpgo.Content{
		&mcpgo.EmbeddedResource{
			Meta: &mcpgo.Meta{AdditionalFields: map[string]any{"source": "upstream"}},
			Type: "resource",
			Resource: mcpgo.TextResourceContents{
				URI:      "ui://demo/index.html",
				MIMEType: "text/html;profile=mcp-app",
				Text:     "<html></html>",
				Meta:     resourceMeta,
			},
		},
	}

	out := convertMCPGoResult(res)
	if assert.Len(t, out.Content, 1) {
		embedded, ok := out.Content[0].(*mcp.EmbeddedResource)
		if assert.True(t, ok) {
			assert.Equal(t, map[string]any{"source": "upstream"}, embedded.Meta)
			contents, ok := embedded.Resource.(mcp.TextResourceContents)
			if assert.True(t, ok) {
				assert.Equal(t, "ui://demo/index.html", contents.URI)
				assert.Equal(t, "text/html;profile=mcp-app", contents.MimeType)
				assert.Equal(t, map[string]any{
					"ui": map[string]any{"csp": map[string]any{
						"connectDomains": []string{"https://api.example.com"},
					}},
				}, contents.Meta)
			}
		}
	}
}

func TestConvertToolMeta(t *testing.T) {
	assert.Nil(t, convertMeta(nil))
	assert.Nil(t, convertMeta(&mcpgo.Meta{}))

	meta := &mcpgo.Meta{AdditionalFields: map[string]any{"a": 1}}
	assert.Equal(t, map[string]any{"a": 1}, convertMeta(meta))
}

func TestConvertAnnotations(t *testing.T) {
	assert.Nil(t, convertAnnotations(nil))
	assert.Nil(t, convertAnnotations(&mcpgo.Annotations{}))

	annotations := convertAnnotations(&mcpgo.Annotations{
		Audience: []mcpgo.Role{mcpgo.RoleUser},
	})
	// Values are JSON-shaped after the wire round-trip.
	assert.Equal(t, map[string]any{"audience": []any{"user"}}, annotations)
}

func TestUIExtensionCapability(t *testing.T) {
	capabilities := uiExtensionCapability()
	ui, ok := capabilities["io.modelcontextprotocol/ui"].(map[string]any)
	if assert.True(t, ok) {
		assert.Equal(t, []string{"text/html;profile=mcp-app"}, ui["mimeTypes"])
	}
}
