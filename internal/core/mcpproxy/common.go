package mcpproxy

import (
	"encoding/json"

	"github.com/amoylab/unla/pkg/mcp"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
)

// uiExtensionCapability returns the MCP Apps UI extension capability
// (SEP-1865) advertised in initialize.params.capabilities.extensions, so
// upstream servers that gate `_meta.ui` declarations on client support keep
// declaring them behind the gateway.
func uiExtensionCapability() map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/ui": map[string]any{
			"mimeTypes": []string{"text/html;profile=mcp-app"},
		},
	}
}

// convertMeta converts mcp-go `_meta` to a plain map so MCP Apps
// metadata (e.g. `_meta.ui.resourceUri`) survives the gateway hop.
func convertMeta(meta *mcpgo.Meta) map[string]any {
	if meta == nil || len(meta.AdditionalFields) == 0 {
		return nil
	}
	out := make(map[string]any, len(meta.AdditionalFields))
	for k, v := range meta.AdditionalFields {
		out[k] = v
	}
	return out
}

// convertResourceContents converts mcp-go resource contents to local mcp format
func convertResourceContents(rc mcpgo.ResourceContents) any {
	switch c := rc.(type) {
	case mcpgo.TextResourceContents:
		return mcp.TextResourceContents{
			URI:      c.URI,
			MimeType: c.MIMEType,
			Text:     c.Text,
			Meta:     c.Meta,
		}
	case mcpgo.BlobResourceContents:
		return mcp.BlobResourceContents{
			URI:      c.URI,
			MimeType: c.MIMEType,
			Blob:     c.Blob,
			Meta:     c.Meta,
		}
	default:
		return nil
	}
}

// convertMCPGoResult converts mcp-go result to local mcp format
func convertMCPGoResult(res *mcpgo.CallToolResult) *mcp.CallToolResult {
	result := &mcp.CallToolResult{
		IsError:           res.IsError,
		Meta:              convertMeta(res.Meta),
		StructuredContent: res.StructuredContent,
	}

	// Process content items
	if len(res.Content) > 0 {
		var validContents []mcp.Content

		for _, content := range res.Content {
			// Skip null content
			if content == nil {
				continue
			}

			// Try to get content type
			contentType := ""
			switch c := content.(type) {
			case *mcpgo.TextContent:
				contentType = "text"
				validContents = append(validContents, &mcp.TextContent{
					Type: "text",
					Text: c.Text,
					Meta: convertMeta(c.Meta),
				})
			case *mcpgo.ImageContent:
				contentType = "image"
				validContents = append(validContents, &mcp.ImageContent{
					Type:     "image",
					Data:     c.Data,
					MimeType: c.MIMEType,
					Meta:     convertMeta(c.Meta),
				})
			case *mcpgo.AudioContent:
				contentType = "audio"
				validContents = append(validContents, &mcp.AudioContent{
					Type:     "audio",
					Data:     c.Data,
					MimeType: c.MIMEType,
					Meta:     convertMeta(c.Meta),
				})
			case *mcpgo.EmbeddedResource:
				contentType = "resource"
				validContents = append(validContents, &mcp.EmbeddedResource{
					Type:     "resource",
					Resource: convertResourceContents(c.Resource),
					Meta:     convertMeta(c.Meta),
				})
			default:
				// Try to parse from raw content
				rawContent, err := json.Marshal(content)
				if err == nil {
					var contentMap map[string]interface{}
					if json.Unmarshal(rawContent, &contentMap) == nil {
						if typ, ok := contentMap["type"].(string); ok {
							contentType = typ

							switch contentType {
							case "text":
								if text, ok := contentMap["text"].(string); ok {
									validContents = append(validContents, &mcp.TextContent{
										Type: "text",
										Text: text,
									})
								}
							case "image":
								data, _ := contentMap["data"].(string)
								mimeType, _ := contentMap["mimeType"].(string)
								validContents = append(validContents, &mcp.ImageContent{
									Type:     "image",
									Data:     data,
									MimeType: mimeType,
								})
							case "audio":
								data, _ := contentMap["data"].(string)
								mimeType, _ := contentMap["mimeType"].(string)
								validContents = append(validContents, &mcp.AudioContent{
									Type:     "audio",
									Data:     data,
									MimeType: mimeType,
								})
							}
						}
					}
				}
			}
		}

		if len(validContents) > 0 {
			result.Content = validContents
		}
	}

	return result
}
