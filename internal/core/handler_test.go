package core

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/template"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateResponseHandlerChain(t *testing.T) {
	handler := CreateResponseHandlerChain()
	assert.NotNil(t, handler)

	// Should be ImageHandler as the first handler
	imageHandler, ok := handler.(*ImageHandler)
	assert.True(t, ok)
	assert.NotNil(t, imageHandler)
}

func TestBaseHandler_SetNext(t *testing.T) {
	base := &BaseHandler{}
	text := &TextHandler{}

	base.SetNext(text)
	assert.Equal(t, text, base.next)
}

func TestBaseHandler_HandleNext(t *testing.T) {
	base := &BaseHandler{}
	text := &TextHandler{}
	base.SetNext(text)

	// Create a test HTTP response
	resp := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewReader([]byte("test content"))),
	}
	resp.Header.Set("Content-Type", "text/plain")

	tool := &config.ToolConfig{}
	tmplCtx := template.NewContext()

	result, err := base.HandleNext(resp, tool, tmplCtx)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestBaseHandler_HandleNext_NoNext(t *testing.T) {
	base := &BaseHandler{}

	// Create a test HTTP response
	resp := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewReader([]byte("test content"))),
	}
	resp.Header.Set("Content-Type", "text/plain")

	tool := &config.ToolConfig{}
	tmplCtx := template.NewContext()

	result, err := base.HandleNext(resp, tool, tmplCtx)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestTextHandler_CanHandle(t *testing.T) {
	handler := &TextHandler{}

	// TextHandler should handle any response
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/plain")
	assert.True(t, handler.CanHandle(resp))

	resp.Header.Set("Content-Type", "application/json")
	assert.True(t, handler.CanHandle(resp))

	resp.Header.Set("Content-Type", "image/png")
	assert.True(t, handler.CanHandle(resp))
}

func TestTextHandler_Handle(t *testing.T) {
	handler := &TextHandler{}

	// Test with plain text response
	resp := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewReader([]byte("test content"))),
	}
	resp.Header.Set("Content-Type", "text/plain")

	tool := &config.ToolConfig{}
	tmplCtx := template.NewContext()

	result, err := handler.Handle(resp, tool, tmplCtx)
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Len(t, result.Content, 1)
}

func TestTextHandler_Handle_WithResponseBodyTemplate(t *testing.T) {
	handler := &TextHandler{}

	// Test with JSON response and template
	resp := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewReader([]byte(`{"message": "hello world"}`))),
	}
	resp.Header.Set("Content-Type", "application/json")

	tool := &config.ToolConfig{
		ResponseBody: "Message: {{.Response.Data.message}}",
	}
	tmplCtx := template.NewContext()

	result, err := handler.Handle(resp, tool, tmplCtx)
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Len(t, result.Content, 1)
}

func TestImageHandler_CanHandle(t *testing.T) {
	handler := &ImageHandler{}

	// Should handle image content types
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "image/png")
	assert.True(t, handler.CanHandle(resp))

	resp.Header.Set("Content-Type", "image/jpeg")
	assert.True(t, handler.CanHandle(resp))

	// Should not handle non-image content types
	resp.Header.Set("Content-Type", "text/plain")
	assert.False(t, handler.CanHandle(resp))

	resp.Header.Set("Content-Type", "application/json")
	assert.False(t, handler.CanHandle(resp))
}

func TestImageHandler_Handle(t *testing.T) {
	handler := &ImageHandler{}

	// Test with image response
	imageData := []byte("fake image data")
	resp := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewReader(imageData)),
	}
	resp.Header.Set("Content-Type", "image/png")

	tool := &config.ToolConfig{}
	tmplCtx := template.NewContext()

	result, err := handler.Handle(resp, tool, tmplCtx)
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Len(t, result.Content, 1)
}

func TestImageHandler_Handle_NotImage(t *testing.T) {
	handler := &ImageHandler{}
	textHandler := &TextHandler{}
	handler.SetNext(textHandler)

	// Test with non-image response should delegate to next handler
	resp := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewReader([]byte("text content"))),
	}
	resp.Header.Set("Content-Type", "text/plain")

	tool := &config.ToolConfig{}
	tmplCtx := template.NewContext()

	result, err := handler.Handle(resp, tool, tmplCtx)
	assert.NoError(t, err)
	require.NotNil(t, result)
}

func TestAudioHandler_CanHandle(t *testing.T) {
	handler := &AudioHandler{}

	// Should handle audio content types
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "audio/mp3")
	assert.True(t, handler.CanHandle(resp))

	resp.Header.Set("Content-Type", "audio/wav")
	assert.True(t, handler.CanHandle(resp))

	// Should not handle non-audio content types
	resp.Header.Set("Content-Type", "text/plain")
	assert.False(t, handler.CanHandle(resp))

	resp.Header.Set("Content-Type", "image/png")
	assert.False(t, handler.CanHandle(resp))
}

func TestAudioHandler_Handle(t *testing.T) {
	handler := &AudioHandler{}

	// Test with audio response
	audioData := []byte("fake audio data")
	resp := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewReader(audioData)),
	}
	resp.Header.Set("Content-Type", "audio/mp3")

	tool := &config.ToolConfig{}
	tmplCtx := template.NewContext()

	result, err := handler.Handle(resp, tool, tmplCtx)
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Len(t, result.Content, 1)
}

func TestAudioHandler_Handle_NotAudio(t *testing.T) {
	handler := &AudioHandler{}
	textHandler := &TextHandler{}
	handler.SetNext(textHandler)

	// Test with non-audio response should delegate to next handler
	resp := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewReader([]byte("text content"))),
	}
	resp.Header.Set("Content-Type", "text/plain")

	tool := &config.ToolConfig{}
	tmplCtx := template.NewContext()

	result, err := handler.Handle(resp, tool, tmplCtx)
	assert.NoError(t, err)
	require.NotNil(t, result)
}

func TestHandlerChain_Integration(t *testing.T) {
	// Test the full chain
	chain := CreateResponseHandlerChain()

	tests := []struct {
		name        string
		contentType string
		body        string
		expectType  string
	}{
		{
			name:        "image response",
			contentType: "image/png",
			body:        "fake image",
			expectType:  "image",
		},
		{
			name:        "audio response",
			contentType: "audio/mp3",
			body:        "fake audio",
			expectType:  "audio",
		},
		{
			name:        "text response",
			contentType: "text/plain",
			body:        "text content",
			expectType:  "text",
		},
		{
			name:        "json response",
			contentType: "application/json",
			body:        `{"message": "hello"}`,
			expectType:  "text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: make(http.Header),
				Body:   io.NopCloser(bytes.NewReader([]byte(tt.body))),
			}
			resp.Header.Set("Content-Type", tt.contentType)

			tool := &config.ToolConfig{}
			tmplCtx := template.NewContext()

			result, err := chain.Handle(resp, tool, tmplCtx)
			assert.NoError(t, err)
			require.NotNil(t, result)
			assert.False(t, result.IsError)
			assert.Len(t, result.Content, 1)

			// Verify content type matches expectation
			content := result.Content[0]
			switch tt.expectType {
			case "image":
				_, ok := content.(*mcp.ImageContent)
				assert.True(t, ok, "Expected image content")
			case "audio":
				_, ok := content.(*mcp.AudioContent)
				assert.True(t, ok, "Expected audio content")
			case "text":
				_, ok := content.(*mcp.TextContent)
				assert.True(t, ok, "Expected text content")
			}
		})
	}
}
