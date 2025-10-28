package core

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/template"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/stretchr/testify/assert"
)

func TestCreateResponseHandlerChainStructure(t *testing.T) {
	handler := CreateResponseHandlerChain()
	assert.NotNil(t, handler)

	// Check that the first handler is ImageHandler
	imageHandler, ok := handler.(*ImageHandler)
	assert.True(t, ok)
	assert.NotNil(t, imageHandler)

	// Check the chain structure
	assert.NotNil(t, imageHandler.next)
	audioHandler, ok := imageHandler.next.(*AudioHandler)
	assert.True(t, ok)

	assert.NotNil(t, audioHandler.next)
	_, ok = audioHandler.next.(*TextHandler)
	assert.True(t, ok)
}

func TestBaseHandler_SetNextChain(t *testing.T) {
	base := &BaseHandler{}
	next := &TextHandler{}

	base.SetNext(next)
	assert.Equal(t, next, base.next)
}

func TestBaseHandler_HandleNext_WithNext(t *testing.T) {
	// Create a mock response with text content
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("test content")),
	}
	resp.Header.Set("Content-Type", "text/plain")

	tool := &config.ToolConfig{Name: "test"}
	tmplCtx := &template.Context{}

	base := &BaseHandler{}
	textHandler := &TextHandler{}
	base.SetNext(textHandler)

	result, err := base.HandleNext(resp, tool, tmplCtx)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestBaseHandler_HandleNext_WithoutNext(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("test")),
	}

	base := &BaseHandler{}
	// No next handler set

	result, err := base.HandleNext(resp, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	// Should use default TextHandler when no next handler is available
}

func TestImageHandler_CanHandleTypes(t *testing.T) {
	handler := &ImageHandler{}

	// Test image content types
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "image/png")
	assert.True(t, handler.CanHandle(resp))

	resp.Header.Set("Content-Type", "image/jpeg")
	assert.True(t, handler.CanHandle(resp))

	resp.Header.Set("Content-Type", "image/jpg")
	assert.True(t, handler.CanHandle(resp))

	// Test non-image content types
	resp.Header.Set("Content-Type", "text/plain")
	assert.False(t, handler.CanHandle(resp))

	resp.Header.Set("Content-Type", "application/json")
	assert.False(t, handler.CanHandle(resp))
}

func TestAudioHandler_CanHandleTypes(t *testing.T) {
	handler := &AudioHandler{}

	// Test audio content types
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "audio/mpeg")
	assert.True(t, handler.CanHandle(resp))

	resp.Header.Set("Content-Type", "audio/wav")
	assert.True(t, handler.CanHandle(resp))

	// Test non-audio content types
	resp.Header.Set("Content-Type", "text/plain")
	assert.False(t, handler.CanHandle(resp))

	resp.Header.Set("Content-Type", "image/png")
	assert.False(t, handler.CanHandle(resp))
}

func TestTextHandler_CanHandleAll(t *testing.T) {
	handler := &TextHandler{}

	// TextHandler should handle everything
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/plain")
	assert.True(t, handler.CanHandle(resp))

	resp.Header.Set("Content-Type", "application/json")
	assert.True(t, handler.CanHandle(resp))

	resp.Header.Set("Content-Type", "image/png")
	assert.True(t, handler.CanHandle(resp))
}

func TestImageHandler_HandleImage(t *testing.T) {
	handler := &ImageHandler{}

	// Create mock image response
	imageData := []byte("fake image data")
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(imageData)),
	}
	resp.Header.Set("Content-Type", "image/png")

	tool := &config.ToolConfig{Name: "image_tool"}
	tmplCtx := &template.Context{}

	result, err := handler.Handle(resp, tool, tmplCtx)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Content, 1)

	// Type assertion to access specific content fields
	imageContent, ok := result.Content[0].(*mcp.ImageContent)
	assert.True(t, ok)
	assert.Equal(t, "image", imageContent.Type)
	assert.NotEmpty(t, imageContent.Data)
	assert.Equal(t, "image/png", imageContent.MimeType)
}

func TestAudioHandler_HandleAudio(t *testing.T) {
	handler := &AudioHandler{}

	// Create mock audio response
	audioData := []byte("fake audio data")
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(audioData)),
	}
	resp.Header.Set("Content-Type", "audio/mpeg")

	tool := &config.ToolConfig{Name: "audio_tool"}
	tmplCtx := &template.Context{}

	result, err := handler.Handle(resp, tool, tmplCtx)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Content, 1)

	// Type assertion to access specific content fields
	audioContent, ok := result.Content[0].(*mcp.AudioContent)
	assert.True(t, ok)
	assert.Equal(t, "audio", audioContent.Type)
	assert.NotEmpty(t, audioContent.Data)
	assert.Equal(t, "audio/mpeg", audioContent.MimeType)
}

func TestTextHandler_HandleText(t *testing.T) {
	handler := &TextHandler{}

	// Create mock text response
	textContent := "This is test content"
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(textContent)),
	}
	resp.Header.Set("Content-Type", "text/plain")

	tool := &config.ToolConfig{Name: "text_tool"}
	tmplCtx := &template.Context{}

	result, err := handler.Handle(resp, tool, tmplCtx)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Content, 1)

	// Type assertion to access specific content fields
	textContent1, ok := result.Content[0].(*mcp.TextContent)
	assert.True(t, ok)
	assert.Equal(t, "text", textContent1.Type)
	assert.Contains(t, textContent1.Text, textContent)
}
