package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/template"
	"github.com/amoylab/unla/pkg/mcp"
)

// CreateResponseHandlerChain create a chain of response handlers
// The first handler is ImageHandler, which handles image responses.
// The second handler is TextHandler, which handles text responses.
// default handler is a base handler that can handle any other type of response.
// If the response is neither, it will return an error.
func CreateResponseHandlerChain() ResponseHandler {
	imageHandler := &ImageHandler{}
	audioHandler := &AudioHandler{}
	textHandler := &TextHandler{}

	imageHandler.SetNext(audioHandler)
	audioHandler.SetNext(textHandler)
	return imageHandler
}

// ResponseHandler is an interface for handling HTTP responses
type ResponseHandler interface {
	// CanHandle checks if the handler can process the given response
	CanHandle(resp *http.Response) bool
	// Handle processes the response and returns the result
	Handle(resp *http.Response, tool *config.ToolConfig, tmplCtx *template.Context) (*mcp.CallToolResult, error)
	// SetNext sets the next handler in the chain
	SetNext(handler ResponseHandler)
}

// BaseHandler is a base implementation of the ResponseHandler interface
type BaseHandler struct {
	next ResponseHandler
}

func (h *BaseHandler) SetNext(handler ResponseHandler) {
	h.next = handler
}

func (h *BaseHandler) HandleNext(resp *http.Response, tool *config.ToolConfig, tmplCtx *template.Context) (*mcp.CallToolResult, error) {
	if h.next != nil {
		return h.next.Handle(resp, tool, tmplCtx)
	}
	// default handler
	handler := &TextHandler{}
	return handler.Handle(resp, tool, tmplCtx)
}

// TextHandler is a handler for text responses
type TextHandler struct {
	BaseHandler
}

func (h *TextHandler) CanHandle(resp *http.Response) bool {
	return true
}

func (h *TextHandler) Handle(resp *http.Response, tool *config.ToolConfig, tmplCtx *template.Context) (*mcp.CallToolResult, error) {
	if !h.CanHandle(resp) {
		// the text handler is the last handler in the chain
		return nil, fmt.Errorf("response type cannot be handled")
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	var rendered string
	if tool == nil || tool.ResponseBody == "" {
		rendered = string(respBody)
	} else {
		var respData map[string]any
		if err := json.Unmarshal(respBody, &respData); err != nil {
			// Non-JSON response, ignore parse error
		}
		// Preprocess response data to handle []any type
		respData = preprocessResponseData(respData)
		tmplCtx.Response.Data = respData
		tmplCtx.Response.Body = string(respBody)

		rendered, err = template.RenderTemplate(tool.ResponseBody, tmplCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render response body template: %w", err)
		}
	}
	isError := resp.StatusCode >= 400
	return mcp.NewCallToolResultTextWithError(rendered, isError), nil
}

// ImageHandler is a handler for image responses
type ImageHandler struct {
	BaseHandler
}

func (h *ImageHandler) CanHandle(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.HasPrefix(contentType, "image/")
}

func (h *ImageHandler) Handle(resp *http.Response, tool *config.ToolConfig, tmplCtx *template.Context) (*mcp.CallToolResult, error) {
	if !h.CanHandle(resp) {
		return h.HandleNext(resp, tool, tmplCtx)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("image handler failed to read response body: %w", err)
	}
	var base64Image string
	if respBody == nil {
		base64Image = ""
	} else {
		base64Image = base64.StdEncoding.EncodeToString(respBody)
	}
	return mcp.NewCallToolResultImage(base64Image, resp.Header.Get("Content-Type")), nil
}

// AudioHandler is a handler for audio responses
type AudioHandler struct {
	BaseHandler
}

func (h *AudioHandler) CanHandle(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.HasPrefix(contentType, "audio/")
}

func (h *AudioHandler) Handle(resp *http.Response, tool *config.ToolConfig, tmplCtx *template.Context) (*mcp.CallToolResult, error) {
	if !h.CanHandle(resp) {
		return h.HandleNext(resp, tool, tmplCtx)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("audio handler failed to read response body: %w", err)
	}
	var base64Audio string
	if respBody == nil {
		base64Audio = ""
	} else {
		base64Audio = base64.StdEncoding.EncodeToString(respBody)
	}
	return mcp.NewCallToolResultAudio(base64Audio, resp.Header.Get("Content-Type")), nil
}
