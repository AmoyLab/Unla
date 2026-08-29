package mcpproxy

import (
	"testing"

	"github.com/amoylab/unla/internal/template"
	"github.com/stretchr/testify/assert"
)

func TestRenderHeaders_Empty(t *testing.T) {
	headers, err := renderHeaders(nil, nil)
	assert.NoError(t, err)
	assert.Nil(t, headers)

	headers, err = renderHeaders(map[string]string{}, nil)
	assert.NoError(t, err)
	assert.Nil(t, headers)
}

func TestRenderHeaders_WithTemplateContext(t *testing.T) {
	tmplCtx := template.NewContext()
	tmplCtx.Env = func(key string) string {
		if key == "MCP_AUTH_TOKEN" {
			return "token"
		}
		return ""
	}
	tmplCtx.Request.Headers["X-Req"] = "req"

	headers, err := renderHeaders(map[string]string{
		"Authorization": "Bearer {{ env \"MCP_AUTH_TOKEN\" }}",
		"X-Req":         "{{ index .Request.Headers \"X-Req\" }}",
	}, tmplCtx)

	assert.NoError(t, err)
	assert.Equal(t, "Bearer token", headers["Authorization"])
	assert.Equal(t, "req", headers["X-Req"])
}

func TestRenderHeaders_InvalidTemplate(t *testing.T) {
	headers, err := renderHeaders(map[string]string{
		"X-Bad": "{{ .Request.Headers",
	}, template.NewContext())
	assert.Error(t, err)
	assert.Nil(t, headers)
}
