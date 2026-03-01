package mcpproxy

import (
	"fmt"

	"github.com/amoylab/unla/internal/template"
)

func renderHeaders(headers map[string]string, tmplCtx *template.Context) (map[string]string, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	if tmplCtx == nil {
		tmplCtx = template.NewContext()
	}

	rendered := make(map[string]string, len(headers))
	for k, v := range headers {
		out, err := template.RenderTemplate(v, tmplCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render header template: %w", err)
		}
		rendered[k] = out
	}
	return rendered, nil
}
