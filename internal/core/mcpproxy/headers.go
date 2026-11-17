package mcpproxy

import (
	"context"
)

// callHeadersContextKey is the context key carrying per-call headers that
// should be attached to upstream requests (e.g. a relayed caller
// Authorization for metadata methods such as tools/list / resources/read).
type callHeadersContextKey struct{}

// WithCallHeaders returns a context carrying per-call upstream headers.
func WithCallHeaders(ctx context.Context, headers map[string]string) context.Context {
	if len(headers) == 0 {
		return ctx
	}
	return context.WithValue(ctx, callHeadersContextKey{}, headers)
}

// CallHeadersFromContext returns the per-call upstream headers stored in ctx,
// or nil when absent.
func CallHeadersFromContext(ctx context.Context) map[string]string {
	if ctx == nil {
		return nil
	}
	headers, _ := ctx.Value(callHeadersContextKey{}).(map[string]string)
	return headers
}
