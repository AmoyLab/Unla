package mcpproxy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCallHeadersContext(t *testing.T) {
	ctx := context.Background()
	assert.Nil(t, CallHeadersFromContext(ctx))

	headers := map[string]string{"Authorization": "Bearer token"}
	ctx = WithCallHeaders(ctx, headers)
	assert.Equal(t, headers, CallHeadersFromContext(ctx))

	// Empty headers do not create a new context value.
	assert.Equal(t, ctx, WithCallHeaders(ctx, nil))
}
