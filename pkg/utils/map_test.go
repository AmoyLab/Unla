package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetBool(t *testing.T) {
	m := map[string]any{
		"a": true,
	}
	assert.Equal(t, GetBool(m, "a", false), true)
}

func TestGetString(t *testing.T) {
	m := map[string]any{
		"a": "123",
	}
	assert.Equal(t, GetString(m, "a", ""), "123")
}
