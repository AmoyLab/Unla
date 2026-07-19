package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidationError_ErrorFormats(t *testing.T) {
	e := &ValidationError{Message: "oops", Locations: []Location{{File: "a.yaml"}, {File: "b.yaml"}}}
	s := e.Error()
	assert.Contains(t, s, "oops")
	assert.Contains(t, s, "--> a.yaml")
	assert.Contains(t, s, "--> b.yaml")
}

func TestValidateSingleConfig_Errors(t *testing.T) {
	longName := strings.Repeat("x", 51)
	cfg := &MCPConfig{
		Name: longName,
		Tools: []ToolConfig{
			{Name: "t1"}, {Name: "t1"}, // duplicate tool
		},
		Servers: []ServerConfig{
			{Name: "srv1", AllowedTools: []string{"missingTool"}},
			{Name: "srv1"}, // duplicate server name
		},
		Routers: []RouterConfig{
			{Server: "missing", Prefix: "/r1"}, // references missing server
			{Server: "mcp1", Prefix: "/ok"},    // will be satisfied by McpServers
		},
		McpServers: []MCPServerConfig{{Name: "mcp1"}},
	}

	errs := validateSingleConfig(cfg)
	// Expect multiple distinct validation errors
	assert.GreaterOrEqual(t, len(errs), 3)
	var msg string
	for _, e := range errs {
		msg += e.Message + "\n"
	}
	assert.Contains(t, msg, "name length exceeds maximum")
	assert.Contains(t, msg, "duplicate server name")
	assert.Contains(t, msg, "duplicate tool name")
	assert.Contains(t, msg, "server \"missing\" referenced")
	// Ensure the router pointing to mcp1 is NOT reported as missing
	assert.NotContains(t, msg, "server \"mcp1\"")
}

func TestFormatAndValidateConfigs_DuplicatePrefixes(t *testing.T) {
	cfg1 := &MCPConfig{
		Name:    "cfg1",
		Routers: []RouterConfig{{Server: "s", Prefix: "/api/"}},
		Servers: []ServerConfig{{Name: "s"}},
	}
	cfg2 := &MCPConfig{
		Name:    "cfg2",
		Routers: []RouterConfig{{Server: "s", Prefix: "/api"}},
		Servers: []ServerConfig{{Name: "s"}},
	}

	// ValidateMCPConfig on single should pass (no single-config errors)
	assert.NoError(t, ValidateMCPConfig(cfg1))

	// ValidateMCPConfigs should detect duplicate prefixes across configs
	err := ValidateMCPConfigs([]*MCPConfig{cfg1, cfg2})
	if assert.Error(t, err) {
		s := err.Error()
		assert.Contains(t, s, "duplicate prefix \"/api\"")
		assert.Contains(t, s, "--> cfg1")
		assert.Contains(t, s, "--> cfg2")
	}
}

func TestValidateMCPConfig_DuplicatePrefixes(t *testing.T) {
	cfg := &MCPConfig{
		Name: "cfg",
		Routers: []RouterConfig{
			{Server: "s", Prefix: "/api/"},
			{Server: "s", Prefix: "/api"},
		},
		Servers: []ServerConfig{{Name: "s"}},
	}

	err := ValidateMCPConfig(cfg)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "duplicate prefix \"/api\"")
	}
}

func TestMergeConfigs_UpdateAppendDelete(t *testing.T) {
	existing := []*MCPConfig{{Tenant: "t", Name: "n1"}, {Tenant: "t", Name: "n2"}}
	// Update n1
	updated := &MCPConfig{Tenant: "t", Name: "n1", UpdatedAt: time.Unix(100, 0)}
	got := MergeConfigs(existing, updated)
	assert.Equal(t, 2, len(got))
	assert.Equal(t, int64(100), got[0].UpdatedAt.Unix())

	// Append new
	appended := &MCPConfig{Tenant: "t", Name: "n3"}
	got = MergeConfigs(got, appended)
	assert.Equal(t, 3, len(got))

	// Delete n2
	del := &MCPConfig{Tenant: "t", Name: "n2", DeletedAt: time.Now()}
	got = MergeConfigs(got, del)
	names := []string{got[0].Name, got[1].Name}
	assert.NotContains(t, names, "n2")
}
