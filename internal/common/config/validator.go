package config

import (
	"fmt"
	"strings"
)

// Location represents a configuration location
type Location struct {
	File string
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Message   string
	Locations []Location
}

func (e *ValidationError) Error() string {
	var sb strings.Builder
	sb.WriteString(e.Message)
	sb.WriteString("\n\n")
	for _, loc := range e.Locations {
		sb.WriteString("--> ")
		sb.WriteString(loc.File)
		sb.WriteString("\n")
	}
	return sb.String()
}

// validateSingleConfig validates a single MCP configuration and returns validation errors
func validateSingleConfig(cfg *MCPConfig) []*ValidationError {
	var errors []*ValidationError

	// Validate name length
	if len(cfg.Name) > 50 {
		errors = append(errors, &ValidationError{
			Message: "name length exceeds maximum limit of 50 characters",
			Locations: []Location{{
				File: cfg.Name,
			}},
		})
	}

	// Check for duplicate server names within this config
	serverNameMap := make(map[string]bool)
	for _, server := range cfg.Servers {
		if serverNameMap[server.Name] {
			errors = append(errors, &ValidationError{
				Message: fmt.Sprintf("duplicate server name %q found in server configurations", server.Name),
				Locations: []Location{{
					File: cfg.Name,
				}},
			})
		}
		serverNameMap[server.Name] = true
	}

	// Check for duplicate tool names within this config
	toolNameMap := make(map[string]bool)
	for _, tool := range cfg.Tools {
		if toolNameMap[tool.Name] {
			errors = append(errors, &ValidationError{
				Message: fmt.Sprintf("duplicate tool name %q found in tool configurations", tool.Name),
				Locations: []Location{{
					File: cfg.Name,
				}},
			})
		}
		toolNameMap[tool.Name] = true
	}

	// Build server name map for this config
	serverNames := make(map[string]bool)
	for _, server := range cfg.Servers {
		serverNames[server.Name] = true
	}

	// Also add MCP servers to the server name map
	for _, mcpServer := range cfg.McpServers {
		serverNames[mcpServer.Name] = true
	}

	// Check for duplicate router prefixes within this config.
	routerPrefixMap := make(map[string]bool)
	for _, router := range cfg.Routers {
		prefix := normalizeRouterPrefix(router.Prefix)
		if routerPrefixMap[prefix] {
			errors = append(errors, &ValidationError{
				Message: fmt.Sprintf("duplicate prefix %q found in router configurations", prefix),
				Locations: []Location{{
					File: cfg.Name,
				}},
			})
		}
		routerPrefixMap[prefix] = true
	}

	// Check if all referenced servers exist
	for _, router := range cfg.Routers {
		if !serverNames[router.Server] {
			errors = append(errors, &ValidationError{
				Message: fmt.Sprintf("server %q referenced in router configuration does not exist", router.Server),
				Locations: []Location{{
					File: cfg.Name,
				}},
			})
		}
	}

	// Check if all referenced tools exist in servers
	for _, server := range cfg.Servers {
		for _, toolName := range server.AllowedTools {
			if !toolNameMap[toolName] {
				errors = append(errors, &ValidationError{
					Message: fmt.Sprintf("tool %q referenced in server %q does not exist", toolName, server.Name),
					Locations: []Location{{
						File: cfg.Name,
					}},
				})
			}
		}
	}

	return errors
}

// formatValidationErrors formats a slice of validation errors into a single error
func formatValidationErrors(errors []*ValidationError) error {
	if len(errors) == 0 {
		return nil
	}

	var sb strings.Builder
	for i, err := range errors {
		if i > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString(err.Error())
	}
	return fmt.Errorf("%s", sb.String())
}

// ValidateMCPConfig validates a single MCP configuration
func ValidateMCPConfig(cfg *MCPConfig) error {
	errors := validateSingleConfig(cfg)
	return formatValidationErrors(errors)
}

// ValidateMCPConfigs validates a list of MCP configurations
func ValidateMCPConfigs(configs []*MCPConfig) error {
	var errors []*ValidationError

	// Check for duplicate prefixes (global check)
	prefixMap := make(map[string][]Location)
	for _, cfg := range configs {
		seenPrefixes := make(map[string]bool)
		for _, router := range cfg.Routers {
			prefix := normalizeRouterPrefix(router.Prefix)
			if seenPrefixes[prefix] {
				continue
			}
			seenPrefixes[prefix] = true
			prefixMap[prefix] = append(prefixMap[prefix], Location{
				File: cfg.Name,
			})
		}
	}

	// Check for duplicate prefixes
	for prefix, locations := range prefixMap {
		if len(locations) > 1 {
			errors = append(errors, &ValidationError{
				Message:   fmt.Sprintf("duplicate prefix %q found in router configurations", prefix),
				Locations: locations,
			})
		}
	}

	// Validate each config individually
	for _, cfg := range configs {
		errors = append(errors, validateSingleConfig(cfg)...)
	}

	return formatValidationErrors(errors)
}

func normalizeRouterPrefix(prefix string) string {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return "/"
	}
	return prefix
}

// MergeConfigs merges a new configuration with existing configurations
// It will update the existing config if it exists, or append the new config if it doesn't exist
// If the new config has DeletedAt set, it will remove the config from the list
func MergeConfigs(existingConfigs []*MCPConfig, newConfig *MCPConfig) []*MCPConfig {
	// Create a copy of existing configs
	configs := make([]*MCPConfig, 0, len(existingConfigs))

	// If the new config has DeletedAt set, we need to remove it from the list
	if !newConfig.DeletedAt.IsZero() {
		for _, existingCfg := range existingConfigs {
			if existingCfg.Tenant != newConfig.Tenant || existingCfg.Name != newConfig.Name {
				configs = append(configs, existingCfg)
			}
		}
		return configs
	}

	// Otherwise, handle normal update/append case
	found := false
	for _, existingCfg := range existingConfigs {
		if existingCfg.Tenant == newConfig.Tenant && existingCfg.Name == newConfig.Name {
			configs = append(configs, newConfig)
			found = true
		} else {
			configs = append(configs, existingCfg)
		}
	}
	if !found {
		configs = append(configs, newConfig)
	}

	return configs
}
