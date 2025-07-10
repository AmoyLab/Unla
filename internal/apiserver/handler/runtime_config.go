package handler

import (
	"net/http"
	"os"
	"strconv"

	"github.com/amoylab/unla/pkg/version"
	"github.com/gin-gonic/gin"
)

// HandleRuntimeConfig serves frontend runtime config as JSON
func HandleRuntimeConfig(c *gin.Context) {
	// Get debug mode from environment or default to false
	debugMode := false
	if debugModeStr := os.Getenv("DEBUG_MODE"); debugModeStr != "" {
		if parsed, err := strconv.ParseBool(debugModeStr); err == nil {
			debugMode = parsed
		}
	}

	versionStr := version.Version

	// Check if experimental features are enabled
	enableExperimental := false
	if expStr := os.Getenv("ENABLE_EXPERIMENTAL"); expStr != "" {
		if parsed, err := strconv.ParseBool(expStr); err == nil {
			enableExperimental = parsed
		}
	}

	c.JSON(http.StatusOK, gin.H{
		// Keep original environment variables for backward compatibility
		"VITE_API_BASE_URL":         getEnvOrDefault("VITE_API_BASE_URL", "/api"),
		"VITE_WS_BASE_URL":          getEnvOrDefault("VITE_WS_BASE_URL", "/api/ws"),
		"VITE_MCP_GATEWAY_BASE_URL": getEnvOrDefault("VITE_MCP_GATEWAY_BASE_URL", "/gateway"),
		"VITE_BASE_URL":             getEnvOrDefault("VITE_BASE_URL", "/"),

		// Add new properties matching our TypeScript interface
		"apiBaseUrl": getEnvOrDefault("VITE_API_BASE_URL", "/api"),
		"debugMode":  debugMode,
		"version":    versionStr,
		"features": gin.H{
			"enableExperimental": enableExperimental,
		},
		"LLM_CONFIG_ADMIN_ONLY": getEnvOrDefault("LLM_CONFIG_ADMIN_ONLY", "N"),
	})
}

// getEnvOrDefault returns the value of the environment variable or a default if not set
func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
