package handler

import (
	"net/http"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/pkg/version"
	"github.com/gin-gonic/gin"
)

// RuntimeConfigHandler represents the runtime configuration handler
type RuntimeConfigHandler struct {
	cfg *config.APIServerConfig
}

// NewRuntimeConfigHandler creates a new runtime configuration handler
func NewRuntimeConfigHandler(cfg *config.APIServerConfig) *RuntimeConfigHandler {
	return &RuntimeConfigHandler{
		cfg: cfg,
	}
}

// HandleRuntimeConfig serves frontend runtime config as JSON
func (h *RuntimeConfigHandler) HandleRuntimeConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		// Keep original environment variables for backward compatibility
		"VITE_API_BASE_URL":                h.cfg.Web.APIBaseURL,
		"VITE_WS_BASE_URL":                 h.cfg.Web.WSBaseURL,
		"VITE_MCP_GATEWAY_BASE_URL":        h.cfg.Web.MCPGatewayBaseURL,
		"VITE_DIRECT_MCP_GATEWAY_MODIFIER": h.cfg.Web.DirectMCPGatewayModifier,
		"VITE_BASE_URL":                    h.cfg.Web.BaseURL,

		// Add new properties matching our TypeScript interface
		"apiBaseUrl":               h.cfg.Web.APIBaseURL,
		"debugMode":                h.cfg.Web.DebugMode,
		"version":                  version.Version,
		"directMcpGatewayModifier": h.cfg.Web.DirectMCPGatewayModifier,
		"features": gin.H{
			"enableExperimental": h.cfg.Web.EnableExperimental,
		},
		"LLM_CONFIG_ADMIN_ONLY": h.cfg.Web.LLMConfigAdminOnly,
	})
}
