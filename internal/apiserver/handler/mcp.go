package handler

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amoylab/unla/internal/apiserver/database"
	"github.com/amoylab/unla/internal/auth/jwt"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/common/dto"
	"github.com/amoylab/unla/internal/core/mcpproxy"
	"github.com/amoylab/unla/internal/i18n"
	"github.com/amoylab/unla/internal/mcp/storage"
	"github.com/amoylab/unla/internal/mcp/storage/notifier"
	"github.com/amoylab/unla/internal/template"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

type MCP struct {
	db                database.Database
	store             storage.Store
	notifier          notifier.Notifier
	logger            *zap.Logger
	capabilitiesCache sync.Map // key: tenant:name, value: *cachedCapabilities
}

type cachedCapabilities struct {
	data      *mcp.CapabilitiesInfo
	timestamp time.Time
	ttl       time.Duration
}

func (c *cachedCapabilities) isExpired() bool {
	return time.Since(c.timestamp) > c.ttl
}

// CapabilitiesStatsResponse represents the response for capabilities statistics
type CapabilitiesStatsResponse struct {
	Server      ServerStatsInfo    `json:"server"`
	Tools       ToolsStatsInfo     `json:"tools"`
	Prompts     PromptsStatsInfo   `json:"prompts"`
	Resources   ResourcesStatsInfo `json:"resources"`
	Summary     StatsOverallInfo   `json:"summary"`
	LastUpdated time.Time          `json:"lastUpdated"`
}

// ServerStatsInfo represents server-level statistics
type ServerStatsInfo struct {
	Tenant     string    `json:"tenant"`
	ServerName string    `json:"serverName"`
	LastSyncAt time.Time `json:"lastSyncAt"`
	Status     string    `json:"status"`
	Version    string    `json:"version,omitempty"`
}

// ToolsStatsInfo represents tools statistics
type ToolsStatsInfo struct {
	Total       int                `json:"total"`
	Enabled     int                `json:"enabled"`
	Disabled    int                `json:"disabled"`
	EnabledRate float64            `json:"enabledRate"`
	ByCategory  map[string]int     `json:"byCategory,omitempty"`
	Usage       ToolUsageStatsInfo `json:"usage,omitempty"`
}

// PromptsStatsInfo represents prompts statistics
type PromptsStatsInfo struct {
	Total       int            `json:"total"`
	WithArgs    int            `json:"withArgs"`
	WithoutArgs int            `json:"withoutArgs"`
	ByCategory  map[string]int `json:"byCategory,omitempty"`
}

// ResourcesStatsInfo represents resources statistics
type ResourcesStatsInfo struct {
	Total      int            `json:"total"`
	Templates  int            `json:"templates"`
	Static     int            `json:"static"`
	ByMimeType map[string]int `json:"byMimeType,omitempty"`
}

// ToolUsageStatsInfo represents tool usage statistics
type ToolUsageStatsInfo struct {
	TotalCalls  int64      `json:"totalCalls"`
	SuccessRate float64    `json:"successRate"`
	AvgExecTime float64    `json:"avgExecTime"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`
}

// StatsOverallInfo represents overall statistics summary
type StatsOverallInfo struct {
	TotalCapabilities  int            `json:"totalCapabilities"`
	ActiveCapabilities int            `json:"activeCapabilities"`
	Distribution       map[string]int `json:"distribution"`
}

func NewMCP(db database.Database, store storage.Store, ntf notifier.Notifier, logger *zap.Logger) *MCP {
	return &MCP{
		db:                db,
		store:             store,
		notifier:          ntf,
		logger:            logger,
		capabilitiesCache: sync.Map{},
	}
}

// checkTenantPermission checks if the user has permission to access the specified tenant and
// verifies that all router prefixes start with the tenant prefix as a complete path segment
func (h *MCP) checkTenantPermission(c *gin.Context, tenantName string, cfg *config.MCPConfig) (*database.Tenant, error) {
	h.logger.Debug("checking tenant permission",
		zap.String("tenant_name", tenantName))

	// Check if tenant name is empty
	if tenantName == "" {
		h.logger.Warn("tenant name is empty")
		return nil, i18n.ErrorTenantNameRequired
	}

	// Get user authentication information
	claims, exists := c.Get("claims")
	if !exists {
		h.logger.Warn("missing JWT claims in context")
		return nil, i18n.ErrUnauthorized
	}
	jwtClaims := claims.(*jwt.Claims)

	// Get user information
	user, err := h.db.GetUserByUsername(c.Request.Context(), jwtClaims.Username)
	if err != nil {
		h.logger.Error("failed to get user info",
			zap.String("username", jwtClaims.Username),
			zap.Error(err))
		return nil, i18n.ErrInternalServer.WithParam("Reason", "Failed to get user info: "+err.Error())
	}

	// Get tenant information
	tenant, err := h.db.GetTenantByName(c.Request.Context(), tenantName)
	if err != nil {
		h.logger.Warn("tenant not found",
			zap.String("tenant_name", tenantName),
			zap.Error(err))
		return nil, i18n.ErrorTenantNotFound.WithParam("Name", tenantName)
	}

	// Normalize tenant prefix
	tenantPrefix := tenant.Prefix
	if !strings.HasPrefix(tenantPrefix, "/") {
		tenantPrefix = "/" + tenantPrefix
	}
	tenantPrefix = strings.TrimSuffix(tenantPrefix, "/")

	// Check if all router prefixes start with tenant prefix
	for _, router := range cfg.Routers {
		// Normalize router prefix
		routerPrefix := router.Prefix
		if !strings.HasPrefix(routerPrefix, "/") {
			routerPrefix = "/" + routerPrefix
		}
		routerPrefix = strings.TrimSuffix(routerPrefix, "/")

		// Allow exact match
		if routerPrefix == tenantPrefix {
			continue
		}

		// Must start with tenant prefix followed by a path separator
		if !strings.HasPrefix(routerPrefix, tenantPrefix+"/") {
			h.logger.Warn("router prefix validation failed",
				zap.String("router_prefix", routerPrefix),
				zap.String("tenant_prefix", tenantPrefix))
			return nil, i18n.ErrorRouterPrefixError
		}
	}

	// Check user permission if not admin
	if user.Role != database.RoleAdmin {
		userTenants, err := h.db.GetUserTenants(c.Request.Context(), user.ID)
		if err != nil {
			h.logger.Error("failed to get user tenants",
				zap.Uint("user_id", user.ID),
				zap.Error(err))
			return nil, i18n.ErrInternalServer.WithParam("Reason", "Failed to get user tenants: "+err.Error())
		}

		allowed := false
		for _, userTenant := range userTenants {
			if userTenant.ID == tenant.ID {
				allowed = true
				break
			}
		}

		if !allowed {
			h.logger.Warn("user lacks permission for tenant",
				zap.Uint("user_id", user.ID),
				zap.Uint("tenant_id", tenant.ID))
			return nil, i18n.ErrorTenantPermissionError
		}
	}

	h.logger.Debug("tenant permission check passed",
		zap.String("tenant_name", tenantName),
		zap.Uint("tenant_id", tenant.ID))
	return tenant, nil
}

func (h *MCP) HandleMCPServerUpdate(c *gin.Context) {
	// Read the raw YAML content from request body
	content, err := c.GetRawData()
	if err != nil {
		h.logger.Error("failed to read request body", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", "Failed to read request body: "+err.Error()))
		return
	}

	// Validate the YAML content
	var cfg config.MCPConfig
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		h.logger.Error("invalid YAML content", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrorMCPServerValidation.WithParam("Reason", "Invalid YAML content: "+err.Error()))
		return
	}

	// Get existing server
	oldCfg, err := h.store.Get(c.Request.Context(), cfg.Tenant, cfg.Name)
	if err != nil {
		h.logger.Error("MCP server not found",
			zap.String("server_name", cfg.Name),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrorMCPServerNotFound.WithParam("Name", cfg.Name))
		return
	}

	if oldCfg.Name != cfg.Name {
		h.logger.Warn("server name mismatch",
			zap.String("config_name", cfg.Name))
		i18n.RespondWithError(c, i18n.ErrorMCPServerValidation.WithParam("Reason", "Server name in configuration must match name parameter"))
		return
	}

	_, err = h.checkTenantPermission(c, cfg.Tenant, &cfg)
	if err != nil {
		h.logger.Warn("tenant permission check failed",
			zap.String("tenant", cfg.Tenant),
			zap.Error(err))
		i18n.RespondWithError(c, err)
		return
	}

	// Get all existing configurations
	configs, err := h.store.List(c.Request.Context())
	if err != nil {
		h.logger.Error("failed to get existing configurations", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get existing configurations: "+err.Error()))
		return
	}

	// Merge the new configuration with existing configs
	configs = config.MergeConfigs(configs, &cfg)

	// Validate all configurations
	if err := config.ValidateMCPConfigs(configs); err != nil {
		var validationErr *config.ValidationError
		if errors.As(err, &validationErr) {
			h.logger.Error("configuration validation failed",
				zap.String("validation_error", validationErr.Error()))
			i18n.RespondWithError(c, i18n.ErrorMCPServerValidation.WithParam("Reason", "Configuration validation failed: "+validationErr.Error()))
		} else {
			h.logger.Error("failed to validate configurations", zap.Error(err))
			i18n.RespondWithError(c, i18n.ErrorMCPServerValidation.WithParam("Reason", "Failed to validate configurations: "+err.Error()))
		}
		return
	}

	if err := h.store.Update(c.Request.Context(), &cfg); err != nil {
		h.logger.Error("failed to update MCP server",
			zap.String("server_name", cfg.Name),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to update MCP server: "+err.Error()))
		return
	}

	// Send reload signal to gateway using notifier
	if err := h.notifier.NotifyUpdate(c.Request.Context(), &cfg); err != nil {
		h.logger.Error("failed to reload gateway", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to reload gateway: "+err.Error()))
		return
	}

	// Clear cache for this server
	cacheKey := cfg.Tenant + ":" + cfg.Name
	h.clearCapabilitiesCache(cacheKey)

	h.logger.Info("MCP server updated successfully",
		zap.String("server_name", cfg.Name))
	i18n.Success(i18n.SuccessMCPServerUpdated).With("status", "success").Send(c)
}

func (h *MCP) HandleListMCPServers(c *gin.Context) {
	h.logger.Info("handling list MCP servers request")

	tenantIDStr := c.Query("tenantId")
	var tenantID uint
	if tenantIDStr != "" {
		tid, err := strconv.ParseUint(tenantIDStr, 10, 32)
		if err != nil {
			h.logger.Warn("invalid tenantId parameter",
				zap.String("tenantId", tenantIDStr))
			i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", "Invalid tenantId parameter"))
			return
		}
		tenantID = uint(tid)
		h.logger.Debug("filtering by tenant ID", zap.Uint("tenant_id", tenantID))
	}

	claims, exists := c.Get("claims")
	if !exists {
		h.logger.Warn("missing JWT claims in context")
		i18n.RespondWithError(c, i18n.ErrUnauthorized)
		return
	}
	jwtClaims := claims.(*jwt.Claims)

	user, err := h.db.GetUserByUsername(c.Request.Context(), jwtClaims.Username)
	if err != nil {
		h.logger.Error("failed to get user info",
			zap.String("username", jwtClaims.Username),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get user info: "+err.Error()))
		return
	}

	servers, err := h.store.List(c.Request.Context())
	if err != nil {
		h.logger.Error("failed to get MCP servers", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get MCP servers: "+err.Error()))
		return
	}

	if user.Role != database.RoleAdmin && tenantID > 0 {
		userTenants, err := h.db.GetUserTenants(c.Request.Context(), user.ID)
		if err != nil {
			h.logger.Error("failed to get user tenants",
				zap.Uint("user_id", user.ID),
				zap.Error(err))
			i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get user tenants: "+err.Error()))
			return
		}

		hasPermission := false
		for _, tenant := range userTenants {
			if tenant.ID == tenantID {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			h.logger.Warn("user lacks permission for tenant",
				zap.Uint("user_id", user.ID),
				zap.Uint("tenant_id", tenantID))
			i18n.RespondWithError(c, i18n.ErrorTenantPermissionError)
			return
		}
	}

	var filteredServers []*config.MCPConfig
	if tenantID > 0 {
		tenant, err := h.db.GetTenantByID(c.Request.Context(), tenantID)
		if err != nil {
			h.logger.Error("tenant not found",
				zap.Uint("tenant_id", tenantID),
				zap.Error(err))
			i18n.RespondWithError(c, i18n.ErrorTenantNotFound)
			return
		}

		name := tenant.Name
		for _, server := range servers {
			if server.Tenant == name {
				filteredServers = append(filteredServers, server)
			}
		}
		h.logger.Debug("filtered servers by tenant name",
			zap.String("tenant_name", name),
			zap.Int("server_count", len(filteredServers)))
	} else if user.Role != database.RoleAdmin {
		userTenants, err := h.db.GetUserTenants(c.Request.Context(), user.ID)
		if err != nil {
			h.logger.Error("failed to get user tenants",
				zap.Uint("user_id", user.ID),
				zap.Error(err))
			i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get user tenants: "+err.Error()))
			return
		}

		tenantNames := make([]string, len(userTenants))
		for i, tenant := range userTenants {
			tenantNames[i] = tenant.Name
		}

		for _, server := range servers {
			for _, name := range tenantNames {
				if server.Tenant == name {
					filteredServers = append(filteredServers, server)
					break
				}
			}
		}
		h.logger.Debug("filtered servers by user tenants",
			zap.Uint("user_id", user.ID),
			zap.Int("tenant_count", len(tenantNames)),
			zap.Int("server_count", len(filteredServers)))
	} else {
		filteredServers = servers
		h.logger.Debug("admin user, returning all servers",
			zap.Int("server_count", len(servers)))
	}

	// TODO: temporary
	results := make([]*dto.MCPServer, len(filteredServers))
	for i, server := range filteredServers {
		results[i] = &dto.MCPServer{
			Name:       server.Name,
			Tenant:     server.Tenant,
			McpServers: dto.FromMCPServerConfigs(server.McpServers),
			Tools:      dto.FromToolConfigs(server.Tools),
			Prompts:    dto.FromPromptConfigs(server.Prompts),
			Servers:    dto.FromServerConfigs(server.Servers),
			Routers:    dto.FromRouterConfigs(server.Routers),
			CreatedAt:  server.CreatedAt,
			UpdatedAt:  server.UpdatedAt,
		}
	}

	h.logger.Info("returning MCP server list",
		zap.Int("server_count", len(results)))
	i18n.Success(i18n.SuccessMCPServerList).With("data", results).Send(c)
}

func (h *MCP) HandleMCPServerCreate(c *gin.Context) {
	h.logger.Info("handling MCP server create request")

	// Read the raw YAML content from request body
	content, err := c.GetRawData()
	if err != nil {
		h.logger.Error("failed to read request body", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", "Failed to read request body: "+err.Error()))
		return
	}

	// Validate the YAML content and get the server name
	var cfg config.MCPConfig
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		h.logger.Error("invalid YAML content", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrorMCPServerValidation.WithParam("Reason", "Invalid YAML content: "+err.Error()))
		return
	}

	if cfg.Name == "" {
		h.logger.Warn("server name is required in configuration")
		i18n.RespondWithError(c, i18n.ErrorMCPServerValidation.WithParam("Reason", "Server name is required in configuration"))
		return
	}

	h.logger.Debug("validating server configuration",
		zap.String("server_name", cfg.Name),
		zap.String("tenant", cfg.Tenant))

	_, err = h.checkTenantPermission(c, cfg.Tenant, &cfg)
	if err != nil {
		h.logger.Warn("tenant permission check failed",
			zap.String("tenant", cfg.Tenant),
			zap.Error(err))

		i18n.RespondWithError(c, err)
		return
	}

	// Check if server already exists
	_, err = h.store.Get(c.Request.Context(), cfg.Tenant, cfg.Name)
	if err == nil {
		h.logger.Warn("MCP server already exists",
			zap.String("server_name", cfg.Name))
		i18n.RespondWithError(c, i18n.ErrorMCPServerExists.WithParam("Name", cfg.Name))
		return
	}

	// Get all existing configurations
	configs, err := h.store.List(c.Request.Context())
	if err != nil {
		h.logger.Error("failed to get existing configurations", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get existing configurations: "+err.Error()))
		return
	}

	// Add the new configuration to the list
	configs = append(configs, &cfg)

	// Validate all configurations
	if err := config.ValidateMCPConfigs(configs); err != nil {
		var validationErr *config.ValidationError
		if errors.As(err, &validationErr) {
			h.logger.Error("configuration validation failed",
				zap.String("validation_error", validationErr.Error()))
			i18n.RespondWithError(c, i18n.ErrorMCPServerValidation.WithParam("Reason", "Configuration validation failed: "+validationErr.Error()))
		} else {
			h.logger.Error("failed to validate configurations", zap.Error(err))
			i18n.RespondWithError(c, i18n.ErrorMCPServerValidation.WithParam("Reason", "Failed to validate configurations: "+err.Error()))
		}
		return
	}

	if err := h.store.Create(c.Request.Context(), &cfg); err != nil {
		h.logger.Error("failed to create MCP server",
			zap.String("server_name", cfg.Name),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to create MCP server: "+err.Error()))
		return
	}

	// Send reload signal to gateway using notifier
	if err := h.notifier.NotifyUpdate(c.Request.Context(), &cfg); err != nil {
		h.logger.Error("failed to reload gateway", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to reload gateway: "+err.Error()))
		return
	}

	// Clear cache for this server (in case it was previously created and cached)
	cacheKey := cfg.Tenant + ":" + cfg.Name
	h.clearCapabilitiesCache(cacheKey)

	h.logger.Info("MCP server created successfully",
		zap.String("server_name", cfg.Name))
	i18n.Created(i18n.SuccessMCPServerCreated).With("status", "success").Send(c)
}

func (h *MCP) HandleMCPServerDelete(c *gin.Context) {
	// Get the server name from path parameter
	tenant := c.Param("tenant")
	if tenant == "" {
		h.logger.Warn("MCP server tenant required but missing")
		i18n.RespondWithError(c, i18n.ErrorTenantRequired)
		return
	}
	name := c.Param("name")
	if name == "" {
		h.logger.Warn("MCP server name required but missing")
		i18n.RespondWithError(c, i18n.ErrorMCPServerNameRequired)
		return
	}

	h.logger.Info("handling MCP server delete request",
		zap.String("server_name", name))

	// Check if server exists
	existingCfg, err := h.store.Get(c.Request.Context(), tenant, name)
	if err != nil {
		h.logger.Error("MCP server not found",
			zap.String("server_name", name),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrorMCPServerNotFound.WithParam("Name", name))
		return
	}

	// Check tenant permission
	_, err = h.checkTenantPermission(c, existingCfg.Tenant, existingCfg)
	if err != nil {
		h.logger.Warn("tenant permission check failed",
			zap.String("tenant", existingCfg.Tenant),
			zap.Error(err))
		i18n.RespondWithError(c, err)
		return
	}

	// Delete server
	if err := h.store.Delete(c.Request.Context(), existingCfg.Tenant, name); err != nil {
		h.logger.Error("failed to delete MCP server",
			zap.String("server_name", name),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to delete MCP server: "+err.Error()))
		return
	}

	// Send reload signal to gateway using notifier
	existingCfg.DeletedAt = time.Now()
	if err := h.notifier.NotifyUpdate(c.Request.Context(), existingCfg); err != nil {
		h.logger.Error("failed to notify gateway", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to notify gateway: "+err.Error()))
		return
	}

	// Clear cache for this server
	cacheKey := existingCfg.Tenant + ":" + name
	h.clearCapabilitiesCache(cacheKey)

	h.logger.Info("MCP server deleted successfully",
		zap.String("server_name", name))
	i18n.Success(i18n.SuccessMCPServerDeleted).With("status", "success").Send(c)
}

func (h *MCP) HandleMCPServerSync(c *gin.Context) {
	// Get user from claims
	claims, exists := c.Get("claims")
	if !exists {
		h.logger.Warn("missing JWT claims in context")
		i18n.RespondWithError(c, i18n.ErrUnauthorized)
		return
	}
	jwtClaims := claims.(*jwt.Claims)

	// Get user information
	user, err := h.db.GetUserByUsername(c.Request.Context(), jwtClaims.Username)
	if err != nil {
		h.logger.Error("failed to get user info",
			zap.String("username", jwtClaims.Username),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get user info: "+err.Error()))
		return
	}

	// Only admin can sync all servers
	if user.Role != database.RoleAdmin {
		h.logger.Warn("non-admin user attempted to sync all servers",
			zap.String("username", user.Username))
		i18n.RespondWithError(c, i18n.ErrUnauthorized)
		return
	}

	h.logger.Info("handling MCP server sync request")

	// Send reload signal to gateway using notifier
	if err := h.notifier.NotifyUpdate(c.Request.Context(), nil); err != nil {
		h.logger.Error("failed to reload gateway", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to reload gateway: "+err.Error()))
		return
	}

	// Clear all cache since we're syncing all servers
	h.clearCapabilitiesCache("")

	h.logger.Info("MCP servers synced successfully")
	i18n.Success(i18n.SuccessMCPServerSynced).With("status", "success").Send(c)
}

// HandleGetConfigVersions handles the request to get configuration versions
func (h *MCP) HandleGetConfigVersions(c *gin.Context) {
	configNames := c.QueryArray("names")
	tenant := c.Query("tenant")
	var versions []*config.MCPConfigVersion
	var configs []*config.MCPConfig

	// Get user from claims
	claims, exists := c.Get("claims")
	if !exists {
		h.logger.Warn("missing JWT claims in context")
		i18n.RespondWithError(c, i18n.ErrUnauthorized)
		return
	}
	jwtClaims := claims.(*jwt.Claims)

	// Get user information
	user, err := h.db.GetUserByUsername(c.Request.Context(), jwtClaims.Username)
	if err != nil {
		h.logger.Error("failed to get user info",
			zap.String("username", jwtClaims.Username),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get user info: "+err.Error()))
		return
	}

	// If no names provided, get all configs first
	configs, err = h.store.List(c.Request.Context(), true)
	if err != nil {
		h.logger.Error("failed to list configs", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer)
		return
	}

	// Filter by tenant if specified
	if tenant != "" {
		filteredConfigs := make([]*config.MCPConfig, 0)
		for _, cfg := range configs {
			if cfg.Tenant == tenant {
				filteredConfigs = append(filteredConfigs, cfg)
			}
		}
		configs = filteredConfigs
	}

	if user.Role != database.RoleAdmin {
		// Get user's tenants
		tenants, err := h.db.GetUserTenants(c.Request.Context(), user.ID)
		if err != nil {
			h.logger.Error("failed to get user tenants",
				zap.String("username", user.Username),
				zap.Error(err))
			i18n.RespondWithError(c, i18n.ErrInternalServer)
			return
		}

		// Create a map of tenant names for faster lookup
		userTenants := make(map[string]bool)
		for _, t := range tenants {
			userTenants[t.Name] = true
		}

		filteredConfigs := make([]*config.MCPConfig, 0)
		for _, cfg := range configs {
			if userTenants[cfg.Tenant] {
				filteredConfigs = append(filteredConfigs, cfg)
			}
		}
		configs = filteredConfigs
	}

	if len(configNames) > 0 {
		// Filter configs by names
		filteredConfigs := make([]*config.MCPConfig, 0)
		for _, cfg := range configs {
			for _, name := range configNames {
				if cfg.Name == name {
					filteredConfigs = append(filteredConfigs, cfg)
					break
				}
			}
		}
		configs = filteredConfigs
	}

	if len(configs) == 0 {
		h.logger.Warn("no configs found")
		i18n.Success(i18n.SuccessMCPConfigVersions).With("data", versions).Send(c)
		return
	}

	// Get versions for each config
	for _, cfg := range configs {
		configVersions, err := h.store.ListVersions(c.Request.Context(), cfg.Tenant, cfg.Name)
		if err != nil {
			h.logger.Error("failed to list versions", zap.String("config", cfg.Name), zap.Error(err))
			continue
		}
		versions = append(versions, configVersions...)
	}

	// Sort versions by created_at in descending order
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].CreatedAt.After(versions[j].CreatedAt)
	})

	i18n.Success(i18n.SuccessMCPConfigVersions).With("data", versions).Send(c)
}

// HandleSetActiveVersion handles setting a version as active
func (h *MCP) HandleSetActiveVersion(c *gin.Context) {
	tenant := c.Param("tenant")
	if tenant == "" {
		h.logger.Warn("MCP server tenant required but missing")
		i18n.RespondWithError(c, i18n.ErrorTenantRequired)
		return
	}
	name := c.Param("name")
	if name == "" {
		h.logger.Warn("config name required but missing")
		i18n.RespondWithError(c, i18n.ErrorMCPServerNameRequired)
		return
	}
	versionStr := c.Param("version")
	if versionStr == "" {
		h.logger.Warn("version required but missing")
		i18n.RespondWithError(c, i18n.ErrorVersionRequired)
		return
	}

	version, err := strconv.Atoi(versionStr)
	if err != nil {
		h.logger.Warn("invalid version number",
			zap.String("version", versionStr),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", "Invalid version number"))
		return
	}

	h.logger.Info("handling set active version request",
		zap.String("config_name", name),
		zap.Int("version", version))

	// Get the config
	existingCfg, err := h.store.Get(c.Request.Context(), tenant, name)
	if err != nil {
		h.logger.Error("failed to get config",
			zap.String("config_name", name),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get config: "+err.Error()))
		return
	}

	// Check tenant permission
	_, err = h.checkTenantPermission(c, existingCfg.Tenant, existingCfg)
	if err != nil {
		h.logger.Warn("tenant permission check failed",
			zap.String("tenant", existingCfg.Tenant),
			zap.Error(err))
		i18n.RespondWithError(c, err)
		return
	}

	// Set version as active in store
	if err := h.store.SetActiveVersion(c.Request.Context(), existingCfg.Tenant, name, version); err != nil {
		h.logger.Error("failed to set active version",
			zap.String("config_name", name),
			zap.Int("version", version),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to set active version: "+err.Error()))
		return
	}

	// Send reload signal to gateway using notifier
	if err := h.notifier.NotifyUpdate(c.Request.Context(), existingCfg); err != nil {
		h.logger.Error("failed to notify gateway", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to notify gateway: "+err.Error()))
		return
	}

	h.logger.Info("active version set successfully",
		zap.String("config_name", name),
		zap.Int("version", version))
	i18n.Success(i18n.SuccessMCPServerUpdated).With("status", "success").Send(c)
}

// HandleGetConfigNames handles the request to get all configuration names
func (h *MCP) HandleGetConfigNames(c *gin.Context) {
	includeDeleted := c.Query("includeDeleted") == "true"
	tenant := c.Query("tenant")

	configs, err := h.store.List(c.Request.Context(), includeDeleted)
	if err != nil {
		h.logger.Error("failed to list configs", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to list configs: "+err.Error()))
		return
	}

	// Get user from claims
	claims, exists := c.Get("claims")
	if !exists {
		h.logger.Warn("missing JWT claims in context")
		i18n.RespondWithError(c, i18n.ErrUnauthorized)
		return
	}
	jwtClaims := claims.(*jwt.Claims)

	// Get user information
	user, err := h.db.GetUserByUsername(c.Request.Context(), jwtClaims.Username)
	if err != nil {
		h.logger.Error("failed to get user info",
			zap.String("username", jwtClaims.Username),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get user info: "+err.Error()))
		return
	}

	// Filter configs by tenant if user is not admin
	if user.Role != database.RoleAdmin {
		// Get user's tenants
		tenants, err := h.db.GetUserTenants(c.Request.Context(), user.ID)
		if err != nil {
			h.logger.Error("failed to get user tenants",
				zap.String("username", user.Username),
				zap.Error(err))
			i18n.RespondWithError(c, i18n.ErrInternalServer)
			return
		}

		// Create a map of tenant names for faster lookup
		userTenants := make(map[string]bool)
		for _, t := range tenants {
			userTenants[t.Name] = true
		}

		filteredConfigs := make([]*config.MCPConfig, 0)
		for _, cfg := range configs {
			if userTenants[cfg.Tenant] {
				filteredConfigs = append(filteredConfigs, cfg)
			}
		}
		configs = filteredConfigs
	}

	// Filter by tenant if specified
	if tenant != "" {
		filteredConfigs := make([]*config.MCPConfig, 0)
		for _, cfg := range configs {
			if cfg.Tenant == tenant {
				filteredConfigs = append(filteredConfigs, cfg)
			}
		}
		configs = filteredConfigs
	}

	// Extract unique config names
	names := make([]string, 0, len(configs))
	for _, cfg := range configs {
		names = append(names, cfg.Name)
	}

	c.JSON(http.StatusOK, gin.H{
		"data": names,
	})
}

// HandleGetCapabilities handles GET /api/mcp/capabilities/:tenant/:name
func (h *MCP) HandleGetCapabilities(c *gin.Context) {
	tenant := c.Param("tenant")
	if tenant == "" {
		h.logger.Warn("tenant parameter required but missing")
		i18n.RespondWithError(c, i18n.ErrorTenantRequired)
		return
	}

	name := c.Param("name")
	if name == "" {
		h.logger.Warn("MCP server name required but missing")
		i18n.RespondWithError(c, i18n.ErrorMCPServerNameRequired)
		return
	}

	h.logger.Info("handling get capabilities request",
		zap.String("tenant", tenant),
		zap.String("name", name))

	// Get MCP server configuration
	cfg, err := h.store.Get(c.Request.Context(), tenant, name)
	if err != nil {
		h.logger.Error("MCP server not found",
			zap.String("tenant", tenant),
			zap.String("name", name),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrorMCPServerNotFound.WithParam("Name", name))
		return
	}

	// Check tenant permission
	_, err = h.checkTenantPermission(c, cfg.Tenant, cfg)
	if err != nil {
		h.logger.Warn("tenant permission check failed",
			zap.String("tenant", cfg.Tenant),
			zap.Error(err))
		i18n.RespondWithError(c, err)
		return
	}

	// Check cache first
	cacheKey := tenant + ":" + name
	capabilities, err := h.getCapabilitiesFromCache(c.Request.Context(), cacheKey, cfg)
	if err != nil {
		h.logger.Error("failed to get capabilities",
			zap.String("tenant", tenant),
			zap.String("name", name),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get capabilities: "+err.Error()))
		return
	}

	h.logger.Info("capabilities fetched successfully",
		zap.String("tenant", tenant),
		zap.String("name", name),
		zap.Int("tools_count", len(capabilities.Tools)),
		zap.Int("prompts_count", len(capabilities.Prompts)),
		zap.Int("resources_count", len(capabilities.Resources)),
		zap.Int("resource_templates_count", len(capabilities.ResourceTemplates)))

	i18n.Success(i18n.SuccessMCPCapabilities).With("data", capabilities).Send(c)
}

// fetchCapabilities fetches capabilities from all MCP servers in the configuration
func (h *MCP) fetchCapabilities(ctx context.Context, cfg *config.MCPConfig) (*mcp.CapabilitiesInfo, error) {
	capabilities := &mcp.CapabilitiesInfo{
		Tools:             make([]mcp.MCPTool, 0),
		Prompts:           make([]mcp.MCPPrompt, 0),
		Resources:         make([]mcp.MCPResource, 0),
		ResourceTemplates: make([]mcp.MCPResourceTemplate, 0),
		LastSynced:        time.Now().UTC(),
		ServerInfo:        mcp.ImplementationSchema{Name: "unknown", Version: "unknown"},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	errChan := make(chan error, len(cfg.McpServers)*4) // 4 operations per server

	// Fetch capabilities from each MCP server concurrently
	for _, mcpServerCfg := range cfg.McpServers {
		wg.Add(1)
		go func(serverCfg config.MCPServerConfig) {
			defer wg.Done()

			// Create transport for this MCP server
			transport, err := mcpproxy.NewTransport(serverCfg)
			if err != nil {
				h.logger.Error("failed to create transport",
					zap.String("server", serverCfg.Name),
					zap.Error(err))
				errChan <- err
				return
			}

			// Start transport if not running
			if !transport.IsRunning() {
				tmplCtx := template.NewContext()
				if err := transport.Start(ctx, tmplCtx); err != nil {
					h.logger.Error("failed to start transport",
						zap.String("server", serverCfg.Name),
						zap.Error(err))
					errChan <- err
					return
				}
				// Ensure transport is stopped after use
				defer func() {
					if stopErr := transport.Stop(ctx); stopErr != nil {
						h.logger.Warn("failed to stop transport",
							zap.String("server", serverCfg.Name),
							zap.Error(stopErr))
					}
				}()
			}

			// Fetch tools, prompts, resources, and resource templates concurrently
			var serverWg sync.WaitGroup
			serverWg.Add(4)

			// Fetch tools
			go func() {
				defer serverWg.Done()
				tools, err := transport.FetchTools(ctx)
				if err != nil {
					h.logger.Error("failed to fetch tools",
						zap.String("server", serverCfg.Name),
						zap.Error(err))
					errChan <- err
					return
				}

				// Get all tool statuses for this server in one query
				toolStatuses, err := h.db.GetToolStatuses(ctx, cfg.Tenant, cfg.Name)
				if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
					h.logger.Debug("failed to get tool statuses, using default enabled=true for all tools",
						zap.String("tenant", cfg.Tenant),
						zap.String("server", cfg.Name),
						zap.Error(err))
				}

				// Create a map for quick lookup of tool statuses
				statusMap := make(map[string]bool)
				for _, status := range toolStatuses {
					statusMap[status.ToolName] = status.Enabled
				}

				// Convert to MCP tools and apply database status
				mcpTools := make([]mcp.MCPTool, len(tools))
				for i, tool := range tools {
					// Check if we have a saved status, otherwise default to enabled
					enabled := true
					if savedEnabled, exists := statusMap[tool.Name]; exists {
						enabled = savedEnabled
					}
					
					mcpTools[i] = mcp.MCPTool{
						Name:        tool.Name,
						Description: tool.Description,
						InputSchema: tool.InputSchema,
						Annotations: tool.Annotations,
						Enabled:     enabled,
						LastSynced:  time.Now().UTC(),
					}
				}

				mu.Lock()
				capabilities.Tools = append(capabilities.Tools, mcpTools...)
				mu.Unlock()
			}()

			// Fetch prompts
			go func() {
				defer serverWg.Done()
				prompts, err := transport.FetchPrompts(ctx)
				if err != nil {
					h.logger.Error("failed to fetch prompts",
						zap.String("server", serverCfg.Name),
						zap.Error(err))
					errChan <- err
					return
				}

				// Convert to MCP prompts
				mcpPrompts := make([]mcp.MCPPrompt, len(prompts))
				for i, prompt := range prompts {
					mcpPrompts[i] = mcp.MCPPrompt{
						Name:        prompt.Name,
						Description: prompt.Description,
						Arguments:   prompt.Arguments,
						LastSynced:  time.Now().UTC(),
					}
				}

				mu.Lock()
				capabilities.Prompts = append(capabilities.Prompts, mcpPrompts...)
				mu.Unlock()
			}()

			// TODO: Resources functionality not yet implemented in transport layer
			// Skip fetching resources and resource templates for now
			serverWg.Done() // Complete the resource fetch
			serverWg.Done() // Complete the resource template fetch

			serverWg.Wait()
		}(mcpServerCfg)
	}

	// Wait for all servers to complete
	wg.Wait()
	close(errChan)

	// Collect any errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	// If there are errors but we got some capabilities, log warnings
	if len(errors) > 0 {
		h.logger.Warn("some capabilities could not be fetched",
			zap.Int("error_count", len(errors)),
			zap.Int("tools_fetched", len(capabilities.Tools)),
			zap.Int("prompts_fetched", len(capabilities.Prompts)))

		// If we didn't get any capabilities at all, return the first error
		if len(capabilities.Tools) == 0 && len(capabilities.Prompts) == 0 &&
			len(capabilities.Resources) == 0 && len(capabilities.ResourceTemplates) == 0 {
			return nil, errors[0]
		}
	}

	return capabilities, nil
}

// getCapabilitiesFromCache checks cache first, then fetches if needed
func (h *MCP) getCapabilitiesFromCache(ctx context.Context, cacheKey string, cfg *config.MCPConfig) (*mcp.CapabilitiesInfo, error) {
	// Check if we have cached data
	if cached, ok := h.capabilitiesCache.Load(cacheKey); ok {
		if cachedCaps, ok := cached.(*cachedCapabilities); ok {
			if !cachedCaps.isExpired() {
				h.logger.Debug("returning cached capabilities",
					zap.String("cache_key", cacheKey),
					zap.Time("cached_at", cachedCaps.timestamp))
				return cachedCaps.data, nil
			} else {
				h.logger.Debug("cached capabilities expired, removing from cache",
					zap.String("cache_key", cacheKey),
					zap.Time("cached_at", cachedCaps.timestamp))
				h.capabilitiesCache.Delete(cacheKey)
			}
		}
	}

	// Fetch fresh data
	h.logger.Debug("fetching fresh capabilities",
		zap.String("cache_key", cacheKey))

	capabilities, err := h.fetchCapabilities(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Cache the result with 5 minute TTL
	cached := &cachedCapabilities{
		data:      capabilities,
		timestamp: time.Now(),
		ttl:       5 * time.Minute,
	}
	h.capabilitiesCache.Store(cacheKey, cached)

	h.logger.Debug("capabilities cached successfully",
		zap.String("cache_key", cacheKey),
		zap.Time("cached_at", cached.timestamp),
		zap.Duration("ttl", cached.ttl))

	return capabilities, nil
}

// clearCapabilitiesCache clears cache for a specific server or all if key is empty
func (h *MCP) clearCapabilitiesCache(key string) {
	if key == "" {
		// Clear all cache
		h.capabilitiesCache.Range(func(k, v interface{}) bool {
			h.capabilitiesCache.Delete(k)
			return true
		})
		h.logger.Debug("cleared all capabilities cache")
	} else {
		h.capabilitiesCache.Delete(key)
		h.logger.Debug("cleared capabilities cache for key", zap.String("key", key))
	}
}

// HandleGetCapabilitiesStats handles GET /api/mcp/capabilities/{tenant}/{name}/stats
func (h *MCP) HandleGetCapabilitiesStats(c *gin.Context) {
	tenant := c.Param("tenant")
	if tenant == "" {
		h.logger.Warn("tenant parameter required but missing")
		i18n.RespondWithError(c, i18n.ErrorTenantRequired)
		return
	}

	name := c.Param("name")
	if name == "" {
		h.logger.Warn("MCP server name required but missing")
		i18n.RespondWithError(c, i18n.ErrorMCPServerNameRequired)
		return
	}

	h.logger.Info("handling get capabilities statistics request",
		zap.String("tenant", tenant),
		zap.String("server_name", name))

	// Get MCP server configuration to check permissions
	cfg, err := h.store.Get(c.Request.Context(), tenant, name)
	if err != nil {
		h.logger.Error("MCP server not found",
			zap.String("tenant", tenant),
			zap.String("server_name", name),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrorMCPServerNotFound.WithParam("Name", name))
		return
	}

	// Check tenant permission
	dbTenant, err := h.checkTenantPermission(c, tenant, cfg)
	if err != nil {
		return // Error already handled in checkTenantPermission
	}
	if dbTenant == nil {
		return // Permission denied, error already sent
	}

	// Get capabilities data
	capabilities, err := h.fetchCapabilities(c.Request.Context(), cfg)
	if err != nil {
		h.logger.Error("failed to get capabilities",
			zap.String("tenant", tenant),
			zap.String("server_name", name),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get capabilities: "+err.Error()))
		return
	}

	// Calculate statistics
	stats := h.calculateCapabilitiesStats(c.Request.Context(), tenant, name, capabilities, cfg)

	h.logger.Info("capabilities statistics calculated successfully",
		zap.String("tenant", tenant),
		zap.String("server_name", name),
		zap.Int("total_capabilities", stats.Summary.TotalCapabilities))

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}

// calculateCapabilitiesStats calculates comprehensive statistics from capabilities data
func (h *MCP) calculateCapabilitiesStats(ctx context.Context, tenant, serverName string, capabilities *mcp.CapabilitiesInfo, cfg *config.MCPConfig) *CapabilitiesStatsResponse {
	stats := &CapabilitiesStatsResponse{
		LastUpdated: time.Now(),
	}

	// Server information
	stats.Server = ServerStatsInfo{
		Tenant:     tenant,
		ServerName: serverName,
		Status:     "active", // Could be derived from proxy health
		Version:    "1.0",    // Default version
	}

	// Get last sync time if available - use current time as placeholder
	stats.Server.LastSyncAt = time.Now()

	// Tools statistics
	stats.Tools = h.calculateToolsStats(ctx, tenant, serverName, capabilities.Tools)

	// Prompts statistics
	stats.Prompts = h.calculatePromptsStats(capabilities.Prompts)

	// Resources statistics (including templates)
	stats.Resources = h.calculateResourcesStats(capabilities.Resources, capabilities.ResourceTemplates)

	// Overall summary
	totalCapabilities := len(capabilities.Tools) + len(capabilities.Prompts) + len(capabilities.Resources) + len(capabilities.ResourceTemplates)
	activeCapabilities := stats.Tools.Enabled + stats.Prompts.Total + stats.Resources.Total

	stats.Summary = StatsOverallInfo{
		TotalCapabilities:  totalCapabilities,
		ActiveCapabilities: activeCapabilities,
		Distribution: map[string]int{
			"tools":             len(capabilities.Tools),
			"prompts":           len(capabilities.Prompts),
			"resources":         len(capabilities.Resources),
			"resourceTemplates": len(capabilities.ResourceTemplates),
		},
	}

	return stats
}

// calculateToolsStats calculates tools-specific statistics
func (h *MCP) calculateToolsStats(ctx context.Context, tenant, serverName string, tools []mcp.MCPTool) ToolsStatsInfo {
	if len(tools) == 0 {
		return ToolsStatsInfo{}
	}

	stats := ToolsStatsInfo{
		Total:      len(tools),
		ByCategory: make(map[string]int),
	}

	enabledCount := 0
	for _, tool := range tools {
		// Default to enabled if no status management system
		enabledCount++

		// Categorize tools by schema properties (simple heuristic)
		category := h.categorizeToolBySchema(tool)
		stats.ByCategory[category]++
	}

	stats.Enabled = enabledCount
	stats.Disabled = stats.Total - enabledCount
	if stats.Total > 0 {
		stats.EnabledRate = float64(enabledCount) / float64(stats.Total) * 100
	}

	// TODO: Add usage statistics from tool call logs if available
	stats.Usage = ToolUsageStatsInfo{
		TotalCalls:  0,
		SuccessRate: 0.0,
		AvgExecTime: 0.0,
	}

	return stats
}

// calculatePromptsStats calculates prompts-specific statistics
func (h *MCP) calculatePromptsStats(prompts []mcp.MCPPrompt) PromptsStatsInfo {
	if len(prompts) == 0 {
		return PromptsStatsInfo{}
	}

	stats := PromptsStatsInfo{
		Total:      len(prompts),
		ByCategory: make(map[string]int),
	}

	withArgsCount := 0
	for _, prompt := range prompts {
		if len(prompt.Arguments) > 0 {
			withArgsCount++
		}

		// Categorize prompts by argument count
		if len(prompt.Arguments) == 0 {
			stats.ByCategory["no-args"]++
		} else if len(prompt.Arguments) <= 3 {
			stats.ByCategory["few-args"]++
		} else {
			stats.ByCategory["many-args"]++
		}
	}

	stats.WithArgs = withArgsCount
	stats.WithoutArgs = stats.Total - withArgsCount

	return stats
}

// calculateResourcesStats calculates resources-specific statistics
func (h *MCP) calculateResourcesStats(resources []mcp.MCPResource, templates []mcp.MCPResourceTemplate) ResourcesStatsInfo {
	stats := ResourcesStatsInfo{
		Total:      len(resources),
		Templates:  len(templates),
		Static:     len(resources),
		ByMimeType: make(map[string]int),
	}

	// Analyze resources by MIME type
	for _, resource := range resources {
		if resource.MimeType != "" {
			stats.ByMimeType[resource.MimeType]++
		} else {
			stats.ByMimeType["unknown"]++
		}
	}

	// Analyze templates by MIME type
	for _, template := range templates {
		if template.MimeType != "" {
			stats.ByMimeType[template.MimeType]++
		} else {
			stats.ByMimeType["unknown"]++
		}
	}

	// Update total to include templates
	stats.Total += stats.Templates

	return stats
}

// categorizeToolBySchema categorizes tools based on their schema properties
func (h *MCP) categorizeToolBySchema(tool mcp.MCPTool) string {
	// Simple heuristic based on tool name and properties
	if len(tool.InputSchema.Properties) == 0 {
		return "simple"
	} else if len(tool.InputSchema.Properties) <= 3 {
		return "medium"
	} else {
		return "complex"
	}
}

// HandleUpdateToolStatus handles PUT /api/mcp/capabilities/{tenant}/{name}/tools/{toolName}/status
func (h *MCP) HandleUpdateToolStatus(c *gin.Context) {
	tenant := c.Param("tenant")
	if tenant == "" {
		h.logger.Warn("tenant parameter required but missing")
		i18n.RespondWithError(c, i18n.ErrorTenantRequired)
		return
	}

	name := c.Param("name")
	if name == "" {
		h.logger.Warn("MCP server name required but missing")
		i18n.RespondWithError(c, i18n.ErrorMCPServerNameRequired)
		return
	}

	toolName := c.Param("toolName")
	if toolName == "" {
		h.logger.Warn("tool name required but missing")
		i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", "Tool name is required"))
		return
	}

	// Parse request body
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("failed to parse request body", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", "Invalid request body: "+err.Error()))
		return
	}

	h.logger.Info("handling update tool status request",
		zap.String("tenant", tenant),
		zap.String("server_name", name),
		zap.String("tool_name", toolName),
		zap.Bool("enabled", req.Enabled))

	// Get MCP server configuration to check permissions
	cfg, err := h.store.Get(c.Request.Context(), tenant, name)
	if err != nil {
		h.logger.Error("MCP server not found",
			zap.String("tenant", tenant),
			zap.String("server_name", name),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrorMCPServerNotFound.WithParam("Name", name))
		return
	}

	// Check tenant permission
	_, err = h.checkTenantPermission(c, tenant, cfg)
	if err != nil {
		h.logger.Warn("tenant permission check failed",
			zap.String("tenant", tenant),
			zap.Error(err))
		i18n.RespondWithError(c, err)
		return
	}

	// Save tool status to database
	err = h.db.SetToolStatus(c.Request.Context(), tenant, name, toolName, req.Enabled)
	if err != nil {
		h.logger.Error("failed to save tool status",
			zap.String("tenant", tenant),
			zap.String("server_name", name),
			zap.String("tool_name", toolName),
			zap.Bool("enabled", req.Enabled),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to save tool status: "+err.Error()))
		return
	}

	// Clear capabilities cache to force refresh
	cacheKey := tenant + ":" + name
	h.clearCapabilitiesCache(cacheKey)
	
	h.logger.Info("tool status updated successfully",
		zap.String("tenant", tenant),
		zap.String("server_name", name),
		zap.String("tool_name", toolName),
		zap.Bool("enabled", req.Enabled))

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Tool status updated successfully",
		"data": gin.H{
			"tenant":    tenant,
			"server":    name,
			"tool":      toolName,
			"enabled":   req.Enabled,
			"updated_at": time.Now(),
		},
	})
}
