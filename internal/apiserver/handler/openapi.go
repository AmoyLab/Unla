package handler

import (
	"github.com/amoylab/unla/internal/apiserver/database"
	"github.com/amoylab/unla/internal/auth/jwt"
	"github.com/amoylab/unla/internal/i18n"
	"github.com/amoylab/unla/internal/mcp/storage"
	"github.com/amoylab/unla/internal/mcp/storage/notifier"
	"github.com/amoylab/unla/pkg/openapi"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// OpenAPI handles OpenAPI related operations
type OpenAPI struct {
	db       database.Database
	store    storage.Store
	notifier notifier.Notifier
	logger   *zap.Logger
}

// NewOpenAPI creates a new OpenAPI handler
func NewOpenAPI(db database.Database, store storage.Store, ntf notifier.Notifier, logger *zap.Logger) *OpenAPI {
	return &OpenAPI{
		db:       db,
		store:    store,
		notifier: ntf,
		logger:   logger,
	}
}

// HandleImport handles OpenAPI import requests
func (h *OpenAPI) HandleImport(c *gin.Context) {
	h.logger.Info("handling OpenAPI import request")

	// Get the file from the request
	file, err := c.FormFile("file")
	if err != nil {
		h.logger.Error("failed to get file from request", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", "Failed to get file: "+err.Error()))
		return
	}

	h.logger.Debug("processing OpenAPI file",
		zap.String("filename", file.Filename),
		zap.Int64("size", file.Size))

	// Open the file
	f, err := file.Open()
	if err != nil {
		h.logger.Error("failed to open uploaded file",
			zap.String("filename", file.Filename),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to open file: "+err.Error()))
		return
	}
	defer f.Close()

	// Read the file content
	content := make([]byte, file.Size)
	if _, err := f.Read(content); err != nil {
		h.logger.Error("failed to read file content",
			zap.String("filename", file.Filename),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to read file: "+err.Error()))
		return
	}

	// Read tenant name and prefix from form
	tenantName := c.PostForm("tenantName")
	prefix := c.PostForm("prefix")

	// Get user from claims for tenant validation
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

	h.logger.Debug("received OpenAPI import request",
		zap.String("tenantName", tenantName),
		zap.String("prefix", prefix),
		zap.String("username", jwtClaims.Username),
		zap.String("user_role", string(user.Role)))

	// Validate tenant is required
	if tenantName == "" {
		h.logger.Warn("tenant is required for OpenAPI import",
			zap.String("username", jwtClaims.Username))
		i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", "Tenant is required"))
		return
	}

	// Find the tenant by name to get its prefix
	tenantObj, err := h.db.GetTenantByName(c.Request.Context(), tenantName)
	if err != nil {
		h.logger.Error("failed to find tenant",
			zap.String("tenantName", tenantName),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", "Tenant not found: "+tenantName))
		return
	}

	// Use the tenant name for config.Tenant and tenant prefix for router prefix
	finalTenant := tenantName
	tenantPrefix := tenantObj.Prefix
	h.logger.Debug("using specified tenant",
		zap.String("tenantName", tenantName),
		zap.String("tenantPrefix", tenantPrefix),
		zap.String("finalTenant", finalTenant))

	h.logger.Debug("creating OpenAPI converter",
		zap.String("final_tenant", finalTenant),
		zap.String("prefix", prefix))
	converter := openapi.NewConverter()

	// Use the validated tenant
	config, err := converter.ConvertWithOptions(content, tenantPrefix, prefix)
	if err == nil {
		// Override the tenant field to use tenant name instead of prefix
		config.Tenant = finalTenant
	}
	if err != nil {
		h.logger.Error("failed to convert OpenAPI specification", zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", "Failed to convert OpenAPI specification: "+err.Error()))
		return
	}

	h.logger.Info("OpenAPI specification converted successfully",
		zap.String("server_name", config.Name))

	// Create the MCP server configuration
	h.logger.Debug("creating MCP server configuration")
	if err := h.store.Create(c.Request.Context(), config); err != nil {
		h.logger.Error("failed to create MCP server",
			zap.String("server_name", config.Name),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to create MCP server: "+err.Error()))
		return
	}

	// Notify the gateway about the update
	h.logger.Debug("notifying gateway about the update")
	if err := h.notifier.NotifyUpdate(c.Request.Context(), config); err != nil {
		h.logger.Error("failed to notify gateway",
			zap.String("server_name", config.Name),
			zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to notify gateway: "+err.Error()))
		return
	}

	h.logger.Info("OpenAPI imported successfully",
		zap.String("server_name", config.Name))

	i18n.Created(i18n.SuccessOpenAPIImported).
		With("status", "success").
		With("config", config).
		Send(c)
}
