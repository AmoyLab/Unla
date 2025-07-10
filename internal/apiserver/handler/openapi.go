package handler

import (
        "github.com/amoylab/unla/internal/common/config"
	"github.com/gin-gonic/gin"
	"github.com/amoylab/unla/internal/apiserver/database"
	"github.com/amoylab/unla/internal/i18n"
	"github.com/amoylab/unla/internal/mcp/storage"
	"github.com/amoylab/unla/internal/mcp/storage/notifier"
	"github.com/amoylab/unla/pkg/openapi"
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

	// Read tenant and prefix from form
	tenant := c.PostForm("tenantId")
	prefix := c.PostForm("prefix")

	h.logger.Debug("creating OpenAPI converter")
	converter := openapi.NewConverter()

	// Use provided tenant/prefix if not empty, else use default logic
	var config *config.MCPConfig
	if tenant == "" && prefix == "" {
		config, err = converter.Convert(content)
	} else {
		config, err = converter.ConvertWithOptions(content, tenant, prefix)
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
