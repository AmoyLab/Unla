package handler

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/amoylab/unla/internal/apiserver/database"
	"github.com/amoylab/unla/internal/i18n"
	"github.com/amoylab/unla/internal/auth/jwt"
	"go.uber.org/zap"
)

type SystemPrompt struct {
	db     database.Database
	logger *zap.Logger
}

func NewSystemPrompt(db database.Database, logger *zap.Logger) *SystemPrompt {
	return &SystemPrompt{db: db, logger: logger.Named("apiserver.handler.systemprompt")}
}

// GetSystemPrompt returns the system prompt for the current user
func (h *SystemPrompt) GetSystemPrompt(c *gin.Context) {
	claims, exists := c.Get("claims")
	if !exists {
		h.logger.Warn("missing claims in context", zap.String("remote_addr", c.ClientIP()))
		i18n.RespondWithError(c, i18n.ErrUnauthorized)
		return
	}
	jwtClaims := claims.(*jwt.Claims)
	user, err := h.db.GetUserByUsername(c.Request.Context(), jwtClaims.Username)
	if err != nil {
		h.logger.Error("failed to get user info", zap.String("username", jwtClaims.Username), zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get user info: "+err.Error()))
		return
	}
	h.logger.Info("retrieving system prompt", zap.Uint("user_id", user.ID), zap.String("remote_addr", c.ClientIP()))
	prompt, err := h.db.GetSystemPrompt(c.Request.Context(), user.ID)
	if err != nil {
		h.logger.Error("failed to get system prompt", zap.Error(err), zap.Uint("user_id", user.ID), zap.String("remote_addr", c.ClientIP()))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", err.Error()))
		return
	}
	h.logger.Debug("successfully retrieved system prompt", zap.Uint("user_id", user.ID), zap.String("remote_addr", c.ClientIP()))
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"prompt": prompt}})
}

// SaveSystemPrompt saves the system prompt for the current user
func (h *SystemPrompt) SaveSystemPrompt(c *gin.Context) {
	claims, exists := c.Get("claims")
	if !exists {
		h.logger.Warn("missing claims in context", zap.String("remote_addr", c.ClientIP()))
		i18n.RespondWithError(c, i18n.ErrUnauthorized)
		return
	}
	jwtClaims := claims.(*jwt.Claims)
	user, err := h.db.GetUserByUsername(c.Request.Context(), jwtClaims.Username)
	if err != nil {
		h.logger.Error("failed to get user info", zap.String("username", jwtClaims.Username), zap.Error(err))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", "Failed to get user info: "+err.Error()))
		return
	}
	var req struct {
		Prompt string `json:"prompt"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("invalid request body", zap.Error(err), zap.Uint("user_id", user.ID), zap.String("remote_addr", c.ClientIP()))
		i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", err.Error()))
		return
	}
	h.logger.Info("saving system prompt", zap.Uint("user_id", user.ID), zap.String("remote_addr", c.ClientIP()))
	if err := h.db.SaveSystemPrompt(c.Request.Context(), user.ID, req.Prompt); err != nil {
		h.logger.Error("failed to save system prompt", zap.Error(err), zap.Uint("user_id", user.ID), zap.String("remote_addr", c.ClientIP()))
		i18n.RespondWithError(c, i18n.ErrInternalServer.WithParam("Reason", err.Error()))
		return
	}
	h.logger.Debug("successfully saved system prompt", zap.Uint("user_id", user.ID), zap.String("remote_addr", c.ClientIP()))
	c.JSON(http.StatusOK, gin.H{"success": true})
}
