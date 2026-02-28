package storage

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/amoylab/unla/internal/common/config"
)

// NewStore creates a new store based on configuration
func NewStore(logger *zap.Logger, cfg *config.StorageConfig) (Store, error) {
	logger.Info("Initializing storage", zap.String("type", cfg.Type))
	switch cfg.Type {
	case "db":
		return NewDBStore(logger, cfg)
	case "api":
		return NewAPIStore(logger, cfg.API.Url, cfg.API.ConfigJSONPath, cfg.API.Timeout, cfg.API.IgnoreInvalidConfig)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", cfg.Type)
	}
}
