package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"

	"github.com/glebarez/sqlite"
	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// DatabaseType represents the type of database
type DatabaseType string

const (
	PostgreSQL DatabaseType = "postgres"
	MySQL      DatabaseType = "mysql"
	SQLite     DatabaseType = "sqlite"
)

// DBStore implements the Store interface using a database
type DBStore struct {
	logger *zap.Logger
	db     *gorm.DB
	cfg    *config.StorageConfig
}

var _ Store = (*DBStore)(nil)

// NewDBStore creates a new database-based store
func NewDBStore(logger *zap.Logger, cfg *config.StorageConfig) (*DBStore, error) {
	logger = logger.Named("mcp.store.db")

	var dialector gorm.Dialector
	switch DatabaseType(cfg.Database.Type) {
	case PostgreSQL:
		dialector = postgres.Open(cfg.Database.GetDSN())
	case MySQL:
		dialector = mysql.Open(cfg.Database.GetDSN())
	case SQLite:
		dialector = sqlite.Open(cfg.Database.GetDSN())
	default:
		return nil, gorm.ErrInvalidDB
	}

	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Auto migrate the schema
	if err := db.AutoMigrate(&MCPConfig{}, &MCPConfigVersion{}, &ActiveVersion{}); err != nil {
		return nil, err
	}

	return &DBStore{
		logger: logger,
		db:     db,
		cfg:    cfg,
	}, nil
}

// Create implements Store.Create
func (s *DBStore) Create(_ context.Context, server *config.MCPConfig) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		model, err := FromMCPConfig(server)
		if err != nil {
			return err
		}

		// Check if there's a soft deleted record
		var existingModel MCPConfig
		if err := tx.Unscoped().Where("tenant = ? AND name = ?", server.Tenant, server.Name).First(&existingModel).Error; err == nil {
			// If found and soft deleted, restore it and update content
			if existingModel.DeletedAt.Valid {
				model.ID = existingModel.ID
				model.CreatedAt = existingModel.CreatedAt
				if err := tx.Model(&existingModel).Unscoped().Updates(map[string]interface{}{
					"deleted_at":  nil,
					"routers":     model.Routers,
					"servers":     model.Servers,
					"tools":       model.Tools,
					"prompts":     model.Prompts,
					"mcp_servers": model.McpServers,
					"updated_at":  time.Now(),
				}).Error; err != nil {
					return err
				}

				// Get the latest version number
				var latestVersion int
				if err := tx.Model(&MCPConfigVersion{}).
					Where("tenant = ? AND name = ?", server.Tenant, server.Name).
					Select("COALESCE(MAX(version), 0)").
					Scan(&latestVersion).Error; err != nil {
					return err
				}

				// Create version record with incremented version number
				version, err := FromMCPConfigVersion(server, latestVersion+1, "system", cnst.ActionCreate)
				if err != nil {
					return err
				}

				if err := tx.Create(version).Error; err != nil {
					return err
				}

				// Create or restore active version record
				activeVersion := &ActiveVersion{
					Name:      server.Name,
					Tenant:    server.Tenant,
					Version:   version.Version,
					UpdatedAt: time.Now(),
				}

				// Check if there's a soft deleted active version
				var existingActiveVersion ActiveVersion
				if err := tx.Unscoped().Where("tenant = ? AND name = ?", server.Tenant, server.Name).First(&existingActiveVersion).Error; err == nil {
					// If found and soft deleted, restore it and update content
					if existingActiveVersion.DeletedAt.Valid {
						activeVersion.ID = existingActiveVersion.ID
						if err := tx.Model(&existingActiveVersion).Unscoped().Updates(map[string]interface{}{
							"deleted_at": nil,
							"version":    activeVersion.Version,
							"updated_at": activeVersion.UpdatedAt,
						}).Error; err != nil {
							return err
						}
					} else {
						// If found and not deleted, update it
						if err := tx.Model(&existingActiveVersion).Updates(map[string]interface{}{
							"version":    activeVersion.Version,
							"updated_at": activeVersion.UpdatedAt,
						}).Error; err != nil {
							return err
						}
					}
				} else if !errors.Is(err, gorm.ErrRecordNotFound) {
					// If error is not "record not found", return it
					return err
				} else {
					// If not found, create new record
					if err := tx.Create(activeVersion).Error; err != nil {
						return err
					}
				}
			} else {
				// If found and not deleted, return error
				return fmt.Errorf("record already exists")
			}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			// If error is not "record not found", return it
			return err
		} else {
			// If not found, create new record
			if err := tx.Create(model).Error; err != nil {
				return err
			}

			// Create version record for new record
			version, err := FromMCPConfigVersion(server, 1, "system", cnst.ActionCreate)
			if err != nil {
				return err
			}

			if err := tx.Create(version).Error; err != nil {
				return err
			}

			// Create active version record for new record
			activeVersion := &ActiveVersion{
				Name:      server.Name,
				Tenant:    server.Tenant,
				Version:   1,
				UpdatedAt: time.Now(),
			}

			if err := tx.Create(activeVersion).Error; err != nil {
				return err
			}
		}

		return nil
	})
}

// Get implements Store.Get
func (s *DBStore) Get(_ context.Context, tenant, name string, includeDeleted ...bool) (*config.MCPConfig, error) {
	var model MCPConfig
	query := s.db
	if len(includeDeleted) > 0 && includeDeleted[0] {
		query = query.Unscoped()
	}
	err := query.Where("tenant = ? AND name = ?", tenant, name).First(&model).Error
	if err != nil {
		return nil, err
	}
	return model.ToMCPConfig()
}

// List implements Store.List
func (s *DBStore) List(_ context.Context, includeDeleted ...bool) ([]*config.MCPConfig, error) {
	var models []MCPConfig
	query := s.db
	if len(includeDeleted) > 0 && includeDeleted[0] {
		query = query.Unscoped()
	}
	err := query.Find(&models).Error
	if err != nil {
		return nil, err
	}

	configs := make([]*config.MCPConfig, len(models))
	for i, model := range models {
		cfg, err := model.ToMCPConfig()
		if err != nil {
			return nil, err
		}
		configs[i] = cfg
	}
	return configs, nil
}

// Update implements Store.Update
func (s *DBStore) Update(ctx context.Context, server *config.MCPConfig) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		model, err := FromMCPConfig(server)
		if err != nil {
			return err
		}

		// Update the main record
		if err := tx.Model(&MCPConfig{}).Where("tenant = ? AND name = ?", server.Tenant, server.Name).Updates(model).Error; err != nil {
			return err
		}

		// Get the latest version
		var latestVersion MCPConfigVersion
		if err := tx.Where("name = ?", server.Name).Order("version DESC").First(&latestVersion).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		// Calculate hash for current config
		version, err := FromMCPConfigVersion(server, latestVersion.Version+1, "system", cnst.ActionUpdate)
		if err != nil {
			return err
		}

		// If there's a latest version and its hash matches the current config's hash, skip creating new version
		if latestVersion.Version > 0 && latestVersion.Hash == version.Hash {
			s.logger.Info("Skipping version creation as content hash matches latest version",
				zap.String("name", server.Name),
				zap.Int("version", latestVersion.Version),
				zap.String("hash", version.Hash))
			return nil
		}

		// Create new version
		if err := tx.Create(version).Error; err != nil {
			return err
		}

		// Update active version
		activeVersion := &ActiveVersion{
			Name:      server.Name,
			Tenant:    server.Tenant,
			Version:   version.Version,
			UpdatedAt: time.Now(),
		}

		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant"}, {Name: "name"}},
			DoUpdates: clause.AssignmentColumns([]string{"version", "updated_at"}),
		}).Create(activeVersion).Error; err != nil {
			return err
		}

		// Delete old versions if revision history limit is set
		if s.cfg.RevisionHistoryLimit > 0 {
			var versionsToDelete []MCPConfigVersion
			if err := tx.Where("tenant = ? AND name = ?", server.Tenant, server.Name).
				Order("version DESC").
				Offset(s.cfg.RevisionHistoryLimit).
				Limit(1_000).
				Find(&versionsToDelete).Error; err != nil {
				return err
			}

			for _, v := range versionsToDelete {
				if err := tx.Delete(&v).Error; err != nil {
					return err
				}
			}
		}

		return nil
	})
}

// Delete implements Store.Delete
func (s *DBStore) Delete(ctx context.Context, tenant, name string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// Get the config before deletion to create version record
		var model MCPConfig
		if err := tx.Where("tenant = ? AND name = ?", tenant, name).First(&model).Error; err != nil {
			return err
		}

		// Get the latest version number
		var latestVersion int
		if err := tx.Model(&MCPConfigVersion{}).
			Where("tenant = ? AND name = ?", tenant, name).
			Select("COALESCE(MAX(version), 0)").
			Scan(&latestVersion).Error; err != nil {
			return err
		}

		// Create version record for deletion
		mcpConfig, err := model.ToMCPConfig()
		if err != nil {
			return err
		}
		version, err := FromMCPConfigVersion(mcpConfig, latestVersion+1, "system", cnst.ActionDelete)
		if err != nil {
			return err
		}

		if err := tx.Create(version).Error; err != nil {
			return err
		}

		// Update active version to the delete action version
		activeVersion := &ActiveVersion{
			Name:      name,
			Tenant:    tenant,
			Version:   version.Version,
			UpdatedAt: time.Now(),
		}

		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant"}, {Name: "name"}},
			DoUpdates: clause.AssignmentColumns([]string{"version", "updated_at"}),
		}).Create(activeVersion).Error; err != nil {
			return err
		}

		// Soft delete the active version
		if err := tx.Where("tenant = ? AND name = ?", tenant, name).Delete(&ActiveVersion{}).Error; err != nil {
			return err
		}

		// Soft delete the main record
		if err := tx.Where("tenant = ? AND name = ?", tenant, name).Delete(&MCPConfig{}).Error; err != nil {
			return err
		}

		return nil
	})
}

// GetVersion gets a specific version of the configuration
func (s *DBStore) GetVersion(ctx context.Context, tenant, name string, version int) (*config.MCPConfigVersion, error) {
	var versionModel MCPConfigVersion
	if err := s.db.Where("tenant = ? AND name = ? AND version = ?", tenant, name, version).First(&versionModel).Error; err != nil {
		return nil, err
	}
	return versionModel.ToConfigVersion(), nil
}

// ListVersions lists all versions of a configuration
func (s *DBStore) ListVersions(ctx context.Context, tenant, name string) ([]*config.MCPConfigVersion, error) {
	var versions []MCPConfigVersion
	err := s.db.Model(&MCPConfigVersion{}).Where("tenant = ? AND name = ?", tenant, name).Order("version DESC").Find(&versions).Error
	if err != nil {
		return nil, err
	}

	// Get active versions
	var activeVersions []ActiveVersion
	if err := s.db.Where("name = ?", name).Find(&activeVersions).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// Create a map of active versions for quick lookup
	activeVersionMap := make(map[string]int)
	for _, av := range activeVersions {
		activeVersionMap[av.Name] = av.Version
	}

	result := make([]*config.MCPConfigVersion, len(versions))
	for i, v := range versions {
		result[i] = &config.MCPConfigVersion{
			Version:    v.Version,
			CreatedBy:  v.CreatedBy,
			CreatedAt:  v.CreatedAt,
			ActionType: v.ActionType,
			Name:       v.Name,
			Tenant:     v.Tenant,
			Routers:    v.Routers,
			Servers:    v.Servers,
			Tools:      v.Tools,
			Prompts:    v.Prompts,
			McpServers: v.McpServers,
			IsActive:   v.Version == activeVersionMap[v.Name],
			Hash:       v.Hash,
		}
	}
	return result, nil
}

// DeleteVersion deletes a specific version
func (s *DBStore) DeleteVersion(ctx context.Context, tenant, name string, version int) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// Check if this is the active version
		var activeVersion ActiveVersion
		if err := tx.Where("tenant = ? AND name = ? AND version = ?", tenant, name, version).First(&activeVersion).Error; err == nil {
			return fmt.Errorf("cannot delete active version")
		}

		// Delete the version
		if err := tx.Where("tenant = ? AND name = ? AND version = ?", tenant, name, version).Delete(&MCPConfigVersion{}).Error; err != nil {
			return err
		}

		return nil
	})
}

// SetActiveVersion sets a specific version as the active version
func (s *DBStore) SetActiveVersion(ctx context.Context, tenant, name string, version int) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// Check if the version exists
		var versionModel MCPConfigVersion
		if err := tx.Unscoped().Where("tenant = ? AND name = ? AND version = ?", tenant, name, version).First(&versionModel).Error; err != nil {
			return fmt.Errorf("version %d not found: %w", version, err)
		}

		// Get the latest version number
		var latestVersion int
		if err := tx.Model(&MCPConfigVersion{}).
			Where("tenant = ? AND name = ?", tenant, name).
			Select("COALESCE(MAX(version), 0)").
			Scan(&latestVersion).Error; err != nil {
			return err
		}

		// Create new version record for revert action
		newVersion := &MCPConfigVersion{
			Name:       versionModel.Name,
			Tenant:     versionModel.Tenant,
			Version:    latestVersion + 1,
			ActionType: cnst.ActionRevert,
			CreatedBy:  "system",
			CreatedAt:  time.Now(),
			Routers:    versionModel.Routers,
			Servers:    versionModel.Servers,
			Tools:      versionModel.Tools,
			Prompts:    versionModel.Prompts,
			McpServers: versionModel.McpServers,
			Hash:       versionModel.Hash,
		}

		if err := tx.Create(newVersion).Error; err != nil {
			return err
		}

		// Update MCPConfig table with the target version's configuration
		mcpConfig := &MCPConfig{
			Name:       versionModel.Name,
			Tenant:     versionModel.Tenant,
			UpdatedAt:  time.Now(),
			Routers:    versionModel.Routers,
			Servers:    versionModel.Servers,
			Tools:      versionModel.Tools,
			Prompts:    versionModel.Prompts,
			McpServers: versionModel.McpServers,
		}

		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "name"}, {Name: "tenant"}},
			DoUpdates: clause.AssignmentColumns([]string{"updated_at", "routers", "servers", "tools", "prompts", "mcp_servers", "deleted_at"}),
		}).Create(mcpConfig).Error; err != nil {
			return err
		}

		// Update or create active version
		activeVersion := &ActiveVersion{
			Name:      name,
			Tenant:    tenant,
			Version:   newVersion.Version,
			UpdatedAt: time.Now(),
		}

		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant"}, {Name: "name"}},
			DoUpdates: clause.AssignmentColumns([]string{"version", "updated_at"}),
		}).Create(activeVersion).Error; err != nil {
			return err
		}

		return nil
	})
}

// ListUpdated implements Store.ListUpdated
func (s *DBStore) ListUpdated(_ context.Context, since time.Time) ([]*config.MCPConfig, error) {
	// Get versions updated since the given time
	var versions []MCPConfigVersion
	err := s.db.Model(&MCPConfigVersion{}).
		Where("created_at > ?", since).
		Order("created_at ASC").
		Find(&versions).Error
	if err != nil {
		return nil, err
	}

	// Convert versions to configs
	configs := make([]*config.MCPConfig, 0, len(versions))
	for _, version := range versions {
		cfg, err := version.ToMCPConfig()
		if err != nil {
			return nil, err
		}

		// For delete action, set deleted_at to created_at
		if version.ActionType == cnst.ActionDelete {
			cfg.DeletedAt = version.CreatedAt
		}

		configs = append(configs, cfg)
	}

	return configs, nil
}
