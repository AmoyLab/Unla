package database

import (
	"context"
	"strings"
	"time"

	"gorm.io/gorm"
)

// InitDefaultTenant initializes the default tenant if it doesn't exist
func InitDefaultTenant(db *gorm.DB) error {
	ctx := context.Background()

	// Check if default tenant already exists
	var count int64
	if err := db.Model(&Tenant{}).Where("name = ?", "default").Count(&count).Error; err != nil {
		return err
	}

	if count > 0 {
		// Default tenant already exists
		return nil
	}

	// Create default tenant
	defaultTenant := &Tenant{
		Name:        "default",
		Prefix:      "/gateway",
		Description: "Default tenant for MCP Gateway",
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := db.WithContext(ctx).Create(defaultTenant).Error; err != nil {
		return err
	}

	// Find all admin users
	var adminUsers []*User
	if err := db.WithContext(ctx).Where("role = ?", RoleAdmin).Find(&adminUsers).Error; err != nil {
		return err
	}

	// Grant admin users access to the default tenant
	for _, user := range adminUsers {
		userTenant := &UserTenant{
			UserID:    user.ID,
			TenantID:  defaultTenant.ID,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		// Ignore duplicate key errors
		if err := db.WithContext(ctx).Create(userTenant).Error; err != nil {
			if !strings.Contains(err.Error(), "duplicate key") && !strings.Contains(err.Error(), "unique constraint") {
				return err
			}
		}
	}

	return nil
}
