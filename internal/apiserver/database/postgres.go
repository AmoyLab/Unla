package database

import (
	"context"
	"fmt"
	"time"

	"github.com/amoylab/unla/internal/common/config"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Postgres implements the Database interface using PostgreSQL
type Postgres struct {
	db  *gorm.DB
	cfg *config.DatabaseConfig
}

// NewPostgres creates a new Postgres instance
func NewPostgres(cfg *config.DatabaseConfig) (Database, error) {
	db := &Postgres{
		cfg: cfg,
	}

	gormDB, err := gorm.Open(postgres.Open(db.cfg.GetDSN()), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Add SystemPrompt and MCPToolStatus to migrations
	if err := gormDB.AutoMigrate(&Message{}, &Session{}, &User{}, &Tenant{}, &UserTenant{}, &SystemPrompt{}, &MCPToolStatus{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	db.db = gormDB

	if err := InitDefaultTenant(gormDB); err != nil {
		return nil, fmt.Errorf("failed to initialize default tenant: %w", err)
	}

	return db, nil
}

// Close closes the database connection
func (db *Postgres) Close() error {
	sqlDB, err := db.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// SaveMessage saves a message to the database
func (db *Postgres) SaveMessage(ctx context.Context, message *Message) error {
	return db.db.WithContext(ctx).Create(message).Error
}

// GetMessages retrieves all messages for a session
func (db *Postgres) GetMessages(ctx context.Context, sessionID string) ([]*Message, error) {
	var messages []*Message
	err := db.db.WithContext(ctx).
		Where("session_id = ?", sessionID).
		Order("timestamp asc").
		Find(&messages).Error
	return messages, err
}

// GetMessagesWithPagination retrieves messages for a specific session with pagination
func (db *Postgres) GetMessagesWithPagination(ctx context.Context, sessionID string, page, pageSize int) ([]*Message, error) {
	var messages []*Message
	offset := (page - 1) * pageSize
	err := db.db.WithContext(ctx).
		Where("session_id = ?", sessionID).
		Order("timestamp asc").
		Offset(offset).
		Limit(pageSize).
		Find(&messages).Error
	return messages, err
}

// CreateSession creates a new session with the given sessionId
func (db *Postgres) CreateSession(ctx context.Context, sessionId string) error {
	session := &Session{
		ID:        sessionId,
		CreatedAt: time.Now(),
	}
	return db.db.WithContext(ctx).Create(session).Error
}

// CreateSessionWithTitle creates a new session with the given sessionId and title
func (db *Postgres) CreateSessionWithTitle(ctx context.Context, sessionId string, title string) error {
	session := &Session{
		ID:        sessionId,
		CreatedAt: time.Now(),
		Title:     title,
	}
	return db.db.WithContext(ctx).Create(session).Error
}

// UpdateSessionTitle updates the title of a session
func (db *Postgres) UpdateSessionTitle(ctx context.Context, sessionID string, title string) error {
	return db.db.WithContext(ctx).
		Model(&Session{}).
		Where("id = ?", sessionID).
		Update("title", title).Error
}

// SessionExists checks if a session exists
func (db *Postgres) SessionExists(ctx context.Context, sessionID string) (bool, error) {
	var count int64
	err := db.db.WithContext(ctx).
		Model(&Session{}).
		Where("id = ?", sessionID).
		Count(&count).Error
	return count > 0, err
}

// GetSessions retrieves all chat sessions with their latest message
func (db *Postgres) GetSessions(ctx context.Context) ([]*Session, error) {
	var sessions []*Session
	err := db.db.WithContext(ctx).
		Order("created_at desc").
		Find(&sessions).Error
	return sessions, err
}

// DeleteSession deletes a session by ID
func (db *Postgres) DeleteSession(ctx context.Context, sessionID string) error {
	return db.db.WithContext(ctx).
		Where("id = ?", sessionID).
		Delete(&Session{}).Error
}

// CreateUser creates a new user
func (db *Postgres) CreateUser(ctx context.Context, user *User) error {
	return db.db.WithContext(ctx).Create(user).Error
}

// GetUserByUsername retrieves a user by username
func (db *Postgres) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	err := db.db.WithContext(ctx).
		Where("username = ?", username).
		First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateUser updates an existing user
func (db *Postgres) UpdateUser(ctx context.Context, user *User) error {
	return db.db.WithContext(ctx).Save(user).Error
}

// DeleteUser deletes a user by ID
func (db *Postgres) DeleteUser(ctx context.Context, id uint) error {
	return db.db.WithContext(ctx).Delete(&User{}, "id = ?", id).Error
}

// ListUsers retrieves all users
func (db *Postgres) ListUsers(ctx context.Context) ([]*User, error) {
	var users []*User
	err := db.db.WithContext(ctx).
		Order("created_at desc").
		Find(&users).Error
	return users, err
}

// CreateTenant creates a new tenant
func (db *Postgres) CreateTenant(ctx context.Context, tenant *Tenant) error {
	return db.db.WithContext(ctx).Create(tenant).Error
}

// GetTenantByName retrieves a tenant by name
func (db *Postgres) GetTenantByName(ctx context.Context, name string) (*Tenant, error) {
	var tenant Tenant
	err := db.db.WithContext(ctx).
		Where("name = ?", name).
		First(&tenant).Error
	if err != nil {
		return nil, err
	}
	return &tenant, nil
}

// GetTenantByID retrieves a tenant by ID
func (db *Postgres) GetTenantByID(ctx context.Context, id uint) (*Tenant, error) {
	var tenant Tenant
	err := db.db.WithContext(ctx).
		Where("id = ?", id).
		First(&tenant).Error
	if err != nil {
		return nil, err
	}
	return &tenant, nil
}

// UpdateTenant updates an existing tenant
func (db *Postgres) UpdateTenant(ctx context.Context, tenant *Tenant) error {
	return db.db.WithContext(ctx).Save(tenant).Error
}

// DeleteTenant deletes a tenant by ID
func (db *Postgres) DeleteTenant(ctx context.Context, id uint) error {
	return db.db.WithContext(ctx).Delete(&Tenant{}, "id = ?", id).Error
}

// ListTenants retrieves all tenants
func (db *Postgres) ListTenants(ctx context.Context) ([]*Tenant, error) {
	var tenants []*Tenant
	err := db.db.WithContext(ctx).
		Order("created_at desc").
		Find(&tenants).Error
	return tenants, err
}

// Transaction implements Database.Transaction
func (db *Postgres) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if tx := TransactionFromContext(ctx); tx != nil {
		return fn(ctx)
	}

	return db.db.Transaction(func(tx *gorm.DB) error {
		txCtx := ContextWithTransaction(ctx, tx)
		return fn(txCtx)
	})
}

// AddUserToTenant adds a user to a tenant
func (db *Postgres) AddUserToTenant(ctx context.Context, userID, tenantID uint) error {
	dbSession := getDBFromContext(ctx, db.db)

	userTenant := &UserTenant{
		UserID:    userID,
		TenantID:  tenantID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return dbSession.Create(userTenant).Error
}

// RemoveUserFromTenant removes a user from a tenant
func (db *Postgres) RemoveUserFromTenant(ctx context.Context, userID, tenantID uint) error {
	dbSession := getDBFromContext(ctx, db.db)

	return dbSession.Where("user_id = ? AND tenant_id = ?", userID, tenantID).Delete(&UserTenant{}).Error
}

// GetUserTenants gets all tenants for a user
func (db *Postgres) GetUserTenants(ctx context.Context, userID uint) ([]*Tenant, error) {
	dbSession := getDBFromContext(ctx, db.db)

	var tenants []*Tenant
	err := dbSession.Model(&UserTenant{}).
		Select("tenants.*").
		Joins("JOIN tenants ON user_tenants.tenant_id = tenants.id").
		Where("user_tenants.user_id = ?", userID).
		Find(&tenants).Error

	return tenants, err
}

// GetTenantUsers gets all users for a tenant
func (db *Postgres) GetTenantUsers(ctx context.Context, tenantID uint) ([]*User, error) {
	dbSession := getDBFromContext(ctx, db.db)

	var users []*User
	err := dbSession.Model(&UserTenant{}).
		Select("users.*").
		Joins("JOIN users ON user_tenants.user_id = users.id").
		Where("user_tenants.tenant_id = ?", tenantID).
		Find(&users).Error

	return users, err
}

// DeleteUserTenants deletes all tenant associations for a user
func (db *Postgres) DeleteUserTenants(ctx context.Context, userID uint) error {
	dbSession := getDBFromContext(ctx, db.db)

	return dbSession.Where("user_id = ?", userID).Delete(&UserTenant{}).Error
}

// --- SystemPrompt persistent methods ---

func (db *Postgres) GetSystemPrompt(ctx context.Context, userID uint) (string, error) {
	var sp SystemPrompt
	err := db.db.WithContext(ctx).Where("user_id = ?", userID).First(&sp).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", nil // No prompt set yet
		}
		return "", err
	}
	return sp.Prompt, nil
}

func (db *Postgres) SaveSystemPrompt(ctx context.Context, userID uint, prompt string) error {
	var sp SystemPrompt
	err := db.db.WithContext(ctx).Where("user_id = ?", userID).First(&sp).Error
	now := time.Now()
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			sp = SystemPrompt{UserID: userID, Prompt: prompt, UpdatedAt: now}
			return db.db.WithContext(ctx).Create(&sp).Error
		}
		return err
	}
	sp.Prompt = prompt
	sp.UpdatedAt = now
	return db.db.WithContext(ctx).Save(&sp).Error
}

// GetToolStatus gets the status of a specific tool
func (db *Postgres) GetToolStatus(ctx context.Context, tenant, server, toolName string) (*MCPToolStatus, error) {
	var status MCPToolStatus
	err := db.db.WithContext(ctx).
		Where("tenant = ? AND server = ? AND tool_name = ?", tenant, server, toolName).
		First(&status).Error
	if err != nil {
		return nil, err
	}
	return &status, nil
}

// SetToolStatus sets the enabled/disabled status of a tool
func (db *Postgres) SetToolStatus(ctx context.Context, tenant, server, toolName string, enabled bool) error {
	var status MCPToolStatus
	err := db.db.WithContext(ctx).
		Where("tenant = ? AND server = ? AND tool_name = ?", tenant, server, toolName).
		First(&status).Error
	
	now := time.Now()
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// Create new record
			status = MCPToolStatus{
				Tenant:    tenant,
				Server:    server,
				ToolName:  toolName,
				Enabled:   enabled,
				CreatedAt: now,
				UpdatedAt: now,
			}
			return db.db.WithContext(ctx).Create(&status).Error
		}
		return err
	}
	
	// Update existing record
	status.Enabled = enabled
	status.UpdatedAt = now
	return db.db.WithContext(ctx).Save(&status).Error
}

// GetToolStatuses gets all tool statuses for a specific server
func (db *Postgres) GetToolStatuses(ctx context.Context, tenant, server string) ([]*MCPToolStatus, error) {
	var statuses []*MCPToolStatus
	err := db.db.WithContext(ctx).
		Where("tenant = ? AND server = ?", tenant, server).
		Find(&statuses).Error
	return statuses, err
}