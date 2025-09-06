package database

import (
	"context"
)

// Database defines the methods for database operations.
type Database interface {
	// Close closes the database connection.
	Close() error

	// SaveMessage saves a message to the database.
	SaveMessage(ctx context.Context, message *Message) error
	// GetMessages gets messages for a specific session.
	GetMessages(ctx context.Context, sessionID string) ([]*Message, error)
	// GetMessagesWithPagination gets messages for a specific session with pagination.
	GetMessagesWithPagination(ctx context.Context, sessionID string, page, pageSize int) ([]*Message, error)
	// CreateSession creates a new session with the given sessionId.
	CreateSession(ctx context.Context, sessionId string) error
	// CreateSessionWithTitle creates a new session with the given sessionId and title.
	CreateSessionWithTitle(ctx context.Context, sessionId string, title string) error
	// SessionExists checks if a session exists.
	SessionExists(ctx context.Context, sessionID string) (bool, error)
	// GetSessions gets all chat sessions with their latest message.
	GetSessions(ctx context.Context) ([]*Session, error)
	// UpdateSessionTitle updates the title of a session.
	UpdateSessionTitle(ctx context.Context, sessionID string, title string) error
	// DeleteSession deletes a session by ID.
	DeleteSession(ctx context.Context, sessionID string) error

	CreateUser(ctx context.Context, user *User) error
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id uint) error
	ListUsers(ctx context.Context) ([]*User, error)

	CreateTenant(ctx context.Context, tenant *Tenant) error
	GetTenantByName(ctx context.Context, name string) (*Tenant, error)
	GetTenantByID(ctx context.Context, id uint) (*Tenant, error)
	UpdateTenant(ctx context.Context, tenant *Tenant) error
	DeleteTenant(ctx context.Context, id uint) error
	ListTenants(ctx context.Context) ([]*Tenant, error)

	AddUserToTenant(ctx context.Context, userID, tenantID uint) error
	RemoveUserFromTenant(ctx context.Context, userID, tenantID uint) error
	GetUserTenants(ctx context.Context, userID uint) ([]*Tenant, error)
	GetTenantUsers(ctx context.Context, tenantID uint) ([]*User, error)
	DeleteUserTenants(ctx context.Context, userID uint) error

	Transaction(ctx context.Context, fn func(ctx context.Context) error) error

	// System prompt methods
	GetSystemPrompt(ctx context.Context, userID uint) (string, error)
	SaveSystemPrompt(ctx context.Context, userID uint, prompt string) error

	// MCP tool status methods
	GetToolStatus(ctx context.Context, tenant, server, toolName string) (*MCPToolStatus, error)
	SetToolStatus(ctx context.Context, tenant, server, toolName string, enabled bool) error
	GetToolStatuses(ctx context.Context, tenant, server string) ([]*MCPToolStatus, error)
}
