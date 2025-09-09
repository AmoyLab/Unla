package database

import "time"

// Session represents a chat session
type Session struct {
	ID        string    `json:"id" gorm:"column:id;type:varchar(64);uniqueIndex"`
	CreatedAt time.Time `json:"createdAt" gorm:"column:created_at"`
	Title     string    `json:"title" gorm:"column:title;type:varchar(255)"`
}

// Message represents a chat message
type Message struct {
	ID               string    `json:"id" gorm:"column:id;type:varchar(64);uniqueIndex"`
	SessionID        string    `json:"session_id" gorm:"column:session_id;type:varchar(64);index"`
	Content          string    `json:"content" gorm:"column:content;type:text"`
	ReasoningContent string    `json:"reasoning_content,omitempty" gorm:"column:reasoning_content;type:text"`
	Sender           string    `json:"sender" gorm:"column:sender;type:varchar(50)"`
	Timestamp        time.Time `json:"timestamp" gorm:"column:timestamp;index"`
	ToolCalls        string    `json:"toolCalls,omitempty" gorm:"column:tool_calls;type:text"`
	ToolResult       string    `json:"toolResult,omitempty" gorm:"column:tool_result;type:text"`
}

// UserRole represents the role of a user
type UserRole string

const (
	RoleAdmin  UserRole = "admin"
	RoleNormal UserRole = "normal"
)

// User represents an admin user
type User struct {
	ID        uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	Username  string    `json:"username" gorm:"type:varchar(50);uniqueIndex"`
	Password  string    `json:"-" gorm:"not null"` // Password is not exposed in JSON
	Role      UserRole  `json:"role" gorm:"not null;default:'normal'"`
	IsActive  bool      `json:"isActive" gorm:"not null;default:true"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Tenant represents a tenant in the system
type Tenant struct {
	ID          uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	Name        string    `json:"name" gorm:"type:varchar(50);uniqueIndex"`
	Prefix      string    `json:"prefix" gorm:"type:varchar(50);uniqueIndex"`
	Description string    `json:"description" gorm:"type:varchar(255)"`
	IsActive    bool      `json:"isActive" gorm:"not null;default:true"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// UserTenant represents the relationship between a user and a tenant
type UserTenant struct {
	ID        uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID    uint      `json:"userId" gorm:"index:idx_user_tenant,unique;not null"`
	TenantID  uint      `json:"tenantId" gorm:"index:idx_user_tenant,unique;not null"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// SystemPrompt stores a user's system prompt
// UserID is a foreign key to User.ID and is the primary key
// Prompt is the text of the system prompt
// UpdatedAt is the last update time
// TableName: system_prompts
type SystemPrompt struct {
	UserID    uint      `json:"userId" gorm:"primaryKey;index;not null"`
	Prompt    string    `json:"prompt" gorm:"type:text;not null"`
	UpdatedAt time.Time `json:"updatedAt"`
}
