package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"
)

// MCPConfig represents the database model for MCPConfig
type MCPConfig struct {
	ID         int64          `gorm:"primaryKey;autoIncrement"`
	Name       string         `gorm:"column:name; type:varchar(50); uniqueIndex:idx_name_tenant,priority:2"`
	Tenant     string         `gorm:"column:tenant; type:varchar(50); default:''; uniqueIndex:idx_name_tenant,priority:1"`
	CreatedAt  time.Time      `gorm:"column:created_at;"`
	UpdatedAt  time.Time      `gorm:"column:updated_at;"`
	Routers    string         `gorm:"type:text; column:routers"`
	Servers    string         `gorm:"type:text; column:servers"`
	Tools      string         `gorm:"type:text; column:tools"`
	Prompts    string         `gorm:"type:text; column:prompts"`
	McpServers string         `gorm:"type:text; column:mcp_servers"`
	DeletedAt  gorm.DeletedAt `gorm:"index"`
}

// ToMCPConfig converts the database model to MCPConfig
func (m *MCPConfig) ToMCPConfig() (*config.MCPConfig, error) {
	cfg := &config.MCPConfig{
		Name:      m.Name,
		Tenant:    m.Tenant,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}

	wrapError := func(context string, err error) error {
		return fmt.Errorf("failed to unmarshal MCP configuration '%s' (tenant: '%s'): %w", m.Name, m.Tenant, err)
	}
	if len(m.Routers) > 0 {
		if err := json.Unmarshal([]byte(m.Routers), &cfg.Routers); err != nil {
			return nil, wrapError("Routers", err)
		}
	}
	if len(m.Servers) > 0 {
		if err := json.Unmarshal([]byte(m.Servers), &cfg.Servers); err != nil {
			return nil, wrapError("Servers", err)
		}
	}
	if len(m.Tools) > 0 {
		if err := json.Unmarshal([]byte(m.Tools), &cfg.Tools); err != nil {
			return nil, wrapError("Tools", err)
		}
	}
	if len(m.Prompts) > 0 {
		if err := json.Unmarshal([]byte(m.Prompts), &cfg.Prompts); err != nil {
			return nil, wrapError("Prompts", err)
		}
	}
	if len(m.McpServers) > 0 {
		if err := json.Unmarshal([]byte(m.McpServers), &cfg.McpServers); err != nil {
			return nil, wrapError("McpServers", err)
		}
	}

	return cfg, nil
}

// FromMCPConfig converts MCPConfig to database model
func FromMCPConfig(cfg *config.MCPConfig) (*MCPConfig, error) {
	routers, err := json.Marshal(cfg.Routers)
	if err != nil {
		return nil, err
	}

	servers, err := json.Marshal(cfg.Servers)
	if err != nil {
		return nil, err
	}

	tools, err := json.Marshal(cfg.Tools)
	if err != nil {
		return nil, err
	}

	prompts, err := json.Marshal(cfg.Prompts)
	if err != nil {
		return nil, err
	}

	mcpServers, err := json.Marshal(cfg.McpServers)
	if err != nil {
		return nil, err
	}

	return &MCPConfig{
		Name:       cfg.Name,
		Tenant:     cfg.Tenant,
		CreatedAt:  cfg.CreatedAt,
		UpdatedAt:  cfg.UpdatedAt,
		Routers:    string(routers),
		Servers:    string(servers),
		Tools:      string(tools),
		Prompts:    string(prompts),
		McpServers: string(mcpServers),
	}, nil
}

// BeforeCreate is a GORM hook that sets timestamps
func (m *MCPConfig) BeforeCreate(_ *gorm.DB) error {
	now := time.Now()
	if m.CreatedAt.IsZero() {
		m.CreatedAt = now
	}
	if m.UpdatedAt.IsZero() {
		m.UpdatedAt = now
	}
	return nil
}

// BeforeUpdate is a GORM hook that updates the UpdatedAt timestamp
func (m *MCPConfig) BeforeUpdate(_ *gorm.DB) error {
	m.UpdatedAt = time.Now()
	return nil
}

// ActiveVersion represents the currently active version of an MCP configuration
type ActiveVersion struct {
	ID        uint           `gorm:"primarykey"`
	Tenant    string         `gorm:"type:varchar(50);not null;uniqueIndex:idx_tenant_name,priority:1"`
	Name      string         `gorm:"type:varchar(50);not null;uniqueIndex:idx_tenant_name,priority:2"`
	Version   int            `gorm:"not null"`
	UpdatedAt time.Time      `gorm:"not null"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

// MCPConfigVersion represents the database model for MCPConfigVersion
type MCPConfigVersion struct {
	ID         int64           `gorm:"primaryKey;autoIncrement"`
	Name       string          `gorm:"column:name;type:varchar(50);index:idx_name_tenant_version,uniqueIndex"`
	Tenant     string          `gorm:"column:tenant;type:varchar(50);index:idx_name_tenant_version,uniqueIndex"`
	Version    int             `gorm:"column:version;index:idx_name_tenant_version,uniqueIndex"`
	ActionType cnst.ActionType `gorm:"column:action_type;not null"` // Create, Update, Delete, Revert
	CreatedBy  string          `gorm:"column:created_by"`
	CreatedAt  time.Time       `gorm:"column:created_at;"`
	Routers    string          `gorm:"type:text;column:routers"`
	Servers    string          `gorm:"type:text;column:servers"`
	Tools      string          `gorm:"type:text;column:tools"`
	Prompts    string          `gorm:"type:text; column:prompts"`
	McpServers string          `gorm:"type:text;column:mcp_servers"`
	Hash       string          `gorm:"column:hash;not null"` // hash of the configuration content
	DeletedAt  gorm.DeletedAt  `gorm:"index"`
}

// ToMCPConfig converts the database model to MCPConfig
func (m *MCPConfigVersion) ToMCPConfig() (*config.MCPConfig, error) {
	cfg := &config.MCPConfig{
		Name:      m.Name,
		Tenant:    m.Tenant,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.CreatedAt, // Use CreatedAt as UpdatedAt for versioned configs
	}

	if len(m.Routers) > 0 {
		if err := json.Unmarshal([]byte(m.Routers), &cfg.Routers); err != nil {
			return nil, err
		}
	}
	if len(m.Servers) > 0 {
		if err := json.Unmarshal([]byte(m.Servers), &cfg.Servers); err != nil {
			return nil, err
		}
	}
	if len(m.Tools) > 0 {
		if err := json.Unmarshal([]byte(m.Tools), &cfg.Tools); err != nil {
			return nil, err
		}
	}
	if len(m.Prompts) > 0 {
		if err := json.Unmarshal([]byte(m.Prompts), &cfg.Prompts); err != nil {
			return nil, err
		}
	}
	if len(m.McpServers) > 0 {
		if err := json.Unmarshal([]byte(m.McpServers), &cfg.McpServers); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// FromMCPConfigVersion converts MCPConfig to database model
func FromMCPConfigVersion(cfg *config.MCPConfig, version int, createdBy string, actionType cnst.ActionType) (*MCPConfigVersion, error) {
	// Initialize empty slices if nil
	if cfg.Routers == nil {
		cfg.Routers = []config.RouterConfig{}
	}
	if cfg.Servers == nil {
		cfg.Servers = []config.ServerConfig{}
	}
	if cfg.Tools == nil {
		cfg.Tools = []config.ToolConfig{}
	}
	if cfg.Prompts == nil {
		cfg.Prompts = []config.PromptConfig{}
	}
	if cfg.McpServers == nil {
		cfg.McpServers = []config.MCPServerConfig{}
	}

	routers, err := json.Marshal(cfg.Routers)
	if err != nil {
		return nil, err
	}

	servers, err := json.Marshal(cfg.Servers)
	if err != nil {
		return nil, err
	}

	tools, err := json.Marshal(cfg.Tools)
	if err != nil {
		return nil, err
	}

	prompts, err := json.Marshal(cfg.Prompts)
	if err != nil {
		return nil, err
	}

	mcpServers, err := json.Marshal(cfg.McpServers)
	if err != nil {
		return nil, err
	}

	// Calculate hash of the configuration content
	content := fmt.Sprintf("%s%s%s%s%s", routers, servers, tools, prompts, mcpServers)
	hash := sha256.Sum256([]byte(content))

	return &MCPConfigVersion{
		Name:       cfg.Name,
		Tenant:     cfg.Tenant,
		Version:    version,
		ActionType: actionType,
		CreatedBy:  createdBy,
		CreatedAt:  time.Now(),
		Routers:    string(routers),
		Servers:    string(servers),
		Tools:      string(tools),
		Prompts:    string(prompts),
		McpServers: string(mcpServers),
		Hash:       hex.EncodeToString(hash[:]),
	}, nil
}

func (m *MCPConfigVersion) ToConfigVersion() *config.MCPConfigVersion {
	return &config.MCPConfigVersion{
		Version:    m.Version,
		CreatedBy:  m.CreatedBy,
		CreatedAt:  m.CreatedAt,
		ActionType: m.ActionType,
		Name:       m.Name,
		Tenant:     m.Tenant,
		Routers:    m.Routers,
		Servers:    m.Servers,
		Tools:      m.Tools,
		Prompts:    m.Prompts,
		McpServers: m.McpServers,
		Hash:       m.Hash,
	}
}
