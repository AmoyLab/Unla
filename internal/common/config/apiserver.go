package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type (
	APIServerConfig struct {
		Database   DatabaseConfig   `yaml:"database"`
		Storage    StorageConfig    `yaml:"storage"`
		Notifier   NotifierConfig   `yaml:"notifier"`
		Logger     LoggerConfig     `yaml:"logger"`
		JWT        JWTConfig        `yaml:"jwt"`
		SuperAdmin SuperAdminConfig `yaml:"super_admin"`
		I18n       I18nConfig       `yaml:"i18n"`
		Web        WebConfig        `yaml:"web"`
	}

	// I18nConfig represents the internationalization configuration
	I18nConfig struct {
		Path string `yaml:"path"` // Path to i18n translation files
	}

	DatabaseConfig struct {
		Type     string `yaml:"type"`     // mysql, postgres, sqlite, etc.
		Host     string `yaml:"host"`     // localhost
		Port     int    `yaml:"port"`     // 3306 (for mysql), 5432 (for postgres)
		User     string `yaml:"user"`     // root (for mysql), postgres (for postgres)
		Password string `yaml:"password"` // password
		DBName   string `yaml:"dbname"`   // database name
		SSLMode  string `yaml:"sslmode"`  // disable (for postgres)
	}

	JWTConfig struct {
		SecretKey string        `yaml:"secret_key"`
		Duration  time.Duration `yaml:"duration"`
	}

	WebConfig struct {
		APIBaseURL               string `yaml:"api_base_url"`
		WSBaseURL                string `yaml:"ws_base_url"`
		MCPGatewayBaseURL        string `yaml:"mcp_gateway_base_url"`
		DirectMCPGatewayModifier string `yaml:"direct_mcp_gateway_modifier"`
		BaseURL                  string `yaml:"base_url"`
		DebugMode                bool   `yaml:"debug_mode"`
		EnableExperimental       bool   `yaml:"enable_experimental"`
		LLMConfigAdminOnly       bool   `yaml:"llm_config_admin_only"`
	}
)

// GetDSN returns the database connection string
func (c *DatabaseConfig) GetDSN() string {
	switch c.Type {
	case "postgres":
		return c.getPostgresDSN()
	case "mysql":
		return c.getMySQLDSN()
	case "sqlite":
		// Ensure the directory for the SQLite database exists.
		// If the directory cannot be created, it's a fatal error.
		if err := os.MkdirAll(filepath.Dir(c.DBName), 0755); err != nil {
			panic(fmt.Errorf("failed to create directory for sqlite database: %w", err))
		}
		return c.DBName // For SQLite, DBName is the file path
	default:
		return ""
	}
}

// getPostgresDSN returns PostgreSQL connection string
func (c *DatabaseConfig) getPostgresDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.User, c.Password, c.Host, c.Port, c.DBName, c.SSLMode)
}

// getMySQLDSN returns MySQL connection string
func (c *DatabaseConfig) getMySQLDSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		c.User, c.Password, c.Host, c.Port, c.DBName)
}
