package config

import (
	"os"
	"regexp"
	"time"

	"github.com/amoylab/unla/pkg/helper"
	"github.com/amoylab/unla/pkg/trace"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

type (
	// SuperAdminConfig represents the super admin configuration
	SuperAdminConfig struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	}

	// ForwardConfig represents the forward configuration for header handling
	ForwardConfig struct {
		Enabled bool `yaml:"enabled"`
		McpArg  struct {
			KeyForHeader string `yaml:"key_for_header"`
		} `yaml:"mcp_arg"`
		Header struct {
			AllowHeaders     string `yaml:"allow_headers"`
			IgnoreHeaders    string `yaml:"ignore_headers"`
			CaseInsensitive  bool   `yaml:"case_insensitive"`
			OverrideExisting bool   `yaml:"override_existing"`
		} `yaml:"header"`
	}

	// MCPGatewayConfig represents the MCP gateway configuration
	MCPGatewayConfig struct {
		Port           int              `yaml:"port"`
		ReloadPort     int              `yaml:"reload_port"`
		ReloadInterval time.Duration    `yaml:"reload_interval"`
		ReloadSwitch   bool             `yaml:"reload_switch"`
		Forward        ForwardConfig    `yaml:"forward"`
		PID            string           `yaml:"pid"`
		SuperAdmin     SuperAdminConfig `yaml:"super_admin"`
		Logger         LoggerConfig     `yaml:"logger"`
		Tracing        trace.Config     `yaml:"tracing"`
		Storage        StorageConfig    `yaml:"storage"`
		Notifier       NotifierConfig   `yaml:"notifier"`
		Session        SessionConfig    `yaml:"session"`
		Auth           AuthConfig       `yaml:"auth"`
		Metrics        MetricsConfig    `yaml:"metrics"`
	}

	// MetricsConfig controls Prometheus metrics exposure
	MetricsConfig struct {
		Enabled   bool      `yaml:"enabled"`
		Path      string    `yaml:"path"`
		Namespace string    `yaml:"namespace"`
		Buckets   []float64 `yaml:"buckets"`
	}

	// SessionConfig represents the session storage configuration
	SessionConfig struct {
		Type  string             `yaml:"type"`  // "memory" or "redis"
		Redis SessionRedisConfig `yaml:"redis"` // Redis configuration
	}

	// SessionRedisConfig represents the Redis configuration for session storage
	SessionRedisConfig struct {
		ClusterType string        `yaml:"cluster_type"` // "single", "cluster" or "sentinel"
		Addr        string        `yaml:"addr"`         // multiple addresses separated by ;.
		MasterName  string        `yaml:"master_name"`  // MasterName is the sentinel master name.
		Username    string        `yaml:"username"`
		Password    string        `yaml:"password"`
		DB          int           `yaml:"db"`
		Topic       string        `yaml:"topic"`
		Prefix      string        `yaml:"prefix"`
		TTL         time.Duration `yaml:"ttl"` // TTL for session data in Redis
	}

	// LoggerConfig represents the logger configuration
	LoggerConfig struct {
		Level      string `yaml:"level"`       // debug, info, warn, error
		Format     string `yaml:"format"`      // json, console
		Output     string `yaml:"output"`      // stdout, file
		FilePath   string `yaml:"file_path"`   // path to log file when output is file
		MaxSize    int    `yaml:"max_size"`    // max size of log file in MB
		MaxBackups int    `yaml:"max_backups"` // max number of backup files
		MaxAge     int    `yaml:"max_age"`     // max age of backup files in days
		Compress   bool   `yaml:"compress"`    // whether to compress backup files
		Color      bool   `yaml:"color"`       // whether to use color in console output
		Stacktrace bool   `yaml:"stacktrace"`  // whether to include stacktrace in error logs
		TimeZone   string `yaml:"time_zone"`   // time zone for log timestamps, e.g., "UTC", default is local
		TimeFormat string `yaml:"time_format"` // time format for log timestamps, default is "2006-01-02 15:04:05"
	}

	// AuthConfig defines the authentication configuration
	AuthConfig struct {
		OAuth2 *OAuth2Config      `yaml:"oauth2"`
		CORS   *CORSConfig        `yaml:"cors,omitempty"`
		Google *GoogleOAuthConfig `yaml:"google,omitempty"`
		GitHub *GitHubOAuthConfig `yaml:"github,omitempty"`
	}
	OAuth2Config struct {
		Issuer  string              `yaml:"issuer"`
		Storage OAuth2StorageConfig `yaml:"storage"`
	}
	OAuth2StorageConfig struct {
		Type  string            `yaml:"type"`
		Redis OAuth2RedisConfig `yaml:"redis"`
	}
	OAuth2RedisConfig struct {
		ClusterType string `yaml:"cluster_type"` // "single", "cluster" or "sentinel"
		Addr        string `yaml:"addr"`
		MasterName  string `yaml:"master_name"` // MasterName is the sentinel master name.
		Username    string `yaml:"username"`
		Password    string `yaml:"password"`
		DB          int    `yaml:"db"`
	}

	// GoogleOAuthConfig defines Google OAuth configuration
	GoogleOAuthConfig struct {
		ClientID     string `yaml:"client_id"`
		ClientSecret string `yaml:"client_secret"`
		RedirectURI  string `yaml:"redirect_uri"`
	}

	// GitHubOAuthConfig defines GitHub OAuth configuration
	GitHubOAuthConfig struct {
		ClientID     string `yaml:"client_id"`
		ClientSecret string `yaml:"client_secret"`
		RedirectURI  string `yaml:"redirect_uri"`
	}
)

type Type interface {
	MCPGatewayConfig | APIServerConfig
}

// LoadConfig loads configuration from a YAML file with environment variable support
func LoadConfig[T Type](filename string) (*T, string, error) {
	// Load .env file if exists
	_ = godotenv.Load()

	cfgPath := helper.GetCfgPath(filename)
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, cfgPath, err
	}

	// Resolve environment variables
	data = resolveEnv(data)
	var cfg T
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, cfgPath, err
	}

	// Validate durations after unmarshalling
	if mcpCfg, ok := any(&cfg).(*MCPGatewayConfig); ok {
		if mcpCfg.ReloadInterval <= time.Second {
			mcpCfg.ReloadInterval = 600 * time.Second
		}
		// Metrics defaults
		if mcpCfg.Metrics.Enabled {
			if mcpCfg.Metrics.Path == "" {
				mcpCfg.Metrics.Path = "/metrics"
			}
			if mcpCfg.Metrics.Namespace == "" {
				mcpCfg.Metrics.Namespace = "mcp_gateway"
			}
			if len(mcpCfg.Metrics.Buckets) == 0 {
				mcpCfg.Metrics.Buckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10}
			}
		}

	}

	// Set defaults for apiserver MCP runtime if missing
	if apiCfg, ok := any(&cfg).(*APIServerConfig); ok {
		if apiCfg.MCP.CapabilitiesRefreshInterval <= 0 {
			apiCfg.MCP.CapabilitiesRefreshInterval = 120 * time.Second
		}
		if apiCfg.MCP.CapabilitiesCacheTTL <= 0 {
			apiCfg.MCP.CapabilitiesCacheTTL = 5 * time.Minute
		}
	}

	return &cfg, cfgPath, nil
}

// resolveEnv replaces environment variable placeholders in YAML content
func resolveEnv(content []byte) []byte {
	regex := regexp.MustCompile(`\$\{(\w+)(?::([^}]*))?\}`)

	return regex.ReplaceAllFunc(content, func(match []byte) []byte {
		matches := regex.FindSubmatch(match)
		envKey := string(matches[1])
		var defaultValue string

		if len(matches) > 2 {
			defaultValue = string(matches[2])
		}

		if value, exists := os.LookupEnv(envKey); exists {
			return []byte(value)
		}
		return []byte(defaultValue)
	})
}
