package dto

import (
	"time"

	"github.com/amoylab/unla/internal/common/config"
)

type MCPServer struct {
	Name       string            `json:"name"`
	Tenant     string            `json:"tenant"`
	McpServers []MCPServerConfig `json:"mcpServers,omitempty"`
	Tools      []ToolConfig      `json:"tools,omitempty"`
	Prompts    []PromptConfig    `json:"prompts,omitempty"`
	Servers    []ServerConfig    `json:"servers,omitempty"`
	Routers    []RouterConfig    `json:"routers,omitempty"`
	CreatedAt  time.Time         `json:"createdAt"`
	UpdatedAt  time.Time         `json:"updatedAt"`
}

type MCPConfig struct {
	Name       string            `json:"name"`
	Tenant     string            `json:"tenant"`
	CreatedAt  time.Time         `json:"createdAt"`
	UpdatedAt  time.Time         `json:"updatedAt"`
	DeletedAt  time.Time         `json:"deletedAt,omitempty"`
	Routers    []RouterConfig    `json:"routers,omitempty"`
	Servers    []ServerConfig    `json:"servers,omitempty"`
	Tools      []ToolConfig      `json:"tools,omitempty"`
	Prompts    []PromptConfig    `json:"prompts,omitempty"`
	McpServers []MCPServerConfig `json:"mcpServers,omitempty"`
}

type RouterConfig struct {
	Server    string      `json:"server"`
	Prefix    string      `json:"prefix"`
	SSEPrefix string      `json:"ssePrefix,omitempty"`
	CORS      *CORSConfig `json:"cors,omitempty"`
	Auth      *Auth       `json:"auth,omitempty"`
}

type CORSConfig struct {
	AllowOrigins     []string `json:"allowOrigins,omitempty"`
	AllowMethods     []string `json:"allowMethods,omitempty"`
	AllowHeaders     []string `json:"allowHeaders,omitempty"`
	ExposeHeaders    []string `json:"exposeHeaders,omitempty"`
	AllowCredentials bool     `json:"allowCredentials"`
}

type Auth struct {
	Mode string `json:"mode"`
}

type ServerConfig struct {
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	AllowedTools []string          `json:"allowedTools,omitempty"`
	Config       map[string]string `json:"config,omitempty"`
}

type ToolConfig struct {
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	Method       string            `json:"method"`
	Endpoint     string            `json:"endpoint"`
	Proxy        *ProxyConfig      `json:"proxy,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Args         []ArgConfig       `json:"args,omitempty"`
	RequestBody  string            `json:"requestBody"`
	ResponseBody string            `json:"responseBody"`
	InputSchema  map[string]any    `json:"inputSchema,omitempty"`
}

type MCPServerConfig struct {
	Type         string            `json:"type"`              // sse, stdio and streamable-http
	Name         string            `json:"name"`              // server name
	Command      string            `json:"command,omitempty"` // for stdio
	Args         []string          `json:"args,omitempty"`    // for stdio
	Env          map[string]string `json:"env,omitempty"`     // for stdio
	URL          string            `json:"url,omitempty"`     // for sse and streamable-http
	Policy       string            `json:"policy"`            // onStart or onDemand
	Preinstalled bool              `json:"preinstalled"`      // whether to install this MCP server when mcp-gateway starts
}

type ProxyConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Type string `json:"type"` // http, https, socks5
}

type ArgConfig struct {
	Name        string      `json:"name"`
	Position    string      `json:"position"` // header, query, path, body
	Required    bool        `json:"required"`
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Default     string      `json:"default"`
	Items       ItemsConfig `json:"items,omitempty"`
}

type ItemsConfig struct {
	Type string   `json:"type"`
	Enum []string `json:"enum,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
	Items      *ItemsConfig   `json:"items,omitempty"`
	Required   []string       `json:"required,omitempty"`
}


type PromptConfig struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Arguments   []PromptArgument    `json:"arguments"`
	PromptResponse []PromptResponse `json:"promptResponse,omitempty"`
}

type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

type PromptResponse struct {
	Role    string                `json:"role"`
	Content PromptResponseContent `json:"content"`
}

type PromptResponseContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// FromConfig converts a config.MCPConfig to dto.MCPServer
func FromConfig(cfg *config.MCPConfig) MCPServer {
	return MCPServer{
		Name:       cfg.Name,
		Tenant:     cfg.Tenant,
		McpServers: FromMCPServerConfigs(cfg.McpServers),
		Tools:      FromToolConfigs(cfg.Tools),
		Prompts:    FromPromptConfigs(cfg.Prompts),
		Servers:    FromServerConfigs(cfg.Servers),
		Routers:    FromRouterConfigs(cfg.Routers),
		CreatedAt:  cfg.CreatedAt,
		UpdatedAt:  cfg.UpdatedAt,
	}
}

// FromRouterConfigs converts a slice of config.RouterConfig to dto.RouterConfig
func FromRouterConfigs(cfgs []config.RouterConfig) []RouterConfig {
	if cfgs == nil {
		return nil
	}
	result := make([]RouterConfig, len(cfgs))
	for i, cfg := range cfgs {
		result[i] = RouterConfig{
			Server:    cfg.Server,
			Prefix:    cfg.Prefix,
			SSEPrefix: cfg.SSEPrefix,
			CORS:      FromCORSConfig(cfg.CORS),
			Auth:      FromAuthConfig(cfg.Auth),
		}
	}
	return result
}

// FromCORSConfig converts a config.CORSConfig to dto.CORSConfig
func FromCORSConfig(cfg *config.CORSConfig) *CORSConfig {
	if cfg == nil {
		return nil
	}
	return &CORSConfig{
		AllowOrigins:     cfg.AllowOrigins,
		AllowMethods:     cfg.AllowMethods,
		AllowHeaders:     cfg.AllowHeaders,
		ExposeHeaders:    cfg.ExposeHeaders,
		AllowCredentials: cfg.AllowCredentials,
	}
}

// FromServerConfigs converts a slice of config.ServerConfig to dto.ServerConfig
func FromServerConfigs(cfgs []config.ServerConfig) []ServerConfig {
	if cfgs == nil {
		return nil
	}
	result := make([]ServerConfig, len(cfgs))
	for i, cfg := range cfgs {
		result[i] = ServerConfig{
			Name:         cfg.Name,
			Description:  cfg.Description,
			AllowedTools: cfg.AllowedTools,
			Config:       cfg.Config,
		}
	}
	return result
}

// FromToolConfigs converts a slice of config.ToolConfig to dto.ToolConfig
func FromToolConfigs(cfgs []config.ToolConfig) []ToolConfig {
	if cfgs == nil {
		return nil
	}
	result := make([]ToolConfig, len(cfgs))
	for i, cfg := range cfgs {
		result[i] = ToolConfig{
			Name:         cfg.Name,
			Description:  cfg.Description,
			Method:       cfg.Method,
			Endpoint:     cfg.Endpoint,
			Proxy:        FromProxyConfig(cfg.Proxy),
			Headers:      cfg.Headers,
			Args:         FromArgConfigs(cfg.Args),
			RequestBody:  cfg.RequestBody,
			ResponseBody: cfg.ResponseBody,
			InputSchema:  cfg.InputSchema,
		}
	}
	return result
}

// FromProxyConfig converts a config.ProxyConfig to dto.ProxyConfig
func FromProxyConfig(cfg *config.ProxyConfig) *ProxyConfig {
	if cfg == nil {
		return nil
	}
	return &ProxyConfig{
		Host: cfg.Host,
		Port: cfg.Port,
		Type: cfg.Type,
	}
}

// FromArgConfigs converts a slice of config.ArgConfig to dto.ArgConfig
func FromArgConfigs(cfgs []config.ArgConfig) []ArgConfig {
	if cfgs == nil {
		return nil
	}
	result := make([]ArgConfig, len(cfgs))
	for i, cfg := range cfgs {
		result[i] = ArgConfig{
			Name:        cfg.Name,
			Position:    cfg.Position,
			Required:    cfg.Required,
			Type:        cfg.Type,
			Description: cfg.Description,
			Default:     cfg.Default,
			Items:       FromItemsConfig(cfg.Items),
		}
	}
	return result
}

// FromItemsConfig converts a config.ItemsConfig to dto.ItemsConfig
func FromItemsConfig(cfg config.ItemsConfig) ItemsConfig {
	var props map[string]any
	if cfg.Properties != nil {
		props = make(map[string]any)
		for k, v := range cfg.Properties {
			// 如果属性本身是 ItemsConfig，递归转换
			if vv, ok := v.(config.ItemsConfig); ok {
				props[k] = FromItemsConfig(vv)
			} else {
				props[k] = v
			}
		}
	}
	var items *ItemsConfig
	if cfg.Items != nil {
		tmp := FromItemsConfig(*cfg.Items)
		items = &tmp
	}
	return ItemsConfig{
		Type: cfg.Type,
		Enum: cfg.Enum,
		Properties: props,
		Items:      items,
		Required:   cfg.Required,
	}
}

// FromMCPServerConfigs converts a slice of config.MCPServerConfig to dto.MCPServerConfig
func FromMCPServerConfigs(cfgs []config.MCPServerConfig) []MCPServerConfig {
	if cfgs == nil {
		return nil
	}
	result := make([]MCPServerConfig, len(cfgs))
	for i, cfg := range cfgs {
		result[i] = MCPServerConfig{
			Type:         string(cfg.Type),
			Name:         cfg.Name,
			Command:      cfg.Command,
			Args:         cfg.Args,
			Env:          cfg.Env,
			URL:          cfg.URL,
			Policy:       string(cfg.Policy),
			Preinstalled: cfg.Preinstalled,
		}
	}
	return result
}

// FromAuthConfig converts a config.Auth to dto.Auth
func FromAuthConfig(cfg *config.Auth) *Auth {
	if cfg == nil {
		return nil
	}
	return &Auth{
		Mode: string(cfg.Mode),
	}
}

// FromPromptConfigs converts a slice of config.PromptConfig to dto.PromptConfig
func FromPromptConfigs(cfgs []config.PromptConfig) []PromptConfig {
	if cfgs == nil {
		return nil
	}
	result := make([]PromptConfig, len(cfgs))
	for i, cfg := range cfgs {
		result[i] = PromptConfig{
			Name:        cfg.Name,
			Description: cfg.Description,
			Arguments:   FromPromptArguments(cfg.Arguments),
			PromptResponse: FromPromptResponses(cfg.PromptResponse),
		}
	}
	return result
}

func FromPromptArguments(cfgs []config.PromptArgument) []PromptArgument {
	if cfgs == nil {
		return nil
	}
	result := make([]PromptArgument, len(cfgs))
	for i, cfg := range cfgs {
		result[i] = PromptArgument{
			Name:        cfg.Name,
			Description: cfg.Description,
			Required:    cfg.Required,
		}
	}
	return result
}

func FromPromptResponses(cfgs []config.PromptResponse) []PromptResponse {
	if cfgs == nil {
		return nil
	}
	result := make([]PromptResponse, len(cfgs))
	for i, cfg := range cfgs {
		result[i] = PromptResponse{
			Role:    cfg.Role,
			Content: FromPromptResponseContent(cfg.Content),
		}
	}
	return result
}

func FromPromptResponseContent(cfg config.PromptResponseContent) PromptResponseContent {
	return PromptResponseContent{
		Type: cfg.Type,
		Text: cfg.Text,
	}
}
