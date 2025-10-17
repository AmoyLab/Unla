package config

import (
	"time"

	"github.com/ifuryst/lol"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/amoylab/unla/pkg/utils"
)

type (
	// MCPServer represents the MCP server data structure
	MCPServer struct {
		Name      string    `json:"name" yaml:"name"`
		Content   MCPConfig `json:"content" yaml:"content"`
		CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
		UpdatedAt time.Time `json:"updatedAt" yaml:"updatedAt"`
	}

	MCPConfig struct {
		Name       string            `json:"name" yaml:"name"`
		Tenant     string            `json:"tenant" yaml:"tenant"`
		CreatedAt  time.Time         `json:"createdAt" yaml:"createdAt"`
		UpdatedAt  time.Time         `json:"updatedAt" yaml:"updatedAt"`
		DeletedAt  time.Time         `json:"deletedAt,omitempty" yaml:"deletedAt,omitempty"` // non-zero indicates that all information has been deleted
		Routers    []RouterConfig    `json:"routers,omitempty" yaml:"routers,omitempty"`
		Servers    []ServerConfig    `json:"servers,omitempty" yaml:"servers,omitempty"`
		Tools      []ToolConfig      `json:"tools,omitempty" yaml:"tools,omitempty"`
		Prompts    []PromptConfig    `json:"prompts,omitempty" yaml:"prompts,omitempty"`
		McpServers []MCPServerConfig `json:"mcpServers,omitempty" yaml:"mcpServers,omitempty"` // proxy mcp servers
	}

	RouterConfig struct {
		Server    string      `json:"server" yaml:"server"`
		Prefix    string      `json:"prefix" yaml:"prefix"`
		SSEPrefix string      `json:"ssePrefix" yaml:"ssePrefix"`
		CORS      *CORSConfig `json:"cors,omitempty" yaml:"cors,omitempty"`
		Auth      *Auth       `json:"auth,omitempty" yaml:"auth,omitempty"`
	}

	CORSConfig struct {
		AllowOrigins     []string `json:"allowOrigins,omitempty" yaml:"allowOrigins,omitempty"`
		AllowMethods     []string `json:"allowMethods,omitempty" yaml:"allowMethods,omitempty"`
		AllowHeaders     []string `json:"allowHeaders,omitempty" yaml:"allowHeaders,omitempty"`
		ExposeHeaders    []string `json:"exposeHeaders,omitempty" yaml:"exposeHeaders,omitempty"`
		AllowCredentials bool     `json:"allowCredentials" yaml:"allowCredentials"`
	}

	ProxyConfig struct {
		Host string `json:"host" yaml:"host"`
		Port int    `json:"port" yaml:"port"`
		Type string `json:"type" yaml:"type"` // http, https, socks5
	}

	ServerConfig struct {
		Name         string            `json:"name" yaml:"name"`
		Description  string            `json:"description" yaml:"description"`
		AllowedTools []string          `json:"allowedTools,omitempty" yaml:"allowedTools,omitempty"`
		Config       map[string]string `json:"config,omitempty" yaml:"config,omitempty"`
	}

	ToolConfig struct {
		Name         string            `json:"name" yaml:"name"`
		Description  string            `json:"description,omitempty" yaml:"description,omitempty"`
		Method       string            `json:"method" yaml:"method"`
		Endpoint     string            `json:"endpoint" yaml:"endpoint"`
		Proxy        *ProxyConfig      `json:"proxy,omitempty" yaml:"proxy,omitempty"`
		Headers      map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
		Args         []ArgConfig       `json:"args,omitempty" yaml:"args,omitempty"`
		RequestBody  string            `json:"requestBody"  yaml:"requestBody"`
		ResponseBody string            `json:"responseBody" yaml:"responseBody"`
		InputSchema  map[string]any    `json:"inputSchema,omitempty" yaml:"inputSchema,omitempty"`
		Annotations  map[string]any    `json:"annotations,omitempty" yaml:"annotations,omitempty"`
		Meta         map[string]any    `json:"meta,omitempty" yaml:"meta,omitempty"`
	}

	MCPServerConfig struct {
		Type         string                `json:"type" yaml:"type"`                           // sse, stdio and streamable-http
		Name         string                `json:"name" yaml:"name"`                           // server name
		Command      string                `json:"command,omitempty" yaml:"command,omitempty"` // for stdio
		Args         []string              `json:"args,omitempty" yaml:"args,omitempty"`       // for stdio
		Env          map[string]string     `json:"env,omitempty" yaml:"env,omitempty"`         // for stdio
		URL          string                `json:"url,omitempty" yaml:"url,omitempty"`         // for sse and streamable-http
		Policy       cnst.MCPStartupPolicy `json:"policy" yaml:"policy"`                       // onStart or onDemand
		Preinstalled bool                  `json:"preinstalled" yaml:"preinstalled"`           // whether to install this MCP server when mcp-gateway starts
	}

	ArgConfig struct {
		Name        string      `json:"name" yaml:"name"`
		Position    string      `json:"position" yaml:"position"` // header, query, path, body
		Required    bool        `json:"required" yaml:"required"`
		Type        string      `json:"type" yaml:"type"`
		Description string      `json:"description" yaml:"description"`
		Default     string      `json:"default" yaml:"default"`
		Items       ItemsConfig `json:"items,omitempty" yaml:"items,omitempty"`
	}

	ItemsConfig struct {
		Type       string         `json:"type" yaml:"type"`
		Enum       []string       `json:"enum,omitempty" yaml:"enum,omitempty"`
		Properties map[string]any `json:"properties,omitempty" yaml:"properties,omitempty"`
		Items      *ItemsConfig   `json:"items,omitempty" yaml:"items,omitempty"`
		Required   []string       `json:"required,omitempty" yaml:"required,omitempty"`
	}

	// MCPConfigVersion represents a version of an MCP configuration
	MCPConfigVersion struct {
		Version    int             `json:"version" yaml:"version"`
		CreatedBy  string          `json:"created_by" yaml:"created_by"`
		CreatedAt  time.Time       `json:"created_at" yaml:"created_at"`
		ActionType cnst.ActionType `json:"action_type" yaml:"action_type"` // Create, Update, Delete, Revert
		Name       string          `json:"name" yaml:"name"`
		Tenant     string          `json:"tenant" yaml:"tenant"`
		Routers    string          `json:"routers" yaml:"routers"`
		Servers    string          `json:"servers" yaml:"servers"`
		Tools      string          `json:"tools" yaml:"tools"`
		Prompts    string          `json:"prompts" yaml:"prompts"`
		McpServers string          `json:"mcp_servers" yaml:"mcp_servers"`
		IsActive   bool            `json:"is_active" yaml:"is_active"` // indicates if this version is currently active
		Hash       string          `json:"hash" yaml:"hash"`           // hash of the configuration content
	}

	// Auth represents authentication configuration
	Auth struct {
		Mode cnst.AuthMode `json:"mode" yaml:"mode"`
	}

	PromptConfig struct {
		Name           string           `json:"name" yaml:"name"`
		Description    string           `json:"description" yaml:"description"`
		Arguments      []PromptArgument `json:"arguments" yaml:"arguments"`
		PromptResponse []PromptResponse `json:"promptResponse,omitempty" yaml:"promptResponse,omitempty"`
	}

	PromptArgument struct {
		Name        string `json:"name" yaml:"name"`
		Description string `json:"description" yaml:"description"`
		Required    bool   `json:"required" yaml:"required"`
	}

	PromptResponse struct {
		Role    string                `json:"role" yaml:"role"`
		Content PromptResponseContent `json:"content" yaml:"content"`
	}

	PromptResponseContent struct {
		Type string `json:"type" yaml:"type"`
		Text string `json:"text" yaml:"text"`
	}
)

// ToToolSchema converts a ToolConfig to a ToolSchema
func (t *ToolConfig) ToToolSchema() mcp.ToolSchema {
	// Create properties map for input schema
	properties := make(map[string]any)
	required := make([]string, 0)
	for _, arg := range t.Args {
		property := map[string]any{
			"type":        arg.Type,
			"description": arg.Description,
		}

		if arg.Type == "array" {
			items := make(map[string]any)
			if len(arg.Items.Enum) > 0 {
				items["enum"] = lol.Union(arg.Items.Enum)
			} else {
				items["type"] = arg.Items.Type
				// If items is an object type, recursively process its properties
				if arg.Items.Properties != nil {
					items["properties"] = arg.Items.Properties
				}
			}
			property["items"] = items
		}

		properties[arg.Name] = property
		if arg.Required {
			required = append(required, arg.Name)
		}
	}

	// Merge with existing input schema if any
	if t.InputSchema != nil {
		for k, v := range t.InputSchema {
			properties[k] = v
		}
	}
	var annotations *mcp.ToolAnnotations
	if t.Annotations != nil {
		annotations = &mcp.ToolAnnotations{
			Title:           utils.GetString(t.Annotations, "title", ""),
			DestructiveHint: utils.GetBool(t.Annotations, "destructiveHint", true),
			IdempotentHint:  utils.GetBool(t.Annotations, "idempotentHint", false),
			OpenWorldHint:   utils.GetBool(t.Annotations, "openWorldHint", true),
			ReadOnlyHint:    utils.GetBool(t.Annotations, "readOnlyHint", false),
		}
	}

	return mcp.ToolSchema{
		Name:        t.Name,
		Description: t.Description,
		InputSchema: mcp.ToolInputSchema{
			Type:       "object",
			Properties: properties,
			Required:   required,
		},
		Annotations: annotations,
		Meta:        t.Meta,
	}
}

// ToPromptSchema converts a PromptConfig to a PromptSchema
func (t *PromptConfig) ToPromptSchema() mcp.PromptSchema {
	args := make([]mcp.PromptArgumentSchema, len(t.Arguments))
	for i, a := range t.Arguments {
		args[i] = mcp.PromptArgumentSchema{
			Name:        a.Name,
			Description: a.Description,
			Required:    a.Required,
		}
	}
	var responses []mcp.PromptResponseSchema
	for _, r := range t.PromptResponse {
		responses = append(responses, mcp.PromptResponseSchema{
			Role: r.Role,
			Content: mcp.PromptResponseContentSchema{
				Type: r.Content.Type,
				Text: r.Content.Text,
			},
		})
	}
	return mcp.PromptSchema{
		Name:           t.Name,
		Description:    t.Description,
		Arguments:      args,
		PromptResponse: responses,
	}
}
