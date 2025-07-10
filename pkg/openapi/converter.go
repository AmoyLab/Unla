package openapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/ifuryst/lol"
	"gopkg.in/yaml.v3"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/pkg/utils"
)

// Converter handles the conversion from OpenAPI to MCP configuration
type Converter struct {
	// Add any necessary fields here
}

const (
	// OpenAPIVersion2 openapi 2.0
	OpenAPIVersion2 = "2.0"
	// OpenAPIVersion3 openapi 3.0
	OpenAPIVersion3 = "3.0"
	// OpenAPIVersion31 openapi 3.1
	OpenAPIVersion31 = "3.1"
)

// NewConverter creates a new Converter instance
func NewConverter() *Converter {
	return &Converter{}
}

// Convert converts OpenAPI specification to MCP configuration
func (c *Converter) Convert(specData []byte) (*config.MCPConfig, error) {
	// check OpenAPI version
	version, err := detectOpenAPIVersion(specData)
	if err != nil {
		return nil, err
	}

	// Select handler based on API version
	if strings.HasPrefix(version, OpenAPIVersion2) {
		// handler Swagger 2.0
		return c.convertSwagger2(specData)
	}

	// handler OpenAPI 3.x
	loader := openapi3.NewLoader()

	// if version is 3.1, allow external references
	if strings.HasPrefix(version, OpenAPIVersion31) {
		loader.IsExternalRefsAllowed = true
	}

	doc, err := loader.LoadFromData(specData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OpenAPI specification: %w", err)
	}

	// if the version is 3.0, validate the document
	if strings.HasPrefix(version, OpenAPIVersion3) {
		if err := doc.Validate(loader.Context); err != nil {
			return nil, fmt.Errorf("invalid OpenAPI specification: %w", err)
		}
	}

	rs := lol.RandomString(4)

	// Create base MCP configuration
	mcpConfig := &config.MCPConfig{
		Name:      doc.Info.Title + "_" + rs,
		Tenant:    "default", // Default tenant prefix
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Routers:   make([]config.RouterConfig, 0),
		Servers:   make([]config.ServerConfig, 0),
		Tools:     make([]config.ToolConfig, 0),
	}

	// Create server configuration
	server := config.ServerConfig{
		Name:         mcpConfig.Name,
		Description:  doc.Info.Description,
		Config:       make(map[string]string),
		AllowedTools: make([]string, 0),
	}

	// Add server URL to config
	if len(doc.Servers) > 0 {
		server.Config["url"] = doc.Servers[0].URL
	}

	// Create a default router for the server
	router := config.RouterConfig{
		Server: mcpConfig.Name,
		Prefix: fmt.Sprintf("/gateway/%s", rs), // Generate a random prefix for each router
		CORS: &config.CORSConfig{
			AllowOrigins:     []string{"*"},
			AllowMethods:     []string{"GET", "POST", "OPTIONS"},
			AllowHeaders:     []string{"Content-Type", "Authorization", "Mcp-Session-Id", "mcp-protocol-version"},
			ExposeHeaders:    []string{"Mcp-Session-Id", "mcp-protocol-version"},
			AllowCredentials: true,
		},
	}

	// Convert paths to tools
	for path, pathItem := range doc.Paths.Map() {
		// Create a tool for each HTTP method
		for method, operation := range pathItem.Operations() {
			if method == "options" {
				continue // Skip CORS options
			}

			// Skip if operation ID is empty
			if operation.OperationID == "" {
				// Generate operationId from method and path
				// Convert path to operationId format: /users/email/{email} -> users_email_argemail
				pathParts := strings.Split(strings.TrimPrefix(path, "/"), "/")
				for i, part := range pathParts {
					if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
						pathParts[i] = "arg" + strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
					}
				}
				operation.OperationID = fmt.Sprintf("%s_%s", strings.ToLower(method), strings.Join(pathParts, "_"))
			}

			tool := config.ToolConfig{
				Name:         operation.OperationID,
				Description:  utils.FirstNonEmpty(operation.Description, operation.Summary),
				Method:       method,
				Endpoint:     fmt.Sprintf("{{.Config.url}}%s", path),
				Headers:      make(map[string]string),
				Args:         make([]config.ArgConfig, 0),
				ResponseBody: "{{.Response.Body}}", // Use passthrough for response
			}

			// Add default headers
			tool.Headers["Content-Type"] = "application/json"
			tool.Headers["Authorization"] = "{{.Request.Headers.Authorization}}"

			// Add parameters
			var bodyArgs []config.ArgConfig
			var pathArgs []config.ArgConfig
			var queryArgs []config.ArgConfig
			var headerArgs []config.ArgConfig

			// Handle path parameters
			for _, param := range operation.Parameters {
				arg := config.ArgConfig{
					Name:        param.Value.Name,
					Position:    param.Value.In,
					Required:    param.Value.Required,
					Type:        "string", // Default to string type
					Description: param.Value.Description,
				}

				// Get schema type if available
				if param.Value.Schema != nil && param.Value.Schema.Value != nil {
					if param.Value.Schema.Value.Type != nil {
						types := param.Value.Schema.Value.Type.Slice()
						if len(types) > 0 {
							arg.Type = types[0]
						}
					}
					if param.Value.Schema.Value.Default != nil {
						arg.Default = fmt.Sprintf("%v", param.Value.Schema.Value.Default)
					}
				}

				switch param.Value.In {
				case "path":
					// Path parameters are always required
					arg.Required = true
					pathArgs = append(pathArgs, arg)
					// Update endpoint with path parameters
					tool.Endpoint = strings.ReplaceAll(tool.Endpoint, fmt.Sprintf("{%s}", arg.Name), fmt.Sprintf("{{.Args.%s}}", arg.Name))
				case "query":
					queryArgs = append(queryArgs, arg)
				case "header":
					tool.Headers[arg.Name] = fmt.Sprintf("{{.Args.%s}}", arg.Name)
					headerArgs = append(headerArgs, arg)
				}
			}

			// Handle request body
			if operation.RequestBody != nil {
				requestBodyRequired := operation.RequestBody.Value.Required
				for contentType, mediaType := range operation.RequestBody.Value.Content {
					if contentType == "application/json" {
						tool.RequestBody = contentType
						// Add request body parameters
						if mediaType.Schema != nil {
							schema := mediaType.Schema.Value
							// Handle schema reference
							if mediaType.Schema.Ref != "" {
								refName := strings.TrimPrefix(mediaType.Schema.Ref, "#/components/schemas/")
								if refSchema, ok := doc.Components.Schemas[refName]; ok {
									schema = refSchema.Value
								}
							}

							if schema.Properties != nil {
								for name, prop := range schema.Properties {
									// Skip response-only fields
									if strings.HasPrefix(name, "response") || name == "id" || name == "createdAt" {
										continue
									}

									arg := config.ArgConfig{
										Name:        name,
										Position:    "body",
										Required:    requestBodyRequired || contains(schema.Required, name),
										Type:        "string", // Default to string type
										Description: prop.Value.Description,
									}

									if prop.Value != nil && prop.Value.Type != nil {
										types := prop.Value.Type.Slice()
										if len(types) > 0 {
											arg.Type = types[0]
											if arg.Type == "array" && prop.Value.Items != nil && prop.Value.Items.Value != nil {
												arg.Items = buildNestedArg(prop.Value.Items.Value)
											}
										}
									}

									if prop.Value.Default != nil {
										arg.Default = fmt.Sprintf("%v", prop.Value.Default)
									}

									bodyArgs = append(bodyArgs, arg)
								}
							}
						}
					}
				}
			}

			// Combine all args
			tool.Args = append(tool.Args, pathArgs...)
			tool.Args = append(tool.Args, queryArgs...)
			tool.Args = append(tool.Args, bodyArgs...)
			tool.Args = append(tool.Args, headerArgs...)

			// Build request body template if there are body args
			if len(bodyArgs) > 0 {
				var bodyTemplate strings.Builder
				bodyTemplate.WriteString("{\n")
				for i, arg := range bodyArgs {
					bodyTemplate.WriteString(fmt.Sprintf(`    "%s": {{ toJSON .Args.%s}}`, arg.Name, arg.Name))
					if i < len(bodyArgs)-1 {
						bodyTemplate.WriteString(",\n")
					} else {
						bodyTemplate.WriteString("\n")
					}
				}
				bodyTemplate.WriteString("}")
				tool.RequestBody = bodyTemplate.String()
			}

			mcpConfig.Tools = append(mcpConfig.Tools, tool)
			server.AllowedTools = append(server.AllowedTools, tool.Name)
		}
	}

	mcpConfig.Servers = append(mcpConfig.Servers, server)
	mcpConfig.Routers = append(mcpConfig.Routers, router)

	return mcpConfig, nil
}

// convertSwagger2 converts Swagger 2.0 specification to OpenAPI 3.0 and then to MCP configuration
func (c *Converter) convertSwagger2(specData []byte) (*config.MCPConfig, error) {
	var swagger2Doc openapi2.T
	if err := json.Unmarshal(specData, &swagger2Doc); err != nil {
		if err := yaml.Unmarshal(specData, &swagger2Doc); err != nil {
			return nil, fmt.Errorf("failed to parse Swagger 2.0 specification: %w", err)
		}
	}

	// convert Swagger 2.0 to OpenAPI 3.0
	openapi3Doc, err := openapi2conv.ToV3(&swagger2Doc)
	if err != nil {
		return nil, fmt.Errorf("failed to convert Swagger 2.0 to OpenAPI 3.0: %w", err)
	}

	openapi3Data, err := json.Marshal(openapi3Doc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize OpenAPI 3.0 document: %w", err)
	}

	return c.Convert(openapi3Data)
}

// detectOpenAPIVersion detects the OpenAPI version from the specification data
func detectOpenAPIVersion(specData []byte) (string, error) {
	var spec map[string]interface{}

	if err := json.Unmarshal(specData, &spec); err != nil {
		if err := yaml.Unmarshal(specData, &spec); err != nil {
			return "", fmt.Errorf("failed to parse specification: %w", err)
		}
	}

	// check if OpenAPI 3.x
	if openapi, ok := spec["openapi"].(string); ok {
		return openapi, nil
	}

	// check if Swagger 2.0
	if swagger, ok := spec["swagger"].(string); ok {
		return swagger, nil
	}

	return "", fmt.Errorf("could not determine OpenAPI version")
}

// ConvertFromJSON converts JSON OpenAPI specification to MCP configuration
func (c *Converter) ConvertFromJSON(jsonData []byte) (*config.MCPConfig, error) {
	return c.Convert(jsonData)
}

// ConvertFromYAML converts YAML OpenAPI specification to MCP configuration
func (c *Converter) ConvertFromYAML(yamlData []byte) (*config.MCPConfig, error) {
	return c.Convert(yamlData)
}

// ConvertWithOptions converts OpenAPI specification to MCP configuration, using tenant and prefix if provided
func (c *Converter) ConvertWithOptions(specData []byte, tenant, prefix string) (*config.MCPConfig, error) {
	config, err := c.Convert(specData)
	if err != nil {
		return nil, err
	}
	// Remove leading / from tenant if present
	cleanTenant := tenant
	if strings.HasPrefix(cleanTenant, "/") {
		cleanTenant = strings.TrimPrefix(cleanTenant, "/")
	}
	if tenant != "" && prefix != "" {
		config.Tenant = cleanTenant
		if len(config.Routers) > 0 {
			config.Routers[0].Prefix = cleanTenant + "/" + prefix
		}
	} else if tenant != "" {
		config.Tenant = cleanTenant
		if len(config.Routers) > 0 {
			// Autogenerate prefix as in default logic
			rs := lol.RandomString(4)
			config.Routers[0].Prefix = cleanTenant + "/" + rs
		}
	} else if prefix != "" {
		config.Tenant = "default"
		if len(config.Routers) > 0 {
			config.Routers[0].Prefix = "/default/" + prefix
		}
	}
	return config, nil
}

// contains checks if a string is in a slice
func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}

func buildNestedArg(schema *openapi3.Schema) config.ItemsConfig {
	var items config.ItemsConfig

	if schema.Type != nil {
		types := schema.Type.Slice()
		if len(types) > 0 {
			schemaType := types[0]
			items.Type = schemaType

			if schemaType == "object" && schema.Properties != nil {
				properties := make(map[string]any)
				for childName, childProp := range schema.Properties {
					propType := "string"
					if childProp.Value.Type != nil && len(childProp.Value.Type.Slice()) > 0 {
						propType = childProp.Value.Type.Slice()[0]
					}
					propSchema := map[string]any{
						"type":        propType,
						"description": childProp.Value.Description,
					}
					// 递归处理嵌套 object/array
					if propType == "object" {
						nested := buildNestedArg(childProp.Value)
						if len(nested.Properties) > 0 {
							propSchema["properties"] = nested.Properties
						}
					} else if propType == "array" && childProp.Value.Items != nil && childProp.Value.Items.Value != nil {
						nested := buildNestedArg(childProp.Value.Items.Value)
						propSchema["items"] = nested
					}
					properties[childName] = propSchema
				}
				items.Properties = properties
				items.Required = schema.Required
			} else if schemaType == "array" && schema.Items != nil && schema.Items.Value != nil {
				nested := buildNestedArg(schema.Items.Value)
				items.Type = "array"
				items.Properties = nil
				items.Items = &nested
			}
		}
	}
	return items
}
