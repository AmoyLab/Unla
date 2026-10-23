package openapi

import (
	"strings"
	"testing"

	commoncfg "github.com/amoylab/unla/internal/common/config"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func TestConverter_Convert(t *testing.T) {
	converter := NewConverter()

	// Test with a simple OpenAPI specification
	spec := `{
		"openapi": "3.0.0",
		"info": {
			"title": "Test API",
			"description": "Test API description",
			"version": "1.0.0"
		},
		"servers": [
			{
				"url": "https://api.example.com/v1"
			}
		],
		"paths": {
			"/test": {
				"get": {
					"summary": "Test endpoint",
					"responses": {
						"200": {
							"description": "Successful response"
						}
					}
				},
				"options": {
					"summary": "CORS options",
					"responses": {
						"200": {
							"description": "CORS headers"
						}
					}
				}
			}
		}
	}`

	config, err := converter.ConvertFromJSON([]byte(spec))
	assert.NoError(t, err)
	assert.NotNil(t, config)

	// Verify the converted configuration
	//assert.Equal(t, "Test API", config.Name)
	assert.Equal(t, 1, len(config.Routers))
	assert.True(t, strings.HasPrefix(config.Routers[0].Prefix, "/gateway/"))
	assert.NotNil(t, config.Routers[0].CORS)

	assert.Equal(t, 1, len(config.Servers))
	//assert.Equal(t, "Test API", config.Servers[0].Name)
	assert.Equal(t, "Test API description", config.Servers[0].Description)
	assert.Equal(t, "https://api.example.com/v1", config.Servers[0].Config["url"])
}

func TestConverter_ConvertFromYAML(t *testing.T) {
	converter := NewConverter()

	// Test with a simple OpenAPI specification in YAML
	spec := `openapi: 3.0.0
info:
  title: Test API
  description: Test API description
  version: 1.0.0
servers:
  - url: https://api.example.com/v1
paths:
  /test:
    get:
      summary: Test endpoint
      responses:
        200:
          description: Successful response
    options:
      summary: CORS options
      responses:
        200:
          description: CORS headers`

	config, err := converter.ConvertFromYAML([]byte(spec))
	assert.NoError(t, err)
	assert.NotNil(t, config)

	// Verify the converted configuration
	//assert.Equal(t, "Test API", config.Name)
	assert.Equal(t, 1, len(config.Routers))
	assert.True(t, strings.HasPrefix(config.Routers[0].Prefix, "/gateway/"))
	assert.NotNil(t, config.Routers[0].CORS)

	assert.Equal(t, 1, len(config.Servers))
	//assert.Equal(t, "Test API", config.Servers[0].Name)
	assert.Equal(t, "Test API description", config.Servers[0].Description)
	assert.Equal(t, "https://api.example.com/v1", config.Servers[0].Config["url"])
}

func TestConverter_ConvertOpenapi2(t *testing.T) {
	converter := NewConverter()

	// Test with a simple Swagger 2.0 specification
	spec := `{
		"swagger": "2.0",
		"info": {
			"title": "Test API",
			"description": "Test API description",
			"version": "1.0.0"
		},
		"host": "api.example.com",
		"basePath": "/v1",
		"schemes": ["https"],
		"paths": {
			"/test": {
				"get": {
					"summary": "Test endpoint",
					"responses": {
						"200": {
							"description": "Successful response"
						}
					}
				},
				"options": {
					"summary": "CORS options",
					"responses": {
						"200": {
							"description": "CORS headers"
						}
					}
				}
			},
			"/users/{userId}": {
				"get": {
					"summary": "Get user by ID",
					"parameters": [
						{
							"name": "userId",
							"in": "path",
							"required": true,
							"type": "string",
							"description": "User ID"
						}
					],
					"responses": {
						"200": {
							"description": "User found"
						}
					}
				}
			}
		}
	}`

	config, err := converter.ConvertFromJSON([]byte(spec))
	assert.NoError(t, err)
	assert.NotNil(t, config)

	// Verify the converted configuration
	assert.Equal(t, 1, len(config.Routers))
	assert.True(t, strings.HasPrefix(config.Routers[0].Prefix, "/gateway/"))
	assert.NotNil(t, config.Routers[0].CORS)

	assert.Equal(t, 1, len(config.Servers))
	assert.Equal(t, "Test API description", config.Servers[0].Description)
	assert.Equal(t, "https://api.example.com/v1", config.Servers[0].Config["url"])

	// Verify tools
	assert.GreaterOrEqual(t, len(config.Tools), 2)
}

func TestConverter_ConvertFromYAMLOpenapi2(t *testing.T) {
	converter := NewConverter()

	// Test with a simple Swagger specification in YAML
	spec := `swagger: '2.0'
info:
  title: Test API
  description: Test API description
  version: 1.0.0
host: api.example.com
basePath: /v1
schemes:
  - https
paths:
  /test:
    get:
      summary: Test endpoint
      responses:
        200:
          description: Successful response
    options:
      summary: CORS options
      responses:
        200:
          description: CORS headers`

	config, err := converter.ConvertFromYAML([]byte(spec))
	assert.NoError(t, err)
	assert.NotNil(t, config)

	// Verify the converted configuration
	assert.Equal(t, 1, len(config.Routers))
	assert.True(t, strings.HasPrefix(config.Routers[0].Prefix, "/gateway/"))
	assert.NotNil(t, config.Routers[0].CORS)

	assert.Equal(t, 1, len(config.Servers))
	assert.Equal(t, "Test API description", config.Servers[0].Description)
	assert.Equal(t, "https://api.example.com/v1", config.Servers[0].Config["url"])
}

func TestConverter_ConvertOpenapi31(t *testing.T) {
	converter := NewConverter()

	// Test with a simple Swagger 2.0 specification
	spec := `{
  "openapi": "3.1.0",
  "info": {
    "title": "通用接口文档",
    "version": "0.0.1"
  },
  "servers": [
    {
      "url": "http://example.com:8080",
      "description": "Generated server url"
    }
  ],
  "paths": {
    "/api/v1/search/requests": {
      "get": {
        "tags": ["search-controller"],
        "summary": "根据关键词返回相关请求信息",
        "description": "根据输入关键词搜索并返回相关的资源请求信息。",
        "operationId": "searchRequests",
        "parameters": [
          {
            "name": "query",
            "in": "query",
            "description": "用于检索的关键字",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "成功获取请求数据",
            "content": {
              "*/*": {
                "schema": {
                  "type": "array",
                  "items": {
                    "$ref": "#/components/schemas/ResourceRequest"
                  }
                }
              }
            }
          },
          "500": {
            "description": "内部服务错误"
          }
        }
      }
    },
    "/api/v1/search/resources": {
      "get": {
        "tags": ["search-controller"],
        "summary": "根据关键词返回相关资源信息",
        "description": "根据输入关键词搜索并返回相关的资源信息。",
        "operationId": "searchResources",
        "parameters": [
          {
            "name": "query",
            "in": "query",
            "description": "用于检索的关键字",
            "required": false,
            "schema": {
              "type": "string",
              "default": "technology"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "成功获取资源数据",
            "content": {
              "*/*": {
                "schema": {
                  "type": "array",
                  "items": {
                    "$ref": "#/components/schemas/ResourceInfo"
                  }
                }
              }
            }
          },
          "500": {
            "description": "内部服务错误"
          }
        }
      }
    }
  },
  "components": {
    "schemas": {
      "ResourceRequest": {
        "type": "object",
        "description": "资源请求实体类",
        "properties": {
          "id": {
            "type": "string",
            "description": "请求编号"
          },
          "requirementName": {
            "type": "string",
            "description": "请求名称"
          },
          "unitName": {
            "type": "string",
            "description": "组织名称"
          },
          "collaborationDescription": {
            "type": "string",
            "description": "协作描述"
          }
        }
      },
      "ResourceInfo": {
        "type": "object",
        "description": "资源信息实体类",
        "properties": {
          "id": {
            "type": "string",
            "description": "资源编号"
          },
          "name": {
            "type": "string",
            "description": "资源名称"
          },
          "unitName": {
            "type": "string",
            "description": "所属组织"
          },
          "synopsis": {
            "type": "string",
            "description": "摘要信息"
          },
          "year": {
            "type": "string",
            "description": "发布年份"
          },
          "type": {
            "type": "string",
            "description": "资源类型"
          }
        }
      }
    }
  }
}`

	config, err := converter.ConvertFromJSON([]byte(spec))
	assert.NoError(t, err)
	assert.NotNil(t, config)

	// Verify the converted configuration
	assert.Equal(t, 1, len(config.Routers))
	assert.True(t, strings.HasPrefix(config.Routers[0].Prefix, "/gateway/"))
	assert.NotNil(t, config.Routers[0].CORS)

	assert.Equal(t, 1, len(config.Servers))
	assert.Equal(t, "", config.Servers[0].Description)
	assert.Equal(t, "http://example.com:8080", config.Servers[0].Config["url"])

	// Verify tools
	assert.GreaterOrEqual(t, len(config.Tools), 2)
}

func TestConverter_ConvertFromYAMLOpenapi31(t *testing.T) {
	converter := NewConverter()

	// Test with a simple Swagger specification in YAML
	spec := `openapi: 3.1.0
info:
  title: 通用接口文档
  version: 0.0.1
servers:
  - url: http://example.com:8080
    description: Generated server url
paths:
  /api/v1/search/requests:
    get:
      tags:
        - search-controller
      summary: 根据关键词返回相关请求信息
      description: 根据输入关键词搜索并返回相关的资源请求信息。
      operationId: searchRequests
      parameters:
        - name: query
          in: query
          description: 用于检索的关键字
          required: true
          schema:
            type: string
      responses:
        '200':
          description: 成功获取请求数据
          content:
            '*/*':
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/ResourceRequest'
        '500':
          description: 内部服务错误
  /api/v1/search/resources:
    get:
      tags:
        - search-controller
      summary: 根据关键词返回相关资源信息
      description: 根据输入关键词搜索并返回相关的资源信息。
      operationId: searchResources
      parameters:
        - name: query
          in: query
          description: 用于检索的关键字
          required: false
          schema:
            type: string
            default: technology
      responses:
        '200':
          description: 成功获取资源数据
          content:
            '*/*':
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/ResourceInfo'
        '500':
          description: 内部服务错误
components:
  schemas:
    ResourceRequest:
      type: object
      description: 资源请求实体类
      properties:
        id:
          type: string
          description: 请求编号
        requirementName:
          type: string
          description: 请求名称
        unitName:
          type: string
          description: 组织名称
        collaborationDescription:
          type: string
          description: 协作描述
    ResourceInfo:
      type: object
      description: 资源信息实体类
      properties:
        id:
          type: string
          description: 资源编号
        name:
          type: string
          description: 资源名称
        unitName:
          type: string
          description: 所属组织
        synopsis:
          type: string
          description: 摘要信息
        year:
          type: string
          description: 发布年份
        type:
          type: string
          description: 资源类型`

	config, err := converter.ConvertFromYAML([]byte(spec))
	assert.NoError(t, err)
	assert.NotNil(t, config)

	// Verify the converted configuration
	assert.Equal(t, 1, len(config.Routers))
	assert.True(t, strings.HasPrefix(config.Routers[0].Prefix, "/gateway/"))
	assert.NotNil(t, config.Routers[0].CORS)

	assert.Equal(t, 1, len(config.Servers))
	assert.Equal(t, "", config.Servers[0].Description)
	assert.Equal(t, "http://example.com:8080", config.Servers[0].Config["url"])
}

func TestConverter_ConvertWithOptions(t *testing.T) {
	converter := NewConverter()

	spec := `{
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.com"}],
        "paths": {"/ping": {"get": {"responses": {"200": {"description": "ok"}}}}}
    }`

	// tenant + prefix
	cfg, err := converter.ConvertWithOptions([]byte(spec), "tenantA", "px")
	assert.NoError(t, err)
	assert.Equal(t, "tenantA", cfg.Tenant)
	assert.Equal(t, 1, len(cfg.Routers))
	assert.True(t, strings.HasPrefix(cfg.Routers[0].Prefix, "/tenantA/px/"))

	// leading slashes should be trimmed
	cfg2, err := converter.ConvertWithOptions([]byte(spec), "/tenantB", "/pref")
	assert.NoError(t, err)
	assert.Equal(t, "tenantB", cfg2.Tenant)
	assert.True(t, strings.HasPrefix(cfg2.Routers[0].Prefix, "/tenantB/pref/"))

	// tenant only
	cfg3, err := converter.ConvertWithOptions([]byte(spec), "tenantOnly", "")
	assert.NoError(t, err)
	assert.Equal(t, "tenantOnly", cfg3.Tenant)
	assert.True(t, strings.HasPrefix(cfg3.Routers[0].Prefix, "/tenantOnly/"))

	// none: falls back to default gateway prefix
	cfg4, err := converter.ConvertWithOptions([]byte(spec), "", "")
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(cfg4.Routers[0].Prefix, "/gateway/"))
}

func TestContains(t *testing.T) {
	assert.True(t, contains([]string{"a", "b"}, "a"))
	assert.False(t, contains([]string{"a", "b"}, "c"))
	assert.False(t, contains(nil, "a"))
}

func TestBuildNestedArg(t *testing.T) {
	// Build schema: array of objects with nested object and nested array fields
	// items: {
	//   type: object,
	//   properties: {
	//     name: string,
	//     meta: { type: object, properties: { count: integer, inner: { type: object, properties: { flag: boolean } } } },
	//     tags: { type: array, items: { type: string } },
	//     children: { type: array, items: { type: object, properties: { id: string } } }
	//   }
	// }
	strType := openapi3.NewStringSchema()
	intType := openapi3.NewIntegerSchema()
	boolType := openapi3.NewBoolSchema()

	innerObj := openapi3.NewObjectSchema()
	innerObj.Properties = openapi3.Schemas{
		"flag": &openapi3.SchemaRef{Value: boolType},
	}

	metaObj := openapi3.NewObjectSchema()
	metaObj.Properties = openapi3.Schemas{
		"count": &openapi3.SchemaRef{Value: intType},
		"inner": &openapi3.SchemaRef{Value: innerObj},
	}

	tagsArray := openapi3.NewArraySchema()
	tagsArray.Items = &openapi3.SchemaRef{Value: strType}

	childObj := openapi3.NewObjectSchema()
	childObj.Properties = openapi3.Schemas{
		"id": &openapi3.SchemaRef{Value: strType},
	}
	childrenArray := openapi3.NewArraySchema()
	childrenArray.Items = &openapi3.SchemaRef{Value: childObj}

	itemObj := openapi3.NewObjectSchema()
	itemObj.Properties = openapi3.Schemas{
		"name":     &openapi3.SchemaRef{Value: strType},
		"meta":     &openapi3.SchemaRef{Value: metaObj},
		"tags":     &openapi3.SchemaRef{Value: tagsArray},
		"children": &openapi3.SchemaRef{Value: childrenArray},
	}

	top := openapi3.NewArraySchema()
	top.Items = &openapi3.SchemaRef{Value: itemObj}

	res := buildNestedArg(top)
	// Top-level must be array
	assert.Equal(t, "array", res.Type)
	assert.Nil(t, res.Properties)
	if assert.NotNil(t, res.Items) {
		// Items should be object with properties
		assert.Equal(t, "object", res.Items.Type)
		assert.NotNil(t, res.Items.Properties)

		// name: type string
		nameProp, ok := res.Items.Properties["name"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "string", nameProp["type"])

		// meta: object with nested properties
		metaProp, ok := res.Items.Properties["meta"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "object", metaProp["type"])
		metaProps, ok := metaProp["properties"].(map[string]any)
		assert.True(t, ok)
		// meta.count
		cnt, ok := metaProps["count"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "integer", cnt["type"])
		// meta.inner.flag
		inner, ok := metaProps["inner"].(map[string]any)
		assert.True(t, ok)
		innerProps, ok := inner["properties"].(map[string]any)
		assert.True(t, ok)
		flag, ok := innerProps["flag"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "boolean", flag["type"])

		// tags: array of string
		tagsProp, ok := res.Items.Properties["tags"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "array", tagsProp["type"])
		tagItems, ok := tagsProp["items"].(commoncfg.ItemsConfig)
		assert.True(t, ok)
		assert.Equal(t, "string", tagItems.Type)

		// children: array of object
		chProp, ok := res.Items.Properties["children"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "array", chProp["type"])
		chItems, ok := chProp["items"].(commoncfg.ItemsConfig)
		assert.True(t, ok)
		assert.Equal(t, "object", chItems.Type)
		assert.NotNil(t, chItems.Properties)
		cid, ok := chItems.Properties["id"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "string", cid["type"])
	}
}

func TestConverter_Convert_ParamsAndBodyMapping(t *testing.T) {
	converter := NewConverter()

	// Spec covers: missing operationId -> generated, path/query/header params, requestBody json schema
	spec := `{
      "openapi": "3.0.0",
      "info": {"title": "ParamBody API", "version": "1.0.0"},
      "servers": [{"url": "https://svc.example"}],
      "paths": {
        "/users/{id}": {
          "post": {
            "summary": "update user",
            "parameters": [
              {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}},
              {"name": "q", "in": "query", "required": true, "schema": {"type": "string"}},
              {"name": "X-Custom", "in": "header", "required": false, "schema": {"type": "string"}}
            ],
            "requestBody": {
              "required": true,
              "content": {
                "application/json": {
                  "schema": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                      "name": {"type": "string"},
                      "tags": {"type": "array", "items": {"type": "string"}}
                    }
                  }
                }
              }
            },
            "responses": {"200": {"description": "ok"}}
          }
        }
      }
    }`

	cfg, err := converter.ConvertFromJSON([]byte(spec))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(cfg.Tools))
	tool := cfg.Tools[0]

	// operationId should be generated as: post_users_argid
	assert.Equal(t, "post_users_argid", tool.Name)

	// Default headers plus mapped header param
	assert.Equal(t, "application/json", tool.Headers["Content-Type"])
	assert.Equal(t, "{{.Request.Headers.Authorization}}", tool.Headers["Authorization"])
	assert.Equal(t, "{{.Args.X-Custom}}", tool.Headers["X-Custom"])

	// Endpoint path param substituted
	assert.Equal(t, "{{.Config.url}}/users/{{.Args.id}}", tool.Endpoint)

	// Validate key properties without depending on body args order
	// First two should be path and query
	if assert.GreaterOrEqual(t, len(tool.Args), 2) {
		assert.Equal(t, "id", tool.Args[0].Name)
		assert.Equal(t, "path", tool.Args[0].Position)
		assert.True(t, tool.Args[0].Required)

		assert.Equal(t, "q", tool.Args[1].Name)
		assert.Equal(t, "query", tool.Args[1].Position)
	}
	// Header should be present as last one
	assert.Equal(t, "X-Custom", tool.Args[len(tool.Args)-1].Name)
	assert.Equal(t, "header", tool.Args[len(tool.Args)-1].Position)

	// Body args: existence check
	hasName := false
	hasTags := false
	for _, a := range tool.Args {
		if a.Name == "name" && a.Position == "body" {
			hasName = true
		}
		if a.Name == "tags" && a.Position == "body" {
			hasTags = true
		}
	}
	assert.True(t, hasName)
	assert.True(t, hasTags)

	// Body template should render toJSON for body args
	assert.Contains(t, tool.RequestBody, `"name": {{ toJSON .Args.name}}`)
	assert.Contains(t, tool.RequestBody, `"tags": {{ toJSON .Args.tags}}`)
}

func TestConverter_Convert_SkipOptionsAndKeepSummaryAsDescription(t *testing.T) {
	converter := NewConverter()

	spec := `{
      "openapi": "3.0.0",
      "info": {"title": "SkipOptions API", "version": "1.0.0"},
      "servers": [{"url": "https://svc.example"}],
      "paths": {
        "/ping": {
          "options": {"summary": "cors", "responses": {"200": {"description": "ok"}}},
          "get": {"summary": "ping", "responses": {"200": {"description": "pong"}}}
        }
      }
    }`

	cfg, err := converter.ConvertFromJSON([]byte(spec))
	assert.NoError(t, err)
	assert.Len(t, cfg.Tools, 1)
	// Ensure GET tool is present with summary used as description
	found := false
	for _, tcfg := range cfg.Tools {
		if strings.HasSuffix(tcfg.Endpoint, "/ping") && strings.ToLower(tcfg.Method) == "get" {
			assert.Equal(t, "ping", tcfg.Description)
			found = true
		}
	}
	assert.True(t, found)
}
