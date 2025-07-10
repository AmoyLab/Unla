package openapi

import (
	"strings"
	"testing"

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
