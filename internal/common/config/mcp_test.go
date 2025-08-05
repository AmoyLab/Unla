package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToolConfigToToolSchema(t *testing.T) {
	// Test ToolConfig with Title and OutputSchema
	toolConfig := ToolConfig{
		Name:        "get_weather_data",
		Title:       "Weather Data Retriever",
		Description: "Get current weather data for a location",
		Method:      "GET",
		Endpoint:    "https://api.weather.com/data",
		Args: []ArgConfig{
			{
				Name:        "location",
				Type:        "string",
				Description: "City name or zip code",
				Required:    true,
			},
		},
		OutputSchema: map[string]any{
			"temperature": map[string]any{
				"type":        "number",
				"description": "Temperature in celsius",
			},
			"conditions": map[string]any{
				"type":        "string", 
				"description": "Weather conditions description",
			},
			"humidity": map[string]any{
				"type":        "number",
				"description": "Humidity percentage",
			},
		},
	}

	toolSchema := toolConfig.ToToolSchema()

	// Verify basic fields
	assert.Equal(t, "get_weather_data", toolSchema.Name)
	assert.Equal(t, "Weather Data Retriever", toolSchema.Title)
	assert.Equal(t, "Get current weather data for a location", toolSchema.Description)

	// Verify InputSchema
	assert.Equal(t, "object", toolSchema.InputSchema.Type)
	assert.Len(t, toolSchema.InputSchema.Properties, 1)
	assert.Contains(t, toolSchema.InputSchema.Properties, "location")
	assert.Equal(t, []string{"location"}, toolSchema.InputSchema.Required)

	// Verify OutputSchema
	assert.NotNil(t, toolSchema.OutputSchema)
	assert.Equal(t, "object", toolSchema.OutputSchema.Type)
	assert.Len(t, toolSchema.OutputSchema.Properties, 3)
	assert.Contains(t, toolSchema.OutputSchema.Properties, "temperature")
	assert.Contains(t, toolSchema.OutputSchema.Properties, "conditions")
	assert.Contains(t, toolSchema.OutputSchema.Properties, "humidity")
}

func TestToolConfigToToolSchemaWithoutOutputSchema(t *testing.T) {
	// Test ToolConfig without Title and OutputSchema (backward compatibility)
	toolConfig := ToolConfig{
		Name:        "simple_tool",
		Description: "A simple tool",
		Method:      "POST",
		Endpoint:    "https://api.example.com/tool",
		Args: []ArgConfig{
			{
				Name:     "param1",
				Type:     "string",
				Required: false,
			},
		},
	}

	toolSchema := toolConfig.ToToolSchema()

	// Verify basic fields
	assert.Equal(t, "simple_tool", toolSchema.Name)
	assert.Equal(t, "", toolSchema.Title) // Should be empty when not provided
	assert.Equal(t, "A simple tool", toolSchema.Description)

	// Verify InputSchema
	assert.Equal(t, "object", toolSchema.InputSchema.Type)
	assert.Len(t, toolSchema.InputSchema.Properties, 1)
	assert.Contains(t, toolSchema.InputSchema.Properties, "param1")
	assert.Empty(t, toolSchema.InputSchema.Required) // No required args

	// Verify OutputSchema is nil
	assert.Nil(t, toolSchema.OutputSchema)
}

func TestToolConfigToToolSchemaWithInputSchema(t *testing.T) {
	// Test ToolConfig that combines Args with explicit InputSchema
	toolConfig := ToolConfig{
		Name:        "mixed_tool",
		Title:       "Mixed Tool",
		Description: "A tool with both Args and InputSchema",
		Method:      "POST",
		Endpoint:    "https://api.example.com/mixed",
		Args: []ArgConfig{
			{
				Name:        "arg1",
				Type:        "string",
				Description: "First argument",
				Required:    true,
			},
		},
		InputSchema: map[string]any{
			"custom_field": map[string]any{
				"type":        "number",
				"description": "Custom field from InputSchema",
			},
		},
		OutputSchema: map[string]any{
			"result": map[string]any{
				"type": "string",
			},
		},
	}

	toolSchema := toolConfig.ToToolSchema()

	// Verify both arg-generated and explicit InputSchema properties are present
	assert.Equal(t, "object", toolSchema.InputSchema.Type)
	assert.Len(t, toolSchema.InputSchema.Properties, 2)
	assert.Contains(t, toolSchema.InputSchema.Properties, "arg1")
	assert.Contains(t, toolSchema.InputSchema.Properties, "custom_field")
	assert.Equal(t, []string{"arg1"}, toolSchema.InputSchema.Required)

	// Verify OutputSchema
	assert.NotNil(t, toolSchema.OutputSchema)
	assert.Equal(t, "object", toolSchema.OutputSchema.Type)
	assert.Len(t, toolSchema.OutputSchema.Properties, 1)
	assert.Contains(t, toolSchema.OutputSchema.Properties, "result")
}