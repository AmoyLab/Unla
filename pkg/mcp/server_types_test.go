package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToolSchemaWithOutputSchema(t *testing.T) {
	// Test ToolSchema with new OutputSchema field
	outputSchema := &ToolInputSchema{
		Type: "object",
		Properties: map[string]any{
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
		Required: []string{"temperature", "conditions", "humidity"},
	}

	toolSchema := ToolSchema{
		Name:  "get_weather_data",
		Title: "Weather Data Retriever",
		Description: "Get current weather data for a location",
		InputSchema: ToolInputSchema{
			Type: "object",
			Properties: map[string]any{
				"location": map[string]any{
					"type":        "string",
					"description": "City name or zip code",
				},
			},
			Required: []string{"location"},
		},
		OutputSchema: outputSchema,
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(toolSchema)
	assert.NoError(t, err)

	// Test JSON deserialization
	var unmarshaled ToolSchema
	err = json.Unmarshal(jsonData, &unmarshaled)
	assert.NoError(t, err)

	// Verify fields are preserved
	assert.Equal(t, "get_weather_data", unmarshaled.Name)
	assert.Equal(t, "Weather Data Retriever", unmarshaled.Title)
	assert.Equal(t, "Get current weather data for a location", unmarshaled.Description)
	assert.NotNil(t, unmarshaled.OutputSchema)
	assert.Equal(t, "object", unmarshaled.OutputSchema.Type)
	assert.Len(t, unmarshaled.OutputSchema.Properties, 3)
	assert.Contains(t, unmarshaled.OutputSchema.Properties, "temperature")
	assert.Contains(t, unmarshaled.OutputSchema.Properties, "conditions")
	assert.Contains(t, unmarshaled.OutputSchema.Properties, "humidity")
	assert.Equal(t, []string{"temperature", "conditions", "humidity"}, unmarshaled.OutputSchema.Required)
}

func TestToolSchemaWithoutOutputSchema(t *testing.T) {
	// Test ToolSchema without OutputSchema (backward compatibility)
	toolSchema := ToolSchema{
		Name:        "simple_tool",
		Description: "A simple tool without output schema",
		InputSchema: ToolInputSchema{
			Type: "object",
			Properties: map[string]any{
				"param": map[string]any{
					"type": "string",
				},
			},
		},
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(toolSchema)
	assert.NoError(t, err)

	// Test JSON deserialization
	var unmarshaled ToolSchema
	err = json.Unmarshal(jsonData, &unmarshaled)
	assert.NoError(t, err)

	// Verify fields are preserved
	assert.Equal(t, "simple_tool", unmarshaled.Name)
	assert.Equal(t, "", unmarshaled.Title) // Should be empty when not provided
	assert.Equal(t, "A simple tool without output schema", unmarshaled.Description)
	assert.Nil(t, unmarshaled.OutputSchema) // Should be nil when not provided
}

func TestToolSchemaJSONFormat(t *testing.T) {
	// Test that JSON output matches expected format from the issue
	toolSchema := ToolSchema{
		Name:  "get_weather_data",
		Title: "Weather Data Retriever",
		Description: "Get current weather data for a location",
		InputSchema: ToolInputSchema{
			Type: "object",
			Properties: map[string]any{
				"location": map[string]any{
					"type":        "string",
					"description": "City name or zip code",
				},
			},
			Required: []string{"location"},
		},
		OutputSchema: &ToolInputSchema{
			Type: "object",
			Properties: map[string]any{
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
			Required: []string{"temperature", "conditions", "humidity"},
		},
	}

	jsonData, err := json.Marshal(toolSchema)
	assert.NoError(t, err)

	// Verify that the JSON contains the expected fields
	jsonStr := string(jsonData)
	assert.Contains(t, jsonStr, `"name":"get_weather_data"`)
	assert.Contains(t, jsonStr, `"title":"Weather Data Retriever"`)
	assert.Contains(t, jsonStr, `"inputSchema"`)
	assert.Contains(t, jsonStr, `"outputSchema"`)
	assert.Contains(t, jsonStr, `"temperature"`)
	assert.Contains(t, jsonStr, `"conditions"`)
	assert.Contains(t, jsonStr, `"humidity"`)
}