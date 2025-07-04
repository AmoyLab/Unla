package handler

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// HandleDefaultLLMProviders returns only the default LLM provider from ENV in the required format
func (h *Chat) HandleDefaultLLMProviders(c *gin.Context) {
	apiKey := strings.TrimSpace(getEnv("OPENAI_API_KEY", ""))
	baseURL := strings.TrimSpace(getEnv("OPENAI_BASE_URL", ""))
	model := strings.TrimSpace(getEnv("OPENAI_MODEL", ""))

	var defaultProvider map[string]interface{}
	if apiKey != "" && baseURL != "" && model != "" {
		defaultProvider = map[string]interface{}{
			"id":      "custom_default", // Changed from "default" to "custom_default"
			"name":    "Default",
			"apiKey":  apiKey,
			"baseURL": baseURL,
			"model":   model,
			"enabled": true,
			"config": map[string]interface{}{ // Add default config values
				"apiKey":     apiKey,
				"baseURL":    baseURL,
			},
			"models": []map[string]interface{}{{ // Add the default model
				"id":       model,
				"name":     model,
				"isCustom": true,
			}},
			"settings": map[string]interface{}{ // Only include essential settings
				"showApiKey":        true,
				"showBaseURL":       true,
				"apiKeyRequired":    true,
				"baseURLRequired":   true,
			},
		}
	}

	var result []interface{}
	if defaultProvider != nil {
		result = append(result, defaultProvider)
	}

	c.JSON(http.StatusOK, gin.H{"configs": result})
}

func getEnv(key, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}
