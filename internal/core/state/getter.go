package state

import (
	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/core/mcpproxy"
	"github.com/amoylab/unla/pkg/mcp"
)

func (s *State) getRuntime(prefix string) runtimeUnit {
	runtime, ok := s.runtime[uriPrefix(prefix)]
	if !ok {
		return runtimeUnit{
			tools:       make(map[toolName]*config.ToolConfig),
			toolSchemas: make([]mcp.ToolSchema, 0),
			prompts:       make(map[promptName]*config.PromptConfig),
			promptSchemas: make([]mcp.PromptSchema, 0),
		}
	}
	return runtime
}

func (s *State) setRouter(prefix string, router *config.RouterConfig) {
	runtime := s.getRuntime(prefix)
	runtime.router = router
	s.runtime[uriPrefix(prefix)] = runtime
}

func (s *State) GetCORS(prefix string) *config.CORSConfig {
	runtime, ok := s.runtime[uriPrefix(prefix)]
	if ok && runtime.router != nil {
		return runtime.router.CORS
	}
	return nil
}

func (s *State) GetRouterCount() int {
	count := 0
	for _, runtime := range s.runtime {
		if runtime.router != nil {
			count++
		}
	}
	return count
}

func (s *State) GetToolCount() int {
	return s.metrics.totalTools
}

func (s *State) GetMissingToolCount() int {
	return s.metrics.missingTools
}

func (s *State) GetServerCount() int {
	count := 0
	for _, runtime := range s.runtime {
		if runtime.server != nil {
			count++
		}
	}
	return count
}

func (s *State) GetTool(prefix, name string) *config.ToolConfig {
	runtime, ok := s.runtime[uriPrefix(prefix)]
	if !ok {
		return nil
	}
	return runtime.tools[toolName(name)]
}

func (s *State) GetToolSchemas(prefix string) []mcp.ToolSchema {
	runtime, ok := s.runtime[uriPrefix(prefix)]
	if !ok {
		return nil
	}
	return runtime.toolSchemas
}

func (s *State) GetServerConfig(prefix string) *config.ServerConfig {
	runtime, ok := s.runtime[uriPrefix(prefix)]
	if !ok {
		return nil
	}
	return runtime.server
}

func (s *State) GetProtoType(prefix string) cnst.ProtoType {
	runtime, ok := s.runtime[uriPrefix(prefix)]
	if !ok {
		return ""
	}
	return runtime.protoType
}

func (s *State) GetTransport(prefix string) mcpproxy.Transport {
	runtime, ok := s.runtime[uriPrefix(prefix)]
	if !ok {
		return nil
	}
	return runtime.transport
}

func (s *State) GetTransports() map[string]mcpproxy.Transport {
	transports := make(map[string]mcpproxy.Transport)
	for prefix, runtime := range s.runtime {
		if runtime.transport != nil {
			transports[string(prefix)] = runtime.transport
		}
	}
	return transports
}

func (s *State) GetRawConfigs() []*config.MCPConfig {
	return s.rawConfigs
}

func (s *State) GetAuth(prefix string) *config.Auth {
	runtime, ok := s.runtime[uriPrefix(prefix)]
	if !ok || runtime.router == nil {
		return nil
	}
	return runtime.router.Auth
}

func (s *State) GetSSEPrefix(prefix string) string {
	runtime, ok := s.runtime[uriPrefix(prefix)]
	if ok && runtime.router != nil {
		return runtime.router.SSEPrefix
	}
	return ""
}

func (s *State) GetPrompt(prefix, name string) *config.PromptConfig {
	runtime, ok := s.runtime[uriPrefix(prefix)]
	if !ok {
		return nil
	}
	return runtime.prompts[promptName(name)]
}

func (s *State) GetPromptSchemas(prefix string) []mcp.PromptSchema {
	runtime, ok := s.runtime[uriPrefix(prefix)]
	if !ok {
		return nil
	}
	return runtime.promptSchemas
}