package state

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/core/mcpproxy"
	"github.com/amoylab/unla/internal/template"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/ifuryst/lol"
	"go.uber.org/zap"
)

type (
	uriPrefix  string
	toolName   string
	promptName string

	// State contains all the read-only shared state
	State struct {
		rawConfigs []*config.MCPConfig
		runtime    map[uriPrefix]runtimeUnit
		metrics    metrics
	}

	runtimeUnit struct {
		protoType cnst.ProtoType
		router    *config.RouterConfig
		server    *config.ServerConfig
		mcpServer *config.MCPServerConfig
		transport mcpproxy.Transport

		tools       map[toolName]*config.ToolConfig
		toolSchemas []mcp.ToolSchema

		prompts       map[promptName]*config.PromptConfig
		promptSchemas []mcp.PromptSchema
	}

	metrics struct {
		totalTools      int
		missingTools    int
		httpServers     int
		mcpServers      int
		idleHTTPServers int
		idleMCPServers  int
	}
)

func NewState() *State {
	return &State{
		rawConfigs: make([]*config.MCPConfig, 0),
		runtime:    make(map[uriPrefix]runtimeUnit),
		metrics:    metrics{},
	}
}

func headersEqual(a, b map[string]string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// BuildStateFromConfig creates a new State from the given configuration
func BuildStateFromConfig(ctx context.Context, cfgs []*config.MCPConfig, oldState *State, logger *zap.Logger) (*State, error) {
	// Create new state
	newState := NewState()
	newState.rawConfigs = cfgs

	for _, cfg := range cfgs {
		toolMap := make(map[toolName]*config.ToolConfig)
		// Initialize tool map and list for MCP servers
		for _, tool := range cfg.Tools {
			newState.metrics.totalTools++
			toolMap[toolName(tool.Name)] = &tool
		}

		// Build prefix to tools mapping for MCP servers
		prefixMap := make(map[string][]string)
		// Support multiple prefixes for a single server
		for _, router := range cfg.Routers {
			prefixMap[router.Server] = append(prefixMap[router.Server], router.Prefix)
			newState.setRouter(router.Prefix, &router)
			logger.Info("registered router",
				zap.String("tenant", cfg.Tenant),
				zap.String("prefix", router.Prefix),
				zap.String("server", router.Server))
		}

		for k, v := range prefixMap {
			prefixMap[k] = lol.UniqSlice(v)
		}

		// Process regular HTTP servers
		for _, server := range cfg.Servers {
			newState.metrics.httpServers++
			prefixes, ok := prefixMap[server.Name]
			if !ok {
				newState.metrics.idleHTTPServers++
				logger.Warn("failed to find prefix for server", zap.String("server", server.Name))
				continue
			}

			var (
				allowedToolSchemas []mcp.ToolSchema
				allowedTools       = make(map[toolName]*config.ToolConfig)
			)
			for _, ss := range server.AllowedTools {
				tool, ok := toolMap[toolName(ss)]
				if ok {
					allowedToolSchemas = append(allowedToolSchemas, tool.ToToolSchema())
					allowedTools[toolName(ss)] = tool
				} else {
					newState.metrics.missingTools++
					logger.Warn("failed to find allowed tool for server", zap.String("server", server.Name),
						zap.String("tool", ss))
				}
			}

			// Process each prefix for this server
			for _, prefix := range prefixes {
				runtime := newState.getRuntime(prefix)
				runtime.protoType = cnst.BackendProtoHttp
				runtime.server = &server
				runtime.tools = allowedTools
				runtime.toolSchemas = allowedToolSchemas
				//runtime.prompts = map[promptName]*cfg.Prompts
				for i := range cfg.Prompts {
					p := &cfg.Prompts[i]
					runtime.prompts[promptName(p.Name)] = p
				}
				//runtime.promptSchemas = cfg.Prompts.ToPromptSchemas()
				runtime.promptSchemas = make([]mcp.PromptSchema, len(cfg.Prompts))
				for i, p := range cfg.Prompts {
					runtime.promptSchemas[i] = p.ToPromptSchema()
				}
				newState.runtime[uriPrefix(prefix)] = runtime
			}
		}

		// Process MCP servers
		for _, mcpServer := range cfg.McpServers {
			newState.metrics.mcpServers++
			prefixes, exists := prefixMap[mcpServer.Name]
			if !exists {
				newState.metrics.idleMCPServers++
				logger.Warn("failed to find prefix for mcp server", zap.String("server", mcpServer.Name))
				continue // Skip MCP servers without router prefix
			}

			// Process each prefix for this MCP server
			for _, prefix := range prefixes {
				runtime := newState.getRuntime(prefix)
				runtime.mcpServer = &mcpServer

				// Check if we already have transport with the same configuration
				var transport mcpproxy.Transport
				if oldState != nil {
					if oldRuntime, exists := oldState.runtime[uriPrefix(prefix)]; exists {
						// Compare configurations to see if we need to create a new transport
						oldConfig := oldRuntime.mcpServer
						if oldConfig != nil && oldConfig.Type == mcpServer.Type &&
							oldConfig.Command == mcpServer.Command &&
							oldConfig.URL == mcpServer.URL &&
							len(oldConfig.Args) == len(mcpServer.Args) {
							// Compare args
							argsMatch := true
							for i, arg := range oldConfig.Args {
								if arg != mcpServer.Args[i] {
									argsMatch = false
									break
								}
							}
							if argsMatch && headersEqual(oldConfig.Headers, mcpServer.Headers) {
								// Reuse existing transport
								transport = oldRuntime.transport
							}
						}
					}
				}

				// Create new transport if needed
				if transport == nil {
					var err error
					transport, err = mcpproxy.NewTransport(mcpServer)
					if err != nil {
						return nil, fmt.Errorf("failed to create transport for server %s: %w", mcpServer.Name, err)
					}
				}

				// Handle server startup based on policy and preinstalled flag
				if mcpServer.Policy == cnst.PolicyOnStart {
					// If PolicyOnStart is set, just start the server and keep it running
					go startMCPServer(ctx, logger, prefix, mcpServer, transport, false)
				} else if mcpServer.Preinstalled {
					// If Preinstalled is set but not PolicyOnStart, verify installation by starting and stopping
					go startMCPServer(ctx, logger, prefix, mcpServer, transport, true)
				}
				runtime.transport = transport

				// Map protocol type based on server type
				switch mcpServer.Type {
				case cnst.BackendProtoStdio.String():
					runtime.protoType = cnst.BackendProtoStdio
				case cnst.BackendProtoSSE.String():
					runtime.protoType = cnst.BackendProtoSSE
				case cnst.BackendProtoStreamable.String():
					runtime.protoType = cnst.BackendProtoStreamable
				}
				newState.runtime[uriPrefix(prefix)] = runtime
			}
		}
	}

	if oldState != nil {
		for prefix, oldRuntime := range oldState.runtime {
			if _, stillExists := newState.runtime[prefix]; !stillExists {
				if oldRuntime.mcpServer == nil {
					continue
				}
				if oldRuntime.transport == nil {
					logger.Info("transport already stopped", zap.String("prefix", string(prefix)),
						zap.String("command", oldRuntime.mcpServer.Command), zap.Strings("args", oldRuntime.mcpServer.Args))
					continue
				}
				logger.Info("shutting down unused transport", zap.String("prefix", string(prefix)),
					zap.String("command", oldRuntime.mcpServer.Command), zap.Strings("args", oldRuntime.mcpServer.Args))
				if err := oldRuntime.transport.Stop(ctx); err != nil {
					logger.Warn("failed to close old transport", zap.String("prefix", string(prefix)),
						zap.Error(err), zap.String("command", oldRuntime.mcpServer.Command),
						zap.Strings("args", oldRuntime.mcpServer.Args))
				}
			}
		}
	}

	return newState, nil
}

func startMCPServer(ctx context.Context, logger *zap.Logger, prefix string, mcpServer config.MCPServerConfig,
	transport mcpproxy.Transport, needStop bool) {
	// If Preinstalled is set but not PolicyOnStart, verify installation by starting and stopping
	if transport.IsRunning() {
		logger.Info("server already started, don't need to preinstall",
			zap.String("prefix", prefix),
			zap.String("command", mcpServer.Command),
			zap.Strings("args", mcpServer.Args))
		return
	}

	// Create a new context to avoid being canceled when the main context is canceled during shutdown
	startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := transport.Start(startCtx, template.NewContext()); err != nil {
		logger.Error("failed to start server for preinstall",
			zap.String("prefix", prefix),
			zap.String("command", mcpServer.Command),
			zap.Strings("args", mcpServer.Args),
			zap.Error(err))
	} else {
		logger.Info("server started for preinstall",
			zap.String("prefix", prefix),
			zap.String("command", mcpServer.Command),
			zap.Strings("args", mcpServer.Args))

		if needStop {
			// Stop the server after successful start
			if err := transport.Stop(startCtx); err != nil {
				logger.Error("failed to stop server for preinstall",
					zap.String("prefix", prefix),
					zap.String("command", mcpServer.Command),
					zap.Strings("args", mcpServer.Args),
					zap.Error(err))
			} else {
				logger.Info("server stopped for preinstall",
					zap.String("prefix", prefix),
					zap.String("command", mcpServer.Command),
					zap.Strings("args", mcpServer.Args))
			}
		}
	}
}
