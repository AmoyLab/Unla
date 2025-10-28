package state

import (
	"context"
	"testing"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"
	"go.uber.org/zap"
)

func TestBuildStateFromConfig_MinimalHTTPAndMCP(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	cfg := &config.MCPConfig{
		Name:   "c1",
		Tenant: "t1",
		Tools: []config.ToolConfig{{
			Name:     "tool1",
			Method:   "GET",
			Endpoint: "/x",
		}},
		Servers: []config.ServerConfig{{
			Name:         "srv1",
			AllowedTools: []string{"tool1"},
		}},
		Routers: []config.RouterConfig{{
			Server: "srv1",
			Prefix: "/h",
		}, {
			Server: "ms1",
			Prefix: "/m",
		}},
		McpServers: []config.MCPServerConfig{{
			Type:   cnst.BackendProtoSSE.String(),
			Name:   "ms1",
			URL:    "http://127.0.0.1:9/", // invalid, but Start is not called
			Policy: cnst.PolicyOnDemand,
		}},
		Prompts: []config.PromptConfig{{
			Name:        "p1",
			Description: "d",
		}},
	}

	ns, err := BuildStateFromConfig(ctx, []*config.MCPConfig{cfg}, nil, logger)
	if err != nil {
		t.Fatalf("BuildStateFromConfig: %v", err)
	}
	if ns.GetProtoType("/h") != cnst.BackendProtoHttp {
		t.Fatalf("expected http proto for /h")
	}
	if ns.GetProtoType("/m") != cnst.BackendProtoSSE {
		t.Fatalf("expected sse proto for /m")
	}
}
