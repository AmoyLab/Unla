package state

import (
	"context"
	"testing"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestBuildStateFromConfig_ReusesTransportWhenHeadersUnchanged(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	cfg := buildMCPConfigWithHeaders(map[string]string{"Authorization": "Bearer a"})
	oldState, err := BuildStateFromConfig(ctx, []*config.MCPConfig{cfg}, nil, logger)
	assert.NoError(t, err)

	newState, err := BuildStateFromConfig(ctx, []*config.MCPConfig{cfg}, oldState, logger)
	assert.NoError(t, err)

	assert.Same(t, oldState.GetTransport("/m"), newState.GetTransport("/m"))
}

func TestBuildStateFromConfig_RebuildsTransportWhenHeadersChange(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	oldCfg := buildMCPConfigWithHeaders(map[string]string{"Authorization": "Bearer a"})
	oldState, err := BuildStateFromConfig(ctx, []*config.MCPConfig{oldCfg}, nil, logger)
	assert.NoError(t, err)

	newCfg := buildMCPConfigWithHeaders(map[string]string{"Authorization": "Bearer b"})
	newState, err := BuildStateFromConfig(ctx, []*config.MCPConfig{newCfg}, oldState, logger)
	assert.NoError(t, err)

	assert.NotSame(t, oldState.GetTransport("/m"), newState.GetTransport("/m"))
}

func buildMCPConfigWithHeaders(headers map[string]string) *config.MCPConfig {
	return &config.MCPConfig{
		Name:   "c1",
		Tenant: "t1",
		Routers: []config.RouterConfig{{
			Server: "ms1",
			Prefix: "/m",
		}},
		McpServers: []config.MCPServerConfig{{
			Type:    cnst.BackendProtoSSE.String(),
			Name:    "ms1",
			URL:     "http://127.0.0.1:9/",
			Policy:  cnst.PolicyOnDemand,
			Headers: headers,
		}},
	}
}
