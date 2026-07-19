package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestProxyExampleConfigs(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	configPattern := filepath.Join(filepath.Dir(filename), "..", "..", "..", "configs", "proxy-*.yaml")
	paths, err := filepath.Glob(configPattern)
	require.NoError(t, err)
	require.NotEmpty(t, paths)

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			contents, err := os.ReadFile(path)
			require.NoError(t, err)

			var cfg MCPConfig
			require.NoError(t, yaml.Unmarshal(contents, &cfg))
			require.NoError(t, ValidateMCPConfig(&cfg))
		})
	}
}
