package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/tidwall/gjson"

	"github.com/amoylab/unla/internal/common/config"

	"go.uber.org/zap"
)

// Note: This APIStore is used to fetch MCP configuration from a remote server, it's not a universal use case,
// if you want to use it, please make sure it's compatible with your server,
// or you can easily modify it to fit your needs.

// APIStore implements the Store interface using the remote http server
type APIStore struct {
	logger *zap.Logger
	url    string
	// read config from response(json body) using gjson
	configJSONPath string
	timeout        time.Duration
}

var _ Store = (*APIStore)(nil)

// NewAPIStore creates a new api-based store
func NewAPIStore(logger *zap.Logger, url string, configJSONPath string, timeout time.Duration) (*APIStore, error) {
	logger = logger.Named("mcp.store")

	logger.Info("Using configuration url", zap.String("path", url))

	return &APIStore{
		logger:         logger,
		url:            url,
		configJSONPath: configJSONPath,
		timeout:        timeout,
	}, nil
}

// Create implements Store.Create
func (s *APIStore) Create(_ context.Context, server *config.MCPConfig) error {
	// only use for read config
	return nil
}

// Get implements Store.Get
func (s *APIStore) Get(_ context.Context, tenant, name string, includeDeleted ...bool) (*config.MCPConfig, error) {
	jsonStr, err := s.request()
	if err != nil {
		return nil, err
	}
	var data config.MCPConfig
	err = json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

// List implements Store.List
func (s *APIStore) List(_ context.Context, _ ...bool) ([]*config.MCPConfig, error) {
	jsonStr, err := s.request()
	if err != nil {
		return nil, err
	}

	//var configs []*config.MCPConfig
	//err = json.Unmarshal([]byte(jsonStr), &configs)
	//if err != nil {
	//	return nil, err
	//}

	// Unmarshal items individually (instead of the whole array) to precisely identify the failing configuration (index/name/tenant).
	var items []json.RawMessage
	if err := json.Unmarshal([]byte(jsonStr), &items); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MCP configuration array: %w", err)
	}

	configs := make([]*config.MCPConfig, 0, len(items))
	for i, raw := range items {
		var cfg config.MCPConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			var meta struct {
				Name   string `json:"name"`
				Tenant string `json:"tenant"`
			}
			_ = json.Unmarshal(raw, &meta)
			if meta.Name != "" || meta.Tenant != "" {
				s.logger.Warn("failed to unmarshal MCP configuration, skipping",
					zap.String("name", meta.Name),
					zap.String("tenant", meta.Tenant),
					zap.Int("index", i),
					zap.Error(err))
			} else {
				s.logger.Warn("failed to unmarshal MCP configuration, skipping",
					zap.Int("index", i),
					zap.Error(err))
			}
			continue // Skip failed configuration
		}
		configs = append(configs, &cfg)
	}
	return configs, nil
}

// Update implements Store.Update
func (s *APIStore) Update(_ context.Context, _ *config.MCPConfig) error {
	// only use for read config
	return nil
}

// Delete implements Store.Delete
func (s *APIStore) Delete(_ context.Context, tenant, name string) error {
	// only use for read config
	return nil
}

// GetVersion implements Store.GetVersion
func (s *APIStore) GetVersion(_ context.Context, tenant, name string, version int) (*config.MCPConfigVersion, error) {
	return nil, nil
}

// ListVersions implements Store.ListVersions
func (s *APIStore) ListVersions(_ context.Context, tenant, name string) ([]*config.MCPConfigVersion, error) {
	// API store is read-only and doesn't support versioning
	return nil, nil
}

// SetActiveVersion implements Store.SetActiveVersion
func (s *APIStore) SetActiveVersion(_ context.Context, tenant, name string, version int) error {
	// API store is read-only
	return nil
}

// DeleteVersion implements Store.DeleteVersion
func (s *APIStore) DeleteVersion(_ context.Context, tenant, name string, version int) error {
	// API store is read-only
	return nil
}

// ListUpdated implements Store.ListUpdated
func (s *APIStore) ListUpdated(_ context.Context, since time.Time) ([]*config.MCPConfig, error) {
	// API store is read-only and doesn't support versioning
	// Just return all configs as they are always up to date
	return s.List(context.Background())
}

func (s *APIStore) request() (string, error) {
	client := &http.Client{
		Timeout: s.timeout,
	}
	resp, err := client.Get(s.url)
	if err != nil {
		s.logger.Error("failed to request url",
			zap.String("url", s.url),
			zap.Error(err))
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("failed to read response",
			zap.String("url", s.url),
			zap.Error(err))
		return "", err
	}
	jsonString := string(body)
	s.logger.Debug("read storage api response", zap.String("body", jsonString))
	if s.configJSONPath == "" {
		return jsonString, nil
	}
	result := gjson.Get(jsonString, s.configJSONPath)
	if !result.Exists() {
		err = fmt.Errorf("configJSONPath is not in response: %s", s.configJSONPath)
		s.logger.Error("configJSONPath is not in response",
			zap.String("url", s.url),
			zap.Error(err))
		return "", err
	}
	return result.Raw, nil
}
