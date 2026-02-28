package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/amoylab/unla/internal/common/config"
)

func TestNewStore_DB_And_API_And_Unsupported(t *testing.T) {
	logger := zap.NewNop()

	// DB store using sqlite memory temp file via helper
	// Leverage the same config shape as newSQLiteStore
	tmp := t.TempDir()
	cfgDB := &config.StorageConfig{Type: "db", Database: config.DatabaseConfig{Type: "sqlite", DBName: tmp + "/store.db"}}
	stDB, err := NewStore(logger, cfgDB)
	assert.NoError(t, err)
	assert.NotNil(t, stDB)

	// API store
	cfgAPI := &config.StorageConfig{Type: "api", API: config.APIStorageConfig{Url: "http://127.0.0.1:1", Timeout: time.Second, IgnoreInvalidConfig: false}}
	stAPI, err := NewStore(logger, cfgAPI)
	assert.NoError(t, err)
	assert.NotNil(t, stAPI)

	// Unsupported
	stX, err := NewStore(logger, &config.StorageConfig{Type: "nope"})
	assert.Error(t, err)
	assert.Nil(t, stX)
}
