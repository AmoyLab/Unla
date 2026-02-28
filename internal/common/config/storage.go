package config

import "time"

type (
	StorageConfig struct {
		Type                 string           `yaml:"type"`                   // db or api
		RevisionHistoryLimit int              `yaml:"revision_history_limit"` // number of versions to keep
		Database             DatabaseConfig   `yaml:"database"`               // database configuration for db type
		API                  APIStorageConfig `yaml:"api"`                    // api configuration for api type
	}

	APIStorageConfig struct {
		Url                 string        `yaml:"url"`                 // http url for api
		ConfigJSONPath      string        `yaml:"configJSONPath"`      // configJSONPath for config in http response
		Timeout             time.Duration `yaml:"timeout"`             // timeout for http request
		IgnoreInvalidConfig bool          `yaml:"ignoreInvalidConfig"` // skip invalid config if true
	}
)
