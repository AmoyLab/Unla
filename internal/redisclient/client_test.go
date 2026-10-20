package redisclient

import (
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestNewDeploymentMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		options redis.UniversalOptions
		cluster bool
		addrs   []string
		db      int
	}{
		{
			name: "standalone",
			mode: "single",
			options: redis.UniversalOptions{
				Addrs: []string{"localhost:6379"}, DB: 3,
			},
			addrs: []string{"localhost:6379"}, db: 3,
		},
		{
			name: "omitted mode defaults to standalone",
			options: redis.UniversalOptions{
				Addrs: []string{"localhost:6379"},
			},
			addrs: []string{"localhost:6379"},
		},
		{
			name: "single cluster seed",
			mode: "cluster",
			options: redis.UniversalOptions{
				Addrs: []string{"localhost:6379"}, DB: 3,
			},
			cluster: true, addrs: []string{"localhost:6379"},
		},
		{
			name: "multiple cluster seeds",
			mode: "cluster",
			options: redis.UniversalOptions{
				Addrs: []string{"localhost:6379", "localhost:6380"},
			},
			cluster: true, addrs: []string{"localhost:6379", "localhost:6380"},
		},
		{
			name: "address separators and whitespace",
			mode: "cluster",
			options: redis.UniversalOptions{
				Addrs: []string{" localhost:6379, ; localhost:6380; "},
			},
			cluster: true, addrs: []string{"localhost:6379", "localhost:6380"},
		},
		{
			name: "explicit single overrides universal inference flags",
			mode: "single",
			options: redis.UniversalOptions{
				Addrs: []string{"localhost:6379"}, MasterName: "unused", IsClusterMode: true,
			},
			addrs: []string{"localhost:6379"},
		},
		{
			name: "explicit cluster ignores sentinel master",
			mode: "cluster",
			options: redis.UniversalOptions{
				Addrs: []string{"localhost:6379"}, MasterName: "unused",
			},
			cluster: true, addrs: []string{"localhost:6379"},
		},
		{
			name: "sentinel",
			mode: "sentinel",
			options: redis.UniversalOptions{
				Addrs: []string{"localhost:26379"}, MasterName: "primary", DB: 4,
			},
			db: 4,
		},
		{
			name: "multiple sentinels remain failover client",
			mode: "sentinel",
			options: redis.UniversalOptions{
				Addrs: []string{"localhost:26379", "localhost:26380"}, MasterName: "primary",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.options.Username = "data-user"
			tt.options.Password = "data-password"
			client, err := New(tt.mode, tt.options)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, client.Close()) })
			if tt.cluster {
				c, ok := client.(*redis.ClusterClient)
				require.True(t, ok, "cluster mode must create ClusterClient with any seed count")
				require.Equal(t, tt.addrs, c.Options().Addrs)
				require.Equal(t, tt.options.Username, c.Options().Username)
				require.Equal(t, tt.options.Password, c.Options().Password)
			} else {
				c, ok := client.(*redis.Client)
				require.True(t, ok, "single and sentinel modes must not create ClusterClient")
				require.Equal(t, tt.db, c.Options().DB)
				require.Equal(t, tt.options.Username, c.Options().Username)
				require.Equal(t, tt.options.Password, c.Options().Password)
				if len(tt.addrs) > 0 {
					require.Equal(t, tt.addrs[0], c.Options().Addr)
				}
			}
		})
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		options redis.UniversalOptions
		want    string
	}{
		{"unknown mode", "clustr", redis.UniversalOptions{Addrs: []string{"localhost:6379"}}, "unsupported Redis mode"},
		{"missing address", "cluster", redis.UniversalOptions{}, "requires at least one address"},
		{"empty addresses", "single", redis.UniversalOptions{Addrs: []string{" , ; "}}, "requires at least one address"},
		{"multiple standalone addresses", "single", redis.UniversalOptions{Addrs: []string{"a:6379,b:6379"}}, "requires one address"},
		{"omitted mode does not infer cluster", "", redis.UniversalOptions{Addrs: []string{"a:6379,b:6379"}}, "requires one address"},
		{"missing sentinel master", "sentinel", redis.UniversalOptions{Addrs: []string{"localhost:26379"}}, "requires master_name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(tt.mode, tt.options)
			if client != nil {
				t.Cleanup(func() { _ = client.Close() })
			}
			require.Nil(t, client)
			require.ErrorContains(t, err, tt.want)
		})
	}
}
