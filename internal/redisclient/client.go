// Package redisclient constructs Redis clients for an explicitly configured deployment mode.
package redisclient

import (
	"fmt"
	"strings"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/redis/go-redis/v9"
)

// New constructs a client without opening a connection. The caller owns connection
// checks and must close the client, including when initialization fails.
//
// +spec=`The configured mode determines the Redis client type regardless of seed count.`
// +why=`A single seed is sufficient to discover a cluster; address-count inference silently creates a standalone client.`
// +link=component://docs/redis-client-modes.md
func New(mode string, options redis.UniversalOptions) (redis.UniversalClient, error) {
	if mode == "" {
		mode = cnst.RedisClusterTypeSingle
	}
	switch mode {
	case cnst.RedisClusterTypeSingle, cnst.RedisClusterTypeSentinel, cnst.RedisClusterTypeCluster:
	default:
		return nil, fmt.Errorf("unsupported Redis mode %q", mode)
	}

	var addrs []string
	for _, addr := range options.Addrs {
		for _, part := range strings.FieldsFunc(addr, func(r rune) bool { return r == ',' || r == ';' }) {
			if part = strings.TrimSpace(part); part != "" {
				addrs = append(addrs, part)
			}
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("Redis mode %q requires at least one address", mode)
	}
	options.Addrs = addrs

	switch mode {
	case cnst.RedisClusterTypeSingle:
		if len(addrs) != 1 {
			return nil, fmt.Errorf("Redis mode %q requires one address, got %d", mode, len(addrs))
		}
		return redis.NewClient(options.Simple()), nil
	case cnst.RedisClusterTypeSentinel:
		if strings.TrimSpace(options.MasterName) == "" {
			return nil, fmt.Errorf("Redis mode %q requires master_name", mode)
		}
		return redis.NewFailoverClient(options.Failover()), nil
	default:
		// ClusterOptions has no DB: preserve the existing behavior of ignoring
		// the configured DB in cluster mode.
		return redis.NewClusterClient(options.Cluster()), nil
	}
}
