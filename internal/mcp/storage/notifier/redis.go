package notifier

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/pkg/utils"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/amoylab/unla/internal/common/config"
)

// RedisNotifier implements Notifier using Redis pub/sub
type RedisNotifier struct {
	logger *zap.Logger
	client redis.UniversalClient
	topic  string
	role   config.NotifierRole
}

// NewRedisNotifier creates a new Redis-based notifier
func NewRedisNotifier(logger *zap.Logger, clusterType, addr, masterName, username, password string, db int, topic string, role config.NotifierRole) (*RedisNotifier, error) {
	addrs := utils.SplitByMultipleDelimiters(addr, ";", ",")
	redisOptions := &redis.UniversalOptions{
		Addrs:    addrs,
		Username: username,
		Password: password,
	}
	if clusterType == cnst.RedisClusterTypeSentinel {
		redisOptions.MasterName = masterName
	}
	if clusterType != cnst.RedisClusterTypeCluster {
		// can not set db in cluster mode
		redisOptions.DB = db
	}
	client := redis.NewUniversalClient(redisOptions)

	// Test connection
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisNotifier{
		logger: logger.Named("notifier.redis"),
		client: client,
		topic:  topic,
		role:   role,
	}, nil
}

// Watch implements Notifier.Watch
func (r *RedisNotifier) Watch(ctx context.Context) (<-chan *config.MCPConfig, error) {
	if !r.CanReceive() {
		return nil, cnst.ErrNotReceiver
	}

	ch := make(chan *config.MCPConfig, 10)

	pubsub := r.client.Subscribe(ctx, r.topic)
	go func() {
		defer close(ch)
		defer pubsub.Close()

		for msg := range pubsub.Channel() {
			var cfg config.MCPConfig
			if err := json.Unmarshal([]byte(msg.Payload), &cfg); err == nil {
				select {
				case ch <- &cfg:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return ch, nil
}

// NotifyUpdate implements Notifier.NotifyUpdate
func (r *RedisNotifier) NotifyUpdate(ctx context.Context, server *config.MCPConfig) error {
	if !r.CanSend() {
		return cnst.ErrNotSender
	}

	data, err := json.Marshal(server)
	if err != nil {
		return fmt.Errorf("failed to marshal server config: %w", err)
	}

	return r.client.Publish(ctx, r.topic, data).Err()
}

// CanReceive returns true if the notifier can receive updates
func (r *RedisNotifier) CanReceive() bool {
	return r.role == config.RoleReceiver || r.role == config.RoleBoth
}

// CanSend returns true if the notifier can send updates
func (r *RedisNotifier) CanSend() bool {
	return r.role == config.RoleSender || r.role == config.RoleBoth
}
