package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/pkg/utils"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/amoylab/unla/internal/common/config"
)

// RedisNotifier implements Notifier using Redis streams
type RedisNotifier struct {
	logger     *zap.Logger
	client     redis.UniversalClient
	streamName string
	role       config.NotifierRole
}

// NewRedisNotifier creates a new Redis-based notifier
func NewRedisNotifier(logger *zap.Logger, clusterType, addr, masterName, username, password string, db int, streamName string, role config.NotifierRole) (*RedisNotifier, error) {
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

	notifier := &RedisNotifier{
		logger:     logger.Named("notifier.redis"),
		client:     client,
		streamName: streamName,
		role:       role,
	}

	return notifier, nil
}

// Watch implements Notifier.Watch
func (r *RedisNotifier) Watch(ctx context.Context) (<-chan *config.MCPConfig, error) {
	if !r.CanReceive() {
		return nil, cnst.ErrNotReceiver
	}

	ch := make(chan *config.MCPConfig, 10)

	go func() {
		defer close(ch)

		// Start from the latest message ($ means read only new messages)
		lastID := "$"

		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Use XREAD instead of XREADGROUP to ensure all instances get messages
				// Each instance will read from the latest position independently
				streams, err := r.client.XRead(ctx, &redis.XReadArgs{
					Streams: []string{r.streamName, lastID},
					Count:   1,
					Block:   1 * time.Second,
				}).Result()

				if err != nil {
					if !errors.Is(err, redis.Nil) {
						r.logger.Error("failed to read from stream", zap.Error(err))
					}
					continue
				}

				for _, stream := range streams {
					for _, message := range stream.Messages {
						// Update lastID to the current message ID for next read
						lastID = message.ID

						if configData, exists := message.Values["config"]; exists {
							var cfg config.MCPConfig
							if err := json.Unmarshal([]byte(configData.(string)), &cfg); err == nil {
								select {
								case ch <- &cfg:
									r.logger.Debug("config notification sent",
										zap.String("messageID", message.ID))
								case <-ctx.Done():
									return
								}
							} else {
								r.logger.Error("failed to unmarshal config", zap.Error(err))
							}
						}
					}
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

	// Add message to stream with MAXLEN 1 to keep only the latest message
	_, err = r.client.XAdd(ctx, &redis.XAddArgs{
		Stream: r.streamName,
		MaxLen: 1,     // Keep only the latest message
		Approx: false, // Exact length limit
		Values: map[string]interface{}{
			"config":    string(data),
			"timestamp": time.Now().Unix(),
		},
	}).Result()

	if err != nil {
		return fmt.Errorf("failed to add message to stream: %w", err)
	}

	return nil
}

// CanReceive returns true if the notifier can receive updates
func (r *RedisNotifier) CanReceive() bool {
	return r.role == config.RoleReceiver || r.role == config.RoleBoth
}

// CanSend returns true if the notifier can send updates
func (r *RedisNotifier) CanSend() bool {
	return r.role == config.RoleSender || r.role == config.RoleBoth
}
