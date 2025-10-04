package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/errorx"
	"github.com/amoylab/unla/pkg/utils"
)

// RedisStorage implements the Store interface using Redis
type RedisStorage struct {
	client redis.UniversalClient
}

// NewRedisStorage creates a new Redis storage instance
func NewRedisStorage(clusterType, addr, masterName string, username, password string, db int) (*RedisStorage, error) {
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
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisStorage{
		client: client,
	}, nil
}

// key prefixes for different types of data
const (
	clientPrefix            = "oauth:client:"
	authorizationCodePrefix = "oauth:code:"
	tokenPrefix             = "oauth:token:"
)

// GetClient retrieves a client by ID
func (s *RedisStorage) GetClient(ctx context.Context, clientID string) (*Client, error) {
	data, err := s.client.Get(ctx, clientPrefix+clientID).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errorx.ErrInvalidClient
		}
		return nil, err
	}

	var client Client
	if err := json.Unmarshal(data, &client); err != nil {
		return nil, err
	}
	return &client, nil
}

// CreateClient creates a new client
func (s *RedisStorage) CreateClient(ctx context.Context, client *Client) error {
	// Check if client already exists
	exists, err := s.client.Exists(ctx, clientPrefix+client.ID).Result()
	if err != nil {
		return err
	}
	if exists == 1 {
		return errorx.ErrClientAlreadyExists
	}

	now := time.Now().Unix()
	client.CreatedAt = now
	client.UpdatedAt = now

	data, err := json.Marshal(client)
	if err != nil {
		return err
	}

	return s.client.Set(ctx, clientPrefix+client.ID, data, 0).Err()
}

// UpdateClient updates an existing client
func (s *RedisStorage) UpdateClient(ctx context.Context, client *Client) error {
	exists, err := s.client.Exists(ctx, clientPrefix+client.ID).Result()
	if err != nil {
		return err
	}
	if exists == 0 {
		return errorx.ErrInvalidClient
	}

	client.UpdatedAt = time.Now().Unix()
	data, err := json.Marshal(client)
	if err != nil {
		return err
	}

	return s.client.Set(ctx, clientPrefix+client.ID, data, 0).Err()
}

// DeleteClient deletes a client
func (s *RedisStorage) DeleteClient(ctx context.Context, clientID string) error {
	exists, err := s.client.Exists(ctx, clientPrefix+clientID).Result()
	if err != nil {
		return err
	}
	if exists == 0 {
		return errorx.ErrInvalidClient
	}

	return s.client.Del(ctx, clientPrefix+clientID).Err()
}

// SaveAuthorizationCode saves an authorization code
func (s *RedisStorage) SaveAuthorizationCode(ctx context.Context, code *AuthorizationCode) error {
	code.CreatedAt = time.Now().Unix()
	data, err := json.Marshal(code)
	if err != nil {
		return err
	}

	ttl := time.Duration(code.ExpiresAt-code.CreatedAt) * time.Second
	return s.client.Set(ctx, authorizationCodePrefix+code.Code, data, ttl).Err()
}

// GetAuthorizationCode retrieves an authorization code
func (s *RedisStorage) GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	data, err := s.client.Get(ctx, authorizationCodePrefix+code).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errorx.ErrInvalidGrant
		}
		return nil, err
	}

	var authCode AuthorizationCode
	if err := json.Unmarshal(data, &authCode); err != nil {
		return nil, err
	}

	if authCode.ExpiresAt < time.Now().Unix() {
		s.client.Del(ctx, authorizationCodePrefix+code)
		return nil, errorx.ErrAuthorizationCodeExpired
	}

	return &authCode, nil
}

// DeleteAuthorizationCode deletes an authorization code
func (s *RedisStorage) DeleteAuthorizationCode(ctx context.Context, code string) error {
	exists, err := s.client.Exists(ctx, authorizationCodePrefix+code).Result()
	if err != nil {
		return err
	}
	if exists == 0 {
		return errorx.ErrInvalidGrant
	}

	return s.client.Del(ctx, authorizationCodePrefix+code).Err()
}

// SaveToken saves a token
func (s *RedisStorage) SaveToken(ctx context.Context, token *Token) error {
	token.CreatedAt = time.Now().Unix()
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	ttl := time.Duration(token.ExpiresAt-token.CreatedAt) * time.Second
	return s.client.Set(ctx, tokenPrefix+token.AccessToken, data, ttl).Err()
}

// GetToken retrieves a token
func (s *RedisStorage) GetToken(ctx context.Context, accessToken string) (*Token, error) {
	data, err := s.client.Get(ctx, tokenPrefix+accessToken).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errorx.ErrInvalidGrant
		}
		return nil, err
	}

	var token Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}

	if token.ExpiresAt < time.Now().Unix() {
		s.client.Del(ctx, tokenPrefix+accessToken)
		return nil, errorx.ErrTokenExpired
	}

	return &token, nil
}

// DeleteToken deletes a token
func (s *RedisStorage) DeleteToken(ctx context.Context, accessToken string) error {
	exists, err := s.client.Exists(ctx, tokenPrefix+accessToken).Result()
	if err != nil {
		return err
	}
	if exists == 0 {
		return errorx.ErrInvalidGrant
	}

	return s.client.Del(ctx, tokenPrefix+accessToken).Err()
}

// DeleteTokensByClientID deletes all tokens for a client
func (s *RedisStorage) DeleteTokensByClientID(ctx context.Context, clientID string) error {
	// Get all tokens
	iter := s.client.Scan(ctx, 0, tokenPrefix+"*", 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		data, err := s.client.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}

		var token Token
		if err := json.Unmarshal(data, &token); err != nil {
			continue
		}

		if token.ClientID == clientID {
			s.client.Del(ctx, key)
		}
	}

	return iter.Err()
}
