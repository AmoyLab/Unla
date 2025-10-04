package storage

import (
	"context"
	"sync"
	"time"

	"github.com/amoylab/unla/internal/common/errorx"
)

// MemoryStorage implements the Store interface using in-memory storage
type MemoryStorage struct {
	mu sync.RWMutex

	clients            map[string]*Client
	authorizationCodes map[string]*AuthorizationCode
	tokens             map[string]*Token
}

// NewMemoryStorage creates a new memory storage instance
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		clients:            make(map[string]*Client),
		authorizationCodes: make(map[string]*AuthorizationCode),
		tokens:             make(map[string]*Token),
	}
}

// GetClient retrieves a client by ID
func (s *MemoryStorage) GetClient(ctx context.Context, clientID string) (*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if client, ok := s.clients[clientID]; ok {
		return client, nil
	}
	return nil, errorx.ErrInvalidClient
}

// CreateClient creates a new client
func (s *MemoryStorage) CreateClient(ctx context.Context, client *Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[client.ID]; exists {
		return errorx.ErrClientAlreadyExists
	}

	now := time.Now().Unix()
	client.CreatedAt = now
	client.UpdatedAt = now
	s.clients[client.ID] = client
	return nil
}

// UpdateClient updates an existing client
func (s *MemoryStorage) UpdateClient(ctx context.Context, client *Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[client.ID]; !exists {
		return errorx.ErrInvalidClient
	}

	client.UpdatedAt = time.Now().Unix()
	s.clients[client.ID] = client
	return nil
}

// DeleteClient deletes a client
func (s *MemoryStorage) DeleteClient(ctx context.Context, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[clientID]; !exists {
		return errorx.ErrInvalidClient
	}

	delete(s.clients, clientID)
	return nil
}

// SaveAuthorizationCode saves an authorization code
func (s *MemoryStorage) SaveAuthorizationCode(ctx context.Context, code *AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	code.CreatedAt = time.Now().Unix()
	s.authorizationCodes[code.Code] = code
	return nil
}

// GetAuthorizationCode retrieves an authorization code
func (s *MemoryStorage) GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	s.mu.RLock()
	authCode, ok := s.authorizationCodes[code]
	s.mu.RUnlock()

	if !ok {
		return nil, errorx.ErrInvalidGrant
	}

	// Check expiry
	if authCode.ExpiresAt < time.Now().Unix() {
		// Expired - need to delete it, so acquire write lock
		s.mu.Lock()
		// Double-check it still exists and is still expired (TOCTOU protection)
		if ac, exists := s.authorizationCodes[code]; exists && ac.ExpiresAt < time.Now().Unix() {
			delete(s.authorizationCodes, code)
		}
		s.mu.Unlock()
		return nil, errorx.ErrAuthorizationCodeExpired
	}

	return authCode, nil
}

// DeleteAuthorizationCode deletes an authorization code
func (s *MemoryStorage) DeleteAuthorizationCode(ctx context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.authorizationCodes[code]; !exists {
		return errorx.ErrInvalidGrant
	}

	delete(s.authorizationCodes, code)
	return nil
}

// SaveToken saves a token
func (s *MemoryStorage) SaveToken(ctx context.Context, token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	token.CreatedAt = time.Now().Unix()
	s.tokens[token.AccessToken] = token
	return nil
}

// GetToken retrieves a token
func (s *MemoryStorage) GetToken(ctx context.Context, accessToken string) (*Token, error) {
	s.mu.RLock()
	token, ok := s.tokens[accessToken]
	s.mu.RUnlock()

	if !ok {
		return nil, errorx.ErrInvalidGrant
	}

	// Check expiry
	if token.ExpiresAt < time.Now().Unix() {
		// Expired - need to delete it, so acquire write lock
		s.mu.Lock()
		// Double-check it still exists and is still expired (TOCTOU protection)
		if t, exists := s.tokens[accessToken]; exists && t.ExpiresAt < time.Now().Unix() {
			delete(s.tokens, accessToken)
		}
		s.mu.Unlock()
		return nil, errorx.ErrTokenExpired
	}

	return token, nil
}

// DeleteToken deletes a token
func (s *MemoryStorage) DeleteToken(ctx context.Context, accessToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tokens[accessToken]; !exists {
		return errorx.ErrInvalidGrant
	}

	delete(s.tokens, accessToken)
	return nil
}

// DeleteTokensByClientID deletes all tokens for a client
func (s *MemoryStorage) DeleteTokensByClientID(ctx context.Context, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for tokenID, token := range s.tokens {
		if token.ClientID == clientID {
			delete(s.tokens, tokenID)
		}
	}
	return nil
}
