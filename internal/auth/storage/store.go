package storage

import (
	"context"
)

// Store defines the interface for OAuth2 data storage
type Store interface {
	GetClient(ctx context.Context, clientID string) (*Client, error)
	CreateClient(ctx context.Context, client *Client) error
	UpdateClient(ctx context.Context, client *Client) error
	DeleteClient(ctx context.Context, clientID string) error

	SaveAuthorizationCode(ctx context.Context, code *AuthorizationCode) error
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
	DeleteAuthorizationCode(ctx context.Context, code string) error

	SaveToken(ctx context.Context, token *Token) error
	GetToken(ctx context.Context, accessToken string) (*Token, error)
	DeleteToken(ctx context.Context, accessToken string) error
	DeleteTokensByClientID(ctx context.Context, clientID string) error
}

// Client represents an OAuth2 client
type Client struct {
	ID              string   `json:"client_id"`
	Secret          string   `json:"client_secret"`
	RedirectURIs    []string `json:"redirect_uris"`
	GrantTypes      []string `json:"grant_types"`
	ResponseTypes   []string `json:"response_types"`
	TokenAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope           string   `json:"scope"`
	CreatedAt       int64    `json:"created_at"`
	UpdatedAt       int64    `json:"updated_at"`
}

// AuthorizationCode represents an authorization code
type AuthorizationCode struct {
	Code                string   `json:"code"`
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	Scope               []string `json:"scope"`
	CodeChallenge       string   `json:"code_challenge,omitempty"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty"`
	ExpiresAt           int64    `json:"expires_at"`
	CreatedAt           int64    `json:"created_at"`
}

// Token represents an OAuth2 token
type Token struct {
	AccessToken  string   `json:"access_token"`
	TokenType    string   `json:"token_type"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	ClientID     string   `json:"client_id"`
	Scope        []string `json:"scope"`
	ExpiresAt    int64    `json:"expires_at"`
	CreatedAt    int64    `json:"created_at"`
}
