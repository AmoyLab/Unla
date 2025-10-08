package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/amoylab/unla/internal/auth/storage"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/common/errorx"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// oauth implements the auth.Auth interface
type oauth struct {
	logger *zap.Logger
	store  storage.Store
	issuer string
}

var _ OAuth2 = (*oauth)(nil)

func newOAuth(logger *zap.Logger, cfg config.OAuth2Config) (OAuth2, error) {
	store, err := storage.NewStore(logger, &cfg.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	return &oauth{
		logger: logger.Named("auth.oauth2"),
		issuer: cfg.Issuer,
		store:  store,
	}, nil
}

// ServerMetadata returns the OAuth2 server metadata
func (s *oauth) ServerMetadata(r *http.Request) map[string]interface{} {
	// TODO: extract to config file
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http" // Default to http if no scheme is provided
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)
	return map[string]interface{}{
		"issuer":                 baseURL,
		"authorization_endpoint": fmt.Sprintf("%s/authorize", baseURL),
		"token_endpoint":         fmt.Sprintf("%s/token", baseURL),
		"registration_endpoint":  fmt.Sprintf("%s/register", baseURL),
		"revocation_endpoint":    fmt.Sprintf("%s/token", baseURL),
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},
		"response_types_supported": []string{
			"code",
		},
		"response_modes_supported": []string{
			"query",
		},
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
		},
		"code_challenge_methods_supported": []string{
			"plain",
			"S256",
		},
		"scopes_supported": []string{
			"openid",
			"profile",
			"email",
		},
	}
}

// Authorize handles the authorization request
func (s *oauth) Authorize(ctx context.Context, r *http.Request) (*AuthorizationResponse, error) {
	// Get required parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	// Validate required parameters
	if clientID == "" || redirectURI == "" || responseType == "" {
		return nil, errorx.ErrInvalidRequest
	}

	// Validate response type
	if responseType != "code" {
		return nil, errorx.ErrUnsupportedGrantType
	}

	// Get client
	client, err := s.store.GetClient(ctx, clientID)
	if err != nil {
		return nil, errorx.ErrInvalidClient
	}

	// Validate redirect URI
	if !isValidRedirectURI(redirectURI, client.RedirectURIs) {
		return nil, errorx.ErrInvalidRequest
	}

	// Validate code challenge if provided
	if codeChallenge != "" {
		if codeChallengeMethod != "plain" && codeChallengeMethod != "S256" {
			return nil, errorx.ErrInvalidRequest
		}
	}

	// Generate authorization code
	code := generateAuthorizationCode()
	expiresAt := time.Now().Add(10 * time.Minute).Unix()

	// Save authorization code
	authCode := &storage.AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               strings.Split(scope, " "),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           expiresAt,
	}
	if err := s.store.SaveAuthorizationCode(ctx, authCode); err != nil {
		return nil, err
	}

	return &AuthorizationResponse{
		Code:  code,
		State: state,
	}, nil
}

// Token handles the token request
func (s *oauth) Token(ctx context.Context, r *http.Request) (*TokenResponse, error) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		return nil, errorx.ErrInvalidRequest
	}

	grantType := r.PostForm.Get("grant_type")
	clientID := r.PostForm.Get("client_id")
	clientSecret := r.PostForm.Get("client_secret")

	// Validate client credentials
	client, err := s.store.GetClient(ctx, clientID)
	if err != nil {
		return nil, errorx.ErrInvalidClient
	}

	// Validate client secret
	if client.Secret != clientSecret {
		return nil, errorx.ErrInvalidClient
	}

	switch grantType {
	case "authorization_code":
		return s.handleAuthorizationCodeGrant(ctx, r, client)
	case "refresh_token":
		return s.handleRefreshTokenGrant(ctx, r, client)
	default:
		return nil, errorx.ErrUnsupportedGrantType
	}
}

type RegisterRequest struct {
	RedirectURIs    []string `json:"redirect_uris"`
	GrantTypes      []string `json:"grant_types"`
	ResponseTypes   []string `json:"response_types"`
	TokenAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope           string   `json:"scope"`
}

// Register handles client registration
func (s *oauth) Register(ctx context.Context, r *http.Request) (*ClientRegistrationResponse, error) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errorx.ErrInvalidRequest
	}

	// Validate required fields
	if len(req.RedirectURIs) == 0 {
		return nil, errorx.ErrInvalidRequest
	}

	// Set default values if not provided
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.TokenAuthMethod == "" {
		req.TokenAuthMethod = "client_secret_basic"
	}
	if req.Scope == "" {
		req.Scope = "openid profile email"
	}

	// Generate client credentials
	clientID := uuid.New().String()
	clientSecret := generateClientSecret()

	// Create client
	client := &storage.Client{
		ID:              clientID,
		Secret:          clientSecret,
		RedirectURIs:    req.RedirectURIs,
		GrantTypes:      req.GrantTypes,
		ResponseTypes:   req.ResponseTypes,
		TokenAuthMethod: req.TokenAuthMethod,
		Scope:           req.Scope,
	}

	if err := s.store.CreateClient(ctx, client); err != nil {
		return nil, err
	}

	return &ClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenAuthMethod,
		Scope:                   req.Scope,
	}, nil
}

// Revoke handles token revocation
func (s *oauth) Revoke(ctx context.Context, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return errorx.ErrInvalidRequest
	}

	token := r.PostForm.Get("token")

	// Get token
	if _, err := s.store.GetToken(ctx, token); err != nil {
		return errorx.ErrInvalidGrant
	}

	// Delete token
	return s.store.DeleteToken(ctx, token)
}

// handleAuthorizationCodeGrant handles the authorization code grant type
func (s *oauth) handleAuthorizationCodeGrant(ctx context.Context, r *http.Request, client *storage.Client) (*TokenResponse, error) {
	code := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	codeVerifier := r.PostForm.Get("code_verifier")

	// Get authorization code
	authCode, err := s.store.GetAuthorizationCode(ctx, code)
	if err != nil {
		return nil, err
	}

	// Validate client ID
	if authCode.ClientID != client.ID {
		return nil, errorx.ErrInvalidClient
	}

	// Validate redirect URI
	if authCode.RedirectURI != redirectURI {
		return nil, errorx.ErrInvalidRequest
	}

	// Validate code verifier if code challenge was provided
	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			return nil, errorx.ErrInvalidRequest
		}

		// Compute challenge from verifier
		computedChallenge, err := computeCodeChallenge(codeVerifier, authCode.CodeChallengeMethod)
		if err != nil {
			return nil, err
		}

		// Verify the challenge matches
		if computedChallenge != authCode.CodeChallenge {
			return nil, errorx.ErrInvalidGrant
		}
	}

	// Generate access token
	accessToken := generateAccessToken()
	refreshToken := generateRefreshToken()
	expiresIn := int64(3600) // 1 hour

	// Save token
	token := &storage.Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		ClientID:     client.ID,
		Scope:        authCode.Scope,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
	}
	if err := s.store.SaveToken(ctx, token); err != nil {
		return nil, err
	}

	// Delete authorization code
	if err := s.store.DeleteAuthorizationCode(ctx, code); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Scope:        strings.Join(authCode.Scope, " "),
	}, nil
}

// handleRefreshTokenGrant handles the refresh token grant type
func (s *oauth) handleRefreshTokenGrant(ctx context.Context, r *http.Request, client *storage.Client) (*TokenResponse, error) {
	refreshToken := r.PostForm.Get("refresh_token")

	// Get token
	token, err := s.store.GetToken(ctx, refreshToken)
	if err != nil {
		return nil, errorx.ErrInvalidGrant
	}

	// Validate client
	if token.ClientID != client.ID {
		return nil, errorx.ErrInvalidClient
	}

	// Generate new access token
	accessToken := generateAccessToken()
	expiresIn := int64(3600) // 1 hour

	// Save new token
	newToken := &storage.Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		ClientID:     client.ID,
		Scope:        token.Scope,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
	}
	if err := s.store.SaveToken(ctx, newToken); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Scope:        strings.Join(token.Scope, " "),
	}, nil
}

// Helper functions

func generateAuthorizationCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateAccessToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateRefreshToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateClientSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func isValidRedirectURI(redirectURI string, allowedURIs []string) bool {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}

	for _, allowed := range allowedURIs {
		allowedURL, err := url.Parse(allowed)
		if err != nil {
			continue
		}

		if u.Scheme == allowedURL.Scheme &&
			u.Host == allowedURL.Host &&
			strings.HasPrefix(u.Path, allowedURL.Path) {
			return true
		}
	}

	return false
}

func computeCodeChallenge(codeVerifier string, method string) (string, error) {
	switch method {
	case "plain":
		return codeVerifier, nil
	case "S256":
		return oauth2.S256ChallengeFromVerifier(codeVerifier), nil
	default:
		return "", errorx.ErrInvalidRequest
	}
}

// ValidateToken validates an access token
func (s *oauth) ValidateToken(ctx context.Context, token string) error {
	// Get token from store
	tokenInfo, err := s.store.GetToken(ctx, token)
	if err != nil {
		return err
	}

	// Check if token is expired
	if tokenInfo.ExpiresAt < time.Now().Unix() {
		// Delete expired token
		_ = s.store.DeleteToken(ctx, token)
		return errorx.ErrTokenExpired
	}

	return nil
}
