package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/amoylab/unla/internal/auth/storage"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/common/errorx"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func newTestOAuth(t *testing.T) *oauth {
	t.Helper()
	logger := zap.NewNop()
	cfg := config.OAuth2Config{Issuer: "http://localhost", Storage: config.OAuth2StorageConfig{Type: "memory"}}
	o, err := newOAuth(logger, cfg)
	if err != nil {
		t.Fatalf("newOAuth error: %v", err)
	}
	return o.(*oauth)
}

func mustCreateClient(t *testing.T, s storage.Store, id, secret string, redirects ...string) *storage.Client {
	t.Helper()
	c := &storage.Client{ID: id, Secret: secret, RedirectURIs: redirects, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenAuthMethod: "client_secret_post", Scope: "openid profile"}
	if err := s.CreateClient(context.Background(), c); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	return c
}

func TestServerMetadata_AndHelpers(t *testing.T) {
	o := newTestOAuth(t)
	req, _ := http.NewRequest("GET", "http://example.com/.well-known/openid-configuration", nil)
	req.Host = "example.com"
	md := o.ServerMetadata(req)
	assert.Equal(t, "http://example.com", md["issuer"])
	assert.Contains(t, md["authorization_endpoint"], "/authorize")

	// isValidRedirectURI
	ok := isValidRedirectURI("https://app.example.com/cb/extra", []string{"https://app.example.com/cb"})
	assert.True(t, ok)
	ok = isValidRedirectURI("https://attacker.example.com/cb", []string{"https://app.example.com/cb"})
	assert.False(t, ok)

	// computeCodeChallenge
	plain, err := computeCodeChallenge("abc", "plain")
	assert.NoError(t, err)
	assert.Equal(t, "abc", plain)
	s256, err := computeCodeChallenge("abc", "S256")
	assert.NoError(t, err)
	assert.NotEmpty(t, s256)
	assert.NotEqual(t, plain, s256)
	_, err = computeCodeChallenge("abc", "unknown")
	assert.ErrorIs(t, err, errorx.ErrInvalidRequest)
}

func TestAuthorize_Success_And_InvalidCases(t *testing.T) {
	o := newTestOAuth(t)
	mustCreateClient(t, o.store, "cli-1", "sec-1", "http://app/callback")

	// success
	u := &url.URL{Path: "/authorize"}
	q := u.Query()
	q.Set("client_id", "cli-1")
	q.Set("redirect_uri", "http://app/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid email")
	q.Set("state", "st")
	u.RawQuery = q.Encode()
	req := &http.Request{URL: u}
	resp, err := o.Authorize(context.Background(), req)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.Code)
	assert.Equal(t, "st", resp.State)

	// invalid response type
	u2 := &url.URL{Path: "/authorize"}
	q2 := u2.Query()
	q2.Set("client_id", "cli-1")
	q2.Set("redirect_uri", "http://app/callback")
	q2.Set("response_type", "token")
	u2.RawQuery = q2.Encode()
	_, err = o.Authorize(context.Background(), &http.Request{URL: u2})
	assert.ErrorIs(t, err, errorx.ErrUnsupportedGrantType)

	// invalid redirect
	u3 := &url.URL{Path: "/authorize"}
	q3 := u3.Query()
	q3.Set("client_id", "cli-1")
	q3.Set("redirect_uri", "http://evil/callback")
	q3.Set("response_type", "code")
	u3.RawQuery = q3.Encode()
	_, err = o.Authorize(context.Background(), &http.Request{URL: u3})
	assert.ErrorIs(t, err, errorx.ErrInvalidRequest)
}

func TestToken_AuthorizationCode_Success_And_Errors(t *testing.T) {
	o := newTestOAuth(t)
	mustCreateClient(t, o.store, "cli-2", "sec-2", "http://app/cb")

	// First authorize to get a code
	u := &url.URL{Path: "/authorize"}
	q := u.Query()
	q.Set("client_id", "cli-2")
	q.Set("redirect_uri", "http://app/cb")
	q.Set("response_type", "code")
	u.RawQuery = q.Encode()
	ar, err := o.Authorize(context.Background(), &http.Request{URL: u})
	assert.NoError(t, err)

	// Exchange code
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "cli-2")
	form.Set("client_secret", "sec-2")
	form.Set("code", ar.Code)
	form.Set("redirect_uri", "http://app/cb")
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	err = req.ParseForm()
	assert.NoError(t, err)
	tr, err := o.Token(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer", tr.TokenType)
	assert.NotEmpty(t, tr.AccessToken)
	assert.NotEmpty(t, tr.RefreshToken)

	// Using wrong secret
	form2 := url.Values{}
	form2.Set("grant_type", "authorization_code")
	form2.Set("client_id", "cli-2")
	form2.Set("client_secret", "bad")
	form2.Set("code", ar.Code)
	form2.Set("redirect_uri", "http://app/cb")
	req2, _ := http.NewRequest("POST", "/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req2.ParseForm()
	_, err = o.Token(context.Background(), req2)
	assert.ErrorIs(t, err, errorx.ErrInvalidClient)

	// Unsupported grant
	form3 := url.Values{}
	form3.Set("grant_type", "password")
	form3.Set("client_id", "cli-2")
	form3.Set("client_secret", "sec-2")
	req3, _ := http.NewRequest("POST", "/token", strings.NewReader(form3.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req3.ParseForm()
	_, err = o.Token(context.Background(), req3)
	assert.ErrorIs(t, err, errorx.ErrUnsupportedGrantType)

	// Refresh token currently looks up by token string; ensure invalid gives proper error
	form4 := url.Values{}
	form4.Set("grant_type", "refresh_token")
	form4.Set("client_id", "cli-2")
	form4.Set("client_secret", "sec-2")
	form4.Set("refresh_token", "non-existent")
	req4, _ := http.NewRequest("POST", "/token", strings.NewReader(form4.Encode()))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req4.ParseForm()
	_, err = o.Token(context.Background(), req4)
	assert.ErrorIs(t, err, errorx.ErrInvalidGrant)
}

func TestRegister_And_Revoke_And_ValidateToken(t *testing.T) {
	o := newTestOAuth(t)

	// Register
	payload := map[string]any{
		"redirect_uris": []string{"http://app/redirect"},
	}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/register", bytes.NewReader(b))
	rr, err := o.Register(context.Background(), req)
	assert.NoError(t, err)
	assert.NotEmpty(t, rr.ClientID)
	assert.NotEmpty(t, rr.ClientSecret)
	assert.Contains(t, rr.GrantTypes, "authorization_code")
	assert.Contains(t, rr.ResponseTypes, "code")
	assert.NotEmpty(t, rr.Scope)

	// Save a token and validate
	tok := &storage.Token{
		AccessToken:  "atk",
		TokenType:    "Bearer",
		RefreshToken: "rtk",
		ClientID:     rr.ClientID,
		Scope:        []string{"openid"},
		ExpiresAt:    time.Now().Add(10 * time.Second).Unix(),
	}
	assert.NoError(t, o.store.SaveToken(context.Background(), tok))
	assert.NoError(t, o.ValidateToken(context.Background(), "atk"))

	// Expired token
	tok2 := &storage.Token{AccessToken: "exp", ExpiresAt: time.Now().Add(-1 * time.Second).Unix()}
	assert.NoError(t, o.store.SaveToken(context.Background(), tok2))
	err = o.ValidateToken(context.Background(), "exp")
	// Underlying store returns invalid_grant for expired token fetch
	assert.ErrorIs(t, err, errorx.ErrInvalidGrant)

	// Revoke
	form := url.Values{}
	form.Set("token", "atk")
	r, _ := http.NewRequest("POST", "/revoke", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	assert.NoError(t, o.Revoke(context.Background(), r))
}
