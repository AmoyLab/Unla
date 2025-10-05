package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amoylab/unla/internal/auth"
	jsvc "github.com/amoylab/unla/internal/auth/jwt"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type fakeExtOAuth struct{ url string }

func (f *fakeExtOAuth) GetAuthURL(state string) string { return f.url }
func (f *fakeExtOAuth) ExchangeCode(_ context.Context, _ string) (*auth.ExternalTokenResponse, error) {
	return nil, nil
}

func (f *fakeExtOAuth) GetUserInfo(_ context.Context, _ string) (*auth.ExternalUserInfo, error) {
	return nil, nil
}

type fakeAuth struct {
	gEnabled  bool
	ghEnabled bool
}

func (f *fakeAuth) ServerMetadata(r *http.Request) map[string]interface{} { return nil }
func (f *fakeAuth) Authorize(ctx context.Context, r *http.Request) (*auth.AuthorizationResponse, error) {
	return nil, nil
}

func (f *fakeAuth) Token(ctx context.Context, r *http.Request) (*auth.TokenResponse, error) {
	return nil, nil
}

func (f *fakeAuth) Register(ctx context.Context, r *http.Request) (*auth.ClientRegistrationResponse, error) {
	return nil, nil
}
func (f *fakeAuth) Revoke(ctx context.Context, r *http.Request) error     { return nil }
func (f *fakeAuth) ValidateToken(ctx context.Context, token string) error { return nil }
func (f *fakeAuth) IsOAuth2Enabled() bool                                 { return false }
func (f *fakeAuth) GetOAuth2CORS() *config.CORSConfig                     { return nil }
func (f *fakeAuth) GetGoogleOAuth() auth.ExternalOAuth                    { return &fakeExtOAuth{url: "http://g/auth"} }
func (f *fakeAuth) GetGitHubOAuth() auth.ExternalOAuth                    { return &fakeExtOAuth{url: "http://gh/auth"} }
func (f *fakeAuth) IsGoogleOAuthEnabled() bool                            { return f.gEnabled }
func (f *fakeAuth) IsGitHubOAuthEnabled() bool                            { return f.ghEnabled }

func TestGoogleAndGitHubLogin_And_Providers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, _ := jsvc.NewService(jsvc.Config{SecretKey: "this-is-a-very-long-secret-key-for-testing", Duration: time.Hour})

	// Disabled -> 400
	h := NewOAuthHandler(nil, svc, &fakeAuth{}, zap.NewNop())
	r := gin.New()
	r.GET("/g", h.GoogleLogin)
	r.GET("/gh", h.GitHubLogin)
	r.GET("/providers", h.GetOAuthProviders)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/g", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/gh", nil)
	r.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusBadRequest, w2.Code)

	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest("GET", "/providers", nil)
	r.ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusOK, w3.Code)
	assert.Contains(t, w3.Body.String(), "providers")

	// Enabled -> 200 with auth_url
	h2 := NewOAuthHandler(nil, svc, &fakeAuth{gEnabled: true, ghEnabled: true}, zap.NewNop())
	r2 := gin.New()
	r2.GET("/g", h2.GoogleLogin)
	r2.GET("/gh", h2.GitHubLogin)
	r2.GET("/providers", h2.GetOAuthProviders)

	w4 := httptest.NewRecorder()
	req4 := httptest.NewRequest("GET", "/g", nil)
	r2.ServeHTTP(w4, req4)
	assert.Equal(t, http.StatusOK, w4.Code)
	assert.Contains(t, w4.Body.String(), "auth_url")
	assert.Contains(t, w4.Body.String(), "state")

	w5 := httptest.NewRecorder()
	req5 := httptest.NewRequest("GET", "/gh", nil)
	r2.ServeHTTP(w5, req5)
	assert.Equal(t, http.StatusOK, w5.Code)
	assert.Contains(t, w5.Body.String(), "auth_url")
	assert.Contains(t, w5.Body.String(), "state")

	w6 := httptest.NewRecorder()
	req6 := httptest.NewRequest("GET", "/providers", nil)
	r2.ServeHTTP(w6, req6)
	assert.Equal(t, http.StatusOK, w6.Code)
	assert.Contains(t, w6.Body.String(), "google")
	assert.Contains(t, w6.Body.String(), "github")
}
