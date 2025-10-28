package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	inta "github.com/amoylab/unla/internal/auth"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// fakeAuth implements inta.Auth for focused handler tests.
type fakeAuth struct{ inta.OAuth2 }

func (f *fakeAuth) IsOAuth2Enabled() bool              { return true }
func (f *fakeAuth) GetOAuth2CORS() *config.CORSConfig  { return nil }
func (f *fakeAuth) GetGoogleOAuth() inta.ExternalOAuth { return nil }
func (f *fakeAuth) GetGitHubOAuth() inta.ExternalOAuth { return nil }
func (f *fakeAuth) IsGoogleOAuthEnabled() bool         { return false }
func (f *fakeAuth) IsGitHubOAuthEnabled() bool         { return false }

type fakeOAuth2 struct{}

func (fakeOAuth2) ServerMetadata(r *http.Request) map[string]interface{} {
	return map[string]any{"ok": true}
}
func (fakeOAuth2) Authorize(_ context.Context, _ *http.Request) (*inta.AuthorizationResponse, error) {
	return &inta.AuthorizationResponse{Code: "abc", State: "s1"}, nil
}
func (fakeOAuth2) Token(_ context.Context, _ *http.Request) (*inta.TokenResponse, error) {
	return &inta.TokenResponse{AccessToken: "t"}, nil
}
func (fakeOAuth2) Register(_ context.Context, _ *http.Request) (*inta.ClientRegistrationResponse, error) {
	return &inta.ClientRegistrationResponse{ClientID: "id"}, nil
}
func (fakeOAuth2) Revoke(_ context.Context, _ *http.Request) error { return nil }
func (fakeOAuth2) ValidateToken(_ context.Context, _ string) error { return nil }

func TestHandleOAuthAuthorize_GET_RendersPage(t *testing.T) {
	// Ensure template exists for rendering
	_ = os.MkdirAll("assets/templates", 0o755)
	tplPath := filepath.Join("assets", "templates", "authorize.html")
	_ = os.WriteFile(tplPath, []byte("authorize page"), 0o644)

	logger := zap.NewNop()
	s, err := NewServer(logger, 0, nil, nil, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// Build gin context bound to server router with HTML renderer loaded
	w := httptest.NewRecorder()
	c, eng := gin.CreateTestContext(w)
	eng.LoadHTMLGlob("assets/templates/*")
	c.Request = httptest.NewRequest(http.MethodGet, "/authorize?client_id=c&redirect_uri=http://x&state=s", nil)
	c.Request.Header.Set("User-Agent", "ut")
	c.Request.RemoteAddr = "127.0.0.1:12345"

	s.renderAuthorizationPage(c, "client", "http://x", "s")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "authorize") {
		t.Fatalf("expected body to contain template content, got %q", w.Body.String())
	}
}

func TestHandleOAuthAuthorize_POST_Redirects(t *testing.T) {
	logger := zap.NewNop()
	s, err := NewServer(logger, 0, nil, nil, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	s.auth = &fakeAuth{OAuth2: fakeOAuth2{}}

	form := url.Values{}
	form.Set("client_id", "cid")
	form.Set("redirect_uri", "http://example.com/cb")
	form.Set("state", "s1")
	form.Set("response_type", "code")
	form.Set("scope", "openid")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request = req

	s.handleOAuthAuthorize(c)

	loc := w.Header().Get("Location")
	if loc == "" || !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=") {
		t.Fatalf("expected redirect to include code and state, got %s", loc)
	}
}
