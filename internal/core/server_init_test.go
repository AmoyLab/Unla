package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amoylab/unla/internal/auth"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/internal/mcp/storage"
	"go.uber.org/zap"
)

type emptyStore struct{ storage.Store }

func (s *emptyStore) List(ctx context.Context, includeDeleted ...bool) ([]*config.MCPConfig, error) {
	return []*config.MCPConfig{}, nil
}
func (s *emptyStore) ListUpdated(ctx context.Context, sinceTime time.Time) ([]*config.MCPConfig, error) {
	return []*config.MCPConfig{}, nil
}

func TestServer_RegisterRoutes_And_Basics(t *testing.T) {
	logger := zap.NewNop()
	sess := session.NewMemoryStore(logger)
	st := &emptyStore{}
	a, err := auth.NewAuth(logger, config.AuthConfig{})
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	// ensure template/static assets exist for gin loader used in NewServer
	_ = os.MkdirAll("assets/templates", 0o755)
	_ = os.MkdirAll("assets/static", 0o755)
	// write a minimal template file to satisfy glob
	tplPath := filepath.Join("assets", "templates", "base.tmpl")
	_ = os.WriteFile(tplPath, []byte("{{ define \"base\" }}ok{{ end }}"), 0o644)

	s, err := NewServer(logger, 0, st, sess, a, WithForwardConfig(config.ForwardConfig{}))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ctx := context.Background()
	if err := s.RegisterRoutes(ctx); err != nil {
		t.Fatalf("register routes: %v", err)
	}

	// exercise reload with no changes
	s.ReloadConfigs(ctx)

	// update with invalid config to walk validation path
	s.UpdateConfig(ctx, &config.MCPConfig{Name: "n", Tenant: "t"})

	// hit root handler invalid path and invalid prefix branches
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	s.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid path, got %d", rr.Code)
	}

	rr2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/a/sse", nil)
	s.router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for invalid prefix, got %d", rr2.Code)
	}
}
