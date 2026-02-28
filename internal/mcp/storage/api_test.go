package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func newTestConfig(name, tenant string) string {
	// Minimal valid MCPConfig JSON
	return `{"name":"` + name + `","tenant":"` + tenant + `"}`
}

func TestAPIStore_Get_And_List_Basic(t *testing.T) {
	// Server returns a single config by default
	cfgJSON := newTestConfig("n1", "t1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(cfgJSON))
	}))
	defer srv.Close()

	store, err := NewAPIStore(zap.NewNop(), srv.URL, "", 2*time.Second, false)
	assert.NoError(t, err)

	// Get returns struct unmarshaled from response
	got, err := store.Get(context.Background(), "t1", "n1")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, "n1", got.Name)
		assert.Equal(t, "t1", got.Tenant)
	}

	// List with array response
	listResp := `[` + newTestConfig("n2", "t2") + `]`
	// Swap the handler to return list
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(listResp))
	})

	lst, err := store.List(context.Background())
	assert.NoError(t, err)
	if assert.Len(t, lst, 1) {
		assert.Equal(t, "n2", lst[0].Name)
		assert.Equal(t, "t2", lst[0].Tenant)
	}
}

func TestAPIStore_Get_WithJSONPath(t *testing.T) {
	inner := newTestConfig("n3", "t3")
	payload := `{"data": {"config": ` + inner + `}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	store, err := NewAPIStore(zap.NewNop(), srv.URL, "data.config", 2*time.Second, false)
	assert.NoError(t, err)

	got, err := store.Get(context.Background(), "t3", "n3")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, "n3", got.Name)
		assert.Equal(t, "t3", got.Tenant)
	}
}

func TestAPIStore_JSONPathMissing_ReturnsError(t *testing.T) {
	payload := `{"data": {"other": 1}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	store, err := NewAPIStore(zap.NewNop(), srv.URL, "data.config", 2*time.Second)
	assert.NoError(t, err)

	got, err := store.Get(context.Background(), "t", "n")
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestAPIStore_RequestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(newTestConfig("n", "t")))
	}))
	defer srv.Close()

	store, err := NewAPIStore(zap.NewNop(), srv.URL, "", 10*time.Millisecond, false)
	assert.NoError(t, err)

	got, err := store.Get(context.Background(), "t", "n")
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestAPIStore_ListUpdated_DelegatesToList(t *testing.T) {
	listResp := `[` + newTestConfig("n4", "t4") + `,` + newTestConfig("n5", "t5") + `]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(listResp))
	}))
	defer srv.Close()

	store, err := NewAPIStore(zap.NewNop(), srv.URL, "", time.Second, false)
	assert.NoError(t, err)

	lst, err := store.ListUpdated(context.Background(), time.Now().Add(-time.Hour))
	assert.NoError(t, err)
	if assert.Len(t, lst, 2) {
		names := []string{lst[0].Name, lst[1].Name}
		tenants := []string{lst[0].Tenant, lst[1].Tenant}
		assert.ElementsMatch(t, []string{"n4", "n5"}, names)
		assert.ElementsMatch(t, []string{"t4", "t5"}, tenants)
	}
}

func TestAPIStore_RWNoops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(newTestConfig("n", "t")))
	}))
	defer srv.Close()

	store, err := NewAPIStore(zap.NewNop(), srv.URL, "", time.Second, false)
	assert.NoError(t, err)

	// Read-only behavior
	assert.NoError(t, store.Create(context.Background(), &config.MCPConfig{}))
	assert.NoError(t, store.Update(context.Background(), &config.MCPConfig{}))
	assert.NoError(t, store.Delete(context.Background(), "t", "n"))
	v, err := store.GetVersion(context.Background(), "t", "n", 1)
	assert.NoError(t, err)
	assert.Nil(t, v)
	vs, err := store.ListVersions(context.Background(), "t", "n")
	assert.NoError(t, err)
	assert.Nil(t, vs)
	assert.NoError(t, store.SetActiveVersion(context.Background(), "t", "n", 1))
	assert.NoError(t, store.DeleteVersion(context.Background(), "t", "n", 1))
}
