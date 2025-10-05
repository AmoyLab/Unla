package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amoylab/unla/internal/apiserver/database"
	jsvc "github.com/amoylab/unla/internal/auth/jwt"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type tenantInfoDBMock struct {
	user        *database.User
	userErr     error
	tenant      *database.Tenant
	tenantErr   error
	userTenants []*database.Tenant
	utErr       error
}

func (m *tenantInfoDBMock) Close() error                                         { return nil }
func (m *tenantInfoDBMock) SaveMessage(context.Context, *database.Message) error { return nil }
func (m *tenantInfoDBMock) GetMessages(context.Context, string) ([]*database.Message, error) {
	return nil, nil
}

func (m *tenantInfoDBMock) GetMessagesWithPagination(context.Context, string, int, int) ([]*database.Message, error) {
	return nil, nil
}
func (m *tenantInfoDBMock) CreateSession(context.Context, string) error                  { return nil }
func (m *tenantInfoDBMock) CreateSessionWithTitle(context.Context, string, string) error { return nil }
func (m *tenantInfoDBMock) SessionExists(context.Context, string) (bool, error)          { return true, nil }
func (m *tenantInfoDBMock) GetSessions(context.Context) ([]*database.Session, error)     { return nil, nil }
func (m *tenantInfoDBMock) UpdateSessionTitle(context.Context, string, string) error     { return nil }
func (m *tenantInfoDBMock) DeleteSession(context.Context, string) error                  { return nil }
func (m *tenantInfoDBMock) CreateUser(context.Context, *database.User) error             { return nil }
func (m *tenantInfoDBMock) GetUserByUsername(context.Context, string) (*database.User, error) {
	return m.user, m.userErr
}
func (m *tenantInfoDBMock) UpdateUser(context.Context, *database.User) error     { return nil }
func (m *tenantInfoDBMock) DeleteUser(context.Context, uint) error               { return nil }
func (m *tenantInfoDBMock) ListUsers(context.Context) ([]*database.User, error)  { return nil, nil }
func (m *tenantInfoDBMock) CreateTenant(context.Context, *database.Tenant) error { return nil }
func (m *tenantInfoDBMock) GetTenantByName(context.Context, string) (*database.Tenant, error) {
	return m.tenant, m.tenantErr
}

func (m *tenantInfoDBMock) GetTenantByID(context.Context, uint) (*database.Tenant, error) {
	return m.tenant, m.tenantErr
}
func (m *tenantInfoDBMock) UpdateTenant(context.Context, *database.Tenant) error    { return nil }
func (m *tenantInfoDBMock) DeleteTenant(context.Context, uint) error                { return nil }
func (m *tenantInfoDBMock) ListTenants(context.Context) ([]*database.Tenant, error) { return nil, nil }
func (m *tenantInfoDBMock) AddUserToTenant(context.Context, uint, uint) error       { return nil }
func (m *tenantInfoDBMock) RemoveUserFromTenant(context.Context, uint, uint) error  { return nil }
func (m *tenantInfoDBMock) GetUserTenants(context.Context, uint) ([]*database.Tenant, error) {
	return m.userTenants, m.utErr
}

func (m *tenantInfoDBMock) GetTenantUsers(context.Context, uint) ([]*database.User, error) {
	return nil, nil
}
func (m *tenantInfoDBMock) DeleteUserTenants(context.Context, uint) error { return nil }
func (m *tenantInfoDBMock) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
func (m *tenantInfoDBMock) GetSystemPrompt(context.Context, uint) (string, error) { return "", nil }
func (m *tenantInfoDBMock) SaveSystemPrompt(context.Context, uint, string) error  { return nil }

func TestTenant_GetTenantInfo_MissingName(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewHandler(&tenantInfoDBMock{}, mustNewJWTService(), nil, zap.NewNop())
	r := gin.New()
	// Route without setting name param to simulate missing name
	r.GET("/tenant-empty", func(c *gin.Context) { h.GetTenantInfo(c) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/tenant-empty", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenant_GetTenantInfo_MissingClaims(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewHandler(&tenantInfoDBMock{}, mustNewJWTService(), nil, zap.NewNop())
	r := gin.New()
	r.GET("/tenant/:name", h.GetTenantInfo)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/tenant/t1", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTenant_GetTenantInfo_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := &tenantInfoDBMock{user: &database.User{ID: 1, Username: "u", Role: database.RoleAdmin}, tenantErr: assert.AnError}
	h := NewHandler(db, mustNewJWTService(), nil, zap.NewNop())
	r := gin.New()
	r.GET("/tenant/:name", func(c *gin.Context) {
		c.Set("claims", &jsvc.Claims{Username: "u"})
		h.GetTenantInfo(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/tenant/t1", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTenant_GetTenantInfo_PermissionDenied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := &tenantInfoDBMock{
		user:        &database.User{ID: 1, Username: "u", Role: database.RoleNormal},
		tenant:      &database.Tenant{ID: 2, Name: "t1", Prefix: "/t1"},
		userTenants: []*database.Tenant{{ID: 3, Name: "other"}},
	}
	h := NewHandler(db, mustNewJWTService(), nil, zap.NewNop())
	r := gin.New()
	r.GET("/tenant/:name", func(c *gin.Context) {
		c.Set("claims", &jsvc.Claims{Username: "u"})
		h.GetTenantInfo(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/tenant/t1", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestTenant_GetTenantInfo_Success_Admin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := &tenantInfoDBMock{user: &database.User{ID: 1, Username: "u", Role: database.RoleAdmin}, tenant: &database.Tenant{ID: 2, Name: "t1", Prefix: "/t1", CreatedAt: time.Now(), UpdatedAt: time.Now()}}
	h := NewHandler(db, mustNewJWTService(), nil, zap.NewNop())
	r := gin.New()
	r.GET("/tenant/:name", func(c *gin.Context) {
		c.Set("claims", &jsvc.Claims{Username: "u"})
		h.GetTenantInfo(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/tenant/t1", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "\"name\":\"t1\"")
}
