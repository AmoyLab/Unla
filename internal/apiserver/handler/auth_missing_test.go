package handler

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/amoylab/unla/internal/apiserver/database"
	"github.com/amoylab/unla/internal/auth/jwt"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// fakeDBAnotherForMissing is for testing missing functions
type fakeDBAnotherForMissing struct {
	fakeDB
	shouldError    bool
	userNotFound   bool
	userWithTenant *database.User
	tenants        []*database.Tenant
}

func (f *fakeDBAnotherForMissing) GetUserByUsername(ctx context.Context, username string) (*database.User, error) {
	if f.userNotFound {
		return nil, assert.AnError
	}
	if f.userWithTenant != nil {
		return f.userWithTenant, nil
	}
	return &database.User{ID: 1, Username: username, Role: database.RoleNormal, IsActive: true}, nil
}

func (f *fakeDBAnotherForMissing) GetUserTenants(ctx context.Context, userID uint) ([]*database.Tenant, error) {
	if f.shouldError {
		return nil, assert.AnError
	}
	return f.tenants, nil
}

func (f *fakeDBAnotherForMissing) ListTenants(ctx context.Context) ([]*database.Tenant, error) {
	if f.shouldError {
		return nil, assert.AnError
	}
	return f.tenants, nil
}

func TestHandler_GetUserWithTenants_MissingClaims(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewHandler(&fakeDB{}, nil, nil, zap.NewNop())

	r.GET("/user", h.GetUserWithTenants)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/user", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandler_GetUserWithTenants_CurrentUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	f := &fakeDBAnotherForMissing{
		tenants: []*database.Tenant{{ID: 1, Name: "test-tenant"}},
	}
	h := NewHandler(f, nil, nil, zap.NewNop())

	r.GET("/user", func(c *gin.Context) {
		c.Set("claims", &jwt.Claims{UserID: 1, Username: "testuser", Role: "normal"})
		h.GetUserWithTenants(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/user", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_GetUserWithTenants_AdminUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	f := &fakeDBAnotherForMissing{
		userWithTenant: &database.User{ID: 1, Username: "admin", Role: database.RoleAdmin, IsActive: true},
		tenants:        []*database.Tenant{{ID: 1, Name: "admin-tenant"}},
	}
	h := NewHandler(f, nil, nil, zap.NewNop())

	r.GET("/users/:username", func(c *gin.Context) {
		c.Set("claims", &jwt.Claims{UserID: 1, Username: "admin", Role: "admin"})
		h.GetUserWithTenants(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/users/admin", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_GetUserWithTenants_UserNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	f := &fakeDBAnotherForMissing{userNotFound: true}
	h := NewHandler(f, nil, nil, zap.NewNop())

	r.GET("/users/:username", func(c *gin.Context) {
		c.Set("claims", &jwt.Claims{UserID: 1, Username: "admin", Role: "admin"})
		h.GetUserWithTenants(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/users/nonexistent", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandler_GetUserWithTenants_NonAdminAccessingOther(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewHandler(&fakeDB{}, nil, nil, zap.NewNop())

	r.GET("/users/:username", func(c *gin.Context) {
		c.Set("claims", &jwt.Claims{UserID: 1, Username: "normal", Role: "normal"})
		h.GetUserWithTenants(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/users/otheruser", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandler_GetUserWithTenants_TenantError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	f := &fakeDBAnotherForMissing{shouldError: true}
	h := NewHandler(f, nil, nil, zap.NewNop())

	r.GET("/users/:username", func(c *gin.Context) {
		c.Set("claims", &jwt.Claims{UserID: 1, Username: "admin", Role: "admin"})
		h.GetUserWithTenants(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/users/testuser", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// fakeDTBUpdateUserTenants for testing UpdateUserTenants
type fakeDBUpdateUserTenants struct {
	fakeDB
	user        *database.User
	shouldError bool
	addedPairs  [][2]uint // [userID, tenantID] pairs
	removedIds  []uint    // tenantIDs
}

func (f *fakeDBUpdateUserTenants) GetUserByUsername(ctx context.Context, username string) (*database.User, error) {
	if f.shouldError {
		return nil, assert.AnError
	}
	if f.user != nil {
		return f.user, nil
	}
	return &database.User{ID: 1, Username: username, Role: database.RoleNormal}, nil
}

func (f *fakeDBUpdateUserTenants) GetUserTenants(ctx context.Context, userID uint) ([]*database.Tenant, error) {
	if f.shouldError {
		return nil, assert.AnError
	}
	return []*database.Tenant{{ID: 1}, {ID: 2}}, nil
}

func (f *fakeDBUpdateUserTenants) AddUserToTenant(ctx context.Context, userID, tenantID uint) error {
	if f.shouldError {
		return assert.AnError
	}
	f.addedPairs = append(f.addedPairs, [2]uint{userID, tenantID})
	return nil
}

func (f *fakeDBUpdateUserTenants) RemoveUserFromTenant(ctx context.Context, userID, tenantID uint) error {
	if f.shouldError {
		return assert.AnError
	}
	f.removedIds = append(f.removedIds, tenantID)
	return nil
}

func TestHandler_UpdateUserTenants_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	f := &fakeDBUpdateUserTenants{
		user: &database.User{ID: 5, Username: "testuser"},
	}
	h := NewHandler(f, nil, nil, zap.NewNop())

	r.PUT("/users/tenants", func(c *gin.Context) {
		c.Set("claims", &jwt.Claims{UserID: 1, Username: "admin", Role: "admin"})
		body := `{"userId":5,"tenantIds":[2,3]}`
		c.Request = c.Request.WithContext(context.Background())
		c.Request.Method = http.MethodPut
		c.Request.Body = io.NopCloser(strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		h.UpdateUserTenants(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/users/tenants", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, f.removedIds, uint(1))       // removed tenant 1
	assert.Contains(t, f.addedPairs, [2]uint{5, 3}) // added tenant 3 to user 5
}

func TestHandler_UpdateUserTenants_MissingClaims(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewHandler(&fakeDB{}, nil, nil, zap.NewNop())

	r.PUT("/users/tenants", h.UpdateUserTenants)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/users/tenants", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_UpdateUserTenants_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewHandler(&fakeDB{}, nil, nil, zap.NewNop())

	r.PUT("/users/tenants", func(c *gin.Context) {
		c.Set("claims", &jwt.Claims{UserID: 1, Username: "admin", Role: "admin"})
		body := `invalid json`
		c.Request = c.Request.WithContext(context.Background())
		c.Request.Method = http.MethodPut
		c.Request.Body = io.NopCloser(strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		h.UpdateUserTenants(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/users/tenants", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_UpdateUserTenants_UserNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	f := &fakeDBUpdateUserTenants{shouldError: true}
	h := NewHandler(f, nil, nil, zap.NewNop())

	r.PUT("/users/tenants", func(c *gin.Context) {
		c.Set("claims", &jwt.Claims{UserID: 1, Username: "admin", Role: "admin"})
		body := `{"userId":999,"tenantIds":[2,3]}`
		c.Request = c.Request.WithContext(context.Background())
		c.Request.Method = http.MethodPut
		c.Request.Body = io.NopCloser(strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		h.UpdateUserTenants(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/users/tenants", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
