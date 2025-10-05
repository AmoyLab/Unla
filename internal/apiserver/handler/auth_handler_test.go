package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amoylab/unla/internal/apiserver/database"
	jsvc "github.com/amoylab/unla/internal/auth/jwt"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/common/dto"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type authDBMock struct{ user *database.User }

func (m *authDBMock) Close() error                                         { return nil }
func (m *authDBMock) SaveMessage(context.Context, *database.Message) error { return nil }
func (m *authDBMock) GetMessages(context.Context, string) ([]*database.Message, error) {
	return nil, nil
}
func (m *authDBMock) GetMessagesWithPagination(context.Context, string, int, int) ([]*database.Message, error) {
	return nil, nil
}
func (m *authDBMock) CreateSession(context.Context, string) error                  { return nil }
func (m *authDBMock) CreateSessionWithTitle(context.Context, string, string) error { return nil }
func (m *authDBMock) SessionExists(context.Context, string) (bool, error)          { return true, nil }
func (m *authDBMock) GetSessions(context.Context) ([]*database.Session, error)     { return nil, nil }
func (m *authDBMock) UpdateSessionTitle(context.Context, string, string) error     { return nil }
func (m *authDBMock) DeleteSession(context.Context, string) error                  { return nil }
func (m *authDBMock) CreateUser(context.Context, *database.User) error             { return nil }
func (m *authDBMock) GetUserByUsername(context.Context, string) (*database.User, error) {
	return m.user, nil
}
func (m *authDBMock) UpdateUser(context.Context, *database.User) error     { return nil }
func (m *authDBMock) DeleteUser(context.Context, uint) error               { return nil }
func (m *authDBMock) ListUsers(context.Context) ([]*database.User, error)  { return nil, nil }
func (m *authDBMock) CreateTenant(context.Context, *database.Tenant) error { return nil }
func (m *authDBMock) GetTenantByName(context.Context, string) (*database.Tenant, error) {
	return nil, nil
}
func (m *authDBMock) GetTenantByID(context.Context, uint) (*database.Tenant, error) { return nil, nil }
func (m *authDBMock) UpdateTenant(context.Context, *database.Tenant) error          { return nil }
func (m *authDBMock) DeleteTenant(context.Context, uint) error                      { return nil }
func (m *authDBMock) ListTenants(context.Context) ([]*database.Tenant, error)       { return nil, nil }
func (m *authDBMock) AddUserToTenant(context.Context, uint, uint) error             { return nil }
func (m *authDBMock) RemoveUserFromTenant(context.Context, uint, uint) error        { return nil }
func (m *authDBMock) GetUserTenants(context.Context, uint) ([]*database.Tenant, error) {
	return nil, nil
}
func (m *authDBMock) GetTenantUsers(context.Context, uint) ([]*database.User, error) { return nil, nil }
func (m *authDBMock) DeleteUserTenants(context.Context, uint) error                  { return nil }
func (m *authDBMock) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
func (m *authDBMock) GetSystemPrompt(context.Context, uint) (string, error) { return "", nil }
func (m *authDBMock) SaveSystemPrompt(context.Context, uint, string) error  { return nil }

func TestAuthHandler_Login_And_ChangePassword(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pwd := "secret"
	hpwd, _ := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	db := &authDBMock{user: &database.User{ID: 1, Username: "u", Password: string(hpwd), Role: database.RoleAdmin, IsActive: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}}

	jwtSvc, _ := jsvc.NewService(jsvc.Config{SecretKey: "this-is-a-very-long-secret-key-for-testing", Duration: time.Hour})
	h := NewHandler(db, jwtSvc, &config.MCPGatewayConfig{}, zap.NewNop())

	// Login
	r := gin.New()
	r.POST("/login", h.Login)
	body, _ := json.Marshal(&dto.LoginRequest{Username: "u", Password: pwd})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Change password
	r2 := gin.New()
	r2.POST("/change", func(c *gin.Context) {
		c.Set("claims", &jsvc.Claims{Username: "u", Role: "admin"})
		h.ChangePassword(c)
	})
	cpBody, _ := json.Marshal(&dto.ChangePasswordRequest{OldPassword: pwd, NewPassword: "newp"})
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("POST", "/change", bytes.NewReader(cpBody))
	req2.Header.Set("Content-Type", "application/json")
	r2.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
}
