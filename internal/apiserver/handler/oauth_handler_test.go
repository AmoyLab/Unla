package handler

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amoylab/unla/internal/apiserver/database"
	"github.com/amoylab/unla/internal/auth"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// Minimal DB mock for OAuth helper tests
type oauthDBMock struct {
	usersCreated   int
	tenantsCreated int
	linksCreated   int
	user           *database.User
	findErr        error
}

func (m *oauthDBMock) Close() error                                         { return nil }
func (m *oauthDBMock) SaveMessage(context.Context, *database.Message) error { return nil }
func (m *oauthDBMock) GetMessages(context.Context, string) ([]*database.Message, error) {
	return nil, nil
}

func (m *oauthDBMock) GetMessagesWithPagination(context.Context, string, int, int) ([]*database.Message, error) {
	return nil, nil
}
func (m *oauthDBMock) CreateSession(context.Context, string) error                  { return nil }
func (m *oauthDBMock) CreateSessionWithTitle(context.Context, string, string) error { return nil }
func (m *oauthDBMock) SessionExists(context.Context, string) (bool, error)          { return true, nil }
func (m *oauthDBMock) GetSessions(context.Context) ([]*database.Session, error)     { return nil, nil }
func (m *oauthDBMock) UpdateSessionTitle(context.Context, string, string) error     { return nil }
func (m *oauthDBMock) DeleteSession(context.Context, string) error                  { return nil }
func (m *oauthDBMock) CreateUser(ctx context.Context, u *database.User) error {
	m.usersCreated++
	// Simulate auto-increment
	if u.ID == 0 {
		u.ID = 100
	}
	return nil
}

func (m *oauthDBMock) GetUserByUsername(context.Context, string) (*database.User, error) {
	return m.user, m.findErr
}
func (m *oauthDBMock) UpdateUser(context.Context, *database.User) error    { return nil }
func (m *oauthDBMock) DeleteUser(context.Context, uint) error              { return nil }
func (m *oauthDBMock) ListUsers(context.Context) ([]*database.User, error) { return nil, nil }
func (m *oauthDBMock) CreateTenant(ctx context.Context, t *database.Tenant) error {
	m.tenantsCreated++
	if t.ID == 0 {
		t.ID = 200
	}
	return nil
}

func (m *oauthDBMock) GetTenantByName(context.Context, string) (*database.Tenant, error) {
	return nil, nil
}
func (m *oauthDBMock) GetTenantByID(context.Context, uint) (*database.Tenant, error) { return nil, nil }
func (m *oauthDBMock) UpdateTenant(context.Context, *database.Tenant) error          { return nil }
func (m *oauthDBMock) DeleteTenant(context.Context, uint) error                      { return nil }
func (m *oauthDBMock) ListTenants(context.Context) ([]*database.Tenant, error)       { return nil, nil }
func (m *oauthDBMock) AddUserToTenant(context.Context, uint, uint) error {
	m.linksCreated++
	return nil
}
func (m *oauthDBMock) RemoveUserFromTenant(context.Context, uint, uint) error { return nil }
func (m *oauthDBMock) GetUserTenants(context.Context, uint) ([]*database.Tenant, error) {
	return nil, nil
}

func (m *oauthDBMock) GetTenantUsers(context.Context, uint) ([]*database.User, error) {
	return nil, nil
}
func (m *oauthDBMock) DeleteUserTenants(context.Context, uint) error { return nil }
func (m *oauthDBMock) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
func (m *oauthDBMock) GetSystemPrompt(context.Context, uint) (string, error) { return "", nil }
func (m *oauthDBMock) SaveSystemPrompt(context.Context, uint, string) error  { return nil }

// Minimal auth mock: we only need IsGoogle/GitHub enabled in other tests; here test helpers directly
type noopAuth struct{ auth.Auth }

func TestOAuthHelper_generateTenantName(t *testing.T) {
	h := NewOAuthHandler(&oauthDBMock{}, mustNewJWTService(), &noopAuth{}, zap.NewNop())
	name, err := h.generateTenantName("user@example.com")
	assert.NoError(t, err)
	// prefix should be username_ and suffix 4 chars
	assert.Regexp(t, `^user_[A-Za-z0-9\-_]{4}$`, name)
}

func TestOAuthHelper_validateState(t *testing.T) {
	h := NewOAuthHandler(&oauthDBMock{}, mustNewJWTService(), &noopAuth{}, zap.NewNop())
	// Insert a state that expires in the future
	h.states["abc"] = time.Now().Add(1 * time.Minute)
	assert.True(t, h.validateState("abc"))
	// Second call should be false since it's consumed
	assert.False(t, h.validateState("abc"))
}

func TestOAuthHelper_handleOAuthUser_ExistingUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := &oauthDBMock{user: &database.User{ID: 1, Username: "u", Role: database.RoleNormal, IsActive: true}}
	h := NewOAuthHandler(db, mustNewJWTService(), &noopAuth{}, zap.NewNop())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)

	token, user, err := h.handleOAuthUser(c, &auth.ExternalUserInfo{Provider: "google", Email: "u"})
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, uint(1), user.ID)
	assert.Equal(t, 0, db.usersCreated)
}

func TestOAuthHelper_handleOAuthUser_CreateNew(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := &oauthDBMock{user: nil, findErr: assert.AnError}
	h := NewOAuthHandler(db, mustNewJWTService(), &noopAuth{}, zap.NewNop())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)

	token, user, err := h.handleOAuthUser(c, &auth.ExternalUserInfo{Provider: "github", Email: "user@example.com", Username: "user"})
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.NotNil(t, user)
	assert.Equal(t, 1, db.usersCreated)
	assert.Equal(t, 1, db.tenantsCreated)
	assert.Equal(t, 1, db.linksCreated)
}
