package storage

import (
	"context"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/errorx"
	"github.com/stretchr/testify/assert"
)

func newTestRedisStorage(t *testing.T) (*RedisStorage, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	s, err := NewRedisStorage(cnst.RedisClusterTypeSingle, mr.Addr(), "", "", "", 0)
	if err != nil {
		mr.Close()
		t.Fatalf("failed to create RedisStorage: %v", err)
	}
	return s, mr
}

func TestRedisStorage_ClientCRUD(t *testing.T) {
	s, mr := newTestRedisStorage(t)
	defer mr.Close()

	ctx := context.Background()

	c := &Client{ID: "c1", Secret: "s1", RedirectURIs: []string{"http://app/cb"}}
	assert.NoError(t, s.CreateClient(ctx, c))
	// duplicate
	assert.ErrorIs(t, s.CreateClient(ctx, c), errorx.ErrClientAlreadyExists)

	got, err := s.GetClient(ctx, "c1")
	assert.NoError(t, err)
	assert.Equal(t, "c1", got.ID)

	got.Secret = "s2"
	assert.NoError(t, s.UpdateClient(ctx, got))

	assert.NoError(t, s.DeleteClient(ctx, "c1"))
	_, err = s.GetClient(ctx, "c1")
	assert.ErrorIs(t, err, errorx.ErrInvalidClient)
}

func TestRedisStorage_AuthorizationCode_Flow(t *testing.T) {
	s, mr := newTestRedisStorage(t)
	defer mr.Close()

	ctx := context.Background()

	code := &AuthorizationCode{Code: "code1", ClientID: "c1", RedirectURI: "http://app/cb", ExpiresAt: time.Now().Add(5 * time.Second).Unix()}
	assert.NoError(t, s.SaveAuthorizationCode(ctx, code))
	got, err := s.GetAuthorizationCode(ctx, "code1")
	assert.NoError(t, err)
	assert.Equal(t, "c1", got.ClientID)

	assert.NoError(t, s.DeleteAuthorizationCode(ctx, "code1"))
	_, err = s.GetAuthorizationCode(ctx, "code1")
	assert.ErrorIs(t, err, errorx.ErrInvalidGrant)

	code2 := &AuthorizationCode{Code: "code2", ExpiresAt: time.Now().Add(-1 * time.Second).Unix()}
	assert.NoError(t, s.SaveAuthorizationCode(ctx, code2))
	_, err = s.GetAuthorizationCode(ctx, "code2")
	assert.ErrorIs(t, err, errorx.ErrAuthorizationCodeExpired)
}

func TestRedisStorage_Token_Flow(t *testing.T) {
	s, mr := newTestRedisStorage(t)
	defer mr.Close()

	ctx := context.Background()

	tok := &Token{AccessToken: "t1", ClientID: "c1", Scope: []string{"openid"}, ExpiresAt: time.Now().Add(5 * time.Second).Unix()}
	assert.NoError(t, s.SaveToken(ctx, tok))
	got, err := s.GetToken(ctx, "t1")
	assert.NoError(t, err)
	assert.Equal(t, "c1", got.ClientID)

	assert.NoError(t, s.DeleteToken(ctx, "t1"))
	_, err = s.GetToken(ctx, "t1")
	assert.ErrorIs(t, err, errorx.ErrInvalidGrant)

	tok2 := &Token{AccessToken: "t2", ClientID: "c2", ExpiresAt: time.Now().Add(-1 * time.Second).Unix()}
	assert.NoError(t, s.SaveToken(ctx, tok2))
	_, err = s.GetToken(ctx, "t2")
	assert.ErrorIs(t, err, errorx.ErrTokenExpired)

	// DeleteTokensByClientID
	_ = s.SaveToken(ctx, &Token{AccessToken: "t3", ClientID: "c3", ExpiresAt: time.Now().Add(5 * time.Second).Unix()})
	_ = s.SaveToken(ctx, &Token{AccessToken: "t4", ClientID: "c3", ExpiresAt: time.Now().Add(5 * time.Second).Unix()})
	assert.NoError(t, s.DeleteTokensByClientID(ctx, "c3"))
	_, err = s.GetToken(ctx, "t3")
	assert.Error(t, err)
}

func TestNewRedisStorage_ConnectionError(t *testing.T) {
	// invalid address should fail to ping
	s, err := NewRedisStorage(cnst.RedisClusterTypeSingle, "127.0.0.1:0", "", "", "", 0)
	assert.Nil(t, s)
	assert.Error(t, err)
}
