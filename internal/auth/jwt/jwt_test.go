package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestJWTService_GenerateAndValidate(t *testing.T) {
	s, err := NewService(Config{SecretKey: "this-is-a-very-long-secret-key-for-testing", Duration: time.Hour})
	assert.NoError(t, err)
	tok, err := s.GenerateToken(42, "alice", "admin")
	assert.NoError(t, err)
	claims, err := s.ValidateToken(tok)
	assert.NoError(t, err)
	if assert.NotNil(t, claims) {
		assert.Equal(t, uint(42), claims.UserID)
		assert.Equal(t, "alice", claims.Username)
		assert.Equal(t, "admin", claims.Role)
	}
}

func TestJWTService_ExpiredToken(t *testing.T) {
	s, err := NewService(Config{SecretKey: "this-is-a-very-long-secret-key-for-testing", Duration: time.Nanosecond})
	assert.NoError(t, err)
	tok, err := s.GenerateToken(1, "bob", "user")
	assert.NoError(t, err)
	time.Sleep(time.Millisecond)
	claims, err := s.ValidateToken(tok)
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, ErrExpiredToken)
}

func TestJWTService_InvalidToken(t *testing.T) {
	s, err := NewService(Config{SecretKey: "this-is-a-very-long-secret-key-for-testing", Duration: time.Hour})
	assert.NoError(t, err)

	claims, err := s.ValidateToken("not-a-token")
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestJWTService_ValidationErrors(t *testing.T) {
	t.Run("empty secret key", func(t *testing.T) {
		s, err := NewService(Config{SecretKey: "", Duration: time.Hour})
		assert.ErrorIs(t, err, ErrEmptySecretKey)
		assert.Nil(t, s)
	})

	t.Run("weak secret key", func(t *testing.T) {
		s, err := NewService(Config{SecretKey: "short", Duration: time.Hour})
		assert.ErrorIs(t, err, ErrWeakSecretKey)
		assert.Nil(t, s)
	})

	t.Run("invalid duration", func(t *testing.T) {
		s, err := NewService(Config{SecretKey: "this-is-a-very-long-secret-key-for-testing", Duration: 0})
		assert.ErrorIs(t, err, ErrInvalidDuration)
		assert.Nil(t, s)
	})
}
