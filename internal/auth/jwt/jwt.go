package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token has expired")
	ErrInvalidAlgorithm = errors.New("invalid signing algorithm")
	ErrEmptySecretKey   = errors.New("secret key cannot be empty")
	ErrWeakSecretKey    = errors.New("secret key must be at least 32 characters")
	ErrInvalidDuration  = errors.New("duration must be positive")
)

// Claims represents the JWT claims
type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Config represents the JWT configuration
type Config struct {
	SecretKey string        `yaml:"secret_key"`
	Duration  time.Duration `yaml:"duration"`
}

// Service represents the JWT service
type Service struct {
	config Config
}

// NewService creates a new JWT service
func NewService(config Config) (*Service, error) {
	if config.SecretKey == "" {
		return nil, ErrEmptySecretKey
	}
	if len(config.SecretKey) < 32 {
		return nil, ErrWeakSecretKey
	}
	if config.Duration <= 0 {
		return nil, ErrInvalidDuration
	}
	return &Service{
		config: config,
	}, nil
}

// GenerateToken generates a new JWT token
func (s *Service) GenerateToken(userID uint, username string, role string) (string, error) {
	claims := &Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.Duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.SecretKey))
}

// ValidateToken validates a JWT token
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidAlgorithm
		}
		return []byte(s.config.SecretKey), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}
