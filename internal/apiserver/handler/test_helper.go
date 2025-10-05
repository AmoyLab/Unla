package handler

import (
	"time"

	jsvc "github.com/amoylab/unla/internal/auth/jwt"
)

func mustNewJWTService() *jsvc.Service {
	s, _ := jsvc.NewService(jsvc.Config{SecretKey: "this-is-a-very-long-secret-key-for-testing", Duration: time.Hour})
	return s
}
