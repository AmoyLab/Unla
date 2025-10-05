package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jsvc "github.com/amoylab/unla/internal/auth/jwt"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func performRequest(h http.HandlerFunc, headers map[string]string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/p", JWTAuthMiddleware(hdrSvc), func(c *gin.Context) {
		h(c.Writer, c.Request)
	})
	req := httptest.NewRequest("GET", "/p", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

var hdrSvc = func() *jsvc.Service {
	s, _ := jsvc.NewService(jsvc.Config{SecretKey: "this-is-a-very-long-secret-key-for-testing", Duration: time.Hour})
	return s
}()

func TestJWTAuthMiddleware_MissingHeader(t *testing.T) {
	w := performRequest(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthMiddleware_BadPrefix(t *testing.T) {
	w := performRequest(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, map[string]string{"Authorization": "Token abc"})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthMiddleware_InvalidToken(t *testing.T) {
	w := performRequest(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, map[string]string{"Authorization": "Bearer invalid"})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthMiddleware_Valid(t *testing.T) {
	tok, _ := hdrSvc.GenerateToken(7, "u", "r")
	w := performRequest(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }, map[string]string{"Authorization": "Bearer " + tok})
	assert.Equal(t, http.StatusNoContent, w.Code)
}
