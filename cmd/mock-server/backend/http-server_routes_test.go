package backend

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPServer_UserRoutes(t *testing.T) {
	s := NewHTTPServer()

	// Create user
	body := map[string]any{
		"username": "u1",
		"email":    "u1@example.com",
	}
	bb, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader(bb))
	r.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("create user status = %d", w.Code)
	}

	// Get by email
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/users/email/u1@example.com", nil)
	s.router.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("get user status = %d", w.Code)
	}

	// Update preferences
	prefs := map[string]any{
		"isPublic":      true,
		"showEmail":     false,
		"theme":         "dark",
		"tags":          []string{"a", "b"},
		"settings":      map[string]any{"k": "v"},
		"notifications": []Notification{{Type: "email", Channel: "system", Enabled: true, Frequency: 0}},
	}
	pb, _ := json.Marshal(prefs)
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPut, "/users/u1@example.com/preferences", bytes.NewReader(pb))
	r.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("update prefs status = %d", w.Code)
	}

	// Upload avatar missing url -> 400
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/users/u1@example.com/avatar", nil)
	s.router.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("avatar missing url status = %d", w.Code)
	}

	// Upload avatar with url
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/users/u1@example.com/avatar", bytes.NewBufferString("url=https://img"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.router.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("avatar ok status = %d", w.Code)
	}
}
