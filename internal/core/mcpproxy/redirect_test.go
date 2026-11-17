package mcpproxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRedirectRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return &http.Request{URL: u}
}

func TestSameOriginRedirectPolicy(t *testing.T) {
	start := newRedirectRequest(t, "https://mcp.example.com/v1")

	tests := []struct {
		name    string
		target  string
		allowed bool
	}{
		{name: "same origin", target: "https://mcp.example.com/v2", allowed: true},
		{name: "default port", target: "https://mcp.example.com:443/v2", allowed: true},
		{name: "host case", target: "https://MCP.Example.com/v2", allowed: true},
		{name: "different host", target: "https://evil.example.net/v2", allowed: false},
		{name: "different scheme", target: "http://mcp.example.com/v2", allowed: false},
		{name: "different port", target: "https://mcp.example.com:8443/v2", allowed: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := sameOriginRedirectPolicy(newRedirectRequest(t, tc.target), []*http.Request{start})
			if tc.allowed {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, ErrCrossOriginRedirect)
		})
	}
}

func TestSameOriginRedirectPolicyTooManyRedirects(t *testing.T) {
	via := make([]*http.Request, maxUpstreamRedirects)
	for i := range via {
		via[i] = newRedirectRequest(t, "https://mcp.example.com/v1")
	}
	err := sameOriginRedirectPolicy(newRedirectRequest(t, "https://mcp.example.com/v2"), via)
	assert.ErrorIs(t, err, ErrCrossOriginRedirect)
}

func TestUpstreamHTTPClientFollowsSameOriginOnly(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/same" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	client := newUpstreamHTTPClient()

	// Same-origin redirects are followed.
	resp, err := client.Get(origin.URL + "/same")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))

	// A redirect to another host is refused so forwarded credentials are not
	// replayed to a host chosen by the upstream.
	crossOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/ok", http.StatusFound)
	}))
	defer crossOrigin.Close()

	_, err = client.Get(crossOrigin.URL)
	if assert.Error(t, err) {
		assert.True(t, errors.Is(err, ErrCrossOriginRedirect), "expected cross-origin redirect error, got %v", err)
	}
}
