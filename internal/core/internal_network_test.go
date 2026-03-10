package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateToolEndpoint_InternalBlocked(t *testing.T) {
	s := &Server{internalNetEnabled: true}
	u, err := url.Parse("http://127.0.0.1:8080")
	assert.NoError(t, err)
	_, verr := s.validateToolEndpoint(context.Background(), u)
	assert.Error(t, verr)
}

func TestValidateToolEndpoint_InternalAllowlistedCIDR(t *testing.T) {
	allowlist, invalid := parseInternalNetworkAllowlist([]string{"127.0.0.0/8"})
	assert.Empty(t, invalid)

	s := &Server{internalNetEnabled: true, internalNetACL: allowlist}
	u, err := url.Parse("http://127.0.0.1:8080")
	assert.NoError(t, err)
	_, verr := s.validateToolEndpoint(context.Background(), u)
	assert.NoError(t, verr)
}

func TestValidateToolEndpoint_InternalAllowlistedHost(t *testing.T) {
	allowlist, invalid := parseInternalNetworkAllowlist([]string{"internal.local"})
	assert.Empty(t, invalid)

	s := &Server{internalNetEnabled: true, internalNetACL: allowlist}
	u, err := url.Parse("http://internal.local/health")
	assert.NoError(t, err)
	_, verr := s.validateToolEndpoint(context.Background(), u)
	assert.NoError(t, verr)
}

func TestValidateToolEndpoint_PublicIPAllowed(t *testing.T) {
	s := &Server{internalNetEnabled: true}
	u, err := url.Parse("http://8.8.8.8")
	assert.NoError(t, err)
	_, verr := s.validateToolEndpoint(context.Background(), u)
	assert.NoError(t, verr)
}

func TestValidateToolEndpoint_Disabled(t *testing.T) {
	s := &Server{internalNetEnabled: false}
	u, err := url.Parse("http://127.0.0.1:8080")
	assert.NoError(t, err)
	// When disabled, internal addresses should be allowed
	_, verr := s.validateToolEndpoint(context.Background(), u)
	assert.NoError(t, verr)
}

func TestIsInternalAddr_IPv4MappedIPv6(t *testing.T) {
	// ::ffff:127.0.0.1 should be detected as loopback
	mapped := netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1})
	assert.True(t, isInternalAddr(mapped), "IPv4-mapped loopback should be internal")

	// ::ffff:10.0.0.1 should be detected as private
	mappedPrivate := netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1})
	assert.True(t, isInternalAddr(mappedPrivate), "IPv4-mapped RFC1918 should be internal")

	// ::ffff:100.64.0.1 (CGNAT) should be detected as internal
	mappedCGNAT := netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 100, 64, 0, 1})
	assert.True(t, isInternalAddr(mappedCGNAT), "IPv4-mapped CGNAT should be internal")

	// ::ffff:8.8.8.8 should NOT be internal
	mappedPublic := netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8})
	assert.False(t, isInternalAddr(mappedPublic), "IPv4-mapped public IP should not be internal")
}

func TestCreateHTTPClient_RedirectToInternalBlocked(t *testing.T) {
	// Simulate a public server that redirects to an internal address
	redirectTarget := "http://169.254.169.254/latest/meta-data/"
	publicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget, http.StatusFound)
	}))
	defer publicServer.Close()

	s := &Server{internalNetEnabled: true}
	cli, err := s.createHTTPClient(nil, "")
	assert.NoError(t, err)

	req, _ := http.NewRequest("GET", publicServer.URL, nil)
	_, err = cli.Do(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redirect")
	assert.Contains(t, err.Error(), "blocked")
}

func TestCreateHTTPClient_RedirectToInternalAllowlisted(t *testing.T) {
	// Internal target server
	internalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer internalServer.Close()

	// Public server that redirects to the internal target
	publicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internalServer.URL+"/data", http.StatusFound)
	}))
	defer publicServer.Close()

	allowlist, _ := parseInternalNetworkAllowlist([]string{"127.0.0.0/8"})
	s := &Server{internalNetEnabled: true, internalNetACL: allowlist}
	cli, err := s.createHTTPClient(nil, "")
	assert.NoError(t, err)

	req, _ := http.NewRequest("GET", publicServer.URL, nil)
	resp, err := cli.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestCreateHTTPClient_ChainedRedirectBlocked(t *testing.T) {
	// Simulates a multi-hop redirect: public -> public -> internal
	internalTarget := "http://10.0.0.1/admin"

	hop2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internalTarget, http.StatusFound)
	}))
	defer hop2.Close()

	hop1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, hop2.URL, http.StatusFound)
	}))
	defer hop1.Close()

	s := &Server{internalNetEnabled: true}
	cli, err := s.createHTTPClient(nil, "")
	assert.NoError(t, err)

	req, _ := http.NewRequest("GET", hop1.URL, nil)
	_, err = cli.Do(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func TestCreateHTTPClient_PinnedAddr(t *testing.T) {
	// Verify that when a pinnedAddr is provided, the client connects to it
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "pinned")
	}))
	defer target.Close()

	// Extract host:port from the test server to use as pinnedAddr
	u, _ := url.Parse(target.URL)

	s := &Server{}
	cli, err := s.createHTTPClient(nil, u.Hostname())
	assert.NoError(t, err)

	// Request a URL with the same port but "127.0.0.1" host;
	// the pinned addr should override the hostname resolution.
	req, _ := http.NewRequest("GET", target.URL, nil)
	resp, err := cli.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}
