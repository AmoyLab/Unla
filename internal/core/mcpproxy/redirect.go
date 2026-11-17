package mcpproxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ErrCrossOriginRedirect is returned when an upstream server redirects a
// request to a different origin. Following it would replay the configured
// headers and any forwarded caller Authorization to a host the upstream chose.
var ErrCrossOriginRedirect = errors.New("refusing cross-origin redirect")

// maxUpstreamRedirects mirrors the limit net/http applies when CheckRedirect
// is nil.
const maxUpstreamRedirects = 10

// newUpstreamHTTPClient returns the HTTP client used for upstream MCP
// transports. It only follows same-origin redirects so caller credentials
// forwarded by the gateway cannot leak to a third-party host (GO-2026-6911).
func newUpstreamHTTPClient() *http.Client {
	return &http.Client{CheckRedirect: sameOriginRedirectPolicy}
}

// sameOriginRedirectPolicy follows a redirect only when the destination has
// the origin of the request that started the chain, and at most
// maxUpstreamRedirects times.
func sameOriginRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= maxUpstreamRedirects {
		return fmt.Errorf("%w: stopped after %d redirects", ErrCrossOriginRedirect, maxUpstreamRedirects)
	}
	if len(via) == 0 {
		return nil
	}
	from := via[0].URL
	if !sameOrigin(from, req.URL) {
		return fmt.Errorf("%w: %s://%s to %s://%s",
			ErrCrossOriginRedirect, from.Scheme, from.Host, req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// sameOrigin reports whether a and b have the same scheme, host and port.
func sameOrigin(a, b *url.URL) bool {
	return origin(a) == origin(b)
}

// origin returns a normalized scheme://host:port string. The scheme and host
// are lowercased and a missing port becomes the scheme default, so
// "https://example.com" and "https://EXAMPLE.com:443" compare equal.
func origin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if n, err := strconv.ParseUint(port, 10, 16); err == nil {
		port = strconv.FormatUint(n, 10)
	}
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}
