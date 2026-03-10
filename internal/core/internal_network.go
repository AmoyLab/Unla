package core

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type internalNetworkAllowlist struct {
	hosts    map[string]struct{}
	addrs    map[netip.Addr]struct{}
	prefixes []netip.Prefix
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

func parseInternalNetworkAllowlist(entries []string) (internalNetworkAllowlist, []string) {
	allowlist := internalNetworkAllowlist{
		hosts: make(map[string]struct{}),
		addrs: make(map[netip.Addr]struct{}),
	}
	var invalid []string

	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}

		normalized := normalizeHost(entry)
		if strings.Contains(normalized, "/") {
			prefix, err := netip.ParsePrefix(normalized)
			if err != nil {
				invalid = append(invalid, entry)
				continue
			}
			allowlist.prefixes = append(allowlist.prefixes, prefix)
			continue
		}

		addr, err := netip.ParseAddr(normalized)
		if err == nil {
			allowlist.addrs[addr] = struct{}{}
			continue
		}

		allowlist.hosts[normalized] = struct{}{}
	}

	return allowlist, invalid
}

func (a internalNetworkAllowlist) allowsHost(host string) bool {
	if len(a.hosts) == 0 {
		return false
	}
	_, ok := a.hosts[normalizeHost(host)]
	return ok
}

func (a internalNetworkAllowlist) allowsAddr(addr netip.Addr) bool {
	if len(a.addrs) > 0 {
		if _, ok := a.addrs[addr]; ok {
			return true
		}
	}
	for _, prefix := range a.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func normalizeHost(host string) string {
	normalized := strings.TrimSpace(strings.ToLower(host))
	return strings.TrimSuffix(normalized, ".")
}

func isInternalAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}

	// Unmap IPv4-in-IPv6 (e.g. ::ffff:10.0.0.1) so all subsequent checks
	// work uniformly. Without this, Is4() returns false for mapped addresses
	// and the CGNAT prefix check would be skipped.
	addr = addr.Unmap()

	if addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
		return true
	}

	if addr.Is4() {
		return cgnatPrefix.Contains(addr)
	}

	return false
}

// validateToolEndpoint checks whether the endpoint is allowed by the
// internal-network policy. It returns the first resolved IP address (if DNS
// resolution was performed) so the caller can pin the connection and prevent
// DNS-rebinding attacks. When the host is already an IP literal or validation
// is disabled, resolvedIP will be empty.
func (s *Server) validateToolEndpoint(ctx context.Context, endpoint *url.URL) (resolvedIP string, err error) {
	if !s.internalNetEnabled {
		return "", nil
	}

	if endpoint == nil {
		return "", fmt.Errorf("tool endpoint is empty")
	}

	host := endpoint.Hostname()
	if host == "" {
		return "", fmt.Errorf("tool endpoint host is empty")
	}

	if s.internalNetACL.allowsHost(host) {
		return "", nil
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if isInternalAddr(addr) && !s.internalNetACL.allowsAddr(addr) {
			return "", fmt.Errorf("internal network access is disabled for tool endpoints")
		}
		// Host is an IP literal; no DNS involved, no rebinding risk.
		return "", nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve tool endpoint host for internal access check: %w", err)
	}

	internalFound := false
	var firstAddr string
	for _, addr := range addrs {
		ip, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if firstAddr == "" {
			firstAddr = ip.String()
		}
		if isInternalAddr(ip) {
			internalFound = true
			if s.internalNetACL.allowsAddr(ip) {
				return firstAddr, nil
			}
		}
	}

	if internalFound {
		return "", fmt.Errorf("internal network access is disabled for tool endpoints")
	}

	// Return the resolved IP so the transport can pin the connection.
	return firstAddr, nil
}
