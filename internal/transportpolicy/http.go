// Package transportpolicy defines which literal relay addresses may use plain
// HTTP for local testing. It never performs DNS resolution or changes TLS policy.
package transportpolicy

import (
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strings"
)

const (
	HTTPRequirement   = "relay URL must use HTTPS for public addresses and hostnames; plain HTTP is allowed only for localhost, loopback IPs, or literal private LAN IPs (RFC1918 IPv4 or IPv6 ULA)"
	PrivateLANWarning = "Warning: private LAN HTTP is unencrypted; relay credentials and messages can be observed on the network. Use it only for trusted-LAN testing, and use HTTPS for shared or untrusted networks."
)

var privateLANPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// PlainHTTPAllowed classifies a URL.Hostname value without resolving names.
// In particular, link-local, unspecified, multicast, CGNAT, and public IPs are
// not accepted. The admin CLI owns its separate exact Compose-host exception.
func PlainHTTPAllowed(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, ok := literalIP(host)
	return ok && (ip.IsLoopback() || privateLANIP(ip))
}

// PrivateLANHost excludes localhost and loopback so only networked cleartext
// traffic produces the trusted-LAN warning. IPv4-mapped IPv6 is classified by
// its underlying IPv4 address, never as an unrelated IPv6 exception.
func PrivateLANHost(host string) bool {
	ip, ok := literalIP(host)
	return ok && privateLANIP(ip)
}

func literalIP(host string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func privateLANIP(ip netip.Addr) bool {
	for _, prefix := range privateLANPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// WarnPrivateLANHTTP writes only a fixed warning, never the URL or credentials.
// Callers choose interactive/setup contexts; background clients stay silent so
// MCP's stdout protocol and daemon output are not polluted on every request.
func WarnPrivateLANHTTP(rawURL string, stderr io.Writer) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err == nil && u.Scheme == "http" && PrivateLANHost(u.Hostname()) {
		_, _ = fmt.Fprintln(stderr, PrivateLANWarning)
	}
}
