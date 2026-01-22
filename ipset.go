//go:build linux
// +build linux

// Package caddy_ipset provides a Caddy HTTP matcher module that matches requests
// based on client IP addresses against Linux ipset lists.
//
// This module allows you to match HTTP requests against existing Linux ipset lists.
// It uses Caddy's built-in client IP detection which respects the trusted_proxies
// configuration, automatically handling X-Forwarded-For, X-Real-IP, Cf-Connecting-IP,
// and other proxy headers when configured.
package caddy_ipset

import (
	"fmt"
	"net"
	"net/http"
	"regexp"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)



var (
	// ipsetNameRegex validates ipset names to prevent command injection
	// Allows alphanumeric characters, hyphens, underscores, and dots
	ipsetNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)
)

func init() {
	caddy.RegisterModule(IpsetMatcher{})
}

// IpsetMatcher is a Caddy HTTP matcher that matches requests based on client IP
// addresses against Linux ipset lists.
type IpsetMatcher struct {
	// Ipset is the name of the ipset list to match against
	Ipset string `json:"ipset,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (m IpsetMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.ipset",
		New: func() caddy.Module { return new(IpsetMatcher) },
	}
}

// Provision sets up the matcher.
func (m *IpsetMatcher) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	if m.Ipset == "" {
		return fmt.Errorf("ipset name is required")
	}

	// Validate ipset name to prevent issues with special characters
	// While we're using netlink now (not shell commands), this is still good practice
	if !ipsetNameRegex.MatchString(m.Ipset) {
		return fmt.Errorf("invalid ipset name '%s': must contain only alphanumeric characters, hyphens, underscores, and dots", m.Ipset)
	}

	// Verify the ipset exists using native netlink
	_, err := netlink.IpsetList(m.Ipset)
	if err != nil {
		return fmt.Errorf("ipset '%s' does not exist or cannot be accessed: %w", m.Ipset, err)
	}

	m.logger.Info("ipset matcher provisioned", zap.String("ipset", m.Ipset))
	return nil
}

// Match returns true if the request's IP is in the configured ipset.
func (m *IpsetMatcher) Match(req *http.Request) bool {
	// Use Caddy's built-in client IP detection which respects trusted_proxies configuration
	// This automatically handles X-Forwarded-For, X-Real-IP, Cf-Connecting-IP, and other headers
	// based on the server's trusted_proxies setting
	var clientIPStr string
	clientIP := caddyhttp.GetVar(req.Context(), caddyhttp.ClientIPVarKey)
	if clientIP != nil {
		// Use the client IP determined by Caddy's trusted proxy logic
		clientIPStr = clientIP.(string)
	} else {
		// Fallback to RemoteAddr if ClientIPVarKey is not set
		// This shouldn't normally happen in a Caddy HTTP handler context
		clientIPStr = req.RemoteAddr
	}

	// Extract IP address, stripping port if present
	// ClientIPVarKey and RemoteAddr may both contain port numbers
	remoteIP, _, err := net.SplitHostPort(clientIPStr)
	if err != nil {
		// If SplitHostPort fails, the string might be just an IP without a port
		// Use it directly
		remoteIP = clientIPStr
	}

	// Parse the IP address
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		m.logger.Error("Invalid IP address",
			zap.String("ip", remoteIP))
		return false
	}

	// Test if the IP is in the ipset using native netlink
	// This communicates directly with the kernel via netlink instead of shelling out
	entry := &netlink.IPSetEntry{
		IP: ip,
	}

	found, err := netlink.IpsetTest(m.Ipset, entry)
	if err != nil {
		m.logger.Error("Error testing IP against ipset",
			zap.String("ip", remoteIP),
			zap.String("ipset", m.Ipset),
			zap.Error(err))
		return false
	}

	if !found {
		m.logger.Debug("IP not in ipset",
			zap.String("ip", remoteIP),
			zap.String("ipset", m.Ipset))
		return false
	}

	m.logger.Info("IP matched in ipset",
		zap.String("ip", remoteIP),
		zap.String("ipset", m.Ipset))
	return true
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *IpsetMatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&m.Ipset) {
			return d.ArgErr()
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*IpsetMatcher)(nil)
	_ caddyfile.Unmarshaler = (*IpsetMatcher)(nil)
)
