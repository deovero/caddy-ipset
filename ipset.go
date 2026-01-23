//go:build linux
// +build linux

// Package caddy_ipset provides a Caddy HTTP matcher module that matches requests
// based on client IP addresses against Linux ipset lists.
// It uses Caddy's built-in client IP detection which respects the trusted_proxies
// configuration.
package caddy_ipset

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"syscall"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

var (
	// ipsetNameRegex validates ipset names to prevent command injection
	// Allows alphanumeric characters, hyphens, underscores, and dots
	ipsetNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-.]+$`)
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
		return fmt.Errorf("ERROR ipset name is required")
	}

	// Validate ipset name
	if !ipsetNameRegex.MatchString(m.Ipset) {
		return fmt.Errorf("ERROR invalid ipset name '%s': must contain only alphanumeric characters, hyphens, underscores, and dots", m.Ipset)
	}

	// Verify the ipset exists using netlink
	if err := m.verifyNetlinkIpset(); err != nil {
		return err
	}

	return nil
}

// Match returns true if the request's IP is in the configured ipset.
func (m *IpsetMatcher) Match(req *http.Request) bool {
	// Use Caddy's built-in client IP detection which respects trusted_proxies configuration
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

	// Match using netlink
	found, err := netlink.IpsetTest(
		m.Ipset,
		&netlink.IPSetEntry{IP: ip},
	)

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

	m.logger.Debug("IP matched in ipset",
		zap.String("ip", remoteIP),
		zap.String("ipset", m.Ipset))
	return true
}

// verifyNetlinkIpset verifies that netlink can access the ipset
func (m *IpsetMatcher) verifyNetlinkIpset() error {
	result, err := netlink.IpsetList(m.Ipset)
	if err == nil {
		m.logger.Info("Tested access to netlink ipset, success",
			zap.String("ipset", m.Ipset),
			zap.String("type", result.TypeName),
			zap.String("family", familyToString(result.Family)),
		)
		return nil
	}
	// Check if this is a permission error
	if isPermissionError(err) {
		return fmt.Errorf("ERROR ipset '%s' cannot be accessed: permission denied. Grant CAP_NET_ADMIN capability with: sudo setcap cap_net_admin+ep ./caddy", m.Ipset)
	}
	// Not a permission error, ipset doesn't exist or other error
	return fmt.Errorf("ERROR ipset '%s' does not exist or cannot be accessed: %w", m.Ipset, err)
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

// isPermissionError checks if an error is a permission-related error
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	// Check for EPERM or EACCES
	if errno, ok := err.(syscall.Errno); ok {
		return errno == syscall.EPERM || errno == syscall.EACCES
	}
	// netlink errors might be wrapped
	return err.Error() == "operation not permitted" ||
		err.Error() == "permission denied"
}

// familyToString converts the ipset family code to a readable string
// Family codes are from NFPROTO_* constants in Linux kernel
func familyToString(family uint8) string {
	switch family {
	case 2: // NFPROTO_IPV4
		return "inet"
	case 10: // NFPROTO_IPV6
		return "inet6"
	default:
		return fmt.Sprintf("unknown(%d)", family)
	}
}

// Interface guards
var (
	_ caddy.Provisioner     = (*IpsetMatcher)(nil)
	_ caddyfile.Unmarshaler = (*IpsetMatcher)(nil)
)
