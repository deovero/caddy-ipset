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
	"sync"
	"syscall"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

var (
	// ipsetNameRegex validates ipset names to prevent command injection
	// Allows alphanumeric characters, hyphens, underscores, and dots
	ipsetNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-.]+$`)
)

func init() {
	caddy.RegisterModule((*IpsetMatcher)(nil))
}

// IpsetMatcher is a Caddy HTTP matcher that matches requests based on client IP
// addresses against Linux ipset lists.
type IpsetMatcher struct {
	// Ipset is the name of the ipset list to match against
	Ipset string `json:"ipset,omitempty"`

	logger *zap.Logger
	handle *netlink.Handle
	// ipsetFamily stores the IP family (IPv4 or IPv6) of the ipset
	// This is set during Provision and used to skip mismatched IP families during Match
	ipsetFamily uint8
	// mu protects concurrent access to the netlink handle
	// The netlink socket is not thread-safe and must be protected
	mu sync.Mutex
}

// CaddyModule returns the Caddy module information.
func (m *IpsetMatcher) CaddyModule() caddy.ModuleInfo {
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

	// Create a persistent netlink handle for reuse across requests
	// This avoids creating/destroying a socket for every HTTP request
	handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("ERROR failed to create netlink handle: %w", err)
	}
	m.handle = handle
	m.logger.Debug("Opened netlink handle", zap.String("ipset", m.Ipset))

	// Verify the ipset exists using netlink
	if err := m.verifyNetlinkIpset(); err != nil {
		_ = m.Cleanup()
		return err
	}

	return nil
}

// Cleanup closes the netlink handle when the module is unloaded.
func (m *IpsetMatcher) Cleanup() error {
	if m.handle != nil {
		m.handle.Close()
		m.logger.Debug("Closed netlink handle", zap.String("ipset", m.Ipset))
		m.handle = nil
	}
	return nil
}

// Match returns true if the request's IP is in the configured ipset.
func (m *IpsetMatcher) Match(req *http.Request) bool {
	// Check if handle is initialized (should be set during Provision)
	if m.handle == nil {
		if m.logger != nil {
			m.logger.Error("Netlink handle not initialized - matcher not properly provisioned")
		}
		return false
	}

	// Use Caddy's built-in client IP detection which respects trusted_proxies configuration
	var clientIP string
	clientIPvar := caddyhttp.GetVar(req.Context(), caddyhttp.ClientIPVarKey)
	if clientIPvar != nil {
		// Use the client IP determined by Caddy's trusted proxy logic
		clientIP = clientIPvar.(string)
		m.logger.Debug("Received client ip from Caddy", zap.String(caddyhttp.ClientIPVarKey, clientIP))
	} else {
		// Fallback to RemoteAddr if ClientIPVarKey is not set
		// This shouldn't normally happen in a Caddy HTTP handler context
		m.logger.Debug("Fallback to RemoteAddr", zap.String("RemoteAddr", req.RemoteAddr))
		// Extract IP address, stripping port if present
		var err error
		clientIP, _, err = net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			// If SplitHostPort fails, the address might not have a port
			// Try using it directly as an IP address
			clientIP = req.RemoteAddr
			m.logger.Debug("RemoteAddr has no port, using as-is",
				zap.String("RemoteAddr", req.RemoteAddr))
		}
	}

	// Parse the IP address
	ip := net.ParseIP(clientIP)
	if ip == nil {
		m.logger.Error("Invalid IP address",
			zap.String("ip", clientIP))
		return false
	}

	// Check if the IP family matches the ipset family
	// This optimization avoids unnecessary ipset lookups when the IP family doesn't match
	// For example, skip checking IPv6 addresses against IPv4 ipsets
	isIPv4 := ip.To4() != nil
	if m.ipsetFamily == unix.NFPROTO_IPV4 && !isIPv4 {
		m.logger.Warn("Skipped matching of IPv6 address against IPv4 ipset",
			zap.String("ip", clientIP),
			zap.String("ipset", m.Ipset))
		return false
	}
	if m.ipsetFamily == unix.NFPROTO_IPV6 && isIPv4 {
		m.logger.Warn("Skipped matching of IPv4 address against IPv6 ipset",
			zap.String("ip", clientIP),
			zap.String("ipset", m.Ipset))
		return false
	}

	// Match using netlink handle
	// Use the persistent handle to avoid creating a new socket for each request
	// Lock the mutex to ensure thread-safe access to the netlink socket
	m.mu.Lock()
	found, err := m.handle.IpsetTest(
		m.Ipset,
		&netlink.IPSetEntry{IP: ip},
	)
	m.mu.Unlock()

	if err != nil {
		m.logger.Error("Error testing IP against ipset",
			zap.String("ip", clientIP),
			zap.String("ipset", m.Ipset),
			zap.Error(err))
		return false
	}

	if !found {
		m.logger.Debug("IP not in ipset",
			zap.String("ip", clientIP),
			zap.String("ipset", m.Ipset))
		return false
	}

	m.logger.Debug("IP matched in ipset",
		zap.String("ip", clientIP),
		zap.String("ipset", m.Ipset))
	return true
}

// verifyNetlinkIpset verifies that netlink can access the ipset
func (m *IpsetMatcher) verifyNetlinkIpset() error {
	result, err := m.handle.IpsetList(m.Ipset)
	if err == nil {
		// Save the ipset family for later use in Match
		m.ipsetFamily = result.Family
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
	case unix.NFPROTO_IPV4:
		return "inet"
	case unix.NFPROTO_IPV6:
		return "inet6"
	default:
		return fmt.Sprintf("unknown(%d)", family)
	}
}

// Interface guards
var (
	_ caddy.Provisioner     = (*IpsetMatcher)(nil)
	_ caddy.CleanerUpper    = (*IpsetMatcher)(nil)
	_ caddyfile.Unmarshaler = (*IpsetMatcher)(nil)
)
