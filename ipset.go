//go:build linux
// +build linux

// Package caddy_ipset provides a Caddy HTTP matcher module that matches requests
// based on client IP addresses against Linux ipset lists.
// It uses Caddy's built-in client IP detection which respects the trusted_proxies
// configuration.
package caddy_ipset

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"syscall"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
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

// Provision sets up the matcher by validating the ipset configuration and
// establishing a persistent netlink connection to the kernel.
// This method is called by Caddy during module initialization.
//
// It performs the following steps:
//   - Validates that an ipset name is provided
//   - Validates the ipset name format and length
//   - Creates a persistent netlink handle for efficient request processing
//   - Verifies the ipset exists and is accessible
//   - Stores the ipset family (IPv4/IPv6) for optimization
//
// Returns an error if:
//   - No ipset name is configured
//   - The ipset name is too long
//   - Netlink handle creation fails
//   - The ipset doesn't exist or cannot be accessed
//   - Permission is denied (CAP_NET_ADMIN capability required)
func (m *IpsetMatcher) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	if m.Ipset == "" {
		return fmt.Errorf("ipset name is required")
	}

	// Validate ipset name length
	if len(m.Ipset) >= nl.IPSET_MAXNAMELEN {
		return fmt.Errorf("ipset name '%s' exceeds maximum length of %d characters", m.Ipset, nl.IPSET_MAXNAMELEN-1)
	}

	// Create a persistent netlink handle for reuse across requests
	// This avoids creating/destroying a socket for every HTTP request
	handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %w", err)
	}
	m.handle = handle
	m.logger.Debug("opened netlink handle", zap.String("ipset", m.Ipset))

	// Verify the ipset exists using netlink
	result, err := m.handle.IpsetList(m.Ipset)
	if err != nil {
		_ = m.Cleanup()
		// Check if this is a permission error
		if isPermissionError(err) {
			return fmt.Errorf("ipset '%s' cannot be accessed: permission denied. Grant CAP_NET_ADMIN capability with: sudo setcap cap_net_admin+ep ./caddy", m.Ipset)
		}
		// Not a permission error, ipset doesn't exist or other error
		return fmt.Errorf("ipset '%s' does not exist or cannot be accessed: %w", m.Ipset, err)
	}
	// Save the ipset family for later use in Match
	m.ipsetFamily = result.Family
	m.logger.Info(fmt.Sprintf("checked netlink ipset '%s', success", m.Ipset),
		zap.String("type", result.TypeName),
		zap.String("family", familyToString(result.Family)),
	)
	return nil
}

// Cleanup closes the netlink handle when the module is unloaded.
// This method is called by Caddy during graceful shutdown or module reload.
// It ensures proper cleanup of system resources.
func (m *IpsetMatcher) Cleanup() error {
	if m.handle != nil {
		// Lock the mutex to ensure thread-safe access to the netlink socket
		m.mu.Lock()
		defer m.mu.Unlock()
		m.handle.Close()
		m.logger.Debug("closed netlink handle", zap.String("ipset", m.Ipset))
		m.handle = nil
	}
	return nil
}

// Match implements the caddyhttp.RequestMatcher interface.
// It returns true if the client's IP address is found in the configured ipset.
// The client IP is determined using Caddy's built-in detection which respects
// the trusted_proxies configuration.
//
// The matching process:
//   - Extracts the client IP from the request (using Caddy's ClientIPVarKey or RemoteAddr)
//   - Validates the IP address format
//   - Checks if the IP family matches the ipset family (optimization)
//   - Performs the ipset lookup via netlink
//
// Returns false if:
//   - The netlink handle is not initialized
//   - The client IP cannot be determined or parsed
//   - The IP family doesn't match the ipset family
//   - An error occurs during ipset lookup
//   - The IP is not found in the ipset
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
		// Safely assert the type to string
		var ok bool
		clientIP, ok = clientIPvar.(string)
		if !ok {
			m.logger.Error("ClientIPVarKey is not a string",
				zap.Any("value", clientIPvar),
				zap.String("type", fmt.Sprintf("%T", clientIPvar)))
			return false
		}
		m.logger.Debug("received client ip from Caddy", zap.String(caddyhttp.ClientIPVarKey, clientIP))
	} else {
		// Fallback to RemoteAddr if ClientIPVarKey is not set
		// This shouldn't normally happen in a Caddy HTTP handler context
		m.logger.Debug("fallback to RemoteAddr", zap.String("RemoteAddr", req.RemoteAddr))
		// Extract IP address, stripping port if present
		var err error
		clientIP, _, err = net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			// If SplitHostPort fails, the address might not have a port
			// Try using it directly as an IP address
			clientIP = req.RemoteAddr
			m.logger.Debug("remoteAddr has no port, using as-is",
				zap.String("remoteAddr", req.RemoteAddr))
		}
	}

	// Parse the IP address
	ip := net.ParseIP(clientIP)
	if ip == nil {
		m.logger.Error("invalid IP address",
			zap.String("ip", clientIP))
		return false
	}

	// Check if the IP family matches the ipset family
	// This optimization avoids unnecessary ipset lookups when the IP family doesn't match
	// For example, skip checking IPv6 addresses against IPv4 ipsets
	// Generating a warning because your Caddy configuration should prevent this.
	isIPv4 := ip.To4() != nil
	if m.ipsetFamily == nl.FAMILY_V4 && !isIPv4 {
		m.logger.Warn("skipped matching of IPv6 address against IPv4 ipset",
			zap.String("ip", clientIP),
			zap.String("ipset", m.Ipset))
		return false
	}
	if m.ipsetFamily == nl.FAMILY_V6 && isIPv4 {
		m.logger.Warn("skipped matching of IPv4 address against IPv6 ipset",
			zap.String("ip", clientIP),
			zap.String("ipset", m.Ipset))
		return false
	}

	// Match using netlink handle
	// Use the persistent handle to avoid creating a new socket for each request
	// Lock the mutex to ensure thread-safe access to the netlink socket
	m.mu.Lock()
	defer m.mu.Unlock()
	found, err := m.handle.IpsetTest(
		m.Ipset,
		&netlink.IPSetEntry{IP: ip},
	)

	if err != nil {
		m.logger.Error("error testing IP against ipset",
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

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
// It parses the Caddyfile configuration for the ipset matcher.
//
// Syntax:
//
//	ipset <name>
//
// Example:
//
//	@blocked ipset blocklist-v4
func (m *IpsetMatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&m.Ipset) {
			return d.ArgErr()
		}
	}
	return nil
}

// isPermissionError checks if an error is a permission-related error.
// It handles both direct syscall errors and wrapped errors.
//
// Returns true if the error is EPERM or EACCES, indicating that
// CAP_NET_ADMIN capability is required.
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	// Check for direct syscall.Errno
	if errno, ok := err.(syscall.Errno); ok {
		return errno == syscall.EPERM || errno == syscall.EACCES
	}
	// Check for wrapped syscall.Errno using errors.As
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EPERM || errno == syscall.EACCES
	}
	return false
}

// familyToString converts the ipset family code to a readable string.
// Family codes are from NFPROTO_* constants in Linux kernel.
//
// Returns:
//   - "inet" for IPv4 (NFPROTO_IPV4)
//   - "inet6" for IPv6 (NFPROTO_IPV6)
//   - "unknown(N)" for unrecognized family codes
func familyToString(family uint8) string {
	switch family {
	case nl.FAMILY_V4:
		return "inet"
	case nl.FAMILY_V6:
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
