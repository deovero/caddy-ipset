//go:build linux
// +build linux

// Package caddy_ipset provides a Caddy HTTP matcher module that matches requests
// based on client IP addresses against Linux ipset lists.
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
	// The netlink socket is not thread-safe and must be protected.
	// We use a mutex instead of a sync.Pool because netlink handles hold file descriptors
	// that must be explicitly closed to avoid leaks during Caddy configuration reloads.
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
	m.logger.Info("validated ipset existence",
		zap.String("ipset", m.Ipset),
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
		// Lock the mutex to ensure we don't close while a Match is in progress
		m.mu.Lock()
		defer m.mu.Unlock()
		m.handle.Close()
		m.logger.Debug("closed netlink handle", zap.String("ipset", m.Ipset))
		m.handle = nil
	}
	return nil
}

// MatchWithError implements the caddyhttp.RequestMatcherWithError interface.
// The client IP is determined using Caddy's built-in detection which respects
// the trusted_proxies configuration.
//
// The matching process:
//   - Extracts the client IP from the request (using Caddy's ClientIPVarKey or RemoteAddr)
//   - Validates the IP address format
//   - Checks if the IP family matches the ipset family (optimization)
//   - Performs the ipset lookup via netlink
//
// Returns false + error if:
//   - The netlink handle is not initialized
//   - The client IP cannot be determined or parsed
//   - An error occurs during ipset lookup
//
// Returns false if:
//   - The IP family doesn't match the ipset family
//   - The IP is not found in the ipset
//
// Returns true if:
//   - the client's IP address is found in the configured ipset.
func (m *IpsetMatcher) MatchWithError(req *http.Request) (bool, error) {
	// Check if handle is initialized (should be set during Provision)
	if m.handle == nil {
		return false, fmt.Errorf("netlink handle not initialized - matcher not properly provisioned")
	}

	// Use Caddy's built-in client IP detection which respects trusted_proxies configuration
	clientIPvar := caddyhttp.GetVar(req.Context(), caddyhttp.ClientIPVarKey)
	clientIP, ok := clientIPvar.(string)
	if !ok {
		return false, fmt.Errorf("%s is not a string but a %T", caddyhttp.ClientIPVarKey, clientIPvar)
	}

	// Parse the IP address
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", clientIP)
	}

	// Check if the IP family matches the ipset family
	// Generating a warning because your Caddy configuration should prevent this.
	isIPv4 := ip.To4() != nil
	if m.ipsetFamily == nl.FAMILY_V4 && !isIPv4 {
		m.logger.Warn("skipped matching of IPv6 address against IPv4 ipset. Your config should prevent this.",
			zap.String("ip", clientIP),
			zap.String("ipset", m.Ipset))
		return false, nil
	}
	if m.ipsetFamily == nl.FAMILY_V6 && isIPv4 {
		m.logger.Warn("skipped matching of IPv4 address against IPv6 ipset. Your config should prevent this.",
			zap.String("ip", clientIP),
			zap.String("ipset", m.Ipset))
		return false, nil
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
		return false, fmt.Errorf("error testing IP '%s' against ipset '%s': %w", clientIP, m.Ipset, err)
	}

	message := "IP not in ipset"
	if found {
		message = "IP matched in ipset"
	}
	m.logger.Debug(message,
		zap.String("ip", clientIP),
		zap.String("ipset", m.Ipset),
	)

	return found, nil
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
		// Ensure no extra arguments are provided
		if d.NextArg() {
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
	_ caddy.Provisioner                 = (*IpsetMatcher)(nil)
	_ caddy.CleanerUpper                = (*IpsetMatcher)(nil)
	_ caddyfile.Unmarshaler             = (*IpsetMatcher)(nil)
	_ caddyhttp.RequestMatcherWithError = (*IpsetMatcher)(nil)
)
