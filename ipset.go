//go:build linux
// +build linux

// Package caddy_ipset provides a Caddy HTTP matcher module that matches requests
// based on client IP addresses against Linux ipset lists.
package caddy_ipset

import (
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func init() {
	caddy.RegisterModule((*IpsetMatcher)(nil))
}

// IpsetMatcher matches the client_ip against Linux ipset lists using native netlink communication.
//
// This matcher provides high-performance IP matching by communicating directly
// with the Linux kernel via netlink, avoiding the overhead of spawning external
// processes.
//
// The matcher maintains a persistent netlink connection that is reused across
// requests for optimal performance. Thread-safety is ensured through mutex
// protection of the netlink handle.
//
// Requirements:
//   - Linux system with ipset kernel module loaded
//   - CAP_NET_ADMIN capability, grant with: `sudo setcap cap_net_admin+ep /path/to/caddy`
//   - Existing ipset list created via the `ipset` command
//
// Supports both IPv4 and IPv6 ipsets and does basic validation during provisioning.
// In case an IPv4 client_ip is matched against an IPv6 ipset or vise versa, the
// matcher will return false.
//
// When multiple ipsets are configured, the matcher will return true if the
// client_ip is in any of the ipsets (OR logic).
//
// Example Caddyfile usage:
//
// ```
//
//	example.com {
//		@matcher {
//			ipset test-ipset-v4
//			ipset test-ipset-v6
//		}
//		handle @matcher {
//			respond "IP matches an ipset" 200
//		}
//		respond "IP does NOT match any of the ipsets" 403
//	}
//
// ```
type IpsetMatcher struct {
	// Ipsets is a list of ipset names to match against
	// If the client IP is in ANY of these ipsets, the matcher returns true
	Ipsets []string `json:"ipsets,omitempty"`

	// handles stores netlink handles for each ipset
	handles []*netlink.Handle
	// ipsetFamilies stores the IP family (IPv4 or IPv6) for each ipset
	ipsetFamilies []uint8

	logger *zap.Logger

	// mu protects concurrent access to the netlink handles
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
//   - Validates that at least one ipset name is configured
//   - Checks for CAP_NET_ADMIN capability (fails fast with clear error)
//   - For each ipset:
//   - Validates the ipset name format and length
//   - Creates a persistent netlink handle for efficient request processing
//   - Verifies the ipset exists and is accessible
//   - Stores the ipset family (IPv4/IPv6) for optimization
//
// Returns an error if:
//   - No ipset name is configured
//   - CAP_NET_ADMIN capability is not granted
//   - An ipset name is empty or too long
//   - Netlink handle creation fails
//   - The ipset doesn't exist or cannot be accessed
func (m *IpsetMatcher) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	if len(m.Ipsets) == 0 {
		return fmt.Errorf("at least one ipset name is required")
	}

	capSet := cap.GetProc()
	// Check if the Effective set contains CAP_NET_ADMIN
	// CAP_NET_ADMIN corresponds to capability number 12, usually defined as cap.NET_ADMIN
	hasNetAdmin, err := capSet.GetFlag(cap.Effective, cap.NET_ADMIN)
	if err != nil {
		return fmt.Errorf("failed to get capability flag: %w", err)
	}
	if hasNetAdmin {
		m.logger.Debug("the process has CAP_NET_ADMIN")
	} else {
		return fmt.Errorf("CAP_NET_ADMIN capability required. Grant with: sudo setcap cap_net_admin+ep ./caddy")
	}

	// Create netlink handles for each ipset
	for _, ipsetName := range m.Ipsets {
		// Validate ipset name is not empty
		if ipsetName == "" {
			return fmt.Errorf("ipset name is required")
		}

		// Validate ipset name length
		if len(ipsetName) >= nl.IPSET_MAXNAMELEN {
			return fmt.Errorf("ipset name '%s' exceeds maximum length of %d characters", ipsetName, nl.IPSET_MAXNAMELEN-1)
		}

		// Create a persistent netlink handle for reuse across requests
		// This avoids creating/destroying a socket for every HTTP request
		handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
		if err != nil {
			return fmt.Errorf("failed to create netlink handle: %w", err)
		}

		m.logger.Debug("opened netlink handle", zap.String("ipset", ipsetName))

		// Verify the ipset exists using netlink
		result, err := handle.IpsetList(ipsetName)
		if err != nil {
			// Close this handle and any previously created handles
			handle.Close()
			for _, h := range m.handles {
				h.Close()
			}
			return fmt.Errorf("ipset '%s' does not exist or cannot be accessed: %w", ipsetName, err)
		}

		// Append the handle and family to the slices
		m.handles = append(m.handles, handle)
		m.ipsetFamilies = append(m.ipsetFamilies, result.Family)

		m.logger.Info("validated ipset existence",
			zap.String("ipset", ipsetName),
			zap.String("type", result.TypeName),
			zap.String("family", familyToString(result.Family)),
		)
	}

	// Sanity check: ensure we have the same number of ipsets, handles and families
	if len(m.Ipsets) != len(m.handles) || len(m.Ipsets) != len(m.ipsetFamilies) {
		return fmt.Errorf("provision error, sanity check failed")
	}

	return nil
}

// Cleanup closes all netlink handles when the module is unloaded.
// This method is called by Caddy during graceful shutdown or module reload.
// It ensures proper cleanup of system resources.
func (m *IpsetMatcher) Cleanup() error {
	if len(m.handles) > 0 {
		// Lock the mutex to ensure we don't close while a Match is in progress
		m.mu.Lock()
		defer m.mu.Unlock()

		// Close all handles
		for i, handle := range m.handles {
			if handle != nil {
				handle.Close()
				ipsetName := m.Ipsets[i]
				m.logger.Debug("closed netlink handle", zap.String("ipset", ipsetName))
			}
		}

		// Clear the slices
		m.Ipsets = nil
		m.handles = nil
		m.ipsetFamilies = nil
	}
	return nil
}

// MatchWithError implements the caddyhttp.RequestMatcherWithError interface.
// The client IP is determined using Caddy's built-in detection which respects
// the trusted_proxies configuration.
//
// The matching process:
//   - Extracts the client_ip from the request
//   - Validates the IP address format
//   - Checks each configured ipset in order
//   - For each ipset, checks if the IP family matches (optimization)
//   - Performs the ipset lookup via netlink
//   - Returns true if found in ANY ipset (OR logic)
//
// Returns false + error if:
//   - No netlink handles are initialized
//   - The client IP cannot be determined or parsed
//   - An error occurs during ipset lookup
//
// Returns false if:
//   - The IP is not found in any of the configured ipsets
//
// Returns true if:
//   - the client's IP address is found in at least one configured ipset.
func (m *IpsetMatcher) MatchWithError(req *http.Request) (bool, error) {
	// Check if handles are initialized (should be set during Provision)
	if len(m.handles) == 0 {
		return false, fmt.Errorf("netlink handles not initialized - matcher not properly provisioned")
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
		return false, fmt.Errorf("invalid IP address '%s'", clientIP)
	}

	// Check if the IP is in ANY of the configured ipsets (OR logic)
	isIPv4 := ip.To4() != nil

	// Lock the mutex to ensure thread-safe access to the netlink sockets
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, ipsetName := range m.Ipsets {
		handle := m.handles[i]
		if handle == nil {
			m.logger.Error("netlink handle is nil, skipping ipset",
				zap.String("ip", clientIP),
				zap.String("ipset", ipsetName),
			)
			continue
		}
		// Check if the IP family matches the ipset family (optimization)
		ipsetFamily := m.ipsetFamilies[i]
		if ipsetFamily == nl.FAMILY_V4 && !isIPv4 {
			m.logger.Debug("skipped matching of IPv6 address against IPv4 ipset",
				zap.String("ip", clientIP),
				zap.String("ipset", ipsetName))
			continue
		}
		if ipsetFamily == nl.FAMILY_V6 && isIPv4 {
			m.logger.Debug("skipped matching of IPv4 address against IPv6 ipset",
				zap.String("ip", clientIP),
				zap.String("ipset", ipsetName))
			continue
		}

		// Test if the IP is in this ipset
		found, err := handle.IpsetTest(
			ipsetName,
			&netlink.IPSetEntry{IP: ip},
		)

		if err != nil {
			return false, fmt.Errorf("error testing IP '%s' against ipset '%s': %w", clientIP, ipsetName, err)
		}

		// OR logic: if found in ANY ipset, return true immediately
		if found {
			m.logger.Debug("IP matched in ipset",
				zap.String("ip", clientIP),
				zap.String("ipset", ipsetName),
			)
			return true, nil
		}

		// Not found in this ipset, continue to check the next one
		m.logger.Debug("IP not in ipset, checking next",
			zap.String("ip", clientIP),
			zap.String("ipset", ipsetName),
		)
	}

	// Not found in any ipset
	m.logger.Debug("IP not found in any ipset",
		zap.String("ip", clientIP),
		zap.Int("ipsets_checked", len(m.Ipsets)),
	)
	return false, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
// It parses the Caddyfile configuration for the ipset matcher.
//
// Syntax:
//
// ```
//
//	ipset <name> <name> ...
//	ipset <name> <name> <name> ...
//
// ```
//
// Example:
//
// ```
//
// @blocked ipset blocklist-v4
//
// ```
//
// Multiple ipset directives in a matcher block:
//
// ```
//
//	@matcher {
//	    ipset test-ipset-v4
//	    ipset test-ipset-v6
//	}
//
// ```
//
// This creates a single matcher that checks if the client IP is in ANY of the
// specified ipsets (OR logic).
func (m *IpsetMatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Process all ipset directives in the matcher block
	for d.Next() {
		for d.NextArg() {
			m.Ipsets = append(m.Ipsets, d.Val())
		}
	}

	if len(m.Ipsets) == 0 {
		return d.Err("expected at least one ipset name")
	}

	return nil
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
