//go:build linux
// +build linux

// Package caddy_ipset provides a Caddy HTTP matcher module that matches requests
// based on client IP addresses against Linux ipset lists.
package caddy_ipset

import (
	"fmt"
	"net"
	"net/http"
	"os"

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
	// Caddy's module analyzer requires either a composite literal or the use of new() instead of the & notation
	// for submission to https://caddyserver.com/account/register-package
	caddy.RegisterModule(IpsetMatcher{})
}

const (
	// IP family string constants
	ipFamilyIPv4 = "IPv4"
	ipFamilyIPv6 = "IPv6"
)

// IpsetMatcher matches the client_ip against Linux ipset lists using native netlink communication.
//
// This matcher provides high-performance IP matching by communicating directly
// with the Linux kernel via netlink, avoiding the overhead of spawning external
// processes.
//
// Requirements:
//   - Linux system with ipset kernel module loaded
//   - CAP_NET_ADMIN capability, grant with: `sudo setcap cap_net_admin+ep /path/to/caddy`
//   - Existing ipset list created via the `ipset` command
//
// Supports both IPv4 and IPv6 ipsets and does basic validation during provisioning.
// In case an IPv4 client_ip is matched against an IPv6 ipset or vice versa, the
// matcher will return false.
//
// When multiple ipsets are configured, the matcher will return true if the
// client_ip is in any of the ipsets (OR logic).
//
// The matcher uses a buffered channel as a "leaky bucket" pool of netlink handles.
// This allows high-performance concurrent processing while preventing resource leaks
// by capping the number of idle handles.
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
//
// Extended documentation can be found in [README.md](https://github.com/deovero/caddy-ipset/blob/main/README.md)
type IpsetMatcher struct {
	// Ipsets is a list of ipset names to match against
	// If the client IP is in ANY of these ipsets, the matcher returns true
	Ipsets []string `json:"ipsets,omitempty"`

	// ipsetFamilies stores the IP family (IPv4 or IPv6) for each ipset
	ipsetFamilies []uint8

	// pool acts as a leaky bucket for netlink handles.
	// It holds a fixed number of reusable handles. If the pool is empty,
	// new handles are created on demand. If the pool is full when returning,
	// excess handles are closed.
	pool chan *netlink.Handle

	// instance is a unique identifier for this Caddy instance
	instance string

	// During Provision() we will store the logger from Caddy's context here.
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
// must have a value receiver so it can be called from a pointer.
func (IpsetMatcher) CaddyModule() caddy.ModuleInfo {
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
//   - Verifies the ipset exists and is accessible
//   - Stores the ipset family (IPv4/IPv6) for optimization
//
// Returns an error if:
//   - CAP_NET_ADMIN capability is not granted
//   - An ipset name is empty or too long
//   - Netlink handle creation fails
//   - The ipset doesn't exist or cannot be accessed
func (m *IpsetMatcher) Provision(ctx caddy.Context) error {
	// Generate a unique instance ID for this matcher instance
	caddyInstanceID, err := caddy.InstanceID()
	if err != nil {
		return fmt.Errorf("failed to get Caddy instance ID: %w", err)
	}
	m.instance = caddyInstanceID.String()

	// Get the logger from Caddy's context
	m.logger = ctx.Logger(m)

	// Check if the Effective capabilities set contains CAP_NET_ADMIN
	capSet := cap.GetProc()
	hasNetAdmin, err := capSet.GetFlag(cap.Effective, cap.NET_ADMIN)
	if err != nil {
		return fmt.Errorf("failed to get capability flag: %w", err)
	}
	if hasNetAdmin {
		m.logger.Debug("the process has CAP_NET_ADMIN capability",
			zap.String("instance", m.instance),
		)
	} else {
		return fmt.Errorf("CAP_NET_ADMIN capability required. Grant with: sudo setcap cap_net_admin+ep %s", os.Args[0])
	}

	// Initialize the channel pool.
	// 128 is a safe buffer size to handle concurrent bursts without
	// constantly creating/destroying sockets, while keeping memory usage low.
	m.pool = make(chan *netlink.Handle, 128)

	// Pre-allocate ipsetFamilies slice with known capacity
	m.ipsetFamilies = make([]uint8, 0, len(m.Ipsets))

	// Create a temporary handle just for ipset access validation.
	// We do not use the pool here to ensure deterministic startup behavior.
	handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		m.logger.Error("failed to create netlink handle for ipset validation",
			zap.Error(err),
			zap.String("instance_id", m.instance),
		)
		return err
	}
	defer handle.Close()

	// Validate each ipset and store its family information
	for _, ipsetName := range m.Ipsets {
		// Validate ipset name is not empty
		if ipsetName == "" {
			return fmt.Errorf("ipset name is required")
		}
		// Validate ipset name maximum length
		if len(ipsetName) >= nl.IPSET_MAXNAMELEN {
			return fmt.Errorf("ipset name '%s' exceeds maximum length of %d characters", ipsetName, nl.IPSET_MAXNAMELEN-1)
		}

		// Verify the ipset exists using netlink
		result, err := handle.IpsetList(ipsetName)
		if err != nil {
			return fmt.Errorf("error checking ipset '%s': %w", ipsetName, err)
		}

		// Store the family information for this ipset
		m.ipsetFamilies = append(m.ipsetFamilies, result.Family)

		m.logger.Info("validated ipset existence",
			zap.String("ipset", ipsetName),
			zap.String("type", result.TypeName),
			zap.String("family", familyCodeToString(result.Family)),
			zap.String("instance_id", m.instance),
		)
	}

	m.logger.Info("ipset matcher provisioned",
		zap.String("instance_id", m.instance),
	)

	return nil
}

// Cleanup closes all netlink handles when the module is unloaded.
// This method is called by Caddy during graceful shutdown or module reload.
// It ensures proper cleanup of system resources.
func (m *IpsetMatcher) Cleanup() error {
	// Close the channel to signal no new items (mostly for correctness,
	// though concurrent writes during cleanup shouldn't happen in Caddy).
	close(m.pool)

	count := 0
	// Drain the pool and close every handle inside
	for handle := range m.pool {
		if handle != nil {
			handle.Close()
			count++
		}
	}

	if count > 0 {
		m.logger.Debug("closed pooled netlink handles",
			zap.Int("count", count),
			zap.String("instance_id", m.instance),
		)
	}

	// Clear the slices
	m.Ipsets = nil
	m.ipsetFamilies = nil

	m.logger.Info("ipset matcher cleaned up",
		zap.String("instance_id", m.instance),
	)

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
	// Use Caddy's built-in client IP detection which respects trusted_proxies configuration
	clientIPvar := caddyhttp.GetVar(req.Context(), caddyhttp.ClientIPVarKey)
	clientIP, ok := clientIPvar.(string)
	if !ok {
		// Should not happen because Caddy always sets this to a string
		return false, fmt.Errorf("%s is not a string but a %T", caddyhttp.ClientIPVarKey, clientIPvar)
	}

	// Parse the IP address because Caddy passes it as a string
	ip := net.ParseIP(clientIP)
	if ip == nil {
		// Should not happen because Caddy's client IP detection should have already validated it
		return false, fmt.Errorf("invalid IP address format '%s'", clientIP)
	}

	// Get the IP family string for comparison and logging
	ipFamily := getIpFamilyString(ip)

	// Reuse IPSetEntry to avoid allocation per ipset test
	entry := &netlink.IPSetEntry{IP: ip}

	// Borrow a handle from the pool (or create a new one)
	handle, err := m.getHandle()
	if err != nil {
		return false, err
	}
	// Return the handle to the pool (or close it if pool is full)
	defer m.putHandle(handle)

	// Get request context for cancellation support
	ctx := req.Context()

	for i, ipsetName := range m.Ipsets {
		// Check for context cancellation (e.g., client disconnected)
		select {
		case <-ctx.Done():
			return false, fmt.Errorf(
				"request canceled while matching ipset '%s': %w [instance=%s]",
				ipsetName, ctx.Err(), m.instance,
			)
		default:
			// Continue processing
		}

		// Check if the IP family matches the ipset family (optimization)
		ipsetFamily := familyCodeToString(m.ipsetFamilies[i])
		if ipFamily != ipsetFamily {
			m.logger.Debug("skipped matching of "+ipFamily+" address against "+ipsetFamily+" ipset",
				zap.String("ip", clientIP),
				zap.String("ipset", ipsetName))
			continue
		}

		// Test if the IP is in this ipset (reusing the entry allocation)
		found, err := handle.IpsetTest(ipsetName, entry)

		if err != nil {
			return false, fmt.Errorf(
				"error testing IP '%s' against ipset '%s': %w [instance=%s]",
				clientIP, ipsetName, err, m.instance,
			)
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
//	ipset <name>
//	ipset <name> <name> <name> ...
//
// ```
//
// Example:
//
// ```
// @blocked ipset blocklist-v4
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

// getHandle retrieves a netlink handle from the pool.
// If the pool is empty, it creates a new handle.
func (m *IpsetMatcher) getHandle() (*netlink.Handle, error) {
	if m.pool == nil {
		return nil, fmt.Errorf(
			"netlink handle pool not initialized - matcher not properly provisioned [instance=%s]",
			m.instance,
		)
	}

	select {
	case h := <-m.pool:
		return h, nil
	default:
		// Pool is empty, create a fresh handle
		handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to create new netlink handle [instance=%s]: %w",
				m.instance, err,
			)
		}
		m.logger.Debug("created new netlink handle",
			zap.Int("pool_size", len(m.pool)),
			zap.String("instance", m.instance),
		)
		return handle, nil
	}
}

// putHandle returns a handle to the pool.
// If the pool is full, the handle is closed and discarded.
func (m *IpsetMatcher) putHandle(h *netlink.Handle) {
	if h == nil || m.pool == nil {
		return
	}
	select {
	case m.pool <- h:
		// Successfully returned to pool
	default:
		// Pool is full, close and discard
		h.Close()
	}
}

// familyCodeToString converts the ipset family code to a readable string.
// Family codes are from NFPROTO_* constants in Linux kernel.
func familyCodeToString(family uint8) string {
	switch family {
	case nl.FAMILY_V4:
		return ipFamilyIPv4
	case nl.FAMILY_V6:
		return ipFamilyIPv6
	default:
		return fmt.Sprintf("unknown(%d)", family)
	}
}

// getIpFamilyString returns the family of the given IP address as a string.
func getIpFamilyString(ip net.IP) string {
	if ip.To4() != nil {
		return ipFamilyIPv4
	}
	return ipFamilyIPv6
}

// Interface guards
var (
	_ caddy.Provisioner                 = (*IpsetMatcher)(nil)
	_ caddy.CleanerUpper                = (*IpsetMatcher)(nil)
	_ caddyfile.Unmarshaler             = (*IpsetMatcher)(nil)
	_ caddyhttp.RequestMatcherWithError = (*IpsetMatcher)(nil)
)
