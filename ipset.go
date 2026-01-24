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
	"sync"
	"sync/atomic"

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

var (
	// instanceCounter is a global counter for generating unique instance IDs
	instanceCounter uint64
)

// IpsetMatcher matches the client_ip against Linux ipset lists using native netlink communication.
//
// This matcher provides high-performance IP matching by communicating directly
// with the Linux kernel via netlink, avoiding the overhead of spawning external
// processes.
//
// The matcher uses a pool of netlink handles (sync.Pool) for concurrent request
// processing. Each request borrows a handle from the pool, uses it, and returns it.
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

	// handlePool provides a pool of netlink handles for concurrent access
	// Each goroutine can borrow a handle from the pool, use it, and return it
	// This allows concurrent ipset lookups without message correlation issues
	handlePool *sync.Pool

	// createdHandles tracks all handles created by the pool for cleanup
	// sync.Pool doesn't provide a way to drain all objects, so we track them separately
	// Protected by handlesMu for thread-safe access
	createdHandles []*netlink.Handle

	// handlesMu protects createdHandles slice for concurrent access
	// Using a pointer to allow value receiver for CaddyModule()
	handlesMu *sync.Mutex

	// instanceID is a unique identifier for this matcher instance
	// Used for logging to distinguish between multiple instances
	instanceID uint64

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
	// Generate a unique instance ID for this matcher instance
	m.instanceID = atomic.AddUint64(&instanceCounter, 1)

	// Get the logger from Caddy's context
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
		m.logger.Debug("the process has CAP_NET_ADMIN capability",
			zap.Uint64("instance_id", m.instanceID),
		)
	} else {
		return fmt.Errorf("CAP_NET_ADMIN capability required. Grant with: sudo setcap cap_net_admin+ep %s", os.Args[0])
	}

	// Initialize the mutex for thread-safe access to createdHandles
	m.handlesMu = &sync.Mutex{}

	// Initialize the slice to track all created handles for cleanup
	m.createdHandles = make([]*netlink.Handle, 0)

	// Initialize the handle pool with a factory function
	// Each goroutine can borrow a handle, use it, and return it
	// We don't worry about memory usage too much because these handles are not expensive.
	m.handlePool = &sync.Pool{
		New: func() interface{} {
			handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
			if err != nil {
				m.logger.Error("failed to create netlink handle", zap.Error(err))
				return nil
			}

			// Track this handle for cleanup (thread-safe)
			m.handlesMu.Lock()
			m.createdHandles = append(m.createdHandles, handle)
			m.handlesMu.Unlock()

			m.logger.Debug("created new netlink handle for pool",
				zap.Int("total_handles", len(m.createdHandles)),
				zap.Uint64("instance_id", m.instanceID),
			)
			return handle
		},
	}

	// Pre-allocate ipsetFamilies slice with known capacity
	m.ipsetFamilies = make([]uint8, 0, len(m.Ipsets))

	// Borrow a handle from the pool to verify the ipset exists
	handle, err := m.getHandle()
	if err != nil {
		return err
	}
	// Return the handle to the pool when done
	defer m.handlePool.Put(handle)

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
			zap.Uint64("instance_id", m.instanceID),
		)
	}

	return nil
}

// Cleanup closes all netlink handles when the module is unloaded.
// This method is called by Caddy during graceful shutdown or module reload.
// It ensures proper cleanup of system resources.
func (m *IpsetMatcher) Cleanup() error {
	// Lock to prevent concurrent access during cleanup
	m.handlesMu.Lock()
	defer m.handlesMu.Unlock()

	// Close all handles that were created by the pool
	for _, handle := range m.createdHandles {
		if handle != nil {
			handle.Close()
		}
	}

	if len(m.createdHandles) > 0 {
		m.logger.Debug("closed all netlink handles",
			zap.Int("count", len(m.createdHandles)),
			zap.Uint64("instance_id", m.instanceID),
		)
	}

	// Clear the slices and pool
	m.Ipsets = nil
	m.createdHandles = nil
	m.handlePool = nil
	m.ipsetFamilies = nil

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
	// Check if handle pool is initialized (should be set during Provision)
	if m.handlePool == nil {
		return false, fmt.Errorf("netlink handle pool not initialized - matcher not properly provisioned")
	}

	// Use Caddy's built-in client IP detection which respects trusted_proxies configuration
	clientIPvar := caddyhttp.GetVar(req.Context(), caddyhttp.ClientIPVarKey)
	clientIP, ok := clientIPvar.(string)
	if !ok {
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

	// Borrow a handle from the pool for this request
	// Each concurrent request gets its own handle, enabling true parallelism
	handle, err := m.getHandle()
	if err != nil {
		return false, err
	}
	// Return the handle to the pool when done
	defer m.handlePool.Put(handle)

	// Get request context for cancellation support
	ctx := req.Context()

	for i, ipsetName := range m.Ipsets {
		// Check for context cancellation (e.g., client disconnected)
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("request canceled while matching ipset '%s': %w", ipsetName, ctx.Err())
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

// getHandle retrieves a netlink handle from the pool and performs type checking.
// Returns an error if the handle cannot be retrieved or is invalid.
func (m *IpsetMatcher) getHandle() (*netlink.Handle, error) {
	handleInterface := m.handlePool.Get()
	if handleInterface == nil {
		return nil, fmt.Errorf("failed to get netlink handle from pool - creation failed")
	}
	handle, ok := handleInterface.(*netlink.Handle)
	if !ok || handle == nil {
		return nil, fmt.Errorf("invalid handle from pool - expected *netlink.Handle, got %T", handleInterface)
	}
	return handle, nil
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
