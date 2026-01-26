//go:build linux

// Package caddy_ipset provides a Caddy HTTP matcher module that matches requests
// based on client IP addresses against Linux ipset lists.
package caddy_ipset

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/syndtr/gocapability/capability" // does not require CGo for libcap
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// Interface guards
var (
	_ caddy.Provisioner                 = (*IpsetMatcher)(nil)
	_ caddy.CleanerUpper                = (*IpsetMatcher)(nil)
	_ caddyfile.Unmarshaler             = (*IpsetMatcher)(nil)
	_ caddyhttp.RequestMatcherWithError = (*IpsetMatcher)(nil)
)

func init() {
	// Caddy's module analyzer requires either a composite literal or the use of new() instead of the & notation
	// for submission to https://caddyserver.com/account/register-package
	caddy.RegisterModule(IpsetMatcher{})
}

const (
	// IP family string constants
	ipFamilyUnknown = 0
	ipFamilyIPv4    = 4
	ipFamilyIPv6    = 6
)

var (
	// instanceCounter is a global counter for generating unique instance IDs
	instanceCounter uint64
)

// IpsetMatcher matches the client_ip against Linux ipset lists using native netlink communication.
// This enables efficient filtering against large, dynamic sets of IPs and CIDR ranges.
//
// Requirements:
//   - Linux system with `ip_set` kernel module loaded
//   - CAP_NET_ADMIN capability, grant with: `sudo setcap cap_net_admin+ep /path/to/caddy`
//   - Existing ipset list created via the `ipset` command
//
// Supports both IPv4 and IPv6 ipsets, performing validation during initialization.
// Protocol mismatches (e.g., checking an IPv4 address against an IPv6 set) return false.
//
// If multiple ipsets are configured, the matcher applies OR logic: it returns true
// if the IP is found in *any* of the provided sets.
//
// Internally, it utilizes a buffered channel to pool netlink handles. This ensures
// high-performance concurrency while capping idle resources to prevent leaks.
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

	// ipsetFamilyVersions stores the IP family (IPv4, IPv6, unknown) for each ipset
	ipsetFamilyVersions []uint8

	// pool acts as a leaky bucket for netlink handles.
	// It holds a fixed number of reusable handles. If the pool is empty,
	// new handles are created on demand. If the pool is full when returning,
	// excess handles are closed.
	pool chan *netlink.Handle

	// instanceID is a unique identifier for this matcher instance
	// Used for logging to distinguish between multiple instances
	instanceID uint64

	// closed is an atomic flag to indicate if the module is being cleaned up
	closed int32

	// During Provision() we will store the logger from Caddy's context here.
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
// must have a value receiver so it can be called from a pointer.
//
// noinspection GoMixedReceiverTypes
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
	m.instanceID = atomic.AddUint64(&instanceCounter, 1)

	// Get the logger from Caddy's context
	m.logger = ctx.Logger()

	// Check if the Effective capabilities set contains CAP_NET_ADMIN
	caps, err := capability.NewPid2(0)
	if err != nil {
		return fmt.Errorf("failed to get process capabilities: %w", err)
	}
	err = caps.Load()
	if err != nil {
		return fmt.Errorf("failed to load process capabilities: %w", err)
	}
	hasNetAdmin := caps.Get(capability.EFFECTIVE, capability.CAP_NET_ADMIN)
	if hasNetAdmin {
		m.logger.Debug("the process has CAP_NET_ADMIN capability",
			zap.Uint64("instance_id", m.instanceID),
		)
	} else {
		return fmt.Errorf("CAP_NET_ADMIN capability required. Grant with: sudo setcap cap_net_admin+ep %s", os.Args[0])
	}

	// Initialize the channel pool.
	// 128 is a safe buffer size to handle concurrent bursts without
	// constantly creating/destroying sockets, while keeping memory usage low.
	m.pool = make(chan *netlink.Handle, 128)

	// Pre-allocate ipsetFamilyVersions slice with known length
	m.ipsetFamilyVersions = make([]uint8, len(m.Ipsets))

	// Create a temporary handle just for ipset access validation.
	// We do not use the pool here to ensure deterministic startup behavior.
	handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		m.logger.Error("failed to create netlink handle for ipset validation",
			zap.Error(err),
			zap.Uint64("instance_id", m.instanceID),
		)
		return err
	}
	defer handle.Close()

	// Validate each ipset and store its family information
	for i, ipsetName := range m.Ipsets {
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
		m.ipsetFamilyVersions[i] = nfprotoFamilyVersion(result.Family)

		m.logger.Info("validated ipset existence",
			zap.String("ipset", ipsetName),
			zap.String("type", result.TypeName),
			zap.Uint8("family", m.ipsetFamilyVersions[i]),
			zap.Uint64("instance_id", m.instanceID),
		)
	}

	m.logger.Info("ipset matcher provisioned",
		zap.Uint64("instance_id", m.instanceID),
	)

	return nil
}

// Cleanup closes all netlink handles when the module is unloaded.
// This method is called by Caddy during graceful shutdown or module reload.
// It ensures proper cleanup of system resources.
func (m *IpsetMatcher) Cleanup() error {
	// Not closing the channel because during reload some handles may still be in use.
	// Only closing returned handles for the same reason.
	count := 0
	// Mark as closed first to prevent new requests from starting new handles
	atomic.StoreInt32(&m.closed, 1)

drainLoop:
	for {
		select {
		case handle := <-m.pool:
			if handle != nil {
				handle.Close()
				count++
			}
		default:
			// Pool is empty
			break drainLoop
		}
	}

	m.logger.Info("ipset matcher cleaned up",
		zap.Int("closed_handles", count),
		zap.Uint64("instance_id", m.instanceID),
	)

	return nil
}

// MatchWithError implements the caddyhttp.RequestMatcherWithError interface.
// The client IP is determined using Caddy's built-in detection which respects
// the trusted_proxies configuration.
//
// IPv4-mapped IPv6 addresses (e.g., ::ffff:192.168.1.1) are treated as IPv4
// addresses because `vishvananda/netlink` treats them as IPv4 addresses.
//
// The matching process:
//   - Extracts the client_ip from the request
//   - Checks each configured ipsets in order
//   - For each ipset, checks if the IP family matches (optimization)
//   - Performs the ipset lookup via netlink
//   - Returns true if found in ANY ipset (OR logic)
//
// Returns false + error if:
//   - The client IP is not found in the request context
//   - There is a problem with the netlink handle
//   - The client IP cannot be parsed
//   - An error occurs during ipset lookup
//
// Returns false if:
//   - The IP is not found in any of the configured ipsets
//
// Returns true if:
//   - the client's IP address is found in at least one configured ipset.
//
// We don't want to silently ignore errors here because this has security implications.
//
// We ignore context cancellation (e.g., client disconnects) to avoid logging an
// unnecessary error. It is not that expensive to complete checking the ipsets.
func (m *IpsetMatcher) MatchWithError(req *http.Request) (bool, error) {
	// Performance optimization: Check if debug is enabled and cache it during the processing of this request.
	// We don't store it in the struct because it could change during the lifetime of the module, although
	// it's very unlikely without a reload (which triggers a restart of the module).
	debugEnabled := m.logger.Core().Enabled(zap.DebugLevel)

	// Use Caddy's built-in client IP detection which respects trusted_proxies configuration
	clientIpVar := caddyhttp.GetVar(req.Context(), caddyhttp.ClientIPVarKey)
	if clientIpVar == nil {
		// Maybe this can happen if the users trusted_proxies configuration is wrong?
		return false, fmt.Errorf("%s not found in request context", caddyhttp.ClientIPVarKey)
	}
	clientIpStr, ok := clientIpVar.(string)
	if !ok {
		// Should not happen because Caddy always sets this to a string
		return false, fmt.Errorf("%s is not a string but a %T", caddyhttp.ClientIPVarKey, clientIpVar)
	}

	// Parse the IP address because Caddy passes it as a string
	clientIp := net.ParseIP(clientIpStr)
	if clientIp == nil {
		// Should not happen because Caddy's client IP detection should have already validated it
		return false, fmt.Errorf("invalid IP address format '%s'", clientIpStr)
	}

	// Get the IP family string for comparison and logging
	ipFamily := ipFamilyVersion(clientIp)

	// Reuse IPSetEntry to avoid allocation per ipset test
	entry := &netlink.IPSetEntry{IP: clientIp}

	// Borrow a handle from the pool (or create a new one)
	handle, err := m.getHandle()
	if err != nil {
		return false, err
	}
	// Return the handle to the pool (or close it if pool is full)
	defer m.putHandle(handle)

ipsetLoop:
	for i, ipsetName := range m.Ipsets {
		// Check if the IP family matches the ipset family (optimization)
		ipsetFamily := m.ipsetFamilyVersions[i]
		if ipsetFamily != ipFamilyUnknown && ipFamily != ipsetFamily {
			if debugEnabled {
				// This is a hot path so we prevent string allocation if debug is not enabled
				m.logger.Debug(
					fmt.Sprintf("skipped matching of IPv%d address against IPv%d ipset", ipFamily, ipsetFamily),
					zap.String("ip", clientIpStr),
					zap.String("ipset", ipsetName),
				)
			}
			continue ipsetLoop
		}

		// Actually test if the IP is in this ipset (reusing the entry allocation)
		found, err := handle.IpsetTest(ipsetName, entry)
		if err != nil {
			return false, fmt.Errorf(
				"error testing IP '%s' against ipset '%s': %w [instance_id=%d]",
				clientIpStr, ipsetName, err, m.instanceID,
			)
		}

		// OR logic: if found in ANY ipset, return true immediately
		if found {
			if debugEnabled {
				// This is a hot path so we prevent string allocation if debug is not enabled
				m.logger.Debug("IP matched in ipset",
					zap.String("clientIp", clientIpStr),
					zap.String("ipset", ipsetName),
				)
			}
			return true, nil
		}

		// Not found in this ipset, continue to check the next one
		if debugEnabled {
			// This is a hot path so we prevent string allocation if debug is not enabled
			m.logger.Debug("IP not in ipset, checking next",
				zap.String("clientIp", clientIpStr),
				zap.String("ipset", ipsetName),
			)
		}
	}

	// Not found in any ipset
	if debugEnabled {
		// This is a hot path so we prevent string allocation if debug is not enabled
		m.logger.Debug("IP not found in any ipset",
			zap.String("clientIp", clientIpStr),
			zap.Int("ipsets_checked", len(m.Ipsets)),
		)
	}
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
			"netlink handle pool not initialized - matcher not properly provisioned [instance_id=%d]",
			m.instanceID,
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
				"failed to create new netlink handle [instance_id=%d]: %w",
				m.instanceID, err,
			)
		}
		m.logger.Debug("created new netlink handle",
			zap.Int("pool_size", len(m.pool)),
			zap.Uint64("instance_id", m.instanceID),
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

	// If module is closed, destroy the handle immediately
	if atomic.LoadInt32(&m.closed) == 1 {
		h.Close()
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

// nfprotoFamilyVersion converts the ipset family code to a human-readable version.
// Family codes are from NFPROTO_* constants in Linux kernel.
func nfprotoFamilyVersion(family uint8) uint8 {
	switch family {
	case nl.FAMILY_V4:
		return ipFamilyIPv4
	case nl.FAMILY_V6:
		return ipFamilyIPv6
	default:
		return ipFamilyUnknown
	}
}

// ipFamilyVersion returns the family of the given IP address as a human-readable version.
// For IPv4-mapped IPv6 addresses (e.g., ::ffff:192.168.1.1), this returns ipFamilyIPv4 because
// `vishvananda/netlink` treats them as IPv4 addresses.
func ipFamilyVersion(ip net.IP) uint8 {
	if ip.To4() != nil {
		return ipFamilyIPv4
	}
	return ipFamilyIPv6
}
