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
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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

var (
	// instanceCounter is a global counter for generating unique instance IDs
	instanceCounter uint64

	// Define Prometheus metrics
	// Caddy exposes these under the /metrics endpoint typically on port 2019
	checkCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "caddy",
		Subsystem: "http_matchers_ipset",
		Name:      "checks_total",
		Help:      "Total number of IPset checks performed",
	}, []string{"result", "ipsets"}) // labels: result=(match|no_match|error), ipsets=(comma_joined_names)

	checkDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "caddy",
		Subsystem: "http_matchers_ipset",
		Name:      "check_duration_seconds",
		Help:      "Duration of IPset netlink checks",
		Buckets:   prometheus.DefBuckets,
	}, []string{"result"})
)

const (
	// IP family string constants
	ipFamilyUnknown = 0
	ipFamilyIPv4    = 4
	ipFamilyIPv6    = 6
)

func init() {
	// Caddy's module analyzer requires either a composite literal or the use of new() instead of the & notation
	// for submission to https://caddyserver.com/account/register-package
	caddy.RegisterModule(IpsetMatcher{})
}

// IpsetMatcher matches the client_ip against Linux ipset lists using native netlink communication.
// ... (comments truncated for brevity)
type IpsetMatcher struct {
	// Ipsets is a list of ipset names to match against
	// If the client IP is in ANY of these ipsets, the matcher returns true
	Ipsets []string `json:"ipsets,omitempty"`

	// ipsetFamilyVersions stores the IP family (IPv4, IPv6, unknown) for each ipset
	ipsetFamilyVersions []uint8

	// pool acts as a leaky bucket for netlink handles.
	pool chan *netlink.Handle

	// instanceID is a unique identifier for this matcher instance
	instanceID string

	// closed is an atomic flag to indicate if the module is being cleaned up
	closed int32

	// matchCount is a counter for the number of times the matcher has been called
	matchCount uint64

	// During Provision() we will store the logger from Caddy's context here.
	logger *zap.Logger

	// joinedIpsetNames is a string of all ipsets joined by commas, used for metrics
	joinedIpsetNames string
}

// CaddyModule returns the Caddy module information.
func (IpsetMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.ipset",
		New: func() caddy.Module { return new(IpsetMatcher) },
	}
}

// Provision sets up the matcher...
func (m *IpsetMatcher) Provision(ctx caddy.Context) error {
	// Generate a unique instance ID for this matcher instance
	m.instanceID = fmt.Sprintf("%d.%d", os.Getpid(), atomic.AddUint64(&instanceCounter, 1))

	// Get the logger from Caddy's context
	m.logger = ctx.Logger()

	// Pre-calculate joined names for metrics to avoid allocation in hot path
	// We do this before validation loops just to have it ready, though logically valid names come later.
	// In practice, this might just be a single name usually.
	m.joinedIpsetNames = fmt.Sprintf("%v", m.Ipsets)

	// Check if the Effective capabilities set contains CAP_NET_ADMIN
	caps, err := capability.NewPid2(0)
	// ... (rest of Provision method remains unchanged) ...
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
			zap.String("instance_id", m.instanceID),
		)
	} else {
		return fmt.Errorf("CAP_NET_ADMIN capability required. Grant with: sudo setcap cap_net_admin+ep %s", os.Args[0])
	}

	// Initialize the channel pool.
	m.pool = make(chan *netlink.Handle, 128)

	// Pre-allocate ipsetFamilyVersions slice with known length
	m.ipsetFamilyVersions = make([]uint8, len(m.Ipsets))

	// Create a temporary handle just for ipset access validation.
	handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		m.logger.Error("failed to create netlink handle for ipset validation",
			zap.Error(err),
			zap.String("instance_id", m.instanceID),
		)
		return err
	}
	defer handle.Close()

	// Validate each ipset and store its family information
	for i, ipsetName := range m.Ipsets {
		if ipsetName == "" {
			return fmt.Errorf("ipset name is required")
		}
		if len(ipsetName) >= nl.IPSET_MAXNAMELEN {
			return fmt.Errorf("ipset name '%s' exceeds maximum length of %d characters", ipsetName, nl.IPSET_MAXNAMELEN-1)
		}

		result, err := handle.IpsetList(ipsetName)
		if err != nil {
			return fmt.Errorf("error checking ipset '%s': %w", ipsetName, err)
		}

		m.ipsetFamilyVersions[i] = nfprotoFamilyVersion(result.Family)

		m.logger.Info("validated ipset existence",
			zap.String("ipset", ipsetName),
			zap.String("type", result.TypeName),
			zap.Uint8("family", m.ipsetFamilyVersions[i]),
			zap.String("instance_id", m.instanceID),
		)
	}

	m.logger.Info("ipset matcher provisioned",
		zap.String("instance_id", m.instanceID),
	)

	return nil
}

// Cleanup closes all netlink handles when the module is unloaded.
// ... (Cleanup method remains unchanged) ...
func (m *IpsetMatcher) Cleanup() error {
	count := 0
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
			break drainLoop
		}
	}

	m.logger.Info("ipset matcher cleaned up",
		zap.Int("closed_handles", count),
		zap.Uint64("match_count", m.matchCount),
		zap.String("instance_id", m.instanceID),
	)

	return nil
}

// MatchWithError implements the caddyhttp.RequestMatcherWithError interface.
// ... (comments truncated) ...
func (m *IpsetMatcher) MatchWithError(req *http.Request) (bool, error) {
	start := time.Now()
	// Record metrics on exit
	// We use named return values implicitly or explicitly, but since we can't change signature,
	// we use a closure or local variables to track state for defer.
	var resultLabel string = "no_match"

	defer func() {
		duration := time.Since(start).Seconds()
		checkDuration.WithLabelValues(resultLabel).Observe(duration)
		checkCount.WithLabelValues(resultLabel, m.joinedIpsetNames).Inc()
	}()

	// Performance optimization
	debugEnabled := m.logger.Core().Enabled(zap.DebugLevel)

	atomic.AddUint64(&m.matchCount, 1)

	clientIpVar := caddyhttp.GetVar(req.Context(), caddyhttp.ClientIPVarKey)
	if clientIpVar == nil {
		resultLabel = "error"
		return false, fmt.Errorf("%s not found in request context", caddyhttp.ClientIPVarKey)
	}
	clientIpStr, ok := clientIpVar.(string)
	if !ok {
		resultLabel = "error"
		return false, fmt.Errorf("%s is not a string but a %T", caddyhttp.ClientIPVarKey, clientIpVar)
	}

	clientIp := net.ParseIP(clientIpStr)
	if clientIp == nil {
		resultLabel = "error"
		return false, fmt.Errorf("invalid IP address format '%s'", clientIpStr)
	}

	ipFamily := ipFamilyVersion(clientIp)
	entry := &netlink.IPSetEntry{IP: clientIp}

	handle, err := m.getHandle()
	if err != nil {
		resultLabel = "error"
		return false, err
	}
	defer m.putHandle(handle)

ipsetLoop:
	for i, ipsetName := range m.Ipsets {
		ipsetFamily := m.ipsetFamilyVersions[i]
		if ipsetFamily != ipFamilyUnknown && ipFamily != ipsetFamily {
			if debugEnabled {
				m.logger.Debug(
					fmt.Sprintf("skipped matching of IPv%d address against IPv%d ipset", ipFamily, ipsetFamily),
					zap.String("ip", clientIpStr),
					zap.String("ipset", ipsetName),
				)
			}
			continue ipsetLoop
		}

		found, err := handle.IpsetTest(ipsetName, entry)
		if err != nil {
			resultLabel = "error"
			return false, fmt.Errorf(
				"error testing IP '%s' against ipset '%s': %w [instance_id=%s]",
				clientIpStr, ipsetName, err, m.instanceID,
			)
		}

		if found {
			if debugEnabled {
				m.logger.Debug("IP matched in ipset",
					zap.String("clientIp", clientIpStr),
					zap.String("ipset", ipsetName),
				)
			}
			resultLabel = "match"
			return true, nil
		}

		if debugEnabled {
			m.logger.Debug("IP not in ipset, checking next",
				zap.String("clientIp", clientIpStr),
				zap.String("ipset", ipsetName),
			)
		}
	}

	if debugEnabled {
		m.logger.Debug("IP not found in any ipset",
			zap.String("clientIp", clientIpStr),
			zap.Int("ipsets_checked", len(m.Ipsets)),
		)
	}

	// resultLabel is "no_match" by default
	return false, nil
}

// ... (Rest of the file: UnmarshalCaddyfile, getHandle, putHandle, helper functions remain unchanged) ...
// The remaining functions do not require changes for metrics.
func (m *IpsetMatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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

func (m *IpsetMatcher) getHandle() (*netlink.Handle, error) {
	if m.pool == nil {
		return nil, fmt.Errorf("netlink handle pool not initialized - matcher not properly provisioned [instance_id=%s]", m.instanceID)
	}
	select {
	case h := <-m.pool:
		return h, nil
	default:
		handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
		if err != nil {
			return nil, fmt.Errorf("failed to create new netlink handle [instance_id=%s]: %w", m.instanceID, err)
		}
		m.logger.Debug("created new netlink handle, pool was empty", zap.String("instance_id", m.instanceID))
		return handle, nil
	}
}

func (m *IpsetMatcher) putHandle(h *netlink.Handle) {
	if h == nil || m.pool == nil {
		return
	}
	if atomic.LoadInt32(&m.closed) == 1 {
		h.Close()
		m.logger.Debug("discarded handle because module is closed", zap.String("instance_id", m.instanceID))
		return
	}
	select {
	case m.pool <- h:
	default:
		m.logger.Info("pool full, closing and discarding handle", zap.Int("pool_size", len(m.pool)), zap.Int("pool_capacity", cap(m.pool)), zap.String("instance_id", m.instanceID))
		h.Close()
	}
}

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

func ipFamilyVersion(ip net.IP) uint8 {
	if ip.To4() != nil {
		return ipFamilyIPv4
	}
	return ipFamilyIPv6
}
