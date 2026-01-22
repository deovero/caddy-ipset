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
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"syscall"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

const (
	// ipsetTestTimeout is the maximum time to wait for ipset test command when using sudo fallback
	ipsetTestTimeout = 5 * time.Second
)

var (
	// ipsetNameRegex validates ipset names to prevent command injection
	// Allows alphanumeric characters, hyphens, underscores, and dots
	ipsetNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)
)

// ipsetMethod represents the method used to access ipset
type ipsetMethod int

const (
	ipsetMethodNetlink ipsetMethod = iota // Direct netlink access (preferred)
	ipsetMethodSudo                       // Fallback to sudo ipset command
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
	method ipsetMethod // The method used to access ipset (netlink or sudo)
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

	// Validate ipset name to prevent command injection (important for sudo fallback)
	if !ipsetNameRegex.MatchString(m.Ipset) {
		return fmt.Errorf("ERROR invalid ipset name '%s': must contain only alphanumeric characters, hyphens, underscores, and dots", m.Ipset)
	}

	// Try to verify the ipset exists using native netlink first
	_, err := netlink.IpsetList(m.Ipset)
	if err != nil {
		// Check if this is a permission error
		if isPermissionError(err) {
			m.logger.Warn("netlink access denied, falling back to 'sudo ipset'",
				zap.String("ipset", m.Ipset),
				zap.Error(err))

			// Try sudo ipset as fallback
			if err := m.verifySudoIpset(); err != nil {
				return fmt.Errorf("ERROR ipset '%s' cannot be accessed via netlink or sudo: %w", m.Ipset, err)
			}

			m.method = ipsetMethodSudo
			m.logger.Info("ipset matcher provisioned using sudo fallback",
				zap.String("ipset", m.Ipset),
				zap.String("method", "sudo"))
			return nil
		}

		// Not a permission error, ipset doesn't exist or other error
		return fmt.Errorf("ERROR ipset '%s' does not exist or cannot be accessed: %w", m.Ipset, err)
	}

	// Netlink access successful
	m.method = ipsetMethodNetlink
	m.logger.Info("ipset matcher provisioned using native netlink",
		zap.String("ipset", m.Ipset),
		zap.String("method", "netlink"))
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

	// Test using the appropriate method
	var found bool
	if m.method == ipsetMethodNetlink {
		found, err = m.testIPNetlink(ip)
	} else {
		found, err = m.testIPSudo(remoteIP)
	}

	if err != nil {
		m.logger.Error("Error testing IP against ipset",
			zap.String("ip", remoteIP),
			zap.String("ipset", m.Ipset),
			zap.String("method", m.methodString()),
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

// testIPNetlink tests if an IP is in the ipset using native netlink
func (m *IpsetMatcher) testIPNetlink(ip net.IP) (bool, error) {
	entry := &netlink.IPSetEntry{
		IP: ip,
	}
	return netlink.IpsetTest(m.Ipset, entry)
}

// testIPSudo tests if an IP is in the ipset using sudo ipset command
func (m *IpsetMatcher) testIPSudo(ipStr string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ipsetTestTimeout)
	defer cancel()

	// Use -n flag for non-interactive sudo (no password prompt)
	cmd := exec.CommandContext(ctx, "sudo", "-n", "ipset", "test", m.Ipset, ipStr)
	output, err := cmd.CombinedOutput()

	if err == nil {
		// Exit code 0 means IP is in the set
		return true, nil
	}

	// Check if it's an exit error
	if exitErr, ok := err.(*exec.ExitError); ok {
		// Exit code 1 means IP is not in the set
		if exitErr.ExitCode() == 1 {
			return false, nil
		}
		// Other exit codes indicate an error
		return false, fmt.Errorf("ERROR: sudo ipset test failed (exit %d): %s", exitErr.ExitCode(), string(output))
	}

	// Any other error is a real error
	return false, fmt.Errorf("ERROR: sudo ipset test failed: %w", err)
}

// verifySudoIpset verifies that sudo ipset can access the ipset
func (m *IpsetMatcher) verifySudoIpset() error {
	ctx, cancel := context.WithTimeout(context.Background(), ipsetTestTimeout)
	defer cancel()

	// Use -n flag for non-interactive sudo (no password prompt)
	cmd := exec.CommandContext(ctx, "sudo", "-n", "ipset", "list", m.Ipset)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Provide helpful error message
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				// sudo requires password or user not in sudoers
				return fmt.Errorf("ERROR: sudo requires password or user not authorized (exit 1). Configure passwordless sudo: add 'your_user ALL=(ALL) NOPASSWD: /usr/sbin/ipset' to /etc/sudoers.d/caddy. Output: %s", string(output))
			}
		}
		return fmt.Errorf("ERROR sudo ipset list failed: %w. Output: %s", err, string(output))
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

// methodString returns a string representation of the ipset method
func (m *IpsetMatcher) methodString() string {
	if m.method == ipsetMethodNetlink {
		return "netlink"
	}
	return "sudo"
}

// Interface guards
var (
	_ caddy.Provisioner     = (*IpsetMatcher)(nil)
	_ caddyfile.Unmarshaler = (*IpsetMatcher)(nil)
)
