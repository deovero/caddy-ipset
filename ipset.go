package caddy_ipset

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(IpsetMatcher{})
}

type IpsetMatcher struct {
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
		return fmt.Errorf("ipset name is required")
	}

	// Verify the ipset exists
	cmd := exec.Command("ipset", "list", m.Ipset, "-name")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ipset '%s' does not exist or cannot be accessed: %w", m.Ipset, err)
	}

	m.logger.Info("ipset matcher provisioned", zap.String("ipset", m.Ipset))
	return nil
}

// Match returns true if the request's IP is in the configured ipset.
func (m *IpsetMatcher) Match(req *http.Request) bool {
	var remoteIP string
	var fieldName string

	// Check for Cloudflare IP header first
	cloudflareIPHeader := req.Header.Get("Cf-Connecting-Ip")
	if len(cloudflareIPHeader) > 0 {
		fieldName = "Cf-Connecting-Ip"
		remoteIP = cloudflareIPHeader
	} else {
		fieldName = "remote_addr"
		remoteAddress := req.RemoteAddr

		var err error
		remoteIP, _, err = net.SplitHostPort(remoteAddress)
		if err != nil {
			m.logger.Error("Error parsing remote addr into IP & port",
				zap.String(fieldName, remoteAddress),
				zap.Error(err))
			// Deny by default on error
			return false
		}
	}

	// Test if the IP is in the ipset
	cmd := exec.Command("ipset", "test", m.Ipset, remoteIP)
	err := cmd.Run()

	if err != nil {
		// ipset test returns exit code 1 if IP is not in the set
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			m.logger.Debug("IP not in ipset",
				zap.String("ip", remoteIP),
				zap.String("source", fieldName),
				zap.String("ipset", m.Ipset))
			return false
		}
		// Other errors (e.g., ipset command failed)
		m.logger.Error("Error testing IP against ipset",
			zap.String("ip", remoteIP),
			zap.String("ipset", m.Ipset),
			zap.Error(err))
		return false
	}

	m.logger.Info("IP matched in ipset",
		zap.String("ip", remoteIP),
		zap.String("source", fieldName),
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

// Interface guards
var (
	_ caddy.Provisioner     = (*IpsetMatcher)(nil)
	_ caddyfile.Unmarshaler = (*IpsetMatcher)(nil)
)
