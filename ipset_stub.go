//go:build !linux
// +build !linux

// Package caddy_ipset provides a Caddy HTTP matcher module that matches requests
// based on client IP addresses against Linux ipset lists.
//
// This module is only functional on Linux systems.
package caddy_ipset

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule((*IpsetMatcher)(nil))
}

// IpsetMatcher is a stub implementation for non-Linux platforms.
// This module only works on Linux systems.
type IpsetMatcher struct {
	Ipsets []string `json:"ipsets,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (m *IpsetMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.ipset",
		New: func() caddy.Module { return new(IpsetMatcher) },
	}
}

// Provision returns an error on non-Linux platforms.
func (m *IpsetMatcher) Provision(ctx caddy.Context) error {
	return fmt.Errorf("ipset matcher is only supported on Linux systems")
}

// MatchWithError always returns an error on non-Linux platforms.
func (m *IpsetMatcher) MatchWithError(req *http.Request) (bool, error) {
	return false, fmt.Errorf("ipset matcher is only supported on Linux systems")
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
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

// Interface guards
var (
	_ caddy.Provisioner                 = (*IpsetMatcher)(nil)
	_ caddyfile.Unmarshaler             = (*IpsetMatcher)(nil)
	_ caddyhttp.RequestMatcherWithError = (*IpsetMatcher)(nil)
)
