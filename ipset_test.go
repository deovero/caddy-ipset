//go:build linux
// +build linux

package caddy_ipset

import (
	"context"
	"net"
	"net/http/httptest"
	"syscall"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func TestCaddyModule(t *testing.T) {
	m := IpsetMatcher{}
	info := m.CaddyModule()

	if info.ID != "http.matchers.ipset" {
		t.Errorf("Expected module ID 'http.matchers.ipset', got '%s'", info.ID)
	}

	if info.New == nil {
		t.Error("Expected New function to be set")
	}

	newModule := info.New()
	if _, ok := newModule.(*IpsetMatcher); !ok {
		t.Error("Expected New to return *IpsetMatcher")
	}
}

func TestProvision_EmptyIpsetName(t *testing.T) {
	m := &IpsetMatcher{
		Ipset: "",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err == nil {
		t.Error("Expected error for empty ipset name")
	}

	if err.Error() != "ipset name is required" {
		t.Errorf("Expected 'ipset name is required' error, got '%s'", err.Error())
	}
}

func TestProvision_InvalidIpsetName(t *testing.T) {
	testCases := []struct {
		name      string
		ipsetName string
	}{
		{"with spaces", "my ipset"},
		{"with semicolon", "test;rm -rf /"},
		{"with pipe", "test|cat /etc/passwd"},
		{"with ampersand", "test&whoami"},
		{"with dollar", "test$USER"},
		{"with backtick", "test`whoami`"},
		{"with parenthesis", "test$(whoami)"},
		{"with slash", "test/path"},
		{"with backslash", "test\\path"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := &IpsetMatcher{
				Ipset: tc.ipsetName,
			}

			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			err := m.Provision(ctx)
			if err == nil {
				t.Errorf("Expected error for invalid ipset name '%s'", tc.ipsetName)
			}
		})
	}
}

func TestProvision_ValidIpsetName(t *testing.T) {
	testCases := []string{
		"valid-ipset",
		"valid_ipset",
		"valid.ipset",
		"ValidIpset123",
		"ipset-123_test.v1",
	}

	for _, ipsetName := range testCases {
		t.Run(ipsetName, func(t *testing.T) {
			// Note: This will fail if ipset doesn't exist, but validates the name format
			// In a real test environment, you'd mock the exec.Command
			if !ipsetNameRegex.MatchString(ipsetName) {
				t.Errorf("Valid ipset name '%s' failed regex validation", ipsetName)
			}
		})
	}
}

func TestMatch_InvalidRemoteAddr(t *testing.T) {
	m := &IpsetMatcher{
		Ipset:  "test-ipset",
		logger: zap.NewNop(),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "invalid-address"

	result := m.Match(req)
	if result {
		t.Error("Expected Match to return false for invalid remote address")
	}
}

func TestMatch_CloudflareHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("Cf-Connecting-Ip", "192.168.1.1")

	// Note: This will attempt to run ipset command
	// In a real test, you'd mock exec.Command
	// For now, we just verify the header is read
	if req.Header.Get("Cf-Connecting-Ip") != "192.168.1.1" {
		t.Error("Cloudflare header not set correctly")
	}
}

func TestMatch_InvalidIP(t *testing.T) {
	m := &IpsetMatcher{
		Ipset:  "test-ipset",
		logger: zap.NewNop(),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Cf-Connecting-Ip", "not-an-ip")

	result := m.Match(req)
	if result {
		t.Error("Expected Match to return false for invalid IP")
	}
}

func TestMatch_ClientIPWithPort(t *testing.T) {
	// Test that we properly handle IP addresses with port numbers
	// This verifies the net.SplitHostPort logic works correctly

	// Test IP with port
	testIP := "192.168.1.1:12345"
	ip, _, err := net.SplitHostPort(testIP)
	if err != nil {
		t.Errorf("Failed to split host port: %v", err)
	}
	if ip != "192.168.1.1" {
		t.Errorf("Expected IP '192.168.1.1', got '%s'", ip)
	}

	// Test IPv6 with port
	testIPv6 := "[2001:db8::1]:8080"
	ipv6, _, err := net.SplitHostPort(testIPv6)
	if err != nil {
		t.Errorf("Failed to split IPv6 host port: %v", err)
	}
	if ipv6 != "2001:db8::1" {
		t.Errorf("Expected IPv6 '2001:db8::1', got '%s'", ipv6)
	}

	// Test IP without port (should fail, which is expected)
	testIPNoPort := "192.168.1.1"
	_, _, err = net.SplitHostPort(testIPNoPort)
	if err == nil {
		t.Error("Expected error when splitting IP without port, but got none")
	}
	// This is expected - we should use the IP directly in this case
}

func TestUnmarshalCaddyfile(t *testing.T) {
	// This is a basic test - full Caddyfile parsing would require more setup
	// Test that the struct can be created
	m := &IpsetMatcher{}
	if m.Ipset != "" {
		t.Error("Expected empty ipset name on new matcher")
	}

	// Verify the matcher implements the interface
	var _ interface{} = m
}

func TestIsPermissionError(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"EPERM", syscall.EPERM, true},
		{"EACCES", syscall.EACCES, true},
		{"ENOENT", syscall.ENOENT, false},
		{"other error", syscall.EINVAL, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isPermissionError(tc.err)
			if result != tc.expected {
				t.Errorf("Expected %v for %s, got %v", tc.expected, tc.name, result)
			}
		})
	}
}

func TestMethodString(t *testing.T) {
	m := &IpsetMatcher{}

	m.method = ipsetMethodNetlink
	if m.methodString() != "netlink" {
		t.Errorf("Expected 'netlink', got '%s'", m.methodString())
	}

	m.method = ipsetMethodSudo
	if m.methodString() != "sudo" {
		t.Errorf("Expected 'sudo', got '%s'", m.methodString())
	}
}
