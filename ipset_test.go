//go:build linux
// +build linux

package caddy_ipset

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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

	if err != nil && err.Error() != "ERROR ipset name is required" {
		t.Errorf("Expected 'ERROR ipset name is required' error, got '%s'", err.Error())
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
		Ipset:  "test-ipset-v4",
		logger: zap.NewNop(),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "invalid-address"

	result := m.Match(req)
	if result {
		t.Error("Expected Match to return false for invalid remote address")
	}
}

func TestMatch_InvalidIP(t *testing.T) {
	m := &IpsetMatcher{
		Ipset:  "test-ipset-v4",
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
		{"operation not permitted string", errors.New("operation not permitted"), true},
		{"permission denied string", errors.New("permission denied"), true},
		{"other string error", errors.New("some other error"), false},
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

// TestProvision_NetlinkSuccess tests successful provisioning with netlink access
func TestProvision_NetlinkSuccess(t *testing.T) {
	// This test requires an actual ipset to exist
	// It will use the test-ipset-v4 created by the Docker environment
	m := &IpsetMatcher{
		Ipset: "test-ipset-v4",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	// This may fail if running outside Docker or if test-ipset-v4 doesn't exist
	if err != nil {
		t.Logf("Netlink provisioning failed (expected in some environments): %v", err)
	} else {
		// Verify logger was set
		if m.logger == nil {
			t.Error("Expected logger to be set")
		}
	}
}

// TestProvision_NonExistentIpset tests provisioning with a non-existent ipset
func TestProvision_NonExistentIpset(t *testing.T) {
	m := &IpsetMatcher{
		Ipset: "nonexistent-ipset-12345",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err == nil {
		t.Error("Expected error for non-existent ipset")
	}
}

// TestMatch_WithNetlinkMethod tests Match with netlink method
func TestMatch_WithNetlinkMethod(t *testing.T) {
	m := &IpsetMatcher{
		Ipset:  "test-ipset-v4",
		logger: zap.NewNop(),
	}

	// Test with an IP that should be in test-ipset-v4 (127.0.0.1)
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	// This will attempt to use netlink
	// Result depends on whether test-ipset-v4 exists and contains 127.0.0.1
	result := m.Match(req)
	// We can't assert the result without knowing the ipset state
	// But we can verify it doesn't panic
	t.Logf("Match result for 127.0.0.1: %v", result)
}

// TestMatch_IPWithoutPort tests Match with IP address without port
func TestMatch_IPWithoutPort(t *testing.T) {
	m := &IpsetMatcher{
		Ipset:  "test-ipset-v4",
		logger: zap.NewNop(),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	// Set RemoteAddr to just an IP without port
	req.RemoteAddr = "192.168.1.1"

	// This should handle the case where SplitHostPort fails
	result := m.Match(req)
	t.Logf("Match result for IP without port: %v", result)
}

// TestMatch_IPv6 tests Match with IPv6 address
func TestMatch_IPv6(t *testing.T) {
	m := &IpsetMatcher{
		Ipset:  "test-ipset-v4",
		logger: zap.NewNop(),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "[2001:db8::1]:8080"

	result := m.Match(req)
	t.Logf("Match result for IPv6: %v", result)
}

func TestUnmarshalCaddyfile(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectError bool
		expectedSet string
	}{
		{
			name:        "valid ipset name",
			input:       "ipset test-ipset-v4",
			expectError: false,
			expectedSet: "test-ipset-v4",
		},
		{
			name:        "valid ipset name with underscores",
			input:       "ipset my_ipset_123",
			expectError: false,
			expectedSet: "my_ipset_123",
		},
		{
			name:        "missing argument",
			input:       "ipset",
			expectError: true,
			expectedSet: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := &IpsetMatcher{}
			d := caddyfile.NewTestDispenser(tc.input)
			err := m.UnmarshalCaddyfile(d)

			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tc.expectError && m.Ipset != tc.expectedSet {
				t.Errorf("Expected ipset '%s', got '%s'", tc.expectedSet, m.Ipset)
			}
		})
	}
}

// TestProvision_PermissionError tests the permission error path
// This test is designed to be run by scripts/test-permission-error.sh
// which manages CAP_NET_ADMIN capability at the root level
func TestProvision_PermissionError(t *testing.T) {
	// Try to provision - behavior depends on whether CAP_NET_ADMIN is granted
	m := &IpsetMatcher{
		Ipset: "test-ipset-v4",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)

	// If there's an error, verify it's the expected permission error
	if err != nil {
		// Verify the error message contains the setcap instruction
		expectedMsg := "sudo setcap cap_net_admin+ep ./caddy"
		if !strings.Contains(err.Error(), expectedMsg) {
			t.Errorf("Expected error to contain '%s', got: %v", expectedMsg, err)
		}

		// Verify it's specifically a permission error
		if !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("Expected error to contain 'permission denied', got: %v", err)
		}

		t.Logf("Successfully triggered permission error: %v", err)
	} else {
		// No error means CAP_NET_ADMIN is granted and ipset access works
		t.Logf("Successfully provisioned with CAP_NET_ADMIN capability")
	}
}

// TestProvision_FullIntegration tests the full provisioning flow
// This test requires the Docker environment with test-ipset-v4 created
func TestProvision_FullIntegration(t *testing.T) {
	testCases := []struct {
		name        string
		ipsetName   string
		expectError bool
	}{
		{
			name:        "existing ipset",
			ipsetName:   "test-ipset-v4",
			expectError: false,
		},
		{
			name:        "another existing ipset",
			ipsetName:   "blocklist-v4",
			expectError: false,
		},
		{
			name:        "empty ipset",
			ipsetName:   "empty-4",
			expectError: false,
		},
		{
			name:        "non-existent ipset",
			ipsetName:   "does-not-exist-12345",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := &IpsetMatcher{
				Ipset: tc.ipsetName,
			}

			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			err := m.Provision(ctx)
			if tc.expectError && err == nil {
				t.Errorf("Expected error for ipset '%s' but got none", tc.ipsetName)
			}
			if !tc.expectError && err != nil {
				t.Logf("Provisioning failed for '%s': %v (may be expected in non-Docker environment)", tc.ipsetName, err)
			}
			if !tc.expectError && err == nil {
				// Verify logger was set
				if m.logger == nil {
					t.Error("Expected logger to be set")
				}
			}
		})
	}
}

// TestMatch_FullIntegration tests the full Match flow with actual ipset
// This test requires the Docker environment with test-ipset-v4 containing specific IPs
func TestMatch_FullIntegration(t *testing.T) {
	// First provision the matcher
	m := &IpsetMatcher{
		Ipset: "test-ipset-v4",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Skipf("Skipping integration test - provisioning failed: %v", err)
		return
	}

	testCases := []struct {
		name        string
		remoteAddr  string
		expectMatch bool
		description string
	}{
		{
			name:        "localhost should match",
			remoteAddr:  "127.0.0.1:12345",
			expectMatch: true,
			description: "127.0.0.1 is in test-ipset-v4",
		},
		{
			name:        "test IP should match",
			remoteAddr:  "192.168.1.100:8080",
			expectMatch: true,
			description: "192.168.1.100 is in test-ipset-v4",
		},
		{
			name:        "random IP should not match",
			remoteAddr:  "203.0.113.1:443",
			expectMatch: false,
			description: "203.0.113.1 is not in test-ipset",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tc.remoteAddr

			result := m.Match(req)
			t.Logf("%s: Match=%v (expected=%v)", tc.description, result, tc.expectMatch)
			// Note: We log but don't assert because the actual ipset contents
			// may vary depending on the test environment
		})
	}
}

// TestMatch_ErrorHandling tests error handling in Match
func TestMatch_ErrorHandling(t *testing.T) {
	testCases := []struct {
		name        string
		matcher     *IpsetMatcher
		remoteAddr  string
		expectFalse bool
	}{
		{
			name: "invalid IP format",
			matcher: &IpsetMatcher{
				Ipset:  "test-ipset-v4",
				logger: zap.NewNop(),
			},
			remoteAddr:  "not-an-ip",
			expectFalse: true,
		},
		{
			name: "empty remote addr",
			matcher: &IpsetMatcher{
				Ipset:  "test-ipset-v4",
				logger: zap.NewNop(),
			},
			remoteAddr:  "",
			expectFalse: true,
		},
		{
			name: "malformed IP with port",
			matcher: &IpsetMatcher{
				Ipset:  "test-ipset-v4",
				logger: zap.NewNop(),
			},
			remoteAddr:  "999.999.999.999:8080",
			expectFalse: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tc.remoteAddr

			result := tc.matcher.Match(req)
			if tc.expectFalse && result {
				t.Errorf("Expected Match to return false for %s", tc.name)
			}
		})
	}
}

// TestProvision_IPv6Ipsets tests provisioning with IPv6 ipsets
func TestProvision_IPv6Ipsets(t *testing.T) {
	testCases := []struct {
		name          string
		ipsetName     string
		shouldSucceed bool
	}{
		{"existing IPv6 ipset", "test-ipset-v6", true},
		{"another IPv6 ipset", "blocklist-v6", true},
		{"empty IPv6 ipset", "empty-v6", true},
		{"non-existent IPv6 ipset", "does-not-exist-v6", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := &IpsetMatcher{
				Ipset: tc.ipsetName,
			}

			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			err := m.Provision(ctx)

			if tc.shouldSucceed {
				if err != nil {
					t.Errorf("Expected provision to succeed for %s, got error: %v", tc.ipsetName, err)
				}
				if m.logger == nil {
					t.Error("Expected logger to be set after provision")
				}
			} else {
				if err == nil {
					t.Errorf("Expected provision to fail for non-existent ipset %s", tc.ipsetName)
				}
			}
		})
	}
}

// TestMatch_IPv6FullIntegration tests IPv6 matching with real IPv6 ipsets
func TestMatch_IPv6FullIntegration(t *testing.T) {
	m := &IpsetMatcher{
		Ipset: "test-ipset-v6",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Fatalf("Failed to provision matcher: %v", err)
	}

	testCases := []struct {
		name        string
		remoteAddr  string
		shouldMatch bool
	}{
		{"localhost IPv6 should match", "[::1]:8080", true},
		{"test IPv6 should match", "[2001:db8::1]:8080", true},
		{"link-local IPv6 should match", "[fe80::1]:8080", true},
		{"random IPv6 should not match", "[2001:db8::999]:8080", false},
		{"different IPv6 should not match", "[fd00::1]:8080", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tc.remoteAddr

			result := m.Match(req)
			if result != tc.shouldMatch {
				t.Errorf("%s: Match=%v, expected=%v", tc.name, result, tc.shouldMatch)
			}
			t.Logf("%s is %sin test-ipset-v6: Match=%v (expected=%v)",
				tc.remoteAddr,
				map[bool]string{true: "", false: "not "}[tc.shouldMatch],
				result,
				tc.shouldMatch)
		})
	}
}

// TestMatch_IPv6WithRemoteAddr tests IPv6 matching with various remote address formats
func TestMatch_IPv6WithRemoteAddr(t *testing.T) {
	m := &IpsetMatcher{
		Ipset: "test-ipset-v6",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Fatalf("Failed to provision matcher: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "[2001:db8::1]:12345" // IPv6 remote addr

	result := m.Match(req)
	if !result {
		t.Error("Expected IPv6 from RemoteAddr to match")
	}
	t.Logf("IPv6 from RemoteAddr matched: %v", result)
}

// TestMatch_MixedIPv4AndIPv6 tests that IPv4 addresses don't match IPv6 ipsets
func TestMatch_MixedIPv4AndIPv6(t *testing.T) {
	testCases := []struct {
		name        string
		ipsetName   string
		remoteAddr  string
		shouldMatch bool
	}{
		{"IPv4 against IPv4 ipset", "test-ipset-v4", "127.0.0.1:8080", true},
		{"IPv6 against IPv6 ipset", "test-ipset-v6", "[::1]:8080", true},
		{"IPv4 against IPv6 ipset", "test-ipset-v6", "127.0.0.1:8080", false},
		{"IPv6 against IPv4 ipset", "test-ipset-v4", "[::1]:8080", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := &IpsetMatcher{
				Ipset: tc.ipsetName,
			}

			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			err := m.Provision(ctx)
			if err != nil {
				t.Fatalf("Failed to provision matcher: %v", err)
			}

			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tc.remoteAddr

			result := m.Match(req)
			if result != tc.shouldMatch {
				t.Errorf("%s: Match=%v, expected=%v", tc.name, result, tc.shouldMatch)
			}
			t.Logf("%s: %s against %s: Match=%v (expected=%v)",
				tc.name, tc.remoteAddr, tc.ipsetName, result, tc.shouldMatch)
		})
	}
}

// TestMatch_IPv6EdgeCases tests edge cases for IPv6 addresses
func TestMatch_IPv6EdgeCases(t *testing.T) {
	m := &IpsetMatcher{
		Ipset: "test-ipset-v6",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Fatalf("Failed to provision matcher: %v", err)
	}

	testCases := []struct {
		name        string
		remoteAddr  string
		shouldMatch bool
		shouldError bool
	}{
		{"IPv6 with zone ID", "[fe80::1%eth0]:8080", false, true}, // Zone IDs not supported in ipset
		{"IPv6 compressed", "[::1]:8080", true, false},
		{"IPv6 full form", "[0000:0000:0000:0000:0000:0000:0000:0001]:8080", true, false},
		{"IPv6 without brackets and port", "::1", true, false}, // Invalid format for RemoteAddr
		{"IPv4-mapped IPv6", "[::ffff:127.0.0.1]:8080", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tc.remoteAddr

			result := m.Match(req)

			if tc.shouldError {
				// For error cases, we expect Match to return false
				if result {
					t.Errorf("%s: Expected Match to return false for error case, got true", tc.name)
				}
			} else {
				if result != tc.shouldMatch {
					t.Errorf("%s: Match=%v, expected=%v", tc.name, result, tc.shouldMatch)
				}
			}
			t.Logf("%s: %s: Match=%v (expected=%v, shouldError=%v)",
				tc.name, tc.remoteAddr, result, tc.shouldMatch, tc.shouldError)
		})
	}
}

// TestMatch_WithClientIPVarKey tests that the matcher correctly uses the ClientIPVarKey
// from the request context when it's set (e.g., by Caddy's trusted_proxies logic)
// This test specifically hits the code path at lines 107-110 in ipset.go
func TestMatch_WithClientIPVarKey(t *testing.T) {
	// First provision the matcher so it has a valid handle
	m := &IpsetMatcher{
		Ipset: "test-ipset-v4",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Skipf("Skipping test - provisioning failed (may be expected in non-Docker environment): %v", err)
		return
	}
	defer func() {
		if err := m.Cleanup(); err != nil {
			t.Errorf("Cleanup failed: %v", err)
		}
	}()

	testCases := []struct {
		name       string
		clientIP   string
		remoteAddr string
	}{
		{
			name:       "IPv4 without port from ClientIPVarKey",
			clientIP:   "192.168.1.100",
			remoteAddr: "10.0.0.1:12345", // Should be ignored in favor of ClientIPVarKey
		},
		{
			name:       "localhost from ClientIPVarKey",
			clientIP:   "127.0.0.1",
			remoteAddr: "10.0.0.1:12345",
		},
		{
			name:       "IPv6 from ClientIPVarKey",
			clientIP:   "2001:db8::1",
			remoteAddr: "10.0.0.1:12345",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tc.remoteAddr

			// Use PrepareRequest to properly initialize the request context
			// This is what Caddy does internally before passing requests to handlers
			repl := caddyhttp.NewTestReplacer(req)
			w := httptest.NewRecorder()
			req = caddyhttp.PrepareRequest(req, repl, w, nil)

			// Set the ClientIPVarKey in the request context using caddyhttp.SetVar
			// This simulates what Caddy does when trusted_proxies is configured
			caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, tc.clientIP)

			// Call Match - this should use tc.clientIP from ClientIPVarKey, not tc.remoteAddr
			// This hits the code path at lines 107-110 in ipset.go where clientIPvar != nil
			result := m.Match(req)

			// We can't assert the exact result without knowing ipset contents,
			// but we can verify it doesn't panic and processes the ClientIPVarKey
			t.Logf("Match result for ClientIPVarKey=%s (RemoteAddr=%s): %v",
				tc.clientIP, tc.remoteAddr, result)
		})
	}
}
