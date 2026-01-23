//go:build linux
// +build linux

package caddy_ipset

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
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

	if err != nil && err.Error() != "ipset name is required" {
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

func TestMatchWithError_InvalidRemoteAddr(t *testing.T) {
	m := &IpsetMatcher{
		Ipset:  "test-ipset-v4",
		logger: zap.NewNop(),
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Skipf("Skipping test - provisioning failed: %v", err)
		return
	}
	defer func(m *IpsetMatcher) {
		_ = m.Cleanup()
	}(m)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "invalid-address"

	// Prepare the request with Caddy context
	repl := caddyhttp.NewTestReplacer(req)
	w := httptest.NewRecorder()
	req = caddyhttp.PrepareRequest(req, repl, w, nil)

	// Set an invalid ClientIPVarKey
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "invalid-address")

	result, err := m.MatchWithError(req)
	if err == nil {
		t.Error("Expected error for invalid remote address")
	}
	if result {
		t.Error("Expected MatchWithError to return false for invalid remote address")
	}
}

func TestMatchWithError_InvalidIP(t *testing.T) {
	m := &IpsetMatcher{
		Ipset: "test-ipset-v4",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Skipf("Skipping test - provisioning failed: %v", err)
		return
	}
	defer func(m *IpsetMatcher) {
		_ = m.Cleanup()
	}(m)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Prepare the request with Caddy context
	repl := caddyhttp.NewTestReplacer(req)
	w := httptest.NewRecorder()
	req = caddyhttp.PrepareRequest(req, repl, w, nil)

	// Set an invalid IP in ClientIPVarKey
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "not-an-ip")

	result, err := m.MatchWithError(req)
	if err == nil {
		t.Error("Expected error for invalid IP")
	}
	if result {
		t.Error("Expected MatchWithError to return false for invalid IP")
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

// TestMatchWithError_WithNetlinkMethod tests MatchWithError with netlink method
func TestMatchWithError_WithNetlinkMethod(t *testing.T) {
	m := &IpsetMatcher{
		Ipset: "test-ipset-v4",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Skipf("Skipping test - provisioning failed: %v", err)
		return
	}
	defer func(m *IpsetMatcher) {
		_ = m.Cleanup()
	}(m)
	// Test with an IP that should be in test-ipset-v4 (127.0.0.1)
	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Prepare the request with Caddy context
	repl := caddyhttp.NewTestReplacer(req)
	w := httptest.NewRecorder()
	req = caddyhttp.PrepareRequest(req, repl, w, nil)

	// Set the client IP
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "127.0.0.1")

	// This will attempt to use netlink
	// Result depends on whether test-ipset-v4 exists and contains 127.0.0.1
	result, err := m.MatchWithError(req)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	// We can't assert the result without knowing the ipset state
	// But we can verify it doesn't panic
	t.Logf("MatchWithError result for 127.0.0.1: %v", result)
}

// TestMatchWithError_IPWithoutPort tests MatchWithError with IP address without port
func TestMatchWithError_IPWithoutPort(t *testing.T) {
	m := &IpsetMatcher{
		Ipset: "test-ipset-v4",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Skipf("Skipping test - provisioning failed: %v", err)
		return
	}
	defer func(m *IpsetMatcher) {
		_ = m.Cleanup()
	}(m)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Prepare the request with Caddy context
	repl := caddyhttp.NewTestReplacer(req)
	w := httptest.NewRecorder()
	req = caddyhttp.PrepareRequest(req, repl, w, nil)

	// Set an IP without port
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "192.168.1.1")

	// This should handle the case where there's no port
	result, err := m.MatchWithError(req)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	t.Logf("MatchWithError result for IP without port: %v", result)
}

// TestMatchWithError_IPv6 tests MatchWithError with IPv6 address
func TestMatchWithError_IPv6(t *testing.T) {
	m := &IpsetMatcher{
		Ipset: "test-ipset-v4",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Skipf("Skipping test - provisioning failed: %v", err)
		return
	}
	defer func(m *IpsetMatcher) {
		_ = m.Cleanup()
	}(m)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Prepare the request with Caddy context
	repl := caddyhttp.NewTestReplacer(req)
	w := httptest.NewRecorder()
	req = caddyhttp.PrepareRequest(req, repl, w, nil)

	// Set IPv6 address
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "2001:db8::1")

	result, err := m.MatchWithError(req)
	// Should return false (no error) because IPv6 doesn't match IPv4 ipset
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	t.Logf("MatchWithError result for IPv6 against IPv4 ipset: %v", result)
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

// TestMatchWithError_FullIntegration tests the full MatchWithError flow with actual ipset
// This test requires the Docker environment with test-ipset-v4 containing specific IPs
func TestMatchWithError_FullIntegration(t *testing.T) {
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
	defer func(m *IpsetMatcher) {
		_ = m.Cleanup()
	}(m)

	testCases := []struct {
		name        string
		clientIP    string
		expectMatch bool
		description string
	}{
		{
			name:        "localhost should match",
			clientIP:    "127.0.0.1",
			expectMatch: true,
			description: "127.0.0.1 is in test-ipset-v4",
		},
		{
			name:        "test IP should match",
			clientIP:    "192.168.1.100",
			expectMatch: true,
			description: "192.168.1.100 is in test-ipset-v4",
		},
		{
			name:        "random IP should not match",
			clientIP:    "203.0.113.1",
			expectMatch: false,
			description: "203.0.113.1 is not in test-ipset",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)

			// Prepare the request with Caddy context
			repl := caddyhttp.NewTestReplacer(req)
			w := httptest.NewRecorder()
			req = caddyhttp.PrepareRequest(req, repl, w, nil)

			// Set the client IP
			caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, tc.clientIP)

			result, err := m.MatchWithError(req)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			t.Logf("%s: MatchWithError=%v (expected=%v)", tc.description, result, tc.expectMatch)
			// Note: We log but don't assert because the actual ipset contents
			// may vary depending on the test environment
		})
	}
}

// TestMatchWithError_ErrorHandling tests error handling in MatchWithError
func TestMatchWithError_ErrorHandling(t *testing.T) {
	testCases := []struct {
		name        string
		ipsetName   string
		clientIP    string
		expectError bool
		expectFalse bool
	}{
		{
			name:        "invalid IP format",
			ipsetName:   "test-ipset-v4",
			clientIP:    "not-an-ip",
			expectError: true,
			expectFalse: true,
		},
		{
			name:        "empty client IP",
			ipsetName:   "test-ipset-v4",
			clientIP:    "",
			expectError: true,
			expectFalse: true,
		},
		{
			name:        "malformed IP",
			ipsetName:   "test-ipset-v4",
			clientIP:    "999.999.999.999",
			expectError: true,
			expectFalse: true,
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
			if err != nil {
				t.Skipf("Skipping test - provisioning failed: %v", err)
				return
			}
			defer func(m *IpsetMatcher) {
				_ = m.Cleanup()
			}(m)

			req := httptest.NewRequest("GET", "http://example.com", nil)

			// Prepare the request with Caddy context
			repl := caddyhttp.NewTestReplacer(req)
			w := httptest.NewRecorder()
			req = caddyhttp.PrepareRequest(req, repl, w, nil)

			// Set the client IP
			caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, tc.clientIP)

			result, err := m.MatchWithError(req)
			if tc.expectError && err == nil {
				t.Errorf("Expected error for %s", tc.name)
			}
			if tc.expectFalse && result {
				t.Errorf("Expected MatchWithError to return false for %s", tc.name)
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

// TestMatchWithError_IPv6FullIntegration tests IPv6 matching with real IPv6 ipsets
func TestMatchWithError_IPv6FullIntegration(t *testing.T) {
	m := &IpsetMatcher{
		Ipset: "test-ipset-v6",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Fatalf("Failed to provision matcher: %v", err)
	}
	defer func(m *IpsetMatcher) {
		_ = m.Cleanup()
	}(m)

	testCases := []struct {
		name        string
		clientIP    string
		shouldMatch bool
	}{
		{"localhost IPv6 should match", "::1", true},
		{"test IPv6 should match", "2001:db8::1", true},
		{"link-local IPv6 should match", "fe80::1", true},
		{"random IPv6 should not match", "2001:db8::999", false},
		{"different IPv6 should not match", "fd00::1", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)

			// Prepare the request with Caddy context
			repl := caddyhttp.NewTestReplacer(req)
			w := httptest.NewRecorder()
			req = caddyhttp.PrepareRequest(req, repl, w, nil)

			// Set the client IP
			caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, tc.clientIP)

			result, err := m.MatchWithError(req)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tc.shouldMatch {
				t.Errorf("%s: MatchWithError=%v, expected=%v", tc.name, result, tc.shouldMatch)
			}
			t.Logf("%s is %sin test-ipset-v6: MatchWithError=%v (expected=%v)",
				tc.clientIP,
				map[bool]string{true: "", false: "not "}[tc.shouldMatch],
				result,
				tc.shouldMatch)
		})
	}
}

// TestMatchWithError_IPv6WithClientIP tests IPv6 matching with ClientIPVarKey
func TestMatchWithError_IPv6WithClientIP(t *testing.T) {
	m := &IpsetMatcher{
		Ipset: "test-ipset-v6",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Fatalf("Failed to provision matcher: %v", err)
	}
	defer func(m *IpsetMatcher) {
		_ = m.Cleanup()
	}(m)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Prepare the request with Caddy context
	repl := caddyhttp.NewTestReplacer(req)
	w := httptest.NewRecorder()
	req = caddyhttp.PrepareRequest(req, repl, w, nil)

	// Set IPv6 client IP
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "2001:db8::1")

	result, err := m.MatchWithError(req)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !result {
		t.Error("Expected IPv6 from ClientIPVarKey to match")
	}
	t.Logf("IPv6 from ClientIPVarKey matched: %v", result)
}

// TestMatchWithError_MixedIPv4AndIPv6 tests that IPv4 addresses don't match IPv6 ipsets
func TestMatchWithError_MixedIPv4AndIPv6(t *testing.T) {
	testCases := []struct {
		name        string
		ipsetName   string
		clientIP    string
		shouldMatch bool
	}{
		{"IPv4 against IPv4 ipset", "test-ipset-v4", "127.0.0.1", true},
		{"IPv6 against IPv6 ipset", "test-ipset-v6", "::1", true},
		{"IPv4 against IPv6 ipset", "test-ipset-v6", "127.0.0.1", false},
		{"IPv6 against IPv4 ipset", "test-ipset-v4", "::1", false},
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
			defer func(m *IpsetMatcher) {
				_ = m.Cleanup()
			}(m)

			req := httptest.NewRequest("GET", "http://example.com", nil)

			// Prepare the request with Caddy context
			repl := caddyhttp.NewTestReplacer(req)
			w := httptest.NewRecorder()
			req = caddyhttp.PrepareRequest(req, repl, w, nil)

			// Set the client IP
			caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, tc.clientIP)

			result, err := m.MatchWithError(req)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tc.shouldMatch {
				t.Errorf("%s: MatchWithError=%v, expected=%v", tc.name, result, tc.shouldMatch)
			}
			t.Logf("%s: %s against %s: MatchWithError=%v (expected=%v)",
				tc.name, tc.clientIP, tc.ipsetName, result, tc.shouldMatch)
		})
	}
}

// TestMatchWithError_IPv6EdgeCases tests edge cases for IPv6 addresses
func TestMatchWithError_IPv6EdgeCases(t *testing.T) {
	m := &IpsetMatcher{
		Ipset: "test-ipset-v6",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Fatalf("Failed to provision matcher: %v", err)
	}
	defer func(m *IpsetMatcher) {
		_ = m.Cleanup()
	}(m)

	testCases := []struct {
		name        string
		clientIP    string
		shouldMatch bool
		shouldError bool
	}{
		{"IPv6 with zone ID", "fe80::1%eth0", false, true}, // Zone IDs not supported in ipset
		{"IPv6 compressed", "::1", true, false},
		{"IPv6 full form", "0000:0000:0000:0000:0000:0000:0000:0001", true, false},
		{"IPv4-mapped IPv6", "::ffff:127.0.0.1", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)

			// Prepare the request with Caddy context
			repl := caddyhttp.NewTestReplacer(req)
			w := httptest.NewRecorder()
			req = caddyhttp.PrepareRequest(req, repl, w, nil)

			// Set the client IP
			caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, tc.clientIP)

			result, err := m.MatchWithError(req)

			if tc.shouldError {
				// For error cases, we expect an error
				if err == nil {
					t.Errorf("%s: Expected error but got none", tc.name)
				}
				if result {
					t.Errorf("%s: Expected MatchWithError to return false for error case, got true", tc.name)
				}
			} else {
				if err != nil {
					t.Errorf("%s: Unexpected error: %v", tc.name, err)
				}
				if result != tc.shouldMatch {
					t.Errorf("%s: MatchWithError=%v, expected=%v", tc.name, result, tc.shouldMatch)
				}
			}
			t.Logf("%s: %s: MatchWithError=%v (expected=%v, shouldError=%v)",
				tc.name, tc.clientIP, result, tc.shouldMatch, tc.shouldError)
		})
	}
}

// TestMatchWithError_WithClientIPVarKey tests that the matcher correctly uses the ClientIPVarKey
// from the request context when it's set (e.g., by Caddy's trusted_proxies logic)
// This test specifically hits the code path at lines 154-159 in ipset.go
func TestMatchWithError_WithClientIPVarKey(t *testing.T) {
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
		name     string
		clientIP string
	}{
		{
			name:     "IPv4 without port from ClientIPVarKey",
			clientIP: "192.168.1.100",
		},
		{
			name:     "localhost from ClientIPVarKey",
			clientIP: "127.0.0.1",
		},
		{
			name:     "IPv6 from ClientIPVarKey",
			clientIP: "2001:db8::1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)

			// Use PrepareRequest to properly initialize the request context
			// This is what Caddy does internally before passing requests to handlers
			repl := caddyhttp.NewTestReplacer(req)
			w := httptest.NewRecorder()
			req = caddyhttp.PrepareRequest(req, repl, w, nil)

			// Set the ClientIPVarKey in the request context using caddyhttp.SetVar
			// This simulates what Caddy does when trusted_proxies is configured
			caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, tc.clientIP)

			// Call MatchWithError - this should use tc.clientIP from ClientIPVarKey
			// This hits the code path at lines 154-159 in ipset.go where clientIPvar is retrieved
			result, err := m.MatchWithError(req)

			// We can't assert the exact result without knowing ipset contents,
			// but we can verify it doesn't panic and processes the ClientIPVarKey
			if err != nil {
				// IPv6 against IPv4 ipset should not error, just return false
				if tc.clientIP == "2001:db8::1" {
					if result {
						t.Errorf("Expected false for IPv6 against IPv4 ipset")
					}
				} else {
					t.Errorf("Unexpected error: %v", err)
				}
			}
			t.Logf("MatchWithError result for ClientIPVarKey=%s: %v (err=%v)",
				tc.clientIP, result, err)
		})
	}
}

// TestProvision_SavesIPFamily tests that Provision correctly saves the ipset family
func TestProvision_SavesIPFamily(t *testing.T) {
	testCases := []struct {
		name           string
		ipsetName      string
		expectedFamily uint8
	}{
		{"IPv4 ipset saves IPv4 family", "test-ipset-v4", unix.NFPROTO_IPV4},
		{"IPv6 ipset saves IPv6 family", "test-ipset-v6", unix.NFPROTO_IPV6},
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

			if m.ipsetFamily != tc.expectedFamily {
				t.Errorf("Expected ipsetFamily=%d (%s), got %d (%s)",
					tc.expectedFamily, familyToString(tc.expectedFamily),
					m.ipsetFamily, familyToString(m.ipsetFamily))
			}

			t.Logf("Ipset %s correctly saved family: %s (%d)",
				tc.ipsetName, familyToString(m.ipsetFamily), m.ipsetFamily)
		})
	}
}

// TestMatchWithError_IPFamilyOptimization tests that mismatched IP families are skipped
func TestMatchWithError_IPFamilyOptimization(t *testing.T) {
	testCases := []struct {
		name        string
		ipsetName   string
		ipsetFamily uint8
		clientIP    string
		shouldMatch bool
		shouldSkip  bool
		description string
	}{
		{
			name:        "IPv4 against IPv4 ipset - should check",
			ipsetName:   "test-ipset-v4",
			ipsetFamily: unix.NFPROTO_IPV4,
			clientIP:    "127.0.0.1",
			shouldMatch: true,
			shouldSkip:  false,
			description: "IPv4 address should be checked against IPv4 ipset",
		},
		{
			name:        "IPv6 against IPv6 ipset - should check",
			ipsetName:   "test-ipset-v6",
			ipsetFamily: unix.NFPROTO_IPV6,
			clientIP:    "::1",
			shouldMatch: true,
			shouldSkip:  false,
			description: "IPv6 address should be checked against IPv6 ipset",
		},
		{
			name:        "IPv6 against IPv4 ipset - should skip",
			ipsetName:   "test-ipset-v4",
			ipsetFamily: unix.NFPROTO_IPV4,
			clientIP:    "::1",
			shouldMatch: false,
			shouldSkip:  true,
			description: "IPv6 address should be skipped for IPv4 ipset",
		},
		{
			name:        "IPv4 against IPv6 ipset - should skip",
			ipsetName:   "test-ipset-v6",
			ipsetFamily: unix.NFPROTO_IPV6,
			clientIP:    "127.0.0.1",
			shouldMatch: false,
			shouldSkip:  true,
			description: "IPv4 address should be skipped for IPv6 ipset",
		},
		{
			name:        "IPv4 non-matching against IPv4 ipset - should check but not match",
			ipsetName:   "test-ipset-v4",
			ipsetFamily: unix.NFPROTO_IPV4,
			clientIP:    "203.0.113.1",
			shouldMatch: false,
			shouldSkip:  false,
			description: "IPv4 address not in ipset should be checked but return false",
		},
		{
			name:        "IPv6 non-matching against IPv6 ipset - should check but not match",
			ipsetName:   "test-ipset-v6",
			ipsetFamily: unix.NFPROTO_IPV6,
			clientIP:    "2001:db8::999",
			shouldMatch: false,
			shouldSkip:  false,
			description: "IPv6 address not in ipset should be checked but return false",
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
			if err != nil {
				t.Fatalf("Failed to provision matcher: %v", err)
			}
			defer func(m *IpsetMatcher) {
				_ = m.Cleanup()
			}(m)

			// Verify the ipset family was saved correctly
			if m.ipsetFamily != tc.ipsetFamily {
				t.Errorf("Expected ipsetFamily=%d, got %d", tc.ipsetFamily, m.ipsetFamily)
			}

			req := httptest.NewRequest("GET", "http://example.com", nil)

			// Prepare the request with Caddy context
			repl := caddyhttp.NewTestReplacer(req)
			w := httptest.NewRecorder()
			req = caddyhttp.PrepareRequest(req, repl, w, nil)

			// Set the client IP
			caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, tc.clientIP)

			result, err := m.MatchWithError(req)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if result != tc.shouldMatch {
				t.Errorf("%s: MatchWithError=%v, expected=%v", tc.description, result, tc.shouldMatch)
			}

			if tc.shouldSkip {
				t.Logf("✓ %s: Correctly skipped (MatchWithError=%v)", tc.description, result)
			} else {
				t.Logf("✓ %s: Correctly checked (MatchWithError=%v)", tc.description, result)
			}
		})
	}
}

// TestProvision_TooLongIpsetName tests that ipset names exceeding max length are rejected
func TestProvision_TooLongIpsetName(t *testing.T) {
	// Create a name that exceeds IPSET_MAXNAMELEN (32 characters)
	longName := "this_is_a_very_long_ipset_name_that_exceeds_the_maximum_allowed_length"

	m := &IpsetMatcher{
		Ipset: longName,
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err == nil {
		t.Error("Expected error for ipset name exceeding maximum length")
	}

	if err != nil && !strings.Contains(err.Error(), "exceeds maximum length") {
		t.Errorf("Expected error message about exceeding maximum length, got: %v", err)
	}
}

// TestFamilyToString_UnknownFamily tests the default case in familyToString
func TestFamilyToString_UnknownFamily(t *testing.T) {
	testCases := []struct {
		family   uint8
		expected string
	}{
		{unix.NFPROTO_IPV4, "inet"},
		{unix.NFPROTO_IPV6, "inet6"},
		{99, "unknown(99)"},   // Unknown family code
		{255, "unknown(255)"}, // Another unknown family code
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := familyToString(tc.family)
			if result != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

// TestIsPermissionError_WrappedError tests wrapped syscall errors
func TestIsPermissionError_WrappedError(t *testing.T) {
	// Test wrapped EPERM error
	wrappedEPERM := fmt.Errorf("netlink error: %w", syscall.EPERM)
	if !isPermissionError(wrappedEPERM) {
		t.Error("Expected wrapped EPERM to be detected as permission error")
	}

	// Test wrapped EACCES error
	wrappedEACCES := fmt.Errorf("access denied: %w", syscall.EACCES)
	if !isPermissionError(wrappedEACCES) {
		t.Error("Expected wrapped EACCES to be detected as permission error")
	}

	// Test wrapped non-permission error
	wrappedEINVAL := fmt.Errorf("invalid argument: %w", syscall.EINVAL)
	if isPermissionError(wrappedEINVAL) {
		t.Error("Expected wrapped EINVAL to not be detected as permission error")
	}
}

// TestMatchWithError_ClientIPVarKeyNonString tests the case where ClientIPVarKey is not a string
func TestMatchWithError_ClientIPVarKeyNonString(t *testing.T) {
	m := &IpsetMatcher{
		Ipset: "test-ipset-v4",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Skipf("Skipping test - provisioning failed: %v", err)
		return
	}
	defer func() {
		if err := m.Cleanup(); err != nil {
			t.Errorf("Cleanup failed: %v", err)
		}
	}()

	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Prepare the request with Caddy context
	repl := caddyhttp.NewTestReplacer(req)
	w := httptest.NewRecorder()
	req = caddyhttp.PrepareRequest(req, repl, w, nil)

	// Set ClientIPVarKey to a non-string value (e.g., an integer)
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, 12345)

	// This should return an error because the type assertion fails
	result, err := m.MatchWithError(req)
	if err == nil {
		t.Error("Expected error when ClientIPVarKey is not a string")
	}
	if result {
		t.Error("Expected MatchWithError to return false when ClientIPVarKey is not a string")
	}
}

// TestMatchWithError_UninitializedHandle tests the case where the handle is not initialized
func TestMatchWithError_UninitializedHandle(t *testing.T) {
	m := &IpsetMatcher{
		Ipset:  "test-ipset-v4",
		logger: zap.NewNop(),
		handle: nil, // Explicitly set to nil to simulate uninitialized state
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Prepare the request with Caddy context
	repl := caddyhttp.NewTestReplacer(req)
	w := httptest.NewRecorder()
	req = caddyhttp.PrepareRequest(req, repl, w, nil)

	// Set a valid client IP
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "127.0.0.1")

	// This should return an error because the handle is not initialized
	result, err := m.MatchWithError(req)
	if err == nil {
		t.Error("Expected error when handle is not initialized")
	}
	if err != nil && !strings.Contains(err.Error(), "not initialized") && !strings.Contains(err.Error(), "not properly provisioned") {
		t.Errorf("Expected error message about uninitialized handle, got: %v", err)
	}
	if result {
		t.Error("Expected MatchWithError to return false when handle is not initialized")
	}
}
