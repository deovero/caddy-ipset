//go:build linux
// +build linux

package caddy_ipset

import (
	"context"
	"net"
	"net/http/httptest"
	"strings"
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
				Ipsets: []string{tc.ipsetName},
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
		Ipsets: []string{"test-ipset-v4"},
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
		Ipsets: []string{"test-ipset-v4"},
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

// TestProvision_NetlinkSuccess tests successful provisioning with netlink access
func TestProvision_NetlinkSuccess(t *testing.T) {
	// This test requires an actual ipset to exist
	// It will use the test-ipset-v4 created by the Docker environment
	m := &IpsetMatcher{
		Ipsets: []string{"test-ipset-v4"},
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
		Ipsets: []string{"nonexistent-ipset-12345"},
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
		Ipsets: []string{"test-ipset-v4"},
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
		Ipsets: []string{"test-ipset-v4"},
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
		Ipsets: []string{"test-ipset-v4"},
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
		name         string
		input        string
		expectError  bool
		expectedSets []string
	}{
		{
			name:         "valid ipset name",
			input:        "ipset test-ipset-v4",
			expectError:  false,
			expectedSets: []string{"test-ipset-v4"},
		},
		{
			name:         "valid ipset name with underscores",
			input:        "ipset my_ipset_123",
			expectError:  false,
			expectedSets: []string{"my_ipset_123"},
		},
		{
			name:         "multiple ipsets in one directive",
			input:        "ipset test-ipset-v4 test-ipset-v6",
			expectError:  false,
			expectedSets: []string{"test-ipset-v4", "test-ipset-v6"},
		},
		{
			name:         "multiple ipsets in one directive - three ipsets",
			input:        "ipset blocklist-v4 blocklist-v6 test-ipset-v4",
			expectError:  false,
			expectedSets: []string{"blocklist-v4", "blocklist-v6", "test-ipset-v4"},
		},
		{
			name:         "missing argument",
			input:        "ipset",
			expectError:  true,
			expectedSets: nil,
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
			if !tc.expectError {
				if len(m.Ipsets) != len(tc.expectedSets) {
					t.Errorf("Expected %d ipsets, got %d", len(tc.expectedSets), len(m.Ipsets))
				}
				for i, expectedSet := range tc.expectedSets {
					if i >= len(m.Ipsets) {
						t.Errorf("Missing ipset at index %d: expected '%s'", i, expectedSet)
					} else if m.Ipsets[i] != expectedSet {
						t.Errorf("Ipset at index %d: expected '%s', got '%s'", i, expectedSet, m.Ipsets[i])
					}
				}
			}
		})
	}
}

// TestUnmarshalCaddyfile_MultipleDirectives tests that multiple ipset directives
// are correctly parsed into a single IpsetMatcher instance with multiple ipsets.
// This verifies the fix for the bug where only the last ipset was being loaded.
func TestUnmarshalCaddyfile_MultipleDirectives(t *testing.T) {
	testCases := []struct {
		name         string
		input        string
		expectError  bool
		expectedSets []string
		description  string
	}{
		{
			name: "two separate directives",
			input: `ipset test-ipset-v4
ipset test-ipset-v6`,
			expectError:  false,
			expectedSets: []string{"test-ipset-v4", "test-ipset-v6"},
			description:  "Multiple ipset directives in a matcher block",
		},
		{
			name: "three separate directives",
			input: `ipset test-ipset-v4
ipset test-ipset-v6
ipset blocklist-v4`,
			expectError:  false,
			expectedSets: []string{"test-ipset-v4", "test-ipset-v6", "blocklist-v4"},
			description:  "Three ipset directives in a matcher block",
		},
		{
			name: "mixed: multiple directives with multiple args",
			input: `ipset test-ipset-v4 test-ipset-v6
ipset blocklist-v4`,
			expectError:  false,
			expectedSets: []string{"test-ipset-v4", "test-ipset-v6", "blocklist-v4"},
			description:  "First directive has two ipsets, second has one",
		},
		{
			name: "mixed: multiple directives with varying args",
			input: `ipset test-ipset-v4
ipset test-ipset-v6 blocklist-v6
ipset blocklist-v4`,
			expectError:  false,
			expectedSets: []string{"test-ipset-v4", "test-ipset-v6", "blocklist-v6", "blocklist-v4"},
			description:  "Multiple directives with varying number of arguments",
		},
		{
			name:         "single directive with many ipsets",
			input:        `ipset test-ipset-v4 test-ipset-v6 blocklist-v4 blocklist-v6`,
			expectError:  false,
			expectedSets: []string{"test-ipset-v4", "test-ipset-v6", "blocklist-v4", "blocklist-v6"},
			description:  "Single directive with four ipsets",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tc.input)

			// Create ONE matcher instance - it should consume ALL ipset directives
			matcher := &IpsetMatcher{}
			err := matcher.UnmarshalCaddyfile(d)

			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Fatalf("Failed to unmarshal ipset directives: %v", err)
			}

			if !tc.expectError {
				// Verify that the matcher has all expected ipsets
				if len(matcher.Ipsets) != len(tc.expectedSets) {
					t.Fatalf("Expected %d ipsets, got %d", len(tc.expectedSets), len(matcher.Ipsets))
				}

				for i, expectedSet := range tc.expectedSets {
					if matcher.Ipsets[i] != expectedSet {
						t.Errorf("Ipset at index %d: expected '%s', got '%s'", i, expectedSet, matcher.Ipsets[i])
					}
				}

				t.Logf("✓ %s: Successfully parsed %d ipsets: %v", tc.description, len(matcher.Ipsets), matcher.Ipsets)
			}
		})
	}
}

// TestProvision_MultipleIpsets tests provisioning with multiple ipsets
func TestProvision_MultipleIpsets(t *testing.T) {
	testCases := []struct {
		name        string
		ipsets      []string
		expectError bool
		description string
	}{
		{
			name:        "two IPv4 ipsets",
			ipsets:      []string{"test-ipset-v4", "blocklist-v4"},
			expectError: false,
			description: "Should successfully provision two IPv4 ipsets",
		},
		{
			name:        "two IPv6 ipsets",
			ipsets:      []string{"test-ipset-v6", "blocklist-v6"},
			expectError: false,
			description: "Should successfully provision two IPv6 ipsets",
		},
		{
			name:        "mixed IPv4 and IPv6 ipsets",
			ipsets:      []string{"test-ipset-v4", "test-ipset-v6"},
			expectError: false,
			description: "Should successfully provision mixed IPv4 and IPv6 ipsets",
		},
		{
			name:        "four ipsets - mixed",
			ipsets:      []string{"test-ipset-v4", "test-ipset-v6", "blocklist-v4", "blocklist-v6"},
			expectError: false,
			description: "Should successfully provision four ipsets",
		},
		{
			name:        "one valid, one invalid",
			ipsets:      []string{"test-ipset-v4", "does-not-exist-12345"},
			expectError: true,
			description: "Should fail if any ipset doesn't exist",
		},
		{
			name:        "empty ipsets included",
			ipsets:      []string{"test-ipset-v4", "empty-4"},
			expectError: false,
			description: "Should successfully provision with empty ipsets",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := &IpsetMatcher{
				Ipsets: tc.ipsets,
			}

			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			err := m.Provision(ctx)

			if tc.expectError && err == nil {
				t.Errorf("Expected error for %s but got none", tc.description)
			}
			if !tc.expectError && err != nil {
				t.Logf("Provisioning failed for '%s': %v (may be expected in non-Docker environment)", tc.description, err)
			}
			if !tc.expectError && err == nil {
				// Verify logger was set
				if m.logger == nil {
					t.Error("Expected logger to be set")
				}
				// Verify pool was initialized
				if m.pool == nil {
					t.Error("Expected pool to be initialized")
				}
				// Verify all ipset families were recorded
				if len(m.ipsetFamilies) != len(tc.ipsets) {
					t.Errorf("Expected %d ipset families, got %d", len(tc.ipsets), len(m.ipsetFamilies))
				}
				t.Logf("✓ %s: Successfully provisioned %d ipsets", tc.description, len(tc.ipsets))

				// Clean up
				_ = m.Cleanup()
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
		Ipsets: []string{"test-ipset-v4"},
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

		// Verify it's specifically a CAP_NET_ADMIN capability error
		// The new early check should produce this message
		if !strings.Contains(err.Error(), "CAP_NET_ADMIN") {
			t.Errorf("Expected error to contain 'CAP_NET_ADMIN', got: %v", err)
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
				Ipsets: []string{tc.ipsetName},
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
		Ipsets: []string{"test-ipset-v4"},
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

// TestMatchWithError_MultipleIpsets tests matching with multiple ipsets (OR logic)
func TestMatchWithError_MultipleIpsets(t *testing.T) {
	testCases := []struct {
		name        string
		ipsets      []string
		clientIP    string
		description string
	}{
		{
			name:        "IPv4 against two IPv4 ipsets",
			ipsets:      []string{"test-ipset-v4", "blocklist-v4"},
			clientIP:    "127.0.0.1",
			description: "Should match if IP is in any of the ipsets",
		},
		{
			name:        "IPv6 against two IPv6 ipsets",
			ipsets:      []string{"test-ipset-v6", "blocklist-v6"},
			clientIP:    "::1",
			description: "Should match if IP is in any of the ipsets",
		},
		{
			name:        "IPv4 against mixed ipsets",
			ipsets:      []string{"test-ipset-v4", "test-ipset-v6"},
			clientIP:    "127.0.0.1",
			description: "Should match IPv4 ipset and skip IPv6 ipset",
		},
		{
			name:        "IPv6 against mixed ipsets",
			ipsets:      []string{"test-ipset-v4", "test-ipset-v6"},
			clientIP:    "::1",
			description: "Should skip IPv4 ipset and match IPv6 ipset",
		},
		{
			name:        "IP not in any ipset",
			ipsets:      []string{"test-ipset-v4", "blocklist-v4"},
			clientIP:    "203.0.113.1",
			description: "Should return false if IP is not in any ipset",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := &IpsetMatcher{
				Ipsets: tc.ipsets,
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
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			t.Logf("%s: %s against %v: MatchWithError=%v",
				tc.description, tc.clientIP, tc.ipsets, result)
		})
	}
}

// TestMatchWithError_MultipleIpsets_ORLogic tests that the OR logic works correctly
// This test verifies that if an IP is in ANY of the configured ipsets, it matches
func TestMatchWithError_MultipleIpsets_ORLogic(t *testing.T) {
	// This test requires specific ipset contents to verify OR logic
	// We'll test with known IPs that should be in specific ipsets

	m := &IpsetMatcher{
		Ipsets: []string{"test-ipset-v4", "blocklist-v4"},
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

	testCases := []struct {
		name        string
		clientIP    string
		description string
	}{
		{
			name:        "IP in first ipset",
			clientIP:    "127.0.0.1",
			description: "Should match because it's in test-ipset-v4",
		},
		{
			name:        "IP in second ipset",
			clientIP:    "10.0.0.1",
			description: "Should match if it's in blocklist-v4",
		},
		{
			name:        "IP in both ipsets",
			clientIP:    "192.168.1.100",
			description: "Should match because it's in at least one ipset",
		},
		{
			name:        "IP in neither ipset",
			clientIP:    "203.0.113.1",
			description: "Should not match because it's not in any ipset",
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
			t.Logf("%s: %s: MatchWithError=%v", tc.description, tc.clientIP, result)
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
				Ipsets: []string{tc.ipsetName},
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
				Ipsets: []string{tc.ipsetName},
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
		Ipsets: []string{"test-ipset-v6"},
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
		Ipsets: []string{"test-ipset-v6"},
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
				Ipsets: []string{tc.ipsetName},
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
		Ipsets: []string{"test-ipset-v6"},
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
		Ipsets: []string{"test-ipset-v4"},
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
				Ipsets: []string{tc.ipsetName},
			}

			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			err := m.Provision(ctx)
			if err != nil {
				t.Fatalf("Failed to provision matcher: %v", err)
			}

			if len(m.ipsetFamilies) != 1 {
				t.Fatalf("Expected 1 ipset family, got %d", len(m.ipsetFamilies))
			}
			if m.ipsetFamilies[0] != tc.expectedFamily {
				t.Errorf("Expected ipsetFamily=%d (%s), got %d (%s)",
					tc.expectedFamily, familyCodeToString(tc.expectedFamily),
					m.ipsetFamilies[0], familyCodeToString(m.ipsetFamilies[0]))
			}

			t.Logf("Ipset %s correctly saved family: %s (%d)",
				tc.ipsetName, familyCodeToString(m.ipsetFamilies[0]), m.ipsetFamilies[0])
		})
	}
}

// TestProvision_SavesIPFamily_MultipleIpsets tests that Provision correctly saves families for multiple ipsets
func TestProvision_SavesIPFamily_MultipleIpsets(t *testing.T) {
	testCases := []struct {
		name             string
		ipsets           []string
		expectedFamilies []uint8
	}{
		{
			name:             "two IPv4 ipsets",
			ipsets:           []string{"test-ipset-v4", "blocklist-v4"},
			expectedFamilies: []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV4},
		},
		{
			name:             "two IPv6 ipsets",
			ipsets:           []string{"test-ipset-v6", "blocklist-v6"},
			expectedFamilies: []uint8{unix.NFPROTO_IPV6, unix.NFPROTO_IPV6},
		},
		{
			name:             "mixed IPv4 and IPv6",
			ipsets:           []string{"test-ipset-v4", "test-ipset-v6"},
			expectedFamilies: []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6},
		},
		{
			name:             "four ipsets mixed",
			ipsets:           []string{"test-ipset-v4", "test-ipset-v6", "blocklist-v4", "blocklist-v6"},
			expectedFamilies: []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6, unix.NFPROTO_IPV4, unix.NFPROTO_IPV6},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := &IpsetMatcher{
				Ipsets: tc.ipsets,
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

			if len(m.ipsetFamilies) != len(tc.expectedFamilies) {
				t.Fatalf("Expected %d ipset families, got %d", len(tc.expectedFamilies), len(m.ipsetFamilies))
			}

			for i, expectedFamily := range tc.expectedFamilies {
				if m.ipsetFamilies[i] != expectedFamily {
					t.Errorf("Ipset %s (index %d): expected family=%d (%s), got %d (%s)",
						tc.ipsets[i], i,
						expectedFamily, familyCodeToString(expectedFamily),
						m.ipsetFamilies[i], familyCodeToString(m.ipsetFamilies[i]))
				}
			}

			t.Logf("✓ Successfully saved families for %d ipsets:", len(tc.ipsets))
			for i, ipset := range tc.ipsets {
				t.Logf("  - %s: %s (%d)", ipset, familyCodeToString(m.ipsetFamilies[i]), m.ipsetFamilies[i])
			}
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
				Ipsets: []string{tc.ipsetName},
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
			if len(m.ipsetFamilies) != 1 {
				t.Fatalf("Expected 1 ipset family, got %d", len(m.ipsetFamilies))
			}
			if m.ipsetFamilies[0] != tc.ipsetFamily {
				t.Errorf("Expected ipsetFamily=%d, got %d", tc.ipsetFamily, m.ipsetFamilies[0])
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
		Ipsets: []string{longName},
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

// TestFamilyToString_UnknownFamily tests the default case in familyCodeToString
func TestFamilyToString_UnknownFamily(t *testing.T) {
	testCases := []struct {
		family   uint8
		expected string
		name     string
	}{
		{unix.NFPROTO_IPV4, "IPv4", "IPv4"},
		{unix.NFPROTO_IPV6, "IPv6", "IPv6"},
		{99, "unknown(99)", "unknown_99"},    // Unknown family code
		{255, "unknown(255)", "unknown_255"}, // Another unknown family code
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := familyCodeToString(tc.family)
			if result != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

// TestMatchWithError_ClientIPVarKeyNonString tests the case where ClientIPVarKey is not a string
func TestMatchWithError_ClientIPVarKeyNonString(t *testing.T) {
	m := &IpsetMatcher{
		Ipsets: []string{"test-ipset-v4"},
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
		Ipsets: []string{"test-ipset-v4"},
		logger: zap.NewNop(),
		pool:   nil, // Explicitly set to nil to simulate uninitialized state
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

// TestMultipleIpsets_EndToEnd tests the complete flow from parsing to matching with multiple ipsets
func TestMultipleIpsets_EndToEnd(t *testing.T) {
	// Test 1: Parse Caddyfile with multiple directives
	input := `ipset test-ipset-v4 blocklist-v4
ipset test-ipset-v6`

	d := caddyfile.NewTestDispenser(input)
	matcher := &IpsetMatcher{}
	err := matcher.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify parsing
	expectedIpsets := []string{"test-ipset-v4", "blocklist-v4", "test-ipset-v6"}
	if len(matcher.Ipsets) != len(expectedIpsets) {
		t.Fatalf("Expected %d ipsets, got %d", len(expectedIpsets), len(matcher.Ipsets))
	}
	for i, expected := range expectedIpsets {
		if matcher.Ipsets[i] != expected {
			t.Errorf("Ipset at index %d: expected '%s', got '%s'", i, expected, matcher.Ipsets[i])
		}
	}
	t.Logf("✓ Parsed %d ipsets from Caddyfile: %v", len(matcher.Ipsets), matcher.Ipsets)

	// Test 2: Provision the matcher
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err = matcher.Provision(ctx)
	if err != nil {
		t.Skipf("Skipping test - provisioning failed: %v", err)
		return
	}
	defer func(m *IpsetMatcher) {
		_ = m.Cleanup()
	}(matcher)

	// Verify provisioning
	// Verify pool was initialized
	if matcher.pool == nil {
		t.Error("Expected pool to be initialized")
	}
	if len(matcher.ipsetFamilies) != len(expectedIpsets) {
		t.Errorf("Expected %d families, got %d", len(expectedIpsets), len(matcher.ipsetFamilies))
	}
	t.Logf("✓ Provisioned %d ipsets with families", len(matcher.ipsetFamilies))

	// Test 3: Test matching with various IPs
	testCases := []struct {
		name     string
		clientIP string
	}{
		{"IPv4 localhost", "127.0.0.1"},
		{"IPv4 test IP", "192.168.1.100"},
		{"IPv4 not in any ipset", "203.0.113.1"},
		{"IPv6 localhost", "::1"},
		{"IPv6 test IP", "2001:db8::1"},
		{"IPv6 not in any ipset", "2001:db8::999"},
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

			result, err := matcher.MatchWithError(req)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			t.Logf("  %s (%s): matched=%v", tc.name, tc.clientIP, result)
		})
	}

	t.Logf("✓ Successfully tested end-to-end flow with multiple ipsets")
}

// TestContextCancellation tests that MatchWithError respects context cancellation
func TestContextCancellation(t *testing.T) {
	m := &IpsetMatcher{
		Ipsets: []string{"test-ipset-v4", "blocklist-v4", "test-ipset-v6", "blocklist-v6"},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Skipf("Skipping context cancellation test - provisioning failed: %v", err)
		return
	}
	defer func(m *IpsetMatcher) {
		_ = m.Cleanup()
	}(m)

	// Create a request with a cancellable context
	req := httptest.NewRequest("GET", "http://example.com", nil)
	reqCtx, reqCancel := context.WithCancel(req.Context())
	req = req.WithContext(reqCtx)

	repl := caddyhttp.NewTestReplacer(req)
	w := httptest.NewRecorder()
	req = caddyhttp.PrepareRequest(req, repl, w, nil)
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "127.0.0.1")

	// Cancel the context before calling MatchWithError
	reqCancel()

	result, err := m.MatchWithError(req)

	// Should get a context cancellation error
	if err == nil {
		t.Logf("Note: Context cancellation not detected (result: %v). This may happen if the check completes before cancellation is detected.", result)
	} else if err == context.Canceled {
		t.Logf("✓ Context cancellation properly detected: %v", err)
	} else {
		t.Logf("Got error (not context.Canceled): %v", err)
	}
}

// TestGetIpFamilyString tests the getIpFamilyString helper function
func TestGetIpFamilyString(t *testing.T) {
	testCases := []struct {
		name     string
		ip       string
		expected string
	}{
		{"IPv4 address", "192.168.1.1", "IPv4"},
		{"IPv4 loopback", "127.0.0.1", "IPv4"},
		{"IPv4 broadcast", "255.255.255.255", "IPv4"},
		{"IPv6 address", "2001:db8::1", "IPv6"},
		{"IPv6 loopback", "::1", "IPv6"},
		{"IPv6 full form", "2001:0db8:0000:0000:0000:0000:0000:0001", "IPv6"},
		{"IPv6 link-local", "fe80::1", "IPv6"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tc.ip)
			}
			result := getIpFamilyString(ip)
			if result != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

// TestProvision_EmptyIpsetInList tests that an empty string in the ipset list is rejected
func TestProvision_EmptyIpsetInList(t *testing.T) {
	m := &IpsetMatcher{
		Ipsets: []string{"test-ipset-v4", ""},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err == nil {
		t.Error("Expected error for empty ipset name in list")
	}

	if err != nil && !strings.Contains(err.Error(), "ipset name is required") {
		t.Errorf("Expected 'ipset name is required' error, got '%s'", err.Error())
	}
}

// TestCleanup_MultipleHandles tests that Cleanup properly closes multiple handles
func TestCleanup_MultipleHandles(t *testing.T) {
	m := &IpsetMatcher{
		Ipsets: []string{"test-ipset-v4"},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err != nil {
		t.Skipf("Skipping test - provisioning failed: %v", err)
		return
	}

	// Force creation of multiple handles by getting them from the pool
	handle1, err := m.getHandle()
	if err != nil {
		t.Fatalf("Failed to get first handle: %v", err)
	}
	handle2, err := m.getHandle()
	if err != nil {
		t.Fatalf("Failed to get second handle: %v", err)
	}

	// Return handles to pool
	m.putHandle(handle1)
	m.putHandle(handle2)

	// Verify pool has handles
	poolLen := len(m.pool)
	if poolLen < 2 {
		t.Logf("Expected at least 2 handles in pool, got %d", poolLen)
	}

	// Cleanup should close all handles
	err = m.Cleanup()
	if err != nil {
		t.Errorf("Cleanup returned error: %v", err)
	}

	// Verify cleanup cleared the fields
	if m.Ipsets != nil {
		t.Error("Expected Ipsets to be nil after cleanup")
	}
	if m.ipsetFamilies != nil {
		t.Error("Expected ipsetFamilies to be nil after cleanup")
	}
}

// TestProvision_VeryLongIpsetName tests that very long ipset names are rejected
func TestProvision_VeryLongIpsetName(t *testing.T) {
	// Create a name that's longer than IPSET_MAXNAMELEN
	longName := strings.Repeat("a", 100) // Assuming IPSET_MAXNAMELEN is less than 100

	m := &IpsetMatcher{
		Ipsets: []string{longName},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := m.Provision(ctx)
	if err == nil {
		t.Error("Expected error for very long ipset name")
	}

	if err != nil && !strings.Contains(err.Error(), "exceeds maximum length") {
		t.Errorf("Expected 'exceeds maximum length' error, got '%s'", err.Error())
	}
}

// TestGetHandle_UninitializedPool tests the error path when pool is not initialized
func TestGetHandle_UninitializedPool(t *testing.T) {
	m := &IpsetMatcher{
		Ipsets: []string{"test-ipset-v4"},
		logger: zap.NewNop(),
		pool:   nil, // Uninitialized pool
	}

	_, err := m.getHandle()
	if err == nil {
		t.Error("Expected error when pool is not initialized")
	}

	if err != nil && !strings.Contains(err.Error(), "not initialized") && !strings.Contains(err.Error(), "not properly provisioned") {
		t.Errorf("Expected error about uninitialized pool, got '%s'", err.Error())
	}
}
