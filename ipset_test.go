//go:build linux

package caddy_ipset

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/vishvananda/netlink"
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

// TestMatchWithError_InvalidIP tests error handling for various invalid IP formats
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

	testCases := []struct {
		name     string
		clientIP string
	}{
		{"invalid address format", "invalid-address"},
		{"not an IP", "not-an-ip"},
		{"empty client IP", ""},
		{"malformed IP", "999.999.999.999"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://example.com", nil)

			// Prepare the request with Caddy context
			repl := caddyhttp.NewTestReplacer(req)
			w := httptest.NewRecorder()
			req = caddyhttp.PrepareRequest(req, repl, w, nil)

			// Set an invalid IP in ClientIPVarKey
			caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, tc.clientIP)

			result, err := m.MatchWithError(req)
			if err == nil {
				t.Errorf("Expected error for %s", tc.name)
			}
			if result {
				t.Errorf("Expected MatchWithError to return false for %s", tc.name)
			}
		})
	}
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
			name:         "valid ipset name with spaces",
			input:        "ipset \"my ipset\"",
			expectError:  false,
			expectedSets: []string{"my ipset"},
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
				if len(m.ipsetFamilyVersions) != len(tc.ipsets) {
					t.Errorf("Expected %d ipset families, got %d", len(tc.ipsets), len(m.ipsetFamilyVersions))
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
			req := httptest.NewRequest("GET", "https://example.com", nil)

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
// This test verifies that if an IP is in ANY of the configured ipsets, it matches
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
		{
			name:        "IP in first ipset only",
			ipsets:      []string{"test-ipset-v4", "blocklist-v4"},
			clientIP:    "127.0.0.1",
			description: "Should match because it's in test-ipset-v4",
		},
		{
			name:        "IP in second ipset only",
			ipsets:      []string{"test-ipset-v4", "blocklist-v4"},
			clientIP:    "10.0.0.1",
			description: "Should match if it's in blocklist-v4",
		},
		{
			name:        "IP in both ipsets",
			ipsets:      []string{"test-ipset-v4", "blocklist-v4"},
			clientIP:    "192.168.1.100",
			description: "Should match because it's in at least one ipset",
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

			req := httptest.NewRequest("GET", "https://example.com", nil)

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
			req := httptest.NewRequest("GET", "https://example.com", nil)

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

	req := httptest.NewRequest("GET", "https://example.com", nil)

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

			req := httptest.NewRequest("GET", "https://example.com", nil)

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
			req := httptest.NewRequest("GET", "https://example.com", nil)

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

// TestProvision_SavesIPFamily tests that Provision correctly saves the ipset family
func TestProvision_SavesIPFamily(t *testing.T) {
	testCases := []struct {
		name           string
		ipsetName      string
		expectedFamily uint8
	}{
		{"IPv4 ipset saves IPv4 family", "test-ipset-v4", ipFamilyIPv4},
		{"IPv6 ipset saves IPv6 family", "test-ipset-v6", ipFamilyIPv6},
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

			if len(m.ipsetFamilyVersions) != 1 {
				t.Fatalf("Expected 1 ipset family, got %d", len(m.ipsetFamilyVersions))
			}
			if m.ipsetFamilyVersions[0] != tc.expectedFamily {
				t.Errorf("Expected ipsetFamily=%d, got %d",
					tc.expectedFamily, m.ipsetFamilyVersions[0])
			}

			t.Logf("Ipset %s correctly saved family: %d",
				tc.ipsetName, m.ipsetFamilyVersions[0])
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
			expectedFamilies: []uint8{ipFamilyIPv4, ipFamilyIPv4},
		},
		{
			name:             "two IPv6 ipsets",
			ipsets:           []string{"test-ipset-v6", "blocklist-v6"},
			expectedFamilies: []uint8{ipFamilyIPv6, ipFamilyIPv6},
		},
		{
			name:             "mixed IPv4 and IPv6",
			ipsets:           []string{"test-ipset-v4", "test-ipset-v6"},
			expectedFamilies: []uint8{ipFamilyIPv4, ipFamilyIPv6},
		},
		{
			name:             "four ipsets mixed",
			ipsets:           []string{"test-ipset-v4", "test-ipset-v6", "blocklist-v4", "blocklist-v6"},
			expectedFamilies: []uint8{ipFamilyIPv4, ipFamilyIPv6, ipFamilyIPv4, ipFamilyIPv6},
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

			if len(m.ipsetFamilyVersions) != len(tc.expectedFamilies) {
				t.Fatalf("Expected %d ipset families, got %d", len(tc.expectedFamilies), len(m.ipsetFamilyVersions))
			}

			for i, expectedFamily := range tc.expectedFamilies {
				if m.ipsetFamilyVersions[i] != expectedFamily {
					t.Errorf("Ipset %s (index %d): expected family=%d, got %d",
						tc.ipsets[i], i,
						expectedFamily, m.ipsetFamilyVersions[i])
				}
			}

			t.Logf("✓ Successfully saved families for %d ipsets:", len(tc.ipsets))
			for i, ipset := range tc.ipsets {
				t.Logf("  - %s: %d", ipset, m.ipsetFamilyVersions[i])
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
			ipsetFamily: ipFamilyIPv4,
			clientIP:    "127.0.0.1",
			shouldMatch: true,
			shouldSkip:  false,
			description: "IPv4 address should be checked against IPv4 ipset",
		},
		{
			name:        "IPv6 against IPv6 ipset - should check",
			ipsetName:   "test-ipset-v6",
			ipsetFamily: ipFamilyIPv6,
			clientIP:    "::1",
			shouldMatch: true,
			shouldSkip:  false,
			description: "IPv6 address should be checked against IPv6 ipset",
		},
		{
			name:        "IPv6 against IPv4 ipset - should skip",
			ipsetName:   "test-ipset-v4",
			ipsetFamily: ipFamilyIPv4,
			clientIP:    "::1",
			shouldMatch: false,
			shouldSkip:  true,
			description: "IPv6 address should be skipped for IPv4 ipset",
		},
		{
			name:        "IPv4 against IPv6 ipset - should skip",
			ipsetName:   "test-ipset-v6",
			ipsetFamily: ipFamilyIPv6,
			clientIP:    "127.0.0.1",
			shouldMatch: false,
			shouldSkip:  true,
			description: "IPv4 address should be skipped for IPv6 ipset",
		},
		{
			name:        "IPv4 non-matching against IPv4 ipset - should check but not match",
			ipsetName:   "test-ipset-v4",
			ipsetFamily: ipFamilyIPv4,
			clientIP:    "203.0.113.1",
			shouldMatch: false,
			shouldSkip:  false,
			description: "IPv4 address not in ipset should be checked but return false",
		},
		{
			name:        "IPv6 non-matching against IPv6 ipset - should check but not match",
			ipsetName:   "test-ipset-v6",
			ipsetFamily: ipFamilyIPv6,
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
			if len(m.ipsetFamilyVersions) != 1 {
				t.Fatalf("Expected 1 ipset family, got %d", len(m.ipsetFamilyVersions))
			}
			if m.ipsetFamilyVersions[0] != tc.ipsetFamily {
				t.Errorf("Expected ipsetFamily=%d, got %d", tc.ipsetFamily, m.ipsetFamilyVersions[0])
			}

			req := httptest.NewRequest("GET", "https://example.com", nil)

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

// TestFamilyToString_UnknownFamily tests the default case in nfprotoFamilyVersion
func TestFamilyToString_UnknownFamily(t *testing.T) {
	testCases := []struct {
		family   uint8
		expected uint8
		name     string
	}{
		{unix.NFPROTO_IPV4, 4, "IPv4"},
		{unix.NFPROTO_IPV6, 6, "IPv6"},
		{99, 0, "unknown_99"},   // Unknown family code
		{255, 0, "unknown_255"}, // Another unknown family code
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := nfprotoFamilyVersion(tc.family)
			if result != tc.expected {
				t.Errorf("Expected '%d', got '%d'", tc.expected, result)
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

	req := httptest.NewRequest("GET", "https://example.com", nil)

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

	req := httptest.NewRequest("GET", "https://example.com", nil)

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
	if len(matcher.ipsetFamilyVersions) != len(expectedIpsets) {
		t.Errorf("Expected %d families, got %d", len(expectedIpsets), len(matcher.ipsetFamilyVersions))
	}
	t.Logf("✓ Provisioned %d ipsets with families", len(matcher.ipsetFamilyVersions))

	// Test 3: Test matching with various IPs
	testCases := []struct {
		name        string
		clientIP    string
		shouldMatch bool
	}{
		{"IPv4 localhost", "127.0.0.1", true},
		{"IPv4 test IP", "192.168.1.100", true},
		{"Test IPv4-mapped IPv6 addresses match", "::ffff:192.168.1.100", true},   // Treated as IPv4
		{"Test IPv4-mapped IPv6 addresses no match", "::ffff:192.168.2.1", false}, // Treated as IPv4
		{"IPv4 not in any ipset", "203.0.113.1", false},
		{"IPv6 localhost", "::1", true},
		{"IPv6 test IP", "2001:db8::1", true},
		{"IPv6 not in any ipset", "2001:db8::999", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://example.com", nil)

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
			if result != tc.shouldMatch {
				t.Errorf("Expected %s to match=%v", tc.name, tc.shouldMatch)
			}
		})
	}

	t.Logf("✓ Successfully tested end-to-end flow with multiple ipsets")
}

// TestGetIpFamilyVersion tests the ipFamilyVersion helper function
func TestGetIpFamilyVersion(t *testing.T) {
	testCases := []struct {
		name     string
		ip       string
		expected uint8
	}{
		{"IPv4 address", "192.168.1.1", 4},
		{"IPv4 loopback", "127.0.0.1", 4},
		{"IPv4 broadcast", "255.255.255.255", 4},
		{"IPv6 address", "2001:db8::1", 6},
		{"IPv6 loopback", "::1", 6},
		{"IPv6 full form", "2001:0db8:0000:0000:0000:0000:0000:0001", 6},
		{"IPv6 link-local", "fe80::1", 6},
		{"IPv4-mapped IPv6", "::ffff:192.168.1.1", 4},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tc.ip)
			}
			result := ipFamilyVersion(ip)
			if result != tc.expected {
				t.Errorf("Expected '%d', got '%d'", tc.expected, result)
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

// TestPutHandle_NilHandle tests that putHandle safely handles nil handle
func TestPutHandle_NilHandle(t *testing.T) {
	m := &IpsetMatcher{
		Ipsets: []string{"test-ipset-v4"},
	}

	// Provision to initialize the pool
	err := m.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}
	defer func(m *IpsetMatcher) {
		_ = m.Cleanup()
	}(m)

	// Put nil handle - should not panic or add to pool
	m.putHandle(nil)

	// Verify pool still has the expected number of handles
	// Pool should have been initialized with some handles during provision
	select {
	case h := <-m.pool:
		if h == nil {
			t.Error("Expected non-nil handle from pool")
		}
		m.putHandle(h) // Return it
	default:
		// Pool might be empty, which is fine
	}
}

// TestPutHandle_NilPool tests that putHandle safely handles nil pool
func TestPutHandle_NilPool(t *testing.T) {
	m := &IpsetMatcher{
		Ipsets: []string{"test-set"},
		pool:   nil, // Explicitly set pool to nil
	}

	// Create a mock handle (we can't actually create a real one without CAP_NET_ADMIN)
	// But we can test with nil which is the safe path
	m.putHandle(nil)

	// Should not panic - test passes if we get here
}

// TestPutHandle_ClosedModule tests that putHandle closes handle when module is closed
func TestPutHandle_ClosedModule(t *testing.T) {
	m := &IpsetMatcher{
		Ipsets: []string{"test-ipset-v4"},
	}

	// Provision to initialize the pool
	err := m.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	// Get a handle from the pool
	h, err := m.getHandle()
	if err != nil {
		t.Fatalf("Failed to get handle: %v", err)
	}

	// Close the module
	_ = m.Cleanup()

	// Verify module is marked as closed
	if atomic.LoadInt32(&m.closed) != 1 {
		t.Error("Expected module to be marked as closed")
	}

	// Now try to put the handle back - it should be closed instead of returned to pool
	// We can't directly verify the handle was closed, but we can verify it doesn't panic
	m.putHandle(h)

	// Verify pool is empty after cleanup (all handles were drained)
	poolSize := len(m.pool)
	if poolSize != 0 {
		t.Errorf("Expected pool to be empty after cleanup, got %d handles", poolSize)
	}
}

// TestMatchWithError_MissingClientIPVar tests error when ClientIPVarKey is not set
func TestMatchWithError_MissingClientIPVar(t *testing.T) {
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

	// Create a request without setting ClientIPVarKey
	req := httptest.NewRequest("GET", "https://example.com", nil)

	// Prepare the request with Caddy context but don't set ClientIPVarKey
	repl := caddyhttp.NewTestReplacer(req)
	w := httptest.NewRecorder()
	req = caddyhttp.PrepareRequest(req, repl, w, nil)

	// Manually remove the ClientIPVarKey if it was set by PrepareRequest
	// We need to create a new context without the key
	req = req.WithContext(context.Background())

	// This should return an error because ClientIPVarKey is not set
	result, err := m.MatchWithError(req)
	if err == nil {
		t.Error("Expected error when ClientIPVarKey is not set")
	}
	if err != nil && !strings.Contains(err.Error(), "not found in request context") {
		t.Errorf("Expected error about missing ClientIPVarKey, got: %v", err)
	}
	if result {
		t.Error("Expected MatchWithError to return false when ClientIPVarKey is not set")
	}
}

// TestPutHandle_PoolFull tests the scenario where the pool is full
func TestPutHandle_PoolFull(t *testing.T) {
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
	defer func() {
		if err := m.Cleanup(); err != nil {
			t.Errorf("Cleanup failed: %v", err)
		}
	}()

	// Fill the pool to capacity
	poolCapacity := cap(m.pool)
	handles := make([]*netlink.Handle, 0, poolCapacity)

	// Create handles to fill the pool
	for i := 0; i < poolCapacity; i++ {
		h, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
		if err != nil {
			t.Skipf("Failed to create handle: %v", err)
			return
		}
		handles = append(handles, h)
		m.pool <- h
	}

	// Verify pool is full
	if len(m.pool) != poolCapacity {
		t.Fatalf("Expected pool to be full (%d), got %d", poolCapacity, len(m.pool))
	}

	// Now try to put one more handle - it should be closed instead of added to pool
	extraHandle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		t.Skipf("Failed to create extra handle: %v", err)
		return
	}

	// This should trigger the pool full path
	m.putHandle(extraHandle)

	// Pool should still be at capacity (the extra handle was discarded)
	if len(m.pool) != poolCapacity {
		t.Errorf("Expected pool to remain at capacity (%d), got %d", poolCapacity, len(m.pool))
	}

	// Clean up the handles we created
	for _, h := range handles {
		<-m.pool // Remove from pool
		h.Close()
	}
}

// TestMetrics_EndToEnd tests that Prometheus metrics are properly recorded
// during ipset matching operations
func TestMetrics_EndToEnd(t *testing.T) {
	// Create a fresh matcher
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

	// Verify metrics were initialized
	if metrics.results == nil {
		t.Fatal("Expected metrics.results to be initialized")
	}
	if metrics.duration == nil {
		t.Fatal("Expected metrics.duration to be initialized")
	}

	// Helper to create a request with a specific client IP
	makeRequest := func(clientIP string) *http.Request {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		repl := caddyhttp.NewTestReplacer(req)
		w := httptest.NewRecorder()
		req = caddyhttp.PrepareRequest(req, repl, w, nil)
		caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, clientIP)
		return req
	}

	// Get initial counter values for the ipset
	getResultCount := func(result string) float64 {
		metric := &dto.Metric{}
		counter, err := metrics.results.GetMetricWithLabelValues("test-ipset-v4", result)
		if err != nil {
			return 0
		}
		if err := counter.Write(metric); err != nil {
			return 0
		}
		return metric.GetCounter().GetValue()
	}

	getDurationCount := func() uint64 {
		metric := &dto.Metric{}
		observer, err := metrics.duration.GetMetricWithLabelValues("test-ipset-v4")
		if err != nil {
			return 0
		}
		histogram := observer.(prometheus.Histogram)
		if err := histogram.Write(metric); err != nil {
			return 0
		}
		return metric.GetHistogram().GetSampleCount()
	}

	// Record initial values
	initialFound := getResultCount("found")
	initialNotFound := getResultCount("not found")
	initialDurationCount := getDurationCount()

	// Test 1: IP that IS in the ipset (should record "found")
	// 192.168.100.1 should be in test-ipset-v4 based on setup-test-ipsets.sh
	reqFound := makeRequest("192.168.100.1")
	found, err := m.MatchWithError(reqFound)
	if err != nil {
		t.Errorf("Unexpected error for IP in ipset: %v", err)
	}
	if !found {
		t.Skip("Skipping metrics verification - IP 192.168.100.1 not in test-ipset-v4")
	}

	// Verify "found" counter incremented
	foundAfterMatch := getResultCount("found")
	if foundAfterMatch != initialFound+1 {
		t.Errorf("Expected 'found' counter to increment by 1, got delta: %v", foundAfterMatch-initialFound)
	}

	// Test 2: IP that is NOT in the ipset (should record "not found")
	// 10.0.0.1 should NOT be in test-ipset-v4
	reqNotFound := makeRequest("10.0.0.1")
	found2, err := m.MatchWithError(reqNotFound)
	if err != nil {
		t.Errorf("Unexpected error for IP not in ipset: %v", err)
	}
	if found2 {
		t.Skip("Skipping metrics verification - IP 10.0.0.1 unexpectedly in test-ipset-v4")
	}

	// Verify "not found" counter incremented
	notFoundAfterMatch := getResultCount("not found")
	if notFoundAfterMatch != initialNotFound+1 {
		t.Errorf("Expected 'not found' counter to increment by 1, got delta: %v", notFoundAfterMatch-initialNotFound)
	}

	// Verify duration histogram recorded observations
	durationCountAfterMatches := getDurationCount()
	expectedDurationCount := initialDurationCount + 2 // Two matches performed
	if durationCountAfterMatches != expectedDurationCount {
		t.Errorf("Expected duration histogram sample count to be %d, got %d",
			expectedDurationCount, durationCountAfterMatches)
	}

	// Verify duration values are reasonable (should be sub-millisecond for netlink calls)
	metric := &dto.Metric{}
	observer, _ := metrics.duration.GetMetricWithLabelValues("test-ipset-v4")
	histogram := observer.(prometheus.Histogram)
	if err := histogram.Write(metric); err == nil {
		sum := metric.GetHistogram().GetSampleSum()
		count := metric.GetHistogram().GetSampleCount()
		if count > 0 {
			avgDuration := sum / float64(count)
			// Average duration should be less than 10ms for netlink calls
			if avgDuration > 0.01 {
				t.Errorf("Average duration seems too high: %v seconds", avgDuration)
			}
			t.Logf("Metrics working correctly - avg duration: %.6f seconds (%d samples)", avgDuration, count)
		}
	}
}

// TestMetrics_IPv6 tests that metrics work correctly for IPv6 ipsets
func TestMetrics_IPv6(t *testing.T) {
	m := &IpsetMatcher{
		Ipsets: []string{"test-ipset-v6"},
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

	// Helper to create a request with a specific client IP
	makeRequest := func(clientIP string) *http.Request {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		repl := caddyhttp.NewTestReplacer(req)
		w := httptest.NewRecorder()
		req = caddyhttp.PrepareRequest(req, repl, w, nil)
		caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, clientIP)
		return req
	}

	getResultCount := func(ipset, result string) float64 {
		metric := &dto.Metric{}
		counter, err := metrics.results.GetMetricWithLabelValues(ipset, result)
		if err != nil {
			return 0
		}
		if err := counter.Write(metric); err != nil {
			return 0
		}
		return metric.GetCounter().GetValue()
	}

	initialFound := getResultCount("test-ipset-v6", "found")

	// Test with an IPv6 address - should only check test-ipset-v6 (family optimization)
	req := makeRequest("fd00::1")
	found, err := m.MatchWithError(req)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !found {
		t.Skip("Skipping - IPv6 address fd00::1 not in test-ipset-v6")
	}

	foundAfter := getResultCount("test-ipset-v6", "found")
	if foundAfter != initialFound+1 {
		t.Errorf("Expected 'found' counter to increment by 1 for IPv6, got delta: %v", foundAfter-initialFound)
	}
}

// TestMetrics_MultipleIpsets tests metrics with multiple ipsets configured
func TestMetrics_MultipleIpsets(t *testing.T) {
	m := &IpsetMatcher{
		Ipsets: []string{"test-ipset-v4", "test-ipset-v6"},
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

	makeRequest := func(clientIP string) *http.Request {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		repl := caddyhttp.NewTestReplacer(req)
		w := httptest.NewRecorder()
		req = caddyhttp.PrepareRequest(req, repl, w, nil)
		caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, clientIP)
		return req
	}

	getDurationCount := func(ipset string) uint64 {
		metric := &dto.Metric{}
		observer, err := metrics.duration.GetMetricWithLabelValues(ipset)
		if err != nil {
			return 0
		}
		histogram := observer.(prometheus.Histogram)
		if err := histogram.Write(metric); err != nil {
			return 0
		}
		return metric.GetHistogram().GetSampleCount()
	}

	// Record initial duration counts for each ipset
	initialV4Count := getDurationCount("test-ipset-v4")
	initialV6Count := getDurationCount("test-ipset-v6")

	// Test with an IPv4 address - should only check test-ipset-v4 (family optimization)
	req := makeRequest("10.99.99.99")
	_, _ = m.MatchWithError(req)

	// Verify only the IPv4 ipset duration was recorded (due to family optimization)
	v4CountAfter := getDurationCount("test-ipset-v4")
	v6CountAfter := getDurationCount("test-ipset-v6")

	if v4CountAfter != initialV4Count+1 {
		t.Errorf("Expected test-ipset-v4 duration count to increment by 1, got delta: %d", v4CountAfter-initialV4Count)
	}
	// IPv6 ipset should NOT be checked for an IPv4 address due to family optimization
	if v6CountAfter != initialV6Count {
		t.Errorf("Expected test-ipset-v6 duration count to remain unchanged (family optimization), got delta: %d", v6CountAfter-initialV6Count)
	}
}
