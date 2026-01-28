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

// --- Test Helpers ---

// provisionMatcher creates and provisions an IpsetMatcher with the given ipsets.
// Returns the matcher or nil if provisioning fails (test is skipped).
func provisionMatcher(t *testing.T, ipsets ...string) *IpsetMatcher {
	t.Helper()
	m := &IpsetMatcher{Ipsets: ipsets}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	if err := m.Provision(ctx); err != nil {
		t.Skipf("Skipping test - provisioning failed: %v", err)
		return nil
	}
	t.Cleanup(func() { _ = m.Cleanup() })
	return m
}

// makeRequest creates a test HTTP request with the given client IP.
func makeRequest(t *testing.T, clientIP string) *http.Request {
	t.Helper()
	req := httptest.NewRequest("GET", "https://example.com", nil)
	repl := caddyhttp.NewTestReplacer(req)
	w := httptest.NewRecorder()
	req = caddyhttp.PrepareRequest(req, repl, w, nil)
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, clientIP)
	return req
}

// --- Unit Tests ---

func TestCaddyModule(t *testing.T) {
	m := IpsetMatcher{}
	info := m.CaddyModule()

	if info.ID != "http.matchers.ipset" {
		t.Errorf("Expected module ID 'http.matchers.ipset', got '%s'", info.ID)
	}
	if info.New == nil {
		t.Error("Expected New function to be set")
	}
	if _, ok := info.New().(*IpsetMatcher); !ok {
		t.Error("Expected New to return *IpsetMatcher")
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantError    bool
		expectedSets []string
	}{
		{"single ipset", "ipset test-ipset-v4", false, []string{"test-ipset-v4"}},
		{"with underscores", "ipset my_ipset_123", false, []string{"my_ipset_123"}},
		{"quoted with spaces", `ipset "my ipset"`, false, []string{"my ipset"}},
		{"multiple in one directive", "ipset test-ipset-v4 test-ipset-v6", false, []string{"test-ipset-v4", "test-ipset-v6"}},
		{"three ipsets", "ipset blocklist-v4 blocklist-v6 test-ipset-v4", false, []string{"blocklist-v4", "blocklist-v6", "test-ipset-v4"}},
		{"missing argument", "ipset", true, nil},
		{"multiple directives", "ipset test-ipset-v4\nipset test-ipset-v6", false, []string{"test-ipset-v4", "test-ipset-v6"}},
		{"mixed directives and args", "ipset test-ipset-v4 test-ipset-v6\nipset blocklist-v4", false, []string{"test-ipset-v4", "test-ipset-v6", "blocklist-v4"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &IpsetMatcher{}
			d := caddyfile.NewTestDispenser(tc.input)
			err := m.UnmarshalCaddyfile(d)

			if tc.wantError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if len(m.Ipsets) != len(tc.expectedSets) {
				t.Fatalf("Expected %d ipsets, got %d", len(tc.expectedSets), len(m.Ipsets))
			}
			for i, expected := range tc.expectedSets {
				if m.Ipsets[i] != expected {
					t.Errorf("Ipset[%d]: expected '%s', got '%s'", i, expected, m.Ipsets[i])
				}
			}
		})
	}
}

func TestNfprotoFamilyVersion(t *testing.T) {
	tests := []struct {
		family   uint8
		expected uint8
	}{
		{unix.NFPROTO_IPV4, 4},
		{unix.NFPROTO_IPV6, 6},
		{99, 0},
		{255, 0},
	}

	for _, tc := range tests {
		result := nfprotoFamilyVersion(tc.family)
		if result != tc.expected {
			t.Errorf("nfprotoFamilyVersion(%d): expected %d, got %d", tc.family, tc.expected, result)
		}
	}
}

func TestIpFamilyVersion(t *testing.T) {
	tests := []struct {
		ip       string
		expected uint8
	}{
		{"192.168.1.1", 4},
		{"127.0.0.1", 4},
		{"255.255.255.255", 4},
		{"2001:db8::1", 6},
		{"::1", 6},
		{"fe80::1", 6},
		{"::ffff:192.168.1.1", 4}, // IPv4-mapped IPv6 treated as IPv4
	}

	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tc.ip)
			}
			result := ipFamilyVersion(ip)
			if result != tc.expected {
				t.Errorf("Expected %d, got %d", tc.expected, result)
			}
		})
	}
}

// --- Provision Tests ---

func TestProvision_InvalidIpsetName(t *testing.T) {
	invalidNames := []struct {
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

	for _, tc := range invalidNames {
		t.Run(tc.name, func(t *testing.T) {
			m := &IpsetMatcher{Ipsets: []string{tc.ipsetName}}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			if err := m.Provision(ctx); err == nil {
				t.Errorf("Expected error for invalid ipset name '%s'", tc.ipsetName)
			}
		})
	}
}

func TestProvision_EdgeCases(t *testing.T) {
	t.Run("too long name", func(t *testing.T) {
		longName := "this_is_a_very_long_ipset_name_that_exceeds_the_maximum_allowed_length"
		m := &IpsetMatcher{Ipsets: []string{longName}}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		err := m.Provision(ctx)
		if err == nil || !strings.Contains(err.Error(), "exceeds maximum length") {
			t.Errorf("Expected error about exceeding maximum length, got: %v", err)
		}
	})

	t.Run("empty ipset in list", func(t *testing.T) {
		m := &IpsetMatcher{Ipsets: []string{"test-ipset-v4", ""}}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		err := m.Provision(ctx)
		if err == nil || !strings.Contains(err.Error(), "ipset name is required") {
			t.Errorf("Expected 'ipset name is required' error, got: %v", err)
		}
	})
}

func TestProvision_MultipleIpsets(t *testing.T) {
	tests := []struct {
		name      string
		ipsets    []string
		wantError bool
	}{
		{"two IPv4 ipsets", []string{"test-ipset-v4", "blocklist-v4"}, false},
		{"two IPv6 ipsets", []string{"test-ipset-v6", "blocklist-v6"}, false},
		{"mixed IPv4 and IPv6", []string{"test-ipset-v4", "test-ipset-v6"}, false},
		{"four ipsets", []string{"test-ipset-v4", "test-ipset-v6", "blocklist-v4", "blocklist-v6"}, false},
		{"one valid one invalid", []string{"test-ipset-v4", "does-not-exist-12345"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &IpsetMatcher{Ipsets: tc.ipsets}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			err := m.Provision(ctx)
			if tc.wantError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.wantError && err == nil {
				if m.logger == nil || m.pool == nil {
					t.Error("Expected logger and pool to be set")
				}
				if len(m.ipsetFamilyVersions) != len(tc.ipsets) {
					t.Errorf("Expected %d ipset families, got %d", len(tc.ipsets), len(m.ipsetFamilyVersions))
				}
				_ = m.Cleanup()
			}
		})
	}
}

func TestProvision_SavesIPFamily(t *testing.T) {
	tests := []struct {
		ipsets           []string
		expectedFamilies []uint8
	}{
		{[]string{"test-ipset-v4"}, []uint8{ipFamilyIPv4}},
		{[]string{"test-ipset-v6"}, []uint8{ipFamilyIPv6}},
		{[]string{"test-ipset-v4", "test-ipset-v6"}, []uint8{ipFamilyIPv4, ipFamilyIPv6}},
	}

	for _, tc := range tests {
		t.Run(strings.Join(tc.ipsets, ","), func(t *testing.T) {
			m := provisionMatcher(t, tc.ipsets...)
			if m == nil {
				return
			}
			for i, expected := range tc.expectedFamilies {
				if m.ipsetFamilyVersions[i] != expected {
					t.Errorf("Family[%d]: expected %d, got %d", i, expected, m.ipsetFamilyVersions[i])
				}
			}
		})
	}
}

func TestProvision_PermissionError(t *testing.T) {
	m := &IpsetMatcher{Ipsets: []string{"test-ipset-v4"}}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	// This test verifies that when there's a permission error, it mentions CAP_NET_ADMIN
	err := m.Provision(ctx)
	if err != nil && !strings.Contains(err.Error(), "CAP_NET_ADMIN") {
		t.Errorf("Expected error to contain 'CAP_NET_ADMIN', got: %v", err)
	}
}

// --- MatchWithError Tests ---

func TestMatchWithError_InvalidIP(t *testing.T) {
	m := provisionMatcher(t, "test-ipset-v4")
	if m == nil {
		return
	}

	invalidIPs := []string{"invalid-address", "not-an-ip", "", "999.999.999.999"}
	for _, ip := range invalidIPs {
		t.Run(ip, func(t *testing.T) {
			req := makeRequest(t, ip)
			result, err := m.MatchWithError(req)
			if err == nil {
				t.Error("Expected error for invalid IP")
			}
			if result {
				t.Error("Expected false for invalid IP")
			}
		})
	}
}

func TestMatchWithError_ClientIPVarKey(t *testing.T) {
	m := provisionMatcher(t, "test-ipset-v4")
	if m == nil {
		return
	}

	t.Run("missing", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		req = req.WithContext(context.Background())
		result, err := m.MatchWithError(req)
		if err == nil || result {
			t.Error("Expected error and false when ClientIPVarKey is missing")
		}
	})

	t.Run("non-string", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		repl := caddyhttp.NewTestReplacer(req)
		w := httptest.NewRecorder()
		req = caddyhttp.PrepareRequest(req, repl, w, nil)
		caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, 12345)
		result, err := m.MatchWithError(req)
		if err == nil || result {
			t.Error("Expected error and false when ClientIPVarKey is not a string")
		}
	})
}

func TestMatchWithError_UninitializedPool(t *testing.T) {
	m := &IpsetMatcher{
		Ipsets: []string{"test-ipset-v4"},
		logger: zap.NewNop(),
		pool:   nil,
	}
	req := makeRequest(t, "127.0.0.1")
	result, err := m.MatchWithError(req)
	if err == nil || result {
		t.Error("Expected error and false when pool is not initialized")
	}
}

func TestMatchWithError_IPFamilyMatching(t *testing.T) {
	tests := []struct {
		name        string
		ipset       string
		clientIP    string
		shouldMatch bool
	}{
		{"IPv4 against IPv4", "test-ipset-v4", "127.0.0.1", true},
		{"IPv6 against IPv6", "test-ipset-v6", "::1", true},
		{"IPv4 against IPv6 ipset", "test-ipset-v6", "127.0.0.1", false},
		{"IPv6 against IPv4 ipset", "test-ipset-v4", "::1", false},
		{"IPv4 not in ipset", "test-ipset-v4", "203.0.113.1", false},
		{"IPv6 not in ipset", "test-ipset-v6", "2001:db8::999", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := provisionMatcher(t, tc.ipset)
			if m == nil {
				return
			}
			req := makeRequest(t, tc.clientIP)
			result, err := m.MatchWithError(req)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tc.shouldMatch {
				t.Errorf("Expected %v, got %v", tc.shouldMatch, result)
			}
		})
	}
}

func TestMatchWithError_MultipleIpsets(t *testing.T) {
	tests := []struct {
		name     string
		ipsets   []string
		clientIP string
	}{
		{"IPv4 against two IPv4", []string{"test-ipset-v4", "blocklist-v4"}, "127.0.0.1"},
		{"IPv6 against two IPv6", []string{"test-ipset-v6", "blocklist-v6"}, "::1"},
		{"IPv4 against mixed", []string{"test-ipset-v4", "test-ipset-v6"}, "127.0.0.1"},
		{"IPv6 against mixed", []string{"test-ipset-v4", "test-ipset-v6"}, "::1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := provisionMatcher(t, tc.ipsets...)
			if m == nil {
				return
			}
			req := makeRequest(t, tc.clientIP)
			if _, err := m.MatchWithError(req); err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestMatchWithError_IPv6EdgeCases(t *testing.T) {
	m := provisionMatcher(t, "test-ipset-v6")
	if m == nil {
		return
	}

	tests := []struct {
		name        string
		clientIP    string
		shouldMatch bool
		shouldError bool
	}{
		{"zone ID", "fe80::1%eth0", false, true},
		{"compressed", "::1", true, false},
		{"full form", "0000:0000:0000:0000:0000:0000:0000:0001", true, false},
		{"IPv4-mapped", "::ffff:127.0.0.1", false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := makeRequest(t, tc.clientIP)
			result, err := m.MatchWithError(req)
			if tc.shouldError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.shouldError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tc.shouldError && result != tc.shouldMatch {
				t.Errorf("Expected %v, got %v", tc.shouldMatch, result)
			}
		})
	}
}

func TestMatchWithError_IPv4MappedIPv6(t *testing.T) {
	m := provisionMatcher(t, "test-ipset-v4", "test-ipset-v6")
	if m == nil {
		return
	}

	tests := []struct {
		clientIP    string
		shouldMatch bool
	}{
		{"::ffff:192.168.1.100", true}, // In test-ipset-v4
		{"::ffff:192.168.2.1", false},  // Not in any ipset
	}

	for _, tc := range tests {
		t.Run(tc.clientIP, func(t *testing.T) {
			req := makeRequest(t, tc.clientIP)
			result, err := m.MatchWithError(req)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tc.shouldMatch {
				t.Errorf("Expected %v, got %v", tc.shouldMatch, result)
			}
		})
	}
}

// --- Handle Pool Tests ---

func TestPutHandle(t *testing.T) {
	t.Run("nil handle", func(t *testing.T) {
		m := provisionMatcher(t, "test-ipset-v4")
		if m == nil {
			return
		}
		m.putHandle(nil) // Should not panic
	})

	t.Run("nil pool", func(t *testing.T) {
		m := &IpsetMatcher{Ipsets: []string{"test-set"}, pool: nil}
		m.putHandle(nil) // Should not panic
	})

	t.Run("closed module", func(t *testing.T) {
		m := &IpsetMatcher{Ipsets: []string{"test-ipset-v4"}}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		if err := m.Provision(ctx); err != nil {
			t.Skipf("Skipping - provisioning failed: %v", err)
			return
		}

		h, err := m.getHandle()
		if err != nil {
			t.Fatalf("Failed to get handle: %v", err)
		}

		_ = m.Cleanup()
		if atomic.LoadInt32(&m.closed) != 1 {
			t.Error("Expected module to be marked as closed")
		}

		m.putHandle(h)
		if len(m.pool) != 0 {
			t.Errorf("Expected pool to be empty after cleanup")
		}
	})

	t.Run("pool full", func(t *testing.T) {
		m := provisionMatcher(t, "test-ipset-v4")
		if m == nil {
			return
		}

		poolCapacity := cap(m.pool)
		handles := make([]*netlink.Handle, 0, poolCapacity)

		for i := 0; i < poolCapacity; i++ {
			h, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
			if err != nil {
				t.Skipf("Failed to create handle: %v", err)
				return
			}
			handles = append(handles, h)
			m.pool <- h
		}

		extraHandle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
		if err != nil {
			t.Skipf("Failed to create extra handle: %v", err)
			return
		}

		m.putHandle(extraHandle)
		if len(m.pool) != poolCapacity {
			t.Errorf("Expected pool to remain at capacity")
		}

		for _, h := range handles {
			<-m.pool
			h.Close()
		}
	})
}

// --- End-to-End Tests ---

func TestEndToEnd_ParseProvisionMatch(t *testing.T) {
	// Parse
	input := "ipset test-ipset-v4 blocklist-v4\nipset test-ipset-v6"
	d := caddyfile.NewTestDispenser(input)
	matcher := &IpsetMatcher{}
	if err := matcher.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	expectedIpsets := []string{"test-ipset-v4", "blocklist-v4", "test-ipset-v6"}
	if len(matcher.Ipsets) != len(expectedIpsets) {
		t.Fatalf("Expected %d ipsets, got %d", len(expectedIpsets), len(matcher.Ipsets))
	}

	// Provision
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := matcher.Provision(ctx); err != nil {
		t.Skipf("Skipping - provisioning failed: %v", err)
		return
	}
	defer func() { _ = matcher.Cleanup() }()

	// Match
	testCases := []struct {
		clientIP    string
		shouldMatch bool
	}{
		{"127.0.0.1", true},
		{"192.168.1.100", true},
		{"::ffff:192.168.1.100", true},
		{"::ffff:192.168.2.1", false},
		{"203.0.113.1", false},
		{"::1", true},
		{"2001:db8::1", true},
		{"2001:db8::999", false},
	}

	for _, tc := range testCases {
		t.Run(tc.clientIP, func(t *testing.T) {
			req := makeRequest(t, tc.clientIP)
			result, err := matcher.MatchWithError(req)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tc.shouldMatch {
				t.Errorf("Expected %v, got %v", tc.shouldMatch, result)
			}
		})
	}
}

// --- Metrics Tests ---

func TestMetrics(t *testing.T) {
	m := provisionMatcher(t, "test-ipset-v4", "test-ipset-v6")
	if m == nil {
		return
	}

	// Verify all metrics are initialized
	if metrics.requestsTotal == nil {
		t.Fatal("Expected metrics.requestsTotal to be initialized")
	}
	if metrics.resultsTotal == nil {
		t.Fatal("Expected metrics.resultsTotal to be initialized")
	}
	if metrics.duration == nil {
		t.Fatal("Expected metrics.duration to be initialized")
	}
	if metrics.handles == nil {
		t.Fatal("Expected metrics.handles to be initialized")
	}
	if metrics.errors == nil {
		t.Fatal("Expected metrics.errors to be initialized")
	}

	// Helper functions to read metric values
	getRequestsTotal := func() float64 {
		metric := &dto.Metric{}
		if err := metrics.requestsTotal.Write(metric); err != nil {
			return 0
		}
		return metric.GetCounter().GetValue()
	}

	getResultsTotal := func(ipset, result string) float64 {
		counter, err := metrics.resultsTotal.GetMetricWithLabelValues(ipset, result)
		if err != nil {
			return 0
		}
		metric := &dto.Metric{}
		if err := counter.Write(metric); err != nil {
			return 0
		}
		return metric.GetCounter().GetValue()
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

	// Record initial values
	initialRequests := getRequestsTotal()
	initialV4NotFound := getResultsTotal("test-ipset-v4", "not_found")
	initialV4DurationCount := getDurationCount("test-ipset-v4")
	initialV6DurationCount := getDurationCount("test-ipset-v6")

	// Test with IPv4 - should only check v4 ipset due to family optimization
	req := makeRequest(t, "10.99.99.99")
	_, _ = m.MatchWithError(req)

	// Verify requestsTotal incremented
	if delta := getRequestsTotal() - initialRequests; delta != 1 {
		t.Errorf("Expected requestsTotal to increment by 1, got delta: %v", delta)
	}

	// Verify resultsTotal incremented for v4 ipset
	if delta := getResultsTotal("test-ipset-v4", "not_found") - initialV4NotFound; delta != 1 {
		t.Errorf("Expected resultsTotal[test-ipset-v4, not_found] to increment by 1, got delta: %v", delta)
	}

	// Verify duration histogram recorded for v4 ipset
	if delta := getDurationCount("test-ipset-v4") - initialV4DurationCount; delta != 1 {
		t.Errorf("Expected v4 duration count to increment by 1, got delta: %d", delta)
	}

	// Verify v6 duration unchanged due to family optimization
	if delta := getDurationCount("test-ipset-v6") - initialV6DurationCount; delta != 0 {
		t.Errorf("Expected v6 duration count to remain unchanged (family optimization), got delta: %d", delta)
	}
}
