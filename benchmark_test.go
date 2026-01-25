//go:build linux
// +build linux

package caddy_ipset

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	benchSetV4 = "caddy-bench-v4"
	benchSetV6 = "caddy-bench-v6"
	benchIP    = "192.168.1.50"
)

func setupBenchmarks(t testing.TB) {
	// 1. OS Check
	if runtime.GOOS != "linux" {
		t.Skip("Skipping benchmark: OS is not Linux")
	}

	// 2. Root/Cap Check
	if os.Geteuid() != 0 {
		t.Skip("Skipping benchmark: must be run as root/sudo for netlink access")
	}

	// 3. Clean up any previous runs
	_ = exec.Command("ipset", "destroy", benchSetV4).Run()
	_ = exec.Command("ipset", "destroy", benchSetV6).Run()

	// 4. Create Sets
	// Create IPv4 set
	if err := exec.Command("ipset", "create", benchSetV4, "hash:ip", "family", "inet").Run(); err != nil {
		t.Fatalf("failed to create ipset %s: %v", benchSetV4, err)
	}
	// Add test IP
	if err := exec.Command("ipset", "add", benchSetV4, benchIP).Run(); err != nil {
		t.Fatalf("failed to add ip to %s: %v", benchSetV4, err)
	}

	// Create IPv6 set (empty for now, used to test multiple set logic)
	if err := exec.Command("ipset", "create", benchSetV6, "hash:ip", "family", "inet6").Run(); err != nil {
		t.Fatalf("failed to create ipset %s: %v", benchSetV6, err)
	}

	// 5. Register Cleanup
	t.Cleanup(func() {
		_ = exec.Command("ipset", "destroy", benchSetV4).Run()
		_ = exec.Command("ipset", "destroy", benchSetV6).Run()
	})
}

func getMatcher(t testing.TB) *IpsetMatcher {
	m := &IpsetMatcher{
		Ipsets: []string{benchSetV4, benchSetV6},
	}

	// Create a minimal Caddy context
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(func() { cancel() })

	// Provision the matcher (opens initial handles)
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Replace logger with a no-op logger to suppress output during benchmarks
	// (must be done AFTER Provision since Provision sets the logger)
	m.logger = zap.NewNop()

	t.Cleanup(func() { _ = m.Cleanup() })
	return m
}

func createRequest(ip string) *http.Request {
	req := httptest.NewRequest("GET", "/", nil)
	// Prepare the request with Caddy context (required for SetVar to work)
	repl := caddyhttp.NewTestReplacer(req)
	w := httptest.NewRecorder()
	req = caddyhttp.PrepareRequest(req, repl, w, nil)
	// Set the client IP using Caddy's SetVar (proper way to set ClientIPVarKey)
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, ip)
	return req
}

// BenchmarkMatchHit measures performance when the IP exists in the set.
// This tests the happy path and netlink query speed.
func BenchmarkMatchHit(b *testing.B) {
	setupBenchmarks(b)
	m := getMatcher(b)
	req := createRequest(benchIP)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		match, err := m.MatchWithError(req)
		if err != nil {
			b.Fatalf("MatchWithError failed: %v", err)
		}
		if !match {
			b.Fatal("Expected match, got false")
		}
	}
}

// BenchmarkMatchMiss measures performance when the IP is NOT in the set.
// This is often slower as it may check all configured sets before returning.
func BenchmarkMatchMiss(b *testing.B) {
	setupBenchmarks(b)
	m := getMatcher(b)
	// IP that is not in the set
	req := createRequest("10.0.0.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		match, err := m.MatchWithError(req)
		if err != nil {
			b.Fatalf("MatchWithError failed: %v", err)
		}
		if match {
			b.Fatal("Expected no match, got true")
		}
	}
}

// BenchmarkMatchParallel stresses the connection pool (leaky bucket).
// It runs concurrent goroutines to ensure the channel pool works efficiently
// and we don't leak socket handles.
func BenchmarkMatchParallel(b *testing.B) {
	setupBenchmarks(b)
	m := getMatcher(b)
	// Use the Hit IP
	reqTemplate := createRequest(benchIP)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Create a shallow copy of the request for this goroutine
		// (though context is thread safe, it's good practice)
		localReq := reqTemplate.Clone(reqTemplate.Context())

		for pb.Next() {
			_, err := m.MatchWithError(localReq)
			if err != nil {
				b.Errorf("MatchWithError failed: %v", err)
			}
		}
	})
}

// BenchmarkFamilySkip optimizes checking.
// This benchmarks checking an IPv6 address against an IPv4 set.
// Your code should skip the netlink call entirely based on family detection.
func BenchmarkFamilySkip(b *testing.B) {
	setupBenchmarks(b)
	// Configure matcher with ONLY v4 sets
	m := &IpsetMatcher{
		Ipsets: []string{benchSetV4},
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	b.Cleanup(func() { cancel() })

	// Provision the matcher (opens initial handles)
	if err := m.Provision(ctx); err != nil {
		b.Fatalf("Provision failed: %v", err)
	}

	// Replace logger with a no-op logger to suppress output during benchmarks
	// (must be done AFTER Provision since Provision sets the logger)
	m.logger = zap.NewNop()

	b.Cleanup(func() { _ = m.Cleanup() })

	// Request with IPv6 address
	req := createRequest("2001:db8::9999")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		match, err := m.MatchWithError(req)
		if err != nil {
			b.Fatalf("MatchWithError failed: %v", err)
		}
		if match {
			b.Fatal("Expected no match")
		}
	}
}
