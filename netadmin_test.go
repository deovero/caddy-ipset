//go:build linux

package caddy_ipset

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/deovero/vishvananda-netlink"
	"golang.org/x/sys/unix"
)

// expectedCapModeEnv can be set to "effective" (binary granted with =+ep) or
// "raise" (binary granted with =+p). When set, the capability tests fail
// instead of skipping, so a broken capability setup can't hide behind the
// skips in the other tests.
const expectedCapModeEnv = "CADDY_IPSET_EXPECT_CAP_MODE"

// requireRaiseMode skips the test unless CAP_NET_ADMIN is permitted but not effective.
func requireRaiseMode(t *testing.T) {
	t.Helper()
	effective, permitted, err := netAdminState()
	if err != nil {
		t.Fatalf("netAdminState: %v", err)
	}
	if effective || !permitted {
		t.Skipf("requires CAP_NET_ADMIN permitted but not effective (setcap cap_net_admin=+p), effective=%v permitted=%v",
			effective, permitted)
	}
}

// threadsWithNetAdmin returns the IDs of all threads of this process that have
// CAP_NET_ADMIN in their effective set.
func threadsWithNetAdmin(t *testing.T) []string {
	t.Helper()
	statusFiles, err := filepath.Glob("/proc/self/task/*/status")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var found []string
	for _, f := range statusFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			continue // thread exited in the meantime
		}
		for _, line := range strings.Split(string(data), "\n") {
			hex, ok := strings.CutPrefix(line, "CapEff:")
			if !ok {
				continue
			}
			capEff, err := strconv.ParseUint(strings.TrimSpace(hex), 16, 64)
			if err != nil {
				t.Fatalf("parse %s CapEff %q: %v", f, hex, err)
			}
			if capEff&netAdminMask != 0 {
				found = append(found, filepath.Base(filepath.Dir(f)))
			}
		}
	}
	return found
}

func TestCapabilityMode(t *testing.T) {
	expected := os.Getenv(expectedCapModeEnv)
	if expected == "" {
		t.Skipf("%s not set", expectedCapModeEnv)
	}

	m := &IpsetMatcher{Ipsets: []string{"test-ipset-v4", "test-ipset-v6"}}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	defer func() { _ = m.Cleanup() }()

	mode := "effective"
	if m.raiseNetAdmin {
		mode = "raise"
	}
	if mode != expected {
		t.Fatalf("capability mode = %q, expected %q", mode, expected)
	}

	for ip, want := range map[string]bool{"127.0.0.1": true, "::1": true, "8.8.8.8": false, "2001:db8::2": false} {
		got, err := m.MatchWithError(makeRequest(t, ip))
		if err != nil {
			t.Fatalf("MatchWithError(%s): %v", ip, err)
		}
		if got != want {
			t.Errorf("MatchWithError(%s) = %v, want %v", ip, got, want)
		}
	}
}

// TestNetAdminRequiredOnThread checks the premise of withNetAdmin(): with =+p,
// netlink ipset calls fail unless CAP_NET_ADMIN is effective on the calling thread.
func TestNetAdminRequiredOnThread(t *testing.T) {
	requireRaiseMode(t)

	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
		if err != nil {
			errCh <- err
			return
		}
		defer handle.Close()
		_, err = handle.IpsetList("test-ipset-v4")
		errCh <- err
	}()
	if err := <-errCh; err == nil {
		t.Fatal("expected ipset list to fail without effective CAP_NET_ADMIN")
	} else {
		t.Logf("without effective CAP_NET_ADMIN: %v", err)
	}
}

// TestNetAdminNotLeaked checks that after many concurrent lookups no thread
// in the process is left with CAP_NET_ADMIN effective.
func TestNetAdminNotLeaked(t *testing.T) {
	requireRaiseMode(t)
	m := provisionMatcher(t, "test-ipset-v4", "test-ipset-v6")
	if m == nil {
		return
	}
	if !m.raiseNetAdmin {
		t.Fatal("expected raiseNetAdmin to be true")
	}

	var wg sync.WaitGroup
	errs := make(chan error, 64*50)
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				ok, err := m.MatchWithError(makeRequest(t, "127.0.0.1"))
				if err != nil {
					errs <- err
				} else if !ok {
					errs <- os.ErrNotExist
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent match failed: %v", err)
	}

	if leaked := threadsWithNetAdmin(t); len(leaked) > 0 {
		t.Fatalf("threads with CAP_NET_ADMIN effective after lookups: %v", leaked)
	}

	// The calling goroutine's thread must not have gained the capability either
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	effective, _, err := netAdminState()
	if err != nil {
		t.Fatal(err)
	}
	if effective {
		t.Fatal("calling thread has CAP_NET_ADMIN effective")
	}
}

func TestWithNetAdmin_RaisesOnlyInside(t *testing.T) {
	requireRaiseMode(t)

	inside, err := withNetAdmin(true, func() (bool, error) {
		effective, _, err := netAdminState()
		return effective, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !inside {
		t.Fatal("CAP_NET_ADMIN not effective inside withNetAdmin")
	}
	if leaked := threadsWithNetAdmin(t); len(leaked) > 0 {
		t.Fatalf("threads with CAP_NET_ADMIN effective after withNetAdmin: %v", leaked)
	}
}

func TestWithNetAdmin_Panic(t *testing.T) {
	requireRaiseMode(t)

	// A panic in fn must propagate, with the capability lowered on the way out
	func() {
		defer func() {
			if r := recover(); r != "boom" {
				t.Fatalf("expected panic \"boom\", got: %v", r)
			}
		}()
		_, _ = withNetAdmin(true, func() (bool, error) {
			panic("boom")
		})
	}()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	effective, _, err := netAdminState()
	if err != nil {
		t.Fatal(err)
	}
	if effective {
		t.Fatal("CAP_NET_ADMIN still effective on this thread after panic")
	}
	if leaked := threadsWithNetAdmin(t); len(leaked) > 0 {
		t.Fatalf("threads with CAP_NET_ADMIN effective after panic: %v", leaked)
	}
}

func TestWithNetAdmin_NoRaise(t *testing.T) {
	// Without raise, fn runs directly on the calling goroutine
	called := false
	got, err := withNetAdmin(false, func() (int, error) {
		called = true
		return 42, nil
	})
	if err != nil || got != 42 || !called {
		t.Fatalf("withNetAdmin(false) = %v, %v, called=%v", got, err, called)
	}
}
