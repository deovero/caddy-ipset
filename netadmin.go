//go:build linux

package caddy_ipset

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// netAdminMask is the bit for CAP_NET_ADMIN in the first 32-bit word of the
// capability sets. CAP_NET_ADMIN is 12, so it always lives in data[0].
const netAdminMask = 1 << unix.CAP_NET_ADMIN

// netAdminState reports whether CAP_NET_ADMIN is in the effective and in the
// permitted set of the calling thread.
func netAdminState() (effective, permitted bool, err error) {
	_, data, err := getCapabilities()
	if err != nil {
		return false, false, err
	}
	return data[0].Effective&netAdminMask != 0, data[0].Permitted&netAdminMask != 0, nil
}

// setNetAdminEffective adds or removes CAP_NET_ADMIN in the effective set of
// the calling thread. Adding it only works when it is in the permitted set.
// Capabilities are per-thread, so the caller must have locked its goroutine to
// the OS thread with runtime.LockOSThread.
func setNetAdminEffective(effective bool) error {
	hdr, data, err := getCapabilities()
	if err != nil {
		return err
	}
	if effective {
		data[0].Effective |= netAdminMask
	} else {
		data[0].Effective &^= netAdminMask
	}
	return unix.Capset(&hdr, &data[0])
}

// getCapabilities returns the capability sets of the calling thread.
func getCapabilities() (unix.CapUserHeader, [2]unix.CapUserData, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	err := unix.Capget(&hdr, &data[0])
	return hdr, data, err
}

// withNetAdmin runs fn with CAP_NET_ADMIN in the effective set of the
// calling thread, and returns what fn returns.
//
// When raise is false the process already has CAP_NET_ADMIN effective on all
// threads (binary granted with =+ep, or running as root), and fn is simply
// called.
//
// When raise is true the binary was granted CAP_NET_ADMIN with =+p: it is
// permitted but not effective. The kernel checks CAP_NET_ADMIN both when the
// netlink socket is opened and for every message sent on it, against the
// calling thread. So the calling goroutine is locked to its OS thread,
// CAP_NET_ADMIN is raised for that thread only, fn runs, and the capability is
// lowered again before the thread is unlocked. While the thread is locked no
// other goroutine runs on it, and the Go runtime does not clone new threads
// from a locked thread, so the capability does not leak to the rest of Caddy.
//
// fn runs on the calling goroutine instead of a dedicated one on purpose:
// handing the netlink round-trip to another goroutine roughly doubled the
// lookup latency in benchmarks, while locking in place costs ~1µs.
func withNetAdmin[T any](raise bool, fn func() (T, error)) (T, error) {
	if !raise {
		return fn()
	}

	runtime.LockOSThread()
	if err := setNetAdminEffective(true); err != nil {
		// Raising failed, so the thread state is unchanged and safe to reuse.
		runtime.UnlockOSThread()
		var zero T
		return zero, fmt.Errorf("raising CAP_NET_ADMIN: %w", err)
	}
	// Deferred, so the capability is also lowered when fn panics
	defer lowerNetAdmin()

	return fn()
}

// lowerNetAdmin removes CAP_NET_ADMIN from the effective set of the calling
// thread and unlocks the goroutine from it. It is the counterpart of the raise
// in withNetAdmin().
//
// Removing a capability from the effective set should never fail. If it does,
// the thread must not be handed back to the Go scheduler, so it stays locked
// and lowerNetAdmin panics: the goroutine unwinds and exits (net/http recovers
// panics per connection), and the Go runtime terminates a thread whose
// goroutine exits while locked, taking the raised capability with it.
func lowerNetAdmin() {
	if err := setNetAdminEffective(false); err != nil {
		panic(fmt.Sprintf("caddy-ipset: lowering CAP_NET_ADMIN failed, abandoning this thread: %v", err))
	}
	runtime.UnlockOSThread()
}
