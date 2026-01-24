//go:build !linux
// +build !linux

package caddy_ipset

import (
	"testing"
)

// TestStubNotSupported verifies that the module is not functional on non-Linux platforms
func TestStubNotSupported(t *testing.T) {
	t.Skip("ipset matcher is only supported on Linux")
}
