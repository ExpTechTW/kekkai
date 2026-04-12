//go:build !linux

package loader

import "fmt"

// stubImpl lets the project build on non-Linux hosts (macOS dev workflow).
// XDP is Linux-only; calling Attach here returns a clear error.
type stubImpl struct{}

func newImpl() implementation { return &stubImpl{} }

func (stubImpl) attach(ifaceIndex int) error {
	return fmt.Errorf("XDP is only supported on Linux; build for linux to attach")
}

func (stubImpl) close() error { return nil }
