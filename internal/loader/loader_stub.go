//go:build !linux

package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// stubImpl lets the project build on non-Linux hosts (macOS dev workflow).
// XDP is Linux-only; calling Attach here returns a clear error.
type stubImpl struct{}

func newImpl() implementation { return &stubImpl{} }

func (stubImpl) attach(ifaceIndex int) error {
	return fmt.Errorf("XDP is only supported on Linux; build for linux to attach")
}

func (stubImpl) close() error { return nil }

// BlocklistMap is a no-op on non-Linux builds.
func (l *Loader) BlocklistMap() (*ebpf.Map, error) {
	return nil, fmt.Errorf("blocklist map not available on non-linux builds")
}

// StatsMap is a no-op on non-Linux builds.
func (l *Loader) StatsMap() (*ebpf.Map, error) {
	return nil, fmt.Errorf("stats map not available on non-linux builds")
}

func (l *Loader) PerIPMap() (*ebpf.Map, error) {
	return nil, fmt.Errorf("perip map not available on non-linux builds")
}

func (l *Loader) EventsMap() (*ebpf.Map, error) {
	return nil, fmt.Errorf("events map not available on non-linux builds")
}
