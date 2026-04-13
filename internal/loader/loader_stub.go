//go:build !linux

package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// stubImpl lets the project build on non-Linux hosts (macOS dev workflow).
type stubImpl struct{}

func newImpl() implementation { return &stubImpl{} }

func (stubImpl) attach(ifaceIndex int, opts Options) error {
	return fmt.Errorf("XDP is only supported on Linux; build for linux to attach")
}
func (stubImpl) detach() error { return nil }
func (stubImpl) close() error  { return nil }

const stubErr = "eBPF maps not available on non-linux builds"

func (l *Loader) BlocklistMap() (*ebpf.Map, error)    { return nil, fmt.Errorf(stubErr) }
func (l *Loader) AllowlistMap() (*ebpf.Map, error)    { return nil, fmt.Errorf(stubErr) }
func (l *Loader) DynBlocklistMap() (*ebpf.Map, error) { return nil, fmt.Errorf(stubErr) }
func (l *Loader) PublicTCPMap() (*ebpf.Map, error)    { return nil, fmt.Errorf(stubErr) }
func (l *Loader) PublicUDPMap() (*ebpf.Map, error)    { return nil, fmt.Errorf(stubErr) }
func (l *Loader) PrivateTCPMap() (*ebpf.Map, error)   { return nil, fmt.Errorf(stubErr) }
func (l *Loader) PrivateUDPMap() (*ebpf.Map, error)   { return nil, fmt.Errorf(stubErr) }
func (l *Loader) StatsMap() (*ebpf.Map, error)        { return nil, fmt.Errorf(stubErr) }
func (l *Loader) PerIPMap() (*ebpf.Map, error)        { return nil, fmt.Errorf(stubErr) }

func (l *Loader) SetBypass(bool) error { return nil }
func (l *Loader) Attached() bool       { return false }
