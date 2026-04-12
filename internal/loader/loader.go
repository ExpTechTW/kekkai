package loader

// Loader attaches and detaches the WAF eBPF program.
// Platform-specific implementations live in loader_linux.go (real eBPF
// attach) and loader_stub.go (no-op for darwin development).
type Loader struct {
	iface string
	impl  implementation
}

type implementation interface {
	attach(ifaceIndex int) error
	close() error
}

func New(iface string) *Loader {
	return &Loader{iface: iface, impl: newImpl()}
}

func (l *Loader) Iface() string { return l.iface }

func (l *Loader) Attach(ifaceIndex int) error {
	return l.impl.attach(ifaceIndex)
}

func (l *Loader) Close() error {
	return l.impl.close()
}
