package loader

// Loader attaches and detaches the WAF eBPF program and exposes handles to
// the maps shared with the data plane. Platform-specific implementations
// live in loader_linux.go (real eBPF) and loader_stub.go (darwin dev stub).
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

func (l *Loader) Attach(ifaceIndex int) error {
	return l.impl.attach(ifaceIndex)
}

func (l *Loader) Close() error {
	return l.impl.close()
}
