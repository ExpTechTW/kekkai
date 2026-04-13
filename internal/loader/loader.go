package loader

// Loader attaches the WAF eBPF program to a network interface and exposes
// handles to the maps shared with the data plane. Platform-specific
// implementations live in loader_linux.go (real eBPF) and loader_stub.go
// (non-linux dev stub).
type Loader struct {
	iface string
	impl  implementation
}

// Options tune runtime-adjustable knobs applied to the eBPF spec or to the
// attach step. Zero values keep compile-time defaults.
type Options struct {
	// PerIPMaxEntries overrides the LRU hash size for perip_v4.
	PerIPMaxEntries uint32

	// XDPMode is one of "generic", "driver", "offload". Empty defaults to
	// generic for maximum compatibility.
	XDPMode string

	// EmergencyBypass loads the eBPF program and maps but does NOT attach
	// to the interface. Useful for quickly restoring connectivity when
	// rules are suspect without stopping the agent entirely.
	EmergencyBypass bool
}

type implementation interface {
	attach(ifaceIndex int, opts Options) error
	detach() error
	close() error
}

func New(iface string) *Loader {
	return &Loader{iface: iface, impl: newImpl()}
}

// Attach loads the eBPF collection and (unless EmergencyBypass is set)
// attaches the XDP program to the given interface index.
func (l *Loader) Attach(ifaceIndex int, opts Options) error {
	return l.impl.attach(ifaceIndex, opts)
}

// Detach removes the XDP link but keeps maps open. Used when switching
// into emergency bypass at runtime.
func (l *Loader) Detach() error {
	return l.impl.detach()
}

// Close tears down the whole collection.
func (l *Loader) Close() error {
	return l.impl.close()
}
