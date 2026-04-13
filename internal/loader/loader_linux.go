//go:build linux

package loader

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/xdp_filter.o
var programBytes []byte

const (
	bpffsRoot = "/sys/fs/bpf/waf-go"

	progName = "waf_xdp"

	mapBlocklistV4     = "blocklist_v4"
	mapAllowlistV4     = "allowlist_v4"
	mapDynBlocklistV4  = "dyn_blocklist_v4"
	mapPublicTCPPorts  = "public_tcp_ports"
	mapPublicUDPPorts  = "public_udp_ports"
	mapPrivateTCPPorts = "private_tcp_ports"
	mapPrivateUDPPorts = "private_udp_ports"
	mapStats           = "stats"
	mapPerIPv4         = "perip_v4"
)

type linuxImpl struct {
	coll       *ebpf.Collection
	lnk        link.Link
	lastIfidx  int
	lastFlags  link.XDPAttachFlags
	bypassed   bool // currently detached due to emergency bypass
}

func newImpl() implementation { return &linuxImpl{} }

func (l *linuxImpl) attach(ifaceIndex int, opts Options) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(programBytes))
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}

	if opts.PerIPMaxEntries > 0 {
		if m := spec.Maps[mapPerIPv4]; m != nil {
			m.MaxEntries = opts.PerIPMaxEntries
		}
	}

	if err := os.MkdirAll(bpffsRoot, 0o755); err != nil {
		return fmt.Errorf("mkdir bpffs: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpffsRoot},
	})
	if err != nil {
		return fmt.Errorf("new collection: %w", err)
	}
	l.coll = coll

	prog := coll.Programs[progName]
	if prog == nil {
		coll.Close()
		l.coll = nil
		return fmt.Errorf("program %s not found in object", progName)
	}

	l.lastIfidx = ifaceIndex
	l.lastFlags = xdpFlags(opts.XDPMode)

	if opts.EmergencyBypass {
		l.bypassed = true
		return nil
	}
	return l.attachLink(prog)
}

func (l *linuxImpl) attachLink(prog *ebpf.Program) error {
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: l.lastIfidx,
		Flags:     l.lastFlags,
	})
	if err != nil {
		// If driver mode was requested but unsupported, retry with generic
		// so the agent still runs in degraded mode.
		if l.lastFlags == link.XDPDriverMode && isXDPModeError(err) {
			lnk, err = link.AttachXDP(link.XDPOptions{
				Program:   prog,
				Interface: l.lastIfidx,
				Flags:     link.XDPGenericMode,
			})
			if err == nil {
				l.lastFlags = link.XDPGenericMode
			}
		}
		if err != nil {
			return fmt.Errorf("attach xdp: %w", err)
		}
	}
	l.lnk = lnk
	l.bypassed = false
	return nil
}

func (l *linuxImpl) detach() error {
	if l.lnk != nil {
		err := l.lnk.Close()
		l.lnk = nil
		l.bypassed = true
		return err
	}
	return nil
}

func (l *linuxImpl) close() error {
	var firstErr error
	if l.lnk != nil {
		if err := l.lnk.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		l.lnk = nil
	}
	if l.coll != nil {
		l.coll.Close()
		l.coll = nil
	}
	return firstErr
}

func xdpFlags(mode string) link.XDPAttachFlags {
	switch mode {
	case "driver":
		return link.XDPDriverMode
	case "offload":
		return link.XDPOffloadMode
	default:
		return link.XDPGenericMode
	}
}

// isXDPModeError detects kernel / driver rejection of a specific XDP mode so
// we can transparently fall back to generic.
func isXDPModeError(err error) bool {
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, os.ErrInvalid) ||
		(err != nil && (containsAny(err.Error(),
			"not supported", "no such device", "invalid argument")))
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if len(n) > 0 && bytesContains([]byte(s), []byte(n)) {
			return true
		}
	}
	return false
}

// bytesContains avoids importing strings for one call.
func bytesContains(haystack, needle []byte) bool {
	return bytes.Contains(haystack, needle)
}

// ---- map accessors --------------------------------------------------------

func (l *Loader) mapByName(name string) (*ebpf.Map, error) {
	li, ok := l.impl.(*linuxImpl)
	if !ok || li.coll == nil {
		return nil, fmt.Errorf("loader not attached")
	}
	m := li.coll.Maps[name]
	if m == nil {
		return nil, fmt.Errorf("map %s not found", name)
	}
	return m, nil
}

func (l *Loader) BlocklistMap() (*ebpf.Map, error)    { return l.mapByName(mapBlocklistV4) }
func (l *Loader) AllowlistMap() (*ebpf.Map, error)    { return l.mapByName(mapAllowlistV4) }
func (l *Loader) DynBlocklistMap() (*ebpf.Map, error) { return l.mapByName(mapDynBlocklistV4) }
func (l *Loader) PublicTCPMap() (*ebpf.Map, error)    { return l.mapByName(mapPublicTCPPorts) }
func (l *Loader) PublicUDPMap() (*ebpf.Map, error)    { return l.mapByName(mapPublicUDPPorts) }
func (l *Loader) PrivateTCPMap() (*ebpf.Map, error)   { return l.mapByName(mapPrivateTCPPorts) }
func (l *Loader) PrivateUDPMap() (*ebpf.Map, error)   { return l.mapByName(mapPrivateUDPPorts) }
func (l *Loader) StatsMap() (*ebpf.Map, error)        { return l.mapByName(mapStats) }
func (l *Loader) PerIPMap() (*ebpf.Map, error)        { return l.mapByName(mapPerIPv4) }

// SetBypass transitions the running agent between attached and bypassed
// states without tearing down the eBPF collection.
func (l *Loader) SetBypass(bypass bool) error {
	li, ok := l.impl.(*linuxImpl)
	if !ok || li.coll == nil {
		return errors.New("loader not attached")
	}
	if bypass {
		return li.detach()
	}
	// Re-attach.
	prog := li.coll.Programs[progName]
	if prog == nil {
		return fmt.Errorf("program %s not found", progName)
	}
	return li.attachLink(prog)
}

// Attached reports whether the XDP link is currently installed on the iface.
func (l *Loader) Attached() bool {
	li, ok := l.impl.(*linuxImpl)
	if !ok {
		return false
	}
	return li.lnk != nil && !li.bypassed
}
