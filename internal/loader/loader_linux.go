//go:build linux

package loader

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/xdp_filter.o
var programBytes []byte

const bpffsRoot = "/sys/fs/bpf/waf-go"

type linuxImpl struct {
	coll *ebpf.Collection
	lnk  link.Link
}

func newImpl() implementation { return &linuxImpl{} }

func (l *linuxImpl) attach(ifaceIndex int) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(programBytes))
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
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

	prog := coll.Programs["waf_xdp"]
	if prog == nil {
		coll.Close()
		return fmt.Errorf("program waf_xdp not found in object")
	}

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifaceIndex,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		coll.Close()
		return fmt.Errorf("attach xdp to iface %d: %w", ifaceIndex, err)
	}
	l.lnk = lnk
	return nil
}

func (l *linuxImpl) close() error {
	if l.lnk != nil {
		l.lnk.Close()
	}
	if l.coll != nil {
		l.coll.Close()
	}
	return nil
}
