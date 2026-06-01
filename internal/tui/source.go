// Package tui powers `kekkai status` — a Bubble Tea interface that renders
// live WAF telemetry from pinned eBPF maps.
//
// The data source opens the maps pinned by kekkai-agent under
// /sys/fs/bpf/kekkai and reads them directly. kekkai-agent stays untouched.
package tui

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf"

	"github.com/ExpTechTW/kekkai/internal/fastio"
	"github.com/ExpTechTW/kekkai/internal/stats"
)

const bpffsRoot = "/sys/fs/bpf/kekkai"

// Source holds pinned map handles for the lifetime of the TUI. All
// per-tick buffers are preallocated so steady-state refresh does no heap
// work beyond what Bubble Tea itself needs.
type Source struct {
	statsMap *ebpf.Map
	peripMap *ebpf.Map

	iface       string
	txBytes     *fastio.CounterReader
	txPkts      *fastio.CounterReader

	// scratch for PERCPU_ARRAY lookups
	perCPU []uint64

	// perip_v4 is a PER-CPU LRU hash: each lookup yields one perIPStat per
	// possible CPU. peripCPU is the pre-sized (len == numCPU) sink the
	// iterate fills in place; values are summed across CPUs per source IP.
	numCPU   int
	peripCPU []stats.PerIPStat

	// preallocated top-N scratch; cap sized to perip MaxEntries
	topBuf []stats.TopEntry
}

// Snapshot is what the Bubble Tea Model consumes each tick.
type Snapshot struct {
	At     time.Time
	Global stats.Global
	Top    []stats.TopEntry

	// Deltas computed between consecutive snapshots.
	PPS, DPS                 float64
	BpsTotal, BpsDropped     float64
	PpsTCP, PpsUDP, PpsICMP  float64
	PpsStatefulTCP, PpsStatefulUDP float64
	TxBps, TxPps             float64

	// Current tx counters (sysfs).
	TxBytes, TxPkts uint64
}

// NewSource opens pinned maps from bpffs. Returns a clear error if the
// agent isn't running (i.e. maps aren't pinned yet).
func NewSource(iface string) (*Source, error) {
	st, err := ebpf.LoadPinnedMap(bpffsRoot+"/stats", nil)
	if err != nil {
		return nil, wrapOpenErr("stats", err)
	}
	perip, err := ebpf.LoadPinnedMap(bpffsRoot+"/perip_v4", nil)
	if err != nil {
		st.Close()
		return nil, wrapOpenErr("perip_v4", err)
	}
	// Fail loudly if the agent's pinned map doesn't match our decoder (e.g.
	// CLI and agent built from different schemas) instead of mis-decoding.
	if err := stats.CheckPerIPMap(perip); err != nil {
		st.Close()
		perip.Close()
		return nil, err
	}

	cap := int(perip.MaxEntries())
	if cap == 0 {
		cap = 65536
	}

	// perip_v4 is per-CPU; size the lookup sink to the possible-CPU count.
	numCPU := stats.PossibleCPUOr1()

	return &Source{
		statsMap:    st,
		peripMap:    perip,
		iface:       iface,
		txBytes:     fastio.NewCounterReader(fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", iface)),
		txPkts:      fastio.NewCounterReader(fmt.Sprintf("/sys/class/net/%s/statistics/tx_packets", iface)),
		perCPU:      make([]uint64, 0, 128),
		numCPU:      numCPU,
		peripCPU:    make([]stats.PerIPStat, numCPU),
		topBuf:      make([]stats.TopEntry, 0, cap),
	}, nil
}

// wrapOpenErr annotates pinned-map open failures. EACCES almost always means
// the user is non-root on a distro that sets kernel.unprivileged_bpf_disabled
// (Debian / Ubuntu / Pi OS default), which blocks bpf(BPF_OBJ_GET) regardless
// of file caps. Tell the operator to rerun with sudo.
func wrapOpenErr(which string, err error) error {
	if errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission) {
		if os.Geteuid() != 0 {
			return fmt.Errorf(
				"open pinned %s map: %w\nkekkai CLI must run as root — retry with: sudo kekkai status",
				which, err)
		}
		return fmt.Errorf(
			"open pinned %s map: %w\n(kernel.unprivileged_bpf_disabled is set; even root may need sysctl=0 if this persists)",
			which, err)
	}
	return fmt.Errorf(
		"open pinned %s map: %w\n(is kekkai-agent running? maps are pinned under %s)",
		which, err, bpffsRoot)
}

func (s *Source) Close() {
	if s.statsMap != nil {
		s.statsMap.Close()
	}
	if s.peripMap != nil {
		s.peripMap.Close()
	}
	if s.txBytes != nil {
		_ = s.txBytes.Close()
	}
	if s.txPkts != nil {
		_ = s.txPkts.Close()
	}
}

// Read produces a Snapshot. `prev` is optional — if non-nil, Read uses it
// to compute per-second rates. The returned Snapshot is safe to pass as
// next prev.
func (s *Source) Read(prev *Snapshot) (Snapshot, error) {
	now := time.Now()
	global, err := s.readGlobal()
	if err != nil {
		return Snapshot{}, err
	}
	txBytes, txPkts := s.readTx()

	snap := Snapshot{
		At:      now,
		Global:  global,
		TxBytes: txBytes,
		TxPkts:  txPkts,
	}

	if prev != nil {
		dt := now.Sub(prev.At).Seconds()
		if dt > 0 {
			snap.PPS = float64(global.PktsTotal-prev.Global.PktsTotal) / dt
			snap.DPS = float64(global.PktsDropped-prev.Global.PktsDropped) / dt
			snap.BpsTotal = float64(global.BytesTotal-prev.Global.BytesTotal) * 8 / dt
			snap.BpsDropped = float64(global.BytesDropped-prev.Global.BytesDropped) * 8 / dt
			snap.PpsTCP = float64(global.PktsTCP-prev.Global.PktsTCP) / dt
			snap.PpsUDP = float64(global.PktsUDP-prev.Global.PktsUDP) / dt
			snap.PpsICMP = float64(global.PktsICMP-prev.Global.PktsICMP) / dt
			snap.PpsStatefulTCP = float64(global.PassStatefulTCP-prev.Global.PassStatefulTCP) / dt
			snap.PpsStatefulUDP = float64(global.PassStatefulUDP-prev.Global.PassStatefulUDP) / dt
			snap.TxBps = float64(txBytes-prev.TxBytes) * 8 / dt
			snap.TxPps = float64(txPkts-prev.TxPkts) / dt
		}
	}

	// Top-N scan — reuse the preallocated buffer. Uses Iterate; the TUI
	// tick cadence (1 s) is generous enough that BatchLookup's added
	// complexity isn't worth it here.
	s.topBuf = s.topBuf[:0]
	var k uint32
	iter := s.peripMap.Iterate()
	// Per-CPU iterate: pass the pre-sized slice (len == numCPU) by value so
	// the lookup fills it in place. A single perIPStat is rejected with
	// "per-cpu value requires a slice".
	for iter.Next(&k, s.peripCPU) {
		s.topBuf = append(s.topBuf, stats.FoldPerIP(k, s.peripCPU))
	}
	if err := iter.Err(); err != nil {
		return snap, fmt.Errorf("perip iterate: %w", err)
	}

	sort.Slice(s.topBuf, func(i, j int) bool {
		return s.topBuf[i].Pkts > s.topBuf[j].Pkts
	})
	snap.Top = s.topBuf
	return snap, nil
}

// readGlobal sums each PERCPU_ARRAY slot and maps it onto Global using the
// shared stats helpers — no per-field wiring duplicated here.
func (s *Source) readGlobal() (stats.Global, error) {
	var g stats.Global
	for slot := uint32(0); slot < stats.SlotCount; slot++ {
		s.perCPU = s.perCPU[:0]
		if err := s.statsMap.Lookup(&slot, &s.perCPU); err != nil {
			return g, fmt.Errorf("lookup slot %d: %w", slot, err)
		}
		stats.AssignSlot(&g, slot, stats.SumPerCPU(s.perCPU))
	}
	return g, nil
}

func (s *Source) readTx() (uint64, uint64) {
	var b, p uint64
	if s.txBytes != nil {
		b, _ = s.txBytes.Read()
	}
	if s.txPkts != nil {
		p, _ = s.txPkts.Read()
	}
	return b, p
}

// FormatAddr renders a [4]byte as dotted-quad. Lives here because both
// source.go and view.go need it.
func FormatAddr(a [4]byte) string {
	return netip.AddrFrom4(a).String()
}
