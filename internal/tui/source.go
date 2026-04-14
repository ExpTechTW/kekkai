// Package tui powers `kekkai status` — a Bubble Tea interface that renders
// live WAF telemetry from pinned eBPF maps.
//
// The data source opens the maps pinned by kekkai-agent under
// /sys/fs/bpf/kekkai and reads them directly. kekkai-agent stays untouched.
package tui

import (
	"fmt"
	"net/netip"
	"sort"
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

	// preallocated top-N scratch; cap sized to perip MaxEntries
	topBuf []topRow
}

// topRow mirrors stats.perIPStat on the eBPF side but with only what the
// TUI needs.
type topRow struct {
	Addr         [4]byte
	Pkts         uint64
	Bytes        uint64
	PktsDropped  uint64
	BytesDropped uint64
	Proto        uint8
	Blocked      bool
}

// Snapshot is what the Bubble Tea Model consumes each tick.
type Snapshot struct {
	At     time.Time
	Global stats.Global
	Top    []topRow

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
		return nil, fmt.Errorf(
			"open pinned stats map: %w\n(is kekkai-agent running? maps are pinned under %s)",
			err, bpffsRoot)
	}
	perip, err := ebpf.LoadPinnedMap(bpffsRoot+"/perip_v4", nil)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("open pinned perip_v4 map: %w", err)
	}

	cap := int(perip.MaxEntries())
	if cap == 0 {
		cap = 65536
	}

	return &Source{
		statsMap:    st,
		peripMap:    perip,
		iface:       iface,
		txBytes:     fastio.NewCounterReader(fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", iface)),
		txPkts:      fastio.NewCounterReader(fmt.Sprintf("/sys/class/net/%s/statistics/tx_packets", iface)),
		perCPU:      make([]uint64, 0, 128),
		topBuf:      make([]topRow, 0, cap),
	}, nil
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
	var v perIPStat
	iter := s.peripMap.Iterate()
	for iter.Next(&k, &v) {
		s.topBuf = append(s.topBuf, topRow{
			Addr:         unpackAddr(k),
			Pkts:         v.Pkts,
			Bytes:        v.Bytes,
			PktsDropped:  v.PktsDropped,
			BytesDropped: v.BytesDropped,
			Proto:        v.LastProto,
			Blocked:      v.Blocked != 0,
		})
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

// perIPStat mirrors struct perip_stat in bpf/xdp_filter.c. Duplicated here
// rather than imported from internal/stats because that package keeps it
// unexported.
type perIPStat struct {
	Pkts         uint64
	Bytes        uint64
	PktsDropped  uint64
	BytesDropped uint64
	LastSeenNS   uint64
	LastProto    uint8
	Blocked      uint8
	_            [6]uint8
}

func (s *Source) readGlobal() (stats.Global, error) {
	var g stats.Global
	for slot := uint32(0); slot < stats.SlotCount; slot++ {
		s.perCPU = s.perCPU[:0]
		if err := s.statsMap.Lookup(&slot, &s.perCPU); err != nil {
			return g, fmt.Errorf("lookup slot %d: %w", slot, err)
		}
		var sum uint64
		for _, v := range s.perCPU {
			sum += v
		}
		assignSlot(&g, slot, sum)
	}
	return g, nil
}

// assignSlot maps a slot index to the corresponding field on Global.
// Centralised so both the agent and the TUI use the same wiring.
func assignSlot(g *stats.Global, slot uint32, sum uint64) {
	switch slot {
	case stats.SlotPktsTotal:
		g.PktsTotal = sum
	case stats.SlotPktsPassed:
		g.PktsPassed = sum
	case stats.SlotPktsDropped:
		g.PktsDropped = sum
	case stats.SlotBytesTotal:
		g.BytesTotal = sum
	case stats.SlotBytesDropped:
		g.BytesDropped = sum
	case stats.SlotPktsTCP:
		g.PktsTCP = sum
	case stats.SlotPktsUDP:
		g.PktsUDP = sum
	case stats.SlotPktsICMP:
		g.PktsICMP = sum
	case stats.SlotPktsOtherL4:
		g.PktsOtherL4 = sum
	case stats.SlotBytesTCP:
		g.BytesTCP = sum
	case stats.SlotBytesUDP:
		g.BytesUDP = sum
	case stats.SlotBytesICMP:
		g.BytesICMP = sum
	case stats.SlotBytesOtherL4:
		g.BytesOtherL4 = sum
	case stats.SlotDropNonIPv4:
		g.DropNonIPv4 = sum
	case stats.SlotDropMalformed:
		g.DropMalformed = sum
	case stats.SlotDropBlocklist:
		g.DropBlocklist = sum
	case stats.SlotDropDynBlock:
		g.DropDynBlock = sum
	case stats.SlotDropNotAllowed:
		g.DropNotAllowed = sum
	case stats.SlotDropNoPolicy:
		g.DropNoPolicy = sum
	case stats.SlotPassFragment:
		g.PassFragment = sum
	case stats.SlotPassReturnTCP:
		g.PassReturnTCP = sum
	case stats.SlotPassReturnUDP:
		g.PassReturnUDP = sum
	case stats.SlotPassReturnICMP:
		g.PassReturnICMP = sum
	case stats.SlotPassPublicTCP:
		g.PassPublicTCP = sum
	case stats.SlotPassPublicUDP:
		g.PassPublicUDP = sum
	case stats.SlotPassPrivateTCP:
		g.PassPrivateTCP = sum
	case stats.SlotPassPrivateUDP:
		g.PassPrivateUDP = sum
	case stats.SlotPassStatefulTCP:
		g.PassStatefulTCP = sum
	case stats.SlotPassStatefulUDP:
		g.PassStatefulUDP = sum
	}
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

func unpackAddr(key uint32) [4]byte {
	return [4]byte{
		byte(key),
		byte(key >> 8),
		byte(key >> 16),
		byte(key >> 24),
	}
}

// FormatAddr renders a [4]byte as dotted-quad. Lives here because both
// source.go and view.go need it.
func FormatAddr(a [4]byte) string {
	return netip.AddrFrom4(a).String()
}
