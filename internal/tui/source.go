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
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"

	"github.com/ExpTechTW/kekkai/internal/fastio"
	"github.com/ExpTechTW/kekkai/internal/stats"
)

const bpffsRoot = "/sys/fs/bpf/kekkai"

// Source holds pinned map handles for the lifetime of the TUI.
// Scratch is reused. Top-N rows are double-buffered so a refresh never
// writes the slice the view is still drawing.
type Source struct {
	statsMap *ebpf.Map
	peripMap *ebpf.Map

	iface   string
	txBytes *fastio.CounterReader
	txPkts  *fastio.CounterReader

	scratch []stats.PerCPUCounters
	scan    *stats.PerIPScan
	bufs    [2][]stats.TopEntry
	ix      int

	// Last successful per-IP walk. Reused when the global counters and the
	// requested limit are unchanged, so an idle second does not walk the LRU.
	topOK     bool
	topLimit  int
	topGlobal stats.Global
	topRows   []stats.TopEntry
}

// Snapshot is what the Bubble Tea Model consumes each tick.
type Snapshot struct {
	At     time.Time
	Global stats.Global
	Top    []stats.TopEntry

	// Deltas computed between consecutive snapshots.
	PPS, DPS                float64
	BpsTotal, BpsDropped    float64
	PpsTCP, PpsUDP, PpsICMP float64
	PpsUDPFlow              float64
	TxBps, TxPps            float64

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
	perip, err := ebpf.LoadPinnedMap(bpffsRoot+"/perip", nil)
	if err != nil {
		st.Close()
		return nil, wrapOpenErr("perip", err)
	}
	// Fail before the first tick if the pinned map is not the per-CPU LRU
	// this decoder sums. A shared hash, or a single-value iterate, dies with
	// "per-cpu value requires a slice".
	if err := stats.CheckPerIPMap(perip); err != nil {
		st.Close()
		perip.Close()
		return nil, err
	}

	statsDir := filepath.Join("/sys/class/net", iface, "statistics")
	return &Source{
		statsMap: st,
		peripMap: perip,
		iface:    iface,
		txBytes:  fastio.NewCounterReader(filepath.Join(statsDir, "tx_bytes")),
		txPkts:   fastio.NewCounterReader(filepath.Join(statsDir, "tx_packets")),
		scratch:  make([]stats.PerCPUCounters, 0, 8),
		scan:     stats.NewPerIPScan(),
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

// Read produces a Snapshot. prev is optional and supplies the previous
// counters for rates. limit selects the per-IP walk:
//
//	limit < 0  skip it (pages that do not draw the table)
//	limit == 0 every row, sorted (the scrollable Top-N page)
//	limit > 0  only the highest `limit` rows
func (s *Source) Read(prev *Snapshot, limit int) (Snapshot, error) {
	now := time.Now()
	global, err := stats.ReadGlobal(s.statsMap, &s.scratch)
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
		if dt := now.Sub(prev.At).Seconds(); dt > 0 {
			inv := 1 / dt
			snap.PPS = stats.PerSecond(global.PktsTotal-prev.Global.PktsTotal, inv)
			snap.DPS = stats.PerSecond(global.PktsDropped-prev.Global.PktsDropped, inv)
			snap.BpsTotal = stats.BitsPerSecond(global.BytesTotal-prev.Global.BytesTotal, inv)
			snap.BpsDropped = stats.BitsPerSecond(global.BytesDropped-prev.Global.BytesDropped, inv)
			snap.PpsTCP = stats.PerSecond(global.PktsTCP-prev.Global.PktsTCP, inv)
			snap.PpsUDP = stats.PerSecond(global.PktsUDP-prev.Global.PktsUDP, inv)
			snap.PpsICMP = stats.PerSecond(global.PktsICMP-prev.Global.PktsICMP, inv)
			snap.PpsUDPFlow = stats.PerSecond(global.PassUDPFlow-prev.Global.PassUDPFlow, inv)
			snap.TxBps = stats.BitsPerSecond(txBytes-prev.TxBytes, inv)
			snap.TxPps = stats.PerSecond(txPkts-prev.TxPkts, inv)
		}
	}

	if limit < 0 {
		return snap, nil
	}
	if reusePerIP(s.topOK, limit, s.topLimit, s.topGlobal, global) {
		snap.Top = s.topRows
		return snap, nil
	}

	dst := s.bufs[s.ix][:0]
	dst, _, err = s.scan.Top(s.peripMap, limit, dst)
	if err != nil {
		s.topOK = false
		return snap, fmt.Errorf("perip scan: %w", err)
	}
	s.bufs[s.ix] = dst
	s.ix ^= 1
	s.topOK = true
	s.topLimit = limit
	s.topGlobal = global
	s.topRows = dst
	snap.Top = dst
	return snap, nil
}

// reusePerIP reports whether the previous walk still answers this read.
// A different limit (overview's 5 versus the full Top-N page) must rescan.
func reusePerIP(ok bool, limit, prevLimit int, prev, cur stats.Global) bool {
	return ok && limit == prevLimit && prev == cur
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

// FormatAddr renders a source address. IPv4-mapped keys are shown as plain IPv4.
func FormatAddr(a netip.Addr) string {
	if !a.IsValid() {
		return "-"
	}
	return a.Unmap().String()
}
