// Package stats reads the eBPF maps populated by the XDP program, aggregates
// global/proto/drop-reason counters, walks the per-IP LRU map to compute a
// top-N table, reads tx counters from sysfs (XDP is ingress-only), and writes
// a human-readable snapshot to disk so operators can `watch -n 1 cat` it.
//
// The fast tick (writer) and the slow tick (top-N scan) run on independent
// goroutines and exchange results through an atomic pointer so the top-N
// computation never blocks the writer.
package stats

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
)

// Global stats slot indices — keep in sync with bpf/xdp_filter.c.
const (
	SlotPktsTotal     = 0
	SlotPktsPassed    = 1
	SlotPktsDropped   = 2
	SlotBytesTotal    = 3
	SlotBytesDropped  = 4
	SlotNonIPv4       = 5
	SlotMalformed     = 6
	SlotPktsTCP       = 7
	SlotPktsUDP       = 8
	SlotPktsICMP      = 9
	SlotPktsOtherL4   = 10
	SlotBytesTCP      = 11
	SlotBytesUDP      = 12
	SlotBytesICMP     = 13
	SlotBytesOtherL4  = 14
	SlotDropBlocklist = 15
	SlotDropMalformed = 16
	SlotCount         = 32
)

// Global mirrors struct of the aggregated stats map.
type Global struct {
	PktsTotal, PktsPassed, PktsDropped uint64
	BytesTotal, BytesDropped           uint64
	NonIPv4, Malformed                 uint64
	PktsTCP, PktsUDP, PktsICMP, PktsOtherL4      uint64
	BytesTCP, BytesUDP, BytesICMP, BytesOtherL4  uint64
	DropBlocklist, DropMalformed                 uint64
}

// perIPStat mirrors `struct perip_stat` in the eBPF program.
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

// TopEntry is one row of the sorted top-N table produced by the slow tick.
type TopEntry struct {
	Addr         [4]byte
	Pkts         uint64
	Bytes        uint64
	PktsDropped  uint64
	BytesDropped uint64
	Proto        uint8
	Blocked      bool
}

type topSnapshot struct {
	Entries  []TopEntry
	ScanAt   time.Time
	ScanSize int
	ScanMS   int64
}

type Reader struct {
	global *ebpf.Map
	perip  *ebpf.Map

	nodeID  string
	iface   string
	outPath string

	fastInterval time.Duration
	slowInterval time.Duration
	topN         int

	startedAt time.Time

	prev    Global
	prevAt  time.Time
	hasPrev bool

	// tx sysfs baseline (kernel counters are monotonic since boot)
	txBytesPath string
	txPktsPath  string
	prevTxBytes uint64
	prevTxPkts  uint64
	prevTxAt    time.Time
	hasPrevTx   bool

	// atomic pointer so the writer goroutine reads without locking
	topPtr atomic.Pointer[topSnapshot]
}

func NewReader(global, perip *ebpf.Map, nodeID, iface, outPath string) *Reader {
	return &Reader{
		global:       global,
		perip:        perip,
		nodeID:       nodeID,
		iface:        iface,
		outPath:      outPath,
		fastInterval: time.Second,
		slowInterval: time.Second, // top-N rescan cadence; can tune later
		topN:         10,
		startedAt:    time.Now(),
		txBytesPath:  fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", iface),
		txPktsPath:   fmt.Sprintf("/sys/class/net/%s/statistics/tx_packets", iface),
	}
}

// Run launches two goroutines: fast (writes snapshot file) and slow (scans
// perip map and swaps the result). Both stop when `stop` closes.
func (r *Reader) Run(stop <-chan struct{}) error {
	if err := os.MkdirAll(filepath.Dir(r.outPath), 0o755); err != nil {
		return fmt.Errorf("mkdir stats dir: %w", err)
	}

	// Seed an empty top snapshot so the writer has something to render.
	r.topPtr.Store(&topSnapshot{})

	done := make(chan struct{}, 2)
	go func() { r.runFast(stop); done <- struct{}{} }()
	go func() { r.runSlow(stop); done <- struct{}{} }()

	<-stop
	<-done
	<-done
	return nil
}

// --- fast path --------------------------------------------------------------

func (r *Reader) runFast(stop <-chan struct{}) {
	t := time.NewTicker(r.fastInterval)
	defer t.Stop()
	r.fastTick()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			r.fastTick()
		}
	}
}

func (r *Reader) fastTick() {
	g, err := r.readGlobal()
	if err != nil {
		fmt.Fprintf(os.Stderr, "stats read global: %v\n", err)
		return
	}
	now := time.Now()

	var pps, dps, bpsTotal, bpsDropped float64
	var ppsTCP, ppsUDP, ppsICMP float64
	if r.hasPrev {
		dt := now.Sub(r.prevAt).Seconds()
		if dt > 0 {
			pps = float64(g.PktsTotal-r.prev.PktsTotal) / dt
			dps = float64(g.PktsDropped-r.prev.PktsDropped) / dt
			bpsTotal = float64(g.BytesTotal-r.prev.BytesTotal) * 8 / dt
			bpsDropped = float64(g.BytesDropped-r.prev.BytesDropped) * 8 / dt
			ppsTCP = float64(g.PktsTCP-r.prev.PktsTCP) / dt
			ppsUDP = float64(g.PktsUDP-r.prev.PktsUDP) / dt
			ppsICMP = float64(g.PktsICMP-r.prev.PktsICMP) / dt
		}
	}
	r.prev = g
	r.prevAt = now
	r.hasPrev = true

	txBytes, txPkts := r.readTx()
	var txBps, txPps float64
	if r.hasPrevTx {
		dt := now.Sub(r.prevTxAt).Seconds()
		if dt > 0 {
			txBps = float64(txBytes-r.prevTxBytes) * 8 / dt
			txPps = float64(txPkts-r.prevTxPkts) / dt
		}
	}
	r.prevTxBytes = txBytes
	r.prevTxPkts = txPkts
	r.prevTxAt = now
	r.hasPrevTx = true

	top := r.topPtr.Load()

	r.writeFile(snapshotView{
		Now:        now,
		Global:     g,
		PPS:        pps,
		DPS:        dps,
		BpsTotal:   bpsTotal,
		BpsDropped: bpsDropped,
		PpsTCP:     ppsTCP,
		PpsUDP:     ppsUDP,
		PpsICMP:    ppsICMP,
		TxBytes:    txBytes,
		TxPkts:     txPkts,
		TxBps:      txBps,
		TxPps:      txPps,
		Top:        top,
	})
}

func (r *Reader) readGlobal() (Global, error) {
	var g Global
	for slot := uint32(0); slot < SlotCount; slot++ {
		var perCPU []uint64
		if err := r.global.Lookup(&slot, &perCPU); err != nil {
			return g, fmt.Errorf("lookup slot %d: %w", slot, err)
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		switch slot {
		case SlotPktsTotal:
			g.PktsTotal = sum
		case SlotPktsPassed:
			g.PktsPassed = sum
		case SlotPktsDropped:
			g.PktsDropped = sum
		case SlotBytesTotal:
			g.BytesTotal = sum
		case SlotBytesDropped:
			g.BytesDropped = sum
		case SlotNonIPv4:
			g.NonIPv4 = sum
		case SlotMalformed:
			g.Malformed = sum
		case SlotPktsTCP:
			g.PktsTCP = sum
		case SlotPktsUDP:
			g.PktsUDP = sum
		case SlotPktsICMP:
			g.PktsICMP = sum
		case SlotPktsOtherL4:
			g.PktsOtherL4 = sum
		case SlotBytesTCP:
			g.BytesTCP = sum
		case SlotBytesUDP:
			g.BytesUDP = sum
		case SlotBytesICMP:
			g.BytesICMP = sum
		case SlotBytesOtherL4:
			g.BytesOtherL4 = sum
		case SlotDropBlocklist:
			g.DropBlocklist = sum
		case SlotDropMalformed:
			g.DropMalformed = sum
		}
	}
	return g, nil
}

func (r *Reader) readTx() (uint64, uint64) {
	b, _ := readUint(r.txBytesPath)
	p, _ := readUint(r.txPktsPath)
	return b, p
}

func readUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// --- slow path: perip scan --------------------------------------------------

func (r *Reader) runSlow(stop <-chan struct{}) {
	t := time.NewTicker(r.slowInterval)
	defer t.Stop()
	r.slowTick()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			r.slowTick()
		}
	}
}

func (r *Reader) slowTick() {
	start := time.Now()
	var key uint32
	var val perIPStat
	entries := make([]TopEntry, 0, 1024)

	iter := r.perip.Iterate()
	for iter.Next(&key, &val) {
		e := TopEntry{
			Pkts:         val.Pkts,
			Bytes:        val.Bytes,
			PktsDropped:  val.PktsDropped,
			BytesDropped: val.BytesDropped,
			Proto:        val.LastProto,
			Blocked:      val.Blocked != 0,
		}
		// key is __u32 in network byte order — bytes 0..3 already correct.
		e.Addr[0] = byte(key)
		e.Addr[1] = byte(key >> 8)
		e.Addr[2] = byte(key >> 16)
		e.Addr[3] = byte(key >> 24)
		entries = append(entries, e)
	}
	scanSize := len(entries)
	if err := iter.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "stats perip iterate: %v\n", err)
		return
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Pkts > entries[j].Pkts
	})
	if len(entries) > r.topN {
		entries = entries[:r.topN]
	}

	r.topPtr.Store(&topSnapshot{
		Entries:  entries,
		ScanAt:   time.Now(),
		ScanSize: scanSize,
		ScanMS:   time.Since(start).Milliseconds(),
	})
}

// --- file rendering ---------------------------------------------------------

type snapshotView struct {
	Now                             time.Time
	Global                          Global
	PPS, DPS                        float64
	BpsTotal, BpsDropped            float64
	PpsTCP, PpsUDP, PpsICMP         float64
	TxBytes, TxPkts                 uint64
	TxBps, TxPps                    float64
	Top                             *topSnapshot
}

func (r *Reader) writeFile(v snapshotView) {
	var b strings.Builder
	uptime := v.Now.Sub(r.startedAt).Truncate(time.Second)

	fmt.Fprintf(&b, "waf-go edge stats            updated: %s\n", v.Now.Format(time.RFC3339))
	fmt.Fprintf(&b, "node=%s  iface=%s  uptime=%s\n\n", r.nodeID, r.iface, uptime)

	fmt.Fprintf(&b, "traffic (rx via XDP)\n")
	fmt.Fprintf(&b, "  pps total       : %15s\n", fmtNum(v.PPS))
	fmt.Fprintf(&b, "  pps passed      : %15s\n", fmtNum(v.PPS-v.DPS))
	fmt.Fprintf(&b, "  pps dropped     : %15s\n", fmtNum(v.DPS))
	fmt.Fprintf(&b, "  rx total        : %15s\n", humanBits(v.BpsTotal))
	fmt.Fprintf(&b, "  rx dropped      : %15s\n\n", humanBits(v.BpsDropped))

	fmt.Fprintf(&b, "traffic (tx via kernel, not filtered by XDP)\n")
	fmt.Fprintf(&b, "  tx              : %15s\n", humanBits(v.TxBps))
	fmt.Fprintf(&b, "  tx pps          : %15s\n\n", fmtNum(v.TxPps))

	g := v.Global
	fmt.Fprintf(&b, "protocols (since start)\n")
	fmt.Fprintf(&b, "  tcp             :  pkts=%-14s bytes=%s\n", fmtU(g.PktsTCP), humanBytes(g.BytesTCP))
	fmt.Fprintf(&b, "  udp             :  pkts=%-14s bytes=%s\n", fmtU(g.PktsUDP), humanBytes(g.BytesUDP))
	fmt.Fprintf(&b, "  icmp            :  pkts=%-14s bytes=%s\n", fmtU(g.PktsICMP), humanBytes(g.BytesICMP))
	fmt.Fprintf(&b, "  other l4        :  pkts=%-14s bytes=%s\n\n", fmtU(g.PktsOtherL4), humanBytes(g.BytesOtherL4))

	fmt.Fprintf(&b, "protocols (rate, last %s)\n", r.fastInterval)
	fmt.Fprintf(&b, "  pps tcp         : %15s\n", fmtNum(v.PpsTCP))
	fmt.Fprintf(&b, "  pps udp         : %15s\n", fmtNum(v.PpsUDP))
	fmt.Fprintf(&b, "  pps icmp        : %15s\n\n", fmtNum(v.PpsICMP))

	fmt.Fprintf(&b, "counters (since start)\n")
	fmt.Fprintf(&b, "  packets total   : %15s\n", fmtU(g.PktsTotal))
	fmt.Fprintf(&b, "  packets passed  : %15s\n", fmtU(g.PktsPassed))
	fmt.Fprintf(&b, "  packets dropped : %15s\n", fmtU(g.PktsDropped))
	fmt.Fprintf(&b, "  bytes total     : %15s\n", humanBytes(g.BytesTotal))
	fmt.Fprintf(&b, "  bytes dropped   : %15s\n", humanBytes(g.BytesDropped))
	fmt.Fprintf(&b, "  non-ipv4        : %15s\n", fmtU(g.NonIPv4))
	fmt.Fprintf(&b, "  malformed       : %15s\n\n", fmtU(g.Malformed))

	fmt.Fprintf(&b, "drops by reason (since start)\n")
	fmt.Fprintf(&b, "  blocklist       : %15s\n", fmtU(g.DropBlocklist))
	fmt.Fprintf(&b, "  malformed       : %15s\n\n", fmtU(g.DropMalformed))

	top := v.Top
	if top != nil {
		fmt.Fprintf(&b, "top %d source IPs (scan: %d entries, %dms, at %s)\n",
			r.topN, top.ScanSize, top.ScanMS,
			formatScanAge(v.Now, top.ScanAt))
		fmt.Fprintf(&b, "  %-4s %-16s %-12s %-12s %-10s %-6s %s\n",
			"#", "SRC_IP", "PKTS", "BYTES", "DROPPED", "PROTO", "STATUS")
		if len(top.Entries) == 0 {
			fmt.Fprintf(&b, "  (no traffic yet)\n")
		}
		for i, e := range top.Entries {
			status := "pass"
			if e.Blocked {
				status = "BLOCK"
			}
			fmt.Fprintf(&b, "  %-4d %-16s %-12s %-12s %-10s %-6s %s\n",
				i+1,
				fmt.Sprintf("%d.%d.%d.%d", e.Addr[0], e.Addr[1], e.Addr[2], e.Addr[3]),
				fmtU(e.Pkts),
				humanBytes(e.Bytes),
				fmtU(e.PktsDropped),
				protoName(e.Proto),
				status,
			)
		}
	}

	// Atomic replace so `watch` never sees a half-written file.
	tmp := r.outPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "stats write: %v\n", err)
		return
	}
	if err := os.Rename(tmp, r.outPath); err != nil {
		fmt.Fprintf(os.Stderr, "stats rename: %v\n", err)
	}
}

func formatScanAge(now, scanAt time.Time) string {
	if scanAt.IsZero() {
		return "pending"
	}
	return fmt.Sprintf("%s ago", now.Sub(scanAt).Truncate(time.Millisecond))
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 0:
		return "-"
	default:
		return fmt.Sprintf("%d", p)
	}
}

func fmtU(v uint64) string {
	return addCommas(strconv.FormatUint(v, 10))
}

func fmtNum(v float64) string {
	return addCommas(strconv.FormatFloat(v, 'f', 2, 64))
}

func addCommas(s string) string {
	// split on decimal point so we only comma the integer part
	intPart, decPart := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, decPart = s[:i], s[i:]
	}
	n := len(intPart)
	if n <= 3 {
		return intPart + decPart
	}
	var out strings.Builder
	pre := n % 3
	if pre > 0 {
		out.WriteString(intPart[:pre])
		if n > pre {
			out.WriteByte(',')
		}
	}
	for i := pre; i < n; i += 3 {
		out.WriteString(intPart[i : i+3])
		if i+3 < n {
			out.WriteByte(',')
		}
	}
	out.WriteString(decPart)
	return out.String()
}

func humanBits(v float64) string {
	const (
		k = 1_000.0
		m = 1_000_000.0
		g = 1_000_000_000.0
	)
	switch {
	case v >= g:
		return fmt.Sprintf("%8.2f Gbps", v/g)
	case v >= m:
		return fmt.Sprintf("%8.2f Mbps", v/m)
	case v >= k:
		return fmt.Sprintf("%8.2f Kbps", v/k)
	default:
		return fmt.Sprintf("%8.2f bps ", v)
	}
}

func humanBytes(v uint64) string {
	const (
		k = 1024.0
		m = k * 1024
		g = m * 1024
		t = g * 1024
	)
	f := float64(v)
	switch {
	case f >= t:
		return fmt.Sprintf("%8.2f TiB", f/t)
	case f >= g:
		return fmt.Sprintf("%8.2f GiB", f/g)
	case f >= m:
		return fmt.Sprintf("%8.2f MiB", f/m)
	case f >= k:
		return fmt.Sprintf("%8.2f KiB", f/k)
	default:
		return fmt.Sprintf("%8d B  ", v)
	}
}
