// Package stats reads the eBPF maps populated by the XDP program, aggregates
// global/proto/drop-reason counters, walks the per-CPU per-IP LRU to compute a
// top-N table, reads tx counters from sysfs (XDP is ingress-only), and writes
// a human-readable snapshot to disk so operators can `watch -n 1 cat` it.
//
// One goroutine owns the tick. The top-N ranking keeps a fixed window instead
// of copying and sorting the whole LRU, and the file buffer is reused.
package stats

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cilium/ebpf"

	"github.com/ExpTechTW/kekkai/internal/fastio"
)

// Slot indices mirror the C enum in bpf/xdp_filter.c, in order. Verdicts
// occupy 0..VerdictCount-1 and SlotPassARP is the first pass. The remaining
// slots are traffic mix and byte totals. PktsTotal / PktsPassed / PktsDropped
// are not slots — the reader derives them from the verdicts.
//
// STAT_VERDICTS and STAT_PKTS_TCP are the same index in C, so VerdictCount
// is an alias of SlotPktsTCP rather than another iota step. Putting it in
// this block would make SlotCount 28 and shift every later counter.
const (
	SlotDropNonIP = iota
	SlotDropMalformed
	SlotDropBlocklist
	SlotDropNotAllowed
	SlotDropNoPolicy
	SlotPassARP
	SlotPassFragment
	SlotPassTCPEst
	SlotPassUDPFlow
	SlotPassDHCP
	SlotPassICMP
	SlotPassPublicTCP
	SlotPassPublicUDP
	SlotPassPrivateTCP
	SlotPassPrivateUDP
	SlotPktsTCP
	SlotPktsUDP
	SlotPktsICMP
	SlotPktsOther
	SlotBytesTCP
	SlotBytesUDP
	SlotBytesICMP
	SlotBytesOther
	SlotPktsIPv6
	SlotBytesIPv6
	SlotBytesTotal
	SlotBytesDropped
	SlotCount
)

const (
	// VerdictCount is the number of verdict slots and the index of the first
	// non-verdict counter.
	VerdictCount = SlotPktsTCP
	// FirstPassVerdict is the first slot that records a pass. Slots below it
	// are drops.
	FirstPassVerdict = SlotPassARP
)

// PerCPUCounters is one CPU's value in the stats map: u64 c[SlotCount].
type PerCPUCounters [SlotCount]uint64

// Global is the summed stats map plus the three derived packet totals.
type Global struct {
	PktsTotal, PktsPassed, PktsDropped uint64

	DropNonIP, DropMalformed, DropBlocklist uint64
	DropNotAllowed, DropNoPolicy            uint64

	PassARP, PassFragment                       uint64
	PassTCPEst, PassUDPFlow, PassDHCP, PassICMP uint64
	PassPublicTCP, PassPublicUDP                uint64
	PassPrivateTCP, PassPrivateUDP              uint64

	PktsTCP, PktsUDP, PktsICMP, PktsOther     uint64
	BytesTCP, BytesUDP, BytesICMP, BytesOther uint64
	PktsIPv6, BytesIPv6                       uint64
	BytesTotal, BytesDropped                  uint64
}

// TopEntry is one row of the sorted top-N table.
// Addr is a plain IPv4 or IPv6 address; IPv4-mapped keys are unmapped.
type TopEntry struct {
	Addr         netip.Addr
	Pkts         uint64
	Bytes        uint64
	PktsDropped  uint64
	BytesDropped uint64
	Proto        uint8
	Blocked      bool
}

type Reader struct {
	global *ebpf.Map
	perip  *ebpf.Map

	nodeID  string
	iface   string
	outPath string

	fastInterval time.Duration
	topN         int
	peripCap     int

	startedAt time.Time

	prev        Global
	prevAt      time.Time
	hasPrev     bool
	txBytes     *fastio.CounterReader
	txPkts      *fastio.CounterReader
	prevTxBytes uint64
	prevTxPkts  uint64
	scratch     []PerCPUCounters
	scan        *PerIPScan
	topEntries  []TopEntry
	scanOK      bool
	scanAt      time.Time
	scanSize    int
	scanMS      int64
	fileBuf     bytes.Buffer
}

func NewReader(global, perip *ebpf.Map, nodeID, iface, outPath string) *Reader {
	peripCap := 0
	if perip != nil {
		peripCap = int(perip.MaxEntries())
	}
	if peripCap == 0 {
		peripCap = 65536 // fall back for stub/non-linux
	}

	r := &Reader{
		global:       global,
		perip:        perip,
		nodeID:       nodeID,
		iface:        iface,
		outPath:      outPath,
		fastInterval: time.Second,
		topN:         10,
		peripCap:     peripCap,
		startedAt:    time.Now(),
		scratch:      make([]PerCPUCounters, 0, 8),
		scan:         NewPerIPScan(),
		topEntries:   make([]TopEntry, 0, 10),
	}
	statsDir := filepath.Join("/sys/class/net", iface, "statistics")
	r.txBytes = fastio.NewCounterReader(filepath.Join(statsDir, "tx_bytes"))
	r.txPkts = fastio.NewCounterReader(filepath.Join(statsDir, "tx_packets"))
	r.fileBuf.Grow(4096)
	return r
}

// Run blocks until stop closes, refreshing the stats file once a second.
func (r *Reader) Run(stop <-chan struct{}) error {
	if err := os.MkdirAll(filepath.Dir(r.outPath), 0o755); err != nil {
		return fmt.Errorf("mkdir stats dir: %w", err)
	}
	defer func() {
		if r.txBytes != nil {
			_ = r.txBytes.Close()
		}
		if r.txPkts != nil {
			_ = r.txPkts.Close()
		}
	}()

	t := time.NewTicker(r.fastInterval)
	defer t.Stop()
	r.tick()
	for {
		select {
		case <-stop:
			return nil
		case <-t.C:
			r.tick()
		}
	}
}

func (r *Reader) tick() {
	g, err := ReadGlobal(r.global, &r.scratch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stats read global: %v\n", err)
		return
	}
	now := time.Now()

	var pps, dps, bpsTotal, bpsDropped float64
	var ppsTCP, ppsUDP, ppsICMP float64
	txBytes, txPkts := r.readTx()
	var txBps, txPps float64
	// perip_touch only runs on the path that also increments these counters,
	// so an unchanged global total means the LRU rows cannot have changed.
	// A failed walk is never reused: the next tick tries again.
	reuse := reusePerIPScan(r.scanOK, r.hasPrev, r.prev, g)
	if r.hasPrev {
		if dt := now.Sub(r.prevAt).Seconds(); dt > 0 {
			inv := 1 / dt
			pps = PerSecond(g.PktsTotal-r.prev.PktsTotal, inv)
			dps = PerSecond(g.PktsDropped-r.prev.PktsDropped, inv)
			bpsTotal = BitsPerSecond(g.BytesTotal-r.prev.BytesTotal, inv)
			bpsDropped = BitsPerSecond(g.BytesDropped-r.prev.BytesDropped, inv)
			ppsTCP = PerSecond(g.PktsTCP-r.prev.PktsTCP, inv)
			ppsUDP = PerSecond(g.PktsUDP-r.prev.PktsUDP, inv)
			ppsICMP = PerSecond(g.PktsICMP-r.prev.PktsICMP, inv)
			txBps = BitsPerSecond(txBytes-r.prevTxBytes, inv)
			txPps = PerSecond(txPkts-r.prevTxPkts, inv)
		}
	}
	r.prev = g
	r.prevAt = now
	r.hasPrev = true
	r.prevTxBytes = txBytes
	r.prevTxPkts = txPkts

	if !reuse {
		start := time.Now()
		entries, n, err := r.scan.Top(r.perip, r.topN, r.topEntries)
		if err != nil {
			r.scanOK = false
			fmt.Fprintf(os.Stderr, "stats perip scan: %v\n", err)
		} else {
			r.topEntries = entries
			r.scanSize = n
			r.scanAt = time.Now()
			r.scanMS = time.Since(start).Milliseconds()
			r.scanOK = true
		}
	}

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
	})
}

func (r *Reader) readTx() (uint64, uint64) {
	var b, p uint64
	if r.txBytes != nil {
		b, _ = r.txBytes.Read()
	}
	if r.txPkts != nil {
		p, _ = r.txPkts.Read()
	}
	return b, p
}

// --- file rendering ---------------------------------------------------------

type snapshotView struct {
	Now                     time.Time
	Global                  Global
	PPS, DPS                float64
	BpsTotal, BpsDropped    float64
	PpsTCP, PpsUDP, PpsICMP float64
	TxBytes, TxPkts         uint64
	TxBps, TxPps            float64
}

func (r *Reader) writeFile(v snapshotView) {
	b := &r.fileBuf
	b.Reset()
	uptime := v.Now.Sub(r.startedAt).Truncate(time.Second)

	fmt.Fprintf(b, "kekkai edge stats            updated: %s\n", v.Now.Format(time.RFC3339))
	fmt.Fprintf(b, "node=%s  iface=%s  uptime=%s\n\n", r.nodeID, r.iface, uptime)

	fmt.Fprintf(b, "traffic (rx via XDP)\n")
	fmt.Fprintf(b, "  pps total       : %15s\n", fmtNum(v.PPS))
	fmt.Fprintf(b, "  pps passed      : %15s\n", fmtNum(v.PPS-v.DPS))
	fmt.Fprintf(b, "  pps dropped     : %15s\n", fmtNum(v.DPS))
	fmt.Fprintf(b, "  rx total        : %15s\n", humanBits(v.BpsTotal))
	fmt.Fprintf(b, "  rx dropped      : %15s\n\n", humanBits(v.BpsDropped))

	fmt.Fprintf(b, "traffic (tx via kernel, not filtered by XDP)\n")
	fmt.Fprintf(b, "  tx              : %15s\n", humanBits(v.TxBps))
	fmt.Fprintf(b, "  tx pps          : %15s\n\n", fmtNum(v.TxPps))

	g := v.Global
	fmt.Fprintf(b, "protocols (since start)\n")
	fmt.Fprintf(b, "  tcp             :  pkts=%-14s bytes=%s\n", fmtU(g.PktsTCP), humanBytes(g.BytesTCP))
	fmt.Fprintf(b, "  udp             :  pkts=%-14s bytes=%s\n", fmtU(g.PktsUDP), humanBytes(g.BytesUDP))
	fmt.Fprintf(b, "  icmp            :  pkts=%-14s bytes=%s\n", fmtU(g.PktsICMP), humanBytes(g.BytesICMP))
	fmt.Fprintf(b, "  other           :  pkts=%-14s bytes=%s\n", fmtU(g.PktsOther), humanBytes(g.BytesOther))
	fmt.Fprintf(b, "  ipv6            :  pkts=%-14s bytes=%s\n\n", fmtU(g.PktsIPv6), humanBytes(g.BytesIPv6))

	fmt.Fprintf(b, "protocols (rate, last %s)\n", r.fastInterval)
	fmt.Fprintf(b, "  pps tcp         : %15s\n", fmtNum(v.PpsTCP))
	fmt.Fprintf(b, "  pps udp         : %15s\n", fmtNum(v.PpsUDP))
	fmt.Fprintf(b, "  pps icmp        : %15s\n\n", fmtNum(v.PpsICMP))

	fmt.Fprintf(b, "counters (since start)\n")
	fmt.Fprintf(b, "  packets total   : %15s\n", fmtU(g.PktsTotal))
	fmt.Fprintf(b, "  packets passed  : %15s\n", fmtU(g.PktsPassed))
	fmt.Fprintf(b, "  packets dropped : %15s\n", fmtU(g.PktsDropped))
	fmt.Fprintf(b, "  bytes total     : %15s\n", humanBytes(g.BytesTotal))
	fmt.Fprintf(b, "  bytes dropped   : %15s\n\n", humanBytes(g.BytesDropped))

	fmt.Fprintf(b, "drops by reason (since start)\n")
	fmt.Fprintf(b, "  non-ip          : %15s\n", fmtU(g.DropNonIP))
	fmt.Fprintf(b, "  malformed       : %15s\n", fmtU(g.DropMalformed))
	fmt.Fprintf(b, "  blocklist       : %15s\n", fmtU(g.DropBlocklist))
	fmt.Fprintf(b, "  not allowed     : %15s\n", fmtU(g.DropNotAllowed))
	fmt.Fprintf(b, "  no policy       : %15s\n\n", fmtU(g.DropNoPolicy))

	fmt.Fprintf(b, "passes by reason (since start)\n")
	fmt.Fprintf(b, "  arp             : %15s\n", fmtU(g.PassARP))
	fmt.Fprintf(b, "  ip fragment     : %15s\n", fmtU(g.PassFragment))
	fmt.Fprintf(b, "  tcp established : %15s\n", fmtU(g.PassTCPEst))
	fmt.Fprintf(b, "  udp flow        : %15s\n", fmtU(g.PassUDPFlow))
	fmt.Fprintf(b, "  dhcp            : %15s\n", fmtU(g.PassDHCP))
	fmt.Fprintf(b, "  icmp            : %15s\n", fmtU(g.PassICMP))
	fmt.Fprintf(b, "  public tcp      : %15s\n", fmtU(g.PassPublicTCP))
	fmt.Fprintf(b, "  public udp      : %15s\n", fmtU(g.PassPublicUDP))
	fmt.Fprintf(b, "  private tcp     : %15s\n", fmtU(g.PassPrivateTCP))
	fmt.Fprintf(b, "  private udp     : %15s\n\n", fmtU(g.PassPrivateUDP))

	fmt.Fprintf(b, "top %d source IPs (scan: %d entries / cap %d, %dms, at %s)\n",
		r.topN, r.scanSize, r.peripCap, r.scanMS,
		formatScanAge(v.Now, r.scanAt))
	fmt.Fprintf(b, "  %-4s %-39s %-12s %-12s %-10s %-6s %s\n",
		"#", "SRC_IP", "PKTS", "BYTES", "DROPPED", "PROTO", "STATUS")
	if len(r.topEntries) == 0 {
		fmt.Fprintf(b, "  (no traffic yet)\n")
	}
	for i, e := range r.topEntries {
		status := "pass"
		if e.Blocked {
			status = "BLOCK"
		}
		fmt.Fprintf(b, "  %-4d %-39s %-12s %-12s %-10s %-6s %s\n",
			i+1,
			formatAddr(e.Addr),
			fmtU(e.Pkts),
			humanBytes(e.Bytes),
			fmtU(e.PktsDropped),
			protoName(e.Proto),
			status,
		)
	}

	// Atomic replace so `watch` never sees a half-written file.
	// 0640: group-readable for operators, not world-readable.
	tmp := r.outPath + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o640); err != nil {
		fmt.Fprintf(os.Stderr, "stats write: %v\n", err)
		return
	}
	// WriteFile applies the process umask. Chmod pins 0640.
	if err := os.Chmod(tmp, 0o640); err != nil {
		fmt.Fprintf(os.Stderr, "stats chmod: %v\n", err)
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

func formatAddr(a netip.Addr) string {
	if !a.IsValid() {
		return "-"
	}
	return a.Unmap().String()
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1, 58:
		return "icmp"
	case 0:
		return "-"
	default:
		return fmt.Sprintf("%d", p)
	}
}

// reusePerIPScan skips the per-IP walk when the last walk succeeded and
// every summed counter is unchanged.
func reusePerIPScan(scanOK, hasPrev bool, prev, cur Global) bool {
	return scanOK && hasPrev && prev == cur
}

func fmtU(v uint64) string {
	var raw [20]byte
	return groupDigits(strconv.AppendUint(raw[:0], v, 10))
}

func fmtNum(v float64) string {
	var raw [64]byte
	return groupDigits(strconv.AppendFloat(raw[:0], v, 'f', 2, 64))
}

// groupDigits inserts thousands separators. The sign, if any, stays in the
// integer part, matching the previous grouping of "-1234.50" as "-1,234.50".
func groupDigits(s []byte) string {
	intPart, dec := s, []byte(nil)
	if i := bytes.IndexByte(s, '.'); i >= 0 {
		intPart, dec = s[:i], s[i:]
	}
	n := len(intPart)
	commas := 0
	if n > 3 {
		commas = (n - 1) / 3
	}
	need := n + commas + len(dec)
	var scratch [64]byte
	out := scratch[:0]
	if need <= len(scratch) {
		out = scratch[:need]
	} else {
		out = make([]byte, need)
	}
	if commas == 0 {
		copy(out, intPart)
		copy(out[n:], dec)
		return string(out)
	}
	pre := n % 3
	pos := 0
	if pre > 0 {
		copy(out, intPart[:pre])
		pos = pre
		out[pos] = ','
		pos++
	}
	for i := pre; i < n; i += 3 {
		copy(out[pos:], intPart[i:i+3])
		pos += 3
		if i+3 < n {
			out[pos] = ','
			pos++
		}
	}
	copy(out[pos:], dec)
	return string(out)
}

func humanBits(v float64) string {
	const (
		k = 1_000.0
		m = 1_000_000.0
		g = 1_000_000_000.0
	)
	var buf [32]byte
	switch {
	case v >= g:
		return string(appendPadFloat(buf[:0], v/g, " Gbps"))
	case v >= m:
		return string(appendPadFloat(buf[:0], v/m, " Mbps"))
	case v >= k:
		return string(appendPadFloat(buf[:0], v/k, " Kbps"))
	default:
		return string(appendPadFloat(buf[:0], v, " bps "))
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
	var buf [32]byte
	switch {
	case f >= t:
		return string(appendPadFloat(buf[:0], f/t, " TiB"))
	case f >= g:
		return string(appendPadFloat(buf[:0], f/g, " GiB"))
	case f >= m:
		return string(appendPadFloat(buf[:0], f/m, " MiB"))
	case f >= k:
		return string(appendPadFloat(buf[:0], f/k, " KiB"))
	default:
		return string(append(appendPadUint(buf[:0], v, 8), " B  "...))
	}
}

func appendPadFloat(dst []byte, v float64, suffix string) []byte {
	var tmp [32]byte
	s := strconv.AppendFloat(tmp[:0], v, 'f', 2, 64)
	for i := len(s); i < 8; i++ {
		dst = append(dst, ' ')
	}
	dst = append(dst, s...)
	return append(dst, suffix...)
}

func appendPadUint(dst []byte, v uint64, width int) []byte {
	var tmp [20]byte
	s := strconv.AppendUint(tmp[:0], v, 10)
	for i := len(s); i < width; i++ {
		dst = append(dst, ' ')
	}
	return append(dst, s...)
}

// Exported aliases for use by other packages (e.g. internal/tui).
// Kept as thin wrappers so the existing call-sites in this file keep
// their short, lower-case names.

// FormatCount renders an integer counter with thousands separators.
func FormatCount(v uint64) string { return fmtU(v) }

// FormatRate renders a floating-point rate with 2 decimals and commas.
func FormatRate(v float64) string { return fmtNum(v) }

// HumanBits renders bits-per-second with the appropriate unit suffix.
func HumanBits(v float64) string { return humanBits(v) }

// HumanBytes renders a byte count with the appropriate binary unit.
func HumanBytes(v uint64) string { return humanBytes(v) }

// ProtoName maps an IP protocol number to its short name.
func ProtoName(p uint8) string { return protoName(p) }
