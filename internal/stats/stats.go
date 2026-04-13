// Package stats reads the eBPF maps populated by the XDP program, aggregates
// global/proto/drop-reason counters, walks the per-IP LRU map to compute a
// top-N table, reads tx counters from sysfs (XDP is ingress-only), and writes
// a human-readable snapshot to disk so operators can `watch -n 1 cat` it.
//
// The fast tick (writer) and the slow tick (top-N scan) run on independent
// goroutines and exchange results through an atomic pointer. All hot-path
// buffers are preallocated once at construction time so steady-state
// operation generates zero heap allocations per tick.
package stats

import (
	"errors"
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
	SlotPktsTotal    = 0
	SlotPktsPassed   = 1
	SlotPktsDropped  = 2
	SlotBytesTotal   = 3
	SlotBytesDropped = 4

	SlotPktsTCP      = 5
	SlotPktsUDP      = 6
	SlotPktsICMP     = 7
	SlotPktsOtherL4  = 8
	SlotBytesTCP     = 9
	SlotBytesUDP     = 10
	SlotBytesICMP    = 11
	SlotBytesOtherL4 = 12

	SlotDropNonIPv4    = 13
	SlotDropMalformed  = 14
	SlotDropBlocklist  = 15
	SlotDropDynBlock   = 16
	SlotDropNotAllowed = 17
	SlotDropNoPolicy   = 18

	SlotPassFragment   = 19
	SlotPassReturnTCP  = 20
	SlotPassReturnUDP  = 21
	SlotPassReturnICMP = 22
	SlotPassPublicTCP  = 23
	SlotPassPublicUDP  = 24
	SlotPassPrivateTCP = 25
	SlotPassPrivateUDP = 26

	SlotCount = 48
)

// Global mirrors the aggregated counters.
type Global struct {
	PktsTotal, PktsPassed, PktsDropped          uint64
	BytesTotal, BytesDropped                    uint64
	PktsTCP, PktsUDP, PktsICMP, PktsOtherL4     uint64
	BytesTCP, BytesUDP, BytesICMP, BytesOtherL4 uint64

	DropNonIPv4, DropMalformed, DropBlocklist uint64
	DropDynBlock, DropNotAllowed, DropNoPolicy uint64

	PassFragment, PassReturnTCP, PassReturnUDP, PassReturnICMP uint64
	PassPublicTCP, PassPublicUDP, PassPrivateTCP, PassPrivateUDP uint64
}

// perIPStat mirrors `struct perip_stat` in the eBPF program. Size: 48 bytes.
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

// TopEntry is one row of the sorted top-N table.
type TopEntry struct {
	Addr         [4]byte
	Pkts         uint64
	Bytes        uint64
	PktsDropped  uint64
	BytesDropped uint64
	Proto        uint8
	Blocked      bool
}

// topSnapshot is what the slow goroutine hands to the fast goroutine via
// atomic pointer swap. The Entries slice backs onto one of the two
// preallocated buffers owned by the Reader — never allocated per tick.
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
	peripCap     int

	startedAt time.Time

	// ----- fast path state (touched only by runFast goroutine) -----
	prev         Global
	prevAt       time.Time
	hasPrev      bool
	txBytesPath  string
	txPktsPath   string
	prevTxBytes  uint64
	prevTxPkts   uint64
	prevTxAt     time.Time
	hasPrevTx    bool
	globalPerCPU []uint64 // scratch for PERCPU_ARRAY lookups
	fileBuf      strings.Builder

	// ----- slow path state (touched only by runSlow goroutine) -----
	bufA, bufB       []TopEntry  // double-buffered top-N storage
	scanKeys         []uint32    // BatchLookup key scratch
	scanVals         []perIPStat // BatchLookup value scratch
	batchUnsupported bool        // fall back to Iterate if kernel rejects batch

	// ----- cross-goroutine handoff -----
	topPtr   atomic.Pointer[topSnapshot]
	snapshot [2]topSnapshot // preallocated headers, one per buffer
}

func NewReader(global, perip *ebpf.Map, nodeID, iface, outPath string) *Reader {
	peripCap := 0
	if perip != nil {
		peripCap = int(perip.MaxEntries())
	}
	if peripCap == 0 {
		peripCap = 65536 // fall back for stub/non-linux
	}

	// BatchLookup pulls at most `batchSize` entries per syscall. Larger
	// batches reduce syscall overhead but need bigger scratch buffers.
	// 4096 keeps scratch at ~200 KiB and fits the 1-iteration-per-second
	// cadence comfortably.
	const batchSize = 4096

	r := &Reader{
		global:       global,
		perip:        perip,
		nodeID:       nodeID,
		iface:        iface,
		outPath:      outPath,
		fastInterval: time.Second,
		slowInterval: time.Second,
		topN:         10,
		peripCap:     peripCap,
		startedAt:    time.Now(),
		txBytesPath:  fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", iface),
		txPktsPath:   fmt.Sprintf("/sys/class/net/%s/statistics/tx_packets", iface),
		globalPerCPU: make([]uint64, 0, 128),
		bufA:         make([]TopEntry, 0, peripCap),
		bufB:         make([]TopEntry, 0, peripCap),
		scanKeys:     make([]uint32, batchSize),
		scanVals:     make([]perIPStat, batchSize),
	}
	r.fileBuf.Grow(4096)
	return r
}

// Run launches fast and slow goroutines and blocks until `stop` closes.
func (r *Reader) Run(stop <-chan struct{}) error {
	if err := os.MkdirAll(filepath.Dir(r.outPath), 0o755); err != nil {
		return fmt.Errorf("mkdir stats dir: %w", err)
	}

	// Seed an empty snapshot so the writer has something to render.
	r.snapshot[0] = topSnapshot{Entries: r.bufA[:0]}
	r.topPtr.Store(&r.snapshot[0])

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
		if dt := now.Sub(r.prevAt).Seconds(); dt > 0 {
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
		if dt := now.Sub(r.prevTxAt).Seconds(); dt > 0 {
			txBps = float64(txBytes-r.prevTxBytes) * 8 / dt
			txPps = float64(txPkts-r.prevTxPkts) / dt
		}
	}
	r.prevTxBytes = txBytes
	r.prevTxPkts = txPkts
	r.prevTxAt = now
	r.hasPrevTx = true

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
		Top:        r.topPtr.Load(),
	})
}

func (r *Reader) readGlobal() (Global, error) {
	var g Global
	for slot := uint32(0); slot < SlotCount; slot++ {
		// Reuse the scratch slice; cilium/ebpf will resize it to nCPU on
		// first call and then keep that length.
		r.globalPerCPU = r.globalPerCPU[:0]
		if err := r.global.Lookup(&slot, &r.globalPerCPU); err != nil {
			return g, fmt.Errorf("lookup slot %d: %w", slot, err)
		}
		var sum uint64
		for _, v := range r.globalPerCPU {
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
		case SlotDropNonIPv4:
			g.DropNonIPv4 = sum
		case SlotDropMalformed:
			g.DropMalformed = sum
		case SlotDropBlocklist:
			g.DropBlocklist = sum
		case SlotDropDynBlock:
			g.DropDynBlock = sum
		case SlotDropNotAllowed:
			g.DropNotAllowed = sum
		case SlotDropNoPolicy:
			g.DropNoPolicy = sum
		case SlotPassFragment:
			g.PassFragment = sum
		case SlotPassReturnTCP:
			g.PassReturnTCP = sum
		case SlotPassReturnUDP:
			g.PassReturnUDP = sum
		case SlotPassReturnICMP:
			g.PassReturnICMP = sum
		case SlotPassPublicTCP:
			g.PassPublicTCP = sum
		case SlotPassPublicUDP:
			g.PassPublicUDP = sum
		case SlotPassPrivateTCP:
			g.PassPrivateTCP = sum
		case SlotPassPrivateUDP:
			g.PassPrivateUDP = sum
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

	// Pick the buffer that isn't currently published. The writer holds the
	// other one read-only until we swap.
	active := r.topPtr.Load()
	var next *topSnapshot
	var buf *[]TopEntry
	if active == &r.snapshot[0] {
		next = &r.snapshot[1]
		buf = &r.bufB
	} else {
		next = &r.snapshot[0]
		buf = &r.bufA
	}
	*buf = (*buf)[:0]

	scanSize, err := r.scanPerIP(buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stats perip scan: %v\n", err)
		return
	}

	entries := *buf
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Pkts > entries[j].Pkts
	})
	if len(entries) > r.topN {
		entries = entries[:r.topN]
	}

	next.Entries = entries
	next.ScanAt = time.Now()
	next.ScanSize = scanSize
	next.ScanMS = time.Since(start).Milliseconds()
	r.topPtr.Store(next)
}

// scanPerIP walks the LRU hash with BatchLookup when the kernel supports it
// (Linux 5.6+) and falls back to Iterate otherwise. Both paths append into
// the caller-provided buffer without allocating per-entry.
func (r *Reader) scanPerIP(buf *[]TopEntry) (int, error) {
	if r.perip == nil {
		return 0, nil
	}
	if !r.batchUnsupported {
		n, err := r.scanPerIPBatch(buf)
		if err == nil {
			return n, nil
		}
		if !errors.Is(err, ebpf.ErrNotSupported) {
			return n, err
		}
		r.batchUnsupported = true
		// fall through to Iterate
	}
	return r.scanPerIPIterate(buf)
}

func (r *Reader) scanPerIPBatch(buf *[]TopEntry) (int, error) {
	total := 0
	cursor := ebpf.MapBatchCursor{}
	for {
		n, err := r.perip.BatchLookup(&cursor, r.scanKeys, r.scanVals, nil)
		for i := 0; i < n; i++ {
			appendEntry(buf, r.scanKeys[i], &r.scanVals[i])
		}
		total += n
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func (r *Reader) scanPerIPIterate(buf *[]TopEntry) (int, error) {
	var key uint32
	var val perIPStat
	iter := r.perip.Iterate()
	n := 0
	for iter.Next(&key, &val) {
		appendEntry(buf, key, &val)
		n++
	}
	return n, iter.Err()
}

// appendEntry translates one eBPF perIPStat into a TopEntry and appends to
// the provided buffer. The buffer must have enough capacity to avoid
// reallocation — callers guarantee this by sizing to perip_max_entries.
func appendEntry(buf *[]TopEntry, key uint32, val *perIPStat) {
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
	*buf = append(*buf, e)
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
	Top                     *topSnapshot
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
	fmt.Fprintf(b, "  other l4        :  pkts=%-14s bytes=%s\n\n", fmtU(g.PktsOtherL4), humanBytes(g.BytesOtherL4))

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
	fmt.Fprintf(b, "  non-ipv4        : %15s\n", fmtU(g.DropNonIPv4))
	fmt.Fprintf(b, "  malformed       : %15s\n", fmtU(g.DropMalformed))
	fmt.Fprintf(b, "  blocklist       : %15s\n", fmtU(g.DropBlocklist))
	fmt.Fprintf(b, "  dyn blocklist   : %15s\n", fmtU(g.DropDynBlock))
	fmt.Fprintf(b, "  not allowed     : %15s\n", fmtU(g.DropNotAllowed))
	fmt.Fprintf(b, "  no policy       : %15s\n\n", fmtU(g.DropNoPolicy))

	fmt.Fprintf(b, "passes by reason (since start)\n")
	fmt.Fprintf(b, "  return tcp (ACK): %15s\n", fmtU(g.PassReturnTCP))
	fmt.Fprintf(b, "  return udp (eph): %15s\n", fmtU(g.PassReturnUDP))
	fmt.Fprintf(b, "  return icmp     : %15s\n", fmtU(g.PassReturnICMP))
	fmt.Fprintf(b, "  ip fragment     : %15s\n", fmtU(g.PassFragment))
	fmt.Fprintf(b, "  public tcp      : %15s\n", fmtU(g.PassPublicTCP))
	fmt.Fprintf(b, "  public udp      : %15s\n", fmtU(g.PassPublicUDP))
	fmt.Fprintf(b, "  private tcp     : %15s\n", fmtU(g.PassPrivateTCP))
	fmt.Fprintf(b, "  private udp     : %15s\n\n", fmtU(g.PassPrivateUDP))

	top := v.Top
	if top != nil {
		fmt.Fprintf(b, "top %d source IPs (scan: %d entries / cap %d, %dms, at %s)\n",
			r.topN, top.ScanSize, r.peripCap, top.ScanMS,
			formatScanAge(v.Now, top.ScanAt))
		fmt.Fprintf(b, "  %-4s %-16s %-12s %-12s %-10s %-6s %s\n",
			"#", "SRC_IP", "PKTS", "BYTES", "DROPPED", "PROTO", "STATUS")
		if len(top.Entries) == 0 {
			fmt.Fprintf(b, "  (no traffic yet)\n")
		}
		for i, e := range top.Entries {
			status := "pass"
			if e.Blocked {
				status = "BLOCK"
			}
			fmt.Fprintf(b, "  %-4d %-16s %-12s %-12s %-10s %-6s %s\n",
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
