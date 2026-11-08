package stats

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/ExpTechTW/kekkai/internal/maps"
)

func TestInsertTopMatchesFullRank(t *testing.T) {
	entries := []TopEntry{
		{Pkts: 3}, {Pkts: 10}, {Pkts: 7}, {Pkts: 1}, {Pkts: 8}, {Pkts: 4}, {Pkts: 10},
	}
	top := make([]TopEntry, 3)
	n := 0
	for _, e := range entries {
		n = insertTop(top, n, e)
	}
	top = top[:n]
	if n != 3 || top[0].Pkts != 10 || top[1].Pkts != 10 || top[2].Pkts != 8 {
		t.Fatalf("got %+v", top)
	}
}

func TestInsertTopKeepsShorterInput(t *testing.T) {
	top := make([]TopEntry, 5)
	n := insertTop(top, 0, TopEntry{Pkts: 2})
	n = insertTop(top, n, TopEntry{Pkts: 9})
	if n != 2 || top[0].Pkts != 9 || top[1].Pkts != 2 {
		t.Fatalf("n=%d top=%+v", n, top[:n])
	}
}

func TestPerSecondSharesOneScale(t *testing.T) {
	const inv = 2.0 // dt = 0.5s
	if got := PerSecond(5, inv); got != 10 {
		t.Fatalf("pps %v", got)
	}
	if got := BitsPerSecond(5, inv); got != 80 {
		t.Fatalf("bps %v", got)
	}
}

func TestSlotConstantsMatchDataPlane(t *testing.T) {
	if SlotCount != 27 || VerdictCount != 15 || FirstPassVerdict != SlotPassARP {
		t.Fatalf("count=%d verdicts=%d firstPass=%d arp=%d",
			SlotCount, VerdictCount, FirstPassVerdict, SlotPassARP)
	}
	if SlotDropNonIP != 0 || SlotPassARP != 5 || SlotPassPrivateUDP != 14 {
		t.Fatalf("drop=%d arp=%d lastPass=%d", SlotDropNonIP, SlotPassARP, SlotPassPrivateUDP)
	}
	if SlotPktsTCP != VerdictCount || SlotBytesDropped != SlotCount-1 {
		t.Fatalf("pktsTCP=%d bytesDropped=%d", SlotPktsTCP, SlotBytesDropped)
	}
	if unsafe.Sizeof(PerCPUCounters{}) != SlotCount*8 {
		t.Fatalf("per-cpu value %d bytes", unsafe.Sizeof(PerCPUCounters{}))
	}
	if unsafe.Sizeof(maps.PerIPStat{}) != 48 || unsafe.Sizeof(perIPKey{}) != 16 {
		t.Fatalf("perip stat %d key %d", unsafe.Sizeof(maps.PerIPStat{}), unsafe.Sizeof(perIPKey{}))
	}
}

func TestAggregateSumsPerCPUAndDerivesTotals(t *testing.T) {
	var cpu0, cpu1 PerCPUCounters
	cpu0[SlotDropBlocklist] = 3
	cpu0[SlotDropNonIP] = 1
	cpu0[SlotPassUDPFlow] = 10
	cpu0[SlotPassARP] = 2
	cpu0[SlotPktsTCP] = 100
	cpu0[SlotBytesTotal] = 1000
	cpu0[SlotPktsIPv6] = 7

	cpu1[SlotDropNonIP] = 4
	cpu1[SlotPassTCPEst] = 5
	cpu1[SlotPassUDPFlow] = 2
	cpu1[SlotPktsIPv6] = 8
	cpu1[SlotBytesDropped] = 40

	g := aggregate([]PerCPUCounters{cpu0, cpu1})

	// Drops: non-ip 1+4, blocklist 3. Passes: arp 2, tcp est 5, udp flow 10+2.
	if g.PktsDropped != 8 || g.PktsPassed != 19 || g.PktsTotal != 27 {
		t.Fatalf("dropped=%d passed=%d total=%d", g.PktsDropped, g.PktsPassed, g.PktsTotal)
	}
	if g.DropNonIP != 5 || g.DropBlocklist != 3 || g.PassUDPFlow != 12 || g.PassTCPEst != 5 || g.PassARP != 2 {
		t.Fatalf("slots %+v", g)
	}
	// Traffic mix and byte counters stay out of the verdict totals.
	if g.PktsTCP != 100 || g.BytesTotal != 1000 || g.PktsIPv6 != 15 || g.BytesDropped != 40 {
		t.Fatalf("traffic counters folded into verdicts: %+v", g)
	}
	if g.PktsTotal != g.PktsDropped+g.PktsPassed {
		t.Fatalf("total %d != dropped+passed", g.PktsTotal)
	}
}

func TestEntryFromUnmapsIPv4(t *testing.T) {
	var mapped perIPKey
	mapped[10], mapped[11] = 0xff, 0xff
	mapped[12], mapped[13], mapped[14], mapped[15] = 1, 2, 3, 4
	e := entryFrom(mapped, &maps.PerIPStat{Pkts: 9, LastProto: 6, Blocked: 1})
	want := netip.MustParseAddr("1.2.3.4")
	if e.Addr != want || !e.Addr.Is4() {
		t.Fatalf("addr %s is4=%v", e.Addr, e.Addr.Is4())
	}
	if !e.Blocked || e.Proto != 6 || e.Pkts != 9 {
		t.Fatalf("%+v", e)
	}

	v6 := perIPKey(netip.MustParseAddr("2001:db8::1").As16())
	if got := entryFrom(v6, &maps.PerIPStat{}); got.Addr != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("v6 %s", got.Addr)
	}
}

func TestWriteFileLabelsAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.txt")
	r := &Reader{
		outPath:   path,
		nodeID:    "n",
		iface:     "eth0",
		startedAt: time.Now(),
		topEntries: []TopEntry{{
			Addr:  netip.MustParseAddr("2001:db8::1"),
			Pkts:  1,
			Proto: 58,
		}},
	}
	r.writeFile(snapshotView{
		Now: time.Now(),
		Global: Global{
			PktsIPv6:    3,
			PassTCPEst:  4,
			PassUDPFlow: 5,
			PassDHCP:    6,
			PassICMP:    7,
			PassARP:     8,
			DropNonIP:   2,
			PktsDropped: 2,
			PktsPassed:  30,
			PktsTotal:   32,
			PktsOther:   9,
		},
	})
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %o, want 0640", st.Mode().Perm())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"ipv6", "tcp established", "udp flow", "dhcp", "icmp", "arp",
		"non-ip", "other", "2001:db8::1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q\n%s", want, text)
		}
	}
	for _, bad := range []string{"dyn blocklist", "stateful", "non-ipv4", "other l4"} {
		if strings.Contains(text, bad) {
			t.Fatalf("snapshot still contains %q", bad)
		}
	}
}

func TestReusePerIPScan(t *testing.T) {
	g := Global{PktsTotal: 4, BytesTotal: 9}
	if !reusePerIPScan(true, true, g, g) {
		t.Fatal("idle counters should skip the walk")
	}
	if reusePerIPScan(false, true, g, g) {
		t.Fatal("a failed walk must be retried")
	}
	if reusePerIPScan(true, false, g, g) {
		t.Fatal("the first sample has no previous walk")
	}
	moved := g
	moved.PktsDropped = 1
	if reusePerIPScan(true, true, g, moved) {
		t.Fatal("a changed counter must rescan")
	}
}

func TestFormatGolden(t *testing.T) {
	counts := []struct {
		v    uint64
		want string
	}{
		{0, "0"},
		{12, "12"},
		{999, "999"},
		{1000, "1,000"},
		{1234567, "1,234,567"},
	}
	for _, c := range counts {
		if got := fmtU(c.v); got != c.want {
			t.Errorf("fmtU(%d)=%q want %q", c.v, got, c.want)
		}
	}
	rates := []struct {
		v    float64
		want string
	}{
		{0, "0.00"},
		{1.2, "1.20"},
		{12.3, "12.30"},
		{1234.5, "1,234.50"},
		{-1234.5, "-1,234.50"},
		{-123, "-,123.00"},
		{999.99, "999.99"},
		{1500, "1,500.00"},
	}
	for _, c := range rates {
		if got := fmtNum(c.v); got != c.want {
			t.Errorf("fmtNum(%v)=%q want %q", c.v, got, c.want)
		}
	}
	bits := []struct {
		v    float64
		want string
	}{
		{0, "    0.00 bps "},
		{1.2, "    1.20 bps "},
		{12.3, "   12.30 bps "},
		{999.99, "  999.99 bps "},
		{1234.5, "    1.23 Kbps"},
		{1500, "    1.50 Kbps"},
		{1.5e6, "    1.50 Mbps"},
		{2.5e9, "    2.50 Gbps"},
	}
	for _, c := range bits {
		if got := humanBits(c.v); got != c.want {
			t.Errorf("humanBits(%v)=%q want %q", c.v, got, c.want)
		}
	}
	bytes := []struct {
		v    uint64
		want string
	}{
		{0, "       0 B  "},
		{12, "      12 B  "},
		{1023, "    1023 B  "},
		{1024, "    1.00 KiB"},
		{1536, "    1.50 KiB"},
		{5 << 20, "    5.00 MiB"},
		{5 << 30, "    5.00 GiB"},
		{5 << 40, "    5.00 TiB"},
	}
	for _, c := range bytes {
		if got := humanBytes(c.v); got != c.want {
			t.Errorf("humanBytes(%d)=%q want %q", c.v, got, c.want)
		}
	}
}

func TestFormatMatchesPreviousGrouping(t *testing.T) {
	for _, v := range []uint64{0, 1, 12, 999, 1000, 999999, 1000000, 1 << 32, ^uint64(0)} {
		if got, want := fmtU(v), previousCommas(strconv.FormatUint(v, 10)); got != want {
			t.Fatalf("fmtU(%d)=%q want %q", v, got, want)
		}
	}
	for _, v := range []float64{-1e20, -1234567.891, -123, -12.3, -1.2, 0, 1.005, 12.3, 999.994, 1234.5, 9999999.99, 1e15, 1e20} {
		raw := strconv.FormatFloat(v, 'f', 2, 64)
		if got, want := fmtNum(v), previousCommas(raw); got != want {
			t.Fatalf("fmtNum(%v)=%q want %q", v, got, want)
		}
	}
	for _, v := range []float64{-1.5, 0, 12.3, 999.994, 1000, 1500, 999999, 1.5e6, 2.5e9, 1e12} {
		if got, want := humanBits(v), previousBits(v); got != want {
			t.Fatalf("humanBits(%v)=%q want %q", v, got, want)
		}
	}
	for _, v := range []uint64{0, 12, 1023, 1024, 1536, 5 << 20, 5 << 30, 5 << 40, ^uint64(0)} {
		if got, want := humanBytes(v), previousBytes(v); got != want {
			t.Fatalf("humanBytes(%d)=%q want %q", v, got, want)
		}
	}
}

func previousCommas(s string) string {
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

func previousBits(v float64) string {
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

func previousBytes(v uint64) string {
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
