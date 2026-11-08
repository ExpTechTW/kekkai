package stats

import (
	"net/netip"
	"testing"

	"github.com/ExpTechTW/kekkai/internal/maps"
)

// TestFoldPerIPPerCPU verifies the per-CPU fold used to read the perip map:
// counters sum across CPUs, Blocked OR-s, and Proto comes from the CPU with
// the freshest last_seen. The key is the 16-byte IPv4-mapped form.
func TestFoldPerIPPerCPU(t *testing.T) {
	perCPU := []maps.PerIPStat{
		{Pkts: 10, Bytes: 100, PktsDropped: 1, BytesDropped: 10, LastSeenNS: 5, LastProto: 6, Blocked: 0}, // cpu0: TCP
		{Pkts: 0, Bytes: 0}, // cpu1: idle
		{Pkts: 3, Bytes: 30, PktsDropped: 3, BytesDropped: 30, LastSeenNS: 9, LastProto: 17, Blocked: 1}, // cpu2: UDP, newest, blocked
	}
	// ::ffff:1.2.3.4
	var key perIPKey
	key[10], key[11] = 0xff, 0xff
	key[12], key[13], key[14], key[15] = 1, 2, 3, 4
	folded := FoldPerIP(perCPU)
	e := entryFrom(key, &folded)

	if e.Pkts != 13 || e.Bytes != 130 {
		t.Errorf("sum pkts/bytes = %d/%d, want 13/130", e.Pkts, e.Bytes)
	}
	if e.PktsDropped != 4 || e.BytesDropped != 40 {
		t.Errorf("sum dropped = %d/%d, want 4/40", e.PktsDropped, e.BytesDropped)
	}
	if !e.Blocked {
		t.Error("Blocked = false, want true (OR across CPUs)")
	}
	if e.Proto != 17 {
		t.Errorf("Proto = %d, want 17 (from freshest last_seen)", e.Proto)
	}
	want := netip.MustParseAddr("1.2.3.4")
	if e.Addr != want || !e.Addr.Is4() {
		t.Errorf("Addr = %v is4=%v, want %v", e.Addr, e.Addr.Is4(), want)
	}
}

// TestFoldPerIPAllIdle confirms an entry that exists but saw no traffic on
// any CPU still folds cleanly to a zero row. The key is v4-mapped 0.0.0.0.
func TestFoldPerIPAllIdle(t *testing.T) {
	var key perIPKey
	key[10], key[11] = 0xff, 0xff
	folded := FoldPerIP([]maps.PerIPStat{{}, {}})
	e := entryFrom(key, &folded)
	if e.Pkts != 0 || e.Blocked || e.Proto != 0 {
		t.Fatalf("idle fold = %+v, want zero row", e)
	}
	if e.Addr != netip.MustParseAddr("0.0.0.0") {
		t.Fatalf("Addr = %v, want 0.0.0.0", e.Addr)
	}
}
