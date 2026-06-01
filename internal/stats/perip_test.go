package stats

import "testing"

// TestAppendEntryPerCPU verifies the per-CPU fold used to read the per-CPU
// perip_v4 map: counters sum across CPUs, Blocked OR-s, and Proto comes from
// the CPU with the freshest last_seen.
func TestAppendEntryPerCPU(t *testing.T) {
	perCPU := []perIPStat{
		{Pkts: 10, Bytes: 100, PktsDropped: 1, BytesDropped: 10, LastSeenNS: 5, LastProto: 6, Blocked: 0}, // cpu0: TCP
		{Pkts: 0, Bytes: 0}, // cpu1: idle
		{Pkts: 3, Bytes: 30, PktsDropped: 3, BytesDropped: 30, LastSeenNS: 9, LastProto: 17, Blocked: 1}, // cpu2: UDP, newest, blocked
	}
	var buf []TopEntry
	// 1.2.3.4 in network byte order little-endian key.
	key := uint32(0x04030201)
	appendEntry(&buf, key, perCPU)

	if len(buf) != 1 {
		t.Fatalf("len(buf)=%d, want 1", len(buf))
	}
	e := buf[0]
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
	if e.Addr != [4]byte{1, 2, 3, 4} {
		t.Errorf("Addr = %v, want [1 2 3 4]", e.Addr)
	}
}

// TestAppendEntryAllIdle confirms an entry that exists but saw no traffic on
// any CPU still folds cleanly to a zero row.
func TestAppendEntryAllIdle(t *testing.T) {
	var buf []TopEntry
	appendEntry(&buf, 0, []perIPStat{{}, {}})
	if len(buf) != 1 || buf[0].Pkts != 0 || buf[0].Blocked {
		t.Fatalf("idle fold = %+v, want zero row", buf)
	}
}
