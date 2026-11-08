package maps

// Layout mirrors of the eBPF map values userspace does not write.
// Sizes must match bpf/xdp_filter.c so a CollectionSpec check can compare
// binary.Size of these structs with the object.

// StatsSlots is the length of struct counters.c (STAT_SLOTS).
const StatsSlots = 27

// StatsCounters is the value of the stats per-CPU array (key 0).
type StatsCounters struct {
	C [StatsSlots]uint64
}

// PerIPKey is the perip LRU key: a 16-byte address. IPv4 is stored
// IPv4-mapped (::ffff:a.b.c.d), the same width as an IPv6 address.
type PerIPKey [16]byte

// PerIPStat mirrors struct perip_stat. The data plane writes it; the
// layout is unchanged from the previous program (48 bytes).
type PerIPStat struct {
	Pkts         uint64
	Bytes        uint64
	PktsDropped  uint64
	BytesDropped uint64
	LastSeenNS   uint64
	LastProto    uint8
	Blocked      uint8
	Pad          [6]uint8
}
