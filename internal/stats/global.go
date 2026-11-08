package stats

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// ReadGlobal sums the stats map with one lookup. The map is a per-CPU array
// whose only element (key 0) is [SlotCount]uint64 on each CPU.
//
// scratch is reused across ticks. It is grown to nCPU once and passed as a
// slice, so the lookup writes into the existing backing array.
func ReadGlobal(m *ebpf.Map, scratch *[]PerCPUCounters) (Global, error) {
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return Global{}, fmt.Errorf("possible cpus: %w", err)
	}
	buf := *scratch
	if cap(buf) < ncpu {
		buf = make([]PerCPUCounters, ncpu)
	} else {
		buf = buf[:ncpu]
	}
	key := uint32(0)
	if err := m.Lookup(&key, buf); err != nil {
		return Global{}, fmt.Errorf("lookup stats: %w", err)
	}
	*scratch = buf
	return aggregate(buf), nil
}

// aggregate sums each slot across CPUs and derives the packet totals once.
// Drop verdicts are [0, FirstPassVerdict). Pass verdicts are
// [FirstPassVerdict, VerdictCount). Traffic-mix and byte slots are not verdicts.
func aggregate(perCPU []PerCPUCounters) Global {
	var sum [SlotCount]uint64
	for i := range perCPU {
		for slot := range sum {
			sum[slot] += perCPU[i][slot]
		}
	}
	g := Global{
		DropNonIP:      sum[SlotDropNonIP],
		DropMalformed:  sum[SlotDropMalformed],
		DropBlocklist:  sum[SlotDropBlocklist],
		DropNotAllowed: sum[SlotDropNotAllowed],
		DropNoPolicy:   sum[SlotDropNoPolicy],

		PassARP:        sum[SlotPassARP],
		PassFragment:   sum[SlotPassFragment],
		PassTCPEst:     sum[SlotPassTCPEst],
		PassUDPFlow:    sum[SlotPassUDPFlow],
		PassDHCP:       sum[SlotPassDHCP],
		PassICMP:       sum[SlotPassICMP],
		PassPublicTCP:  sum[SlotPassPublicTCP],
		PassPublicUDP:  sum[SlotPassPublicUDP],
		PassPrivateTCP: sum[SlotPassPrivateTCP],
		PassPrivateUDP: sum[SlotPassPrivateUDP],

		PktsTCP:      sum[SlotPktsTCP],
		PktsUDP:      sum[SlotPktsUDP],
		PktsICMP:     sum[SlotPktsICMP],
		PktsOther:    sum[SlotPktsOther],
		BytesTCP:     sum[SlotBytesTCP],
		BytesUDP:     sum[SlotBytesUDP],
		BytesICMP:    sum[SlotBytesICMP],
		BytesOther:   sum[SlotBytesOther],
		PktsIPv6:     sum[SlotPktsIPv6],
		BytesIPv6:    sum[SlotBytesIPv6],
		BytesTotal:   sum[SlotBytesTotal],
		BytesDropped: sum[SlotBytesDropped],
	}
	for slot := 0; slot < FirstPassVerdict; slot++ {
		g.PktsDropped += sum[slot]
	}
	for slot := FirstPassVerdict; slot < VerdictCount; slot++ {
		g.PktsPassed += sum[slot]
	}
	g.PktsTotal = g.PktsDropped + g.PktsPassed
	return g
}

// PerSecond converts a counter delta into a rate. invDt is 1/seconds,
// so every rate in a tick shares one division.
func PerSecond(delta uint64, invDt float64) float64 {
	return float64(delta) * invDt
}

// BitsPerSecond is PerSecond for a byte counter, scaled to bits.
func BitsPerSecond(delta uint64, invDt float64) float64 {
	return float64(delta) * (8 * invDt)
}
