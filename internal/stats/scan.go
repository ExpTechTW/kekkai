package stats

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/ebpf"

	"github.com/ExpTechTW/kekkai/internal/maps"
)

// perIPBatch is how many LRU entries one BPF_MAP_LOOKUP_BATCH pulls.
// 4096 keeps a full-table walk to a handful of syscalls. The value scratch
// is this times the possible-CPU count, because perip is a per-CPU map.
const perIPBatch = 4096

// perIPKey is the perip LRU key: 16 bytes. IPv4 is stored IPv4-mapped.
type perIPKey [16]byte

// PerIPScan walks perip. Scratch buffers live for the life of the scanner
// so a tick does not allocate them again. Not safe for concurrent Walk/Top.
//
// perip is a per-CPU LRU hash: each lookup yields one maps.PerIPStat per
// possible CPU. vals is entry-major (entry i occupies vals[i*nCPU:(i+1)*nCPU]).
// perCPU is the iterate sink; it is passed by value so cilium fills it in
// place instead of allocating a fresh slice per entry.
type PerIPScan struct {
	keys    []perIPKey
	vals    []maps.PerIPStat
	perCPU  []maps.PerIPStat
	nCPU    int
	noBatch bool
}

func NewPerIPScan() *PerIPScan {
	nCPU := possibleCPUOr1()
	return &PerIPScan{
		keys:   make([]perIPKey, perIPBatch),
		vals:   make([]maps.PerIPStat, perIPBatch*nCPU),
		perCPU: make([]maps.PerIPStat, nCPU),
		nCPU:   nCPU,
	}
}

// possibleCPUOr1 is the kernel possible-CPU count used to size per-CPU
// scratch, or 1 when it can't be read (non-Linux tests, where the map is nil).
func possibleCPUOr1() int {
	if n, err := ebpf.PossibleCPU(); err == nil && n > 0 {
		return n
	}
	return 1
}

// CheckPerIPMap verifies a pinned perip handle matches the decoder: a per-CPU
// LRU hash whose key is 16 bytes and whose value is one maps.PerIPStat.
// A mismatch (old agent, or a shared hash) becomes a startup error instead of
// a per-tick "per-cpu value requires a slice" failure.
func CheckPerIPMap(m *ebpf.Map) error {
	if m == nil {
		return fmt.Errorf("perip map is nil")
	}
	if m.Type() != ebpf.LRUCPUHash {
		return fmt.Errorf("perip map type is %s, expected per-CPU LRU hash (agent/CLI build mismatch?)", m.Type())
	}
	if got, want := m.KeySize(), uint32(binary.Size(maps.PerIPKey{})); got != want {
		return fmt.Errorf("perip key size %d, decoder expects %d", got, want)
	}
	if got, want := m.ValueSize(), uint32(binary.Size(maps.PerIPStat{})); got != want {
		return fmt.Errorf("perip value size %d, decoder expects %d (struct layout drift)", got, want)
	}
	return nil
}

// FoldPerIP aggregates one source's per-CPU values. Counters sum, Blocked is
// OR-ed, and LastProto / LastSeenNS come from the CPU with the latest
// last_seen. Equal timestamps keep the earlier CPU.
func FoldPerIP(perCPU []maps.PerIPStat) maps.PerIPStat {
	var e maps.PerIPStat
	var newest uint64
	for i := range perCPU {
		c := &perCPU[i]
		e.Pkts += c.Pkts
		e.Bytes += c.Bytes
		e.PktsDropped += c.PktsDropped
		e.BytesDropped += c.BytesDropped
		if c.Blocked != 0 {
			e.Blocked = 1
		}
		if c.LastSeenNS > newest {
			newest = c.LastSeenNS
			e.LastSeenNS = c.LastSeenNS
			e.LastProto = c.LastProto
		}
	}
	return e
}

// Top returns per-IP rows ordered by packet count, highest first.
//
// limit > 0 keeps only that many rows and does not retain the rest.
// limit <= 0 returns every row. dst is reused when it has enough capacity;
// the returned slice is the one the caller should publish.
//
// total is the number of map entries visited, which can be larger than
// len(out) when limit is set.
func (s *PerIPScan) Top(m *ebpf.Map, limit int, dst []TopEntry) ([]TopEntry, int, error) {
	if m == nil {
		if dst == nil {
			return nil, 0, nil
		}
		return dst[:0], 0, nil
	}

	if limit > 0 {
		if cap(dst) < limit {
			dst = make([]TopEntry, limit)
		}
		dst = dst[:limit]
		n := 0
		total, err := s.walk(m, func(key perIPKey, v *maps.PerIPStat) {
			n = insertTop(dst, n, entryFrom(key, v))
		})
		if err != nil {
			return nil, total, err
		}
		return dst[:n], total, nil
	}

	dst = dst[:0]
	total, err := s.walk(m, func(key perIPKey, v *maps.PerIPStat) {
		dst = append(dst, entryFrom(key, v))
	})
	if err != nil {
		return nil, total, err
	}
	slices.SortFunc(dst, func(a, b TopEntry) int {
		if a.Pkts > b.Pkts {
			return -1
		}
		if a.Pkts < b.Pkts {
			return 1
		}
		return 0
	})
	return dst, total, nil
}

// insertTop keeps dst[:n] as the highest packet counts, descending.
// dst's length is the capacity of the ranking (the limit). Equal counts
// keep the row already in the ranking; sort.Slice was not stable either,
// so tie order was never part of the result.
func insertTop(dst []TopEntry, n int, e TopEntry) int {
	if n < len(dst) {
		i := n
		for i > 0 && dst[i-1].Pkts < e.Pkts {
			dst[i] = dst[i-1]
			i--
		}
		dst[i] = e
		return n + 1
	}
	if n == 0 || e.Pkts <= dst[n-1].Pkts {
		return n
	}
	i := n - 1
	for i > 0 && dst[i-1].Pkts < e.Pkts {
		dst[i] = dst[i-1]
		i--
	}
	dst[i] = e
	return n
}

func entryFrom(key perIPKey, v *maps.PerIPStat) TopEntry {
	return TopEntry{
		Addr:         netip.AddrFrom16(key).Unmap(),
		Pkts:         v.Pkts,
		Bytes:        v.Bytes,
		PktsDropped:  v.PktsDropped,
		BytesDropped: v.BytesDropped,
		Proto:        v.LastProto,
		Blocked:      v.Blocked != 0,
	}
}

func (s *PerIPScan) walk(m *ebpf.Map, fn func(perIPKey, *maps.PerIPStat)) (int, error) {
	if !s.noBatch {
		n, err := s.walkBatch(m, fn)
		if err == nil {
			return n, nil
		}
		if !errors.Is(err, ebpf.ErrNotSupported) {
			return n, err
		}
		// Kernel rejected the batch syscall. Fall back only when nothing
		// was consumed; otherwise the next tick retries with Iterate on
		// a clean buffer so rows are not duplicated.
		s.noBatch = true
		if n == 0 {
			return s.walkIter(m, fn)
		}
		return n, err
	}
	return s.walkIter(m, fn)
}

func (s *PerIPScan) walkBatch(m *ebpf.Map, fn func(perIPKey, *maps.PerIPStat)) (int, error) {
	total := 0
	var cursor ebpf.MapBatchCursor
	for {
		n, err := m.BatchLookup(&cursor, s.keys, s.vals, nil)
		for i := 0; i < n; i++ {
			folded := FoldPerIP(s.vals[i*s.nCPU : (i+1)*s.nCPU])
			fn(s.keys[i], &folded)
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

func (s *PerIPScan) walkIter(m *ebpf.Map, fn func(perIPKey, *maps.PerIPStat)) (int, error) {
	var key perIPKey
	iter := m.Iterate()
	n := 0
	// Pass the pre-sized slice (len == nCPU) by value so the lookup fills it
	// in place. Passing &slice makes cilium allocate a fresh slice on every
	// entry. A single PerIPStat is rejected with "per-cpu value requires a slice".
	for iter.Next(&key, s.perCPU) {
		folded := FoldPerIP(s.perCPU)
		fn(key, &folded)
		n++
	}
	return n, iter.Err()
}
