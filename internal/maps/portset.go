package maps

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
)

// PortSet wraps a HASH map keyed on a big-endian __u16 dst port. eBPF reads
// `tcphdr->dest` directly which is already in network byte order, so the Go
// side must match.
type PortSet struct {
	m    *ebpf.Map
	name string
}

func NewPortSet(m *ebpf.Map, name string) *PortSet {
	return &PortSet{m: m, name: name}
}

// Sync reconciles the map contents with the desired ports.
func (s *PortSet) Sync(desired []uint16) error {
	want := make(map[uint16]struct{}, len(desired))
	for _, p := range desired {
		want[htons(p)] = struct{}{}
	}

	var current []uint16
	{
		var key uint16
		var val uint8
		iter := s.m.Iterate()
		for iter.Next(&key, &val) {
			current = append(current, key)
		}
		if err := iter.Err(); err != nil {
			return fmt.Errorf("%s iterate: %w", s.name, err)
		}
	}

	for _, k := range current {
		if _, keep := want[k]; !keep {
			if err := s.m.Delete(k); err != nil {
				return fmt.Errorf("%s prune: %w", s.name, err)
			}
		}
	}
	val := uint8(1)
	for k := range want {
		if err := s.m.Update(k, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%s add: %w", s.name, err)
		}
	}
	return nil
}

// htons converts a host-order port number to the eBPF key format (network
// byte order). We pack it into a little-endian uint16 view of the two
// big-endian bytes so that cilium/ebpf writes them verbatim to the kernel.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.LittleEndian.Uint16(b[:])
}
