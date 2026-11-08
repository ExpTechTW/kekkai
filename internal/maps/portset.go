package maps

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
)

// PortsMaxEntries is the ports map capacity (PORTS_MAX in bpf/xdp_filter.c).
const PortsMaxEntries = 4096

const (
	// ProtoTCP and ProtoUDP are the IP protocol numbers stored in PortKey.
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17

	// PortClassPublic and PortClassPrivate are the ports map values.
	PortClassPublic  uint8 = 1
	PortClassPrivate uint8 = 2
)

// PortKey is the HASH key of the ports map. Port is big-endian on the
// wire, matching tcphdr/udphdr port fields. Pad keeps the key 4 bytes.
type PortKey struct {
	Port  [2]byte
	Proto uint8
	Pad   uint8
}

func portKey(port uint16, proto uint8) PortKey {
	var k PortKey
	binary.BigEndian.PutUint16(k.Port[:], port)
	k.Proto = proto
	return k
}

// PortTable wraps the single ports map. Each entry is a destination port
// plus protocol, valued as public or private.
type PortTable struct {
	m    *ebpf.Map
	name string
}

func NewPortTable(m *ebpf.Map, name string) *PortTable {
	return &PortTable{m: m, name: name}
}

// Sync reconciles the map with the four configured port lists. Entries
// whose class changed, and entries that are missing, are written first;
// keys that are no longer wanted are deleted afterwards. An entry whose
// class is already correct is not rewritten.
func (t *PortTable) Sync(pubTCP, pubUDP, privTCP, privUDP []uint16) error {
	want, err := t.desired(pubTCP, pubUDP, privTCP, privUDP)
	if err != nil {
		return err
	}

	current := make(map[PortKey]uint8, len(want))
	var key PortKey
	var val uint8
	iter := t.m.Iterate()
	for iter.Next(&key, &val) {
		current[key] = val
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("%s iterate: %w", t.name, err)
	}

	for k, class := range want {
		if have, ok := current[k]; ok && have == class {
			continue
		}
		if err := t.m.Update(k, class, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%s update: %w", t.name, err)
		}
	}
	for k := range current {
		if _, keep := want[k]; keep {
			continue
		}
		if err := t.m.Delete(k); err != nil {
			return fmt.Errorf("%s prune: %w", t.name, err)
		}
	}
	return nil
}

// desired builds the wanted key set. It does not touch the map, so a
// conflict or a capacity error leaves the map unchanged.
func (t *PortTable) desired(pubTCP, pubUDP, privTCP, privUDP []uint16) (map[PortKey]uint8, error) {
	n := len(pubTCP) + len(pubUDP) + len(privTCP) + len(privUDP)
	want := make(map[PortKey]uint8, n)
	add := func(ports []uint16, proto, class uint8) error {
		for _, p := range ports {
			k := portKey(p, proto)
			if prev, ok := want[k]; ok && prev != class {
				return fmt.Errorf("%s: port %d proto %d is both public and private", t.name, p, proto)
			}
			want[k] = class
		}
		return nil
	}
	if err := add(pubTCP, ProtoTCP, PortClassPublic); err != nil {
		return nil, err
	}
	if err := add(pubUDP, ProtoUDP, PortClassPublic); err != nil {
		return nil, err
	}
	if err := add(privTCP, ProtoTCP, PortClassPrivate); err != nil {
		return nil, err
	}
	if err := add(privUDP, ProtoUDP, PortClassPrivate); err != nil {
		return nil, err
	}
	if len(want) > PortsMaxEntries {
		return nil, fmt.Errorf("%s: %d entries exceed map capacity %d", t.name, len(want), PortsMaxEntries)
	}
	return want, nil
}
