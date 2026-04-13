// Package maps provides Go wrappers around the eBPF maps shared with the XDP
// data plane. Each wrapper encapsulates the key/value layout for its map and
// exposes typed Sync / Add operations.
package maps

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

// lpmV4Key mirrors `struct lpm_v4_key` in bpf/xdp_filter.c. Prefixlen is in
// host byte order; addr is in network byte order.
type lpmV4Key struct {
	Prefixlen uint32
	Addr      [4]byte
}

// PrefixSet is a wrapper around an LPM_TRIE map keyed on (prefixlen, IPv4).
// Used for blocklist_v4 and allowlist_v4 — same shape, different semantics.
type PrefixSet struct {
	m    *ebpf.Map
	name string
}

func NewPrefixSet(m *ebpf.Map, name string) *PrefixSet {
	return &PrefixSet{m: m, name: name}
}

func (s *PrefixSet) Add(p netip.Prefix) error {
	key, err := keyFromPrefix(p)
	if err != nil {
		return err
	}
	val := uint8(1)
	if err := s.m.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("%s add %s: %w", s.name, p, err)
	}
	return nil
}

func (s *PrefixSet) Delete(p netip.Prefix) error {
	key, err := keyFromPrefix(p)
	if err != nil {
		return err
	}
	if err := s.m.Delete(key); err != nil {
		return fmt.Errorf("%s delete %s: %w", s.name, p, err)
	}
	return nil
}

// Sync reconciles the map contents with the desired set. Entries not in
// `desired` are removed; missing entries are added. Used by config reload.
func (s *PrefixSet) Sync(desired []netip.Prefix) error {
	want := make(map[lpmV4Key]struct{}, len(desired))
	for _, p := range desired {
		key, err := keyFromPrefix(p)
		if err != nil {
			return err
		}
		want[key] = struct{}{}
	}

	// Collect current keys first so we don't mutate while iterating.
	var current []lpmV4Key
	{
		var key lpmV4Key
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

func keyFromPrefix(p netip.Prefix) (lpmV4Key, error) {
	if !p.IsValid() {
		return lpmV4Key{}, fmt.Errorf("invalid prefix")
	}
	if !p.Addr().Is4() {
		return lpmV4Key{}, fmt.Errorf("ipv6 not supported: %s", p)
	}
	bits := p.Bits()
	if bits < 0 || bits > 32 {
		return lpmV4Key{}, fmt.Errorf("invalid prefix bits: %d", bits)
	}
	masked := p.Masked().Addr().As4()
	key := lpmV4Key{Prefixlen: uint32(bits)}
	copy(key.Addr[:], masked[:])
	return key, nil
}

