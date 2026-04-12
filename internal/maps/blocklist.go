// Package maps provides Go wrappers around the eBPF maps shared with the XDP
// data plane. Blocklist is an LPM trie keyed on (prefixlen, ipv4 addr).
package maps

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

// lpmV4Key mirrors `struct lpm_v4_key` in bpf/xdp_filter.c.
// prefixlen is in host byte order; addr is in network byte order.
type lpmV4Key struct {
	Prefixlen uint32
	Addr      [4]byte
}

type Blocklist struct {
	m *ebpf.Map
}

func NewBlocklist(m *ebpf.Map) *Blocklist {
	return &Blocklist{m: m}
}

// Add inserts a CIDR into the blocklist. IPv6 prefixes return an error until
// an ipv6 trie is added.
func (b *Blocklist) Add(prefix netip.Prefix) error {
	key, err := keyFromPrefix(prefix)
	if err != nil {
		return err
	}
	val := uint8(1)
	if err := b.m.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("map update %s: %w", prefix, err)
	}
	return nil
}

func keyFromPrefix(p netip.Prefix) (lpmV4Key, error) {
	if !p.IsValid() {
		return lpmV4Key{}, fmt.Errorf("invalid prefix")
	}
	addr := p.Addr()
	if !addr.Is4() {
		return lpmV4Key{}, fmt.Errorf("ipv6 not yet supported: %s", p)
	}
	bits := p.Bits()
	if bits < 0 || bits > 32 {
		return lpmV4Key{}, fmt.Errorf("invalid prefix bits: %d", bits)
	}
	// Mask the address to the prefix length so callers can pass either
	// "1.2.3.4/24" or "1.2.3.0/24" and get the same key.
	// As4() returns the address in network byte order, which is what the
	// eBPF LPM trie expects for IPv4 keys.
	masked := p.Masked().Addr().As4()
	key := lpmV4Key{Prefixlen: uint32(bits)}
	copy(key.Addr[:], masked[:])
	return key, nil
}
