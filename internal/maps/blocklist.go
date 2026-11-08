// Package maps provides Go wrappers around the eBPF maps shared with the XDP
// data plane. Each wrapper encapsulates the key/value layout for its map and
// exposes typed Sync operations.
package maps

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

// v4MappedBits is the IPv6 prefix length of the IPv4-mapped range
// (::ffff:0:0/96). An IPv4 prefix /n is stored as /(96+n).
const v4MappedBits = 96

// LPMKey is the LPM_TRIE key shared by blocklist and allowlist.
// Prefixlen is host byte order; Addr is network order. IPv4 is stored
// IPv4-mapped (::ffff:a.b.c.d) with Prefixlen = 96+n.
type LPMKey struct {
	Prefixlen uint32
	Addr      [16]byte
}

// PrefixSet is a wrapper around an LPM_TRIE map keyed on LPMKey.
// Used for blocklist and allowlist — same shape, different semantics.
type PrefixSet struct {
	m    *ebpf.Map
	name string
}

func NewPrefixSet(m *ebpf.Map, name string) *PrefixSet {
	return &PrefixSet{m: m, name: name}
}

// Sync reconciles the map with desired. Missing keys are inserted first and
// extras are deleted after that, so an entry that is in both sets is never
// absent. Keys that already exist are left untouched.
func (s *PrefixSet) Sync(desired []netip.Prefix) error {
	want := make(map[LPMKey]struct{}, len(desired))
	for _, p := range desired {
		key, err := KeyFromPrefix(p)
		if err != nil {
			return err
		}
		want[key] = struct{}{}
	}

	current := make(map[LPMKey]struct{}, len(want))
	var key LPMKey
	var val uint8
	iter := s.m.Iterate()
	for iter.Next(&key, &val) {
		current[key] = struct{}{}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("%s iterate: %w", s.name, err)
	}

	val = 1
	for k := range want {
		if _, exists := current[k]; exists {
			continue
		}
		if err := s.m.Update(k, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%s add: %w", s.name, err)
		}
	}
	for k := range current {
		if _, keep := want[k]; keep {
			continue
		}
		if err := s.m.Delete(k); err != nil {
			return fmt.Errorf("%s prune: %w", s.name, err)
		}
	}
	return nil
}

// NormalizePrefix rewrites p into the form stored in the LPM maps.
//
// IPv4 prefixes become IPv4-mapped IPv6 with prefix length 96+n. An
// IPv4-mapped IPv6 prefix (::ffff:a.b.c.d/120) is treated as IPv4: its
// length is reduced by 96, and it is rejected when shorter than /96.
// Every other IPv6 prefix is kept as IPv6, unless its length is at most 96
// and its network contains ::ffff:0.0.0.0. IPv4 is stored inside that
// mapped range, so such a prefix would also match every IPv4 source.
// The result is always masked, so host bits do not create a second key
// for the same network.
func NormalizePrefix(p netip.Prefix) (netip.Prefix, error) {
	if !p.IsValid() {
		return netip.Prefix{}, errors.New("invalid prefix")
	}

	bits := p.Bits()
	addr := p.Addr()
	if addr.Is4In6() {
		if bits < v4MappedBits {
			return netip.Prefix{}, fmt.Errorf("ipv4-mapped prefix %s is shorter than /%d", p, v4MappedBits)
		}
		bits -= v4MappedBits
		addr = addr.Unmap()
	}
	if addr.Is4() {
		v4 := netip.PrefixFrom(addr, bits)
		if !v4.IsValid() {
			return netip.Prefix{}, fmt.Errorf("invalid ipv4 prefix length %d", bits)
		}
		v4 = v4.Masked()
		mapped := netip.PrefixFrom(mapIPv4(v4.Addr()), v4MappedBits+v4.Bits())
		if !mapped.IsValid() {
			return netip.Prefix{}, fmt.Errorf("invalid mapped prefix for %s", p)
		}
		return mapped, nil
	}

	masked := p.Masked()
	if !masked.IsValid() {
		return netip.Prefix{}, fmt.Errorf("invalid ipv6 prefix %s", p)
	}
	if coversMappedIPv4(masked) {
		return netip.Prefix{}, fmt.Errorf(
			"ipv6 prefix %s also covers IPv4 (::ffff:0:0/96); list IPv4 and IPv6 ranges separately, e.g. 0.0.0.0/0 and 2000::/3",
			masked)
	}
	return masked, nil
}

// coversMappedIPv4 reports whether a native IPv6 prefix includes
// ::ffff:0.0.0.0. Lengths above /96 cannot cover the whole mapped range.
func coversMappedIPv4(p netip.Prefix) bool {
	if p.Bits() > v4MappedBits {
		return false
	}
	var mapped [16]byte
	mapped[10], mapped[11] = 0xff, 0xff
	return p.Contains(netip.AddrFrom16(mapped))
}

// KeyFromPrefix builds the LPM map key for p using NormalizePrefix.
func KeyFromPrefix(p netip.Prefix) (LPMKey, error) {
	n, err := NormalizePrefix(p)
	if err != nil {
		return LPMKey{}, err
	}
	return LPMKey{Prefixlen: uint32(n.Bits()), Addr: n.Addr().As16()}, nil
}

func mapIPv4(addr netip.Addr) netip.Addr {
	v4 := addr.As4()
	var a [16]byte
	a[10], a[11] = 0xff, 0xff
	copy(a[12:], v4[:])
	return netip.AddrFrom16(a)
}
