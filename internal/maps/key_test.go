package maps

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"unsafe"
)

func TestStructSizes(t *testing.T) {
	checks := []struct {
		name string
		size int
		got  int
		mem  uintptr
	}{
		{"LPMKey", 20, binary.Size(LPMKey{}), unsafe.Sizeof(LPMKey{})},
		{"PortKey", 4, binary.Size(PortKey{}), unsafe.Sizeof(PortKey{})},
		{"StatsCounters", StatsSlots * 8, binary.Size(StatsCounters{}), unsafe.Sizeof(StatsCounters{})},
		{"PerIPStat", 48, binary.Size(PerIPStat{}), unsafe.Sizeof(PerIPStat{})},
		{"PerIPKey", 16, binary.Size(PerIPKey{}), unsafe.Sizeof(PerIPKey{})},
	}
	for _, c := range checks {
		if c.got != c.size {
			t.Errorf("%s binary.Size = %d, want %d", c.name, c.got, c.size)
		}
		if int(c.mem) != c.size {
			t.Errorf("%s unsafe.Sizeof = %d, want %d (padding would break the map layout)", c.name, c.mem, c.size)
		}
	}
}

func TestLPMKeyBytes(t *testing.T) {
	mapped := func(a, b, c, d byte) [16]byte {
		var addr [16]byte
		addr[10], addr[11] = 0xff, 0xff
		addr[12], addr[13], addr[14], addr[15] = a, b, c, d
		return addr
	}

	tests := []struct {
		name      string
		prefix    netip.Prefix
		prefixlen uint32
		addr      [16]byte
	}{
		{
			name:      "v4 /24",
			prefix:    netip.MustParsePrefix("1.2.3.0/24"),
			prefixlen: 120,
			addr:      mapped(1, 2, 3, 0),
		},
		{
			name:      "v4 host bits masked",
			prefix:    netip.MustParsePrefix("1.2.3.255/24"),
			prefixlen: 120,
			addr:      mapped(1, 2, 3, 0),
		},
		{
			name:      "v4 /32",
			prefix:    netip.MustParsePrefix("10.1.2.3/32"),
			prefixlen: 128,
			addr:      mapped(10, 1, 2, 3),
		},
		{
			name:      "mapped input treated as v4",
			prefix:    netip.MustParsePrefix("::ffff:1.2.3.255/120"),
			prefixlen: 120,
			addr:      mapped(1, 2, 3, 0),
		},
		{
			name:      "mapped /128 is v4 /32",
			prefix:    netip.MustParsePrefix("::ffff:10.1.2.3/128"),
			prefixlen: 128,
			addr:      mapped(10, 1, 2, 3),
		},
		{
			name:      "v6 /32 masked",
			prefix:    netip.MustParsePrefix("2001:db8::1/32"),
			prefixlen: 32,
			addr:      netip.MustParseAddr("2001:db8::").As16(),
		},
		{
			name:      "v6 /128",
			prefix:    netip.MustParsePrefix("2001:db8::1/128"),
			prefixlen: 128,
			addr:      netip.MustParseAddr("2001:db8::1").As16(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := KeyFromPrefix(tt.prefix)
			if err != nil {
				t.Fatalf("KeyFromPrefix: %v", err)
			}
			if key.Prefixlen != tt.prefixlen {
				t.Fatalf("prefixlen %d, want %d", key.Prefixlen, tt.prefixlen)
			}
			if key.Addr != tt.addr {
				t.Fatalf("addr %x, want %x", key.Addr, tt.addr)
			}

			// bpfel image: prefixlen is little-endian, address is network order.
			var raw [20]byte
			binary.LittleEndian.PutUint32(raw[:4], tt.prefixlen)
			copy(raw[4:], tt.addr[:])
			var got [20]byte
			binary.LittleEndian.PutUint32(got[:4], key.Prefixlen)
			copy(got[4:], key.Addr[:])
			if got != raw {
				t.Fatalf("key bytes %x, want %x", got, raw)
			}
		})
	}

	// The same network written as v4 or as a mapped prefix is one key.
	a, err := KeyFromPrefix(netip.MustParsePrefix("1.2.3.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := KeyFromPrefix(netip.MustParsePrefix("::ffff:1.2.3.9/120"))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("v4 and mapped keys differ: %+v vs %+v", a, b)
	}
}

func TestNormalizePrefixRejectsIPv4Overlap(t *testing.T) {
	rejected := []string{"::/0", "::/64", "::/80"}
	for _, s := range rejected {
		p := netip.MustParsePrefix(s)
		_, err := NormalizePrefix(p)
		if err == nil {
			t.Fatalf("%s accepted", s)
		}
		msg := err.Error()
		if !strings.Contains(msg, "also covers IPv4") || !strings.Contains(msg, s) {
			t.Fatalf("%s error %q", s, msg)
		}
	}

	accepted := []string{"2000::/3", "fe80::/10", "::1/128", "::/96", "0.0.0.0/0", "::ffff:0:0/96"}
	for _, s := range accepted {
		if _, err := NormalizePrefix(netip.MustParsePrefix(s)); err != nil {
			t.Fatalf("%s rejected: %v", s, err)
		}
	}
}

func TestNormalizePrefixRejectsShortMapped(t *testing.T) {
	p := netip.MustParsePrefix("::ffff:1.2.3.0/95")
	if _, err := NormalizePrefix(p); err == nil {
		t.Fatal("expected error for ipv4-mapped prefix shorter than /96")
	}
	if _, err := NormalizePrefix(netip.Prefix{}); err == nil {
		t.Fatal("expected error for invalid prefix")
	}
}

func TestPortKeyBytes(t *testing.T) {
	tests := []struct {
		port  uint16
		proto uint8
		want  [4]byte
	}{
		{443, ProtoTCP, [4]byte{0x01, 0xbb, ProtoTCP, 0}},
		{53, ProtoUDP, [4]byte{0x00, 0x35, ProtoUDP, 0}},
		{22, ProtoTCP, [4]byte{0x00, 0x16, ProtoTCP, 0}},
		{8080, ProtoUDP, [4]byte{0x1f, 0x90, ProtoUDP, 0}},
	}
	for _, tt := range tests {
		k := portKey(tt.port, tt.proto)
		got := [4]byte{k.Port[0], k.Port[1], k.Proto, k.Pad}
		if got != tt.want {
			t.Fatalf("port %d proto %d bytes %x, want %x", tt.port, tt.proto, got, tt.want)
		}
		if k.Proto != tt.proto || k.Pad != 0 {
			t.Fatalf("proto/pad = %d/%d", k.Proto, k.Pad)
		}
	}
	if ProtoTCP != 6 || ProtoUDP != 17 {
		t.Fatalf("proto numbers tcp=%d udp=%d", ProtoTCP, ProtoUDP)
	}
	if PortClassPublic != 1 || PortClassPrivate != 2 {
		t.Fatalf("classes public=%d private=%d", PortClassPublic, PortClassPrivate)
	}
}

func TestRuntimeFlags(t *testing.T) {
	if RuntimeFlagAllowICMP != 1 || RuntimeFlagAllowARP != 2 || RuntimeFlagEgressSeed != 4 {
		t.Fatalf("flags icmp=%d arp=%d egress=%d",
			RuntimeFlagAllowICMP, RuntimeFlagAllowARP, RuntimeFlagEgressSeed)
	}
	const all = RuntimeFlagAllowICMP | RuntimeFlagAllowARP | RuntimeFlagEgressSeed
	if all != 7 {
		t.Fatalf("combined flags %d, want 7", all)
	}
}
