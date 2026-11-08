//go:build linux && bpftest

package loader

import (
	"net"
	"testing"

	"github.com/ExpTechTW/kekkai/internal/maps"
	"github.com/ExpTechTW/kekkai/internal/stats"
)

func tcpPort(t *testing.T, a net.Addr) uint16 {
	t.Helper()
	ta, ok := a.(*net.TCPAddr)
	if !ok || ta.Port <= 0 || ta.Port > 65535 {
		t.Fatalf("tcp port from %v", a)
	}
	return uint16(ta.Port)
}

func udpPort(t *testing.T, a net.Addr) uint16 {
	t.Helper()
	ua, ok := a.(*net.UDPAddr)
	if !ok || ua.Port <= 0 || ua.Port > 65535 {
		t.Fatalf("udp port from %v", a)
	}
	return uint16(ua.Port)
}

func v4Quote(src, dst string, proto uint8, sport, dport uint16) []byte {
	return v4Packet(v4Opt{
		Src:   mustAddr(src),
		Dst:   mustAddr(dst),
		Proto: proto,
		L4:    tcpHeader(sport, dport, 0),
	})
}

func icmp4(src, dst string, typ, code byte, inner []byte, tot *uint16) []byte {
	return v4Frame(v4Opt{
		Src:    mustAddr(src),
		Dst:    mustAddr(dst),
		Proto:  protoICMP,
		TotLen: tot,
		L4:     icmpHeader(typ, code, inner),
	})
}

func TestICMPv4(t *testing.T) {
	h := newHarness(t)
	random := v4Quote("203.0.113.50", "198.51.100.80", protoTCP, 1111, 2222)
	echoReq := icmp4("192.0.2.1", host4, 8, 0, nil, nil)
	echoRep := icmp4("192.0.2.1", host4, 0, 0, nil, nil)
	h.runCases(t, []xdpCase{
		{"echo request", echoReq, stats.SlotPassICMP},
		{"echo reply", echoRep, stats.SlotPassICMP},
		{"redirect", icmp4("192.0.2.1", host4, 5, 0, nil, nil), stats.SlotDropNoPolicy},
		{"timestamp", icmp4("192.0.2.1", host4, 13, 0, nil, nil), stats.SlotDropNoPolicy},
		{"address mask", icmp4("192.0.2.1", host4, 17, 0, nil, nil), stats.SlotDropNoPolicy},
		{"router advertisement", icmp4("192.0.2.1", host4, 9, 0, nil, nil), stats.SlotDropNoPolicy},
		{"source quench", icmp4("192.0.2.1", host4, 4, 0, nil, nil), stats.SlotDropNoPolicy},
		{"frag-needed quoting a random tuple", icmp4("192.0.2.1", host4, 3, 4, random, nil), stats.SlotPassICMP},
		{"port-unreachable quoting a random tuple", icmp4("192.0.2.1", host4, 3, 3, random, nil), stats.SlotDropNoPolicy},
		{"time-exceeded quoting a random tuple", icmp4("192.0.2.1", host4, 11, 0, random, nil), stats.SlotDropNoPolicy},
	})

	t.Run("echo without ALLOW_ICMP", func(t *testing.T) {
		h.setFlags(t, maps.RuntimeFlagAllowARP|maps.RuntimeFlagEgressSeed)
		h.expect(t, echoReq, stats.SlotDropNoPolicy)
		h.expect(t, echoRep, stats.SlotDropNoPolicy)
	})

	innerEcho := v4Packet(v4Opt{
		Src:   mustAddr("192.0.2.10"),
		Dst:   mustAddr("198.51.100.80"),
		Proto: protoICMP,
		L4:    []byte{8, 0, 0, 0},
	})
	exceeded := icmp4("192.0.2.1", host4, 11, 0, innerEcho, nil)
	t.Run("time-exceeded quoting our echo request", func(t *testing.T) {
		h.expect(t, exceeded, stats.SlotPassICMP)
	})
	t.Run("time-exceeded quoting our echo without ALLOW_ICMP", func(t *testing.T) {
		h.setFlags(t, maps.RuntimeFlagAllowARP|maps.RuntimeFlagEgressSeed)
		h.expect(t, exceeded, stats.SlotDropNoPolicy)
	})

	badIHL := v4Packet(v4Opt{
		Src: mustAddr("10.1.2.3"), Dst: mustAddr("10.9.9.9"),
		Proto: protoTCP, IHL: 4, L4: tcpHeader(1, 2, tcpACK),
	})
	t.Run("inner IHL < 5", func(t *testing.T) {
		h.expect(t, icmp4("192.0.2.1", host4, 3, 1, badIHL, nil), anyDrop)
	})
	t.Run("truncated quote", func(t *testing.T) {
		h.expect(t, icmp4("192.0.2.1", host4, 3, 3, random, u16p(28)), anyDrop)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })

	live := v4Quote("127.0.0.1", "127.0.0.1", protoTCP,
		tcpPort(t, client.LocalAddr()), tcpPort(t, ln.Addr()))
	t.Run("dest-unreach quoting a live local TCP connection", func(t *testing.T) {
		h.expect(t, icmp4("192.0.2.1", host4, 3, 1, live, nil), stats.SlotPassICMP)
	})

	// Only the listener matches a quote of its own port toward an unknown peer.
	listenOnly := v4Quote("127.0.0.1", "198.51.100.40", protoTCP,
		tcpPort(t, ln.Addr()), 9)
	t.Run("dest-unreach quoting only a listening socket", func(t *testing.T) {
		h.expect(t, icmp4("192.0.2.1", host4, 3, 1, listenOnly, nil), stats.SlotDropNoPolicy)
	})

	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	udpQuote := v4Quote("127.0.0.1", "198.51.100.40", protoUDP, udpPort(t, pc.LocalAddr()), 53)
	t.Run("port-unreachable quoting a bound UDP socket", func(t *testing.T) {
		h.expect(t, icmp4("192.0.2.1", host4, 3, 3, udpQuote, nil), stats.SlotPassICMP)
	})
}

func TestICMPv6(t *testing.T) {
	h := newHarness(t)
	const src = "2001:db8::20"
	h.runCases(t, []xdpCase{
		{"echo request", v6ICMP(src, host6, 64, 128, 0, nil), stats.SlotPassICMP},
		{"echo reply", v6ICMP(src, host6, 64, 129, 0, nil), stats.SlotPassICMP},
	})
	t.Run("echo without ALLOW_ICMP", func(t *testing.T) {
		h.setFlags(t, maps.RuntimeFlagAllowARP|maps.RuntimeFlagEgressSeed)
		h.expect(t, v6ICMP(src, host6, 64, 128, 0, nil), stats.SlotDropNoPolicy)
		h.expect(t, v6ICMP(src, host6, 64, 129, 0, nil), stats.SlotDropNoPolicy)
	})

	ndp := []struct {
		name string
		typ  byte
	}{
		{"router solicitation", 133},
		{"router advertisement", 134},
		{"neighbor solicitation", 135},
		{"neighbor advertisement", 136},
	}
	for _, tc := range ndp {
		t.Run(tc.name+" hop 255", func(t *testing.T) {
			h.expect(t, v6ICMP(src, host6, 255, tc.typ, 0, nil), stats.SlotPassICMP)
		})
		t.Run(tc.name+" hop 64", func(t *testing.T) {
			h.expect(t, v6ICMP(src, host6, 64, tc.typ, 0, nil), stats.SlotDropNoPolicy)
		})
	}
	t.Run("redirect hop 255", func(t *testing.T) {
		h.expect(t, v6ICMP(src, host6, 255, 137, 0, nil), stats.SlotDropNoPolicy)
	})
	t.Run("MLD query hop 1", func(t *testing.T) {
		h.expect(t, v6ICMP(src, host6, 1, 130, 0, nil), stats.SlotPassICMP)
	})
	t.Run("MLD report hop 1", func(t *testing.T) {
		h.expect(t, v6ICMP(src, host6, 1, 143, 0, nil), stats.SlotPassICMP)
	})
	t.Run("MLD query hop 255", func(t *testing.T) {
		h.expect(t, v6ICMP(src, host6, 255, 130, 0, nil), stats.SlotDropNoPolicy)
	})
	t.Run("MLD report hop 255", func(t *testing.T) {
		h.expect(t, v6ICMP(src, host6, 255, 143, 0, nil), stats.SlotDropNoPolicy)
	})

	random := v6Packet(v6Opt{
		Src: mustAddr("2001:db8::1"), Dst: mustAddr("2001:db8::2"), Proto: protoTCP,
		L4: tcpHeader(1111, 2222, 0)[:4],
	})
	t.Run("packet-too-big quoting a random tuple", func(t *testing.T) {
		h.expect(t, v6ICMP(src, host6, 64, 2, 0, random), stats.SlotPassICMP)
	})
	t.Run("dest-unreach quoting a random tuple", func(t *testing.T) {
		h.expect(t, v6ICMP(src, host6, 64, 1, 0, random), stats.SlotDropNoPolicy)
	})
	t.Run("node information", func(t *testing.T) {
		h.expect(t, v6ICMP(src, host6, 64, 139, 0, nil), stats.SlotDropNoPolicy)
	})

	t.Run("dest-unreach quoting a live ::1 connection", func(t *testing.T) {
		ln, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Skipf("::1 unavailable: %v", err)
		}
		t.Cleanup(func() { ln.Close() })
		client, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Skipf("dial ::1: %v", err)
		}
		t.Cleanup(func() { client.Close() })
		server, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { server.Close() })
		live := v6Packet(v6Opt{
			Src: mustAddr("::1"), Dst: mustAddr("::1"), Proto: protoTCP,
			L4: tcpHeader(tcpPort(t, client.LocalAddr()), tcpPort(t, ln.Addr()), 0)[:4],
		})
		h.expect(t, v6ICMP(src, host6, 64, 1, 0, live), stats.SlotPassICMP)
	})
}

func TestTCPListenGuard(t *testing.T) {
	h := newHarness(t)
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := tcpPort(t, ln.Addr())
	if p == 22 || p == 80 {
		t.Fatalf("ephemeral port %d collided with the policy", p)
	}
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	cp := tcpPort(t, client.LocalAddr())
	t.Cleanup(func() {
		_ = h.ports.Sync([]uint16{80}, []uint16{53}, []uint16{22}, []uint16{51820})
	})

	if err := h.ports.Sync([]uint16{80}, []uint16{53}, []uint16{22, p}, []uint16{51820}); err != nil {
		t.Fatal(err)
	}
	t.Run("ACK to a private listener from a non-allowlisted source", func(t *testing.T) {
		h.expect(t, v4TCP("198.51.100.7", "127.0.0.1", 40000, p, tcpACK, v4Opt{}), stats.SlotDropNotAllowed)
	})
	t.Run("ACK to a private listener from an allowlisted source", func(t *testing.T) {
		h.expect(t, v4TCP("10.1.2.3", "127.0.0.1", 40000, p, tcpACK, v4Opt{}), stats.SlotPassPrivateTCP)
	})

	if err := h.ports.Sync([]uint16{80}, []uint16{53}, []uint16{22}, []uint16{51820}); err != nil {
		t.Fatal(err)
	}
	t.Run("ACK to an unlisted listener", func(t *testing.T) {
		h.expect(t, v4TCP("198.51.100.7", "127.0.0.1", 40000, p, tcpACK, v4Opt{}), stats.SlotDropNoPolicy)
	})

	if err := h.ports.Sync([]uint16{80, p}, []uint16{53}, []uint16{22}, []uint16{51820}); err != nil {
		t.Fatal(err)
	}
	t.Run("ACK to a public listener skips the socket lookup", func(t *testing.T) {
		h.expect(t, v4TCP("198.51.100.7", "127.0.0.1", 40000, p, tcpACK, v4Opt{}), stats.SlotPassTCPEst)
	})

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := tcpPort(t, ln2.Addr())
	ln2.Close()
	if closed == 22 || closed == 80 || closed == p {
		t.Fatalf("closed port %d collided with the policy", closed)
	}
	t.Run("ACK to a port with no socket", func(t *testing.T) {
		h.expect(t, v4TCP("198.51.100.7", "127.0.0.1", 40000, closed, tcpACK, v4Opt{}), stats.SlotPassTCPEst)
	})
	t.Run("ACK on the established loopback tuple", func(t *testing.T) {
		h.expect(t, v4TCP("127.0.0.1", "127.0.0.1", p, cp, tcpACK, v4Opt{}), stats.SlotPassTCPEst)
	})
}

func TestTCPListenGuardV6(t *testing.T) {
	h := newHarness(t)
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("::1 unavailable: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	p := tcpPort(t, ln.Addr())
	if p == 22 || p == 80 {
		t.Fatalf("ephemeral port %d collided with the policy", p)
	}
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("dial ::1: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	cp := tcpPort(t, client.LocalAddr())
	t.Cleanup(func() {
		_ = h.ports.Sync([]uint16{80}, []uint16{53}, []uint16{22}, []uint16{51820})
	})

	if err := h.ports.Sync([]uint16{80}, []uint16{53}, []uint16{22, p}, []uint16{51820}); err != nil {
		t.Fatal(err)
	}
	t.Run("ACK to a private listener from a non-allowlisted source", func(t *testing.T) {
		h.expect(t, v6TCP("2001:db8:c::7", "::1", 40000, p, tcpACK, v6Opt{}), stats.SlotDropNotAllowed)
	})
	t.Run("ACK to a private listener from an allowlisted source", func(t *testing.T) {
		h.expect(t, v6TCP("2001:db8:a::7", "::1", 40000, p, tcpACK, v6Opt{}), stats.SlotPassPrivateTCP)
	})

	if err := h.ports.Sync([]uint16{80}, []uint16{53}, []uint16{22}, []uint16{51820}); err != nil {
		t.Fatal(err)
	}
	t.Run("ACK to an unlisted listener", func(t *testing.T) {
		h.expect(t, v6TCP("2001:db8:c::7", "::1", 40000, p, tcpACK, v6Opt{}), stats.SlotDropNoPolicy)
	})

	if err := h.ports.Sync([]uint16{80, p}, []uint16{53}, []uint16{22}, []uint16{51820}); err != nil {
		t.Fatal(err)
	}
	t.Run("ACK to a public listener skips the socket lookup", func(t *testing.T) {
		h.expect(t, v6TCP("2001:db8:c::7", "::1", 40000, p, tcpACK, v6Opt{}), stats.SlotPassTCPEst)
	})

	ln2, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := tcpPort(t, ln2.Addr())
	ln2.Close()
	if closed == 22 || closed == 80 || closed == p {
		t.Fatalf("closed port %d collided with the policy", closed)
	}
	t.Run("ACK to a port with no socket", func(t *testing.T) {
		h.expect(t, v6TCP("2001:db8:c::7", "::1", 40000, closed, tcpACK, v6Opt{}), stats.SlotPassTCPEst)
	})
	t.Run("ACK on the established loopback tuple", func(t *testing.T) {
		h.expect(t, v6TCP("::1", "::1", p, cp, tcpACK, v6Opt{}), stats.SlotPassTCPEst)
	})
}
