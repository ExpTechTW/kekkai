//go:build linux && bpftest

package loader

import (
	"encoding/binary"
	"net/netip"
)

// Ethernet types and protocol numbers the frame builders stamp into headers.
// Checksums are left zero: the data plane does not verify them.
const (
	ethIPv4 = 0x0800
	ethARP  = 0x0806
	ethVLAN = 0x8100
	ethIPv6 = 0x86DD

	protoICMP  = 1
	protoTCP   = 6
	protoUDP   = 17
	protoGRE   = 47
	protoESP   = 50
	protoSCTP  = 132
	protoICMP6 = 58

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
	tcpURG = 0x20
	tcpECE = 0x40
	tcpCWR = 0x80

	extHop  = 0
	extFrag = 44
	extAH   = 51
	extDest = 60
)

// v4Opt is one IPv4 datagram. A nil TotLen means the header is filled with
// the bytes actually written, excluding Pad (Pad is trailing junk past
// tot_len). IHL and Version of 0 mean the normal 5 and 4.
type v4Opt struct {
	Src, Dst netip.Addr
	TTL      uint8
	Proto    uint8
	IHL      uint8
	Version  uint8
	FragOff  uint16 // offset in 8-byte units; the MF bit is separate
	MF       bool
	TotLen   *uint16
	L4       []byte
	Pad      []byte
}

// v6Ext is one IPv6 extension header. Size 0 selects the length the data
// plane uses: (hdrlen+1)*8, 8 for a fragment header, (hdrlen+2)*4 for AH.
type v6Ext struct {
	Kind   uint8
	HdrLen uint8
	Frag   uint16 // fragment header offset field, host order (includes M)
	Size   int
}

// v6Opt is one IPv6 packet. Hop 0 means 64. Version 0 means 6.
// A nil PayloadLen means the length of the extension chain plus L4 plus Pad.
type v6Opt struct {
	Src, Dst   netip.Addr
	Hop        uint8
	Proto      uint8
	Version    uint8
	PayloadLen *uint16
	Exts       []v6Ext
	L4         []byte
	Pad        []byte
}

func u16p(v uint16) *uint16 { return &v }

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func ethFrame(proto uint16, payload []byte) []byte {
	f := make([]byte, 14+len(payload))
	f[0], f[5] = 0x02, 0x01
	f[6], f[11] = 0x02, 0x02
	f[12] = byte(proto >> 8)
	f[13] = byte(proto)
	copy(f[14:], payload)
	return f
}

func tcpHeader(sport, dport uint16, flags byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	h[12] = 0x50 // data offset 5
	h[13] = flags
	return h
}

func udpHeader(sport, dport uint16) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint16(h[4:6], 8)
	return h
}

func icmpHeader(typ, code byte, body []byte) []byte {
	h := make([]byte, 8+len(body))
	h[0] = typ
	h[1] = code
	copy(h[8:], body)
	return h
}

func put4(dst []byte, a netip.Addr) {
	if !a.IsValid() {
		return
	}
	b := a.Unmap().As4()
	copy(dst, b[:])
}

// v4Packet is the IPv4 header plus L4 and Pad, without Ethernet.
func v4Packet(o v4Opt) []byte {
	ihl := o.IHL
	if ihl == 0 {
		ihl = 5
	}
	ver := o.Version
	if ver == 0 {
		ver = 4
	}
	// A short IHL is still written as a full header so the parser can read
	// the fixed fields and reject the nibble, rather than a truncated buffer.
	emit := int(ihl) * 4
	if emit < 20 {
		emit = 20
	}
	ip := make([]byte, emit)
	ip[0] = (ver << 4) | (ihl & 0x0f)
	ttl := o.TTL
	if ttl == 0 {
		ttl = 64
	}
	ip[8] = ttl
	ip[9] = o.Proto
	frag := o.FragOff & 0x1fff
	if o.MF {
		frag |= 0x2000
	}
	binary.BigEndian.PutUint16(ip[6:8], frag)
	put4(ip[12:16], o.Src)
	put4(ip[16:20], o.Dst)

	var tot uint16
	if o.TotLen != nil {
		tot = *o.TotLen
	} else {
		n := emit + len(o.L4)
		if n > 65535 {
			n = 65535
		}
		tot = uint16(n)
	}
	binary.BigEndian.PutUint16(ip[2:4], tot)
	out := append(ip, o.L4...)
	return append(out, o.Pad...)
}

func v4Frame(o v4Opt) []byte { return ethFrame(ethIPv4, v4Packet(o)) }

func v4TCP(src, dst string, sport, dport uint16, flags byte, extra v4Opt) []byte {
	extra.Src = mustAddr(src)
	extra.Dst = mustAddr(dst)
	extra.Proto = protoTCP
	extra.L4 = tcpHeader(sport, dport, flags)
	return v4Frame(extra)
}

func v4UDP(src, dst string, sport, dport uint16, extra v4Opt) []byte {
	extra.Src = mustAddr(src)
	extra.Dst = mustAddr(dst)
	extra.Proto = protoUDP
	extra.L4 = udpHeader(sport, dport)
	return v4Frame(extra)
}

func (e v6Ext) length() int {
	if e.Size != 0 {
		return e.Size
	}
	switch e.Kind {
	case extFrag:
		return 8
	case extAH:
		return int(e.HdrLen+2) * 4
	default:
		return int(e.HdrLen+1) * 8
	}
}

// chainExts links headers so each nexthdr points at the next one, and the
// IPv6 header's nexthdr is the first extension (or l4Proto when there are none).
func chainExts(exts []v6Ext, l4Proto uint8) (nexthdr uint8, body []byte) {
	if len(exts) == 0 {
		return l4Proto, nil
	}
	next := l4Proto
	parts := make([][]byte, len(exts))
	for i := len(exts) - 1; i >= 0; i-- {
		e := exts[i]
		n := e.length()
		if n < 8 {
			n = 8
		}
		h := make([]byte, n)
		h[0] = next
		h[1] = e.HdrLen
		binary.BigEndian.PutUint16(h[2:4], e.Frag)
		parts[i] = h
		next = e.Kind
	}
	for _, p := range parts {
		body = append(body, p...)
	}
	return exts[0].Kind, body
}

func v6Packet(o v6Opt) []byte {
	nh, ext := chainExts(o.Exts, o.Proto)
	ip := make([]byte, 40)
	ver := o.Version
	if ver == 0 {
		ver = 6
	}
	ip[0] = ver << 4
	hop := o.Hop
	if hop == 0 {
		hop = 64
	}
	ip[6] = nh
	ip[7] = hop
	if o.Src.IsValid() {
		b := o.Src.As16()
		copy(ip[8:24], b[:])
	}
	if o.Dst.IsValid() {
		b := o.Dst.As16()
		copy(ip[24:40], b[:])
	}
	payload := append(append(ext, o.L4...), o.Pad...)
	var plen uint16
	if o.PayloadLen != nil {
		plen = *o.PayloadLen
	} else if len(payload) > 65535 {
		plen = 65535
	} else {
		plen = uint16(len(payload))
	}
	binary.BigEndian.PutUint16(ip[4:6], plen)
	return append(ip, payload...)
}

func v6Frame(o v6Opt) []byte { return ethFrame(ethIPv6, v6Packet(o)) }

func v6TCP(src, dst string, sport, dport uint16, flags byte, extra v6Opt) []byte {
	extra.Src = mustAddr(src)
	extra.Dst = mustAddr(dst)
	extra.Proto = protoTCP
	extra.L4 = tcpHeader(sport, dport, flags)
	return v6Frame(extra)
}

func v6UDP(src, dst string, sport, dport uint16, extra v6Opt) []byte {
	extra.Src = mustAddr(src)
	extra.Dst = mustAddr(dst)
	extra.Proto = protoUDP
	extra.L4 = udpHeader(sport, dport)
	return v6Frame(extra)
}

func v6ICMP(src, dst string, hop uint8, typ, code byte, body []byte) []byte {
	return v6Frame(v6Opt{
		Src:   mustAddr(src),
		Dst:   mustAddr(dst),
		Hop:   hop,
		Proto: protoICMP6,
		L4:    icmpHeader(typ, code, body),
	})
}
