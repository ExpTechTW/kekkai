//go:build linux && bpftest

package loader

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/ExpTechTW/kekkai/internal/maps"
	"github.com/ExpTechTW/kekkai/internal/stats"
)

// XDP action codes and the TC "continue" result. TC_ACT_UNSPEC is -1, which
// the test-run return value carries as uint32.
const (
	xdpDrop     = 1
	xdpPass     = 2
	tcActUnspec = 0xffffffff

	// anyDrop accepts every drop verdict. Used where the case only requires
	// that a forged quote is not delivered.
	anyDrop = -1

	defaultFlags = maps.RuntimeFlagAllowICMP | maps.RuntimeFlagAllowARP | maps.RuntimeFlagEgressSeed

	host4 = "192.0.2.10"
	host6 = "2001:db8::10"
)

// verdictNames is indexed by the stats slot constants.
var verdictNames = []string{
	"drop_non_ip",
	"drop_malformed",
	"drop_blocklist",
	"drop_not_allowed",
	"drop_no_policy",
	"pass_arp",
	"pass_fragment",
	"pass_tcp_established",
	"pass_udp_flow",
	"pass_dhcp",
	"pass_icmp",
	"pass_public_tcp",
	"pass_public_udp",
	"pass_private_tcp",
	"pass_private_udp",
}

func verdictName(v int) string {
	if v == anyDrop {
		return "drop"
	}
	if v >= 0 && v < len(verdictNames) {
		return verdictNames[v]
	}
	return fmt.Sprintf("slot %d", v)
}

type xdpCase struct {
	name  string
	frame []byte
	want  int
}

// harness is one unpinned, unattached collection. Maps are programmed through
// the userspace encoders so a layout mistake fails these tests too.
type harness struct {
	coll    *ebpf.Collection
	xdp     *ebpf.Program
	tc      *ebpf.Program
	stats   *ebpf.Map
	perip   *ebpf.Map
	ports   *maps.PortTable
	rt      *maps.RuntimeCfg
	scratch []stats.PerCPUCounters
}

func loadObject(t *testing.T) []byte {
	t.Helper()
	if p := os.Getenv("KEKKAI_BPF_OBJ"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		return b
	}
	return programBytes
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	if len(verdictNames) != stats.VerdictCount ||
		verdictNames[stats.SlotPassARP] != "pass_arp" ||
		verdictNames[stats.SlotPassTCPEst] != "pass_tcp_established" {
		t.Fatalf("verdict name table does not match stats slots")
	}
	// CI sets KEKKAI_BPF_REQUIRE=1 so a missing object or privilege fails
	// the run instead of silently skipping every case.
	skip := t.Skip
	if os.Getenv("KEKKAI_BPF_REQUIRE") == "1" {
		skip = t.Fatal
	}
	if os.Geteuid() != 0 {
		skip("bpftest requires root")
	}
	obj := loadObject(t)
	if len(obj) == 4 {
		skip("bpf object is a 4-byte placeholder")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load collection: %v", err)
	}
	t.Cleanup(coll.Close)

	h := &harness{
		coll:  coll,
		xdp:   coll.Programs[progNameXDP],
		tc:    coll.Programs[progNameTCEgress],
		stats: coll.Maps[mapStats],
		perip: coll.Maps[mapPerIP],
		ports: maps.NewPortTable(coll.Maps[mapPorts], mapPorts),
		rt:    maps.NewRuntimeCfg(coll.Maps[mapRuntimeCfg]),
	}
	if h.xdp == nil || h.tc == nil || h.stats == nil || h.perip == nil ||
		coll.Maps[mapPorts] == nil || coll.Maps[mapAllowlist] == nil ||
		coll.Maps[mapBlocklist] == nil || coll.Maps[mapRuntimeCfg] == nil {
		t.Fatal("collection is missing a program or map")
	}
	h.applyPolicy(t)
	return h
}

func (h *harness) applyPolicy(t *testing.T) {
	t.Helper()
	allow := maps.NewPrefixSet(h.coll.Maps[mapAllowlist], mapAllowlist)
	if err := allow.Sync(mustPrefixes("10.0.0.0/8", "2001:db8:a::/48")); err != nil {
		t.Fatal(err)
	}
	block := maps.NewPrefixSet(h.coll.Maps[mapBlocklist], mapBlocklist)
	if err := block.Sync(mustPrefixes("203.0.113.0/24", "2001:db8:bad::/48")); err != nil {
		t.Fatal(err)
	}
	if err := h.ports.Sync([]uint16{80}, []uint16{53}, []uint16{22}, []uint16{51820}); err != nil {
		t.Fatal(err)
	}
	if err := h.rt.Sync(defaultFlags); err != nil {
		t.Fatal(err)
	}
}

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, s := range cidrs {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// snap sums the per-CPU stats array. scratch is reused across runs.
func (h *harness) snap(t *testing.T) [stats.SlotCount]uint64 {
	t.Helper()
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	buf := h.scratch
	if cap(buf) < ncpu {
		buf = make([]stats.PerCPUCounters, ncpu)
	}
	buf = buf[:ncpu]
	var key uint32
	if err := h.stats.Lookup(&key, buf); err != nil {
		t.Fatalf("stats lookup: %v", err)
	}
	h.scratch = buf
	var sum [stats.SlotCount]uint64
	for _, cpu := range buf {
		for i := range sum {
			sum[i] += cpu[i]
		}
	}
	return sum
}

func formatDeltas(before, after [stats.SlotCount]uint64) string {
	var b bytes.Buffer
	for i := 0; i < stats.VerdictCount; i++ {
		if after[i] == before[i] {
			continue
		}
		fmt.Fprintf(&b, " %s %+d", verdictName(i), int64(after[i]-before[i]))
	}
	if b.Len() == 0 {
		return " none"
	}
	return b.String()
}

// runXDP executes one frame and returns the action plus the single verdict
// slot that incremented. Exactly one verdict slot must move by 1, and the
// action must agree with which side of FirstPassVerdict that slot is on.
func (h *harness) runXDP(t *testing.T, frame []byte) (uint32, int) {
	t.Helper()
	if len(frame) < 14 {
		t.Fatalf("frame is %d bytes", len(frame))
	}
	before := h.snap(t)
	action, err := h.xdp.Run(&ebpf.RunOptions{Data: frame, Repeat: 1})
	if err != nil {
		t.Fatalf("xdp run: %v", err)
	}
	after := h.snap(t)
	hit := -1
	for i := 0; i < stats.VerdictCount; i++ {
		delta := after[i] - before[i]
		if delta == 0 {
			continue
		}
		if delta != 1 || hit >= 0 {
			t.Fatalf("action %d, verdict slots:%s", action, formatDeltas(before, after))
		}
		hit = i
	}
	if hit < 0 {
		t.Fatalf("action %d, no verdict slot moved", action)
	}
	wantAct := uint32(xdpDrop)
	if hit >= stats.FirstPassVerdict {
		wantAct = xdpPass
	}
	if action != wantAct {
		t.Fatalf("action %d disagrees with %s", action, verdictName(hit))
	}
	return action, hit
}

// runTC executes the egress program. It must always return TC_ACT_UNSPEC so
// a later tcx program still runs.
func (h *harness) runTC(t *testing.T, frame []byte) {
	t.Helper()
	ret, err := h.tc.Run(&ebpf.RunOptions{Data: frame, Repeat: 1})
	if err != nil {
		t.Fatalf("tc run: %v", err)
	}
	if ret != tcActUnspec {
		t.Fatalf("tc returned %#x, want TC_ACT_UNSPEC", ret)
	}
}

func (h *harness) expect(t *testing.T, frame []byte, want int) {
	t.Helper()
	_, got := h.runXDP(t, frame)
	if want == anyDrop {
		if got >= stats.FirstPassVerdict {
			t.Fatalf("got %s, want a drop", verdictName(got))
		}
		return
	}
	if got != want {
		t.Fatalf("got %s, want %s", verdictName(got), verdictName(want))
	}
}

func (h *harness) runCases(t *testing.T, cases []xdpCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h.expect(t, tc.frame, tc.want)
		})
	}
}

func (h *harness) setFlags(t *testing.T, flags uint32) {
	t.Helper()
	if err := h.rt.Sync(flags); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.rt.Sync(defaultFlags); err != nil {
			t.Errorf("restore runtime flags: %v", err)
		}
	})
}

func (h *harness) zeroDHCP(t *testing.T) {
	t.Helper()
	m := h.coll.Maps["dhcp_tx"]
	if m == nil {
		t.Fatal("dhcp_tx missing")
	}
	for i := uint32(0); i < 2; i++ {
		if err := m.Update(i, uint64(0), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
}

// peripStat reads one per-CPU perip entry and folds it the same way userspace
// does. A single PerIPStat is rejected ("per-cpu value requires a slice");
// the packet may have landed on any CPU, so the counters have to be summed.
func (h *harness) peripStat(t *testing.T, key maps.PerIPKey) (maps.PerIPStat, bool) {
	t.Helper()
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	vals := make([]maps.PerIPStat, ncpu)
	err = h.perip.Lookup(&key, vals)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return maps.PerIPStat{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return stats.FoldPerIP(vals), true
}

func mappedKey(a [4]byte) maps.PerIPKey {
	var k maps.PerIPKey
	k[10], k[11] = 0xff, 0xff
	copy(k[12:], a[:])
	return k
}

func TestXDPBaseline(t *testing.T) {
	h := newHarness(t)
	h.runCases(t, []xdpCase{
		{"v4 SYN to public :80 from anywhere",
			v4TCP("198.51.100.7", host4, 40000, 80, tcpSYN, v4Opt{}), stats.SlotPassPublicTCP},
		{"v6 SYN to public :80 from anywhere",
			v6TCP("2001:db8::5", host6, 40000, 80, tcpSYN, v6Opt{}), stats.SlotPassPublicTCP},
		{"v4 SYN to private :22 from allowlisted 10.1.2.3",
			v4TCP("10.1.2.3", host4, 40000, 22, tcpSYN, v4Opt{}), stats.SlotPassPrivateTCP},
		{"v4 SYN to private :22 from non-allowlisted 198.51.100.7",
			v4TCP("198.51.100.7", host4, 40000, 22, tcpSYN, v4Opt{}), stats.SlotDropNotAllowed},
		{"v4 SYN to unlisted :23",
			v4TCP("198.51.100.7", host4, 40000, 23, tcpSYN, v4Opt{}), stats.SlotDropNoPolicy},
		{"v4 UDP to public :53",
			v4UDP("198.51.100.7", host4, 40000, 53, v4Opt{}), stats.SlotPassPublicUDP},
		{"v6 UDP to private :51820 from allowlisted 2001:db8:a::1",
			v6UDP("2001:db8:a::1", host6, 40000, 51820, v6Opt{}), stats.SlotPassPrivateUDP},
		{"v6 UDP to private :51820 from non-allowlisted 2001:db8:c::1",
			v6UDP("2001:db8:c::1", host6, 40000, 51820, v6Opt{}), stats.SlotDropNotAllowed},
		{"802.1Q tag is not IP",
			ethFrame(ethVLAN, []byte{0, 0, 0, 0}), stats.SlotDropNonIP},
		{"GRE is not a handled L4 protocol",
			v4Frame(v4Opt{Src: mustAddr("198.51.100.7"), Dst: mustAddr(host4), Proto: protoGRE}), stats.SlotDropNoPolicy},
		{"ESP is not a handled L4 protocol",
			v4Frame(v4Opt{Src: mustAddr("198.51.100.7"), Dst: mustAddr(host4), Proto: protoESP}), stats.SlotDropNoPolicy},
		{"SCTP is not a handled L4 protocol",
			v4Frame(v4Opt{Src: mustAddr("198.51.100.7"), Dst: mustAddr(host4), Proto: protoSCTP}), stats.SlotDropNoPolicy},
	})
}

func TestACKToClosedPortIsEstablished(t *testing.T) {
	h := newHarness(t)
	// Bind and close so the port is not a listener. An ACK must not consult
	// port policy when nothing is listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := tcpPort(t, ln.Addr())
	ln.Close()
	h.expect(t, v4TCP("198.51.100.7", "127.0.0.1", 40000, port, tcpACK, v4Opt{}), stats.SlotPassTCPEst)
}

func TestARP(t *testing.T) {
	h := newHarness(t)
	arp := ethFrame(ethARP, make([]byte, 28))
	h.expect(t, arp, stats.SlotPassARP)
	t.Run("ALLOW_ARP cleared", func(t *testing.T) {
		h.setFlags(t, maps.RuntimeFlagAllowICMP|maps.RuntimeFlagEgressSeed)
		h.expect(t, arp, stats.SlotDropNonIP)
	})
}

func TestStatelessACKDoesNotOpenTCP(t *testing.T) {
	h := newHarness(t)
	// The ACK is delivered or policed; either way it must not make the
	// following SYN from the same non-allowlisted tuple succeed.
	h.runXDP(t, v4TCP("198.51.100.7", host4, 40000, 22, tcpACK, v4Opt{}))
	h.expect(t, v4TCP("198.51.100.7", host4, 40000, 22, tcpSYN, v4Opt{}), stats.SlotDropNotAllowed)
}

func TestEgressTCPDoesNotSeed(t *testing.T) {
	h := newHarness(t)
	h.runTC(t, v4TCP("127.0.0.1", "198.51.100.7", 22, 40000, tcpRST, v4Opt{}))
	t.Run("SYN after an egress RST", func(t *testing.T) {
		h.expect(t, v4TCP("198.51.100.7", "127.0.0.1", 40000, 22, tcpSYN, v4Opt{}), stats.SlotDropNotAllowed)
	})

	h.runTC(t, v4TCP("127.0.0.1", "198.51.100.7", 22, 40001, tcpACK|tcpPSH, v4Opt{}))
	t.Run("SYN after an egress data ACK", func(t *testing.T) {
		h.expect(t, v4TCP("198.51.100.7", "127.0.0.1", 40001, 22, tcpSYN, v4Opt{}), stats.SlotDropNotAllowed)
	})
}

func TestBlocklistWins(t *testing.T) {
	h := newHarness(t)
	const v4src = "203.0.113.9"
	const v6src = "2001:db8:bad::1"
	h.runCases(t, []xdpCase{
		{"v4 blocklist ACK is not established",
			v4TCP(v4src, host4, 40000, 80, tcpACK, v4Opt{}), stats.SlotDropBlocklist},
		{"v4 blocklist SYN to public :80",
			v4TCP(v4src, host4, 40000, 80, tcpSYN, v4Opt{}), stats.SlotDropBlocklist},
		{"v4 blocklist non-first fragment",
			v4Frame(v4Opt{Src: mustAddr(v4src), Dst: mustAddr(host4), Proto: protoTCP, FragOff: 1}), stats.SlotDropBlocklist},
		{"v4 blocklist ICMP echo",
			v4Frame(v4Opt{Src: mustAddr(v4src), Dst: mustAddr(host4), Proto: protoICMP, L4: icmpHeader(8, 0, nil)}), stats.SlotDropBlocklist},
		{"v4 blocklist DHCP reply",
			v4UDP(v4src, "255.255.255.255", 67, 68, v4Opt{}), stats.SlotDropBlocklist},
		{"v6 blocklist ACK",
			v6TCP(v6src, host6, 40000, 80, tcpACK, v6Opt{}), stats.SlotDropBlocklist},
		{"v6 blocklist SYN to public :80",
			v6TCP(v6src, host6, 40000, 80, tcpSYN, v6Opt{}), stats.SlotDropBlocklist},
		{"v6 blocklist non-first fragment",
			v6Frame(v6Opt{Src: mustAddr(v6src), Dst: mustAddr(host6), Proto: protoTCP, Exts: []v6Ext{{Kind: extFrag, Frag: 8}}}), stats.SlotDropBlocklist},
		{"v6 blocklist echo",
			v6ICMP(v6src, host6, 64, 128, 0, nil), stats.SlotDropBlocklist},
		{"v6 blocklist DHCPv6 reply",
			v6UDP(v6src, "fe80::1", 547, 546, v6Opt{}), stats.SlotDropBlocklist},
		{"v4-mapped source ::ffff:10.1.2.3 must not hit the v4 allowlist",
			v6TCP("::ffff:10.1.2.3", host6, 40000, 22, tcpSYN, v6Opt{}), stats.SlotDropMalformed},
		{"v4-mapped source ::ffff:203.0.113.9 must not hit the v4 blocklist",
			v6TCP("::ffff:203.0.113.9", host6, 40000, 80, tcpSYN, v6Opt{}), stats.SlotDropMalformed},
	})
}

func TestTCPFlagScans(t *testing.T) {
	h := newHarness(t)
	// Malformed combinations are rejected before port policy. SYN|ACK and RST
	// go to a public port so a listener cannot pull them back into policy.
	h.runCases(t, []xdpCase{
		{"NULL scan", v4TCP("198.51.100.7", host4, 40000, 80, 0, v4Opt{}), stats.SlotDropMalformed},
		{"FIN scan", v4TCP("198.51.100.7", host4, 40000, 80, tcpFIN, v4Opt{}), stats.SlotDropMalformed},
		{"Xmas FIN|PSH|URG", v4TCP("198.51.100.7", host4, 40000, 80, tcpFIN|tcpPSH|tcpURG, v4Opt{}), stats.SlotDropMalformed},
		{"SYN|FIN", v4TCP("198.51.100.7", host4, 40000, 80, tcpSYN|tcpFIN, v4Opt{}), stats.SlotDropMalformed},
		{"SYN|RST", v4TCP("198.51.100.7", host4, 40000, 80, tcpSYN|tcpRST, v4Opt{}), stats.SlotDropMalformed},
		{"SYN|ACK is established", v4TCP("198.51.100.7", host4, 40000, 80, tcpSYN|tcpACK, v4Opt{}), stats.SlotPassTCPEst},
		{"SYN|ECE|CWR to :80 is a new public connection", v4TCP("198.51.100.7", host4, 40000, 80, tcpSYN|tcpECE|tcpCWR, v4Opt{}), stats.SlotPassPublicTCP},
		{"RST alone is established", v4TCP("198.51.100.7", host4, 40000, 80, tcpRST, v4Opt{}), stats.SlotPassTCPEst},
	})
}

func TestFragmentAndLengthEvasion(t *testing.T) {
	h := newHarness(t)
	// First fragment whose tot_len covers 8 bytes of TCP. The ACK flag sits
	// at TCP offset 13, which is past tot_len and must be ignored.
	shortTCP := v4TCP("198.51.100.7", host4, 40000, 22, tcpACK, v4Opt{MF: true, TotLen: u16p(28)})
	padded := v4TCP("198.51.100.7", host4, 40000, 22, tcpACK, v4Opt{TotLen: u16p(24)})
	oversize := v4TCP("198.51.100.7", host4, 40000, 80, tcpSYN, v4Opt{TotLen: u16p(1500)})
	h.runCases(t, []xdpCase{
		{"first fragment hides ACK past tot_len", shortTCP, stats.SlotDropMalformed},
		{"unfragmented TCP shorter than its header, padded frame", padded, stats.SlotDropMalformed},
		{"tot_len larger than the frame", oversize, stats.SlotDropMalformed},
		{"IHL < 5", v4Frame(v4Opt{Src: mustAddr("198.51.100.7"), Dst: mustAddr(host4), Proto: protoTCP, IHL: 4, L4: tcpHeader(1, 80, tcpSYN)}), stats.SlotDropMalformed},
		{"IPv4 version nibble is not 4", v4Frame(v4Opt{Src: mustAddr("198.51.100.7"), Dst: mustAddr(host4), Proto: protoTCP, Version: 5, L4: tcpHeader(1, 80, tcpSYN)}), stats.SlotDropMalformed},
		{"tot_len 0 GRO aggregate SYN to :80", v4TCP("198.51.100.7", host4, 40000, 80, tcpSYN, v4Opt{TotLen: u16p(0)}), stats.SlotPassPublicTCP},
		{"non-first fragment from a clean source", v4Frame(v4Opt{Src: mustAddr("192.0.2.20"), Dst: mustAddr(host4), Proto: protoTCP, FragOff: 1}), stats.SlotPassFragment},
	})
}

func TestIPv6Parsing(t *testing.T) {
	h := newHarness(t)
	seven := make([]v6Ext, 7)
	for i := range seven {
		seven[i].Kind = extHop
	}
	h.runCases(t, []xdpCase{
		{"payload_len larger than the frame",
			v6TCP("2001:db8::8", host6, 40000, 80, tcpSYN, v6Opt{PayloadLen: u16p(200)}), stats.SlotDropMalformed},
		{"version nibble 4 inside an IPv6 ethertype",
			v6TCP("2001:db8::8", host6, 40000, 80, tcpSYN, v6Opt{Version: 4}), stats.SlotDropMalformed},
		{"HBH + destination options + TCP SYN to :80",
			v6TCP("2001:db8::8", host6, 40000, 80, tcpSYN, v6Opt{Exts: []v6Ext{{Kind: extHop}, {Kind: extDest}}}), stats.SlotPassPublicTCP},
		{"AH length (hdrlen+2)*4 then TCP to private :22 from a non-allowlisted source",
			v6TCP("2001:db8:c::1", host6, 40000, 22, tcpSYN, v6Opt{Exts: []v6Ext{{Kind: extAH, HdrLen: 1}}}), stats.SlotDropNotAllowed},
		{"seven extension headers exceed the walk limit",
			v6TCP("2001:db8::8", host6, 40000, 80, tcpSYN, v6Opt{Exts: seven}), stats.SlotDropMalformed},
		{"extension header extends past payload_len",
			v6Frame(v6Opt{Src: mustAddr("2001:db8::8"), Dst: mustAddr(host6), Proto: protoTCP, PayloadLen: u16p(4), Exts: []v6Ext{{Kind: extHop}}}), stats.SlotDropMalformed},
		{"first fragment (offset 0) of TCP SYN to unlisted :23",
			v6TCP("2001:db8::8", host6, 40000, 23, tcpSYN, v6Opt{Exts: []v6Ext{{Kind: extFrag, Frag: 1}}}), stats.SlotDropNoPolicy},
		{"non-first fragment",
			v6Frame(v6Opt{Src: mustAddr("2001:db8::8"), Dst: mustAddr(host6), Proto: protoTCP, Exts: []v6Ext{{Kind: extFrag, Frag: 8}}}), stats.SlotPassFragment},
		{"ESP",
			v6Frame(v6Opt{Src: mustAddr("2001:db8::8"), Dst: mustAddr(host6), Proto: protoESP, L4: []byte{0, 0, 0, 0}}), stats.SlotDropNoPolicy},
	})
}

func TestUDPFlowSeed(t *testing.T) {
	h := newHarness(t)
	h.runTC(t, v4UDP(host4, "8.8.8.8", 5353, 53, v4Opt{}))
	t.Run("v4 reply on the seeded tuple", func(t *testing.T) {
		h.expect(t, v4UDP("8.8.8.8", host4, 53, 5353, v4Opt{}), stats.SlotPassUDPFlow)
	})
	t.Run("v4 reply from a different resolver", func(t *testing.T) {
		h.expect(t, v4UDP("8.8.4.4", host4, 53, 5353, v4Opt{}), stats.SlotDropNoPolicy)
	})

	h.runTC(t, v6UDP("2001:db8:1::10", "2001:db8:ff::8", 5353, 53, v6Opt{}))
	t.Run("v6 reply on the seeded tuple", func(t *testing.T) {
		h.expect(t, v6UDP("2001:db8:ff::8", "2001:db8:1::10", 53, 5353, v6Opt{}), stats.SlotPassUDPFlow)
	})
	t.Run("v6 reply from a different resolver", func(t *testing.T) {
		h.expect(t, v6UDP("2001:db8:ff::9", "2001:db8:1::10", 53, 5353, v6Opt{}), stats.SlotDropNoPolicy)
	})

	// Outbound source port 53 is public, so egress must not insert a flow.
	// The reversed packet lands on :53 and is admitted by port policy. A seeded
	// flow would have been pass_udp_flow, because the flow check runs first.
	// A packet aimed at the ephemeral port has no policy and no flow.
	h.runTC(t, v4UDP(host4, "8.8.8.8", 53, 40000, v4Opt{}))
	t.Run("outbound public :53 does not seed; reverse is public UDP", func(t *testing.T) {
		h.expect(t, v4UDP("8.8.8.8", host4, 40000, 53, v4Opt{}), stats.SlotPassPublicUDP)
	})
	t.Run("packet to the ephemeral port of that exchange", func(t *testing.T) {
		h.expect(t, v4UDP("8.8.8.8", host4, 53, 40000, v4Opt{}), stats.SlotDropNoPolicy)
	})

	h.runTC(t, v4UDP(host4, "8.8.8.8", 51820, 40001, v4Opt{}))
	t.Run("outbound private :51820 does seed", func(t *testing.T) {
		h.expect(t, v4UDP("8.8.8.8", host4, 40001, 51820, v4Opt{}), stats.SlotPassUDPFlow)
	})
}

func TestDHCPWindow(t *testing.T) {
	h := newHarness(t)
	reply := v4UDP("192.0.2.1", "255.255.255.255", 67, 68, v4Opt{})
	t.Run("DHCPv4 reply before any request", func(t *testing.T) {
		h.expect(t, reply, stats.SlotDropNoPolicy)
	})
	h.runTC(t, v4UDP("0.0.0.0", "255.255.255.255", 68, 67, v4Opt{}))
	t.Run("DHCPv4 reply after DISCOVER", func(t *testing.T) {
		h.expect(t, reply, stats.SlotPassDHCP)
	})
	t.Run("DHCPv4 reply from a non-server port", func(t *testing.T) {
		h.expect(t, v4UDP("192.0.2.1", "255.255.255.255", 1234, 68, v4Opt{}), stats.SlotDropNoPolicy)
	})

	v6reply := v6UDP("fe80::2", "fe80::1", 547, 546, v6Opt{})
	t.Run("DHCPv6 reply before any request", func(t *testing.T) {
		h.expect(t, v6reply, stats.SlotDropNoPolicy)
	})
	h.runTC(t, v6UDP("fe80::1", "ff02::1:2", 546, 547, v6Opt{}))
	t.Run("DHCPv6 link-local reply after solicit", func(t *testing.T) {
		h.expect(t, v6reply, stats.SlotPassDHCP)
	})
	t.Run("DHCPv6 reply from a global source", func(t *testing.T) {
		h.expect(t, v6UDP("2001:db8::2", "fe80::1", 547, 546, v6Opt{}), stats.SlotDropNoPolicy)
	})

	t.Run("EGRESS_SEED cleared allows a reply with no request", func(t *testing.T) {
		h.setFlags(t, maps.RuntimeFlagAllowICMP|maps.RuntimeFlagAllowARP)
		h.zeroDHCP(t)
		h.expect(t, reply, stats.SlotPassDHCP)
	})
}

func TestAccounting(t *testing.T) {
	h := newHarness(t)
	v6src := mustAddr("2001:db8::99")
	v4src := mustAddr("198.51.100.40")
	v6f := v6TCP(v6src.String(), host6, 40000, 80, tcpSYN, v6Opt{})
	before := h.snap(t)
	h.expect(t, v6f, stats.SlotPassPublicTCP)
	after := h.snap(t)
	if after[stats.SlotPktsIPv6] != before[stats.SlotPktsIPv6]+1 {
		t.Fatalf("PktsIPv6 %d -> %d", before[stats.SlotPktsIPv6], after[stats.SlotPktsIPv6])
	}
	if got := after[stats.SlotBytesIPv6] - before[stats.SlotBytesIPv6]; got != uint64(len(v6f)) {
		t.Fatalf("BytesIPv6 moved %d, frame is %d", got, len(v6f))
	}
	if after[stats.SlotBytesDropped] != before[stats.SlotBytesDropped] {
		t.Fatal("BytesDropped moved on a pass")
	}
	v6key := maps.PerIPKey(v6src.As16())
	if st, ok := h.peripStat(t, v6key); !ok || st.Pkts != 1 {
		t.Fatalf("v6 perip = %+v ok=%v", st, ok)
	}

	arp := ethFrame(ethARP, make([]byte, 28))
	b := h.snap(t)
	h.expect(t, arp, stats.SlotPassARP)
	a := h.snap(t)
	if got := a[stats.SlotBytesTotal] - b[stats.SlotBytesTotal]; got != uint64(len(arp)) {
		t.Fatalf("ARP BytesTotal moved %d, frame is %d", got, len(arp))
	}
	if a[stats.SlotBytesDropped] != b[stats.SlotBytesDropped] {
		t.Fatal("BytesDropped moved on ARP pass")
	}

	dropf := v4TCP("198.51.100.7", host4, 40000, 23, tcpSYN, v4Opt{})
	b = h.snap(t)
	h.expect(t, dropf, stats.SlotDropNoPolicy)
	a = h.snap(t)
	if got := a[stats.SlotBytesDropped] - b[stats.SlotBytesDropped]; got != uint64(len(dropf)) {
		t.Fatalf("BytesDropped moved %d, frame is %d", got, len(dropf))
	}

	v4f := v4TCP(v4src.String(), host4, 40000, 80, tcpSYN, v4Opt{})
	b = h.snap(t)
	h.expect(t, v4f, stats.SlotPassPublicTCP)
	a = h.snap(t)
	if a[stats.SlotPktsIPv6] != b[stats.SlotPktsIPv6] {
		t.Fatal("v4 packet moved PktsIPv6")
	}
	key := mappedKey(v4src.As4())
	st, ok := h.peripStat(t, key)
	if !ok || st.Pkts != 1 {
		t.Fatalf("mapped v4 perip = %+v ok=%v", st, ok)
	}
	var bare maps.PerIPKey
	raw := v4src.As4()
	copy(bare[12:], raw[:])
	if _, ok := h.peripStat(t, bare); ok {
		t.Fatal("v4 source was stored without the ::ffff:0:0/96 prefix")
	}
}
