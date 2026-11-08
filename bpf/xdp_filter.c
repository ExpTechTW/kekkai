// SPDX-License-Identifier: GPL-2.0
//
// kekkai data plane: XDP ingress filter + TC egress state seed, IPv4 and IPv6.
//
// Ingress decision order (first match wins; readme "過濾模型" is the spec):
//   L2  ARP                                   → PASS if filter.allow_arp
//       anything else that is not IPv4/IPv6   → DROP
//   L3  bad version / IHL, datagram longer than the frame, IPv6 extension
//       chain too long                        → DROP (malformed)
//    1. source in static_blocklist            → DROP
//    2. non-first fragment                    → PASS (no L4 header; the
//       first fragment was filtered and the kernel discards datagrams it
//       cannot reassemble or whose fragments overlap)
//    3. TCP  invalid flag combination         → DROP (malformed)
//            ACK or RST set                   → PASS (established; creates
//              no state). Exception: if the only socket that could take it
//              is a listener (SYN-cookie completion), the port policy
//              decides as for a SYN — cookies cannot be brute-forced past
//              the allowlist
//            SYN                              → port policy (5)
//    4. UDP  reply on a flow seeded by egress → PASS
//            DHCP/DHCPv6 reply within 60 s of a local request → PASS
//            otherwise                        → port policy (5)
//       ICMP / ICMPv6
//            echo request / reply             → PASS if filter.allow_icmp
//            frag-needed / packet-too-big     → PASS (PMTU; the kernel checks
//                                               them against its own sockets)
//            other error quoting a live local TCP/UDP socket, or a local
//            ping when filter.allow_icmp      → PASS
//            NDP (hop limit 255), MLD (hop limit 1)    → PASS (IPv6 needs them)
//            anything else (redirect, timestamp, ...)  → DROP
//       other L4 protocols                    → DROP
//    5. dst port public                       → PASS
//       dst port private + source allowlisted → PASS
//       dst port private otherwise            → DROP
//       no rule                               → DROP (default deny)
//
// Source addresses are taken at face value. The allowlist cannot tell a
// spoofed source from a real one; anti-spoofing has to happen upstream.
//
// IPv4 addresses are stored IPv4-mapped (::ffff:a.b.c.d), so both families
// share one set of maps and one code path.

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "headers.h"

char __license[] SEC("license") = "GPL";

#define BLOCKLIST_MAX 1048576
#define ALLOWLIST_MAX 65536
#define FLOW_MAX      262144
#define PERIP_MAX     65536   // overridden by the loader
#define PORTS_MAX     4096

#define NSEC           1000000000LL
#define FLOW_TTL_NS    (120 * NSEC)   // UDP flow idle timeout
#define FLOW_TOUCH_NS  NSEC           // refresh last_seen at most once a second
#define DHCP_WINDOW_NS (60 * NSEC)    // RFC 2131 retransmit backoff tops out at 64 s

#define IPV6_EXT_MAX       6     // extension headers walked before giving up
#define IPV6_EXT_MAX_BYTES 512
#define L4_OFF_MAX (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + IPV6_EXT_MAX_BYTES)

#define DHCP4_SERVER 67
#define DHCP4_CLIENT 68
#define DHCP6_CLIENT 546
#define DHCP6_SERVER 547

// --- stats slots: keep in sync with internal/stats -------------------------
enum {
    // Verdicts. Every frame bumps exactly one; drops come first, then passes.
    // Userspace derives the passed / dropped / total packet counts.
    STAT_DROP_NON_IP = 0,
    STAT_DROP_MALFORMED,
    STAT_DROP_BLOCKLIST,
    STAT_DROP_NOT_ALLOWED,
    STAT_DROP_NO_POLICY,
    STAT_PASS_ARP,          // first pass verdict
    STAT_PASS_FRAGMENT,
    STAT_PASS_TCP_EST,
    STAT_PASS_UDP_FLOW,
    STAT_PASS_DHCP,
    STAT_PASS_ICMP,
    STAT_PASS_PUBLIC_TCP,
    STAT_PASS_PUBLIC_UDP,
    STAT_PASS_PRIVATE_TCP,
    STAT_PASS_PRIVATE_UDP,
    STAT_VERDICTS,

    // Traffic mix of IP packets, whatever the verdict. Order: TCP, UDP,
    // ICMP (v4+v6), other.
    STAT_PKTS_TCP = STAT_VERDICTS,
    STAT_PKTS_UDP,
    STAT_PKTS_ICMP,
    STAT_PKTS_OTHER,
    STAT_BYTES_TCP,
    STAT_BYTES_UDP,
    STAT_BYTES_ICMP,
    STAT_BYTES_OTHER,
    STAT_PKTS_IPV6,
    STAT_BYTES_IPV6,
    STAT_BYTES_TOTAL,       // every frame, IP or not
    STAT_BYTES_DROPPED,
    STAT_SLOTS,
};

// runtime_cfg flags: keep in sync with internal/maps
enum {
    RT_ALLOW_ICMP  = 1u << 0,   // echo request/reply
    RT_ALLOW_ARP   = 1u << 1,
    RT_EGRESS_SEED = 1u << 2,   // TC egress hook attached
};

enum { PORT_PUBLIC = 1, PORT_PRIVATE = 2 };

// --- map types ---------------------------------------------------------------

struct addr {
    __be32 w[4];                // IPv6, or IPv4-mapped IPv6
};

struct lpm_key {
    __u32 prefixlen;            // IPv4 /n is stored as /(96+n)
    struct addr addr;
};

struct port_key {
    __be16 port;
    __u8   proto;
    __u8   _pad;
};

struct flow_key {
    struct addr saddr;          // remote
    struct addr daddr;          // local
    __be16 sport;
    __be16 dport;
    __u8   proto;
    __u8   _pad[3];
};

struct flow_val {
    __u64 last_seen_ns;
};

struct perip_stat {
    __u64 pkts;
    __u64 bytes;
    __u64 pkts_dropped;
    __u64 bytes_dropped;
    __u64 last_seen_ns;
    __u8  last_proto;
    __u8  blocked;
    __u8  _pad[6];
};

struct counters {
    __u64 c[STAT_SLOTS];
};

// --- maps --------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(max_entries, BLOCKLIST_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(max_entries, ALLOWLIST_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allowlist SEC(".maps");

// {dst port, proto} → PORT_PUBLIC / PORT_PRIVATE
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_key);
    __type(value, __u8);
    __uint(max_entries, PORTS_MAX);
} ports SEC(".maps");

// UDP flows the host itself opened; written only by the egress hook.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
    __uint(max_entries, FLOW_MAX);
} flowtrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct counters);
    __uint(max_entries, 1);
} stats SEC(".maps");

// Per-source stats. PER-CPU so the per-packet update stays on the local
// core. Userspace sums the counters, ORs blocked, and takes last_proto
// from the CPU with the latest last_seen. Key stays 16 bytes, value 48.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, struct addr);
    __type(value, struct perip_stat);
    __uint(max_entries, PERIP_MAX);
} perip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);       // RT_* flags
    __uint(max_entries, 1);
} runtime_cfg SEC(".maps");

// Last time the local DHCP client transmitted: [0] DHCPv4, [1] DHCPv6.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} dhcp_tx SEC(".maps");

// --- parsing -----------------------------------------------------------------

struct pkt {
    struct flow_key k;          // ports are filled in by the L4 step
    __u64 now;
    __u32 l4off;                // L4 header offset from the start of the frame
    __u32 l4len;                // IP payload bytes from l4off on
    __u8  family;               // 4 or 6 once an IP header was read, else 0
    __u8  hlim;                 // TTL / hop limit
    __u8  frag;                 // non-first fragment
};

enum { L3_OK, L3_NOT_IP, L3_BAD };

static __always_inline void addr_from_v4(struct addr *a, __be32 v4)
{
    a->w[0] = 0;
    a->w[1] = 0;
    a->w[2] = bpf_htonl(0xffff);
    a->w[3] = v4;
}

static __always_inline int ipv6_is_ext(__u8 nh)
{
    return nh == NEXTHDR_HOP || nh == NEXTHDR_ROUTING || nh == NEXTHDR_DEST ||
           nh == NEXTHDR_FRAGMENT || nh == NEXTHDR_AUTH;
}

static __always_inline int parse_ipv4(struct iphdr *ip, void *data_end,
                                      __u32 frame_len, struct pkt *p)
{
    if ((void *)(ip + 1) > data_end)
        return L3_BAD;
    p->family = 4;
    addr_from_v4(&p->k.saddr, ip->saddr);
    addr_from_v4(&p->k.daddr, ip->daddr);
    p->k.proto = ip->protocol;
    p->hlim = ip->ttl;

    __u32 hlen = (ip->ihl_version & 0x0f) << 2;
    __u32 tot = bpf_ntohs(ip->tot_len);
    if ((ip->ihl_version >> 4) != 4 || hlen < sizeof(*ip))
        return L3_BAD;
    // tot_len 0 marks a GRO / BIG TCP aggregate whose length lives in the
    // skb; the kernel drops any other zero-length datagram itself. The
    // datagram is compared with the frame length, not data_end: on egress
    // only the headers of a GSO / zerocopy skb are linear.
    if (tot == 0)
        tot = 0xffff;
    else if (tot < hlen || sizeof(struct ethhdr) + tot > frame_len)
        return L3_BAD;

    p->frag = (bpf_ntohs(ip->frag_off) & IP_OFFSET) != 0;
    p->l4off = sizeof(struct ethhdr) + hlen;
    p->l4len = tot - hlen;
    return L3_OK;
}

static __always_inline int parse_ipv6(struct ipv6hdr *ip6, void *data_end,
                                      __u32 frame_len, struct pkt *p)
{
    if ((void *)(ip6 + 1) > data_end)
        return L3_BAD;
    // ::ffff:a.b.c.d must never appear on the wire (the kernel drops it in
    // ip6_rcv_core). Reject it before the address is recorded, or it would
    // match IPv4 entries of the shared maps and be booked on that v4 host.
    if ((ip6->vtc >> 4) != 6 ||
        (ip6->saddr[0] == 0 && ip6->saddr[1] == 0 &&
         ip6->saddr[2] == bpf_htonl(0xffff)))
        return L3_BAD;
    p->family = 6;
    __builtin_memcpy(&p->k.saddr, ip6->saddr, sizeof(p->k.saddr));
    __builtin_memcpy(&p->k.daddr, ip6->daddr, sizeof(p->k.daddr));
    p->hlim = ip6->hop_limit;

    __u32 plen = bpf_ntohs(ip6->payload_len);
    if (plen == 0)              // jumbogram / BIG TCP aggregate
        plen = 0xffff;
    else if (sizeof(struct ethhdr) + sizeof(*ip6) + plen > frame_len)
        return L3_BAD;

    // Step over extension headers to the upper-layer header. Every
    // extension header lies inside the payload and is at least 8 bytes.
    void *base = ip6 + 1;
    __u8 nh = ip6->nexthdr;
    __u32 off = 0;
#pragma unroll
    for (int i = 0; i < IPV6_EXT_MAX; i++) {
        if (!ipv6_is_ext(nh))
            break;
        struct ipv6_ext *h = base + off;
        if ((void *)(h + 1) > data_end || off + sizeof(*h) > plen)
            return L3_BAD;
        __u32 len;
        if (nh == NEXTHDR_FRAGMENT) {
            len = sizeof(*h);
            if (h->frag_off & bpf_htons(IP6_OFFSET)) {
                // Past the first fragment only payload follows.
                p->frag = 1;
                nh = h->nexthdr;
                off += len;
                break;
            }
        } else if (nh == NEXTHDR_AUTH) {
            len = ((__u32)h->hdrlen + 2) << 2;
        } else {
            len = ((__u32)h->hdrlen + 1) << 3;
        }
        nh = h->nexthdr;
        off += len;
        if (off > IPV6_EXT_MAX_BYTES)
            return L3_BAD;
    }
    if ((!p->frag && ipv6_is_ext(nh)) || off > plen)
        return L3_BAD;

    p->k.proto = nh;
    p->l4off = sizeof(struct ethhdr) + sizeof(*ip6) + off;
    p->l4len = plen - off;
    return L3_OK;
}

static __always_inline int parse_l3(void *data, void *data_end, __u32 frame_len,
                                    struct pkt *p)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return L3_BAD;
    if (eth->h_proto == bpf_htons(ETH_P_IP))
        return parse_ipv4((void *)(eth + 1), data_end, frame_len, p);
    if (eth->h_proto == bpf_htons(ETH_P_IPV6))
        return parse_ipv6((void *)(eth + 1), data_end, frame_len, p);
    return L3_NOT_IP;
}

// l4_hdr returns the L4 header when `need` bytes of it lie inside both the
// frame and the IP payload. Checking the payload length too matters: bytes
// past tot_len (Ethernet padding, trailing junk) are attacker-chosen and
// the kernel trims them, so a header that only fits in the frame is fake.
// The l4off re-check is load-bearing for the verifier: l4off shares a stack
// slot with l4len, so its spilled bounds do not survive.
static __always_inline void *l4_hdr(void *data, void *data_end, struct pkt *p,
                                    __u32 need)
{
    __u32 off = p->l4off;
    if (off > L4_OFF_MAX || p->l4len < need)
        return NULL;
    void *h = data + off;
    if (h + need > data_end)
        return NULL;
    return h;
}

// --- socket lookups ----------------------------------------------------------

enum { SK_NONE, SK_LISTEN, SK_CONN };

// sk_find asks the kernel's socket tables who would receive a packet with
// this tuple (seen from the remote side, like an incoming packet).
static __always_inline int sk_find(struct xdp_md *ctx, struct bpf_sock_tuple *t,
                                   __u32 len, __u8 proto)
{
    struct bpf_sock *sk;
    int r;
    if (proto == IPPROTO_TCP) {
        sk = bpf_skc_lookup_tcp(ctx, t, len, BPF_F_CURRENT_NETNS, 0);
        if (!sk)
            return SK_NONE;
        r = sk->state == BPF_TCP_LISTEN ? SK_LISTEN : SK_CONN;
        bpf_sk_release(sk);
        return r;
    }
    if (proto == IPPROTO_UDP) {
        sk = bpf_sk_lookup_udp(ctx, t, len, BPF_F_CURRENT_NETNS, 0);
        if (!sk)
            return SK_NONE;
        bpf_sk_release(sk);
        return SK_CONN;
    }
    return SK_NONE;
}

// fill_tuple builds a lookup tuple and returns its size.
static __always_inline __u32 fill_tuple(struct bpf_sock_tuple *t, __u8 family,
                                        struct addr *src, struct addr *dst,
                                        __be16 sport, __be16 dport)
{
    if (family == 4) {
        t->ipv4.saddr = src->w[3];
        t->ipv4.daddr = dst->w[3];
        t->ipv4.sport = sport;
        t->ipv4.dport = dport;
        return sizeof(t->ipv4);
    }
    __builtin_memcpy(t->ipv6.saddr, src, sizeof(t->ipv6.saddr));
    __builtin_memcpy(t->ipv6.daddr, dst, sizeof(t->ipv6.daddr));
    t->ipv6.sport = sport;
    t->ipv6.dport = dport;
    return sizeof(t->ipv6);
}

// --- policy ------------------------------------------------------------------

static __always_inline __u8 port_class(struct pkt *p)
{
    struct port_key pk = { .port = p->k.dport, .proto = p->k.proto };
    __u8 *cls = bpf_map_lookup_elem(&ports, &pk);
    return cls ? *cls : 0;
}

static __always_inline int port_policy(struct pkt *p, __u8 cls)
{
    int tcp = p->k.proto == IPPROTO_TCP;
    if (!cls)
        return STAT_DROP_NO_POLICY;
    if (cls == PORT_PUBLIC)
        return tcp ? STAT_PASS_PUBLIC_TCP : STAT_PASS_PUBLIC_UDP;

    struct lpm_key ak = { .prefixlen = 128, .addr = p->k.saddr };
    if (bpf_map_lookup_elem(&allowlist, &ak))
        return tcp ? STAT_PASS_PRIVATE_TCP : STAT_PASS_PRIVATE_UDP;
    return STAT_DROP_NOT_ALLOWED;
}

static __always_inline int decide_tcp(struct xdp_md *ctx, void *data,
                                      void *data_end, struct pkt *p)
{
    struct tcphdr *t = l4_hdr(data, data_end, p, sizeof(*t));
    if (!t)
        return STAT_DROP_MALFORMED;
    p->k.sport = t->source;
    p->k.dport = t->dest;

    // Every real segment carries SYN, ACK or RST, and SYN never pairs with
    // FIN or RST. NULL / FIN / Xmas / SYN|FIN probes are scans or evasion;
    // FIN without ACK in particular would map listening ports.
    __u8 f = t->flags;
    if (!(f & (TCP_SYN | TCP_ACK | TCP_RST)) ||
        ((f & TCP_SYN) && (f & (TCP_FIN | TCP_RST))))
        return STAT_DROP_MALFORMED;

    __u8 cls = port_class(p);
    if (!(f & (TCP_ACK | TCP_RST)))
        return port_policy(p, cls);

    // Established traffic, stateless ("tcp-established"): the kernel takes
    // these only for an existing connection and answers anything else with
    // RST, so no state is created here. The one case that needs a closer
    // look is a segment that only a listener would take: under SYN cookies
    // a guessed ACK becomes a connection, so it must pass the same port
    // policy as a SYN. Public ports skip the lookup — a SYN is allowed there
    // anyway.
    if (cls != PORT_PUBLIC) {
        struct bpf_sock_tuple tup = {};
        __u32 len = fill_tuple(&tup, p->family, &p->k.saddr, &p->k.daddr,
                               p->k.sport, p->k.dport);
        if (sk_find(ctx, &tup, len, IPPROTO_TCP) == SK_LISTEN)
            return port_policy(p, cls);
    }
    return STAT_PASS_TCP_EST;
}

// Refreshed by egress only: replies alone must not keep a flow alive after
// the local socket is gone.
static __always_inline int flow_alive(struct flow_key *k, __u64 now)
{
    struct flow_val *v = bpf_map_lookup_elem(&flowtrack, k);
    // Signed: another CPU may have stored a slightly newer timestamp.
    return v && (__s64)(now - v->last_seen_ns) <= FLOW_TTL_NS;
}

// DHCP replies are only expected right after the local client asked. With
// no egress hook there is nothing to check against, so keep leases alive.
// DHCPv6 replies always come from a link-local server or relay.
static __always_inline int dhcp_reply(struct pkt *p, __u32 flags)
{
    __u32 idx;
    if (p->family == 4 && p->k.sport == bpf_htons(DHCP4_SERVER) &&
        p->k.dport == bpf_htons(DHCP4_CLIENT))
        idx = 0;
    else if (p->family == 6 && p->k.sport == bpf_htons(DHCP6_SERVER) &&
             p->k.dport == bpf_htons(DHCP6_CLIENT) &&
             (p->k.saddr.w[0] & bpf_htonl(0xffc00000)) == bpf_htonl(0xfe800000))
        idx = 1;
    else
        return 0;
    if (!(flags & RT_EGRESS_SEED))
        return 1;
    __u64 *tx = bpf_map_lookup_elem(&dhcp_tx, &idx);
    return tx && *tx && (__s64)(p->now - *tx) <= DHCP_WINDOW_NS;
}

static __always_inline int decide_udp(void *data, void *data_end, struct pkt *p,
                                      __u32 flags)
{
    struct udphdr *u = l4_hdr(data, data_end, p, sizeof(*u));
    if (!u)
        return STAT_DROP_MALFORMED;
    p->k.sport = u->source;
    p->k.dport = u->dest;
    if (flow_alive(&p->k, p->now))
        return STAT_PASS_UDP_FLOW;
    if (dhcp_reply(p, flags))
        return STAT_PASS_DHCP;
    return port_policy(p, port_class(p));
}

// An ICMP error quotes the datagram we sent (local → remote). It is worth
// delivering if a local socket owns that datagram — looked up from the
// remote side, i.e. with source and destination swapped — or, when ping is
// allowed, if it quotes our own echo request (traceroute -I, mtr).
static __always_inline int quote_related(struct xdp_md *ctx, __u8 family,
                                         struct addr *src, struct addr *dst,
                                         __u8 proto, __be16 *l4, __u32 flags)
{
    if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
        __u8 type = *(__u8 *)l4;
        return (flags & RT_ALLOW_ICMP) &&
               (type == ICMP_ECHO || type == ICMPV6_ECHO_REQUEST);
    }
    struct bpf_sock_tuple t = {};
    __u32 len = fill_tuple(&t, family, dst, src, l4[1], l4[0]);
    return sk_find(ctx, &t, len, proto) == SK_CONN;
}

static __always_inline int icmp4_related(struct xdp_md *ctx, void *data,
                                         void *data_end, struct pkt *p,
                                         __u32 flags)
{
    void *ic = l4_hdr(data, data_end, p,
                      sizeof(struct icmphdr) + sizeof(struct iphdr) + 4);
    if (!ic)
        return 0;
    struct iphdr *in = ic + sizeof(struct icmphdr);
    __u32 ihl = (in->ihl_version & 0x0f) << 2;
    if (ihl < sizeof(*in) || sizeof(struct icmphdr) + ihl + 4 > p->l4len)
        return 0;
    __be16 *l4 = (void *)in + ihl;
    if ((void *)(l4 + 2) > data_end)
        return 0;
    struct addr src, dst;
    addr_from_v4(&src, in->saddr);
    addr_from_v4(&dst, in->daddr);
    return quote_related(ctx, 4, &src, &dst, in->protocol, l4, flags);
}

static __always_inline int icmp6_related(struct xdp_md *ctx, void *data,
                                         void *data_end, struct pkt *p,
                                         __u32 flags)
{
    void *ic = l4_hdr(data, data_end, p,
                      sizeof(struct icmphdr) + sizeof(struct ipv6hdr) + 4);
    if (!ic)
        return 0;
    struct ipv6hdr *in = ic + sizeof(struct icmphdr);
    struct addr src, dst;
    __builtin_memcpy(&src, in->saddr, sizeof(src));
    __builtin_memcpy(&dst, in->daddr, sizeof(dst));
    return quote_related(ctx, 6, &src, &dst, in->nexthdr, (void *)(in + 1),
                         flags);
}

static __always_inline int decide_icmp(struct xdp_md *ctx, void *data,
                                       void *data_end, struct pkt *p,
                                       __u32 flags)
{
    struct icmphdr *ic = l4_hdr(data, data_end, p, sizeof(*ic));
    if (!ic)
        return STAT_DROP_MALFORMED;
    __u8 type = ic->type;
    int ok = 0;

    // Frag-needed / packet-too-big pass without a socket check: they also
    // serve NATed and forwarded flows that have no local socket, and the
    // kernel validates them against its own sockets (and clamps the MTU).
    if (p->family == 4) {
        if (type == ICMP_ECHO || type == ICMP_ECHOREPLY)
            ok = flags & RT_ALLOW_ICMP;
        else if (type == ICMP_DEST_UNREACH && ic->code == ICMP_FRAG_NEEDED)
            ok = 1;
        else if (type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED ||
                 type == ICMP_PARAMETERPROB)
            ok = icmp4_related(ctx, data, data_end, p, flags);
    } else {
        if (type == ICMPV6_ECHO_REQUEST || type == ICMPV6_ECHO_REPLY)
            ok = flags & RT_ALLOW_ICMP;
        else if (type == ICMPV6_PKT_TOOBIG)
            ok = 1;
        else if (type >= ICMPV6_DEST_UNREACH && type <= ICMPV6_PARAMPROB)
            ok = icmp6_related(ctx, data, data_end, p, flags);
        // RFC 4861: NDP must arrive with hop limit 255, i.e. from on-link.
        else if (type >= ICMPV6_NDISC_RS && type <= ICMPV6_NDISC_NA)
            ok = p->hlim == 255;
        // MLD is link-scoped and sent with hop limit 1.
        else if (type == ICMPV6_MLD_QUERY || type == ICMPV6_MLD_REPORT ||
                 type == ICMPV6_MLD_DONE || type == ICMPV6_MLD2_REPORT)
            ok = p->hlim == 1;
    }
    return ok ? STAT_PASS_ICMP : STAT_DROP_NO_POLICY;
}

static __always_inline int decide(struct xdp_md *ctx, struct pkt *p,
                                  __u32 frame_len, __u32 flags)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return STAT_DROP_MALFORMED;
    if (eth->h_proto == bpf_htons(ETH_P_ARP))
        return (flags & RT_ALLOW_ARP) ? STAT_PASS_ARP : STAT_DROP_NON_IP;

    int l3 = parse_l3(data, data_end, frame_len, p);
    if (l3 == L3_NOT_IP)
        return STAT_DROP_NON_IP;
    if (l3 != L3_OK)
        return STAT_DROP_MALFORMED;

    // Blocklist first: a blocked source gets nothing, not even established
    // traffic, fragments or ICMP.
    struct lpm_key bk = { .prefixlen = 128, .addr = p->k.saddr };
    if (bpf_map_lookup_elem(&blocklist, &bk))
        return STAT_DROP_BLOCKLIST;

    if (p->frag)
        return STAT_PASS_FRAGMENT;

    __u8 proto = p->k.proto;
    if (proto == IPPROTO_TCP)
        return decide_tcp(ctx, data, data_end, p);
    if (proto == IPPROTO_UDP)
        return decide_udp(data, data_end, p, flags);
    if ((proto == IPPROTO_ICMP && p->family == 4) ||
        (proto == IPPROTO_ICMPV6 && p->family == 6))
        return decide_icmp(ctx, data, data_end, p, flags);
    return STAT_DROP_NO_POLICY;
}

static __always_inline __u32 proto_class(__u8 proto)
{
    switch (proto) {
    case IPPROTO_TCP:    return 0;
    case IPPROTO_UDP:    return 1;
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6: return 2;
    }
    return 3;
}

static __always_inline void perip_touch(struct pkt *p, __u32 len, int dropped)
{
    struct perip_stat *ps = bpf_map_lookup_elem(&perip, &p->k.saddr);
    if (ps) {
        ps->pkts += 1;
        ps->bytes += len;
        if (dropped) {
            ps->pkts_dropped += 1;
            ps->bytes_dropped += len;
            ps->blocked = 1;
        }
        ps->last_seen_ns = p->now;
        ps->last_proto = p->k.proto;
        return;
    }
    struct perip_stat init = {
        .pkts = 1,
        .bytes = len,
        .last_seen_ns = p->now,
        .last_proto = p->k.proto,
    };
    if (dropped) {
        init.pkts_dropped = 1;
        init.bytes_dropped = len;
        init.blocked = 1;
    }
    bpf_map_update_elem(&perip, &p->k.saddr, &init, BPF_NOEXIST);
}

SEC("xdp")
int kekkai_xdp(struct xdp_md *ctx)
{
    __u32 zero = 0;
    struct counters *st = bpf_map_lookup_elem(&stats, &zero);
    __u32 *flags = bpf_map_lookup_elem(&runtime_cfg, &zero);
    if (!st || !flags)
        return XDP_DROP;        // unreachable: single-slot arrays always resolve

    __u32 len = ctx->data_end - ctx->data;
    struct pkt p = {};
    p.now = bpf_ktime_get_coarse_ns();
    __u32 reason = decide(ctx, &p, len, *flags);
    if (reason >= STAT_VERDICTS)
        reason = STAT_DROP_NO_POLICY;
    int pass = reason >= STAT_PASS_ARP;

    st->c[reason] += 1;
    st->c[STAT_BYTES_TOTAL] += len;
    if (!pass)
        st->c[STAT_BYTES_DROPPED] += len;
    if (p.family) {
        __u32 cls = proto_class(p.k.proto);
        st->c[STAT_PKTS_TCP + cls] += 1;
        st->c[STAT_BYTES_TCP + cls] += len;
        if (p.family == 6) {
            st->c[STAT_PKTS_IPV6] += 1;
            st->c[STAT_BYTES_IPV6] += len;
        }
        perip_touch(&p, len, !pass);
    }
    return pass ? XDP_PASS : XDP_DROP;
}

// --- egress ------------------------------------------------------------------
//
// Seeds the UDP return path: local:a → remote:b admits remote:b → local:a.
// TCP needs no state (established traffic passes on flags), and leaving it
// out means nothing the kernel sends on its own, such as a RST, can open a
// path. Replies from public UDP services are not seeded either: their port
// is open anyway, and seeding them would let spoofed floods churn the table.
// Returns TC_ACT_UNSPEC (tcx "next") so other egress programs still run.
SEC("tc")
int kekkai_tc_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct pkt p = {};

    if (parse_l3(data, data_end, skb->len, &p) != L3_OK || p.frag ||
        p.k.proto != IPPROTO_UDP)
        return TC_ACT_UNSPEC;
    struct udphdr *u = l4_hdr(data, data_end, &p, sizeof(*u));
    if (!u)
        return TC_ACT_UNSPEC;
    __u64 now = bpf_ktime_get_coarse_ns();

    // A DHCP client request opens the reply window; nothing to seed.
    __u32 v6 = p.family == 6;
    if (u->source == bpf_htons(v6 ? DHCP6_CLIENT : DHCP4_CLIENT) &&
        u->dest == bpf_htons(v6 ? DHCP6_SERVER : DHCP4_SERVER)) {
        __u64 *tx = bpf_map_lookup_elem(&dhcp_tx, &v6);
        if (tx)
            *tx = now;
        return TC_ACT_UNSPEC;
    }

    struct port_key pk = { .port = u->source, .proto = IPPROTO_UDP };
    __u8 *cls = bpf_map_lookup_elem(&ports, &pk);
    if (cls && *cls == PORT_PUBLIC)
        return TC_ACT_UNSPEC;

    struct flow_key rk = {
        .saddr = p.k.daddr,
        .daddr = p.k.saddr,
        .sport = u->dest,
        .dport = u->source,
        .proto = IPPROTO_UDP,
    };
    struct flow_val *v = bpf_map_lookup_elem(&flowtrack, &rk);
    if (v) {
        if ((__s64)(now - v->last_seen_ns) > FLOW_TOUCH_NS)
            v->last_seen_ns = now;
    } else {
        struct flow_val nv = { .last_seen_ns = now };
        bpf_map_update_elem(&flowtrack, &rk, &nv, BPF_ANY);
    }
    return TC_ACT_UNSPEC;
}
