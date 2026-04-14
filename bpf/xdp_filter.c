// SPDX-License-Identifier: GPL-2.0
//
// WAF edge data plane — strict policy model.
//
// Decision flow (see readme §filter for the spec):
//   1. ARP                   → PASS (if enabled)
//      non-IPv4/ARP          → DROP
//   2. IP frag 2+            → PASS (no L4 header to inspect)
//   3. conntrack hit         → PASS (TCP/UDP stateful fast path)
//   4. return traffic        → PASS (TCP ACK, UDP ephemeral, ICMP-if-enabled)
//   4. static blocklist      → DROP
//   5. dynamic blocklist     → DROP (if not expired)
//   6. public port           → PASS (any source)
//   7. private port + allow  → PASS
//   8. private port, no allow→ DROP
//   9. no rule               → DROP (default deny)
//
// All counters are per-CPU to avoid contention on the hot path. Userspace
// sums across CPUs when rendering stats.

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "headers.h"

char __license[] SEC("license") = "GPL";

// --- map sizes --------------------------------------------------------------
#define BLOCKLIST_MAX_ENTRIES     1048576
#define ALLOWLIST_MAX_ENTRIES     65536
#define DYN_BLOCKLIST_MAX_ENTRIES 262144
#define FLOWTRACK_MAX_ENTRIES     262144
#define PERIP_MAX_ENTRIES         65536   // overridden by loader at runtime
#define PORTSET_MAX_ENTRIES       1024
#define EVENTS_RINGBUF_BYTES      (1 << 18)
#define FLOW_TCP_TTL_NS           (5ULL * 60ULL * 1000000000ULL)
#define FLOW_UDP_TTL_NS           (120ULL * 1000000000ULL)
#define DEFAULT_UDP_EPHEMERAL_MIN 32768
#define LEGACY_DHCP_CLIENT_PORT   68

// --- global stats slots -----------------------------------------------------
// Keep these in sync with internal/stats/stats.go.
enum {
    // basic counters
    STAT_PKTS_TOTAL        = 0,
    STAT_PKTS_PASSED       = 1,
    STAT_PKTS_DROPPED      = 2,
    STAT_BYTES_TOTAL       = 3,
    STAT_BYTES_DROPPED     = 4,

    // protocol breakdown
    STAT_PKTS_TCP          = 5,
    STAT_PKTS_UDP          = 6,
    STAT_PKTS_ICMP         = 7,
    STAT_PKTS_OTHER_L4     = 8,
    STAT_BYTES_TCP         = 9,
    STAT_BYTES_UDP         = 10,
    STAT_BYTES_ICMP        = 11,
    STAT_BYTES_OTHER_L4    = 12,

    // drop reasons
    STAT_DROP_NON_IPV4     = 13,
    STAT_DROP_MALFORMED    = 14,
    STAT_DROP_BLOCKLIST    = 15,
    STAT_DROP_DYN_BLOCK    = 16,
    STAT_DROP_NOT_ALLOWED  = 17,
    STAT_DROP_NO_POLICY    = 18,

    // pass reasons
    STAT_PASS_FRAGMENT     = 19,
    STAT_PASS_RETURN_TCP   = 20,
    STAT_PASS_RETURN_UDP   = 21,
    STAT_PASS_RETURN_ICMP  = 22,
    STAT_PASS_PUBLIC_TCP   = 23,
    STAT_PASS_PUBLIC_UDP   = 24,
    STAT_PASS_PRIVATE_TCP  = 25,
    STAT_PASS_PRIVATE_UDP  = 26,
    STAT_PASS_STATEFUL_TCP = 27,
    STAT_PASS_STATEFUL_UDP = 28,

    STAT_SLOTS             = 48,
};

// --- map key / value types --------------------------------------------------

struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr;
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

struct dyn_block_val {
    __u64 until_ns;
    __u8  reason;
    __u8  _pad[7];
};

struct runtime_cfg_v4 {
    __u32 initialized;
    __u32 flags;
    __u16 udp_ephemeral_min;
    __u16 _pad;
};

struct flow4_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  _pad[3];
};

struct flow4_val {
    __u64 last_seen_ns;
};

enum {
    RUNTIME_FLAG_ALLOW_ICMP = 1u << 0,
    RUNTIME_FLAG_ALLOW_ARP  = 1u << 1,
};

// Reserved for M4+: anomaly event layout locked in now.
struct event {
    __u64 ts_ns;
    __u32 saddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  event_type;
    __u8  action;
    __u8  reason;
};

// --- maps -------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(max_entries, BLOCKLIST_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(max_entries, ALLOWLIST_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allowlist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct dyn_block_val);
    __uint(max_entries, DYN_BLOCKLIST_MAX_ENTRIES);
} dyn_blocklist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);               // dst port in network byte order
    __type(value, __u8);
    __uint(max_entries, PORTSET_MAX_ENTRIES);
} public_tcp_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, PORTSET_MAX_ENTRIES);
} public_udp_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, PORTSET_MAX_ENTRIES);
} private_tcp_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, PORTSET_MAX_ENTRIES);
} private_udp_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow4_key);
    __type(value, struct flow4_val);
    __uint(max_entries, FLOWTRACK_MAX_ENTRIES);
} flowtrack_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_SLOTS);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct perip_stat);
    __uint(max_entries, PERIP_MAX_ENTRIES);
} perip_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct runtime_cfg_v4);
    __uint(max_entries, 1);
} runtime_cfg_v4 SEC(".maps");

// Reserved for M4+.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, EVENTS_RINGBUF_BYTES);
} events SEC(".maps");

// --- helpers ---------------------------------------------------------------

static __always_inline void stat_add(__u32 slot, __u64 delta) {
    __u64 *v = bpf_map_lookup_elem(&stats, &slot);
    if (v)
        *v += delta;
}

static __always_inline void perip_touch(__u32 saddr, __u64 len, __u8 proto,
                                         __u8 dropped) {
    struct perip_stat *ps = bpf_map_lookup_elem(&perip_v4, &saddr);
    if (ps) {
        ps->pkts += 1;
        ps->bytes += len;
        if (dropped) {
            ps->pkts_dropped += 1;
            ps->bytes_dropped += len;
            ps->blocked = 1;
        }
        ps->last_seen_ns = bpf_ktime_get_ns();
        ps->last_proto = proto;
        return;
    }
    struct perip_stat init = {
        .pkts          = 1,
        .bytes         = len,
        .pkts_dropped  = dropped ? 1 : 0,
        .bytes_dropped = dropped ? len : 0,
        .last_seen_ns  = bpf_ktime_get_ns(),
        .last_proto    = proto,
        .blocked       = dropped,
    };
    bpf_map_update_elem(&perip_v4, &saddr, &init, BPF_ANY);
}

static __always_inline int port_in(void *map, __u16 port_be) {
    return bpf_map_lookup_elem(map, &port_be) != NULL;
}

static __always_inline void runtime_cfg_get(__u8 *allow_arp, __u8 *allow_icmp,
                                            __u16 *udp_ephemeral_min) {
    *allow_arp = 1;
    *allow_icmp = 1;
    *udp_ephemeral_min = DEFAULT_UDP_EPHEMERAL_MIN;

    __u32 k = 0;
    struct runtime_cfg_v4 *cfg = bpf_map_lookup_elem(&runtime_cfg_v4, &k);
    if (!cfg || cfg->initialized != 1)
        return;

    *allow_arp = (cfg->flags & RUNTIME_FLAG_ALLOW_ARP) ? 1 : 0;
    *allow_icmp = (cfg->flags & RUNTIME_FLAG_ALLOW_ICMP) ? 1 : 0;
    if (cfg->udp_ephemeral_min >= 1024)
        *udp_ephemeral_min = cfg->udp_ephemeral_min;
}

static __always_inline __u64 flow_ttl_ns(__u8 proto) {
    return proto == IPPROTO_TCP ? FLOW_TCP_TTL_NS : FLOW_UDP_TTL_NS;
}

static __always_inline int flow_lookup_alive(struct flow4_key *k, __u64 now_ns) {
    struct flow4_val *v = bpf_map_lookup_elem(&flowtrack_v4, k);
    if (!v)
        return 0;
    if (now_ns - v->last_seen_ns <= flow_ttl_ns(k->proto)) {
        v->last_seen_ns = now_ns;
        return 1;
    }
    bpf_map_delete_elem(&flowtrack_v4, k);
    return 0;
}

static __always_inline void flow_upsert(struct flow4_key *k, __u64 now_ns) {
    struct flow4_val v = { .last_seen_ns = now_ns };
    bpf_map_update_elem(&flowtrack_v4, k, &v, BPF_ANY);
}

static __always_inline int flow_parse_v4_l4(void *data, void *data_end,
                                             struct iphdr **ip_out,
                                             __u8 *proto_out,
                                             __u16 *sport_be_out,
                                             __u16 *dport_be_out) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    __u16 frag = bpf_ntohs(ip->frag_off) & IP_FRAG_OFFSET_MASK;
    if (frag != 0)
        return 0;

    __u32 ihl = iphdr_ihl(ip);
    if (ihl < 5)
        return 0;

    void *l4 = (void *)ip + ihl * 4;
    __u8 proto = ip->protocol;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        *sport_be_out = tcp->source;
        *dport_be_out = tcp->dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return 0;
        *sport_be_out = udp->source;
        *dport_be_out = udp->dest;
    } else {
        return 0;
    }

    *ip_out = ip;
    *proto_out = proto;
    return 1;
}

// --- main --------------------------------------------------------------------

SEC("xdp")
int kekkai_xdp(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len  = (__u64)(data_end - data);

    stat_add(STAT_PKTS_TOTAL, 1);
    stat_add(STAT_BYTES_TOTAL, pkt_len);

    __u8 allow_arp = 1, allow_icmp = 1;
    __u16 udp_ephemeral_min = DEFAULT_UDP_EPHEMERAL_MIN;
    runtime_cfg_get(&allow_arp, &allow_icmp, &udp_ephemeral_min);

    // 1. ethernet + IPv4 only (ARP may be toggled at runtime)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        stat_add(STAT_DROP_MALFORMED, 1);
        stat_add(STAT_PKTS_DROPPED, 1);
        stat_add(STAT_BYTES_DROPPED, pkt_len);
        return XDP_DROP;
    }
    if (allow_arp && eth->h_proto == bpf_htons(ETH_P_ARP)) {
        stat_add(STAT_PKTS_PASSED, 1);
        return XDP_PASS;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        stat_add(STAT_DROP_NON_IPV4, 1);
        stat_add(STAT_PKTS_DROPPED, 1);
        stat_add(STAT_BYTES_DROPPED, pkt_len);
        return XDP_DROP;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        stat_add(STAT_DROP_MALFORMED, 1);
        stat_add(STAT_PKTS_DROPPED, 1);
        stat_add(STAT_BYTES_DROPPED, pkt_len);
        return XDP_DROP;
    }

    __u32 saddr = ip->saddr;
    __u8 proto  = ip->protocol;

    // protocol counters (counted before filtering so drops still show)
    switch (proto) {
    case IPPROTO_TCP:
        stat_add(STAT_PKTS_TCP, 1); stat_add(STAT_BYTES_TCP, pkt_len); break;
    case IPPROTO_UDP:
        stat_add(STAT_PKTS_UDP, 1); stat_add(STAT_BYTES_UDP, pkt_len); break;
    case IPPROTO_ICMP:
        stat_add(STAT_PKTS_ICMP, 1); stat_add(STAT_BYTES_ICMP, pkt_len); break;
    default:
        stat_add(STAT_PKTS_OTHER_L4, 1); stat_add(STAT_BYTES_OTHER_L4, pkt_len); break;
    }

    // 2. IP fragment 2+ — no L4 header, let kernel defrag handle it
    __u16 frag = bpf_ntohs(ip->frag_off) & IP_FRAG_OFFSET_MASK;
    if (frag != 0) {
        stat_add(STAT_PASS_FRAGMENT, 1);
        stat_add(STAT_PKTS_PASSED, 1);
        perip_touch(saddr, pkt_len, proto, 0);
        return XDP_PASS;
    }

    // Compute L4 start from IP IHL. Header length is ihl * 4 bytes, min 20.
    __u32 ihl = iphdr_ihl(ip);
    if (ihl < 5) {
        stat_add(STAT_DROP_MALFORMED, 1);
        stat_add(STAT_PKTS_DROPPED, 1);
        stat_add(STAT_BYTES_DROPPED, pkt_len);
        perip_touch(saddr, pkt_len, proto, 1);
        return XDP_DROP;
    }
    void *l4 = (void *)ip + ihl * 4;

    __u16 sport_be = 0, dport_be = 0;
    __u8 tcp_flags = 0;
    __u64 now_ns = bpf_ktime_get_ns();

    // Parse L4 header once (stateful + policy paths reuse these fields).
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            stat_add(STAT_DROP_MALFORMED, 1);
            stat_add(STAT_PKTS_DROPPED, 1);
            stat_add(STAT_BYTES_DROPPED, pkt_len);
            perip_touch(saddr, pkt_len, proto, 1);
            return XDP_DROP;
        }
        sport_be = tcp->source;
        dport_be = tcp->dest;
        tcp_flags = tcp->flags;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            stat_add(STAT_DROP_MALFORMED, 1);
            stat_add(STAT_PKTS_DROPPED, 1);
            stat_add(STAT_BYTES_DROPPED, pkt_len);
            perip_touch(saddr, pkt_len, proto, 1);
            return XDP_DROP;
        }
        sport_be = udp->source;
        dport_be = udp->dest;
    }

    // 3. stateful conntrack fast path (TCP/UDP only).
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        struct flow4_key fkey = {
            .saddr = saddr,
            .daddr = ip->daddr,
            .sport = sport_be,
            .dport = dport_be,
            .proto = proto,
        };
        if (flow_lookup_alive(&fkey, now_ns)) {
            if (proto == IPPROTO_TCP) {
                stat_add(STAT_PASS_STATEFUL_TCP, 1);
                stat_add(STAT_PASS_RETURN_TCP, 1);
            } else {
                stat_add(STAT_PASS_STATEFUL_UDP, 1);
                stat_add(STAT_PASS_RETURN_UDP, 1);
            }
            stat_add(STAT_PKTS_PASSED, 1);
            perip_touch(saddr, pkt_len, proto, 0);
            return XDP_PASS;
        }
    }

    // 4. return traffic fallback → PASS
    //    - ICMP: always (ping replies, PMTU, etc)
    //    - TCP: packets that are part of an established session. In
    //      stateless terms this is the classic "tcp-established" match
    //      used by AWS NACLs and Juniper filters: any segment where
    //      ACK, RST or FIN is set. A brand-new connection is SYN-only,
    //      which is the single case that falls through to port checks.
    //      Matching RST/FIN is essential — otherwise the server-side
    //      session dies the moment the peer sends a reset or starts a
    //      graceful close, because those packets carry no payload ACK.
    //    - UDP: dst port in ephemeral range (matches responses to
    //      agent-initiated DNS/NTP/etc without conntrack). DHCP client
    //      replies (dst 68) are also always allowed so lease renewal does
    //      not flap the interface IP.
    if (proto == IPPROTO_ICMP && allow_icmp) {
        stat_add(STAT_PASS_RETURN_ICMP, 1);
        stat_add(STAT_PKTS_PASSED, 1);
        perip_touch(saddr, pkt_len, proto, 0);
        return XDP_PASS;
    }
    if (proto == IPPROTO_TCP) {
        if (tcp_flags & (TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN)) {
            struct flow4_key fkey = {
                .saddr = saddr, .daddr = ip->daddr,
                .sport = sport_be, .dport = dport_be, .proto = proto,
            };
            flow_upsert(&fkey, now_ns);
            stat_add(STAT_PASS_RETURN_TCP, 1);
            stat_add(STAT_PKTS_PASSED, 1);
            perip_touch(saddr, pkt_len, proto, 0);
            return XDP_PASS;
        }
    } else if (proto == IPPROTO_UDP) {
        if (dport_be == bpf_htons(LEGACY_DHCP_CLIENT_PORT)) {
            struct flow4_key fkey = {
                .saddr = saddr, .daddr = ip->daddr,
                .sport = sport_be, .dport = dport_be, .proto = proto,
            };
            flow_upsert(&fkey, now_ns);
            stat_add(STAT_PASS_RETURN_UDP, 1);
            stat_add(STAT_PKTS_PASSED, 1);
            perip_touch(saddr, pkt_len, proto, 0);
            return XDP_PASS;
        }
        if (bpf_ntohs(dport_be) >= udp_ephemeral_min) {
            struct flow4_key fkey = {
                .saddr = saddr, .daddr = ip->daddr,
                .sport = sport_be, .dport = dport_be, .proto = proto,
            };
            flow_upsert(&fkey, now_ns);
            stat_add(STAT_PASS_RETURN_UDP, 1);
            stat_add(STAT_PKTS_PASSED, 1);
            perip_touch(saddr, pkt_len, proto, 0);
            return XDP_PASS;
        }
    } else {
        // Unknown L4 proto and not a return classification — default deny.
        stat_add(STAT_DROP_NO_POLICY, 1);
        stat_add(STAT_PKTS_DROPPED, 1);
        stat_add(STAT_BYTES_DROPPED, pkt_len);
        perip_touch(saddr, pkt_len, proto, 1);
        return XDP_DROP;
    }

    // 5. static blocklist
    struct lpm_v4_key bkey = { .prefixlen = 32, .addr = saddr };
    if (bpf_map_lookup_elem(&blocklist_v4, &bkey)) {
        stat_add(STAT_DROP_BLOCKLIST, 1);
        stat_add(STAT_PKTS_DROPPED, 1);
        stat_add(STAT_BYTES_DROPPED, pkt_len);
        perip_touch(saddr, pkt_len, proto, 1);
        return XDP_DROP;
    }

    // 6. dynamic blocklist (TTL)
    struct dyn_block_val *dyn = bpf_map_lookup_elem(&dyn_blocklist_v4, &saddr);
    if (dyn && dyn->until_ns > now_ns) {
        stat_add(STAT_DROP_DYN_BLOCK, 1);
        stat_add(STAT_PKTS_DROPPED, 1);
        stat_add(STAT_BYTES_DROPPED, pkt_len);
        perip_touch(saddr, pkt_len, proto, 1);
        return XDP_DROP;
    }

    // 7. public ports (any source)
    if (proto == IPPROTO_TCP && port_in(&public_tcp_ports, dport_be)) {
        struct flow4_key fkey = {
            .saddr = saddr, .daddr = ip->daddr,
            .sport = sport_be, .dport = dport_be, .proto = proto,
        };
        flow_upsert(&fkey, now_ns);
        stat_add(STAT_PASS_PUBLIC_TCP, 1);
        stat_add(STAT_PKTS_PASSED, 1);
        perip_touch(saddr, pkt_len, proto, 0);
        return XDP_PASS;
    }
    if (proto == IPPROTO_UDP && port_in(&public_udp_ports, dport_be)) {
        struct flow4_key fkey = {
            .saddr = saddr, .daddr = ip->daddr,
            .sport = sport_be, .dport = dport_be, .proto = proto,
        };
        flow_upsert(&fkey, now_ns);
        stat_add(STAT_PASS_PUBLIC_UDP, 1);
        stat_add(STAT_PKTS_PASSED, 1);
        perip_touch(saddr, pkt_len, proto, 0);
        return XDP_PASS;
    }

    // 8. private ports (allowlist only)
    __u8 is_private = 0;
    if (proto == IPPROTO_TCP && port_in(&private_tcp_ports, dport_be))
        is_private = 1;
    else if (proto == IPPROTO_UDP && port_in(&private_udp_ports, dport_be))
        is_private = 1;

    if (is_private) {
        struct lpm_v4_key akey = { .prefixlen = 32, .addr = saddr };
        if (bpf_map_lookup_elem(&allowlist_v4, &akey)) {
            struct flow4_key fkey = {
                .saddr = saddr, .daddr = ip->daddr,
                .sport = sport_be, .dport = dport_be, .proto = proto,
            };
            flow_upsert(&fkey, now_ns);
            if (proto == IPPROTO_TCP)
                stat_add(STAT_PASS_PRIVATE_TCP, 1);
            else
                stat_add(STAT_PASS_PRIVATE_UDP, 1);
            stat_add(STAT_PKTS_PASSED, 1);
            perip_touch(saddr, pkt_len, proto, 0);
            return XDP_PASS;
        }
        stat_add(STAT_DROP_NOT_ALLOWED, 1);
        stat_add(STAT_PKTS_DROPPED, 1);
        stat_add(STAT_BYTES_DROPPED, pkt_len);
        perip_touch(saddr, pkt_len, proto, 1);
        return XDP_DROP;
    }

    // 8. default deny
    stat_add(STAT_DROP_NO_POLICY, 1);
    stat_add(STAT_PKTS_DROPPED, 1);
    stat_add(STAT_BYTES_DROPPED, pkt_len);
    perip_touch(saddr, pkt_len, proto, 1);
    return XDP_DROP;
}

SEC("tc")
int kekkai_tcx_egress_seed(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip = NULL;
    __u8 proto = 0;
    __u16 sport_be = 0, dport_be = 0;
    if (!flow_parse_v4_l4(data, data_end, &ip, &proto, &sport_be, &dport_be))
        return TC_ACT_OK;

    // Seed ingress-fast-path key for the reverse direction:
    // outbound local:a -> remote:b  ==> insert remote:b -> local:a.
    struct flow4_key reverse_key = {
        .saddr = ip->daddr,
        .daddr = ip->saddr,
        .sport = dport_be,
        .dport = sport_be,
        .proto = proto,
    };
    flow_upsert(&reverse_key, bpf_ktime_get_ns());
    return TC_ACT_OK;
}
