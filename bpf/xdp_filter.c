// SPDX-License-Identifier: GPL-2.0
//
// WAF edge data plane — strict policy model.
//
// Decision flow (see readme §filter for the spec):
//   1. ARP                   → PASS
//      non-IPv4/ARP          → DROP
//   2. IP frag 2+            → PASS (no L4 header to inspect)
//   3. return traffic        → PASS (TCP ACK, UDP ephemeral, ICMP)
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
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "headers.h"

char __license[] SEC("license") = "GPL";

// --- map sizes --------------------------------------------------------------
#define BLOCKLIST_MAX_ENTRIES     1048576
#define ALLOWLIST_MAX_ENTRIES     65536
#define DYN_BLOCKLIST_MAX_ENTRIES 262144
#define PERIP_MAX_ENTRIES         65536   // overridden by loader at runtime
#define PORTSET_MAX_ENTRIES       1024
#define EVENTS_RINGBUF_BYTES      (1 << 18)

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

// --- main --------------------------------------------------------------------

SEC("xdp")
int kekkai_xdp(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len  = (__u64)(data_end - data);

    stat_add(STAT_PKTS_TOTAL, 1);
    stat_add(STAT_BYTES_TOTAL, pkt_len);

    // 1. ethernet + IPv4 only (except ARP, which must pass for LAN liveness)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        stat_add(STAT_DROP_MALFORMED, 1);
        stat_add(STAT_PKTS_DROPPED, 1);
        stat_add(STAT_BYTES_DROPPED, pkt_len);
        return XDP_DROP;
    }
    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
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

    // 3. return traffic → PASS
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
    //      agent-initiated DNS/NTP/etc without conntrack).
    __u16 dport_be = 0;
    if (proto == IPPROTO_ICMP) {
        stat_add(STAT_PASS_RETURN_ICMP, 1);
        stat_add(STAT_PKTS_PASSED, 1);
        perip_touch(saddr, pkt_len, proto, 0);
        return XDP_PASS;
    }
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            stat_add(STAT_DROP_MALFORMED, 1);
            stat_add(STAT_PKTS_DROPPED, 1);
            stat_add(STAT_BYTES_DROPPED, pkt_len);
            perip_touch(saddr, pkt_len, proto, 1);
            return XDP_DROP;
        }
        dport_be = tcp->dest;
        if (tcp->flags & (TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN)) {
            stat_add(STAT_PASS_RETURN_TCP, 1);
            stat_add(STAT_PKTS_PASSED, 1);
            perip_touch(saddr, pkt_len, proto, 0);
            return XDP_PASS;
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            stat_add(STAT_DROP_MALFORMED, 1);
            stat_add(STAT_PKTS_DROPPED, 1);
            stat_add(STAT_BYTES_DROPPED, pkt_len);
            perip_touch(saddr, pkt_len, proto, 1);
            return XDP_DROP;
        }
        dport_be = udp->dest;
        if (bpf_ntohs(dport_be) >= EPHEMERAL_PORT_MIN) {
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

    // 4. static blocklist
    struct lpm_v4_key bkey = { .prefixlen = 32, .addr = saddr };
    if (bpf_map_lookup_elem(&blocklist_v4, &bkey)) {
        stat_add(STAT_DROP_BLOCKLIST, 1);
        stat_add(STAT_PKTS_DROPPED, 1);
        stat_add(STAT_BYTES_DROPPED, pkt_len);
        perip_touch(saddr, pkt_len, proto, 1);
        return XDP_DROP;
    }

    // 5. dynamic blocklist (TTL)
    struct dyn_block_val *dyn = bpf_map_lookup_elem(&dyn_blocklist_v4, &saddr);
    if (dyn && dyn->until_ns > bpf_ktime_get_ns()) {
        stat_add(STAT_DROP_DYN_BLOCK, 1);
        stat_add(STAT_PKTS_DROPPED, 1);
        stat_add(STAT_BYTES_DROPPED, pkt_len);
        perip_touch(saddr, pkt_len, proto, 1);
        return XDP_DROP;
    }

    // 6. public ports (any source)
    if (proto == IPPROTO_TCP && port_in(&public_tcp_ports, dport_be)) {
        stat_add(STAT_PASS_PUBLIC_TCP, 1);
        stat_add(STAT_PKTS_PASSED, 1);
        perip_touch(saddr, pkt_len, proto, 0);
        return XDP_PASS;
    }
    if (proto == IPPROTO_UDP && port_in(&public_udp_ports, dport_be)) {
        stat_add(STAT_PASS_PUBLIC_UDP, 1);
        stat_add(STAT_PKTS_PASSED, 1);
        perip_touch(saddr, pkt_len, proto, 0);
        return XDP_PASS;
    }

    // 7. private ports (allowlist only)
    __u8 is_private = 0;
    if (proto == IPPROTO_TCP && port_in(&private_tcp_ports, dport_be))
        is_private = 1;
    else if (proto == IPPROTO_UDP && port_in(&private_udp_ports, dport_be))
        is_private = 1;

    if (is_private) {
        struct lpm_v4_key akey = { .prefixlen = 32, .addr = saddr };
        if (bpf_map_lookup_elem(&allowlist_v4, &akey)) {
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
