// SPDX-License-Identifier: GPL-2.0
//
// WAF edge data plane.
//
// Responsibilities:
//   - Parse eth + IPv4, classify by L4 proto.
//   - Look up src IP in LPM trie blocklist; drop on hit with reason code.
//   - Maintain global PERCPU_ARRAY counters (proto breakdown, drop reasons).
//   - Maintain per-src-IP LRU hash for top-N analysis in userspace.
//   - Reserve event ringbuf layout for future anomaly reporting (M4+).

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "headers.h"

char __license[] SEC("license") = "GPL";

#define BLOCKLIST_MAX_ENTRIES 1048576
#define PERIP_MAX_ENTRIES     65536
#define EVENTS_RINGBUF_BYTES  (1 << 18)  // 256 KiB, reserved for M4+

// --- global stats slots -----------------------------------------------------
// Keep these in sync with internal/stats/stats.go.
#define STAT_PKTS_TOTAL        0
#define STAT_PKTS_PASSED       1
#define STAT_PKTS_DROPPED      2
#define STAT_BYTES_TOTAL       3
#define STAT_BYTES_DROPPED     4
#define STAT_NON_IPV4          5
#define STAT_MALFORMED         6
#define STAT_PKTS_TCP          7
#define STAT_PKTS_UDP          8
#define STAT_PKTS_ICMP         9
#define STAT_PKTS_OTHER_L4    10
#define STAT_BYTES_TCP        11
#define STAT_BYTES_UDP        12
#define STAT_BYTES_ICMP       13
#define STAT_BYTES_OTHER_L4   14
#define STAT_DROP_BLOCKLIST   15
#define STAT_DROP_MALFORMED   16
#define STAT_SLOTS            32  // headroom for M4+

// --- event types (reserved, ringbuf not produced yet) -----------------------
#define EVT_BLOCK     1
#define EVT_RATELIMIT 2
#define EVT_MALFORMED 3

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
    __u8  last_proto;     // IPPROTO_TCP / UDP / ICMP / other
    __u8  blocked;        // 1 if ever matched blocklist
    __u8  _pad[6];
};

struct event {
    __u64 ts_ns;
    __u32 saddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  event_type;
    __u8  action;         // 0 = PASS, 1 = DROP
    __u8  reason;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(max_entries, BLOCKLIST_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_SLOTS);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);                  // src IPv4, network byte order
    __type(value, struct perip_stat);
    __uint(max_entries, PERIP_MAX_ENTRIES);
} perip_v4 SEC(".maps");

// Reserved for M4+: anomaly event ringbuf. Declared now to lock in layout.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, EVENTS_RINGBUF_BYTES);
} events SEC(".maps");

static __always_inline void stat_add(__u32 slot, __u64 delta) {
    __u64 *val = bpf_map_lookup_elem(&stats, &slot);
    if (val)
        *val += delta;
}

static __always_inline void perip_update(__u32 saddr, __u64 len, __u8 proto,
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

SEC("xdp")
int waf_xdp(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len  = (__u64)(data_end - data);

    stat_add(STAT_PKTS_TOTAL, 1);
    stat_add(STAT_BYTES_TOTAL, pkt_len);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        stat_add(STAT_MALFORMED, 1);
        stat_add(STAT_PKTS_PASSED, 1);
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        stat_add(STAT_NON_IPV4, 1);
        stat_add(STAT_PKTS_PASSED, 1);
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        stat_add(STAT_MALFORMED, 1);
        stat_add(STAT_DROP_MALFORMED, 1);
        stat_add(STAT_PKTS_PASSED, 1);
        return XDP_PASS;
    }

    __u8 proto = ip->protocol;
    switch (proto) {
    case IPPROTO_TCP:
        stat_add(STAT_PKTS_TCP, 1);
        stat_add(STAT_BYTES_TCP, pkt_len);
        break;
    case IPPROTO_UDP:
        stat_add(STAT_PKTS_UDP, 1);
        stat_add(STAT_BYTES_UDP, pkt_len);
        break;
    case 1: // ICMP
        stat_add(STAT_PKTS_ICMP, 1);
        stat_add(STAT_BYTES_ICMP, pkt_len);
        break;
    default:
        stat_add(STAT_PKTS_OTHER_L4, 1);
        stat_add(STAT_BYTES_OTHER_L4, pkt_len);
        break;
    }

    struct lpm_v4_key bkey = {
        .prefixlen = 32,
        .addr      = ip->saddr,
    };

    __u8 dropped = 0;
    if (bpf_map_lookup_elem(&blocklist_v4, &bkey)) {
        stat_add(STAT_PKTS_DROPPED, 1);
        stat_add(STAT_BYTES_DROPPED, pkt_len);
        stat_add(STAT_DROP_BLOCKLIST, 1);
        dropped = 1;
    } else {
        stat_add(STAT_PKTS_PASSED, 1);
    }

    perip_update(ip->saddr, pkt_len, proto, dropped);

    return dropped ? XDP_DROP : XDP_PASS;
}
