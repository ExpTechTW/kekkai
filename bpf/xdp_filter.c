// SPDX-License-Identifier: GPL-2.0
//
// M2: LPM_TRIE-based source-IP blocklist.
// Parses eth + IPv4 header, looks up saddr in a longest-prefix-match trie,
// and drops on hit. Non-IPv4 and non-matching traffic passes through.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "headers.h"

char __license[] SEC("license") = "GPL";

#define BLOCKLIST_MAX_ENTRIES 1048576  // 1M CIDRs

struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr;      // network byte order
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(max_entries, BLOCKLIST_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist_v4 SEC(".maps");

SEC("xdp")
int waf_xdp(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct lpm_v4_key key = {
        .prefixlen = 32,
        .addr      = ip->saddr,
    };

    if (bpf_map_lookup_elem(&blocklist_v4, &key))
        return XDP_DROP;

    return XDP_PASS;
}
