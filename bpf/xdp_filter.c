// SPDX-License-Identifier: GPL-2.0
//
// Minimal XDP pass-all program — M1 skeleton.
// Future milestones extend this with LPM_TRIE blocklist, per-IP counters,
// ringbuf sampling, and rate-limit logic.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

SEC("xdp")
int waf_xdp(struct xdp_md *ctx) {
    return XDP_PASS;
}
