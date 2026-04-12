// SPDX-License-Identifier: GPL-2.0
//
// Minimal packet header definitions for the XDP data plane.
// Defined locally to avoid depending on BTF / vmlinux.h — RPi kernels
// often ship without CONFIG_DEBUG_INFO_BTF.

#ifndef WAF_HEADERS_H
#define WAF_HEADERS_H

#include <linux/types.h>

#define ETH_P_IP   0x0800
#define ETH_ALEN   6
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct ethhdr {
    __u8  h_dest[ETH_ALEN];
    __u8  h_source[ETH_ALEN];
    __be16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8  ihl_version;       // ihl:4, version:4 (little-endian bitfield order)
    __u8  tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

static __always_inline __u8 iphdr_ihl(const struct iphdr *ip) {
    return ip->ihl_version & 0x0f;
}

#endif
