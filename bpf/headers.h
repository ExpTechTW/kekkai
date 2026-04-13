// SPDX-License-Identifier: GPL-2.0
//
// Minimal packet header definitions for the XDP data plane.
// Defined locally to avoid depending on BTF / vmlinux.h — RPi kernels
// often ship without CONFIG_DEBUG_INFO_BTF.

#ifndef WAF_HEADERS_H
#define WAF_HEADERS_H

#include <linux/types.h>

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_ALEN    6

#define IPPROTO_ICMP 1
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

// IP fragment offset mask (lower 13 bits). Non-zero means this is the 2nd+
// fragment of a larger packet and has no L4 header to inspect.
#define IP_FRAG_OFFSET_MASK 0x1FFF

// TCP flag bits we care about. The XDP program reads the flags byte directly
// from the TCP header (byte offset 13) and masks against these.
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

// Ephemeral port range used to identify return UDP traffic. Matches Linux
// default /proc/sys/net/ipv4/ip_local_port_range on recent kernels.
#define EPHEMERAL_PORT_MIN 32768

struct ethhdr {
    __u8   h_dest[ETH_ALEN];
    __u8   h_source[ETH_ALEN];
    __be16 h_proto;
} __attribute__((packed));

// IPv4 header. Bit-field order differs by endianness; we treat ihl/version
// as one byte and extract the nibbles manually to stay portable.
struct iphdr {
    __u8   ihl_version;
    __u8   tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8   ttl;
    __u8   protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

static __always_inline __u8 iphdr_ihl(const struct iphdr *ip) {
    return ip->ihl_version & 0x0f;
}

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8   doff_res;    // data offset (4 bits) + reserved (4 bits)
    __u8   flags;       // URG/ACK/PSH/RST/SYN/FIN
    __be16 window;
    __be16 check;
    __be16 urg_ptr;
} __attribute__((packed));

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
} __attribute__((packed));

#endif
