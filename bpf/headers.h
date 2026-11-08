// SPDX-License-Identifier: GPL-2.0
//
// Packet header layouts for the data plane. Defined locally so the object
// builds without BTF / vmlinux.h (RPi kernels often ship without
// CONFIG_DEBUG_INFO_BTF). Layouts match the kernel UAPI. None of them need
// `packed`: natural alignment already yields the wire layout, and leaving
// it off lets clang emit word loads instead of byte-by-byte reassembly.

#ifndef KEKKAI_HEADERS_H
#define KEKKAI_HEADERS_H

#include <linux/types.h>

#define ETH_P_IP    0x0800
#define ETH_P_ARP   0x0806
#define ETH_P_IPV6  0x86DD

#define IPPROTO_ICMP    1
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17
#define IPPROTO_ICMPV6  58

// IPv6 extension headers the parser steps over to reach the L4 header.
#define NEXTHDR_HOP      0
#define NEXTHDR_ROUTING  43
#define NEXTHDR_FRAGMENT 44
#define NEXTHDR_AUTH     51
#define NEXTHDR_DEST     60

#define IP_OFFSET  0x1FFF   // IPv4 fragment offset bits (host order)
#define IP6_OFFSET 0xFFF8   // IPv6 fragment offset bits (host order)

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

#define ICMP_ECHOREPLY     0
#define ICMP_DEST_UNREACH  3
#define ICMP_FRAG_NEEDED   4   // code under ICMP_DEST_UNREACH
#define ICMP_ECHO          8
#define ICMP_TIME_EXCEEDED 11
#define ICMP_PARAMETERPROB 12

#define ICMPV6_DEST_UNREACH   1   // 1..4 are the error messages
#define ICMPV6_PKT_TOOBIG     2
#define ICMPV6_PARAMPROB      4
#define ICMPV6_ECHO_REQUEST   128
#define ICMPV6_ECHO_REPLY     129
#define ICMPV6_MLD_QUERY      130
#define ICMPV6_MLD_REPORT     131
#define ICMPV6_MLD_DONE       132
#define ICMPV6_NDISC_RS       133 // 133..136: RS, RA, NS, NA
#define ICMPV6_NDISC_NA       136 // 137 (redirect) is deliberately excluded
#define ICMPV6_MLD2_REPORT    143

struct ethhdr {
    __u8   h_dest[6];
    __u8   h_source[6];
    __be16 h_proto;
};

// Version and IHL share one byte; nibbles are extracted by hand so the
// layout does not depend on bit-field endianness.
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
};

struct ipv6hdr {
    __u8   vtc;            // version (high nibble) + traffic class
    __u8   flow_lbl[3];
    __be16 payload_len;
    __u8   nexthdr;
    __u8   hop_limit;
    __be32 saddr[4];
    __be32 daddr[4];
};

// Common prefix of the IPv6 extension headers. For the fragment header the
// second byte is reserved and frag_off carries offset + M flag.
struct ipv6_ext {
    __u8   nexthdr;
    __u8   hdrlen;
    __be16 frag_off;
    __be32 _rest;
};

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8   doff_res;
    __u8   flags;
    __be16 window;
    __be16 check;
    __be16 urg_ptr;
};

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
};

// ICMPv6 uses the same first eight bytes.
struct icmphdr {
    __u8   type;
    __u8   code;
    __be16 checksum;
    __be32 rest;
};

#endif
