#define KBUILD_MODNAME "xdp_dnat"

#include <uapi/linux/bpf.h>

#include <bpf_macros.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_debug.h>

#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>

#define IPPROTO_TCP 6

#define MAX_TCP_LENGTH 1480

/* eBPF lacks these functions, but LLVM provides builtins */
#ifndef memset
#define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

/**
 * Packet processing context.
 */
struct Packet {
    /* For verification to for passing to BPF helpers. */
    struct xdp_md *ctx;

    /* Layer headers (may be NULL on lower stages) */
    struct ethhdr *ether;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u16 tcp_len;
};


/**
 * Cookie computation
 */

struct FourTuple {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

INTERNAL void swap_eth_addr(__u8 *a, __u8 *b) {
    __u8 tmp[ETH_ALEN];

    __builtin_memcpy(tmp, a, ETH_ALEN);
    __builtin_memcpy(a, b, ETH_ALEN);
    __builtin_memcpy(b, tmp, ETH_ALEN);
}

/**
 * Calculate sum of 16-bit words from `data` of `size` bytes,
 * Size is assumed to be even, from 0 to MAX_CSUM_BYTES.
 */
#define MAX_CSUM_WORDS 32
#define MAX_CSUM_BYTES (MAX_CSUM_WORDS * 2)

/**
 * A handy version of `sum16()` for 32-bit words.
 * Does not actually conserve any instructions.
 */
INTERNAL u32
sum16_32(u32 v) {
    return (v >> 16) + (v & 0xffff);
}

/**
 * Carry upper bits and compute one's complement for a checksum.
 */
INTERNAL __u16
carry(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16); // loop
    return ~csum;
}

INTERNAL int
process_tcp(struct Packet *packet) {
    struct xdp_md *ctx = packet->ctx;
    struct iphdr *iph = packet->ip;
    struct tcphdr *tcph = packet->tcp;

    if (bpf_ntohs(tcph->source) == 22) {
        return XDP_PASS;
    }
    bpf_debug("[xdp dnat] IP(iph->saddr=%pI4 iph->daddr=%pI4 iph->protocol=%d)", &iph->saddr, &iph->daddr, iph->protocol);
    bpf_debug("[xdp dnat] TCP(tcph->source=%d tcph->dest=%d)", bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest));
    if (bpf_ntohs(tcph->source) == 6000) {
        bpf_debug("[xdp dnat] -->INBOUND");
        bpf_debug("[xdp dnat] IP(src=%pI4 dst=%pI4 proto=%d)", &iph->saddr, &iph->daddr, iph->protocol);
        bpf_debug("[xdp dnat] TCP(sport=%d dport=%d)", bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest));
        /* Validate IP header length */
        const __u32 ip_len = iph->ihl * 4;
        if ((void *) iph + ip_len > ctx->data_end) {
            return XDP_DROP; /* malformed packet */
        }
        if (ip_len > MAX_CSUM_BYTES) {
            return XDP_ABORTED; /* implementation limitation */
        }

        /* Validate TCP length */
        const __u32 tcp_len = tcph->doff * 4;
        if ((void *) tcph + tcp_len > ctx->data_end) {
            return XDP_DROP; /* malformed packet */
        }
        if (tcp_len > MAX_CSUM_BYTES) {
            return XDP_ABORTED; /* implementation limitation */
        }
        bpf_debug("[xdp dnat] TCP(tcp_len=%d tcp_len=%d)", tcp_len, sizeof(*tcph));
        if (tcp_len < sizeof(*tcph)) {
            return XDP_ABORTED;
        }

        __u16 kept_check = tcph->check;

        /* Update TCP checksum */
        // Compute pseudo-header checksum
        __u32 tcp_csum = 0;
        tcp_csum += sum16_32(iph->saddr);
        tcp_csum += sum16_32(iph->daddr);
        tcp_csum += 0x0600;
        //tcp_csum += (__u16)iph->protocol << 8;
        tcp_csum += tcp_len << 8;

        tcph->check = 0;
        tcph->source = bpf_htons(5000);

        __u16 *buf = (void *) tcph;

        // Compute checksum on udp header + payload
#pragma clang loop unroll(full)
        for (int i = 0; i < MAX_CSUM_BYTES; i += 2) {
            if (i >= tcp_len) {
                break; /* normal exit */
            }
            if ((void *) (buf + 1) > ctx->data_end) {
                break;
            }
            tcp_csum += *buf;
            buf++;
        }
        if ((void *) buf + 1 <= ctx->data_end) {
            // In case payload is not 2 bytes aligned
            tcp_csum += *(u8 *) buf;
        }

        tcph->check = carry(tcp_csum);


        bpf_debug("[xdp dnat] -->INBOUND Rewrite(sport=%d dport=%d  tcp len=%d)", bpf_ntohs(tcph->source),
               bpf_ntohs(tcph->dest), tcp_len);

        bpf_debug("[xdp dnat] -->INBOUND Rewrite(csum=0x%x rewrite csum=0x%x)", bpf_ntohs(kept_check),
               bpf_htons(tcph->check));
        return XDP_PASS;
    }

    return XDP_PASS;
}

INTERNAL int
process_ip(struct Packet *packet) {
    struct iphdr *ip = packet->ip;

    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    /* TODO: check if client has passed SYN cookie challenge */

    struct tcphdr *tcp = (struct tcphdr *) (ip + 1);
    if ((void *) (tcp + 1) > (void *) packet->ctx->data_end) {
        bpf_debug("[xdp] XDP_DROP");
        return XDP_DROP; /* malformed packet */
    }
    packet->tcp = tcp;

    return process_tcp(packet);
}

INTERNAL int
process_ether(struct Packet *packet) {
    struct ethhdr *ether = packet->ether;

    //LOG("Ether(proto=0x%x)", bpf_ntohs(ether->h_proto));

    if (ether->h_proto != bpf_ntohs(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *) (ether + 1);
    if ((void *) (ip + 1) > (void *) packet->ctx->data_end) {
        return XDP_DROP; /* malformed packet */
    }
    packet->ip = ip;
    return process_ip(packet);
}

SEC("prog")
int xdp_main(struct xdp_md *ctx) {
    struct Packet packet;
    packet.ctx = ctx;

    struct ethhdr *ether = (struct ethhdr *) (void *) ctx->data;
    if ((void *) (ether + 1) > (void *) ctx->data_end) {
        return XDP_PASS; /* what are you? */
    }

    packet.ether = ether;
    return process_ether(&packet);
}

char _license[] SEC("license") = "GPL";
int _version __section("version") = 1;