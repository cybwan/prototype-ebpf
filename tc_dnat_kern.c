#define KBUILD_MODNAME "tc_dnat"

#include <linux/bpf.h>

#include <bpf_macros.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_debug.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

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
 * Calculate sum of 16-bit words from `data` of `size` bytes,
 * Size is assumed to be even, from 0 to MAX_CSUM_BYTES.
 */
#define MAX_CSUM_WORDS 32
#define MAX_CSUM_BYTES (MAX_CSUM_WORDS * 2)

SEC("nat")
int tc_egress(struct __sk_buff *skb) {
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;
    struct ethhdr *eth = (struct ethhdr *) data;
    if ((void *) (eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    if (eth->h_proto != bpf_ntohs(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *iph = (struct iphdr *) (eth + 1);
    if ((void *) (iph + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcph = (struct tcphdr *) (iph + 1);
    if ((void *) (tcph + 1) > data_end) {
        return TC_ACT_SHOT; /* malformed packet */
    }

    if (bpf_ntohs(tcph->dest) == 5000) {
        bpf_debug("[NODE.EGS]->[SIDECAR.INBOUND]");
        bpf_debug("[NODE.EGS]->[SIDECAR.INBOUND] IP(src ip=%pI4 dst ip=%pI4 proto=%d)", &iph->saddr, &iph->daddr, iph->protocol);
        bpf_debug("[NODE.EGS]->[SIDECAR.INBOUND] TCP(src port=%d dst port=%d)", bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest));
        /* Validate IP header length */
        const __u32 ip_len = iph->ihl * 4;
        if ((void *) iph + ip_len > data_end) {
            return TC_ACT_SHOT; /* malformed packet */
        }
        if (ip_len > MAX_CSUM_BYTES) {
            return TC_ACT_SHOT; /* implementation limitation */
        }

        /* Validate TCP length */
        const __u32 tcp_len = tcph->doff * 4;
        if ((void *) tcph + tcp_len > data_end) {
            return TC_ACT_SHOT; /* malformed packet */
        }
        if (tcp_len > MAX_CSUM_BYTES) {
            return TC_ACT_SHOT; /* implementation limitation */
        }
        bpf_debug("[tc  snat] TCP(tcp_len=%d tcp_len=%d)", tcp_len, sizeof(*tcph));
        if (tcp_len < sizeof(*tcph)) {
            return TC_ACT_SHOT;
        }

        __u32 csum_off = ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
        __u32 sport_off = ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source);
        __u32 dport_off = ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest);
        __u16 src_port = tcph->source;
        __u16 dst_port = tcph->dest;
        __u16 new_port = bpf_htons(15003);
        bpf_l4_csum_replace(skb, csum_off, dst_port, new_port, sizeof(dst_port));
        bpf_skb_store_bytes(skb, dport_off, &new_port, sizeof(new_port), 0);
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
int _version __section("version") = 1;