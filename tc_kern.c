#define KBUILD_MODNAME "tc_demo"

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_debug.h>
#include <linux/pkt_cls.h>

#define PIN_GLOBAL_NS 2

struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};

#ifndef __section
# define __section(NAME)                  \
    __attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
        inline __attribute__((always_inline))
#endif

#ifndef lock_xadd
# define lock_xadd(ptr, val)              \
        ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
        (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);

struct bpf_elf_map acc_map __section("maps") = {
        .type           = BPF_MAP_TYPE_ARRAY,
        .size_key       = sizeof(uint32_t),
        .size_value     = sizeof(uint32_t),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 2,
};

static __inline int account_data(struct __sk_buff *skb, uint32_t dir) {
    uint32_t *bytes;

    bytes = map_lookup_elem(&acc_map, &dir);
    if (bytes) {
        lock_xadd(bytes, skb->len);
        if (dir == 0) {
            bpf_debug("ingress bytes:%d", *bytes);
        }
        if (dir == 1) {
            bpf_debug("egress  bytes:%d", *bytes);
        }
    }

    return TC_ACT_OK;
}

__section("classifier/ingress")
int tc_ingress(struct __sk_buff *skb) {
    return account_data(skb, 0);
}

__section("classifier/egress")
int tc_egress(struct __sk_buff *skb) {
    return account_data(skb, 1);
}

char __license[] __section("license") = "GPL";