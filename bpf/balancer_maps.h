#ifndef __BALANCER_MAPS_H
#define __BALANCER_MAPS_H

/*
 * This file contains definition of maps used by the balancer typically
 * involving information pertaining to proper forwarding of packets
 */

#include "bpf.h"
#include "bpf_helpers.h"

#include "balancer_consts.h"
#include "balancer_structs.h"

//// map, which contains all the vips for which we are doing load balancing
// struct SEC(".maps") vip_map = {
//         .type = BPF_MAP_TYPE_HASH,
//         .size_key = sizeof(struct vip_definition),
//         .size_value = sizeof(struct vip_meta),
//         .max_elem = MAX_VIPS,
//         .flags = NO_FLAGS,
// };

// map, which contains all the vips for which we are doing load balancing
struct bpf_elf_map SEC("maps") vip_map = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct vip_definition),
    .size_value = sizeof(struct vip_meta),
    .max_elem = MAX_VIPS,
    .flags = NO_FLAGS,
};

//// fallback lru. we should never hit this one outside of unittests
// struct {
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __type(key, struct flow_key);
//     __type(value, struct real_pos_lru);
//     __uint(max_entries, DEFAULT_LRU_SIZE);
//     __uint(map_flags, NO_FLAGS);
// } fallback_cache SEC(".maps");

// fallback lru. we should never hit this one outside of unittests
struct bpf_elf_map SEC("maps") fallback_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(struct flow_key),
    .size_value = sizeof(struct real_pos_lru),
    .max_elem = DEFAULT_LRU_SIZE,
    .flags = NO_FLAGS,
};

//// map which contains cpu core to lru mapping
// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
//   __type(key, __u32);
//   __type(value, __u32);
//   __uint(max_entries, MAX_SUPPORTED_CPUS);
//   __uint(map_flags, NO_FLAGS);
//   __array(
//       values, struct {
//         __uint(type, BPF_MAP_TYPE_LRU_HASH);
//         __type(key, struct flow_key);
//         __type(value, struct real_pos_lru);
//         __uint(max_entries, DEFAULT_LRU_SIZE);
//       });
// } lru_mapping SEC(".maps");

// map which contains cpu core to lru mapping
struct bpf_elf_map SEC("maps") lru_mapping = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
    .max_elem = MAX_SUPPORTED_CPUS,
    .flags = NO_FLAGS,
};

//// map which contains all vip to real mappings
// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY);
//   __type(key, __u32);
//   __type(value, __u32);
//   __uint(max_entries, CH_RINGS_SIZE);
//   __uint(map_flags, NO_FLAGS);
// } ch_rings SEC(".maps");

// map which contains all vip to real mappings
struct bpf_elf_map SEC("maps") ch_rings = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
    .max_elem = CH_RINGS_SIZE,
    .flags = NO_FLAGS,
};

//// map which contains opaque real's id to real mapping
// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY);
//   __type(key, __u32);
//   __type(value, struct real_definition);
//   __uint(max_entries, MAX_REALS);
//   __uint(map_flags, NO_FLAGS);
// } reals SEC(".maps");

// map which contains opaque real's id to real mapping
struct bpf_elf_map SEC("maps") reals = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct real_definition),
    .max_elem = MAX_REALS,
    .flags = NO_FLAGS,
};

//// map with per real pps/bps statistic
// struct {
//   __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//   __type(key, __u32);
//   __type(value, struct lb_stats);
//   __uint(max_entries, MAX_REALS);
//   __uint(map_flags, NO_FLAGS);
// } reals_stats SEC(".maps");

// map with per real pps/bps statistic
struct bpf_elf_map SEC("maps") reals_stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct lb_stats),
    .max_elem = MAX_REALS,
    .flags = NO_FLAGS,
};

//// map with per real lru miss statistic
// struct {
//   __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//   __type(key, __u32);   // key is backend index
//   __type(value, __u32); // value is lru miss count of the backend
//   __uint(max_entries, MAX_REALS);
//   __uint(map_flags, NO_FLAGS);
// } lru_miss_stats SEC(".maps");

// map with per real lru miss statistic
struct bpf_elf_map SEC("maps") lru_miss_stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .size_key = sizeof(__u32),   // key is backend index
    .size_value = sizeof(__u32), // value is lru miss count of the backend
    .max_elem = MAX_REALS,
    .flags = NO_FLAGS,
};

// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY);
//   __type(key, __u32);
//   __type(value, struct vip_definition);
//   __uint(max_entries, 1);
//   __uint(map_flags, NO_FLAGS);
// } lru_miss_stats_vip SEC(".maps");

struct bpf_elf_map SEC("maps") lru_miss_stats_vip = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct vip_definition),
    .max_elem = 1,
    .flags = NO_FLAGS,
};

//// map w/ per vip statistics
// struct {
//   __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//   __type(key, __u32);
//   __type(value, struct lb_stats);
//   __uint(max_entries, STATS_MAP_SIZE);
//   __uint(map_flags, NO_FLAGS);
// } stats SEC(".maps");

// map w/ per vip statistics
struct bpf_elf_map SEC("maps") stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct lb_stats),
    .max_elem = STATS_MAP_SIZE,
    .flags = NO_FLAGS,
};

//// map for server-id to real's id mapping. The ids can be embedded in header
/// of / QUIC or TCP (if enabled) packets for routing of packets for existing
/// flows
// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY);
//   __type(key, __u32);
//   __type(value, __u32);
//   __uint(max_entries, MAX_QUIC_REALS);
//   __uint(map_flags, NO_FLAGS);
// } server_id_map SEC(".maps");

// map for server-id to real's id mapping. The ids can be embedded in header of
// QUIC or TCP (if enabled) packets for routing of packets for existing flows
struct bpf_elf_map SEC("maps") server_id_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
    .max_elem = MAX_QUIC_REALS,
    .flags = NO_FLAGS,
};

#ifdef LPM_SRC_LOOKUP
// struct {
//  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
//  __type(key, struct v4_lpm_key);
//  __type(value, __u32);
//  __uint(max_entries, MAX_LPM_SRC);
//  __uint(map_flags, BPF_F_NO_PREALLOC);
//} lpm_src_v4 SEC(".maps");

struct bpf_elf_map SEC("maps") lpm_src_v4 = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .size_key = sizeof(struct v4_lpm_key),
    .size_value = sizeof(__u32),
    .max_elem = MAX_LPM_SRC,
    .flags = BPF_F_NO_PREALLOC,
};

// struct {
//   __uint(type, BPF_MAP_TYPE_LPM_TRIE);
//   __type(key, struct v6_lpm_key);
//   __type(value, __u32);
//   __uint(max_entries, MAX_LPM_SRC);
//   __uint(map_flags, BPF_F_NO_PREALLOC);
// } lpm_src_v6 SEC(".maps");

struct bpf_elf_map SEC("maps") lpm_src_v6 = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .size_key = sizeof(struct v6_lpm_key),
    .size_value = sizeof(__u32),
    .max_elem = MAX_LPM_SRC,
    .flags = BPF_F_NO_PREALLOC,
};

#endif // of LPM_SRC_LOOKUP

#ifdef GLOBAL_LRU_LOOKUP

// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
//   __type(key, __u32);
//   __type(value, __u32);
//   __uint(max_entries, MAX_SUPPORTED_CPUS);
//   __uint(map_flags, NO_FLAGS);
//   __array(
//       values, struct {
//         __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
//         __type(key, struct flow_key);
//         __type(value, __u32);
//         __uint(max_entries, DEFAULT_LRU_SIZE);
//       });
// } global_lru_maps SEC(".maps");

struct bpf_elf_map SEC("maps") global_lru_maps = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
    .max_elem = MAX_SUPPORTED_CPUS,
    .flags = NO_FLAGS,
};

// struct {
//   __uint(type, BPF_MAP_TYPE_LRU_HASH);
//   __type(key, struct flow_key);
//   __type(value, __u32);
//   __uint(max_entries, DEFAULT_GLOBAL_LRU_SIZE);
//   __uint(map_flags, NO_FLAGS);
// } fallback_glru SEC(".maps");

struct bpf_elf_map SEC("maps") fallback_glru = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(struct flow_key),
    .size_value = sizeof(__u32),
    .max_elem = DEFAULT_GLOBAL_LRU_SIZE,
    .flags = NO_FLAGS,
};

#endif // of GLOBAL_LRU_LOOKUP

#endif // of _BALANCER_MAPS
