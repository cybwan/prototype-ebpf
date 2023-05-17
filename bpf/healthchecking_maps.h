#ifndef __HEALTHCHECKING_MAPS_H
#define __HEALTHCHECKING_MAPS_H

#include "bpf.h"
#include "bpf_helpers.h"

#include "balancer_consts.h"
#include "healthchecking_consts.h"
#include "healthchecking_structs.h"

// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY);
//   __type(key, __u32);
//   __type(value, __u32);
//   __uint(max_entries, CTRL_MAP_SIZE);
// } hc_ctrl_map SEC(".maps");
struct bpf_elf_map SEC("maps") hc_ctrl_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
    .max_elem = CTRL_MAP_SIZE,
};

// struct {
//   __uint(type, BPF_MAP_TYPE_HASH);
//   __type(key, __u32);
//   __type(value, struct hc_real_definition);
//   __uint(max_entries, MAX_REALS);
// } hc_reals_map SEC(".maps");
struct bpf_elf_map SEC("maps") hc_reals_map = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct hc_real_definition),
    .max_elem = MAX_REALS,
};

// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY);
//   __type(key, __u32);
//   __type(value, struct hc_real_definition);
//   __uint(max_entries, 2);
//   __uint(map_flags, NO_FLAGS);
// } hc_pckt_srcs_map SEC(".maps");
struct bpf_elf_map SEC("maps") hc_pckt_srcs_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct hc_real_definition),
    .max_elem = 2,
    .flags = NO_FLAGS,
};

// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY);
//   __type(key, __u32);
//   __type(value, struct hc_mac);
//   __uint(max_entries, 2);
//   __uint(map_flags, NO_FLAGS);
// } hc_pckt_macs SEC(".maps");
struct bpf_elf_map SEC("maps") hc_pckt_macs = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct hc_mac),
    .max_elem = 2,
    .flags = NO_FLAGS,
};

// map which contains counters for monitoring
// struct {
//  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//  __type(key, __u32);
//  __type(value, struct hc_stats);
//  __uint(max_entries, STATS_SIZE);
//  __uint(map_flags, NO_FLAGS);
//} hc_stats_map SEC(".maps");
struct bpf_elf_map SEC("maps") hc_stats_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct hc_stats),
    .max_elem = STATS_SIZE,
    .flags = NO_FLAGS,
};

// struct {
//   __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//   __type(key, __u32);
//   __type(value, __u64);
//   __uint(max_entries, MAX_VIPS);
//   __uint(map_flags, NO_FLAGS);
// } per_hckey_stats SEC(".maps");
struct bpf_elf_map SEC("maps") per_hckey_stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u64),
    .max_elem = MAX_VIPS,
    .flags = NO_FLAGS,
};

// struct {
//   __uint(type, BPF_MAP_TYPE_HASH);
//   __type(key, struct hc_key);
//   __type(value, __u32);
//   __uint(max_entries, MAX_VIPS);
//   __uint(map_flags, NO_FLAGS);
// } hc_key_map SEC(".maps");
struct bpf_elf_map SEC("maps") hc_key_map = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct hc_key),
    .size_value = sizeof(__u32),
    .max_elem = MAX_VIPS,
    .flags = NO_FLAGS,
};

#endif // of __HEALTHCHECKING_MAPS_H
