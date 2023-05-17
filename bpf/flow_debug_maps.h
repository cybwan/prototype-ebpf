#ifndef __FLOW_DEBUG_MAPS_H
#define __FLOW_DEBUG_MAPS_H

#include "include/bpf.h"
#include "include/bpf_helpers.h"

#include "balancer_structs.h"
#include "flow_debug.h"

// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
//   __type(key, __u32);
//   __type(value, __u32);
//   __uint(max_entries, MAX_SUPPORTED_CPUS);
//   __uint(map_flags, NO_FLAGS);
//   __array(
//       values, struct {
//         __uint(type, BPF_MAP_TYPE_LRU_HASH);
//         __uint(key_size, sizeof(struct flow_key));
//         __uint(value_size, sizeof(struct flow_debug_info));
//         __uint(max_entries, DEFAULT_LRU_SIZE);
//       });
// } flow_debug_maps SEC(".maps");
struct bpf_elf_map SEC("maps") flow_debug_maps = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
    .max_elem = MAX_SUPPORTED_CPUS,
    .flags = NO_FLAGS,
};

#endif // of __FLOW_DEBUG_MAPS_H
