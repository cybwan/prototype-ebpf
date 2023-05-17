#ifndef __CONTROL_DATA_MAPS_H
#define __CONTROL_DATA_MAPS_H

/*
 * This file contains definition of maps used for passing of control data and
 * information about encapsulation / decapsulation
 */

#include "bpf.h"
#include "bpf_helpers.h"

#include "balancer_consts.h"
#include "balancer_structs.h"

// control array. contains metadata such as default router mac
// and/or interfaces ifindexes
// indexes:
// 0 - default's mac
// struct {
//  __uint(type, BPF_MAP_TYPE_ARRAY);
//  __type(key, __u32);
//  __type(value, struct ctl_value);
//  __uint(max_entries, CTL_MAP_SIZE);
//  __uint(map_flags, NO_FLAGS);
//} ctl_array SEC(".maps");
struct bpf_elf_map SEC("maps") ctl_array = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct ctl_value),
    .max_elem = CTL_MAP_SIZE,
    .flags = NO_FLAGS,
};

#ifdef KATRAN_INTROSPECTION

// struct {
//   __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//   __type(key, int);
//   __type(value, __u32);
//   __uint(max_entries, MAX_SUPPORTED_CPUS);
//   __uint(map_flags, NO_FLAGS);
// } event_pipe SEC(".maps");
struct bpf_elf_map SEC("maps") event_pipe = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .size_key = sizeof(int),
    .size_value = sizeof(__u32),
    .max_elem = MAX_SUPPORTED_CPUS,
    .flags = NO_FLAGS,
};

#endif

#ifdef INLINE_DECAP_GENERIC
// struct {
//   __uint(type, BPF_MAP_TYPE_HASH);
//   __type(key, struct address);
//   __type(value, __u32);
//   __uint(max_entries, MAX_VIPS);
//   __uint(map_flags, NO_FLAGS);
// } decap_dst SEC(".maps");
struct bpf_elf_map SEC("maps") decap_dst = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct address),
    .size_value = sizeof(__u32),
    .max_elem = MAX_VIPS,
    .flags = NO_FLAGS,
};

// struct {
//   __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
//   __type(key, __u32);
//   __type(value, __u32);
//   __uint(max_entries, SUBPROGRAMS_ARRAY_SIZE);
// } subprograms SEC(".maps");
struct bpf_elf_map SEC("maps") subprograms = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
    .max_elem = SUBPROGRAMS_ARRAY_SIZE,
};
#endif

#if defined(GUE_ENCAP) || defined(DECAP_STRICT_DESTINATION)
// map which src ip address for outer ip packet while using GUE encap
// NOTE: This is not a stable API. This is to be reworked when static
// variables will be available in mainline kernels
// struct {
//  __uint(type, BPF_MAP_TYPE_ARRAY);
//  __type(key, __u32);
//  __type(value, struct real_definition);
//  __uint(max_entries, 2);
//  __uint(map_flags, NO_FLAGS);
//} pckt_srcs SEC(".maps");
struct bpf_elf_map SEC("maps") pckt_srcs = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct real_definition),
    .max_elem = 2,
    .flags = NO_FLAGS,
};
#endif

#endif // of __CONTROL_DATA_MAPS_H
