/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BPF_MACROS__
#define __BPF_MACROS__

/* eBPF requires all functions to be inlined */
#define INTERNAL static __attribute__((always_inline))

#endif /* __BPF_MACROS__ */
