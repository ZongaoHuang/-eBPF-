/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#include <vmlinux.h>
#include "ipc.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 8 * 1024

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");


SEC("lsm/ipc_permission")
int BPF_PROG(ipc_permission, struct kern_ipc_perm *ipcp, short flag)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct ipc_event *event = bpf_ringbuf_reserve(&events, sizeof(struct ipc_event), 0);
    if(!event) {
        return 0;
    }
    event->pid = pid;
    event->uid = ipcp->uid.val;
    event->gid = ipcp->gid.val;
    event->cuid = ipcp->cuid.val;
    event->cgid = ipcp->cgid.val;
    bpf_ringbuf_submit(event, 0);

    return 0;
}
