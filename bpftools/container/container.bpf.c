/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
 *
 * Copyright (c) 2020, Andrii Nakryiko
 * 
 * modified from https://github.com/libbpf/libbpf-bootstrap/
 * We use libbpf-bootstrap as a start template for our bpf program.
 */
#include <vmlinux.h>
#include "container.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 8 * 1024
#define MAX_SYSCALLS 1024
#define MAX_COMM_LEN 64

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct container_event);
} processes SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");


// SEC("tracepoint/sched/sched_process_fork")
// int tp__sched_process_fork(struct trace_event_raw_sched_process_fork *args) {
//     pid_t parent_pid = args->parent_pid;
//     pid_t child_pid = args->child_pid;
//     struct container_event *buf;
//     struct container_event *e = bpf_map_lookup_elem(&processes, &parent_pid);
    
//     if(!e) {
//         return 0;
//     }
//     struct container_event new_event = {
//         .container_id = e->container_id,
//         .pid = child_pid,
//         .ppid = parent_pid,
//     };
//     buf = bpf_ringbuf_reserve(&events, sizeof(*buf), 0);
//     if(!buf) {
//         return 0;
//     }
//     bpf_map_update_elem(&processes, &child_pid, &new_event, 0);
//     buf->container_id = new_event.container_id;
//     buf->pid = new_event.pid;
//     buf->ppid = new_event.ppid;
//     bpf_ringbuf_submit(buf, 0);
//     return 0;
// }
