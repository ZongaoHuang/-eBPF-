// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "update.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 8192);
// 	__type(key, pid_t);
// 	__type(value, u64);
// } exec_start SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_open")
int handle_exec(struct trace_event_raw_sys_enter* ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 pid = id;
	struct event *e;
	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->pid = pid;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx->args[0]);
	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// SEC("tp/sched/sched_process_exec")
// int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
// {
// 	struct task_struct *task;
// 	unsigned fname_off;
// 	struct event *e;
// 	pid_t pid;
// 	u64 ts;

// 	/* remember time exec() was executed for this PID */
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	// ts = bpf_ktime_get_ns();
// 	// bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

// 	/* reserve sample from BPF ringbuf */
// 	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
// 	if (!e)
// 		return 0;

// 	/* fill out the sample with data */
// 	task = (struct task_struct *)bpf_get_current_task();

// 	e->exit_event = false;
// 	e->pid = pid;
// 	e->duration_ns = 1;
// 	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
// 	bpf_get_current_comm(&e->comm, sizeof(e->comm));

// 	fname_off = ctx->__data_loc_filename & 0xFFFF;
// 	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

// 	/* successfully submit it to user-space for post-processing */
// 	bpf_ringbuf_submit(e, 0);
// 	return 0;
// }

// SEC("tp/sched/sched_process_exit")
// int handle_exit(struct trace_event_raw_sched_process_template* ctx)
// {
// 	struct task_struct *task;
// 	struct event *e;
// 	pid_t pid, tid;
// 	u64 id, ts, *start_ts, duration_ns = 0;

// 	/* get PID and TID of exiting thread/process */
// 	id = bpf_get_current_pid_tgid();
// 	pid = id >> 32;
// 	tid = (u32)id;

// 	/* ignore thread exits */
// 	if (pid != tid)
// 		return 0;

// 	/* reserve sample from BPF ringbuf */
// 	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
// 	if (!e)
// 		return 0;

// 	/* fill out the sample with data */
// 	task = (struct task_struct *)bpf_get_current_task();

// 	e->exit_event = true;
// 	e->duration_ns = duration_ns;
// 	e->pid = pid;
// 	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
// 	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
// 	bpf_get_current_comm(&e->comm, sizeof(e->comm));

// 	/* send data to user-space for post-processing */
// 	bpf_ringbuf_submit(e, 0);
// 	return 0;
// }
