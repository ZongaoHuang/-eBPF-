/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
 *
 * Copyright (c) 2020, Andrii Nakryiko
 *
 * modified from https://github.com/libbpf/libbpf-bootstrap/
 * We use libbpf-bootstrap as a start template for our bpf program.
 */
#ifndef PROCESS_TRACKER_H
#define PROCESS_TRACKER_H

#include <argp.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>

#include "process.h"
#include "process.skel.h"

struct process_env
{
  bool verbose;
  bool is_csv;
  pid_t target_pid;
  pid_t exclude_current_ppid;
  long min_duration_ms;
  volatile bool *exiting;
};

#include <time.h>

static void print_table_header(const char *custom_headers[], bool is_csv)
{
  if (is_csv)
  {
    printf(
        "time,pid,ppi,cgroup_id,user_namespace_id,pid_namespace_id,mount_"
        "namespace_id");
  }
  else
  {
    printf(
        "%s\t\t%s\t%s\t%s\t%s\t%s\t%s",
        "time",
        "pid",
        "ppid",
        "cgroup_id",
        "user_namespace_id",
        "pid_namespace_id",
        "mount_namespace_id");
  }
  while (*custom_headers)
  {
    if (is_csv)
    {
      printf(",%s", *custom_headers);
    }
    else
    {
      printf("\t%s", *custom_headers);
    }
    custom_headers++;
  }
  printf("\n");
}

static void print_basic_info(const struct common_event *e, bool is_csv)
{
  struct tm *tm;
  char ts[32];
  time_t t;

  if (!e)
  {
    return;
  }
  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);
  /* format: [time] [pid] [ppid] [cgroup_id] [user_namespace_id]
   * [pid_namespace_id] [mount_namespace_id] */
  if (is_csv)
  {
    printf(
        "%s,%d,%d,%lu,%u,%u,%u",
        ts,
        e->pid,
        e->ppid,
        e->cgroup_id,
        e->user_namespace_id,
        e->pid_namespace_id,
        e->mount_namespace_id);
  }
  else
  {
    printf(
        "%-8s\t%-7d\t%-7d\t%lu\t\t%u\t\t%u\t\t%u\t\t",
        ts,
        e->pid,
        e->ppid,
        e->cgroup_id,
        e->user_namespace_id,
        e->pid_namespace_id,
        e->mount_namespace_id);
  }
}

static int start_process_tracker(
    ring_buffer_sample_fn handle_event,
    libbpf_print_fn_t libbpf_print_fn,
    struct process_env env,
    struct process_bpf *skel,
    void *ctx)
{
  struct ring_buffer *rb = NULL;
  int err;

  if (!env.exiting)
  {
    fprintf(stderr, "env.exiting is not set.\n");
    return -1;
  }
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Load and verify BPF application */
  skel = process_bpf__open();
  if (!skel)
  {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /* Parameterize BPF code with minimum duration parameter */
  skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
  skel->rodata->target_pid = env.target_pid;
  skel->rodata->exclude_current_ppid = env.exclude_current_ppid;

  /* Load & verify BPF programs */
  err = process_bpf__load(skel);
  if (err)
  {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoints */
  err = process_bpf__attach(skel);
  if (err)
  {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, ctx, NULL);
  if (!rb)
  {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }
  while (!(*env.exiting))
  {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR)
    {
      err = 0;
      break;
    }
    if (err < 0)
    {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
  /* Clean up */
  ring_buffer__free(rb);
  process_bpf__destroy(skel);

  return err < 0 ? -err : 0;
}

#endif