/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef IPC_TRACKER_H
#define IPC_TRACKER_H

#include <argp.h>

#include "ipc.h"
#include "ipc.skel.h"

struct ipc_env
{
  bool verbose;
  volatile bool *exiting;
};

static int start_ipc_tracker(ring_buffer_sample_fn handle_event, libbpf_print_fn_t libbpf_print_fn, struct ipc_env env)
{
  struct ring_buffer *rb = NULL;
  struct ipc_bpf *skel;
  int err;

  /* Parse command line arguments */
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Load and verify BPF application */
  skel = ipc_bpf__open();
  if (!skel)
  {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }
  /* Load & verify BPF programs */
  err = ipc_bpf__load(skel);
  if (err)
  {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoints */
  err = ipc_bpf__attach(skel);
  if (err)
  {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
  if (!rb)
  {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  /* Process events */
  printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "PID", "UID", "GID", "CUID", "CGID");
  while (!*env.exiting)
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
  ipc_bpf__destroy(skel);

  return err < 0 ? -err : 0;
}

#endif