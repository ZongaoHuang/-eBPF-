#ifndef SYS_CALL_TRACKER_H
#define SYS_CALL_TRACKER_H

#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "syscall.h"
#include "syscall.skel.h"

struct syscall_env
{
  bool verbose;
  volatile bool *exiting;

  char *cgroupspath;
  // file cgroup
  bool filter_cg;
  pid_t target_pid;
  // the min sample duration in ms
  long min_duration_ms;
  // the times syscall a process is sampled
  unsigned char filter_report_times;
};

static int start_syscall_tracker(
    ring_buffer_sample_fn handle_event,
    libbpf_print_fn_t libbpf_print_fn,
    struct syscall_env env,
    void *ctx)
{
  struct ring_buffer *rb = NULL;
  struct syscall_bpf *skel;
  int err;

  if (!env.exiting)
  {
    fprintf(stderr, "env.exiting is not set.\n");
    return -1;
  }
  /* Parse command line arguments */
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Load and verify BPF application */
  skel = syscall_bpf__open();
  if (!skel)
  {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  skel->rodata->filter_pid = env.target_pid;
  skel->rodata->filter_cg = env.filter_cg;
  /* Parameterize BPF code with minimum duration parameter */
  skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
  if (env.filter_report_times > 200)
  {
    fprintf(stderr, "filter_report_times to large\n");
    return 1;
  }
  skel->rodata->filter_report_times = env.filter_report_times;

  /* update cgroup path fd to map */
  if (env.filter_cg)
  {
    int idx, cg_map_fd;
    int cgfd = -1;
    idx = 0;
    cg_map_fd = bpf_map__fd(skel->maps.cgroup_map);
    cgfd = open(env.cgroupspath, O_RDONLY);
    if (cgfd < 0)
    {
      fprintf(stderr, "Failed opening Cgroup path: %s", env.cgroupspath);
      goto cleanup;
    }
    if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY))
    {
      fprintf(stderr, "Failed adding target cgroup to map");
      goto cleanup;
    }
  }

  /* Load & verify BPF programs */
  err = syscall_bpf__load(skel);
  if (err)
  {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoints */
  err = syscall_bpf__attach(skel);
  if (err)
  {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, ctx, NULL);
  if (!rb)
  {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

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
  syscall_bpf__destroy(skel);

  return err < 0 ? -err : 0;
}

#endif /* SYS_CALL_TRACKER_H */