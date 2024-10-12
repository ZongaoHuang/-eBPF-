#ifndef CONTAINER_TRACKER_H
#define CONTAINER_TRACKER_H

#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdarg.h>
#include <unistd.h>

#include "container.h"
#include "container.skel.h"

static const char hex_dec_arr[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

struct container_env
{
  bool verbose;
  volatile bool *exiting;
};

static void consist_str(char *dest, int num, ...)
{
  va_list valist;
  va_start(valist, num);
  int i = 0;
  for (i = 0; i < num; i++)
  {
    strcat(dest, va_arg(valist, char *));
  }
}

static void init_container_map(struct container_bpf *skel, int processes_fd)
{
  char cmd[200] = "./library/container/namespace.sh";
  FILE *container_txt = popen(cmd, "r");
  if (container_txt == NULL)
  {
    fprintf(stderr, "Fail to open container.txt\n");
    exit(0);
  }
  char content_line[150];
  /* ignore the first two line*/
  fgets(content_line, 150, container_txt);
  fgets(content_line, 150, container_txt);

  unsigned long cgroup_id, ipc_id, mnt_id, net_id, pid_id, user_id, uts;
  char name[50], container_id[16];
  pid_t pid;

  /* read from txt */
  while (fscanf(
             container_txt,
             "%s %s %d %*s %lu %lu %lu %lu %lu %lu %lu\n",
             container_id,
             name,
             &pid,
             &cgroup_id,
             &ipc_id,
             &mnt_id,
             &net_id,
             &pid_id,
             &user_id,
             &uts) == 10)
  {
    char top_cmd[100] = "docker top ";
    consist_str(top_cmd, 1, container_id);

    FILE *f = popen(top_cmd, "r");
    if (f == NULL)
    {
      exit(0);
    }
    /* read the process detail from the assist.txt and ignore the first line */
    fgets(content_line, 150, f);
    char uid[10];
    pid_t c_pid, ppid;
    while (fscanf(f, "%s %d %d %*[^\n]\n", uid, &c_pid, &ppid) == 3)
    {
      // printf("%d, %d\n", c_pid, ppid);
      struct container_event data = {
        .container_id = strtol(container_id, NULL, 16),
      };
      bpf_map_update_elem(processes_fd, &c_pid, &data, BPF_ANY);
    }
  }
}

static int
start_container_tracker(ring_buffer_sample_fn handle_event, libbpf_print_fn_t libbpf_print_fn, struct container_env env)
{
  struct ring_buffer *rb = NULL;
  struct container_bpf *skel;
  int err;
  int processes_fd;
  int to_lookup, next_key;
  struct container_event container_value;

  /* Parse command line arguments */
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);
  /* Load and verify BPF application */

  skel = container_bpf__open();
  if (!skel)
  {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = container_bpf__load(skel);
  if (err)
  {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* execute shell to generate container data */
  processes_fd = bpf_map__fd(skel->maps.processes);
  init_container_map(skel, processes_fd);

  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
  if (!rb)
  {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  /* Container events */
  printf("%-10s %-15s %s\n", "PID", "PARENT_PID", "CONTAINER_ID");
  to_lookup = 0;
  next_key = 0;
  while (!bpf_map_get_next_key(processes_fd, &to_lookup, &next_key))
  {
    bpf_map_lookup_elem(processes_fd, &next_key, &container_value);
    // printf("%-10u %-15u %lu \n", container_value.pid, container_value.ppid,
    // container_value.container_id);
    to_lookup = next_key;
  }

  while (!*env.exiting)
  {
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
  container_bpf__destroy(skel);
  return err < 0 ? -err : 0;
}

#endif