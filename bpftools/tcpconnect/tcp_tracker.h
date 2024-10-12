// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Anton Protopopov
#ifndef TCP_TRACKER_H
#define TCP_TRACKER_H

#include <argp.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include <signal.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "map_helper.h"
#include "tcp.h"
#include "tcp.skel.h"

struct tcp_count_event
{
  bool is_ipv4;
  char LADDR[25];
  char RADDR[25];
  int RPORT;
  long long unsigned int CONNECTS;
};

struct tcp_env
{
  bool verbose;
  volatile bool *exiting;
  void *ctx;

  bool count;
  void (*count_collector)(struct tcp_count_event);

  bool print_timestamp;
  bool print_uid;
  pid_t pid;
  uid_t uid;
  int nports;
  int ports[MAX_PORTS];

  bool is_csv;
};

static void handle_lost_events(void *ctx, int cpu, long long unsigned int lost_cnt)
{
  fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void print_events(int perf_map_fd, perf_buffer_sample_fn handle_event, struct tcp_env env)
{
  struct perf_buffer *pb;
  int err;

  pb = perf_buffer__new(perf_map_fd, 128, handle_event, handle_lost_events, env.ctx, NULL);
  if (!pb)
  {
    err = -errno;
    fprintf(stderr, "failed to open perf buffer: %d\n", err);
    goto cleanup;
  }

  while (!*env.exiting)
  {
    err = perf_buffer__poll(pb, 100);
    if (err < 0 && err != -EINTR)
    {
      fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
      goto cleanup;
    }
    /* reset err to return 0 if exiting */
    err = 0;
  }

cleanup:
  perf_buffer__free(pb);
}

static void print_count_ipv4(int map_fd, void (*count_collector)(struct tcp_count_event))
{
  static struct ipv4_flow_key keys[MAX_ENTRIES];
  uint32_t value_size = sizeof(uint64_t);
  uint32_t key_size = sizeof(keys[0]);
  static struct ipv4_flow_key zero;
  static uint64_t counts[MAX_ENTRIES];
  char s[INET_ADDRSTRLEN];
  char d[INET_ADDRSTRLEN];
  uint32_t i, n = MAX_ENTRIES;
  struct in_addr src;
  struct in_addr dst;

  if (dump_hash(map_fd, keys, key_size, counts, value_size, &n, &zero))
  {
    fprintf(stderr, "dump_hash: %s", strerror(errno));
    return;
  }

  for (i = 0; i < n; i++)
  {
    src.s_addr = keys[i].saddr;
    dst.s_addr = keys[i].daddr;

    struct tcp_count_event tcp_event;
    strcpy(tcp_event.LADDR, inet_ntop(AF_INET, &src, s, sizeof(s)));
    strcpy(tcp_event.RADDR, inet_ntop(AF_INET, &dst, d, sizeof(d)));
    tcp_event.RPORT = ntohs(keys[i].dport);
    tcp_event.CONNECTS = counts[i];
    tcp_event.is_ipv4 = true;

    count_collector(tcp_event);
  }
}

static void print_count_ipv6(int map_fd, void (*count_collector)(struct tcp_count_event))
{
  static struct ipv6_flow_key keys[MAX_ENTRIES];
  uint32_t value_size = sizeof(uint64_t);
  uint32_t key_size = sizeof(keys[0]);
  static struct ipv6_flow_key zero;
  static uint64_t counts[MAX_ENTRIES];
  char s[INET6_ADDRSTRLEN];
  char d[INET6_ADDRSTRLEN];
  uint32_t i, n = MAX_ENTRIES;
  struct in6_addr src;
  struct in6_addr dst;

  if (dump_hash(map_fd, keys, key_size, counts, value_size, &n, &zero))
  {
    fprintf(stderr, "dump_hash: %s", strerror(errno));
    return;
  }

  for (i = 0; i < n; i++)
  {
    memcpy(src.s6_addr, keys[i].saddr, sizeof(src.s6_addr));
    memcpy(dst.s6_addr, keys[i].daddr, sizeof(src.s6_addr));

    // printf("%-25s %-25s %-20d %-10llu\n",
    //        inet_ntop(AF_INET6, &src, s, sizeof(s)),
    //        inet_ntop(AF_INET6, &dst, d, sizeof(d)), ntohs(keys[i].dport),
    //        counts[i]);
    struct tcp_count_event tcp_event;
    strcpy(tcp_event.LADDR, inet_ntop(AF_INET, &src, s, sizeof(s)));
    strcpy(tcp_event.RADDR, inet_ntop(AF_INET, &dst, d, sizeof(d)));
    tcp_event.RPORT = ntohs(keys[i].dport);
    tcp_event.CONNECTS = counts[i];
    tcp_event.is_ipv4 = false;

    count_collector(tcp_event);
  }
}

static void print_count(int map_fd_ipv4, int map_fd_ipv6, struct tcp_env env)
{
  // static const char *header_fmt = "\n%-25s %-25s %-20s %-10s\n";

  while (!*env.exiting)
    pause();

  // printf(header_fmt, "LADDR", "RADDR", "RPORT", "CONNECTS");
  print_count_ipv4(map_fd_ipv4, env.count_collector);
  print_count_ipv6(map_fd_ipv6, env.count_collector);
}

static int start_tcp_tracker(perf_buffer_sample_fn handle_event, libbpf_print_fn_t libbpf_print_fn, struct tcp_env env)
{
  if (!env.exiting)
  {
    fprintf(stderr, "env.exiting is not set.\n");
    return -1;
  }
  struct tcp_bpf *obj;
  LIBBPF_OPTS(bpf_object_open_opts, open_opts);

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Load and verify BPF application */
  obj = tcp_bpf__open_opts(&open_opts);
  if (!obj)
  {
    fprintf(stderr, "failed to open BPF object\n");
    return 1;
  }

  int i, err;
  if (env.count)
  {
    obj->rodata->do_count = true;
    if (!env.count_collector)
    {
      fprintf(stderr, "env.count_collector is not set.\n");
      return -1;
    }
  }
  if (env.pid)
    obj->rodata->filter_pid = env.pid;
  if (env.uid != (uid_t)-1)
    obj->rodata->filter_uid = env.uid;
  if (env.nports > 0)
  {
    obj->rodata->filter_ports_len = env.nports;
    for (i = 0; i < env.nports; i++)
    {
      obj->rodata->filter_ports[i] = htons(env.ports[i]);
    }
  }

  /* Load & verify BPF programs */
  err = tcp_bpf__load(obj);
  if (err)
  {
    fprintf(stderr, "failed to load BPF object: %d\n", err);
    goto cleanup;
  }

  /* Attach tracepoints */
  err = tcp_bpf__attach(obj);
  if (err)
  {
    fprintf(stderr, "failed to attach BPF programs: %s\n", strerror(-err));
    goto cleanup;
  }

  if (env.count)
  {
    print_count(bpf_map__fd(obj->maps.ipv4_count), bpf_map__fd(obj->maps.ipv6_count), env);
  }
  else
  {
    print_events(bpf_map__fd(obj->maps.events), handle_event, env);
  }

cleanup:
  tcp_bpf__destroy(obj);

  return err != 0;
}

#endif /* TCP_TRACKER_H */
