/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "file_tracker.h"

static volatile bool exiting = 0;

static pid_t target_pid = 0;
static bool clear_screen = true;
static bool regular_file_only = true;
static int output_rows = 20;
static int sort_by = ALL;
static int interval = 1;
static int count = 99999999;
static bool verbose = false;

static const char argp_program_doc[] =
    "Trace file reads/writes by process.\n"
    "\n"
    "USAGE: filetop [-h] [-p PID] [interval] [count]\n"
    "\n"
    "EXAMPLES:\n"
    "    filetop            # file I/O top, refresh every 1s\n"
    "    filetop -p 1216    # only trace PID 1216\n"
    "    filetop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
  { "pid", 'p', "PID", 0, "Process ID to trace" },
  { "noclear", 'C', NULL, 0, "Don't clear the screen" },
  { "all", 'a', NULL, 0, "Include special files" },
  { "sort", 's', "SORT", 0, "Sort columns, default all [all, reads, writes, rbytes, wbytes]" },
  { "rows", 'r', "ROWS", 0, "Maximum rows to print, default 20" },
  { "verbose", 'v', NULL, 0, "Verbose debug output" },
  { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
  {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
  long pid, rows;
  static int pos_args;

  switch (key)
  {
    case 'p':
      errno = 0;
      pid = strtol(arg, NULL, 10);
      if (errno || pid <= 0)
      {
        fprintf(stderr, "invalid PID: %s\n", arg);
        argp_usage(state);
      }
      target_pid = pid;
      break;
    case 'C': clear_screen = false; break;
    case 'a': regular_file_only = false; break;
    case 's':
      if (!strcmp(arg, "all"))
      {
        sort_by = ALL;
      }
      else if (!strcmp(arg, "reads"))
      {
        sort_by = READS;
      }
      else if (!strcmp(arg, "writes"))
      {
        sort_by = WRITES;
      }
      else if (!strcmp(arg, "rbytes"))
      {
        sort_by = RBYTES;
      }
      else if (!strcmp(arg, "wbytes"))
      {
        sort_by = WBYTES;
      }
      else
      {
        fprintf(stderr, "invalid sort method: %s\n", arg);
        argp_usage(state);
      }
      break;
    case 'r':
      errno = 0;
      rows = strtol(arg, NULL, 10);
      if (errno || rows <= 0)
      {
        fprintf(stderr, "invalid rows: %s\n", arg);
        argp_usage(state);
      }
      output_rows = rows;
      if (output_rows > OUTPUT_ROWS_LIMIT)
        output_rows = OUTPUT_ROWS_LIMIT;
      break;
    case 'v': verbose = true; break;
    case 'h': argp_state_help(state, stderr, ARGP_HELP_STD_HELP); break;
    case ARGP_KEY_ARG:
      errno = 0;
      if (pos_args == 0)
      {
        interval = strtol(arg, NULL, 10);
        if (errno || interval <= 0)
        {
          fprintf(stderr, "invalid interval\n");
          argp_usage(state);
        }
      }
      else if (pos_args == 1)
      {
        count = strtol(arg, NULL, 10);
        if (errno || count <= 0)
        {
          fprintf(stderr, "invalid count\n");
          argp_usage(state);
        }
      }
      else
      {
        fprintf(stderr, "unrecognized positional argument: %s\n", arg);
        argp_usage(state);
      }
      pos_args++;
      break;
    default: return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  if (level == LIBBPF_DEBUG && !verbose)
    return 0;
  return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
  exiting = 1;
}

static int sort_column(const void *obj1, const void *obj2)
{
  struct file_stat *s1 = (struct file_stat *)obj1;
  struct file_stat *s2 = (struct file_stat *)obj2;

  if (sort_by == READS)
  {
    return s2->reads - s1->reads;
  }
  else if (sort_by == WRITES)
  {
    return s2->writes - s1->writes;
  }
  else if (sort_by == RBYTES)
  {
    return s2->read_bytes - s1->read_bytes;
  }
  else if (sort_by == WBYTES)
  {
    return s2->write_bytes - s1->write_bytes;
  }
  else
  {
    return (s2->reads + s2->writes + s2->read_bytes + s2->write_bytes) -
           (s1->reads + s1->writes + s1->read_bytes + s1->write_bytes);
  }
}

static int print_event(void *ctx, void *data, size_t size)
{
  if (!data || !ctx)
  {
    return 0;
  }
  struct files_event *event = (struct files_event *)data;
  struct files_env *env = (struct files_env *)ctx;
  int i, n;
  FILE *f;
  time_t t;
  struct tm *tm;
  char ts[16], buf[256];
  f = fopen("/proc/loadavg", "r");
  if (f)
  {
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    memset(buf, 0, sizeof(buf));
    n = fread(buf, 1, sizeof(buf), f);
    if (n)
      printf("%8s loadavg: %s\n", ts, buf);
    fclose(f);
  }

  printf("%-7s %-16s %-6s %-6s %-7s %-7s %1s %s\n", "TID", "COMM", "READS", "WRITES", "R_Kb", "W_Kb", "T", "FILE");

  qsort(event->values, event->rows, sizeof(struct file_stat), sort_column);
  event->rows = event->rows < env->output_rows ? event->rows : env->output_rows;
  for (i = 0; i < event->rows; i++)
    printf(
        "%-7d %-16s %-6lld %-6lld %-7lld %-7lld %c %s\n",
        event->values[i].tid,
        event->values[i].comm,
        event->values[i].reads,
        event->values[i].writes,
        event->values[i].read_bytes / 1024,
        event->values[i].write_bytes / 1024,
        event->values[i].type,
        event->values[i].filename);

  printf("\n");
  return 0;
}

int main(int argc, char **argv)
{
  static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
  };
  int err;

  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err)
    return err;

  if (signal(SIGINT, sig_int) == SIG_ERR)
  {
    fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
    err = 1;
    goto cleanup;
  }
  struct files_env env = {
    .output_rows = output_rows,
    .target_pid = target_pid,
    .clear_screen = clear_screen,
    .regular_file_only = regular_file_only,
    .exiting = &exiting,
    .sort_by = sort_by,
    .interval = interval,
    .verbose = verbose,
    .output_rows = output_rows,
  };
  env.ctx = &env;
  exiting = false;
  start_file_tracker(print_event, libbpf_print_fn, env);
cleanup:
  return err != 0;
}