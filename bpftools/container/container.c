/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
 *
 * Copyright (c) 2020, Andrii Nakryiko
 * 
 * modified from https://github.com/libbpf/libbpf-bootstrap/
 * We use libbpf-bootstrap as a start template for our bpf program.
 */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include "container.h"
#include "container.skel.h"
#include "container_tracker.h"

static volatile bool exiting = false;

static struct container_env container_env;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !container_env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	// const struct container_event *e = data;

	// printf("%-10u %-15u %lu \n", e->pid, e->ppid, e->container_id);
	return 0;
}


int main(int argc, char **argv)
{
	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	container_env.exiting = &exiting;

	return start_container_tracker(handle_event, libbpf_print_fn, container_env);
}
