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
#include <stdlib.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "process.h"
#include "process_tracker.h"
#include "process.skel.h"

static const char *headers[] = {
	"stat", "comm", "filename/exitcode", "duration",
	(const char*)((void*)0)};

static struct process_env process_env = {0};

static const char argp_program_doc[] =
	"eBPF process tracing application.\n"
	"\n"
	"It traces process start and exits and shows associated \n"
	"information (filename, process duration, PID and PPID, etc).\n"
	"\n"
	"USAGE: ./process [-d <min-duration-ms>] [-v]\n";
const char *namespaces[] = {"cgroup", "user", "pid", "mnt"};
#define NS_LEN 4

static struct process_bpf *skel;

static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Process ID to trace"},
	{"verbose", 'v', NULL, 0, "Verbose debug output"},
	{"csv", 'C', NULL, 0, "Output in the CSV format"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{"duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	pid_t pid;
	switch (key)
	{
	case 'v':
		process_env.verbose = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0)
		{
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		process_env.target_pid = pid;
		break;
	case 'd':
		errno = 0;
		process_env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || process_env.min_duration_ms <= 0)
		{
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'C':
		process_env.is_csv = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !process_env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void print_table_data(const struct process_event *e)
{
	print_basic_info((const struct common_event *)e, false);

	if (e->exit_event)
	{
		printf("%-5s %-16s [%u]",
			   "EXIT", e->comm, e->exit_code);
		if (e->duration_ns)
			printf(" (%llums)", e->duration_ns / 1000000);
		printf("\n");
	}
	else
	{
		printf("%-5s %-16s %s\n",
			   "EXEC", e->comm, e->filename);
	}
}

static void
print_header(void)
{
	print_table_header(headers, process_env.is_csv);
}

static void
print_csv_data(const struct process_event *e)
{
	print_basic_info((const struct common_event *)e, true);

	if (e->exit_event)
	{
		printf("%s,%s,%u,",
			   "EXIT", e->comm, e->exit_code);
		if (e->duration_ns)
			printf("%llu", e->duration_ns / 1000000);
		printf("\n");
	}
	else
	{
		printf("%s,%s,%s,\n",
			   "EXEC", e->comm, e->filename);
	}
}

static void 
copy_process_event(struct process_event *dest, const struct process_event *src)
{
	dest->common = src->common;
	dest->duration_ns = src->duration_ns;
	dest->exit_code = src->exit_code;
	// dest->filename = src->filename;
	strcpy(dest->filename, src->filename);
	strcpy(dest->comm, src->comm);
}
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	printf("handle\n");
	//int i, err;
	const struct process_event *e = data;
	// struct process_event parent, curr = {0};
	// char buf[10] = {0};
	// FILE* fp;
	// uint32_t ns;
	// int processes_fd;

	// const uint32_t e_ns[] = {e->common.cgroup_id, e->common.user_namespace_id,
	// 				e->common.pid_namespace_id, e->common.mount_namespace_id};
	// // printf("cut here\n");
	// /* bug happens here */
	// processes_fd = bpf_map__fd(skel->maps.processes);
	
	// err = bpf_map_lookup_elem(processes_fd, &e->common.ppid, &parent);
	
	// sprintf(buf,"%d/ns/",e->common.pid);
	// if (err) {
		
	// 	for (i = 0; i < NS_LEN; i++)
	// 	{
	// 		char cmd[] = "stat --format=\%N /proc/";
	// 		strcat(cmd, buf);
	// 		strcat(cmd, namespaces[i]);
	// 		fp = popen(cmd, "r");
	// 		if(fscanf(fp, "%*[^[][%u]'\n", &ns) != 1) {
	// 			continue;
	// 		}
	// 		fclose(fp);
	// 		/* namespace has changed */
	// 		if(ns != e_ns[i]) {
	// 			copy_process_event(&curr, e);
	// 			bpf_map_update_elem(processes_fd, &curr.common.pid, &curr, 0);
	// 			break;
	// 		}
	// 	}
	// } else {
	// 	printf("another");
	// 	copy_process_event(&curr, e);
	// 	bpf_map_update_elem(processes_fd, &curr.common.pid, &curr, 0);
	// }

	if (process_env.is_csv)
		print_csv_data(e);
	else
		print_table_data(e);
	return 0;
}

int main(int argc, char **argv)
{
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	print_header();
	process_env.exiting = &exiting;
	return start_process_tracker(handle_event, libbpf_print_fn, process_env, skel, NULL);
}
