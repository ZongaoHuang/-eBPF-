#include "syscall_tracker.h"
#include "syscall_helper.h"
#include <sys/syscall.h>

static struct syscall_env syscall_env = {0};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !syscall_env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct syscall_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	if (e->syscall_id < 0 || e->syscall_id >= syscall_names_x86_64_size)
		return 0;

	printf("%-8s %-16s %-7d %-7d [%lu] %u\t%s\t%d\n",
		   ts, e->comm, e->pid, e->ppid, e->mntns, e->syscall_id, syscall_names_x86_64[e->syscall_id], e->occur_times);

	return 0;
}

int main(int argc, char **argv)
{
	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Process events */
	printf("%-8s %-5s %-16s %-7s %-7s %s\n",
		   "TIME", "EVENT", "COMM", "PID", "PPID", "SYSCALL_ID");

	syscall_env.exiting = &exiting;
	//syscall_env.filter_cg = true;
	//syscall_env.cgroupspath = "/sys/fs/cgroup/unified/cgroup.controllers";
	// syscall_env.target_pid = 9666;
	// syscall_env.filter_report_times = 200;
	// syscall_env.min_duration_ms = 50;
	return start_syscall_tracker(handle_event, libbpf_print_fn, syscall_env, NULL);
}
