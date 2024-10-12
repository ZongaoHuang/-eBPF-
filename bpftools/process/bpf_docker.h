#ifndef BPF_DOCKER_H
#define BPF_DOCKER_H

/* Get the mount namespace id for the current task.
 *
 * return: Mount namespace id or 0 if we couldn't find it.
 */
static __always_inline u32 get_current_mnt_ns_id()
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	return task->nsproxy->mnt_ns->ns.inum;
}

/* Get the pid namespace id for the current task.
 *
 * return: Pid namespace id or 0 if we couldn't find it.
 */
static __always_inline u32 get_current_pid_ns_id()
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	return task->thread_pid->numbers[0].ns->ns.inum;
}

/* Get the user namespace id for the current task.
 *
 * return: user namespace id or 0 if we couldn't find it.
 */
static __always_inline u32 get_current_user_ns_id()
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	return task->cred->user_ns->ns.inum;
}

static __always_inline void fill_event_basic(pid_t pid, struct task_struct *task, struct process_event *e)
{
	e->common.pid = pid;
	e->common.ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->common.cgroup_id = bpf_get_current_cgroup_id();
	e->common.user_namespace_id = get_current_user_ns_id();
	e->common.pid_namespace_id = get_current_pid_ns_id();
	e->common.mount_namespace_id = get_current_mnt_ns_id();
}

#endif