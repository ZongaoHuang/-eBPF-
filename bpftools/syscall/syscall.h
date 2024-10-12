#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define SYSCALL_TASK_COMM_LEN 64

// if pid is not set, this message is the first time a syscall happends in a process;
// if target_pid or cgroups is set, this message is all syscalls
struct syscall_event
{
  int pid;
  int ppid;
  uint32_t syscall_id;
  uint64_t mntns;
  char comm[SYSCALL_TASK_COMM_LEN];

  // long unsigned int args[6];
  unsigned char occur_times;
};

#endif /* __BOOTSTRAP_H */
