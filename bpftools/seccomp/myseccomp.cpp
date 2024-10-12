#include "agent/myseccomp.h"
#include "spdlog/spdlog.h"

// if interger var id is not exist in array syscall_id[] return true, otherwise return false
bool is_not_exist(uint32_t syscall_id[], int len, int id)
{
  for (auto i = 0; i < len; i++)
  {
    if (id == syscall_id[i])
      return false;
  }
  return true;
}

static int install_syscall_filter(uint32_t syscall_id[], int len)
{
  std::vector<sock_filter> filter_vec = { /* Validate architecture. */
                                          BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 4),
                                          BPF_JUMP(BPF_JMP + BPF_JEQ, 0xc000003e, 0, 2),
                                          /* Grab the system call number. */
                                          BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0),
                                          /* syscalls. */
                                          BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
  };

  int syscalls_size = sizeof(syscall_id) / sizeof(syscall_id[0]);
  /* add ban rules All syscalls*/
  for (auto i = 0; i < syscalls_size; i++)
  {
    if (is_not_exist(syscall_id, len, i))
    {
      filter_vec.insert(filter_vec.end() - 1, BPF_JUMP(BPF_JMP + BPF_JEQ, i, 0, 1));
      //printf("banned syscall_id : %d\n", i);
      filter_vec.insert(filter_vec.end() - 1, BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL));
    }
    else
    {
        spdlog::info("allowed syscall_id : {0:d}", i);
    }
  }

  filter_vec.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));

  sock_filter filter[filter_vec.size()];
  std::copy(filter_vec.begin(), filter_vec.end(), filter);

  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
  {
    perror("prctl(NO_NEW_PRIVS)");
    goto failed;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
  {
    perror("prctl(SECCOMP)");
    goto failed;
  }
  return 0;

failed:
  if (errno == EINVAL)
    fprintf(stderr, "SECCOMP_FILTER is not available. :(n");
  return 1;
}

int get_syscall_id(std::string syscall_name)
{
  for (int i = 0; i < 439; i++)
  {
    if (strcmp(syscall_names_x86_64[i], syscall_name.data()) == 0)
      return i;
  }
  return -1;
}

// Enable Seccomp syscall
// param seccomp_config type is defined by include/agent/config.h
int enable_seccomp_white_list(const seccomp_config& config)
{
  spdlog::info("enabled seccomp");
  std::vector<uint32_t> syscall_vec;  // allow_syscall_id list
  for (int i = 0; i < config.allow_syscall.size(); i++)
  {
    int id = get_syscall_id(config.allow_syscall[i]);
    if (id == -1)
    {
      spdlog::error("syscall_id error {0} has no corresponding syscall in x86 system arch", config.allow_syscall[i]);
      continue;
    }
    syscall_vec.push_back(id);
  }
  uint32_t syscall_id[syscall_vec.size()];
  std::copy(syscall_vec.begin(), syscall_vec.end(), syscall_id);
  //  printf("ban %d syscalls\n allow %d syscalls\n",config.len,439-config.len);
  if (install_syscall_filter(syscall_id, syscall_vec.size()))
    return 1;

  return 0;
}

