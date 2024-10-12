#include <stdio.h>
#include <stdlib.h>
#include "agent/myseccomp.h"
#include "agent/config.h"
#include "spdlog/spdlog.h"

seccomp_config config;

int main()
{
  std::vector<std::string> str = {
      "open",
      "close",
      "fstat",
      "execve",
      "mmap",
      "munmap",
      "uname",
      "arch_prctl",
      "brk",
      "access",
      "readlink",
      "sysinfo",
      "writev",
      "lseek",
      "mprotect",
      "exit_group",
//      "read",
      "write",
      "exit",
      "rt_sigreturn"
  };

  config.allow_syscall.assign(str.begin(), str.end());
  /*
   * ...
   */
  enable_seccomp_white_list(config);
  int d;
  scanf("%d",&d);
  spdlog::info("your input is :{0} \nif you get the print is equal to your input,congraduation! you are successful to enable seccomp, and don't care about next line print\n",d);
  //execv("./process_test_Tests",NULL);
  spdlog::info("if you can get here,that means seccomp is wrong\n");

  return 0;
}
