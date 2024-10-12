#ifndef SECCOMP_H
#define SECCOMP_H

#define _GNU_SOURCE 1
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "config.h"
#include "seccomp-bpf.h"
#include "syscall_helper.h"
#include "spdlog/spdlog.h"

bool is_not_exist(uint32_t syscall_id[], int len, int id);

static int install_syscall_filter(uint32_t syscall_id[], int len);

int get_syscall_id(std::string syscall_name);

// Enable Seccomp syscall
// param seccomp_config type is defined by include/agent/config.h
int enable_seccomp_white_list(seccomp_config config);

#endif
