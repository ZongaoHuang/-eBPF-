// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
#ifndef __TCPCONNECT_H
#define __TCPCONNECT_H

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

/* The maximum number of ports to filter */
#define MAX_PORTS 64

#define TASK_COMM_LEN 16

struct ipv4_flow_key {
  unsigned int saddr;
  unsigned int daddr;
  unsigned short dport;
};

struct ipv6_flow_key {
  unsigned char saddr[16];
  unsigned char daddr[16];
  unsigned short dport;
};

struct tcp_event {
  union {
    unsigned int saddr_v4;
    unsigned char saddr_v6[16];
  };
  union {
    unsigned int daddr_v4;
    unsigned char daddr_v6[16];
  };
  char task[TASK_COMM_LEN];
  unsigned long ts_us;
  unsigned int af; // AF_INET or AF_INET6
  unsigned int pid;
  unsigned int uid;
  unsigned short dport;
};

#endif /* __TCPCONNECT_H */
