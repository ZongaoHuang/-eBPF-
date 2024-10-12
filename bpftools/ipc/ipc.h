/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __IPC_H
#define __IPC_H

struct ipc_event {
    unsigned int pid;
    unsigned int uid;
    unsigned int gid;
    unsigned int cuid;
    unsigned int cgid;
};

#endif /* __IPC_H */
