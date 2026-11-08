/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ns_mnt_watch.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/* 只负责把路径拼出来并打开：EPOLL_CTL_ADD 的掩码约束在头文件里写明，
   调用方（injector 主循环）按 events=0 注册。不在这里做 poll 探测——
   挂载表没变化时 poll 本来就该静默，探不出「支持与否」。 */
int ns_mnt_watch_open(int ns_pid) {
    char path[64];
    int n = snprintf(path, sizeof(path), "/proc/%d/mountinfo", ns_pid);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    return fd;
}
