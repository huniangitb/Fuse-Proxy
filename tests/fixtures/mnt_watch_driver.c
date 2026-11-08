/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
/*
 * mnt_watch_driver — 挂载表变化事件源的验收驱动（仅测试用）
 *
 * 直编 src/injector/ns_mnt_watch.c，在私有挂载命名空间里制造真实的 mount/umount，
 * 量出「挂载表变化 → 事件源可读」的延迟与次数，供 tests/test_mnt_watch.py 断言。
 * 断言全部放在 Python 侧，本驱动只负责按 KEY=VALUE 打印观测值。
 *
 * 用法：mnt_watch_driver <mode> [scratch_dir]
 *   idle    — 不制造变化，量 300ms 内的唤醒次数（必须是 0：既没有自旋，也没有误报）
 *   mount   — 挂上 tmpfs，量到事件的毫秒数，再等 200ms 看是否只有一次
 *   umount  — 先挂再卸，量卸载到事件的毫秒数
 *   seq     — 连续两次变化（挂 → 卸）各量一次延迟
 *   read    — 先把 mountinfo 整份读一遍再等：读文件不得产生也不得吞掉事件
 *   badpid  — 打开不存在的 pid，必须返回 -1
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "ns_mnt_watch.h"

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* 按生产代码的用法注册：掩码为 0，只收 EPOLLERR */
static int arm(int* ep_out, int* fd_out) {
    int fd = ns_mnt_watch_open((int)getpid());
    if (fd < 0) {
        printf("arm_error=open errno=%d\n", errno);
        return -1;
    }
    int ep = epoll_create1(0);
    if (ep < 0) {
        printf("arm_error=epoll_create1 errno=%d\n", errno);
        close(fd);
        return -1;
    }
    struct epoll_event ev = {.events = 0, .data.fd = fd};
    if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) != 0) {
        printf("arm_error=epoll_ctl errno=%d\n", errno);
        close(ep);
        close(fd);
        return -1;
    }
    *ep_out = ep;
    *fd_out = fd;
    return 0;
}

static int wait_event(int ep, int timeout_ms, unsigned* revents) {
    struct epoll_event out[4];
    int n = epoll_wait(ep, out, 4, timeout_ms);
    if (n > 0 && revents) *revents = out[0].events;
    return n;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "用法: %s <idle|mount|umount|seq|read|badpid> [scratch_dir]\n", argv[0]);
        return 2;
    }
    const char* mode = argv[1];
    const char* dir = (argc > 2) ? argv[2] : nullptr;
    printf("driver_mode=%s\n", mode);

    if (strcmp(mode, "badpid") == 0) {
        int fd = ns_mnt_watch_open(999999);
        printf("badpid_fd=%d errno=%d\n", fd, fd < 0 ? errno : 0);
        if (fd >= 0) close(fd);
        return 0;
    }
    if (!dir) {
        fprintf(stderr, "缺少 scratch_dir\n");
        return 2;
    }
    mkdir(dir, 0755);

    int ep = -1, fd = -1;
    if (arm(&ep, &fd) != 0) return 1;

    unsigned revents = 0;
    if (strcmp(mode, "idle") == 0) {
        int n = wait_event(ep, 300, &revents);
        printf("idle_events=%d revents=0x%x\n", n, revents);
        return 0;
    }
    if (strcmp(mode, "read") == 0) {
        /* 读一遍整份挂载表：旧实现靠的就是这次读，本驱动要证明它既不自造事件，
           也不会把后续真实变化的事件吞掉 */
        char buf[4096];
        long lines = 0;
        ssize_t r;
        while ((r = read(fd, buf, sizeof(buf))) > 0) {
            for (ssize_t i = 0; i < r; i++)
                if (buf[i] == '\n') lines++;
        }
        int before = wait_event(ep, 200, &revents);
        long t0 = now_ms();
        int rc = mount("tmpfs", dir, "tmpfs", 0, nullptr);
        int n = wait_event(ep, 500, &revents);
        printf("read_lines=%ld read_rc=%zd events_after_read=%d mount_rc=%d mount_events=%d "
               "mount_ms=%ld revents=0x%x\n",
               lines, r, before, rc, n, now_ms() - t0, revents);
        if (rc == 0) umount2(dir, MNT_DETACH);
        return 0;
    }
    if (strcmp(mode, "mount") == 0) {
        long t0 = now_ms();
        int rc = mount("tmpfs", dir, "tmpfs", 0, nullptr);
        int n = wait_event(ep, 500, &revents);
        long dt = now_ms() - t0;
        int again = wait_event(ep, 200, &revents);
        printf("mount_rc=%d mount_events=%d mount_ms=%ld again_events=%d revents=0x%x\n", rc, n,
               dt, again, revents);
        if (rc == 0) umount2(dir, MNT_DETACH);
        return 0;
    }
    if (strcmp(mode, "umount") == 0) {
        if (mount("tmpfs", dir, "tmpfs", 0, nullptr) != 0) {
            printf("setup_error=mount errno=%d\n", errno);
            return 1;
        }
        /* 挂载本身已经产生一次事件，先把它取走，保证下面量的是卸载那一次 */
        wait_event(ep, 500, &revents);
        long t0 = now_ms();
        int rc = umount2(dir, MNT_DETACH);
        int n = wait_event(ep, 500, &revents);
        printf("umount_rc=%d umount_events=%d umount_ms=%ld revents=0x%x\n", rc, n, now_ms() - t0,
               revents);
        return 0;
    }
    if (strcmp(mode, "seq") == 0) {
        long t0 = now_ms();
        int rc1 = mount("tmpfs", dir, "tmpfs", 0, nullptr);
        int n1 = wait_event(ep, 500, &revents);
        long d1 = now_ms() - t0;
        long t1 = now_ms();
        int rc2 = umount2(dir, MNT_DETACH);
        int n2 = wait_event(ep, 500, &revents);
        long d2 = now_ms() - t1;
        printf("mount_rc=%d mount_events=%d mount_ms=%ld umount_rc=%d umount_events=%d "
               "umount_ms=%ld\n",
               rc1, n1, d1, rc2, n2, d2);
        return 0;
    }
    fprintf(stderr, "未知 mode: %s\n", mode);
    return 2;
}
