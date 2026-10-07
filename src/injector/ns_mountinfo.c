/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * ns_mountinfo.c — /proc/<pid>/mountinfo 的**唯一**扫描实现（review-todo §C7）
 *
 * 背景：ns_utils.c 内四处手写扫描（do_umount_recursive / do_umount_and_rmdir /
 * do_force_umount_stale / do_combined_mount）与 ns_global_replace.c 的
 * ns_read_mountinfo_pid 曾各自 fopen + sscanf + 自定缓冲与边界——A9 的栈越界就出在
 * 其中两份，容量触顶的处理也各写一套（有的告警、有的静默丢弃）。本文件把解析、
 * 超长行处理与「容量触顶/超长条目一律告警并拒绝，绝不静默截断」收成单点，新增
 * 调用方不可能再漂移出一套边界。
 *
 * 独立编译单元的理由：两个直编驱动（ns_umount_overflow / ns_global_replace_rollback）
 * 各自只 #include 一个实现文件，本原语需可被它们单独 #include 而不牵连别的模块。
 */
#include "ns_global_replace.h"

#include "common.h"      /* LOG_WRN */
#include "fast_search.h" /* fast_strstr */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int ns_scan_mountinfo(int pid, NsMountinfoLineFn cb, void* ctx) {
    if (!cb) return -1;
    char path[64];
    /* 自身进程走 /proc/self：省一次 pid 复用竞态窗口，也是既有实现与测试桩
       （--wrap=fopen 匹配 "/proc/self/mountinfo"）依赖的字面形态 */
    if (pid == (int)getpid())
        snprintf(path, sizeof path, "/proc/self/mountinfo");
    else
        snprintf(path, sizeof path, "/proc/%d/mountinfo", pid);
    FILE* fp = fopen(path, "re");
    if (!fp) return -1;
    int count = 0;
    char line[4096];
    while (fgets(line, sizeof line, fp)) {
        /* 超长行（fgets 填满缓冲且未遇换行）：整行丢弃并吃掉残段，绝不把一行
           裂成两条畸形条目——截断/碎片化的挂载点会 umount 到错误位置 */
        size_t llen = strlen(line);
        if (llen == sizeof line - 1 && line[llen - 1] != '\n') {
            int c;
            while ((c = fgetc(fp)) != EOF && c != '\n') {
            }
            LOG_WRN("mountinfo 行超长（≥ %zu 字节）已整行丢弃（pid=%d）", sizeof line - 1, pid);
            continue;
        }
        char mp[PATH_MAX] = {0};
        char dev[64] = {0};
        if (sscanf(line, "%*d %*d %63s %*s %4095s", dev, mp) != 2) continue;
        char fstype[64] = {0};
        char src[PATH_MAX] = {0};
        const char* sep = fast_strstr(line, " - ");
        if (sep && sscanf(sep + 3, "%63s %4095s", fstype, src) < 1) src[0] = '\0';
        int depth = 0;
        for (const char* p = mp; *p; p++)
            if (*p == '/') depth++;
        NsMountLine ln = {.mount_point = mp, .source = src, .fstype = fstype, .dev = dev,
                          .depth = depth};
        count++;
        if (cb(&ln, ctx) != 0) break;
    }
    fclose(fp);
    return count;
}

struct NsCollectCtx {
    const char* base;
    size_t blen;
    char (*out)[NS_MOUNT_PATH_MAX];
    int max;
    int n;
    const char* who;
};

static int ns_collect_cb(const NsMountLine* ln, void* vctx) {
    struct NsCollectCtx* c = vctx;
    const char* mp = ln->mount_point;
    if (strcmp(mp, c->base) == 0) return 0; /* 不含自身 */
    if (strncmp(mp, c->base, c->blen) != 0 || mp[c->blen] != '/') return 0;
    if (c->n >= c->max) {
        LOG_WRN("%s: %s 下匹配挂载点达到 %d 上限，拒绝静默截断", c->who, c->base, c->max);
        return 1; /* 停止扫描 */
    }
    size_t mlen = strlen(mp);
    if (mlen >= NS_MOUNT_PATH_MAX) {
        LOG_WRN("%s: 挂载点路径超长（%zu 字节）已跳过: %.64s...", c->who, mlen, mp);
        return 0;
    }
    memcpy(c->out[c->n], mp, mlen + 1);
    c->n++;
    return 0;
}

int ns_collect_mounts_under_pid(int pid, const char* base, char (*out)[NS_MOUNT_PATH_MAX],
                                int max, const char* who) {
    if (!base || !out || max <= 0) return 0;
    struct NsCollectCtx c = {.base = base,
                             .blen = strlen(base),
                             .out = out,
                             .max = max,
                             .who = who ? who : "收集挂载点"};
    if (ns_scan_mountinfo(pid, ns_collect_cb, &c) < 0) return -1;
    return c.n;
}
