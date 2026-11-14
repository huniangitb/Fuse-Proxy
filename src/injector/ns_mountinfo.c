/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * ns_mountinfo.c — /proc/<pid>/mountinfo 的**唯一**扫描实现（历史审计项 C7）
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
 *
 * 成本模型（2026-10-31 真机取证）：扫描成本只与**命名空间条目总数**成正比，与
 * 「真正要收的子挂载数」无关。某台 Redmi/Android 14 上 `[ns计]` 里 mountinfo 段
 * 稳定 134~136ms（同一台设备上另一个应用只要 6ms），而当时任何规则都没配——所以
 * 与规则引擎无关，纯粹是"几千条 /apex、/system、/data 挂载每条都要过两次 4KB
 * 零初始化 + 两次 sscanf"。两条对策：
 *   ① 前缀预筛：collect 路径在字段解析**之前**先用 base 做一次子串预筛，命中者才
 *      做字段级精确判定（x86_64 合成数据实测：2000 行 2.3ms→0.5ms，20000 行
 *      13.8ms→3.6ms，两次扫描合计）。预筛只是**必要非充分**条件（base 也可能只
 *      出现在 source/root 字段），故行为语义一字不变。
 *   ② 一次扫描收多棵子树（ns_collect_mounts_multi）：合并挂载原本对「备份树」和
 *      「目标树」各全量扫一遍同一份 mountinfo，纯浪费一次读。
 * 剩下的不确定性（是"条目多"还是"CPU 被应用冷启动抢走"）由规模快照回答：行数/
 * 字节/预筛命中 + 同期 CPU 时间 + 非自愿上下文切换，全部由调用方输出到 `[ns计]`。
 */
#include "ns_global_replace.h"

#include "common.h"      /* LOG_WRN */
#include "fast_search.h" /* fast_strstr */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> /* malloc/setvbuf 缓冲 */
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static int64_t mi_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/* 本进程累计 CPU 时间（user+sys）与非自愿上下文切换：与墙钟一对照就能判定
   "慢在自己干活"还是"慢在被别人抢 CPU"——后者不是优化扫描能解决的。 */
static void mi_rusage(int64_t* cpu_us, long* nivcsw) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) {
        *cpu_us = 0;
        *nivcsw = 0;
        return;
    }
    *cpu_us = (int64_t)(ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1000000 +
              (int64_t)(ru.ru_utime.tv_usec + ru.ru_stime.tv_usec);
    *nivcsw = ru.ru_nivcsw;
}

/* 最近一次扫描的规模快照：只服务诊断输出，多线程各自覆盖、不加锁——它不是判据，
   任何行为都不得依赖它的取值。 */
static NsMountinfoStats g_mi_last;

void ns_mountinfo_last_stats(NsMountinfoStats* out) {
    if (out) *out = g_mi_last;
}

/* 前缀预筛：挂载点落在 prefixes[i] 子树内 ⇒ 该行必然包含该前缀子串，因此
   「一个前缀都不含」的行可以完全跳过解析。空前缀 = 不过滤（保持旧语义）。 */
static bool mi_prefilter_pass(const char* line, const char* const* prefixes, int nprefixes) {
    if (!prefixes || nprefixes <= 0) return true;
    for (int i = 0; i < nprefixes; i++) {
        const char* p = prefixes[i];
        if (!p || !p[0]) return true; /* 空前缀：调用方要全量（旧行为） */
        if (fast_strstr(line, p)) return true;
    }
    return false;
}

/* 扫描实现：prefixes 为 NULL/0 时逐行解析（全量读取，ns_read_mountinfo_pid 走这条），
   否则先预筛再解析。返回已回调行数；-1 = 打开失败（errno 有效）。 */
static int mi_scan(int pid, const char* const* prefixes, int nprefixes, NsMountinfoLineFn cb,
                   void* ctx, NsMountinfoStats* out_stats) {
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
    /* /proc/<pid>/mountinfo 是 seq_file：**每次 read() 都从挂载表头部重新走一遍**
       （按字节偏移重放到当前位置），于是 read 次数直接决定总耗时——默认 4KB 缓冲
       下真机 2.6MB 要 ~640 次 read，等价于 O(n²) 的重复遍历，实测单次 ~68ms。
       缓冲拉到 256KB 后 read 降到个位数；逐行解析再由前缀预筛挡掉绝大多数。
       用堆缓冲而非 static：v2 的后台还原线程与主循环可能并发扫描（static 会串内容）。 */
    char* iobuf = malloc(1u << 18);
    if (iobuf) setvbuf(fp, iobuf, _IOFBF, 1u << 18);
    int64_t t_begin = mi_now_us();
    int64_t cpu_begin = 0;
    long csw_begin = 0;
    mi_rusage(&cpu_begin, &csw_begin);
    NsMountinfoStats st;
    memset(&st, 0, sizeof st);
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
            st.truncated = true;
            continue;
        }
        st.lines++;
        st.bytes += (long)llen;
        if (!mi_prefilter_pass(line, prefixes, nprefixes)) continue;
        st.candidates++;
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
    free(iobuf);
    st.scan_us = mi_now_us() - t_begin;
    int64_t cpu_end = 0;
    long csw_end = 0;
    mi_rusage(&cpu_end, &csw_end);
    st.cpu_us = cpu_end - cpu_begin;
    st.csw = csw_end - csw_begin;
    g_mi_last = st;
    /* 调用方自带快照：全局 g_mi_last 会被并发扫描覆盖，判据（例如「这次有没有丢弃
       过超长行」）必须用本次扫描自己的那份 */
    if (out_stats) *out_stats = st;
    return count;
}

int ns_scan_mountinfo(int pid, NsMountinfoLineFn cb, void* ctx) {
    return mi_scan(pid, nullptr, 0, cb, ctx, nullptr);
}

int ns_scan_mountinfo_stats(int pid, NsMountinfoLineFn cb, void* ctx, NsMountinfoStats* out) {
    return mi_scan(pid, nullptr, 0, cb, ctx, out);
}

int ns_scan_mountinfo_prefixed(int pid, const char* const* prefixes, int nprefixes,
                               NsMountinfoLineFn cb, void* ctx) {
    /* 预筛只是"必要非充分"：命中者仍走完整字段解析，回调拿到的行与全量扫描完全
       一致——调用方按 mount_point 做精确判定即可，语义与逐行全扫一字不差。 */
    return mi_scan(pid, prefixes, nprefixes, cb, ctx, nullptr);
}

/* 单棵子树的收集状态：单 base 与多 base 共用一个 applier，保证两条路径的
   「不含自身 / 严格子路径 / 容量触顶拒截断 / 超长跳过」判定完全同源。 */
struct NsCollectCtx {
    const char* base;
    size_t blen;
    char (*out)[NS_MOUNT_PATH_MAX];
    int max;
    int n;
    const char* who;
    bool full; /* 已触顶并告警过：后续条目直接跳过（不静默截断，也不再重复告警） */
};

/* 返回 0 继续，1 表示"该目标不再需要后面的条目"。 */
static int ns_collect_apply(struct NsCollectCtx* c, const char* mp) {
    if (c->full) return 1;
    if (strcmp(mp, c->base) == 0) return 0; /* 不含自身 */
    if (strncmp(mp, c->base, c->blen) != 0 || mp[c->blen] != '/') return 0;
    if (c->n >= c->max) {
        LOG_WRN("%s: %s 下匹配挂载点达到 %d 上限，拒绝静默截断", c->who, c->base, c->max);
        c->full = true;
        return 1;
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

static int ns_collect_cb(const NsMountLine* ln, void* vctx) {
    return ns_collect_apply(vctx, ln->mount_point);
}

int ns_collect_mounts_under_pid(int pid, const char* base, char (*out)[NS_MOUNT_PATH_MAX],
                                int max, const char* who) {
    if (!base || !out || max <= 0) return 0;
    struct NsCollectCtx c = {.base = base,
                             .blen = strlen(base),
                             .out = out,
                             .max = max,
                             .who = who ? who : "收集挂载点"};
    /* 以 base 作前缀预筛：只有可能落在该子树内的行才做字段级解析 */
    const char* prefixes[1] = {base};
    if (mi_scan(pid, prefixes, 1, ns_collect_cb, &c, nullptr) < 0) return -1;
    return c.n;
}

/* 多目标单次扫描：合并挂载要同时收「备份树」与「目标树」，两者读的是同一份
   mountinfo——各扫一遍就是把最贵的那步（读文件）做两次。 */
#define NS_COLLECT_TARGETS_MAX 4

struct NsCollectMultiCtx {
    struct NsCollectCtx* t;
    int n;
};

static int ns_collect_multi_cb(const NsMountLine* ln, void* vctx) {
    struct NsCollectMultiCtx* mc = vctx;
    bool all_full = true;
    for (int i = 0; i < mc->n; i++) {
        struct NsCollectCtx* c = &mc->t[i];
        if (c->full) continue; /* 无效目标 / 已触顶：本行与它无关 */
        ns_collect_apply(c, ln->mount_point);
        if (!c->full) all_full = false;
    }
    return all_full; /* 全部目标都触顶才停止扫描 */
}

int ns_collect_mounts_multi(int pid, NsCollectTarget* targets, int ntargets) {
    if (!targets || ntargets <= 0 || ntargets > NS_COLLECT_TARGETS_MAX) return 0;
    struct NsCollectCtx ctx[NS_COLLECT_TARGETS_MAX];
    const char* prefixes[NS_COLLECT_TARGETS_MAX];
    int nprefix = 0;
    for (int i = 0; i < ntargets; i++) {
        NsCollectTarget* g = &targets[i];
        g->n = 0;
        ctx[i] = (struct NsCollectCtx){0};
        if (!g->base || !g->out || g->max <= 0) {
            ctx[i].full = true; /* 占位：回调直接跳过 */
            continue;
        }
        ctx[i] = (struct NsCollectCtx){.base = g->base,
                                       .blen = strlen(g->base),
                                       .out = g->out,
                                       .max = g->max,
                                       .who = g->who ? g->who : "收集挂载点"};
        prefixes[nprefix++] = g->base;
    }
    if (nprefix == 0) return 0;
    struct NsCollectMultiCtx mc = {.t = ctx, .n = ntargets};
    if (mi_scan(pid, prefixes, nprefix, ns_collect_multi_cb, &mc, nullptr) < 0) return -1;
    for (int i = 0; i < ntargets; i++) targets[i].n = ctx[i].n;
    return 0;
}
