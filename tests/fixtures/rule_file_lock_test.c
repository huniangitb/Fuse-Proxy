/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
/* nsp_rule_file 跨进程编辑回归：读-改-写必须串行，否则丢更新。
 *
 * 场景：4 个进程各自向同一个规则文件连续 upsert 150 条互不相同的规则
 * （rule_server 与多个 log_ctl 并发编辑的现实缩影）。断言最终恰好 600 条、无重复。
 * 去掉目录 flock 后实测只剩约 200 条（后写者吃掉前者的修改）——这正是本用例的
 * 判别力所在；同时覆盖「临时名带 pid」：固定 <path>.tmp 会让并发写者互相 rename
 * 掉对方未写完的临时文件（表现为规则内容损坏/丢行）。
 *
 * 输出：一行汇总 + RESULT OK/FAIL；失败退出码 1。
 *
 * 另含三组回归：
 *   A10 —— 规则文件读失败（EACCES）时编辑必须失败且不覆盖原文件；
 *   A6/C6 —— **全部**公共编辑入口（upsert_line / upsert_in_section / remove_nth /
 *            remove_nth_scoped / toggle_nth_scoped）必须走同一把目录 flock：
 *            锁被持有时逐个断言阻塞，而手工「读-改-写」形态立即返回
 *            （见 case_edit_entries_locked）。C6 后库只保留 nsp_rule_file_edit
 *            一条写入路径，任何入口都不可能退化成锁外读改写。 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "nsp_rule_file.h"

#define CHILDREN 4
#define PER_CHILD 150
#define WORKDIR "/tmp/nsp_rulelock_probe"

static char g_conf[512];

static void child_work(int idx) {
    for (int i = 0; i < PER_CHILD; i++) {
        char line[128];
        snprintf(line, sizeof line, "HIDE /w%d-%03d", idx, i);
        for (int t = 0; t < 20; t++) { /* 目录锁争用时短暂重试（写路径 fail-open 不阻塞） */
            bool changed = false;
            if (nsp_rule_file_upsert_line(g_conf, false, "HIDE", line, &changed) == 0) break;
            usleep(2000);
        }
    }
    _exit(0);
}

/* A10：规则文件**读失败**（EACCES）时编辑必须失败且绝不覆盖原文件。
 * 旧实现把 NULL（=读失败）当空文件 → 写回「段头 + 本次 1 条」把原规则全丢。
 * 目录保持可写、只把文件本身置 000，使「读失败但写路径可用」——正是丢数据的窗口。
 * 以 root 运行时 chmod 000 不生效，跳过该组（gap）。 */
static int case_read_failure(void) {
    char path[512];
    snprintf(path, sizeof path, WORKDIR "/readfail.conf");
    FILE* f = fopen(path, "w");
    if (!f) {
        printf("FAIL A10 无法创建 %s\n", path);
        return 1;
    }
    fputs("[GLOBAL]\nHIDE /keep1\nHIDE /keep2\nHIDE /keep3\n", f);
    fclose(f);

    if (geteuid() == 0) {
        printf("SKIP A10 以 root 运行，chmod 000 不阻断读取\n");
        return 2; /* gap */
    }
    if (chmod(path, 0000) != 0) {
        printf("FAIL A10 chmod 000 失败\n");
        return 1;
    }
    bool changed = true;
    int rc = nsp_rule_file_upsert_line(path, false, "HIDE", "HIDE /new\n", &changed);
    (void)chmod(path, 0644);

    int count = 0, cap = 0;
    char** lines = nsp_rule_file_read(path, &count, &cap);
    int keep = 0;
    for (int i = 0; lines && i < count; i++) {
        if (strstr(lines[i], "/keep")) keep++;
    }
    if (lines) nsp_rule_file_free(lines, count);

    int ok = (rc != 0 && !changed && keep == 3);
    printf("%s A10 读失败不覆盖原文件：rc=%d changed=%d 原规则保留=%d/3\n",
           ok ? "PASS" : "FAIL", rc, changed, keep);
    return ok ? 0 : 1;
}

/* ============ A6/C6：全部公共编辑入口必须走同一把目录 flock ============
 * 判别方式（确定性，不靠竞态概率）：
 *   另起一个进程持有规则文件**所在目录**的 flock 不放，然后逐个执行
 *     ① 手工「读-改-写」形态（不经库、不取锁）
 *     ② 库的全部公共编辑入口
 *   ① 必须**立即**返回（证明锁是协作式的、绕过路径在原理上存在）；
 *   ② 必须**全部阻塞**，直到锁释放才返回。
 * C6 后库只保留 nsp_rule_file_edit 一条写入路径，任何入口都不可能在锁外完成
 * 读改写；若某个入口退化成不持锁的读改写，本组即失败。
 */

/* 手工「读-改-写」落盘（不经库、不取锁）：C6 后库不再对外暴露 rule_file_write，
 * 调用方若要绕过目录 flock 只能自己重写这一套——本函数即演示该路径**在原理上
 * 可行**（故被要求阻塞的是库入口，而不是「任何代码」）。tmp+rename 与库同形，
 * 避免留下半截文件影响后续断言。 */
static int manual_write_file(const char* path, char** lines, int count) {
    char tmp[600];
    snprintf(tmp, sizeof tmp, "%s.manual.%ld", path, (long)getpid());
    FILE* fp = fopen(tmp, "w");
    if (!fp) return -1;
    for (int i = 0; i < count; i++) {
        if (fputs(lines[i], fp) < 0) {
            fclose(fp);
            unlink(tmp);
            return -1;
        }
    }
    if (fclose(fp) != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

/* 旧形态：读全文 → 把第 0 条 HIDE 加/去 # → 覆盖写。不带任何锁。 */
static int old_shape_toggle(void) {
    int count = 0, cap = 0;
    char** lines = nsp_rule_file_read(g_conf, &count, &cap);
    if (!lines) return -1;
    int found = nsp_rule_file_find_nth(lines, count, "HIDE", 0);
    if (found < 0) {
        nsp_rule_file_free(lines, count);
        return -1;
    }
    char* p = lines[found];
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#') {
        char* q = p + 1;
        while (*q == ' ' || *q == '\t') q++;
        memmove(p, q, strlen(q) + 1);
    } else {
        size_t prefix = (size_t)(p - lines[found]);
        size_t len = strlen(lines[found]);
        char* nl = malloc(len + 2);
        if (!nl) {
            nsp_rule_file_free(lines, count);
            return -1;
        }
        memcpy(nl, lines[found], prefix);
        nl[prefix] = '#';
        strcpy(nl + prefix + 1, p);
        free(lines[found]);
        lines[found] = nl;
    }
    int ok = manual_write_file(g_conf, lines, count);
    nsp_rule_file_free(lines, count);
    return ok;
}

/* 在子进程里跑 fn()，返回「400ms 内是否仍未返回」（true = 被阻塞） */
static bool call_blocks_over_400ms(int (*fn)(void)) {
    int p[2];
    if (pipe(p) != 0) return false;
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        (void)fn();
        ssize_t w = write(p[1], "D", 1);
        (void)w;
        _exit(0);
    }
    close(p[1]);
    struct pollfd pfd = {.fd = p[0], .events = POLLIN};
    int pr = poll(&pfd, 1, 400);
    bool blocked = (pr == 0);
    if (pr > 0) {
        (void)waitpid(pid, NULL, 0);
    } else {
        kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
    }
    close(p[0]);
    return blocked;
}

static int e_old_manual(void) {
    return old_shape_toggle();
}
static int e_upsert_line(void) {
    bool ch = false;
    return nsp_rule_file_upsert_line(g_conf, false, "HIDE", "HIDE /c6-line\n", &ch);
}
static int e_upsert_section(void) {
    bool ch = false;
    return nsp_rule_file_upsert_in_section(g_conf, "GLOBAL", NSP_RULE_SEC_PREFIX, false, "HIDE",
                                           "HIDE /c6-sec\n", &ch);
}
static int e_remove_nth(void) {
    return nsp_rule_file_remove_nth(g_conf, "HIDE", 0, NULL, 0);
}
static int e_remove_nth_scoped(void) {
    NspRuleScope s = {"GLOBAL", NSP_RULE_SEC_PREFIX};
    return nsp_rule_file_remove_nth_scoped(g_conf, &s, "HIDE", 0, NULL, 0);
}
static int e_toggle_nth(void) {
    NspRuleScope s = {"GLOBAL", NSP_RULE_SEC_PREFIX};
    bool ch = false;
    return nsp_rule_file_toggle_nth_scoped(g_conf, &s, "HIDE", 0, false, NULL, 0, &ch);
}

static int case_edit_entries_locked(void) {
    char path[512];
    snprintf(path, sizeof path, WORKDIR "/toggle.conf");
    FILE* f = fopen(path, "w");
    if (!f) {
        printf("FAIL A6/C6 无法创建 %s\n", path);
        return 1;
    }
    /* 5 条 HIDE：释放锁后逐个入口都要能正常完成（remove 不因越界而 ENOTFND） */
    fputs("[GLOBAL]\nHIDE /e0\nHIDE /e1\nHIDE /e2\nHIDE /e3\nHIDE /e4\n", f);
    fclose(f);
    snprintf(g_conf, sizeof g_conf, "%s", path);

    int ready[2], rel[2];
    if (pipe(ready) != 0 || pipe(rel) != 0) {
        printf("FAIL A6/C6 pipe 失败\n");
        return 1;
    }
    pid_t locker = fork();
    if (locker == 0) {
        close(ready[0]);
        close(rel[1]);
        int dfd = open(WORKDIR, O_RDONLY | O_DIRECTORY);
        if (dfd < 0 || flock(dfd, LOCK_EX) != 0) {
            ssize_t w = write(ready[1], "E", 1);
            (void)w;
            _exit(1);
        }
        ssize_t w = write(ready[1], "R", 1);
        (void)w;
        char c;
        ssize_t r = read(rel[0], &c, 1); /* 阻塞直到父进程放行 */
        (void)r;
        flock(dfd, LOCK_UN);
        close(dfd);
        _exit(0);
    }
    close(ready[1]);
    close(rel[0]);
    char c = 0;
    ssize_t rr = read(ready[0], &c, 1);
    close(ready[0]);
    if (rr != 1 || c != 'R') {
        printf("FAIL A6/C6 锁持有者未就绪\n");
        close(rel[1]);
        (void)waitpid(locker, NULL, 0);
        return 1;
    }

    bool old_blocked = call_blocks_over_400ms(e_old_manual);
    struct {
        const char* name;
        int (*fn)(void);
    } entries[] = {
        {"upsert_line", e_upsert_line},
        {"upsert_in_section", e_upsert_section},
        {"remove_nth", e_remove_nth},
        {"remove_nth_scoped", e_remove_nth_scoped},
        {"toggle_nth_scoped", e_toggle_nth},
    };
    int n = (int)(sizeof entries / sizeof entries[0]);
    bool all_blocked = true;
    printf("    入口阻塞矩阵：旧形态(手工读改写)=%d(期望0)", (int)old_blocked);
    for (int i = 0; i < n; i++) {
        bool b = call_blocks_over_400ms(entries[i].fn);
        printf(" %s=%d(期望1)", entries[i].name, (int)b);
        if (!b) all_blocked = false;
    }
    printf("\n");

    /* 放行锁持有者，并确认各入口随后都能正常完成 */
    ssize_t w = write(rel[1], "G", 1);
    (void)w;
    close(rel[1]);
    (void)waitpid(locker, NULL, 0);

    int rc[5];
    rc[0] = e_upsert_line();
    rc[1] = e_upsert_section();
    rc[2] = e_remove_nth();
    rc[3] = e_remove_nth_scoped();
    rc[4] = e_toggle_nth();
    int rc_ok = 0;
    for (int i = 0; i < n; i++)
        if (rc[i] == 0) rc_ok++;

    int ok = (!old_blocked && all_blocked && rc_ok == n);
    printf("%s A6/C6 编辑入口串行化：旧形态未阻塞=%d 全部入口阻塞=%d 释放后成功=%d/%d\n",
           ok ? "PASS" : "FAIL", (int)!old_blocked, (int)all_blocked, rc_ok, n);
    return ok ? 0 : 1;
}

int main(void) {
    snprintf(g_conf, sizeof g_conf, WORKDIR "/injector.conf");
    (void)system("rm -rf " WORKDIR " && mkdir -p " WORKDIR);
    FILE* f = fopen(g_conf, "w");
    if (!f) {
        printf("FAIL 无法创建 %s\nRESULT FAIL\n", g_conf);
        return 1;
    }
    fputs("[GLOBAL]\n", f);
    fclose(f);

    for (int i = 0; i < CHILDREN; i++) {
        if (fork() == 0) child_work(i);
    }
    for (int i = 0; i < CHILDREN; i++) (void)wait(NULL);

    int count = 0, cap = 0;
    char** lines = nsp_rule_file_read(g_conf, &count, &cap);
    int hits = 0, dup = 0;
    for (int i = 0; lines && i < count; i++) {
        if (strncmp(lines[i], "HIDE /w", 7) != 0) continue;
        hits++;
        for (int j = 0; j < i; j++) {
            if (strcmp(lines[j], lines[i]) == 0) {
                dup++;
                break;
            }
        }
    }
    int want = CHILDREN * PER_CHILD;
    printf("%s 并发 upsert：期望 %d 条，实际 %d 条，重复 %d 条\n",
           (hits == want && dup == 0) ? "PASS" : "FAIL", want, hits, dup);
    if (lines) nsp_rule_file_free(lines, count);

    int fail = (hits == want && dup == 0) ? 0 : 1;
    int gap = 0;
    int a10 = case_read_failure();
    if (a10 == 1) fail = 1;
    else if (a10 == 2) gap = 1;
    if (case_edit_entries_locked() != 0) fail = 1;

    printf("%s\n", fail ? "RESULT FAIL" : (gap ? "RESULT GAP" : "RESULT OK"));
    if (fail) return 1;
    return gap ? 78 : 0; /* 78 = 部分子组跳过（gap），与 tests/run.py 约定一致 */
}
