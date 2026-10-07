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
 * 输出：一行汇总 + RESULT OK/FAIL；失败退出码 1。 */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

    printf("%s\n", fail ? "RESULT FAIL" : (gap ? "RESULT GAP" : "RESULT OK"));
    if (fail) return 1;
    return gap ? 78 : 0; /* 78 = 部分子组跳过（gap），与 tests/run.py 约定一致 */
}
