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
    printf((hits == want && dup == 0) ? "RESULT OK\n" : "RESULT FAIL\n");
    return (hits == want && dup == 0) ? 0 : 1;
}
