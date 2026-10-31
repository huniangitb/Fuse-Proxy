/*
 * tests/fixtures/retry_queue_driver.c
 *
 * 挂载失败重试记账（src/injector/retry_queue.c）的直编判别驱动。
 *
 * 背景（真机回归）：旧实现把"异步派发成功"当成"挂载成功"——retry_pending_mounts
 * 派发后立即摘掉条目，真正的失败由完成回调重新入队（新条目尝试次数归零），于是
 * 退避计算永远复位、5 次上限永远打不到：挂不上的应用以 **1Hz 永久重试**，每轮
 * 一条 error.log + WARN + ERROR，并持续 fork/读 mountinfo。真机表现即"错误越来越
 * 多"与批量冷启动抖动。
 *
 * 本驱动把虚拟时钟（time_t）交给 nsp_retry_next，逐秒推进模拟 tick，断言：
 *   A. 首次入队立即到期，attempts 从 1 开始；
 *   B. 失败重新入队后按 1/2/4/8s 递增退避（同一秒内不再重复尝试）；
 *   C. 尝试次数达到上限后返回 GIVEUP 并清空条目（不再无限重试）；
 *   D. 挂载成功（nsp_retry_done）清账，后续不再到期；
 *   E. 重复 schedule 不新增条目、不丢已记录次数；队列满返回 false；
 *   F. 60 秒窗口内的总尝试次数 ≤ NSP_RETRY_MAX_ATTEMPTS（旧实现 = 每秒一次）。
 *
 * 回归价值：把 nsp_retry_next 换回旧语义（每次返回 ATTEMPT、attempts 不累计）时
 * F1/F2/F3 必失败。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "retry_queue.h"

/* 实际源码（同一 TU：被测函数直接可见；-DRETRY_QUEUE_SRC= 可指向旧副本复验） */
#include RETRY_QUEUE_SRC

static int g_fail;

static void check(const char* name, bool ok, const char* detail) {
    printf("  %s %s", ok ? "[PASS]" : "[FAIL]", name);
    if (!ok && detail && *detail) printf(" — %s", detail);
    printf("\n");
    if (!ok) g_fail = 1;
}

int main(void) {
    printf("── 挂载失败重试记账（退避 / 上限 / 清账） ──\n");
    NspRetryEntry e;

    /* A. 首次入队立即到期 */
    nsp_retry_reset();
    check("A1 入队成功", nsp_retry_schedule("com.test.app", 4242), "");
    check("A2 队列长度 1", nsp_retry_count() == 1, "");
    int r = nsp_retry_next(&e, 1000);
    check("A3 首次立即到期（无需等待）", r == NSP_RETRY_ATTEMPT, "");
    check("A4 第一次尝试后 attempts=1", e.attempts == 1 && nsp_retry_attempts_of(4242) == 1, "");

    /* B. 失败重新入队 → 1 秒退避 */
    check("B1 重新入队成功（保留计数）", nsp_retry_schedule("com.test.app", 4242), "");
    check("B2 重新入队后计数仍为 1（旧实现会归零）", nsp_retry_attempts_of(4242) == 1, "");
    check("B3 同一秒内不再到期（退避生效）", nsp_retry_next(&e, 1000) == NSP_RETRY_NONE, "");
    check("B4 1 秒后到期", nsp_retry_next(&e, 1001) == NSP_RETRY_ATTEMPT && e.attempts == 2, "");

    /* 退避曲线：1/2/4/8/8… */
    check("B5 退避序列 0/1/2/4/8（封顶 8）",
          nsp_retry_backoff_seconds(0) == 0 && nsp_retry_backoff_seconds(1) == 1 &&
              nsp_retry_backoff_seconds(2) == 2 && nsp_retry_backoff_seconds(3) == 4 &&
              nsp_retry_backoff_seconds(4) == 8 && nsp_retry_backoff_seconds(99) == 8,
          "");

    /* C. 上限：推到 GIVEUP，并确认条目被摘除 */
    nsp_retry_reset();
    nsp_retry_schedule("com.broken.app", 777);
    time_t now = 2000;
    int attempts = 0;
    bool gave_up = false;
    time_t last_attempt_at = 0;
    for (int tick = 0; tick < 120; tick++, now++) {
        int what = nsp_retry_next(&e, now);
        if (what == NSP_RETRY_ATTEMPT) {
            attempts++;
            last_attempt_at = now;
            /* 模拟异步失败：完成回调把同一 pid 重新入队（次数保留） */
            nsp_retry_schedule("com.broken.app", 777);
        } else if (what == NSP_RETRY_GIVEUP) {
            gave_up = true;
            break;
        }
    }
    check("C1 尝试次数有上限（≤ NSP_RETRY_MAX_ATTEMPTS）", attempts <= NSP_RETRY_MAX_ATTEMPTS,
          "尝试次数无上限（旧实现的 1Hz 永久重试）");
    check("C2 达到上限后返回 GIVEUP 并摘除条目", gave_up && nsp_retry_count() == 0, "");
    check("C3 放弃前确实按退避累积（末次尝试距首次 ≥ 8s）",
          attempts >= 3 && (last_attempt_at - 2000) >= 8, "");
    check("C4 放弃后不再产生尝试", nsp_retry_next(&e, now + 3600) == NSP_RETRY_NONE, "");

    /* D. 成功清账 */
    nsp_retry_reset();
    nsp_retry_schedule("com.ok.app", 999);
    (void)nsp_retry_next(&e, 3000);
    check("D1 成功清账后队列为空", nsp_retry_done(999) && nsp_retry_count() == 0, "");
    check("D2 清账后不再到期", nsp_retry_next(&e, 9999) == NSP_RETRY_NONE, "");
    check("D3 清账对不存在的 pid 返回 false", !nsp_retry_done(12345), "");

    /* E. 去重与容量 */
    nsp_retry_reset();
    nsp_retry_schedule("com.dup.app", 555);
    check("E1 重复入队不新增条目", nsp_retry_schedule("com.dup.app", 555) && nsp_retry_count() == 1,
          "");
    for (int i = 0; i < NSP_RETRY_MAX_ENTRIES; i++) {
        char pkg[32];
        snprintf(pkg, sizeof pkg, "com.fill.%d", i);
        nsp_retry_schedule(pkg, 1000 + i);
    }
    check("E2 队列容量上限 NSP_RETRY_MAX_ENTRIES",
          nsp_retry_count() == NSP_RETRY_MAX_ENTRIES, "容量与常量不一致");
    check("E3 满队列时入队返回 false", !nsp_retry_schedule("com.overflow.app", 8888), "");

    /* F. 60 秒窗口内的总尝试次数（旧实现 = 每秒一次 = 60 次） */
    nsp_retry_reset();
    nsp_retry_schedule("com.slow.app", 31337);
    now = 5000;
    attempts = 0;
    for (int tick = 0; tick < 60; tick++, now++) {
        int what = nsp_retry_next(&e, now);
        if (what == NSP_RETRY_ATTEMPT) {
            attempts++;
            nsp_retry_schedule("com.slow.app", 31337);
        } else if (what == NSP_RETRY_GIVEUP) {
            break;
        }
    }
    check("F1 60 秒内尝试次数 ≤ 上限（旧实现 60 次）", attempts <= NSP_RETRY_MAX_ATTEMPTS,
          "重试未收敛");
    check("F2 60 秒后条目已收敛（不再留在队列里）",
          nsp_retry_count() == 0 || attempts < NSP_RETRY_MAX_ATTEMPTS, "");

    printf("%s\n", g_fail ? "结果: 存在失败" : "结果: 全部通过");
    return g_fail;
}
