#ifndef NSP_RETRY_QUEUE_H
#define NSP_RETRY_QUEUE_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/*
 * 挂载失败重试队列（injector 内部记账）
 *
 * 旧实现把"派发"当成"成功"：retry_pending_mounts 调异步 perform_app_mount，
 * fork 成功即返回 0，条目当场摘掉；真正的失败要等子进程结束，由
 * handle_async_mount_event 重新 schedule_retry_mount 入队——新条目重试计数为 0，
 * 退避计算（只在 retries>1 时生效）永远复位，于是**每个 1s tick 立刻再试**：
 * 挂不上的应用会以 1Hz 永久反复，每轮至少一条 error.log + 一次 fork/mountinfo
 * 解析。真机表现就是"错误刷屏"与批量冷启动时的 IPC 抖动。
 *
 * 本模块把"尝试次数"随条目保存，只有**成功**才清账。
 *
 * 退避分三档（全部按**毫秒**记账，旧实现是秒——秒粒度装不下"视图 140ms 后才
 * 出现"这个主流场景，首个退避 1s 等于白等）：
 *   快档 20ms × 10  → 覆盖 0~200ms：vold 把 /storage/emulated 装配进应用 ns 的
 *                     实测窗口（真机 322 次挂载 avg=142ms），视图一出现就补挂；
 *   中档 100ms × 5  → 覆盖 0.2~0.7s：慢设备 / 首屏批量冷启动；
 *   指数 1/2/4/8s   → 覆盖到 ~16s：FUSE 崩溃重建、vold 重挂等长尾。
 * 同一 pid 最多 NSP_RETRY_MAX_ATTEMPTS（20）次，超限由调用方 loud 一次后放弃
 * （应用继续用原生视图，不再刷错）。
 * 队列纯记账，不做 I/O、不 fork，可直接被单测驱动（虚拟毫秒时钟）。
 */

#define NSP_RETRY_MAX_ENTRIES 64
/* 单进程最多尝试次数（含首次入队那次）：10×20ms + 5×100ms + 1/2/4/8s×… ≈ 16s */
#define NSP_RETRY_MAX_ATTEMPTS 20
/* 快档：每次 20ms，共 10 次（首轮入队仍立即尝试，不计入这 10 次） */
#define NSP_RETRY_FAST_MS    20
#define NSP_RETRY_FAST_STEPS 10
/* 中档：每次 100ms，共 5 次 */
#define NSP_RETRY_MID_MS    100
#define NSP_RETRY_MID_STEPS 5
/* 指数档封顶（ms） */
#define NSP_RETRY_BACKOFF_CAP_MS 8000

typedef struct {
    char pkg[256];
    int pid;
    int attempts;          /* 已发起的尝试次数（nsp_retry_next 返回 ATTEMPT 时已累加） */
    int64_t last_attempt_ms; /* 上次尝试的单调毫秒时刻（0 = 从未尝试 → 立即到期） */
} NspRetryEntry;

/* nsp_retry_next 的返回：无到期条目 / 该尝试一次 / 已耗尽（条目已被摘除） */
enum { NSP_RETRY_NONE = 0, NSP_RETRY_ATTEMPT = 1, NSP_RETRY_GIVEUP = 2 };

/* 单调毫秒时钟：队列记账与主循环定时器共用同一口径（唯一出处，禁止各处自拼） */
int64_t nsp_retry_now_ms(void);

/* 相邻两次尝试的最小间隔（ms）：attempts=0 → 0（首次立即），此后
 * 快档 20ms×10 → 中档 100ms×5 → 指数 1/2/4/8s（封顶） */
int nsp_retry_backoff_ms(int attempts);

void nsp_retry_reset(void);
/* 入队（已在队列则保留原尝试次数，只刷新包名）。队列满返回 false */
bool nsp_retry_schedule(const char* pkg, int pid);
/* 挂载成功：摘除条目并清账。命中返回 true */
bool nsp_retry_done(int pid);
/* 取一个到期条目：ATTEMPT 时 *out 已填且 attempts 已累加（调用方随即发起挂载，
 * 成功走 nsp_retry_done、失败走 nsp_retry_schedule 重新入队等下一轮退避）；
 * GIVEUP 时条目已摘除，*out 保留最后一次计数供调用方打一条 loud 日志 */
int nsp_retry_next(NspRetryEntry* out, int64_t now_ms);
/* 距最近一条到期还需多少毫秒（0 = 现在就有到期条目；<0 = 队列空）。
 * 主循环据此把一次性定时器臂到"下一个该重试的时刻"——快档 20ms 靠 1s 的
 * 周期 tick 是等不来的。 */
int64_t nsp_retry_next_due_ms(int64_t now_ms);
int nsp_retry_count(void);
/* 只读查询：该 pid 已记录的尝试次数（0 = 不在队列） */
int nsp_retry_attempts_of(int pid);

#endif /* NSP_RETRY_QUEUE_H */
