#ifndef NSP_RETRY_QUEUE_H
#define NSP_RETRY_QUEUE_H

#include <stdbool.h>
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
 * 本模块把"尝试次数"随条目保存，只有**成功**才清账：
 *   - 相邻尝试按 1/2/4/8s 递增退避（首次立即）；
 *   - 同一 pid 最多 NSP_RETRY_MAX_ATTEMPTS 次，超限由调用方 loud 一次后放弃
 *     （应用继续用原生视图，不再刷错）。
 * 队列纯记账，不做 I/O、不 fork，可直接被单测驱动。
 */

#define NSP_RETRY_MAX_ENTRIES 64
/* 单进程最多尝试次数（含首次入队那次）。6 次 ≈ 1+2+4+8+8 秒退避后放弃 */
#define NSP_RETRY_MAX_ATTEMPTS 6
#define NSP_RETRY_BACKOFF_CAP_S 8

typedef struct {
    char pkg[256];
    int pid;
    int attempts;      /* 已发起的尝试次数（nsp_retry_next 返回 ATTEMPT 时已累加） */
    time_t last_attempt;
} NspRetryEntry;

/* nsp_retry_next 的返回：无到期条目 / 该尝试一次 / 已耗尽（条目已被摘除） */
enum { NSP_RETRY_NONE = 0, NSP_RETRY_ATTEMPT = 1, NSP_RETRY_GIVEUP = 2 };

/* 相邻两次尝试的最小间隔（秒）：attempts=0 → 0（首次立即），此后 1/2/4/8（封顶） */
int nsp_retry_backoff_seconds(int attempts);

void nsp_retry_reset(void);
/* 入队（已在队列则保留原尝试次数，只刷新包名）。队列满返回 false */
bool nsp_retry_schedule(const char* pkg, int pid);
/* 挂载成功：摘除条目并清账。命中返回 true */
bool nsp_retry_done(int pid);
/* 取一个到期条目：ATTEMPT 时 *out 已填且 attempts 已累加（调用方随即发起挂载，
 * 成功走 nsp_retry_done、失败走 nsp_retry_schedule 重新入队等下一轮退避）；
 * GIVEUP 时条目已摘除，*out 保留最后一次计数供调用方打一条 loud 日志 */
int nsp_retry_next(NspRetryEntry* out, time_t now);
int nsp_retry_count(void);
/* 只读查询：该 pid 已记录的尝试次数（0 = 不在队列） */
int nsp_retry_attempts_of(int pid);

#endif /* NSP_RETRY_QUEUE_H */
