/* audit_worker 的起线程失败路径：必须“保留待跑集合 + 唤醒等在 shutdown 上的人”。
 *
 * 该路径只在资源耗尽（pthread_create 返回 EAGAIN）时走到，生产里靠运气撞不上，
 * 所以用 --wrap=pthread_create 精确注入：
 *   retry          —— 第一次创建失败后，下一次请求必须能把这一轮补跑掉；
 *   shutdown_race  —— 创建正在慢慢失败时有人调 shutdown，必须能返回（旧实现在这里
 *                     只清 running 不 broadcast，等的人永久挂住）。
 *
 * 用法：cc ... tests/fixtures/audit_spawn_fail_driver.c src/injector/audit_worker.c \
 *          -Wl,--wrap=pthread_create -o out -pthread && ./out retry|shutdown_race
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "audit_worker.h"
#include "inject_target.h"
#include "injector.h"

InjectMethod g_inject_method = INJECT_METHOD_V2;

static _Atomic int g_tracked_runs;
static _Atomic int g_create_calls;
static int g_fail_index = -1;   /* 第几次 pthread_create 返回失败 */
static int g_fail_delay_ms;     /* 失败之前先睡多久（模拟创建很慢） */

/* 审计本体：只需要证明“跑了”，不碰真实挂载 */
void audit_tracked_apps(void) {
    atomic_fetch_add(&g_tracked_runs, 1);
    usleep(50 * 1000);
}

#define SEEN_MAX 16
static _Atomic int g_specific_runs;
static char g_seen[SEEN_MAX][160];
static int g_seen_n;

void audit_and_remount_specific_apps(ChangedPkg* changed, int count) {
    const int n = count > SEEN_MAX ? SEEN_MAX : count;
    for (int i = 0; i < n && g_seen_n < SEEN_MAX; i++) {
        snprintf(g_seen[g_seen_n], sizeof g_seen[g_seen_n], "%s:%d", changed[i].pkg_name,
                 changed[i].user_id);
        g_seen_n++;
    }
    atomic_fetch_add(&g_specific_runs, 1);
}

void audit_running_apps(void) {}

/* g_inject_method = V2 已让 inject_is_global_replace/restore_nontarget（injector.h 的
   内联判定）为真：审计走 v2 分支，reset 时调 audit_tracked_apps 全量扫描。 */

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static int tasks(void) {
    DIR* d = opendir("/proc/self/task");
    if (!d) return -1;
    int n = 0;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_name[0] != '.') n++;
    }
    closedir(d);
    return n;
}

/* 线程退出后 /proc/self/task 的条目摘除晚于完成通知/关停返回：观测改成有界收敛
   （最多 300ms），断言仍要求等于 1。 */
static int tasks_settled(void) {
    for (int i = 0; i < 300; i++) {
        const int n = tasks();
        if (n == 1) return n;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000000L};
        nanosleep(&ts, NULL);
    }
    return tasks();
}

int __real_pthread_create(pthread_t* tid, const pthread_attr_t* attr,
                         void* (*fn)(void*), void* arg);

int __wrap_pthread_create(pthread_t* tid, const pthread_attr_t* attr,
                         void* (*fn)(void*), void* arg) {
    const int n = atomic_fetch_add(&g_create_calls, 1) + 1;
    if (n == g_fail_index) {
        if (g_fail_delay_ms > 0) usleep((useconds_t)g_fail_delay_ms * 1000);
        errno = EAGAIN;
        return EAGAIN;
    }
    return __real_pthread_create(tid, attr, fn, arg);
}

static int fail(const char* why) {
    printf("FAIL %s\n", why);
    return 1;
}

/* 创建失败之后：保留的那一轮必须补跑，且与它合并的具体条目一条都不能丢。
 * 失败时排队的是「整体变化」，恢复后的请求带 3 条具体条目（与失败那一轮不同）：
 *   * 丢掉保留集合（旧失败路径的写法）→ 整体变化整轮不见、tracked_runs=0；
 *   * 两路互斥（老 audit_run_job）→ reset 命中即 return，3 条条目全被吞。 */
static int run_retry(void) {
    g_fail_index = 1;
    g_fail_delay_ms = 0;
    const long long t0 = now_us();
    nsp_audit_request(NULL, 0, true);
    const long long call_us = now_us() - t0;
    if (call_us > 50000) return fail("起线程失败时调用线程被拖住");
    if (atomic_load(&g_tracked_runs) != 0) return fail("创建失败却报告跑过对账");
    if (atomic_load(&g_create_calls) != 1) return fail("没有走到注入的创建失败");
    ChangedPkg b[3];
    memset(b, 0, sizeof b);
    snprintf(b[0].pkg_name, sizeof b[0].pkg_name, "com.retry.a");
    b[0].user_id = 0;
    snprintf(b[1].pkg_name, sizeof b[1].pkg_name, "com.retry.b");
    b[1].user_id = 10;
    snprintf(b[2].pkg_name, sizeof b[2].pkg_name, "com.retry.c");
    b[2].user_id = 0;
    nsp_audit_request(b, 3, false);
    const long long deadline = now_us() + 3000000;
    while ((atomic_load(&g_tracked_runs) < 1 || atomic_load(&g_specific_runs) < 1) &&
           now_us() < deadline)
        usleep(1000);
    if (atomic_load(&g_tracked_runs) < 1) return fail("失败那一轮的整体变化没补跑（保留集合丢失）");
    if (atomic_load(&g_specific_runs) < 1) return fail("合并进同一轮的具体变更没送达（两路互斥）");
    if (g_seen_n != 3) return fail("具体变更条数不符（被 reset 吞掉）");
    const long long s0 = now_us();
    nsp_audit_shutdown();
    const long long shutdown_us = now_us() - s0;
    if (shutdown_us > 3000000) return fail("shutdown 等太久");
    if (tasks_settled() != 1) return fail("shutdown 后仍有 worker 线程");
    printf("mode=retry create_calls=%d tracked_runs=%d specific_runs=%d seen=%d call_us=%lld "
           "shutdown_us=%lld ok=1\n",
           atomic_load(&g_create_calls), atomic_load(&g_tracked_runs),
           atomic_load(&g_specific_runs), g_seen_n, call_us, shutdown_us);
    return 0;
}

static void* request_thread(void* arg) {
    (void)arg;
    nsp_audit_request(NULL, 0, true);
    return NULL;
}

/* 创建正在失败时有人调 shutdown：必须返回（旧实现只清 running 不唤醒 → 永久挂住）。 */
static int run_shutdown_race(void) {
    g_fail_index = 2; /* 第 1 次是下面的请求线程 */
    g_fail_delay_ms = 300;
    pthread_t helper;
    if (pthread_create(&helper, NULL, request_thread, NULL) != 0) return fail("起请求线程失败");
    usleep(50 * 1000); /* 让请求线程先置 running 并停在慢创建里 */
    const long long t0 = now_us();
    nsp_audit_shutdown();
    const long long shutdown_us = now_us() - t0;
    pthread_join(helper, NULL);
    if (shutdown_us > 2000000) return fail("shutdown 被失败路径永久挂住");
    if (tasks_settled() != 1) return fail("shutdown 后仍有线程");
    printf("mode=shutdown_race create_calls=%d shutdown_us=%lld ok=1\n",
           atomic_load(&g_create_calls), shutdown_us);
    return 0;
}

int main(int argc, char** argv) {
    alarm(10); /* 看门狗：旧实现在 shutdown_race 上永久挂住，靠它把进程打掉 */
    if (argc != 2) return fail("用法: audit_spawn_fail_driver retry|shutdown_race");
    if (strcmp(argv[1], "retry") == 0) return run_retry();
    if (strcmp(argv[1], "shutdown_race") == 0) return run_shutdown_race();
    return fail("未知模式");
}
