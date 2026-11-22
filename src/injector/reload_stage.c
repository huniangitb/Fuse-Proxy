/* 配置视图的读取阶段：把「真读盘 + pm 用户探测」挪出事件循环线程。
 *
 * 动机与语义见 include/reload_stage.h。实现要点：
 *   - 一个常驻 worker（start 起、shutdown join）：等待「有待读请求」，读到结果后
 *     放进槽里并写就绪 eventfd 叫醒事件循环来取；
 *   - 槽只留最新一份：发布新结果时释放没被取走的旧视图（读取窗口内连续重载时
 *     这是唯一会让旧视图泄漏的地方，必须显式释放）；
 *   - 请求合并：worker 正在读时新到的请求只置 g_rs_want，读完立刻再跑一轮；
 *   - 不取消：shutdown 置 stop 后 join，等手上那一轮读完（最长一次 pm 预算），
 *     读回来的结果直接丢弃——不安全取消会让 allocator/日志锁处于未知状态。
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "reload_stage.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "nsp_log.h"

static pthread_mutex_t g_rs_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_rs_cv = PTHREAD_COND_INITIALIZER; /* 只等 signal，不用超时 */
static pthread_t g_rs_thread;
static bool g_rs_live;   /* worker 线程存在（start 成功到 join 之间） */
static bool g_rs_stop;   /* 收到退出请求 */
static bool g_rs_want;   /* 有未处理的读取请求 */
static bool g_rs_have;   /* 槽里有一份备好未取走的视图（count 可能为 0） */
static int g_rs_fd = -1; /* 就绪 eventfd */
static char g_rs_path[PATH_MAX];
static NspCfgRec* g_rs_recs;
static int g_rs_count;

/* 叫醒事件循环（无锁调用：g_rs_fd 只在 start/shutdown 内外切换，且那时没有并发
   请求）。eventfd 计数溢出只可能发生在循环已经停止的场景，忽略 EAGAIN。 */
static void rs_wake(void) {
    if (g_rs_fd < 0) return;
    const uint64_t one = 1;
    ssize_t n = write(g_rs_fd, &one, sizeof one);
    (void)n;
}

/* 释放槽内视图。调用方持 g_rs_mu（只有 free，没有 IO，临界区很短）。 */
static void rs_drop_locked(void) {
    NspCfgRec* recs = g_rs_recs;
    const int count = g_rs_count;
    g_rs_recs = nullptr;
    g_rs_count = 0;
    g_rs_have = false;
    if (recs) config_free_view(recs, count);
}

static void* rs_worker(void* arg) {
    (void)arg;
    pthread_mutex_lock(&g_rs_mu);
    for (;;) {
        while (!g_rs_stop && !g_rs_want) pthread_cond_wait(&g_rs_cv, &g_rs_mu);
        if (g_rs_stop) break;
        g_rs_want = false;
        char path[PATH_MAX];
        snprintf(path, sizeof path, "%s", g_rs_path);
        /* 读盘与 pm 探测都在锁外、在本线程上：主循环随时能继续跑 */
        pthread_mutex_unlock(&g_rs_mu);
        NspCfgRec* recs = nullptr;
        int count = 0;
        (void)config_read_view(path, &recs, &count);
        pthread_mutex_lock(&g_rs_mu);
        if (g_rs_stop) { /* 退出优先：本轮结果丢弃，不发布也不留槽 */
            if (recs) config_free_view(recs, count);
            break;
        }
        rs_drop_locked(); /* 未取走的旧视图作废：槽里只留最新一份 */
        g_rs_recs = recs;
        g_rs_count = count;
        g_rs_have = true;
        rs_wake();
    }
    pthread_mutex_unlock(&g_rs_mu);
    return nullptr;
}

int nsp_reload_stage_start(const char* config_path) {
    if (g_rs_fd >= 0) return g_rs_fd; /* 幂等 */
    if (!config_path || !config_path[0]) return -1;
    const int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0) return -1;
    pthread_mutex_lock(&g_rs_mu);
    snprintf(g_rs_path, sizeof g_rs_path, "%s", config_path);
    g_rs_want = false;
    g_rs_stop = false;
    pthread_mutex_unlock(&g_rs_mu);
    if (pthread_create(&g_rs_thread, nullptr, rs_worker, nullptr) != 0) {
        close(fd);
        return -1;
    }
    g_rs_fd = fd;
    pthread_mutex_lock(&g_rs_mu);
    g_rs_live = true;
    pthread_mutex_unlock(&g_rs_mu);
    LOG("配置视图读取线程已启动：读盘与 pm 探测不再占事件循环");
    return fd;
}

void nsp_reload_stage_request(void) {
    if (g_rs_fd < 0) return;
    pthread_mutex_lock(&g_rs_mu);
    g_rs_want = true;
    pthread_cond_signal(&g_rs_cv);
    pthread_mutex_unlock(&g_rs_mu);
}

bool nsp_reload_stage_take(NspCfgRec** recs, int* count) {
    if (recs) *recs = nullptr;
    if (count) *count = 0;
    if (g_rs_fd < 0) return false;
    pthread_mutex_lock(&g_rs_mu);
    const bool have = g_rs_have;
    NspCfgRec* got_recs = g_rs_recs;
    const int got_count = g_rs_count;
    g_rs_recs = nullptr;
    g_rs_count = 0;
    g_rs_have = false;
    pthread_mutex_unlock(&g_rs_mu);
    if (!have) return false;
    if (recs) *recs = got_recs;
    if (count) *count = got_count;
    if (!recs && got_recs) config_free_view(got_recs, got_count);
    return true;
}

void nsp_reload_stage_shutdown(void) {
    if (g_rs_fd < 0) return;
    pthread_mutex_lock(&g_rs_mu);
    const bool live = g_rs_live;
    g_rs_live = false;
    g_rs_stop = true;
    g_rs_want = false;
    pthread_cond_broadcast(&g_rs_cv);
    pthread_mutex_unlock(&g_rs_mu);
    /* 等手上那一轮读完：读盘/ pm 都有预算上界，这里绝不无限等 */
    if (live) pthread_join(g_rs_thread, nullptr);
    pthread_mutex_lock(&g_rs_mu);
    g_rs_stop = false; /* 允许之后再 start（幂等收尾） */
    rs_drop_locked();
    pthread_mutex_unlock(&g_rs_mu);
    close(g_rs_fd);
    g_rs_fd = -1;
}
