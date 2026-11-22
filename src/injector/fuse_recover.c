/* FUSE 崩溃恢复的阶段化：把「重启序列」挪出事件循环线程。
 *
 * 动机与语义见 include/fuse_recover.h。实现要点：
 *   - 请求按需求起一个 detached worker（跑完一轮、没有新请求就退出，不常驻）；
 *   - 一轮结束写就绪 eventfd，事件循环据此补上只有循环线程才写的记账；
 *   - 请求合并：worker 正在跑时新到的请求只置 g_fr_pending，跑完立刻再跑一轮；
 *   - 起线程失败：清掉待跑标记并返回 false，让调用方内联执行（恢复不能丢）；
 *   - 不取消：shutdown 置 stop 后等 running 归零，等手上那一轮跑完。
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fuse_recover.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <unistd.h>

static pthread_mutex_t g_fr_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_fr_cv = PTHREAD_COND_INITIALIZER; /* 只等 signal，不用超时 */
static NspFuseRecoverFn g_fr_fn;
static void* g_fr_ctx;
static bool g_fr_pending;  /* 有未跑的请求（含 worker 正在跑时新到的） */
static bool g_fr_running;  /* 已有 worker 线程 */
static bool g_fr_stopping; /* 收到关停请求 */
static int g_fr_fd = -1;   /* 就绪 eventfd */
/* 完成标志：worker 每跑完一轮置位，take() 取走。与 eventfd 分工——eventfd 只负责
   叫醒 epoll，标志负责「确实跑完过一轮」这个事实（读 fd 与置标志是两次操作，
   中间可能被合并，标志不会丢）。 */
static _Atomic int g_fr_done;

static void fuse_recover_notify(void) {
    if (g_fr_fd < 0) return;
    const uint64_t one = 1;
    /* EAGAIN = 计数器已饱和，说明还没被取走，等价于「已经叫醒过」 */
    (void)write(g_fr_fd, &one, sizeof one);
}

static void* fuse_recover_worker(void* arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_fr_mu);
        if (!g_fr_pending) {
            g_fr_running = false;
            pthread_cond_broadcast(&g_fr_cv);
            pthread_mutex_unlock(&g_fr_mu);
            return NULL;
        }
        NspFuseRecoverFn fn = g_fr_fn;
        void* ctx = g_fr_ctx;
        g_fr_pending = false;
        pthread_mutex_unlock(&g_fr_mu);
        if (fn) fn(ctx); /* 慢活：整段重启序列在这里跑，期间事件循环照常服务 */
        atomic_store_explicit(&g_fr_done, 1, memory_order_release);
        fuse_recover_notify();
    }
}

int nsp_fuse_recover_start(NspFuseRecoverFn fn, void* ctx) {
    pthread_mutex_lock(&g_fr_mu);
    g_fr_fn = fn;
    g_fr_ctx = ctx;
    g_fr_stopping = false;
    if (g_fr_fd < 0) g_fr_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    const int fd = g_fr_fd;
    pthread_mutex_unlock(&g_fr_mu);
    return fd;
}

bool nsp_fuse_recover_request(void) {
    bool spawn = false;
    pthread_mutex_lock(&g_fr_mu);
    if (!g_fr_fn || g_fr_stopping || g_fr_fd < 0) {
        pthread_mutex_unlock(&g_fr_mu);
        return false;
    }
    g_fr_pending = true;
    if (!g_fr_running) {
        g_fr_running = true;
        spawn = true;
    }
    pthread_mutex_unlock(&g_fr_mu);
    if (!spawn) return true; /* 已有 worker：请求并入它的下一轮 */
    pthread_attr_t attr;
    pthread_t tid;
    bool ok = false;
    if (pthread_attr_init(&attr) == 0) {
        (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        ok = pthread_create(&tid, &attr, fuse_recover_worker, NULL) == 0;
        pthread_attr_destroy(&attr);
    }
    if (ok) return true;
    /* 起不来：清掉待跑标记并放回 running，由调用方内联执行这一轮——恢复不能丢。
       broadcast 不可省：此刻可能已有人在 shutdown 里等 running 归零。 */
    pthread_mutex_lock(&g_fr_mu);
    g_fr_running = false;
    g_fr_pending = false;
    pthread_cond_broadcast(&g_fr_cv);
    pthread_mutex_unlock(&g_fr_mu);
    return false;
}

bool nsp_fuse_recover_take(void) {
    return atomic_exchange_explicit(&g_fr_done, 0, memory_order_acq_rel) != 0;
}

void nsp_fuse_recover_shutdown(void) {
    pthread_mutex_lock(&g_fr_mu);
    g_fr_stopping = true;
    g_fr_pending = false; /* 未开始的排空，正在跑的那一轮等它结束 */
    pthread_cond_broadcast(&g_fr_cv);
    while (g_fr_running) {
        if (pthread_cond_wait(&g_fr_cv, &g_fr_mu) != 0) break;
    }
    const int fd = g_fr_fd;
    g_fr_fd = -1;
    g_fr_fn = NULL;
    g_fr_ctx = NULL;
    pthread_mutex_unlock(&g_fr_mu);
    if (fd >= 0) close(fd);
    atomic_store_explicit(&g_fr_done, 0, memory_order_release);
}
