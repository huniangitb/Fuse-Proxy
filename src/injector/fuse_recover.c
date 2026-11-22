/* FUSE 维护 worker：把「重启序列 / 启动扫描 / 重挂」挪出事件循环线程。
 *
 * 动机与语义见 include/fuse_recover.h。实现要点：
 *   - 请求按需求起一个 detached worker（跑完一轮、没有新请求就退出，不常驻）；
 *   - 任务位合并：worker 正在跑时新到的请求按位 OR 进 g_fr_pending，跑完立刻再跑一轮；
 *     用赋值会覆盖掉先到的任务（一次崩溃恢复就此丢失），故必须 OR；
 *   - 一轮结束把这一轮的任务位 OR 进完成位并写 eventfd，事件循环据此记账；
 *   - 起线程失败：清掉待跑标记并返回 false，让调用方内联执行（任务不能丢）；
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
static unsigned g_fr_pending; /* 未跑的任务位（含 worker 正在跑时新到的） */
static bool g_fr_running;     /* 已有 worker 线程 */
static bool g_fr_stopping;    /* 收到关停请求 */
static int g_fr_fd = -1;      /* 就绪 eventfd */
/* 完成位：worker 每跑完一轮把该轮任务位 OR 进来，take() 取走。与 eventfd 分工——
   eventfd 只负责叫醒 epoll，位图负责「哪些任务确实跑完过」这个事实（读 fd 与取位是
   两次操作，中间可能被合并，位图不会丢）。 */
static _Atomic unsigned g_fr_done;

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
        const unsigned jobs = g_fr_pending;
        g_fr_pending = 0;
        pthread_mutex_unlock(&g_fr_mu);
        if (fn) fn(jobs, ctx); /* 慢活：整段序列在这里跑，期间事件循环照常服务 */
        atomic_fetch_or_explicit(&g_fr_done, jobs, memory_order_release);
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

static bool fuse_recover_spawn(void) {
    pthread_attr_t attr;
    pthread_t tid;
    bool ok = false;
    if (pthread_attr_init(&attr) != 0) return false;
    (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ok = pthread_create(&tid, &attr, fuse_recover_worker, NULL) == 0;
    pthread_attr_destroy(&attr);
    return ok;
}

bool nsp_fuse_recover_request(unsigned jobs) {
    jobs &= NSP_FUSE_JOB_ALL;
    if (jobs == 0) return false;
    pthread_mutex_lock(&g_fr_mu);
    if (!g_fr_fn || g_fr_stopping || g_fr_fd < 0) {
        pthread_mutex_unlock(&g_fr_mu);
        return false;
    }
    g_fr_pending |= jobs; /* 按位合并：赋值会丢掉先到的任务 */
    if (g_fr_running) {
        pthread_mutex_unlock(&g_fr_mu);
        return true; /* 已有 worker：请求并入它的下一轮 */
    }
    g_fr_running = true;
    pthread_mutex_unlock(&g_fr_mu);
    if (fuse_recover_spawn()) return true;
    /* 起不来：只撤回自己这几位，别人的并入必须保留（别人已经拿到 true，不会再内联）。
       旧实现把 g_fr_pending 整个清 0，会把它们的任务位一起抹掉、谁都不会再跑。 */
    pthread_mutex_lock(&g_fr_mu);
    g_fr_running = false;
    g_fr_pending &= ~jobs;
    pthread_mutex_unlock(&g_fr_mu);
    /* 还有别人的任务位：就地再试几次建线程，别让它等到下一次请求。自己这几位已撤下，
       无论这里成不成，调用方都要内联跑它们，所以照旧返回 false。 */
    for (int attempt = 0; attempt < 3; attempt++) {
        pthread_mutex_lock(&g_fr_mu);
        const bool more = g_fr_pending != 0 && !g_fr_running && g_fr_fn && !g_fr_stopping;
        if (more) g_fr_running = true;
        pthread_mutex_unlock(&g_fr_mu);
        if (!more) break;
        if (fuse_recover_spawn()) break;
        pthread_mutex_lock(&g_fr_mu);
        g_fr_running = false;
        pthread_mutex_unlock(&g_fr_mu);
    }
    /* 三次都没起来：任务位留在 pending，下一次请求再拉起；running 已归零，shutdown 不挂。 */
    pthread_mutex_lock(&g_fr_mu);
    pthread_cond_broadcast(&g_fr_cv);
    pthread_mutex_unlock(&g_fr_mu);
    return false;
}

unsigned nsp_fuse_recover_take(void) {
    return atomic_exchange_explicit(&g_fr_done, 0, memory_order_acq_rel);
}

void nsp_fuse_recover_shutdown(void) {
    pthread_mutex_lock(&g_fr_mu);
    g_fr_stopping = true;
    g_fr_pending = 0; /* 未开始的排空，正在跑的那一轮等它结束 */
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
