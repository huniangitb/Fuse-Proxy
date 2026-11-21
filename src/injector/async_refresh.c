/* 异步刷新：把一次可能长达数秒的外部查询（如 pm 扫描）挪出调用线程。
 *
 * 动机：注入器只有一条事件循环线程，配置重载路径里内联 sys_pkg_refresh() 会 fork
 * `pm list packages -s`（预算 3s）。这段时间里所有 pre-hook 判定、挂载派发都被冻住：
 * 一次慢查询放大成整进程无响应，且配置目录被反复写（工具/用户）时会一轮接一轮。
 *
 * 语义（刻意保守）：
 *   - 请求绝不阻塞调用线程，也不在调用线程上执行回调；
 *   - 至多一个 worker：重复请求合并成「再来一轮」，突发 N 次写只跑 1~2 轮；
 *   - worker 空闲 200ms 自行退出，下一次请求重新拉起，不需要常驻线程；
 *   - 起线程失败丢弃本次刷新（fail-open：少刷一次表，不让循环卡住）。
 */
#include "async_refresh.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

#define ASYNC_REFRESH_IDLE_MS 200

static pthread_mutex_t g_ar_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_ar_cv = PTHREAD_COND_INITIALIZER;
static pthread_once_t g_ar_once = PTHREAD_ONCE_INIT;
/* 条件变量时钟：能设成 MONOTONIC 就用它（墙钟被改也不会把空闲等待拉长/立刻唤醒），
   设不了退回默认时钟，等待截止时间相应改用 CLOCK_REALTIME。 */
static bool g_ar_cv_monotonic;

static void async_refresh_globals_init(void) {
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr) != 0) return; /* 保留静态初始化值（默认时钟） */
    g_ar_cv_monotonic = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0;
    if (pthread_cond_init(&g_ar_cv, &attr) != 0) {
        g_ar_cv_monotonic = false;
        (void)pthread_cond_init(&g_ar_cv, nullptr);
    }
    pthread_condattr_destroy(&attr);
}
static NspAsyncRefreshFn g_ar_fn;
static void* g_ar_ctx;
static bool g_ar_pending; /* 有未处理的请求（含 worker 正在跑时新到的） */
static bool g_ar_running; /* 已有 worker 线程 */
static bool g_ar_stopping;
/* 正在执行回调的 worker 数（恒 0 或 1，测试用来证明没有并发/线程泄漏） */
static _Atomic int g_ar_active;

static void* async_refresh_worker(void* arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_ar_mu);
        while (!g_ar_pending && !g_ar_stopping) {
            struct timespec deadline;
            clock_gettime(g_ar_cv_monotonic ? CLOCK_MONOTONIC : CLOCK_REALTIME, &deadline);
            deadline.tv_nsec += (long)ASYNC_REFRESH_IDLE_MS * 1000000L;
            if (deadline.tv_nsec >= 1000000000L) {
                deadline.tv_sec += 1;
                deadline.tv_nsec -= 1000000000L;
            }
            /* 空闲到期 = 这一阵子没新请求：worker 自己退出，不常驻 */
            if (pthread_cond_timedwait(&g_ar_cv, &g_ar_mu, &deadline) == ETIMEDOUT) break;
        }
        if (!g_ar_pending) { /* 空闲到期，或 stopping 且已无待处理请求 */
            g_ar_running = false;
            pthread_cond_broadcast(&g_ar_cv);
            pthread_mutex_unlock(&g_ar_mu);
            return NULL;
        }
        NspAsyncRefreshFn fn = g_ar_fn;
        void* ctx = g_ar_ctx;
        g_ar_pending = false;
        pthread_mutex_unlock(&g_ar_mu);
        if (fn) {
            atomic_fetch_add_explicit(&g_ar_active, 1, memory_order_acq_rel);
            fn(ctx);
            atomic_fetch_sub_explicit(&g_ar_active, 1, memory_order_acq_rel);
        }
    }
}

void nsp_async_refresh_init(NspAsyncRefreshFn fn, void* ctx) {
    pthread_once(&g_ar_once, async_refresh_globals_init);
    pthread_mutex_lock(&g_ar_mu);
    g_ar_fn = fn;
    g_ar_ctx = ctx;
    pthread_mutex_unlock(&g_ar_mu);
}

void nsp_async_refresh_request(void) {
    pthread_once(&g_ar_once, async_refresh_globals_init);
    bool spawn = false;
    pthread_mutex_lock(&g_ar_mu);
    if (!g_ar_fn || g_ar_stopping) {
        pthread_mutex_unlock(&g_ar_mu);
        return;
    }
    g_ar_pending = true;
    if (!g_ar_running) {
        g_ar_running = true;
        spawn = true;
    }
    pthread_cond_signal(&g_ar_cv);
    pthread_mutex_unlock(&g_ar_mu);
    if (!spawn) return; /* 已有 worker：请求已并入它的下一轮 */
    pthread_attr_t attr;
    pthread_t tid;
    if (pthread_attr_init(&attr) != 0) {
        spawn = false;
    } else {
        (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        spawn = pthread_create(&tid, &attr, async_refresh_worker, NULL) == 0;
        pthread_attr_destroy(&attr);
    }
    if (!spawn) {
        /* 起不来就丢弃本轮：绝不在调用线程上同步执行 */
        pthread_mutex_lock(&g_ar_mu);
        g_ar_running = false;
        g_ar_pending = false;
        pthread_mutex_unlock(&g_ar_mu);
    }
}

bool nsp_async_refresh_active(void) {
    pthread_mutex_lock(&g_ar_mu);
    const bool running = g_ar_running;
    pthread_mutex_unlock(&g_ar_mu);
    return running || atomic_load_explicit(&g_ar_active, memory_order_acquire) > 0;
}

void nsp_async_refresh_shutdown(void) {
    pthread_once(&g_ar_once, async_refresh_globals_init);
    pthread_mutex_lock(&g_ar_mu);
    g_ar_stopping = true;
    g_ar_pending = false; /* 未开始的排空，正在跑的那一轮等它结束 */
    pthread_cond_broadcast(&g_ar_cv);
    while (g_ar_running) {
        if (pthread_cond_wait(&g_ar_cv, &g_ar_mu) != 0) break;
    }
    pthread_mutex_unlock(&g_ar_mu);
}
