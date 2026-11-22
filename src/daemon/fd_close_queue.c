/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
/* 延迟 close：锁内转移 fd 所有权，锁外执行可能阻塞的 close。 */
#include "fd_close_queue.h"

#include <stdlib.h>
#include <unistd.h>

/* 测试期间只在所有相关线程停止后更换关闭函数。 */
static FdqCloseFn g_close_fn = close;

void fdq_set_close_fn(FdqCloseFn fn) { g_close_fn = fn ? fn : close; }

void fdq_init(FdCloseQueue* q) {
    if (!q) return;
    pthread_mutex_init(&q->lock, nullptr);
    for (int i = 0; i < FD_CLOSE_QUEUE_CAP; ++i) q->fds[i] = -1;
    atomic_store_explicit(&q->next, 0, memory_order_relaxed);
    atomic_store_explicit(&q->ready, 0, memory_order_relaxed);
    atomic_store_explicit(&q->consumed, 0, memory_order_relaxed);
}

/* 调用者持 lock。先复制到消费者私有批次，再允许生产者复用槽位。 */
static unsigned fdq_claim_locked(FdCloseQueue* q, int* batch) {
    unsigned end = atomic_load_explicit(&q->ready, memory_order_relaxed);
    unsigned start = atomic_load_explicit(&q->consumed, memory_order_relaxed);
    unsigned count = end - start;
    for (unsigned i = 0; i < count; ++i)
        batch[i] = q->fds[(start + i) & FD_CLOSE_QUEUE_MASK];
    atomic_store_explicit(&q->consumed, end, memory_order_release);
    return count;
}

static void fdq_close_batch(const int* batch, unsigned count) {
    for (unsigned i = 0; i < count; ++i)
        if (batch[i] >= 0) g_close_fn(batch[i]);
}

void fdq_defer(FdCloseQueue* q, int fd) {
    if (!q) {
        if (fd >= 0) g_close_fn(fd);
        return;
    }
    for (;;) {
        int batch[FD_CLOSE_QUEUE_CAP];
        pthread_mutex_lock(&q->lock);
        unsigned next = atomic_load_explicit(&q->next, memory_order_relaxed);
        unsigned consumed = atomic_load_explicit(&q->consumed, memory_order_relaxed);
        if (next - consumed < FD_CLOSE_QUEUE_CAP) {
            q->fds[next & FD_CLOSE_QUEUE_MASK] = fd;
            atomic_store_explicit(&q->next, next + 1, memory_order_relaxed);
            atomic_store_explicit(&q->ready, next + 1, memory_order_release);
            pthread_mutex_unlock(&q->lock);
            return;
        }
        unsigned count = fdq_claim_locked(q, batch);
        pthread_mutex_unlock(&q->lock);
        /* 当前 fd 尚未发布：不能先把它入队，再被旧批次的慢 close 留住。 */
        fdq_close_batch(batch, count);
    }
}

void fdq_flush(FdCloseQueue* q) {
    if (!q) return;
    if (atomic_load_explicit(&q->ready, memory_order_acquire) ==
        atomic_load_explicit(&q->consumed, memory_order_relaxed)) return;
    int batch[FD_CLOSE_QUEUE_CAP];
    pthread_mutex_lock(&q->lock);
    unsigned count = fdq_claim_locked(q, batch);
    pthread_mutex_unlock(&q->lock);
    fdq_close_batch(batch, count);
}

/* Android legacy lookup 每个 worker 最多一个尚未回复的 backing fd。只能在
 * 同 worker 的下一请求入口或退出时回收；其他 worker 不得消费它。 */
static pthread_key_t g_thread_key;
static pthread_once_t g_thread_key_once = PTHREAD_ONCE_INIT;
static int g_thread_key_error;
static _Thread_local FdCloseQueue* g_thread_queue;

static void fdq_thread_destroy(void* raw) {
    FdCloseQueue* q = raw;
    g_thread_queue = nullptr;
    fdq_flush(q);
    pthread_mutex_destroy(&q->lock);
    free(q);
}

static void fdq_thread_key_init(void) {
    g_thread_key_error = pthread_key_create(&g_thread_key, fdq_thread_destroy);
}

bool fdq_thread_defer(int fd) {
    if (fd < 0) return false;
    FdCloseQueue* q = g_thread_queue;
    if (!q) {
        if (pthread_once(&g_thread_key_once, fdq_thread_key_init) != 0 || g_thread_key_error)
            return false;
        q = calloc(1, sizeof(*q));
        if (!q) return false;
        if (pthread_mutex_init(&q->lock, nullptr) != 0) {
            free(q);
            return false;
        }
        if (pthread_setspecific(g_thread_key, q) != 0) {
            pthread_mutex_destroy(&q->lock);
            free(q);
            return false;
        }
        g_thread_queue = q;
    }
    /* 不把同一未回复请求内的第二次 defer 当成成熟回收时机。 */
    if (atomic_load_explicit(&q->ready, memory_order_relaxed) !=
        atomic_load_explicit(&q->consumed, memory_order_relaxed)) return false;
    fdq_defer(q, fd);
    return true;
}

void fdq_thread_flush(void) {
    if (g_thread_queue) fdq_flush(g_thread_queue);
}
