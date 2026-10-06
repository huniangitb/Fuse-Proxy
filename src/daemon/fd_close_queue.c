/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
/* 延迟 close 环形队列实现：并发语义与不变量见 fd_close_queue.h */
#include "fd_close_queue.h"

#include <sched.h>
#include <unistd.h>

/* 实际 close 出口（测试可注入计数器验证「恰好关闭一次」） */
static FdqCloseFn g_close_fn = close;

void fdq_set_close_fn(FdqCloseFn fn) { g_close_fn = fn ? fn : close; }

void fdq_init(FdCloseQueue* q) {
    if (!q) return;
    pthread_mutex_init(&q->lock, nullptr);
    for (int i = 0; i < FD_CLOSE_QUEUE_CAP; i++) q->fds[i] = -1;
    atomic_store_explicit(&q->next, 0, memory_order_relaxed);
    atomic_store_explicit(&q->ready, 0, memory_order_relaxed);
    atomic_store_explicit(&q->consumed, 0, memory_order_relaxed);
}

void fdq_defer(FdCloseQueue* q, int fd) {
    if (!q) {
        if (fd >= 0) g_close_fn(fd);
        return;
    }
    unsigned idx;
    for (;;) {
        unsigned next = atomic_load_explicit(&q->next, memory_order_relaxed);
        /* 完成水位：只统计已 close 的槽位，故占号前判满即可保证复用槽位安全 */
        unsigned consumed = atomic_load_explicit(&q->consumed, memory_order_acquire);
        if (next - consumed >= FD_CLOSE_QUEUE_CAP) {
            g_close_fn(fd); /* 满：退化直接关闭，不阻塞生产者 */
            return;
        }
        /* 满判定先于占号：占号后才判满并直接返回，会让 ready 水位永远缺这一格，
           后续生产者自旋等待一个永不发布的槽位 → worker 永久挂起 */
        if (atomic_compare_exchange_weak_explicit(&q->next, &next, next + 1,
                                                  memory_order_relaxed, memory_order_relaxed)) {
            idx = next;
            break;
        }
    }
    q->fds[idx & FD_CLOSE_QUEUE_MASK] = fd;
    /* 发布：槽位已写，把 ready 按序推到 idx+1。前序占号者可能被抢占，
       故须等它先发布；自旋让出 CPU，避免空转烧核 */
    for (unsigned spin = 0;; spin++) {
        unsigned r = atomic_load_explicit(&q->ready, memory_order_acquire);
        if (r > idx) break; /* 已被前序推进覆盖 */
        if (r == idx && atomic_compare_exchange_weak_explicit(&q->ready, &r, idx + 1,
                                                              memory_order_release,
                                                              memory_order_relaxed))
            break;
        if (spin >= 1024) {
            sched_yield();
            spin = 0;
        }
    }
}

void fdq_flush(FdCloseQueue* q) {
    if (!q) return;
    /* 空队列快速路径：不加锁（稳态零原子写） */
    if (atomic_load_explicit(&q->ready, memory_order_acquire) ==
        atomic_load_explicit(&q->consumed, memory_order_relaxed))
        return;
    pthread_mutex_lock(&q->lock);
    unsigned ready = atomic_load_explicit(&q->ready, memory_order_acquire);
    unsigned consumed = atomic_load_explicit(&q->consumed, memory_order_relaxed);
    /* 独占领取 [consumed, ready)：多 worker 同时 flush 时只有一个执行体关这批，
       否则两个线程读到同一 ready/consumed 会重复 close（第二次可能命中被复用的
       fd 号，误关其他线程的资源） */
    for (unsigned i = consumed; i < ready; i++) {
        int fd = q->fds[i & FD_CLOSE_QUEUE_MASK];
        if (fd >= 0) g_close_fn(fd);
    }
    /* 关闭完成后才推进完成水位（先推进会让生产者复用尚未 close 的槽位） */
    atomic_store_explicit(&q->consumed, ready, memory_order_release);
    pthread_mutex_unlock(&q->lock);
}
