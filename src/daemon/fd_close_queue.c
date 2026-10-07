/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
/* 延迟 close 环形队列实现：并发语义与不变量见 fd_close_queue.h */
#include "fd_close_queue.h"

#include "nsp_log.h"

#include <sched.h>
#include <unistd.h>

/* 实际 close 出口（测试可注入计数器验证「恰好关闭一次」） */
static FdqCloseFn g_close_fn = close;

/* 饱和时促消费的让出预算（次）。稳态下每个回调至多 1 次 defer + 1 次 flush，
   队列净增长 ≤ 0，本分支不可达；仅在 worker 数 ≥ 容量时才可能进入，此时
   占号者都在运行中，几轮 yield 内必发布槽位。 */
#define FDQ_RECLAIM_SPINS 4096

void fdq_set_close_fn(FdqCloseFn fn) { g_close_fn = fn ? fn : close; }

void fdq_init(FdCloseQueue* q) {
    if (!q) return;
    pthread_mutex_init(&q->lock, nullptr);
    for (int i = 0; i < FD_CLOSE_QUEUE_CAP; i++) q->fds[i] = -1;
    atomic_store_explicit(&q->next, 0, memory_order_relaxed);
    atomic_store_explicit(&q->ready, 0, memory_order_relaxed);
    atomic_store_explicit(&q->consumed, 0, memory_order_relaxed);
}

/* 饱和时腾位：回收已完成批次（关的是**更早**回调留下的 fd，与本次无关），
   若槽位仅被「已占号未发布」的在途生产者持有，则让出 CPU 等其发布后再回收。
   返回 true = 已腾出可占槽位；false = 预算内无进展（调用方兜底）。 */
static bool fdq_reclaim(FdCloseQueue* q) {
    for (int spin = 0; spin < FDQ_RECLAIM_SPINS; spin++) {
        fdq_flush(q);
        unsigned next = atomic_load_explicit(&q->next, memory_order_relaxed);
        unsigned consumed = atomic_load_explicit(&q->consumed, memory_order_acquire);
        if (next - consumed < FD_CLOSE_QUEUE_CAP) return true;
        sched_yield();
    }
    return false;
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
            /* 饱和：**绝不立即关闭本次的 fd**。队列存在的唯一理由就是「内核可能
               在 reply 发送完成前仍引用该 fd」（见头注释）：立即 close 会让内核
               拿到已关闭的 fd，而该 fd 号可被另一 worker 的 open 立刻复用 →
               backing 挂到无关文件（确定的正确性缺陷，不是性能取舍）。
               改为促消费腾位后重试占号。 */
            if (fdq_reclaim(q)) continue;
            /* 预算内无进展：只有 worker 数 ≥ 队列容量时才可能到达（每回调至多
               1 次 defer + 1 次 flush，稳态净增长 ≤ 0）。此处如实降级并 loud
               告警——既不静默、也不把 worker 挂死。 */
            LOG_ERR("延迟 close 队列饱和且回收无进展（cap=%d）：降级为直接关闭 fd=%d",
                    FD_CLOSE_QUEUE_CAP, fd);
            if (fd >= 0) g_close_fn(fd);
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
