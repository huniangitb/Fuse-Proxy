/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
/* fd_close_queue 单测驱动：直编实际实现（tests/test_pending_close.py 编译运行）。
 *
 * 覆盖三条不变量（对应 src/daemon/fd_close_queue.h 的并发契约）：
 *   1) 每个入队 fd 恰好 close 一次——close(2) 被计数钩子替换，重复 close 可
 *      确定性检出（真实 fd 上只有在 fd 号被复用后才表现为误关无关资源）。
 *   2) 队列满不阻塞、不制造被放弃的槽位——「饱和 → flush → 再入队」这一组合
 *      在旧实现（先占号再判满、占号者直接返回）下会把 ready 水位永久卡住：
 *      新生产者要么自旋等待永不发布的槽位（挂死），要么永远走直接 close
 *      （队列静默失效）。此处断言新 fd 仍被延迟（未立即 close）且最终恰好关一次。
 *   3) 多生产者/多消费者并发下不重不漏。
 *   4) **饱和时不得提前关闭本次 fd**（A22）——旧实现「满则直接 close」会让内核
 *      拿到已关闭的 fd（fd 号可被另一 worker 的 open 立刻复用 → backing 挂到无关
 *      文件）。判别：填满队列后再 defer 一个探针 fd，断言它**此刻未被关闭**；
 *      旧实现立即关闭，新实现先促消费腾位再入队。 */
#include "fd_close_queue.h"
#include "nsp_log.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 本驱动直编 fd_close_queue.c（它经 LOG_ERR 上报饱和兜底），故需提供日志符号 */
void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}

#define ID_SPACE 1000000

static _Atomic unsigned char g_closed[ID_SPACE];
static _Atomic unsigned g_close_calls;
static _Atomic unsigned g_dup_close;
static _Atomic unsigned g_bad_fd;
static int g_fail;

/* 关闭钩子的确定性延迟：指定 fd 首次被关闭时阻塞，用于把并发窗口「撑开」——
   消费者 A 停在批次中途，此时另一线程进入 flush 就能确定性地暴露
   「非独占领取 → 两个消费者关同一批 fd」的缺陷（纯压测只能靠运气撞窗口）。 */
static _Atomic int g_delay_fd = -1;
static _Atomic int g_delay_used;
static _Atomic unsigned g_delay_ms;

/* 计数 close：替换真实 close(2)，避免依赖 fd 号回收时序 */
static int counting_close(int fd) {
    if (fd < 0 || fd >= ID_SPACE) {
        atomic_fetch_add_explicit(&g_bad_fd, 1, memory_order_relaxed);
        return 0;
    }
    if (fd == atomic_load_explicit(&g_delay_fd, memory_order_relaxed) &&
        !atomic_exchange_explicit(&g_delay_used, 1, memory_order_relaxed)) {
        unsigned ms = atomic_load_explicit(&g_delay_ms, memory_order_relaxed);
        if (ms) usleep(ms * 1000);
    }
    if (atomic_exchange_explicit(&g_closed[fd], 1, memory_order_relaxed))
        atomic_fetch_add_explicit(&g_dup_close, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_close_calls, 1, memory_order_relaxed);
    return 0;
}

static bool was_closed(int id) { return atomic_load_explicit(&g_closed[id], memory_order_relaxed); }

static void track_reset(void) {
    for (int i = 0; i < ID_SPACE; i++)
        atomic_store_explicit(&g_closed[i], 0, memory_order_relaxed);
    atomic_store_explicit(&g_close_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&g_dup_close, 0, memory_order_relaxed);
    atomic_store_explicit(&g_bad_fd, 0, memory_order_relaxed);
}

static void check(const char* name, bool ok, const char* detail) {
    if (ok) {
        printf("PASS %s\n", name);
    } else {
        printf("FAIL %s: %s\n", name, detail);
        g_fail = 1;
    }
}

/* 1) 单线程：延迟语义 + 恰好一次。入队数须 < 队列容量：超过容量的部分按设计
   （满则不阻塞）直接 close，不属于「延迟」语义。 */
static void test_defer_and_flush(void) {
    track_reset();
    FdCloseQueue q;
    fdq_init(&q);
    const int base = 1000;
    const int n = FD_CLOSE_QUEUE_CAP - 8;
    for (int i = 0; i < n; i++) fdq_defer(&q, base + i);
    check("defer_delays_close", atomic_load(&g_close_calls) == 0,
          "入队后未被 flush 就 close 了");
    bool all_pending = true;
    for (int i = 0; i < n; i++)
        if (was_closed(base + i)) all_pending = false;
    check("defer_no_early_close", all_pending, "有 fd 在 flush 前被关闭");
    fdq_flush(&q);
    bool all_closed_once = (atomic_load(&g_dup_close) == 0);
    for (int i = 0; i < n; i++)
        if (!was_closed(base + i)) all_closed_once = false;
    check("flush_closes_each_once", all_closed_once && atomic_load(&g_bad_fd) == 0,
          "有 fd 未关闭或重复关闭");
    /* 再 flush 一次（幂等）：不得重复关闭 */
    fdq_flush(&q);
    check("flush_idempotent", atomic_load(&g_dup_close) == 0, "空队列 flush 重复关闭");
}

/* 2) 饱和 → flush → 再入队：旧实现在此挂死或永久失效 */
static void test_saturate_then_reuse(void) {
    track_reset();
    FdCloseQueue q;
    fdq_init(&q);
    const int base = 10000;
    const int burst = FD_CLOSE_QUEUE_CAP * 2;
    for (int i = 0; i < burst; i++) fdq_defer(&q, base + i); /* 满则直接 close，不阻塞 */
    fdq_flush(&q);
    bool burst_closed_once = (atomic_load(&g_dup_close) == 0);
    for (int i = 0; i < burst; i++)
        if (!was_closed(base + i)) burst_closed_once = false;
    check("saturated_burst_all_closed_once", burst_closed_once, "饱和突发中有 fd 未关或重关");

    /* 饱和后队列必须恢复可用：新 fd 应被真正延迟（仍未关闭），而不是直接 close */
    int probe = base + burst + 1;
    fdq_defer(&q, probe);
    check("reuse_after_saturation_deferred", !was_closed(probe),
          "饱和后新 fd 被立即关闭（队列永久失效）");
    fdq_flush(&q);
    check("reuse_after_saturation_closed_once", was_closed(probe) && atomic_load(&g_dup_close) == 0,
          "恢复后的 fd 未恰好关闭一次");
}

/* 3) 两个消费者并发：独占领取（确定性，靠钩子撑开窗口） */
static void* flush_thread(void* raw) {
    fdq_flush((FdCloseQueue*)raw);
    return NULL;
}

static void test_two_consumers_exclusive(void) {
    track_reset();
    FdCloseQueue q;
    fdq_init(&q);
    const int base = 300000;
    const int n = 40;
    for (int i = 0; i < n; i++) fdq_defer(&q, base + i);
    /* 消费者 A 关闭到 base 时被钩子阻塞在批次中途 */
    atomic_store_explicit(&g_delay_fd, base, memory_order_relaxed);
    atomic_store_explicit(&g_delay_used, 0, memory_order_relaxed);
    atomic_store_explicit(&g_delay_ms, 200, memory_order_relaxed);
    pthread_t a;
    if (pthread_create(&a, NULL, flush_thread, &q) != 0) {
        check("two_consumers_thread_started", false, "消费者线程创建失败");
        return;
    }
    usleep(50000); /* A 已进入 close 批次并停在钩子里 */
    fdq_flush(&q); /* B 并发进入同一批：旧实现会重复关闭 */
    pthread_join(a, NULL);
    atomic_store_explicit(&g_delay_fd, -1, memory_order_relaxed);
    atomic_store_explicit(&g_delay_ms, 0, memory_order_relaxed);
    fdq_flush(&q);
    int missing = 0;
    for (int i = 0; i < n; i++)
        if (!was_closed(base + i)) missing++;
    check("two_consumers_no_double_close", atomic_load(&g_dup_close) == 0,
          "两个消费者重复关闭同一批 fd");
    check("two_consumers_no_loss", missing == 0, "两个消费者下有 fd 未被关闭");
}

/* 4) 多生产者/多消费者并发：不重不漏 */
typedef struct {
    FdCloseQueue* q;
    int base;
    int n;
} ProdArg;

static void* producer(void* raw) {
    ProdArg* a = raw;
    for (int i = 0; i < a->n; i++) {
        fdq_defer(a->q, a->base + i);
        if ((i & 63) == 0) sched_yield();
    }
    return NULL;
}

static void* consumer(void* raw) {
    FdCloseQueue* q = raw;
    for (int i = 0; i < 50000; i++) {
        fdq_flush(q);
        sched_yield();
    }
    return NULL;
}

static void test_concurrent(void) {
    track_reset();
    FdCloseQueue q;
    fdq_init(&q);
    enum { NP = 4, NC = 3, PER = 2000, BASE = 100000 };
    pthread_t pt[NP], ct[NC];
    ProdArg args[NP];
    for (int i = 0; i < NP; i++) {
        args[i] = (ProdArg){&q, BASE + i * PER, PER};
        if (pthread_create(&pt[i], NULL, producer, &args[i]) != 0) {
            check("concurrent_threads_started", false, "生产者线程创建失败");
            return;
        }
    }
    for (int i = 0; i < NC; i++)
        if (pthread_create(&ct[i], NULL, consumer, &q) != 0) {
            check("concurrent_threads_started", false, "消费者线程创建失败");
            return;
        }
    for (int i = 0; i < NP; i++) pthread_join(pt[i], NULL);
    for (int i = 0; i < NC; i++) pthread_join(ct[i], NULL);
    fdq_flush(&q); /* 收尾：消费线程可能恰好在最后一次入队前退出 */
    int missing = 0;
    for (int i = 0; i < NP * PER; i++)
        if (!was_closed(BASE + i)) missing++;
    check("concurrent_no_loss", missing == 0, "并发后有 fd 未被关闭");
    check("concurrent_no_double_close", atomic_load(&g_dup_close) == 0, "并发下有 fd 被重复关闭");
    check("concurrent_no_bad_fd", atomic_load(&g_bad_fd) == 0, "关闭了非法 fd");
}

/* 5) 饱和时不得提前关闭本次 fd（A22 判别）。
   填满到恰好 CAP 条（不 flush）→ 再 defer 一个探针：旧实现在此处直接
   close(probe)（内核可能仍在 reply 前引用它，且 fd 号可被复用），新实现先
   促消费腾位再入队 → 探针此刻仍未被关闭。 */
static void test_saturation_no_early_close(void) {
    track_reset();
    FdCloseQueue q;
    fdq_init(&q);
    const int base = 500000;
    for (int i = 0; i < FD_CLOSE_QUEUE_CAP; i++) fdq_defer(&q, base + i);
    check("sat_fill_deferred_no_close", atomic_load(&g_close_calls) == 0,
          "填满过程中就有 fd 被提前关闭（未 flush）");

    const int probe = base + FD_CLOSE_QUEUE_CAP;
    fdq_defer(&q, probe); /* 旧实现：满 → 立即 close(probe) */
    check("sat_probe_not_closed_immediately", !was_closed(probe),
          "饱和时本次 fd 被立即关闭（内核可能仍引用该 fd / fd 号可被复用）");

    fdq_flush(&q);
    check("sat_probe_closed_once_after_flush", was_closed(probe) && atomic_load(&g_dup_close) == 0,
          "探针 fd 未恰好关闭一次");
    int missing = 0;
    for (int i = 0; i < FD_CLOSE_QUEUE_CAP; i++)
        if (!was_closed(base + i)) missing++;
    check("sat_batch_all_closed_once", missing == 0 && atomic_load(&g_dup_close) == 0,
          "腾位回收的批次有 fd 未关闭或重复关闭");
}

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    FdCloseQueue* queue;
    int slow_fd;
    int producer_base;
    int producer_count;
    unsigned followers_done;
    bool close_entered;
    bool released;
    bool producer_done;
} SlowClose;

static SlowClose* g_slow_close;

static struct timespec slow_deadline(unsigned ms) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_nsec += (long)ms * 1000000L;
    ts.tv_sec += ts.tv_nsec / 1000000000L;
    ts.tv_nsec %= 1000000000L;
    return ts;
}

static int held_counting_close(int fd) {
    SlowClose* s = g_slow_close;
    if (fd == s->slow_fd) {
        pthread_mutex_lock(&s->lock);
        s->close_entered = true;
        pthread_cond_broadcast(&s->changed);
        while (!s->released) pthread_cond_wait(&s->changed, &s->lock);
        pthread_mutex_unlock(&s->lock);
    }
    return counting_close(fd);
}

static void* slow_owner(void* raw) {
    SlowClose* s = raw;
    fdq_flush(s->queue);
    return NULL;
}

static void* slow_follower(void* raw) {
    SlowClose* s = raw;
    fdq_flush(s->queue);
    pthread_mutex_lock(&s->lock);
    ++s->followers_done;
    pthread_cond_broadcast(&s->changed);
    pthread_mutex_unlock(&s->lock);
    return NULL;
}

static void* slow_producer(void* raw) {
    SlowClose* s = raw;
    for (int i = 0; i < s->producer_count; ++i)
        fdq_defer(s->queue, s->producer_base + i);
    fdq_flush(s->queue);
    pthread_mutex_lock(&s->lock);
    s->producer_done = true;
    pthread_cond_broadcast(&s->changed);
    pthread_mutex_unlock(&s->lock);
    return NULL;
}

/* Keep exactly one close paused until after measuring unrelated progress.  The
 * producer wraps the ring several times while the old batch still owns its fds. */
static void test_one_slow_close(unsigned followers) {
    track_reset();
    FdCloseQueue q;
    fdq_init(&q);
    enum { BASE = 600000, OLD_COUNT = 40, NEW_BASE = 601000 };
    SlowClose s = {.lock = PTHREAD_MUTEX_INITIALIZER, .queue = &q,
                   .slow_fd = BASE, .producer_base = NEW_BASE,
                   .producer_count = FD_CLOSE_QUEUE_CAP * 3 + 5};
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&s.changed, &attr);
    pthread_condattr_destroy(&attr);
    g_slow_close = &s;
    fdq_set_close_fn(held_counting_close);
    for (int i = 0; i < OLD_COUNT; ++i) fdq_defer(&q, BASE + i);

    pthread_t owner, producer_id, follower_ids[7];
    bool owner_created = pthread_create(&owner, NULL, slow_owner, &s) == 0;
    pthread_mutex_lock(&s.lock);
    struct timespec entered = slow_deadline(1000);
    int wait_rc = 0;
    while (owner_created && !s.close_entered && wait_rc == 0)
        wait_rc = pthread_cond_timedwait(&s.changed, &s.lock, &entered);
    bool reached_close = s.close_entered;
    pthread_mutex_unlock(&s.lock);

    unsigned created = 0;
    bool producer_created = false;
    if (reached_close) {
        for (; created < followers; ++created)
            if (pthread_create(&follower_ids[created], NULL, slow_follower, &s) != 0) break;
        producer_created = pthread_create(&producer_id, NULL, slow_producer, &s) == 0;
    }
    pthread_mutex_lock(&s.lock);
    struct timespec observe = slow_deadline(300);
    wait_rc = 0;
    while (reached_close && (s.followers_done < created ||
           (producer_created && !s.producer_done)) && wait_rc == 0)
        wait_rc = pthread_cond_timedwait(&s.changed, &s.lock, &observe);
    bool followers_progress = s.followers_done == followers;
    bool producer_progress = s.producer_done;
    bool old_still_owned = !was_closed(BASE);
    printf("slow-close followers=%u completed=%u producer_completed=%d before_release=1\n",
           followers, s.followers_done, producer_progress);
    s.released = true;
    pthread_cond_broadcast(&s.changed);
    pthread_mutex_unlock(&s.lock);

    if (owner_created) pthread_join(owner, NULL);
    for (unsigned i = 0; i < created; ++i) pthread_join(follower_ids[i], NULL);
    if (producer_created) pthread_join(producer_id, NULL);
    fdq_flush(&q);
    fdq_set_close_fn(counting_close);
    g_slow_close = NULL;
    bool all_closed = true;
    for (int i = 0; i < OLD_COUNT; ++i)
        if (!was_closed(BASE + i)) all_closed = false;
    if (producer_created)
        for (int i = 0; i < s.producer_count; ++i)
            if (!was_closed(NEW_BASE + i)) all_closed = false;
    check("slow_close_threads_and_owner_ready",
          owner_created && reached_close && created == followers && producer_created,
          "测试线程未就绪或未命中唯一慢关闭");
    check("slow_close_other_flushes_progress", followers_progress,
          "一次慢close让其他flush线程等到它释放");
    check("slow_close_saturated_producer_progress", producer_progress,
          "慢close传播到满队列生产者");
    check("slow_close_owned_fd_not_early_closed", old_still_owned,
          "旧批次仍在使用的fd被提前关闭");
    check("slow_close_ring_reuse_exactly_once",
          all_closed && atomic_load(&g_dup_close) == 0 && atomic_load(&g_bad_fd) == 0,
          "复用槽位后旧批次或新批次fd漏关/重关");
    pthread_cond_destroy(&s.changed);
    pthread_mutex_destroy(&s.lock);
    pthread_mutex_destroy(&q.lock);
}

int main(void) {
    alarm(15);
    fdq_set_close_fn(counting_close);
    test_defer_and_flush();
    test_saturate_then_reuse();
    test_saturation_no_early_close();
    test_two_consumers_exclusive();
    test_concurrent();
    test_one_slow_close(3);
    test_one_slow_close(7);
    if (g_fail) {
        printf("RESULT FAIL\n");
        return 1;
    }
    printf("RESULT OK\n");
    return 0;
}
