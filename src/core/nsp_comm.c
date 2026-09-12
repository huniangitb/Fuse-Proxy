#include "nsp_comm.h"
#include "nsp_util.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

/* 通道容量（槽数）与单条上限：LOG 沿用旧 ring 2048 条；BCAST JSON 可达数百 KB */
static const uint64_t kCap[NSP_CH__N] = { 2048, 64, 32 };
static const size_t kMaxPayload[NSP_CH__N] = { 16 * 1024, 1024, 1024 * 1024 };
/* drain 优先级：生命线 IPC > 日志 LOG > 广播 BCAST */
static const nsp_ch_t kPrio[NSP_CH__N] = { NSP_CH_IPC, NSP_CH_LOG, NSP_CH_BCAST };
#define DRAIN_BATCH 64          /* 单轮单通道最多取走条数（有界临界区外发送） */
#define BACKOFF_MIN_MS 100      /* 重连退避起点（与旧 sender 100ms 一致） */
#define BACKOFF_MAX_MS 1000

typedef struct {
    void *data;
    size_t len;
} slot_t;

typedef struct {
    pthread_mutex_t lock;       /* 仅保护 head/tail/slots，临界区内无 IO、无大拷贝 */
    slot_t *slots;
    uint64_t cap;               /* 2 的幂 */
    uint64_t mask;
    uint64_t head;              /* 下一写入位 */
    uint64_t tail;              /* 下一读出位 */
    size_t max_payload;
    _Atomic uint64_t dropped;   /* 累计覆盖/丢弃（含未 init、超长、满环、链路断时批丢） */
    _Atomic uint64_t pending_report; /* 待上报丢弃数：post 侧 fetch_add，drain 侧 exchange 取走 */
    nsp_comm_backend_t be;
    _Atomic bool has_be;
    /* 链路状态（仅 comm 线程触碰） */
    bool link_up;
    uint64_t backoff_ms;
    uint64_t retry_at_ms;       /* monotonic ms，0=无需定时 */
} channel_t;

static channel_t g_ch[NSP_CH__N];
static bool g_ch_init = false; /* 仅 g_init_lock 内读写 */
static pthread_mutex_t g_init_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_inited = false;  /* 仅 g_init_lock 内读写 */
static _Atomic bool g_shutdown = false;
static _Atomic bool g_accepting = false; /* fini 置 false 后 post 只计数不写 fd（断 fini/close 竞态） */
static pthread_t g_tid;
static int g_epfd = -1;
static int g_evfd = -1;
static int g_timerfd = -1;

static void *nsp_comm_thread(void *arg);

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void ch_setup(void) {
    if (g_ch_init) return;
    for (int c = 0; c < NSP_CH__N; c++) {
        channel_t *ch = &g_ch[c];
        pthread_mutex_init(&ch->lock, NULL);
        ch->cap = kCap[c];
        ch->mask = ch->cap - 1;
        ch->slots = calloc(ch->cap, sizeof(slot_t));
        ch->max_payload = kMaxPayload[c];
        atomic_init(&ch->dropped, 0);
        atomic_init(&ch->pending_report, 0);
        atomic_init(&ch->has_be, false);
        ch->backoff_ms = BACKOFF_MIN_MS;
    }
    g_ch_init = true;
}

int nsp_comm_init(void) {
    pthread_mutex_lock(&g_init_lock);
    ch_setup();
    if (g_inited) { pthread_mutex_unlock(&g_init_lock); return 0; }
    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    g_evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    g_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (g_epfd < 0 || g_evfd < 0 || g_timerfd < 0) {
        if (g_epfd >= 0) close(g_epfd);
        if (g_evfd >= 0) close(g_evfd);
        if (g_timerfd >= 0) close(g_timerfd);
        g_epfd = g_evfd = g_timerfd = -1;
        pthread_mutex_unlock(&g_init_lock);
        return -1;
    }
    struct epoll_event ev = { .events = EPOLLIN, .data.u32 = 0 };
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_evfd, &ev);
    ev.data.u32 = 1;
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_timerfd, &ev);
    atomic_store(&g_shutdown, false);
    atomic_store(&g_accepting, true);
    if (pthread_create(&g_tid, NULL, nsp_comm_thread, NULL) != 0) {
        atomic_store(&g_accepting, false);
        close(g_epfd); close(g_evfd); close(g_timerfd);
        g_epfd = g_evfd = g_timerfd = -1;
        pthread_mutex_unlock(&g_init_lock);
        return -1;
    }
    g_inited = true;
    pthread_mutex_unlock(&g_init_lock);
    return 0;
}

int nsp_comm_register(nsp_ch_t ch, const nsp_comm_backend_t *be) {
    if ((int)ch < 0 || ch >= NSP_CH__N || !be || !be->emit) return -1;
    pthread_mutex_lock(&g_init_lock);
    ch_setup();
    channel_t *c = &g_ch[ch];
    pthread_mutex_lock(&c->lock);
    c->be = *be;
    pthread_mutex_unlock(&c->lock);
    atomic_store(&c->has_be, true);
    pthread_mutex_unlock(&g_init_lock);
    return 0;
}

/* 空转非空才写一次 eventfd（批量唤醒，稳态高吞吐下单次 write 覆盖一批 post） */
void nsp_comm_post(nsp_ch_t ch, const void *data, size_t len) {
    if ((int)ch < 0 || ch >= NSP_CH__N || !data || len == 0) return;
    channel_t *c = &g_ch[ch];
    /* 未注册/已 fini → 只计数不触碰环与 fd（fini 后 post 安全） */
    if (!atomic_load(&g_accepting) || !atomic_load(&c->has_be)) {
        atomic_fetch_add(&c->dropped, 1);
        return;
    }
    if (len > c->max_payload) {
        atomic_fetch_add(&c->dropped, 1);
        atomic_fetch_add(&c->pending_report, 1);
        return;
    }
    void *copy = malloc(len);
    if (!copy) {
        atomic_fetch_add(&c->dropped, 1);
        return;
    }
    memcpy(copy, data, len);
    bool wake = false;
    pthread_mutex_lock(&c->lock);
    /* P1：锁内二次检查 accepting/has_be——fini 翻转 accepting 后 join + 逐通道
       释放，锁外检查通过的 post 若直接入队会造成 fini 后堆积泄漏；此处复核，
       fini 后一律只计数 */
    if (!atomic_load(&g_accepting) || !atomic_load(&c->has_be)) {
        pthread_mutex_unlock(&c->lock);
        free(copy);
        atomic_fetch_add(&c->dropped, 1);
        return;
    }
    if (c->head - c->tail >= c->cap) {
        /* 满环覆盖最旧（与旧 sender 语义一致）+ 计数 */
        slot_t *old = &c->slots[c->tail & c->mask];
        free(old->data);
        c->tail++;
        atomic_fetch_add(&c->dropped, 1);
        atomic_fetch_add(&c->pending_report, 1);
    } else if (c->head == c->tail) {
        wake = true;
    }
    slot_t *s = &c->slots[c->head & c->mask];
    s->data = copy;
    s->len = len;
    c->head++;
    pthread_mutex_unlock(&c->lock);
    if (wake) {
        /* P1：fd 写与 fini 的 close 同持 g_init_lock（先放 c->lock 再取
           init_lock，无嵌套、与 register 的 init→ch 顺序无 ABBA 死锁）——
           杜绝 close/write 竞态导致的 use-after-close 误写 */
        pthread_mutex_lock(&g_init_lock);
        if (g_evfd >= 0) {
            uint64_t v = 1;
            (void)write(g_evfd, &v, sizeof(v));
        }
        pthread_mutex_unlock(&g_init_lock);
    }
}

uint64_t nsp_comm_dropped(nsp_ch_t ch) {
    if ((int)ch < 0 || ch >= NSP_CH__N) return 0;
    return atomic_load(&g_ch[ch].dropped);
}

/* timerfd 单次到期（最早 retry_at）；backend 退避到期由 drain 侧按时间判定 */
static void arm_timer(uint64_t at_ms) {
    if (g_timerfd < 0) return;
    struct itimerspec ts = {0};
    if (at_ms == 0) {
        timerfd_settime(g_timerfd, 0, &ts, NULL); /* 撤防 */
        return;
    }
    uint64_t now = now_ms();
    uint64_t delta = (at_ms > now) ? (at_ms - now) : 1;
    ts.it_value.tv_sec = (time_t)(delta / 1000u);
    ts.it_value.tv_nsec = (long)((delta % 1000u) * 1000000u);
    timerfd_settime(g_timerfd, 0, &ts, NULL);
}

/* 取一批（调用方持有返回数组；失败只发生在链路断时由调用方计 dropped） */
static int ch_take(channel_t *c, void **out_data, size_t *out_len, int max) {
    int n = 0;
    pthread_mutex_lock(&c->lock);
    while (n < max && c->tail != c->head) {
        slot_t *s = &c->slots[c->tail & c->mask];
        out_data[n] = s->data;
        out_len[n] = s->len;
        s->data = NULL;
        s->len = 0;
        c->tail++;
        n++;
    }
    pthread_mutex_unlock(&c->lock);
    return n;
}

/* 单通道排空至空（循环取批发送）：修复旧版单轮 64 条上限 + 空转非空才唤醒
   组合导致的永久堆积。链路断/退避未到期则跳出等下轮。 */
static void drain_channel(nsp_ch_t ch_id, bool for_shutdown, uint64_t *earliest) {
    channel_t *c = &g_ch[ch_id];
    if (!atomic_load(&c->has_be)) return;
    for (;;) {
        uint64_t now = now_ms();
        uint64_t pending;
        pthread_mutex_lock(&c->lock);
        pending = c->head - c->tail;
        pthread_mutex_unlock(&c->lock);
        if (pending == 0) break;
        if (!c->link_up && !for_shutdown && c->retry_at_ms != 0 && now < c->retry_at_ms) {
            if (*earliest == 0 || c->retry_at_ms < *earliest) *earliest = c->retry_at_ms;
            break;
        }
        if (!c->link_up) {
            bool ok = c->be.ensure_link ? c->be.ensure_link(c->be.ctx) : true;
            if (!ok) {
                if (!for_shutdown) {
                    c->retry_at_ms = now + c->backoff_ms;
                    if (c->backoff_ms < BACKOFF_MAX_MS) c->backoff_ms *= 2;
                    if (*earliest == 0 || c->retry_at_ms < *earliest) *earliest = c->retry_at_ms;
                }
                break;
            }
            c->link_up = true;
            c->backoff_ms = BACKOFF_MIN_MS;
            c->retry_at_ms = 0;
        }
        void *bufs[DRAIN_BATCH];
        size_t lens[DRAIN_BATCH];
        int n = ch_take(c, bufs, lens, DRAIN_BATCH);
        if (n == 0) break;
        for (int i = 0; i < n; i++) {
            int r = c->be.emit(c->be.ctx, bufs[i], lens[i]);
            free(bufs[i]);
            if (r < 0) {
                /* 链路断：本批剩余计 dropped（有界损失，替代旧 sender 的整环冻结） */
                c->link_up = false;
                c->retry_at_ms = now_ms() + c->backoff_ms;
                if (c->backoff_ms < BACKOFF_MAX_MS) c->backoff_ms *= 2;
                if (!for_shutdown) {
                    if (*earliest == 0 || c->retry_at_ms < *earliest) *earliest = c->retry_at_ms;
                }
                for (int j = i + 1; j < n; j++) {
                    free(bufs[j]);
                    atomic_fetch_add(&c->dropped, 1);
                    atomic_fetch_add(&c->pending_report, 1);
                }
                break;
            }
        }
        if (!c->link_up) break;   /* 刚断链：等退避，不再空转 */
    }
    /* 本轮上报覆盖丢弃（exchange 取走一次，避免风暴） */
    if (c->be.report) {
        uint64_t m = atomic_exchange(&c->pending_report, 0);
        if (m > 0) c->be.report(ch_id, m, c->be.ctx);
    }
}

static void drain_once(bool for_shutdown) {
    uint64_t earliest = 0;
    for (int p = 0; p < NSP_CH__N; p++)
        drain_channel(kPrio[p], for_shutdown, &earliest);
    if (!for_shutdown) arm_timer(earliest);
}

static void *nsp_comm_thread(void *arg) {
    (void)arg;
    nsp_set_thread_name("nsp_comm");
    struct epoll_event evs[4];
    drain_once(false); /* 启动即排空 init 前堆积（未 init 的 post 已计 dropped，不会堆积） */
    while (!g_shutdown) {
        int n = epoll_wait(g_epfd, evs, 4, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; i++) {
            if (evs[i].data.u32 == 0) {
                uint64_t v;
                while (read(g_evfd, &v, sizeof(v)) > 0) { } /* 读空防忙转 */
            } else {
                uint64_t v;
                while (read(g_timerfd, &v, sizeof(v)) > 0) { }
            }
        }
        drain_once(false);
    }
    drain_once(true); /* 退出前最尽力 drain */
    return NULL;
}

void nsp_comm_fini(void) {
    pthread_mutex_lock(&g_init_lock);
    if (!g_inited) { pthread_mutex_unlock(&g_init_lock); return; }
    g_inited = false;
    /* 先停接收：此后 post 只计数不写 fd，join 前无任何线程能触碰待关闭 fd */
    atomic_store(&g_accepting, false);
    atomic_store(&g_shutdown, true);
    uint64_t v = 1;
    if (g_evfd >= 0) (void)write(g_evfd, &v, sizeof(v));
    pthread_mutex_unlock(&g_init_lock);
    pthread_join(g_tid, NULL);
    for (int c = 0; c < NSP_CH__N; c++) {
        channel_t *ch = &g_ch[c];
        if (atomic_load(&ch->has_be) && ch->be.fini) ch->be.fini(ch->be.ctx);
        pthread_mutex_lock(&ch->lock);
        while (ch->tail != ch->head) {
            free(ch->slots[ch->tail & ch->mask].data);
            ch->tail++;
        }
        pthread_mutex_unlock(&ch->lock);
        atomic_store(&ch->has_be, false);
        ch->link_up = false;
        atomic_store(&ch->pending_report, 0);
    }
    /* P1：关 fd 持 g_init_lock，与 post 侧唤醒写同锁，互斥 close/write */
    pthread_mutex_lock(&g_init_lock);
    close(g_epfd); close(g_evfd); close(g_timerfd);
    g_epfd = g_evfd = g_timerfd = -1;
    pthread_mutex_unlock(&g_init_lock);
}
