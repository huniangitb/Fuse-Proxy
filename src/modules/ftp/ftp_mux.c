/*
 * ftp_mux.c — FTP 控制面「epoll + curl_multi」连接复用器（接口见 ftp_mux.h）
 *
 * 线程模型（libcurl 多接口非线程安全，CURLM 必须单线程持有）：
 *   提交线程                                    事件线程（每 mux 一个）
 *   ftp_mux_perform：入队 + eventfd 唤醒 ──→ mux_take_jobs → curl_multi_add_handle
 *                    等 m->cond 完成广播      epoll_wait ← socket 回调注册的 fd
 *                    ← mux_finish 置 done ─── curl_multi_info_read → remove_handle
 *
 * 连接复用：CURLM 句柄自带连接缓存（curl ≥ 7.57 起连接缓存在 multi 上），
 * 任务完成即把 FTP 控制连接归还缓存，后续任意任务直接取用——不再重复
 * USER/PASS 登录。缓存条目上限由 CURLMOPT_MAXCONNECTS / MAX_HOST_CONNECTIONS
 * 约束。
 *
 * 生命周期：ftp_mux_new 建立结构体 + epoll + 事件线程；ftp_mux_shutdown 停线程
 * 并把在途任务全部以 CURLE_ABORTED_BY_CALLBACK 归位（提交者绝不永久阻塞），
 * 随后等引用计数归零释放。热重载（ftp_backend_clear）期间在途的提交者因此
 * 拿到失败码而非悬挂或触碰已释放内存。
 */
#include "ftp_mux.h"
#include "nsp_module.h"
#include "nsp_util.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

/* epoll 等待上限（ms）：纯保险——新任务/停止都经 eventfd 唤醒，不依赖超时；
   libcurl 需要定时器时由 CURLMOPT_TIMERFUNCTION 给出更短的等待 */
#define FTP_MUX_MAX_WAIT_MS 1000
/* 同一服务器的并发控制连接上限：即控制面并发度（多个 FUSE 线程不再排队），
   同时约束该主机的连接缓存条目数（缓存即复用连接的载体） */
#define FTP_MUX_MAX_HOST_CONN 4
#define FTP_MUX_MAX_TOTAL_CONN 8
#define FTP_MUX_EPOLL_EVENTS 32

/* 一个任务：easy 句柄 + 完成状态。job 由提交者放在**自己的栈**上，
   事件线程在 done 置位前保证不再触碰它（见 ftp_mux_perform 注释）。 */
typedef struct FtpJob {
    CURL* easy;
    CURLcode code;
    bool done;
    bool in_multi;      /* 已 add_handle（仅事件线程读写） */
    struct FtpJob* next; /* 待取队列链 / 在飞链 */
} FtpJob;

struct FtpMux {
    CURLM* multi;
    int epfd;
    int wake_fd; /* eventfd：提交/停止唤醒 epoll_wait */
    pthread_t tid;
    bool thread_started;
    _Atomic bool dead;  /* 停止：新任务立即失败（shutdown 或事件线程致命退出时置位） */
    bool shutdown_done; /* shutdown 已在进行/已完成（lock 保护）：幂等标记 */
    _Atomic int refs;
    _Atomic bool fresh; /* 下次 perform 以全新连接执行（invalidate 置位） */
    pthread_mutex_t lock; /* 保护 dead 复查 / 队列 / active / 任务完成广播 */
    pthread_cond_t cond;
    FtpJob* q_head; /* 待事件线程取走 */
    FtpJob* q_tail;
    FtpJob* live; /* 事件线程已接管的在飞链（事件线程私有，无需锁） */
    int active;   /* 在途提交者数（lock 保护；shutdown 等其归零） */
    long timer_ms; /* libcurl 定时器（事件线程私有，timer 回调填充；-1=无） */
};

/* ================= 引用计数 ================= */

FtpMux* ftp_mux_ref(FtpMux* m) {
    if (m) atomic_fetch_add_explicit(&m->refs, 1, memory_order_relaxed);
    return m;
}

void ftp_mux_unref(FtpMux* m) {
    if (!m) return;
    if (atomic_fetch_sub_explicit(&m->refs, 1, memory_order_acq_rel) != 1) return;
    /* 归零：事件线程已 join、multi/epoll 已清理（见 ftp_mux_shutdown），
       此处只剩同步对象与结构体 */
    pthread_cond_destroy(&m->cond);
    pthread_mutex_destroy(&m->lock);
    free(m);
}

/* ================= easy 句柄工厂 ================= */

CURL* ftp_easy_new(const FtpServerCfg* cfg) {
    if (!cfg) return NULL;
    CURL* c = curl_easy_init();
    if (!c) return NULL;
    curl_easy_setopt(c, CURLOPT_USERNAME, cfg->user);
    curl_easy_setopt(c, CURLOPT_PASSWORD, cfg->pass);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 30L);
    /* 弱网适配：不用 CURLOPT_TIMEOUT 总超时（慢速大文件传输会被误杀），
       改低速率判定——持续 30s 低于 1KB/s 才算卡死，数据在流动就不超时 */
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, 1024L);
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, 30L);
    curl_easy_setopt(c, CURLOPT_FTP_RESPONSE_TIMEOUT, 30L);
    curl_easy_setopt(c, CURLOPT_FTP_SKIP_PASV_IP, 1L);
    curl_easy_setopt(c, CURLOPT_USE_SSL, CURLUSESSL_NONE);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
    return c;
}

/* ================= libcurl 回调（全部只在事件线程内触发） ================= */

/* socket 回调：把 libcurl 关心的 fd 注册/改注册/摘除出 epoll。
   libcurl 对同一 fd 会多次回调（先 IN 后 OUT 等），故 ADD 失败即改 MOD，
   不额外维护 fd→状态映射表；fd 关闭时 libcurl 会回调 REMOVE，epoll 也会在
   句柄关闭时自动摘除，二者不冲突。 */
static int mux_socket_cb(CURL* easy, curl_socket_t s, int what, void* userp, void* socketp) {
    (void)easy;
    (void)socketp;
    FtpMux* m = userp;
    if (what == CURL_POLL_REMOVE) {
        (void)epoll_ctl(m->epfd, EPOLL_CTL_DEL, s, NULL);
        return 0;
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.data.fd = s;
    if (what == CURL_POLL_IN)
        ev.events = EPOLLIN;
    else if (what == CURL_POLL_OUT)
        ev.events = EPOLLOUT;
    else if (what == CURL_POLL_INOUT)
        ev.events = EPOLLIN | EPOLLOUT;
    else
        ev.events = 0; /* CURL_POLL_NONE：登记但暂不关心可读性 */
    if (epoll_ctl(m->epfd, EPOLL_CTL_ADD, s, &ev) != 0 && errno == EEXIST)
        (void)epoll_ctl(m->epfd, EPOLL_CTL_MOD, s, &ev);
    return 0;
}

/* 定时器回调：记录 libcurl 希望的下次超时，作为 epoll_wait 的等待上限。
   值只在事件线程读写（回调由 curl_multi_socket_action 内触发），无需加锁。
   不在此处消费：libcurl 只在超时值**变化**时回调，自行清零会漏掉下一次。 */
static int mux_timer_cb(CURLM* multi, long timeout_ms, void* userp) {
    (void)multi;
    FtpMux* m = userp;
    m->timer_ms = timeout_ms;
    return 0;
}

/* ================= 事件线程内部 ================= */

static void mux_wake(FtpMux* m) {
    uint64_t one = 1;
    /* 计数已满（EFD_NONBLOCK）也无妨：事件线程本轮必会取队列 */
    ssize_t n = write(m->wake_fd, &one, sizeof one);
    (void)n;
}

/* 从在飞链摘除（仅事件线程） */
static void mux_live_unlink(FtpMux* m, FtpJob* j) {
    FtpJob** pp = &m->live;
    while (*pp && *pp != j) pp = &(*pp)->next;
    if (*pp) *pp = j->next;
    j->next = NULL;
}

/* 任务归位：置结果码并唤醒提交者。调用前必须已从 multi 摘除。 */
static void mux_finish(FtpMux* m, FtpJob* j, CURLcode code) {
    pthread_mutex_lock(&m->lock);
    j->code = code;
    j->done = true;
    pthread_cond_broadcast(&m->cond);
    pthread_mutex_unlock(&m->lock);
}

/* 取走待办队列并交给 multi。返回是否有任务被接管。 */
static bool mux_take_jobs(FtpMux* m) {
    pthread_mutex_lock(&m->lock);
    FtpJob* j = m->q_head;
    m->q_head = NULL;
    m->q_tail = NULL;
    pthread_mutex_unlock(&m->lock);
    if (!j) return false;
    while (j) {
        FtpJob* next = j->next;
        j->next = m->live;
        m->live = j;
        j->in_multi = true;
        if (curl_multi_add_handle(m->multi, j->easy) != CURLM_OK) {
            /* 加不进 multi（异常）：按失败归位，避免提交者永久等待 */
            j->in_multi = false;
            mux_live_unlink(m, j);
            mux_finish(m, j, CURLE_FAILED_INIT);
        }
        j = next;
    }
    return true;
}

/* 收完成消息：摘除句柄 → 归位任务。任务按 easy 句柄在**在飞链**定位，不依赖
   CURLINFO_PRIVATE——getinfo 一旦失败就跳过会让提交者永久等待，而「完成消息
   必须归位」是提交者绝不悬挂的前提。in-multi ⊆ live 是结构不变量：take_jobs
   先链入 live 再 add_handle（add 失败即摘链归位），故此处必能定位到任务 */
static void mux_reap(FtpMux* m) {
    CURLMsg* msg;
    int left = 0;
    while ((msg = curl_multi_info_read(m->multi, &left)) != NULL) {
        if (msg->msg != CURLMSG_DONE) continue;
        curl_multi_remove_handle(m->multi, msg->easy_handle);
        FtpJob* j = m->live;
        while (j && j->easy != msg->easy_handle) j = j->next;
        if (!j) continue; /* 不可达：见上方结构不变量注释 */
        j->in_multi = false;
        mux_live_unlink(m, j);
        mux_finish(m, j, msg->data.result);
    }
}

/* 停止前的收尾：队列与在飞任务全部以 CURLE_ABORTED_BY_CALLBACK 归位——
   事件线程退出后不再有人驱动传输，否则提交者会永久等待 */
static void mux_abort_all(FtpMux* m) {
    mux_take_jobs(m);
    while (m->live) {
        FtpJob* j = m->live;
        m->live = j->next;
        j->next = NULL;
        if (j->in_multi) {
            curl_multi_remove_handle(m->multi, j->easy);
            j->in_multi = false;
        }
        mux_finish(m, j, CURLE_ABORTED_BY_CALLBACK);
    }
}

static void* mux_thread(void* arg) {
    FtpMux* m = arg;
    nsp_set_thread_name("nsp_ftpmux");
    struct epoll_event evs[FTP_MUX_EPOLL_EVENTS];
    int running = 0;
    for (;;) {
        if (mux_take_jobs(m))
            curl_multi_socket_action(m->multi, CURL_SOCKET_TIMEOUT, 0, &running);
        if (atomic_load_explicit(&m->dead, memory_order_acquire)) break;

        long tmo = m->timer_ms;
        int wait_ms = (tmo < 0 || tmo > FTP_MUX_MAX_WAIT_MS) ? FTP_MUX_MAX_WAIT_MS : (int)tmo;
        int n = epoll_wait(m->epfd, evs, FTP_MUX_EPOLL_EVENTS, wait_ms);
        if (n < 0) {
            if (errno == EINTR) continue;
            /* epoll_wait 致命错误（实际仅 ENOMEM）：事件线程无法继续驱动传输。
               必须在**锁内**置 dead 再退出——与 perform 的入队检查同一把锁，
               保证此后新任务直接拿到 CURLE_ABORTED_BY_CALLBACK、不再入队；
               若不置 dead 直接退出，后续 perform 入队后将永久等待，且
               ftp_backend_clear 的 active 归零等待随之死锁（控制面与热重载
               整体挂死）。随后 mux_abort_all 归位在途任务 */
            int err = errno;
            pthread_mutex_lock(&m->lock);
            atomic_store_explicit(&m->dead, true, memory_order_release);
            pthread_mutex_unlock(&m->lock);
            LOG_ERR("ftp_mux: epoll_wait 致命错误（%s），事件线程停止，控制面快速失败",
                    strerror(err));
            break;
        }
        if (n == 0) {
            /* 等待到点：把时间推进交给 libcurl（连接/响应超时靠它判定） */
            if (tmo >= 0) curl_multi_socket_action(m->multi, CURL_SOCKET_TIMEOUT, 0, &running);
        } else {
            for (int i = 0; i < n; i++) {
                if (evs[i].data.fd == m->wake_fd) {
                    uint64_t v;
                    ssize_t r = read(m->wake_fd, &v, sizeof v); /* 计数归零 */
                    (void)r;
                    continue;
                }
                int act = 0;
                if (evs[i].events & EPOLLIN) act |= CURL_CSELECT_IN;
                if (evs[i].events & EPOLLOUT) act |= CURL_CSELECT_OUT;
                if (evs[i].events & (EPOLLERR | EPOLLHUP)) act |= CURL_CSELECT_ERR;
                curl_multi_socket_action(m->multi, evs[i].data.fd, act, &running);
            }
        }
        mux_reap(m);
    }
    mux_abort_all(m);
    return NULL;
}

/* ================= 对外接口 ================= */

FtpMux* ftp_mux_new(void) {
    FtpMux* m = calloc(1, sizeof *m);
    if (!m) return NULL;
    m->epfd = -1;
    m->wake_fd = -1;
    m->timer_ms = -1;
    atomic_init(&m->dead, false);
    atomic_init(&m->refs, 1);
    atomic_init(&m->fresh, false);
    pthread_mutex_init(&m->lock, NULL);
    pthread_cond_init(&m->cond, NULL);

    m->multi = curl_multi_init();
    if (!m->multi) goto fail;
    m->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (m->epfd < 0) goto fail;
    m->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (m->wake_fd < 0) goto fail;
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN;
    ev.data.fd = m->wake_fd;
    if (epoll_ctl(m->epfd, EPOLL_CTL_ADD, m->wake_fd, &ev) != 0) goto fail;

    curl_multi_setopt(m->multi, CURLMOPT_SOCKETFUNCTION, mux_socket_cb);
    curl_multi_setopt(m->multi, CURLMOPT_SOCKETDATA, m);
    curl_multi_setopt(m->multi, CURLMOPT_TIMERFUNCTION, mux_timer_cb);
    curl_multi_setopt(m->multi, CURLMOPT_TIMERDATA, m);
    curl_multi_setopt(m->multi, CURLMOPT_MAX_HOST_CONNECTIONS, (long)FTP_MUX_MAX_HOST_CONN);
    curl_multi_setopt(m->multi, CURLMOPT_MAX_TOTAL_CONNECTIONS, (long)FTP_MUX_MAX_TOTAL_CONN);
    curl_multi_setopt(m->multi, CURLMOPT_MAXCONNECTS, (long)FTP_MUX_MAX_HOST_CONN);

    int terr = pthread_create(&m->tid, NULL, mux_thread, m);
    if (terr != 0) {
        errno = terr; /* pthread_create 返回错误码而不置 errno：回填供统一日志 */
        goto fail;
    }
    m->thread_started = true;
    return m;
fail:
    LOG_ERR("ftp_mux: 初始化失败（%s），后端不可用", strerror(errno));
    if (m->multi) curl_multi_cleanup(m->multi);
    if (m->epfd >= 0) close(m->epfd);
    if (m->wake_fd >= 0) close(m->wake_fd);
    pthread_cond_destroy(&m->cond);
    pthread_mutex_destroy(&m->lock);
    free(m);
    return NULL;
}

void ftp_mux_shutdown(FtpMux* m) {
    if (!m) return;
    pthread_mutex_lock(&m->lock);
    /* 幂等标记必须是 shutdown_done 而非 dead：事件线程可能因 epoll_wait 致命
       错误自行置 dead 退出（见 mux_thread），dead 为真并不代表 join 与资源
       清理已做过——以 dead 为幂等键会跳过 join/cleanup 直接把结构体交给
       unref 释放，与仍在收尾的事件线程构成 UAF */
    bool first = !m->shutdown_done;
    m->shutdown_done = true;
    atomic_store_explicit(&m->dead, true, memory_order_release);
    pthread_mutex_unlock(&m->lock);
    if (!first) return;
    mux_wake(m); /* 唤醒 epoll_wait：事件线程见 dead 后归位在途任务并退出 */
    if (m->thread_started) {
        pthread_join(m->tid, NULL); /* 线程已自行退出时立即返回（尚未 join，安全） */
        m->thread_started = false;
    }
    /* 等在途提交者全部离开 perform 再销毁 multi：它们返回前仍要读结果码，
       且 cleanup 必须发生在无人在飞时 */
    pthread_mutex_lock(&m->lock);
    while (m->active > 0) pthread_cond_wait(&m->cond, &m->lock);
    pthread_mutex_unlock(&m->lock);
    curl_multi_cleanup(m->multi); /* 线程已 join，仅此一处触碰 multi */
    m->multi = NULL;
    close(m->epfd);
    m->epfd = -1;
    close(m->wake_fd);
    m->wake_fd = -1;
}

CURLcode ftp_mux_perform(FtpMux* m, CURL* easy) {
    if (!m || !easy) return CURLE_FAILED_INIT;
    /* 失效标记：本次以全新连接（重新登录）执行，等价旧 reset_curl 的重建句柄
       语义，但不牵连其他在途任务，也不因业务失败白丢健康连接 */
    bool fresh = atomic_exchange_explicit(&m->fresh, false, memory_order_acq_rel);
    curl_easy_setopt(easy, CURLOPT_FRESH_CONNECT, fresh ? 1L : 0L);

    FtpJob job;
    memset(&job, 0, sizeof job);
    job.easy = easy;
    job.code = CURLE_OK;

    pthread_mutex_lock(&m->lock);
    if (atomic_load_explicit(&m->dead, memory_order_relaxed)) {
        pthread_mutex_unlock(&m->lock);
        return CURLE_ABORTED_BY_CALLBACK;
    }
    if (m->q_tail)
        m->q_tail->next = &job;
    else
        m->q_head = &job;
    m->q_tail = &job;
    m->active++;
    mux_wake(m);
    /* 事件线程在置 done 之前必已 curl_multi_remove_handle 并停止触碰 job，
       故 done 之后（含本函数返回后）job 与 easy 归调用方独占 */
    while (!job.done) pthread_cond_wait(&m->cond, &m->lock);
    m->active--;
    pthread_cond_broadcast(&m->cond); /* 唤醒 shutdown 的 active 归零等待 */
    pthread_mutex_unlock(&m->lock);
    return job.code;
}

void ftp_mux_invalidate(FtpMux* m) {
    if (!m) return;
    atomic_store_explicit(&m->fresh, true, memory_order_release);
}
