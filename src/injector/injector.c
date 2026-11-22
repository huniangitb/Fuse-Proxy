/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "injector.h"
#include "common.h"
#include "nsp_util.h"
#include "config_parser.h"
#include "ns_utils.h"
#include "ns_mnt_watch.h"
#include "ns_mnt_wait.h"
#include "fast_pid.h"
#include "inject_target.h"
#include "reaped_managed.h"
#include "retry_queue.h"
#include "mount_manager.h"
#include "ipc_server.h"
#include "config_publisher.h"
#include "sys_pkg.h"
#include "async_refresh.h"
#include "audit_worker.h"
#include "reload_stage.h"
#include "fuse_recover.h"
#include "build_info.h"
#include "crash_tail.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <dirent.h>
#include <ctype.h>
#include <fnmatch.h>
#include <errno.h>
#include <limits.h>
#include <sys/syscall.h>

volatile sig_atomic_t g_should_exit = 0;
volatile sig_atomic_t g_reload_config = 0;
volatile sig_atomic_t g_passive_mode = 0;
volatile sig_atomic_t g_fuse_ready = 0;
int g_global_root_fd = -1;
int g_epoll_fd = -1;
int g_inotify_fd = -1;
int g_config_pub_fd = -1;
static int seconds_until_next_scan = 1;
static int g_scan_interval_seconds = 30;
static bool g_last_scan_found = false;
/* 全局替换模式首次兜底扫描标志：FUSE 就绪后仅执行一次扫描，
   还原存量非目标应用；之后生命周期内不再反复周期检测（新应用
   由 zygisk IPC 通知即时还原） */
static bool g_global_replace_scanned_once = false;
/* 全局替换（v2/v3）对账状态：见 maybe_reconcile_global_replace()
 * g_grepl_next_sec 同时表达三件事：>0 = 还有几秒复查（1s tick 递减）；
 * 0 = 下一个 tick 立即复查；GREPL_STEADY_EVENT = 稳态，等挂载表变化事件。
 * g_grepl_backoff 管「还没就绪/失败后」的复查节奏，g_grepl_replace_gap 管
 * 「两次动挂载之间」的最小间隔（替换自身会触发事件源，见函数头注释）。 */
#define GREPL_STEADY_SEC    5    /* 事件源不可用时的稳态复查间隔（兜底） */
#define GREPL_STEADY_EVENT  (-1) /* 稳态：等挂载表变化事件 */
#define GREPL_RETRY_MIN_SEC 1
#define GREPL_RETRY_MAX_SEC 30
/* 连续动挂载的观察窗口：替换自身也改挂载表，事件源会立刻回报自己的动作。
   只有「窗口内反复动挂载」才把最小间隔加倍——健康的单次替换（开机一次、
   vold 重挂一次、新用户出现一次）不该把间隔越推越大，否则紧随其后出现的
   族根要等一个凭空变长的间隔，反而比原来的周期复查更慢。 */
#define GREPL_CHURN_WINDOW_MS 10000
#define GREPL_CHURN_SLOTS     4
static int g_grepl_next_sec;
static int g_grepl_backoff = GREPL_RETRY_MIN_SEC;
static int g_grepl_replace_gap = GREPL_RETRY_MIN_SEC;
static int64_t g_grepl_last_replace_ms;
static int64_t g_grepl_churn_ms[GREPL_CHURN_SLOTS];
static int g_grepl_churn_n;
static int g_grepl_churn_pos;
static bool g_grepl_replaced_once;
static int g_grepl_watch_fd = -1;
/* 事件源不可用是持续状态而不是一次性事件：注册函数每个 tick 都被调用，
   不加这两个标志就会按秒刷同一条告警。它们在「事件源重新可用」或对账记账
   复位时清掉，于是一次不可用只留一条 WRN + 一条回落 INFO。 */
static bool g_grepl_watch_warned;
static bool g_grepl_fallback_logged;
struct GlobalFuseInfo g_global_fuse = {.pid = 1,
                                       .fuse_pid = 0,
                                       .mnt_path = "/mnt/nsp_global",
                                       .crash_count = 0,
                                       .last_crash_time = 0,
                                       .disabled = false};
struct GlobalFuseInfo g_media_fuse = {.pid = 1,
                                      .fuse_pid = 0,
                                      .mnt_path = "/mnt/nsp_media",
                                      .crash_count = 0,
                                      .last_crash_time = 0,
                                      .disabled = false};

/* 注入方法（--inject-method=v1|v2|v3）：默认 v1 逐应用挂载；
   v2 全局替换 + 非目标应用还原；v3 全局替换且不还原（默认全局挂载） */
InjectMethod g_inject_method = INJECT_METHOD_V1;

/* 回退处理标记：INIT 回包被内核拒绝（就绪验证 ECONNREFUSED 且 daemon 进程存活）时置位，
   之后启动 fuse_daemon 一律附加 --no-passthrough，以标准 FUSE 模式规避透传协商位被拒 */
static bool g_no_passthrough_fallback = false;
/* 崩溃触发测试：--crash-test 传递给 fuse_daemon，验证崩溃日志捕获链路 */
static bool g_crash_test = false;

/* 重入保护：防止并发调用 inject_global_fuse() */
static volatile int g_fuse_starting = 0;
/* 延迟首次扫描标记：main() 中注入 FUSE 后不立即扫描，等就绪后再触发 */
static int g_pending_first_scan = 0;
/* FUSE 崩溃恢复后待重挂标记：新 FUSE 就绪时重挂所有追踪应用 */
static volatile sig_atomic_t g_pending_remount = 0;
/* 启动扫描待办标记：FUSE 就绪后扫一次「挂着项目 FUSE 但连接已断」的进程。
   只在进程启动时置位——FUSE 崩溃恢复走 g_pending_remount（追踪表），两者不同：
   前者覆盖本进程启动前就已存在、且不在追踪表里的旧进程。 */
static volatile sig_atomic_t g_pending_startup_scan = 0;

/* 挂载失败重试记账在 src/injector/retry_queue.c（纯记账、可直编单测）。
   这里只保留调度：旧实现把"异步派发成功"当成"挂载成功"，条目当场摘掉、
   失败回调再以 attempts=0 重新入队——退避永不生效、5 次上限永远打不到，
   于是挂不上的应用以 1Hz 永久反复（每轮一条 error.log + 一次 fork/mountinfo）。
   现在尝试次数随条目保存（nsp_retry_*），成功才清账，超限 loud 一次后放弃。 */

/* 异步就绪与挂载任务全局描述符注册系统 */
static int g_fuse_ready_pipe_fd = -1;
/* 配置读取 worker 的就绪 eventfd（<0 = worker 没起来，重载退回内联读） */
static int g_reload_ready_fd = -1;
/* FUSE 崩溃恢复 worker 的就绪 eventfd（<0 = worker 没起来，恢复退回内联执行） */
static int g_fuse_recover_fd = -1;
static void* g_fuse_ready_ctx = nullptr;
#define MAX_ASYNC_MOUNTS 128
static int g_async_mount_fds[MAX_ASYNC_MOUNTS];
static void* g_async_mount_ctxs[MAX_ASYNC_MOUNTS];
static int g_async_mount_count = 0;

/* 注册新的 FUSE 就绪管道。同一时刻只跟踪一条就绪管道（g_fuse_ready_pipe_fd
   是单值，见 epoll 分发）——若上一次的还没就绪就被覆盖，旧 fd 会永久泄漏，
   且旧 daemon 若稍后写入就绪字节，EPOLLIN 仍会触发但主循环按**新** ctx 处理，
   把旧 fd 当新管道读（读不到就绪字节 → 走失败分支，旧 daemon 被误判）。
   故覆盖前必须把旧 fd 从 epoll 摘除并关闭，同时释放其 ctx（ctx 由本文件的
   malloc 分配，所有权随管道转移）。 */
void register_fuse_ready_pipe(int fd, void* ctx) {
    if (g_fuse_ready_pipe_fd >= 0 && g_fuse_ready_pipe_fd != fd) {
        LOG_WRN("FUSE 就绪管道被重新注册（旧 fd=%d 尚未就绪），关闭旧管道",
                g_fuse_ready_pipe_fd);
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, g_fuse_ready_pipe_fd, nullptr);
        close(g_fuse_ready_pipe_fd);
        free(g_fuse_ready_ctx);
    }
    g_fuse_ready_pipe_fd = fd;
    g_fuse_ready_ctx = ctx;
}

/* 异步挂载完成注册表：生产者是挂载工作线程（run_in_mnt_ns_async），消费者是主
   epoll 线程（on_client_fd），两侧都必须持锁——无锁时两个工作线程读到同一 count
   会覆盖同一槽位，被覆盖者注册的 status pipe 在主线程查不到归属，会被当普通 IPC
   客户端读掉并 close：挂载结果永不被处理，该应用既不标注入也不重试。 */
static pthread_mutex_t g_async_mount_mutex = PTHREAD_MUTEX_INITIALIZER;

/* 持锁前提下的摘表：命中则摘除并返回 ctx，否则返回 NULL */
static void* async_mount_take_locked(int fd) {
    for (int i = 0; i < g_async_mount_count; i++) {
        if (g_async_mount_fds[i] != fd) continue;
        void* ctx = g_async_mount_ctxs[i];
        g_async_mount_fds[i] = g_async_mount_fds[g_async_mount_count - 1];
        g_async_mount_ctxs[i] = g_async_mount_ctxs[g_async_mount_count - 1];
        g_async_mount_count--;
        return ctx;
    }
    return NULL;
}

bool register_async_mount_pipe(int fd, void* ctx) {
    bool ok = false;
    pthread_mutex_lock(&g_async_mount_mutex);
    if (g_async_mount_count < MAX_ASYNC_MOUNTS) {
        g_async_mount_fds[g_async_mount_count] = fd;
        g_async_mount_ctxs[g_async_mount_count] = ctx;
        g_async_mount_count++;
        ok = true;
    }
    pthread_mutex_unlock(&g_async_mount_mutex);
    return ok;
}

/* 注册回滚（注册成功但 epoll_ctl 失败等路径）：不摘表就会留下已 close 的 fd 与
   已 free 的 ctx，同号 fd 之后被复用时会被误当挂载完成事件、拿野指针当 ctx。 */
void unregister_async_mount_pipe(int fd) {
    pthread_mutex_lock(&g_async_mount_mutex);
    (void)async_mount_take_locked(fd);
    pthread_mutex_unlock(&g_async_mount_mutex);
}

/* 重试唤醒 eventfd：入队后立刻叫醒主循环跑一轮 retry_pending_mounts，
   而不是等 1s timer 的下一次 tick（视图迟到时最长差近 1s，直接体现为
   "代理视图比应用晚到"的观感延迟）。已由 injector_setup_epoll 注册进 epoll。 */
static int g_retry_wake_fd = -1;
static void retry_wake_main_loop(void) {
    if (g_retry_wake_fd < 0) return;
    uint64_t one = 1;
    ssize_t w = write(g_retry_wake_fd, &one, sizeof one); /* eventfd 写是原子的，可跨线程 */
    (void)w;
}

/* ══════════════ 毫秒到期定时器 + 配置重载去抖 ══════════════
 * 两件事都需要"毫秒级、事件驱动"的唤醒，1s 的周期 timer 等不来：
 *   ① 重试队列快档 20ms（vold 把 /storage/emulated 装配进应用 ns 的实测窗口
 *      是 ~140ms，1s 退避等于白等——真机 322 次挂载 avg=142ms 的由来）；
 *   ② 配置重载去抖窗口（500ms）。
 * 共用一个一次性 timerfd：每次臂到"两者中最近的那个到期时刻"，到点后跑一轮
 * 各自的到期逻辑再重新臂。定时器只做唤醒，不做决策（到期判定仍以
 * nsp_retry_next_due_ms / g_reload_due_ms 为准，幂等可重入）。 */
static int g_due_fd = -1;
/* 配置重载去抖状态。旧实现对 inotify 的每个事件立刻做一次全量重载
   （reload + 全量对账 + 72KB JSON 广播 + 重加全部 watch），真机实测被刷到
   **每秒 54 次**（sys.log「配置广播: 0 订阅者, JSON 大小 72469 字节」×54/s），
   而 v1 的 POST 挂载请求就在同一个单线程事件循环里排队——重载风暴直接把
   挂载应答饿住，这就是"挂载超时"的第二个成因。现在：窗口内只记
   「待重载 + 首个触发文件 + 合并事件数」，静默 NSP_RELOAD_DEBOUNCE_MS 后做
   **一次**重载，并打一条 INFO 说明触发源与合并数（旧实现重载完全静默，
   现场只能靠 broadcast 行反推，取证极难）。连续写入时窗口最多推迟
   NSP_RELOAD_MAX_DEFER_MS，保证"一直在写"也不会永远不重载。 */
#define NSP_RELOAD_DEBOUNCE_MS   500
#define NSP_RELOAD_MAX_DEFER_MS  2000
static int64_t g_reload_due_ms = 0;  /* 0 = 无待处理重载 */
static int64_t g_reload_first_ms = 0;
static char g_reload_trigger[64];    /* 窗口内第一个 .conf 事件的文件名 */
static unsigned g_reload_events = 0; /* 窗口内合并的 .conf 事件数 */
static unsigned long g_reload_total = 0; /* 生命周期内真实重载次数（日志序号） */

/* 把一次性定时器臂到"下一个该做事的时刻"（重试到期 / 重载窗口到期）。
   两者都空 → 解除定时（it_value 全 0）。可被任意线程调用（IPC 线程入队重试时
   也要臂一下），定时器本身只负责唤醒主循环。 */
static void arm_due_timer(void) {
    if (g_due_fd < 0) return;
    int64_t now = nsp_retry_now_ms();
    int64_t wait = -1;
    int64_t retry_wait = nsp_retry_next_due_ms(now);
    if (retry_wait >= 0) wait = retry_wait;
    if (g_reload_due_ms > 0) {
        int64_t rw = g_reload_due_ms - now;
        if (rw < 0) rw = 0;
        if (wait < 0 || rw < wait) wait = rw;
    }
    struct itimerspec its;
    memset(&its, 0, sizeof its);
    if (wait >= 0) {
        if (wait == 0) wait = 1; /* 0 表示"解除"，立即到期用 1ms 表达 */
        its.it_value.tv_sec = (time_t)(wait / 1000);
        its.it_value.tv_nsec = (long)((wait % 1000) * 1000000L);
    }
    timerfd_settime(g_due_fd, 0, &its, nullptr);
}

/* 登记一次"需要重载配置"的请求并臂上去抖窗口（滑动窗口：每个新事件把 deadline
   往后推 NSP_RELOAD_DEBOUNCE_MS，静默后才真正重载一次）。连续写入时 deadline 最多
   推到首个事件之后 NSP_RELOAD_MAX_DEFER_MS——否则"一直在写"会让重载永远不发生。
   trigger 只记**第一个**触发文件（定位"谁在写配置"靠它）。 */
static void injector_request_reload(const char* trigger, unsigned events) {
    int64_t now = nsp_retry_now_ms();
    if (g_reload_due_ms == 0) {
        g_reload_first_ms = now;
        snprintf(g_reload_trigger, sizeof(g_reload_trigger), "%s", trigger ? trigger : "(未知)");
        g_reload_events = 0;
    }
    g_reload_events += events ? events : 1;
    int64_t due = now + NSP_RELOAD_DEBOUNCE_MS;
    int64_t cap = g_reload_first_ms + NSP_RELOAD_MAX_DEFER_MS;
    g_reload_due_ms = due > cap ? cap : due;
    arm_due_timer();
}

void schedule_retry_mount(const char* pkg, int pid) {
    if (!nsp_retry_schedule(pkg, pid)) {
        LOG_DBG("重试队列已满，丢弃 %s(PID:%d) 的重试", pkg, pid);
        return;
    }
    LOG_DBG("加入重试队列: %s(PID:%d), 队列长度=%d, 已尝试=%d", pkg, pid, nsp_retry_count(),
            nsp_retry_attempts_of(pid));
    /* 立即叫醒主循环跑一轮（首次尝试 backoff=0，不叫醒就得等 1s tick），
       同时把毫秒定时器臂到该条目的下一次退避到期时刻（快档 20ms）。 */
    arm_due_timer();
    retry_wake_main_loop();
}

/* 挂载成功后清账（重试队列里该 pid 的尝试计数归零）。由 IPC 挂载线程与异步
   完成回调在**真正成功**时调用；派发成功不算成功。 */
void retry_mount_succeeded(int pid) {
    if (nsp_retry_done(pid)) LOG_DBG("挂载成功，清除 %d 的重试记账", pid);
}

const char* get_active_mnt_src() {
    if (!g_fuse_ready || g_global_fuse.fuse_pid <= 0) return nullptr;
    if (kill(g_global_fuse.fuse_pid, 0) != 0) return nullptr;
    if (faccessat(g_global_root_fd, g_global_fuse.mnt_path + 1, F_OK, 0) != 0) {
        LOG_DBG("FUSE 挂载点 g_global_fuse %s 不可达: %s", g_global_fuse.mnt_path, strerror(errno));
        return nullptr;
    }
    return g_global_fuse.mnt_path;
}

const char* get_media_mnt_src() {
    if (g_media_fuse.fuse_pid <= 0) return nullptr;
    if (kill(g_media_fuse.fuse_pid, 0) != 0) return nullptr;
    if (faccessat(g_global_root_fd, g_media_fuse.mnt_path + 1, F_OK, 0) != 0) {
        LOG_DBG("媒体 FUSE 挂载点 g_media_fuse %s 不可达: %s", g_media_fuse.mnt_path,
                strerror(errno));
        return nullptr;
    }
    return g_media_fuse.mnt_path;
}

void notify_fuses(int sig) {
    if (g_global_fuse.fuse_pid > 0 && kill(g_global_fuse.fuse_pid, sig) != 0 && errno != ESRCH)
        LOG_ERR("通知全局 FUSE 失败");
    if (g_media_fuse.fuse_pid > 0 && kill(g_media_fuse.fuse_pid, sig) != 0 && errno != ESRCH)
        LOG_ERR("通知媒体 FUSE 失败");
}

/* 建监听并挂到 epoll。返回是否**全部**成功；失败 loud 告警（此前静默吞掉
   返回值 → 规则改了不生效且无任何提示）。

   幂等刷新，不 close/重建 fd：inotify_add_watch 对**已存在**的 watch 直接返回
   同一个 wd（只改 mask，无新内核对象），所以重复调用是廉价的；而目录被替换
   （watch 收到 IN_IGNORED 后内核已删除该 watch）时再 add 会重新建立。旧实现
   每次重载都 close+inotify_init1+epoll_ctl+全量 add_watch，在配置重载风暴里
   （真机实测 54 次重载/秒）等于每秒重建 54 次监听器，纯属给单线程事件循环
   添堵——而 v1 的 POST 挂载请求就在同一个循环里排队。 */
static bool setup_inotify_watches(void) {
    if (g_inotify_fd < 0) {
        g_inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (g_inotify_fd < 0) {
            LOG_ERR("inotify_init1 失败: %s（配置热重载失效，改配置需重启）", strerror(errno));
            return false;
        }
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = g_inotify_fd};
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_inotify_fd, &ev) != 0) {
            LOG_ERR("inotify fd 挂入 epoll 失败: %s（配置热重载整体失效）", strerror(errno));
            return false;
        }
    }
    bool ok = true;
    int wd = inotify_add_watch(g_inotify_fd, CONFIG_DIR,
                               IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_TO | IN_DELETE);
    if (wd < 0) {
        LOG_ERR("inotify 监听 %s 失败: %s（该目录下配置变更不会热重载）", CONFIG_DIR,
                strerror(errno));
        ok = false;
    }
    config_lock_read();
    for (int i = 0; i < g_active_user_count; i++) {
        char dir_path[128];
        nsp_app_rule_dir(CONFIG_DIR, g_active_users[i], dir_path, sizeof(dir_path));
        mkdir(dir_path, 0755);
        int wd_u = inotify_add_watch(g_inotify_fd, dir_path,
                                     IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_TO |
                                         IN_DELETE);
        if (wd_u < 0) {
            LOG_ERR("inotify 监听 %s 失败: %s（该用户目录规则变更不会热重载）", dir_path,
                    strerror(errno));
            ok = false;
        }
    }
    config_unlock_read();
    return ok;
}

static void reload_injector_config() {
    /* 真读盘 + 活跃用户扫描（pm，最坏 800ms）放在写锁之外：写锁挡着本进程全部
       config 读者（pre-hook 判定、发布器、控制面查询），锁内读盘会把一次慢盘放大
       成整进程无响应；锁内只做解析与 COW 发布。 */
    NspCfgRec* recs = nullptr;
    int count = 0;
    config_read_view(INJECTOR_CONFIG_PATH, &recs, &count);
    config_lock_write();
    config_build_from_view(recs, count);
    config_unlock_write();
    config_free_view(recs, count);
    /* 系统应用表刷新（pm→内存+落盘 sys_pkgs.cache，供 fuse_daemon 只读消费；
       仅当类别段存在时查询，避免无谓 popen） */
    if (config_has_category_rules()) sys_pkg_refresh();
    setup_inotify_watches();
}

/* 崩溃诊断：只摊「本次守护进程启动之后」写进 fuse_crash.log 的 stderr。
   该文件跨启动 append（见 inject_global_fuse 的 O_APPEND 打开），直接把尾部
   16KB 交给现场，会把上一次启动的 linker 报错读成本次崩溃原因。起点用 spawn
   时记下的文件大小（crash_log_start），窗口计算见 crash_tail.h。 */
static void dump_crash_log_tail(off_t run_start) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/fuse_crash.log", LOG_DIR);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return;
    }
    const size_t cap = 16384;
    CrashTailWindow win;
    if (!crash_tail_window(st.st_size, run_start, cap, &win)) {
        close(fd);
        LOG_ERR("===== FUSE 崩溃诊断信息 =====");
        LOG_ERR("| 本次守护进程启动后 fuse_crash.log 无新增输出（起点偏移 %lld，当前大小 %lld）",
                (long long)run_start, (long long)st.st_size);
        LOG_ERR("===== 诊断结束 =====");
        return;
    }
    char buf[16384 + 1];
    size_t want = win.len < cap ? win.len : cap;
    if (lseek(fd, win.start, SEEK_SET) < 0) {
        close(fd);
        return;
    }
    ssize_t n = read(fd, buf, want);
    close(fd);
    if (n > 0) {
        buf[n] = '\0';
        char* p = buf;
        if (win.drop_first_line) {
            p = memchr(buf, '\n', (size_t)n);
            if (p)
                p++;
            else
                p = buf;
        }
        if (*p) {
            LOG_ERR("===== FUSE 崩溃诊断信息（仅本次启动后，起点偏移 %lld）=====",
                    (long long)win.start);
            char* line = p;
            while (line && *line) {
                char* nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                if (*line) LOG_ERR("| %s", line);
                if (nl)
                    line = nl + 1;
                else
                    break;
            }
            LOG_ERR("===== 诊断结束 =====");
        }
    }
}

typedef struct {
    int pipe_fd;
    pid_t child_pid;
} FuseReadyCtx;

static void remount_all_tracked(void);
static void maybe_reconcile_global_replace(void);
static void grepl_reconcile_reset(void);

void handle_fuse_ready_event(void* ptr) {
    FuseReadyCtx* ctx = (FuseReadyCtx*)ptr;
    char buf;
    ssize_t r = read(ctx->pipe_fd, &buf, 1);
    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, ctx->pipe_fd, nullptr);
    close(ctx->pipe_fd);
    if (r == 1) {
        LOG_DBG("FUSE 守护进程成功通知就绪，执行共享视图转换");
        if (ns_make_shared(g_global_fuse.pid, g_global_fuse.mnt_path) != 0) {
            LOG_ERR("FUSE 共享传播设置失败: make_shared(%s)", g_global_fuse.mnt_path);
        } else {
            if (faccessat(g_global_root_fd, g_global_fuse.mnt_path + 1, F_OK, 0) != 0) {
                LOG_ERR("FUSE 就绪验证失败: stat(%s) → %s", g_global_fuse.mnt_path,
                        strerror(errno));
                /* ECONNREFUSED(=fc->conn_error)/ENOTCONN(=fc->connected 断开)：
                   区分两类根因——daemon 进程死亡(崩溃/被杀) vs 进程存活但连接被内核中止(INIT 回包被拒) */
                if (errno == ECONNREFUSED || errno == ENOTCONN) {
                    if (g_global_fuse.fuse_pid > 0 && kill(g_global_fuse.fuse_pid, 0) != 0) {
                        /* ① daemon 已退出：连接随进程死亡而中止 */
                        LOG_ERR("fuse_daemon(pid=%d) 已退出，连接随之中止（崩溃或被杀）",
                                g_global_fuse.fuse_pid);
                        dump_crash_log_tail(g_global_fuse.crash_log_start);
                    } else {
                        /* ② daemon 存活但连接死亡：内核拒绝了 INIT 回包（fc->conn_error）。
                           典型：DAX 内核把回包 legacy bit31 误读为 FUSE_MAP_ALIGNMENT，
                           或回包请求了内核无法兑现的能力位——可对照 fuse_daemon 的
                           “FUSE 协商详情 (capable/want)”日志定位具体位 */
                        LOG_ERR("fuse_daemon 进程存活但 FUSE 连接被内核中止（fc->conn_error）");
                        LOG_ERR(
                            "→ 判定: 内核拒绝了 INIT 回包（DAX 内核误读 legacy bit31 为 FUSE_MAP_ALIGNMENT，或请求位不被接受）");
                        /* 回退处理：杀掉存活 daemon，后续以 --no-passthrough 标准 FUSE 模式重启，
                           规避透传协商位导致回包再次被拒 */
                        g_no_passthrough_fallback = true;
                        LOG("回退处理: 透传协商异常，改用 --no-passthrough 标准 FUSE 模式重启");
                        if (g_global_fuse.fuse_pid > 0) {
                            kill(g_global_fuse.fuse_pid, SIGTERM);
                            for (int w = 0; w < 50; w++) {
                                if (kill(g_global_fuse.fuse_pid, 0) != 0) break;
                                usleep(20000);
                            }
                            if (g_global_fuse.fuse_pid > 0 && kill(g_global_fuse.fuse_pid, 0) == 0)
                                kill(g_global_fuse.fuse_pid, SIGKILL);
                        }
                        dump_crash_log_tail(g_global_fuse.crash_log_start);
                    }
                    g_fuse_ready = 0;
                    g_pending_remount = 1;
                    seconds_until_next_scan = 0;
                }
            } else {
                g_fuse_ready = 1;
                LOG_DBG("FUSE 就绪确认: %s", g_global_fuse.mnt_path);
                /* 全局替换模式：FUSE 就绪后立即尝试把 emulated 族根替换为代理视图。
                   此时 vold 可能尚未建立族根（用户未启动）——replace 返回 1 表示
                   「尚未就绪」，由周期对账退避重试；旧实现在这种情况下静默成功、
                   此后永不重试，真机上就是「开机后 v2/v3 不生效」。 */
                if (inject_is_global_replace()) {
                    grepl_reconcile_reset();
                    maybe_reconcile_global_replace();
                }
            }
        }
        /* 启动扫描：injector 重启后，已注入应用命名空间里的旧挂载仍指向随旧 daemon
           中止的 FUSE 连接（访问一律 ENOTCONN）。追踪表此时是空的，崩溃恢复路径覆盖
           不到它们，只能靠这里扫一遍。健康进程零行为变化（判据见
           repair_stale_app_mounts_at_startup）。 */
        if (g_pending_startup_scan) {
            g_pending_startup_scan = 0;
            /* 被动模式只处理新 IPC 通知，避免存量逐进程修复阻塞启动；旧应用需重启。 */
            if (!g_passive_mode) {
                int repaired = repair_stale_app_mounts_at_startup();
                if (repaired > 0) LOG("启动扫描: 修复了 %d 个连接已断的应用挂载", repaired);
            } else {
                LOG_DBG("被动模式: 跳过存量应用启动修复，旧应用需重启或重新 IPC 通知");
            }
        }
        if (g_pending_first_scan) {
            g_pending_first_scan = 0;
            seconds_until_next_scan = 0;
        }
        if (nsp_retry_count() > 0) {
            seconds_until_next_scan = 0;
        }
        if (g_pending_remount) {
            remount_all_tracked();
        }
    } else {
        LOG_ERR("FUSE 异步启动失败，管道未收到就绪字符");
        dump_crash_log_tail(g_global_fuse.crash_log_start);
    }
    free(ctx);
}

static void inject_global_fuse() {
    if (g_global_fuse.disabled) return;
    if (__sync_lock_test_and_set(&g_fuse_starting, 1)) {
        LOG_DBG("FUSE 已经在启动中，跳过重复启动");
        return;
    }
    if (g_global_fuse.fuse_pid > 0) {
        kill(g_global_fuse.fuse_pid, SIGTERM);
        for (int wait_ms = 0; wait_ms < 500; wait_ms += 10) {
            if (kill(g_global_fuse.fuse_pid, 0) != 0) break;
            usleep(10000);
        }
        if (kill(g_global_fuse.fuse_pid, 0) == 0) {
            kill(g_global_fuse.fuse_pid, SIGKILL);
            usleep(50000);
        }
        int status;
        waitpid(g_global_fuse.fuse_pid, &status, WNOHANG);
    }
    ns_force_umount_stale(g_global_fuse.pid, g_global_fuse.mnt_path);
    for (int verify = 0; verify < 20; verify++) {
        if (ns_is_mounted(g_global_fuse.pid, g_global_fuse.mnt_path, nullptr) <= 0) break;
        usleep(20000);
    }
    ns_umount_and_rmdir(g_global_fuse.pid, g_global_fuse.mnt_path);
    int ready_pipe[2];
    if (pipe2(ready_pipe, O_CLOEXEC | O_NONBLOCK) == -1) {
        __sync_lock_release(&g_fuse_starting);
        return;
    }
    /* fuse_crash.log 在 fork 之前打开并记下当前大小：daemon 的 stderr 追加写这个
       文件，记下的偏移就是「本次启动」的起点，诊断只读它之后的内容（历史启动的
       报错不能被读成本次崩溃原因）。子进程直接复用这个 fd。 */
    int crash_fd =
        open(LOG_DIR "/fuse_crash.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    g_global_fuse.crash_log_start = -1;
    if (crash_fd >= 0) {
        struct stat crash_st;
        if (fstat(crash_fd, &crash_st) == 0) g_global_fuse.crash_log_start = crash_st.st_size;
    }
    pid_t child = fork();
    if (child == -1) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        if (crash_fd >= 0) close(crash_fd);
        __sync_lock_release(&g_fuse_starting);
        return;
    }
    if (child == 0) {
        close(ready_pipe[0]);
        sigset_t empty_mask;
        sigemptyset(&empty_mask);
        pthread_sigmask(SIG_SETMASK, &empty_mask, nullptr);
        char ns_path[64];
        snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", g_global_fuse.pid);
        int fd = open(ns_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) _exit(10);
        if (setns(fd, CLONE_NEWNS) != 0) {
            close(fd);
            _exit(11);
        }
        close(fd);
        if (mkdir(g_global_fuse.mnt_path, 0755) != 0 && errno != EEXIST) _exit(12);
        /* stderr 接到父进程开好的 crash_fd：crash_handler 的 backtrace 帧写
           stderr，崩溃后由 dump_crash_log_tail(crash_log_start) 从「本次启动」
           的偏移开始摊开（O_CREAT 保证首次崩溃即能捕获完整 backtrace）。 */
        if (crash_fd >= 0) {
            dup2(crash_fd, STDERR_FILENO);
            dup2(crash_fd, STDOUT_FILENO);
            close(crash_fd);
        }
        char exe[256];
        snprintf(exe, sizeof(exe), "%s/fuse_daemon", get_self_dir());
        char arg_ready[64];
        snprintf(arg_ready, sizeof(arg_ready), "--ready-fd=%d", ready_pipe[1]);
        fcntl(ready_pipe[1], F_SETFD, 0);
        /* 日志级别透传：daemon 侧默认即 INFO（g_min_log_level），默认级别不占参数位 */
        const char* log_lvl = NULL;
        if (g_min_log_level == LOG_DEBUG)
            log_lvl = "debug";
        else if (g_min_log_level == LOG_ERROR)
            log_lvl = "error";
        else if (g_min_log_level == LOG_WARN)
            log_lvl = "warn";
        char* args[32];
        int ai = 0;
        args[ai++] = "fuse_daemon";
        args[ai++] = g_global_fuse.mnt_path;
        /* --root= 必须显式传递：vfs_bpf_setup 直接拼接 g_real_root（无 common
           回退），缺省会导致 backing 路径成虚拟路径、open 恒 ENOENT */
        args[ai++] = "--root=" STORAGE_BASE;
        args[ai++] = "--rules=" INJECTOR_CONFIG_PATH;
        if (g_strip_o_direct) args[ai++] = "--strip-o-direct";
        if (g_no_passthrough_fallback) args[ai++] = "--no-passthrough";
        if (g_crash_test) args[ai++] = "--crash-test";
        args[ai++] = arg_ready;
        if (log_lvl) args[ai++] = (char*)log_lvl;
        char threads_arg[32];
        if (g_global_cfg.fuse_threads != 0) {
            /* [GLOBAL] FUSE_THREADS 非 0 时显式下发；0 表示交给 daemon 按核数取默认 */
            snprintf(threads_arg, sizeof threads_arg, "--fuse-threads=%d",
                     g_global_cfg.fuse_threads);
            args[ai++] = threads_arg;
        }
        /* FUSE_EXTRA_ARGS 分词追加：守卫必须按「尾部固定项数」预留——尾部还要
           无条件追加 -f / -o / 挂载选项 / NULL 共 4 项。旧守卫 ai < 31 会让
           末条 token 落到 args[31] 之后（FUSE_EXTRA_ARGS 上限 512 字节，24 个
           空格分隔 token 轻易达到），fork 后子进程栈损坏、execv 参数不可控
           （历史审计项 A11：分词守卫越界）。超限 loud 告警并截断。 */
        const int fuse_args_cap = (int)(sizeof args / sizeof args[0]);
        const int fuse_args_tail = 4; /* -f / -o / 挂载选项 / NULL */
        bool extra_truncated = false;
        if (g_global_cfg.fuse_extra_args[0]) {
            char extra_copy[512];
            strncpy(extra_copy, g_global_cfg.fuse_extra_args, sizeof(extra_copy) - 1);
            extra_copy[sizeof(extra_copy) - 1] = '\0';
            /* strtok_r：bionic 无条件弃用 strtok（非线程安全）；此处非嵌套使用，
               换 strtok_r 行为等价（save 为本次分割的显式游标） */
            char* save = nullptr;
            char* tok = strtok_r(extra_copy, " ", &save);
            while (tok) {
                if (ai >= fuse_args_cap - fuse_args_tail) {
                    extra_truncated = true;
                    break;
                }
                args[ai++] = tok;
                tok = strtok_r(nullptr, " ", &save);
            }
        }
        if (extra_truncated) {
            /* stderr 已重定向至 fuse_crash.log（见上），子进程内不做日志环写入 */
            fprintf(stderr, "[injector] FUSE_EXTRA_ARGS 超出参数上限（%d 项），已截断: %s\n",
                    fuse_args_cap - fuse_args_tail, g_global_cfg.fuse_extra_args);
        }
        args[ai++] = "-f";
        args[ai++] = "-o";
        /* noatime 对齐 Android 原生 FUSE（/mnt/user/0/emulated 挂载即 noatime,lazytime）：
           atime 更新是纯写放大（媒体扫描/备份工具依赖 mtime 而非 atime） */
        args[ai++] = "allow_other,auto_cache,noatime,fsname=fuse_daemon,subtype=fuse_daemon";
        args[ai] = nullptr;
        setenv("LD_LIBRARY_PATH", get_self_dir(), 1);
        execv(exe, args);
        _exit(13);
    }
    close(ready_pipe[1]);
    if (crash_fd >= 0) close(crash_fd);
    g_global_fuse.fuse_pid = child;
    FuseReadyCtx* ctx = malloc(sizeof(FuseReadyCtx));
    if (ctx) {
        ctx->pipe_fd = ready_pipe[0];
        ctx->child_pid = child;
        struct epoll_event ev_ready = {.events = EPOLLIN | EPOLLONESHOT, .data.fd = ready_pipe[0]};
        epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, ready_pipe[0], &ev_ready);
        register_fuse_ready_pipe(ready_pipe[0], ctx);
    } else {
        close(ready_pipe[0]);
    }
    __sync_lock_release(&g_fuse_starting);
}

static void inject_media_fuse() {
    if (inject_is_global_replace()) return; /* 新挂载方案（全局替换）无需媒体专属 FUSE */
    if (g_media_fuse.disabled) return;
    if (g_media_fuse.fuse_pid > 0) {
        kill(g_media_fuse.fuse_pid, SIGTERM);
        for (int wait_ms = 0; wait_ms < 500; wait_ms += 10) {
            if (kill(g_media_fuse.fuse_pid, 0) != 0) break;
            usleep(10000);
        }
        if (kill(g_media_fuse.fuse_pid, 0) == 0) {
            kill(g_media_fuse.fuse_pid, SIGKILL);
            usleep(50000);
        }
        int status;
        waitpid(g_media_fuse.fuse_pid, &status, WNOHANG);
    }
    ns_force_umount_stale(g_media_fuse.pid, g_media_fuse.mnt_path);
    for (int verify = 0; verify < 20; verify++) {
        if (ns_is_mounted(g_media_fuse.pid, g_media_fuse.mnt_path, nullptr) <= 0) break;
        usleep(20000);
    }
    ns_umount_and_rmdir(g_media_fuse.pid, g_media_fuse.mnt_path);
    int ready_pipe[2];
    if (pipe2(ready_pipe, O_CLOEXEC | O_NONBLOCK) == -1) return;
    /* 同全局实例：fork 前打开 crash log 并记下偏移，子进程只管接 stderr */
    int crash_fd =
        open(LOG_DIR "/fuse_crash.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    g_media_fuse.crash_log_start = -1;
    if (crash_fd >= 0) {
        struct stat crash_st;
        if (fstat(crash_fd, &crash_st) == 0) g_media_fuse.crash_log_start = crash_st.st_size;
    }
    pid_t child = fork();
    if (child == -1) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        if (crash_fd >= 0) close(crash_fd);
        return;
    }
    if (child == 0) {
        close(ready_pipe[0]);
        sigset_t empty_mask;
        sigemptyset(&empty_mask);
        pthread_sigmask(SIG_SETMASK, &empty_mask, nullptr);
        char ns_path[64];
        snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", g_media_fuse.pid);
        int fd = open(ns_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) _exit(10);
        if (setns(fd, CLONE_NEWNS) != 0) {
            close(fd);
            _exit(11);
        }
        close(fd);
        if (mkdir(g_media_fuse.mnt_path, 0755) != 0 && errno != EEXIST) _exit(12);
        /* stderr 接到父进程开好的 crash_fd：crash_handler 的 backtrace 帧写
           stderr，崩溃后由 dump_crash_log_tail(crash_log_start) 从「本次启动」
           的偏移开始摊开（O_CREAT 保证首次崩溃即能捕获完整 backtrace）。 */
        if (crash_fd >= 0) {
            dup2(crash_fd, STDERR_FILENO);
            dup2(crash_fd, STDOUT_FILENO);
            close(crash_fd);
        }
        char exe[256];
        snprintf(exe, sizeof(exe), "%s/fuse_daemon", get_self_dir());
        char arg_ready[64];
        snprintf(arg_ready, sizeof(arg_ready), "--ready-fd=%d", ready_pipe[1]);
        fcntl(ready_pipe[1], F_SETFD, 0);
        /* 日志级别透传：daemon 侧默认即 INFO，默认级别不占参数位 */
        const char* log_lvl = NULL;
        if (g_min_log_level == LOG_DEBUG)
            log_lvl = "debug";
        else if (g_min_log_level == LOG_ERROR)
            log_lvl = "error";
        else if (g_min_log_level == LOG_WARN)
            log_lvl = "warn";
        char* args[32];
        int ai = 0;
        args[ai++] = "fuse_daemon";
        args[ai++] = g_media_fuse.mnt_path;
        /* --root= 必须显式传递（同全局实例，见上） */
        args[ai++] = "--root=" STORAGE_BASE;
        args[ai++] = "--rules=" INJECTOR_CONFIG_PATH;
        if (g_strip_o_direct) args[ai++] = "--strip-o-direct";
        if (g_no_passthrough_fallback) args[ai++] = "--no-passthrough";
        if (g_crash_test) args[ai++] = "--crash-test";
        args[ai++] = arg_ready;
        if (log_lvl) args[ai++] = (char*)log_lvl;
        char threads_arg[32];
        if (g_global_cfg.fuse_threads != 0) {
            /* [GLOBAL] FUSE_THREADS 非 0 时显式下发；0 表示交给 daemon 按核数取默认 */
            snprintf(threads_arg, sizeof threads_arg, "--fuse-threads=%d",
                     g_global_cfg.fuse_threads);
            args[ai++] = threads_arg;
        }
        args[ai++] = "--no-passthrough";
        args[ai++] = "--media-fuse";

        /* ============== 核心改动：在启动参数中强制追加禁用沙盒标志 ============== */
        args[ai++] = "--disable-sandbox";

        args[ai++] = "-f";
        args[ai++] = "-o";
        args[ai++] = "allow_other,auto_cache,noatime,fsname=fuse_daemon,subtype=fuse_media_daemon";
        args[ai] = nullptr;
        setenv("LD_LIBRARY_PATH", get_self_dir(), 1);
        execv(exe, args);
        _exit(13);
    }
    close(ready_pipe[1]);
    if (crash_fd >= 0) close(crash_fd);
    g_media_fuse.fuse_pid = child;
    close(ready_pipe[0]);
}

static int cleanup_cb(int pid, const char* cmd, void* data) {
    (void)data;
    if (!is_process_safe_to_inject(cmd)) return 0;
    uid_t uid = get_app_uid(pid);
    char target_path[128];
    get_target_storage_path(uid, target_path, sizeof(target_path));
    char backup_path[PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/storage");
    bool has_backup = ns_is_mounted(pid, backup_path, nullptr) > 0;
    bool has_fuse = (ns_is_mounted(pid, target_path, "fuse.fuse_daemon") > 0 ||
                     ns_is_mounted(pid, target_path, "fuse_daemon") > 0);
    if (!has_backup && !has_fuse) return 0;
    cleanup_app_mounts(pid, target_path, backup_path, uid);
    return 0;
}

static void cleanup_all_target_apps() {
    fast_pid_each(cleanup_cb, nullptr);
}

/* FUSE 崩溃后的重启序列：等旧实例退出 → 卸载并复核 → fork 新实例 → 扫全进程清理残留。
 * 整段是秒级慢活（10ms×50 轮询 + 50ms + 20×20ms 复核 + 全进程表遍历），只能跑在
 * 恢复 worker 上，跑完由 worker 写就绪 eventfd 通知事件循环。
 * 「重挂所有追踪应用」的标记由事件循环在发请求时就置好（见 check_and_recover_fuse）：
 * 新实例的就绪事件一定晚于这个标记，若等 worker 回报才置标记，就绪事件可能已经过去，
 * 重挂会一直等到下一次 FUSE 就绪（追踪应用停在断掉的旧挂载上）。 */
static void injector_fuse_recover_cb(void* ctx) {
    (void)ctx;
    force_recover_tracked_mounts();
    inject_global_fuse();
    if (g_global_fuse.fuse_pid > 0) cleanup_all_target_apps();
}

/* 崩溃恢复重挂的计数：只统计真正挂上的应用，失败另有逐条日志 */
static int g_remount_done;

static int remount_cb(int pid, const char* cmd, void* data) {
    if (!is_process_safe_to_inject(cmd)) return 0;
    uid_t uid = get_app_uid(pid);
    if (is_target_app(cmd, uid, pid, false)) {
        const char* mnt_src = (const char*)data;
        char pkg[256];
        strncpy(pkg, cmd, sizeof(pkg) - 1);
        pkg[sizeof(pkg) - 1] = '\0';
        char* colon = strchr(pkg, ':');
        if (colon) *colon = '\0';
        if (perform_app_mount(pkg, pid, uid, mnt_src, "FUSE崩溃恢复重挂") == 0) {
            g_remount_done++;
        } else {
            LOG_DBG("FUSE 崩溃恢复重挂失败: %s(PID:%d)", pkg, pid);
        }
    }
    return 0;
}

static void remount_all_tracked() {
    const char* mnt_src = get_active_mnt_src();
    if (!mnt_src) {
        LOG_DBG("FUSE 尚未就绪，推迟重挂所有追踪应用");
        return;
    }
    struct timespec ts_start;
    struct timespec ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    g_remount_done = 0;
    LOG("FUSE 崩溃恢复: 开始重挂所有目标应用");
    /* PID 缓存记录的是「本进程已经处理过的 pid」，命中即跳过回调。守护进程崩溃后
       这些 pid 的挂载连接已经断了，缓存却仍把它们当已处理——不清缓存，遍历只看得到
       崩溃后新起的进程，活着的应用一个都不会重挂。 */
    fast_pid_cache_clear();
    fast_pid_each(remount_cb, (void*)mnt_src);
    g_pending_remount = 0;
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    long elapsed_ms = (ts_end.tv_sec - ts_start.tv_sec) * 1000L +
                      (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000L;
    LOG("FUSE 崩溃恢复重挂完成: 重挂 %d 个（用时 %ldms）", g_remount_done, elapsed_ms);
}

/* 受管子进程的退出状态留档与复核见 reaped_managed.{h,c}：通用收尸
   （reap_zombies 的 waitpid(-1)）会抢先取走 fuse_daemon 的僵尸，恢复路径不能只
   靠 waitpid(pid)——否则 ECHILD 会让崩溃现场不再进日志环 */

static void check_and_recover_fuse() {
    if (g_global_fuse.disabled || g_global_fuse.pid <= 0) return;
    if (g_global_fuse.fuse_pid > 0 && kill(g_global_fuse.fuse_pid, 0) != 0) {
        g_fuse_ready = 0;
        int status = 0;
        if (reaped_managed_exited(g_global_fuse.fuse_pid, &status)) dump_crash_log_tail(g_global_fuse.crash_log_start);
        g_global_fuse.fuse_pid = 0;
        time_t now = time(nullptr);
        if (now - g_global_fuse.last_crash_time < 60)
            g_global_fuse.crash_count++;
        else
            g_global_fuse.crash_count = 1;
        g_global_fuse.last_crash_time = now;
        if (g_global_fuse.crash_count > 5) {
            g_global_fuse.disabled = true;
            /* 全局替换模式：崩溃超限禁用 FUSE 前必须恢复系统 emulated 视图，
               避免系统停留在失效的代理 bind 上 */
            if (inject_is_global_replace()) {
                LOG("FUSE 崩溃超限，恢复系统 emulated 视图");
                ns_global_restore_system(g_global_fuse.pid, GLOBAL_BACKUP_ROOT);
            }
            /* 崩溃超限仍无法恢复正常：核心 FUSE 已不可用，injector 自动退出
               （主循环退出后 do_cleanup 会终结残留 daemon 并完成卸载） */
            LOG_ERR("FUSE 连续崩溃 %d 次仍无法恢复，injector 自动退出", g_global_fuse.crash_count);
            g_should_exit = 1;
            return;
        }
        /* 重启序列是秒级慢活，必须移出事件循环：循环同时承载 pre-hook 判定、
           挂载派发与 IPC ACK，一次慢恢复会让这段时间里的所有启动走 fail-open。
           重挂标记在这里就置好——新实例的就绪事件晚于本次崩溃，就绪处理器会消费它；
           若等 worker 回报再置，就绪事件可能已经过去，重挂会被无限推迟。
           worker 起不来时按旧行为内联执行——宁可慢一次也不能丢恢复。 */
        g_pending_remount = 1;
        if (!nsp_fuse_recover_request()) {
            LOG_WRN("FUSE 恢复线程不可用：重启序列回退到事件循环内联执行");
            injector_fuse_recover_cb(nullptr);
        }
    }

    /* 新挂载方案（全局替换模式）：媒体专属 FUSE 仅传统逐应用挂载方案需要。
       全局替换下 /storage/emulated 已整体由全局 FUSE 提供代理视图，媒体模块
       自动继承，无需专属 FUSE——整体跳过启动/崩溃恢复/热重载终结管理。 */
    if (inject_is_global_replace()) return;

    /* 
     * 媒体 FUSE 专属崩溃恢复：
     * 只有当 com.android.providers.media.module 仍是注入目标时才拉起。
     */
    if (g_media_fuse.fuse_pid > 0 && kill(g_media_fuse.fuse_pid, 0) != 0) {
        (void)reaped_managed_exited(g_media_fuse.fuse_pid, nullptr);
        g_media_fuse.fuse_pid = 0;
        time_t now = time(nullptr);
        if (now - g_media_fuse.last_crash_time < 60)
            g_media_fuse.crash_count++;
        else
            g_media_fuse.crash_count = 1;
        g_media_fuse.last_crash_time = now;
        if (g_media_fuse.crash_count > 5) {
            g_media_fuse.disabled = true;
            return;
        }
        if (!inject_is_global_replace() && is_media_module_injected_target()) {
            LOG("专用媒体 FUSE 异常退出，执行重新拉起任务");
            inject_media_fuse();
        }
    } else if (g_media_fuse.fuse_pid <= 0 && !g_media_fuse.disabled && g_fuse_ready &&
               !inject_is_global_replace()) {
        /* 
         * 媒体 FUSE 惰性启动：
         * 初始时未启动，在定时轮询中检测到 com.android.providers.media.module 变动为注入目标时，惰性启动媒体 FUSE。
         * 全局替换模式下无需媒体专属 FUSE（全局 FUSE 已提供代理视图）。
         */
        if (is_media_module_injected_target()) {
            LOG("惰性启动媒体 FUSE 实例 (com.android.providers.media.module 专属)");
            inject_media_fuse();
        }
    } else if (g_media_fuse.fuse_pid > 0 && !is_media_module_injected_target()) {
        /*
         * 热重载安全防御：
         * 媒体组件不再是注入目标时，安全终结其专属 FUSE，防止挂载空转。
         */
        LOG("配置变更：媒体组件不再是注入目标。正在终结专属媒体 FUSE...");
        kill(g_media_fuse.fuse_pid, SIGTERM);
        (void)reaped_managed_exited(g_media_fuse.fuse_pid, nullptr);
        g_media_fuse.fuse_pid = 0;
        ns_force_umount_stale(g_media_fuse.pid, g_media_fuse.mnt_path);
    }
}

typedef struct {
    char cmdline[256];
    int pid;
    uid_t uid;
    const char* mnt_src;
} MountTask;

static pid_t g_zygote_pids[4] = {0};
static int g_zygote_count = 0;

static void find_zygotes() {
    g_zygote_count = 0;
    DIR* dir = opendir("/proc");
    if (!dir) return;
    struct dirent* de;
    while ((de = readdir(dir)) != nullptr && g_zygote_count < 4) {
        if (de->d_type != DT_DIR) continue;
        if (!isdigit(de->d_name[0])) continue;
        int pid = atoi(de->d_name);
        char cmdline[64] = {0};
        if (proc_get_cmdline(pid, cmdline, sizeof(cmdline))) {
            if (strcmp(cmdline, "zygote") == 0 || strcmp(cmdline, "zygote64") == 0 ||
                strcmp(cmdline, "usap32") == 0 || strcmp(cmdline, "usap64") == 0) {
                g_zygote_pids[g_zygote_count++] = pid;
            }
        }
    }
    closedir(dir);
}

static bool is_parent_zygote(pid_t ppid) {
    for (int i = 0; i < g_zygote_count; i++) {
        if (g_zygote_pids[i] == ppid) return true;
    }
    return false;
}

int scan_zygote_children() {
    static bool first_scan = true;
    struct timespec ts_start, ts_zygote;
    all_apps_prune(); /* 扫描前清理全量缓存中的已死进程 */
    if (first_scan) clock_gettime(CLOCK_MONOTONIC, &ts_start);
    find_zygotes();
    if (first_scan) {
        clock_gettime(CLOCK_MONOTONIC, &ts_zygote);
        long elapsed = (ts_zygote.tv_sec - ts_start.tv_sec) * 1000 +
                       (ts_zygote.tv_nsec - ts_start.tv_nsec) / 1000000;
        LOG("初次扫描 - zygote查询完成, 耗时: %ldms", elapsed);
    }
#define MAX_CANDIDATES 8192
    typedef struct {
        int pid;
        uid_t uid;
        char cmdline[256];
    } ProcEntry;
    ProcEntry* entries = malloc(MAX_CANDIDATES * sizeof(ProcEntry));
    if (!entries) {
        LOG_ERR("无法 Zygote 候选进程分配临时扫描内存");
        return 0;
    }
    int entry_count = 0;
    int proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd < 0) {
        if (first_scan) {
            clock_gettime(CLOCK_MONOTONIC, &ts_zygote);
            long elapsed = (ts_zygote.tv_sec - ts_start.tv_sec) * 1000 +
                           (ts_zygote.tv_nsec - ts_start.tv_nsec) / 1000000;
            LOG("初次扫描 - open /proc失败, 耗时: %ldms", elapsed);
            first_scan = false;
        }
        free(entries);
        return 0;
    }
    char path[64];
    char status_buf[1024];
    char cmdline[256];
    char dent_buf[32768];
    while (true) {
        long nread = syscall(SYS_getdents64, proc_fd, dent_buf, sizeof(dent_buf));
        if (nread < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (nread == 0) break;
        for (long bpos = 0; bpos < nread && entry_count < MAX_CANDIDATES;) {
            struct linux_dirent64* d = (struct linux_dirent64*)(dent_buf + bpos);
            if (d->d_reclen == 0) break;
            bpos += d->d_reclen;
            if (d->d_type != DT_DIR) continue;
            if (!isdigit((unsigned char)d->d_name[0])) continue;
            int pid = atoi(d->d_name);
            if (pid < 1000) continue;
            if (!proc_get_cmdline(pid, cmdline, sizeof(cmdline))) continue;
            if (!is_process_safe_to_inject(cmdline)) continue;
            snprintf(path, sizeof(path), "/proc/%d/status", pid);
            int status_fd = open(path, O_RDONLY | O_CLOEXEC);
            if (status_fd < 0) continue;
            int status_n = read(status_fd, status_buf, sizeof(status_buf) - 1);
            close(status_fd);
            if (status_n <= 0) continue;
            status_buf[status_n] = '\0';
            int ppid = 0, uid = 0;
            char* line = status_buf;
            while (*line) {
                char* nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                if (line[0] == 'P' && line[1] == 'P' && line[2] == 'i' && line[3] == 'd' &&
                    line[4] == ':')
                    ppid = atoi(line + 5);
                else if (line[0] == 'U' && line[1] == 'i' && line[2] == 'd' && line[3] == ':')
                    uid = atoi(line + 4);
                if (!nl) break;
                line = nl + 1;
            }
            if (!is_parent_zygote(ppid)) continue;
            if (is_isolated_uid(uid)) continue;
            /* 全量应用 PID 缓存：无条件记录所有 zygote 子进程（含已停用/
               未追踪应用），规则变化时可快速定位 pid 立即挂载 */
            all_apps_upsert(pid, uid, cmdline);
            if (is_tracked(pid)) continue; /* 挂载候选仍跳过已追踪（避免重复处理） */
            strncpy(entries[entry_count].cmdline, cmdline,
                    sizeof(entries[entry_count].cmdline) - 1);
            entries[entry_count].cmdline[sizeof(entries[entry_count].cmdline) - 1] = '\0';
            entries[entry_count].pid = pid;
            entries[entry_count].uid = uid;
            entry_count++;
        }
    }
    close(proc_fd);
    if (first_scan) {
        clock_gettime(CLOCK_MONOTONIC, &ts_zygote);
        long elapsed = (ts_zygote.tv_sec - ts_start.tv_sec) * 1000 +
                       (ts_zygote.tv_nsec - ts_start.tv_nsec) / 1000000;
        LOG("初次扫描 - 扫描 /proc 完成, 收集 %d 个候选进程, 耗时: %ldms", entry_count, elapsed);
    }

#define MAX_ASYNC_MOUNTS_LOCAL 128
    int m_count = 0;
    MountTask* m_tasks = malloc(MAX_ASYNC_MOUNTS_LOCAL * sizeof(MountTask));
    if (!m_tasks) {
        free(entries);
        return 0;
    }

    config_lock_read();
    for (int i = 0; i < entry_count && m_count < MAX_ASYNC_MOUNTS_LOCAL; i++) {
        bool is_target =
            is_target_app_locked(entries[i].cmdline, entries[i].uid, entries[i].pid, false);
        if (inject_is_global_replace()) {
            /* 全局替换：目标应用已由全局替换自动获得代理视图，无需逐应用挂载；
               非目标应用仅 v2 主动卸载项目 FUSE 并还原系统视图（卸载优先），
               v3 不还原——默认全局挂载，故 v3 下不产生任何任务 */
            if (inject_restore_nontarget() && !is_target) {
                m_tasks[m_count].pid = entries[i].pid;
                m_tasks[m_count].uid = entries[i].uid;
                strncpy(m_tasks[m_count].cmdline, entries[i].cmdline,
                        sizeof(m_tasks[m_count].cmdline) - 1);
                m_tasks[m_count].cmdline[sizeof(m_tasks[m_count].cmdline) - 1] = '\0';
                m_count++;
            }
        } else if (is_target) {
            m_tasks[m_count].pid = entries[i].pid;
            m_tasks[m_count].uid = entries[i].uid;
            strncpy(m_tasks[m_count].cmdline, entries[i].cmdline,
                    sizeof(m_tasks[m_count].cmdline) - 1);
            m_tasks[m_count].cmdline[sizeof(m_tasks[m_count].cmdline) - 1] = '\0';
            m_count++;
        }
    }
    config_unlock_read();

    struct timespec ts_match_start, ts_match_end;
    if (first_scan) clock_gettime(CLOCK_MONOTONIC, &ts_match_start);
    if (m_count > 0) {
        for (int i = 0; i < m_count; i++) {
            struct timespec ts_mnt;
            if (first_scan) clock_gettime(CLOCK_MONOTONIC, &ts_mnt);

            if (inject_restore_nontarget()) {
                /* v2 增量还原：还原成功（或已还原跳过）后标记追踪，
                   后续周期扫描经 is_tracked 直接跳过，避免反复检测；
                   还原即解除注入状态（显式标志清除） */
                if (perform_app_restore(m_tasks[i].cmdline, m_tasks[i].pid, m_tasks[i].uid) >= 0) {
                    add_tracked(m_tasks[i].pid);
                    unmark_injected(m_tasks[i].pid);
                }
            } else if (!inject_is_global_replace()) {
                perform_app_mount(m_tasks[i].cmdline, m_tasks[i].pid, m_tasks[i].uid, nullptr,
                                  "主动扫描");
            }
            /* v3 不入队（上方分支），故不存在第三类任务 */

            if (first_scan) {
                struct timespec ts_mnt_end;
                clock_gettime(CLOCK_MONOTONIC, &ts_mnt_end);
                long el = (ts_mnt_end.tv_sec - ts_mnt.tv_sec) * 1000 +
                          (ts_mnt_end.tv_nsec - ts_mnt.tv_nsec) / 1000000;
                LOG_DBG("初次扫描 - %s %s(PID:%d) 完成, 耗时: %ldms",
                        inject_is_global_replace() ? "还原" : "挂载", m_tasks[i].cmdline,
                        m_tasks[i].pid, el);
            }
        }
    }
    if (first_scan) {
        clock_gettime(CLOCK_MONOTONIC, &ts_match_end);
        long elapsed = (ts_match_end.tv_sec - ts_match_start.tv_sec) * 1000 +
                       (ts_match_end.tv_nsec - ts_match_start.tv_nsec) / 1000000;
        LOG("初次扫描 - 配置匹配完成, %d 候选/%d 配置, 耗时: %ldms", m_count, g_app_cfg_count,
            elapsed);
        first_scan = false;
    }
    free(m_tasks);
    free(entries);
    return m_count;
}

void reap_zombies() {
    int status;
    pid_t reaped;
    while ((reaped = waitpid(-1, &status, WNOHANG)) > 0) {
        /* 受管子进程的退出状态留档，供恢复路径复核后 dump 崩溃 backtrace
           （见 reaped_managed.h）；其余子进程照常收割 */
        if (reaped != g_global_fuse.fuse_pid && reaped != g_media_fuse.fuse_pid) continue;
        reaped_managed_put(reaped, status);
    }
}

static void do_cleanup() {
    g_should_exit = 1;
    all_apps_cleanup(); /* 释放全量应用 PID 缓存 */
    if (g_inotify_fd >= 0) {
        close(g_inotify_fd);
        g_inotify_fd = -1;
    }
    force_recover_tracked_mounts();
    /* 全局替换模式：退出前先恢复系统 emulated 视图，再终结 FUSE。
       **不得**以 g_fuse_ready 为门控：FUSE 崩溃时 check_and_recover_fuse 会把它清 0，
       而那恰恰是最需要还原的时刻——跳过还原会让族根停在失效的代理 bind（或裸挂载点）
       上，关机后系统存储视图丢失。还原只依赖备份树与 FUSE 的 mount ns（pid），
       与 FUSE 是否存活无关；备份已被消费时重复调用是无害空操作。 */
    if (inject_is_global_replace() && g_global_fuse.pid > 0) {
        LOG("退出前恢复系统 emulated 视图");
        ns_global_restore_system(g_global_fuse.pid, GLOBAL_BACKUP_ROOT);
    }
    if (g_global_fuse.fuse_pid > 0) {
        kill(g_global_fuse.fuse_pid, SIGTERM);
        int status;
        for (int i = 0; i < 20; i++) {
            if (waitpid(g_global_fuse.fuse_pid, &status, WNOHANG) == g_global_fuse.fuse_pid) {
                g_global_fuse.fuse_pid = 0;
                break;
            }
            usleep(50000);
        }
        if (g_global_fuse.fuse_pid > 0) {
            kill(g_global_fuse.fuse_pid, SIGKILL);
            for (int i = 0; i < 10; i++) {
                if (waitpid(g_global_fuse.fuse_pid, &status, WNOHANG) == g_global_fuse.fuse_pid) {
                    g_global_fuse.fuse_pid = 0;
                    break;
                }
                usleep(10000);
            }
        }
        ns_force_umount_stale(g_global_fuse.pid, g_global_fuse.mnt_path);
        ns_umount_and_rmdir(g_global_fuse.pid, g_global_fuse.mnt_path);
    }
    if (g_media_fuse.fuse_pid > 0) {
        kill(g_media_fuse.fuse_pid, SIGTERM);
        int status;
        for (int i = 0; i < 20; i++) {
            if (waitpid(g_media_fuse.fuse_pid, &status, WNOHANG) == g_media_fuse.fuse_pid) {
                g_media_fuse.fuse_pid = 0;
                break;
            }
            usleep(50000);
        }
        if (g_media_fuse.fuse_pid > 0) {
            kill(g_media_fuse.fuse_pid, SIGKILL);
            waitpid(g_media_fuse.fuse_pid, &status, WNOHANG);
            g_media_fuse.fuse_pid = 0;
        }
        ns_force_umount_stale(g_media_fuse.pid, g_media_fuse.mnt_path);
        ns_umount_and_rmdir(g_media_fuse.pid, g_media_fuse.mnt_path);
    }
    config_publisher_cleanup(g_config_pub_fd);
    g_config_pub_fd = -1;
    cleanup_system_pkg_cache();
    log_close();
    config_destroy_lock();
    fast_pid_cleanup();
}

/* ============ 主入口编排（main 只按序调用，不含具体逻辑） ============
   下列 static 阶段/分发函数语义与原 main 内联代码逐行一致（纯搬运），
   便于单测与阅读：parse → early_init → setup_epoll → start_fuses →
   event_loop → shutdown。 */
typedef struct {
    int sig_fd;
    int timer_fd;
    int ipc_sock;
    /* 重试唤醒 eventfd：入队重试时立刻叫醒主循环跑一轮，而不是等 1s timer 的
       下一次 tick（挂载失败后视图迟到的那段最长可差近 1s，直接体现为
       "代理视图比应用晚到"的观感延迟） */
    int retry_fd;
    /* 毫秒到期定时器（一次性）：臂到「重试队列下一个到期」与「配置重载去抖窗口
       到期」中最近者。1s 周期 tick 装不下 20ms 快档退避与 200ms 去抖窗口。 */
    int due_fd;
} InjectorFds;

static void parse_cli_args(int argc, char* argv[], bool* start_passive_out) {
    bool start_passive = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0)
            g_min_log_level = LOG_DEBUG;
        else if (strcmp(argv[i], "error") == 0)
            g_min_log_level = LOG_ERROR;
        else if (strcmp(argv[i], "info") == 0)
            g_min_log_level = LOG_INFO;
        else if (strcmp(argv[i], "warn") == 0 || strcmp(argv[i], "warning") == 0)
            g_min_log_level = LOG_WARN;
        else if (strcmp(argv[i], "--strip-o-direct") == 0)
            g_strip_o_direct = true;
        else if (strcmp(argv[i], "--crash-test") == 0)
            g_crash_test = true;
        else if (strcmp(argv[i], "--passive") == 0 || strcmp(argv[i], "passive") == 0)
            start_passive = true;
        else if (strncmp(argv[i], "--inject-method=", 16) == 0) {
            const char* v = argv[i] + 16;
            if (strcmp(v, "v1") == 0)
                g_inject_method = INJECT_METHOD_V1;
            else if (strcmp(v, "v2") == 0)
                g_inject_method = INJECT_METHOD_V2;
            else if (strcmp(v, "v3") == 0)
                g_inject_method = INJECT_METHOD_V3;
            else {
                /* 静默回退 v1 会让生产配置与预期完全不符（尤其 service.sh），
                   故参数错值直接拒绝启动 */
                fprintf(stderr, "injector: 未知注入方法 '%s'（可用 v1/v2/v3）\n", v);
                exit(1);
            }
        }
    }
    *start_passive_out = start_passive;
}

/* P3：信号集唯一构造点（early_init 填充，setup_epoll 复用，禁两处手写重复） */
static sigset_t g_injector_sig_mask;

/* sys_pkgs 表的重读在**后台**跑：`pm list packages -s` 有 3s 预算，内联在事件循环里
   会让一次慢 pm 把 pre-hook 判定与挂载派发一起冻住（工具/用户连写配置时一轮接一轮）。
   表由 sys_pkg 自己的锁与 epoch 发布，延迟一轮刷新的代价只是短暂沿用旧表。 */
static void injector_sys_pkg_refresh_cb(void* ctx) {
    (void)ctx;
    if (config_has_category_rules()) sys_pkg_refresh();
}

static void injector_early_init(void) {
    /* 信号屏蔽须在 daemonize 之前（原 main 时序）：fork/setsid 期间不丢信号，
       signalfd 创建后统一经 epoll 分发 */
    sigemptyset(&g_injector_sig_mask);
    sigaddset(&g_injector_sig_mask, SIGINT);
    sigaddset(&g_injector_sig_mask, SIGTERM);
    sigaddset(&g_injector_sig_mask, SIGHUP);
    sigaddset(&g_injector_sig_mask, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &g_injector_sig_mask, nullptr);
    g_global_root_fd = open("/", O_RDONLY | O_PATH | O_CLOEXEC);
    escape_cgroup();
    /* 后台化经 nsp_util 公共库复用（保留 g_global_root_fd，禁私刻 fork 样板） */
    nsp_daemonize(g_global_root_fd);
    log_init("injector");
    /* 构建水印 + 设备环境进 sys.log（崩溃包归因用，失败不阻断启动） */
    nsp_log_build_info("injector");
    init_system_pkg_cache();
    config_init_lock();
    fast_pid_init();
    init_uid_map_cache();
    /* 装配异步刷新回调：在所有 init 之后、事件循环之前（此后才允许 request） */
    nsp_async_refresh_init(injector_sys_pkg_refresh_cb, nullptr);
}

static void injector_setup_epoll(InjectorFds* fds) {
    /* P3：复用 early_init 已构造的信号集；escape_cgroup 只保留 early_init
       open 后的那一次（原 main 入口处多余的一次不再重复） */
    g_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epoll_fd < 0) {
        PERROR("无法创建 epoll 实例");
        exit(1);
    }
    int sig_fd = signalfd(-1, &g_injector_sig_mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sig_fd < 0) {
        PERROR("无法创建 signalfd");
        exit(1);
    }
    struct epoll_event ev_sig = {.events = EPOLLIN, .data.fd = sig_fd};
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, sig_fd, &ev_sig);
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd < 0) {
        PERROR("无法创建 timerfd");
        exit(1);
    }
    struct itimerspec ts = {.it_interval = {.tv_sec = 1, .tv_nsec = 0},
                            .it_value = {.tv_sec = 1, .tv_nsec = 0}};
    timerfd_settime(timer_fd, 0, &ts, nullptr);
    struct epoll_event ev_timer = {.events = EPOLLIN, .data.fd = timer_fd};
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev_timer);
    int retry_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (retry_fd < 0) {
        PERROR("无法创建 eventfd");
        exit(1);
    }
    struct epoll_event ev_retry = {.events = EPOLLIN, .data.fd = retry_fd};
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, retry_fd, &ev_retry);
    g_retry_wake_fd = retry_fd;
    int due_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (due_fd < 0) {
        PERROR("无法创建到期定时器");
        exit(1);
    }
    struct epoll_event ev_due = {.events = EPOLLIN, .data.fd = due_fd};
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, due_fd, &ev_due);
    g_due_fd = due_fd; /* 初始不臂：it_value 全 0 = 解除定时 */
    /* 配置视图读取 worker：daemonize 之后、事件循环之前起（线程不能跨 fork）。
       没起来就退回内联读：宁可慢一次也不能丢重载。 */
    g_reload_ready_fd = nsp_reload_stage_start(INJECTOR_CONFIG_PATH);
    if (g_reload_ready_fd >= 0) {
        struct epoll_event ev_reload = {.events = EPOLLIN, .data.fd = g_reload_ready_fd};
        epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_reload_ready_fd, &ev_reload);
    } else {
        LOG_WRN("配置读取线程未启动：热重载的读盘仍内联在事件循环上");
    }
    /* FUSE 崩溃恢复 worker 同理：没起来就退回内联恢复。 */
    g_fuse_recover_fd = nsp_fuse_recover_start(injector_fuse_recover_cb, nullptr);
    if (g_fuse_recover_fd >= 0) {
        struct epoll_event ev_recover = {.events = EPOLLIN, .data.fd = g_fuse_recover_fd};
        epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_fuse_recover_fd, &ev_recover);
    } else {
        LOG_WRN("FUSE 恢复线程未启动：崩溃恢复的重启序列仍内联在事件循环上");
    }
    int ipc_sock = ipc_server_init();
    if (ipc_sock < 0) {
        PERROR("无法初始化 IPC 服务");
        exit(1);
    }
    struct epoll_event ev_ipc = {.events = EPOLLIN, .data.fd = ipc_sock};
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, ipc_sock, &ev_ipc);
    fds->sig_fd = sig_fd;
    fds->timer_fd = timer_fd;
    fds->ipc_sock = ipc_sock;
    fds->retry_fd = retry_fd;
    fds->due_fd = due_fd;
}

static void injector_start_fuses(bool start_passive) {
    g_config_pub_fd = config_publisher_init();
    strcpy(g_real_root, STORAGE_BASE);
    mkdir_recursive(BACKUP_DIR);
    /* 备份根收敛：v2/v3 全局替换备份树（GLOBAL_BACKUP_ROOT）与 v1 占位同处
       BACKUP_DIR 下，生命周期内此处预建一次，各 ns 操作内不再逐次建目录 */
    mkdir_recursive(GLOBAL_BACKUP_ROOT);
    /* 应用规则目录创建权归属 injector 单一进程：显式开启后，后续所有
       config_read_view 调用（启动 reload_injector_config + 热重载
       handle_pending_reload）均允许 mkdir App-rules / App-rules-<uid>；fuse_daemon/log_ctl 等
       只读加载方保持默认 false，杜绝伪用户目录固化 */
    config_set_allow_app_rules_mkdir(true);
    reload_injector_config();
    int wait_count = 0;
    while (faccessat(g_global_root_fd, "data/media/0", F_OK, 0) != 0 && wait_count < 120 &&
           !g_should_exit) {
        usleep(500000);
        wait_count++;
    }
    inject_global_fuse();
    if (g_global_fuse.fuse_pid <= 0) exit(1);

    if (!inject_is_global_replace() && is_media_module_injected_target()) {
        LOG("检测到 com.android.providers.media.module 在注入目标之列，正在启动专用媒体 FUSE 实例。");
        inject_media_fuse();
    } else {
        LOG_DBG("com.android.providers.media.module 未开启注入，跳过媒体 FUSE 实例的启动。");
    }

    g_pending_first_scan = 1;
    g_pending_startup_scan = 1;
    seconds_until_next_scan = 0;
    if (start_passive) {
        g_passive_mode = 1;
        LOG("被动监听模式启动");
    }
}

static void on_signal_event(int sig_fd) {
    struct signalfd_siginfo fdsi;
    ssize_t s = read(sig_fd, &fdsi, sizeof(struct signalfd_siginfo));
    if (s == sizeof(struct signalfd_siginfo)) {
        if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM) {
            LOG("收到终止信号 (%d)，执行退出...", fdsi.ssi_signo);
            g_should_exit = 1;
        } else if (fdsi.ssi_signo == SIGHUP) {
            LOG("收到规则重载指令 (SIGHUP)。");
            g_reload_config = 1;
        } else if (fdsi.ssi_signo == SIGCHLD) {
            reap_zombies();
        }
    }
}

static void maybe_periodic_scan(void) {
    if (!g_passive_mode || (inject_is_global_replace() && !g_global_replace_scanned_once)) {
        /* 被动模式下禁用周期扫描（新应用由 zygisk IPC 通知即时处理）；
           全局替换（v2/v3）仅在程序生命周期开始时执行一次兜底扫描——
           v2 用于还原存量非目标应用、v3 用于刷新全量应用 PID 缓存，
           之后不再反复周期检测 */
        if (seconds_until_next_scan > 0) {
            seconds_until_next_scan--;
        }
        if (seconds_until_next_scan == 0) {
            int found_now = scan_zygote_children();
            if (inject_is_global_replace()) {
                g_global_replace_scanned_once = true;
            }
            if (found_now > 0) {
                g_last_scan_found = true;
                g_scan_interval_seconds = 30;
            } else {
                if (g_last_scan_found) {
                    g_last_scan_found = false;
                    g_scan_interval_seconds = 60;
                } else {
                    if (g_scan_interval_seconds < 300) {
                        g_scan_interval_seconds = (g_scan_interval_seconds * 3) / 2;
                        if (g_scan_interval_seconds > 300) g_scan_interval_seconds = 300;
                    }
                }
            }
            seconds_until_next_scan = g_scan_interval_seconds;
        }
    }
}

/* 读取 stat 的 PPid/starttime；comm 可含空格和 ')'，不能按空白拆整行。 */
static bool retry_proc_identity(int pid, int* ppid, unsigned long long* starttime) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    char* text = read_file_dynamic(path, NULL, 4096);
    if (!text) return false;
    char* end = NULL;
    errno = 0;
    long actual_pid = strtol(text, &end, 10);
    char* close = strrchr(text, ')');
    bool ok = errno == 0 && actual_pid == pid && end && end[0] == ' ' && end[1] == '(' &&
              close && close > end && close[1] == ' ';
    char* cursor = ok ? close + 2 : NULL;
    for (int field = 3; ok && field <= 22; field++) {
        while (*cursor == ' ') cursor++;
        char* token_end = cursor;
        while (*token_end && !isspace((unsigned char)*token_end)) token_end++;
        ok = token_end != cursor;
        if (!ok) break;
        if (field == 4 || field == 22) {
            for (char* p = cursor; p < token_end; p++) {
                if (!isdigit((unsigned char)*p)) { ok = false; break; }
            }
            errno = 0;
            unsigned long long value = strtoull(cursor, &end, 10);
            ok = ok && errno == 0 && end == token_end;
            if (field == 4) {
                ok = ok && value > 0 && value <= INT_MAX;
                if (ok) *ppid = (int)value;
            } else {
                ok = ok && value > 0;
                if (ok) *starttime = value;
            }
        }
        cursor = token_end;
    }
    free(text);
    return ok;
}

typedef struct {
    int ppid, parent_ppid;
    unsigned long long start, parent_start;
    dev_t dev, parent_dev;
    ino_t ino, parent_ino;
} RetryMountIdentity;

/* /storage/emulated 可能早已存在于 zygote ns，不能拿它证明已隔离。
 * 只接受可识别的当前 zygote/USAP 父进程且 ns 不同；未知/重挂靠有界重试。
 * 双读身份和 namespace 防止采样间的 PID 复用、reparent 或再次换 ns。 */
static bool retry_mount_ns_ready(int pid, RetryMountIdentity* identity) {
    int ppid = 0, parent_ppid = 0, ppid_after = 0, parent_ppid_after = 0;
    unsigned long long start = 0, parent_start = 0, start_after = 0, parent_start_after = 0;
    if (!retry_proc_identity(pid, &ppid, &start) || ppid <= 1 ||
        !retry_proc_identity(ppid, &parent_ppid, &parent_start)) return false;
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/cmdline", ppid);
    char* cmd = read_file_dynamic(path, NULL, 4096);
    if (!cmd) return false;
    size_t len = strlen(cmd);
    bool zygote = strcmp(cmd, "zygote") == 0 || strcmp(cmd, "zygote64") == 0 ||
                  strcmp(cmd, "usap32") == 0 || strcmp(cmd, "usap64") == 0 ||
                  (len > 7 && strcmp(cmd + len - 7, "_zygote") == 0);
    free(cmd);
    if (!zygote) return false;
    dev_t dev, parent_dev, dev_after, parent_dev_after;
    ino_t ino, parent_ino, ino_after, parent_ino_after;
    if (!ns_mnt_wait_capture(pid, &dev, &ino) ||
        !ns_mnt_wait_capture(ppid, &parent_dev, &parent_ino) ||
        (dev == parent_dev && ino == parent_ino)) return false;
    bool stable = retry_proc_identity(pid, &ppid_after, &start_after) && ppid == ppid_after &&
           start == start_after &&
           retry_proc_identity(ppid, &parent_ppid_after, &parent_start_after) &&
           parent_ppid == parent_ppid_after && parent_start == parent_start_after &&
           ns_mnt_wait_capture(pid, &dev_after, &ino_after) && dev == dev_after && ino == ino_after &&
           ns_mnt_wait_capture(ppid, &parent_dev_after, &parent_ino_after) &&
           parent_dev == parent_dev_after && parent_ino == parent_ino_after;
    if (!stable) return false;
    *identity = (RetryMountIdentity){
        .ppid = ppid, .parent_ppid = parent_ppid, .start = start, .parent_start = parent_start,
        .dev = dev, .parent_dev = parent_dev, .ino = ino, .parent_ino = parent_ino
    };
    return true;
}

static void retry_pending_mounts(void) {
    if (!g_fuse_ready) return;
    const char* mnt_src_retry = get_active_mnt_src();
    if (!mnt_src_retry) return;
    /* 每 tick 至多取 NSP_RETRY_TICK_BUDGET 条：重试要读 mountinfo + fork，主循环里
       一次做完几十条会把其它应用的 IPC 应答排到后面（批量冷启动时的抖动来源）。
       退避与尝试上限都在 retry_queue 内（nsp_retry_next 自带到期判定与计数）。 */
    enum { NSP_RETRY_TICK_BUDGET = 4 };
    for (int i = 0; i < NSP_RETRY_TICK_BUDGET; i++) {
        NspRetryEntry e;
        int what = nsp_retry_next(&e, nsp_retry_now_ms());
        if (what == NSP_RETRY_NONE) break;
        if (what == NSP_RETRY_GIVEUP) {
            /* 退避耗尽：整个生命周期只 loud 这一次，应用继续用原生视图 */
            LOG_WRN("挂载重试耗尽，放弃 %s(PID:%d)（已尝试 %d 次，保持原生视图）", e.pkg, e.pid,
                    e.attempts);
            continue;
        }
        if (kill(e.pid, 0) != 0) {
            LOG_DBG("重试跳过 %s(PID:%d) — 进程已死亡", e.pkg, e.pid);
            nsp_retry_done(e.pid);
            continue;
        }
        uid_t uid = get_app_uid(e.pid);
        if (uid == 0 || uid == (uid_t)-1 || is_isolated_uid(uid)) {
            nsp_retry_done(e.pid);
            remove_tracked(e.pid);
            continue;
        }
        RetryMountIdentity before, after;
        if (!retry_mount_ns_ready(e.pid, &before)) continue;
        if (!is_target_app(e.pkg, uid, e.pid, true)) {
            nsp_retry_done(e.pid);
            remove_tracked(e.pid);
            continue;
        }
        /* UID 可在 specialize 中变化；配置裁决后再验证，禁止用 pre 的旧 UID 挂。 */
        uid_t current_uid = get_app_uid(e.pid);
        if (current_uid == 0 || current_uid == (uid_t)-1 || is_isolated_uid(current_uid)) {
            nsp_retry_done(e.pid);
            remove_tracked(e.pid);
            continue;
        }
        /* 配置前后必须是同一对进程和 ns；两次各自稳定不代表跨窗口同一身份。 */
        if (current_uid != uid || !retry_mount_ns_ready(e.pid, &after) ||
            before.ppid != after.ppid || before.parent_ppid != after.parent_ppid ||
            before.start != after.start || before.parent_start != after.parent_start ||
            before.dev != after.dev || before.parent_dev != after.parent_dev ||
            before.ino != after.ino || before.parent_ino != after.parent_ino) continue;
        LOG_DBG("重试挂载 %s(PID:%d, UID:%d) 第 %d 次", e.pkg, e.pid, uid, e.attempts);
        /* 结果由 handle_async_mount_event 收尾：成功清账、失败重新入队等下一轮退避。
           这里**不**按返回值摘条目——异步派发成功不等于挂载成功（旧实现正是在此
           把条目摘掉，于是每个 tick 都从头再试）。 */
        perform_app_mount(e.pkg, e.pid, uid, nullptr, "失败重试");
    }
    /* 队列里还有未到期的条目 → 把毫秒定时器臂到最近那个到期时刻（快档 20ms）；
       空了就解除定时（nsp_retry_next_due_ms 返回 -1）。 */
    arm_due_timer();
}

/* 全局替换（v2/v3）对账 =====================================================
 * 族根的生命周期由 vold 掌握：用户启动/切换、卷重挂、FUSE 崩溃恢复都会新建或重建
 * /mnt/<族>/<uid>/emulated。旧实现只在「FUSE 就绪」这一刻替换一次：族根还没出现时
 * 静默成功（见 ns_global_replace.c 的 root_count==0 分支）、此后永不重试——真机上
 * 表现为「开机后 v2/v3 不生效」；运行中新用户的族根也永远不会被接管。
 *
 * 稳态（已是 REPLACED）由挂载表变化驱动，不再按固定周期复查：事件源是
 * ns_mnt_watch 打开的 /proc/<pid>/mountinfo，内核在该命名空间每次 mount/umount 后
 * 用 EPOLLERR 回报一次。vold 重挂族根、新用户出现都必然改变挂载表，于是「变化发生
 * → 复查」只隔一次 epoll 唤醒；没有变化时一次复查都不做，也不整份读挂载表。
 * 事件源打不开时才退回 GREPL_STEADY_SEC 周期复查（功能不变，只是延迟受周期限制）。
 *
 * 尚未替换时按退避节奏动手：
 *   - replace 返回 1（尚无族根）：1s→2s→…→30s；事件源把倒计时压到 1s——族根一
 *     出现（vold 一挂上，挂载表就变）就复查，不必等满一个退避周期。
 *   - replace 返回 <0（真实失败）：同样退避；替换内部已把动过的族根回滚到备份。
 *   - replace 返回 0：1s 后自检一次确认真的生效，之后回到事件驱动。
 * 两次真正动挂载之间至少隔 g_grepl_replace_gap（1s 起，短窗口内反复时加倍）：
 * 替换自身就会改变挂载表，事件源随即回报自己的动作——没有这道闸，「替换 → 事件 →
 * 再替换」会退化成毫秒级循环（ns_global_replace.c 记过「5s 一次卸载 + 重 bind」
 * 的老毛病；换成事件驱动后周期由事件定，只会更快，所以间隔闸必须自己设）。
 * 加倍的条件是「短窗口内反复动挂载」（g_grepl_churn_*），不是「动过一次」：健康的
 * 单次替换不该把间隔推大，否则紧随其后的族根反而要等更久；真在打转时 1s→2s→…→30s
 * 仍然成立，最终节奏远慢于老周期。状态回到 REPLACED 时窗口与间隔一起复位。
 * replace 返回 1 时一点挂载都没动，故不记 last：否则前面攒下的退避会正好把
 * 「族根刚刚出现」这一刻挡在门外。
 *
 * 首次成功替换后若又发生了「后续替换成功」，说明出现了新用户/新族根：复位兜底扫描
 * 标记，让 v2 对该用户的存量应用再审查一次（非目标应用还原）。 */

/* 事件源：/proc/<init 命名空间的 pid>/mountinfo，注册进主循环 epoll。幂等；
   取不到只告警一次，g_grepl_watch_fd 保持 -1（对账退回 GREPL_STEADY_SEC 周期）。 */
static void grepl_watch_arm(void) {
    if (g_grepl_watch_fd >= 0 || g_epoll_fd < 0) return;
    int fd = ns_mnt_watch_open(g_global_fuse.pid);
    if (fd < 0) {
        if (!g_grepl_watch_warned) {
            g_grepl_watch_warned = true;
            LOG_WRN("全局替换对账: 挂载表变化事件源不可用(%s)，稳态按 %ds 周期复查",
                    strerror(errno), GREPL_STEADY_SEC);
        }
        return;
    }
    /* 掩码必须为 0：mounts_poll 恒置 EPOLLIN（文件恒可读），带进掩码就是忙轮询；
       EPOLLERR 不受掩码约束，只留它才是「挂载表变了」的纯通知。 */
    struct epoll_event ev = {.events = 0, .data.fd = fd};
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        if (!g_grepl_watch_warned) {
            g_grepl_watch_warned = true;
            LOG_WRN("全局替换对账: 事件源注册失败(%s)，稳态按 %ds 周期复查", strerror(errno),
                    GREPL_STEADY_SEC);
        }
        close(fd);
        return;
    }
    g_grepl_watch_fd = fd;
    g_grepl_watch_warned = false;  /* 事件源回来了：下次再坏值得重新报一条 */
    g_grepl_fallback_logged = false;
    LOG_DBG("全局替换对账: 挂载表变化事件源就绪(/proc/%d/mountinfo)", g_global_fuse.pid);
}

/* 记账复位：FUSE 重建或注入方法切换后按「什么都没做过」重新开始，别让上一轮攒下的
   退避与间隔闸把这一轮的首次替换挡在门外。 */
static void grepl_reconcile_reset(void) {
    g_grepl_next_sec = 0;
    g_grepl_backoff = GREPL_RETRY_MIN_SEC;
    g_grepl_replace_gap = GREPL_RETRY_MIN_SEC;
    g_grepl_last_replace_ms = 0;
    g_grepl_churn_n = 0;
    g_grepl_churn_pos = 0;
}

static void maybe_reconcile_global_replace(void) {
    if (!inject_is_global_replace()) return;
    if (g_global_fuse.disabled || g_global_fuse.pid <= 0 || !g_fuse_ready) return;
    grepl_watch_arm();
    if (g_grepl_next_sec > 0) { /* 退避/自检倒计时（1s tick 递减） */
        g_grepl_next_sec--;
        return;
    }
    if (g_grepl_next_sec < 0) return; /* 稳态：等挂载表变化事件 */
    int st = ns_global_status(g_global_fuse.pid, g_global_fuse.mnt_path);
    if (st == NSP_GLOBAL_STATUS_REPLACED) {
        g_grepl_next_sec = (g_grepl_watch_fd >= 0) ? GREPL_STEADY_EVENT : GREPL_STEADY_SEC;
        if (g_grepl_watch_fd < 0 && !g_grepl_fallback_logged) {
            /* 事件源不可用：此后没有任何东西会主动唤醒对账，族根变化只能等一个
               周期才被发现。稳态判定每个周期都会走到这一行，故只报一次——这条
               是现场判断「为什么新用户要等一个周期才接管」的唯一线索，级别 INFO
               而不是 DEBUG。 */
            g_grepl_fallback_logged = true;
            LOG("全局替换对账: 事件源不可用，稳态回落到 %ds 周期复查（族根变化发现延迟上限为该周期）",
                GREPL_STEADY_SEC);
        }
        g_grepl_backoff = GREPL_RETRY_MIN_SEC;
        g_grepl_replace_gap = GREPL_RETRY_MIN_SEC;
        g_grepl_churn_n = 0; /* 收敛了：间隔闸的观察窗口清零 */
        return;
    }
    /* 不是「已替换」：要动挂载，先过最小间隔闸（见函数头注释） */
    int64_t now = nsp_retry_now_ms();
    if (g_grepl_last_replace_ms > 0 &&
        now - g_grepl_last_replace_ms < (int64_t)g_grepl_replace_gap * 1000) {
        g_grepl_next_sec = GREPL_RETRY_MIN_SEC;
        return;
    }
    int ret =
        ns_global_replace_system(g_global_fuse.pid, g_global_fuse.mnt_path, GLOBAL_BACKUP_ROOT);
    if (ret > 0) {
        int delay = g_grepl_backoff;
        g_grepl_backoff = (delay * 2 > GREPL_RETRY_MAX_SEC) ? GREPL_RETRY_MAX_SEC : delay * 2;
        g_grepl_next_sec = delay;
        LOG_DBG("全局替换对账: 族根尚未建立，%ds 后重试", delay);
        return;
    }
    g_grepl_last_replace_ms = nsp_retry_now_ms();
    /* 记下这次动挂载；只有窗口内已攒够 GREPL_CHURN_SLOTS 次才认为在打转、加倍间隔。
       g_grepl_churn_pos 指向最旧的一格（刚被覆盖的就是它）。 */
    g_grepl_churn_ms[g_grepl_churn_pos] = g_grepl_last_replace_ms;
    g_grepl_churn_pos = (g_grepl_churn_pos + 1) % GREPL_CHURN_SLOTS;
    if (g_grepl_churn_n < GREPL_CHURN_SLOTS) g_grepl_churn_n++;
    if (g_grepl_churn_n >= GREPL_CHURN_SLOTS &&
        g_grepl_last_replace_ms - g_grepl_churn_ms[g_grepl_churn_pos] < GREPL_CHURN_WINDOW_MS) {
        g_grepl_replace_gap =
            (g_grepl_replace_gap * 2 > GREPL_RETRY_MAX_SEC) ? GREPL_RETRY_MAX_SEC : g_grepl_replace_gap * 2;
    }
    g_grepl_next_sec = GREPL_RETRY_MIN_SEC; /* 1s 后自检一次：确认真的生效 */
    if (ret == 0) {
        bool followup = g_grepl_replaced_once; /* 本次不是首次替换 → 出现了新族根 */
        g_grepl_replaced_once = true;
        g_grepl_backoff = GREPL_RETRY_MIN_SEC;
        if (followup) {
            LOG("全局替换: 新族根已接管（新用户/重挂），补一次应用审查");
            g_global_replace_scanned_once = false;
            seconds_until_next_scan = 0;
        }
        return;
    }
    int delay = g_grepl_backoff;
    g_grepl_backoff = (delay * 2 > GREPL_RETRY_MAX_SEC) ? GREPL_RETRY_MAX_SEC : delay * 2;
    g_grepl_next_sec = delay;
    LOG_ERR("全局替换对账失败（系统视图保持原样），%ds 后重试", delay);
}

/* 挂载表变了：稳态立刻复查；退避中把倒计时压到最小档——开机阶段挂载事件密集，
   逐条复查等于把「没就绪」的判定换成挂载事件轮询，反而更贵。 */
static void on_mnt_watch_event(void) {
    if (!inject_is_global_replace()) return;
    if (g_grepl_next_sec > GREPL_RETRY_MIN_SEC) {
        g_grepl_next_sec = GREPL_RETRY_MIN_SEC;
        return;
    }
    if (g_grepl_next_sec < 0) g_grepl_next_sec = 0;
    maybe_reconcile_global_replace();
}

/* 运行期注入方法切换 ========================================================
 * g_inject_method 只在启动时由 argv 决定。运行期改方法不是改一个标志位：
 * v2/v3 把三族族根整体换成了项目 FUSE（MS_SHARED 传播给所有应用命名空间），
 * v1 是逐应用进命名空间挂载——直接改标志会让「已替换的全局视图」失去维护者，
 * 系统停在代理视图上而没人卸载/还原，这正是过去只能重启设备的原因。
 *
 * 这里把切换做成一次显式迁移：
 *   切到 v1：先按备份树把三族还原成系统视图（与退出/崩溃恢复同一条原语），
 *            再清全局替换记账；随后的应用对账按 v1 逐应用挂载目标。
 *   切到 v2/v3：先改标志位，立即对账一次全局替换，让存量命名空间马上接管。
 * 还原失败时保持原方法不动——半新半旧比全旧更难排查。
 * 方法来源是 INJECT_METHOD_PATH（内容 v1|v2|v3）。文件缺失或无法识别一律
 * 保持当前方法：配置目录被误删不该把注入方法重置成默认值。 */
static InjectMethod read_inject_method_file(void) {
    FILE* fp = fopen(INJECT_METHOD_PATH, "re");
    if (!fp) return (InjectMethod)0;
    char buf[8] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    if (n == 0) return (InjectMethod)0;
    const char* p = buf;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (strncmp(p, "v1", 2) == 0) return INJECT_METHOD_V1;
    if (strncmp(p, "v2", 2) == 0) return INJECT_METHOD_V2;
    if (strncmp(p, "v3", 2) == 0) return INJECT_METHOD_V3;
    return (InjectMethod)0;
}

static void apply_inject_method_switch(void) {
    InjectMethod want = read_inject_method_file();
    if (want == 0 || want == g_inject_method) return;
    InjectMethod had = g_inject_method;
    if (want == INJECT_METHOD_V1) {
        if (inject_is_global_replace() && g_global_fuse.pid > 0) {
            if (ns_global_restore_system(g_global_fuse.pid, GLOBAL_BACKUP_ROOT) != 0) {
                LOG_ERR("注入方法切换 v%d -> v1: 系统视图还原失败，保持 v%d 不变", (int)had,
                        (int)had);
                return;
            }
        }
        grepl_reconcile_reset();
        g_grepl_replaced_once = false;
        g_global_replace_scanned_once = true; /* v1 不做全局兜底扫描 */
        g_inject_method = INJECT_METHOD_V1;
        LOG("注入方法切换: v%d -> v1（系统 emulated 视图已还原，运行中应用改走逐应用挂载）",
            (int)had);
        return;
    }
    g_inject_method = want;
    grepl_reconcile_reset();
    g_grepl_replaced_once = false;
    g_global_replace_scanned_once = false; /* 新方法下对存量应用重新审查一次 */
    LOG("注入方法切换: v%d -> v%d（立即对账全局替换）", (int)had, (int)want);
    maybe_reconcile_global_replace();
}

static void on_timer_event(int timer_fd) {
    uint64_t expirations;
    if (read(timer_fd, &expirations, sizeof(expirations)) > 0) {
        check_and_recover_fuse();
        maybe_reconcile_global_replace();
        reap_zombies();
        maybe_periodic_scan();
        retry_pending_mounts();
        arm_due_timer(); /* retry_pending_mounts 内部已臂过一次，这里兜住其它路径 */
    }
}

/* 只认「以 .conf 结尾」的文件名。旧实现用 strstr(name, ".conf") 做子串匹配，
   于是 CONFIG_DIR 里任何 *.config（例如别的工具维护的包名对照表 list.config）
   每写一次都触发一次整份重载——现场「配置重载 #1 来源=inotify 合并事件=390」
   就是这么来的。后缀比较后 .config / .conf.bak 都不再算。 */
static bool reload_name_matches(const char* name) {
    if (!name || !name[0]) return 0;
    static const char kSuffix[] = ".conf";
    const size_t slen = sizeof(kSuffix) - 1;
    const size_t len = strlen(name);
    if (len <= slen) return 0;
    return strcmp(name + len - slen, kSuffix) == 0;
}

/* 一次唤醒把 inotify fd **读空**，再把本批事件折成一条"待重载"请求交给去抖窗口。
   旧实现只 read 一次 4096 字节（约 100 条事件）就返回：一次唤醒里剩下的上千条
   要么推迟到下一轮 epoll，要么因内核队列溢出被丢弃——真机 20:05:18 一秒 633 条
   的 unlink 与 20:13:00 一秒 54 次重载都是从这儿漏进来的。 */
static void on_inotify_event(void) {
    char inotify_buf[8192] __attribute__((aligned(__alignof__(struct inotify_event))));
    bool overflow = false;
    unsigned conf_events = 0;
    char first_name[64] = {0};
    for (;;) {
        ssize_t len = read(g_inotify_fd, inotify_buf, sizeof(inotify_buf));
        if (len <= 0) {
            /* EAGAIN：已读空（非阻塞 fd 的正常收尾）；其余 errno 记一行便于定位 */
            if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                LOG_ERR("inotify read 失败: %s", strerror(errno));
            break;
        }
        for (char* ptr = inotify_buf; ptr < inotify_buf + len;) {
            struct inotify_event* ev = (struct inotify_event*)ptr;
            /* IN_Q_OVERFLOW 是 wd == -1 的合成事件，**不代表任何具体文件**；
               队列溢出说明此间有事件被内核丢弃（用户/规则目录可能已改而我们没
               看到）。此前因 `ev->len` 为 0 被整条跳过 → 规则改了不生效且无提示。 */
            if (ev->mask & IN_Q_OVERFLOW) overflow = true;
            if (ev->len && reload_name_matches(ev->name)) {
                conf_events++;
                if (!first_name[0]) snprintf(first_name, sizeof(first_name), "%s", ev->name);
            }
            ptr += sizeof(struct inotify_event) + ev->len;
        }
    }
    if (overflow) {
        LOG_WRN("inotify 队列溢出（事件被内核丢弃），按一次配置重载补齐");
        if (!first_name[0]) snprintf(first_name, sizeof(first_name), "IN_Q_OVERFLOW");
        if (conf_events == 0) conf_events = 1;
    }
    /* 有 .conf 变更 → 只登记去抖窗口，不在事件处理里直接跑全量重载：
       重载要全量解析 + 全量对账 + 72KB JSON 广播，跑在单线程事件循环里，
       而 v1 的 POST 挂载请求就在同一个循环排队。 */
    if (conf_events > 0) injector_request_reload(first_name, conf_events);
}

static void on_ipc_accept(int ipc_sock) {
    int client_fd = accept(ipc_sock, nullptr, nullptr);
    if (client_fd >= 0) {
        int flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
        fcntl(client_fd, F_SETFD, FD_CLOEXEC);
        struct epoll_event ev_client = {.events = EPOLLIN | EPOLLONESHOT, .data.fd = client_fd};
        epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, client_fd, &ev_client);
    }
}

static void on_client_fd(int fd) {
    /* 先在锁内摘表取出 ctx（消费即摘）：命中说明这是异步挂载的 status pipe，
       否则才是普通 IPC 客户端。事件处理放在锁外（可能耗时）。 */
    pthread_mutex_lock(&g_async_mount_mutex);
    void* mount_ctx = async_mount_take_locked(fd);
    pthread_mutex_unlock(&g_async_mount_mutex);
    if (mount_ctx) {
        handle_async_mount_event(mount_ctx);
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
        close(fd);
    } else {
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
        handle_ipc_client_readable(fd);
    }
}

/* 提交一份准备好的视图：写锁只罩内存构建（读盘已经在读取 worker 上完成），
   其余后续动作照旧。只在事件循环线程上执行。 */
static void reload_apply_view(NspCfgRec* reload_recs, int reload_count) {
    ChangedPkg out_changed[NSP_AUDIT_MAX_CHANGED];
    config_lock_write();
    int changed_count =
        config_commit_prepared(reload_recs, reload_count, out_changed, NSP_AUDIT_MAX_CHANGED);
    config_unlock_write();
    config_free_view(reload_recs, reload_count);
    apply_inject_method_switch();
    /* 只入队，不在这里读盘/等 pm：本函数跑在唯一事件循环线程上 */
    nsp_async_refresh_request();
    setup_inotify_watches();
    config_publisher_broadcast();

    if (g_media_fuse.fuse_pid > 0 && !is_media_module_injected_target()) {
        LOG("配置变更：媒体组件不再是注入目标。正在终结专属媒体 FUSE...");
        kill(g_media_fuse.fuse_pid, SIGTERM);
        int status;
        waitpid(g_media_fuse.fuse_pid, &status, WNOHANG);
        g_media_fuse.fuse_pid = 0;
        ns_force_umount_stale(g_media_fuse.pid, g_media_fuse.mnt_path);
    } else if (g_media_fuse.fuse_pid <= 0 && !inject_is_global_replace() &&
               is_media_module_injected_target() && g_fuse_ready) {
        LOG("配置变更：检测到专属媒体 FUSE 需要被拉起...");
        inject_media_fuse();
    }

    /* 运行中应用的挂载对账要对每个应用做「配置判定 + 实测视图 + 挂载/卸载/
       还原」，单次预算就有数百毫秒：留在本线程会把 pre-hook 判定、IPC ACK
       与挂载派发一起冻住，几十个在跑的应用叠起来就是数十秒无响应。这里只
       入队；粒度（v1 无论 diff 如何都全量对账 / v2 整体变化重置 / v2 具体
       变更只重挂这几个）由后台 worker 在动手那一刻按当时的注入方法重选，
       连续重载的变更集合与它合并。 */
    nsp_audit_request(changed_count > 0 ? out_changed : nullptr,
                      changed_count > 0 ? changed_count : 0, changed_count == -1);

    arm_due_timer(); /* 重载可能改了活跃用户集合，重臂一次兜住 */
}

/* 配置重载的第一段：判定本次重载是否到期，清 pending 标记并把「读盘 + pm 用户
   探测」派给读取 worker。本函数仍在事件循环线程上——但只发请求，不碰磁盘：
   旧实现内联 config_read_view()，一次慢盘读写或一次慢 `pm list users`（预算
   800ms）就把 pre-hook 判定、挂载派发与 IPC ACK 一起冻住，而 zygisk pre-hook 的
   IPC 超时只有 100ms，超时即 fail-open（这次启动看到的是系统视图）。
   重载次数与触发源必须留痕——旧实现重载完全静默，现场只能靠"配置广播: 0
   订阅者"行反推次数，取证极难；而"到底谁在写 .conf"正是本次真机 54 次/秒
   风暴查不下去的原因。 */
static void handle_pending_reload_begin(void) {
    if (g_should_exit) return;
    const char* why;
    if (g_reload_config) {
        g_reload_config = 0; /* SIGHUP：显式指令，不参与去抖 */
        snprintf(g_reload_trigger, sizeof(g_reload_trigger), "SIGHUP");
        g_reload_events = 0;
        g_reload_due_ms = 0;
        why = "信号";
    } else if (g_reload_due_ms > 0 && nsp_retry_now_ms() >= g_reload_due_ms) {
        why = "inotify";
    } else {
        return; /* 没有待处理重载，或去抖窗口还没到期 */
    }
    char trigger[64];
    snprintf(trigger, sizeof(trigger), "%s", g_reload_trigger);
    unsigned merged = g_reload_events;
    g_reload_due_ms = 0;
    g_reload_first_ms = 0;
    g_reload_events = 0;
    g_reload_trigger[0] = '\0';
    g_reload_total++;
    LOG("配置重载 #%lu: 来源=%s 触发=%s 合并事件=%u", g_reload_total, why, trigger, merged);
    fast_pid_cache_clear();
    if (g_reload_ready_fd >= 0) {
        nsp_reload_stage_request();
        return;
    }
    /* 读取 worker 起不来（eventfd/线程创建失败）时的退路：仍在本线程内联读。
       宁可慢一次也不能丢重载——重载失败会让规则与运行视图长期不一致。 */
    NspCfgRec* reload_recs = nullptr;
    int reload_count = 0;
    config_read_view(INJECTOR_CONFIG_PATH, &reload_recs, &reload_count);
    reload_apply_view(reload_recs, reload_count);
}

/* 配置重载的第二段：读取 worker 的就绪 eventfd 可读时调用——取走视图并提交。
   这一段的耗时只在内存构建与派发上（写锁内的 config_commit_prepared）。 */
static void handle_pending_reload_finish(void) {
    if (g_should_exit) return; /* 退出中：视图留槽，由 shutdown 释放 */
    NspCfgRec* reload_recs = nullptr;
    int reload_count = 0;
    if (!nsp_reload_stage_take(&reload_recs, &reload_count)) return;
    reload_apply_view(reload_recs, reload_count);
}

/* 毫秒到期定时器到点：跑「重试到期」与「重载窗口到期」，再重新臂。
   定时器只负责唤醒，到期判定仍在各自函数里（幂等、可被 1s tick 重复触发）。 */
static void on_due_event(int due_fd) {
    uint64_t expirations;
    while (read(due_fd, &expirations, sizeof(expirations)) == sizeof(expirations)) {
    }
    retry_pending_mounts();
    handle_pending_reload_begin();
    arm_due_timer();
}

static void injector_event_loop(const InjectorFds* fds) {
    struct epoll_event events[64];
    while (!g_should_exit) {
        int nfds = epoll_wait(g_epoll_fd, events, 64, -1);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            PERROR("epoll_wait 失败");
            break;
        }
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            if (fd == fds->sig_fd) {
                on_signal_event(fds->sig_fd);
            } else if (fd == fds->timer_fd) {
                on_timer_event(fds->timer_fd);
            } else if (fd == fds->retry_fd) {
                /* 重试入队时被唤醒：立刻跑一轮（首轮 backoff=0），不再等下一次 1s tick */
                uint64_t drained;
                while (read(fds->retry_fd, &drained, sizeof drained) == sizeof drained) {
                }
                retry_pending_mounts();
            } else if (fd == fds->due_fd) {
                on_due_event(fds->due_fd);
            } else if (fd == g_inotify_fd) {
                on_inotify_event();
            } else if (fd == g_grepl_watch_fd) {
                on_mnt_watch_event();
            } else if (fd == fds->ipc_sock) {
                on_ipc_accept(fds->ipc_sock);
            } else if (fd == g_config_pub_fd) {
                config_publisher_handle_readable(fd);
            } else if (fd == g_reload_ready_fd) {
                /* 配置读取 worker 备好了视图：取走并提交（读盘已经在别的线程完成） */
                uint64_t drained;
                while (read(fd, &drained, sizeof drained) == sizeof drained) {
                }
                handle_pending_reload_finish();
            } else if (fd == g_fuse_recover_fd) {
                /* 恢复 worker 跑完了一轮重启序列（新实例是否就绪仍由 ready 管道裁决） */
                uint64_t drained;
                while (read(fd, &drained, sizeof drained) == sizeof drained) {
                }
                if (nsp_fuse_recover_take()) LOG_DBG("FUSE 崩溃恢复序列已完成（worker）");
            } else if (fd == g_fuse_ready_pipe_fd) {
                handle_fuse_ready_event(g_fuse_ready_ctx); /* 内部已 free(ctx) */
                g_fuse_ready_pipe_fd = -1;
                g_fuse_ready_ctx = nullptr;
            } else {
                on_client_fd(fd);
            }
        }
        handle_pending_reload_begin();
    }
}

static void injector_shutdown(const InjectorFds* fds) {
    int ipc_sock = fds->ipc_sock;
    int timer_fd = fds->timer_fd;
    int sig_fd = fds->sig_fd;
    /* 循环已退出，不再有新请求；等后台刷新与后台对账把手上那轮跑完再动全局状态 */
    nsp_async_refresh_shutdown();
    nsp_audit_shutdown();
    /* 读取 worker 也一样：等它手上那轮读盘结束（有界），再释放槽里没取走的视图 */
    nsp_reload_stage_shutdown();
    /* 恢复 worker 若正在跑重启序列，等它跑完再拆全局状态，不取消 */
    nsp_fuse_recover_shutdown();
    do_cleanup();
    ipc_server_cleanup(ipc_sock);
    if (timer_fd >= 0) close(timer_fd);
    if (fds->due_fd >= 0) close(fds->due_fd);
    if (sig_fd >= 0) close(sig_fd);
    if (g_grepl_watch_fd >= 0) close(g_grepl_watch_fd);
    if (g_epoll_fd >= 0) close(g_epoll_fd);
}

/* 主入口：只负责按序调用，不含具体逻辑（见上方阶段/分发函数） */
int main(int argc, char* argv[]) {
    bool start_passive = false;
    parse_cli_args(argc, argv, &start_passive);
    injector_early_init();
    /* 运行期方法文件优先于 argv：切换过一次就是持久选择（argv 只是首次默认值），
       否则重启会把用户显式切到的方法悄悄改回去。日志在 early_init 之后才可用。 */
    InjectMethod persisted_method = read_inject_method_file();
    if (persisted_method != 0 && persisted_method != g_inject_method) {
        LOG("注入方法: 覆盖启动参数 v%d -> v%d（来自 %s）", (int)g_inject_method,
            (int)persisted_method, INJECT_METHOD_PATH);
        g_inject_method = persisted_method;
    }
    const char* method_desc = g_inject_method == INJECT_METHOD_V1   ? "逐应用挂载"
                              : g_inject_method == INJECT_METHOD_V2 ? "全局替换，非目标应用还原"
                                                                    : "全局替换，不还原非目标（默认全局挂载）";
    LOG("注入方法: v%d（%s）", (int)g_inject_method, method_desc);
    InjectorFds fds = {.sig_fd = -1, .timer_fd = -1, .ipc_sock = -1, .due_fd = -1};
    injector_setup_epoll(&fds);
    injector_start_fuses(start_passive);
    injector_event_loop(&fds);
    injector_shutdown(&fds);
    return 0;
}