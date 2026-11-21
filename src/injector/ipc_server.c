#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ipc_server.h"
#include "common.h"
#include "nsp_util.h"
#include "injector.h"
#include "inject_target.h"
#include "retry_queue.h"
#include "mount_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stddef.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <dirent.h>
#include "config_parser.h"
#include "fast_pid.h"
#include "ns_mnt_wait.h"
#include "ns_utils.h"

/* LIST_MODULES 应答：扫描模块目录，列出含 <name>.so 的模块（与 fuse_daemon 加载约定一致）。
   应答动态翻倍（初容 4KB）：模块数无上限后固定 4KB 会在约 15 个模块处截断
   列表（且截断时连 END 尾标记都发不出，客户端误以为全量）。 */
static void handle_list_modules(int client_fd) {
    size_t cap = 4096;
    char* reply = malloc(cap);
    if (!reply) return;
    size_t offset = 0;
    bool truncated = false;
    DIR* d = opendir(MODULES_DIR);
    if (d) {
        struct dirent* de;
        while ((de = readdir(d))) {
            if (de->d_name[0] == '.') continue;
            char so[PATH_MAX];
            snprintf(so, sizeof so, "%s/%s/%s.so", MODULES_DIR, de->d_name, de->d_name);
            if (access(so, F_OK) != 0) continue;
            /* 先算整行长度，放不下则翻倍（OOM 即截断收尾，见下） */
            int n = snprintf(nullptr, 0, "MODULE|%s\n", de->d_name);
            if (n <= 0) continue;
            while (offset + (size_t)n + 5 > cap) {
                size_t ncap = cap * 2;
                if (ncap > 1u << 20) {
                    truncated = true; /* 1MB 仍不够：loud 截断（absurd） */
                    break;
                }
                char* grown = realloc(reply, ncap);
                if (!grown) {
                    truncated = true;
                    break;
                }
                reply = grown;
                cap = ncap;
            }
            if (truncated) break;
            int w = snprintf(reply + offset, cap - offset, "MODULE|%s\n", de->d_name);
            if (w > 0) offset += (size_t)w;
        }
        closedir(d);
    }
    if (truncated) {
        /* 截断标记行（客户端可辨“非全量”，不静默缺模块） */
        const char* mark = "TRUNCATED\nEND\n";
        size_t ml = strlen(mark);
        if (offset + ml > cap) {
            char* grown = realloc(reply, offset + ml + 1);
            if (grown) {
                reply = grown;
                cap = offset + ml + 1;
            } else {
                send(client_fd, reply, offset, MSG_NOSIGNAL);
                free(reply);
                return;
            }
        }
        memcpy(reply + offset, mark, ml + 1);
        offset += ml;
    } else {
        memcpy(reply + offset, "END\n", 5);
        offset += 4;
    }
    send(client_fd, reply, offset, MSG_NOSIGNAL);
    free(reply);
}

/* IPC 线程挂载参数 */
typedef struct {
    char pkg[256];
    int pid;
    uid_t uid;
    char mnt_src[256];
    /* 视图就绪后才放行的 ACK 目标 fd（-1 = 无需 ACK：早已在决策分支内应答）。
       归派发线程所有，线程发完 ACK 即 close。此前 ACK 在派发前就发出，应用会在
       代理视图就绪前继续 specialize 并访问存储（首次启动读到原始目录，或撞上
       合并挂载的裸挂载点窗口 ENOENT）。 */
    int ack_fd;
    /* 还原线程完成时写入 1 字节的通知管道（-1 = 不通知）。v2 的非目标还原不再
       把 ACK 挂在还原末尾：主流程做"有界快等"（IPC_RESTORE_INLINE_MS），
       线程跑完第一轮就写这个字节；超预算则由主流程先 ACK 放行、线程继续在后台
       做完——**正确性不依赖这次阻塞**（audit_tracked_apps 仍会兜底复查）。 */
    int done_fd;
    /* 还原线程的等待预算（ms）：命中"顶层还不是项目 FUSE"时按 10ms 步进重试，
       直到该预算耗尽。pre 阶段派发的后台兜底给足 1200ms（此时共享传播/volad
       装配可能还没完成，但线程是后台的，不占应用时间）；inline/POST 路径给 300ms
       （那时视图通常已就绪，一次命中）。 */
    int wait_ms;
    /* 挂载前等待目标 ns 内 /storage/emulated 的预算（ms）：POST 通道 20ms
       （IPC_MOUNT_INLINE_MS），旧模块就地挂载 250ms（IPC_MOUNT_READINESS_MS），
       见 ipc_channel_readiness。正预算 = 权威尝试：缺失即 loud 并排重试（后台通道
       的静默口径见 ns_utils.h 的 NSP_READINESS_QUIET）。 */
    int readiness_ms;
} IpcMountArg;

/* v2 非目标应用还原的"有界快等"预算：正常一遍只有一次 setns + 逐节点卸载/bind
   （实测数 ms），超预算立即 ACK 放行并让线程在后台做完——把应用冻在 specialize
   上等还原（旧实现最坏 300ms 重试预算 + 还原本身）正是 v2 冷启动变慢的来源。 */
#define IPC_RESTORE_INLINE_MS 30

/* 通知主流程"还原线程已完成"（幂等；不持有 arg） */
static void ipc_restore_signal_done(int* done_fd) {
    if (*done_fd < 0) return;
    char b = 1;
    ssize_t w = write(*done_fd, &b, 1);
    (void)w;
    close(*done_fd);
    *done_fd = -1;
}

/* 见 include/ipc_server.h 的契约说明（IPC_MOUNT_READINESS_MS 亦定义在那里）。
   独立成纯函数是为了让"哪条通道该挂、等多久、失败回什么"可被直编单测钉死——
   真机上的 REPORT/POST 通道只允许 root 对端，普通单测进程无法伪造该凭据。 */
IpcChannel ipc_plan_channel(bool is_post, bool is_report, int proto) {
    if (is_post) return IPC_CHAN_POST;
    if (is_report) return (proto >= 2) ? IPC_CHAN_DEFER : IPC_CHAN_LEGACY;
    return IPC_CHAN_LEGACY; /* REQ：应用直连的历史通道，就地挂载 */
}

int ipc_channel_readiness(IpcChannel ch) {
    switch (ch) {
        case IPC_CHAN_DEFER:
            return 0; /* pre 只裁决、不挂载 */
        case IPC_CHAN_POST:
            /* 20ms：POST 阶段视图通常还没被 vold 装配好（真机 ~135ms 才出现），
               在应用主线程上等满 250ms 只会把 18% 的请求打爆且仍拿到原生视图。
               未就绪就走 fail-open + 后台快重试，应用不被冻在 specialize 上。 */
            return IPC_MOUNT_INLINE_MS;
        case IPC_CHAN_LEGACY:
        default:
            /* 旧模块没有 post 通知，只能就地等（语义不变） */
            return IPC_MOUNT_READINESS_MS;
    }
}

/* 见 include/ipc_server.h：v2 非目标还原的时序（事件驱动优先，不靠轮询猜时间） */
IpcRestorePlan ipc_plan_restore(bool is_post, bool is_report, int proto) {
    if (is_post) return IPC_RESTORE_NOW;
    if (is_report && proto >= 2) return IPC_RESTORE_ON_POST;
    return IPC_RESTORE_INLINE;
}

/* 视图就绪语义的唯一出口：挂载/还原线程在真实完成后才应答并交还 fd。
   对端（zygisk companion）只把 ACK 当作"可以继续 specialize"的信号，
   所以这里的时序就是应用可见的存储视图时序。 */
static void ipc_reply_and_close(int fd, const char* verb) {
    if (fd < 0) return;
    send(fd, verb, strlen(verb), MSG_NOSIGNAL);
    close(fd);
}

static void ipc_ack_and_close(int fd, bool ok) {
    ipc_reply_and_close(fd, ok ? "OK" : "ERR");
}

static void* ipc_restore_thread(void* raw); /* 定义在后（见下） */

/* 还原派发去重表：pre 的后台兜底与 POST 的快路径可能对同一 pid 各派发一次。
   两条线程同时跑没有正确性问题（后到的那条只会命中"顶层非项目 FUSE→跳过"），
   但会白跑一轮并打出误导性的"仍非项目 FUSE 视图"告警——这里按 pid 去重：
   已有线程在跑就直接复用它的结果。 */
#define IPC_RESTORE_MAX_INFLIGHT 32
static pthread_mutex_t g_restore_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_restore_inflight[IPC_RESTORE_MAX_INFLIGHT];

static bool ipc_restore_claim(int pid) {
    bool ok = false;
    pthread_mutex_lock(&g_restore_lock);
    for (int i = 0; i < IPC_RESTORE_MAX_INFLIGHT; i++) {
        if (g_restore_inflight[i] == pid) {
            pthread_mutex_unlock(&g_restore_lock);
            return false; /* 已有线程在跑 */
        }
    }
    for (int i = 0; i < IPC_RESTORE_MAX_INFLIGHT; i++) {
        if (g_restore_inflight[i] == 0) {
            g_restore_inflight[i] = pid;
            ok = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_restore_lock);
    return ok;
}

static void ipc_restore_release(int pid) {
    pthread_mutex_lock(&g_restore_lock);
    for (int i = 0; i < IPC_RESTORE_MAX_INFLIGHT; i++) {
        if (g_restore_inflight[i] == pid) g_restore_inflight[i] = 0;
    }
    pthread_mutex_unlock(&g_restore_lock);
}

/* 派发一次 v2 非目标还原（异步线程）。done_pipe_out 非 NULL 时返回一个读端，
   主流程可 poll 它做有界快等（legacy 通道）；传 NULL 表示完全后台（post 通知路径），
   此时不创建管道，ACK 也不经线程。返回 false 表示未能派发（调用方按已就绪放行）。 */
static bool ipc_restore_dispatch(const char* pkg, int pid, uid_t uid, int* done_pipe_out,
                               int wait_ms) {
    if (!ipc_restore_claim(pid)) {
        LOG_DBG("IPC还原去重: %s(PID:%d) 已有还原在跑，复用其结果", pkg, pid);
        return true; /* 覆盖已存在：调用方按"已派发"处理即可 */
    }
    int done_pipe[2] = {-1, -1};
    if (done_pipe_out) {
        *done_pipe_out = -1;
        if (pipe2(done_pipe, O_CLOEXEC) != 0) done_pipe[0] = done_pipe[1] = -1;
    }
    IpcMountArg* arg = malloc(sizeof(IpcMountArg));
    if (!arg) {
        ipc_restore_release(pid);
        if (done_pipe[0] >= 0) close(done_pipe[0]);
        if (done_pipe[1] >= 0) close(done_pipe[1]);
        return false;
    }
    memset(arg, 0, sizeof(*arg));
    strncpy(arg->pkg, pkg, sizeof(arg->pkg) - 1);
    arg->pid = pid;
    arg->uid = uid;
    arg->ack_fd = -1; /* ACK 由调用方发（线程只通知完成） */
    arg->done_fd = done_pipe[1];
    arg->wait_ms = wait_ms;
    pthread_t tid;
    if (pthread_create(&tid, NULL, ipc_restore_thread, arg) == 0) {
        pthread_detach(tid);
        if (done_pipe_out) {
            *done_pipe_out = done_pipe[0];
        } else if (done_pipe[0] >= 0) {
            close(done_pipe[0]);
        }
        return true;
    }
    arg->done_fd = -1;
    ipc_restore_release(pid);
    if (done_pipe[0] >= 0) close(done_pipe[0]);
    if (done_pipe[1] >= 0) close(done_pipe[1]);
    free(arg);
    return false;
}

/* 全局替换模式：非目标应用异步还原线程（卸载项目 FUSE，bind 回系统视图备份）。
   整个还原周期（派发→重试→完成）合并为单条汇总日志，方便调试、减少占用 */
static void* ipc_restore_thread(void* raw) {
    IpcMountArg* arg = (IpcMountArg*)raw;
    nsp_set_thread_name("nsp_restore");
    int ret = -1;
    int attempts = 0;
    /* IPC 通知时间非常早（应用 fork 后视图尚未就绪）：跳过(ret=1)表示
       当前顶层还不是项目 FUSE，需等待共享传播完成。整个还原周期（含重试）
       总预算 300ms，超预算仍跳过即判定为异常（传播未生效） */
    struct timespec t0, tn;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    /* 整个挂载周期（含重试）的日志打包发送：begin 后 sender 累积日志，
       pop 后一次性打包发送给 log_monitor（不丢日志、减少发送次数） */
    log_batch_begin();
    int budget_ms = arg->wait_ms > 0 ? arg->wait_ms : 300;
    for (;;) {
        if (kill(arg->pid, 0) != 0) {
            log_batch_end();
            /* 进程已死：无需还原，通知主流程放行（ACK 已由主流程发出时 fd=-1） */
            ipc_restore_signal_done(&arg->done_fd);
            ipc_ack_and_close(arg->ack_fd, true);
            ipc_restore_release(arg->pid);
            free(arg);
            return NULL;
        }
        attempts++;
        ret = perform_app_restore(arg->pkg, arg->pid, arg->uid);
        if (ret != 1) break; /* 0=成功 或 -1=失败：结束重试 */
        clock_gettime(CLOCK_MONOTONIC, &tn);
        long elapsed_ms = (tn.tv_sec - t0.tv_sec) * 1000 + (tn.tv_nsec - t0.tv_nsec) / 1000000;
        if (elapsed_ms >= budget_ms) break; /* 预算耗尽（见 wait_ms） */
        usleep(10000);                     /* 10ms 间隔采样 */
    }
    log_batch_end();
    /* 还原成功（或已还原跳过）后标记追踪，生命周期内不再反复检测该应用；
       还原即解除注入状态（显式标志清除，列表不再误报） */
    if (ret == 0) {
        add_tracked(arg->pid);
        unmark_injected(arg->pid);
    }
    /* 单条汇总日志：一次还原周期仅输出一条（派发→重试→完成合并） */
    clock_gettime(CLOCK_MONOTONIC, &tn);
    long total_ms = (tn.tv_sec - t0.tv_sec) * 1000 + (tn.tv_nsec - t0.tv_nsec) / 1000000;
    if (ret == 0) {
        LOG("IPC还原: %s(PID:%d) 成功 (尝试%d次, %ldms)", arg->pkg, arg->pid, attempts, total_ms);
    } else if (ret == 1) {
        /* "仍非项目 FUSE 视图"= 该进程本来就不在我们的代理视图上（已隔离），
           无需还原；这不是异常，只是没抢到"视图出现"那一刻。前置派发/POST 双路
           并发时另一条线程可能已经完成，故只记 DEBUG（真机上占多数，记 WARN 会
           变成噪声）。 */
        LOG_DBG("IPC还原无需动作: %s(PID:%d) %ldms内视图始终非项目 FUSE (尝试%d次)", arg->pkg,
                arg->pid, total_ms, attempts);
    } else {
        LOG_ERR("IPC还原失败: %s(PID:%d) ret=%d (尝试%d次, %ldms)", arg->pkg, arg->pid, ret,
                attempts, total_ms);
    }
    /* 先通知主流程：还原已完成（主流程多半早已 ACK 放行——v2 不依赖这次阻塞）。
       若主流程仍在"有界快等"里，这一字节就是它的放行信号；若主流程已超时放行，
       这里只剩兜底 ACK（ack_fd=-1 时是空操作）。 */
    ipc_restore_signal_done(&arg->done_fd);
    ipc_ack_and_close(arg->ack_fd, ret == 0 || ret == 1);
    ipc_restore_release(arg->pid);
    free(arg);
    return NULL;
}

static void* ipc_mount_thread(void* raw) {
    IpcMountArg* arg = (IpcMountArg*)raw;
    nsp_set_thread_name("nsp_mount");
    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    /* IPC 线程设置最高实时调度优先级，确保不被普通进程抢占 */
    {
        struct sched_param param;
        param.sched_priority = sched_get_priority_max(SCHED_FIFO);
        if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) != 0) {
            /* 降级：SCHED_FIFO 需要 CAP_SYS_NICE，失败时退化为最低 nice */
            LOG_DBG("IPC线程: SCHED_FIFO 设置失败(%s), 降级为 nice -20", strerror(errno));
            setpriority(PRIO_PROCESS, 0, -20);
        }
    }

    /* 防御性短路：全局替换（v2/v3）下目标应用无需逐应用挂载
       （全局 FUSE 已提供代理视图），即使被误调也直接跳过挂载操作 */
    if (inject_is_global_replace()) {
        mark_injected(arg->pid);
        print_active_rules(arg->pkg, arg->pid, arg->uid, "IPC通知");
        ipc_ack_and_close(arg->ack_fd, true);
        free(arg);
        return NULL;
    }

    //LOG("IPC线程开始异步挂载: %s(PID:%d)", arg->pkg, arg->pid);

    /* 先加入追踪列表，防止并发重入（幂等操作） */
    add_tracked(arg->pid);

    if (kill(arg->pid, 0) != 0) {
        LOG_DBG("IPC线程: 进程已死 %s(PID:%d)", arg->pkg, arg->pid);
        remove_tracked(arg->pid);
        /* 进程已死：无需挂载，放行对端（避免 companion 空等 1s 拖慢冷启动） */
        ipc_ack_and_close(arg->ack_fd, true);
        free(arg);
        return NULL;
    }
    if (arg->uid >= NSP_SYSTEM_APP_UID_MIN) update_uid_map(arg->uid, arg->pkg);

    /* 再做一次配置匹配（主线程已检查过，但线程内重检保证一致性） */
    if (!is_target_app(arg->pkg, arg->uid, arg->pid, true)) {
        LOG_DBG("IPC线程: 配置无匹配 %s(PID:%d)", arg->pkg, arg->pid);
        remove_tracked(arg->pid);
        ipc_ack_and_close(arg->ack_fd, true);
        free(arg);
        return NULL;
    }

    /* 检查 FUSE 源 */
    const char* mnt_src = get_active_mnt_src();
    if (!mnt_src) {
        LOG_ERR("IPC线程: 全局 FUSE 不可用，无法为 %s(PID:%d) 挂载", arg->pkg, arg->pid);
        remove_tracked(arg->pid);
        /* FUSE 可能正在崩溃重建：交给重试队列，本次先放行（应用可稍后重新访问） */
        schedule_retry_mount(arg->pkg, arg->pid);
        ipc_ack_and_close(arg->ack_fd, false);
        free(arg);
        return NULL;
    }

    int ret = -1;
    /* 同步挂载（阻塞到目标命名空间内的挂载真实完成）：ACK 必须是"视图已就绪"
       的信号。异步版 perform_app_mount 只负责 fork 就返回，完成事件回到主循环，
       无法与本次 ACK 对齐——那正是"应用先访问、代理视图后到"旧竞态的成因。 */
    ret = perform_app_mount_sync(arg->pkg, arg->pid, arg->uid, NULL, arg->readiness_ms);

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    long elapsed_us =
        (ts_end.tv_sec - ts_start.tv_sec) * 1000000L + (ts_end.tv_nsec - ts_start.tv_nsec) / 1000L;

    if (ret == 0) {
        /* 同步版不做异步版的簿记（mark_injected/规则转储），在此补齐 */
        mark_injected(arg->pid);
        /* 真正挂上了才清重试记账（见 retry_queue.h：尝试次数随条目保存） */
        retry_mount_succeeded(arg->pid);
        print_active_rules(arg->pkg, arg->pid, arg->uid, "IPC通知");
        LOG("IPC挂载完成: %s(PID:%d) 耗时: %ldus（已延迟 ACK 到挂载完成）", arg->pkg, arg->pid,
            elapsed_us);
    } else if (ret == NSP_MOUNT_DEFERRED) {
        /* 视图未就绪（vold 还没把 /storage/emulated 装配进应用 ns，真机实测 ~135ms）：
           **fail-open** 立刻回 OK 让应用继续 specialize，挂载交后台重试队列（快档
           20ms 起）。旧实现会在这里等满整个预算（250ms）再回 ERR，应用白等一场仍然
           拿到原生视图——322 次挂载里 59 次 >250ms 就是这么来的。
           不做 mark_injected（视图确实没挂上），也不清重试记账。 */
        remove_tracked(arg->pid);
        schedule_retry_mount(arg->pkg, arg->pid);
        LOG_DBG("IPC挂载延迟: %s(PID:%d) 视图未就绪，已 fail-open 交后台重试，耗时: %ldus",
                arg->pkg, arg->pid, elapsed_us);
    } else {
        LOG_ERR("IPC挂载失败: %s(PID:%d) 耗时: %ldus", arg->pkg, arg->pid, elapsed_us);
        remove_tracked(arg->pid);
        schedule_retry_mount(arg->pkg, arg->pid);
    }
    ipc_ack_and_close(arg->ack_fd, ret == 0 || ret == NSP_MOUNT_DEFERRED);
    free(arg);
    return NULL;
}

/* ================= v3 补挂载盯梢 =================
 * proto>=3 的模块在 pre-specialize 里拿完判决就关掉 companion 连接，post 阶段
 * 不再回连（ZygiskNext 1.3.4+ 会关掉跨回调遗留的 companion fd；官方 Zygisk 的
 * connectCompanion 也只在 pre 可用）。"何时可以挂"因此改由 injector 判定：
 * pre 时应用还在 zygote 的挂载命名空间里（见 ipc_plan_channel 的 DEFER 说明），
 * 这里盯 /proc/<pid>/ns/mnt 的 (dev, ino)，一变即说明应用自己的 ns 已成立，
 * 立刻同步挂载；模块在 post 里等自己的视图出现，两侧以"视图"对齐，不再有
 * 跨回调的连接。 */
typedef struct {
    char pkg[256];
    int pid;
    uid_t uid;
    dev_t ns_dev;
    ino_t ns_ino;
    int readiness_ms;
} IpcPostArg;

static long ipc_elapsed_ms(const struct timespec* from, const struct timespec* to) {
    return (to->tv_sec - from->tv_sec) * 1000L + (to->tv_nsec - from->tv_nsec) / 1000000L;
}

static void* ipc_post_mount_thread(void* raw) {
    IpcPostArg* arg = (IpcPostArg*)raw;
    nsp_set_thread_name("nsp_post");
    struct timespec t0, tn;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* 先占追踪位，避免与后台重试队列对同一 pid 并发挂载 */
    add_tracked(arg->pid);

    /* 等应用自己的挂载命名空间成立：挂载表变化事件能把等待提前叫醒，精度由
       节拍给出，整个等待仍有界（IPC_POST_WAIT_MS），到点就走跳过分支。 */
    bool switched = false;
    long waited_us = ns_mnt_wait_switch(arg->pid, arg->ns_dev, arg->ns_ino, IPC_POST_WAIT_MS,
                                        &switched);
    long waited_ms = waited_us / 1000L;
    if (!switched) {
        /* 没等到切换就绝不挂：此时挂上去会落进 zygote 的命名空间，被之后 fork 的
           每个应用继承且无法清理。应用先用原生视图跑，视图交后台重试队列补。 */
        remove_tracked(arg->pid);
        uid_t current_uid = get_app_uid(arg->pid);
        if (kill(arg->pid, 0) == 0 && current_uid != 0 && current_uid != (uid_t)-1 &&
            !is_isolated_uid(current_uid)) {
            schedule_retry_mount(arg->pkg, arg->pid);
        } else {
            nsp_retry_done(arg->pid); /* 取消而非成功：清掉 specialize 前已有的条目 */
        }
        LOG_DBG("IPC补挂载跳过: %s(PID:%d) %ldms 内未见命名空间切换", arg->pkg, arg->pid,
                waited_ms);
        free(arg);
        return NULL;
    }
    if (!is_target_app(arg->pkg, arg->uid, arg->pid, true)) {
        remove_tracked(arg->pid);
        LOG_DBG("IPC补挂载: 配置无匹配 %s(PID:%d)", arg->pkg, arg->pid);
        free(arg);
        return NULL;
    }
    if (!get_active_mnt_src()) {
        remove_tracked(arg->pid);
        LOG_ERR("IPC补挂载: 全局 FUSE 不可用，无法为 %s(PID:%d) 挂载", arg->pkg, arg->pid);
        schedule_retry_mount(arg->pkg, arg->pid);
        free(arg);
        return NULL;
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int ret = perform_app_mount_sync(arg->pkg, arg->pid, arg->uid, NULL, arg->readiness_ms);
    clock_gettime(CLOCK_MONOTONIC, &tn);
    long mount_ms = ipc_elapsed_ms(&t0, &tn);
    if (ret == 0) {
        /* 同步版不做异步版的簿记，在此补齐（与 POST 通道一致） */
        mark_injected(arg->pid);
        retry_mount_succeeded(arg->pid);
        print_active_rules(arg->pkg, arg->pid, arg->uid, "IPC通知");
        /* 切换后的等待量按微秒记：节拍在毫秒以下，毫秒级取值把对照信息抹平了 */
        LOG("IPC补挂载完成: %s(PID:%d) 切换后 %ldus 就绪（挂载 %ldms）", arg->pkg, arg->pid,
            waited_us, mount_ms);
    } else if (ret == NSP_MOUNT_DEFERRED) {
        remove_tracked(arg->pid);
        schedule_retry_mount(arg->pkg, arg->pid);
        LOG_DBG("IPC补挂载延迟: %s(PID:%d) 视图未就绪，交后台重试（挂载 %ldms）", arg->pkg, arg->pid,
                mount_ms);
    } else {
        remove_tracked(arg->pid);
        schedule_retry_mount(arg->pkg, arg->pid);
        LOG_ERR("IPC补挂载失败: %s(PID:%d) ret=%d（挂载 %ldms）", arg->pkg, arg->pid, ret, mount_ms);
    }
    free(arg);
    return NULL;
}

/* 派发补挂载盯梢（pre 通道，proto>=3）。先取当前命名空间身份作为"还没切换"的
   基线；取不到说明进程已消失，交由调用方按已就绪处理。 */
static bool ipc_post_mount_dispatch(const char* pkg, int pid, uid_t uid) {
    dev_t ns_dev;
    ino_t ns_ino;
    if (!ns_mnt_wait_capture(pid, &ns_dev, &ns_ino)) {
        LOG_DBG("IPC补挂载: 无法读取 %s(PID:%d) 的命名空间（%s）", pkg, pid, strerror(errno));
        return false;
    }
    IpcPostArg* arg = malloc(sizeof(*arg));
    if (!arg) return false;
    memset(arg, 0, sizeof(*arg));
    snprintf(arg->pkg, sizeof arg->pkg, "%s", pkg);
    arg->pid = pid;
    arg->uid = uid;
    arg->ns_dev = ns_dev;
    arg->ns_ino = ns_ino;
    /* 盯梢线程不在应用主线程上等，可以给足 vold 装配窗口（实测 ~135–150ms），
       让"应用首次读存储"就能看到代理视图；模块侧只等 100ms（且仅在明确 DEFER
       时），没赶上就由后台重试队列补挂，应用启动不被拖慢。 */
    arg->readiness_ms = IPC_MOUNT_READINESS_MS;
    pthread_t tid;
    if (pthread_create(&tid, NULL, ipc_post_mount_thread, arg) == 0) {
        pthread_detach(tid);
        LOG_DBG("IPC派发补挂载盯梢: %s(PID:%d)（等待命名空间切换，上限 %dms）", pkg, pid,
                IPC_POST_WAIT_MS);
        return true;
    }
    free(arg);
    LOG_ERR("IPC补挂载: 创建盯梢线程失败 %s(PID:%d)", pkg, pid);
    return false;
}

int ipc_server_init() {
    /* 将整个 injector 进程绑定到大核 4-7，减少调度迁移延迟 */
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(4, &cpus);
    CPU_SET(5, &cpus);
    CPU_SET(6, &cpus);
    CPU_SET(7, &cpus);
    if (sched_setaffinity(0, sizeof(cpus), &cpus) != 0) {
        LOG_DBG("IPC: 进程 CPU 亲和性设置失败: %s", strerror(errno));
    } else {
        LOG("IPC: 进程已绑定到 CPU 4-7");
    }

    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr;
    socklen_t addr_len = nsp_uds_abstract_addr(&addr, IPC_SOCKET_NAME);
    if (bind(sock, (struct sockaddr*)&addr, addr_len) < 0) {
        close(sock);
        return -1;
    }
    if (listen(sock, 20) < 0) {
        close(sock);
        return -1;
    }
    LOG_DBG("IPC 服务已启动");
    return sock;
}
void ipc_server_cleanup(int sock_fd) {
    if (sock_fd >= 0) {
        close(sock_fd);
    }
}

/* ================= 请求身份绑定（R8） =================
 * 只核对 SO_PEERCRED 的 uid 不足以确认"是谁在替谁说话"：同一个 uid 下的进程
 * 可以自报**别的 pid**（例如 init）或**别的包名**。一旦采信：
 *  - 该 uid 的 uid→包名映射被污染，HIDE/RO 规则整体失配；
 *  - v2 下按伪包判定"非目标"并派发还原，合法应用可能因此失去代理视图。
 * 故两条通道各有独立的身份模型：
 *  - REQ：应用自身在 specialize 阶段直连（peer uid == 应用 uid）。必须
 *    peer_pid == 自报 pid，且 /proc/<pid> 的 uid 与 cmdline 与自报 uid/pkg 一致；
 *  - REPORT：Zygisk companion（root）代应用上报。pre-specialize 阶段该进程还是
 *    zygote 的 root 子进程，pid/uid/pkg 是"即将成为目标"的值，天然无法与当前
 *    身份比对——这是唯一例外，只允许 root 对端，且走独立分支，**不复用**应用
 *    REQ 的路径，故不会削弱上面的绑定。
 * 两条通道都在写 uid.map / 切 g_passive_mode / 派发挂载·还原之前完成校验。 */

/* cmdline 首段与包名比对：两侧都剥掉 ":<process>" 后缀（zygote 子进程名与
   自报包名都可能带后缀）。cmdline 原始缓冲以 NUL 分隔 argv，%s 取到首段。 */
static bool ipc_pkg_matches_cmdline(const char* cmdline, const char* pkg) {
    char cmd_base[256];
    char pkg_base[256];
    snprintf(cmd_base, sizeof cmd_base, "%s", cmdline);
    snprintf(pkg_base, sizeof pkg_base, "%s", pkg);
    char* c = strchr(cmd_base, ':');
    if (c) *c = '\0';
    char* p = strchr(pkg_base, ':');
    if (p) *p = '\0';
    if (cmd_base[0] == '\0' || pkg_base[0] == '\0') return false;
    return strcmp(cmd_base, pkg_base) == 0;
}

/* 非 root 对端（应用自身）的身份绑定。只读 /proc，不改任何状态；失败即拒绝。 */
static bool ipc_verify_app_identity(pid_t peer_pid, uid_t peer_uid, const char* pkg, int pid,
                                    int uid) {
    if (peer_pid <= 0 || peer_uid == (uid_t)-1) {
        LOG_WRN("IPC: 无法读取对端凭据（SO_PEERCRED），拒绝请求");
        return false;
    }
    if ((uid_t)uid != peer_uid) {
        LOG_WRN("IPC: 拒绝 uid 不匹配的请求（自报 uid=%d，对端 uid=%u）", uid, (unsigned)peer_uid);
        return false;
    }
    if (peer_pid != (pid_t)pid) {
        LOG_WRN("IPC: 拒绝 pid 不匹配的请求（自报 pid=%d，对端 pid=%d）", pid, (int)peer_pid);
        return false;
    }
    /* 该 pid 必须确实是自报 uid 的进程：/proc/<pid> 的属主由内核给出，伪造不了 */
    uid_t real_uid = get_app_uid((pid_t)pid);
    if (real_uid != peer_uid) {
        LOG_WRN("IPC: 拒绝 uid 不匹配的请求（自报 uid=%d，/proc/%d uid=%u）", uid, pid,
                (unsigned)real_uid);
        return false;
    }
    /* 包名必须与进程名一致（或与框架对该 uid 的解析一致——此处取更严格且不依赖
       uid.map 的 cmdline 口径）。读不到 cmdline 一律按失败处理（fail-closed：
       宁可拒绝一次合法请求，也不让伪造包名落进 uid.map）。 */
    char cmdline[256] = {0};
    if (!proc_get_cmdline((pid_t)pid, cmdline, sizeof cmdline)) {
        LOG_WRN("IPC: 拒绝无法读取 cmdline 的请求（pid=%d）", pid);
        return false;
    }
    if (!ipc_pkg_matches_cmdline(cmdline, pkg)) {
        LOG_WRN("IPC: 拒绝包名与进程不符的请求（自报 %s，/proc/%d cmdline=%s）", pkg, pid,
                cmdline);
        return false;
    }
    return true;
}

void handle_ipc_client_readable(int client_fd) {
    /* 核心修复：清除 O_NONBLOCK 状态使 Socket 回退至阻塞模式。
     * 唯有如此，内核底层的 SO_RCVTIMEO / SO_SNDTIMEO 500ms 保护逻辑才会真正生效。 */
    int flags = fcntl(client_fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(client_fd, F_SETFL, flags & ~O_NONBLOCK);
    }
    // 设置严格的 500ms 读写超时，防止异常客户端引发挂起
    struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    char buf[512] = {0};
    ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    char pkg[256];
    int pid = 0, uid = 0;
    /* 三个动词 = 三条语义不同的通道（身份模型见 ipc_verify_app_identity 上方注释）：
       REPORT（root companion，pre-specialize 上报）、POST（root companion，
       post-specialize 的补挂载请求）、REQ（应用自身直连，历史通道，完整绑定校验）。
       末尾可选 proto 令牌：>=2 的模块支持"pre 回 DEFER、post 发 POST"的两段式
       补挂载；不带的旧模块一律走原有"就地挂载 + 异步重试"路径（零回归）。 */
    int proto = 0;
    bool is_report = false, is_req = false, is_post = false;
    int nf = sscanf(buf, "REPORT %255s %d %d %d", pkg, &pid, &uid, &proto);
    if (nf >= 3) {
        is_report = true;
        if (nf < 4) proto = 0;
    } else {
        proto = 0;
        nf = sscanf(buf, "REQ %255s %d %d %d", pkg, &pid, &uid, &proto);
        if (nf >= 3) {
            is_req = true;
            if (nf < 4) proto = 0;
        } else {
            proto = 0;
            nf = sscanf(buf, "POST %255s %d %d %d", pkg, &pid, &uid, &proto);
            if (nf >= 3) {
                is_post = true;
                if (nf < 4) proto = 0;
            }
        }
    }
    if (is_report || is_req || is_post) {
        /* 输入校验：拒绝越界 pid/uid，避免后续 /proc/<pid> 路径被构造用于越权访问 */
        if (pid <= 0 || pid >= 1048576 /* PID_BITMAP_MAX, Android PID 上限 */) {
            LOG_WRN("IPC: 拒绝非法 pid=%d", pid);
            send(client_fd, "ERR", 3, MSG_NOSIGNAL);
            close(client_fd);
            return;
        }
        if (uid < 0) {
            LOG_WRN("IPC: 拒绝非法 uid=%d", uid);
            send(client_fd, "ERR", 3, MSG_NOSIGNAL);
            close(client_fd);
            return;
        }
        pid_t peer_pid = -1;
        uid_t peer_uid = (uid_t)-1;
        if (nsp_peer_cred(client_fd, &peer_pid, &peer_uid, NULL) != 0) {
            peer_pid = -1;
            peer_uid = (uid_t)-1;
        }
        if (is_report || is_post) {
            /* root companion 通道：pre-specialize 上报的 pid/uid/pkg 是"即将成为
               目标"的值，不能要求当前进程身份匹配；root 是唯一合法对端。
               POST（post-specialize 补挂载）同属该通道，语义与校验完全一致。 */
            if (peer_uid != 0) {
                LOG_WRN("IPC: 拒绝非 root 对端的 %s（对端 uid=%u）；应用自身请走 REQ",
                        is_post ? "POST" : "REPORT", (unsigned)peer_uid);
                send(client_fd, "ERR", 3, MSG_NOSIGNAL);
                close(client_fd);
                return;
            }
        } else {
            /* 应用自身通道：root 必须走 REPORT（独立通道），非 root 必须通过
               pid/uid/包名绑定——校验通过前不得写 uid.map、切被动模式或派发。 */
            if (peer_uid == 0) {
                LOG_WRN("IPC: 拒绝 root 对端的 REQ（companion 必须走 REPORT 通道）");
                send(client_fd, "ERR", 3, MSG_NOSIGNAL);
                close(client_fd);
                return;
            }
            if (!ipc_verify_app_identity(peer_pid, peer_uid, pkg, pid, uid)) {
                send(client_fd, "ERR", 3, MSG_NOSIGNAL);
                close(client_fd);
                return;
            }
        }
        if (!g_passive_mode) {
            g_passive_mode = true;
            LOG("已接收到IPC通知，切换到被动模式，停止周期扫描");
        }
        /* 生命周期清理：清除已退出应用的追踪缓存（被动模式无周期扫描，
           此路径是唯一可靠的清理时机）。但它要持 g_tracked_mutex 对整表逐条
           kill(pid,0)，放在每条 IPC 消息里会给批量冷启动叠加排队延迟
           （首屏 10+ 应用同时 specialize 时最明显）——限频到每秒一次。 */
        static time_t last_stale_cleanup;
        time_t now_ts = time(NULL);
        if (now_ts != last_stale_cleanup) {
            last_stale_cleanup = now_ts;
            cleanup_stale_tracked();
        }
        if (is_isolated_uid(uid) || strstr(pkg, "_zygote") != nullptr) {
            ipc_ack_and_close(client_fd, true);
            return;
        }
        char clean_pkg[256];
        strncpy(clean_pkg, pkg, sizeof(clean_pkg) - 1);
        clean_pkg[sizeof(clean_pkg) - 1] = '\0';
        char* colon = strchr(clean_pkg, ':');
        if (colon) *colon = '\0';
        if (uid >= NSP_SYSTEM_APP_UID_MIN) update_uid_map(uid, clean_pkg);
        /* 全量应用注册（配置热对账的候选来源）：被动模式停掉了周期扫描，
           这里是「运行中应用」唯一的登记入口——不登记就无法回答「这个应用
           已经在跑、配置现在把它变成目标了，挂给谁」，只能等应用重启。裸
           clean_pkg 即可：对账时会重新读 /proc cmdline。 */
        all_apps_upsert(pid, uid, clean_pkg);

        /* ACK 的语义是"目标进程的存储视图已就绪，可以继续 specialize"。
           需要挂载（v1）的路径把 client_fd 交给挂载线程、挂完才 ACK（POST 短预算，
           超时 fail-open）；v2 非目标还原走事件驱动（见下方分支），ACK 最多等
           IPC_RESTORE_INLINE_MS。旧实现在派发前无条件应答，应用会在代理视图就绪前
           读到原始目录——那种"提前应答"只对不需要视图操作的路径成立。

           注意：使用 clean_pkg 而非原始 pkg 进行配置匹配，
           避免带 ':process' 后缀的包名误判为未配置应用 */
        bool is_target = is_target_app(clean_pkg, uid, pid, true);
        if (!is_target) {
            /* 注入方法 v2：非目标应用要卸载项目 FUSE 并还原系统视图；v3 不还原
               （默认全局挂载）。时序按「事件驱动优先」排：
                 - 新协议（REPORT+proto>=2）的 pre 阶段**不还原、不轮询**：此刻应用
                   ns 里还没有项目视图，还原只会命中「顶层非项目 FUSE→跳过」（旧实现
                   靠 10ms 步进轮询猜时间，实测 46–60ms 才落地）。直接回 DEFER，
                   让模块在 post-specialize（视图已就绪、仍早于 Java 代码）再通知；
                 - post 通知到达即**异步**还原 + 立刻 ACK（不阻塞、不等待）；
                 - 旧模块（无 proto）/ REQ 没有 post 通知可用，退化为「就地派发 +
                   有界快等」（IPC_RESTORE_INLINE_MS），超时先放行、后台继续。 */
            if (inject_restore_nontarget()) {
                IpcRestorePlan plan = ipc_plan_restore(is_post, is_report, proto);
                if (plan == IPC_RESTORE_ON_POST) {
                    /* 双保险：① 立刻派发一次**后台**还原线程（10ms 步进、最多 1.2s），
                       视图一出现就还原——这条不依赖任何模块通知，是正确性底线；
                       ② 旧模块（proto<3）同时回 DEFER，让它在 post-specialize 再通知
                       一次：POST 到达时再派发一次，通常一次命中（~5ms），把窗口压到
                       最小。两条路重复执行时，后到的那条只会命中"顶层非项目 FUSE→
                       跳过"。
                       新模块（proto>=3）没有第二次通知，且它会把 DEFER 当成"要等自己的
                       代理视图"——本应用恰恰不该被代理，等满自己的 100ms 上界只会白等一场
                       （每次冷启动可见地变慢）。故对这类模块直接回 OK，还原仍由上面
                       那条后台线程完成。 */
                    bool dispatched =
                        ipc_restore_dispatch(clean_pkg, pid, uid, nullptr, 1200);
                    bool defer = proto < IPC_PROTO_LOCAL_WAIT;
                    LOG_DBG("IPC还原计划: %s(PID:%d) 后台还原%s；%s", clean_pkg, pid,
                            dispatched ? "已派发" : "派发失败",
                            defer ? "同时回 DEFER 等 post 通知加速" : "回 OK（新模块不再回连）");
                    if (defer) {
                        ipc_reply_and_close(client_fd, "DEFER");
                    } else {
                        ipc_ack_and_close(client_fd, true);
                    }
                    return;
                }
                if (plan == IPC_RESTORE_NOW) {
                    bool dispatched = ipc_restore_dispatch(clean_pkg, pid, uid, nullptr, 300);
                    LOG_DBG("IPC还原（post 通知）: %s(PID:%d) %s", clean_pkg, pid,
                            dispatched ? "已派发，立即放行（不等还原）"
                                       : "派发失败，按已就绪放行");
                    ipc_ack_and_close(client_fd, true);
                    return;
                }
                /* legacy：就地派发 + 有界快等；超预算先放行、线程后台做完 */
                int done_fd = -1;
                if (ipc_restore_dispatch(clean_pkg, pid, uid, &done_fd, 300)) {
                    bool inline_done = false;
                    if (done_fd >= 0) {
                        struct pollfd pfd = {.fd = done_fd, .events = POLLIN};
                        inline_done = (poll(&pfd, 1, IPC_RESTORE_INLINE_MS) > 0);
                        close(done_fd);
                    }
                    if (inline_done) {
                        LOG_DBG("IPC还原与放行（legacy）: %s(PID:%d) 在 %dms 内完成", clean_pkg, pid,
                                IPC_RESTORE_INLINE_MS);
                    } else {
                        LOG("IPC还原转后台（legacy）: %s(PID:%d) 超过 %dms 未完成，先放行", clean_pkg,
                            pid, IPC_RESTORE_INLINE_MS);
                    }
                    ipc_ack_and_close(client_fd, true);
                    return;
                }
                LOG_ERR("IPC创建还原线程失败: %s(PID:%d)，按已就绪放行", clean_pkg, pid);
            }
            ipc_ack_and_close(client_fd, true);
            return;
        }
        if (inject_is_global_replace()) {
            /* 新挂载方案（全局替换 v2/v3）：全局 FUSE 已挂载 /storage/emulated，
               目标应用自动继承代理视图，无需 injector 逐应用挂载——
               仅标记注入状态并打印规则即可（避免 perform_app_mount 的
               mountinfo 全量读取等 20ms+ 耗时）；非目标应用还原走上方分支（仅 v2） */
            mark_injected(pid);
            print_active_rules(clean_pkg, pid, uid, "IPC通知");
            LOG_DBG("全局替换模式: 目标应用 %s(PID:%d) 无需挂载，已由全局 FUSE 提供代理视图",
                    clean_pkg, pid);
            ipc_ack_and_close(client_fd, true);
            return;
        }
        if (access(NSP_ANDROID_EMULATED_ROOT "/", F_OK) != 0) {
            /* 目标存储路径在 injector 命名空间不可见（异常态）：不挂载也不拖延，
               按已就绪放行（与旧行为一致，仅提前到派发前判定） */
            ipc_ack_and_close(client_fd, true);
            return;
        }

        /* v1 就绪预算与失败语义按通道区分：
           - POST（post-specialize）：应用已被本进程阻塞，就地等到视图出现再挂；
             失败才排重试（权威路径）。
           - REPORT + proto>=2（pre-specialize）：只快速试一次（预算 0）——视图已
             就绪时立刻挂上（保住"首写前就绪"的快路径），未就绪则回 DEFER，让
             zygisk 在 post-specialize 重发 POST；此路径不排重试、不报错。
           - 旧模块（无 proto）/ REQ：维持原有"等待 1s + 失败排重试"行为。 */
        /* 通道决策（见 include/ipc_server.h）：
           - pre-specialize 的 REPORT（proto>=2）只裁决、**不挂载**，立即回 DEFER：
             此刻应用还在 zygote 的挂载命名空间里（部分 ROM 该 ns 就有
             /storage/emulated），在这里挂载会把项目 FUSE 装进 zygote ns，之后
             fork 的每个应用（含非目标）都继承它，且没人能清——应用自己的 ns 要到
             post-specialize 才成立，那才是唯一该挂载的时机。
           - POST：就地挂载（短预算，失败排重试）。
           - 旧模块（无 proto）/ REQ：就地挂载，语义不变。 */
        IpcChannel chan = ipc_plan_channel(is_post, is_report, proto);
        if (chan == IPC_CHAN_DEFER) {
            /* 应答文本随 proto 分叉：proto>=4 的模块按 "DEFER <ms>" 里的数字决定
               post 等多久（0 = 不等、一次 mountinfo 都不读）；旧模块用 strcmp 只
               认裸 "DEFER"，带数字会让它整段等待失效。 */
            int wait_ms = 0;
            char defer_reply[32];
            if (proto >= IPC_PROTO_POST_WAIT) {
                wait_ms = g_global_cfg.zygisk_post_wait_ms;
                snprintf(defer_reply, sizeof defer_reply, "DEFER %d", wait_ms);
            } else {
                snprintf(defer_reply, sizeof defer_reply, "DEFER");
            }
            ipc_reply_and_close(client_fd, defer_reply);
            LOG_DBG("IPC裁决: %s(PID:%d) DEFER（proto %d，post 等待预算 %s）", clean_pkg, pid, proto,
                    proto >= IPC_PROTO_POST_WAIT ? (wait_ms > 0 ? "见配置" : "0ms，不等")
                                                 : "由旧模块自己决定");
            /* 新模块（proto>=3）post 阶段不再回连，改由这里盯它的命名空间：
               应答先发出去（模块在等），盯梢线程随后建，不拖慢判决。 */
            if (proto >= IPC_PROTO_LOCAL_WAIT) {
                ipc_post_mount_dispatch(clean_pkg, pid, uid);
            }
            return;
        }
        int readiness_ms = ipc_channel_readiness(chan);
        IpcMountArg* arg = malloc(sizeof(IpcMountArg));
        if (arg) {
            strncpy(arg->pkg, clean_pkg, sizeof(arg->pkg) - 1);
            arg->pkg[sizeof(arg->pkg) - 1] = '\0';
            arg->pid = pid;
            arg->uid = uid;
            arg->mnt_src[0] = '\0';
            arg->ack_fd = client_fd; /* 挂载完成后由线程 ACK + close */
            arg->done_fd = -1;       /* 挂载线程不参与还原完成通知 */
            arg->readiness_ms = readiness_ms;
            pthread_t tid;
            if (pthread_create(&tid, NULL, ipc_mount_thread, arg) == 0) {
                pthread_detach(tid);
                LOG_DBG("IPC派发挂载线程（%s，readiness=%dms，ACK 延迟到挂载完成）: %s(PID:%d)",
                        is_post ? "POST" : "legacy", readiness_ms, clean_pkg, pid);
                return;
            }
            LOG_ERR("IPC创建挂载线程失败: %s(PID:%d)，按已就绪放行", clean_pkg, pid);
            free(arg);
        }
        ipc_ack_and_close(client_fd, true);
        return;
    }
    if (strncmp(buf, "LIST_INJECTED", 13) == 0) {
        handle_list_injected(client_fd);
        close(client_fd);
        return;
    }
    if (strncmp(buf, "LIST_MODULES", 12) == 0) {
        handle_list_modules(client_fd);
        close(client_fd);
        return;
    }
    if (strncmp(buf, "FUSE_ALIVE", 10) == 0 || strncmp(buf, "FUSE_EXIT", 9) == 0) {
        close(client_fd);
        return;
    }
    close(client_fd);
}