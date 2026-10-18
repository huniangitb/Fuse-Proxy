#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ipc_server.h"
#include "common.h"
#include "nsp_util.h"
#include "injector.h"
#include "inject_target.h"
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
#include <time.h>
#include <sched.h>
#include <sys/resource.h>
#include <dirent.h>
#include "config_parser.h"
#include "fast_pid.h"
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
} IpcMountArg;

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
    for (int attempt = 0; attempt < 20; attempt++) {
        if (kill(arg->pid, 0) != 0) {
            log_batch_end();
            free(arg);
            return NULL;
        }
        attempts++;
        ret = perform_app_restore(arg->pkg, arg->pid, arg->uid);
        if (ret != 1) break; /* 0=成功 或 -1=失败：结束重试 */
        clock_gettime(CLOCK_MONOTONIC, &tn);
        long elapsed_ms = (tn.tv_sec - t0.tv_sec) * 1000 + (tn.tv_nsec - t0.tv_nsec) / 1000000;
        if (elapsed_ms >= 300) break; /* 总预算 300ms 耗尽 */
        usleep(10000);                /* 10ms 间隔，配合 300ms 总预算 */
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
        LOG_WRN("IPC还原异常: %s(PID:%d) %ldms内仍非项目 FUSE 视图 (尝试%d次)", arg->pkg, arg->pid,
                total_ms, attempts);
    } else {
        LOG_ERR("IPC还原失败: %s(PID:%d) ret=%d (尝试%d次, %ldms)", arg->pkg, arg->pid, ret,
                attempts, total_ms);
    }
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
        free(arg);
        return NULL;
    }

    //LOG("IPC线程开始异步挂载: %s(PID:%d)", arg->pkg, arg->pid);

    /* 先加入追踪列表，防止并发重入（幂等操作） */
    add_tracked(arg->pid);

    if (kill(arg->pid, 0) != 0) {
        LOG_DBG("IPC线程: 进程已死 %s(PID:%d)", arg->pkg, arg->pid);
        remove_tracked(arg->pid);
        free(arg);
        return NULL;
    }
    if (arg->uid >= NSP_SYSTEM_APP_UID_MIN) update_uid_map(arg->uid, arg->pkg);

    /* 再做一次配置匹配（主线程已检查过，但线程内重检保证一致性） */
    if (!is_target_app(arg->pkg, arg->uid, arg->pid, true)) {
        LOG_DBG("IPC线程: 配置无匹配 %s(PID:%d)", arg->pkg, arg->pid);
        remove_tracked(arg->pid);
        free(arg);
        return NULL;
    }

    /* 检查 FUSE 源 */
    const char* mnt_src = get_active_mnt_src();
    if (!mnt_src) {
        LOG_ERR("IPC线程: 全局 FUSE 不可用，无法为 %s(PID:%d) 挂载", arg->pkg, arg->pid);
        remove_tracked(arg->pid);
        free(arg);
        return NULL;
    }

    int ret = -1;
    /* 完整 perform_app_mount（含 mountinfo 读取） */
    ret = perform_app_mount(arg->pkg, arg->pid, arg->uid, NULL, "IPC通知");

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    long elapsed_us =
        (ts_end.tv_sec - ts_start.tv_sec) * 1000000L + (ts_end.tv_nsec - ts_start.tv_nsec) / 1000L;

    if (ret == 0) {
        LOG("IPC挂载完成: %s(PID:%d)%s 耗时: %ldus", arg->pkg, arg->pid, "", elapsed_us);
    } else {
        LOG_ERR("IPC挂载失败: %s(PID:%d) 耗时: %ldus", arg->pkg, arg->pid, elapsed_us);
        remove_tracked(arg->pid);
    }
    free(arg);
    return NULL;
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
    /* 两个动词 = 两条身份模型不同的通道（见 ipc_verify_app_identity 上方注释）：
       REPORT 只允许 root companion，REQ 只允许应用自身并通过完整绑定校验。 */
    bool is_report = (sscanf(buf, "REPORT %255s %d %d", pkg, &pid, &uid) == 3);
    bool is_req = false;
    if (!is_report) is_req = (sscanf(buf, "REQ %255s %d %d", pkg, &pid, &uid) == 3);
    if (is_report || is_req) {
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
        if (is_report) {
            /* root companion 通道：pre-specialize 上报的 pid/uid/pkg 是"即将成为
               目标"的值，不能要求当前进程身份匹配；root 是唯一合法对端。 */
            if (peer_uid != 0) {
                LOG_WRN("IPC: 拒绝非 root 对端的 REPORT（对端 uid=%u）；应用自身请走 REQ",
                        (unsigned)peer_uid);
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
           此路径是唯一可靠的清理时机） */
        cleanup_stale_tracked();
        if (is_isolated_uid(uid) || strstr(pkg, "_zygote") != nullptr) {
            send(client_fd, "OK", 2, MSG_NOSIGNAL);
            close(client_fd);
            return;
        }
        char clean_pkg[256];
        strncpy(clean_pkg, pkg, sizeof(clean_pkg) - 1);
        clean_pkg[sizeof(clean_pkg) - 1] = '\0';
        char* colon = strchr(clean_pkg, ':');
        if (colon) *colon = '\0';
        if (uid >= NSP_SYSTEM_APP_UID_MIN) update_uid_map(uid, clean_pkg);
        send(client_fd, "OK", 2, MSG_NOSIGNAL);
        close(client_fd); // 快速释放客户端连接

        /* 核心修复：使用 clean_pkg 而非原始 pkg 进行配置匹配，
           避免带 ':process' 后缀的包名误判为未配置应用 */
        if (!is_target_app(clean_pkg, uid, pid, true)) {
            /* 注入方法 v2：非目标应用需主动卸载项目 FUSE 并还原系统视图
               （IPC 通知是最常见的应用启动路径，必须覆盖，否则非目标应用
               永远停留在项目 FUSE 视图上）；v3 不还原——默认全局挂载 */
            if (inject_restore_nontarget()) {
                IpcMountArg* arg = malloc(sizeof(IpcMountArg));
                if (arg) {
                    strncpy(arg->pkg, clean_pkg, sizeof(arg->pkg) - 1);
                    arg->pkg[sizeof(arg->pkg) - 1] = '\0';
                    arg->pid = pid;
                    arg->uid = uid;
                    arg->mnt_src[0] = '\0';
                    pthread_t tid;
                    if (pthread_create(&tid, NULL, ipc_restore_thread, arg) == 0) {
                        pthread_detach(tid);
                        /* 派发日志已并入 ipc_restore_thread 的单条汇总，不再单独输出 */
                    } else {
                        LOG_ERR("IPC创建还原线程失败: %s(PID:%d)", clean_pkg, pid);
                        free(arg);
                    }
                }
            }
            return;
        }
        if (access(NSP_ANDROID_EMULATED_ROOT "/", F_OK) != 0) return;

        if (inject_is_global_replace()) {
            /* 新挂载方案（全局替换 v2/v3）：全局 FUSE 已挂载 /storage/emulated，
               目标应用自动继承代理视图，无需 injector 逐应用挂载——
               仅标记注入状态并打印规则即可（避免 perform_app_mount 的
               mountinfo 全量读取等 20ms+ 耗时）；非目标应用还原走上方分支（仅 v2） */
            mark_injected(pid);
            print_active_rules(clean_pkg, pid, uid, "IPC通知");
            LOG_DBG("全局替换模式: 目标应用 %s(PID:%d) 无需挂载，已由全局 FUSE 提供代理视图",
                    clean_pkg, pid);
            return;
        }

        /* 异步线程挂载：不阻塞主循环，子进程在后台完成 */
        IpcMountArg* arg = malloc(sizeof(IpcMountArg));
        if (arg) {
            strncpy(arg->pkg, clean_pkg, sizeof(arg->pkg) - 1);
            arg->pkg[sizeof(arg->pkg) - 1] = '\0';
            arg->pid = pid;
            arg->uid = uid;
            arg->mnt_src[0] = '\0';
            pthread_t tid;
            if (pthread_create(&tid, NULL, ipc_mount_thread, arg) == 0) {
                pthread_detach(tid);
                LOG_DBG("IPC派发异步挂载线程: %s(PID:%d)", clean_pkg, pid);
            } else {
                LOG_ERR("IPC创建挂载线程失败: %s(PID:%d)", clean_pkg, pid);
                free(arg);
            }
        }
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