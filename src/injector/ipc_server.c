#define _GNU_SOURCE
#include "ipc_server.h"
#include "common.h"
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
#include "ns_utils.h"

/* LIST_MODULES 应答：扫描模块目录，列出含 <name>.so 的模块（与 fuse_daemon 加载约定一致） */
static void handle_list_modules(int client_fd) {
    char reply[4096];
    int offset = 0;
    DIR* d = opendir(MODULES_DIR);
    if (d) {
        struct dirent* de;
        while ((de = readdir(d)) && offset < (int)sizeof(reply) - 64) {
            if (de->d_name[0] == '.') continue;
            char so[PATH_MAX];
            snprintf(so, sizeof so, "%s/%s/%s.so", MODULES_DIR, de->d_name, de->d_name);
            if (access(so, F_OK) == 0) {
                /* 先算整行长度，放得下才追加，防止 offset 越过缓冲区
                   （snprintf 返回应写长度，255 字符模块名单行最长 263 字节） */
                int n = snprintf(nullptr, 0, "MODULE|%s\n", de->d_name);
                if (n <= 0 || n >= (int)sizeof(reply) - offset) break;
                int w = snprintf(reply + offset, (size_t)((int)sizeof(reply) - offset), "MODULE|%s\n", de->d_name);
                if (w > 0) offset += w;
            }
        }
        closedir(d);
    }
    if (offset < (int)sizeof(reply) - 4) {
        int n = snprintf(reply + offset, sizeof(reply) - (size_t)offset, "END\n");
        if (n > 0) offset += n;
    } else {
        offset = (int)sizeof(reply) - 1;   /* 钳制，杜绝 size 回绕越界写 */
        reply[offset] = '\0';
    }
    send(client_fd, reply, offset, MSG_NOSIGNAL);
}

/* IPC 线程挂载参数 */
typedef struct {
    char pkg[256];
    int pid;
    uid_t uid;
    char mnt_src[256];
} IpcMountArg;

static void* ipc_mount_thread(void* raw) {
    IpcMountArg* arg = (IpcMountArg*)raw;
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

    //LOG("IPC线程开始异步挂载: %s(PID:%d)", arg->pkg, arg->pid);

    /* 先加入追踪列表，防止并发重入（幂等操作） */
    add_tracked(arg->pid);

    if (kill(arg->pid, 0) != 0) {
        LOG_DBG("IPC线程: 进程已死 %s(PID:%d)", arg->pkg, arg->pid);
        remove_tracked(arg->pid);
        free(arg);
        return NULL;
    }
    if (arg->uid >= 10000) update_uid_map(arg->uid, arg->pkg);

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
    bool fast_path = false;

    /*
     * 快速路径（fuse_direct）：跳过 /proc/pid/mountinfo 读取，直接发起异步 bind mount。
     * 对于首次启动的应用，目标路径几乎一定未被挂载，无需提前检查挂载状态，
     * 显著减少延迟，避免目标进程抢先创建文件。
     */
    if (g_global_cfg.fuse_direct) {
        char target_path[128];
        get_target_storage_path(arg->uid, target_path, sizeof(target_path));

        ret = ns_global_mount_async(arg->pid, arg->pkg, mnt_src, target_path);
        if (ret == 0) {
            fast_path = true;
            /* 快速路径成功：手动处理追踪标记与日志 */
            add_tracked(arg->pid);
            print_active_rules(arg->pkg, arg->pid, arg->uid, "IPC通知");
        }
    }

    /*
     * 慢速路径：回退到完整的 perform_app_mount（含 mountinfo 读取）。
     * 命中场景：非 fuse_direct 模式、或快速路径 mount 失败（需诊断挂载状态）。
     */
    if (!fast_path) {
        ret = perform_app_mount(arg->pkg, arg->pid, arg->uid, NULL, "IPC通知");
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    long elapsed_us = (ts_end.tv_sec - ts_start.tv_sec) * 1000000L +
                      (ts_end.tv_nsec - ts_start.tv_nsec) / 1000L;

    if (ret == 0) {
        LOG("IPC挂载完成: %s(PID:%d)%s 耗时: %ldus",
            arg->pkg, arg->pid, fast_path ? " [快速路径]" : "", elapsed_us);
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
    struct sockaddr_un addr = { .sun_family = AF_UNIX }; 
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, IPC_SOCKET_NAME, sizeof(addr.sun_path) - 2);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(IPC_SOCKET_NAME);
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
void handle_ipc_client_readable(int client_fd) {
    /* 核心修复：清除 O_NONBLOCK 状态使 Socket 回退至阻塞模式。
     * 唯有如此，内核底层的 SO_RCVTIMEO / SO_SNDTIMEO 500ms 保护逻辑才会真正生效。 */
    int flags = fcntl(client_fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(client_fd, F_SETFL, flags & ~O_NONBLOCK);
    }
    // 设置严格的 500ms 读写超时，防止异常客户端引发挂起
    struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
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
    if (sscanf(buf, "REPORT %255s %d %d", pkg, &pid, &uid) == 3 || sscanf(buf, "REQ %255s %d %d", pkg, &pid, &uid) == 3) {
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
        if (!g_passive_mode) {
            g_passive_mode = true;
            LOG("已接收到IPC通知，切换到被动模式，停止周期扫描");
        }
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
        if (uid >= 10000) update_uid_map(uid, clean_pkg);
        send(client_fd, "OK", 2, MSG_NOSIGNAL);
        close(client_fd); // 快速释放客户端连接

        /* 核心修复：使用 clean_pkg 而非原始 pkg 进行配置匹配，
           避免带 ':process' 后缀的包名误判为未配置应用 */
        if (!is_target_app(clean_pkg, uid, pid, true)) return;
        if (access("/storage/emulated/", F_OK) != 0) return;

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
    if (strncmp(buf, "MODULE_CHANGED", 14) == 0) {
        /* fuse_daemon 热插拔模块变更通知：置标志，主循环全量重挂 */
        extern volatile sig_atomic_t g_module_changed;
        g_module_changed = 1;
        send(client_fd, "OK", 2, MSG_NOSIGNAL);
        close(client_fd);
        return;
    }
    if (strncmp(buf, "FUSE_ALIVE", 10) == 0 || strncmp(buf, "FUSE_EXIT", 9) == 0) { 
        close(client_fd); 
        return; 
    }
    close(client_fd);
}