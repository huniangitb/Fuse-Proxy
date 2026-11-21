#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include "common.h"
#include "ns_utils.h"
#include "ns_global_replace.h"
#include "fast_search.h"
#include "injector.h"
#include "inject_target.h"
/* 非 static 导出：全局替换方案（ns_global_replace.c）共用此 ns 错误日志 */
void log_ns_error(const char* format, ...) {
    int fd = open(ERROR_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    if (fd >= 0) {
        char buf[512];
        va_list args;
        va_start(args, format);
        int len = vsnprintf(buf, sizeof(buf), format, args);
        va_end(args);
        if (len > 0) {
            write(fd, buf, len);
        }
        close(fd);
    }
}
/* read_file_dynamic 已抽取至 src/core/common.c（公共工具，见 common.h），
   此处不再重复实现 */
/* 解析子进程回传日志行（格式 "<level>|<msg>\n"）并写入父进程环形缓冲 */
static void replay_child_log_line(char* line) {
    char* sep = strchr(line, '|');
    if (!sep) {
        LOG("[ns子进程] %s", line);
        return;
    }
    *sep = '\0';
    int lv = atoi(line);
    const char* msg = sep + 1;
    size_t mlen = strlen(msg);
    while (mlen > 0 && (msg[mlen - 1] == '\n' || msg[mlen - 1] == '\r'))
        ((char*)msg)[--mlen] = '\0';
    log_internal((LogLevel)lv, "%s\n", msg);
}

/* 非 static 导出：ns_global_replace.c（全局替换方案）在目标命名空间内
   执行 replace/restore 时共用本命名空间执行原语 */
int run_in_mnt_ns_timeout(int target_pid, int (*func)(void*), void* args, int* child_err,
                          int timeout_ms) {
    struct timespec t_start;
    clock_gettime(CLOCK_MONOTONIC, &t_start);
    int status_pipe[2];
    if (pipe2(status_pipe, O_CLOEXEC) < 0) {
        log_ns_error("[ns_error] Failed to create sync pipe: %s\n", strerror(errno));
        return -1;
    }
    /* 子进程日志回传管道：fork 后子进程内环形缓冲/sender 线程不可达，
       子进程 log_internal 经 g_log_forward_fd 写入本管道，父进程读取后
       统一写入环形缓冲，保证 ns 操作子进程日志在 log_ctl 可见 */
    int log_pipe[2];
    if (pipe2(log_pipe, O_CLOEXEC) < 0) {
        close(status_pipe[0]);
        close(status_pipe[1]);
        log_ns_error("[ns_error] Failed to create log pipe: %s\n", strerror(errno));
        return -1;
    }
    pid_t child = fork();
    if (child < 0) {
        close(status_pipe[0]);
        close(status_pipe[1]);
        close(log_pipe[0]);
        close(log_pipe[1]);
        return -1;
    }
    if (child == 0) {
        close(status_pipe[0]);
        close(log_pipe[0]);
        g_log_forward_fd = log_pipe[1]; /* 子进程日志转发到管道 */
        char ns_path[64];
        snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", target_pid);
        int fd = open(ns_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) _exit(10);
        if (setns(fd, CLONE_NEWNS) != 0) {
            close(fd);
            _exit(11);
        }
        close(fd);
        int ret = func(args);
        ssize_t w = write(status_pipe[1], &ret, sizeof(ret));
        (void)w;
        close(status_pipe[1]);
        close(log_pipe[1]);
        /* 退出码映射：0=成功, 正数=业务返回值(1=跳过), 255=负数(-1=失败)，
           供父进程 fallback 分支（未读到 status 管道）还原返回值 */
        _exit(ret == 0 ? 0 : (ret > 0 ? ret : 255));
    }
    close(status_pipe[1]);
    close(log_pipe[1]);
    /* 日志管道非阻塞：子进程可能持续输出，读空后不能阻塞等待 */
    int log_flags = fcntl(log_pipe[0], F_GETFL, 0);
    fcntl(log_pipe[0], F_SETFL, log_flags | O_NONBLOCK);
    int ret_val = -1;
    bool status_ready = false;
    long elapsed = 0;
    /* 循环 poll：日志管道可能先就绪而 status 未就绪，必须继续等 status */
    for (;;) {
        struct pollfd pfd[2] = {{.fd = status_pipe[0], .events = POLLIN | POLLHUP},
                                {.fd = log_pipe[0], .events = POLLIN | POLLHUP}};
        int poll_ret = poll(pfd, 2, timeout_ms);
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed = (now.tv_sec - t_start.tv_sec) * 1000 + (now.tv_nsec - t_start.tv_nsec) / 1000000;
        if (poll_ret < 0) {
            ret_val = -1;
            break;
        }
        /* 排空子进程回传日志（非阻塞，EAGAIN/EOF 即止） */
        if (poll_ret > 0 && (pfd[1].revents & (POLLIN | POLLHUP))) {
            char line[2048];
            size_t plen = 0;
            char chunk[1024];
            for (;;) {
                ssize_t r = read(log_pipe[0], chunk, sizeof(chunk));
                if (r < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    break;
                }
                if (r == 0) break;
                for (ssize_t i = 0; i < r; i++) {
                    if (chunk[i] == '\n') {
                        line[plen] = '\0';
                        replay_child_log_line(line);
                        plen = 0;
                    } else if (plen < sizeof(line) - 1) {
                        line[plen++] = chunk[i];
                    }
                }
            }
            if (plen > 0) {
                line[plen] = '\0';
                replay_child_log_line(line);
            }
        }
        if (poll_ret > 0 && (pfd[0].revents & (POLLIN | POLLHUP))) {
            status_ready = true;
            break;
        }
        if (poll_ret == 0 || elapsed >= timeout_ms) break; /* 超时 */
        /* 仅日志就绪而 status 未就绪：继续轮询 */
    }
    if (status_ready) {
        int child_ret = -1;
        ssize_t r_len = read(status_pipe[0], &child_ret, sizeof(child_ret));
        int status = 0;
        /* waitpid 返回值必须检查：主循环的 reap_zombies（waitpid(-1,WNOHANG)）
           可能已抢先收走本子进程（ns 子进程与主循环并发 wait），此时返回
           -1/ECHILD，status 保持初值 0（WIFEXITED(0)=true、WEXITSTATUS=0），
           下面的退出码还原会把"未知"误判成"成功"。子进程先写 status 管道再
           _exit，故 r_len 命中时 status 用不上；r_len 未命中才依赖它——那种
           情况下拿不到真实状态必须判失败，不能默认成 0。
           更稳的做法是让主循环收尸时把 ns 子进程也留档（见 reaped_managed），
           此处先做"返回值必查"的最小修复。 */
        pid_t w = waitpid(child, &status, 0);
        bool know_status = (w == child);
        if (w < 0 && errno != ECHILD && errno != EINTR)
            LOG_WRN("ns操作 waitpid 失败 pid=%d: %s", target_pid, strerror(errno));
        if (r_len == sizeof(child_ret)) {
            ret_val = child_ret;
            if (child_err) *child_err = child_ret;
            if (ret_val != 0) {
                if (ret_val == 1) {
                    LOG_DBG("ns操作 pid=%d 耗时: %ldms, 结果: 跳过(1)", target_pid, elapsed);
                } else {
                    LOG_DBG("ns操作 pid=%d 耗时: %ldms, 失败码: %d", target_pid, elapsed, ret_val);
                }
            } else if (elapsed > 50) {
                LOG_DBG("ns操作 pid=%d 耗时: %ldms", target_pid, elapsed);
            }
        } else if (!know_status) {
            /* 子进程状态被通用收尸抢先取走且未留档：无法判定结果，按失败处理
               （fail-closed——把"未知"当成功会让上层认为挂载/卸载已完成） */
            LOG_WRN("ns操作 pid=%d 子进程状态不可得（已被通用收尸取走），按失败处理", target_pid);
            if (child_err) *child_err = ECHILD;
            ret_val = -1;
        } else {
            /* 子进程未写 status 管道（异常路径）：以退出码还原返回值。
               func 退出码映射（见 fork 子进程 _exit）：0=成功, 正数=业务
               返回值(1=跳过), 255=负数(-1=失败) */
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                if (child_err) *child_err = code;
                ret_val = (code == 0) ? 0 : (code == 255 ? -1 : code);
                LOG_WRN("ns操作子进程未写入管道异常退出, pid=%d, code: %d (ret=%d)", target_pid,
                        code, ret_val);
            } else if (WIFSIGNALED(status)) {
                LOG_WRN("ns操作子进程被信号杀死, pid=%d, signal=%d", target_pid, WTERMSIG(status));
                ret_val = -1;
            } else {
                ret_val = -1;
            }
        }
    } else {
        kill(child, SIGKILL);
        /* 强制终止后回收：同样不能假设成功——ECHILD 说明已被主循环收走 */
        if (waitpid(child, NULL, 0) < 0 && errno != ECHILD)
            LOG_WRN("ns操作超时后 waitpid 失败 pid=%d: %s", target_pid, strerror(errno));
        if (child_err) *child_err = ETIMEDOUT;
        errno = ETIMEDOUT;
        LOG_WRN("ns操作 pid=%d 超时(%dms), 予以强制终止", target_pid, timeout_ms);
    }
    close(status_pipe[0]);
    close(log_pipe[0]);
    /* 透传子进程业务返回值：0=成功, 1=跳过, -1=失败（不允许再折叠，否则
       调用方无法区分"跳过"与"失败"） */
    return ret_val == 0 ? 0 : (ret_val > 0 ? ret_val : -1);
}
static int run_in_mnt_ns(int target_pid, int (*func)(void*), void* args, int* child_err) {
    return run_in_mnt_ns_timeout(target_pid, func, args, child_err, 500);
}
/* 核心优化：高并发非阻塞异步 fork 机制 */
int run_in_mnt_ns_async(int target_pid, const char* pkg, int (*func)(void*), void* args,
                        void* mount_args) {
    int status_pipe[2];
    if (pipe2(status_pipe, O_CLOEXEC | O_NONBLOCK) < 0) {
        return -1;
    }
    pid_t child = fork();
    if (child < 0) {
        close(status_pipe[0]);
        close(status_pipe[1]);
        return -1;
    }
    if (child == 0) {
        close(status_pipe[0]);
        char ns_path[64];
        snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", target_pid);
        int fd = open(ns_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) _exit(10);
        if (setns(fd, CLONE_NEWNS) != 0) {
            close(fd);
            _exit(11);
        }
        close(fd);
        int ret = func(args);
        ssize_t w = write(status_pipe[1], &ret, sizeof(ret));
        (void)w;
        close(status_pipe[1]);
        _exit(ret == 0 ? 0 : 1);
    }
    close(status_pipe[1]);
    MountTaskCtx* ctx = malloc(sizeof(MountTaskCtx));
    if (!ctx) {
        close(status_pipe[0]);
        kill(child, SIGKILL);
        waitpid(child, nullptr, WNOHANG);
        return -1;
    }
    ctx->status_pipe_fd = status_pipe[0];
    ctx->child_pid = child;
    ctx->target_pid = target_pid;
    strncpy(ctx->pkg_name, pkg, sizeof(ctx->pkg_name) - 1);
    ctx->pkg_name[sizeof(ctx->pkg_name) - 1] = '\0';
    ctx->mount_args = mount_args;
    /* 注册**先于** epoll_ctl(ADD)：反过来的话，事件可以在注册完成前就被主线程
       收到，on_client_fd 在注册表里查不到该 fd，会把它当普通 IPC 客户端读掉并
       close —— 挂载结果丢失且 ctx 泄漏（该应用既不标注入也不重试）。 */
    if (!register_async_mount_pipe(status_pipe[0], ctx)) {
        close(status_pipe[0]);
        free(ctx);
        kill(child, SIGKILL);
        waitpid(child, nullptr, WNOHANG);
        return -1;
    }
    struct epoll_event ev = {.events = EPOLLIN | EPOLLONESHOT, .data.fd = status_pipe[0]};
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, status_pipe[0], &ev) < 0) {
        unregister_async_mount_pipe(status_pipe[0]); /* 撤销注册：别留下已关闭 fd/已释放 ctx */
        close(status_pipe[0]);
        free(ctx);
        kill(child, SIGKILL);
        waitpid(child, nullptr, WNOHANG);
        return -1;
    }
    return 0;
}
struct MountArgs {
    const char* src;
    const char* target;
    int tree_fd; /* ns_bind_mount_cross：调用方命名空间预克隆的源树 fd（-1=无） */
};
static int do_bind_mount(void* raw_args) {
    struct MountArgs* args = (struct MountArgs*)raw_args;
    if (access(args->src, F_OK) != 0) return errno;
    struct stat st;
    if (stat(args->target, &st) != 0) mkdir(args->target, 0755);
    if (mount(args->src, args->target, nullptr, MS_BIND | MS_REC, nullptr) != 0) return errno;
    return 0;
}
/* mountinfo 扫描的唯一实现已移至 src/injector/ns_mountinfo.c（C7 收口）：
   ns_scan_mountinfo / ns_collect_mounts_under_pid，声明见 ns_global_replace.h。 */

static int do_umount_recursive(void* raw_args) {
    const char* target = (const char*)raw_args;
    char mounts[128][NS_MOUNT_PATH_MAX];
    int count = ns_collect_mounts_under_pid(getpid(), target, mounts, 128, "递归卸载");
    for (int i = count - 1; i >= 0; i--)
        for (int t = 0; t < 8; t++)
            if (umount2(mounts[i], MNT_DETACH) == 0) break;
    for (int t = 0; t < 8; t++)
        if (umount2(target, MNT_DETACH) == 0) break;
    return 0;
}
static int do_umount_and_rmdir(void* raw_args) {
    const char* target = (const char*)raw_args;
    char mounts[64][NS_MOUNT_PATH_MAX];
    int count = ns_collect_mounts_under_pid(getpid(), target, mounts, 64, "卸载并删除");
    for (int i = count - 1; i >= 0; i--)
        for (int t = 0; t < 8; t++)
            if (umount2(mounts[i], MNT_DETACH) == 0) break;
    for (int t = 0; t < 8; t++) {
        if (umount2(target, MNT_DETACH) == 0) break;
    }
    rmdir(target);
    return 0;
}

/*
 * do_force_umount_stale — 强制卸载目标路径上的所有挂载（包括陈旧的 FUSE 挂载），
 * 使用 MNT_DETACH 确保即使 FUSE 守护进程已死也能成功卸载。
 * 与 do_umount_and_rmdir 的区别：
 *  - 不执行 rmdir，保留目录结构
 *  - 更宽松的匹配：目标路径自身以及其下的子挂载全部卸载
 *  - 对 EINVAL（未挂载）静默跳过
 *  - 专门用于 inject_global_fuse 启动前的预清理
 */
static int do_force_umount_stale(void* raw_args) {
    const char* target = (const char*)raw_args;
    /* 1. 先递归卸载所有子挂载点（从最深层开始） */
    char mounts[64][NS_MOUNT_PATH_MAX];
    int count = ns_collect_mounts_under_pid(getpid(), target, mounts, 64, "强制卸载");
    for (int i = count - 1; i >= 0; i--) {
        for (int t = 0; t < 8; t++) {
            if (umount2(mounts[i], MNT_DETACH) == 0) break;
            if (errno == EINVAL) break; /* 本就不是挂载点 */
        }
    }
    /* 2. 强制卸载目标挂载点本身 */
    for (int t = 0; t < 8; t++) {
        if (umount2(target, MNT_DETACH) == 0) break;
        if (errno == EINVAL) break; /* 本就不是挂载点，静默通过 */
    }
    return 0;
}

/*
 * ns_force_umount_stale — 在目标 PID 的挂载命名空间内强制卸载陈旧 FUSE 挂载。
 * 用于 inject_global_fuse() 启动新 fuse_daemon 之前的预清理，
 * 确保 /mnt/nsp_global 上没有残留的 "Transport endpoint is not connected" 挂载。
 *
 * 多级防御：
 *   ① umount2(MNT_DETACH) 不依赖 FUSE 守护进程响应
 *   ② 子挂载优先卸载，避免 EBUSY
 *   ③ 最多重试 8 次，容忍短暂竞争
 *   ④ 非挂载点（EINVAL）静默跳过
 */
int ns_force_umount_stale(int pid, const char* target) {
    int child_err = 0;
    /* 在目标命名空间中执行卸载（超时 5 秒） */
    int ret = run_in_mnt_ns_timeout(pid, do_force_umount_stale, (void*)target, &child_err, 5000);
    if (ret != 0) {
        LOG_DBG("force_umount_stale pid=%d target=%s 子进程异常退出, err=%d", pid, target,
                child_err);
    }
    /* 自己也卸载一次，覆盖 pid 就是当前进程自身的情况 */
    do_force_umount_stale((void*)target);
    return 0;
}

static int do_make_shared(void* raw_args) {
    const char* target = (const char*)raw_args;
    if (mount(nullptr, target, nullptr, MS_SHARED, nullptr) != 0) return errno;
    return 0;
}
int ns_bind_mount(int pid, const char* source, const char* target) {
    struct MountArgs args = {source, target, -1};
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_bind_mount, &args, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}
/* open_tree/move_mount 常量：宿主 glibc <sys/mount.h>/<fcntl.h> 已提供，
   NDK bionic 缺失时按 UAPI 值补齐（Linux 5.2+ 系统调用） */
#ifndef SYS_open_tree
#if defined(__x86_64__) || defined(__aarch64__)
#define SYS_open_tree 428
#endif
#endif
#ifndef SYS_move_mount
#if defined(__x86_64__) || defined(__aarch64__)
#define SYS_move_mount 429
#endif
#endif
#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif
/* 在调用方（源）命名空间内克隆 source 处的挂载树：open_tree 克隆以路径为根、
   AT_RECURSIVE 含全部子挂载，语义与 mount(2) MS_BIND|MS_REC 逐字节等价 */
static int open_tree_clone(const char* source) {
    return (int)syscall(SYS_open_tree, AT_FDCWD, source,
                        OPEN_TREE_CLONE | AT_RECURSIVE | OPEN_TREE_CLOEXEC);
}
static int do_cross_bind(void* raw_args) {
    struct MountArgs* args = (struct MountArgs*)raw_args;
    if (args->tree_fd >= 0) {
        struct stat st;
        if (stat(args->target, &st) != 0 && mkdir_recursive(args->target) != 0 && errno != EEXIST) {
            return errno;
        }
        if (syscall(SYS_move_mount, args->tree_fd, "", AT_FDCWD, args->target,
                    MOVE_MOUNT_F_EMPTY_PATH) == 0) {
            return 0;
        }
        int err = errno;
        log_ns_error("[ns_error] cross bind move_mount(fd -> %s) errno=%d (%s)\n", args->target,
                     err, strerror(err));
        return err;
    }
    /* 兜底：源无法在调用方命名空间克隆（如缺 open_tree 的老内核）时退回旧式
       mount(2)——仅在允许源路径穿越 /proc/<pid>/root 的内核上可用 */
    return do_bind_mount(raw_args);
}
/* 在目标 pid 的挂载命名空间内查找应用 uid 对应的族根挂载点
   （/mnt/<family>/<user_id>/emulated，user_id = uid/100000）。族根即目标存储
   路径（/storage/emulated）的系统视图本体，且在应用 ns 内始终存活——逐应用
   注入/清理只动 target、不碰族根——同 ns 内 MS_REC bind 即可重建目标，无需跨
   ns 拉 /proc/<pid>/root<target>。族优先级与 preserve 一致：
   user > androidwritable > installer。命中返回 0 并填充 out，否则 ENOENT */
int ns_find_family_root(int pid, uid_t app_uid, char* out, size_t outsz) {
    if (!out || outsz == 0) return EINVAL;
    out[0] = '\0';
    int user_id = (int)(app_uid / 100000u);
    NsMountEntry* all = NULL;
    int n = ns_read_mountinfo_pid(pid, &all);
    if (n < 0) {
        /* 读不到挂载表 = 未知：不能报 ENOENT（调用方会当成「这个用户没有族根」） */
        free(all);
        return EIO;
    }
    int ret = ENOENT;
    for (int fam = 2; fam >= 0 && ret == ENOENT; fam--) {
        for (int i = 0; i < n; i++) {
            int ruid = 0;
            if (ns_is_family_root(all[i].mount_point) &&
                ns_parse_family_root(all[i].mount_point, &ruid) == fam && ruid == user_id) {
                snprintf(out, outsz, "%s", all[i].mount_point);
                ret = 0;
                break;
            }
        }
    }
    free(all);
    return ret;
}
/* 跨命名空间 bind：内核拒绝 mount(2) 的源路径经 /proc/<pid>/root 穿越到外层
   命名空间（源必须位于当前命名空间，一律 EINVAL），合法机制是「源命名空间
   open_tree(OPEN_TREE_CLONE) 克隆 → 目标命名空间 move_mount」。fd 在调用方
   命名空间打开，fork 后由 setns 到目标命名空间的子进程继承；父进程在
   run_in_mnt_ns 返回后关闭自身副本 */
int ns_bind_mount_cross(int pid, const char* source, const char* target) {
    struct MountArgs args = {source, target, -1};
    args.tree_fd = open_tree_clone(source);
    if (args.tree_fd < 0) {
        int e = errno;
        log_ns_error("[ns_error] open_tree(%s) errno=%d (%s)，退回 mount(2) 源穿越\n", source, e,
                     strerror(e));
    }
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_cross_bind, &args, &child_err);
    if (args.tree_fd >= 0) close(args.tree_fd);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}
int ns_umount_recursive(int pid, const char* target) {
    return run_in_mnt_ns(pid, do_umount_recursive, (void*)target, nullptr);
}
int ns_umount_and_rmdir(int pid, const char* target) {
    return run_in_mnt_ns(pid, do_umount_and_rmdir, (void*)target, nullptr);
}
int ns_make_shared(int pid, const char* target) {
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_make_shared, (void*)target, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}
/* ns_find_native_submounts 的回调上下文：与旧实现逐字相同的判定
   （严格子路径、不含 base 自身、跳过 fuse 类、容量触顶即停），只是把"整文件
   读入 + 逐行手写分词"换成唯一的扫描原语 + 前缀预筛。 */
struct NsNativeSubCtx {
    const char* base;
    size_t base_len;
    char (*out)[256];
    int max;
    int n;
};

static int ns_native_sub_cb(const NsMountLine* ln, void* vctx) {
    struct NsNativeSubCtx* c = vctx;
    const char* mp = ln->mount_point;
    if (strncmp(mp, c->base, c->base_len) != 0) return 0;
    if (mp[c->base_len] != '/' && mp[c->base_len] != '\0') return 0;
    if (strcmp(mp, c->base) == 0) return 0;
    if (strlen(mp) >= 256) return 0;
    if (fast_strstr(ln->fstype, "fuse") != nullptr) return 0; /* 只保留系统原生视图 */
    if (c->n >= c->max) return 1;                             /* 触顶：停止扫描 */
    snprintf(c->out[c->n], 256, "%s", mp);
    c->n++;
    return 0;
}

int ns_find_native_submounts(int pid, const char* base_path, char mount_points[][256],
                             int max_count) {
    if (!base_path || !mount_points || max_count <= 0) return 0;
    struct NsNativeSubCtx c = {.base = base_path,
                               .base_len = strlen(base_path),
                               .out = mount_points,
                               .max = max_count,
                               .n = 0};
    /* 前缀预筛：只有含 base_path 子串的行才解析（真机上应用 ns 有上千条 /apex、
       /system 挂载，旧实现每条都要过 4KB 零初始化 + 手写分词） */
    const char* prefixes[1] = {base_path};
    if (ns_scan_mountinfo_prefixed(pid, prefixes, 1, ns_native_sub_cb, &c) < 0) return 0;
    return c.n;
}
/* ══════════════ 合并挂载分段计时（定位"135ms 花在哪"） ══════════════
 * do_combined_mount 跑在 fork 出的子进程里，与父进程不共享栈（COW）——所以用一页
 * MAP_SHARED|MAP_ANONYMOUS 由子进程写、父进程读；限速输出也放在父进程：子进程每次
 * 都是新 fork，在那里做采样/限速计数永远从 0 开始，毫无意义。
 * 只在同步路径（ns_combined_mount）开启；异步/重试路径传 NULL，零成本。
 * 输出纪律：总耗时 ≥ NSP_SEG_LOG_MIN_MS 一定打一条（慢挂载才是排查目标），否则
 * 1/NSP_SEG_SAMPLE 采样；另有每秒 NSP_SEG_MAX_PER_SEC 条的硬上限，被折叠的条数
 * 附在下一行行尾——绝不允许分段计时自己变成新的刷屏源。 */
enum {
    NSP_SEG_READY = 0, /* 就绪门控：等 /storage/emulated 出现在应用 ns */
    NSP_SEG_PRE,       /* 源预检 statfs（必须在任何卸载之前） */
    NSP_SEG_PRIV,      /* MS_PRIVATE|MS_REC 传播隔离 */
    NSP_SEG_MOUNTINFO, /* /proc/self/mountinfo 扫描（备份 + 目标） */
    NSP_SEG_UMOUNT,    /* umount2 卸载（备份子挂载 + 目标子挂载 + 目标） */
    NSP_SEG_BIND,      /* bind 源到目标 */
    NSP_SEG_VERIFY,    /* 挂载后 statfs 复核 */
    NSP_SEG_SUB,       /* preserve 子挂载（Android/data|obb|media） */
    NSP_SEG_COUNT
};

struct NsMountSeg {
    int64_t us[NSP_SEG_COUNT];
    /* mountinfo 段的规模快照（子进程写、父进程读）：段耗时偏高时用来区分
       「命名空间条目多」（靠预筛/少扫一次解决）与「CPU 被抢」（只能挪出关键路径）。
       两次扫描读的是同一份 mountinfo，故只记最后一次的规模。 */
    long mo_lines;
    long mo_bytes;
    long mo_candidates;
    long mo_cpu_us; /* 扫描期间本进程 CPU 时间（user+sys） */
    long mo_csw;    /* 扫描期间非自愿上下文切换次数 */
    int mo_skipped; /* 1 = 目标已是挂载点，快路径未读 mountinfo */
};

#define NSP_SEG_LOG_MIN_MS 20
#define NSP_SEG_SAMPLE 1024
#define NSP_SEG_MAX_PER_SEC 20

static int64_t ns_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/* 限速状态（多 IPC 挂载线程并发调用 → 用原子计数，不加锁） */
static unsigned long g_seg_samples;
static int64_t g_seg_window_ms;
static int g_seg_window_lines;
static unsigned long g_seg_suppressed;

static void ns_seg_log(const char* pkg, const struct NsMountSeg* seg, int64_t outer_us) {
    int64_t total_us = 0;
    for (int i = 0; i < NSP_SEG_COUNT; i++) total_us += seg->us[i];
    unsigned long n = __atomic_add_fetch(&g_seg_samples, 1, __ATOMIC_RELAXED);
    bool want = (total_us / 1000 >= NSP_SEG_LOG_MIN_MS) || (n % NSP_SEG_SAMPLE == 0);
    if (!want) return;
    int64_t now_ms = ns_now_us() / 1000;
    if (now_ms - g_seg_window_ms >= 1000) {
        g_seg_window_ms = now_ms;
        g_seg_window_lines = 0;
    }
    if (g_seg_window_lines >= NSP_SEG_MAX_PER_SEC) {
        g_seg_suppressed++;
        return;
    }
    g_seg_window_lines++;
    int64_t outer = outer_us - total_us;
    /* mountinfo 段后面的括号是规模快照：行数/字节/预筛命中行数。段耗时长而条目
       不多 = CPU 被应用冷启动抢走；条目几千行 = 命名空间本身巨大（预筛已挡掉
       99% 的解析，剩下的主要是读文件本身）。 */
    char mi_detail[128];
    if (seg->mo_skipped)
        snprintf(mi_detail, sizeof mi_detail, "跳过:目标已是挂载点,未读 mountinfo");
    else
        snprintf(mi_detail, sizeof mi_detail,
                 "行=%ld 字节=%ldKB 预筛过=%ld CPU=%ldms 抢断=%ld", seg->mo_lines,
                 seg->mo_bytes / 1024, seg->mo_candidates, seg->mo_cpu_us, seg->mo_csw);
    LOG_DBG("[ns计] %s 就绪=%lldms 预检=%lldms 私有=%lldms mountinfo=%lldms(%s) umount=%lldms "
            "bind=%lldms 复核=%lldms 子挂载=%lldms 合计=%lldms 段外=%lldms 采样=%lu 折叠=%lu",
            pkg ? pkg : "?", (long long)(seg->us[NSP_SEG_READY] / 1000),
            (long long)(seg->us[NSP_SEG_PRE] / 1000), (long long)(seg->us[NSP_SEG_PRIV] / 1000),
            (long long)(seg->us[NSP_SEG_MOUNTINFO] / 1000), mi_detail,
            (long long)(seg->us[NSP_SEG_UMOUNT] / 1000),
            (long long)(seg->us[NSP_SEG_BIND] / 1000), (long long)(seg->us[NSP_SEG_VERIFY] / 1000),
            (long long)(seg->us[NSP_SEG_SUB] / 1000), (long long)(total_us / 1000),
            (long long)(outer < 0 ? 0 : outer / 1000), n, g_seg_suppressed);
}

struct CombinedMountArgs {
    const char* pkg;
    const char* source;
    const char* target;
    const char* backup;
    char (*preserve_paths)[256];
    int preserve_count;
    pid_t target_pid; /* 就绪等待期间的存活检查目标 */
    /* 目标应用的 uid（父进程在 fork 前解析一次）。回滚要按 uid 找族根
       /mnt/{user,androidwritable,installer}/<uid>/emulated；旧实现在子进程里用
       get_app_uid(target_pid) 反查——进程已退出时得 0，二次用户会被绑到用户 0
       的视图（跨用户泄漏），用户 0 则找不到族根。 */
    uid_t app_uid;
    /* 挂载前等待目标 ns 内 /storage/emulated 出现的预算（ms）。0 = 只查一次、
       缺失即裁决失败（权威尝试，loud）；>0 = 在其内按 100ms 步进等待；
       负值哨兵 NSP_READINESS_QUIET = 后台通道（异步/重试）：不等待，缺失属预期，
       只记 DEBUG、不写 error.log、不出现"交由重试队列"措辞。 */
    int readiness_ms;
    /* 分段计时共享页：仅同步路径（ns_combined_mount）非 NULL，异步/重试路径为 NULL
       （见上方 NsMountSeg 注释）。 */
    struct NsMountSeg* seg;
};

#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546 /* linux/magic.h；NDK 与 GNU 头文件均有，兜底防缺 */
#endif

/* 该路径当前是不是 FUSE 挂载（statfs 一次，无 /proc 解析）。
   三处使用：挂载前校验**源**（不同 ROM 的 /mnt 传播设置可能让源在应用 ns 里只是
   一个普通空目录，bind 照样"成功"但视图全空）、挂载后校验**目标**（必须真的变成
   FUSE 视图，否则立即回滚，绝不把"挂载成功但空"的状态留给应用）、以及稳态对账的
   族根快查（族根与源都必须还是 FUSE 视图）。 */
bool ns_path_is_fuse_mount(const char* path) {
    struct statfs sfs;
    if (statfs(path, &sfs) != 0) return false;
    return (unsigned long)sfs.f_type == (unsigned long)FUSE_SUPER_MAGIC;
}

/* 合并挂载失败/校验失败后的唯一回滚出口：用应用 ns 内始终存活的族根（
   /mnt/{user,androidwritable,installer}/<uid>/emulated）重新 bind 出原生视图。
   回滚失败即 loud 报错——此时应用存储确实不可用，只能交重试队列按退避接管。 */
static void ns_rollback_to_family_root(const char* pkg, const char* target, uid_t app_uid) {
    char fam_src[PATH_MAX];
    if (ns_find_family_root(getpid(), app_uid, fam_src, sizeof fam_src) == 0 &&
        mount(fam_src, target, nullptr, MS_BIND | MS_REC, nullptr) == 0) {
        log_internal(LOG_WARN, "[ns_error] [%s] 合并挂载失败已回滚：%s 还原为族根视图 %s（uid=%u）", pkg,
                     target, fam_src, (unsigned)app_uid);
    } else {
        log_ns_error(
            "[ns_error] [%s] Combined mount rollback failed: target=%s 仍无挂载，应用存储不可用\n", pkg,
            target);
        log_internal(LOG_ERROR,
                     "[ns_error] [%s] 合并挂载失败且回滚未成功（族根 %s 不可用或 bind 失败），"
                     "target=%s 保持裸挂载态，交由重试队列",
                     pkg, fam_src[0] ? fam_src : "(未找到)", target);
    }
}

/* NsMountEntry 类型、NS_MOUNTINFO_MAX、mountinfo 枚举与族根工具
   （ns_read_mountinfo_pid/ns_is_family_root/ns_parse_family_root 等）已拆至
   src/injector/ns_global_replace.c/.h（见头部 include） */
/* 就绪门控（仅进程生命周期首次注入，先于任何 umount2）：ColorOS 等 ROM 的应用
   命名空间可能尚未建立 /storage/emulated 条目且 /storage tmpfs 只读——旧实现此处
   mkdir_recursive 触发 EROFS 降级。现改为等待 vold 完成装配：5ms 步进（旧实现
   100ms，视图一出现就立刻挂载，避免最多 ~100ms 的采样滞后——这段等待落在应用主线程
   上时，粒度直接就是冷启动延迟），预算由调用方给定，期间进程死亡立即放弃；超时
   返回 ENOENT 交由重试队列接管。全程不主动创建目录，且失败发生在任何卸载之前，
   应用原生视图零污染。返回 0=已就绪，否则 errno 风格失败码。 */
static int ns_wait_ready(const struct CombinedMountArgs* args) {
    const char* pkg = args->pkg;
    const char* target = args->target;
    if (access(target, F_OK) == 0) return 0;
    int waited = 0;
    while (waited < args->readiness_ms) {
        if (kill(args->target_pid, 0) != 0) {
            log_ns_error("[ns_error] [%s] 等待 %s 出现期间目标进程退出\n", pkg, target);
            log_internal(LOG_WARN, "[ns_error] [%s] 等待 %s 出现期间目标进程退出", pkg, target);
            return ESRCH;
        }
        usleep(5 * 1000);
        waited += 5;
        if (access(target, F_OK) == 0) {
            LOG_DBG("[%s] %s 已就绪（等待 %dms 后出现），继续合并挂载", pkg, target, waited);
            return 0;
        }
    }
    /* 两类"缺失属常态"的通道都只记 DEBUG：
       ① 负值哨兵 = 后台通道（异步扫描 / 失败重试）——本通道正是重试队列自己；
       ② 就地快试预算（>0 且 ≤ NSP_READINESS_INLINE_MAX_MS，POST 的 20ms）——真机
          vold 装配 /storage/emulated 要 135–150ms，20ms 必然等不到，那是**预期**
          未就绪，调用方 fail-open 交后台重试。若按权威尝试 loud 落 error.log，
          真机每次冷启动都会留一条"缺失(20ms 内未出现)"：旧实现 250ms 预算下
          error.log 已有 31 条这种噪声，改成 20ms 后会变成 202/322 次挂载各一条。 */
    if (args->readiness_ms < 0 || (args->readiness_ms > 0 &&
                                   args->readiness_ms <= NSP_READINESS_INLINE_MAX_MS)) {
        LOG_DBG("[%s] %s 未就绪（%s，稍后补挂载）", pkg, target,
                args->readiness_ms < 0 ? "后台通道" : "就地快试");
        return ENOENT;
    }
    log_ns_error("[ns_error] [%s] %s 在应用命名空间缺失(%dms 内未出现)，交由重试队列\n", pkg,
                 target, args->readiness_ms);
    log_internal(LOG_WARN, "[ns_error] [%s] %s 在应用命名空间缺失(%dms 内未出现)，交由重试队列",
                 pkg, target, args->readiness_ms);
    return ENOENT;
}

/* 懒卸载一个挂载点（MNT_DETACH：只摘本命名空间的挂载，不等待引用计数）。
   旧实现对每个点固定重试 8 次——MNT_DETACH 不会返回 EBUSY 之外的"可重试"错误，
   8 次纯属重复系统调用（4 处 × 8 次 = 最坏 32 次无效 umount2）。这里只在 EBUSY
   上再试一次（1ms 间隔），其余错误（EINVAL=本来就不是挂载点、ENOENT…）直接放弃。 */
static void ns_umount_detach(const char* path) {
    if (umount2(path, MNT_DETACH) == 0) return;
    if (errno != EBUSY) return;
    usleep(1000);
    if (umount2(path, MNT_DETACH) != 0)
        LOG_DBG("卸载 %s 失败: %s（保持原样，后续 bind 覆盖）", path, strerror(errno));
}

/* 分段计时打点：把"距上一个打点"的耗时累加进该段（循环里的多次迭代会累加）。 */
#define SEG_MARK(idx)                             \
    do {                                          \
        if (seg) {                                \
            int64_t t_now = ns_now_us();          \
            seg->us[idx] += t_now - t_prev;       \
            t_prev = t_now;                       \
        }                                         \
    } while (0)

static int do_combined_mount(void* raw_args) {
    struct CombinedMountArgs* args = (struct CombinedMountArgs*)raw_args;
    const char* pkg = args->pkg;
    const char* source = args->source;
    const char* target = args->target;
    const char* backup = args->backup;
    char (*preserve_paths)[256] = args->preserve_paths;
    int preserve_count = args->preserve_count;
    struct NsMountSeg* seg = args->seg; /* 同步路径才有；NULL = 不计时（零成本） */
    int64_t t_prev = seg ? ns_now_us() : 0;
    /* 就绪门控（先于任何 umount2，见 ns_wait_ready）：预算由调用方给定——
         0（IPC pre-specialize 快速尝试）：只查一次，缺失立即 ENOENT；
         >0（POST / 异步首次注入）：5ms 步进等待 vold 装配完成；
         <0（NSP_READINESS_QUIET，后台通道）：不等待，缺失只记 DEBUG。 */
    int ready_rc = ns_wait_ready(args);
    SEG_MARK(NSP_SEG_READY);
    if (ready_rc != 0) return ready_rc;
    /* 源预检（必须在任何卸载之前）：源要是本命名空间内真实的 FUSE 挂载。旧实现
       先卸载目标再 mount，源不可用就把应用的原生存储视图拆成空目录，回滚再失败
       就是"存储整个空了"。这里提前裁决，目标一点不动。 */
    bool src_is_fuse = ns_path_is_fuse_mount(source);
    SEG_MARK(NSP_SEG_PRE);
    if (!src_is_fuse) {
        log_ns_error(
            "[ns_error] [%s] 合并挂载放弃: 源 %s 在本命名空间不是 FUSE 挂载，保持原生视图\n", pkg,
            source);
        log_internal(LOG_WARN,
                     "[ns_error] [%s] 合并挂载放弃: 源 %s 在本命名空间不是 FUSE 挂载（未就绪或传播"
                     "未到位），保持原生视图",
                     pkg, source);
        return ENODEV;
    }
    /* 传播隔离：把目标子树置私有，使随后的 umount/mount 事件只在本命名空间生效。
       部分 ROM 的应用命名空间里 /storage/emulated 仍是 shared 挂载（与 zygote 或
       其它应用同组），直接卸载会**连带摘掉所有共享者**的存储视图——真机表现就是
       "整台设备的 /storage/emulated/0 都空了"。目标不是挂载点时该调用返回 EINVAL，
       无害（随后的 bind 自会建立挂载）。 */
    /* 传播隔离，同时顺手当"目标是挂载点吗"的探针：MS_PRIVATE|MS_REC 只在
       **目标本身是挂载点**时成功，普通目录一律 EINVAL。这个返回值决定了要不要
       枚举子树，而不只是记一条 DEBUG：
         - 成功 ⇒ 目标已是挂载点，umount2(target, MNT_DETACH) 会把整棵子树
           （含其下所有子挂载）一起摘掉，**不需要读 mountinfo**。真机 [ns计]
           实测这一步每次冷启动 134~136ms，正是"注入后冷启动明显变慢"的来源；
         - EINVAL ⇒ 目标不是挂载点（首次注入时的普通目录），子挂载只能逐条摘，
           必须扫描一次；
         - 其它错误（EPERM/EACCES，SELinux 拒绝）⇒ 判断不了，按"不是挂载点"
           保守处理（照旧枚举 + 逐条摘）。
       三条守卫不变：源预检仍在任何卸载之前；MS_PRIVATE 仍先于第一次 umount；
       挂载后仍 statfs 复核 + 失败回滚族根。 */
    bool target_is_mount = (mount(nullptr, target, nullptr, MS_PRIVATE | MS_REC, nullptr) == 0);
    int priv_errno = target_is_mount ? 0 : errno;
    if (!target_is_mount && priv_errno != EINVAL)
        LOG_DBG("[%s] %s 私有化失败（errno=%d），按枚举子树处理", pkg, target, priv_errno);
    SEG_MARK(NSP_SEG_PRIV);
    size_t tlen = strlen(target); /* preserve 恢复段用它剥前缀（见下方 rel 解析） */
    char backup_mounts[128][NS_MOUNT_PATH_MAX];
    char target_mounts[128][NS_MOUNT_PATH_MAX];
    int backup_count = 0;
    int target_count = 0;
    if (!target_is_mount) {
        /* 备份树与目标树读的是同一份 mountinfo：一次扫描同时收两者（旧实现各扫
           一遍，等于把最贵的那步做两遍）。 */
        NsCollectTarget tg[2] = {
            {.base = backup, .out = backup_mounts, .max = 128, .who = "合并挂载(备份)"},
            {.base = target, .out = target_mounts, .max = 128, .who = "合并挂载(目标)"},
        };
        if (ns_collect_mounts_multi(getpid(), tg, 2) < 0) {
            log_ns_error("[ns_error] [%s] open /proc/self/mountinfo failed, errno=%d\n", pkg,
                         errno);
            log_internal(LOG_ERROR,
                         "[ns_error] [%s] open /proc/self/mountinfo failed, errno=%d", pkg, errno);
            return errno;
        }
        backup_count = tg[0].n;
        target_count = tg[1].n;
    }
    if (seg) {
        struct NsMountinfoStats mi;
        ns_mountinfo_last_stats(&mi);
        seg->mo_lines = mi.lines;
        seg->mo_bytes = mi.bytes;
        seg->mo_candidates = mi.candidates;
        seg->mo_cpu_us = (long)(mi.cpu_us / 1000);
        seg->mo_csw = mi.csw;
        seg->mo_skipped = target_is_mount ? 1 : 0;
    }
    SEG_MARK(NSP_SEG_MOUNTINFO);
    for (int i = backup_count - 1; i >= 0; i--) {
        ns_umount_detach(backup_mounts[i]);
    }
    ns_umount_detach(backup);
    /* 备份机制已移除（不再 mount target→backup 复制原生视图，效仿新挂载
       方案）：preserve 恢复改为直接 bind /mnt/ 下系统 fuse 挂载视图（见
       Step J）。收益：免一次 bind 复制 + 免备份管理，缩短挂载周期延迟；
       且规避部分设备/ROM 应用命名空间内源路径不可见（ENOENT/EROFS）误报。
       backup 目录仍由父进程 ns_combined_mount 预先 mkdir（保留挂载点占位）。
       注意：快路径（目标是挂载点）不枚举 backup 子树，只摘 backup 自身——
       旧版本留下的 backup 子挂载只可能出现在长命应用命名空间里，随进程退出
       一起消失，不值得为此在每次注入都读一遍 mountinfo。 */
    for (int i = target_count - 1; i >= 0; i--) {
        ns_umount_detach(target_mounts[i]);
    }
    /* 目标已是挂载点时，这一条 MNT_DETACH 连同整棵子树一起摘掉（含
       Android/data、Android/obb 等子挂载），等价于旧实现"逐条摘 + 摘自身" */
    ns_umount_detach(target);
    SEG_MARK(NSP_SEG_UMOUNT);
    /* Step H（mkdir_recursive target）已移除：不再主动创建 /storage/emulated。
       就绪性由函数头部门控保证——首次注入在卸载前等待条目出现；重试注入
       时目录通常已存在（裸挂载点可直接 bind）。此处若仍缺失，Step I 的
       mount 以 ENOENT 真实裁决 */
    if (mount(source, target, nullptr, MS_BIND | MS_REC, nullptr) != 0) {
        int err = errno;
        SEG_MARK(NSP_SEG_BIND);
        log_ns_error(
            "[ns_error] [%s] Combined mount FUSE source failed: mount(src=%s, tgt=%s) errno=%d (%s)\n",
            pkg, source, target, err, strerror(err));
        log_internal(
            LOG_ERROR,
            "[ns_error] [%s] Combined mount FUSE source failed: mount(src=%s, tgt=%s) errno=%d (%s)",
            pkg, source, target, err, strerror(err));
        /* 回滚：本函数前面已经卸载了 backup 与 target 下的子挂载以及 target 本身，
           挂载再失败就把应用留在"裸"状态（连 /storage/emulated 都没有，直到进程
           重启或重试成功）。用应用 ns 内始终存活的族根重新 bind 出原生视图。 */
        ns_rollback_to_family_root(pkg, target, args->app_uid);
        return err;
    }
    SEG_MARK(NSP_SEG_BIND);
    /* 挂载后校验：目标必须真的变成 FUSE 视图。某些 ROM 的 /mnt 传播设置会让源在
       应用 ns 里只是一个普通空目录——bind 照样"成功"，但 /storage/emulated/0 全空。
       这种"挂上了却什么都没有"比挂不上更难排查，故校验失败一律回滚原生视图。 */
    bool target_is_fuse = ns_path_is_fuse_mount(target);
    SEG_MARK(NSP_SEG_VERIFY);
    if (!target_is_fuse) {
        log_ns_error("[ns_error] [%s] 合并挂载校验失败: %s 未变成 FUSE 视图（源 %s 在本命名空间不是 FUSE 挂载）\n",
                     pkg, target, source);
        log_internal(LOG_ERROR,
                     "[ns_error] [%s] 合并挂载校验失败: %s 未变成 FUSE 视图（源 %s 在本命名空间不是 FUSE"
                     "挂载），回滚原生视图",
                     pkg, target, source);
        ns_umount_detach(target);
        ns_rollback_to_family_root(pkg, target, args->app_uid);
        return EIO;
    }
    if (preserve_count > 0) {
        /* 备份机制已移除（不再 mount target→backup 复制原生视图）：preserve
           恢复直接 bind /mnt/ 下系统 fuse 挂载视图（Android 多用户族根
           /mnt/(installer|androidwritable|user)/<uid>/emulated），源即系统
           原生视图，无需备份副本。扫描 mountinfo 收集全部族根并按 rel 首段
           user id 匹配——确保多用户（/mnt/user/0、/mnt/user/10…）各自恢复
           到正确族根，不串用户 */
        NsMountEntry* all = NULL;
        NsMountEntry* roots = malloc(128 * sizeof(NsMountEntry));
        /* n < 0 = 挂载表读不到（结论未知）：不逐条去猜族根，整体跳过并告警 */
        int n = roots ? ns_read_mountinfo_pid(getpid(), &all) : -1;
        if (roots && n >= 0) {
            int root_count = 0;
            for (int i = 0; i < n && root_count < 128; i++) {
                if (ns_is_family_root(all[i].mount_point)) roots[root_count++] = all[i];
            }
            for (int i = 0; i < preserve_count; i++) {
                const char* mp = preserve_paths[i];
                if (mp[0] == '\0') continue;
                const char* rel = mp + tlen;
                while (*rel == '/') rel++;
                /* rel_full：含 user id 段的原始相对路径。源路径合成必须保留 uid
                   （族根镜像为 <族根>/<uid>/Android/data），下面的 rel 解析仅消费
                   uid 用于族根匹配，不可再用于拼源路径（否则丢 uid → ENOENT） */
                const char* rel_full = rel;
                /* 解析 rel 首段 user id（如 /0/Android/data → 0） */
                int user = 0;
                if (ns_is_digit_char(*rel)) {
                    while (ns_is_digit_char(*rel)) {
                        user = user * 10 + (*rel - '0');
                        rel++;
                    }
                    while (*rel == '/') rel++;
                }
                /* 匹配该 user 的族根（优先 user 族，其次 androidwritable/installer） */
                const char* sys_src = NULL;
                for (int fam = 2; fam >= 0 && !sys_src; fam--) {
                    for (int k = 0; k < root_count; k++) {
                        int ruid = 0;
                        if (ns_parse_family_root(roots[k].mount_point, &ruid) == fam &&
                            ruid == user) {
                            sys_src = roots[k].mount_point;
                            break;
                        }
                    }
                }
                if (!sys_src) {
                    log_ns_error(
                        "[ns_error] [%s] Combined mount preserve skip: no /mnt family root for user %d (%s)\n",
                        pkg, user, mp);
                    continue;
                }
                char src[PATH_MAX];
                int slen = snprintf(src, sizeof src, "%s/%s", sys_src, rel_full);
                if (slen < 0 || (size_t)slen >= sizeof src) {
                    log_ns_error(
                        "[ns_error] [%s] Combined mount preserve skip: composed source path truncated (%s/%s)\n",
                        pkg, sys_src, rel_full);
                    continue;
                }
                mkdir_recursive(mp);
                if (mount(src, mp, nullptr, MS_BIND | MS_REC, nullptr) != 0) {
                    int err = errno;
                    log_ns_error(
                        "[ns_error] [%s] Combined mount preserve path failed: mount(%s -> %s) errno=%d (%s)\n",
                        pkg, src, mp, err, strerror(err));
                    log_internal(
                        LOG_ERROR,
                        "[ns_error] [%s] Combined mount preserve path failed: mount(%s -> %s) errno=%d (%s)",
                        pkg, src, mp, err, strerror(err));
                }
            }
            free(all);
            free(roots);
        } else {
            free(all);
            free(roots);
            log_ns_error(
                "[ns_error] [%s] Combined mount preserve skipped: mountinfo unreadable (unknown), %d path(s) not restored\n",
                pkg, preserve_count);
            log_internal(LOG_ERROR,
                         "[ns_error] [%s] 恢复保留子挂载点失败：读不到挂载表（结论未知），本次未恢复 %d 条",
                         pkg, preserve_count);
        }
    }
    SEG_MARK(NSP_SEG_SUB);
    return 0;
}
#undef SEG_MARK

int ns_combined_mount(int pid, const char* pkg, const char* source, const char* target,
                      const char* backup, char preserve_paths[][256], int preserve_count,
                      int readiness_ms) {
    /* 父进程命名空间先行 mkdir backup：确保目标目录在宿主存在——
       子进程 do_combined_mount 的 mkdir 在目标应用命名空间执行，
       若 /data/Namespace-Proxy 在该命名空间不可见会连带 mount 目标失败 */
    if (backup && backup[0]) {
        mkdir_recursive(backup);
    }
    struct CombinedMountArgs args;
    memset(&args, 0, sizeof args);
    args.pkg = pkg;
    args.source = source;
    args.target = target;
    args.backup = backup;
    args.preserve_paths = preserve_paths;
    args.preserve_count = preserve_count;
    args.target_pid = pid;
    /* 父进程此刻能可靠读到目标属主；子进程里再反查会在进程退出后拿到 0 */
    args.app_uid = get_app_uid(pid);
    /* 保留负值哨兵（NSP_READINESS_QUIET = 后台通道）：它决定缺失路径的日志口径，
       不能像预算那样归一成 0。预算另按正值计算。 */
    args.readiness_ms = readiness_ms;
    /* 分段计时页：MAP_SHARED 让 fork 出的子进程写、本进程读（COW 栈不共享）。
       申请失败只意味着"这次没计时"，绝不影响挂载本身。 */
    struct NsMountSeg* seg =
        mmap(nullptr, sizeof *seg, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (seg == MAP_FAILED) seg = nullptr;
    if (seg) memset(seg, 0, sizeof *seg);
    args.seg = seg;
    int64_t t_begin = seg ? ns_now_us() : 0;
    int child_err = 0;
    /* 子进程预算 = 就绪等待 + 800ms 余量：等待发生在子进程内，超时会被 SIGKILL，
       预算必须留够。健康路径只有一次 access，不消耗预算。注意这段预算**不是**
       挂载耗时（日志里的"ns操作 耗时"含它）。 */
    int budget_ms = (readiness_ms > 0 ? readiness_ms : 0) + 800;
    int ret = run_in_mnt_ns_timeout(pid, do_combined_mount, &args, &child_err, budget_ms);
    /* child_err 是子进程的 errno 风格返回值（ENOENT/ENODEV/EIO/ESRCH/ETIMEDOUT…）。
       旧实现只在 ret<0 时写 errno，于是"未就绪返回 ENOENT(2)"这类正数返回值到了
       调用方手里 errno 是脏值——上层无法据此判"可 fail-open 交重试"。 */
    if (child_err != 0) errno = child_err;
    if (seg) {
        ns_seg_log(pkg, seg, ns_now_us() - t_begin);
        munmap(seg, sizeof *seg);
    }
    return ret;
}
/* 全局注入方案：简洁追加挂载，无备份/恢复逻辑 */
static int do_global_mount(void* raw_args) {
    struct CombinedMountArgs* args = (struct CombinedMountArgs*)raw_args;
    const char* source = args->source;
    const char* target = args->target;
    /* 先尝试直接 bind mount（依赖 mount propagation） */
    if (mount(source, target, nullptr, MS_BIND | MS_REC, nullptr) == 0) return 0;
    /* ENOENT 表示源路径在当前命名空间不可见 —— 通过父进程的 /proc/<ppid>/root 跨命名空间访问 */
    if (errno == ENOENT) {
        char src_buf[256];
        snprintf(src_buf, sizeof(src_buf), "/proc/%d/root%s", getppid(), source);
        struct stat st;
        if (stat(src_buf, &st) == 0 &&
            mount(src_buf, target, nullptr, MS_BIND | MS_REC, nullptr) == 0) {
            LOG_DBG("全局注入跨 ns 挂载成功: %s(proc) -> %s", source, target);
            return 0;
        }
        log_ns_error(
            "[ns_error] Global mount failed: mount(%s -> %s) errno=%d (%s), proc fallback also failed\n",
            source, target, errno, strerror(errno));
        return errno;
    }
    log_ns_error("[ns_error] Global mount failed: mount(%s -> %s) errno=%d (%s)\n", source, target,
                 errno, strerror(errno));
    return errno;
}

int ns_global_mount_async(int pid, const char* pkg, const char* source, const char* target) {
    /* 同 ns_combined_mount_async：结构字段只增不减，零初始化免掉"新字段没赋值"
       这类静默故障（do_global_mount 目前不读 pkg/seg，但下一个改它的人不会知道）。 */
    struct CombinedMountArgs* args = calloc(1, sizeof(struct CombinedMountArgs));
    if (!args) return -1;
    args->source = strdup(source);
    if (!args->source) {
        free(args);
        return -1;
    }
    args->target = strdup(target);
    if (!args->target) {
        free((void*)args->source);
        free(args);
        return -1;
    }
    args->backup = NULL;
    args->preserve_paths = NULL;
    args->preserve_count = 0;
    /* 全局注入为纯追加 bind，无卸载前置流程，无需就绪门控 */
    args->target_pid = pid;
    args->app_uid = get_app_uid(pid);
    args->readiness_ms = 0;
    int ret = run_in_mnt_ns_async(pid, pkg, do_global_mount, args, args);
    if (ret < 0) {
        free((void*)args->source);
        free((void*)args->target);
        free(args);
    }
    return ret;
}

/* 同步版全局挂载：挂载完成才返回，用于 IPC 线程 */
int ns_global_mount(int pid, const char* pkg, const char* source, const char* target) {
    /* 指定初始化：CombinedMountArgs 还会长（seg 等），位置初始化每加一个字段就
       触发一条 -Wmissing-field-initializers，改用字段名后不再受结构演化影响 */
    struct CombinedMountArgs args = {
        .pkg = pkg,
        .source = source,
        .target = target,
        .backup = NULL,
        .preserve_paths = NULL,
        .preserve_count = 0,
        .target_pid = pid,
        .app_uid = get_app_uid(pid),
        .readiness_ms = 0,
        .seg = NULL,
    };
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_global_mount, &args, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}

/* 核心优化：异步非阻塞合并挂载启动函数 */
int ns_combined_mount_async(int pid, const char* pkg, const char* source, const char* target,
                            const char* backup, char preserve_paths[][256], int preserve_count) {
    /* 必须 calloc：本结构会随功能增长（seg 等），漏初始化某个指针字段就是
       "子进程 SIGSEGV → 完成管道 EOF → 按失败处理 → 重试"的静默故障。真机/沙箱
       都复现过：seg 未初始化时 SEG_MARK 往垃圾地址写，异步挂载整批失败（日志只
       剩"异步挂载结果不可得 read=0"）。calloc 让未显式赋值的字段一律 NULL/0。 */
    struct CombinedMountArgs* args = calloc(1, sizeof(struct CombinedMountArgs));
    if (!args) return -1;
    args->pkg = pkg ? strdup(pkg) : NULL;
    args->source = strdup(source);
    args->target = strdup(target);
    args->backup = strdup(backup);
    args->preserve_count = preserve_count;
    args->preserve_paths = malloc(sizeof(char[256]) * (size_t)preserve_count);
    if (args->preserve_paths && preserve_count > 0) {
        memcpy(args->preserve_paths, preserve_paths, sizeof(char[256]) * (size_t)preserve_count);
    }
    args->target_pid = pid;
    args->app_uid = get_app_uid(pid);
    /* 后台通道：不等待、缺失只记 DEBUG。迟到由重试队列按退避补挂（旧实现首轮
       等 1000ms 且失败 loud 记账，配上"派发即出队"就变成 1Hz 刷屏）。 */
    args->readiness_ms = NSP_READINESS_QUIET;
    /* 后台通道不传分段计时共享页（子进程填了也没人读）：显式置空，
       别依赖 calloc 之外的东西。 */
    args->seg = NULL;
    int ret = run_in_mnt_ns_async(pid, pkg, do_combined_mount, args, args);
    if (ret < 0) {
        free((void*)args->pkg);
        free((void*)args->source);
        free((void*)args->target);
        free((void*)args->backup);
        free(args->preserve_paths);
        free(args);
    }
    return ret;
}

/* ══════════════ 目标命名空间挂载状态探测（不读 mountinfo） ══════════════
 * 真机取证（2026-10-31，Redmi/Android 14）：一次冷启动注入的 207ms 里，父进程
 * read_mount_state 的整文件 mountinfo 读 + 解析占 ~71ms（子进程那两次已由
 * do_combined_mount 的"目标是挂载点"快路径消掉）。整文件扫描的成本与命名空间
 * 条目数成正比，与应用、规则、是否注入都无关——这正是"只开一个目标应用、不配
 * 任何规则也照样慢"的原因。
 * 替代方案只需要 3 次轻量系统调用：
 *   statx(target)  → dev + mount id
 *   statx(target/..) → mount id（两者不同 ⇒ target 是挂载点，libmount 同款判定）
 *   stat(src)      → dev（相等 ⇒ 就是本项目 FUSE 的 bind/共享视图）
 * 旧内核（< 5.8）不支持 STATX_MNT_ID 时退回 statfs 判 FUSE_SUPER_MAGIC——本项目的
 * 目标路径一旦被挂载必然是 FUSE（vold 的原生视图或我们的代理视图），语义等价。 */
#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U /* linux/stat.h；旧头文件兜底 */
#endif

struct NsStatProbe {
    dev_t dev;
    uint64_t mnt_id;
    bool has_mnt_id;
};

/* statx 一次：dev 与 mount id 一起拿。返回 0 成功（errno 由调用方解读） */
static int ns_stat_probe(const char* path, struct NsStatProbe* out) {
    struct statx stx;
    memset(&stx, 0, sizeof stx);
    if (statx(AT_FDCWD, path, 0, STATX_BASIC_STATS | STATX_MNT_ID, &stx) != 0) return -1;
    out->dev = makedev(stx.stx_dev_major, stx.stx_dev_minor);
    out->has_mnt_id = (stx.stx_mask & STATX_MNT_ID) != 0;
    out->mnt_id = out->has_mnt_id ? (uint64_t)stx.stx_mnt_id : 0;
    return 0;
}

int ns_probe_target_view(int pid, const char* path, const char* src, bool* is_mount,
                         bool* is_ours) {
    if (is_mount) *is_mount = false;
    if (is_ours) *is_ours = false;
    if (!path || !path[0] || pid <= 0) return -1;
    char full[PATH_MAX];
    int n = snprintf(full, sizeof full, "/proc/%d/root%s", pid, path);
    if (n < 0 || (size_t)n >= sizeof full) return -1;
    struct NsStatProbe self;
    if (ns_stat_probe(full, &self) != 0) {
        /* 目标 ns 里 stat 不到这个路径 ⇒ 它肯定不是挂载点（挂载点必然可 stat，
           例如应用 ns 还没被 vold 装配出 /storage/emulated）。这是**确定结论**，
           不必回退整文件扫描；只有权限类错误才交给调用方回退。 */
        return (errno == ENOENT || errno == ENOTDIR) ? 0 : -1;
    }
    bool mounted = false;
    if (self.has_mnt_id) {
        char parent[PATH_MAX];
        n = snprintf(parent, sizeof parent, "%s/..", full);
        if (n < 0 || (size_t)n >= sizeof parent) return -1;
        struct NsStatProbe up;
        if (ns_stat_probe(parent, &up) != 0) return -1;
        if (!up.has_mnt_id) return -1;
        mounted = (self.mnt_id != up.mnt_id);
    } else {
        /* 旧内核：没有 mount id 可用，按"目标一旦挂载必然是 FUSE"判定 */
        struct statfs sfs;
        if (statfs(full, &sfs) != 0) return -1;
        mounted = ((unsigned long)sfs.f_type == (unsigned long)FUSE_SUPER_MAGIC);
    }
    if (is_mount) *is_mount = mounted;
    if (is_ours && mounted && src && src[0]) {
        struct stat ss;
        if (stat(src, &ss) == 0) *is_ours = (self.dev == ss.st_dev);
    }
    return 0;
}

int ns_is_mounted(int pid, const char* target_mount, const char* match_fs_name) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
    FILE* fp = fopen(path, "re");
    if (!fp) return -1;
    /* 同 ns_mountinfo.c 的 mi_scan：seq_file 每次 read 都从头重放挂载表，缓冲越小
       越亏（默认 4KB → 上千次 read）。这里同样拉到 256KB，且用堆缓冲避免线程串内容。 */
    char* iobuf = malloc(1u << 18);
    if (iobuf) setvbuf(fp, iobuf, _IOFBF, 1u << 18);
    int found = 0;
    char line[2048], mount_point[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (!fast_strstr(line, target_mount)) continue;
        if (match_fs_name && !fast_strstr(line, match_fs_name)) continue;
        if (fast_strstr(line, " - ") && sscanf(line, "%*s %*s %*s %*s %1023s", mount_point) == 1) {
            if (strcmp(mount_point, target_mount) == 0) {
                found = 1;
                break;
            }
        }
    }
    fclose(fp);
    free(iobuf);
    return found;
}
/* 核心优化：异步合并挂载完成后，用于回收父进程内存的全局回调 */
void handle_async_mount_event(void* ptr) {
    MountTaskCtx* ctx = (MountTaskCtx*)ptr;
    int child_ret = -1;
    ssize_t r = read(ctx->status_pipe_fd, &child_ret, sizeof(child_ret));
    /* 结果判定与收尸解耦（R9）：子进程先写一整个 int 再 _exit，完成管道里读到
       完整 status 就是权威结果；waitpid 只负责回收——主循环 reap_zombies
       （waitpid(-1)）可能已抢先收走该子进程（ECHILD），那**不影响**判定。
       旧实现在 ECHILD 时走独立分支：即使管道已完整回传非 0 失败码，也只记
       "结果不可得"就释放任务——不调度重试、不摘追踪、不清理注入标志；被动模式下
       该应用可能整个生命周期都没有代理视图，列表却仍显示已注入。 */
    int status = 0;
    /* 管道结果就绪不等于子进程已退出；这里运行在 injector 事件循环，不能等待
       退出收尾。仍存活的子进程由既有 SIGCHLD / timer 的 reap_zombies 回收。 */
    pid_t w = waitpid(ctx->child_pid, &status, WNOHANG);
    if (w < 0 && errno != ECHILD && errno != EINTR)
        LOG_WRN("异步挂载 waitpid 失败 pid=%d: %s", ctx->child_pid, strerror(errno));
    bool have_status = (r == (ssize_t)sizeof(child_ret));
    if (have_status && child_ret == 0) {
        /* 真正挂上了才清重试记账（旧实现把"派发成功"当成功，失败回调又以
           attempts=0 重新入队 → 退避与上限失效，1Hz 永久重试） */
        retry_mount_succeeded(ctx->target_pid);
        LOG_DBG("异步挂载成功: App=%s, PID=%d", ctx->pkg_name, ctx->target_pid);
    } else {
        /* 失败 / status 缺失(EOF) / 未知：一律按失败收尾（fail-closed——把"未知"
           当成功会让上层以为挂载已完成）。失败收尾统一走 schedule_retry_mount +
           remove_tracked，并按目标存活/是否已被其他任务成功挂载做幂等判定，
           不再与成功分支或收尸结果互斥。 */
        /* 单次失败只记 DEBUG：后台通道的失败由重试队列接续，逐轮 WARN/ERROR 会在
           "视图迟迟不出现"的设备上把正常等待刷成故障（error.log 无上限增长）。
           真正的结论由 retry_queue 在退避耗尽时 loud 一次（"挂载重试耗尽"）。 */
        if (have_status) {
            LOG_DBG("异步挂载失败: App=%s, PID=%d, ret_val=%d, exit_status=%d", ctx->pkg_name,
                    ctx->target_pid, child_ret, status);
        } else {
            LOG_WRN("异步挂载结果不可得: App=%s, PID=%d, read=%zd, exit=%d（完成管道未回传完整 "
                    "status，按失败处理）",
                    ctx->pkg_name, ctx->target_pid, r, status);
        }
        /*
         * 只在以下条件满足时才调度重试：
         * 1) 进程仍然存活
         * 2) 目标进程尚未被其他重试成功挂载上 FUSE
         */
        bool alive = (kill(ctx->target_pid, 0) == 0);
        bool already_mounted = false;
        if (alive) {
            char tgt[128];
            uid_t uid = get_app_uid(ctx->target_pid);
            get_target_storage_path(uid, tgt, sizeof(tgt));
            already_mounted = (ns_is_mounted(ctx->target_pid, tgt, "fuse.fuse_daemon") > 0 ||
                               ns_is_mounted(ctx->target_pid, tgt, "fuse_daemon") > 0);
        }
        if (alive && !already_mounted) {
            /* 加入重试队列并从追踪中移除，确保后续扫描可重新发现并注入 */
            schedule_retry_mount(ctx->pkg_name, ctx->target_pid);
            remove_tracked(ctx->target_pid);
        } else if (!alive) {
            LOG_DBG("异步挂载失败，进程已死，不重试: %s(PID:%d)", ctx->pkg_name,
                    ctx->target_pid);
            remove_tracked(ctx->target_pid);
        } else {
            LOG_DBG("异步挂载失败但目标已存在FUSE挂载，不重试: %s(PID:%d)", ctx->pkg_name,
                    ctx->target_pid);
        }
    }
    struct CombinedMountArgs* args = (struct CombinedMountArgs*)ctx->mount_args;
    if (args) {
        free((void*)args->source);
        free((void*)args->target);
        free((void*)args->backup);
        free(args->preserve_paths);
        free(args);
    }
    free(ctx);
}

/* 全局替换式挂载方案（mountinfo 枚举/族根工具/global replace+restore/
   app fuse 还原/状态查询）已整体拆至 src/injector/ns_global_replace.c，
   共享接口见 ns_global_replace.h。 */

/* 全局替换方案（do_global_replace/restore、app fuse 还原、状态查询）已拆至
   src/injector/ns_global_replace.c（见 ns_global_replace.h） */