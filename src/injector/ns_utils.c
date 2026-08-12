#define _GNU_SOURCE
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <poll.h>
#include <sys/epoll.h>
#include "common.h"
#include "ns_utils.h"
#include "fast_search.h"
#include "injector.h"
#include "inject_target.h"
struct DebugMountArgs {
    const char* pkg;
    int pid;
    const char* stage;
};
static void log_ns_error(const char* format, ...) {
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
static char* read_file_dynamic(const char* path, size_t* out_size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    size_t capacity = 65536;
    size_t size = 0;
    char* buf = malloc(capacity);
    if (!buf) {
        close(fd);
        return NULL;
    }
    while (1) {
        ssize_t r = read(fd, buf + size, capacity - size - 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return NULL;
        }
        if (r == 0) break;
        size += r;
        if (size >= capacity - 1) {
            capacity *= 2;
            char* new_buf = realloc(buf, capacity);
            if (!new_buf) {
                free(buf);
                close(fd);
                return NULL;
            }
            buf = new_buf;
        }
    }
    buf[size] = '\0';
    close(fd);
    if (out_size) *out_size = size;
    return buf;
}
/* 解析子进程回传日志行（格式 "<level>|<msg>\n"）并写入父进程环形缓冲 */
static void replay_child_log_line(char* line) {
    char* sep = strchr(line, '|');
    if (!sep) { LOG("[ns子进程] %s", line); return; }
    *sep = '\0';
    int lv = atoi(line);
    const char* msg = sep + 1;
    size_t mlen = strlen(msg);
    while (mlen > 0 && (msg[mlen - 1] == '\n' || msg[mlen - 1] == '\r'))
        ((char*)msg)[--mlen] = '\0';
    log_internal((LogLevel)lv, "%s\n", msg);
}

static int run_in_mnt_ns_timeout(int target_pid, int (*func)(void*), void* args, int* child_err, int timeout_ms) {
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
        close(status_pipe[0]); close(status_pipe[1]);
        log_ns_error("[ns_error] Failed to create log pipe: %s\n", strerror(errno));
        return -1;
    }
    pid_t child = fork();
    if (child < 0) {
        close(status_pipe[0]); close(status_pipe[1]);
        close(log_pipe[0]); close(log_pipe[1]);
        return -1;
    }
    if (child == 0) {
        close(status_pipe[0]);
        close(log_pipe[0]);
        g_log_forward_fd = log_pipe[1];   /* 子进程日志转发到管道 */
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
        struct pollfd pfd[2] = {
            { .fd = status_pipe[0], .events = POLLIN | POLLHUP },
            { .fd = log_pipe[0],    .events = POLLIN | POLLHUP }
        };
        int poll_ret = poll(pfd, 2, timeout_ms);
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed = (now.tv_sec - t_start.tv_sec) * 1000 +
                  (now.tv_nsec - t_start.tv_nsec) / 1000000;
        if (poll_ret < 0) { ret_val = -1; break; }
        /* 排空子进程回传日志（非阻塞，EAGAIN/EOF 即止） */
        if (poll_ret > 0 && (pfd[1].revents & (POLLIN | POLLHUP))) {
            char line[2048];
            size_t plen = 0;
            char chunk[1024];
            for (;;) {
                ssize_t r = read(log_pipe[0], chunk, sizeof(chunk));
                if (r < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) break; break; }
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
            if (plen > 0) { line[plen] = '\0'; replay_child_log_line(line); }
        }
        if (poll_ret > 0 && (pfd[0].revents & (POLLIN | POLLHUP))) { status_ready = true; break; }
        if (poll_ret == 0 || elapsed >= timeout_ms) break;   /* 超时 */
        /* 仅日志就绪而 status 未就绪：继续轮询 */
    }
    if (status_ready) {
        int child_ret = -1;
        ssize_t r_len = read(status_pipe[0], &child_ret, sizeof(child_ret));
        int status;
        waitpid(child, &status, 0); 
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
        } else {
            /* 子进程未写 status 管道（异常路径）：以退出码还原返回值。
               func 退出码映射（见 fork 子进程 _exit）：0=成功, 正数=业务
               返回值(1=跳过), 255=负数(-1=失败) */
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                if (child_err) *child_err = code;
                ret_val = (code == 0) ? 0 : (code == 255 ? -1 : code);
                LOG_WRN("ns操作子进程未写入管道异常退出, pid=%d, code: %d (ret=%d)", target_pid, code, ret_val);
            } else if (WIFSIGNALED(status)) {
                LOG_WRN("ns操作子进程被信号杀死, pid=%d, signal=%d", target_pid, WTERMSIG(status));
                ret_val = -1;
            } else {
                ret_val = -1;
            }
        }
    } else {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
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
int run_in_mnt_ns_async(int target_pid, const char* pkg, int (*func)(void*), void* args, void* mount_args) {
    int status_pipe[2];
    if (pipe2(status_pipe, O_CLOEXEC | O_NONBLOCK) < 0) {
        return -1;
    }
    pid_t child = fork();
    if (child < 0) {
        close(status_pipe[0]); close(status_pipe[1]);
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
    MountTaskCtx *ctx = malloc(sizeof(MountTaskCtx));
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
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLONESHOT,
        .data.fd = status_pipe[0] 
    };
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, status_pipe[0], &ev) < 0) {
        close(status_pipe[0]);
        free(ctx);
        kill(child, SIGKILL);
        waitpid(child, nullptr, WNOHANG);
        return -1;
    }
    if (!register_async_mount_pipe(status_pipe[0], ctx)) {
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, status_pipe[0], nullptr);
        close(status_pipe[0]);
        free(ctx);
        kill(child, SIGKILL);
        waitpid(child, nullptr, WNOHANG);
        return -1;
    }
    return 0;
}
struct MountArgs { const char *src; const char *target; };
static int do_bind_mount(void* raw_args) {
    struct MountArgs* args = (struct MountArgs*)raw_args;
    if (access(args->src, F_OK) != 0) return errno;
    struct stat st;
    if (stat(args->target, &st) != 0) mkdir(args->target, 0755);
    if (mount(args->src, args->target, nullptr, MS_BIND | MS_REC, nullptr) != 0)
        return errno;
    return 0;
}
static int do_umount_recursive(void* raw_args) {
    const char* target = (const char*)raw_args;
    size_t tlen = strlen(target);
    FILE* fp = fopen("/proc/self/mountinfo", "re");
    if (fp) {
        char mounts[128][256];
        int count = 0;
        char line[1024];
        while (fgets(line, sizeof(line), fp) && count < 128) {
            char mp[PATH_MAX] = {0};
            if (sscanf(line, "%*d %*d %*d:%*d %*s %4095s", mp) != 1) continue;
            if (strcmp(mp, target) == 0) continue;
            if (strncmp(mp, target, tlen) == 0 &&
                (mp[tlen] == '/' || mp[tlen] == '\0')) {
                strncpy(mounts[count], mp, PATH_MAX - 1);
                count++;
            }
        }
        fclose(fp);
        for (int i = count - 1; i >= 0; i--)
            for (int t = 0; t < 8; t++)
                if (umount2(mounts[i], MNT_DETACH) == 0) break;
    }
    for (int t = 0; t < 8; t++)
        if (umount2(target, MNT_DETACH) == 0) break;
    return 0;
}
static int do_umount_and_rmdir(void* raw_args) {
    const char* target = (const char*)raw_args;
    size_t tlen = strlen(target);
    FILE* fp = fopen("/proc/self/mountinfo", "re");
    if (fp) {
        char mounts[64][256];
        int count = 0;
        char line[1024];
        while (fgets(line, sizeof(line), fp) && count < 64) {
            char mp[PATH_MAX] = {0};
            if (sscanf(line, "%*d %*d %*d:%*d %*s %4095s", mp) != 1) continue;
            if (strcmp(mp, target) == 0) continue;
            if (strncmp(mp, target, tlen) == 0 && mp[tlen] == '/') {
                strncpy(mounts[count], mp, PATH_MAX - 1);
                count++;
            }
        }
        fclose(fp);
        for (int i = count - 1; i >= 0; i--)
            for (int t = 0; t < 8; t++)
                if (umount2(mounts[i], MNT_DETACH) == 0) break;
    }
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
    size_t tlen = strlen(target);
    /* 1. 先递归卸载所有子挂载点（从最深层开始） */
    FILE* fp = fopen("/proc/self/mountinfo", "re");
    if (fp) {
        char mounts[64][256];
        int count = 0;
        char line[1024];
        while (fgets(line, sizeof(line), fp) && count < 64) {
            char mp[PATH_MAX] = {0};
            if (sscanf(line, "%*d %*d %*d:%*d %*s %4095s", mp) != 1) continue;
            if (strcmp(mp, target) == 0) continue;           /* 目标本身稍后处理 */
            if (strncmp(mp, target, tlen) == 0 && mp[tlen] == '/') {
                strncpy(mounts[count], mp, sizeof(mounts[count]) - 1);
                mounts[count][sizeof(mounts[count]) - 1] = '\0';
                count++;
            }
        }
        fclose(fp);
        /* 逆序卸载（最深优先） */
        for (int i = count - 1; i >= 0; i--) {
            for (int t = 0; t < 8; t++) {
                if (umount2(mounts[i], MNT_DETACH) == 0) break;
                if (errno == EINVAL) break;  /* 本就不是挂载点 */
            }
        }
    }
    /* 2. 强制卸载目标挂载点本身 */
    for (int t = 0; t < 8; t++) {
        if (umount2(target, MNT_DETACH) == 0) break;
        if (errno == EINVAL) break;  /* 本就不是挂载点，静默通过 */
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
        LOG_DBG("force_umount_stale pid=%d target=%s 子进程异常退出, err=%d",
                pid, target, child_err);
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
static int do_move_mount(void* raw_args) {
    struct MountArgs* args = (struct MountArgs*)raw_args;
    char parent[PATH_MAX];
    strncpy(parent, args->target, PATH_MAX - 1);
    parent[PATH_MAX - 1] = '\0';
    char* last = strrchr(parent, '/');
    if (last && last != parent) {
        *last = '\0';
        mkdir(parent, 0755);
    }
    mkdir(args->target, 0755);
    if (mount(args->src, args->target, nullptr, MS_MOVE, nullptr) != 0)
        return errno;
    return 0;
}
int ns_bind_mount(int pid, const char* source, const char* target) {
    struct MountArgs args = { source, target };
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_bind_mount, &args, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}
int ns_umount_recursive(int pid, const char* target) {
    return run_in_mnt_ns(pid, do_umount_recursive, (void*)target, nullptr);
}
int ns_umount_and_rmdir(int pid, const char* target) {
    return run_in_mnt_ns(pid, do_umount_and_rmdir, (void*)target, nullptr);
}
int ns_move_mount(int pid, const char* source, const char* target) {
    struct MountArgs args = { source, target };
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_move_mount, &args, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}
int ns_make_shared(int pid, const char* target) {
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_make_shared, (void*)target, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}
int ns_find_native_submounts(int pid, const char* base_path, char mount_points[][256], int max_count) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
    size_t nread = 0;
    char* buf = read_file_dynamic(path, &nread);
    if (!buf) return 0;
    int count = 0;
    size_t base_len = strlen(base_path);
    char* line = buf;
    while (line < buf + nread && count < max_count) {
        char* next_line = strchr(line, '\n');
        if (next_line) *next_line = '\0';
        if (fast_strstr(line, base_path) != nullptr) {
            char* p = line;
            int fields_skipped = 0;
            while (fields_skipped < 4 && *p) {
                if (*p == ' ') {
                    fields_skipped++;
                    while (*p == ' ') p++;
                } else {
                    p++;
                }
            }
            if (fields_skipped == 4 && *p) {
                char* mp_start = p;
                while (*p && *p != ' ') p++;
                size_t mp_len = p - mp_start;
                if (mp_len > 0 && mp_len < 256) {
                    char mount_point[256];
                    memcpy(mount_point, mp_start, mp_len);
                    mount_point[mp_len] = '\0';
                    if (strncmp(mount_point, base_path, base_len) == 0 &&
                        (mount_point[base_len] == '/' || mount_point[base_len] == '\0') &&
                        strcmp(mount_point, base_path) != 0) {
                        const char* sep = fast_strstr(p, " - ");
                        if (sep) {
                            char fstype[64] = {0};
                            if (sscanf(sep + 3, "%63s", fstype) == 1) {
                                if (fast_strstr(fstype, "fuse") == nullptr) {
                                    strncpy(mount_points[count], mount_point, 255);
                                    mount_points[count][255] = '\0';
                                    count++;
                                }
                            }
                        }
                    }
                }
            }
        }
        if (!next_line) break;
        line = next_line + 1;
    }
    free(buf);
    return count;
}
struct PreserveMountArgs {
    const char* source;
    const char* target;
    char (*preserve_paths)[256];
    int preserve_count;
};
static int do_bind_mount_with_preserve(void* raw_args) {
    struct PreserveMountArgs* args = (struct PreserveMountArgs*)raw_args;
    const char* source = args->source;
    const char* target = args->target;
    char (*preserve_paths)[256] = args->preserve_paths;
    int preserve_count = args->preserve_count;
    if (mount(source, target, nullptr, MS_BIND | MS_REC, nullptr) != 0) return errno;
    char backup_base[PATH_MAX];
    snprintf(backup_base, sizeof(backup_base), BACKUP_DIR "/storage");
    size_t target_len = strlen(target);
    for (int i = 0; i < preserve_count; i++) {
        const char* mp = preserve_paths[i];
        if (mp[0] == '\0') continue;
        const char* rel = mp + target_len;
        while (*rel == '/') rel++;
        char backup_src[PATH_MAX];
        snprintf(backup_src, sizeof(backup_src), "%s/%s", backup_base, rel);
        mkdir_recursive(mp);
        mount(backup_src, mp, nullptr, MS_BIND | MS_REC, nullptr);
    }
    return 0;
}
int ns_bind_mount_with_preserve(int pid, const char* source, const char* target, char preserve_paths[][256], int preserve_count) {
    struct PreserveMountArgs args = { source, target, preserve_paths, preserve_count };
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_bind_mount_with_preserve, &args, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}
struct BackupTargetArgs {
    const char* target;
    const char* backup;
};
static int do_backup_and_clear_target(void* raw_args) {
    struct BackupTargetArgs* args = (struct BackupTargetArgs*)raw_args;
    const char* target = args->target;
    const char* backup = args->backup;
    size_t tlen = strlen(target);
    size_t blen = strlen(backup);
    FILE* fp = fopen("/proc/self/mountinfo", "re");
    if (fp) {
        char line[4096], mounts[128][PATH_MAX];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 128) {
            char mp[PATH_MAX] = {0};
            if (sscanf(line, "%*d %*d %*d:%*d %*s %4095s", mp) != 1) continue;
            if (strcmp(mp, backup) == 0) continue;
            if (strncmp(mp, backup, blen) == 0 && (mp[blen] == '/' || mp[blen] == '\0')) {
                strncpy(mounts[count], mp, PATH_MAX - 1);
                count++;
            }
        }
        fclose(fp);
        for (int i = count - 1; i >= 0; i--)
            for (int t = 0; t < 8; t++)
                if (umount2(mounts[i], MNT_DETACH) == 0) break;
    }
    for (int t = 0; t < 8; t++)
        if (umount2(backup, MNT_DETACH) == 0) break;
    if (mount(target, backup, nullptr, MS_BIND | MS_REC, nullptr) != 0)
        return errno;
    fp = fopen("/proc/self/mountinfo", "re");
    if (fp) {
        char line[4096], mounts[128][PATH_MAX];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 128) {
            char mp[PATH_MAX] = {0};
            if (sscanf(line, "%*d %*d %*d:%*d %*s %4095s", mp) != 1) continue;
            if (strcmp(mp, target) == 0) continue;
            if (strncmp(mp, target, tlen) == 0 && (mp[tlen] == '/' || mp[tlen] == '\0')) {
                strncpy(mounts[count], mp, PATH_MAX - 1);
                count++;
            }
        }
        fclose(fp);
        for (int i = count - 1; i >= 0; i--)
            for (int t = 0; t < 8; t++)
                if (umount2(mounts[i], MNT_DETACH) == 0) break;
    }
    for (int t = 0; t < 8; t++)
        if (umount2(target, MNT_DETACH) == 0) break;
    return 0;
}
int ns_backup_and_clear_target(int pid, const char* target, const char* backup) {
    struct BackupTargetArgs bargs = { target, backup };
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_backup_and_clear_target, &bargs, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}
struct CombinedMountArgs {
    const char* pkg;
    const char* source;
    const char* target;
    const char* backup;
    char (*preserve_paths)[256];
    int preserve_count;
};
static int do_combined_mount(void* raw_args) {
    struct CombinedMountArgs* args = (struct CombinedMountArgs*)raw_args;
    const char* pkg = args->pkg;
    const char* source = args->source;
    const char* target = args->target;
    const char* backup = args->backup;
    char (*preserve_paths)[256] = args->preserve_paths;
    int preserve_count = args->preserve_count;
    size_t tlen = strlen(target);
    size_t blen = strlen(backup);
    //log_ns_error("[combined] Step A: read mountinfo for pkg=%s\n", pkg);
    size_t nread = 0;
    char* buf = read_file_dynamic("/proc/self/mountinfo", &nread);
    if (!buf) {
        log_ns_error("[ns_error] [%s] open /proc/self/mountinfo failed, errno=%d\n", pkg, errno);
        log_internal(LOG_ERROR, "[ns_error] [%s] open /proc/self/mountinfo failed, errno=%d", pkg, errno);
        return errno;
    }
    char backup_mounts[128][256];
    int backup_count = 0;
    char target_mounts[128][256];
    int target_count = 0;
    char* line = buf;
    while (line < buf + nread) {
        char* next_line = strchr(line, '\n');
        if (next_line) *next_line = '\0';
        if (fast_strstr(line, backup) != nullptr || fast_strstr(line, target) != nullptr) {
            char* p = line;
            int fields_skipped = 0;
            while (fields_skipped < 4 && *p) {
                if (*p == ' ') {
                    fields_skipped++;
                    while (*p == ' ') p++;
                } else {
                    p++;
                }
            }
            if (fields_skipped == 4 && *p) {
                char* mp_start = p;
                while (*p && *p != ' ') p++;
                size_t mp_len = p - mp_start;
                if (mp_len > 0 && mp_len < 256) {
                    char mp[256];
                    memcpy(mp, mp_start, mp_len);
                    mp[mp_len] = '\0';
                    if (strcmp(mp, backup) != 0 && strncmp(mp, backup, blen) == 0 && (mp[blen] == '/' || mp[blen] == '\0')) {
                        if (backup_count < 128) {
                            strcpy(backup_mounts[backup_count++], mp);
                        }
                    }
                    if (strcmp(mp, target) != 0 && strncmp(mp, target, tlen) == 0 && (mp[tlen] == '/' || mp[tlen] == '\0')) {
                        if (target_count < 128) {
                            strcpy(target_mounts[target_count++], mp);
                        }
                    }
                }
            }
        }
        if (!next_line) break;
        line = next_line + 1;
    }
    free(buf);
    //log_ns_error("[combined] Step B: umount2 sub-backup mounts, count=%d\n", backup_count);
    for (int i = backup_count - 1; i >= 0; i--) {
        for (int t = 0; t < 8; t++) {
            if (umount2(backup_mounts[i], MNT_DETACH) == 0) break;
        }
    }
   // log_ns_error("[combined] Step C: umount2 backup=%s\n", backup);
    for (int t = 0; t < 8; t++) {
        if (umount2(backup, MNT_DETACH) == 0) break;
    }
 //   log_ns_error("[combined] Step D: mkdir_recursive backup=%s\n", backup);
    if (mkdir_recursive(backup) != 0) {
        int err = errno;
        log_ns_error("[ns_error] [%s] Combined mount mkdir_recursive backup failed: mkdir_recursive(%s) errno=%d (%s)\n", pkg, backup, err, strerror(err));
        log_internal(LOG_ERROR, "[ns_error] [%s] Combined mount mkdir_recursive backup failed: mkdir_recursive(%s) errno=%d (%s)", pkg, backup, err, strerror(err));
        return err;
    }
   // log_ns_error("[combined] Step E: mount(target->backup) target=%s backup=%s\n", target, backup);
    if (mount(target, backup, nullptr, MS_BIND | MS_REC, nullptr) != 0) {
        int err = errno;
        /* 降级处理：backup 仅是保留原生子视图的优化步骤（Step J preserve 用），
           其失败不应中止主挂载——尤其 ENOENT（目标应用命名空间里源/目标路径
           不可见，特定设备/ROM 命名空间差异，见 do_global_mount 同场景注释）。
           记录 WRN 后继续 Step H/I 主挂载 */
        log_ns_error("[ns_error] [%s] Combined mount backup failed: mount(%s -> %s) errno=%d (%s)\n", pkg, target, backup, err, strerror(err));
        log_internal(LOG_WARN, "[ns_error] [%s] Combined mount backup failed(降级): mount(%s -> %s) errno=%d (%s)", pkg, target, backup, err, strerror(err));
    }
  //  log_ns_error("[combined] Step F: umount2 sub-target mounts, count=%d\n", target_count);
    for (int i = target_count - 1; i >= 0; i--) {
        for (int t = 0; t < 8; t++) {
            if (umount2(target_mounts[i], MNT_DETACH) == 0) break;
        }
    }
 //   log_ns_error("[combined] Step G: umount2 target=%s\n", target);
    for (int t = 0; t < 8; t++) {
        if (umount2(target, MNT_DETACH) == 0) break;
    }
  //  log_ns_error("[combined] Step H: mkdir_recursive target=%s\n", target);
    if (mkdir_recursive(target) != 0) {
        int err = errno;
        log_ns_error("[ns_error] [%s] Combined mount mkdir_recursive target failed: mkdir_recursive(%s) errno=%d (%s)\n", pkg, target, err, strerror(err));
        log_internal(LOG_ERROR, "[ns_error] [%s] Combined mount mkdir_recursive target failed: mkdir_recursive(%s) errno=%d (%s)", pkg, target, err, strerror(err));
        return err;
    }
  //  log_ns_error("[combined] Step I: mount(source->target) source=%s target=%s\n", source, target);
    if (mount(source, target, nullptr, MS_BIND | MS_REC, nullptr) != 0) {
        int err = errno;
        log_ns_error("[ns_error] [%s] Combined mount FUSE source failed: mount(src=%s, tgt=%s) errno=%d (%s)\n",
                     pkg, source, target, err, strerror(err));
        log_internal(LOG_ERROR, "[ns_error] [%s] Combined mount FUSE source failed: mount(src=%s, tgt=%s) errno=%d (%s)",
                     pkg, source, target, err, strerror(err));
        return err;
    }
  //  log_ns_error("[combined] Step J: preserve sub-mounts, count=%d\n", preserve_count);
    for (int i = 0; i < preserve_count; i++) {
        const char* mp = preserve_paths[i];
        if (mp[0] == '\0') continue;
        const char* rel = mp + tlen;
        while (*rel == '/') rel++;
        char backup_src[256];
        snprintf(backup_src, sizeof(backup_src), "%s/%s", backup, rel);
        mkdir_recursive(mp);
        if (mount(backup_src, mp, nullptr, MS_BIND | MS_REC, nullptr) != 0) {
            int err = errno;
            log_ns_error("[ns_error] [%s] Combined mount preserve path failed: mount(%s -> %s) errno=%d (%s)\n", pkg, backup_src, mp, err, strerror(err));
            log_internal(LOG_ERROR, "[ns_error] [%s] Combined mount preserve path failed: mount(%s -> %s) errno=%d (%s)", pkg, backup_src, mp, err, strerror(err));
        }
    }
  //  log_ns_error("[combined] Step Z: done\n");
    return 0;
}
int ns_combined_mount(int pid, const char* pkg, const char* source, const char* target, const char* backup,
                      char preserve_paths[][256], int preserve_count) {
    /* 父进程命名空间先行 mkdir backup：确保目标目录在宿主存在——
       子进程 do_combined_mount 的 mkdir 在目标应用命名空间执行，
       若 /data/Namespace-Proxy 在该命名空间不可见会连带 mount 目标失败 */
    if (backup && backup[0]) {
        mkdir_recursive(backup);
    }
    struct CombinedMountArgs args = { pkg, source, target, backup, preserve_paths, preserve_count };
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_combined_mount, &args, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}
/* 全局注入方案：简洁追加挂载，无备份/恢复逻辑 */
static int do_global_mount(void* raw_args) {
    struct CombinedMountArgs* args = (struct CombinedMountArgs*)raw_args;
    const char* source = args->source;
    const char* target = args->target;
    /* 先尝试直接 bind mount（依赖 mount propagation） */
    if (mount(source, target, nullptr, MS_BIND | MS_REC, nullptr) == 0)
        return 0;
    /* ENOENT 表示源路径在当前命名空间不可见 —— 通过父进程的 /proc/<ppid>/root 跨命名空间访问 */
    if (errno == ENOENT) {
        char src_buf[256];
        snprintf(src_buf, sizeof(src_buf), "/proc/%d/root%s", getppid(), source);
        struct stat st;
        if (stat(src_buf, &st) == 0 && mount(src_buf, target, nullptr, MS_BIND | MS_REC, nullptr) == 0) {
            LOG_DBG("全局注入跨 ns 挂载成功: %s(proc) -> %s", source, target);
            return 0;
        }
        log_ns_error("[ns_error] Global mount failed: mount(%s -> %s) errno=%d (%s), proc fallback also failed\n",
                     source, target, errno, strerror(errno));
        return errno;
    }
    log_ns_error("[ns_error] Global mount failed: mount(%s -> %s) errno=%d (%s)\n",
                 source, target, errno, strerror(errno));
    return errno;
}

int ns_global_mount_async(int pid, const char* pkg, const char* source, const char* target) {
    struct CombinedMountArgs *args = malloc(sizeof(struct CombinedMountArgs));
    if (!args) return -1;
    args->source = strdup(source);
    if (!args->source) { free(args); return -1; }
    args->target = strdup(target);
    if (!args->target) { free((void*)args->source); free(args); return -1; }
    args->backup = NULL;
    args->preserve_paths = NULL;
    args->preserve_count = 0;
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
    struct CombinedMountArgs args = { pkg, source, target, NULL, NULL, 0 };
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_global_mount, &args, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}

/* 核心优化：异步非阻塞合并挂载启动函数 */
int ns_combined_mount_async(int pid, const char* pkg, const char* source, const char* target, const char* backup,
                            char preserve_paths[][256], int preserve_count) {
    struct CombinedMountArgs *args = malloc(sizeof(struct CombinedMountArgs));
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

int ns_is_mounted(int pid, const char* target_mount, const char* match_fs_name) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
    FILE* fp = fopen(path, "re");
    if (!fp) return -1;
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
    return found;
}
static int do_debug_log_mounts(void* raw_args) {
    struct DebugMountArgs* args = (struct DebugMountArgs*)raw_args;
    mkdir_recursive(LOG_DIR);
    FILE* log_fp = fopen(LOG_DIR "/mount_debug.log", "ae");
    if (!log_fp) return errno;
    time_t now = time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    fprintf(log_fp, "[%s] [PKG: %s] [PID: %d] [STAGE: %s]\n", time_buf, args->pkg, args->pid, args->stage);
    FILE* mounts_fp = fopen("/proc/self/mounts", "re");
    if (mounts_fp) {
        char line[1024];
        bool found = false;
        while (fgets(line, sizeof(line), mounts_fp)) {
            if (fast_strstr(line, "/storage/emulated") != nullptr) {
                fprintf(log_fp, "  %s", line);
                found = true;
            }
        }
        if (!found) {
            fprintf(log_fp, "  (未找到包含 /storage/emulated 的挂载点)\n");
        }
        fclose(mounts_fp);
    } else {
        fprintf(log_fp, "  错误：无法读取 /proc/self/mounts\n");
    }
    fprintf(log_fp, "------------------------------------------------------------\n");
    fflush(log_fp);
    fclose(log_fp);
    return 0;
}
int ns_debug_log_mounts(int pid, const char* pkg, const char* stage) {
    struct DebugMountArgs args = { pkg, pid, stage };
    return run_in_mnt_ns(pid, do_debug_log_mounts, &args, nullptr);
}
struct SysFuseArgs {
    char fuse_src[PATH_MAX];
    char backup_path[PATH_MAX];
};
static int do_backup_and_remove_sys_fuse(void* raw_args) {
    struct SysFuseArgs* args = (struct SysFuseArgs*)raw_args;
    struct stat st;
    if (stat("/storage/emulated", &st) != 0) return -1;
    if (mkdir_recursive(args->backup_path) != 0) {
        return -1;
    }
    if (mount("/storage/emulated", args->backup_path, nullptr, MS_BIND | MS_REC, nullptr) != 0) {
        return -2;
    }
    if (umount2("/storage/emulated", MNT_DETACH) != 0) {
        umount2(args->backup_path, MNT_DETACH);
        return -1;
    }
    if (mount(args->fuse_src, "/storage/emulated", nullptr, MS_BIND | MS_REC, nullptr) != 0) {
        mount(args->backup_path, "/storage/emulated", nullptr, MS_BIND | MS_REC, nullptr);
        return -2;
    }
    mount(nullptr, "/storage/emulated", nullptr, MS_SHARED, nullptr);
    return 0;
}
static int do_restore_sys_fuse(void* raw_args) {
    struct SysFuseArgs* args = (struct SysFuseArgs*)raw_args;
    if (access(args->backup_path, F_OK) != 0) return -1;
    umount2("/storage/emulated", MNT_DETACH);
    struct stat st;
    if (stat("/storage/emulated", &st) != 0) {
        mount(args->backup_path, "/storage/emulated", nullptr, MS_BIND | MS_REC, nullptr);
        return 0;
    }
    mount(args->backup_path, "/storage/emulated", nullptr, MS_BIND | MS_REC, nullptr);
    return 0;
}
int ns_backup_and_remove_system_fuse(int mnt_ns_pid, const char* fuse_src, const char* backup_path) {
    struct SysFuseArgs args;
    memset(&args, 0, sizeof(args));
    strncpy(args.fuse_src, fuse_src, sizeof(args.fuse_src) - 1);
    strncpy(args.backup_path, backup_path, sizeof(args.backup_path) - 1);
    int child_err = 0;
    int ret = run_in_mnt_ns_timeout(mnt_ns_pid, do_backup_and_remove_sys_fuse, &args, &child_err, 2000);
    if (ret != 0) {
        LOG_ERR("系统 FUSE 备份/卸载失败 (ret=%d, err=%d)", ret, child_err);
    } else {
        LOG("系统 FUSE 已备份至 %s 并卸载", backup_path);
    }
    return ret;
}
int ns_restore_system_fuse(int mnt_ns_pid, const char* fuse_src, const char* backup_path) {
    (void)fuse_src;
    struct SysFuseArgs args;
    memset(&args, 0, sizeof(args));
    strncpy(args.backup_path, backup_path, sizeof(args.backup_path) - 1);
    int ret = run_in_mnt_ns_timeout(mnt_ns_pid, do_restore_sys_fuse, &args, nullptr, 2000);
    if (ret == 0) {
        LOG("系统 FUSE 已从 %s 恢复", backup_path);
    }
    return ret;
}
/* 核心优化：异步合并挂载完成后，用于回收父进程内存的全局回调 */
void handle_async_mount_event(void *ptr) {
    MountTaskCtx *ctx = (MountTaskCtx*)ptr;
    int child_ret = -1;
    ssize_t r = read(ctx->status_pipe_fd, &child_ret, sizeof(child_ret));
    int status;
    waitpid(ctx->child_pid, &status, 0); 
    if (r == sizeof(child_ret) && child_ret == 0) {
        LOG_DBG("异步挂载成功: App=%s, PID=%d", ctx->pkg_name, ctx->target_pid);
    } else {
        LOG_ERR("异步挂载失败: App=%s, PID=%d, ret_val=%zd, exit_status=%d", 
                ctx->pkg_name, ctx->target_pid, r, child_ret);
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
        } else {
            if (!alive) {
                LOG_DBG("异步挂载失败，进程已死，不重试: %s(PID:%d)", ctx->pkg_name, ctx->target_pid);
                remove_tracked(ctx->target_pid);
            } else {
                LOG_DBG("异步挂载失败但目标已存在FUSE挂载，不重试: %s(PID:%d)", ctx->pkg_name, ctx->target_pid);
            }
        }
    }
    struct CombinedMountArgs *args = (struct CombinedMountArgs *)ctx->mount_args;
    if (args) {
        free((void*)args->source);
        free((void*)args->target);
        free((void*)args->backup);
        free(args->preserve_paths);
        free(args);
    }
    free(ctx);
}

/* ================= 全局替换式挂载方案（--global-replace，卸载优先） =================
 * 对应 scripts/global.sh 的 replace/restore/status，injector 内建实现。
 * 目标设备不支持 MS_REC：备份/替换/恢复全部逐节点枚举 mountinfo 后单个
 * MS_BIND（父先子后 bind、最深优先 MNT_DETACH 卸载），确保不遗漏系统
 * 子挂载节点（f2fs 直通 Android/data|obb、嵌套跨用户 fuse 视图）。
 * 多用户网格：installer/androidwritable/user 三族 × 每用户 id 全量处理；
 * 备份仅取一个族（优先级 user > androidwritable > installer），三族共用。
 */

typedef struct {
    char mount_point[PATH_MAX];
    char source[PATH_MAX];
    char fstype[64];
    char dev[64];      /* major:minor，bind 与源共享 superblock，用于替换状态判断 */
    int depth;
} NsMountEntry;

/* mountinfo 全量读取上限：真实设备（多用户 + 嵌套视图 + f2fs 直通）可达 1900+ 行，
   旧上限 512 会截断族根（行号 1894+）与 nsp_global（1934 行），导致替换静默失败 */
#define NS_MOUNTINFO_MAX 4096

/* 读取指定进程的 mountinfo（本函数不进入命名空间，仅解析文件） */
static int read_mountinfo_pid(int pid, NsMountEntry* out, int max) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
    FILE* fp = fopen(path, "re");
    if (!fp) return -1;
    int count = 0;
    char line[4096];
    while (fgets(line, sizeof(line), fp) && count < max) {
        char mp[PATH_MAX] = {0}, dev[64] = {0};
        if (sscanf(line, "%*d %*d %63s %*s %4095s", dev, mp) != 2) continue;
        const char* sep = fast_strstr(line, " - ");
        char fstype[64] = {0}, src[PATH_MAX] = {0};
        if (sep) {
            if (sscanf(sep + 3, "%63s %4095s", fstype, src) < 1) src[0] = '\0';
        }
        strncpy(out[count].mount_point, mp, PATH_MAX - 1);
        out[count].mount_point[PATH_MAX - 1] = '\0';
        strncpy(out[count].source, src, PATH_MAX - 1);
        out[count].source[PATH_MAX - 1] = '\0';
        strncpy(out[count].fstype, fstype, sizeof(out[count].fstype) - 1);
        out[count].fstype[sizeof(out[count].fstype) - 1] = '\0';
        strncpy(out[count].dev, dev, sizeof(out[count].dev) - 1);
        out[count].dev[sizeof(out[count].dev) - 1] = '\0';
        int d = 0;
        for (char* p = mp; *p; p++) if (*p == '/') d++;
        out[count].depth = d;
        count++;
    }
    fclose(fp);
    return count;
}

static bool is_digit_char(char c) { return c >= '0' && c <= '9'; }

/* 判断是否为 emulated 族根：/mnt/(installer|androidwritable|user)/<数字>/emulated */
static bool is_family_root(const char* mp) {
    static const char* const families[] = { "installer", "androidwritable", "user" };
    if (strncmp(mp, "/mnt/", 5) != 0) return false;
    const char* p = mp + 5;
    for (int i = 0; i < 3; i++) {
        size_t flen = strlen(families[i]);
        if (strncmp(p, families[i], flen) == 0 && p[flen] == '/') {
            const char* q = p + flen + 1;
            if (!is_digit_char(*q)) return false;
            while (is_digit_char(*q)) q++;
            return strcmp(q, "/emulated") == 0;
        }
    }
    return false;
}

/* 提取族根的 family 索引（0=installer,1=androidwritable,2=user）与用户 id，失败返回 -1 */
static int parse_family_root(const char* mp, int* user_id) {
    static const char* const families[] = { "installer", "androidwritable", "user" };
    if (strncmp(mp, "/mnt/", 5) != 0) return -1;
    const char* p = mp + 5;
    for (int i = 0; i < 3; i++) {
        size_t flen = strlen(families[i]);
        if (strncmp(p, families[i], flen) == 0 && p[flen] == '/') {
            const char* q = p + flen + 1;
            if (!is_digit_char(*q)) return -1;
            int id = 0;
            while (is_digit_char(*q)) { id = id * 10 + (*q - '0'); q++; }
            if (strcmp(q, "/emulated") != 0) return -1;
            if (user_id) *user_id = id;
            return i;
        }
    }
    return -1;
}

/* 收集 base 前缀下的挂载点（含/不含自身，含/不含 fuse 类型），不排序 */
static int collect_mounts_under(const NsMountEntry* all, int n, const char* base,
                                bool include_self, bool include_fuse,
                                NsMountEntry* out, int max) {
    size_t blen = strlen(base);
    int count = 0;
    for (int i = 0; i < n && count < max; i++) {
        const char* mp = all[i].mount_point;
        if (strncmp(mp, base, blen) != 0) continue;
        if (mp[blen] != '/' && mp[blen] != '\0') continue;
        if (!include_self && strcmp(mp, base) == 0) continue;
        if (!include_fuse && fast_strstr(all[i].fstype, "fuse") != nullptr) continue;
        out[count++] = all[i];
    }
    return count;
}

/* 统计 base 前缀下匹配的挂载点数量（与 collect_mounts_under 同规则，仅计数） */
static int count_mounts_under(const NsMountEntry* all, int n, const char* base,
                              bool include_self, bool include_fuse) {
    size_t blen = strlen(base);
    int count = 0;
    for (int i = 0; i < n; i++) {
        const char* mp = all[i].mount_point;
        if (strncmp(mp, base, blen) != 0) continue;
        if (mp[blen] != '/' && mp[blen] != '\0') continue;
        if (!include_self && strcmp(mp, base) == 0) continue;
        if (!include_fuse && fast_strstr(all[i].fstype, "fuse") != nullptr) continue;
        count++;
    }
    return count;
}

/* 按深度降序排序（最深优先，用于卸载顺序） */
static void sort_deepest_first(NsMountEntry* arr, int n) {
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (arr[j].depth > arr[i].depth) {
                NsMountEntry t = arr[i]; arr[i] = arr[j]; arr[j] = t;
            }
        }
    }
}
/* 按深度升序排序（最浅优先，用于 bind 顺序：父先子后） */
static void sort_shallowest_first(NsMountEntry* arr, int n) {
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (arr[j].depth < arr[i].depth) {
                NsMountEntry t = arr[i]; arr[i] = arr[j]; arr[j] = t;
            }
        }
    }
}

/* 备份点有效性：0=未挂载(可新建), 1=已挂载且为系统视图备份(有效), -1=已被项目 FUSE 视图污染。
   关键：系统视图备份的 bind 视图，mountinfo source 是 fsname=/dev/fuse（fstype=fuse），
   **这是有效备份的正常特征**，绝不能判为污染；仅当 source/fstype 含 fuse_daemon
   （项目 FUSE 视图，如崩溃恢复二次替换叠上去的代理 bind）时才判为污染 */
static int backup_point_state(int pid, const char* path) {
    NsMountEntry* all = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    if (!all) return 0;
    int n = read_mountinfo_pid(pid, all, NS_MOUNTINFO_MAX);
    if (n <= 0) { free(all); return 0; }
    int st = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(all[i].mount_point, path) != 0) continue;
        if (fast_strstr(all[i].source, "fuse_daemon") != nullptr ||
            fast_strstr(all[i].fstype, "fuse_daemon") != nullptr) { st = -1; break; }
        st = 1;
        break;
    }
    free(all);
    return st;
}

struct GlobalReplaceArgs {
    const char* fuse_src;
    const char* backup_root;
};

struct AppRestoreArgs {
    char fuse_src[PATH_MAX];
    char backup_root[PATH_MAX];
    int user_id;
};

/* 在目标命名空间内执行：备份一个族 + 三族全部替换 */
static int do_global_replace(void* raw) {
    struct GlobalReplaceArgs* args = (struct GlobalReplaceArgs*)raw;
    const char* fuse_src = args->fuse_src;
    const char* backup_root = args->backup_root;
    /* NsMountEntry 单条约 8.3KB，栈上声明大数组会叠加超 8MB 栈上限导致 SIGSEGV，
       全部改为堆分配 */
    NsMountEntry* all = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    NsMountEntry* roots = malloc(128 * sizeof(NsMountEntry));
    NsMountEntry* sub = malloc(128 * sizeof(NsMountEntry));
    if (!all || !roots || !sub) {
        free(all); free(roots); free(sub);
        LOG_ERR("全局替换: 分配内存失败");
        return -1;
    }
    int n = read_mountinfo_pid(getpid(), all, NS_MOUNTINFO_MAX);
    if (n <= 0) { free(all); free(roots); free(sub); log_ns_error("[global_replace] read mountinfo failed n=%d errno=%d\n", n, errno); LOG_ERR("全局替换: 读取 mountinfo 失败"); return -1; }
    LOG_DBG("全局替换: mountinfo 共 %d 行, fuse_src=%s, backup_root=%s", n, fuse_src, backup_root);

    /* 项目 FUSE 源的 major:minor：bind 视图与源共享 superblock，
       以此判定族根是否已是项目 FUSE 视图（重入场景） */
    char src_dev[64] = {0};
    for (int i = 0; i < n; i++) {
        if (strcmp(all[i].mount_point, fuse_src) == 0) {
            strncpy(src_dev, all[i].dev, sizeof(src_dev) - 1);
            break;
        }
    }
    LOG_DBG("全局替换: fuse_src=%s dev=%s", fuse_src, src_dev[0] ? src_dev : "(未挂载)");

    /* 1. 枚举全部族根 */
    int root_count = 0;
    for (int i = 0; i < n && root_count < 128; i++) {
        if (is_family_root(all[i].mount_point)) {
            roots[root_count++] = all[i];
            LOG_DBG("全局替换: 族根[%d] %s dev=%s fstype=%s", root_count - 1,
                    all[i].mount_point, all[i].dev, all[i].fstype);
        }
    }
    if (root_count == 0) {
        LOG_WRN("全局替换: 未找到任何 emulated 族根，跳过");
        free(all); free(roots); free(sub);
        return 0;
    }

    /* 2. 选择备份族：优先级 user(2) > androidwritable(1) > installer(0) */
    int backup_family = -1;
    for (int fam = 2; fam >= 0; fam--) {
        bool exists = false;
        for (int i = 0; i < root_count; i++) {
            int uid = 0;
            if (parse_family_root(roots[i].mount_point, &uid) == fam) { exists = true; break; }
        }
        if (exists) { backup_family = fam; break; }
    }
    if (backup_family < 0) { free(all); free(roots); free(sub); LOG_ERR("全局替换: 无法确定备份族"); return -1; }
    static const char* const fam_names[] = { "installer", "androidwritable", "user" };
    LOG("全局替换: 备份族=%s, 共 %d 个族根", fam_names[backup_family], root_count);

    /* 3. 备份：对备份族每个用户，逐节点 bind 到 backup_root/user_<id>/emulated */
    for (int i = 0; i < root_count; i++) {
        int uid = 0;
        if (parse_family_root(roots[i].mount_point, &uid) != backup_family) continue;
        const char* root = roots[i].mount_point;
        char backup_top[PATH_MAX];
        snprintf(backup_top, sizeof(backup_top), "%s/user_%d/emulated", backup_root, uid);
        /* 重入防护：族根已是项目 FUSE 视图（FUSE 崩溃自动恢复后的二次替换），
           备份应已存在；若此时再备份会把代理视图叠在已有系统备份之上，跳过 */
        bool root_is_proxy = (src_dev[0] && strcmp(roots[i].dev, src_dev) == 0) ||
                             fast_strstr(roots[i].fstype, "fuse_daemon") != nullptr ||
                             fast_strstr(roots[i].source, "fuse_daemon") != nullptr;
        if (root_is_proxy) {
            LOG_WRN("全局替换: 族根 %s 已是项目 FUSE 视图，跳过备份（重入）", root);
            continue;
        }
        /* 污染检查：备份顶层已挂载为 fuse 则拒绝 */
        int st = backup_point_state(getpid(), backup_top);
        if (st < 0) {
            LOG_ERR("全局替换: 备份点 %s 已被挂载为 fuse(污染)，拒绝替换", backup_top);
            free(all); free(roots); free(sub);
            return -1;
        }
        if (st == 1) {
            LOG("全局替换: 备份点 %s 已有有效备份，跳过（避免叠 bind）", backup_top);
            continue;
        }
        /* 收集该族根全部挂载点（含自身与 fuse 子挂载） */
        int sn = collect_mounts_under(all, n, root, true, true, sub, 128);
        sort_shallowest_first(sub, sn);   /* 父先子后 bind */
        for (int k = 0; k < sn; k++) {
            const char* rel = sub[k].mount_point + strlen(root);   /* "" 或 "/0/Android/data" */
            char target[PATH_MAX];
            snprintf(target, sizeof(target), "%s%s", backup_top, rel);
            if (mkdir_recursive(target) != 0) {
                log_ns_error("[global_replace] mkdir %s failed errno=%d (%s)\n", target, errno, strerror(errno));
                LOG_ERR("全局替换: mkdir %s 失败: %s", target, strerror(errno));
                free(all); free(roots); free(sub);
                return -1;
            }
            if (mount(sub[k].mount_point, target, nullptr, MS_BIND, nullptr) != 0) {
                log_ns_error("[global_replace] backup bind %s -> %s failed errno=%d (%s)\n",
                             sub[k].mount_point, target, errno, strerror(errno));
                LOG_ERR("全局替换: 备份 bind %s -> %s 失败: %s", sub[k].mount_point, target, strerror(errno));
                free(all); free(roots); free(sub);
                return -1;
            }
            LOG_DBG("全局替换: 备份 %s -> %s", sub[k].mount_point, target);
        }
    }

    /* 4. 替换：三族全部族根，最深优先卸载后 bind fuse_src，并置 MS_SHARED 传播 */
    for (int i = 0; i < root_count; i++) {
        const char* root = roots[i].mount_point;
        int sn = collect_mounts_under(all, n, root, true, true, sub, 128);
        sort_deepest_first(sub, sn);   /* 最深优先卸载 */
        for (int k = 0; k < sn; k++) {
            for (int t = 0; t < 8; t++) {
                if (umount2(sub[k].mount_point, MNT_DETACH) == 0) break;
                if (errno == EINVAL) break;   /* 本就不是挂载点 */
            }
        }
        if (mkdir_recursive((char*)root) != 0) {
            LOG_WRN("全局替换: mkdir %s 失败: %s", root, strerror(errno));
        }
        if (mount(fuse_src, root, nullptr, MS_BIND, nullptr) != 0) {
            log_ns_error("[global_replace] replace bind %s -> %s failed errno=%d (%s)\n",
                         fuse_src, root, errno, strerror(errno));
            LOG_ERR("全局替换: bind %s -> %s 失败: %s", fuse_src, root, strerror(errno));
            free(all); free(roots); free(sub);
            return -1;
        }
        if (mount(nullptr, root, nullptr, MS_SHARED, nullptr) != 0) {
            log_ns_error("[global_replace] MS_SHARED %s failed errno=%d (%s)\n",
                         root, errno, strerror(errno));
            LOG_ERR("全局替换: 置 MS_SHARED %s 失败: %s（传播不可用，替换视为失败）", root, strerror(errno));
            free(all); free(roots); free(sub);
            return -1;
        }
        LOG_DBG("全局替换: %s -> %s", root, fuse_src);
    }
    free(all); free(roots); free(sub);
    return 0;
}

int ns_global_replace_system(int mnt_ns_pid, const char* fuse_src, const char* backup_root) {
    if (!fuse_src || !backup_root) return -1;
    struct GlobalReplaceArgs args = { fuse_src, backup_root };
    int child_err = 0;
    int ret = run_in_mnt_ns_timeout(mnt_ns_pid, do_global_replace, &args, &child_err, 15000);
    if (ret != 0) {
        LOG_ERR("全局替换失败 (ret=%d, err=%d)", ret, child_err);
    }
    return ret;
}

/* 在目标命名空间内执行：从备份恢复三族所有用户视图 */
static int do_global_restore(void* raw) {
    const char* backup_root = (const char*)raw;
    NsMountEntry* all = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    NsMountEntry* bsub = malloc(128 * sizeof(NsMountEntry));
    NsMountEntry* cur = malloc(128 * sizeof(NsMountEntry));
    if (!all || !bsub || !cur) {
        free(all); free(bsub); free(cur);
        return -1;
    }
    int n = read_mountinfo_pid(getpid(), all, NS_MOUNTINFO_MAX);
    if (n <= 0) { free(all); free(bsub); free(cur); return -1; }
    /* 枚举备份顶层：backup_root/user_<id>/emulated */
    size_t blen = strlen(backup_root);
    for (int i = 0; i < n; i++) {
        const char* btop = all[i].mount_point;
        if (strncmp(btop, backup_root, blen) != 0 || btop[blen] != '/') continue;
        if (strncmp(btop + blen + 1, "user_", 5) != 0) continue;
        const char* q = btop + blen + 1 + 5;
        if (!is_digit_char(*q)) continue;
        int uid = 0;
        while (is_digit_char(*q)) { uid = uid * 10 + (*q - '0'); q++; }
        if (strcmp(q, "/emulated") != 0) continue;
        /* 校验备份点未被 fuse 污染 */
        if (backup_point_state(getpid(), btop) != 1) {
            LOG_WRN("全局恢复: 备份点 %s 无效或已被污染，跳过用户 %d", btop, uid);
            continue;
        }
        /* 收集备份树全部挂载点（父先子后 bind 用） */
        int bn = collect_mounts_under(all, n, btop, true, true, bsub, 128);
        sort_shallowest_first(bsub, bn);
        /* 对三族该用户的族根逐一恢复 */
        for (int fam = 0; fam < 3; fam++) {
            static const char* const fam_names[] = { "installer", "androidwritable", "user" };
            char root[PATH_MAX];
            snprintf(root, sizeof(root), "/mnt/%s/%d/emulated", fam_names[fam], uid);
            /* 卸载当前族根上的全部挂载（含 fuse_src bind 与传播子挂载） */
            int cn = collect_mounts_under(all, n, root, true, true, cur, 128);
            sort_deepest_first(cur, cn);
            for (int k = 0; k < cn; k++) {
                for (int t = 0; t < 8; t++) {
                    if (umount2(cur[k].mount_point, MNT_DETACH) == 0) break;
                    if (errno == EINVAL) break;
                }
            }
            if (mkdir_recursive(root) != 0 && errno != EEXIST) {
                LOG_WRN("全局恢复: mkdir %s 失败: %s", root, strerror(errno));
                continue;
            }
            /* 父先子后 bind 备份树节点到族根 */
            for (int k = 0; k < bn; k++) {
                const char* rel = bsub[k].mount_point + strlen(btop);   /* "" 或 "/0/Android/data" */
                char target[PATH_MAX];
                snprintf(target, sizeof(target), "%s%s", root, rel);
                if (mkdir_recursive(target) != 0) { LOG_WRN("全局恢复: mkdir %s 失败", target); continue; }
                if (mount(bsub[k].mount_point, target, nullptr, MS_BIND, nullptr) != 0) {
                    LOG_WRN("全局恢复: bind %s -> %s 失败: %s", bsub[k].mount_point, target, strerror(errno));
                    continue;
                }
            }
            if (mount(nullptr, root, nullptr, MS_SHARED, nullptr) != 0) {
                LOG_WRN("全局恢复: 置 MS_SHARED %s 失败: %s（传播不可用）", root, strerror(errno));
            }
            LOG_DBG("全局恢复: 用户 %d 族 %s 已还原", uid, fam_names[fam]);
        }
        /* 卸载备份点（最深优先） */
        sort_deepest_first(bsub, bn);
        for (int k = 0; k < bn; k++) {
            for (int t = 0; t < 8; t++) {
                if (umount2(bsub[k].mount_point, MNT_DETACH) == 0) break;
                if (errno == EINVAL) break;
            }
        }
    }
    free(all); free(bsub); free(cur);
    return 0;
}

int ns_global_restore_system(int mnt_ns_pid, const char* backup_root) {
    if (!backup_root) return -1;
    int child_err = 0;
    int ret = run_in_mnt_ns_timeout(mnt_ns_pid, do_global_restore, (void*)backup_root, &child_err, 15000);
    if (ret != 0) LOG_ERR("全局恢复失败 (ret=%d, err=%d)", ret, child_err);
    return ret;
}

/* 在应用命名空间内执行：卸载项目 FUSE 并 bind 回备份（幂等） */
static int do_restore_app_fuse(void* raw) {
    struct AppRestoreArgs* args = (struct AppRestoreArgs*)raw;
    NsMountEntry* all = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    NsMountEntry* sub = NULL;   /* 动态分配：按 target/备份树下实际挂载数决定容量 */
    if (!all) { free(all); free(sub); return -1; }
    int n = read_mountinfo_pid(getpid(), all, NS_MOUNTINFO_MAX);
    if (n <= 0) { free(all); free(sub); return -1; }
    const char* target = "/storage/emulated";
    /* 项目 FUSE 源（fuse_src 挂载点）的 major:minor：bind 视图与源共享 superblock，
       以此识别顶层是否为项目 FUSE（mountinfo source 字段是 devname/fsname，
       非 bind 源路径，不能直接比较字符串） */
    char src_dev[64] = {0};
    for (int i = 0; i < n; i++) {
        if (strcmp(all[i].mount_point, args->fuse_src) == 0) {
            strncpy(src_dev, all[i].dev, sizeof(src_dev) - 1);
            break;
        }
    }
    bool is_project = false;
    for (int i = 0; i < n; i++) {
        if (strcmp(all[i].mount_point, target) != 0) continue;
        /* 同挂载点可有多层叠加挂载（系统视图先挂载、项目视图经共享传播
           后叠加），mountinfo 最后一条才是实际生效的最顶层视图：
           必须遍历全部匹配，不能看到第一条就 break */
        if ((src_dev[0] && strcmp(all[i].dev, src_dev) == 0) ||
            fast_strstr(all[i].fstype, "fuse_daemon") != nullptr ||
            fast_strstr(all[i].source, "fuse_daemon") != nullptr) {
            is_project = true;
        }
        /* 不 break：继续遍历，以最后一条（最顶层）为准 */
    }
    if (!is_project) {
        LOG_DBG("应用还原: %s 顶层非项目 FUSE，跳过", target);
        free(all); free(sub);
        return 1;   /* 1=跳过（非项目 FUSE），区别于 0=成功还原 */
    }
    /* 先校验备份点有效，再执行任何卸载：备份无效时必须保留当前可用的代理视图，
       避免把应用置于既无代理视图也无系统视图的裸挂载态（后续扫描还会因顶层
       不再是项目 FUSE 而永久跳过该应用） */
    char backup_top[PATH_MAX];
    snprintf(backup_top, sizeof(backup_top), "%s/user_%d/emulated", args->backup_root, args->user_id);
    if (backup_point_state(getpid(), backup_top) != 1) {
        LOG_ERR("应用还原: 备份点 %s 无效，放弃还原", backup_top);
        free(all); free(sub);
        return -1;
    }
    /* 动态分配 sub：容量取 target 与备份树挂载数的较大值（+余量），
       彻底避免固定上限导致的堆溢出 */
    int cap_target = count_mounts_under(all, n, target, true, true);
    int cap_backup = count_mounts_under(all, n, backup_top, true, true);
    int sub_cap = cap_target > cap_backup ? cap_target : cap_backup;
    if (sub_cap < 16) sub_cap = 16;   /* 保底容量 */
    sub = malloc(sub_cap * sizeof(NsMountEntry));
    if (!sub) {
        free(all);
        return -1;
    }
    /* 卸载顶层（含子挂载，最深优先） */
    int sn = collect_mounts_under(all, n, target, true, true, sub, sub_cap);
    sort_deepest_first(sub, sn);
    for (int k = 0; k < sn; k++) {
        for (int t = 0; t < 8; t++) {
            if (umount2(sub[k].mount_point, MNT_DETACH) == 0) break;
            if (errno == EINVAL) break;
        }
    }
    if (mkdir_recursive((char*)target) != 0) {
        LOG_WRN("应用还原: mkdir %s 失败: %s", target, strerror(errno));
    }
    /* 收集备份树全部挂载点（含自身与 f2fs 子挂载），父先子后逐节点 bind 回
       target：仅 bind 顶层会丢失 Android/data|obb 等 f2fs 直通子挂载 */
    int bn = collect_mounts_under(all, n, backup_top, true, true, sub, sub_cap);
    sort_shallowest_first(sub, bn);
    if (bn == 0) {
        LOG_ERR("应用还原: 备份点 %s 下未收集到任何挂载，放弃还原", backup_top);
        free(all); free(sub);
        return -1;
    }
    for (int k = 0; k < bn; k++) {
        const char* rel = sub[k].mount_point + strlen(backup_top);   /* "" 或 "/0/Android/data" */
        char tgt[PATH_MAX];
        snprintf(tgt, sizeof(tgt), "%s%s", target, rel);
        if (mkdir_recursive(tgt) != 0) {
            LOG_WRN("应用还原: mkdir %s 失败: %s", tgt, strerror(errno));
            continue;
        }
        if (mount(sub[k].mount_point, tgt, nullptr, MS_BIND, nullptr) != 0) {
            LOG_WRN("应用还原: bind %s -> %s 失败: %s", sub[k].mount_point, tgt, strerror(errno));
            continue;
        }
        LOG_DBG("应用还原: bind %s -> %s", sub[k].mount_point, tgt);
    }
    LOG_DBG("应用还原: %s 已从备份 %s 还原（%d 个节点）", target, backup_top, bn);

    /* FUSE BPF passthrough 不可用时需补充 f2fs 直通子挂载：备份树可能不含
       Android/data（备份时源已缺失），此时从真实 f2fs 源 bind 补充。
       仅处理 data（obb 无需处理）；直接复用备份树节点信息判断是否已还原，
       不重读 mountinfo、不额外分配，确保还原路径低延迟。
       注意多用户：/data/media/<uid>/Android/data */
    bool data_in_backup = false;
    for (int k = 0; k < bn; k++) {
        if (fast_strstr(sub[k].mount_point, "/Android/data") != nullptr) { data_in_backup = true; break; }
    }
    if (!data_in_backup) {
        char src[PATH_MAX], dst[PATH_MAX];
        snprintf(src, sizeof src, "/data/media/%d/Android/data", args->user_id);
        snprintf(dst, sizeof dst, "%s/%d/Android/data", target, args->user_id);
        if (access(src, F_OK) != 0) {
            LOG_DBG("应用还原: f2fs 源 %s 不存在，跳过", src);
        } else if (mkdir_recursive(dst) != 0) {
            LOG_WRN("应用还原: mkdir %s 失败: %s", dst, strerror(errno));
        } else if (mount(src, dst, nullptr, MS_BIND, nullptr) != 0) {
            LOG_WRN("应用还原: f2fs bind %s -> %s 失败: %s", src, dst, strerror(errno));
        } else {
            LOG_DBG("应用还原: f2fs 补充 bind %s -> %s", src, dst);
        }
    }
    free(all); free(sub);
    return 0;
}

int ns_restore_app_fuse(int app_pid, const char* fuse_src, const char* backup_root, int user_id) {
    if (!fuse_src || !backup_root) return -1;
    struct AppRestoreArgs args;
    memset(&args, 0, sizeof(args));
    strncpy(args.fuse_src, fuse_src, sizeof(args.fuse_src) - 1);
    strncpy(args.backup_root, backup_root, sizeof(args.backup_root) - 1);
    args.user_id = user_id;
    int child_err = 0;
    int ret = run_in_mnt_ns_timeout(app_pid, do_restore_app_fuse, &args, &child_err, 5000);
    if (ret == 0) {
        LOG_DBG("应用还原成功 (pid=%d)", app_pid);
    } else if (ret == 1) {
        LOG_DBG("应用还原跳过 (pid=%d) 顶层非项目 FUSE", app_pid);
    } else {
        LOG_ERR("应用还原失败 (pid=%d, ret=%d, err=%d)", app_pid, ret, child_err);
    }
    return ret;
}

/* 查询全局替换状态（读 /proc/<pid>/mountinfo，无需进入命名空间） */
int ns_global_status(int mnt_ns_pid, const char* fuse_src) {
    NsMountEntry* all = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    if (!all) return NSP_GLOBAL_STATUS_UNKNOWN;
    int n = read_mountinfo_pid(mnt_ns_pid, all, NS_MOUNTINFO_MAX);
    if (n <= 0) { free(all); return NSP_GLOBAL_STATUS_UNKNOWN; }
    /* 项目 FUSE 源的 major:minor：bind 视图与源共享 superblock，
       mountinfo source 字段是 devname/fsname 而非 bind 源路径，需以 dev 判定 */
    char src_dev[64] = {0};
    for (int i = 0; i < n; i++) {
        if (strcmp(all[i].mount_point, fuse_src) == 0) {
            strncpy(src_dev, all[i].dev, sizeof(src_dev) - 1);
            break;
        }
    }
    int total = 0, replaced = 0;
    for (int i = 0; i < n; i++) {
        if (!is_family_root(all[i].mount_point)) continue;
        total++;
        bool is_proxy = (src_dev[0] && strcmp(all[i].dev, src_dev) == 0);
        if (!is_proxy && fast_strstr(all[i].fstype, "fuse_daemon") != nullptr)
            is_proxy = true;   /* 兜底：fstype 含 fuse_daemon 视为项目视图 */
        if (is_proxy) replaced++;
    }
    free(all);
    if (total == 0) return NSP_GLOBAL_STATUS_UNKNOWN;
    if (replaced == total) return NSP_GLOBAL_STATUS_REPLACED;
    if (replaced == 0) return NSP_GLOBAL_STATUS_NORMAL;
    return NSP_GLOBAL_STATUS_MIXED;
}

int ns_collect_mounts_under(int pid, const char* base_path, int include_self, int include_fuse,
                            char mount_points[][PATH_MAX], int max_count) {
    if (!base_path || max_count <= 0) return 0;
    NsMountEntry* all = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    NsMountEntry* sub = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    if (!all || !sub) { free(all); free(sub); return 0; }
    int n = read_mountinfo_pid(pid, all, NS_MOUNTINFO_MAX);
    if (n <= 0) { free(all); free(sub); return 0; }
    int count = collect_mounts_under(all, n, base_path, include_self != 0, include_fuse != 0, sub, 512);
    sort_deepest_first(sub, count);
    if (count > max_count) count = max_count;
    for (int i = 0; i < count; i++) {
        strncpy(mount_points[i], sub[i].mount_point, PATH_MAX - 1);
        mount_points[i][PATH_MAX - 1] = '\0';
    }
    free(all); free(sub);
    return count;
}