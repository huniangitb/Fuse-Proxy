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
static int run_in_mnt_ns_timeout(int target_pid, int (*func)(void*), void* args, int* child_err, int timeout_ms) {
    struct timespec t_start;
    clock_gettime(CLOCK_MONOTONIC, &t_start);
    int status_pipe[2];
    if (pipe2(status_pipe, O_CLOEXEC) < 0) {
        log_ns_error("[ns_error] Failed to create sync pipe: %s\n", strerror(errno));
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
        _exit(ret == 0 ? 0 : (ret > 0 ? ret : 1));
    }
    close(status_pipe[1]); 
    struct pollfd pfd = {
        .fd = status_pipe[0],
        .events = POLLIN | POLLHUP
    };
    int ret_val = -1;
    int poll_ret = poll(&pfd, 1, timeout_ms);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed = (now.tv_sec - t_start.tv_sec) * 1000 +
                   (now.tv_nsec - t_start.tv_nsec) / 1000000;
    if (poll_ret > 0) {
        int child_ret = -1;
        ssize_t r_len = read(status_pipe[0], &child_ret, sizeof(child_ret));
        int status;
        waitpid(child, &status, 0); 
        if (r_len == sizeof(child_ret)) {
            ret_val = child_ret;
            if (child_err) *child_err = child_ret; 
            if (ret_val != 0) {
                LOG("ns操作 pid=%d 耗时: %ldms, 失败码: %d", target_pid, elapsed, ret_val);
            } else if (elapsed > 50) {
                LOG("ns操作 pid=%d 耗时: %ldms", target_pid, elapsed);
            }
        } else {
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                if (child_err) *child_err = code;
                LOG("ns操作子进程未写入管道异常退出, pid=%d, code: %d", target_pid, code);
            }
            ret_val = -1;
        }
    } else {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        if (child_err) *child_err = ETIMEDOUT;
        errno = ETIMEDOUT;
        LOG("ns操作 pid=%d 超时(%dms), 予以强制终止", target_pid, timeout_ms);
    }
    close(status_pipe[0]);
    return ret_val == 0 ? 0 : -1;
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
        log_ns_error("[ns_error] [%s] Combined mount backup failed: mount(%s -> %s) errno=%d (%s)\n", pkg, target, backup, err, strerror(err));
        log_internal(LOG_ERROR, "[ns_error] [%s] Combined mount backup failed: mount(%s -> %s) errno=%d (%s)", pkg, target, backup, err, strerror(err));
        return err;
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