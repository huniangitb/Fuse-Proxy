#define _GNU_SOURCE
#include "injector.h"
#include "common.h"
#include "config_parser.h"
#include "ns_utils.h"
#include "fast_pid.h"
#include "inject_target.h"
#include "mount_manager.h"
#include "ipc_server.h"
#include "config_publisher.h"
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
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <dirent.h>
#include <ctype.h>
#include <fnmatch.h>
#include <errno.h>
#include <sys/syscall.h>

volatile sig_atomic_t g_should_exit = 0;
volatile sig_atomic_t g_reload_config = 0;
volatile sig_atomic_t g_passive_mode = 0;
volatile sig_atomic_t g_fuse_ready = 0;
int g_global_root_fd = -1;
int g_epoll_fd = -1;
int g_inotify_fd = -1;
int g_config_pub_fd = -1;
static int reload_cooldown_seconds = 0;
static int seconds_until_next_scan = 1; 
static int g_scan_interval_seconds = 30;   
static bool g_last_scan_found = false;          
struct GlobalFuseInfo g_global_fuse = {
    .pid = 1, .fuse_pid = 0, .mnt_path = "/mnt/nsp_global",
    .crash_count = 0, .last_crash_time = 0, .disabled = false
};
struct GlobalFuseInfo g_media_fuse = {
    .pid = 1, .fuse_pid = 0, .mnt_path = "/mnt/nsp_media",
    .crash_count = 0, .last_crash_time = 0, .disabled = false
};

/* 重入保护：防止并发调用 inject_global_fuse() */
static volatile int g_fuse_starting = 0;
/* 延迟首次扫描标记：main() 中注入 FUSE 后不立即扫描，等就绪后再触发 */
static int g_pending_first_scan = 0;
/* FUSE 崩溃恢复后待重挂标记：新 FUSE 就绪时重挂所有追踪应用 */
static volatile sig_atomic_t g_pending_remount = 0;

/* 挂载失败重试队列：应对 FUSE 重建期间并发挂载的瞬态失败 */
#define MAX_RETRY_MOUNTS 64
typedef struct {
    char cmdline[256];
    int pid;
    uid_t uid;
    int retries;
    time_t last_attempt;
} RetryMountEntry;
static RetryMountEntry g_retry_mounts[MAX_RETRY_MOUNTS];
static int g_retry_mount_count = 0;

/* 异步就绪与挂载任务全局描述符注册系统 */
static int g_fuse_ready_pipe_fd = -1;
static void* g_fuse_ready_ctx = nullptr;
#define MAX_ASYNC_MOUNTS 128
static int g_async_mount_fds[MAX_ASYNC_MOUNTS];
static void* g_async_mount_ctxs[MAX_ASYNC_MOUNTS];
static int g_async_mount_count = 0;

void register_fuse_ready_pipe(int fd, void* ctx) {
    g_fuse_ready_pipe_fd = fd;
    g_fuse_ready_ctx = ctx;
}

bool register_async_mount_pipe(int fd, void* ctx) {
    if (g_async_mount_count >= MAX_ASYNC_MOUNTS) return false;
    g_async_mount_fds[g_async_mount_count] = fd;
    g_async_mount_ctxs[g_async_mount_count] = ctx;
    g_async_mount_count++;
    return true;
}

void schedule_retry_mount(const char* pkg, int pid) {
    if (g_retry_mount_count >= MAX_RETRY_MOUNTS) {
        LOG_DBG("重试队列已满，丢弃 %s(PID:%d) 的重试", pkg, pid);
        return;
    }
    for (int i = 0; i < g_retry_mount_count; i++) {
        if (g_retry_mounts[i].pid == pid) return;
    }
    RetryMountEntry *e = &g_retry_mounts[g_retry_mount_count++];
    strncpy(e->cmdline, pkg, sizeof(e->cmdline) - 1);
    e->cmdline[sizeof(e->cmdline) - 1] = '\0';
    e->pid = pid;
    e->uid = 0; 
    e->retries = 0;
    e->last_attempt = time(NULL);
    LOG_DBG("加入重试队列: %s(PID:%d), 队列长度=%d", pkg, pid, g_retry_mount_count);
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
        LOG_DBG("媒体 FUSE 挂载点 g_media_fuse %s 不可达: %s", g_media_fuse.mnt_path, strerror(errno));
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

static void setup_inotify_watches() {
    if (g_inotify_fd >= 0) {
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, g_inotify_fd, nullptr);
        close(g_inotify_fd);
    }
    g_inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (g_inotify_fd < 0) return;
    inotify_add_watch(g_inotify_fd, CONFIG_DIR, IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_TO | IN_DELETE);
    config_lock_read();
    for (int i = 0; i < g_active_user_count; i++) {
        char dir_path[128];
        if (g_active_users[i] == 0)
            snprintf(dir_path, sizeof(dir_path), "%s/App-rules", CONFIG_DIR);
        else
            snprintf(dir_path, sizeof(dir_path), "%s/App-rules-%d", CONFIG_DIR, g_active_users[i]);
        mkdir(dir_path, 0755);
        inotify_add_watch(g_inotify_fd, dir_path, IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_TO | IN_DELETE);
    }
    config_unlock_read();
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = g_inotify_fd };
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_inotify_fd, &ev);
}

static void reload_injector_config() {
    config_lock_write();
    load_config_rules(INJECTOR_CONFIG_PATH);
    config_unlock_write();
    setup_inotify_watches();
}

static void dump_crash_log_tail() {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/fuse_crash.log", LOG_DIR);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    char buf[16384];
    off_t end = lseek(fd, 0, SEEK_END);
    off_t start = (end > (off_t)sizeof(buf)) ? end - (off_t)sizeof(buf) : 0;
    lseek(fd, start, SEEK_SET);
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0) {
        buf[n] = '\0';
        char *p = buf;
        if (start > 0) {
            p = memchr(buf, '\n', n);
            if (p) p++; else p = buf;
        }
        if (*p) {
            LOG_ERR("===== FUSE 崩溃诊断信息 =====");
            char *line = p;
            while (line && *line) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                if (*line) LOG_ERR("| %s", line);
                if (nl) line = nl + 1; else break;
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

void handle_fuse_ready_event(void *ptr) {
    FuseReadyCtx *ctx = (FuseReadyCtx*)ptr;
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
                LOG_ERR("FUSE 就绪验证失败: stat(%s) → %s", g_global_fuse.mnt_path, strerror(errno));
            } else {
                g_fuse_ready = 1;
                LOG_DBG("FUSE 就绪确认: %s", g_global_fuse.mnt_path);
            }
        }
        if (g_pending_first_scan) {
            g_pending_first_scan = 0;
            seconds_until_next_scan = 0;
        }
        if (g_retry_mount_count > 0) {
            seconds_until_next_scan = 0;
        }
        if (g_pending_remount) {
            remount_all_tracked();
        }
    } else {
        LOG_ERR("FUSE 异步启动失败，管道未收到就绪字符");
        dump_crash_log_tail();
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
        if (ns_is_mounted(g_global_fuse.pid, g_global_fuse.mnt_path, nullptr) <= 0)
            break;
        usleep(20000);
    }
    if (!g_global_cfg.fuse_direct) {
        ns_umount_and_rmdir(g_global_fuse.pid, g_global_fuse.mnt_path);
    }
    int ready_pipe[2];
    if (pipe2(ready_pipe, O_CLOEXEC | O_NONBLOCK) == -1) { __sync_lock_release(&g_fuse_starting); return; }
    pid_t child = fork();
    if (child == -1) {
        close(ready_pipe[0]); close(ready_pipe[1]);
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
        if (setns(fd, CLONE_NEWNS) != 0) { close(fd); _exit(11); }
        close(fd);
        if (mkdir(g_global_fuse.mnt_path, 0755) != 0 && errno != EEXIST) _exit(12);
        int log_fd = open(LOG_DIR "/fuse_crash.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
        if (log_fd >= 0) {
            dup2(log_fd, STDERR_FILENO);
            dup2(log_fd, STDOUT_FILENO);
            close(log_fd);
        }
        char exe[256];
        snprintf(exe, sizeof(exe), "%s/fuse_daemon", get_self_dir());
        char arg_ready[64];
        snprintf(arg_ready, sizeof(arg_ready), "--ready-fd=%d", ready_pipe[1]);
        fcntl(ready_pipe[1], F_SETFD, 0);
        char arg_global[64];
        if (g_global_root_fd >= 0) {
            fcntl(g_global_root_fd, F_SETFD, 0);
            snprintf(arg_global, sizeof(arg_global), "--global-root-fd=%d", g_global_root_fd);
        } else {
            strcpy(arg_global, "--global-root-fd=-1");
        }
        const char* log_lvl = "info";
        if (g_min_log_level == LOG_DEBUG) log_lvl = "debug";
        else if (g_min_log_level == LOG_ERROR) log_lvl = "error";
        else if (g_min_log_level == LOG_WARN) log_lvl = "warn";
        char* args[32];
        int ai = 0;
        args[ai++] = "fuse_daemon";
        args[ai++] = g_global_fuse.mnt_path;
        args[ai++] = "--mode=redirect";
        args[ai++] = "--root=" STORAGE_BASE;
        args[ai++] = "--rules=" INJECTOR_CONFIG_PATH;
        if (g_strip_o_direct) args[ai++] = "--strip-o-direct";
        args[ai++] = arg_ready;
        args[ai++] = arg_global;
        args[ai++] = (char*)log_lvl;
        if (g_global_cfg.fuse_extra_args[0]) {
            char extra_copy[512];
            strncpy(extra_copy, g_global_cfg.fuse_extra_args, sizeof(extra_copy) - 1);
            extra_copy[sizeof(extra_copy) - 1] = '\0';
            char *tok = strtok(extra_copy, " ");
            while (tok && ai < 31) {
                args[ai++] = tok;
                tok = strtok(nullptr, " ");
            }
        }
        args[ai++] = "-f";
        args[ai++] = "-o";
        args[ai++] = "allow_other,auto_cache,fsname=fuse_daemon,subtype=fuse_daemon";
        args[ai] = nullptr;
        setenv("LD_LIBRARY_PATH", get_self_dir(), 1);
        execv(exe, args);
        _exit(13);
    }
    close(ready_pipe[1]);
    g_global_fuse.fuse_pid = child;
    FuseReadyCtx *ctx = malloc(sizeof(FuseReadyCtx));
    if (ctx) {
        ctx->pipe_fd = ready_pipe[0];
        ctx->child_pid = child;
        struct epoll_event ev_ready = { .events = EPOLLIN | EPOLLONESHOT, .data.fd = ready_pipe[0] };
        epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, ready_pipe[0], &ev_ready);
        register_fuse_ready_pipe(ready_pipe[0], ctx);
    } else {
        close(ready_pipe[0]);
    }
    __sync_lock_release(&g_fuse_starting);
}

static void inject_media_fuse() {
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
    if (!g_global_cfg.fuse_direct) {
        ns_umount_and_rmdir(g_media_fuse.pid, g_media_fuse.mnt_path);
    }
    int ready_pipe[2];
    if (pipe2(ready_pipe, O_CLOEXEC | O_NONBLOCK) == -1) return;
    pid_t child = fork();
    if (child == -1) { close(ready_pipe[0]); close(ready_pipe[1]); return; }
    if (child == 0) {
        close(ready_pipe[0]);
        sigset_t empty_mask;
        sigemptyset(&empty_mask);
        pthread_sigmask(SIG_SETMASK, &empty_mask, nullptr);
        char ns_path[64];
        snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", g_media_fuse.pid);
        int fd = open(ns_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) _exit(10);
        if (setns(fd, CLONE_NEWNS) != 0) { close(fd); _exit(11); }
        close(fd);
        if (mkdir(g_media_fuse.mnt_path, 0755) != 0 && errno != EEXIST) _exit(12);
        int log_fd = open(LOG_DIR "/fuse_crash.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
        if (log_fd >= 0) {
            dup2(log_fd, STDERR_FILENO);
            dup2(log_fd, STDOUT_FILENO);
            close(log_fd);
        }
        char exe[256];
        snprintf(exe, sizeof(exe), "%s/fuse_daemon", get_self_dir());
        char arg_ready[64];
        snprintf(arg_ready, sizeof(arg_ready), "--ready-fd=%d", ready_pipe[1]);
        fcntl(ready_pipe[1], F_SETFD, 0);
        char arg_global[64];
        if (g_global_root_fd >= 0) {
            fcntl(g_global_root_fd, F_SETFD, 0);
            snprintf(arg_global, sizeof(arg_global), "--global-root-fd=%d", g_global_root_fd);
        } else {
            strcpy(arg_global, "--global-root-fd=-1");
        }
        const char* log_lvl = "info";
        if (g_min_log_level == LOG_DEBUG) log_lvl = "debug";
        else if (g_min_log_level == LOG_ERROR) log_lvl = "error";
        else if (g_min_log_level == LOG_WARN) log_lvl = "warn";
        char* args[32];
        int ai = 0;
        args[ai++] = "fuse_daemon";
        args[ai++] = g_media_fuse.mnt_path;
        args[ai++] = "--mode=redirect";
        args[ai++] = "--root=" STORAGE_BASE;
        args[ai++] = "--rules=" INJECTOR_CONFIG_PATH;
        if (g_strip_o_direct) args[ai++] = "--strip-o-direct";
        args[ai++] = arg_ready;
        args[ai++] = arg_global;
        args[ai++] = (char*)log_lvl;
        args[ai++] = "--no-passthrough";
        args[ai++] = "--media-fuse";

        /* ============== 核心改动：在启动参数中强制追加禁用沙盒标志 ============== */
        args[ai++] = "--disable-sandbox";
        
        args[ai++] = "-f";
        args[ai++] = "-o";
        args[ai++] = "allow_other,auto_cache,fsname=fuse_daemon,subtype=fuse_media_daemon";
        args[ai] = nullptr;
        setenv("LD_LIBRARY_PATH", get_self_dir(), 1);
        execv(exe, args);
        _exit(13);
    }
    close(ready_pipe[1]);
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
    bool has_fuse = (ns_is_mounted(pid, target_path, "fuse.fuse_daemon") > 0 || ns_is_mounted(pid, target_path, "fuse_daemon") > 0);
    if (!has_backup && !has_fuse) return 0;
    cleanup_app_mounts(pid, target_path, backup_path, uid);
    return 0;
}

static void cleanup_all_target_apps() {
    fast_pid_each(cleanup_cb, nullptr);
}

static int remount_cb(int pid, const char* cmd, void* data) {
    if (!is_process_safe_to_inject(cmd)) return 0;
    uid_t uid = get_app_uid(pid);
    if (is_target_app(cmd, uid, pid, false)) {
        const char* mnt_src = (const char*)data;
        char pkg[256];
        strncpy(pkg, cmd, sizeof(pkg) - 1);
        pkg[sizeof(pkg) - 1] = '\0';
        char *colon = strchr(pkg, ':');
        if (colon) *colon = '\0';
        if (perform_app_mount(pkg, pid, uid, mnt_src, "FUSE崩溃恢复重挂") != 0) {
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
    LOG("FUSE 崩溃恢复: 开始重挂所有目标应用");
    fast_pid_each(remount_cb, (void*)mnt_src);
    g_pending_remount = 0;
    LOG("FUSE 崩溃恢复重挂完成");
}

static void check_and_recover_fuse() {
    if (g_global_fuse.disabled || g_global_fuse.pid <= 0) return;
    if (g_global_fuse.fuse_pid > 0 && kill(g_global_fuse.fuse_pid, 0) != 0) {
        g_fuse_ready = 0;
        int status = 0;
        if (waitpid(g_global_fuse.fuse_pid, &status, WNOHANG) == g_global_fuse.fuse_pid)
            dump_crash_log_tail();
        g_global_fuse.fuse_pid = 0;
        time_t now = time(nullptr);
        if (now - g_global_fuse.last_crash_time < 60)
            g_global_fuse.crash_count++;
        else
            g_global_fuse.crash_count = 1;
        g_global_fuse.last_crash_time = now;
        if (g_global_fuse.crash_count > 5) {
            g_global_fuse.disabled = true;
            return;
        }
        force_recover_tracked_mounts();
        inject_global_fuse();
        if (g_global_fuse.fuse_pid > 0) {
            cleanup_all_target_apps();
            g_pending_remount = 1;
        }
    }
    
    /* 
     * 媒体 FUSE 专属崩溃恢复：
     * 只有当 com.android.providers.media.module 仍是注入目标时才拉起。
     */
    if (g_media_fuse.fuse_pid > 0 && kill(g_media_fuse.fuse_pid, 0) != 0) {
        int status;
        waitpid(g_media_fuse.fuse_pid, &status, WNOHANG);
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
        if (is_media_module_injected_target()) {
            LOG("专用媒体 FUSE 异常退出，执行重新拉起任务");
            inject_media_fuse();
        }
    } else if (g_media_fuse.fuse_pid <= 0 && !g_media_fuse.disabled && g_fuse_ready) {
        /* 
         * 媒体 FUSE 惰性启动：
         * 初始时未启动，在定时轮询中检测到 com.android.providers.media.module 变动为注入目标时，惰性启动媒体 FUSE。
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
        int status;
        waitpid(g_media_fuse.fuse_pid, &status, WNOHANG);
        g_media_fuse.fuse_pid = 0;
        ns_force_umount_stale(g_media_fuse.pid, g_media_fuse.mnt_path);
    }
}

typedef struct {
    char cmdline[256];
    int pid;
    uid_t uid;
    const char *mnt_src;
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
    ProcEntry *entries = malloc(MAX_CANDIDATES * sizeof(ProcEntry));
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
        for (long bpos = 0; bpos < nread && entry_count < MAX_CANDIDATES; ) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(dent_buf + bpos);
            if (d->d_reclen == 0) break;
            bpos += d->d_reclen;
            if (d->d_type != DT_DIR) continue;
            if (!isdigit((unsigned char)d->d_name[0])) continue;
            int pid = atoi(d->d_name);
            if (pid < 1000) continue;
            if (is_tracked(pid)) continue;
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
            char *line = status_buf;
            while (*line) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                if (line[0] == 'P' && line[1] == 'P' && line[2] == 'i' && line[3] == 'd' && line[4] == ':')
                    ppid = atoi(line + 5);
                else if (line[0] == 'U' && line[1] == 'i' && line[2] == 'd' && line[3] == ':')
                    uid = atoi(line + 4);
                if (!nl) break;
                line = nl + 1;
            }
            if (!is_parent_zygote(ppid)) continue;
            if (is_isolated_uid(uid)) continue;
            strncpy(entries[entry_count].cmdline, cmdline, sizeof(entries[entry_count].cmdline) - 1);
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
        if (is_target_app_locked(entries[i].cmdline, entries[i].uid, entries[i].pid, false)) {
            m_tasks[m_count].pid = entries[i].pid;
            m_tasks[m_count].uid = entries[i].uid;
            strncpy(m_tasks[m_count].cmdline, entries[i].cmdline, sizeof(m_tasks[m_count].cmdline) - 1);
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
            
            perform_app_mount(m_tasks[i].cmdline, m_tasks[i].pid, m_tasks[i].uid, nullptr, "主动扫描");
            
            if (first_scan) {
                struct timespec ts_mnt_end;
                clock_gettime(CLOCK_MONOTONIC, &ts_mnt_end);
                long el = (ts_mnt_end.tv_sec - ts_mnt.tv_sec) * 1000 +
                          (ts_mnt_end.tv_nsec - ts_mnt.tv_nsec) / 1000000;
                LOG("初次扫描 - 挂载 %s(PID:%d) 完成, 耗时: %ldms", m_tasks[i].cmdline, m_tasks[i].pid, el);
            }
        }
    }
    if (first_scan) {
        clock_gettime(CLOCK_MONOTONIC, &ts_match_end);
        long elapsed = (ts_match_end.tv_sec - ts_match_start.tv_sec) * 1000 +
                       (ts_match_end.tv_nsec - ts_match_start.tv_nsec) / 1000000;
        LOG("初次扫描 - 配置匹配完成, %d 候选/%d 配置, 耗时: %ldms", m_count, g_app_cfg_count, elapsed);
        first_scan = false;
    }
    free(m_tasks);
    free(entries);
    return m_count;
}

void reap_zombies() {
    int status;
    while (waitpid(-1, &status, WNOHANG) > 0);
}

static void do_cleanup() {
    g_should_exit = 1;
    if (g_inotify_fd >= 0) {
        close(g_inotify_fd);
        g_inotify_fd = -1;
    }
    force_recover_tracked_mounts();
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
        if (!g_global_cfg.fuse_direct) {
            ns_umount_and_rmdir(g_global_fuse.pid, g_global_fuse.mnt_path);
        }
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
        if (!g_global_cfg.fuse_direct) {
            ns_umount_and_rmdir(g_media_fuse.pid, g_media_fuse.mnt_path);
        }
    }
    config_publisher_cleanup(g_config_pub_fd);
    g_config_pub_fd = -1;
    cleanup_system_pkg_cache();
    log_close();
    config_destroy_lock();
    fast_pid_cleanup();
}

int main(int argc, char *argv[]) {
    escape_cgroup();
    sigset_t sig_mask;
    sigemptyset(&sig_mask);
    sigaddset(&sig_mask, SIGINT);
    sigaddset(&sig_mask, SIGTERM);
    sigaddset(&sig_mask, SIGHUP);
    sigaddset(&sig_mask, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &sig_mask, nullptr);
    bool start_passive = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) g_min_log_level = LOG_DEBUG;
        else if (strcmp(argv[i], "error") == 0) g_min_log_level = LOG_ERROR;
        else if (strcmp(argv[i], "info") == 0) g_min_log_level = LOG_INFO;
        else if (strcmp(argv[i], "warn") == 0 || strcmp(argv[i], "warning") == 0) g_min_log_level = LOG_WARN;
        else if (strcmp(argv[i], "--strip-o-direct") == 0) g_strip_o_direct = true;
        else if (strcmp(argv[i], "--passive") == 0 || strcmp(argv[i], "passive") == 0) start_passive = true;
    }
    signal(SIGPIPE, SIG_IGN);
    g_global_root_fd = open("/", O_RDONLY | O_PATH | O_CLOEXEC);
    escape_cgroup();
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    setsid();
    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        if (x != g_global_root_fd) close(x);
    }
    int dev_null = open("/dev/null", O_RDWR | O_CLOEXEC);
    dup2(dev_null, 0);
    dup2(dev_null, 1);
    dup2(dev_null, 2);
    close(dev_null);
    log_init("injector");
    init_system_pkg_cache();
    config_init_lock();
    fast_pid_init();
    init_uid_map_cache();
    g_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epoll_fd < 0) {
        PERROR("无法创建 epoll 实例");
        exit(1);
    }
    int sig_fd = signalfd(-1, &sig_mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sig_fd < 0) {
        PERROR("无法创建 signalfd");
        exit(1);
    }
    struct epoll_event ev_sig = { .events = EPOLLIN, .data.fd = sig_fd };
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, sig_fd, &ev_sig);
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd < 0) {
        PERROR("无法创建 timerfd");
        exit(1);
    }
    struct itimerspec ts = {
        .it_interval = { .tv_sec = 1, .tv_nsec = 0 },
        .it_value = { .tv_sec = 1, .tv_nsec = 0 }
    };
    timerfd_settime(timer_fd, 0, &ts, nullptr);
    struct epoll_event ev_timer = { .events = EPOLLIN, .data.fd = timer_fd };
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev_timer);
    int ipc_sock = ipc_server_init();
    if (ipc_sock < 0) {
        PERROR("无法初始化 IPC 服务");
        exit(1);
    }
    struct epoll_event ev_ipc = { .events = EPOLLIN, .data.fd = ipc_sock };
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, ipc_sock, &ev_ipc);
    g_config_pub_fd = config_publisher_init();
    strcpy(g_real_root, STORAGE_BASE);
    mkdir_recursive(BACKUP_DIR);
    reload_injector_config();
    int wait_count = 0;
    while (faccessat(g_global_root_fd, "data/media/0", F_OK, 0) != 0 && wait_count < 120 && !g_should_exit) {
        usleep(500000);
        wait_count++;
    }
    inject_global_fuse();
    if (g_global_fuse.fuse_pid <= 0) exit(1);
    
    if (is_media_module_injected_target()) {
        LOG("检测到 com.android.providers.media.module 在注入目标之列，正在启动专用媒体 FUSE 实例。");
        inject_media_fuse();
    } else {
        LOG_DBG("com.android.providers.media.module 未开启注入，跳过媒体 FUSE 实例的启动。");
    }
    
    g_pending_first_scan = 1;
    seconds_until_next_scan = 0;
    if (start_passive) {
        g_passive_mode = 1;
        LOG("被动监听模式启动");
    }
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
            if (fd == sig_fd) {
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
            } else if (fd == timer_fd) {
                uint64_t expirations;
                if (read(timer_fd, &expirations, sizeof(expirations)) > 0) {
                    check_and_recover_fuse();
                    reap_zombies();
                    if (reload_cooldown_seconds > 0) {
                        reload_cooldown_seconds--;
                        if (reload_cooldown_seconds == 0) {
                            g_reload_config = 1;
                        }
                    }
                    if (!g_passive_mode) {
                        if (seconds_until_next_scan > 0) {
                            seconds_until_next_scan--;
                        }
                        if (seconds_until_next_scan == 0) {
                            int found_now = scan_zygote_children();
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
                    if (g_fuse_ready && g_retry_mount_count > 0) {
                        const char *mnt_src_retry = get_active_mnt_src();
                        if (mnt_src_retry) {
                            int retry_idx = 0;
                            while (retry_idx < g_retry_mount_count) {
                                RetryMountEntry *e = &g_retry_mounts[retry_idx];
                                e->retries++;
                                if (e->retries > 5) {
                                    LOG_DBG("重试耗尽，放弃 %s(PID:%d)", e->cmdline, e->pid);
                                    e->pid = -1; 
                                } else if (kill(e->pid, 0) != 0) {
                                    LOG_DBG("重试跳过 %s(PID:%d) — 进程已死亡", e->cmdline, e->pid);
                                    e->pid = -1; 
                                } else {
                                    /* 指数退避：第 N 次重试间隔 2^(N-2) 秒 (N>=2) */
                                    if (e->retries > 1) {
                                        time_t now = time(NULL);
                                        int backoff = 1 << (e->retries - 2); /* 1, 2, 4, 8 秒 */
                                        if (now - e->last_attempt < backoff) {
                                            LOG_DBG("重试退避 %s(PID:%d), 第%d次, 已过%lds<%ds",
                                                    e->cmdline, e->pid, e->retries,
                                                    now - e->last_attempt, backoff);
                                            retry_idx++;
                                            continue;
                                        }
                                    }
                                    uid_t uid = get_app_uid(e->pid);
                                    e->last_attempt = time(NULL);
                                    LOG_DBG("重试挂载 %s(PID:%d, UID:%d) 第 %d 次", e->cmdline, e->pid, uid, e->retries);
                                    int ret = perform_app_mount(e->cmdline, e->pid, uid, nullptr, "失败重试");
                                    if (ret == 0) {
                                        LOG_DBG("重试成功/跳过, 移除 %s(PID:%d) 的重试", e->cmdline, e->pid);
                                        e->pid = -1;
                                    }
                                }
                                retry_idx++;
                            }
                            int new_count = 0;
                            for (int i = 0; i < g_retry_mount_count; i++) {
                                if (g_retry_mounts[i].pid > 0)
                                    g_retry_mounts[new_count++] = g_retry_mounts[i];
                            }
                            g_retry_mount_count = new_count;
                        }
                    }
                }
            } else if (fd == g_inotify_fd) {
                char inotify_buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
                ssize_t len = read(g_inotify_fd, inotify_buf, sizeof(inotify_buf));
                if (len > 0) {
                    bool need_reload = false;
                    for (char *ptr = inotify_buf; ptr < inotify_buf + len; ) {
                        struct inotify_event *ev = (struct inotify_event *) ptr;
                        if (ev->len && (strcmp(ev->name, "injector.conf") == 0 || strstr(ev->name, ".conf"))) {
                            need_reload = true;
                        }
                        ptr += sizeof(struct inotify_event) + ev->len;
                    }
                    if (need_reload) {
                        reload_cooldown_seconds = 1; 
                    }
                }
            } else if (fd == ipc_sock) {
                int client_fd = accept(ipc_sock, nullptr, nullptr);
                if (client_fd >= 0) {
                    int flags = fcntl(client_fd, F_GETFL, 0);
                    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
                    fcntl(client_fd, F_SETFD, FD_CLOEXEC);
                    struct epoll_event ev_client = { .events = EPOLLIN | EPOLLONESHOT, .data.fd = client_fd };
                    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, client_fd, &ev_client);
                }
            } else if (fd == g_config_pub_fd) {
                config_publisher_handle_readable(fd);
            } else if (fd == g_fuse_ready_pipe_fd) {
                handle_fuse_ready_event(g_fuse_ready_ctx);
                g_fuse_ready_pipe_fd = -1;
                g_fuse_ready_ctx = nullptr;
            } else {
                int mount_idx = -1;
                for (int m = 0; m < g_async_mount_count; m++) {
                    if (g_async_mount_fds[m] == fd) {
                        mount_idx = m;
                        break;
                    }
                }
                if (mount_idx >= 0) {
                    handle_async_mount_event(g_async_mount_ctxs[mount_idx]);
                    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, g_async_mount_fds[mount_idx], nullptr);
                    close(g_async_mount_fds[mount_idx]);
                    g_async_mount_fds[mount_idx] = g_async_mount_fds[g_async_mount_count - 1];
                    g_async_mount_ctxs[mount_idx] = g_async_mount_ctxs[g_async_mount_count - 1];
                    g_async_mount_count--;
                } else {
                    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
                    handle_ipc_client_readable(fd);
                }
            }
        }
        if (g_reload_config && !g_should_exit) {
            g_reload_config = 0;
            fast_pid_cache_clear();
            ChangedPkg out_changed[128];
            config_lock_write();
            int changed_count = reload_config_rules_diff(INJECTOR_CONFIG_PATH, out_changed, 128);
            config_unlock_write();
            setup_inotify_watches();
            config_publisher_broadcast();
            
            if (g_media_fuse.fuse_pid > 0 && !is_media_module_injected_target()) {
                LOG("配置变更：媒体组件不再是注入目标。正在终结专属媒体 FUSE...");
                kill(g_media_fuse.fuse_pid, SIGTERM);
                int status;
                waitpid(g_media_fuse.fuse_pid, &status, WNOHANG);
                g_media_fuse.fuse_pid = 0;
                ns_force_umount_stale(g_media_fuse.pid, g_media_fuse.mnt_path);
            } else if (g_media_fuse.fuse_pid <= 0 && is_media_module_injected_target() && g_fuse_ready) {
                LOG("配置变更：检测到专属媒体 FUSE 需要被拉起...");
                inject_media_fuse();
            }

            if (changed_count == -1) {
                audit_tracked_apps();
            } else if (changed_count > 0) {
                audit_and_remount_specific_apps(out_changed, changed_count);
            }
        }
    }
    do_cleanup();
    ipc_server_cleanup(ipc_sock);
    if (timer_fd >= 0) close(timer_fd);
    if (sig_fd >= 0) close(sig_fd);
    if (g_epoll_fd >= 0) close(g_epoll_fd);
    return 0;
}