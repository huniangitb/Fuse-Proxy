/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#define _GNU_SOURCE
#include "injector.h"
#include "common.h"
#include "nsp_util.h"
#include "config_parser.h"
#include "ns_utils.h"
#include "fast_pid.h"
#include "inject_target.h"
#include "mount_manager.h"
#include "ipc_server.h"
#include "config_publisher.h"
#include "sys_pkg.h"
#include "build_info.h"
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
static int seconds_until_next_scan = 1; 
static int g_scan_interval_seconds = 30;   
static bool g_last_scan_found = false;          
/* 全局替换模式首次兜底扫描标志：FUSE 就绪后仅执行一次扫描，
   还原存量非目标应用；之后生命周期内不再反复周期检测（新应用
   由 zygisk IPC 通知即时还原） */
static bool g_global_replace_scanned_once = false;
struct GlobalFuseInfo g_global_fuse = {
    .pid = 1, .fuse_pid = 0, .mnt_path = "/mnt/nsp_global",
    .crash_count = 0, .last_crash_time = 0, .disabled = false
};
struct GlobalFuseInfo g_media_fuse = {
    .pid = 1, .fuse_pid = 0, .mnt_path = "/mnt/nsp_media",
    .crash_count = 0, .last_crash_time = 0, .disabled = false
};

/* 全局替换式挂载方案开关（--global-replace）：默认关闭，沿用逐应用挂载 */
bool g_global_replace_mode = false;

/* 权限完全镜像开关（--preserve-perms）：injector 命令行解析，启动
   fuse_daemon 时传递 --preserve-perms，使 FUSE 保留底层真实文件的
   uid/gid/权限（不伪造为访问者权限） */
static bool g_preserve_perms_flag = false;

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
    /* 系统应用表刷新（pm→内存+落盘 sys_pkgs.cache，供 fuse_daemon 只读消费；
       仅当类别段存在时查询，避免无谓 popen） */
    if (config_has_category_rules()) sys_pkg_refresh();
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
                /* ECONNREFUSED(=fc->conn_error)/ENOTCONN(=fc->connected 断开)：
                   区分两类根因——daemon 进程死亡(崩溃/被杀) vs 进程存活但连接被内核中止(INIT 回包被拒) */
                if (errno == ECONNREFUSED || errno == ENOTCONN) {
                    if (g_global_fuse.fuse_pid > 0 && kill(g_global_fuse.fuse_pid, 0) != 0) {
                        /* ① daemon 已退出：连接随进程死亡而中止 */
                        LOG_ERR("fuse_daemon(pid=%d) 已退出，连接随之中止（崩溃或被杀）", g_global_fuse.fuse_pid);
                        dump_crash_log_tail();
                    } else {
                        /* ② daemon 存活但连接死亡：内核拒绝了 INIT 回包（fc->conn_error）。
                           典型：DAX 内核把回包 legacy bit31 误读为 FUSE_MAP_ALIGNMENT，
                           或回包请求了内核无法兑现的能力位——可对照 fuse_daemon 的
                           “FUSE 协商详情 (capable/want)”日志定位具体位 */
                        LOG_ERR("fuse_daemon 进程存活但 FUSE 连接被内核中止（fc->conn_error）");
                        LOG_ERR("→ 判定: 内核拒绝了 INIT 回包（DAX 内核误读 legacy bit31 为 FUSE_MAP_ALIGNMENT，或请求位不被接受）");
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
                        dump_crash_log_tail();
                    }
                    g_fuse_ready = 0;
                    g_pending_remount = 1;
                    seconds_until_next_scan = 0;
                }
            } else {
                g_fuse_ready = 1;
                LOG_DBG("FUSE 就绪确认: %s", g_global_fuse.mnt_path);
                /* 全局替换模式：FUSE 就绪后立即将 emulated 族根替换为代理视图 */
                if (g_global_replace_mode) {
                    LOG("全局替换模式: 执行 emulated 全局替换 (fuse_src=%s)", g_global_fuse.mnt_path);
                    if (ns_global_replace_system(g_global_fuse.pid, g_global_fuse.mnt_path, GLOBAL_BACKUP_ROOT) != 0) {
                        LOG_ERR("全局替换失败，系统视图可能处于混合状态");
                    }
                }
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
    ns_umount_and_rmdir(g_global_fuse.pid, g_global_fuse.mnt_path);
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
        /* fuse_crash.log 始终创建（O_CREAT）：确保首次崩溃即捕获完整
           backtrace——daemon 的 stderr 重定向到此文件（crash_handler 的
           backtrace 帧写 stderr），崩溃后 injector 的 dump_crash_log_tail()
           读取其尾部。此前不带 O_CREAT 导致文件从不创建、stderr 不重定向，
           backtrace 全部丢失（设备上 fuse_crash.log 从未出现即此原因） */
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
        if (g_preserve_perms_flag) args[ai++] = "--preserve-perms";
        if (g_no_passthrough_fallback) args[ai++] = "--no-passthrough";
        if (g_crash_test) args[ai++] = "--crash-test";
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
    if (g_global_replace_mode) return;  /* 新挂载方案（全局替换）无需媒体专属 FUSE */
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
        /* fuse_crash.log 始终创建（O_CREAT）：确保首次崩溃即捕获完整
           backtrace——daemon 的 stderr 重定向到此文件（crash_handler 的
           backtrace 帧写 stderr），崩溃后 injector 的 dump_crash_log_tail()
           读取其尾部。此前不带 O_CREAT 导致文件从不创建、stderr 不重定向，
           backtrace 全部丢失（设备上 fuse_crash.log 从未出现即此原因） */
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
        if (g_preserve_perms_flag) args[ai++] = "--preserve-perms";
        if (g_no_passthrough_fallback) args[ai++] = "--no-passthrough";
        if (g_crash_test) args[ai++] = "--crash-test";
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
            /* 全局替换模式：崩溃超限禁用 FUSE 前必须恢复系统 emulated 视图，
               避免系统停留在失效的代理 bind 上 */
            if (g_global_replace_mode) {
                LOG("FUSE 崩溃超限，恢复系统 emulated 视图");
                ns_global_restore_system(g_global_fuse.pid, GLOBAL_BACKUP_ROOT);
            }
            /* 崩溃超限仍无法恢复正常：核心 FUSE 已不可用，injector 自动退出
               （主循环退出后 do_cleanup 会终结残留 daemon 并完成卸载） */
            LOG_ERR("FUSE 连续崩溃 %d 次仍无法恢复，injector 自动退出", g_global_fuse.crash_count);
            g_should_exit = 1;
            return;
        }
        force_recover_tracked_mounts();
        inject_global_fuse();
        if (g_global_fuse.fuse_pid > 0) {
            cleanup_all_target_apps();
            g_pending_remount = 1;
        }
    }
    
    /* 新挂载方案（全局替换模式）：媒体专属 FUSE 仅传统逐应用挂载方案需要。
       全局替换下 /storage/emulated 已整体由全局 FUSE 提供代理视图，媒体模块
       自动继承，无需专属 FUSE——整体跳过启动/崩溃恢复/热重载终结管理。 */
    if (g_global_replace_mode) return;

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
        if (!g_global_replace_mode && is_media_module_injected_target()) {
            LOG("专用媒体 FUSE 异常退出，执行重新拉起任务");
            inject_media_fuse();
        }
    } else if (g_media_fuse.fuse_pid <= 0 && !g_media_fuse.disabled && g_fuse_ready && !g_global_replace_mode) {
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
    all_apps_prune();   /* 扫描前清理全量缓存中的已死进程 */
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
            /* 全量应用 PID 缓存：无条件记录所有 zygote 子进程（含已停用/
               未追踪应用），规则变化时可快速定位 pid 立即挂载 */
            all_apps_upsert(pid, uid, cmdline);
            if (is_tracked(pid)) continue;   /* 挂载候选仍跳过已追踪（避免重复处理） */
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
        bool is_target = is_target_app_locked(entries[i].cmdline, entries[i].uid, entries[i].pid, false);
        if (g_global_replace_mode) {
            /* 全局替换模式：目标应用已由全局替换自动获得代理视图，无需逐应用挂载；
               非目标应用需主动卸载项目 FUSE 并还原系统视图（卸载优先） */
            if (!is_target) {
                m_tasks[m_count].pid = entries[i].pid;
                m_tasks[m_count].uid = entries[i].uid;
                strncpy(m_tasks[m_count].cmdline, entries[i].cmdline, sizeof(m_tasks[m_count].cmdline) - 1);
                m_tasks[m_count].cmdline[sizeof(m_tasks[m_count].cmdline) - 1] = '\0';
                m_count++;
            }
        } else if (is_target) {
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
            
            if (g_global_replace_mode) {
                /* 增量还原：还原成功（或已还原跳过）后标记追踪，
                   后续周期扫描经 is_tracked 直接跳过，避免反复检测；
                   还原即解除注入状态（显式标志清除） */
                if (perform_app_restore(m_tasks[i].cmdline, m_tasks[i].pid, m_tasks[i].uid) >= 0) {
                    add_tracked(m_tasks[i].pid);
                    unmark_injected(m_tasks[i].pid);
                }
            } else {
                perform_app_mount(m_tasks[i].cmdline, m_tasks[i].pid, m_tasks[i].uid, nullptr, "主动扫描");
            }
            
            if (first_scan) {
                struct timespec ts_mnt_end;
                clock_gettime(CLOCK_MONOTONIC, &ts_mnt_end);
                long el = (ts_mnt_end.tv_sec - ts_mnt.tv_sec) * 1000 +
                          (ts_mnt_end.tv_nsec - ts_mnt.tv_nsec) / 1000000;
                LOG_DBG("初次扫描 - %s %s(PID:%d) 完成, 耗时: %ldms",
                    g_global_replace_mode ? "还原" : "挂载",
                    m_tasks[i].cmdline, m_tasks[i].pid, el);
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
    all_apps_cleanup();   /* 释放全量应用 PID 缓存 */
    if (g_inotify_fd >= 0) {
        close(g_inotify_fd);
        g_inotify_fd = -1;
    }
    force_recover_tracked_mounts();
    /* 全局替换模式：退出前先恢复系统 emulated 视图，再终结 FUSE */
    if (g_global_replace_mode && g_fuse_ready) {
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
} InjectorFds;

static void parse_cli_args(int argc, char *argv[], bool *start_passive_out) {
    bool start_passive = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) g_min_log_level = LOG_DEBUG;
        else if (strcmp(argv[i], "error") == 0) g_min_log_level = LOG_ERROR;
        else if (strcmp(argv[i], "info") == 0) g_min_log_level = LOG_INFO;
        else if (strcmp(argv[i], "warn") == 0 || strcmp(argv[i], "warning") == 0) g_min_log_level = LOG_WARN;
        else if (strcmp(argv[i], "--strip-o-direct") == 0) g_strip_o_direct = true;
        else if (strcmp(argv[i], "--preserve-perms") == 0) g_preserve_perms_flag = true;
        else if (strcmp(argv[i], "--crash-test") == 0) g_crash_test = true;
        else if (strcmp(argv[i], "--passive") == 0 || strcmp(argv[i], "passive") == 0) start_passive = true;
        else if (strcmp(argv[i], "--global-replace") == 0) g_global_replace_mode = true;
    }
    *start_passive_out = start_passive;
}

/* P3：信号集唯一构造点（early_init 填充，setup_epoll 复用，禁两处手写重复） */
static sigset_t g_injector_sig_mask;

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
}

static void injector_setup_epoll(InjectorFds *fds) {
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
    fds->sig_fd = sig_fd;
    fds->timer_fd = timer_fd;
    fds->ipc_sock = ipc_sock;
}

static void injector_start_fuses(bool start_passive) {
    g_config_pub_fd = config_publisher_init();
    strcpy(g_real_root, STORAGE_BASE);
    mkdir_recursive(BACKUP_DIR);
    /* 应用规则目录创建权归属 injector 单一进程：显式开启后，后续所有
       load_config_rules 调用（启动 + 热重载 reload_config_rules_diff）均
       允许 mkdir App-rules / App-rules-<uid>；fuse_daemon/log_ctl 等
       只读加载方保持默认 false，杜绝伪用户目录固化 */
    config_set_allow_app_rules_mkdir(true);
    reload_injector_config();
    int wait_count = 0;
    while (faccessat(g_global_root_fd, "data/media/0", F_OK, 0) != 0 && wait_count < 120 && !g_should_exit) {
        usleep(500000);
        wait_count++;
    }
    inject_global_fuse();
    if (g_global_fuse.fuse_pid <= 0) exit(1);

    if (!g_global_replace_mode && is_media_module_injected_target()) {
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
    if (!g_passive_mode || (g_global_replace_mode && !g_global_replace_scanned_once)) {
        /* 被动模式下禁用周期扫描（新应用由 zygisk IPC 通知即时还原）；
           全局替换模式仅在程序生命周期开始时执行一次兜底扫描，
           还原存量非目标应用，之后不再反复周期检测 */
        if (seconds_until_next_scan > 0) {
            seconds_until_next_scan--;
        }
        if (seconds_until_next_scan == 0) {
            int found_now = scan_zygote_children();
            if (g_global_replace_mode) {
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

static void retry_pending_mounts(void) {
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

static void on_timer_event(int timer_fd) {
    uint64_t expirations;
    if (read(timer_fd, &expirations, sizeof(expirations)) > 0) {
        check_and_recover_fuse();
        reap_zombies();
        maybe_periodic_scan();
        retry_pending_mounts();
    }
}

static void on_inotify_event(void) {
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
            g_reload_config = 1;  /* 直接触发，去除 cooldown race */
        }
    }
}

static void on_ipc_accept(int ipc_sock) {
    int client_fd = accept(ipc_sock, nullptr, nullptr);
    if (client_fd >= 0) {
        int flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
        fcntl(client_fd, F_SETFD, FD_CLOEXEC);
        struct epoll_event ev_client = { .events = EPOLLIN | EPOLLONESHOT, .data.fd = client_fd };
        epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, client_fd, &ev_client);
    }
}

static void on_client_fd(int fd) {
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

static void handle_pending_reload(void) {
    if (g_reload_config && !g_should_exit) {
        g_reload_config = 0;
        fast_pid_cache_clear();
        ChangedPkg out_changed[128];
        config_lock_write();
        int changed_count = reload_config_rules_diff(INJECTOR_CONFIG_PATH, out_changed, 128);
        config_unlock_write();
        if (config_has_category_rules()) sys_pkg_refresh();
        setup_inotify_watches();
        config_publisher_broadcast();

        if (g_media_fuse.fuse_pid > 0 && !is_media_module_injected_target()) {
            LOG("配置变更：媒体组件不再是注入目标。正在终结专属媒体 FUSE...");
            kill(g_media_fuse.fuse_pid, SIGTERM);
            int status;
            waitpid(g_media_fuse.fuse_pid, &status, WNOHANG);
            g_media_fuse.fuse_pid = 0;
            ns_force_umount_stale(g_media_fuse.pid, g_media_fuse.mnt_path);
        } else if (g_media_fuse.fuse_pid <= 0 && !g_global_replace_mode &&
                   is_media_module_injected_target() && g_fuse_ready) {
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

static void injector_event_loop(const InjectorFds *fds) {
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
            } else if (fd == g_inotify_fd) {
                on_inotify_event();
            } else if (fd == fds->ipc_sock) {
                on_ipc_accept(fds->ipc_sock);
            } else if (fd == g_config_pub_fd) {
                config_publisher_handle_readable(fd);
            } else if (fd == g_fuse_ready_pipe_fd) {
                handle_fuse_ready_event(g_fuse_ready_ctx);
                g_fuse_ready_pipe_fd = -1;
                g_fuse_ready_ctx = nullptr;
            } else {
                on_client_fd(fd);
            }
        }
        handle_pending_reload();
    }
}

static void injector_shutdown(const InjectorFds *fds) {
    int ipc_sock = fds->ipc_sock;
    int timer_fd = fds->timer_fd;
    int sig_fd = fds->sig_fd;
    do_cleanup();
    ipc_server_cleanup(ipc_sock);
    if (timer_fd >= 0) close(timer_fd);
    if (sig_fd >= 0) close(sig_fd);
    if (g_epoll_fd >= 0) close(g_epoll_fd);
}

/* 主入口：只负责按序调用，不含具体逻辑（见上方阶段/分发函数） */
int main(int argc, char *argv[]) {
    bool start_passive = false;
    parse_cli_args(argc, argv, &start_passive);
    injector_early_init();
    InjectorFds fds = { .sig_fd = -1, .timer_fd = -1, .ipc_sock = -1 };
    injector_setup_epoll(&fds);
    injector_start_fuses(start_passive);
    injector_event_loop(&fds);
    injector_shutdown(&fds);
    return 0;
}