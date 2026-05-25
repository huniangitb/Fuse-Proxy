#define _GNU_SOURCE
#include "injector.h"
#include "common.h"
#include "config_parser.h"
#include "ns_utils.h"
#include "fast_pid.h"
#include "inject_target.h"
#include "mount_manager.h"
#include "ipc_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/resource.h>

volatile sig_atomic_t g_should_exit = 0;
volatile sig_atomic_t g_reload_config = 0; 
volatile sig_atomic_t g_passive_mode = 0;
int g_global_root_fd = -1;
int g_inotify_fd = -1;

struct GlobalFuseInfo g_global_fuse = { .pid = 1, .fuse_pid = 0, .mnt_path = "/mnt/nsp_global", .crash_count = 0, .last_crash_time = 0, .disabled = 0 };

const char* get_active_mnt_src(void) {
    if (g_global_fuse.fuse_pid > 0 && kill(g_global_fuse.fuse_pid, 0) == 0) return g_global_fuse.mnt_path;
    return NULL;
}

void notify_fuses(int sig) {
    if (g_global_fuse.fuse_pid > 0 && kill(g_global_fuse.fuse_pid, sig) != 0 && errno != ESRCH) LOG_ERR("通知全局 FUSE 失败");
}

static void setup_inotify_watches(void) {
    config_lock_read();
    for (int i = 0; i < g_active_user_count; i++) {
        char dir_path[128];
        if (g_active_users[i] == 0) snprintf(dir_path, sizeof(dir_path), "%s/App-rules", CONFIG_DIR); else snprintf(dir_path, sizeof(dir_path), "%s/App-rules-%d", CONFIG_DIR, g_active_users[i]);
        mkdir(dir_path, 0755); inotify_add_watch(g_inotify_fd, dir_path, IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_TO | IN_DELETE);
    }
    config_unlock_read();
}

static void reload_injector_config(void) {
    config_lock_write(); load_config_rules(INJECTOR_CONFIG_PATH); config_unlock_write();
    setup_inotify_watches();
}

static void* config_watcher_thread(void* arg) {
    (void)arg; char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event)))); ssize_t len;
    while (!g_should_exit) {
        len = read(g_inotify_fd, buf, sizeof(buf)); if (len <= 0) { if (errno == EINTR) continue; sleep(1); continue; }
        usleep(500000); int need_reload = 0;
        for (char *ptr = buf; ptr < buf + len; ) { 
            struct inotify_event *ev = (struct inotify_event *) ptr; 
            if (ev->len && (strcmp(ev->name, "injector.conf") == 0 || strstr(ev->name, ".conf"))) need_reload = 1; 
            ptr += sizeof(struct inotify_event) + ev->len; 
        }
        if (need_reload) { g_reload_config = 1; notify_fuses(SIGHUP); }
    } 
    return NULL;
}

static void dump_crash_log_tail(void) {
    char path[PATH_MAX]; snprintf(path, sizeof(path), "%s/fuse_crash.log", LOG_DIR);
    int fd = open(path, O_RDONLY | O_CLOEXEC); if (fd < 0) return;
    char buf[16384]; off_t end = lseek(fd, 0, SEEK_END); off_t start = (end > (off_t)sizeof(buf)) ? end - (off_t)sizeof(buf) : 0;
    lseek(fd, start, SEEK_SET); ssize_t n = read(fd, buf, sizeof(buf) - 1); close(fd);
    if (n > 0) {
        buf[n] = '\0'; char *p = buf; if (start > 0) { p = memchr(buf, '\n', n); if (p) p++; else p = buf; }
        if (*p) { LOG_ERR("===== FUSE 崩溃诊断信息 ====="); char *line = p; while (line && *line) { char *nl = strchr(line, '\n'); if (nl) *nl = '\0'; if (*line) LOG_ERR("| %s", line); if (nl) line = nl + 1; else break; } LOG_ERR("===== 诊断结束 ====="); }
    }
}

static void inject_global_fuse(void) {
    if (g_global_fuse.disabled) return;
    if (g_global_fuse.fuse_pid > 0) { kill(g_global_fuse.fuse_pid, SIGTERM); usleep(50000); }
    ns_umount_and_rmdir(g_global_fuse.pid, g_global_fuse.mnt_path);
    int ready_pipe[2]; if (pipe(ready_pipe) == -1) return;
    pid_t child = fork(); if (child == -1) { close(ready_pipe[0]); close(ready_pipe[1]); return; }
    
    if (child == 0) {
        close(ready_pipe[0]);
        char ns_path[64]; snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", g_global_fuse.pid);
        int fd = open(ns_path, O_RDONLY | O_CLOEXEC); if (fd < 0) _exit(10);
        if (setns(fd, CLONE_NEWNS) != 0) { close(fd); _exit(11); } close(fd);
        if (mkdir(g_global_fuse.mnt_path, 0755) != 0 && errno != EEXIST) _exit(12);
        
        int log_fd = open(LOG_DIR "/fuse_crash.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
        if (log_fd >= 0) { dup2(log_fd, STDERR_FILENO); dup2(log_fd, STDOUT_FILENO); close(log_fd); }
        
        char exe[256]; snprintf(exe, sizeof(exe), "%s/fuse_daemon", get_self_dir());
        char arg_ready[64]; snprintf(arg_ready, sizeof(arg_ready), "--ready-fd=%d", ready_pipe[1]); fcntl(ready_pipe[1], F_SETFD, 0);
        char arg_global[64]; if (g_global_root_fd >= 0) { fcntl(g_global_root_fd, F_SETFD, 0); snprintf(arg_global, sizeof(arg_global), "--global-root-fd=%d", g_global_root_fd); } else strcpy(arg_global, "--global-root-fd=-1");
        const char* log_lvl = "info"; if (g_min_log_level == LOG_DEBUG) log_lvl = "debug"; else if (g_min_log_level == LOG_ERROR) log_lvl = "error";

        char* args[16]; int ai = 0; args[ai++] = "fuse_daemon"; args[ai++] = g_global_fuse.mnt_path; args[ai++] = "--mode=redirect"; args[ai++] = "--root=" STORAGE_BASE; args[ai++] = "--rules=" INJECTOR_CONFIG_PATH; //args[ai++] = "--preserve-perms";
        if (g_strip_o_direct) args[ai++] = "--strip-o-direct";
        args[ai++] = arg_ready; args[ai++] = arg_global; args[ai++] = (char*)log_lvl; args[ai++] = "-f"; args[ai++] = "-o"; args[ai++] = "allow_other,auto_cache"; args[ai] = NULL;
        setenv("LD_LIBRARY_PATH", get_self_dir(), 1); execv(exe, args); _exit(13);
    }
    
    close(ready_pipe[1]); g_global_fuse.fuse_pid = child;
    struct timeval tv; fd_set readfds; FD_ZERO(&readfds); FD_SET(ready_pipe[0], &readfds); tv.tv_sec = 5; tv.tv_usec = 0;
    if (select(ready_pipe[0] + 1, &readfds, NULL, NULL, &tv) > 0 && FD_ISSET(ready_pipe[0], &readfds)) {
        char buf; if (read(ready_pipe[0], &buf, 1) == 1) ns_make_shared(g_global_fuse.pid, g_global_fuse.mnt_path);
    } else {
        int status; pid_t ret = waitpid(child, &status, WNOHANG);
        if (ret == child) dump_crash_log_tail(); else { kill(child, SIGKILL); waitpid(child, &status, WNOHANG); }
        g_global_fuse.fuse_pid = 0;
    }
    close(ready_pipe[0]);
}

static int cleanup_cb(int pid, const char* cmd, void* data) {
    (void)data; if (!is_process_safe_to_inject(cmd)) return 0;
    uid_t uid = get_app_uid(pid); char target_path[128]; get_target_storage_path(uid, target_path, sizeof(target_path));
    char backup_path[PATH_MAX]; snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/nsp_sys_storage");
    int has_backup = ns_is_mounted(pid, backup_path, NULL) > 0, has_fuse = ns_is_mounted(pid, target_path, "fuse_daemon") > 0;
    if (!has_backup && !has_fuse) return 0;
    while (ns_is_mounted(pid, target_path, "fuse_daemon") > 0) ns_umount_recursive(pid, target_path);
    if (ns_is_mounted(pid, backup_path, NULL) > 0) ns_move_mount(pid, backup_path, target_path);
    if (ns_is_mounted(pid, target_path, NULL) <= 0) { char init_src[256]; snprintf(init_src, sizeof(init_src), "/proc/1/root%s", target_path); ns_bind_mount(pid, init_src, target_path); }
    return 0;
}

static void cleanup_all_target_apps(void) {
    pthread_mutex_lock(&(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER); /* hack clear count via track API */ 
    pthread_mutex_unlock(&(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER);
    fast_pid_each(cleanup_cb, NULL);
}

static void check_and_recover_fuse(void) {
    if (g_global_fuse.disabled || g_global_fuse.pid <= 0) return;
    if (g_global_fuse.fuse_pid > 0 && kill(g_global_fuse.fuse_pid, 0) != 0) {
        int status = 0; if (waitpid(g_global_fuse.fuse_pid, &status, WNOHANG) == g_global_fuse.fuse_pid) dump_crash_log_tail();
        g_global_fuse.fuse_pid = 0;
        time_t now = time(NULL); if (now - g_global_fuse.last_crash_time < 60) g_global_fuse.crash_count++; else g_global_fuse.crash_count = 1; g_global_fuse.last_crash_time = now;
        if (g_global_fuse.crash_count > 5) { g_global_fuse.disabled = 1; return; }
        force_recover_tracked_mounts(); inject_global_fuse();
        if (g_global_fuse.fuse_pid > 0) cleanup_all_target_apps();
    }
}

static int scan_cb(int pid, const char* cmd, void* data) {
    (void)data; if (pid == g_global_fuse.pid || pid == g_global_fuse.fuse_pid) return 0; 
    if (strstr(cmd, "zygote") != NULL || strstr(cmd, "<pre-") != NULL) return 2;
    if (!is_process_safe_to_inject(cmd)) return 0;
    uid_t uid = get_app_uid(pid); if (is_isolated_uid(uid)) return 0;
    if (!is_target_app(cmd, uid, pid, 0)) return 0;
    if (is_tracked(pid)) return 0;
    const char* mnt_src = get_active_mnt_src(); if (!mnt_src) return 2; 
    int ret = perform_app_mount(cmd, pid, uid, mnt_src, "主动扫描");
    return ret == 0 ? 0 : 2;
}

static void reap_zombies(void) { int status; while (waitpid(-1, &status, WNOHANG) > 0); }
static void do_cleanup(void) {
    g_should_exit = 1; force_recover_tracked_mounts();
    if (g_global_fuse.fuse_pid > 0) { kill(g_global_fuse.fuse_pid, SIGTERM); ns_umount_and_rmdir(g_global_fuse.pid, g_global_fuse.mnt_path); }
    unlink(CONFIG_DIR "/uid.map"); log_close(); config_destroy_lock(); fast_pid_cleanup();
}

static void handle_signal(int sig) { if (sig == SIGINT || sig == SIGTERM) g_should_exit = 1; else if (sig == SIGHUP) g_reload_config = 1; }

int main(int argc, char *argv[]) {
    escape_cgroup();
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) g_min_log_level = LOG_DEBUG; else if (strcmp(argv[i], "error") == 0) g_min_log_level = LOG_ERROR; else if (strcmp(argv[i], "info") == 0) g_min_log_level = LOG_INFO; else if (strcmp(argv[i], "--strip-o-direct") == 0) g_strip_o_direct = 1;
    }
    signal(SIGPIPE, SIG_IGN); g_global_root_fd = open("/", O_RDONLY | O_PATH | O_CLOEXEC); escape_cgroup();
    pid_t pid = fork(); if (pid < 0) exit(1); if (pid > 0) exit(0);
    setsid(); pid = fork(); if (pid < 0) exit(1); if (pid > 0) exit(0);
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) { if (x != g_global_root_fd) close(x); }
    int dev_null = open("/dev/null", O_RDWR); dup2(dev_null, 0); dup2(dev_null, 1); dup2(dev_null, 2);
    log_init("injector"); config_init_lock(); fast_pid_init();
    g_inotify_fd = inotify_init(); if (g_inotify_fd >= 0) inotify_add_watch(g_inotify_fd, CONFIG_DIR, IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_TO | IN_DELETE);
    strcpy(g_real_root, STORAGE_BASE); reload_injector_config(); unlink(CONFIG_DIR "/uid.map");
    pthread_t w_tid, ipc_tid; pthread_create(&w_tid, NULL, config_watcher_thread, NULL); pthread_create(&ipc_tid, NULL, ipc_server_thread, NULL);
    int wait_count = 0; while (faccessat(g_global_root_fd, "data/media/0", F_OK, 0) != 0 && wait_count < 120) { usleep(500000); wait_count++; }
    inject_global_fuse(); if (g_global_fuse.fuse_pid <= 0) exit(1);
    cleanup_all_target_apps();
    signal(SIGINT, handle_signal); signal(SIGTERM, handle_signal); signal(SIGHUP, handle_signal);
    while (!g_should_exit) {
        check_and_recover_fuse(); reap_zombies();
        int do_scan = !g_passive_mode;
        if (g_reload_config) { 
            g_reload_config = 0; 
            fast_pid_cache_clear(); 
            reload_injector_config(); 
            audit_tracked_apps(); 
            do_scan = 1; // 配置重载时强制扫描一次，以应用新规则
        } 
        if (do_scan) {
            fast_pid_each(scan_cb, NULL);
        }
        for (int i = 0; i < 50 && !g_should_exit && !g_reload_config; i++) usleep(100000);
    }
    do_cleanup(); return 0;
}