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

struct linux_dirent64 {
    unsigned long  d_ino;
    long           d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

volatile sig_atomic_t g_should_exit = 0;
volatile sig_atomic_t g_reload_config = 0;
volatile sig_atomic_t g_passive_mode = 0;
int g_global_root_fd = -1;
int g_epoll_fd = -1;
int g_inotify_fd = -1;

static int reload_cooldown_seconds = 0;
static int seconds_until_next_scan = 1; 
static int g_scan_interval_seconds = 30;   
static bool g_last_scan_found = false;          

struct GlobalFuseInfo g_global_fuse = {
    .pid = 1, .fuse_pid = 0, .mnt_path = "/mnt/nsp_global",
    .crash_count = 0, .last_crash_time = 0, .disabled = false
};

const char* get_active_mnt_src() {
    if (g_global_fuse.fuse_pid > 0 && kill(g_global_fuse.fuse_pid, 0) == 0)
        return g_global_fuse.mnt_path;
    return nullptr;
}

void notify_fuses(int sig) {
    if (g_global_fuse.fuse_pid > 0 && kill(g_global_fuse.fuse_pid, sig) != 0 && errno != ESRCH)
        LOG_ERR("通知全局 FUSE 失败");
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

static void inject_global_fuse() {
    if (g_global_fuse.disabled) return;
    if (g_global_fuse.fuse_pid > 0) {
        kill(g_global_fuse.fuse_pid, SIGTERM);
        usleep(50000);
    }
    ns_umount_and_rmdir(g_global_fuse.pid, g_global_fuse.mnt_path);

    int ready_pipe[2];
    if (pipe(ready_pipe) == -1) return;
    pid_t child = fork();
    if (child == -1) {
        close(ready_pipe[0]); close(ready_pipe[1]);
        return;
    }

    if (child == 0) {
        close(ready_pipe[0]);
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

        char* args[16];
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
    struct timeval tv;
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(ready_pipe[0], &readfds);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (select(ready_pipe[0] + 1, &readfds, nullptr, nullptr, &tv) > 0 && FD_ISSET(ready_pipe[0], &readfds)) {
        char buf;
        if (read(ready_pipe[0], &buf, 1) == 1) {
            ns_make_shared(g_global_fuse.pid, g_global_fuse.mnt_path);
        }
    } else {
        int status;
        pid_t ret = waitpid(child, &status, WNOHANG);
        if (ret == child) dump_crash_log_tail();
        else { kill(child, SIGKILL); waitpid(child, &status, WNOHANG); }
        g_global_fuse.fuse_pid = 0;
    }
    close(ready_pipe[0]);
}

static int cleanup_cb(int pid, const char* cmd, void* data) {
    (void)data;
    if (!is_process_safe_to_inject(cmd)) return 0;
    uid_t uid = get_app_uid(pid);
    char target_path[128];
    get_target_storage_path(uid, target_path, sizeof(target_path));
    char backup_path[PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/nsp_sys_storage");
    bool has_backup = ns_is_mounted(pid, backup_path, nullptr) > 0;
    bool has_fuse = (ns_is_mounted(pid, target_path, "fuse.fuse_daemon") > 0 || ns_is_mounted(pid, target_path, "fuse_daemon") > 0);
    if (!has_backup && !has_fuse) return 0;
    
    for (int t = 0; t < 3 && (ns_is_mounted(pid, target_path, "fuse.fuse_daemon") > 0 || ns_is_mounted(pid, target_path, "fuse_daemon") > 0); t++) {
        ns_umount_recursive(pid, target_path);
    }

    for (int t = 0; t < 3 && (ns_is_mounted(pid, backup_path, "fuse.fuse_daemon") > 0 || ns_is_mounted(pid, backup_path, "fuse_daemon") > 0); t++) {
        ns_umount_recursive(pid, backup_path);
    }

    if (ns_is_mounted(pid, backup_path, nullptr) > 0)
        ns_move_mount(pid, backup_path, target_path);
    if (ns_is_mounted(pid, target_path, nullptr) <= 0) {
        char init_src[256];
        snprintf(init_src, sizeof(init_src), "/proc/1/root%s", target_path);
        ns_bind_mount(pid, init_src, target_path);
    }
    return 0;
}

static void cleanup_all_target_apps() {
    fast_pid_each(cleanup_cb, nullptr);
}

static void check_and_recover_fuse() {
    if (g_global_fuse.disabled || g_global_fuse.pid <= 0) return;
    if (g_global_fuse.fuse_pid > 0 && kill(g_global_fuse.fuse_pid, 0) != 0) {
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
        if (g_global_fuse.fuse_pid > 0)
            cleanup_all_target_apps();
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
        char cmdline[64] = {0};
        char path[64];
        snprintf(path, sizeof(path), "/proc/%s/cmdline", de->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
            close(fd);
            if (n > 0) {
                if (strcmp(cmdline, "zygote") == 0 || strcmp(cmdline, "zygote64") == 0 || 
                    strcmp(cmdline, "usap32") == 0 || strcmp(cmdline, "usap64") == 0) {
                    g_zygote_pids[g_zygote_count++] = atoi(de->d_name);
                }
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

    ProcEntry entries[MAX_CANDIDATES];
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
            if (!isdigit(d->d_name[0])) continue;

            int pid = atoi(d->d_name);
            if (pid < 1000) continue;
            if (is_tracked(pid)) continue;

            snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
            int fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) continue;
            ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
            close(fd);
            if (n <= 0) continue;
            cmdline[n] = '\0';

            if (!is_process_safe_to_inject(cmdline)) continue;

            snprintf(path, sizeof(path), "/proc/%d/status", pid);
            fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) continue;
            n = read(fd, status_buf, sizeof(status_buf) - 1);
            close(fd);
            if (n <= 0) continue;
            status_buf[n] = '\0';

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

    #define MAX_TASKS 256
    MountTask *tasks[MAX_TASKS];
    int task_count = 0;
    const char *mnt_src = get_active_mnt_src();

    struct timespec ts_match_start, ts_match_end;
    if (first_scan) clock_gettime(CLOCK_MONOTONIC, &ts_match_start);

    if (mnt_src && entry_count > 0) {
        config_lock_read();
        for (int i = 0; i < entry_count && task_count < MAX_TASKS; i++) {
            if (is_target_app_locked(entries[i].cmdline, entries[i].uid, entries[i].pid, false)) {
                MountTask *task = malloc(sizeof(MountTask));
                if (task) {
                    strncpy(task->cmdline, entries[i].cmdline, sizeof(task->cmdline) - 1);
                    task->pid = entries[i].pid;
                    task->uid = entries[i].uid;
                    task->mnt_src = mnt_src;
                    tasks[task_count++] = task;
                }
            }
        }
        config_unlock_read();
    }

    if (first_scan) {
        clock_gettime(CLOCK_MONOTONIC, &ts_match_end);
        long elapsed = (ts_match_end.tv_sec - ts_match_start.tv_sec) * 1000 +
                       (ts_match_end.tv_nsec - ts_match_start.tv_nsec) / 1000000;
        LOG("初次扫描 - 配置匹配完成, %d候选/%d配置, 耗时: %ldms", entry_count, g_app_cfg_count, elapsed);
    }

    if (task_count > 0) {
        for (int i = 0; i < task_count; i++) {
            struct timespec ts_mnt;
            if (first_scan) clock_gettime(CLOCK_MONOTONIC, &ts_mnt);
            perform_app_mount(tasks[i]->cmdline, tasks[i]->pid, tasks[i]->uid, tasks[i]->mnt_src, "主动扫描");
            if (first_scan) {
                struct timespec ts_mnt_end;
                clock_gettime(CLOCK_MONOTONIC, &ts_mnt_end);
                long el = (ts_mnt_end.tv_sec - ts_mnt.tv_sec) * 1000 +
                          (ts_mnt_end.tv_nsec - ts_mnt.tv_nsec) / 1000000;
                LOG("初次扫描 - 挂载 %s(PID:%d) 完成, 耗时: %ldms", tasks[i]->cmdline, tasks[i]->pid, el);
            }
            free(tasks[i]);
        }
    }

    if (first_scan) {
        struct timespec ts_end;
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        long elapsed = (ts_end.tv_sec - ts_start.tv_sec) * 1000 +
                       (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000;
        LOG("初次扫描完成 - 共发现 %d 个应用, 总耗时: %ldms", task_count, elapsed);
        first_scan = false;
    }

    return task_count;
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
        ns_umount_and_rmdir(g_global_fuse.pid, g_global_fuse.mnt_path);
    }
    unlink(CONFIG_DIR "/uid.map");
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
    int dev_null = open("/dev/null", O_RDWR);
    dup2(dev_null, 0);
    dup2(dev_null, 1);
    dup2(dev_null, 2);

    log_init("injector");
    config_init_lock();
    fast_pid_init();

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

    strcpy(g_real_root, STORAGE_BASE);
    mkdir_recursive(BACKUP_DIR);
    reload_injector_config();
    unlink(CONFIG_DIR "/uid.map");

    int wait_count = 0;
    while (faccessat(g_global_root_fd, "data/media/0", F_OK, 0) != 0 && wait_count < 120 && !g_should_exit) {
        usleep(500000);
        wait_count++;
    }

    inject_global_fuse();
    if (g_global_fuse.fuse_pid <= 0) exit(1);

    if (start_passive) {
        g_passive_mode = 1;
        LOG("被动监听模式启动");
    } else {
        int found = scan_zygote_children();
        if (found > 0) {
            g_last_scan_found = true;
            g_scan_interval_seconds = 30;
        } else {
            g_last_scan_found = false;
            g_scan_interval_seconds = 60;   
        }
    }
    seconds_until_next_scan = g_scan_interval_seconds;

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
                            notify_fuses(SIGHUP);
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
            } else {
                epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
                handle_ipc_client_readable(fd);
            }
        }

        if (g_reload_config && !g_should_exit) {
            g_reload_config = 0;
            fast_pid_cache_clear();
            
            ChangedPkg changed_pkgs[128];
            config_lock_write();
            int changed_count = reload_config_rules_diff(INJECTOR_CONFIG_PATH, changed_pkgs, 128);
            config_unlock_write();
            
            setup_inotify_watches();
            
            if (changed_count == -1) {
                LOG("全局规则变动或重置，执行全盘审查...");
                audit_tracked_apps();
                if (!g_passive_mode) {
                    scan_zygote_children();
                }
            } else if (changed_count > 0) {
                LOG("局部规则分析：检测到 %d 个应用的规则更新，基于 PID 缓存执行增量更新...", changed_count);
                audit_and_remount_specific_apps(changed_pkgs, changed_count);
            } else {
                LOG_DBG("规则未有实质内容变化，跳过增量审查。");
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