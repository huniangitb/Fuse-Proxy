#define _GNU_SOURCE
#include "inject_target.h"
#include "injector.h"
#include "common.h"
#include "config_parser.h"
#include "ns_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
static pid_t g_zygote_pid = 0;
static int g_tracked_pids[4096];
static int g_tracked_count = 0;
static pthread_mutex_t g_track_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct { uid_t uid; char pkg[128]; } UidMap;
static UidMap g_uid_map[1024];
static int g_uid_map_count = 0;

int is_isolated_uid(uid_t uid) {
    uid_t app_id = uid % 100000;
    return (app_id >= 90000 && app_id <= 99999);
}

int is_process_safe_to_inject(const char* cmdline) {
    if (strchr(cmdline, ':')) return 0;
    if (strstr(cmdline, "_zygote")) return 0;
    if (strstr(cmdline, "com.android.providers.media")) return 0;
    if (strstr(cmdline, "android.process.media")) return 0;
    if (strstr(cmdline, "com.google.android.webview")) return 0;
    if (strstr(cmdline, "com.android.webview")) return 0;
    if (strstr(cmdline, "injector")) return 0;
    if (strstr(cmdline, "fuse_daemon")) return 0;
    return 1;
}

static pid_t find_zygote_pid(void) {
    DIR* dir = opendir("/proc");
    if (!dir) return 0;
    struct dirent* de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_type != DT_DIR) continue;
        if (!(de->d_name[0] >= '0' && de->d_name[0] <= '9')) continue;
        char cmdline[32] = {0}; char path[64]; snprintf(path, sizeof(path), "/proc/%s/cmdline", de->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC); if (fd < 0) continue;
        ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1); close(fd);
        if (n > 0 && (strcmp(cmdline, "zygote") == 0 || strcmp(cmdline, "zygote64") == 0)) {
            pid_t pid = atoi(de->d_name); closedir(dir); return pid;
        }
    }
    closedir(dir); return 0;
}

static int is_zygote_child(pid_t pid) {
    if (g_zygote_pid <= 0 || kill(g_zygote_pid, 0) != 0) g_zygote_pid = find_zygote_pid();
    if (g_zygote_pid <= 0) return 0;
    char path[64]; snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC); if (fd < 0) return 0;
    char buf[512] = {0}; ssize_t n = read(fd, buf, sizeof(buf) - 1); close(fd); if (n <= 0) return 0;
    char* close_paren = strrchr(buf, ')'); if (!close_paren) return 0;
    char* p = close_paren + 2; if (*p) p++; if (*p) p++; int ppid = atoi(p); return ppid == g_zygote_pid;
}

static int is_user_app(const char* cmdline, uid_t uid, pid_t pid) {
    char pkg[256]; strncpy(pkg, cmdline, sizeof(pkg) - 1); pkg[sizeof(pkg) - 1] = '\0'; char* colon = strchr(pkg, ':'); if (colon) *colon = '\0';
    uid_t app_id = uid % 100000; if (app_id < 10000 || app_id >= 90000) return 0; if (!strchr(pkg, '.')) return 0; 
    if (!is_zygote_child(pid)) return 0;
    if (strncmp(pkg, "com.android.", 11) == 0 || strncmp(pkg, "com.google.android.", 19) == 0 || strncmp(pkg, "android.", 8) == 0) return 0;
    static const char* sys_volumes[] = {"/system", "/product", "/vendor", "/system_ext"};
    static const char* sys_subdirs[] = {"app", "priv-app"};
    for (int v = 0; v < 4; v++) for (int s = 0; s < 2; s++) { char path[512]; snprintf(path, sizeof(path), "%s/%s/%s", sys_volumes[v], sys_subdirs[s], pkg); if (access(path, F_OK) == 0) return 0; }
    return 1;
}

int is_target_app(const char* cmdline, uid_t uid, pid_t pid, int from_ipc) {
    (void)from_ipc;
    char base_pkg[256]; strncpy(base_pkg, cmdline, sizeof(base_pkg) - 1); base_pkg[sizeof(base_pkg) - 1] = '\0'; char* colon = strchr(base_pkg, ':'); if (colon) *colon = '\0';
    int is_target = 0; int user_id = uid / 100000; config_lock_read(); int found_exact = 0;
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i]->user_id == user_id && (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 || fnmatch(g_app_cfgs[i]->pkg_name, cmdline, 0) == 0)) { is_target = g_app_cfgs[i]->inject_enable; found_exact = 1; break; }
    }
    if (!found_exact) {
        for (int i = 0; i < g_app_cfg_count; i++) {
            if (g_app_cfgs[i]->user_id == -1 && (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 || fnmatch(g_app_cfgs[i]->pkg_name, cmdline, 0) == 0)) { is_target = g_app_cfgs[i]->inject_enable; found_exact = 1; break; }
        }
    }
    if (!found_exact && uid >= 10000) {
        for (int i = 0; i < g_app_cfg_count; i++) { if (g_app_cfgs[i]->user_id == user_id && strcmp(g_app_cfgs[i]->pkg_name, "*") == 0 && g_app_cfgs[i]->inject_enable) { is_target = 1; break; } }
        if (!is_target) { for (int i = 0; i < g_app_cfg_count; i++) { if (g_app_cfgs[i]->user_id == -1 && strcmp(g_app_cfgs[i]->pkg_name, "*") == 0 && g_app_cfgs[i]->inject_enable) { is_target = 1; break; } } }
        if (!is_target && g_global_cfg.global_inject && is_process_safe_to_inject(cmdline) && is_user_app(cmdline, uid, pid)) is_target = 1;
    }
    config_unlock_read(); return is_target;
}

uid_t get_app_uid(int pid) { struct stat st; char path[64]; snprintf(path, 63, "/proc/%d", pid); return (stat(path, &st) == 0) ? st.st_uid : 0; }
void get_target_storage_path(uid_t uid, char* path, size_t size) { (void)uid; snprintf(path, size, "%s", "/storage/emulated"); }

void update_uid_map(uid_t uid, const char* pkg) {
    if (uid < 10000 || is_isolated_uid(uid)) return;
    pthread_mutex_lock(&g_track_mutex); int found = 0;
    for(int i=0; i<g_uid_map_count; i++) { if(g_uid_map[i].uid == uid) { found = 1; break; } }
    if (!found && g_uid_map_count < 1024) {
        g_uid_map[g_uid_map_count].uid = uid; strncpy(g_uid_map[g_uid_map_count].pkg, pkg, 127); g_uid_map_count++;
        FILE* fp = fopen(CONFIG_DIR "/uid.map", "w");
        if (fp) { for(int i=0; i<g_uid_map_count; i++) fprintf(fp, "%d %s\n", g_uid_map[i].uid, g_uid_map[i].pkg); fclose(fp); LOG("UID映射已更新: %u -> %s", uid, pkg); }
        notify_fuses(SIGHUP);
    }
    pthread_mutex_unlock(&g_track_mutex);
}

void add_tracked(int pid) {
    pthread_mutex_lock(&g_track_mutex);
    for(int i=0; i<g_tracked_count; i++) { if(g_tracked_pids[i] == pid) { pthread_mutex_unlock(&g_track_mutex); return; } }
    if (g_tracked_count < 4096) g_tracked_pids[g_tracked_count++] = pid;
    pthread_mutex_unlock(&g_track_mutex);
}

int is_tracked(int pid) {
    pthread_mutex_lock(&g_track_mutex);
    for (int i = 0; i < g_tracked_count; i++) { if (g_tracked_pids[i] == pid) { pthread_mutex_unlock(&g_track_mutex); return 1; } }
    pthread_mutex_unlock(&g_track_mutex); return 0;
}

void force_recover_tracked_mounts(void) {
    pthread_mutex_lock(&g_track_mutex);
    for(int i=0; i<g_tracked_count; i++) {
        int pid = g_tracked_pids[i];
        if (kill(pid, 0) == 0) {
            uid_t uid = get_app_uid(pid); char target_path[128]; get_target_storage_path(uid, target_path, sizeof(target_path));
            char backup_path[PATH_MAX]; snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/nsp_sys_storage");
            while (ns_is_mounted(pid, target_path, "fuse_daemon") > 0) ns_umount_recursive(pid, target_path);
            if (ns_is_mounted(pid, backup_path, NULL) > 0) ns_move_mount(pid, backup_path, target_path);
            if (ns_is_mounted(pid, target_path, NULL) > 0) continue;
            char init_src[256]; snprintf(init_src, sizeof(init_src), "/proc/1/root%s", target_path);
            if (ns_bind_mount(pid, init_src, target_path) != 0) LOG_ERR("force_recover: PID %d bind 恢复失败", pid);
        }
    }
    g_tracked_count = 0;
    pthread_mutex_unlock(&g_track_mutex);
}

void audit_tracked_apps(void) {
    pthread_mutex_lock(&g_track_mutex); int new_count = 0;
    for (int i = 0; i < g_tracked_count; i++) {
        int pid = g_tracked_pids[i]; char cmd[256] = {0}; char path[64]; snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        int fd = open(path, O_RDONLY | O_CLOEXEC); if (fd >= 0) { read(fd, cmd, sizeof(cmd) - 1); close(fd); }
        if (cmd[0] == '\0') continue;
        uid_t uid = get_app_uid(pid); int is_target = is_target_app(cmd, uid, pid, 0);
        if (!is_target) {
            char target_path[128]; get_target_storage_path(uid, target_path, sizeof(target_path));
            char backup_path[PATH_MAX]; snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/nsp_sys_storage");
            while (ns_is_mounted(pid, target_path, "fuse_daemon") > 0) ns_umount_recursive(pid, target_path);
            if (ns_is_mounted(pid, backup_path, NULL) > 0) ns_move_mount(pid, backup_path, target_path);
            if (ns_is_mounted(pid, target_path, NULL) <= 0) {
                char init_src[256]; snprintf(init_src, sizeof(init_src), "/proc/1/root%s", target_path);
                ns_bind_mount(pid, init_src, target_path);
            }
            LOG("配置审查: %s (PID: %d) 挂载已还原。", cmd, pid);
        } else g_tracked_pids[new_count++] = pid;
    }
    g_tracked_count = new_count; pthread_mutex_unlock(&g_track_mutex);
}

void handle_list_injected(int client_fd) {
    char reply[4096]; int offset = 0; int total = 0;
    pthread_mutex_lock(&g_track_mutex);
    for (int i = 0; i < g_tracked_count; i++) {
        int pid = g_tracked_pids[i]; if (kill(pid, 0) != 0) continue;
        char cmdline[256] = {0}; char proc_path[64]; snprintf(proc_path, sizeof(proc_path), "/proc/%d/cmdline", pid);
        int fd = open(proc_path, O_RDONLY | O_CLOEXEC); if (fd < 0) continue; ssize_t rlen = read(fd, cmdline, sizeof(cmdline) - 1); close(fd);
        if (rlen <= 0 || cmdline[0] == '\0') continue;
        uid_t uid = get_app_uid(pid); char base_pkg[256]; strncpy(base_pkg, cmdline, sizeof(base_pkg) - 1); char* colon = strchr(base_pkg, ':'); if (colon) *colon = '\0';
        int app_redir = 0, app_hide = 0, app_ro = 0; config_lock_read(); int user_id = uid / 100000; AppConfig* cfg = NULL;
        for (int j = 0; j < g_app_cfg_count; j++) { if (g_app_cfgs[j]->user_id == user_id && (fnmatch(g_app_cfgs[j]->pkg_name, base_pkg, 0) == 0 || fnmatch(g_app_cfgs[j]->pkg_name, cmdline, 0) == 0)) { cfg = g_app_cfgs[j]; break; } }
        if (!cfg) { for (int j = 0; j < g_app_cfg_count; j++) { if (g_app_cfgs[j]->user_id == -1 && (fnmatch(g_app_cfgs[j]->pkg_name, base_pkg, 0) == 0 || fnmatch(g_app_cfgs[j]->pkg_name, cmdline, 0) == 0)) { cfg = g_app_cfgs[j]; break; } } }
        if (cfg) { app_redir = cfg->redir_count; app_hide = cfg->hide_count; app_ro = cfg->ro_count; }
        int total_redir = app_redir + g_global_cfg.redir_count, total_hide = app_hide + g_global_cfg.hide_count, total_ro = app_ro + g_global_cfg.ro_count;
        config_unlock_read();
        int n = snprintf(reply + offset, sizeof(reply) - offset, "APP|%s|%d|%u|%d|%d|%d\n", base_pkg, pid, uid, total_redir, total_hide, total_ro);
        if (n > 0 && offset + n < (int)sizeof(reply)) offset += n; total++;
    }
    pthread_mutex_unlock(&g_track_mutex);
    snprintf(reply + offset, sizeof(reply) - offset, "DONE|%d\n", total);
    send(client_fd, reply, strlen(reply), MSG_NOSIGNAL);
}