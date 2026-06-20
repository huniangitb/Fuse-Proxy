`c
#define _GNU_SOURCE
#include "inject_target.h"
#include "injector.h"
#include "common.h"
#include "config_parser.h"
#include "ns_utils.h"
#include "mount_manager.h"
#include "uid_map.h"
#include "fast_pid.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/socket.h>
#define TRACKED_HASH_SIZE 2048
typedef struct TrackedEntry {
    int pid;
    struct TrackedEntry *next;
} TrackedEntry;
static TrackedEntry *g_tracked_hash[TRACKED_HASH_SIZE];
static unsigned int hash_pid(int pid) {
    return (unsigned int)pid % TRACKED_HASH_SIZE;
}
void add_tracked(int pid) {
    unsigned int h = hash_pid(pid);
    TrackedEntry *e = g_tracked_hash[h];
    while (e) {
        if (e->pid == pid) {
            return;
        }
        e = e->next;
    }
    e = malloc(sizeof(TrackedEntry));
    if (e) {
        e->pid = pid;
        e->next = g_tracked_hash[h];
        g_tracked_hash[h] = e;
    }
}
bool is_tracked(int pid) {
    unsigned int h = hash_pid(pid);
    TrackedEntry *e = g_tracked_hash[h];
    while (e) {
        if (e->pid == pid) {
            return true;
        }
        e = e->next;
    }
    return false;
}
void remove_tracked(int pid) {
    unsigned int h = hash_pid(pid);
    TrackedEntry **pp = &g_tracked_hash[h];
    while (*pp) {
        if ((*pp)->pid == pid) {
            TrackedEntry *tmp = *pp;
            *pp = (*pp)->next;
            free(tmp);
            break;
        }
        pp = &(*pp)->next;
    }
}
static void prune_stale_tracked() {
    for (int i = 0; i < TRACKED_HASH_SIZE; i++) {
        TrackedEntry **pp = &g_tracked_hash[i];
        while (*pp) {
            if (kill((*pp)->pid, 0) != 0) {
                TrackedEntry *tmp = *pp;
                *pp = (*pp)->next;
                free(tmp);
            } else {
                pp = &(*pp)->next;
            }
        }
    }
}
static UidMapEntry g_uid_map[UID_MAP_MAX_ENTRIES];
static int g_uid_map_count = 0;
void init_uid_map_cache(void) {
    g_uid_map_count = uid_map_load(g_uid_map, UID_MAP_MAX_ENTRIES);
    LOG_DBG("UID映射内存缓存已初始化: 从文件载入 %d 条映射记录", g_uid_map_count);
}
bool is_isolated_uid(uid_t uid) {
    uid_t app_id = uid % 100000;
    return (app_id >= 90000 && app_id <= 99999);
}
bool is_process_safe_to_inject(const char* cmdline) {
    if (strstr(cmdline, "_zygote")) return false;
    if (strstr(cmdline, "com.android.providers.media")) return false;
    if (strstr(cmdline, "android.process.media")) return false;
    if (strstr(cmdline, "com.google.android.webview")) return false;
    if (strstr(cmdline, "com.android.webview")) return false;
    if (strstr(cmdline, "injector")) return false;
    if (strstr(cmdline, "fuse_daemon")) return false;
    return true;
}
static bool is_zygote_child(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[512] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return false;
    char* close_paren = strrchr(buf, ')');
    if (!close_paren) return false;
    char* p = close_paren + 2;
    if (*p) p++;
    if (*p) p++;
    int ppid = atoi(p);
    if (ppid <= 1) return false;
    char pcmd[64] = {0};
    if (!proc_get_cmdline(ppid, pcmd, sizeof(pcmd))) return false;
    if (strcmp(pcmd, "zygote") == 0 || strcmp(pcmd, "zygote64") == 0 || strstr(pcmd, "zygote") != nullptr || strstr(pcmd, "usap") != nullptr)
        return true;
    return false;
}
bool is_target_app_locked(const char* cmdline, uid_t uid, pid_t pid, bool from_ipc) {
    int user_id = uid / 100000;
    AppConfig* cfg = find_app_cfg_locked(cmdline, user_id);
    if (cfg) return cfg->inject_enable;
    if (has_wildcard_enabled_locked(user_id)) return true;
    if (g_global_cfg.global_inject && !is_isolated_uid(uid) && !strstr(cmdline, "zygote")) {
        if (from_ipc || is_zygote_child(pid)) return true;
    }
    return false;
}
bool is_target_app(const char* cmdline, uid_t uid, pid_t pid, bool from_ipc) {
    config_lock_read();
    bool result = is_target_app_locked(cmdline, uid, pid, from_ipc);
    config_unlock_read();
    return result;
}
uid_t get_app_uid(int pid) {
    struct stat st;
    char path[64];
    snprintf(path, 63, "/proc/%d", pid);
    return (stat(path, &st) == 0) ? st.st_uid : 0;
}
void get_target_storage_path(uid_t uid, char* path, size_t size) {
    (void)uid;
    snprintf(path, size, "%s", "/storage/emulated");
}
void update_uid_map(uid_t uid, const char* pkg) {
    if (uid < 10000 || is_isolated_uid(uid)) return;
    char clean_pkg[128];
    strncpy(clean_pkg, pkg, sizeof(clean_pkg) - 1);
    clean_pkg[sizeof(clean_pkg) - 1] = '\0';
    char* colon = strchr(clean_pkg, ':');
    if (colon) *colon = '\0';
    /* 1. 优先检索内存缓存，如果记录已经吻合，则直接忽略，杜绝磁盘 I/O 穿透 */
    for (int i = 0; i < g_uid_map_count; i++) {
        if (g_uid_map[i].uid == uid) {
            if (strcmp(g_uid_map[i].pkg, clean_pkg) == 0) {
                return; // 缓存完全匹配，无摩擦退出
            }
            break;
        }
    }
    /* 2. 只有在数据发生变更或属于全新映射时，才穿透执行物理磁盘落盘 */
    if (uid_map_upsert(uid, clean_pkg) != 0) {
        LOG_ERR("uid_map_upsert 失败: %u -> %s", uid, clean_pkg);
        return;
    }
    /* 3. 同步更新内存缓存 */
    bool updated = false;
    for (int i = 0; i < g_uid_map_count; i++) {
        if (g_uid_map[i].uid == uid) {
            strncpy(g_uid_map[i].pkg, clean_pkg, 127);
            g_uid_map[i].pkg[127] = '\0';
            updated = true;
            LOG_DBG("UID内存映射已更新 (覆盖旧记录): %u -> %s", uid, clean_pkg);
            break;
        }
    }
    if (!updated && g_uid_map_count < UID_MAP_MAX_ENTRIES) {
        g_uid_map[g_uid_map_count].uid = uid;
        strncpy(g_uid_map[g_uid_map_count].pkg, clean_pkg, 127);
        g_uid_map[g_uid_map_count].pkg[127] = '\0';
        g_uid_map_count++;
        LOG_DBG("UID内存映射已更新 (新增记录): %u -> %s", uid, clean_pkg);
    }
    notify_fuses(SIGHUP);
}
void cleanup_app_mounts(int pid, const char* target_path, const char* backup_path) {
    /* 卸载 FUSE 挂载 */
    for (int t = 0; t < 3 && (ns_is_mounted(pid, target_path, "fuse.fuse_daemon") > 0 || ns_is_mounted(pid, target_path, "fuse_daemon") > 0); t++) {
        ns_umount_recursive(pid, target_path);
    }
    for (int t = 0; t < 3 && (ns_is_mounted(pid, backup_path, "fuse.fuse_daemon") > 0 || ns_is_mounted(pid, backup_path, "fuse_daemon") > 0); t++) {
        ns_umount_recursive(pid, backup_path);
    }
    /* 从备份恢复或从 init 命名空间重建 */
    if (ns_is_mounted(pid, backup_path, nullptr) > 0) {
        ns_bind_mount(pid, backup_path, target_path);
        ns_umount_recursive(pid, backup_path);
    }
    if (ns_is_mounted(pid, target_path, nullptr) <= 0) {
        char init_src[256];
        snprintf(init_src, sizeof(init_src), "/proc/1/root%s", target_path);
        ns_bind_mount(pid, init_src, target_path);
    }
}
void force_recover_tracked_mounts() {
    for (int i = 0; i < TRACKED_HASH_SIZE; i++) {
        TrackedEntry *e = g_tracked_hash[i];
        while (e) {
            int pid = e->pid;
            if (kill(pid, 0) == 0) {
                uid_t uid = get_app_uid(pid);
                char target_path[128];
                get_target_storage_path(uid, target_path, sizeof(target_path));
                char backup_path[PATH_MAX];
                snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/storage");
                cleanup_app_mounts(pid, target_path, backup_path);
            }
            e = e->next;
        }
    }
    for (int i = 0; i < TRACKED_HASH_SIZE; i++) {
        TrackedEntry *e = g_tracked_hash[i];
        while (e) {
            TrackedEntry *tmp = e;
            e = e->next;
            free(tmp);
        }
        g_tracked_hash[i] = nullptr;
    }
}
/* 核心优化：配置审查时，就算应用解除注入，只要进程依然物理存活，就必须保持哈希追踪监听 */
void audit_tracked_apps() {
    prune_stale_tracked();
    for (int i = 0; i < TRACKED_HASH_SIZE; i++) {
        TrackedEntry **pp = &g_tracked_hash[i];
        while (*pp) {
            int pid = (*pp)->pid;
            char cmd[256] = {0};
            if (!proc_get_cmdline(pid, cmd, sizeof(cmd))) {
                TrackedEntry *tmp = *pp;
                *pp = (*pp)->next;
                free(tmp);
                continue;
            }
            uid_t uid = get_app_uid(pid);
            bool is_target = is_target_app(cmd, uid, pid, false);
            char target_path[128];
            get_target_storage_path(uid, target_path, sizeof(target_path));
            bool has_fuse = (ns_is_mounted(pid, target_path, "fuse.fuse_daemon") > 0 || ns_is_mounted(pid, target_path, "fuse_daemon") > 0);
            if (!is_target && has_fuse) {
                char backup_path[PATH_MAX];
                snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/storage");
                cleanup_app_mounts(pid, target_path, backup_path);
                LOG_DBG("配置审查: %s (PID: %d) 已取消注入，视图已安全解挂恢复，继续保持运行追踪。", cmd, pid);
            } else if (is_target && !has_fuse) {
                const char* mnt_src = get_active_mnt_src();
                if (mnt_src) {
                    perform_app_mount(cmd, pid, uid, mnt_src, "配置审查重新挂载");
                }
            }
            // 绝不在此处释放物理存活的追踪节点，始终沿链表后移
            pp = &(*pp)->next;
        }
    }
}
/* 核心优化：局部规则发生变化时，解除注入仅做解挂视图动作，绝对保留 PID 节点的物理追踪 */
void audit_and_remount_specific_apps(ChangedPkg* changed, int count) {
    prune_stale_tracked();
    const char* mnt_src = get_active_mnt_src();
    for (int i = 0; i < TRACKED_HASH_SIZE; i++) {
        TrackedEntry **pp = &g_tracked_hash[i];
        while (*pp) {
            int pid = (*pp)->pid;
            char cmd[256] = {0};
            if (!proc_get_cmdline(pid, cmd, sizeof(cmd))) {
                TrackedEntry *tmp = *pp;
                *pp = (*pp)->next;
                free(tmp);
                continue;
            }
            uid_t uid = get_app_uid(pid);
            int user_id = uid / 100000;
            bool matched = false;
            for (int c = 0; c < count; c++) {
                if ((changed[c].user_id == -1 || changed[c].user_id == user_id) &&
                    (fnmatch(changed[c].pkg_name, cmd, 0) == 0)) {
                    matched = true;
                    break;
                }
            }
            if (matched) {
                char target_path[128];
                get_target_storage_path(uid, target_path, sizeof(target_path));
                char backup_path[PATH_MAX];
                snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/storage");
                cleanup_app_mounts(pid, target_path, backup_path);
                bool is_target = is_target_app(cmd, uid, pid, false);
                if (is_target && mnt_src) {
                    LOG_DBG("局部规则审查: 受到变动影响的应用 %s (PID: %d) 进行重新挂载。", cmd, pid);
                    perform_app_mount(cmd, pid, uid, mnt_src, "局部规则变动重新挂载");
                } else {
                    LOG_DBG("局部规则审查: 受到变动影响的应用 %s (PID: %d) 已清空还原物理挂载，保持物理追踪监听。", cmd, pid);
                }
            }
            // 安全保留追踪节点。由于 add_tracked 的无副作用性（若 PID 重复则不改变任何链表指针），
            // 直接进行 pp 后移是 100% 内存安全的，杜绝了重置外层大循环（i = -1）产生的多余 CPU 轮转
            pp = &(*pp)->next;
        }
    }
}
void handle_list_injected(int client_fd) {
    char reply[4096];
    int offset = 0;
    int total = 0;
    for (int i = 0; i < TRACKED_HASH_SIZE; i++) {
        TrackedEntry *e = g_tracked_hash[i];
        while (e) {
            int pid = e->pid;
            if (kill(pid, 0) != 0) { e = e->next; continue; }
            char cmdline[256] = {0};
            if (!proc_get_cmdline(pid, cmdline, sizeof(cmdline))) { e = e->next; continue; }
            uid_t uid = get_app_uid(pid);
            // 状态过滤机制：穿透目标命名空间，验证是否真实处于 FUSE 挂载状态
            char target_path[128];
            get_target_storage_path(uid, target_path, sizeof(target_path));
            bool has_fuse = (ns_is_mounted(pid, target_path, "fuse.fuse_daemon") > 0 || 
                             ns_is_mounted(pid, target_path, "fuse_daemon") > 0);
            if (!has_fuse) {
                e = e->next;
                continue; // 物理卸载后代表应用处于逻辑停止状态，过滤不汇报
            }
            char base_pkg[256];
            strncpy(base_pkg, cmdline, sizeof(base_pkg) - 1);
            char* colon = strchr(base_pkg, ':');
            if (colon) *colon = '\0';
            int app_redir = 0, app_hide = 0, app_ro = 0;
            config_lock_read();
            AppConfig* cfg = find_app_cfg_locked(cmdline, uid / 100000);
            if (cfg) {
                app_redir = cfg->redir_count;
                app_hide = cfg->hide_count;
                app_ro = cfg->ro_count;
            }
            int total_redir = app_redir + g_global_cfg.redir_count;
            int total_hide = app_hide + g_global_cfg.hide_count;
            int total_ro = app_ro + g_global_cfg.ro_count;
            config_unlock_read();
            int n = snprintf(reply + offset, sizeof(reply) - offset, "APP|%s|%d|%u|%d|%d|%d\n",
                             base_pkg, pid, uid, total_redir, total_hide, total_ro);
            if (n > 0 && offset + n < (int)sizeof(reply))
                offset += n;
            total++;
            e = e->next;
        }
    }
    snprintf(reply + offset, sizeof(reply) - offset, "DONE|%d\n", total);
    send(client_fd, reply, strlen(reply), MSG_NOSIGNAL);
}
int get_injected_snapshot(int *out_pids, char (*out_pkgs)[256], uid_t *out_uids, int max_count) {
    int count = 0;
    for (int i = 0; i < TRACKED_HASH_SIZE && count < max_count; i++) {
        TrackedEntry *e = g_tracked_hash[i];
        while (e && count < max_count) {
            int pid = e->pid;
            if (kill(pid, 0) != 0) { e = e->next; continue; }
            char cmdline[256] = {0};
            if (!proc_get_cmdline(pid, cmdline, sizeof(cmdline))) { e = e->next; continue; }
            uid_t uid = get_app_uid(pid);
            // 状态过滤机制：仅当系统挂载了 FUSE 文件系统时才捕获快照
            char target_path[128];
            get_target_storage_path(uid, target_path, sizeof(target_path));
            bool has_fuse = (ns_is_mounted(pid, target_path, "fuse.fuse_daemon") > 0 || 
                             ns_is_mounted(pid, target_path, "fuse_daemon") > 0);
            if (!has_fuse) {
                e = e->next;
                continue;
            }
            char base_pkg[256];
            strncpy(base_pkg, cmdline, sizeof(base_pkg) - 1);
            base_pkg[sizeof(base_pkg) - 1] = '\0';
            char *colon = strchr(base_pkg, ':');
            if (colon) *colon = '\0';
            out_pids[count] = pid;
            strncpy(out_pkgs[count], base_pkg, 255);
            out_pkgs[count][255] = '\0';
            out_uids[count] = uid;
            count++;
            e = e->next;
        }
    }
    return count;
}
int get_uid_map_snapshot(UidMapEntry *out, int max_count) {
    int count = g_uid_map_count;
    if (count > max_count) count = max_count;
    for (int i = 0; i < count; i++) {
        out[i].uid = g_uid_map[i].uid;
        strncpy(out[i].pkg, g_uid_map[i].pkg, 127);
        out[i].pkg[127] = '\0';
    }
    return count;
}