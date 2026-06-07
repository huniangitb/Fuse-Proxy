#define _GNU_SOURCE
#include "mount_manager.h"
#include "ns_utils.h"
#include "config_parser.h"
#include "inject_target.h"
#include "common.h"
#include "fast_search.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fnmatch.h>

static bool is_mount_error_permanent(int err) {
    switch (err) {
        case EPERM: case EACCES: case EINVAL: case ENODEV: case ENOTDIR:
        case ELOOP: case ENAMETOOLONG: case EROFS: case ENOSYS: case EOPNOTSUPP: return true;
        default: return false;
    }
}

bool app_has_active_rules(const char* pkg, uid_t uid) {
    char base_pkg[256]; strncpy(base_pkg, pkg, sizeof(base_pkg) - 1); char* colon = strchr(base_pkg, ':'); if (colon) *colon = '\0';
    int user_id = uid / 100000; config_lock_read(); AppConfig* cfg = nullptr;
    for (int i = 0; i < g_app_cfg_count; i++) {
        if ((g_app_cfgs[i]->user_id == user_id || g_app_cfgs[i]->user_id == -1) && (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 || fnmatch(g_app_cfgs[i]->pkg_name, pkg, 0) == 0)) { cfg = g_app_cfgs[i]; break; }
    }
    bool has_rules = false;
    if (cfg) has_rules = (cfg->redir_count > 0 || cfg->hide_count > 0 || cfg->ro_count > 0 || cfg->sandbox);
    if (!has_rules) has_rules = (g_global_cfg.redir_count > 0 || g_global_cfg.hide_count > 0 || g_global_cfg.ro_count > 0 || g_global_cfg.sandbox);
    config_unlock_read(); return has_rules;
}

typedef struct {
    bool target_has_fuse;
    bool target_has_fuse_daemon;
    bool target_is_mounted;
    bool backup_has_fuse;
    bool backup_has_fuse_daemon;
    bool backup_is_mounted;
} MountState;

/* 极致优化版：单次全量内存读取检测 */
static bool read_mount_state(int pid, const char* target, const char* backup, MountState* st) {
    memset(st, 0, sizeof(*st));
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    char* buf = malloc(65536);
    if (!buf) { close(fd); return false; }

    ssize_t nread = 0;
    while (nread < 65535) {
        ssize_t r = read(fd, buf + nread, 65535 - nread);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        nread += r;
    }
    buf[nread] = '\0';
    close(fd);

    size_t tlen = strlen(target);
    size_t blen = strlen(backup);

    char* line = buf;
    while (line < buf + nread) {
        char* next_line = strchr(line, '\n');
        if (next_line) *next_line = '\0';

        if (fast_strstr(line, target) != nullptr || fast_strstr(line, backup) != nullptr) {
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

                if (mp_len > 0) {
                    bool target_match = (mp_len == tlen && memcmp(mp_start, target, tlen) == 0);
                    bool backup_match = (mp_len == blen && memcmp(mp_start, backup, blen) == 0);

                    if (target_match || backup_match) {
                        bool has_fuse = (fast_strstr(line, "fuse.fuse_daemon") != nullptr);
                        bool has_fuse_daemon = (fast_strstr(line, "fuse_daemon") != nullptr);

                        if (target_match) {
                            st->target_is_mounted = true;
                            if (has_fuse) st->target_has_fuse = true;
                            if (has_fuse_daemon) st->target_has_fuse_daemon = true;
                        }
                        if (backup_match) {
                            st->backup_is_mounted = true;
                            if (has_fuse) st->backup_has_fuse = true;
                            if (has_fuse_daemon) st->backup_has_fuse_daemon = true;
                        }
                    }
                }
            }
        }

        if (!next_line) break;
        line = next_line + 1;
    }

    free(buf);
    return true;
}

static bool path_prefix_overlap(const char* a, const char* b) {
    size_t alen = strlen(a), blen = strlen(b), minlen = alen < blen ? alen : blen;
    if (strncmp(a, b, minlen) != 0) return false;
    return (a[minlen] == '/' || a[minlen] == '\0') && (b[minlen] == '/' || b[minlen] == '\0');
}

static bool submount_conflicts_with_rules_locked(const AppConfig* cfg, const char* rel_path) {
    bool conflicts = false;
    if (cfg) {
        for (int i = 0; i < cfg->redir_count && !conflicts; i++) {
            if (path_prefix_overlap(cfg->redir_rules[i].virtual_prefix, rel_path)) conflicts = true;
        }
        for (int i = 0; i < cfg->hide_count && !conflicts; i++) {
            if (path_prefix_overlap(cfg->hide_rules[i], rel_path)) conflicts = true;
        }
        for (int i = 0; i < cfg->ro_count && !conflicts; i++) {
            if (path_prefix_overlap(cfg->ro_rules[i], rel_path)) conflicts = true;
        }
        if (cfg->sandbox && !conflicts) {
            const char* sb[] = {"/Android/data", "/Android/obb"};
            for (int s = 0; s < 2 && !conflicts; s++) {
                if (path_prefix_overlap(sb[s], rel_path)) conflicts = true;
            }
        }
    }
    if (!conflicts) {
        for (int i = 0; i < g_global_cfg.redir_count && !conflicts; i++) {
            if (path_prefix_overlap(g_global_cfg.redir_rules[i].virtual_prefix, rel_path)) conflicts = true;
        }
        for (int i = 0; i < g_global_cfg.hide_count && !conflicts; i++) {
            if (path_prefix_overlap(g_global_cfg.hide_rules[i], rel_path)) conflicts = true;
        }
        for (int i = 0; i < g_global_cfg.ro_count && !conflicts; i++) {
            if (path_prefix_overlap(g_global_cfg.ro_rules[i], rel_path)) conflicts = true;
        }
        if (g_global_cfg.sandbox && !conflicts) {
            const char* sb[] = {"/Android/data", "/Android/obb"};
            for (int s = 0; s < 2 && !conflicts; s++) {
                if (path_prefix_overlap(sb[s], rel_path)) conflicts = true;
            }
        }
    }
    return conflicts;
}

int perform_app_mount(const char* pkg, int pid, uid_t uid, const char* mnt_src, const char* trigger) {
    struct timespec t_start, t_step;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    char target_path[128]; get_target_storage_path(uid, target_path, sizeof(target_path));
    char backup_path[PATH_MAX]; snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/nsp_sys_storage");

    MountState mnt;
    read_mount_state(pid, target_path, backup_path, &mnt);

    if (mnt.target_has_fuse || mnt.target_has_fuse_daemon) {
        LOG_DBG("挂载跳过: %s (PID: %d, %s) - 已经存在程序自身的 FUSE 挂载", target_path, pid, pkg);
        if (uid >= 10000) update_uid_map(uid, pkg);
        add_tracked(pid);
        print_active_rules(pkg, pid, uid, trigger);
        return 0;
    }

    if (mnt.backup_has_fuse || mnt.backup_has_fuse_daemon) {
        ns_umount_recursive(pid, backup_path);
    }

    if (mnt.backup_is_mounted) {
        ns_bind_mount(pid, backup_path, target_path);
        ns_umount_recursive(pid, backup_path);
    }

    bool has_rules = app_has_active_rules(pkg, uid);
    if (mnt.target_is_mounted && !has_rules) {
        LOG_DBG("挂载保留: %s (PID: %d, %s) - 无规则冲突，保留原生视图", target_path, pid, pkg);
        if (uid >= 10000) update_uid_map(uid, pkg);
        add_tracked(pid);
        print_active_rules(pkg, pid, uid, trigger);
        return 0;
    }

    char preserve_paths[16][256];
    int preserve_count = 0;
    if (mnt.target_is_mounted && has_rules) {
        char found[16][256];
        int n = ns_find_native_submounts(pid, target_path, found, 16);
        if (n > 0) {
            config_lock_read();
            char base_pkg[256];
            strncpy(base_pkg, pkg, sizeof(base_pkg) - 1);
            char* colon = strchr(base_pkg, ':');
            if (colon) *colon = '\0';
            int user_id = uid / 100000;
            AppConfig* cfg = nullptr;
            for (int i = 0; i < g_app_cfg_count; i++) {
                if ((g_app_cfgs[i]->user_id == user_id || g_app_cfgs[i]->user_id == -1) &&
                    (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 || fnmatch(g_app_cfgs[i]->pkg_name, pkg, 0) == 0)) {
                    cfg = g_app_cfgs[i];
                    break;
                }
            }

            size_t tlen = strlen(target_path);
            for (int i = 0; i < n; i++) {
                const char* rel = found[i] + tlen;
                char rel_buf[256];
                snprintf(rel_buf, sizeof(rel_buf), "/%s", rel[0] == '/' ? rel + 1 : rel);
                if (!submount_conflicts_with_rules_locked(cfg, rel_buf)) {
                    snprintf(preserve_paths[preserve_count++], 256, "%s%s", target_path, rel_buf);
                }
            }
            config_unlock_read();
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t_step);
    long t_after_submounts = (t_step.tv_sec - t_start.tv_sec) * 1000 +
                             (t_step.tv_nsec - t_start.tv_nsec) / 1000000;

    bool success = false;
    int mount_attempts = 0;
    for (int i = 0; i < 3; i++) {
        if (ns_is_mounted(pid, target_path, "fuse.fuse_daemon") || ns_is_mounted(pid, target_path, "fuse_daemon")) {
            success = true;
            break;
        }
        mount_attempts++;
        if (ns_combined_mount(pid, mnt_src, target_path, backup_path, preserve_paths, preserve_count) == 0) {
            success = true;
            break;
        }
        if (is_mount_error_permanent(errno) && errno != 0) break;
        if (i < 2) usleep(50000);
    }

    clock_gettime(CLOCK_MONOTONIC, &t_step);
    long t_total = (t_step.tv_sec - t_start.tv_sec) * 1000 +
                   (t_step.tv_nsec - t_start.tv_nsec) / 1000000;

    LOG("合并挂载优化计时: parse_submounts=%ldms mount_attempts=%d total=%ldms",
        t_after_submounts, mount_attempts, t_total);

    if (success) {
        if (uid >= 10000) update_uid_map(uid, pkg);
        add_tracked(pid);
        print_active_rules(pkg, pid, uid, trigger);
        return 0;
    } else {
        return -1;
    }
}