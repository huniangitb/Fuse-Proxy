#define _GNU_SOURCE
#include "mount_manager.h"
#include "ns_utils.h"
#include "config_parser.h"
#include "inject_target.h"
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fnmatch.h>

static int is_mount_error_permanent(int err) {
    switch (err) {
        case EPERM: case EACCES: case EINVAL: case ENODEV: case ENOTDIR:
        case ELOOP: case ENAMETOOLONG: case EROFS: case ENOSYS: case EOPNOTSUPP: return 1;
        default: return 0;
    }
}

int app_has_active_rules(const char* pkg, uid_t uid) {
    char base_pkg[256]; strncpy(base_pkg, pkg, sizeof(base_pkg) - 1); char* colon = strchr(base_pkg, ':'); if (colon) *colon = '\0';
    int user_id = uid / 100000; config_lock_read(); AppConfig* cfg = NULL;
    for (int i = 0; i < g_app_cfg_count; i++) {
        if ((g_app_cfgs[i]->user_id == user_id || g_app_cfgs[i]->user_id == -1) && (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 || fnmatch(g_app_cfgs[i]->pkg_name, pkg, 0) == 0)) { cfg = g_app_cfgs[i]; break; }
    }
    int has_rules = 0;
    if (cfg) has_rules = (cfg->redir_count > 0 || cfg->hide_count > 0 || cfg->ro_count > 0 || cfg->sandbox);
    if (!has_rules) has_rules = (g_global_cfg.redir_count > 0 || g_global_cfg.hide_count > 0 || g_global_cfg.ro_count > 0 || g_global_cfg.sandbox);
    config_unlock_read(); return has_rules;
}

static int path_prefix_overlap(const char* a, const char* b) {
    size_t alen = strlen(a), blen = strlen(b), minlen = alen < blen ? alen : blen;
    if (strncmp(a, b, minlen) != 0) return 0;
    return (a[minlen] == '/' || a[minlen] == '\0') && (b[minlen] == '/' || b[minlen] == '\0');
}

static int submount_conflicts_with_rules(const char* pkg, uid_t uid, const char* rel_path) {
    char base_pkg[256]; strncpy(base_pkg, pkg, sizeof(base_pkg) - 1); char* colon = strchr(base_pkg, ':'); if (colon) *colon = '\0';
    int user_id = uid / 100000; config_lock_read(); AppConfig* cfg = NULL;
    for (int i = 0; i < g_app_cfg_count; i++) {
        if ((g_app_cfgs[i]->user_id == user_id || g_app_cfgs[i]->user_id == -1) && (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 || fnmatch(g_app_cfgs[i]->pkg_name, pkg, 0) == 0)) { cfg = g_app_cfgs[i]; break; }
    }
    int conflicts = 0;
    if (cfg) {
        for (int i = 0; i < cfg->redir_count && !conflicts; i++) if (path_prefix_overlap(cfg->redir_rules[i].virtual_prefix, rel_path)) conflicts = 1;
        for (int i = 0; i < cfg->hide_count && !conflicts; i++) if (path_prefix_overlap(cfg->hide_rules[i], rel_path)) conflicts = 1;
        for (int i = 0; i < cfg->ro_count && !conflicts; i++) if (path_prefix_overlap(cfg->ro_rules[i], rel_path)) conflicts = 1;
        if (cfg->sandbox && !conflicts) { const char* sb[] = {"/Android/data", "/Android/obb"}; for (int s = 0; s < 2 && !conflicts; s++) if (path_prefix_overlap(sb[s], rel_path)) conflicts = 1; }
    }
    if (!conflicts) {
        for (int i = 0; i < g_global_cfg.redir_count && !conflicts; i++) if (path_prefix_overlap(g_global_cfg.redir_rules[i].virtual_prefix, rel_path)) conflicts = 1;
        for (int i = 0; i < g_global_cfg.hide_count && !conflicts; i++) if (path_prefix_overlap(g_global_cfg.hide_rules[i], rel_path)) conflicts = 1;
        for (int i = 0; i < g_global_cfg.ro_count && !conflicts; i++) if (path_prefix_overlap(g_global_cfg.ro_rules[i], rel_path)) conflicts = 1;
        if (g_global_cfg.sandbox && !conflicts) { const char* sb[] = {"/Android/data", "/Android/obb"}; for (int s = 0; s < 2 && !conflicts; s++) if (path_prefix_overlap(sb[s], rel_path)) conflicts = 1; }
    }
    config_unlock_read(); return conflicts;
}

int perform_app_mount(const char* pkg, int pid, uid_t uid, const char* mnt_src, const char* trigger) {
    char target_path[128]; get_target_storage_path(uid, target_path, sizeof(target_path));
    char backup_path[PATH_MAX]; snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/nsp_sys_storage");

    while (ns_is_mounted(pid, target_path, "fuse_daemon") > 0) ns_umount_recursive(pid, target_path);
    if (ns_is_mounted(pid, backup_path, NULL) > 0) ns_move_mount(pid, backup_path, target_path);

    int mount_status = ns_is_mounted(pid, target_path, NULL);
    if (mount_status > 0 && !app_has_active_rules(pkg, uid)) {
        LOG("挂载保留: %s (PID: %d, %s) - 无规则冲突，保留原生视图", target_path, pid, pkg);
        if (uid >= 10000) update_uid_map(uid, pkg); add_tracked(pid); print_active_rules(pkg, pid, uid, trigger);
        return 0;
    }

    if (ns_is_mounted(pid, target_path, NULL) > 0) {
        if (ns_move_mount(pid, target_path, backup_path) != 0) ns_umount_recursive(pid, target_path);
    }

    char preserve_paths[16][256]; int preserve_count = 0;
    if (app_has_active_rules(pkg, uid)) {
        char found[16][256]; int n = ns_find_native_submounts(pid, backup_path, found, 16);
        size_t tlen = strlen(backup_path);
        for (int i = 0; i < n; i++) {
            const char* rel = found[i] + tlen; char rel_buf[256]; snprintf(rel_buf, sizeof(rel_buf), "/%s", rel[0] == '/' ? rel + 1 : rel);
            if (!submount_conflicts_with_rules(pkg, uid, rel_buf)) snprintf(preserve_paths[preserve_count++], 256, "%s%s", target_path, rel_buf);
        }
    }

    int success = 0, max_retries = 3, retry_delay = 100;
    for (int i = 0; i < max_retries; i++) {
        if (ns_is_mounted(pid, target_path, "fuse")) { success = 1; break; }
        if (preserve_count > 0) {
            if (ns_bind_mount_with_preserve(pid, mnt_src, target_path, preserve_paths, preserve_count) == 0) { success = 1; break; }
        } else {
            if (ns_bind_mount(pid, mnt_src, target_path) == 0) { success = 1; break; }
        }
        if (is_mount_error_permanent(errno) && errno != 0) break;
        usleep(retry_delay * 1000); retry_delay *= 2;
    }
    if (success) {
        if (uid >= 10000) update_uid_map(uid, pkg);
        add_tracked(pid); print_active_rules(pkg, pid, uid, trigger); return 0;
    } else return -1;
}