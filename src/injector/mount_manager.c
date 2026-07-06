#define _GNU_SOURCE
#include "mount_manager.h"
#include "ns_utils.h"
#include "config_parser.h"
#include "inject_target.h"
#include "injector.h"
#include "common.h"
#include "fast_search.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fnmatch.h>
#include <stdlib.h>

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

bool app_has_active_rules(const char* pkg, uid_t uid) {
    int user_id = uid / 100000;
    config_lock_read();
    AppConfig* cfg = find_app_cfg_locked(pkg, user_id);
    bool has_rules = false;
    if (cfg) has_rules = (cfg->redir_count > 0 || cfg->hide_count > 0 || cfg->ro_count > 0 || cfg->sandbox);
    if (!has_rules) {
        bool use_global_sandbox = !is_media_provider(pkg);
        has_rules = (g_global_cfg.global_inject ||
                     g_global_cfg.redir_count > 0 || g_global_cfg.hide_count > 0 || g_global_cfg.ro_count > 0 ||
                     (g_global_cfg.sandbox && use_global_sandbox));
    }
    config_unlock_read();
    return has_rules;
}

typedef struct {
    bool target_has_fuse;
    bool target_has_fuse_daemon;
    bool target_is_mounted;
    bool backup_has_fuse;
    bool backup_has_fuse_daemon;
    bool backup_is_mounted;
} MountState;

static bool read_mount_state(int pid, const char* target, const char* backup, MountState* st) {
    memset(st, 0, sizeof(*st));
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
    size_t nread = 0;
    char* buf = read_file_dynamic(path, &nread);
    if (!buf) return false;
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

static bool submount_conflicts_with_rules_locked(const AppConfig* cfg, const char* rel_path, const char* pkg) {
    bool conflicts = false;
    bool is_media = is_media_provider(pkg);
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
        /* com.android.providers.media.module 默认关闭沙盒，不受全局设置影响，除非显式配置开启 */
        if (g_global_cfg.sandbox && !conflicts && !is_media) {
            const char* sb[] = {"/Android/data", "/Android/obb"};
            for (int s = 0; s < 2 && !conflicts; s++) {
                if (path_prefix_overlap(sb[s], rel_path)) conflicts = true;
            }
        }
    }
    return conflicts;
}

/*
 * 精确研判当前请求挂载的应用包名是否为 com.android.providers.media.module（包含多租户变体）。
 */
static bool is_exact_media_module(const char* pkg) {
    if (!pkg) return false;
    if (strcmp(pkg, "com.android.providers.media.module") == 0 ||
        strcmp(pkg, "com.android.providers.media") == 0 ||
        strncmp(pkg, "com.android.providers.media.module:", 34) == 0 ||
        strncmp(pkg, "com.android.providers.media:", 28) == 0) {
        return true;
    }
    return false;
}

int perform_app_mount(const char* pkg, int pid, uid_t uid, const char* mnt_src, const char* trigger) {
    if (kill(pid, 0) != 0) {
        LOG_DBG("目标进程已退出，跳过挂载: %s(PID:%d)", pkg, pid);
        return -1;
    }
    /*
     * 专属映射策略：
     * 1. 如果是 com.android.providers.media.module，则强制映射到专用媒体 FUSE 挂载源，不允许使用全局 FUSE。
     * 2. 如果是其他普通应用，强制限制挂载源为全局 FUSE，绝对阻止使用媒体 FUSE 挂载源，实现强隔离。
     */
    if (is_exact_media_module(pkg)) {
        const char* media_src = get_media_mnt_src();
        if (media_src) {
            mnt_src = media_src;
        } else {
            LOG_ERR("专用媒体 FUSE 实例未就绪/未启用，拒绝为媒体模块 %s(PID:%d) 执行挂载", pkg, pid);
            return -1;
        }
    } else {
        const char* active_src = get_active_mnt_src();
        if (active_src) {
            mnt_src = active_src;
        } else {
            LOG_ERR("全局 FUSE 实例不可用，%s(PID:%d) 挂载失败", pkg, pid);
            return -1;
        }
    }

    char target_path[128]; get_target_storage_path(uid, target_path, sizeof(target_path));
    char backup_path[PATH_MAX]; snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/storage");
    MountState mnt;
    if (!read_mount_state(pid, target_path, backup_path, &mnt)) {
        LOG_ERR("读取挂载状态失败: PID=%d, target=%s", pid, target_path);
        return -1;
    }
    
    if (mnt.target_has_fuse || mnt.target_has_fuse_daemon) {
        LOG_DBG("挂载跳过: %s (PID: %d, %s) - 已经存在程序自身的 FUSE 挂载", target_path, pid, pkg);
        if (uid >= 10000) update_uid_map(uid, pkg);
        add_tracked(pid);
        print_active_rules(pkg, pid, uid, trigger);
        return 0;
    }
    
    /* 解析 fuse_direct：per-app 优先，未设置则回退到全局 */
    bool fuse_direct = g_global_cfg.fuse_direct;
    {
        config_lock_read();
        AppConfig* cfg = find_app_cfg_locked(pkg, uid / 100000);
        if (cfg && cfg->fuse_direct) fuse_direct = true;
        config_unlock_read();
    }
    
    if (fuse_direct) {
        /* FUSE 直挂方案：简洁追加挂载，不卸载原有挂载点，不备份不还原 */
        /* 在发起异步挂载前，验证挂载源是否存在，避免 ENOENT 空转 */
        if (mnt_src && faccessat(g_global_root_fd, mnt_src + 1, F_OK, 0) != 0) {
            LOG_ERR("全局注入跳过 %s(PID:%d): 挂载源 %s 不存在(FUSE可能未就绪)", pkg, pid, mnt_src);
            return -1;
        }
        bool has_rules = app_has_active_rules(pkg, uid);
        if (mnt.target_is_mounted && !has_rules) {
            LOG_DBG("全局注入挂载保留: %s (PID: %d, %s) - 无规则冲突，保留原生视图", target_path, pid, pkg);
            if (uid >= 10000) update_uid_map(uid, pkg);
            add_tracked(pid);
            print_active_rules(pkg, pid, uid, trigger);
            return 0;
        }
        if (mnt.backup_has_fuse || mnt.backup_has_fuse_daemon) {
            ns_umount_recursive(pid, backup_path);
        }
        if (ns_global_mount_async(pid, pkg, mnt_src, target_path) == 0) {
            if (uid >= 10000) update_uid_map(uid, pkg);
            add_tracked(pid);
            print_active_rules(pkg, pid, uid, trigger);
            return 0;
        } else {
            LOG_ERR("全局注入异步追加挂载失败: PID=%d, pkg=%s", pid, pkg);
            return -1;
        }
    }
    
    /* 原始注入方案：备份 + 合并挂载 + 保留非冲突子挂载 */
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
            AppConfig* cfg = find_app_cfg_locked(pkg, uid / 100000);
            size_t tlen = strlen(target_path);
            for (int i = 0; i < n; i++) {
                const char* rel = found[i] + tlen;
                char rel_buf[256];
                snprintf(rel_buf, sizeof(rel_buf), "/%s", rel[0] == '/' ? rel + 1 : rel);
                if (!submount_conflicts_with_rules_locked(cfg, rel_buf, pkg)) {
                    snprintf(preserve_paths[preserve_count++], 256, "%s%s", target_path, rel_buf);
                }
            }
            config_unlock_read();
        }
    }
    if (ns_combined_mount_async(pid, pkg, mnt_src, target_path, backup_path, preserve_paths, preserve_count) == 0) {
        if (uid >= 10000) update_uid_map(uid, pkg);
        add_tracked(pid);
        print_active_rules(pkg, pid, uid, trigger);
        return 0;
    } else {
        LOG_ERR("启动异步合并挂载任务失败: PID=%d, pkg=%s", pid, pkg);
        return -1;
    }
}