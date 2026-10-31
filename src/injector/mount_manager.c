#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "mount_manager.h"
#include "ns_utils.h"
#include "config_parser.h"
#include "inject_target.h"
#include "injector.h"
#include "common.h"
#include "sys_pkg.h"
#include "fast_search.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fnmatch.h>
#include <stdlib.h>
#include <pthread.h>
#ifdef TARGET_ANDROID
#include <sys/system_properties.h>
#endif

/* read_file_dynamic 已抽取至 src/core/common.c（公共工具，见 common.h），
   此处不再重复实现 */

bool app_has_active_rules(const char* pkg, uid_t uid) {
    int user_id = uid / NSP_PER_USER_UID_STRIDE;
    config_lock_read();
    AppConfig* cfg = find_app_cfg_locked(pkg, user_id);
    bool has_rules = false;
    if (cfg)
        has_rules =
            (cfg->redir_count > 0 || cfg->hide_count > 0 || cfg->ro_count > 0 || cfg->sandbox);
    /* 类别层（与 br_pick_category 同口径）：应用段无规则时看类别段 */
    if (!has_rules) {
        bool is_sys = (uid < NSP_SYSTEM_APP_UID_MIN) || (pkg && sys_pkg_is_system(pkg));
        has_rules = category_has_rules_locked(is_sys, user_id);
    }
    if (!has_rules) {
        bool use_global_sandbox = !is_media_provider(pkg);
        has_rules = (g_global_cfg.global_inject || g_global_cfg.redir_count > 0 ||
                     g_global_cfg.hide_count > 0 || g_global_cfg.ro_count > 0 ||
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

/* MountState 缓存：避免为同一 PID 重复读取 /proc/<pid>/mountinfo

   互斥保护：主 epoll 线程（handle_list_injected、主动扫描）与 detach 的
   ipc_mount_thread / ipc_restore_thread（perform_app_mount/restore 的查询与
   失效）会并发读写本缓存。无锁时除撕裂读外，update 的"检查后自增"还会让
   计数越过 MOUNT_STATE_CACHE_SIZE 造成越界写。锁仅覆盖数组访问本身——
   read_mount_state 的 /proc 扫描一律在锁外执行（竞态下最多重复读一次
   mountinfo，不影响正确性），且三个函数都不再调用其它加锁子系统，无嵌套风险 */
#define MOUNT_STATE_CACHE_SIZE 64
static struct {
    int pid;
    MountState st;
} g_mount_cache[MOUNT_STATE_CACHE_SIZE];
static int g_mount_cache_count;
static pthread_mutex_t g_mount_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool lookup_mount_cache(int pid, MountState* st) {
    bool found = false;
    pthread_mutex_lock(&g_mount_cache_mutex);
    for (int i = 0; i < g_mount_cache_count; i++) {
        if (g_mount_cache[i].pid == pid) {
            *st = g_mount_cache[i].st; /* 值拷贝：调用方拿到快照，不持有数组指针 */
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_mount_cache_mutex);
    return found;
}

static void update_mount_cache(int pid, const MountState* st) {
    pthread_mutex_lock(&g_mount_cache_mutex);
    for (int i = 0; i < g_mount_cache_count; i++) {
        if (g_mount_cache[i].pid == pid) {
            g_mount_cache[i].st = *st;
            pthread_mutex_unlock(&g_mount_cache_mutex);
            return;
        }
    }
    /* 槽位先快照到局部变量：边界检查与下标使用之间不再重读全局计数 */
    int slot = g_mount_cache_count;
    if (slot >= 0 && slot < MOUNT_STATE_CACHE_SIZE) {
        g_mount_cache[slot].pid = pid;
        g_mount_cache[slot].st = *st;
        g_mount_cache_count = slot + 1;
    }
    pthread_mutex_unlock(&g_mount_cache_mutex);
}

static void invalidate_mount_cache(int pid) {
    pthread_mutex_lock(&g_mount_cache_mutex);
    for (int i = 0; i < g_mount_cache_count; i++) {
        if (g_mount_cache[i].pid == pid) {
            g_mount_cache[i] = g_mount_cache[--g_mount_cache_count];
            break;
        }
    }
    pthread_mutex_unlock(&g_mount_cache_mutex);
}

static bool read_mount_state(int pid, const char* target, const char* backup, MountState* st);

/* 注入状态检查（跨文件）：复用挂载状态缓存，避免每次扫描 mountinfo——
   缓存未命中时读取一次并写入缓存（挂载/还原/卸载路径均会失效缓存，
   inject_target 的 handle_list_injected/get_injected_snapshot 等高频调用受益） */
bool is_project_fuse_cached(int pid, const char* target_path) {
    MountState mnt;
    if (!lookup_mount_cache(pid, &mnt)) {
        if (!read_mount_state(pid, target_path, "", &mnt)) return false;
        update_mount_cache(pid, &mnt);
    }
    return mnt.target_has_fuse || mnt.target_has_fuse_daemon;
}

static bool read_mount_state(int pid, const char* target, const char* backup, MountState* st) {
    memset(st, 0, sizeof(*st));
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
    size_t nread = 0;
    char* buf = read_file_dynamic(path, &nread, 0);
    if (!buf) return false;
    size_t tlen = strlen(target);
    size_t blen = strlen(backup);
    /* 全局替换共享传播视图：fstype 可能不含 fuse_daemon（mountinfo source 是
       devname/fsname），需以 dev（major:minor，bind/共享视图与源同 superblock）
       判定。先收集全局 FUSE 源挂载点在该命名空间内的 dev */
    char src_dev[64] = {0};
    const char* src = get_active_mnt_src();
    if (src) {
        char* l = buf;
        while (l < buf + nread) {
            char* nl = strchr(l, '\n');
            char devbuf[64] = {0}, mpbuf[PATH_MAX] = {0};
            if (sscanf(l, "%*d %*d %63s %*s %4095s", devbuf, mpbuf) == 2 &&
                strcmp(mpbuf, src) == 0) {
                strncpy(src_dev, devbuf, sizeof(src_dev) - 1);
                break;
            }
            if (!nl) break;
            l = nl + 1;
        }
    }
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
                            /* dev 匹配：全局替换共享传播视图（fstype 不含 fuse_daemon
                               时仅 dev 与全局 FUSE 源一致可判定为项目视图） */
                            char devbuf[64] = {0};
                            sscanf(line, "%*d %*d %63s", devbuf);
                            if (has_fuse || (src_dev[0] && strcmp(devbuf, src_dev) == 0))
                                st->target_has_fuse = true;
                            if (has_fuse_daemon) st->target_has_fuse_daemon = true;
                        }
                        if (backup_match) {
                            st->backup_is_mounted = true;
                            if (has_fuse) st->backup_has_fuse = true;
                            if (has_fuse_daemon) st->backup_has_fuse_daemon = true;
                        }
                        /* 需要 target 和 backup 均确定后才退出 */
                        if (st->target_is_mounted && st->backup_is_mounted) {
                            break;
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

static bool submount_conflicts_with_rules_locked(const AppConfig* cfg, const char* rel_path,
                                                 const char* pkg) {
    bool conflicts = false;
    bool is_media = is_media_provider(pkg);
    bool app_sandbox_off = (cfg && cfg->sandbox_explicit && !cfg->sandbox);
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
            if (path_prefix_overlap(g_global_cfg.redir_rules[i].virtual_prefix, rel_path))
                conflicts = true;
        }
        for (int i = 0; i < g_global_cfg.hide_count && !conflicts; i++) {
            if (path_prefix_overlap(g_global_cfg.hide_rules[i], rel_path)) conflicts = true;
        }
        for (int i = 0; i < g_global_cfg.ro_count && !conflicts; i++) {
            if (path_prefix_overlap(g_global_cfg.ro_rules[i], rel_path)) conflicts = true;
        }
        /* com.android.providers.media.module 默认关闭沙盒，不受全局设置影响，除非显式配置开启 */
        if (g_global_cfg.sandbox && !conflicts && !is_media && !app_sandbox_off) {
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

/* ro.fuse.bpf.is_running 缓存：-1=未检查, 0=false, 1=true
   （仅 TARGET_ANDROID 下使用；GNU 侧 is_bpf_fuse_running 直接 return false） */
#ifdef TARGET_ANDROID
static int g_bpf_fuse_running = -1;
#endif

static inline bool is_bpf_fuse_running(void) {
#ifdef TARGET_ANDROID
    if (g_bpf_fuse_running < 0) {
        char prop[PROP_VALUE_MAX];
        g_bpf_fuse_running =
            (__system_property_get("ro.fuse.bpf.is_running", prop) > 0 && strcmp(prop, "true") == 0)
                ? 1
                : 0;
        if (g_bpf_fuse_running) LOG_DBG("(ro.fuse.bpf.is_running=true)，跳过子挂载扫描");
    }
    return g_bpf_fuse_running == 1;
#else
    return false;
#endif
}

int perform_app_mount(const char* pkg, int pid, uid_t uid, const char* mnt_src,
                      const char* trigger) {
    if (kill(pid, 0) != 0) {
        LOG_DBG("目标进程已退出，跳过挂载: %s(PID:%d)", pkg, pid);
        invalidate_mount_cache(pid);
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
            LOG_ERR("专用媒体 FUSE 实例未就绪/未启用，拒绝为媒体模块 %s(PID:%d) 执行挂载", pkg,
                    pid);
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

    char target_path[128];
    get_target_storage_path(uid, target_path, sizeof(target_path));
    char backup_path[PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/storage");

    MountState mnt;
    if (!lookup_mount_cache(pid, &mnt)) {
        if (!read_mount_state(pid, target_path, backup_path, &mnt)) {
            LOG_ERR("读取挂载状态失败: PID=%d, target=%s", pid, target_path);
            return -1;
        }
        update_mount_cache(pid, &mnt);
    }

    if (mnt.target_has_fuse || mnt.target_has_fuse_daemon) {
        LOG_DBG("挂载跳过: %s (PID: %d, %s) - 已经存在程序自身的 FUSE 挂载", target_path, pid, pkg);
        if (uid >= NSP_SYSTEM_APP_UID_MIN) update_uid_map(uid, pkg);
        mark_injected(pid);
        print_active_rules(pkg, pid, uid, trigger);
        return 0;
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
        if (uid >= NSP_SYSTEM_APP_UID_MIN) update_uid_map(uid, pkg);
        add_tracked(pid);
        print_active_rules(pkg, pid, uid, trigger);
        return 0;
    }

    /* preserve 目标收集：combined 挂载保留 target 下原生子视图（如
       Android/data）时使用。备份复制已弃用（不再 mount target→backup），
       恢复源改为直接 bind /mnt/ 下系统视图（多用户族根）——收集的仍是
       target 下的原生子挂载清单（规则非冲突项） */
    char preserve_paths[16][256];
    int preserve_count = 0;
    if (mnt.target_is_mounted && has_rules && !is_bpf_fuse_running()) {
        char found[16][256];
        int n = ns_find_native_submounts(pid, target_path, found, 16);
        if (n > 0) {
            config_lock_read();
            AppConfig* cfg = find_app_cfg_locked(pkg, uid / NSP_PER_USER_UID_STRIDE);
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
    if (ns_combined_mount_async(pid, pkg, mnt_src, target_path, backup_path, preserve_paths,
                                preserve_count) == 0) {
        if (uid >= NSP_SYSTEM_APP_UID_MIN) update_uid_map(uid, pkg);
        mark_injected(pid);
        invalidate_mount_cache(pid);
        print_active_rules(pkg, pid, uid, trigger);
        return 0;
    } else {
        LOG_ERR("启动异步合并挂载任务失败: PID=%d, pkg=%s", pid, pkg);
        return -1;
    }
}

/*
 * 同步版应用挂载：阻塞等待挂载完成，返回真实结果。
 * 由 IPC 线程调用，不涉及异步 fork / 重试队列。
 */
int perform_app_mount_sync(const char* pkg, int pid, uid_t uid, const char* mnt_src,
                           int readiness_ms) {
    if (kill(pid, 0) != 0) {
        LOG_DBG("目标进程已退出，跳过同步挂载: %s(PID:%d)", pkg, pid);
        invalidate_mount_cache(pid);
        return -1;
    }

    if (is_exact_media_module(pkg)) {
        const char* media_src = get_media_mnt_src();
        if (media_src) {
            mnt_src = media_src;
        } else {
            LOG_ERR("专用媒体 FUSE 未就绪，拒绝同步挂载 %s(PID:%d)", pkg, pid);
            return -1;
        }
    } else {
        const char* active_src = get_active_mnt_src();
        if (active_src) {
            mnt_src = active_src;
        } else {
            LOG_ERR("全局 FUSE 不可用，同步挂载 %s(PID:%d) 失败", pkg, pid);
            return -1;
        }
    }

    char target_path[128];
    get_target_storage_path(uid, target_path, sizeof(target_path));
    char backup_path[PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/storage");

    MountState mnt;
    if (!lookup_mount_cache(pid, &mnt)) {
        if (!read_mount_state(pid, target_path, backup_path, &mnt)) {
            LOG_ERR("同步挂载读取挂载状态失败: PID=%d, target=%s", pid, target_path);
            return -1;
        }
        update_mount_cache(pid, &mnt);
    }

    if (mnt.target_has_fuse || mnt.target_has_fuse_daemon) {
        LOG_DBG("同步挂载跳过: %s (PID: %d, %s) - 已存在 FUSE 挂载", target_path, pid, pkg);
        return 0;
    }

    /* 原始注入方案 */
    if (mnt.backup_has_fuse || mnt.backup_has_fuse_daemon) {
        ns_umount_recursive(pid, backup_path);
    }
    if (mnt.backup_is_mounted) {
        ns_bind_mount(pid, backup_path, target_path);
        ns_umount_recursive(pid, backup_path);
    }
    bool has_rules = app_has_active_rules(pkg, uid);
    if (mnt.target_is_mounted && !has_rules) {
        LOG_DBG("同步挂载保留: %s (PID: %d, %s) - 无规则冲突", target_path, pid, pkg);
        return 0;
    }

    char preserve_paths[16][256];
    int preserve_count = 0;
    if (mnt.target_is_mounted && has_rules && !is_bpf_fuse_running()) {
        char found[16][256];
        int n = ns_find_native_submounts(pid, target_path, found, 16);
        if (n > 0) {
            config_lock_read();
            AppConfig* cfg = find_app_cfg_locked(pkg, uid / NSP_PER_USER_UID_STRIDE);
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
    /* 同步合并挂载 */
    if (ns_combined_mount(pid, pkg, mnt_src, target_path, backup_path, preserve_paths,
                          preserve_count, readiness_ms) == 0) {
        invalidate_mount_cache(pid);
        return 0;
    } else {
        /* readiness_ms < 0 = 后台通道（异步扫描 / 失败重试）：应用已经在运行，
           代理视图稍后到达即可，本次未就绪属**预期**——记 ERROR 会把正常等待刷成
           故障（历史上每次应用启动留一条"挂载失败"，与最终真实结果相反）。 */
        if (readiness_ms < 0) {
            LOG_DBG("后台通道视图未就绪（稍后补挂载）: %s(PID:%d)", pkg, pid);
        } else {
            LOG_ERR("同步合并挂载失败: PID=%d, pkg=%s", pid, pkg);
        }
        return -1;
    }
}

/*
 * 注入方法 v2（全局替换且还原非目标）下的非目标应用还原：
 * （v3 不调用本函数——不对非目标应用做任何还原）
 * 进入应用命名空间，卸载项目 FUSE 并 bind 回该用户备份的系统视图。
 * 幂等：仅当 /storage/emulated 顶层源为项目 FUSE（nsp_global 或 fuse_daemon）
 * 时才操作；非目标应用已还原/未受影响时直接跳过。
 */
int perform_app_restore(const char* pkg, int pid, uid_t uid) {
    if (kill(pid, 0) != 0) {
        LOG_DBG("目标进程已退出，跳过还原: %s(PID:%d)", pkg, pid);
        invalidate_mount_cache(pid);
        return -1;
    }
    /* 还原不依赖全局 FUSE 实例是否存在：目标顶层是否为项目 FUSE（fuse_daemon）
       由 ns_restore_app_fuse 基于目标挂载状态判断（fstype/source 特征），
       fuse_src 仅用于精确 dev 匹配，可为空（全局 FUSE 不可用时走特征兜底） */
    int user_id = (int)(uid / NSP_PER_USER_UID_STRIDE);
    int ret = ns_restore_app_fuse(pid, get_active_mnt_src(), GLOBAL_BACKUP_ROOT, user_id);
    if (ret == 0) {
        LOG_DBG("非目标应用已还原系统视图: %s(PID:%d, user=%d)", pkg, pid, user_id);
        invalidate_mount_cache(pid);
        unmark_injected(pid); /* 还原即解除注入状态（显式标志清除） */
    } else if (ret == 1) {
        LOG_DBG("非目标应用还原跳过: %s(PID:%d, user=%d) 顶层非项目 FUSE", pkg, pid, user_id);
        /* 还原跳过（顶层非项目 FUSE）：缓存可能残留旧的 target_has_fuse=true，
           须失效重建，否则 list-injected 会误判该应用仍已注入 */
        invalidate_mount_cache(pid);
        unmark_injected(pid);
    } else {
        LOG_ERR("非目标应用还原失败: %s(PID:%d, user=%d)", pkg, pid, user_id);
        invalidate_mount_cache(pid);
    }
    return ret;
}