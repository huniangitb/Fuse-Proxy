#define _GNU_SOURCE
#include "inject_target.h"
#include "injector.h"
#include "common.h"
#include "config_parser.h"
#include "ns_utils.h"
#include "mount_manager.h"
#include "uid_map.h"
#include "fast_pid.h"
#include "sys_pkg.h"
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
#include <pthread.h>

#define TRACKED_HASH_SIZE 2048
typedef struct TrackedEntry {
    int pid;
    bool injected;              /* 注入状态显式标志：注入成功路径置位，
                                   restore/卸载路径清除（稳定公共函数维护，
                                   列表不再依赖挂载状态探测） */
    struct TrackedEntry *next;
} TrackedEntry;

static TrackedEntry *g_tracked_hash[TRACKED_HASH_SIZE];
static pthread_mutex_t g_tracked_mutex = PTHREAD_MUTEX_INITIALIZER;

/* 系统应用包名缓存：实现已抽取至 src/core/sys_pkg.c（跨进程共享，
 * injector pm 查询并落盘，fuse_daemon 侧只读文件）；此处仅保留同名薄封装，
 * 调用点（init/cleanup/is_system_app_by_pkg）零改动 */
static bool is_system_pkg_cached(const char* pkg) {
    return sys_pkg_is_system(pkg);
}

void cleanup_system_pkg_cache(void) {
    sys_pkg_cleanup();
}

void init_system_pkg_cache(void) {
    /* injector 是唯一允许 pm 查询的进程：查表并落盘 sys_pkgs.cache，
       供 fuse_daemon 侧只读消费（禁 popen，防 binder 挂起） */
    sys_pkg_init(true);
}

static unsigned int hash_pid(int pid) {
    return (unsigned int)pid % TRACKED_HASH_SIZE;
}

void add_tracked(int pid) {
    pthread_mutex_lock(&g_tracked_mutex);
    unsigned int h = hash_pid(pid);
    TrackedEntry *e = g_tracked_hash[h];
    while (e) {
        if (e->pid == pid) {
            pthread_mutex_unlock(&g_tracked_mutex);
            return;
        }
        e = e->next;
    }
    /* calloc 而非 malloc：injected 必须零初始化——add_tracked 仅表示"已跟踪"，
       未注入是唯一正确的初始状态。挂载保留分支、缓存快速响应路径等只调
       add_tracked 而不跟 mark_injected 的调用点若拿到堆上残值，
       is_injected 会把未注入应用误报为已注入（list-injected 是其唯一权威） */
    e = calloc(1, sizeof(TrackedEntry));
    if (e) {
        e->pid = pid;
        e->injected = false;
        e->next = g_tracked_hash[h];
        g_tracked_hash[h] = e;
    }
    pthread_mutex_unlock(&g_tracked_mutex);

    /* 此处不再预热挂载状态缓存（080fcd2 引入，现已无收益且有害）：
       1) 收益消失——预热的唯一目的是让 LIST_INJECTED 首次请求命中缓存，
          但注入状态改为显式标志维护后，handle_list_injected /
          get_injected_snapshot 已完全不查挂载缓存；
       2) 主动有害——预热走 is_project_fuse_cached，其 read_mount_state 传的是
          空 backup 路径，blen==0 使 backup_match 恒为 false，写入缓存的条目里
          backup_* 三个字段一律为 false（与真实状态无关）。传统模式下
          ipc_mount_thread 先 add_tracked 再 perform_app_mount，后者命中该条目
          即跳过 backup 的解挂与回绑——残留备份挂载不会被清理；
       3) 开销在热路径——全局替换模式下该调用位于 injector 主 epoll 线程，
          每次应用启动同步付一次 /proc/<pid>/mountinfo 全量读取。
       需要挂载状态的调用方各自按自身查询形状调 read_mount_state 即可。 */
}

/* ============ 注入状态稳定公共函数 ============
   add_tracked 仅表示"已处理/已跟踪"（含还原后的非目标应用）；是否确实
   **已注入**由显式标志维护，list-injected/快照据此判定，不再重新探测
   mountinfo——GLOBAL_INJECT 下全局替换无逐应用挂载、异步挂载时序、
   系统应用命名空间差异都会让挂载状态探测误判，导致刚注入的应用被过滤 */

/* 标记 pid 为已注入（注入成功路径调用，幂等） */
void mark_injected(int pid) {
    add_tracked(pid);   /* 确保条目存在（幂等） */
    pthread_mutex_lock(&g_tracked_mutex);
    unsigned int h = hash_pid(pid);
    TrackedEntry *e = g_tracked_hash[h];
    while (e) {
        if (e->pid == pid) {
            e->injected = true;
            break;
        }
        e = e->next;
    }
    pthread_mutex_unlock(&g_tracked_mutex);
}

/* 清除注入标志（还原/卸载路径调用，幂等；条目仍保留以便继续追踪） */
void unmark_injected(int pid) {
    pthread_mutex_lock(&g_tracked_mutex);
    unsigned int h = hash_pid(pid);
    TrackedEntry *e = g_tracked_hash[h];
    while (e) {
        if (e->pid == pid) {
            e->injected = false;
            break;
        }
        e = e->next;
    }
    pthread_mutex_unlock(&g_tracked_mutex);
}

/* 注入状态查询：返回 pid 是否处于已注入状态（tracked 且 injected） */
bool is_injected(int pid) {
    bool injected = false;
    pthread_mutex_lock(&g_tracked_mutex);
    unsigned int h = hash_pid(pid);
    TrackedEntry *e = g_tracked_hash[h];
    while (e) {
        if (e->pid == pid) {
            injected = e->injected;
            break;
        }
        e = e->next;
    }
    pthread_mutex_unlock(&g_tracked_mutex);
    return injected;
}

bool is_tracked(int pid) {
    pthread_mutex_lock(&g_tracked_mutex);
    unsigned int h = hash_pid(pid);
    TrackedEntry *e = g_tracked_hash[h];
    while (e) {
        if (e->pid == pid) {
            pthread_mutex_unlock(&g_tracked_mutex);
            return true;
        }
        e = e->next;
    }
    pthread_mutex_unlock(&g_tracked_mutex);
    return false;
}

void remove_tracked(int pid) {
    pthread_mutex_lock(&g_tracked_mutex);
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
    pthread_mutex_unlock(&g_tracked_mutex);
}

static void prune_stale_tracked() {
    pthread_mutex_lock(&g_tracked_mutex);
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
    pthread_mutex_unlock(&g_tracked_mutex);
}

/* 生命周期清理入口：清除已退出应用的追踪缓存（被动模式禁用周期扫描后，
   prune_stale_tracked 无自动调用时机，由 IPC 通知路径主动触发） */
void cleanup_stale_tracked(void) {
    prune_stale_tracked();
}

/* ================= 全量应用 PID 缓存 =================
   非被动模式下每次扫描刷新：缓存所有 zygote 子进程（含已停用/未追踪
   的应用），便于规则变化时快速定位 pid 立即挂载，无需等待应用重启
   或下一次扫描。 */

#define ALL_APPS_HASH_SIZE 2048
typedef struct AllAppEntry {
    int pid;
    uid_t uid;
    char cmdline[256];
    struct AllAppEntry *next;
} AllAppEntry;

static AllAppEntry *g_all_apps_hash[ALL_APPS_HASH_SIZE];
static pthread_mutex_t g_all_apps_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned int hash_app_pid(int pid) {
    return ((unsigned int)pid * 2654435761u) % ALL_APPS_HASH_SIZE;
}

void all_apps_upsert(int pid, uid_t uid, const char* cmdline) {
    if (pid <= 0 || !cmdline) return;
    pthread_mutex_lock(&g_all_apps_mutex);
    unsigned int h = hash_app_pid(pid);
    AllAppEntry *e = g_all_apps_hash[h];
    while (e) {
        if (e->pid == pid) {
            e->uid = uid;
            strncpy(e->cmdline, cmdline, sizeof e->cmdline - 1);
            e->cmdline[sizeof e->cmdline - 1] = '\0';
            pthread_mutex_unlock(&g_all_apps_mutex);
            return;
        }
        e = e->next;
    }
    e = malloc(sizeof *e);
    if (e) {
        e->pid = pid;
        e->uid = uid;
        strncpy(e->cmdline, cmdline, sizeof e->cmdline - 1);
        e->cmdline[sizeof e->cmdline - 1] = '\0';
        e->next = g_all_apps_hash[h];
        g_all_apps_hash[h] = e;
    }
    pthread_mutex_unlock(&g_all_apps_mutex);
}

/* 按包名查找存活的运行中应用（fnmatch 匹配完整 cmdline，支持 :process 后缀）。
   用于规则变化响应快速定位 pid。 */
bool all_apps_find_by_cmdline(const char* pkg, int* pid_out, uid_t* uid_out) {
    if (!pkg) return false;
    bool found = false;
    pthread_mutex_lock(&g_all_apps_mutex);
    for (int i = 0; i < ALL_APPS_HASH_SIZE && !found; i++) {
        AllAppEntry *e = g_all_apps_hash[i];
        while (e) {
            if (kill(e->pid, 0) == 0 && fnmatch(pkg, e->cmdline, 0) == 0) {
                if (pid_out) *pid_out = e->pid;
                if (uid_out) *uid_out = e->uid;
                found = true;
                break;
            }
            e = e->next;
        }
    }
    pthread_mutex_unlock(&g_all_apps_mutex);
    return found;
}

/* 移除已死进程（扫描刷新时清理，保留存活项） */
void all_apps_prune(void) {
    pthread_mutex_lock(&g_all_apps_mutex);
    for (int i = 0; i < ALL_APPS_HASH_SIZE; i++) {
        AllAppEntry **pp = &g_all_apps_hash[i];
        while (*pp) {
            if (kill((*pp)->pid, 0) != 0) {
                AllAppEntry *tmp = *pp;
                *pp = (*pp)->next;
                free(tmp);
            } else {
                pp = &(*pp)->next;
            }
        }
    }
    pthread_mutex_unlock(&g_all_apps_mutex);
}

/* 释放全部节点（进程退出清理） */
void all_apps_cleanup(void) {
    pthread_mutex_lock(&g_all_apps_mutex);
    for (int i = 0; i < ALL_APPS_HASH_SIZE; i++) {
        AllAppEntry *e = g_all_apps_hash[i];
        while (e) {
            AllAppEntry *tmp = e;
            e = e->next;
            free(tmp);
        }
        g_all_apps_hash[i] = NULL;
    }
    pthread_mutex_unlock(&g_all_apps_mutex);
}

static UidMapEntry *g_uid_map = NULL;
static int g_uid_map_count = 0;
static int g_uid_map_cap = 0;

/* uid_map_upsert 失败的 UID 集合，避免反复重试 */
#define MAX_FAILED_UIDS 64
static uid_t g_failed_uids[MAX_FAILED_UIDS];
static int g_failed_uid_count = 0;

static bool uid_has_failed(uid_t uid) {
    for (int i = 0; i < g_failed_uid_count; i++) {
        if (g_failed_uids[i] == uid) return true;
    }
    return false;
}

static void uid_mark_failed(uid_t uid) {
    if (uid_has_failed(uid)) return;
    if (g_failed_uid_count < MAX_FAILED_UIDS)
        g_failed_uids[g_failed_uid_count++] = uid;
}

void init_uid_map_cache(void) {
    /* 初次分配：从 UID_MAP_INIT_CAPACITY 开始，读取文件，若不够则翻倍重试 */
    int cap = UID_MAP_INIT_CAPACITY;
    g_uid_map = malloc((size_t)cap * sizeof(UidMapEntry));
    if (!g_uid_map) {
        LOG_ERR("uid_map_cache: malloc(%d) 失败", cap);
        g_uid_map_count = 0;
        g_uid_map_cap = 0;
        return;
    }
    g_uid_map_count = uid_map_load(g_uid_map, cap);
    while (g_uid_map_count > 0 && g_uid_map_count == cap) {
        cap *= 2;
        UidMapEntry *new_map = realloc(g_uid_map, (size_t)cap * sizeof(UidMapEntry));
        if (!new_map) {
            LOG_ERR("uid_map_cache: realloc(%d) 失败", cap);
            free(g_uid_map);
            g_uid_map = NULL;
            g_uid_map_count = 0;
            g_uid_map_cap = 0;
            return;
        }
        g_uid_map = new_map;
        g_uid_map_count = uid_map_load(g_uid_map, cap);
    }
    g_uid_map_cap = cap;
    LOG_DBG("UID映射内存缓存已初始化: 从文件载入 %d 条映射记录 (容量 %d)", g_uid_map_count, g_uid_map_cap);
}

bool is_isolated_uid(uid_t uid) {
    uid_t app_id = uid % 100000;
    return (app_id >= 90000 && app_id <= 99999);
}

bool is_system_app(uid_t uid) {
    return (uid < 10000);
}

bool is_system_app_by_pkg(const char* cmdline, uid_t uid) {
    char base_pkg[256] = {0};
    if (cmdline && cmdline[0]) {
        strncpy(base_pkg, cmdline, sizeof(base_pkg) - 1);
        char* colon = strchr(base_pkg, ':');
        if (colon) *colon = '\0';
    }
    if (base_pkg[0] && is_system_pkg_cached(base_pkg)) {
        return true;
    }
    return is_system_app(uid);
}

bool is_process_safe_to_inject(const char* cmdline) {
    if (strstr(cmdline, "_zygote")) return false;
    if (strstr(cmdline, "com.google.android.webview")) return false;
    if (strstr(cmdline, "com.android.webview")) return false;
    if (strstr(cmdline, "injector")) return false;
    if (strstr(cmdline, "fuse_daemon")) return false;
    if (strstr(cmdline, "usap")) return false;
    return true;
}


bool is_zygote_child(pid_t pid) {
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
    /* 类别段点名（[USER_APPS[:uid]] / [SYSTEM_APPS]）：与应用段同优先级——
       显式 OFF 否决注入（含通配/全局），有实质规则则直接判为目标（点名即
       注入，跳过下方 SKIP_SYSTEM_APPS 过滤）；空类别段（只有段头）透传 */
    bool is_sys = is_system_app_by_pkg(cmdline, uid);
    AppConfig* cat = find_category_cfg_locked(is_sys, user_id);
    if (cat) {
        if (!cat->inject_enable) return false;
        if (category_has_rules_locked(is_sys, user_id)) return true;
    }
    if (has_wildcard_enabled_locked(user_id)) return true;
    if (g_global_cfg.global_inject && !is_isolated_uid(uid) && !strstr(cmdline, "zygote")) {
        /* 默认跳过系统应用，pm list packages -s 查询失败时回退到 uid < 10000 */
        if (g_global_cfg.skip_system_apps && is_system_app_by_pkg(cmdline, uid)) return false;
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
    if (uid_has_failed(uid)) return;
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
    int ret = uid_map_upsert(uid, clean_pkg);
    if (ret != 0) {
        const char *reason = "未知错误";
        if (ret == UID_MAP_ERR_FULL) reason = "条目已满(>1024)";
        else if (ret == UID_MAP_ERR_IO) reason = "文件写入失败";
        else if (ret == UID_MAP_ERR_RENAME) reason = "原子重命名失败";
        LOG_ERR("uid_map_upsert 失败: %u -> %s (%s)", uid, clean_pkg, reason);
        uid_mark_failed(uid);
        return;
    }
    /* 3. 同步更新内存缓存 */
    bool updated = false;
    for (int i = 0; i < g_uid_map_count; i++) {
        if (g_uid_map[i].uid == uid) {
            strncpy(g_uid_map[i].pkg, clean_pkg, 127);
            g_uid_map[i].pkg[127] = '\0';
            updated = true;
            break;
        }
    }
    if (!updated) {
        if (g_uid_map_count >= g_uid_map_cap) {
            /* 缓存容量不够，动态扩容 */
            int new_cap = g_uid_map_cap ? g_uid_map_cap * 2 : UID_MAP_INIT_CAPACITY;
            UidMapEntry *new_map = realloc(g_uid_map, (size_t)new_cap * sizeof(UidMapEntry));
            if (!new_map) {
                LOG_ERR("update_uid_map: realloc(%d) 失败，无法缓存 %s", new_cap, clean_pkg);
                return;
            }
            g_uid_map = new_map;
            g_uid_map_cap = new_cap;
        }
        g_uid_map[g_uid_map_count].uid = uid;
        strncpy(g_uid_map[g_uid_map_count].pkg, clean_pkg, 127);
        g_uid_map[g_uid_map_count].pkg[127] = '\0';
        g_uid_map_count++;
        LOG_DBG("UID内存映射已更新 (新增记录): %u -> %s", uid, clean_pkg);
    }
}

void cleanup_app_mounts(int pid, const char* target_path, const char* backup_path, uid_t uid) {
    /* 卸载 FUSE 挂载 */
    for (int t = 0; t < 3 && (ns_is_mounted(pid, target_path, "fuse.fuse_daemon") > 0 || ns_is_mounted(pid, target_path, "fuse_daemon") > 0); t++) {
        ns_umount_recursive(pid, target_path);
    }
    for (int t = 0; t < 3 && (ns_is_mounted(pid, backup_path, "fuse.fuse_daemon") > 0 || ns_is_mounted(pid, backup_path, "fuse_daemon") > 0); t++) {
        ns_umount_recursive(pid, backup_path);
    }
    /* 原始注入方案：从备份恢复或从 init 命名空间重建 */
    if (ns_is_mounted(pid, backup_path, nullptr) > 0) {
        ns_bind_mount(pid, backup_path, target_path);
        ns_umount_recursive(pid, backup_path);
    }
    if (ns_is_mounted(pid, target_path, nullptr) <= 0) {
        char init_src[256];
        snprintf(init_src, sizeof(init_src), "/proc/1/root%s", target_path);
        ns_bind_mount(pid, init_src, target_path);
    }
    /* 卸载/还原即解除注入状态（显式标志清除，列表不再误报） */
    unmark_injected(pid);
}

void force_recover_tracked_mounts() {
    if (g_global_replace_mode) {
        /* 全局替换模式：系统 emulated 视图由 ns_global_restore_system 统一还原，
           逐应用旧式 cleanup_app_mounts 会造成重复/冲突卸载，此处仅清理追踪表 */
        LOG_DBG("全局替换模式: force_recover 跳过逐应用卸载，由全局恢复统一处理");
    } else {
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
                    cleanup_app_mounts(pid, target_path, backup_path, uid);
                }
                e = e->next;
            }
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
            bool has_fuse = is_project_fuse_cached(pid, target_path);
            /* 注入标志与"是否仍为目标应用"对齐：解挂动作依赖 has_fuse 探测，
               而该探测在全局替换模式下可能误判（dev 匹配失败、挂载缓存过期）。
               若只在 has_fuse 为真的分支里 unmark，GLOBAL_INJECT ON→OFF 后
               一旦探测失手，标志就永远清不掉——list-injected 以显式标志为唯一
               权威，会把早已非目标的应用一直报成已注入。故先按配置判定无条件
               校正标志，再按探测结果执行实际解挂/挂载 */
            if (!is_target && is_injected(pid)) {
                unmark_injected(pid);
                LOG_DBG("配置审查: %s (PID: %d) 已非注入目标，清除注入标志。", cmd, pid);
            }
            if (!is_target && has_fuse) {
                if (g_global_replace_mode) {
                    /* 全局替换模式：非目标应用需卸载项目 FUSE 并还原系统视图备份 */
                    perform_app_restore(cmd, pid, uid);
                } else {
                    char backup_path[PATH_MAX];
                    snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/storage");
                    cleanup_app_mounts(pid, target_path, backup_path, uid);
                }
                LOG_DBG("配置审查: %s (PID: %d) 已取消注入，视图已安全解挂恢复，继续保持运行追踪。", cmd, pid);
            } else if (is_target && !has_fuse) {
                if (g_global_replace_mode) {
                    /* 全局替换模式：目标应用已由全局替换自动获得代理视图，无需逐应用挂载 */
                    LOG_DBG("配置审查: %s (PID: %d) 全局替换模式，目标应用无需逐应用挂载。", cmd, pid);
                } else {
                    const char* mnt_src = get_active_mnt_src();
                    if (mnt_src) {
                        perform_app_mount(cmd, pid, uid, mnt_src, "配置审查重新挂载");
                    }
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
                bool is_target = is_target_app(cmd, uid, pid, false);
                if (g_global_replace_mode) {
                    /* 全局替换模式：目标应用已由全局替换自动获得代理视图，无需逐应用挂载；
                       非目标应用需主动卸载项目 FUSE 并还原系统视图备份 */
                    if (is_target) {
                        LOG_DBG("局部规则审查: 全局替换模式，目标应用 %s (PID: %d) 无需逐应用挂载。", cmd, pid);
                    } else {
                        perform_app_restore(cmd, pid, uid);
                        LOG_DBG("局部规则审查: 全局替换模式，非目标应用 %s (PID: %d) 已还原系统视图。", cmd, pid);
                    }
                } else {
                    char target_path[128];
                    get_target_storage_path(uid, target_path, sizeof(target_path));
                    char backup_path[PATH_MAX];
                    snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/storage");
                    cleanup_app_mounts(pid, target_path, backup_path, uid);
                    if (is_target && mnt_src) {
                        LOG_DBG("局部规则审查: 受到变动影响的应用 %s (PID: %d) 进行重新挂载。", cmd, pid);
                        perform_app_mount(cmd, pid, uid, mnt_src, "局部规则变动重新挂载");
                    } else {
                        LOG_DBG("局部规则审查: 受到变动影响的应用 %s (PID: %d) 已清空还原物理挂载，保持物理追踪监听。", cmd, pid);
                    }
                }
            }
            // 安全保留追踪节点。由于 add_tracked 的无副作用性（若 PID 重复则不改变任何链表指针），
            // 直接进行 pp 后移是 100% 内存安全的，杜绝了重置外层大循环（i = -1）产生的多余 CPU 轮转
            pp = &(*pp)->next;
        }
    }
    /* 缓存补充：变更包不在追踪列表（如曾被停用的应用）时，从全量应用
       缓存快速定位运行中的 pid 立即挂载，无需等待应用重启或下次扫描 */
    for (int c = 0; c < count; c++) {
        int pid = 0;
        uid_t uid = 0;
        if (!all_apps_find_by_cmdline(changed[c].pkg_name, &pid, &uid)) continue;
        if (is_tracked(pid)) continue;   /* 追踪列表已处理 */
        char cmd[256] = {0};
        if (!proc_get_cmdline(pid, cmd, sizeof cmd)) continue;
        int user_id = uid / 100000;
        if (changed[c].user_id != -1 && changed[c].user_id != user_id) continue;
        if (!is_target_app(cmd, uid, pid, false)) continue;
        char target_path[128];
        get_target_storage_path(uid, target_path, sizeof target_path);
        bool has_fuse = is_project_fuse_cached(pid, target_path);
        if (has_fuse) continue;
        if (mnt_src) {
            add_tracked(pid);
            perform_app_mount(cmd, pid, uid, mnt_src, "缓存快速响应规则变化");
            LOG("缓存响应: %s (PID: %d) 规则启用，立即挂载", cmd, pid);
        }
    }
}

void handle_list_injected(int client_fd) {
    /* 动态缓冲：tracked 应用可达数百，固定 4096 会截断后段 APP 行与 DONE 行，
       导致 log_ctl 端"共计 0 个"误报（DONE 解析失败） */
    size_t cap = 4096;
    char* reply = malloc(cap);
    if (!reply) { send(client_fd, "DONE|0\n", 7, MSG_NOSIGNAL); return; }
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
            /* 注入状态以显式标志为权威：不再探测 mountinfo（GLOBAL_INJECT
               下全局替换无逐应用挂载/异步挂载时序会导致 is_project_fuse_cached
               误判），也不再二次跑 is_target_app（注入路径已判定过）——
               mark_injected 只在注入成功路径置位，还原/卸载路径已清除 */
            if (!is_injected(pid)) {
                e = e->next;
                continue;
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
            int n = snprintf(nullptr, 0, "APP|%s|%d|%u|%d|%d|%d\n",
                             base_pkg, pid, uid, total_redir, total_hide, total_ro);
            if (n > 0) {
                if ((size_t)offset + n + 1 > cap) {
                    cap = ((size_t)offset + n + 1) * 2;
                    char* nr = realloc(reply, cap);
                    if (!nr) break;
                    reply = nr;
                }
                offset += snprintf(reply + offset, cap - offset, "APP|%s|%d|%u|%d|%d|%d\n",
                                   base_pkg, pid, uid, total_redir, total_hide, total_ro);
            }
            total++;
            e = e->next;
        }
    }
    int dn = snprintf(nullptr, 0, "DONE|%d\n", total);
    if ((size_t)offset + dn + 1 > cap) {
        cap = (size_t)offset + dn + 1;
        char* nr = realloc(reply, cap);
        if (nr) reply = nr;
    }
    snprintf(reply + offset, cap - offset, "DONE|%d\n", total);
    send(client_fd, reply, strlen(reply), MSG_NOSIGNAL);
    free(reply);
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
            /* 与 handle_list_injected 一致：以显式注入标志为权威，
               不再探测 mountinfo（GLOBAL_INJECT 下挂载状态不可靠） */
            if (!is_injected(pid)) {
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

/*
 * 精确分析当前规则中 com.android.providers.media.module 是否真正属于注入目标。
 * 支持多用户 UID 解析。
 */
bool is_media_module_injected_target(void) {
    bool target = false;
    config_lock_read();
    
    // 1. 优先扫描活跃用户的专属规则
    for (int i = 0; i < g_active_user_count; i++) {
        int user_id = g_active_users[i];
        AppConfig* cfg = find_app_cfg_locked("com.android.providers.media.module", user_id);
        if (cfg) {
            if (cfg->inject_enable) {
                target = true;
                break;
            }
        } else {
            // 如果该用户下没有显式规则，则看是否命中了通配符 [*] 注入
            if (has_wildcard_enabled_locked(user_id)) {
                target = true;
                break;
            }
            /* 类别段点名：media 在不同设备可归系统/用户任一类，两类有实质
               规则（且段头启用）即视为注入目标 */
            AppConfig* ucat = find_category_cfg_locked(false, user_id);
            if (ucat && ucat->inject_enable && category_has_rules_locked(false, user_id)) {
                target = true;
                break;
            }
            AppConfig* scat = find_category_cfg_locked(true, user_id);
            if (scat && scat->inject_enable && category_has_rules_locked(true, user_id)) {
                target = true;
                break;
            }
            // 或者是全局注入方案开启
            if (g_global_cfg.global_inject) {
                target = true;
                break;
            }
        }
    }

    // 2. 无活跃用户时，回退到默认用户配置判定
    if (!target && g_global_cfg.global_inject) {
        AppConfig* cfg = find_app_cfg_locked("com.android.providers.media.module", 0);
        if (!cfg || cfg->inject_enable) {
            target = true;
        }
    }

    config_unlock_read();
    return target;
}