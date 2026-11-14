#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
    bool injected; /* 注入状态显式标志：注入成功路径置位，
                                   restore/卸载路径清除（稳定公共函数维护，
                                   列表不再依赖挂载状态探测） */
    struct TrackedEntry* next;
} TrackedEntry;

static TrackedEntry* g_tracked_hash[TRACKED_HASH_SIZE];
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
    TrackedEntry* e = g_tracked_hash[h];
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

    /* 此处不再预热挂载状态缓存（历史实现曾引入，现已无收益且有害）：
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
    add_tracked(pid); /* 确保条目存在（幂等） */
    pthread_mutex_lock(&g_tracked_mutex);
    unsigned int h = hash_pid(pid);
    TrackedEntry* e = g_tracked_hash[h];
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
    TrackedEntry* e = g_tracked_hash[h];
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
    TrackedEntry* e = g_tracked_hash[h];
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
    TrackedEntry* e = g_tracked_hash[h];
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
    TrackedEntry** pp = &g_tracked_hash[h];
    while (*pp) {
        if ((*pp)->pid == pid) {
            TrackedEntry* tmp = *pp;
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
        TrackedEntry** pp = &g_tracked_hash[i];
        while (*pp) {
            if (kill((*pp)->pid, 0) != 0) {
                TrackedEntry* tmp = *pp;
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

/* 追踪表 pid 快照：**锁内**复制 pid 列表，供调用方在**锁外**做重活
   （/proc 读取、mount/umount、config 判定）。三条遍历路径统一走它——
   直接裸遍历 g_tracked_hash 与 add_tracked/remove_tracked/prune_stale_tracked
   并发时，游标指向的 next 槽所属节点可能被释放，`pp = &(*pp)->next` 读到
   悬垂地址、下一次迭代解引用即 UAF；且这些路径本身要调 cleanup_app_mounts /
   perform_app_mount，它们内部会再取 g_tracked_mutex，持锁遍历必然自锁。

   返回 malloc 的数组，*n_out 为条数（空表返回 NULL 且 *n_out=0）；
   分配失败返回 NULL 且 *n_out=-1（调用方应放弃本轮，下次重试）。调用方 free。 */
static int* tracked_snapshot(int* n_out) {
    int* out = nullptr;
    int n = 0, cap = 0;
    pthread_mutex_lock(&g_tracked_mutex);
    for (int i = 0; i < TRACKED_HASH_SIZE; i++) {
        for (TrackedEntry* e = g_tracked_hash[i]; e; e = e->next) {
            if (n >= cap) {
                int ncap = cap > 0 ? cap * 2 : 16;
                int* grown = realloc(out, (size_t)ncap * sizeof *grown);
                if (!grown) {
                    pthread_mutex_unlock(&g_tracked_mutex);
                    free(out);
                    *n_out = -1;
                    return nullptr;
                }
                out = grown;
                cap = ncap;
            }
            out[n++] = e->pid;
        }
    }
    pthread_mutex_unlock(&g_tracked_mutex);
    *n_out = n;
    return out;
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
    struct AllAppEntry* next;
} AllAppEntry;

static AllAppEntry* g_all_apps_hash[ALL_APPS_HASH_SIZE];
static pthread_mutex_t g_all_apps_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned int hash_app_pid(int pid) {
    return ((unsigned int)pid * 2654435761u) % ALL_APPS_HASH_SIZE;
}

void all_apps_upsert(int pid, uid_t uid, const char* cmdline) {
    if (pid <= 0 || !cmdline) return;
    pthread_mutex_lock(&g_all_apps_mutex);
    unsigned int h = hash_app_pid(pid);
    AllAppEntry* e = g_all_apps_hash[h];
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
        AllAppEntry* e = g_all_apps_hash[i];
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
        AllAppEntry** pp = &g_all_apps_hash[i];
        while (*pp) {
            if (kill((*pp)->pid, 0) != 0) {
                AllAppEntry* tmp = *pp;
                *pp = (*pp)->next;
                free(tmp);
            } else {
                pp = &(*pp)->next;
            }
        }
    }
    pthread_mutex_unlock(&g_all_apps_mutex);
}

/* 全量应用注册表的 pid 快照：语义同 tracked_snapshot（锁内复制、锁外做重活）。
   返回 malloc 数组，空表返回 NULL 且 *n_out=0；分配失败返回 NULL 且 *n_out=-1。 */
static int* all_apps_snapshot(int* n_out) {
    int* out = nullptr;
    int n = 0, cap = 0;
    pthread_mutex_lock(&g_all_apps_mutex);
    for (int i = 0; i < ALL_APPS_HASH_SIZE; i++) {
        for (AllAppEntry* e = g_all_apps_hash[i]; e; e = e->next) {
            if (n >= cap) {
                int ncap = cap > 0 ? cap * 2 : 16;
                int* grown = realloc(out, (size_t)ncap * sizeof *grown);
                if (!grown) {
                    pthread_mutex_unlock(&g_all_apps_mutex);
                    free(out);
                    *n_out = -1;
                    return nullptr;
                }
                out = grown;
                cap = ncap;
            }
            out[n++] = e->pid;
        }
    }
    pthread_mutex_unlock(&g_all_apps_mutex);
    *n_out = n;
    return out;
}

/* 释放全部节点（进程退出清理） */
void all_apps_cleanup(void) {
    pthread_mutex_lock(&g_all_apps_mutex);
    for (int i = 0; i < ALL_APPS_HASH_SIZE; i++) {
        AllAppEntry* e = g_all_apps_hash[i];
        while (e) {
            AllAppEntry* tmp = e;
            e = e->next;
            free(tmp);
        }
        g_all_apps_hash[i] = NULL;
    }
    pthread_mutex_unlock(&g_all_apps_mutex);
}

static UidMapEntry* g_uid_map = NULL;
static int g_uid_map_count = 0;
static int g_uid_map_cap = 0;

/* uid_map_upsert 失败的 UID 集合，避免反复重试 */
#define MAX_FAILED_UIDS 64
static uid_t g_failed_uids[MAX_FAILED_UIDS];
static int g_failed_uid_count = 0;

/* g_uid_map / g_failed_uids 的互斥：update_uid_map 的调用方既有主线程
   （ipc_server 的 IPC 客户端处理），也有每次 IPC 通知 detach 出来的挂载线程
   （ipc_server.c 的 ipc_mount_thread 与 mount_manager），而它执行「线性查找 +
   落盘 upsert + realloc + count++」整套读改写——无锁在开机多应用并发上报时
   会 realloc 覆盖/悬垂或丢记录。初始化在 early_init 单线程完成，故
   init_uid_map_cache 不取锁。 */
static pthread_mutex_t g_uid_map_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool uid_has_failed(uid_t uid) {
    for (int i = 0; i < g_failed_uid_count; i++) {
        if (g_failed_uids[i] == uid) return true;
    }
    return false;
}

static void uid_mark_failed(uid_t uid) {
    if (uid_has_failed(uid)) return;
    if (g_failed_uid_count < MAX_FAILED_UIDS) g_failed_uids[g_failed_uid_count++] = uid;
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
        UidMapEntry* new_map = realloc(g_uid_map, (size_t)cap * sizeof(UidMapEntry));
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
    LOG_DBG("UID映射内存缓存已初始化: 从文件载入 %d 条映射记录 (容量 %d)", g_uid_map_count,
            g_uid_map_cap);
}

bool is_isolated_uid(uid_t uid) {
    uid_t app_id = uid % NSP_PER_USER_UID_STRIDE;
    return (app_id >= 90000 && app_id <= 99999);
}

bool is_system_app(uid_t uid) {
    return (uid < NSP_SYSTEM_APP_UID_MIN);
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
    if (strcmp(pcmd, "zygote") == 0 || strcmp(pcmd, "zygote64") == 0 ||
        strstr(pcmd, "zygote") != nullptr || strstr(pcmd, "usap") != nullptr)
        return true;
    return false;
}

/* 全局层的豁免：GLOBAL_INJECT（v1/v2）或 v3 全局挂载才算「全局覆盖到」，
   隔离进程与 zygote 一律排除。
   SKIP_SYSTEM_APPS 是这个全局层的作用域收窄项，只在全局层本身成立时才参与判定
   —— GLOBAL_INJECT 关闭时它不单独生效（否则等于给「没开全局注入」的配置
   凭空加一条跳过规则）。v3 是全局挂载，系统应用没有「不注入」这个选项，故跳过
   判定在 v3 下不适用。显式点名的应用段 / 类别段 / [*] 段各有自己的使能位，
   在到达这里之前就已经返回，不受这两个全局键影响。 */
static bool global_scope_covers_locked(const char* cmdline, uid_t uid) {
    if (!(g_inject_method == INJECT_METHOD_V3) && !g_global_cfg.global_inject) return false;
    if (is_isolated_uid(uid)) return false;
    if (strstr(cmdline, "zygote")) return false;
    if (g_inject_method != INJECT_METHOD_V3 && g_global_cfg.skip_system_apps &&
        is_system_app_by_pkg(cmdline, uid))
        return false;
    return true;
}

bool is_target_app_locked(const char* cmdline, uid_t uid, pid_t pid, bool from_ipc) {
    int user_id = uid / NSP_PER_USER_UID_STRIDE;
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
    /* 走到这里说明没有任何显式段命中该应用，归属全局层裁决 */
    if (!global_scope_covers_locked(cmdline, uid)) return false;
    if (from_ipc || is_zygote_child(pid)) return true;
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
    snprintf(path, size, "%s", NSP_ANDROID_EMULATED_ROOT);
}

/* 加锁实现（调用方须持 g_uid_map_mutex）：拆分只为让早退分支不必逐个解锁 */
static void update_uid_map_locked(uid_t uid, const char* pkg) {
    if (uid < NSP_SYSTEM_APP_UID_MIN || is_isolated_uid(uid)) return;
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
        const char* reason = "未知错误";
        if (ret == UID_MAP_ERR_FULL)
            reason = "条目已满(>1024)";
        else if (ret == UID_MAP_ERR_IO)
            reason = "文件写入失败";
        else if (ret == UID_MAP_ERR_RENAME)
            reason = "原子重命名失败";
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
            UidMapEntry* new_map = realloc(g_uid_map, (size_t)new_cap * sizeof(UidMapEntry));
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

void update_uid_map(uid_t uid, const char* pkg) {
    pthread_mutex_lock(&g_uid_map_mutex);
    update_uid_map_locked(uid, pkg);
    pthread_mutex_unlock(&g_uid_map_mutex);
}

void cleanup_app_mounts(int pid, const char* target_path, const char* backup_path, uid_t uid) {
    /* 卸载 FUSE 挂载 */
    for (int t = 0; t < 3 && (ns_is_mounted(pid, target_path, "fuse.fuse_daemon") > 0 ||
                              ns_is_mounted(pid, target_path, "fuse_daemon") > 0);
         t++) {
        ns_umount_recursive(pid, target_path);
    }
    for (int t = 0; t < 3 && (ns_is_mounted(pid, backup_path, "fuse.fuse_daemon") > 0 ||
                              ns_is_mounted(pid, backup_path, "fuse_daemon") > 0);
         t++) {
        ns_umount_recursive(pid, backup_path);
    }
    /* 原始注入方案：从备份恢复或从 init 命名空间重建 */
    if (ns_is_mounted(pid, backup_path, nullptr) > 0) {
        ns_bind_mount(pid, backup_path, target_path);
        ns_umount_recursive(pid, backup_path);
    }
    if (ns_is_mounted(pid, target_path, nullptr) <= 0) {
        /* 首选同 ns 族根重建：目标的系统视图就是族根的传播副本
           （/storage/emulated ← rbind /mnt/user/<uid>/emulated），族根在应用
           ns 内始终存活，直接 MS_REC bind 即可，完全不涉及跨 ns */
        char fam_src[PATH_MAX];
        int fr = ns_find_family_root(pid, uid, fam_src, sizeof(fam_src));
        if (fr == 0) {
            ns_bind_mount(pid, fam_src, target_path);
        } else {
            LOG_DBG("应用清理: 应用 ns 内无 uid %u 对应族根(rc=%d)，走跨 ns 兜底重建",
                    (unsigned)uid, fr);
        }
        if (ns_is_mounted(pid, target_path, nullptr) <= 0) {
            /* 兜底：应用 ns 内无可用族根（异常态）→ 拉 init 视图。mount(2) 源
               穿越被内核拒绝（EINVAL），须走 open_tree+move_mount */
            char init_src[256];
            snprintf(init_src, sizeof(init_src), "/proc/1/root%s", target_path);
            ns_bind_mount_cross(pid, init_src, target_path);
        }
    }
    /* 卸载/还原即解除注入状态（显式标志清除，列表不再误报） */
    unmark_injected(pid);
    /* 挂载状态缓存同步失效：cleanup 之后 is_project_fuse_cached 仍返回旧的
       「已挂载」快照时，热对账会认为无需重新挂载 → 配置改回来也不生效 */
    invalidate_app_mount_cache(pid);
}

void force_recover_tracked_mounts() {
    if (inject_is_global_replace()) {
        /* 注入方法 v2/v3（全局替换）：系统 emulated 视图由 ns_global_restore_system
           统一还原，逐应用旧式 cleanup_app_mounts 会造成重复/冲突卸载，
           此处仅清理追踪表 */
        LOG_DBG("全局替换: force_recover 跳过逐应用卸载，由全局恢复统一处理");
    } else {
        int n = 0;
        int* pids = tracked_snapshot(&n);
        for (int k = 0; pids && k < n; k++) {
            int pid = pids[k];
            if (kill(pid, 0) == 0) {
                uid_t uid = get_app_uid(pid);
                char target_path[128];
                get_target_storage_path(uid, target_path, sizeof(target_path));
                char backup_path[PATH_MAX];
                snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/storage");
                cleanup_app_mounts(pid, target_path, backup_path, uid);
            }
        }
        free(pids);
    }
    /* 整表摘除：必须在锁内（旧实现锁外 free，与并发 add_tracked 竞争：
       新节点可能刚挂上就被这轮 free 走，或摘除后残留悬垂桶头） */
    pthread_mutex_lock(&g_tracked_mutex);
    for (int i = 0; i < TRACKED_HASH_SIZE; i++) {
        TrackedEntry* e = g_tracked_hash[i];
        while (e) {
            TrackedEntry* tmp = e;
            e = e->next;
            free(tmp);
        }
        g_tracked_hash[i] = nullptr;
    }
    pthread_mutex_unlock(&g_tracked_mutex);
}

/* 核心优化：配置审查时，就算应用解除注入，只要进程依然物理存活，就必须保持哈希追踪监听 */
void audit_tracked_apps() {
    prune_stale_tracked();
    /* 锁内快照 → 锁外处理：本函数会调 cleanup_app_mounts / perform_app_mount /
       perform_app_restore，它们内部再取 g_tracked_mutex（持锁遍历必自锁），
       而裸遍历又会被并发的 add_tracked/remove_tracked 摘链致 UAF。 */
    int n = 0;
    int* pids = tracked_snapshot(&n);
    for (int k = 0; pids && k < n; k++) {
        {
            int pid = pids[k];
            char cmd[256] = {0};
            if (!proc_get_cmdline(pid, cmd, sizeof(cmd))) {
                remove_tracked(pid); /* 锁内摘除（快照遍历下不得直接改链） */
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
                if (inject_restore_nontarget()) {
                    /* 注入方法 v2：非目标应用需卸载项目 FUSE 并还原系统视图备份 */
                    perform_app_restore(cmd, pid, uid);
                    LOG_DBG(
                            "配置审查: %s (PID: %d) 已取消注入，视图已安全解挂恢复，继续保持运行追踪。",
                            cmd, pid);
                } else if (inject_is_global_replace()) {
                    /* 注入方法 v3：不对非目标应用还原/卸载，保持全局代理视图 */
                    LOG_DBG("配置审查(v3): %s (PID: %d) 非目标应用保持全局代理视图，不还原。", cmd,
                            pid);
                } else {
                    char backup_path[PATH_MAX];
                    snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/storage");
                    cleanup_app_mounts(pid, target_path, backup_path, uid);
                    LOG_DBG(
                            "配置审查: %s (PID: %d) 已取消注入，视图已安全解挂恢复，继续保持运行追踪。",
                            cmd, pid);
                }
            } else if (is_target && !has_fuse) {
                if (inject_restore_nontarget()) {
                    /* v2：非目标应用此前已被 perform_app_restore 还原为系统视图，
                       配置 OFF→ON 后必须重新执行逐应用挂载，否则该应用整个生命周期
                       都没有代理视图（列表却显示已注入）。不能像 v3 那样跳过——
                       v2 的"非目标即还原"策略让"非目标→目标"成为真实的视图迁移。 */
                    const char* mnt_src = get_active_mnt_src();
                    if (mnt_src) {
                        LOG("配置审查(v2): %s (PID: %d) 重新接入代理视图（非目标→目标）", cmd,
                            pid);
                        perform_app_mount(cmd, pid, uid, mnt_src, "配置审查重新挂载");
                    } else {
                        LOG_ERR(
                                "配置审查(v2): 全局 FUSE 不可用，无法为 %s (PID: %d) 恢复代理视图",
                                cmd, pid);
                    }
                } else if (inject_is_global_replace()) {
                    /* v3：从不还原非目标应用，全局视图由替换保证，无需逐应用挂载 */
                    LOG_DBG("配置审查(v3): %s (PID: %d) 全局替换模式，目标应用无需逐应用挂载。",
                            cmd, pid);
                } else {
                    const char* mnt_src = get_active_mnt_src();
                    if (mnt_src) {
                        perform_app_mount(cmd, pid, uid, mnt_src, "配置审查重新挂载");
                    }
                }
            }
        }
    }
    free(pids);
}

/* 核心优化：局部规则发生变化时，解除注入仅做解挂视图动作，绝对保留 PID 节点的物理追踪 */
void audit_and_remount_specific_apps(ChangedPkg* changed, int count) {
    prune_stale_tracked();
    const char* mnt_src = get_active_mnt_src();
    int n = 0;
    int* pids = tracked_snapshot(&n);
    for (int k = 0; pids && k < n; k++) {
        {
            int pid = pids[k];
            char cmd[256] = {0};
            if (!proc_get_cmdline(pid, cmd, sizeof(cmd))) {
                remove_tracked(pid); /* 锁内摘除（快照遍历下不得直接改链） */
                continue;
            }
            uid_t uid = get_app_uid(pid);
            int user_id = uid / NSP_PER_USER_UID_STRIDE;
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
                if (inject_is_global_replace()) {
                    /* 全局替换（v2/v3）：目标应用已由全局替换自动获得代理视图，无需逐应用挂载；
                       非目标应用仅 v2 主动卸载项目 FUSE 并还原系统视图备份，
                       v3 一律不还原（默认全局挂载，含系统应用） */
                    if (is_target) {
                        if (inject_restore_nontarget()) {
                            /* v2：该应用可能刚在配置 OFF 期间被还原（顶层已是系统
                               视图），此处必须重新执行逐应用挂载，否则 OFF→ON 不生效；
                               已处于代理视图的应用跳过（幂等）。 */
                            char target_path[128];
                            get_target_storage_path(uid, target_path, sizeof target_path);
                            const char* mnt_src = get_active_mnt_src();
                            if (is_project_fuse_cached(pid, target_path)) {
                                LOG_DBG(
                                    "局部规则审查(v2): %s (PID: %d) 已在代理视图，无需重新挂载",
                                    cmd, pid);
                            } else if (mnt_src) {
                                LOG(
                                    "局部规则审查(v2): %s (PID: %d) 重新接入代理视图"
                                    "（非目标→目标）",
                                    cmd, pid);
                                perform_app_mount(cmd, pid, uid, mnt_src,
                                                  "局部规则变动重新挂载");
                            } else {
                                LOG_ERR(
                                    "局部规则审查(v2): 全局 FUSE 不可用，无法为 %s (PID: %d) "
                                    "恢复代理视图",
                                    cmd, pid);
                            }
                        } else {
                            /* v3：从不还原非目标应用，全局视图由替换保证 */
                            LOG_DBG(
                                "局部规则审查(v3): 全局替换模式，目标应用 %s (PID: %d) 无需逐应用"
                                "挂载。",
                                cmd, pid);
                        }
                    } else if (inject_restore_nontarget()) {
                        perform_app_restore(cmd, pid, uid);
                        LOG_DBG(
                            "局部规则审查: 全局替换模式，非目标应用 %s (PID: %d) 已还原系统视图。",
                            cmd, pid);
                    } else {
                        LOG_DBG(
                            "局部规则审查(v3): 非目标应用 %s (PID: %d) 保持全局代理视图，不还原。",
                            cmd, pid);
                    }
                } else {
                    char target_path[128];
                    get_target_storage_path(uid, target_path, sizeof(target_path));
                    char backup_path[PATH_MAX];
                    snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/storage");
                    cleanup_app_mounts(pid, target_path, backup_path, uid);
                    if (is_target && mnt_src) {
                        LOG_DBG("局部规则审查: 受到变动影响的应用 %s (PID: %d) 进行重新挂载。", cmd,
                                pid);
                        perform_app_mount(cmd, pid, uid, mnt_src, "局部规则变动重新挂载");
                    } else {
                        LOG_DBG(
                            "局部规则审查: 受到变动影响的应用 %s (PID: %d) 已清空还原物理挂载，保持物理追踪监听。",
                            cmd, pid);
                    }
                }
            }
        }
    }
    free(pids);
    /* 缓存补充：变更包不在追踪列表（如曾被停用的应用）时，从全量应用
       缓存快速定位运行中的 pid 立即挂载，无需等待应用重启或下次扫描 */
    for (int c = 0; c < count; c++) {
        int pid = 0;
        uid_t uid = 0;
        if (!all_apps_find_by_cmdline(changed[c].pkg_name, &pid, &uid)) continue;
        if (is_tracked(pid)) continue; /* 追踪列表已处理 */
        char cmd[256] = {0};
        if (!proc_get_cmdline(pid, cmd, sizeof cmd)) continue;
        int user_id = uid / NSP_PER_USER_UID_STRIDE;
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

/* ================= 配置热对账（v1 逐应用挂载的实时生效路径） =================
   语义：运行中的应用也要立即跟随配置变化，不许要求先杀进程（V1 挂载模式下
   最明显）。旧实现只在 reload_config_rules_diff 判出「应用段
   inject_enable 翻转 / 全局开关变化」时才动挂载：规则内容变化、类别段与
   App-rules 子文件的增删都被判成 changed_count==0 → handle_pending_reload
   什么都不做；而被动模式（真机必有 zygisk 上报）停掉周期扫描后，运行中的应用
   也从未被登记，即使想动挂载也找不到 pid。

   本函数在**每次**配置重载后对运行中应用做一次全量对账：
     期望视图 want = is_target_app() && app_has_active_rules()
   （后者与 perform_app_mount 的「无规则冲突 → 保留原生视图」语义对齐，故
   「删掉最后一条规则」也会被正确收回，这正是「删了规则还得杀进程」的现场）
     want 且实测无 → perform_app_mount（热挂载）
     !want 且实测有 → cleanup_app_mounts（热卸载并还原原生族根视图）
   候选集 = 追踪表快照 ∪ 全量应用注册表快照（后者由 IPC 通知路径填充，是唯一
   能覆盖「已在运行、之后才被配成目标」的来源）。逐 pid 幂等：已就绪不动；
   单条动作有界、失败只记日志，绝不中断主循环。v2/v3 不走本函数（全局替换 +
   还原策略，见 audit_tracked_apps / audit_and_remount_specific_apps）。 */
void audit_running_apps(void) {
    all_apps_prune();
    int tn = 0;
    int* tracked = tracked_snapshot(&tn);
    if (tn < 0) {
        free(tracked);
        return; /* 内存不足：放弃本轮，下次重载再对账 */
    }
    int rn = 0;
    int* known = all_apps_snapshot(&rn);
    size_t cap = (size_t)(tn > 0 ? tn : 0) + (size_t)(rn > 0 ? rn : 0);
    int* pids = cap > 0 ? malloc(cap * sizeof *pids) : nullptr;
    size_t n = 0;
    if (pids) {
        for (int k = 0; k < tn; k++) pids[n++] = tracked[k];
        for (int k = 0; k < rn; k++) {
            bool dup = false;
            for (size_t j = 0; j < n; j++) {
                if (pids[j] == known[k]) {
                    dup = true;
                    break;
                }
            }
            if (!dup) pids[n++] = known[k];
        }
    }
    free(tracked);
    free(known);
    if (!pids) return;

    const char* mnt_src = get_active_mnt_src();
    int mounted = 0, unmounted = 0;
    for (size_t k = 0; k < n; k++) {
        int pid = pids[k];
        char cmd[256] = {0};
        if (!proc_get_cmdline(pid, cmd, sizeof(cmd))) continue; /* 死进程由 prune 清账 */
        uid_t uid = get_app_uid(pid);
        bool want = is_target_app(cmd, uid, pid, false) && app_has_active_rules(cmd, uid);
        char target_path[128];
        get_target_storage_path(uid, target_path, sizeof(target_path));
        /* 先丢陈旧快照再探测：本函数紧跟在挂载/卸载动作之后做判定，缓存命中
           会让「刚卸掉」仍被判成已挂载（反之亦然），热挂载/热卸载就永远对不上 */
        invalidate_app_mount_cache(pid);
        bool has_fuse = is_project_fuse_cached(pid, target_path);
        if (want && !has_fuse) {
            if (!mnt_src) {
                LOG_DBG("配置热对账: 全局 FUSE 未就绪，跳过 %s(PID:%d) 的热挂载", cmd, pid);
                continue;
            }
            if (perform_app_mount(cmd, pid, uid, mnt_src, "配置热对账挂载") == 0) mounted++;
        } else if (!want && has_fuse) {
            char backup_path[PATH_MAX];
            snprintf(backup_path, sizeof(backup_path), BACKUP_DIR "/storage");
            cleanup_app_mounts(pid, target_path, backup_path, uid);
            unmounted++;
        }
    }
    free(pids);
    /* 一条汇总日志，不逐条刷屏（真实设备上候选可达数十个） */
    if (mounted > 0 || unmounted > 0) {
        LOG("配置热对账: 运行中应用热挂载 %d 个、热卸载 %d 个（候选 %zu 个）", mounted,
            unmounted, n);
    } else {
        LOG_DBG("配置热对账: 运行中应用视图均无需变更（候选 %zu 个）", n);
    }
}

void handle_list_injected(int client_fd) {
    /* 动态缓冲：tracked 应用可达数百，固定 4096 会截断后段 APP 行与 DONE 行，
       导致 log_ctl 端"共计 0 个"误报（DONE 解析失败） */
    size_t cap = 4096;
    char* reply = malloc(cap);
    if (!reply) {
        send(client_fd, "DONE|0\n", 7, MSG_NOSIGNAL);
        return;
    }
    int offset = 0;
    int total = 0;
    /* 锁内快照 → 锁外遍历：本函数在遍历中调 config_lock_read 与 /proc 读取，
       而并发的 add_tracked/remove_tracked 会摘链释放节点 → 裸遍历的
       `e = e->next` 读到悬垂地址（A25 同类缺陷，一并收敛到 tracked_snapshot） */
    int np = 0;
    int* pids = tracked_snapshot(&np);
    for (int k = 0; pids && k < np; k++) {
        {
            int pid = pids[k];
            if (kill(pid, 0) != 0) continue;
            char cmdline[256] = {0};
            if (!proc_get_cmdline(pid, cmdline, sizeof(cmdline))) continue;
            uid_t uid = get_app_uid(pid);
            /* 注入状态以显式标志为权威：不再探测 mountinfo（GLOBAL_INJECT
               下全局替换无逐应用挂载/异步挂载时序会导致 is_project_fuse_cached
               误判），也不再二次跑 is_target_app（注入路径已判定过）——
               mark_injected 只在注入成功路径置位，还原/卸载路径已清除 */
            if (!is_injected(pid)) continue;
            char base_pkg[256];
            strncpy(base_pkg, cmdline, sizeof(base_pkg) - 1);
            char* colon = strchr(base_pkg, ':');
            if (colon) *colon = '\0';
            int app_redir = 0, app_hide = 0, app_ro = 0;
            config_lock_read();
            AppConfig* cfg = find_app_cfg_locked(cmdline, uid / NSP_PER_USER_UID_STRIDE);
            if (cfg) {
                app_redir = cfg->redir_count;
                app_hide = cfg->hide_count;
                app_ro = cfg->ro_count;
            }
            int total_redir = app_redir + g_global_cfg.redir_count;
            int total_hide = app_hide + g_global_cfg.hide_count;
            int total_ro = app_ro + g_global_cfg.ro_count;
            config_unlock_read();
            int n = snprintf(nullptr, 0, "APP|%s|%d|%u|%d|%d|%d\n", base_pkg, pid, uid, total_redir,
                             total_hide, total_ro);
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
        }
    }
    free(pids);
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

int get_injected_snapshot(int* out_pids, char (*out_pkgs)[256], uid_t* out_uids, int max_count) {
    int count = 0;
    /* 锁内快照 → 锁外遍历（同 handle_list_injected：并发摘链会致悬垂） */
    int np = 0;
    int* pids = tracked_snapshot(&np);
    for (int k = 0; pids && k < np && count < max_count; k++) {
        {
            int pid = pids[k];
            if (kill(pid, 0) != 0) continue;
            char cmdline[256] = {0};
            if (!proc_get_cmdline(pid, cmdline, sizeof(cmdline))) continue;
            uid_t uid = get_app_uid(pid);
            /* 与 handle_list_injected 一致：以显式注入标志为权威，
               不再探测 mountinfo（GLOBAL_INJECT 下挂载状态不可靠） */
            if (!is_injected(pid)) continue;
            char base_pkg[256];
            strncpy(base_pkg, cmdline, sizeof(base_pkg) - 1);
            base_pkg[sizeof(base_pkg) - 1] = '\0';
            char* colon = strchr(base_pkg, ':');
            if (colon) *colon = '\0';
            out_pids[count] = pid;
            strncpy(out_pkgs[count], base_pkg, 255);
            out_pkgs[count][255] = '\0';
            out_uids[count] = uid;
            count++;
        }
    }
    free(pids);
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