#define _GNU_SOURCE
#include "br_rules.h"
#include "nsp_module.h"       /* LOG_*、g_log_shutdown、g_real_root、STORAGE_BASE 等 */
#include "path_vars.h"
#include "uid_map.h"
#include "fast_pid.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fnmatch.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/inotify.h>
#include <poll.h>

/* ============ 模块内部状态（从 vfs_core.c 适配，不再依赖 fuse_context） ============ */

static char g_br_rules_path[PATH_MAX] = {0};
static bool g_br_disable_sandbox = false;
/* 模块退出标志与监控线程句柄：exit 时置标志并 join，确保 dlclose 前线程已退出
   （否则线程仍在已卸载的 .so 代码页中运行 → SIGSEGV） */
static volatile bool g_br_stop = false;
static pthread_t g_br_monitor_tid;

#define UID_CACHE_SIZE 2048
typedef struct {
    pthread_mutex_t lock;
    uid_t uid;
    AppConfig* cfg;
    char pkg[128];
} UidCacheSlot;
static UidCacheSlot g_uid_cache[UID_CACHE_SIZE];
static UidMapEntry *g_uid_maps = NULL;
static int g_uid_map_count = 0;

/* ============ readdir 目录级 probe 缓存 ============
   br_probe 是 readdir 逐条目过滤的热路径：同一父目录的连续条目共享一次
   「根→父目录」trie 下降与 uid→cfg 解析，命中后仅按最后一段查子节点，
   避免每条目重复全路径 trie 遍历与 uid 缓存锁（大目录 O(n) 锁风暴）。
   线程私有（FUSE 多线程各自独立，readdir 循环在单线程内顺序执行）；
   配置重载（g_br_cfg_gen 递增，写锁内）后失效，杜绝 trie/cfg 悬垂。 */
typedef struct {
    bool valid;
    uint64_t gen;              /* 配置代际（br_reload_config 递增） */
    uid_t uid;
    pid_t pid;
    char dir[PATH_MAX];        /* 父目录 sub_path（"/" 或 "/a/b"） */
    AppConfig* cfg;            /* 命中的应用段（可 NULL=system） */
    char current_pkg[128];
    const TrieNode* app_dir_node;   /* app trie 父目录最深节点（可 NULL） */
    bool app_dir_hidden;            /* 根→父目录累积 hidden（app） */
    const TrieNode* g_dir_node;     /* global trie 父目录最深节点（可 NULL） */
    bool g_dir_hidden;              /* 根→父目录累积 hidden（global） */
} BrProbeDirCache;

static _Thread_local BrProbeDirCache g_probe_dir_cache;
static uint64_t g_br_cfg_gen = 0;

static void load_uid_map(void) {
    free(g_uid_maps);
    int cap = UID_MAP_INIT_CAPACITY;
    g_uid_maps = malloc((size_t)cap * sizeof(UidMapEntry));
    if (!g_uid_maps) {
        LOG_ERR("load_uid_map: malloc(%d) 失败", cap);
        g_uid_map_count = 0;
        return;
    }
    g_uid_map_count = uid_map_load(g_uid_maps, cap);
    while (g_uid_map_count > 0 && g_uid_map_count == cap) {
        cap *= 2;
        UidMapEntry *new_maps = realloc(g_uid_maps, (size_t)cap * sizeof(UidMapEntry));
        if (!new_maps) {
            LOG_ERR("load_uid_map: realloc(%d) 失败", cap);
            free(g_uid_maps);
            g_uid_maps = NULL;
            g_uid_map_count = 0;
            return;
        }
        g_uid_maps = new_maps;
        g_uid_map_count = uid_map_load(g_uid_maps, cap);
    }
    LOG_DBG("uid.map 已加载: %d 条映射 (容量 %d)", g_uid_map_count, cap);
}

static void clear_uid_cache(void) {
    for (int i = 0; i < UID_CACHE_SIZE; i++) {
        pthread_mutex_lock(&g_uid_cache[i].lock);
        g_uid_cache[i].uid = 0;
        g_uid_cache[i].cfg = nullptr;
        g_uid_cache[i].pkg[0] = '\0';
        pthread_mutex_unlock(&g_uid_cache[i].lock);
    }
}

/* 配置热重载（含 uid.map 与 uid 缓存重建） */
void br_reload_config(void) {
    config_lock_write();
    load_config_rules(g_br_rules_path);
    load_uid_map();
    clear_uid_cache();
    g_br_cfg_gen++;   /* 使目录级 probe 缓存失效（trie/cfg 可能被 free） */
    config_unlock_write();
    LOG_DBG("已检测到配置变更，重新加载配置，全局监控状态: %s",
            g_global_cfg.monitor ? "开启" : "关闭");
}

/* inotify 监听规则目录，热重载（沿用 vfs_core 的 watch 重建/归并模式） */
static void* config_monitor_thread(void* arg) {
    (void)arg;
    int inotify_fd = -1;
    int wd = -1;
    while (!g_log_shutdown && !g_br_stop) {
        if (inotify_fd < 0) {
            inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
            if (inotify_fd < 0) { sleep(2); continue; }
        }
        if (wd < 0) {
            char dir[PATH_MAX];
            strncpy(dir, g_br_rules_path, sizeof(dir) - 1);
            dir[sizeof(dir) - 1] = '\0';
            char *slash = strrchr(dir, '/');
            if (!slash) { close(inotify_fd); inotify_fd = -1; sleep(2); continue; }
            *slash = '\0';
            wd = inotify_add_watch(inotify_fd, dir,
                IN_CLOSE_WRITE | IN_MODIFY | IN_MOVED_TO | IN_MOVED_FROM | IN_CREATE | IN_DELETE | IN_DELETE_SELF);
            if (wd < 0) { close(inotify_fd); inotify_fd = -1; sleep(2); continue; }
        }
        struct pollfd pfd = { .fd = inotify_fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 5000);
        if (pr < 0) {
            if (errno == EINTR) continue;
            inotify_rm_watch(inotify_fd, wd);
            wd = -1;
            close(inotify_fd);
            inotify_fd = -1;
            continue;
        }
        if (pr == 0) continue;
        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t len = read(inotify_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            inotify_rm_watch(inotify_fd, wd);
            wd = -1;
            close(inotify_fd);
            inotify_fd = -1;
            continue;
        }
        if (len == 0) continue;
        bool watch_invalidated = false;
        for (char* p = buf; p < buf + len; ) {
            struct inotify_event* ev = (struct inotify_event*)p;
            if (ev->mask & IN_IGNORED) watch_invalidated = true;
            p += sizeof(struct inotify_event) + ev->len;
        }
        sleep(1);
        br_reload_config();
        if (watch_invalidated) wd = -1;
    }
    if (inotify_fd >= 0) {
        if (wd >= 0) inotify_rm_watch(inotify_fd, wd);
        close(inotify_fd);
    }
    return nullptr;
}

int br_rules_init(const char* rules_path, bool disable_sandbox) {
    strncpy(g_br_rules_path, rules_path ? rules_path : "", sizeof(g_br_rules_path) - 1);
    g_br_disable_sandbox = disable_sandbox;
    g_br_stop = false;
    config_init_lock();
    for (int i = 0; i < UID_CACHE_SIZE; i++) {
        pthread_mutex_init(&g_uid_cache[i].lock, nullptr);
        g_uid_cache[i].uid = 0;
        g_uid_cache[i].cfg = nullptr;
        g_uid_cache[i].pkg[0] = '\0';
    }
    /* 不 detach：exit 时需要 join，确保 dlclose 前监控线程已退出 */
    if (pthread_create(&g_br_monitor_tid, nullptr, config_monitor_thread, nullptr) != 0)
        LOG_WRN("basic_rules: 配置监控线程创建失败，规则热重载不可用");
    config_lock_write();
    load_config_rules(g_br_rules_path);
    load_uid_map();
    config_unlock_write();
    LOG("basic_rules: 规则引擎已初始化 (rules=%s, sandbox=%s)",
        g_br_rules_path[0] ? g_br_rules_path : "(none)",
        disable_sandbox ? "off" : "on");
    return 0;
}

void br_rules_exit(void) {
    /* 先停止并 join 监控线程（最迟等其 poll 5s 超时退出），
       再销毁锁/释放内存——线程可能正持锁或正在 .so 代码中 */
    g_br_stop = true;
    pthread_join(g_br_monitor_tid, nullptr);
    config_destroy_lock();
    free(g_uid_maps);
    g_uid_maps = NULL;
    g_uid_map_count = 0;
}

/* ============ uid → AppConfig 解析（适配 vfs_get_app_cfg） ============ */

static AppConfig* br_get_app_cfg(uid_t uid, pid_t tid, char* current_pkg_out) {
    if (uid < 10000) {
        strncpy(current_pkg_out, "system", 127);
        current_pkg_out[127] = '\0';
        return nullptr;
    }
    int slot = uid % UID_CACHE_SIZE;
    pthread_mutex_lock(&g_uid_cache[slot].lock);
    if (g_uid_cache[slot].uid == uid && g_uid_cache[slot].cfg != (AppConfig*)-1) {
        strncpy(current_pkg_out, g_uid_cache[slot].pkg, 127);
        current_pkg_out[127] = '\0';
        AppConfig* cached_cfg = g_uid_cache[slot].cfg;
        pthread_mutex_unlock(&g_uid_cache[slot].lock);
        return cached_cfg;
    }
    pthread_mutex_unlock(&g_uid_cache[slot].lock);

    int user_id = uid / 100000;
    char final_pkg[256] = {0};
    pid_t main_pid = tid;
    const char* mapped = uid_map_lookup(g_uid_maps, g_uid_map_count, uid);
    if (mapped) strncpy(final_pkg, mapped, 255);
    if (final_pkg[0] == '\0') {
        char status_path[64];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", tid);
        FILE* fp = fopen(status_path, "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "Tgid:", 5) == 0) { main_pid = atoi(line + 5); break; }
            }
            fclose(fp);
        }
        proc_get_cmdline(main_pid, final_pkg, sizeof(final_pkg));
    }
    char base_pkg[256];
    strncpy(base_pkg, final_pkg, sizeof(base_pkg) - 1);
    base_pkg[sizeof(base_pkg) - 1] = '\0';
    char* colon = strchr(base_pkg, ':');
    if (colon) *colon = 0;
    strncpy(current_pkg_out, base_pkg, 127);
    current_pkg_out[127] = '\0';

    if (strlen(base_pkg) < 3 || strstr(base_pkg, "zygote") != nullptr || strstr(base_pkg, "<pre-") != nullptr) {
        if (base_pkg[0] == '\0') {
            strncpy(base_pkg, "unknown", sizeof(base_pkg) - 1);
            base_pkg[sizeof(base_pkg) - 1] = '\0';
        }
        strncpy(current_pkg_out, base_pkg, 127);
        current_pkg_out[127] = '\0';
        pthread_mutex_lock(&g_uid_cache[slot].lock);
        g_uid_cache[slot].uid = uid;
        g_uid_cache[slot].cfg = nullptr;
        strncpy(g_uid_cache[slot].pkg, base_pkg, 127);
        g_uid_cache[slot].pkg[127] = '\0';
        pthread_mutex_unlock(&g_uid_cache[slot].lock);
        return nullptr;
    }

    AppConfig* matched = find_app_cfg_locked(final_pkg, user_id);
    pthread_mutex_lock(&g_uid_cache[slot].lock);
    g_uid_cache[slot].uid = uid;
    g_uid_cache[slot].cfg = matched;
    strncpy(g_uid_cache[slot].pkg, current_pkg_out, 127);
    g_uid_cache[slot].pkg[127] = '\0';
    pthread_mutex_unlock(&g_uid_cache[slot].lock);
    return matched;
}

/* ============ 规则决策（适配 vfs_core 的 Trie + 线性通道） ============ */

static bool br_is_other_app_pkg(const char* sub_path, const char* current_pkg) {
    if (!current_pkg[0] || strcmp(current_pkg, "system") == 0 || strcmp(current_pkg, "unknown") == 0) return false;
    const char* prefixes[] = {"/Android/data/", "/Android/obb/"};
    for (int i = 0; i < 2; i++) {
        size_t plen = strlen(prefixes[i]);
        if (strncmp(sub_path, prefixes[i], plen) == 0) {
            const char* pkg_start = sub_path + plen;
            if (*pkg_start == '\0') return false;
            const char* slash = strchr(pkg_start, '/');
            size_t pkg_len = slash ? (size_t)(slash - pkg_start) : strlen(pkg_start);
            if (pkg_len > 0 && pkg_len < 256) {
                char target_pkg[256];
                memcpy(target_pkg, pkg_start, pkg_len);
                target_pkg[pkg_len] = '\0';
                if (strcmp(target_pkg, current_pkg) != 0) return true;
            }
            break;
        }
    }
    return false;
}

static void br_trie_resolve(AppConfig* cfg, const char* sub_path, TrieMatch* out) {
    if (!out) return;
    out->valid = true;
    out->hidden = false;
    out->ro = false;
    out->has_redir = false;
    out->redir[0] = '\0';
    out->app_node = NULL;
    out->global_node = NULL;
    if (cfg && cfg->trie_root) {
        bool h = false, r = false;
        char redir[PATH_MAX]; redir[0] = '\0';
        /* trie_lookup_full：一次下降同时取得 hidden/ro/redir 与完整匹配节点，
           供 resolve 复用判定 virtual_ancestor/redirect_target（省重复遍历） */
        out->app_node = trie_lookup_full(cfg->trie_root, sub_path, &h, &r, redir, sizeof(redir));
        if (h) out->hidden = true;
        if (r) out->ro = true;
        if (redir[0] != '\0') {
            out->has_redir = true;
            strncpy(out->redir, redir, sizeof(out->redir) - 1);
            out->redir[sizeof(out->redir) - 1] = '\0';
        }
    }
    if (g_global_cfg.trie_root) {
        bool h = false, r = false;
        char redir[PATH_MAX]; redir[0] = '\0';
        out->global_node = trie_lookup_full(g_global_cfg.trie_root, sub_path, &h, &r, redir, sizeof(redir));
        if (h) out->hidden = true;
        if (r) out->ro = true;
        if (!out->has_redir && redir[0] != '\0') {
            out->has_redir = true;
            strncpy(out->redir, redir, sizeof(out->redir) - 1);
            out->redir[sizeof(out->redir) - 1] = '\0';
        }
    }
}

static bool br_is_path_hidden_internal(AppConfig* cfg, const char* sub_path, const char* current_pkg, const TrieMatch* tm) {
    if (strncmp(sub_path, CONFIG_DIR, strlen(CONFIG_DIR)) == 0) return true;
    if (strcmp(sub_path, "/Android") == 0 || strcmp(sub_path, "/Android/") == 0 ||
        strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0 ||
        strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0) {
        return false;
    }
    if (br_is_other_app_pkg(sub_path, current_pkg)) return true;
    if (tm && tm->valid) {
        if (tm->hidden) return true;
    } else {
        bool hidden = false;
        bool dummy_ro = false;
        if (cfg && cfg->trie_root) {
            if (trie_lookup(cfg->trie_root, sub_path, &hidden, &dummy_ro, NULL, 0)) {
                if (hidden) return true;
            }
        }
        if (g_global_cfg.trie_root) {
            bool global_hidden = false;
            if (trie_lookup(g_global_cfg.trie_root, sub_path, &global_hidden, &dummy_ro, NULL, 0)) {
                if (global_hidden) return true;
            }
        }
    }
    if (cfg && cfg->hide_rules) {
        for (int i = 0; i < cfg->hide_count; i++) {
            if (cfg->hide_rules[i]) {
                const char* rule = cfg->hide_rules[i];
                char expanded[PATH_MAX];
                const char* match_str = rule;
                if (has_path_var(rule)) {
                    if (!pkg_resolvable(current_pkg)) continue;
                    expand_path_vars(rule, expanded, sizeof expanded, cfg, &g_global_cfg, current_pkg);
                    match_str = expanded;
                }
                if (fnmatch(match_str, sub_path, 0) == 0) return true;
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) return true;
            }
        }
    }
    if (g_global_cfg.hide_rules) {
        for (int i = 0; i < g_global_cfg.hide_count; i++) {
            if (g_global_cfg.hide_rules[i]) {
                const char* rule = g_global_cfg.hide_rules[i];
                char expanded[PATH_MAX];
                const char* match_str = rule;
                if (has_path_var(rule)) {
                    if (!pkg_resolvable(current_pkg)) continue;
                    expand_path_vars(rule, expanded, sizeof expanded, cfg, &g_global_cfg, current_pkg);
                    match_str = expanded;
                }
                if (fnmatch(match_str, sub_path, 0) == 0) return true;
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) return true;
            }
        }
    }
    return false;
}

/* 剥离 /<user_id>/ 前缀 + 非法字符清理，得到 sub_path。
   返回 0 成功；-ENOENT 表示清理后为空（路径无效，调用方视为不可解析）。 */
static int br_strip_and_sanitize(const char* path, int* path_user_id_out,
                                 char* sub_path_out, size_t sub_path_size) {
    if (!path) return -ENOENT;
    const char* sub_path_orig = path;
    /* 仅当完整 user_id 目录（/数字 或 /数字/...）才剥离数字前缀——与框架
       vfs_readdir 的 uid_dir 判定一致。若数字后不是 '/' 或结尾（如 /1_abc.txt、
       /12_34 这类普通文件/目录名），不得剥离：否则 sub_path 被截成 "/"，
       规则判定（hidden/redirect_target）基于错误路径，沙盒+应用上下文中
       数字前缀条目会被误过滤（用户报告：数字 x_ 前缀文件/文件夹不显示，
       字母前缀正常） */
    if (path[0] == '/' && isdigit((unsigned char)path[1])) {
        /* 数字序列后必须是结尾或 '/' 才是完整 user_id 目录（/0、/10、
           /100/...）；普通数字前缀文件名（/1_abc.txt、/12_34）不剥离 */
        const char* d = path + 1;
        while (isdigit((unsigned char)*d)) d++;
        if (*d == '\0' || *d == '/') {
            if (path_user_id_out) *path_user_id_out = atoi(path + 1);
            const char* slash = strchr(path + 1, '/');
            sub_path_orig = slash ? slash : "/";
        }
    }
    if (path_contains_invalid_chars(sub_path_orig)) {
        path_sanitize(sub_path_out, sub_path_size, sub_path_orig);
        if (sub_path_out[0] == '\0') return -ENOENT;
    } else {
        strncpy(sub_path_out, sub_path_orig, sub_path_size - 1);
        sub_path_out[sub_path_size - 1] = '\0';
    }
    return 0;
}

static int br_sanitize_and_check_hidden(AppConfig* cfg, const char* path, int* path_user_id_out,
                                        char* sub_path_out, size_t sub_path_size,
                                        const char* current_pkg, uid_t uid, TrieMatch* tm_out) {
    if (br_strip_and_sanitize(path, path_user_id_out, sub_path_out, sub_path_size) != 0)
        return -ENOENT;
    if (tm_out) br_trie_resolve(cfg, sub_path_out, tm_out);
    if (uid != 0 && br_is_path_hidden_internal(cfg, sub_path_out, current_pkg, tm_out)) return -ENOENT;
    return 0;
}

/* check_redir_rule：uid 由调用方传入，不再依赖 fuse_get_context */
static bool br_check_redir_rule(AppConfig* c, const char* sub_path, char* temp, int user_id,
                                const char* current_pkg, bool skip_sandbox, size_t temp_size, uid_t uid) {
    if (!c) return false;
    bool matched = false;
    if (c->redir_rules && c->redir_count > 0) {
        for (int i = 0; i < c->redir_count; i++) {
            const char* prefix = c->redir_rules[i].virtual_prefix;
            size_t len = strlen(prefix);
            bool is_root = (strcmp(prefix, "/") == 0);
            if (is_root || (strncmp(sub_path, prefix, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/'))) {
                const char* suffix = is_root ? sub_path : (sub_path + len);
                char real_base[PATH_MAX];
                const char* target = c->redir_rules[i].real_target;
                if (!build_real_base_from_target(target, (user_id >= 0 ? user_id : 0),
                                                 real_base, sizeof real_base,
                                                 c, &g_global_cfg, current_pkg)) {
                    continue;
                }
                size_t tlen = strlen(real_base);
                bool t_slash = (tlen > 0 && real_base[tlen-1] == '/');
                bool s_slash = (suffix[0] == '/');
                if (t_slash && s_slash) snprintf(temp, temp_size, "%s%s", real_base, suffix + 1);
                else if (!t_slash && !s_slash) {
                    if (suffix[0] == '\0') snprintf(temp, temp_size, "%s", real_base);
                    else snprintf(temp, temp_size, "%s/%s", real_base, suffix);
                } else snprintf(temp, temp_size, "%s%s", real_base, suffix);
                matched = true;
                break;
            }
        }
    }
    if (matched) return true;

    if (!skip_sandbox && c->sandbox && current_pkg[0] && strcmp(current_pkg, "system") != 0 && strcmp(current_pkg, "unknown") != 0) {
        if (strncmp(sub_path, "/Android", 8) == 0) {
            if (sub_path[8] == '\0' || sub_path[8] == '/') {
                bool is_data = (strncmp(sub_path, "/Android/data", 13) == 0 && (sub_path[13] == '\0' || sub_path[13] == '/'));
                bool is_obb = (strncmp(sub_path, "/Android/obb", 12) == 0 && (sub_path[12] == '\0' || sub_path[12] == '/'));
                if (!is_data && !is_obb) return false;
            }
        }
        char exp_data[MAX_PATH_LEN], exp_obb[MAX_PATH_LEN];
        snprintf(exp_data, sizeof(exp_data), "/Android/data/%s", current_pkg);
        snprintf(exp_obb, sizeof(exp_obb), "/Android/obb/%s", current_pkg);
        size_t elen_data = strlen(exp_data), elen_obb = strlen(exp_obb);
        if (strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0 ||
            strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0 ||
            (strncmp(sub_path, exp_data, elen_data) == 0 && (sub_path[elen_data] == '\0' || sub_path[elen_data] == '/')) ||
            (strncmp(sub_path, exp_obb, elen_obb) == 0 && (sub_path[elen_obb] == '\0' || sub_path[elen_obb] == '/'))) {
            return false;
        }
        int effective_uid = user_id;
        if (effective_uid < 0) {
            if (uid >= 10000) effective_uid = (int)(uid / 100000);
        }
        if (effective_uid < 0) effective_uid = 0;
        char sandbox_target[MAX_PATH_LEN];
        int need = snprintf(nullptr, 0, STORAGE_BASE "/%d/Android/data/%s/sandbox", effective_uid, current_pkg);
        if (need <= 0 || (size_t)need >= sizeof(sandbox_target)) {
            LOG_WRN("sandbox 路径过长（%d），放弃沙盒重定向: pkg=%s", need, current_pkg);
            return false;
        }
        snprintf(sandbox_target, sizeof(sandbox_target), STORAGE_BASE "/%d/Android/data/%s/sandbox", effective_uid, current_pkg);
        if (access(sandbox_target, F_OK) != 0) mkdir_recursive_p(sandbox_target, 0775);
        snprintf(temp, temp_size, "%s%s", sandbox_target, sub_path);
        return true;
    }
    return false;
}

static int br_to_real_path(AppConfig* cfg, const char* sub_path, char* out_buf, size_t size,
                           int user_id, bool* is_redir_out, const char* current_pkg,
                           const TrieMatch* tm, uid_t uid) {
    char temp[PATH_MAX] = {0};
    bool redir = false;

    if (tm && tm->valid) {
        if (tm->has_redir) {
            strncpy(temp, tm->redir, sizeof(temp) - 1);
            temp[sizeof(temp) - 1] = '\0';
            redir = true;
        }
    } else {
        bool dummy_hidden = false;
        bool dummy_ro = false;
        if (cfg && cfg->trie_root) {
            if (trie_lookup(cfg->trie_root, sub_path, &dummy_hidden, &dummy_ro, temp, sizeof(temp))) {
                if (temp[0] != '\0') redir = true;
            }
        }
        if (!redir && g_global_cfg.trie_root) {
            temp[0] = '\0';
            if (trie_lookup(g_global_cfg.trie_root, sub_path, &dummy_hidden, &dummy_ro, temp, sizeof(temp))) {
                if (temp[0] != '\0') redir = true;
            }
        }
    }

    if (redir && temp[0] == '?') {
        int effective_uid = user_id >= 0 ? user_id : 0;
        char real_base[1024];
        if (g_real_root[0])
            snprintf(real_base, sizeof(real_base), "%s/%d%s", g_real_root, effective_uid, temp + 1);
        else
            snprintf(real_base, sizeof(real_base), STORAGE_BASE "/%d%s", effective_uid, temp + 1);
        strncpy(temp, real_base, sizeof(temp) - 1);
        temp[sizeof(temp) - 1] = '\0';
    }

    if (!redir) redir = br_check_redir_rule(cfg, sub_path, temp, user_id, current_pkg, true, sizeof(temp), uid);
    if (!redir) redir = br_check_redir_rule(&g_global_cfg, sub_path, temp, user_id, current_pkg, true, sizeof(temp), uid);
    if (!redir && !g_br_disable_sandbox) {
        bool app_sandbox_off = (cfg && cfg->sandbox_explicit && !cfg->sandbox);
        if (!app_sandbox_off) redir = br_check_redir_rule(cfg, sub_path, temp, user_id, current_pkg, false, sizeof(temp), uid);
    }
    if (!redir && !g_br_disable_sandbox) {
        bool app_sandbox_off = (cfg && cfg->sandbox_explicit && !cfg->sandbox);
        if (!app_sandbox_off) redir = br_check_redir_rule(&g_global_cfg, sub_path, temp, user_id, current_pkg, false, sizeof(temp), uid);
    }
    if (!redir) {
        if (user_id >= 0) {
            if (g_real_root[0])
                snprintf(temp, sizeof(temp), "%s/%d%s", g_real_root, user_id, sub_path);
            else
                snprintf(temp, sizeof(temp), STORAGE_BASE "/%d%s", user_id, sub_path);
        } else {
            if (g_real_root[0])
                snprintf(temp, sizeof(temp), "%s%s", g_real_root, sub_path);
            else
                snprintf(temp, sizeof(temp), STORAGE_BASE "%s", sub_path);
        }
    }
    strncpy(out_buf, temp, size - 1);
    out_buf[size - 1] = '\0';
    if (is_redir_out) *is_redir_out = redir;
    if (out_buf[0] == '\0') return -ENOENT;
    return 0;
}

static bool br_is_path_ro(AppConfig* cfg, const char* sub_path, const char* current_pkg, const TrieMatch* tm) {
    if (tm && tm->valid) {
        if (tm->ro) return true;
    } else {
        bool dummy_hidden = false;
        bool ro = false;
        if (cfg && cfg->trie_root) {
            if (trie_lookup(cfg->trie_root, sub_path, &dummy_hidden, &ro, NULL, 0)) {
                if (ro) return true;
            }
        }
        if (g_global_cfg.trie_root) {
            bool global_ro = false;
            if (trie_lookup(g_global_cfg.trie_root, sub_path, &dummy_hidden, &global_ro, NULL, 0)) {
                if (global_ro) return true;
            }
        }
    }
    if (cfg && cfg->ro_rules) {
        for (int i = 0; i < cfg->ro_count; i++) {
            if (cfg->ro_rules[i]) {
                const char* rule = cfg->ro_rules[i];
                char expanded[PATH_MAX];
                const char* match_str = rule;
                if (has_path_var(rule)) {
                    if (!pkg_resolvable(current_pkg)) continue;
                    expand_path_vars(rule, expanded, sizeof expanded, cfg, &g_global_cfg, current_pkg);
                    match_str = expanded;
                }
                if (fnmatch(match_str, sub_path, 0) == 0) return true;
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) return true;
            }
        }
    }
    if (g_global_cfg.ro_rules) {
        for (int i = 0; i < g_global_cfg.ro_count; i++) {
            if (g_global_cfg.ro_rules[i]) {
                const char* rule = g_global_cfg.ro_rules[i];
                char expanded[PATH_MAX];
                const char* match_str = rule;
                if (has_path_var(rule)) {
                    if (!pkg_resolvable(current_pkg)) continue;
                    expand_path_vars(rule, expanded, sizeof expanded, cfg, &g_global_cfg, current_pkg);
                    match_str = expanded;
                }
                if (fnmatch(match_str, sub_path, 0) == 0) return true;
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) return true;
            }
        }
    }
    return false;
}

/* ============ 虚拟目录合成 ============ */

static bool br_get_virtual_child(const char* parent, const char* desc, char* name, size_t max_len) {
    size_t plen = strlen(parent);
    if (strcmp(parent, "/") == 0) plen = 0;
    if (strncmp(parent, desc, plen) != 0) return false;
    if (plen > 0 && desc[plen] != '/' && desc[plen] != '\0') return false;
    const char* p = desc + plen;
    if (*p == '/') p++;
    if (*p == '\0') return false;
    const char* slash = strchr(p, '/');
    size_t nlen = slash ? (size_t)(slash - p) : strlen(p);
    if (nlen == 0) return false;
    if (name && max_len > 0) {
        size_t copy_len = nlen < (max_len - 1) ? nlen : (max_len - 1);
        strncpy(name, p, copy_len);
        name[copy_len] = '\0';
    }
    return true;
}

/* 虚拟祖先判定的线性规则部分（redir/ftp 前缀的祖先检查，不含 trie）——
   readdir 目录级缓存命中时复用，避免每条目重复全路径 trie 遍历 */
static bool br_virtual_ancestor_linear(AppConfig* cfg, const char* sub_path) {
    bool res = false;
    if (cfg) {
        if (cfg->redir_rules) {
            for (int i = 0; i < cfg->redir_count; i++) {
                if (strlen(sub_path) < strlen(cfg->redir_rules[i].virtual_prefix)) {
                    if (br_get_virtual_child(sub_path, cfg->redir_rules[i].virtual_prefix, nullptr, 0)) { res = true; break; }
                }
            }
        }
        if (!res && cfg->ftp_rules) {
            for (int i = 0; i < cfg->ftp_count; i++) {
                if (strlen(sub_path) < strlen(cfg->ftp_rules[i].virtual_prefix)) {
                    if (br_get_virtual_child(sub_path, cfg->ftp_rules[i].virtual_prefix, nullptr, 0)) { res = true; break; }
                }
            }
        }
    }
    if (!res) {
        if (g_global_cfg.redir_rules) {
            for (int i = 0; i < g_global_cfg.redir_count; i++) {
                if (strlen(sub_path) < strlen(g_global_cfg.redir_rules[i].virtual_prefix)) {
                    if (br_get_virtual_child(sub_path, g_global_cfg.redir_rules[i].virtual_prefix, nullptr, 0)) { res = true; break; }
                }
            }
        }
        if (!res && g_global_cfg.ftp_rules) {
            for (int i = 0; i < g_global_cfg.ftp_count; i++) {
                if (strlen(sub_path) < strlen(g_global_cfg.ftp_rules[i].virtual_prefix)) {
                    if (br_get_virtual_child(sub_path, g_global_cfg.ftp_rules[i].virtual_prefix, nullptr, 0)) { res = true; break; }
                }
            }
        }
    }
    return res;
}

/* redirect_target 判定的线性规则部分（redir 前缀精确匹配 + 根 sandbox），不含 trie */
static bool br_redirect_target_linear(AppConfig* cfg, const char* sub_path) {
    bool res = false;
    if (cfg) {
        if (cfg->redir_rules) {
            for (int i = 0; i < cfg->redir_count; i++) {
                if (strcmp(sub_path, cfg->redir_rules[i].virtual_prefix) == 0) { res = true; break; }
            }
        }
        if (!res && cfg->sandbox && strcmp(sub_path, "/") == 0) res = true;
    }
    if (!res) {
        if (g_global_cfg.redir_rules) {
            for (int i = 0; i < g_global_cfg.redir_count; i++) {
                if (strcmp(sub_path, g_global_cfg.redir_rules[i].virtual_prefix) == 0) { res = true; break; }
            }
        }
        if (!res && !(cfg && cfg->sandbox_explicit) && g_global_cfg.sandbox && strcmp(sub_path, "/") == 0) res = true;
    }
    return res;
}

static bool br_is_virtual_ancestor(AppConfig* cfg, const char* sub_path) {
    bool res = false;
    if (cfg && cfg->trie_root) res = trie_is_ancestor(cfg->trie_root, sub_path);
    if (!res && g_global_cfg.trie_root) res = trie_is_ancestor(g_global_cfg.trie_root, sub_path);
    if (!res) res = br_virtual_ancestor_linear(cfg, sub_path);
    return res;
}

static bool br_is_redirect_target(AppConfig* cfg, const char* sub_path) {
    bool res = false;
    if (cfg && cfg->trie_root) res = trie_is_redirect_target(cfg->trie_root, sub_path);
    if (!res && g_global_cfg.trie_root) res = trie_is_redirect_target(g_global_cfg.trie_root, sub_path);
    if (!res) res = br_redirect_target_linear(cfg, sub_path);
    return res;
}

/* ============ 核心决策入口 ============ */

void br_resolve(const BrQuery* q, BrResult* out) {
    if (!q || !out) return;
    memset(out, 0, sizeof *out);
    char current_pkg[128] = "unknown";
    /* 读规则前加锁：config_monitor_thread 重载时会写 g_global_cfg/g_app_cfgs */
    config_lock_read();
    AppConfig* cfg = br_get_app_cfg(q->uid, q->pid, current_pkg);

    int path_user_id = -1;
    char sub_path[PATH_MAX];
    TrieMatch tm;
    if (br_sanitize_and_check_hidden(cfg, q->path, &path_user_id, sub_path, sizeof sub_path,
                                     current_pkg, q->uid, &tm) != 0) {
        out->valid = true;
        out->hidden = true;
        out->user_id = path_user_id;
        strncpy(out->sub_path, sub_path, sizeof out->sub_path - 1);
        strncpy(out->pkg, current_pkg, sizeof out->pkg - 1);
        out->monitor_on = (cfg && cfg->monitor_explicit) ? cfg->monitor : g_global_cfg.monitor;
        config_unlock_read();
        return;
    }
    char p[PATH_MAX];
    bool is_redir = false;
    if (br_to_real_path(cfg, sub_path, p, sizeof p, path_user_id, &is_redir, current_pkg, &tm, q->uid) != 0) {
        out->valid = false;
        config_unlock_read();
        return;
    }
    out->valid = true;
    out->user_id = path_user_id;
    strncpy(out->sub_path, sub_path, sizeof out->sub_path - 1);
    strncpy(out->pkg, current_pkg, sizeof out->pkg - 1);
    out->ro = br_is_path_ro(cfg, sub_path, current_pkg, &tm);
    out->is_redir = is_redir;
    strncpy(out->real_path, p, sizeof out->real_path - 1);
    if (tm.has_redir) {
        out->has_redir = true;
        strncpy(out->redir_target, tm.redir, sizeof out->redir_target - 1);
    }
    /* ALLOW 豁免：命中 is_allow 规则的 redir（目标为 ? 自身存储形式） */
    if (cfg && cfg->redir_rules) {
        for (int i = 0; i < cfg->redir_count; i++) {
            const char* prefix = cfg->redir_rules[i].virtual_prefix;
            size_t len = strlen(prefix);
            if (strcmp(prefix, "/") == 0 || (strncmp(sub_path, prefix, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/'))) {
                if (cfg->redir_rules[i].is_allow) { out->has_redir = true; break; }
            }
        }
    }
    /* 复用 br_trie_resolve 已完成的 trie 下降结果（app/global 完整匹配节点），
       直接判定 virtual_ancestor / redirect_target，避免各自再全路径遍历：
       - virtual_ancestor：最深节点下存在带规则子节点（trie_is_ancestor 语义）
       - redirect_target：最深节点本身是重定向目标（trie_is_redirect_target 语义）
       （节点为 NULL = 路径未完整命中，两语义均为 false，与 trie_* 一致） */
    out->is_virtual_ancestor =
        ((tm.app_node && trie_any_child_has_rules(tm.app_node)) ||
         (tm.global_node && trie_any_child_has_rules(tm.global_node))) ||
        br_virtual_ancestor_linear(cfg, sub_path);
    out->is_redirect_target =
        ((tm.app_node && tm.app_node->redir_target) ||
         (tm.global_node && tm.global_node->redir_target)) ||
        br_redirect_target_linear(cfg, sub_path);
    /* FTP 规则（`FTP <虚拟前缀> <段名>`）：应用段规则优先、GLOBAL 兜底
       （与 REDIRECT 作用域语义一致）；命中后由框架分派给 FTP 后端模块 */
    if (cfg && cfg != &g_global_cfg) {
        char bk[64] = {0};
        if (!config_ftp_match(cfg, sub_path, bk, sizeof bk))
            config_ftp_match(&g_global_cfg, sub_path, bk, sizeof bk);
        if (bk[0]) {
            out->is_ftp = true;
            strncpy(out->ftp_backend, bk, sizeof out->ftp_backend - 1);
            out->ftp_backend[sizeof out->ftp_backend - 1] = '\0';
        }
    } else {
        char bk[64] = {0};
        if (config_ftp_match(cfg ? cfg : &g_global_cfg, sub_path, bk, sizeof bk) && bk[0]) {
            out->is_ftp = true;
            strncpy(out->ftp_backend, bk, sizeof out->ftp_backend - 1);
            out->ftp_backend[sizeof out->ftp_backend - 1] = '\0';
        }
    }
    out->is_other_app_pkg = br_is_other_app_pkg(sub_path, current_pkg);
    out->monitor_on = (cfg && cfg->monitor_explicit) ? cfg->monitor : g_global_cfg.monitor;
    config_unlock_read();
}

/* uid → 包名解析（框架日志用），语义与 br_get_app_cfg 的 pkg 输出一致 */
int br_get_pkg(uid_t uid, pid_t tid, char* pkg_out, size_t pkg_size) {
    if (!pkg_out || pkg_size == 0) return -1;
    config_lock_read();
    char pkg[128];
    br_get_app_cfg(uid, tid, pkg);
    config_unlock_read();
    strncpy(pkg_out, pkg, pkg_size - 1);
    pkg_out[pkg_size - 1] = '\0';
    return 0;
}

/* 轻量探测：readdir 逐条目过滤用。只做 sanitize + hidden/redirect_target/
   虚拟目录判断，不构建真实路径、不触发 sandbox 目录创建（性能敏感） */
void br_probe(const BrQuery* q, BrProbeResult* out) {
    if (!q || !out) return;
    memset(out, 0, sizeof *out);
    char current_pkg[128] = "unknown";
    config_lock_read();
    uint64_t gen = g_br_cfg_gen;
    AppConfig* cfg = NULL;

    int path_user_id = -1;
    char sub_path[PATH_MAX];
    if (br_strip_and_sanitize(q->path, &path_user_id, sub_path, sizeof sub_path) != 0) {
        config_unlock_read();   /* 无效路径：out->valid=false，框架不过滤 */
        return;
    }

    /* 提取父目录与条目名："/a/b" → 父 "/a"、名 "b"；"/xxx" → 父 "/"、名 "xxx" */
    char dir[PATH_MAX];
    const char* name;
    size_t name_len;
    {
        const char* last = strrchr(sub_path, '/');
        if (!last) {                       /* 无 '/'（防御） */
            strncpy(dir, "/", sizeof dir - 1); dir[sizeof dir - 1] = '\0';
            name = sub_path;
        } else if (last == sub_path) {     /* "/xxx" → 父目录 "/" */
            strncpy(dir, "/", sizeof dir - 1); dir[sizeof dir - 1] = '\0';
            name = last + 1;
        } else {
            size_t dlen = (size_t)(last - sub_path);
            if (dlen >= sizeof dir) dlen = sizeof dir - 1;
            memcpy(dir, sub_path, dlen);
            dir[dlen] = '\0';
            name = last + 1;
        }
        name_len = strlen(name);
    }

    BrProbeDirCache* pc = &g_probe_dir_cache;
    /* 缓存命中：同线程同一 (uid,pid,父目录) 的连续条目共享一次
       「根→父目录」trie 下降与 uid→cfg 解析，这里只按最后一段查子节点 */
    if (pc->valid && pc->gen == gen && pc->uid == q->uid && pc->pid == q->pid &&
        strcmp(pc->dir, dir) == 0) {
        cfg = pc->cfg;
        strncpy(current_pkg, pc->current_pkg, 127); current_pkg[127] = '\0';
        const TrieNode* ca = trie_find_child(pc->app_dir_node, name, name_len);
        const TrieNode* cg = trie_find_child(pc->g_dir_node, name, name_len);
        bool trie_hidden = pc->app_dir_hidden || pc->g_dir_hidden;
        if (ca && ca->is_hidden) trie_hidden = true;
        if (cg && cg->is_hidden) trie_hidden = true;
        TrieMatch tm; memset(&tm, 0, sizeof tm);
        tm.valid = true;
        tm.hidden = trie_hidden;
        /* 完整隐藏判定（CONFIG_DIR/Android 骨架/其他应用/hide 规则），
           trie 部分用缓存值（tm.valid 使其跳过内部 trie 查询） */
        if (q->uid != 0 && br_is_path_hidden_internal(cfg, sub_path, current_pkg, &tm)) {
            out->valid = true;
            out->hidden = true;
            config_unlock_read();
            return;
        }
        out->valid = true;
        out->hidden = trie_hidden;
        out->is_redirect_target = ((ca && ca->redir_target) || (cg && cg->redir_target)) ||
                                  br_redirect_target_linear(cfg, sub_path);
        out->is_virtual_ancestor = ((ca && trie_any_child_has_rules(ca)) ||
                                    (cg && trie_any_child_has_rules(cg))) ||
                                   br_virtual_ancestor_linear(cfg, sub_path);
        out->is_other_app_pkg = br_is_other_app_pkg(sub_path, current_pkg);
        config_unlock_read();
        return;
    }

    /* 未命中：完整路径解析（原逻辑）+ 填充目录缓存 */
    cfg = br_get_app_cfg(q->uid, q->pid, current_pkg);
    TrieMatch tm;
    if (br_sanitize_and_check_hidden(cfg, q->path, &path_user_id, sub_path, sizeof sub_path,
                                     current_pkg, q->uid, &tm) != 0) {
        out->valid = true;
        out->hidden = true;
        config_unlock_read();
        return;
    }
    out->valid = true;
    out->hidden = tm.hidden;
    out->is_redirect_target = br_is_redirect_target(cfg, sub_path);
    out->is_virtual_ancestor = br_is_virtual_ancestor(cfg, sub_path);
    out->is_other_app_pkg = br_is_other_app_pkg(sub_path, current_pkg);

    /* 填充目录缓存（trie 沿父目录一次下降，后续条目复用） */
    memset(pc, 0, sizeof *pc);
    pc->valid = true;
    pc->gen = gen;
    pc->uid = q->uid;
    pc->pid = q->pid;
    strncpy(pc->dir, dir, sizeof pc->dir - 1);
    pc->dir[sizeof pc->dir - 1] = '\0';
    pc->cfg = cfg;
    strncpy(pc->current_pkg, current_pkg, sizeof pc->current_pkg - 1);
    pc->current_pkg[sizeof pc->current_pkg - 1] = '\0';
    bool h = false, r = false;
    pc->app_dir_node = (cfg && cfg->trie_root) ? trie_walk_to(cfg->trie_root, dir, &h, &r) : NULL;
    pc->app_dir_hidden = h;
    h = false; r = false;
    pc->g_dir_node = g_global_cfg.trie_root ? trie_walk_to(g_global_cfg.trie_root, dir, &h, &r) : NULL;
    pc->g_dir_hidden = h;
    config_unlock_read();
}

/* ============ readdir 虚拟目录补充 ============ */

/* 处理单个配置（app 或 global）的 REDIRECT 前缀虚拟子目录。
   函数化替代宏：避免对 &g_global_cfg 这类常量地址判空触发 -Waddress */
static int br_process_cfg_dirs(AppConfig* c, const char* sub_path, int user_id,
                               const char* pkg, bool is_root, NspDirEntry* out, int max, int n) {
    if (!c || n >= max) return n;
    /* REDIRECT 虚拟目录合成 */
    if (c->redir_rules) {
        for (int i = 0; i < c->redir_count && n < max; i++) {
            char name[256];
            if (br_get_virtual_child(sub_path, c->redir_rules[i].virtual_prefix, name, sizeof(name))) {
                char full_vpath[PATH_MAX];
                if (is_root) snprintf(full_vpath, PATH_MAX, "/%s", name);
                else snprintf(full_vpath, PATH_MAX, "%s/%s", sub_path, name);
                if (strcmp(full_vpath, c->redir_rules[i].virtual_prefix) == 0) {
                    char dummy[PATH_MAX];
                    if (!build_real_base_from_target(c->redir_rules[i].real_target,
                            (user_id >= 0 ? user_id : 0), dummy, sizeof dummy, c, &g_global_cfg,
                            pkg && pkg[0] ? pkg : "unknown")) continue;
                }
                bool dup = false;
                for (int k = 0; k < n; k++) {
                    if (strcmp(out[k].name, name) == 0) { dup = true; break; }
                }
                if (!dup) {
                    strncpy(out[n].name, name, sizeof out[n].name - 1);
                    out[n].name[sizeof out[n].name - 1] = '\0';
                    out[n].is_dir = true;
                    n++;
                }
            }
        }
    }
    /* FTP 虚拟目录合成：FTP <虚拟前缀> <段名> 规则的前缀条目（如 /0/ 下显示"云盘"） */
    if (c->ftp_rules) {
        for (int i = 0; i < c->ftp_count && n < max; i++) {
            char name[256];
            if (br_get_virtual_child(sub_path, c->ftp_rules[i].virtual_prefix, name, sizeof name)) {
                bool dup = false;
                for (int k = 0; k < n; k++) {
                    if (strcmp(out[k].name, name) == 0) { dup = true; break; }
                }
                if (!dup) {
                    strncpy(out[n].name, name, sizeof out[n].name - 1);
                    out[n].name[sizeof out[n].name - 1] = '\0';
                    out[n].is_dir = true;
                    n++;
                }
            }
        }
    }
    return n;
}

int br_readdir_extra(const BrQuery* q, const char* sub_path, int user_id,
                     const char* pkg, bool is_root, NspDirEntry* out, int max) {
    if (!q || !out || max <= 0) return 0;
    char pkg_buf[128];
    (void)pkg;
    /* 持读锁：br_get_app_cfg 走 g_uid_maps/g_app_cfgs，config_monitor_thread
       热重载会在写锁下释放重建它们（与 br_resolve/br_get_pkg 一致） */
    config_lock_read();
    AppConfig* cfg = br_get_app_cfg(q->uid, q->pid, pkg_buf);

    int n = 0;
    n = br_process_cfg_dirs(cfg, sub_path, user_id, pkg_buf, is_root, out, max, n);
    n = br_process_cfg_dirs(&g_global_cfg, sub_path, user_id, pkg_buf, is_root, out, max, n);
    config_unlock_read();
    return n;
}
