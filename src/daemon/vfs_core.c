#define _GNU_SOURCE
#include "vfs_core.h"
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

char g_rules_path[PATH_MAX] = {0};
UidMapEntry *g_uid_maps = NULL;
int g_uid_map_count = 0;

#define UID_CACHE_SIZE 2048
typedef struct {
    pthread_mutex_t lock;
    uid_t uid;
    AppConfig* cfg;
    char pkg[128];
} UidCacheSlot;
static UidCacheSlot g_uid_cache[UID_CACHE_SIZE];

static void load_uid_map() {
    /* 释放旧缓存，重新动态分配 */
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

static void reload_config(void) {
    config_lock_write();
    load_config_rules(g_rules_path);
    load_uid_map();
    for (int i = 0; i < UID_CACHE_SIZE; i++) {
        pthread_mutex_lock(&g_uid_cache[i].lock);
        g_uid_cache[i].uid = 0;
        g_uid_cache[i].cfg = nullptr;
        g_uid_cache[i].pkg[0] = '\0';
        pthread_mutex_unlock(&g_uid_cache[i].lock);
    }
    config_unlock_write();
    LOG_DBG("已检测到配置变更，重新加载配置，全局监控状态: %s",
            g_global_cfg.monitor ? "开启" : "关闭");
}

static void* config_monitor_thread(void* arg) {
    (void)arg;

    int inotify_fd = -1;
    int wd = -1;
    /* inotify fd 因内核内存压力或原子替换（vim/sed -i）可能失效，
       外层循环负责重建 watch；log_close() 设置 g_log_shutdown 后退出循环，释放 inotify 资源。
       非阻塞 fd + poll 超时避免 read 永久卡死；处理 IN_IGNORED 以感知 watch 失效 */
    while (!g_log_shutdown) {
        if (inotify_fd < 0) {
            inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
            if (inotify_fd < 0) {
                sleep(2);
                continue;
            }
        }
        if (wd < 0) {
            char dir[PATH_MAX];
            strncpy(dir, g_rules_path, sizeof(dir) - 1);
            dir[sizeof(dir) - 1] = '\0';
            char *slash = strrchr(dir, '/');
            if (!slash) { close(inotify_fd); inotify_fd = -1; sleep(2); continue; }
            *slash = '\0';
            /* 扩展掩码：覆盖原子替换全阶段（IN_MOVED_FROM/IN_MOVED_TO/IN_CREATE/IN_DELETE/IN_DELETE_SELF） */
            wd = inotify_add_watch(inotify_fd, dir,
                IN_CLOSE_WRITE | IN_MODIFY | IN_MOVED_TO | IN_MOVED_FROM | IN_CREATE | IN_DELETE | IN_DELETE_SELF);
            if (wd < 0) { close(inotify_fd); inotify_fd = -1; sleep(2); continue; }
        }

        /* poll 等待事件，5 秒超时让外层循环能感知 g_log_shutdown */
        struct pollfd pfd = { .fd = inotify_fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 5000);
        if (pr < 0) {
            if (errno == EINTR) continue;
            /* poll 永久失败：重建 inotify fd 与 watch */
            inotify_rm_watch(inotify_fd, wd);
            wd = -1;
            close(inotify_fd);
            inotify_fd = -1;
            continue;
        }
        if (pr == 0) continue;  /* 超时，无事件 */

        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t len = read(inotify_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;  /* EAGAIN: 非阻塞无数据 */
            /* 真正的永久失败：重建 */
            inotify_rm_watch(inotify_fd, wd);
            wd = -1;
            close(inotify_fd);
            inotify_fd = -1;
            continue;
        }
        if (len == 0) continue;  /* EOF，不应发生但防御性处理 */

        /* 遍历事件：检测 IN_IGNORED（watch 失效，需重建）；
           合并窗口：sleep 1 秒让多个叠加事件归并，再仅 reload 一次 */
        bool watch_invalidated = false;
        for (char* p = buf; p < buf + len; ) {
            struct inotify_event* ev = (struct inotify_event*)p;
            if (ev->mask & IN_IGNORED) watch_invalidated = true;
            p += sizeof(struct inotify_event) + ev->len;
        }

        sleep(1);
        reload_config();

        /* watch 被内核撤销（如原子替换），下一轮重建 */
        if (watch_invalidated) {
            wd = -1;
        }
    }

    if (inotify_fd >= 0) {
        if (wd >= 0) inotify_rm_watch(inotify_fd, wd);
        close(inotify_fd);
    }
    return nullptr;
}

void vfs_core_init(const char* rules_path) {
    config_init_lock();
    strncpy(g_rules_path, rules_path, PATH_MAX - 1);
    for (int i = 0; i < UID_CACHE_SIZE; i++) {
        pthread_mutex_init(&g_uid_cache[i].lock, nullptr);
        g_uid_cache[i].uid = 0;
        g_uid_cache[i].cfg = nullptr;
        g_uid_cache[i].pkg[0] = '\0';
    }
    pthread_t sig_thread;
    pthread_create(&sig_thread, nullptr, config_monitor_thread, nullptr);
    pthread_detach(sig_thread);
    
    config_lock_write();
    load_config_rules(g_rules_path);
    load_uid_map();
    config_unlock_write();
}

AppConfig* vfs_get_app_cfg(uid_t uid, pid_t tid, char* current_pkg_out) {
    if (uid < 10000) {
        strncpy(current_pkg_out, "system", sizeof(g_uid_cache[0].pkg) - 1);
        current_pkg_out[sizeof(g_uid_cache[0].pkg) - 1] = '\0';
        return nullptr;
    }
    int slot = uid % UID_CACHE_SIZE;
    pthread_mutex_lock(&g_uid_cache[slot].lock);
    if (g_uid_cache[slot].uid == uid && g_uid_cache[slot].cfg != (AppConfig*)-1) {
        strncpy(current_pkg_out, g_uid_cache[slot].pkg, sizeof(g_uid_cache[slot].pkg) - 1);
        current_pkg_out[sizeof(g_uid_cache[slot].pkg) - 1] = '\0';
        AppConfig* cached_cfg = g_uid_cache[slot].cfg;
        pthread_mutex_unlock(&g_uid_cache[slot].lock);
        return cached_cfg;
    }
    pthread_mutex_unlock(&g_uid_cache[slot].lock);
    
    int user_id = uid / 100000;
    char final_pkg[256] = {0}; 
    pid_t main_pid = tid;
    const char* mapped = uid_map_lookup(g_uid_maps, g_uid_map_count, uid);
    if (mapped) {
        strncpy(final_pkg, mapped, 255);
    }
    if (final_pkg[0] == '\0') {
        char status_path[64]; 
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", tid);
        FILE* fp = fopen(status_path, "r");
        if (fp) {
            char line[256];
            while(fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "Tgid:", 5) == 0) { 
                    main_pid = atoi(line + 5); 
                    break; 
                }
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

bool vfs_is_other_app_pkg(const char* sub_path, const char* current_pkg) {
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

void vfs_trie_resolve(AppConfig* cfg, const char* sub_path, TrieMatch* out) {
    if (!out) return;
    out->valid = true;
    out->hidden = false;
    out->ro = false;
    out->has_redir = false;
    out->redir[0] = '\0';

    /* app trie 优先：一次遍历同时取 hidden/ro/redir */
    if (cfg && cfg->trie_root) {
        bool h = false, r = false;
        char redir[PATH_MAX]; redir[0] = '\0';
        if (trie_lookup(cfg->trie_root, sub_path, &h, &r, redir, sizeof(redir))) {
            if (h) out->hidden = true;
            if (r) out->ro = true;
            if (redir[0] != '\0') {
                out->has_redir = true;
                strncpy(out->redir, redir, sizeof(out->redir) - 1);
                out->redir[sizeof(out->redir) - 1] = '\0';
            }
        }
    }
    /* global trie：hidden/ro 取并集；redir 仅在 app 未命中时兜底（与原 app 优先语义一致） */
    if (g_global_cfg.trie_root) {
        bool h = false, r = false;
        char redir[PATH_MAX]; redir[0] = '\0';
        if (trie_lookup(g_global_cfg.trie_root, sub_path, &h, &r, redir, sizeof(redir))) {
            if (h) out->hidden = true;
            if (r) out->ro = true;
            if (!out->has_redir && redir[0] != '\0') {
                out->has_redir = true;
                strncpy(out->redir, redir, sizeof(out->redir) - 1);
                out->redir[sizeof(out->redir) - 1] = '\0';
            }
        }
    }
}

static bool is_path_hidden_internal(AppConfig* cfg, const char* sub_path, const char* current_pkg, const TrieMatch* tm) {
    if (strncmp(sub_path, CONFIG_DIR, strlen(CONFIG_DIR)) == 0) return true;
    if (strcmp(sub_path, "/Android") == 0 || strcmp(sub_path, "/Android/") == 0 ||
        strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0 ||
        strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0) {
        return false; 
    }
    if (vfs_is_other_app_pkg(sub_path, current_pkg)) return true;
    /* Trie 静态规则命中：优先复用缓存，避免重复遍历 */
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
                if (fnmatch(match_str, sub_path, 0) == 0) { return true; }
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { return true; }
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
                if (fnmatch(match_str, sub_path, 0) == 0) { return true; }
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { return true; }
            }
        }
    }
    return false;
}

int vfs_sanitize_and_check_hidden(AppConfig* cfg, const char* path, int* path_user_id_out, char* sub_path_out, size_t sub_path_size, const char* current_pkg, uid_t uid, TrieMatch* tm_out) {
    if (!path) return -ENOENT;
    const char* sub_path_orig = path;
    if (path[0] == '/' && isdigit((unsigned char)path[1])) {
        if (path_user_id_out) *path_user_id_out = atoi(path + 1);
        char* slash = strchr(path + 1, '/');
        sub_path_orig = slash ? slash : "/";
    }
    if (path_contains_invalid_chars(sub_path_orig)) {
        path_sanitize(sub_path_out, sub_path_size, sub_path_orig);
        if (sub_path_out[0] == '\0') return -ENOENT;
    } else {
        strncpy(sub_path_out, sub_path_orig, sub_path_size - 1);
        sub_path_out[sub_path_size - 1] = '\0';
    }
    /* sub_path 已定型：一次性 resolve app+global 两棵 Trie，供本函数判 hidden
       及后续 to_real_path(redir)/is_path_ro(ro) 复用，避免重复遍历 */
    if (tm_out) vfs_trie_resolve(cfg, sub_path_out, tm_out);
    if (uid != 0 && is_path_hidden_internal(cfg, sub_path_out, current_pkg, tm_out)) return -ENOENT;
    return 0;
}

static bool check_redir_rule(AppConfig* c, const char* sub_path, char* temp, int user_id, const char* current_pkg, bool skip_sandbox, size_t temp_size) {
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
                    continue;   /* 含 $ 但包名不可解析 → 本条 redir 不命中 */
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
    
    /* 拦截所有的沙盒请求，如果显式设定了 skip_sandbox 则直接跳过 */
    if (!skip_sandbox && c->sandbox && current_pkg[0] && strcmp(current_pkg, "system") != 0 && strcmp(current_pkg, "unknown") != 0) {
        if (strncmp(sub_path, "/Android", 8) == 0) {
            if (sub_path[8] == '\0' || sub_path[8] == '/') {
                bool is_data = (strncmp(sub_path, "/Android/data", 13) == 0 && (sub_path[13] == '\0' || sub_path[13] == '/'));
                bool is_obb = (strncmp(sub_path, "/Android/obb", 12) == 0 && (sub_path[12] == '\0' || sub_path[12] == '/'));
                if (!is_data && !is_obb) {
                    return false;
                }
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
            struct fuse_context* fctx = fuse_get_context();
            if (fctx && fctx->uid >= 10000) effective_uid = (int)(fctx->uid / 100000);
        }
        if (effective_uid < 0) effective_uid = 0;
        /* 长度校验：current_pkg 来自 uid 缓存可极长，避免 sandbox_target 截断后 mkdir 错误位置 */
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

int vfs_to_real_path(AppConfig* cfg, const char* sub_path, char* out_buf, size_t size, int user_id, bool* is_redir_out, const char* current_pkg, const TrieMatch* tm) {
    char temp[PATH_MAX] = {0};
    bool redir = false;

    /* Trie 静态 redirect 命中：优先复用缓存（含 app 优先语义），否则自查 */
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

    /* 核心修复：还原 ALLOW 或部分 REDIRECT 被 Trie 拦截的 `?` 前缀动态解析机制 */
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
    
    if (!redir) {
        redir = check_redir_rule(cfg, sub_path, temp, user_id, current_pkg, true, sizeof(temp));
    }
    if (!redir) {
        redir = check_redir_rule(&g_global_cfg, sub_path, temp, user_id, current_pkg, true, sizeof(temp));
    }
    if (!redir && !g_disable_sandbox) {
        bool app_sandbox_off = (cfg && cfg->sandbox_explicit && !cfg->sandbox);
        if (!app_sandbox_off) {
            redir = check_redir_rule(cfg, sub_path, temp, user_id, current_pkg, false, sizeof(temp));
        }
    }
    if (!redir && !g_disable_sandbox) {
        bool app_sandbox_off = (cfg && cfg->sandbox_explicit && !cfg->sandbox);
        if (!app_sandbox_off) {
            redir = check_redir_rule(&g_global_cfg, sub_path, temp, user_id, current_pkg, false, sizeof(temp));
        }
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

bool vfs_is_path_ro(AppConfig* cfg, const char* sub_path, const char* current_pkg, const TrieMatch* tm) {
    /* Trie 静态 RO 命中：优先复用缓存，否则自查 */
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
                if (fnmatch(match_str, sub_path, 0) == 0) { return true; }
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { return true; }
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
                if (fnmatch(match_str, sub_path, 0) == 0) { return true; }
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { return true; }
            }
        }
    }
    return false;
}

bool vfs_get_virtual_child(const char* parent, const char* desc, char* name, size_t max_len) {
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

bool vfs_is_virtual_ancestor(AppConfig* cfg, const char* sub_path) {
    bool res = false;
    if (cfg && cfg->trie_root) {
        res = trie_is_ancestor(cfg->trie_root, sub_path);
    }
    if (!res && g_global_cfg.trie_root) {
        res = trie_is_ancestor(g_global_cfg.trie_root, sub_path);
    }
    if (!res && cfg) {
        if (cfg->redir_rules) {
            for (int i = 0; i < cfg->redir_count; i++) {
                if (strlen(sub_path) < strlen(cfg->redir_rules[i].virtual_prefix)) {
                    if (vfs_get_virtual_child(sub_path, cfg->redir_rules[i].virtual_prefix, nullptr, 0)) { 
                        res = true; 
                        break; 
                    }
                }
            }
        }
    }
    if (!res) {
        if (g_global_cfg.redir_rules) {
            for (int i = 0; i < g_global_cfg.redir_count; i++) {
                if (strlen(sub_path) < strlen(g_global_cfg.redir_rules[i].virtual_prefix)) {
                    if (vfs_get_virtual_child(sub_path, g_global_cfg.redir_rules[i].virtual_prefix, nullptr, 0)) { 
                        res = true; 
                        break; 
                    }
                }
            }
        }
    }
    return res;
}

bool vfs_is_redirect_target(AppConfig* cfg, const char* sub_path) {
    bool res = false;
    if (cfg && cfg->trie_root) {
        res = trie_is_redirect_target(cfg->trie_root, sub_path);
    }
    if (!res && g_global_cfg.trie_root) {
        res = trie_is_redirect_target(g_global_cfg.trie_root, sub_path);
    }
    if (!res && cfg) {
        if (cfg->redir_rules) {
            for (int i = 0; i < cfg->redir_count; i++) {
                if (strcmp(sub_path, cfg->redir_rules[i].virtual_prefix) == 0) { 
                    res = true; 
                    break; 
                }
            }
        }
        if (!res && cfg->sandbox && strcmp(sub_path, "/") == 0) res = true;
    }
    if (!res) {
        if (g_global_cfg.redir_rules) {
            for (int i = 0; i < g_global_cfg.redir_count; i++) {
                if (strcmp(sub_path, g_global_cfg.redir_rules[i].virtual_prefix) == 0) { 
                    res = true; 
                    break; 
                }
            }
        }
        if (!res && !(cfg && cfg->sandbox_explicit) && g_global_cfg.sandbox && strcmp(sub_path, "/") == 0) res = true;
    }
    return res;
}

void vfs_log_io(AppConfig* cfg, const char* pkg, uid_t uid, const char* op, const char* sub_path, const char* real_path, bool is_redir) {
    bool monitor_on = (cfg && cfg->monitor_explicit) ? cfg->monitor : g_global_cfg.monitor;
    if (monitor_on) {
        if (is_redir) {
            log_internal(LOG_IO, "[%s(%u)] [%s] %s -> %s", pkg, uid, op, sub_path, real_path);
        } else {
            log_internal(LOG_IO, "[%s(%u)] [%s] %s", pkg, uid, op, sub_path);
        }
    }
    if (is_redir && g_min_log_level == LOG_DEBUG) {
        log_internal(LOG_DEBUG, "[MAP] %s: '%s' -> '%s'", op, sub_path, real_path);
    }
}

void vfs_log_io_err(const char* pkg, const char* op, const char* sub_path, const char* fmt, ...) {
    char msg[1024]; 
    va_list args; 
    va_start(args, fmt); 
    vsnprintf(msg, sizeof(msg), fmt, args); 
    va_end(args);
    log_internal(LOG_IO, "[%s] [ERR] %s %s %s", pkg, op, sub_path, msg);
}

void vfs_hash_init(DirHashTable* ht) { 
    memset(ht->buckets, 0, sizeof(ht->buckets)); 
}

static unsigned long hash_djb2(const char *str) { 
    unsigned long hash = 5381; 
    int c; 
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; 
    }
    return hash; 
}

bool vfs_hash_insert(DirHashTable* ht, const char* name) {
    unsigned long h = hash_djb2(name) % HASH_BUCKETS; 
    HashNode* node = ht->buckets[h];
    while (node) { 
        if (strcmp(node->name, name) == 0) return false; 
        node = node->next; 
    }
    HashNode* new_node = malloc(sizeof(HashNode));
    if (new_node) { 
        new_node->name = strdup(name); 
        if (!new_node->name) {
            free(new_node);
            return false;
        }
        new_node->next = ht->buckets[h]; 
        ht->buckets[h] = new_node; 
        return true; 
    }
    return false;
}

void vfs_hash_free(DirHashTable* ht) {
    for (int i = 0; i < HASH_BUCKETS; i++) {
        HashNode* node = ht->buckets[i];
        while (node) { 
            HashNode* temp = node; 
            node = node->next; 
            free(temp->name); 
            free(temp); 
        }
    }
}

bool vfs_is_virtual_dir_empty(AppConfig* cfg, const char* sub_path, const char* real_path, const char* current_pkg) {
    if (vfs_is_virtual_ancestor(cfg, sub_path)) return false; 
    struct stat st; 
    if (lstat(real_path, &st) == -1) return true;
    DIR* dp = opendir(real_path); 
    if (!dp) return false;
    struct fuse_context* ctx = fuse_get_context();
    if (!ctx) {
        closedir(dp);
        return true;
    }
    struct dirent *de; 
    bool empty = true;
    bool is_root = (strcmp(sub_path, "/") == 0 || sub_path[0] == '\0');
    bool sandbox_enabled = (!g_disable_sandbox && cfg && cfg->sandbox && current_pkg[0] && strcmp(current_pkg, "system") != 0 && strcmp(current_pkg, "unknown") != 0);
    
    while ((de = readdir(dp)) != nullptr) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (path_contains_invalid_chars(de->d_name)) continue;
        char item_sub_path[2048];
        if (is_root) snprintf(item_sub_path, 2047, "/%s", de->d_name);
        else snprintf(item_sub_path, 2047, "%s/%s", sub_path, de->d_name);
        if (ctx->uid != 0 && (is_path_hidden_internal(cfg, item_sub_path, current_pkg, nullptr) || vfs_is_redirect_target(cfg, item_sub_path))) continue;
        if (sandbox_enabled) {
            if (strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0 ||
                strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0) {
                if (strcmp(de->d_name, current_pkg) != 0) continue; 
            }
        }
        empty = false; 
        break;
    }
    closedir(dp); 
    return empty;
}

bool vfs_fill_virtual_dirs(AppConfig* cfg, const char* sub_path, int path_user_id, void* buf, fuse_fill_dir_t filler, uid_t uid, gid_t gid, DirHashTable* ht, bool is_root, const char* current_pkg) {
#define PROCESS_CFG_DIRS(c) \
    do { \
        if (!(c) || !(c)->redir_rules) break; \
        for (int i = 0; i < (c)->redir_count; i++) { \
            char name[256]; \
            if (vfs_get_virtual_child(sub_path, (c)->redir_rules[i].virtual_prefix, name, sizeof(name))) { \
                char full_vpath[PATH_MAX]; \
                if (is_root) snprintf(full_vpath, PATH_MAX, "/%s", name); \
                else snprintf(full_vpath, PATH_MAX, "%s/%s", sub_path, name); \
                if (strcmp(full_vpath, (c)->redir_rules[i].virtual_prefix) == 0) { \
                     char dummy[PATH_MAX]; \
                     if (!build_real_base_from_target((c)->redir_rules[i].real_target, (path_user_id >= 0 ? path_user_id : 0), dummy, sizeof dummy, (c), &g_global_cfg, current_pkg)) continue; \
                } \
                if (vfs_hash_insert(ht, name)) { \
                    struct stat st_dir; memset(&st_dir, 0, sizeof(st_dir)); \
                    st_dir.st_ino = synthetic_inode(name); st_dir.st_mode = S_IFDIR | 0755; st_dir.st_uid = uid; st_dir.st_gid = gid; \
                    if (filler(buf, name, &st_dir, 0, 0) != 0) return false; \
                } \
            } \
        } \
    } while(0)
    
    PROCESS_CFG_DIRS(cfg);
    PROCESS_CFG_DIRS(&g_global_cfg);
#undef PROCESS_CFG_DIRS
    return true;
}