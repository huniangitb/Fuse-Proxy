#define _GNU_SOURCE
#include "vfs_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <fnmatch.h>
#include <pthread.h>
#include <dirent.h>
char g_rules_path[PATH_MAX] = {0};

typedef struct { uid_t uid; char pkg[128]; } UidMap;
static UidMap g_uid_maps[1024];
static int g_uid_map_count = 0;

#define UID_CACHE_SIZE 2048
static AppConfig* uid_cfg_cache[UID_CACHE_SIZE] = {nullptr};
static uid_t uid_cached[UID_CACHE_SIZE] = {0};
static char uid_pkg_cache[UID_CACHE_SIZE][128];

static void load_uid_map() {
    FILE* fp = fopen(CONFIG_DIR "/uid.map", "r");
    g_uid_map_count = 0; 
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp) && g_uid_map_count < 1024) {
        uid_t u; char p[128];
        if (sscanf(line, "%d %127s", &u, p) == 2) {
            g_uid_maps[g_uid_map_count].uid = u;
            strncpy(g_uid_maps[g_uid_map_count].pkg, p, 127);
            g_uid_map_count++;
        }
    }
    fclose(fp);
}

static void* signal_monitor_thread(void* arg) {
    (void)arg; sigset_t set; int sig; sigemptyset(&set); sigaddset(&set, SIGHUP);
    while (true) {
        if (sigwait(&set, &sig) != 0) continue;
        if (sig == SIGHUP) {
            config_lock_write();
            load_config_rules(g_rules_path); 
            load_uid_map();
            memset(uid_cached, 0, sizeof(uid_cached)); 
            memset(uid_cfg_cache, 0, sizeof(uid_cfg_cache)); 
            memset(uid_pkg_cache, 0, sizeof(uid_pkg_cache));
            config_unlock_write();
            LOG_MON("已接收通知，重新加载配置，全局监控状态: %s", g_global_cfg.monitor ? "开启" : "关闭");
        }
    }
    return nullptr;
}

void vfs_core_init(const char* rules_path) {
    strncpy(g_rules_path, rules_path, PATH_MAX - 1);
    sigset_t set; sigemptyset(&set); sigaddset(&set, SIGHUP); pthread_sigmask(SIG_BLOCK, &set, nullptr);
    pthread_t sig_thread; pthread_create(&sig_thread, nullptr, signal_monitor_thread, nullptr); pthread_detach(sig_thread);

    config_lock_write();
    load_config_rules(g_rules_path);
    load_uid_map();
    config_unlock_write();
}

AppConfig* vfs_get_app_cfg(uid_t uid, pid_t tid, char* current_pkg_out) {
    if (uid < 10000) {
        strncpy(current_pkg_out, "system", 127);
        current_pkg_out[127] = '\0';
        return nullptr; 
    }
    
    int slot = uid % UID_CACHE_SIZE;
    if (uid_cached[slot] == uid && uid_cfg_cache[slot] != (AppConfig*)-1) {
        strncpy(current_pkg_out, uid_pkg_cache[slot], 127);
        current_pkg_out[127] = '\0';
        return uid_cfg_cache[slot];
    }
    
    int user_id = uid / 100000;
    char final_pkg[256] = {0}; pid_t main_pid = tid;
    
    // 关键：外部调用者已持有 config_lock_read()，移除此处冗余的 config_lock_read() 杜绝锁重入死锁
    for (int i = 0; i < g_uid_map_count; i++) {
        if (g_uid_maps[i].uid == uid) { strncpy(final_pkg, g_uid_maps[i].pkg, 255); break; }
    }

    if (final_pkg[0] == '\0') {
        char status_path[64]; snprintf(status_path, sizeof(status_path), "/proc/%d/status", tid);
        FILE* fp = fopen(status_path, "r");
        if (fp) {
            char line[256];
            while(fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "Tgid:", 5) == 0) { main_pid = atoi(line + 5); break; }
            }
            fclose(fp);
        }
        char path[64]; snprintf(path, sizeof(path), "/proc/%d/cmdline", main_pid);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) { read(fd, final_pkg, sizeof(final_pkg)-1); close(fd); }
    }

    char base_pkg[256];
    strncpy(base_pkg, final_pkg, sizeof(base_pkg) - 1);
    char* colon = strchr(base_pkg, ':'); 
    if (colon) *colon = 0;

    strncpy(current_pkg_out, base_pkg, 127); current_pkg_out[127] = '\0';

    // 关键：如果尚未完成初始化或为 zygote 等过渡进程，决不能向缓存写入 UID 导致配置锁死
    if (strlen(base_pkg) < 3 || strstr(base_pkg, "zygote") != nullptr || strstr(base_pkg, "<pre-") != nullptr) {
        uid_cached[slot] = 0; // 强制设为0，使后续 specialized 后仍能重新穿透查询
        uid_cfg_cache[slot] = nullptr;
        return nullptr; 
    }

    strncpy(uid_pkg_cache[slot], current_pkg_out, 127); uid_pkg_cache[slot][127] = '\0';

    AppConfig* matched = nullptr;
    // 关键：同理移除冗余的 config_lock_read() 
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i]->user_id == user_id && (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 || fnmatch(g_app_cfgs[i]->pkg_name, final_pkg, 0) == 0)) { 
            matched = g_app_cfgs[i]; break; 
        }
    }
    if (!matched) {
        for (int i = 0; i < g_app_cfg_count; i++) {
            if (g_app_cfgs[i]->user_id == -1 && (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 || fnmatch(g_app_cfgs[i]->pkg_name, final_pkg, 0) == 0)) { 
                matched = g_app_cfgs[i]; break; 
            }
        }
    }
    
    uid_cached[slot] = uid; uid_cfg_cache[slot] = matched; 
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
                memcpy(target_pkg, pkg_start, pkg_len); target_pkg[pkg_len] = '\0';
                if (strcmp(target_pkg, current_pkg) != 0) return true;
            }
            break;
        }
    }
    return false;
}

static bool is_path_hidden_internal(AppConfig* cfg, const char* sub_path, const char* current_pkg) {
    if (strncmp(sub_path, CONFIG_DIR, strlen(CONFIG_DIR)) == 0) return true;

    if (strcmp(sub_path, "/Android") == 0 || strcmp(sub_path, "/Android/") == 0 ||
        strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0 ||
        strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0) {
        return false; 
    }

    if (vfs_is_other_app_pkg(sub_path, current_pkg)) return true;

    config_lock_read();
    bool hidden = false;
    if (cfg) {
        for (int i = 0; i < cfg->hide_count; i++) {
            if (fnmatch(cfg->hide_rules[i], sub_path, 0) == 0) { hidden = true; break; }
            size_t len = strlen(cfg->hide_rules[i]);
            if (strncmp(sub_path, cfg->hide_rules[i], len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { hidden = true; break; }
        }
    }
    if (!hidden) {
        for (int i = 0; i < g_global_cfg.hide_count; i++) {
            if (fnmatch(g_global_cfg.hide_rules[i], sub_path, 0) == 0) { hidden = true; break; }
            size_t len = strlen(g_global_cfg.hide_rules[i]);
            if (strncmp(sub_path, g_global_cfg.hide_rules[i], len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { hidden = true; break; }
        }
    }
    config_unlock_read();
    return hidden;
}

int vfs_sanitize_and_check_hidden(AppConfig* cfg, const char* path, int* path_user_id_out, char* sub_path_out, size_t sub_path_size, const char* current_pkg, uid_t uid) {
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

    if (uid != 0 && is_path_hidden_internal(cfg, sub_path_out, current_pkg)) return -ENOENT;
    return 0;
}

static bool check_redir_rule(AppConfig* c, const char* sub_path, char* temp, int user_id, const char* current_pkg) {
    if (!c) return false;
    for (int i = 0; i < c->redir_count; i++) {
        const char* prefix = c->redir_rules[i].virtual_prefix; size_t len = strlen(prefix);
        bool is_root = (strcmp(prefix, "/") == 0);
        if (is_root || (strncmp(sub_path, prefix, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/'))) {
            const char* suffix = is_root ? sub_path : (sub_path + len);
            char real_base[MAX_PATH_LEN];
            const char* target = c->redir_rules[i].real_target;
            if (target[0] == '?') {
                int effective_uid = user_id >= 0 ? user_id : 0;
                snprintf(real_base, sizeof(real_base), STORAGE_BASE "/%d%s", effective_uid, target + 1);
            } else {
                strncpy(real_base, target, sizeof(real_base) - 1); real_base[sizeof(real_base) - 1] = '\0';
            }
            size_t tlen = strlen(real_base);
            bool t_slash = (tlen > 0 && real_base[tlen-1] == '/'); bool s_slash = (suffix[0] == '/');
            if (t_slash && s_slash) snprintf(temp, 1023, "%s%s", real_base, suffix + 1);
            else if (!t_slash && !s_slash) {
                if (suffix[0] == '\0') snprintf(temp, 1023, "%s", real_base);
                else snprintf(temp, 1023, "%s/%s", real_base, suffix);
            } else snprintf(temp, 1023, "%s%s", real_base, suffix);
            return true;
        }
    }
    
    if (c->sandbox && current_pkg[0] && strcmp(current_pkg, "system") != 0 && strcmp(current_pkg, "unknown") != 0) {
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

        char sandbox_target[MAX_PATH_LEN];
        int effective_uid = user_id;
        if (effective_uid < 0) {
            struct fuse_context* fctx = fuse_get_context();
            if (fctx && fctx->uid >= 10000) effective_uid = (int)(fctx->uid / 100000);
        }
        if (effective_uid < 0) effective_uid = 0;
        snprintf(sandbox_target, sizeof(sandbox_target), STORAGE_BASE "/%d/Android/data/%s/sandbox", effective_uid, current_pkg);
        if (access(sandbox_target, F_OK) != 0) mkdir_recursive_p(sandbox_target, 0775);
        snprintf(temp, 1023, "%s%s", sandbox_target, sub_path);
        return true;
    }
    return false;
}

int vfs_to_real_path(AppConfig* cfg, const char* sub_path, char* out_buf, size_t size, int user_id, bool* is_redir_out, const char* current_pkg) {
    char temp[1024]; 
    bool redir = false;
    config_lock_read();
    redir = check_redir_rule(cfg, sub_path, temp, user_id, current_pkg);
    if (!redir) redir = check_redir_rule(&g_global_cfg, sub_path, temp, user_id, current_pkg);
    config_unlock_read();

    if (!redir) {
        if (user_id >= 0) snprintf(temp, sizeof(temp), STORAGE_BASE "/%d%s", user_id, sub_path);
        else snprintf(temp, sizeof(temp), STORAGE_BASE "%s", sub_path);
    }
    
    strncpy(out_buf, temp, size - 1);
    out_buf[size - 1] = '\0';
    if (is_redir_out) *is_redir_out = redir;
    if (out_buf[0] == '\0') return -ENOENT;
    return 0;
}

bool vfs_is_path_ro(AppConfig* cfg, const char* sub_path) {
    config_lock_read(); 
    bool ro = false;
    if (cfg) {
        for (int i = 0; i < cfg->ro_count; i++) {
            if (fnmatch(cfg->ro_rules[i], sub_path, 0) == 0) { ro = true; break; }
            size_t len = strlen(cfg->ro_rules[i]);
            if (strncmp(sub_path, cfg->ro_rules[i], len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { ro = true; break; }
        }
    }
    if (!ro) {
        for (int i = 0; i < g_global_cfg.ro_count; i++) {
            if (fnmatch(g_global_cfg.ro_rules[i], sub_path, 0) == 0) { ro = true; break; }
            size_t len = strlen(g_global_cfg.ro_rules[i]);
            if (strncmp(sub_path, g_global_cfg.ro_rules[i], len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { ro = true; break; }
        }
    }
    config_unlock_read();
    return ro;
}

bool vfs_get_virtual_child(const char* parent, const char* desc, char* name) {
    size_t plen = strlen(parent); if (strcmp(parent, "/") == 0) plen = 0; 
    if (strncmp(parent, desc, plen) != 0) return false;
    if (plen > 0 && desc[plen] != '/' && desc[plen] != '\0') return false;
    const char* p = desc + plen; if (*p == '/') p++; if (*p == '\0') return false;
    const char* slash = strchr(p, '/'); size_t nlen = slash ? (size_t)(slash - p) : strlen(p);
    if (nlen == 0) return false; if (name) { strncpy(name, p, nlen); name[nlen] = '\0'; }
    return true;
}

bool vfs_is_virtual_ancestor(AppConfig* cfg, const char* sub_path) {
    config_lock_read(); 
    bool res = false;
    if (cfg) {
        for (int i = 0; i < cfg->redir_count; i++)
            if (strlen(sub_path) < strlen(cfg->redir_rules[i].virtual_prefix))
                if (vfs_get_virtual_child(sub_path, cfg->redir_rules[i].virtual_prefix, nullptr)) { res = true; break; }
    }
    if (!res) {
        for (int i = 0; i < g_global_cfg.redir_count; i++)
            if (strlen(sub_path) < strlen(g_global_cfg.redir_rules[i].virtual_prefix))
                if (vfs_get_virtual_child(sub_path, g_global_cfg.redir_rules[i].virtual_prefix, nullptr)) { res = true; break; }
    }
    config_unlock_read(); return res;
}

bool vfs_is_redirect_target(AppConfig* cfg, const char* sub_path) {
    config_lock_read(); 
    bool res = false;
    if (cfg) {
        for (int i = 0; i < cfg->redir_count; i++)
            if (strcmp(sub_path, cfg->redir_rules[i].virtual_prefix) == 0) { res = true; break; }
        if (!res && cfg->sandbox && strcmp(sub_path, "/") == 0) res = true;
    }
    if (!res) {
        for (int i = 0; i < g_global_cfg.redir_count; i++)
            if (strcmp(sub_path, g_global_cfg.redir_rules[i].virtual_prefix) == 0) { res = true; break; }
        if (!res && g_global_cfg.sandbox && strcmp(sub_path, "/") == 0) res = true;
    }
    config_unlock_read(); return res;
}

void vfs_log_io(AppConfig* cfg, const char* pkg, uid_t uid, const char* op, const char* sub_path, const char* real_path, bool is_redir) {
    if ((cfg && cfg->monitor) || g_global_cfg.monitor) {
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
    char msg[1024]; va_list args; va_start(args, fmt); vsnprintf(msg, sizeof(msg), fmt, args); va_end(args);
    log_internal(LOG_ERROR, "[ERR] %s %s %s", op, sub_path, msg);
    log_internal(LOG_IO, "[%s(%u)] [ERR] %s %s %s", pkg, fuse_get_context()->uid, op, sub_path, msg);
}

void vfs_hash_init(DirHashTable* ht) { memset(ht->buckets, 0, sizeof(ht->buckets)); }
static unsigned long hash_djb2(const char *str) { unsigned long hash = 5381; int c; while ((c = *str++)) hash = ((hash << 5) + hash) + c; return hash; }

bool vfs_hash_insert(DirHashTable* ht, const char* name) {
    unsigned long h = hash_djb2(name) % HASH_BUCKETS; HashNode* node = ht->buckets[h];
    while (node) { if (strcmp(node->name, name) == 0) return false; node = node->next; }
    HashNode* new_node = malloc(sizeof(HashNode));
    if (new_node) { new_node->name = strdup(name); new_node->next = ht->buckets[h]; ht->buckets[h] = new_node; return true; }
    return false;
}

void vfs_hash_free(DirHashTable* ht) {
    for (int i = 0; i < HASH_BUCKETS; i++) {
        HashNode* node = ht->buckets[i];
        while (node) { HashNode* temp = node; node = node->next; free(temp->name); free(temp); }
    }
}

bool vfs_is_virtual_dir_empty(AppConfig* cfg, const char* sub_path, const char* real_path, const char* current_pkg) {
    struct stat st; if (lstat(real_path, &st) == -1) return true;
    DIR* dp = opendir(real_path); if (!dp) return false;
    struct fuse_context* ctx = fuse_get_context();
    struct dirent *de; 
    bool empty = true;
    bool is_root = (strcmp(sub_path, "/") == 0 || sub_path[0] == '\0');
    bool sandbox_enabled = (cfg && current_pkg[0] && strcmp(current_pkg, "system") != 0 && strcmp(current_pkg, "unknown") != 0);

    while ((de = readdir(dp)) != nullptr) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (path_contains_invalid_chars(de->d_name)) continue;
        char item_sub_path[2048];
        if (is_root) snprintf(item_sub_path, 2047, "/%s", de->d_name);
        else snprintf(item_sub_path, 2047, "%s/%s", sub_path, de->d_name);

        if (ctx->uid != 0 && (is_path_hidden_internal(cfg, item_sub_path, current_pkg) || vfs_is_redirect_target(cfg, item_sub_path))) continue;

        if (sandbox_enabled) {
            if (strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0 ||
                strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0) {
                if (strcmp(de->d_name, current_pkg) != 0) continue; 
            }
        }
        empty = false; break;
    }
    closedir(dp); return empty;
}

void vfs_fill_virtual_dirs(AppConfig* cfg, const char* sub_path, int path_user_id, void* buf, fuse_fill_dir_t filler, uid_t uid, gid_t gid, DirHashTable* ht, bool is_root) {
    config_lock_read();
#define PROCESS_CFG_DIRS(c) \
    do { \
        if (!(c)) break; \
        for (int i = 0; i < (c)->redir_count; i++) { \
            char name[256]; \
            if (vfs_get_virtual_child(sub_path, (c)->redir_rules[i].virtual_prefix, name)) { \
                char full_vpath[PATH_MAX]; \
                if (is_root) snprintf(full_vpath, PATH_MAX, "/%s", name); \
                else snprintf(full_vpath, PATH_MAX, "%s/%s", sub_path, name); \
                if (strcmp(full_vpath, (c)->redir_rules[i].virtual_prefix) == 0) { \
                     char dummy[1024]; const char* target = (c)->redir_rules[i].real_target; \
                     if (target[0] == '?') { int effective_uid = path_user_id >= 0 ? path_user_id : 0; snprintf(dummy, sizeof(dummy), STORAGE_BASE "/%d%s", effective_uid, target + 1); } \
                     else { strncpy(dummy, target, sizeof(dummy)-1); } \
                     if (access(dummy, F_OK) != 0) continue; \
                } \
                if (vfs_hash_insert(ht, name)) { \
                    struct stat st_dir; memset(&st_dir, 0, sizeof(st_dir)); \
                    st_dir.st_mode = S_IFDIR | 0755; st_dir.st_uid = uid; st_dir.st_gid = gid; \
                    filler(buf, name, &st_dir, 0, 0); \
                } \
            } \
        } \
    } while(0)

    PROCESS_CFG_DIRS(cfg);
    PROCESS_CFG_DIRS(&g_global_cfg);
#undef PROCESS_CFG_DIRS
    config_unlock_read();
}