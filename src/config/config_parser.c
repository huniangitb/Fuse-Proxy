#define _GNU_SOURCE
#include "config_parser.h"
#include "common.h"
#include "path_vars.h"
#include "inject_target.h"
#include <sys/stat.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <ctype.h>
#include <fnmatch.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
AppConfig g_global_cfg;
AppConfig** g_app_cfgs = nullptr;
int g_app_cfg_count = 0;
int g_app_cfg_capacity = 0;
int g_active_users[MAX_USERS];
int g_active_user_count = 0;
static pthread_rwlock_t g_rules_lock;
static bool is_wildcard_string(const char *str) {
    /* `?` 作为首字符是项目自定义的"相对当前 user 存储"前缀，非 fnmatch 通配；
       仅从第二字符起检测真正的通配符 * ? [ ]，避免 ALLOW/REDIRECT 的 ? 前缀路径被误判跳过 trie */
    if (!str || !str[0]) return false;
    const char *p = (str[0] == '?') ? str + 1 : str;
    return strpbrk(p, "*?[]") != NULL;
}
void config_init_lock() { pthread_rwlock_init(&g_rules_lock, nullptr); }
void config_destroy_lock() { pthread_rwlock_destroy(&g_rules_lock); }
void config_lock_read() { pthread_rwlock_rdlock(&g_rules_lock); }
void config_unlock_read() { pthread_rwlock_unlock(&g_rules_lock); }
void config_lock_write() { pthread_rwlock_wrlock(&g_rules_lock); }
void config_unlock_write() { pthread_rwlock_unlock(&g_rules_lock); }
static void free_app_config_rules(AppConfig* cfg) {
    if (!cfg) return;
    if (cfg->trie_root) {
        trie_free(cfg->trie_root);
        cfg->trie_root = nullptr;
    }
    if (cfg->hide_rules) {
        for (int i = 0; i < cfg->hide_count; i++) free(cfg->hide_rules[i]);
        free(cfg->hide_rules);
        cfg->hide_rules = nullptr;
    }
    cfg->hide_count = 0;
    cfg->hide_capacity = 0;
    if (cfg->ro_rules) {
        for (int i = 0; i < cfg->ro_count; i++) free(cfg->ro_rules[i]);
        free(cfg->ro_rules);
        cfg->ro_rules = nullptr;
    }
    cfg->ro_count = 0;
    cfg->ro_capacity = 0;
    if (cfg->redir_rules) {
        free(cfg->redir_rules);
        cfg->redir_rules = nullptr;
    }
    cfg->redir_count = 0;
    cfg->redir_capacity = 0;
    if (cfg->ftp_rules) {
        free(cfg->ftp_rules);
        cfg->ftp_rules = nullptr;
    }
    cfg->ftp_count = 0;
    cfg->ftp_capacity = 0;
    if (cfg->var_names) {
        for (int i = 0; i < cfg->var_count; i++) free(cfg->var_names[i]);
        free(cfg->var_names);
        cfg->var_names = nullptr;
    }
    if (cfg->var_values) {
        for (int i = 0; i < cfg->var_count; i++) free(cfg->var_values[i]);
        free(cfg->var_values);
        cfg->var_values = nullptr;
    }
    if (cfg->var_resolved) {
        for (int i = 0; i < cfg->var_count; i++) free(cfg->var_resolved[i]);
        free(cfg->var_resolved);
        cfg->var_resolved = nullptr;
    }
    if (cfg->var_is_static) {
        free(cfg->var_is_static);
        cfg->var_is_static = nullptr;
    }
    cfg->var_count = 0;
    cfg->var_capacity = 0;
}
static void free_config_rules() {
    free_app_config_rules(&g_global_cfg);
    if (g_app_cfgs) {
        for (int i = 0; i < g_app_cfg_count; i++) {
            free_app_config_rules(g_app_cfgs[i]);
            free(g_app_cfgs[i]);
        }
        free(g_app_cfgs);
        g_app_cfgs = nullptr;
    }
    g_app_cfg_count = 0;
    g_app_cfg_capacity = 0;
}
char* clean_path_string(char* str) {
    if (!str) return nullptr;
    while(isspace((unsigned char)*str)) str++; if(*str == 0) return str;
    char* end = str + strlen(str) - 1; while(end > str && isspace((unsigned char)*end)) end--;
    *(end+1) = 0;
    for (int i = 0; str[i]; i++) { if (str[i] == '\r' || str[i] == '\n') { str[i] = '\0'; break; } }
    return str;
}
void strip_trailing_slash(char* path) {
    /* 剥尾随 '/'，但保留 "?/"——'?' 后必跟 '/' 是内部前缀语义（见 docs/path-variables.md），
       剥成裸 '?' 会使 Trie 命中根 redirect 时拼出 ?Android 而非 ?/Android，
       导致 vfs_to_real_path 还原成 /data/media/0Android（缺分隔符） */
    size_t len = strlen(path);
    if (len > 1 && path[len - 1] == '/' && !(len == 2 && path[0] == '?')) path[len - 1] = '\0';
}
/* mkdir_recursive_p / inherit_from_parent / sync_attributes 已迁移至 common.c（公共工具） */
static char* get_next_token(char** ptr) {
    char* p = *ptr;
    if (!p) return nullptr;
    while (isspace((unsigned char)*p)) p++;
    if (*p == '\0') { *ptr = nullptr; return nullptr; }
    char* start;
    if (*p == '"') {
        start = ++p;
        while (*p && *p != '"') p++;
        if (*p == '"') { *p = '\0'; *ptr = p + 1; } 
        else *ptr = p;
    } else {
        start = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        if (*p != '\0') { *p = '\0'; *ptr = p + 1; } 
        else *ptr = p;
    }
    return start;
}
static char* strip_storage_prefix(char* path) {
    if (strncmp(path, "/storage/emulated/", 18) == 0) {
        char* p = path + 18;
        while (*p && isdigit((unsigned char)*p)) p++;
        if (*p == '/') return p;       /* /storage/emulated/0/Download -> /Download */
        if (*p == '\0') return "/";    /* /storage/emulated/0 -> / */
        /* 异常形态:缺数字 user_id 或后跟非数字(如 /storage/emulated/Download)。
           把 p 退回非数字起始位置,前面补 '/',让残留当子路径(与正常 emulated 剥离一致)。 */
        return p - 1;
    }
    return path;
}
static int cmp_redir(const void* a, const void* b) {
    return (int)strlen(((const RedirectRule*)b)->virtual_prefix) - (int)strlen(((const RedirectRule*)a)->virtual_prefix);
}
static int cmp_hide(const void* a, const void* b) {
    const char* str_a = *(const char**)a;
    const char* str_b = *(const char**)b;
    return (int)strlen(str_b) - (int)strlen(str_a);
}
static void parse_config_line(AppConfig* cur, char* line, int user_id, int line_num, const char* file_path) {
    (void)user_id;
    char* p_ptr = line;
    /* 先尝试 NAME=VALUE 赋值（紧凑形式，无空格围绕 =） */
    {
        char vname[128], vvalue[MAX_PATH_LEN];
        if (parse_var_assignment(line, vname, sizeof vname, vvalue, sizeof vvalue)) {
            if (strcmp(vname, "package") == 0) {
                LOG_WRN("不允许覆盖系统保留变量 package (行 %d, 文件 %s)", line_num, file_path);
            } else {
                if (cur->var_count >= cur->var_capacity) {
                    int newcap = cur->var_capacity == 0 ? 8 : cur->var_capacity * 2;
                    char **new_names = realloc(cur->var_names, newcap * sizeof(char*));
                    char **new_values = realloc(cur->var_values, newcap * sizeof(char*));
                    char **new_resolved = realloc(cur->var_resolved, newcap * sizeof(char*));
                    bool *new_is_static = realloc(cur->var_is_static, newcap * sizeof(bool));
                    if (!new_names || !new_values || !new_resolved || !new_is_static) {
                        LOG_ERR("realloc 变量数组失败 (行 %d)", line_num);
                        free(new_names); free(new_values);
                        free(new_resolved); free(new_is_static);
                        return;
                    }
                    cur->var_names   = new_names;
                    cur->var_values  = new_values;
                    cur->var_resolved= new_resolved;
                    cur->var_is_static = new_is_static;
                    cur->var_capacity = newcap;
                }
                cur->var_names[cur->var_count] = strdup(vname);
                cur->var_values[cur->var_count] = strdup(vvalue);
                cur->var_resolved[cur->var_count] = NULL;
                cur->var_is_static[cur->var_count] = false;
                cur->var_count++;
            }
            return;
        }
    }
    char* tok = get_next_token(&p_ptr);
    if (!tok) return;
    if (strcmp(tok, "MONITOR") == 0) {
        char* val = get_next_token(&p_ptr);
        cur->monitor = (val && (strcmp(val, "ON") == 0 || strcmp(val, "1") == 0));
        cur->monitor_explicit = true;
    } else if (strcmp(tok, "SANDBOX") == 0) {
        char* val = get_next_token(&p_ptr);
        cur->sandbox = (val && (strcmp(val, "ON") == 0 || strcmp(val, "1") == 0));
        cur->sandbox_explicit = true;
    } else if (strcmp(tok, "GLOBAL_INJECT") == 0) {
        char* val = get_next_token(&p_ptr);
        cur->global_inject = (val && (strcmp(val, "ON") == 0 || strcmp(val, "1") == 0));
    } else if (strcmp(tok, "FUSE_DIRECT") == 0) {
        char* val = get_next_token(&p_ptr);
        cur->fuse_direct = (val && (strcmp(val, "ON") == 0 || strcmp(val, "1") == 0));
    } else if (strcmp(tok, "SKIP_SYSTEM_APPS") == 0) {
        char* val = get_next_token(&p_ptr);
        cur->skip_system_apps = (val && (strcmp(val, "ON") == 0 || strcmp(val, "1") == 0));
    } else if (strcmp(tok, "FUSE_EXTRA_ARGS") == 0) {
        /* 读取行尾剩余全部内容，不做分词（原样透传给 fuse_daemon） */
        char* p = p_ptr;
        while (p && isspace((unsigned char)*p)) p++;
        if (p && *p) {
            size_t len = strlen(p);
            while (len > 0 && isspace((unsigned char)p[len - 1])) len--;
            if (len > 0) {
                size_t copy_len = len < sizeof(cur->fuse_extra_args) - 1 ? len : sizeof(cur->fuse_extra_args) - 1;
                memcpy(cur->fuse_extra_args, p, copy_len);
                cur->fuse_extra_args[copy_len] = '\0';
            }
        }
    } else if (strcmp(tok, "HIDE") == 0) {
        char* val = get_next_token(&p_ptr);
        if (val) {
            char *v_ptr = strip_storage_prefix(val);
            char clean_rule[MAX_PATH_LEN];
            if (v_ptr[0] != '/' && v_ptr[0] != '*') snprintf(clean_rule, MAX_PATH_LEN, "/%s", v_ptr);
            else {
                strncpy(clean_rule, v_ptr, MAX_PATH_LEN - 1);
                clean_rule[MAX_PATH_LEN - 1] = '\0';
            }
            if (strpbrk(clean_rule, "*?[]") == nullptr) strip_trailing_slash(clean_rule);
            if (cur->hide_count >= cur->hide_capacity) {
                int new_cap = cur->hide_capacity == 0 ? 8 : cur->hide_capacity * 2;
                char **new_hide = realloc(cur->hide_rules, new_cap * sizeof(char*));
                if (!new_hide) {
                    LOG_ERR("realloc hide_rules 失败");
                    return;
                }
                cur->hide_rules = new_hide;
                cur->hide_capacity = new_cap;
            }
            cur->hide_rules[cur->hide_count] = strdup(clean_rule);
            cur->hide_count++;
            if (!is_wildcard_string(clean_rule) && !has_path_var(clean_rule)) {
                trie_insert(cur->trie_root, clean_rule, NULL, true, false);
            }
        }
    } else if (strcmp(tok, "RO") == 0) {
        char* val = get_next_token(&p_ptr);
        if (val) {
            char *v_ptr = strip_storage_prefix(val);
            char clean_rule[MAX_PATH_LEN];
            if (v_ptr[0] != '/' && v_ptr[0] != '*') snprintf(clean_rule, MAX_PATH_LEN, "/%s", v_ptr);
            else {
                strncpy(clean_rule, v_ptr, MAX_PATH_LEN - 1);
                clean_rule[MAX_PATH_LEN - 1] = '\0';
            }
            if (strpbrk(clean_rule, "*?[]") == nullptr) strip_trailing_slash(clean_rule);
            if (cur->ro_count >= cur->ro_capacity) {
                int new_cap = cur->ro_capacity == 0 ? 8 : cur->ro_capacity * 2;
                char **new_ro = realloc(cur->ro_rules, new_cap * sizeof(char*));
                if (!new_ro) {
                    LOG_ERR("realloc ro_rules 失败");
                    return;
                }
                cur->ro_rules = new_ro;
                cur->ro_capacity = new_cap;
            }
            cur->ro_rules[cur->ro_count] = strdup(clean_rule);
            cur->ro_count++;
            if (!is_wildcard_string(clean_rule) && !has_path_var(clean_rule)) {
                trie_insert(cur->trie_root, clean_rule, NULL, false, true);
            }
        }
    } else if (strcmp(tok, "ALLOW") == 0) {
        char* val = get_next_token(&p_ptr);
        if (val) {
            char *v_ptr = strip_storage_prefix(val);
            char virtual_prefix[MAX_PATH_LEN];
            if (v_ptr[0] == '\0') strcpy(virtual_prefix, "/"); 
            else {
                if (v_ptr[0] != '/') snprintf(virtual_prefix, MAX_PATH_LEN, "/%s", v_ptr);
                else {
                    strncpy(virtual_prefix, v_ptr, MAX_PATH_LEN - 1);
                    virtual_prefix[MAX_PATH_LEN - 1] = '\0';
                }
            }
            strip_trailing_slash(virtual_prefix);
            if (is_wildcard_string(virtual_prefix)) {
                LOG_WRN("ALLOW 不支持通配符，规则已忽略；如需放行该目录请去掉 '*' (行 %d, 文件 %s): %s", line_num, file_path, val);
                return;
            }
            char real_target[MAX_PATH_LEN];
            snprintf(real_target, MAX_PATH_LEN - 1, "?%s", virtual_prefix);
            strip_trailing_slash(real_target);
            if (cur->redir_count >= cur->redir_capacity) {
                int new_cap = cur->redir_capacity == 0 ? 8 : cur->redir_capacity * 2;
                RedirectRule *new_redir = realloc(cur->redir_rules, new_cap * sizeof(RedirectRule));
                if (!new_redir) {
                    LOG_ERR("realloc redir_rules 失败 (ALLOW)");
                    return;
                }
                cur->redir_rules = new_redir;
                cur->redir_capacity = new_cap;
            }
            RedirectRule* r = &cur->redir_rules[cur->redir_count++];
            strncpy(r->virtual_prefix, virtual_prefix, sizeof(r->virtual_prefix) - 1);
            r->virtual_prefix[sizeof(r->virtual_prefix) - 1] = '\0';
            strncpy(r->real_target, real_target, sizeof(r->real_target) - 1);
            r->real_target[sizeof(r->real_target) - 1] = '\0';
            r->is_allow = true;
            if (!is_wildcard_string(virtual_prefix) && !has_path_var(virtual_prefix)) {
                trie_insert(cur->trie_root, virtual_prefix, real_target, false, false);
            }
        }
    } else if (strcmp(tok, "REDIRECT") == 0) {
        char* v1 = get_next_token(&p_ptr);
        char* v2 = get_next_token(&p_ptr);
        if (v1 && v2) {
            char *v_ptr = strip_storage_prefix(v1);
            char virtual_prefix[MAX_PATH_LEN];
            if (v_ptr[0] == '\0') strcpy(virtual_prefix, "/"); 
            else {
                if (v_ptr[0] != '/') snprintf(virtual_prefix, MAX_PATH_LEN, "/%s", v_ptr);
                else {
                    strncpy(virtual_prefix, v_ptr, MAX_PATH_LEN - 1);
                    virtual_prefix[MAX_PATH_LEN - 1] = '\0';
                }
            }
            strip_trailing_slash(virtual_prefix);
            char real_target[MAX_PATH_LEN];
            if (has_path_var(v2)) {
                /* 含变量：原样存入，路径分类延迟到运行时 build_real_base_from_target */
                strncpy(real_target, v2, MAX_PATH_LEN - 1);
                real_target[MAX_PATH_LEN - 1] = '\0';
            }
            else if (strncmp(v2, "/storage/emulated/", 18) == 0) {
                char* p = v2 + 18;
                while (*p && isdigit((unsigned char)*p)) p++;
                if (*p == '/') p++;
                snprintf(real_target, MAX_PATH_LEN - 1, "?/%s", p);
            }
            else if (is_system_abs_path(v2)) {
                strncpy(real_target, v2, MAX_PATH_LEN - 1);
                real_target[MAX_PATH_LEN - 1] = '\0';
            }
            else {
                snprintf(real_target, MAX_PATH_LEN - 1, "?/%s", v2[0] == '/' ? v2 + 1 : v2);
            }
            strip_trailing_slash(real_target);
            if (cur->redir_count >= cur->redir_capacity) {
                int new_cap = cur->redir_capacity == 0 ? 8 : cur->redir_capacity * 2;
                RedirectRule *new_redir = realloc(cur->redir_rules, new_cap * sizeof(RedirectRule));
                if (!new_redir) {
                    LOG_ERR("realloc redir_rules 失败 (ALLOW)");
                    return;
                }
                cur->redir_rules = new_redir;
                cur->redir_capacity = new_cap;
            }
            RedirectRule* r = &cur->redir_rules[cur->redir_count++];
            strncpy(r->virtual_prefix, virtual_prefix, sizeof(r->virtual_prefix) - 1);
            r->virtual_prefix[sizeof(r->virtual_prefix) - 1] = '\0';
            strncpy(r->real_target, real_target, sizeof(r->real_target) - 1);
            r->real_target[sizeof(r->real_target) - 1] = '\0';
            r->is_allow = false;
            if (!is_wildcard_string(virtual_prefix) && !is_wildcard_string(real_target) && !has_path_var(virtual_prefix) && !has_path_var(real_target)) {
                trie_insert(cur->trie_root, virtual_prefix, real_target, false, false);
            }
        }
    } else if (strcmp(tok, "FTP") == 0) {
        /* FTP <虚拟前缀> <段名>：虚拟前缀命中时由 FTP 后端（段名）提供。
           规则所在段决定作用域：GLOBAL=全局，应用段=仅该应用 */
        char* v1 = get_next_token(&p_ptr);
        char* v2 = get_next_token(&p_ptr);
        if (!v1 || !v2) {
            LOG_WRN("FTP 规则缺少参数 (行 %d, 文件 %s)", line_num, file_path);
            return;
        }
        char virtual_prefix[MAX_PATH_LEN];
        if (v1[0] != '/') snprintf(virtual_prefix, MAX_PATH_LEN, "/%s", v1);
        else { strncpy(virtual_prefix, v1, MAX_PATH_LEN - 1); virtual_prefix[MAX_PATH_LEN - 1] = '\0'; }
        strip_trailing_slash(virtual_prefix);
        if (virtual_prefix[0] == '\0') strcpy(virtual_prefix, "/");
        if (cur->ftp_count >= cur->ftp_capacity) {
            int newcap = cur->ftp_capacity == 0 ? 8 : cur->ftp_capacity * 2;
            FtpRule* new_rules = realloc(cur->ftp_rules, newcap * sizeof(FtpRule));
            if (!new_rules) { LOG_ERR("realloc ftp_rules 失败 (行 %d)", line_num); return; }
            cur->ftp_rules = new_rules;
            cur->ftp_capacity = newcap;
        }
        FtpRule* fr = &cur->ftp_rules[cur->ftp_count++];
        memset(fr, 0, sizeof *fr);
        strncpy(fr->virtual_prefix, virtual_prefix, sizeof fr->virtual_prefix - 1);
        fr->virtual_prefix[sizeof fr->virtual_prefix - 1] = '\0';
        strncpy(fr->backend_name, v2, sizeof fr->backend_name - 1);
        fr->backend_name[sizeof fr->backend_name - 1] = '\0';
    } else {
        LOG_WRN("不支持的规则 \"%s\" (行 %d, 文件 %s)", tok, line_num, file_path);
    }
}

/* FTP 规则最长前缀优先匹配：sub_path 命中 FTP 规则时输出后端段名 */
bool config_ftp_match(const AppConfig* cfg, const char* sub_path, char* backend_out, size_t sz) {
    if (!cfg || !sub_path || cfg->ftp_count <= 0) return false;
    FtpRule* best = NULL;
    size_t best_len = 0;
    for (int i = 0; i < cfg->ftp_count; i++) {
        const char* p = cfg->ftp_rules[i].virtual_prefix;
        size_t plen = strlen(p);
        if (plen > best_len && strncmp(p, sub_path, plen) == 0 &&
            (sub_path[plen] == '\0' || sub_path[plen] == '/')) {
            best = &cfg->ftp_rules[i];
            best_len = plen;
        }
    }
    if (best && backend_out && sz) {
        strncpy(backend_out, best->backend_name, sz - 1);
        backend_out[sz - 1] = '\0';
    }
    return best != NULL;
}
static AppConfig* get_or_create_app_cfg(const char* pkg, int user_id) {
    if (strcmp(pkg, "GLOBAL") == 0) return &g_global_cfg;
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i]->user_id == user_id && strcmp(g_app_cfgs[i]->pkg_name, pkg) == 0) 
            return g_app_cfgs[i];
    }
    if (g_app_cfg_count >= g_app_cfg_capacity) {
        int new_cap = g_app_cfg_capacity == 0 ? 8 : g_app_cfg_capacity * 2;
        AppConfig **new_cfgs = realloc(g_app_cfgs, new_cap * sizeof(AppConfig*));
        if (!new_cfgs) {
            LOG_ERR("realloc g_app_cfgs 失败，跳过应用 %s", pkg);
            return nullptr;
        }
        g_app_cfgs = new_cfgs;
        g_app_cfg_capacity = new_cap;
    }
    g_app_cfgs[g_app_cfg_count] = calloc(1, sizeof(AppConfig));
    strncpy(g_app_cfgs[g_app_cfg_count]->pkg_name, pkg, 127);
    g_app_cfgs[g_app_cfg_count]->user_id = user_id;
    g_app_cfgs[g_app_cfg_count]->inject_enable = false; 
    g_app_cfgs[g_app_cfg_count]->trie_root = trie_create_node(NULL); 
    return g_app_cfgs[g_app_cfg_count++];
}
void scan_active_users() {
    g_active_user_count = 0;

    // 优先通过 pm list users 获取真实用户列表
    FILE* fp = popen("pm list users 2>/dev/null", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            int uid = -1;
            if (sscanf(line, " UserInfo{%d:", &uid) == 1) {
                if (uid >= 0 && g_active_user_count < MAX_USERS)
                    g_active_users[g_active_user_count++] = uid;
            }
        }
        pclose(fp);
    }

    // pm 失败时回退到 /data/media/ 扫描
    if (g_active_user_count == 0) {
        DIR* dir = opendir("/data/media");
        if (dir) {
            struct dirent* de;
            while ((de = readdir(dir)) != nullptr) {
                if (de->d_type == DT_DIR || de->d_type == DT_LNK) {
                    bool is_num = true;
                    for (int i = 0; de->d_name[i]; i++) {
                        if (!isdigit(de->d_name[i])) { is_num = false; break; }
                    }
                    if (is_num && g_active_user_count < MAX_USERS) {
                        int uid = atoi(de->d_name);
                        if (uid >= 0 && uid < MAX_REASONABLE_UID)
                            g_active_users[g_active_user_count++] = uid;
                    }
                }
            }
            closedir(dir);
        }
    }

    // 确保至少有 user 0
    if (g_active_user_count == 0) {
        g_active_users[0] = 0;
        g_active_user_count = 1;
    }

    LOG_DBG("scan_active_users: 发现 %d 个活跃用户", g_active_user_count);
    for (int i = 0; i < g_active_user_count; i++)
        LOG_DBG("  活跃用户[%d]: uid=%d", i, g_active_users[i]);
}
void load_config_rules(const char* path) {
    free_config_rules();
    memset(&g_global_cfg, 0, sizeof(AppConfig)); 
    g_global_cfg.trie_root = trie_create_node(NULL);
    g_global_cfg.skip_system_apps = true; /* 默认跳过系统应用 */
    scan_active_users();
    for (int i = 0; i < g_active_user_count; i++) {
        int uid = g_active_users[i];
        char app_rules_dir[PATH_MAX];
        if (uid == 0) snprintf(app_rules_dir, sizeof(app_rules_dir), "%s/App-rules", CONFIG_DIR);
        else snprintf(app_rules_dir, sizeof(app_rules_dir), "%s/App-rules-%d", CONFIG_DIR, uid);
        if (access(app_rules_dir, F_OK) != 0) {
            mkdir(app_rules_dir, 0755);
            LOG("自动为多用户 %d 创建应用规则目录: %s", uid, app_rules_dir);
        }
    }
    FILE* fp = fopen(path, "r");
    if (fp) {
        AppConfig* cur = &g_global_cfg; char line[2048];
        int current_user_id = -1;
        int line_num = 0;
        while (fgets(line, sizeof(line), fp)) {
            line_num++;
            char* p = clean_path_string(line); if (!p || p[0] == '#' || p[0] == 0) continue;
            if (p[0] == '[') {
                char* end = strchr(p, ']');
                if (end) {
                    *end = '\0';
                    char* sec = p + 1;
                    char* after = end + 1;
                    bool enabled = true;
                    while (isspace(*after)) after++;
                    if (strncmp(after, "OFF", 3) == 0) enabled = false;
                    else if (strncmp(after, "ON", 2) == 0) enabled = true;
                    char pkg[128];
                    current_user_id = -1; 
                    char* colon = strchr(sec, ':');
                    if (colon) {
                        *colon = '\0';
                        current_user_id = atoi(colon + 1);
                    }
                    strncpy(pkg, sec, sizeof(pkg)-1);
                    if (strcmp(pkg, "GLOBAL") == 0) {
                        cur = &g_global_cfg;
                    } else {
                        cur = get_or_create_app_cfg(pkg, current_user_id);
                        if (cur) cur->inject_enable = enabled;
                    }
                }
                continue;
            }
            if (cur) parse_config_line(cur, p, current_user_id, line_num, path);
        }
        fclose(fp);
    } else {
        LOG_ERR("无法打开主规则文件: %s (%s)", path, strerror(errno));
    }
    for (int i = 0; i < g_active_user_count; i++) {
        int uid = g_active_users[i];
        char app_rules_dir[PATH_MAX];
        if (uid == 0) snprintf(app_rules_dir, sizeof(app_rules_dir), "%s/App-rules", CONFIG_DIR);
        else snprintf(app_rules_dir, sizeof(app_rules_dir), "%s/App-rules-%d", CONFIG_DIR, uid);
        DIR* dir = opendir(app_rules_dir);
        if (dir) {
            struct dirent* de;
            while ((de = readdir(dir)) != nullptr) {
                if (de->d_type == DT_REG || de->d_type == DT_LNK) {
                    char* ext = strrchr(de->d_name, '.');
                    if (ext && strcmp(ext, ".conf") == 0) {
                        char pkg[128];
                        size_t len = ext - de->d_name;
                        if (len >= sizeof(pkg)) len = sizeof(pkg) - 1;
                        strncpy(pkg, de->d_name, len);
                        pkg[len] = '\0';
                        AppConfig* file_cur = get_or_create_app_cfg(pkg, uid);
                        /* 存在 <pkg>.conf（未被重命名 .disabled）即启用该应用注入：
                           与 rule-server-api 文档语义一致，不依赖段头 ON。
                           文件内若含 [pkg] OFF 段头会在下方解析时覆盖为 false */
                        file_cur->inject_enable = true;
                        AppConfig* cur = file_cur; 
                        char app_conf_path[PATH_MAX];
                        snprintf(app_conf_path, sizeof(app_conf_path), "%s/%s", app_rules_dir, de->d_name);
                        FILE* afp = fopen(app_conf_path, "r");
                        if (afp) {
                            char line[2048];
                            int app_line_num = 0;
                            while (fgets(line, sizeof(line), afp)) {
                                app_line_num++;
                                char* p = clean_path_string(line);
                                if (!p || p[0] == '#' || p[0] == 0) continue;
                                if (p[0] == '[') {
                                    char* end = strchr(p, ']');
                                    if (end) {
                                        *end = '\0';
                                        char* sec = p + 1;
                                        char* after = end + 1;
                                        bool enabled = true;
                                        while (isspace(*after)) after++;
                                        if (strncmp(after, "OFF", 3) == 0) enabled = false;
                                        else if (strncmp(after, "ON", 2) == 0) enabled = true;
                                        char sub_pkg[128];
                                        int sub_uid = uid; 
                                        char* colon = strchr(sec, ':');
                                        if (colon) { *colon = '\0'; sub_uid = atoi(colon + 1); }
                                        strncpy(sub_pkg, sec, sizeof(sub_pkg)-1);
                                        if (strcmp(sub_pkg, "GLOBAL") == 0) cur = &g_global_cfg;
                                        else { cur = get_or_create_app_cfg(sub_pkg, sub_uid); if (cur) cur->inject_enable = enabled; }
                                    }
                                    continue;
                                }
                                if (cur) parse_config_line(cur, p, uid, app_line_num, app_conf_path);
                            }
                            fclose(afp);
                        }
                    } else if (ext && strcmp(ext, ".disabled") == 0) {
                        /* 停用状态识别：<pkg>.conf.disabled = 该应用规则被停用
                           （rule_server INJECT_ENABLE OFF 重命名而来）。
                           仅当无对应 <pkg>.conf（未被启用）时创建 cfg 并置
                           inject_enable=false——使 is_target_app 能识别停用
                           状态并触发热卸载（此前 cfg 消失导致有通配符/全局
                           注入时停用应用仍被判为目标无法卸载） */
                        size_t nlen = strlen(de->d_name);
                        const char* suffix = ".conf.disabled";
                        size_t slen = strlen(suffix);
                        if (nlen > slen && strcmp(de->d_name + nlen - slen, suffix) == 0) {
                            char pkg[128];
                            size_t len = nlen - slen;
                            if (len >= sizeof(pkg)) len = sizeof(pkg) - 1;
                            strncpy(pkg, de->d_name, len);
                            pkg[len] = '\0';
                            char conf_path[PATH_MAX];
                            snprintf(conf_path, sizeof(conf_path), "%s/%s.conf", app_rules_dir, pkg);
                            if (access(conf_path, F_OK) != 0) {
                                AppConfig* file_cur = get_or_create_app_cfg(pkg, uid);
                                file_cur->inject_enable = false;   /* 明确停用 */
                            }
                        }
                    }
                }
            }
            closedir(dir);
        }
    }
    qsort(g_global_cfg.redir_rules, g_global_cfg.redir_count, sizeof(RedirectRule), cmp_redir);
    qsort(g_global_cfg.hide_rules, g_global_cfg.hide_count, sizeof(char*), cmp_hide);
    qsort(g_global_cfg.ro_rules, g_global_cfg.ro_count, sizeof(char*), cmp_hide);
    for(int i = 0; i < g_app_cfg_count; i++) {
        qsort(g_app_cfgs[i]->redir_rules, g_app_cfgs[i]->redir_count, sizeof(RedirectRule), cmp_redir);
        qsort(g_app_cfgs[i]->hide_rules, g_app_cfgs[i]->hide_count, sizeof(char*), cmp_hide);
        qsort(g_app_cfgs[i]->ro_rules, g_app_cfgs[i]->ro_count, sizeof(char*), cmp_hide);
    }
    analyze_var_staticness(&g_global_cfg, NULL);
    for (int i = 0; i < g_app_cfg_count; i++) {
        analyze_var_staticness(g_app_cfgs[i], &g_global_cfg);
    }
}
int reload_config_rules_diff(const char* path, ChangedPkg* out_changed, int max_changed) {
    AppConfig old_global_cfg;
    memcpy(&old_global_cfg, &g_global_cfg, sizeof(AppConfig));
    AppConfig** old_app_cfgs = g_app_cfgs;
    int old_app_cfg_count = g_app_cfg_count;
    memset(&g_global_cfg, 0, sizeof(AppConfig));
    g_global_cfg.trie_root = trie_create_node(NULL);
    g_global_cfg.skip_system_apps = true; /* 默认跳过系统应用 */
    g_app_cfgs = nullptr;
    g_app_cfg_count = 0;
    g_app_cfg_capacity = 0;
    load_config_rules(path);
    // 遵循设计：injector不处理单个挂载树内的文件规则变化，仅处理全局挂载ON/OFF与应用开关
    bool global_changed = (old_global_cfg.global_inject != g_global_cfg.global_inject);
    int changed_count = 0;
    if (global_changed) {
        changed_count = -1;
    } else {
        for (int i = 0; i < g_app_cfg_count; i++) {
            AppConfig* new_cfg = g_app_cfgs[i];
            AppConfig* old_cfg = nullptr;
            for (int j = 0; j < old_app_cfg_count; j++) {
                if (old_app_cfgs[j] && old_app_cfgs[j]->user_id == new_cfg->user_id && 
                    strcmp(old_app_cfgs[j]->pkg_name, new_cfg->pkg_name) == 0) {
                    old_cfg = old_app_cfgs[j];
                    break;
                }
            }
            if (!old_cfg || old_cfg->inject_enable != new_cfg->inject_enable) {
                if (changed_count < max_changed) {
                    strncpy(out_changed[changed_count].pkg_name, new_cfg->pkg_name, 127);
                    out_changed[changed_count].pkg_name[127] = '\0';
                    out_changed[changed_count].user_id = new_cfg->user_id;
                    changed_count++;
                }
            }
        }
        for (int j = 0; j < old_app_cfg_count; j++) {
            AppConfig* old_cfg = old_app_cfgs[j];
            if (!old_cfg) continue;
            bool found = false;
            for (int i = 0; i < g_app_cfg_count; i++) {
                if (g_app_cfgs[i]->user_id == old_cfg->user_id && 
                    strcmp(g_app_cfgs[i]->pkg_name, old_cfg->pkg_name) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (changed_count < max_changed) {
                    strncpy(out_changed[changed_count].pkg_name, old_cfg->pkg_name, 127);
                    out_changed[changed_count].pkg_name[127] = '\0';
                    out_changed[changed_count].user_id = old_cfg->user_id;
                    changed_count++;
                }
            }
        }
    }
    if (old_app_cfgs) {
        for (int i = 0; i < old_app_cfg_count; i++) {
            if (old_app_cfgs[i]) {
                free_app_config_rules(old_app_cfgs[i]);
                free(old_app_cfgs[i]);
            }
        }
        free(old_app_cfgs);
    }
    free_app_config_rules(&old_global_cfg);
    return changed_count;
}
AppConfig* find_app_cfg_locked(const char* pkg, int user_id) {
    char base_pkg[256];
    strncpy(base_pkg, pkg, sizeof(base_pkg) - 1);
    base_pkg[sizeof(base_pkg) - 1] = '\0';
    char* colon = strchr(base_pkg, ':');
    if (colon) *colon = '\0';
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == user_id &&
            (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 ||
             fnmatch(g_app_cfgs[i]->pkg_name, pkg, 0) == 0))
            return g_app_cfgs[i];
    }
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == -1 &&
            (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 ||
             fnmatch(g_app_cfgs[i]->pkg_name, pkg, 0) == 0))
            return g_app_cfgs[i];
    }
    return NULL;
}
bool has_wildcard_enabled_locked(int user_id) {
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == user_id &&
            strcmp(g_app_cfgs[i]->pkg_name, "*") == 0 &&
            g_app_cfgs[i]->inject_enable)
            return true;
    }
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == -1 &&
            strcmp(g_app_cfgs[i]->pkg_name, "*") == 0 &&
            g_app_cfgs[i]->inject_enable)
            return true;
    }
    return false;
}
void print_active_rules(const char* pkg, int pid, uid_t linux_uid, const char* trigger_source) {
    config_lock_read();
    int user_id = linux_uid / 100000;
    AppConfig* cfg = find_app_cfg_locked(pkg, user_id);
    bool is_wildcard = (cfg == NULL) && has_wildcard_enabled_locked(user_id);
    int final_redir_count = (cfg ? cfg->redir_count : 0) + g_global_cfg.redir_count;
    int final_hide_count = (cfg ? cfg->hide_count : 0) + g_global_cfg.hide_count;
    int final_ro_count = (cfg ? cfg->ro_count : 0) + g_global_cfg.ro_count;
    bool final_sandbox;
    if (cfg && cfg->sandbox_explicit) {
        final_sandbox = cfg->sandbox;
    } else {
        final_sandbox = g_global_cfg.sandbox && !is_media_provider(pkg);
    }
    bool final_monitor;
    if (cfg && cfg->monitor_explicit) {
        final_monitor = cfg->monitor;
    } else {
        final_monitor = g_global_cfg.monitor;
    }
    if (cfg) {
        LOG("应用 %s (PID: %d, 用户: %d) 注入完毕 [%s] | 规则细节 -> MONITOR:%s SANDBOX:%s 重定向(通配):%d条 隐藏(通配):%d条 只读(通配):%d条",
            pkg, pid, user_id, trigger_source,
            final_monitor ? "ON" : "OFF",
            final_sandbox ? "ON" : "OFF",
            final_redir_count, final_hide_count, final_ro_count);
        for (int i = 0; i < cfg->redir_count; i++) {
            //LOG_DBG("  [重定向通配] %s -> %s", cfg->redir_rules[i].virtual_prefix, cfg->redir_rules[i].real_target);
        }
        for (int i = 0; i < cfg->hide_count; i++) {
            //LOG_DBG("  [隐藏通配]   %s", cfg->hide_rules[i]);
        }
        for (int i = 0; i < cfg->ro_count; i++) {
            //LOG_DBG("  [只读通配]   %s", cfg->ro_rules[i]);
        }
    } else {
        const char* match_desc = 
            is_wildcard ? "命中通配符 [*]" :
            (g_global_cfg.global_inject ? "命中 GLOBAL_INJECT" : "无匹配规则");
        LOG("应用 %s (PID: %d, 用户: %d) 注入完毕 [%s] | %s (全局 MONITOR:%s SANDBOX:%s)",
            pkg, pid, user_id, trigger_source, match_desc,
            final_monitor ? "ON" : "OFF",
            final_sandbox ? "ON" : "OFF");
    }
    if (g_global_cfg.redir_count > 0 || g_global_cfg.hide_count > 0 || g_global_cfg.ro_count > 0) {
        LOG_DBG("  [全局规则通配] MONITOR:%s SANDBOX:%s 重定向:%d条 隐藏:%d条 只读:%d条",
            g_global_cfg.monitor ? "ON" : "OFF",
            g_global_cfg.sandbox ? "ON" : "OFF",
            g_global_cfg.redir_count, g_global_cfg.hide_count, g_global_cfg.ro_count);
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            LOG_DBG("  [全局重定向通配] %s -> %s", g_global_cfg.redir_rules[i].virtual_prefix, g_global_cfg.redir_rules[i].real_target);
        }
        for (int i = 0; i < g_global_cfg.hide_count; i++) {
            LOG_DBG("  [全局隐藏通配]   %s", g_global_cfg.hide_rules[i]);
        }
        for (int i = 0; i < g_global_cfg.ro_count; i++) {
            LOG_DBG("  [全局只读通配]   %s", g_global_cfg.ro_rules[i]);
        }
    }
    config_unlock_read();
}