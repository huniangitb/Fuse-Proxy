#include "config_parser.h"
#include <sys/stat.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <ctype.h>
#include <fnmatch.h>
#include <pthread.h>

AppConfig g_global_cfg;
AppConfig** g_app_cfgs = NULL;
int g_app_cfg_count = 0;
int g_app_cfg_capacity = 0;

int g_active_users[MAX_USERS];
int g_active_user_count = 0;

static pthread_rwlock_t g_rules_lock;

void config_init_lock(void) { pthread_rwlock_init(&g_rules_lock, NULL); }
void config_destroy_lock(void) { pthread_rwlock_destroy(&g_rules_lock); }
void config_lock_read(void) { pthread_rwlock_rdlock(&g_rules_lock); }
void config_unlock_read(void) { pthread_rwlock_unlock(&g_rules_lock); }
void config_lock_write(void) { pthread_rwlock_wrlock(&g_rules_lock); }
void config_unlock_write(void) { pthread_rwlock_unlock(&g_rules_lock); }

static void free_app_config_rules(AppConfig* cfg) {
    if (!cfg) return;
    if (cfg->hide_rules) {
        for (int i = 0; i < cfg->hide_count; i++) free(cfg->hide_rules[i]);
        free(cfg->hide_rules);
        cfg->hide_rules = NULL;
    }
    cfg->hide_count = 0;
    cfg->hide_capacity = 0;
    
    if (cfg->ro_rules) {
        for (int i = 0; i < cfg->ro_count; i++) free(cfg->ro_rules[i]);
        free(cfg->ro_rules);
        cfg->ro_rules = NULL;
    }
    cfg->ro_count = 0;
    cfg->ro_capacity = 0;

    if (cfg->redir_rules) {
        free(cfg->redir_rules);
        cfg->redir_rules = NULL;
    }
    cfg->redir_count = 0;
    cfg->redir_capacity = 0;
}

static void free_config_rules(void) {
    free_app_config_rules(&g_global_cfg);
    if (g_app_cfgs) {
        for (int i = 0; i < g_app_cfg_count; i++) {
            free_app_config_rules(g_app_cfgs[i]);
            free(g_app_cfgs[i]);
        }
        free(g_app_cfgs);
        g_app_cfgs = NULL;
    }
    g_app_cfg_count = 0;
    g_app_cfg_capacity = 0;
}

char* clean_path_string(char* str) {
    if (!str) return NULL;
    while(isspace((unsigned char)*str)) str++; if(*str == 0) return str;
    char* end = str + strlen(str) - 1; while(end > str && isspace((unsigned char)*end)) end--;
    *(end+1) = 0;
    for (int i = 0; str[i]; i++) { if (str[i] == '\r' || str[i] == '\n') { str[i] = '\0'; break; } }
    return str;
}

void strip_trailing_slash(char* path) {
    size_t len = strlen(path); if (len > 1 && path[len - 1] == '/') path[len - 1] = '\0';
}

static void sync_attributes(const char* source_parent, const char* target_path) {
    struct stat st;
    if (lstat(source_parent, &st) != 0) return;
    if (lchown(target_path, st.st_uid, st.st_gid) != 0) {}
    chmod(target_path, st.st_mode & 07777);
    char context[256];
    ssize_t ctx_len = lgetxattr(source_parent, "security.selinux", context, sizeof(context));
    if (ctx_len > 0) {
        lsetxattr(target_path, "security.selinux", context, (size_t)ctx_len, 0);
    } else if (strstr(target_path, STORAGE_BASE) == target_path) {
        const char* default_ctx = "u:object_r:media_rw_data_file:s0";
        lsetxattr(target_path, "security.selinux", default_ctx, strlen(default_ctx) + 1, 0);
    }
}

static void inherit_from_parent(const char* real_path) {
    char parent[PATH_MAX]; strncpy(parent, real_path, PATH_MAX - 1);
    char* last = strrchr(parent, '/');
    if (last) {
        if (last == parent) strcpy(parent, "/"); 
        else *last = '\0';
        sync_attributes(parent, real_path);
    }
}

int mkdir_recursive_p(const char *path, mode_t mode) {
    char tmp[PATH_MAX]; char *p = NULL; snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp); if (tmp[len - 1] == '/') tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (access(tmp, F_OK) != 0) {
                if (mkdir(tmp, mode) == 0) inherit_from_parent(tmp);
                else if (errno != EEXIST) return -1;
            }
            *p = '/';
        }
    }
    if (access(tmp, F_OK) != 0) {
        if (mkdir(tmp, mode) == 0) inherit_from_parent(tmp);
        else if (errno != EEXIST) return -1;
    }
    return 0;
}

static char* get_next_token(char** ptr) {
    char* p = *ptr;
    if (!p) return NULL;
    while (isspace((unsigned char)*p)) p++;
    if (*p == '\0') { *ptr = NULL; return NULL; }
    
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
        if (*p == '/') return p;
        if (*p == '\0') return "/";
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

static void parse_config_line(AppConfig* cur, char* line, int user_id) {
    (void)user_id;
    char* p_ptr = line;
    char* tok = get_next_token(&p_ptr);
    if (!tok) return;
    
    if (strcmp(tok, "MONITOR") == 0) {
        char* val = get_next_token(&p_ptr);
        cur->monitor = (val && (strcmp(val, "ON")==0 || strcmp(val, "1")==0)) ? 1 : 0;
    } else if (strcmp(tok, "SANDBOX") == 0) {
        char* val = get_next_token(&p_ptr);
        cur->sandbox = (val && (strcmp(val, "ON")==0 || strcmp(val, "1")==0)) ? 1 : 0;
    } else if (strcmp(tok, "GLOBAL_INJECT") == 0) {
        char* val = get_next_token(&p_ptr);
        cur->global_inject = (val && (strcmp(val, "ON")==0 || strcmp(val, "1")==0)) ? 1 : 0;
    } else if (strcmp(tok, "HIDE") == 0) {
        char* val = get_next_token(&p_ptr);
        if (val) {
            if (cur->hide_count >= cur->hide_capacity) {
                cur->hide_capacity = cur->hide_capacity == 0 ? 8 : cur->hide_capacity * 2;
                cur->hide_rules = realloc(cur->hide_rules, cur->hide_capacity * sizeof(char*));
            }
            cur->hide_rules[cur->hide_count] = malloc(MAX_PATH_LEN);
            
            char *v_ptr = strip_storage_prefix(val);
            if (v_ptr[0] != '/' && v_ptr[0] != '*') snprintf(cur->hide_rules[cur->hide_count], MAX_PATH_LEN, "/%s", v_ptr);
            else strncpy(cur->hide_rules[cur->hide_count], v_ptr, MAX_PATH_LEN - 1);
            if (strpbrk(cur->hide_rules[cur->hide_count], "*?[]") == NULL) strip_trailing_slash(cur->hide_rules[cur->hide_count]);
            cur->hide_count++;
        }
    } else if (strcmp(tok, "RO") == 0) {
        char* val = get_next_token(&p_ptr);
        if (val) {
            if (cur->ro_count >= cur->ro_capacity) {
                cur->ro_capacity = cur->ro_capacity == 0 ? 8 : cur->ro_capacity * 2;
                cur->ro_rules = realloc(cur->ro_rules, cur->ro_capacity * sizeof(char*));
            }
            cur->ro_rules[cur->ro_count] = malloc(MAX_PATH_LEN);
            
            char *v_ptr = strip_storage_prefix(val);
            if (v_ptr[0] != '/' && v_ptr[0] != '*') snprintf(cur->ro_rules[cur->ro_count], MAX_PATH_LEN, "/%s", v_ptr);
            else strncpy(cur->ro_rules[cur->ro_count], v_ptr, MAX_PATH_LEN - 1);
            if (strpbrk(cur->ro_rules[cur->ro_count], "*?[]") == NULL) strip_trailing_slash(cur->ro_rules[cur->ro_count]);
            cur->ro_count++;
        }
    } else if (strcmp(tok, "ALLOW") == 0) {
        char* val = get_next_token(&p_ptr);
        if (val) {
            if (cur->redir_count >= cur->redir_capacity) {
                cur->redir_capacity = cur->redir_capacity == 0 ? 8 : cur->redir_capacity * 2;
                cur->redir_rules = realloc(cur->redir_rules, cur->redir_capacity * sizeof(RedirectRule));
            }
            RedirectRule* r = &cur->redir_rules[cur->redir_count++];
            
            char *v_ptr = strip_storage_prefix(val);
            if (v_ptr[0] == '\0') strcpy(r->virtual_prefix, "/"); 
            else {
                if (v_ptr[0] != '/') snprintf(r->virtual_prefix, MAX_PATH_LEN, "/%s", v_ptr);
                else strncpy(r->virtual_prefix, v_ptr, MAX_PATH_LEN - 1);
            }
            strip_trailing_slash(r->virtual_prefix);

            snprintf(r->real_target, MAX_PATH_LEN - 1, "?%s", r->virtual_prefix);
            strip_trailing_slash(r->real_target);
        }
    } else if (strcmp(tok, "REDIRECT") == 0) {
        char* v1 = get_next_token(&p_ptr);
        char* v2 = get_next_token(&p_ptr);
        if (v1 && v2) {
            if (cur->redir_count >= cur->redir_capacity) {
                cur->redir_capacity = cur->redir_capacity == 0 ? 8 : cur->redir_capacity * 2;
                cur->redir_rules = realloc(cur->redir_rules, cur->redir_capacity * sizeof(RedirectRule));
            }
            RedirectRule* r = &cur->redir_rules[cur->redir_count++];
            
            char *v_ptr = strip_storage_prefix(v1);
            if (v_ptr[0] == '\0') strcpy(r->virtual_prefix, "/"); 
            else {
                if (v_ptr[0] != '/') snprintf(r->virtual_prefix, MAX_PATH_LEN, "/%s", v_ptr);
                else strncpy(r->virtual_prefix, v_ptr, MAX_PATH_LEN - 1);
            }
            strip_trailing_slash(r->virtual_prefix);

            if (strncmp(v2, "/storage/emulated/", 18) == 0) {
                char* p = v2 + 18;
                while (*p && isdigit((unsigned char)*p)) p++;
                if (*p == '/') p++;
                snprintf(r->real_target, MAX_PATH_LEN - 1, "?/%s", p);
            }
            else if (strncmp(v2, "/data/", 6) == 0 || strncmp(v2, "/mnt/", 5) == 0 || strncmp(v2, "/storage/", 9) == 0) {
                strncpy(r->real_target, v2, MAX_PATH_LEN - 1);
            }
            else {
                snprintf(r->real_target, MAX_PATH_LEN - 1, "?/%s", v2[0] == '/' ? v2 + 1 : v2);
            }
            strip_trailing_slash(r->real_target);
        }
    }
}

static AppConfig* get_or_create_app_cfg(const char* pkg, int user_id) {
    if (strcmp(pkg, "GLOBAL") == 0) return &g_global_cfg;
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i]->user_id == user_id && strcmp(g_app_cfgs[i]->pkg_name, pkg) == 0) 
            return g_app_cfgs[i];
    }
    if (g_app_cfg_count >= g_app_cfg_capacity) {
        g_app_cfg_capacity = g_app_cfg_capacity == 0 ? 8 : g_app_cfg_capacity * 2;
        g_app_cfgs = realloc(g_app_cfgs, g_app_cfg_capacity * sizeof(AppConfig*));
    }
    g_app_cfgs[g_app_cfg_count] = calloc(1, sizeof(AppConfig));
    strncpy(g_app_cfgs[g_app_cfg_count]->pkg_name, pkg, 127);
    g_app_cfgs[g_app_cfg_count]->user_id = user_id;
    g_app_cfgs[g_app_cfg_count]->inject_enable = 1; 
    return g_app_cfgs[g_app_cfg_count++];
}

void scan_active_users(void) {
    g_active_user_count = 0;
    DIR* dir = opendir("/data/media");
    if (dir) {
        struct dirent* de;
        while ((de = readdir(dir)) != NULL) {
            if (de->d_type == DT_DIR || de->d_type == DT_LNK) {
                int is_num = 1;
                for (int i = 0; de->d_name[i]; i++) {
                    if (!isdigit(de->d_name[i])) { is_num = 0; break; }
                }
                if (is_num && g_active_user_count < MAX_USERS) {
                    g_active_users[g_active_user_count++] = atoi(de->d_name);
                }
            }
        }
        closedir(dir);
    }
}

void load_config_rules(const char* path) {
    free_config_rules();
    memset(&g_global_cfg, 0, sizeof(AppConfig)); 
    
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
        while (fgets(line, sizeof(line), fp)) {
            char* p = clean_path_string(line); if (!p || p[0] == '#' || p[0] == 0) continue;
            if (p[0] == '[') {
                char* end = strchr(p, ']');
                if (end) {
                    *end = '\0';
                    char* sec = p + 1;
                    char* after = end + 1;
                    int enabled = 1;
                    while (isspace(*after)) after++;
                    if (strncmp(after, "OFF", 3) == 0) enabled = 0;
                    else if (strncmp(after, "ON", 2) == 0) enabled = 1;

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
            if (cur) parse_config_line(cur, p, current_user_id);
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
            while ((de = readdir(dir)) != NULL) {
                if (de->d_type == DT_REG || de->d_type == DT_LNK) {
                    char* ext = strrchr(de->d_name, '.');
                    if (ext && strcmp(ext, ".conf") == 0) {
                        char pkg[128];
                        size_t len = ext - de->d_name;
                        if (len >= sizeof(pkg)) len = sizeof(pkg) - 1;
                        strncpy(pkg, de->d_name, len);
                        pkg[len] = '\0';

                        AppConfig* file_cur = get_or_create_app_cfg(pkg, uid);
                        AppConfig* cur = file_cur; 
                        
                        char app_conf_path[PATH_MAX];
                        snprintf(app_conf_path, sizeof(app_conf_path), "%s/%s", app_rules_dir, de->d_name);
                        FILE* afp = fopen(app_conf_path, "r");
                        if (afp) {
                            char line[2048];
                            while (fgets(line, sizeof(line), afp)) {
                                char* p = clean_path_string(line);
                                if (!p || p[0] == '#' || p[0] == 0) continue;
                                
                                if (p[0] == '[') {
                                    char* end = strchr(p, ']');
                                    if (end) {
                                        *end = '\0';
                                        char* sec = p + 1;
                                        char* after = end + 1;
                                        int enabled = 1;
                                        while (isspace(*after)) after++;
                                        if (strncmp(after, "OFF", 3) == 0) enabled = 0;
                                        else if (strncmp(after, "ON", 2) == 0) enabled = 1;

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
                                if (cur) parse_config_line(cur, p, uid);
                            }
                            fclose(afp);
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
}

void print_active_rules(const char* pkg, int pid, uid_t linux_uid, const char* trigger_source) {
    config_lock_read();
    int user_id = linux_uid / 100000;
    
    char base_pkg[256];
    strncpy(base_pkg, pkg, sizeof(base_pkg) - 1);
    base_pkg[sizeof(base_pkg) - 1] = '\0';
    char* colon = strchr(base_pkg, ':');
    if (colon) *colon = '\0';

    AppConfig* cfg = NULL;
    int is_wildcard = 0;
    
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i]->user_id == user_id && 
           (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 || fnmatch(g_app_cfgs[i]->pkg_name, pkg, 0) == 0)) {
            cfg = g_app_cfgs[i];
            break;
        }
    }
    
    if (!cfg) {
        for (int i = 0; i < g_app_cfg_count; i++) {
            if (g_app_cfgs[i]->user_id == -1 && 
               (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 || fnmatch(g_app_cfgs[i]->pkg_name, pkg, 0) == 0)) {
                cfg = g_app_cfgs[i];
                break;
            }
        }
    }
    
    if (!cfg) {
        for (int i = 0; i < g_app_cfg_count; i++) {
            if (g_app_cfgs[i]->user_id == user_id && strcmp(g_app_cfgs[i]->pkg_name, "*") == 0 && g_app_cfgs[i]->inject_enable) {
                is_wildcard = 1;
                break;
            }
        }
        if (!is_wildcard) {
            for (int i = 0; i < g_app_cfg_count; i++) {
                if (g_app_cfgs[i]->user_id == -1 && strcmp(g_app_cfgs[i]->pkg_name, "*") == 0 && g_app_cfgs[i]->inject_enable) {
                    is_wildcard = 1;
                    break;
                }
            }
        }
    }

    if (cfg) {
        LOG_MON("应用 %s (PID: %d, 用户: %d) 注入完毕 [%s] | 规则细节 -> MONITOR:%s SANDBOX:%s 重定向:%d条 隐藏:%d条 只读:%d条",
            pkg, pid, user_id, trigger_source,
            cfg->monitor ? "ON" : "OFF",
            cfg->sandbox ? "ON" : "OFF",
            cfg->redir_count, cfg->hide_count, cfg->ro_count);

        for (int i = 0; i < cfg->redir_count; i++) {
            LOG_MON("  [重定向] %s -> %s", cfg->redir_rules[i].virtual_prefix, cfg->redir_rules[i].real_target);
        }
        for (int i = 0; i < cfg->hide_count; i++) {
            LOG_MON("  [隐藏]   %s", cfg->hide_rules[i]);
        }
        for (int i = 0; i < cfg->ro_count; i++) {
            LOG_MON("  [只读]   %s", cfg->ro_rules[i]);
        }
    } else {
        LOG_MON("应用 %s (PID: %d, 用户: %d) 注入完毕 [%s] | %s",
            pkg, pid, user_id, trigger_source,
            is_wildcard ? "命中通配符 [*]" :
            g_global_cfg.global_inject ? "命中 GLOBAL_INJECT" : "无匹配规则");
    }

    if (g_global_cfg.redir_count > 0 || g_global_cfg.hide_count > 0 || g_global_cfg.ro_count > 0) {
        LOG_MON("  [全局规则] MONITOR:%s SANDBOX:%s 重定向:%d条 隐藏:%d条 只读:%d条",
            g_global_cfg.monitor ? "ON" : "OFF",
            g_global_cfg.sandbox ? "ON" : "OFF",
            g_global_cfg.redir_count, g_global_cfg.hide_count, g_global_cfg.ro_count);

        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            LOG_MON("  [全局重定向] %s -> %s", g_global_cfg.redir_rules[i].virtual_prefix, g_global_cfg.redir_rules[i].real_target);
        }
        for (int i = 0; i < g_global_cfg.hide_count; i++) {
            LOG_MON("  [全局隐藏]   %s", g_global_cfg.hide_rules[i]);
        }
        for (int i = 0; i < g_global_cfg.ro_count; i++) {
            LOG_MON("  [全局只读]   %s", g_global_cfg.ro_rules[i]);
        }
    }

    config_unlock_read();
}