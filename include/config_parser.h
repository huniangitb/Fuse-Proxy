#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <stdbool.h>
#include <sys/types.h>

#define MAX_PATH_LEN 256
#define MAX_USERS 64

typedef struct { 
    char virtual_prefix[MAX_PATH_LEN]; 
    char real_target[MAX_PATH_LEN]; 
} RedirectRule;

typedef struct {
    char pkg_name[128];
    int user_id;         // 区分用户
    bool inject_enable;   
    bool monitor;
    bool sandbox;
    bool global_inject;   // 全局规则启用所有应用注入
    
    char** hide_rules;
    int hide_count;
    int hide_capacity;
    
    char** ro_rules;
    int ro_count;
    int ro_capacity;
    
    RedirectRule* redir_rules;
    int redir_count;
    int redir_capacity;
} AppConfig;

typedef struct {
    char pkg_name[128];
    int user_id;
} ChangedPkg;

extern AppConfig g_global_cfg;
extern AppConfig** g_app_cfgs;
extern int g_app_cfg_count;

extern int g_active_users[MAX_USERS];
extern int g_active_user_count;

void config_init_lock();
void config_destroy_lock();
void config_lock_read();
void config_unlock_read();
void config_lock_write();
void config_unlock_write();

void scan_active_users();
void load_config_rules(const char* main_conf_path);
int reload_config_rules_diff(const char* path, ChangedPkg* out_changed, int max_changed);

char* clean_path_string(char* str);
void strip_trailing_slash(char* path);
int mkdir_recursive_p(const char *path, mode_t mode);

void print_active_rules(const char* pkg, int pid, uid_t uid, const char* trigger_source);

/*
 * 在应用配置列表中查找匹配的 AppConfig。
 * 调用方需持有 config_lock_read() 锁。
 * 查找策略：先按精确 user_id 匹配，再按 user_id==-1 (通配) 匹配。
 */
AppConfig* find_app_cfg_locked(const char* pkg, int user_id);

/*
 * 检查应用是否有通配符 "*" 规则且 inject_enable 启用。
 * 调用方需持有 config_lock_read() 锁。
 */
bool has_wildcard_enabled_locked(int user_id);

#endif