#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include "common.h"

#define MAX_PATH_LEN 256
#define MAX_USERS 64

typedef struct { 
    char virtual_prefix[MAX_PATH_LEN]; 
    char real_target[MAX_PATH_LEN]; 
} RedirectRule;

typedef struct {
    char pkg_name[128];
    int user_id;         // 新增：区分用户
    int inject_enable;   
    int monitor;
    int sandbox;
    int global_inject;   // 新增：全局规则启用所有应用注入
    
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

extern AppConfig g_global_cfg;
extern AppConfig** g_app_cfgs;
extern int g_app_cfg_count;

extern int g_active_users[MAX_USERS];
extern int g_active_user_count;

void config_init_lock(void);
void config_destroy_lock(void);
void config_lock_read(void);
void config_unlock_read(void);
void config_lock_write(void);
void config_unlock_write(void);

void scan_active_users(void);
void load_config_rules(const char* main_conf_path);

char* clean_path_string(char* str);
void strip_trailing_slash(char* path);
int mkdir_recursive_p(const char *path, mode_t mode);

void print_active_rules(const char* pkg, int pid, uid_t uid, const char* trigger_source);

#endif