#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H
#include <stdbool.h>
#include <sys/types.h>
#include "path_trie.h"
#define MAX_PATH_LEN 256
#define MAX_USERS 64
#define MAX_REASONABLE_UID 1000

typedef struct {
    char virtual_prefix[MAX_PATH_LEN]; 
    char real_target[MAX_PATH_LEN]; 
    bool is_allow;           // true=ALLOW 规则, false=REDIRECT 规则
} RedirectRule;

typedef struct {
    char pkg_name[128];
    int user_id;         
    bool inject_enable;   
    bool monitor;
    bool monitor_explicit; /* true = 显式设置过 MONITOR ON/OFF，可覆盖全局 */
    bool sandbox;
    bool sandbox_explicit; /* true = 显式设置过 SANDBOX ON/OFF，可覆盖全局 */
    bool global_inject;   
    bool fuse_direct;
    bool skip_system_apps; /* 默认跳过 Android 系统应用 (uid < 10000)，配置 SKIP_SYSTEM_APPS OFF 可关闭 */
    char** hide_rules;
    int hide_count;
    int hide_capacity;
    char** ro_rules;
    int ro_count;
    int ro_capacity;
    RedirectRule* redir_rules;
    int redir_count;
    int redir_capacity;
    TrieNode* trie_root;
    char** var_names;
    char** var_values;      /* 原始值（含 $ 占位），动态变量运行时展开用 */
    char** var_resolved;    /* 静态变量的预计算展开值；动态变量为 NULL */
    bool*  var_is_static;   /* 静态/动态标记 */
    int    var_count;
    int    var_capacity;
    char fuse_extra_args[512];
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
AppConfig* find_app_cfg_locked(const char* pkg, int user_id);
bool has_wildcard_enabled_locked(int user_id);
/* Trie 接口见 path_trie.h（config_parser.h 已 include） */

#endif