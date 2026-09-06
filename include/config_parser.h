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

/* FTP 后端规则：`FTP <虚拟前缀> <段名>`（段名 = ftp.conf [段名]）。
   规则所在段决定作用域：GLOBAL 段=全局，应用段=仅该应用。 */
typedef struct {
    char virtual_prefix[MAX_PATH_LEN];  /* 虚拟前缀（不含 user_id，如 /云盘） */
    char backend_name[64];              /* FTP 段名（ftp.conf [段名]） */
} FtpRule;

typedef struct {
    char pkg_name[128];
    int user_id;         
    bool inject_enable;   
    bool monitor;
    bool monitor_explicit; /* true = 显式设置过 MONITOR ON/OFF，可覆盖全局 */
    bool sandbox;
    bool sandbox_explicit; /* true = 显式设置过 SANDBOX ON/OFF，可覆盖全局 */
    bool global_inject;
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
    FtpRule* ftp_rules;      /* FTP <虚拟前缀> <段名> 规则 */
    int ftp_count;
    int ftp_capacity;
    TrieNode* trie_root;
    /* 动态规则标志：redir/hide/ro 规则中存在通配符或路径变量（未入 trie，
       须运行时线性匹配）。全静态时 trie 为完整决策源，resolve/probe 可跳过
       线性兜底（热路径）——br_probe 目录缓存命中路径据此实现无锁读取 */
    bool dyn_redir;
    bool dyn_hide;
    bool dyn_ro;
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

/* S1 无锁快照协议（热路径 br_resolve/br_probe 使用，替代 config_lock_read）：
   读者 config_read_begin() 返回稳定代际（偶数）并持槽；config_read_end(gen)
   释放槽并返回代际是否未变（false = 读期间发生发布，调用方须重试）。
   写者 config_publish_begin() 返回旧代际并置奇数（封锁新读者）；
   config_drain_readers(old_gen) 等待旧代际读者归零（交换前调用，防撕裂读）；
   config_publish_end(old_gen) 放行并等待旧代际读者归零（之后方可释放旧配置）。 */
uint64_t config_read_begin(void);
bool config_read_end(uint64_t gen);
uint64_t config_publish_begin(void);
void config_drain_readers(uint64_t old_gen);
void config_publish_end(uint64_t old_gen);

/* FTP 规则匹配（供规则模块 resolve 用）：sub_path 命中 FTP 规则虚拟前缀
   （最长前缀优先）时输出 FTP 段名（ftp.conf [段名]），返回 true */
bool config_ftp_match(const AppConfig* cfg, const char* sub_path, char* backend_out, size_t sz);
void scan_active_users();
/* 应用规则目录创建权限开关：仅 injector 应开启（true）；fuse_daemon（经
   basic_rules 模块）、log_ctl 等只读加载方保持默认 false，加载配置时
   不得 mkdir App-rules / App-rules-<uid>（防止伪用户目录固化） */
void config_set_allow_app_rules_mkdir(bool allow);
/* 活跃用户 pm 探测开关：fuse_daemon（经 basic_rules 模块）、log_ctl 等只读
   加载方置 true——scan_active_users 跳过 popen("pm list users")（该命令需
   binder 通信 system_server，受限环境会挂起阻塞配置加载），改由 /data/media
   与已存在的 App-rules-<uid> 目录推导用户列表 */
void config_set_scan_users_skip_pm(bool skip);
void load_config_rules(const char* main_conf_path);
int reload_config_rules_diff(const char* path, ChangedPkg* out_changed, int max_changed);
char* clean_path_string(char* str);
void strip_trailing_slash(char* path);
/* mkdir_recursive_p 声明归 common.h 所有（实现已迁移至 common.c），此处不重复声明 */
void print_active_rules(const char* pkg, int pid, uid_t uid, const char* trigger_source);
AppConfig* find_app_cfg_locked(const char* pkg, int user_id);
bool has_wildcard_enabled_locked(int user_id);
/* Trie 接口见 path_trie.h（config_parser.h 已 include） */

#endif