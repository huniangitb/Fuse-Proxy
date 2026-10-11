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

/* FTP 后端规则：`FTP <虚拟前缀> <段名>`（段名 = 模块配置里的 [段名]）。
   规则所在段决定作用域：GLOBAL 段=全局，应用段=仅该应用。 */
typedef struct {
    char virtual_prefix[MAX_PATH_LEN];  /* 虚拟前缀（不含 user_id，如 /云盘） */
    char backend_name[64];              /* FTP 段名（模块配置里的 [段名]） */
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
    /* [GLOBAL] 段 SANDBOX_DIR：沙盒目录名（覆盖 NSP_SANDBOX_DIRNAME 默认
       "sandbox"）；仅 [GLOBAL] 段有效，空串 = 用默认 */
    char sandbox_dir[64];
} AppConfig;

typedef struct {
    char pkg_name[128];
    int user_id;
} ChangedPkg;

/* ================= 配置扁平视图（读文件 与 建索引 分离） =================
 * 目的：配置的**读取**（文件 I/O + 行级词法 + 段头识别）与**建索引**
 * （关键字 → 规则对象 → trie/变量静态性 → COW 发布）拆成两段，两段共用同一
 * 构建逻辑，语义零漂移。框架读文件产出视图，消费者（含 dlopen 模块）由视图
 * 重建配置而无需触碰文件系统——模块不再自行读文件/跑 inotify。
 *
 * 记录类型（NspCfgRec / NspCfgRecKind）与下发载荷（NspModuleConfig）定义在
 * nsp_cfg_view.h——该头是框架侧与模块侧的共享契约，属模块 ABI 的一部分。
 *
 * 视图为只读：config_build_from_view 内部复制行文本后再解析，不修改入参。 */
#include "nsp_cfg_view.h"

/* 读主文件 + App-rules* 目录 + 各模块自有配置（<modules_dir>/<名>/<名>.conf）
   为扁平视图（读文件；框架/单进程消费者调用）。
   返回记录数（>=0）；视图与其中字符串经 config_free_view 释放。
   主文件缺失不致命：仍返回 App-rules 记录（与逐文件解析行为一致）。 */
int config_read_view(const char* main_path, NspCfgRec** out_recs, int* out_count);
void config_free_view(NspCfgRec* recs, int count);
/* 模块目录覆盖（--modules-dir= 与加载器同一取值；NULL/空 = 默认 MODULES_DIR）。
   模块自有配置的位置由此派生，故必须在首次 config_read_view 之前设置。 */
void config_set_modules_dir(const char* dir);
/* 当前生效的模块目录（fw_config 据此挂模块配置文件的 inotify watch） */
const char* config_modules_dir(void);
/* 由扁平视图重建配置并 COW 发布（不读文件系统；模块消费框架下发的视图）。
   视图仅 RULE 记录被逐行复制后解析，其余记录按值读取。
   调用方须持 config_lock_write。 */
void config_build_from_view(const NspCfgRec* recs, int count);

/* 发布期派生缓存作废钩子（进程内单一注册者：内建规则引擎）：config_publish 在
   「旧代际读者已排空、新读者仍被封锁」的窗口内调用一次，此时没有任何读者能
   重算并缓存即将释放的配置指针。派生缓存（uid→AppConfig 指针等）必须在此刻
   作废：早于该窗口，读者会把旧指针以新代际重新缓存（发布后即成悬垂）；晚于
   发布（放行新读者之后），则留出命中已释放指针的窗口。
   钩子运行在发布写者线程、已持 config_lock_write 的上下文里，不得再取该锁。 */
void config_set_publish_invalidate_hook(void (*fn)(void));

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

/* FTP 规则命中由 trie 在 resolve 热路径一次下降取得（最长前缀优先），
   不再有每请求 O(N) 线性扫描的独立匹配入口 */
void scan_active_users();
/* 应用规则目录创建权限开关：仅 injector 应开启（true）；fuse_daemon（经
   内建规则引擎）、log_ctl 等只读加载方保持默认 false，加载配置时
   不得 mkdir App-rules / App-rules-<uid>（防止伪用户目录固化） */
void config_set_allow_app_rules_mkdir(bool allow);
/* 活跃用户 pm 探测开关：fuse_daemon（内建引擎）、log_ctl 等只读
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
/* 类别段查找：is_system_app=true → SYSTEM_APPS（忽略 user_id）；
   false → USER_APPS[user_id]，无则 USER_APPS[-1]。调用方须持读锁/快照槽。
   类别段名（USER_APPS/SYSTEM_APPS）：[USER_APPS[:uid]] 对用户应用生效
   （无 :uid 则对所有用户生效）；[SYSTEM_APPS] 对所有 uid 系统应用生效 */
AppConfig* find_category_cfg_locked(bool is_system_app, int user_id);
/* 是否存在类别段（publish 时设置）：热路径据此跳过分类开销 */
bool config_has_category_rules(void);
/* 类别段是否有实质规则（注入判定用，调用方须持读锁） */
bool category_has_rules_locked(bool is_system_app, int user_id);
/* Trie 接口见 path_trie.h（config_parser.h 已 include） */

#endif