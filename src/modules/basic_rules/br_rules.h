#ifndef BR_RULES_H
#define BR_RULES_H
/*
 * br_rules.h — basic_rules 模块内部决策引擎接口
 *
 * 从 vfs_core.c 适配：规则决策（REDIRECT/SANDBOX/HIDE/ALLOW/RO）
 * 输出接口供 basic_rules.c 的 resolve/readdir 使用。
 * 不再依赖 fuse_get_context，uid 由 resolve 上下文传入。
 */
#include "config_parser.h"
#include "nsp_module.h" /* NspDirEntry（readdir 补充接口） */
#include <sys/types.h>
#include <limits.h>
#include <stdbool.h>

/* 与 vfs_core.h 的 TrieMatch 定义保持一致（避免引入 fuse3 头依赖）：
   单次操作内对同一 sub_path 的 Trie 查询结果缓存，redir 存已拼接的完整目标串
   （可能含 '?' 前缀，运行时再展开）。 */
typedef struct {
    bool valid;     /* 是否已 resolve */
    bool hidden;    /* app_hidden || cat_hidden || global_hidden */
    bool ro;        /* app_ro || cat_ro || global_ro */
    bool has_redir; /* 命中 redirect（app > 类别 > global） */
    char redir[PATH_MAX];
    /* FTP 最长前缀命中（trie 下降过程输出）：app > 类别 > global */
    char ftp_app[64];    /* app trie 命中段名（可空） */
    char ftp_cat[64];    /* 类别 trie（USER_APPS/SYSTEM_APPS）命中段名（可空） */
    char ftp_global[64]; /* global trie 命中段名（可空） */
    /* trie 完整匹配的最深节点（由 trie_lookup_full 填充，可 NULL）：
       供 br_resolve 复用一次遍历结果判定 virtual_ancestor / redirect_target，
       避免各自再全路径遍历（FUSE 热路径每操作最多省 4 次 trie 下降） */
    const TrieNode* app_node;
    const TrieNode* cat_node; /* 类别 trie 最深节点（可 NULL） */
    const TrieNode* global_node;
} TrieMatch;

/* 模块初始化：rules_path = --rules= 参数，disable_sandbox = --disable-sandbox 标志 */
int br_rules_init(const char* rules_path, bool disable_sandbox);
void br_rules_exit(void);

/* 核心决策：替代 vfs_core 的三连调用（sanitize + hidden + to_real_path + ro） */
typedef struct {
    const char* path; /* 原始路径 */
    uid_t uid;
    pid_t pid;
    gid_t gid;
} BrQuery;

typedef struct {
    bool valid;
    int user_id;
    char sub_path[PATH_MAX];
    char pkg[128];
    bool hidden;
    bool ro;
    bool has_redir;
    char redir_target[PATH_MAX];
    bool has_sandbox;
    char sandbox_target[PATH_MAX];
    char real_path[PATH_MAX];
    bool is_redir;
    bool is_virtual_ancestor;
    bool is_redirect_target;
    bool is_other_app_pkg;
    bool is_ftp;          /* FTP <虚拟前缀> <段名> 规则命中（作用域由段决定） */
    char ftp_backend[64]; /* FTP 段名（ftp.conf [段名]） */
    bool monitor_on;
} BrResult;

typedef struct {
    bool valid;
    bool hidden;
    bool is_redirect_target;
    bool is_virtual_ancestor;
    bool is_other_app_pkg;
} BrProbeResult;

void br_resolve(const BrQuery* q, BrResult* out);

/* 轻量探测：只判 hidden/redirect_target/虚拟目录标志，不构建真实路径、
   不触发 sandbox 目录创建（readdir 逐条目过滤用，性能敏感） */
void br_probe(const BrQuery* q, BrProbeResult* out);

/* readdir 虚拟目录补充：返回属于 sub_path 的 REDIRECT 前缀合成子目录条目
   （框架负责 ht 去重 + filler；sandbox/Android 骨架由框架基于 path_user_id/
    g_disable_sandbox/current_pkg 自行合成，模块无需提供） */
int br_readdir_extra(const BrQuery* q, const char* sub_path, int user_id, const char* pkg,
                     bool is_root, NspDirEntry* out, int max);

/* 配置热重载 */
void br_reload_config(void);

/* uid → 包名解析（框架日志用） */
int br_get_pkg(uid_t uid, pid_t tid, char* pkg_out, size_t pkg_size);

#endif /* BR_RULES_H */