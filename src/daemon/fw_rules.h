#ifndef FW_RULES_H
#define FW_RULES_H
/*
 * fw_rules.h — 框架内建规则引擎（原 basic_rules 模块的决策核心）
 *
 * 规则决策（REDIRECT / SANDBOX / HIDE / ALLOW / RO + FTP 前缀归属）是**框架
 * 能力**，不是可插拔的第三方扩展：它读的是框架自己的配置索引，算的是框架自己的
 * 路径语义，与 uid→包名（fw_pkg.c）、配置视图（fw_config.c）同源同生。放进模块
 * 只会让「模块缺席 ⇒ 规则与监控一起失效」。故本引擎编入 fuse_daemon，模块只剩
 * 后端存储方法（`backend_*`）。
 *
 * 因此**决策结构与查询上下文不再是模块 ABI 的一部分**（见 nsp_module.h）：
 * 它只在本头与 fuse_daemon/fw_rules 之间流转。唯一跨 ABI 的数据类型是
 * `NspDirEntry`（后端 readdir 用它回传条目）。
 */
#include "nsp_module.h" /* NspDirEntry（跨 ABI 类型） */
#include "nsp_constants.h"
#include "path_trie.h" /* TrieNode（引擎内部 trie 查询） */
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* ================= 查询上下文（框架 → 引擎） ================= */

typedef struct NspQueryCtx {
    uid_t uid; /* 触发 FUSE 操作的进程 uid */
    pid_t pid; /* 触发 FUSE 操作的进程 pid */
    gid_t gid;
    const char* path; /* FUSE 原始路径（含 /0/ user_id 前缀） */
} NspQueryCtx;

/* ================= 决策结果（引擎 → 框架） ================= */

/* 虚拟路径性质（合成目录判定） */
typedef enum {
    NSP_VK_NONE = 0,     /* 普通路径 */
    NSP_VK_ANCESTOR = 1, /* 某 REDIRECT 前缀的祖先（合成目录） */
    NSP_VK_TARGET = 2,   /* 路径本身是某 REDIRECT 的真实目标 */
} NspVirtualKind;

/* 声明式决策：引擎只声明"这个路径该怎么表现"，由框架单点强制（fw_route），
   errno 映射与权限策略不在引擎里。

   注：V3 时代曾另有 attr_override + mode/uid/gid（模块声明属主/权限覆盖），
   但规则语法从未支持它、引擎恒不置位，属无生产者的能力；V4 连同 ABI 一起删除
   ——框架一律原样上报真实属主/权限。 */
typedef struct NspPathDecision {
    bool valid;          /* false = 不参与规则（无 <uid>/ 用户层或路径被拒），框架直通 */
    bool appear_missing; /* 视为不存在 → 框架在**所有**回调统一返回 ENOENT */
    bool read_only;      /* 只读 → 框架在所有变更操作统一返回 EROFS
                            （root 豁免等策略由框架持有） */
    uint8_t virtual_kind; /* NspVirtualKind：合成目录判定 */
    /* 最终真实路径（引擎已把重定向/沙箱落实为可操作路径；
       未命中任何规则时为默认存储路径 STORAGE_BASE/<uid><sub>） */
    char real_path[PATH_MAX];
    bool is_redirect; /* 最终路径是否经重定向（日志/权限处理用） */
    /* FTP 后端规则命中（injector.conf 的 `FTP <虚拟前缀> <段名>` 规则）：
       规则所在段决定作用域（[GLOBAL]=全局，[应用段]=仅该应用）；
       命中后框架将该路径操作分派给对应 FTP 后端模块。 */
    bool is_ftp;
} NspPathDecision;

/* ================= 轻量路径探测 =================
   readdir 逐条目过滤用（性能敏感）：只判 appear_missing/虚拟目录性质/
   跨应用隔离，不构建最终真实路径、不触发 sandbox 目录创建等副作用。 */

typedef struct NspProbeResult {
    bool valid;              /* false = 不参与规则，框架视为不过滤 */
    bool appear_missing;     /* 条目应视为不存在 → 跳过 */
    uint8_t virtual_kind;    /* NspVirtualKind：TARGET 条目跳过（避免与虚拟目录重复） */
    bool is_other_app_pkg;   /* 跨应用隔离 */
} NspProbeResult;

/* ================= 引擎内部：单次操作的 trie 查询结果缓存 =================
   同一次 resolve 对同一 sub_path 会问 app/类别/global 三棵 trie：一次下降把
   命中信息全带上，避免各自再全路径遍历（热路径每操作最多省 4 次 trie 下降）。 */

/* 规则作用域（数值即优先级：应用 > 类别 > [GLOBAL]，见 docs/config.md §2）。
   Trie 与线性通道是同一作用域内的两种等价实现（Trie 只是静态规则的加速索引），
   故跨作用域比较一律用本枚举，不得让「通道」压过「作用域」。 */
typedef enum {
    BR_SCOPE_NONE = 0,   /* 未命中 */
    BR_SCOPE_GLOBAL = 1, /* [GLOBAL] */
    BR_SCOPE_CAT = 2,    /* 类别段 [USER_APPS[:uid]] / [SYSTEM_APPS] */
    BR_SCOPE_APP = 3,    /* 应用段 [<pkg>] / [<pkg>:<uid>] */
} BrRuleScope;

typedef struct {
    bool valid;     /* 是否已 resolve */
    bool hidden;    /* app_hidden || cat_hidden || global_hidden */
    bool ro;        /* app_ro || cat_ro || global_ro */
    bool has_redir; /* 命中 redirect（app > 类别 > global） */
    BrRuleScope redir_scope; /* has_redir 时命中所在作用域：同层静态 vs 线性、
                                跨层作用域优先的比较都靠它（旧实现只留合并后的
                                目标、丢了作用域，导致 GLOBAL 静态压过应用/类别的
                                动态规则） */
    char redir[PATH_MAX];
    /* FTP 最长前缀命中（trie 下降过程输出）：app > 类别 > global */
    char ftp_app[64];
    char ftp_cat[64];
    char ftp_global[64];
    const TrieNode* app_node; /* trie 完整匹配的最深节点（可 NULL），供虚拟目录判定复用 */
    const TrieNode* cat_node;
    const TrieNode* global_node;
} FwRulesTrieMatch;

/* ================= 接口 ================= */

/* 初始化（fuse_daemon 启动期、fw_config_init 之前）：只建内部缓存，并把
   「派生缓存作废」注册到配置发布临界区（config_set_publish_invalidate_hook），
   此后每次发布都会在唯一安全窗口内自动作废，重载方无需（也不该）在发布后补调。 */
int fw_rules_init(const char* rules_path, bool disable_sandbox);
void fw_rules_exit(void);

/* 配置发布临界区内的作废钩子实现（由 config_publish 在「旧读者已排空、
   新读者仍封锁」的窗口内调用）：作废 uid→AppConfig 指针缓存并递增代际
   （旧 AppConfig 随即被 COW 释放，缓存不禁会造成悬垂）。
   不得直接调用——它是 config_set_publish_invalidate_hook 的注册体。 */
void fw_rules_invalidate_caches(void);

/* 路径决策：一次返回全部决策。无 <uid>/ 用户层（挂载点根）时 uns 置 valid=false。 */
void fw_rules_resolve(const NspQueryCtx* q, NspPathDecision* out);

/* 轻量探测：readdir 逐条目过滤用 */
void fw_rules_probe(const NspQueryCtx* q, NspProbeResult* out);

/* backing 直通仲裁：Android/data|obb 子树是否需 daemon 仲裁。
   背景：内核侧挂接 backing 后该子树 I/O 不再经过 daemon，且系统 BPF 策略
   程序（如挂接）会按调用方独立裁决——线上实例：空规则下 root 按名 stat 他包
   data 目录被系统程序以 ENOENT 拒绝（直接访问 backing 则正常），daemon 日志
   零痕迹；挂接后 SANDBOX 过滤/REDIRECT/HIDE/RO 对该子树同样整体失效。
   故挂接前须确认没有任何规则需要对此子树仲裁。判定保守（fail-closed）：
   任一段 SANDBOX ON，或任一条 REDIRECT（ALLOW 除外，ALLOW 即直通）/HIDE/RO/
   FTP 前缀的字面量或其变量展开值与 data/obb 相交（其下、其本身、其祖先、
   或规则即 "/"），即要求仲裁。经 config_read_begin/end 快照协议读索引。 */
bool fw_data_mediation_required(void);

/* backing 按路径仲裁（细粒度门）：查询路径 fuse_path（可带 /<uid>/ 层，
   内部归一为 sub_path）是否需 daemon 仲裁。语义 = 全局门
   fw_data_mediation_required() 的按路径细化：仅当某条规则在该路径自身
   （相等/其下）或其直接父目录（readdir 会列出受影响名，attr 可能来自
   重定向目标）上产生 per-caller 差异时返回 true；远祖先（挂载根、/0、
   /Android 等，只列出中间名）不强制要求仲裁，允许 backing 保留。
   SANDBOX ON 除外：共享目录重定向 + 跨应用隔离影响整树，任一查询均 true
   （隐私模式，正确优先）。REDIRECT 只看 virtual_prefix（ALLOW 跳过）；
   HIDE/RO/FTP 看各自前缀；含 $变量时追查展开值。fail-closed。 */
bool fw_backing_mediation_required_for(const char* fuse_path);

/* readdir 虚拟目录补充：向 out 填充最多 max 个虚拟条目，返回条目数
   （框架负责 filler 与去重；sandbox/Android 骨架由框架自行合成）。 */
int fw_rules_readdir_extra(const NspQueryCtx* q, const char* sub_path, int user_id,
                           const char* pkg, bool is_root, NspDirEntry* out, int max);

/* 路径是否含 <uid>/ 用户层（如 /0/foo、/10/、或 /0 本身）：挂载点根（/、/obb）
   不进行任何规则合成——从源头规避挂载点根下出现额外虚拟目录。 */
bool fw_rules_path_has_uid_layer(const char* path);

#endif /* FW_RULES_H */
