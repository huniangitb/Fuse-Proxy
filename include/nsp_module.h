/* SPDX-License-Identifier: GPL-3.0-or-later WITH Fuse-Proxy-module-exception */
/*
 * 版权所有 (C) 2026 huniangitb <3361107168@qq.com>
 *
 * 本文件是 Fuse-Proxy 的一部分，以 GPL-3.0-or-later 发布（见 LICENSE）。
 *
 * 模块 ABI 链接例外：仅通过本头文件声明的公开 ABI 与 Fuse-Proxy 结合的
 * 独立模块（运行时 dlopen 加载的 .so），可按任意条款发布，不因此受 GPL
 * 约束。完整条款见 LICENSE.module-exception。
 */
#ifndef NSP_MODULE_H
#define NSP_MODULE_H
/*
 * nsp_module.h — Fuse-Proxy 热插拔模块 ABI
 *
 * 设计目标：
 *   1. 框架（fuse_daemon）与模块完全解耦：框架通过「能力位图」了解模块
 *      支持什么，只调用模块声明过的接口；模块通过「框架服务表」使用框架
 *      提供的参数；日志与路径工具经公开运行时导出表解析。
 *   2. 可扩展：能力位图（32 位）与接口表按 ABI 版本演进；旧模块在框架
 *      ABI 不一致时拒绝加载，兼容新增服务追加在框架表尾部。
 *   3. 高性能：规则决策是 FUSE 热路径，一次 resolve 调用返回全部声明式决策
 *      （NspPathDecision：是否视为不存在/只读/属性覆盖/虚拟目录性质/最终真实
 *      路径），避免多次查询；框架在无模块注册时走快速路径，不产生任何函数
 *      指针调用开销。模块只声明"该怎么表现"，强制与 errno 映射由框架单点完成。
 *
 * 模块约定：
 *   - 模块为共享库（.so），放在 MODULES_DIR/<模块名>/<模块名>.so
 *   - 每个模块必须导出静态符号 nsp_module_info（NspModuleInfo 结构）
 *   - 加载流程：dlopen → dlsym(nsp_module_info) → 魔数/ABI 校验 →
 *     登记能力 → 调 init(api) → 注册完成；卸载流程：调 exit → dlclose
 *   - 模块名仅含 [a-z0-9_-]，目录名 = 模块名
 *
 * 规则类型注册（rule_server 动态扩展）：
 *   - 模块可在其目录放置 <模块名>.rules 文本文件，向 rule_server 声明
 *     自己支持的规则类型，实现「支持的规则随加载模块动态追加」。
 *   - 每行格式：<TYPE> <FORMAT>，FORMAT 取值：
 *       path   — 单值路径（如 HIDE /x）
 *       pair   — src|dst 双值（如 REDIRECT /a|/b）
 *       switch — ON/OFF 开关（如 MONITOR ON）
 *       tokens — 空格分隔多 token（ADD 时 value 用 | 分隔）
 *   - rule_server 按需扫描模块目录下的 <模块名>.rules（目录/文件 mtime 缓存，
 *     未变化时直接复用类型表），动态合并进规则类型表；不存在的类型无法
 *     ADD/REMOVE/ENABLE/DISABLE。
 *   - 无 .rules 文件的模块不影响加载（rule_server 仅跳过其类型注册）。
 *
 * 规则类型说明（basic_rules 模块承载）：
 *   REDIRECT  — 路径重定向（虚拟前缀 → 真实目标，含 ALLOW 豁免的内部 ? 形式）
 *   SANDBOX   — 应用存储沙箱隔离（/Android/data/<pkg>/sandbox）
 *   HIDE      — 路径隐藏（返回 ENOENT）
 *   ALLOW     — 豁免（放行，等价重定向回自身存储）
 *   RO        — 只读保护（写操作返回 EROFS）
 */
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h> /* struct stat（后端 getattr，系统类型与 fuse 无关） */
#include <limits.h>
#include <linux/limits.h> /* Linux/Android ABI 的 PATH_MAX，不依赖 libc 特性宏。 */
#include "nsp_cfg_view.h" /* 配置扁平视图（框架下发规则/变量给模块） */

/* ================= ABI 版本与魔数 ================= */

/* V3：决策结果改为声明式 NspPathDecision（取代 NspResolveResult），
   删除 hidden/ro/is_virtual_ancestor/is_redirect_target/user_id/sub_path，
   新增 appear_missing/read_only/mode/uid/gid/virtual_kind。属不兼容变更，
   加载器拒绝 V2 模块——**V2 模块须重编译**。 */
#define NSP_MODULE_ABI_VERSION 3u
#define NSP_MODULE_MAGIC       0x4E53504Du /* "NSPM" */

/* ================= 模块类型 ================= */

typedef enum {
    NSP_MODULE_TYPE_RULES = 1,   /* 规则模块：参与路径决策（REDIRECT/HIDE/RO/ALLOW/SANDBOX） */
    NSP_MODULE_TYPE_BACKEND = 2, /* 存储后端模块：提供新的存储后端（如 FTP），挂载到本地路径 */
} NspModuleType;

/* ================= 能力位图（32 位，按类型分组） ================= */

/* ---- 规则能力（NSP_MODULE_TYPE_RULES）----
   0..4 位用于模块自述，框架按整组判断是否参与 resolve/probe。 */
#define NSP_CAP_REDIRECT      (1u << 0) /* 支持 REDIRECT 重定向 */
#define NSP_CAP_SANDBOX       (1u << 1) /* 支持 SANDBOX 沙箱 */
#define NSP_CAP_HIDE          (1u << 2) /* 支持 HIDE 隐藏 */
#define NSP_CAP_ALLOW         (1u << 3) /* 支持 ALLOW 豁免 */
#define NSP_CAP_RO            (1u << 4) /* 支持 RO 只读 */
#define NSP_CAP_READDIR_EXTRA (1u << 5) /* 支持 readdir 虚拟目录补充 */

/* ---- 后端能力（NSP_MODULE_TYPE_BACKEND）---- */
#define NSP_CAP_BACKEND_IO \
    (1u << 12) /* 后端 I/O：路径命中时由框架调用模块方法
                                               完成文件操作（模块不实现 FUSE，只提供方法） */

/* ================= 框架服务表（框架 → 模块） =================
   模块 init 时收到该表，仅通过它使用框架设施。
   版本化：新增字段追加在结构尾部，旧模块按 api_version 决定是否访问。 */

typedef struct NspFrameworkApi {
    uint32_t api_version;                /* 当前 NSP_FRAMEWORK_API_VERSION */
    const char* (*get_rules_path)(void); /* 规则配置文件路径（--rules= 参数） */
    uint32_t (*get_flags)(void);         /* 框架启动标志（NSP_FLAG_*） */

    /* ---- API V4 追加（尾部新增，旧模块按 api_version 决定是否使用）----
       配置读取完全由框架完成：框架读 injector.conf / App-rules* 及模块目录下的
       模块配置文件，按订阅过滤后以扁平视图下发；模块不再读文件、不再跑 inotify。

       两者都**只在 init 内调用**（框架以"当前正在初始化的模块"为上下文记录，
       故无需额外参数）。订阅缺失 = 申请全部规则（不推荐，失去隔离）。 */

    /* 声明本模块申请的规则类型（如 "HIDE"/"REDIRECT"/"FTP"/"VAR"）。
       框架只下发这些类型的记录，实现模块间规则隔离——A 模块看不到 B 模块的规则。 */
    void (*subscribe_rules)(const char* const* types, int count);
    /* 注册配置变更回调：框架在每次发布新配置后、按本模块订阅过滤后调用；
       回调内应重建索引。cfg 仅在回调期间有效（框架持有，模块不得留存指针）。
       注册后框架会立即回调一次（init 期间）以完成首次加载。 */
    void (*set_config_listener)(void (*cb)(const NspModuleConfig* cfg));
} NspFrameworkApi;

#define NSP_FRAMEWORK_API_VERSION 4u

/* 框架启动标志（get_flags 返回） */
#define NSP_FLAG_DISABLE_SANDBOX (1u << 0) /* --disable-sandbox */

/* ================= 路径决策上下文（框架 → 模块） ================= */

typedef struct NspQueryCtx {
    uid_t uid; /* 触发 FUSE 操作的进程 uid */
    pid_t pid; /* 触发 FUSE 操作的进程 pid */
    gid_t gid;
    const char* path; /* FUSE 原始路径（含 /0/ user_id 前缀） */
} NspQueryCtx;

/* ================= 决策结果（模块 → 框架） ================= */

/* 属性覆盖开关位：默认 0 = 不覆盖任何属性，故模块 `memset(out, 0, sizeof *out)`
   这类零初始化是安全的（若用"特殊值哨兵"表示不改，零初始化会静默变成
   "权限清 0 + 属主 root"）。要覆盖哪个字段就置对应位，字段值才被读取。 */
#define NSP_OV_MODE (1u << 0) /* 读 mode（仅权限位，文件类型位由框架保留） */
#define NSP_OV_UID  (1u << 1) /* 读 uid */
#define NSP_OV_GID  (1u << 2) /* 读 gid */
#define NSP_OV_ALL  (NSP_OV_MODE | NSP_OV_UID | NSP_OV_GID)

/* 虚拟路径性质（合成目录判定）：单字段取代原先两个并列 bool，
   模块按需声明，框架据此决定合成目录 / readdir 条目过滤 */
typedef enum {
    NSP_VK_NONE = 0,     /* 普通路径 */
    NSP_VK_ANCESTOR = 1, /* 某 REDIRECT 前缀的祖先（合成目录） */
    NSP_VK_TARGET = 2,   /* 路径本身是某 REDIRECT 的真实目标 */
} NspVirtualKind;

/* 声明式决策：模块只声明"这个路径该怎么表现"，由框架单点强制
   （vfs_apply_decision）。这样模块无需了解 FUSE 回调类别与 errno 映射，
   也不会出现"读类回调 ENOENT、写类回调 EACCES"这类不一致。

   框架自算字段（**不在本结构内**，模块无需也不得回填）：
     user_id / sub_path —— 框架由原始路径解析（fw_parse_path），与模块侧
     剥离逻辑逐行等价，故无需跨 ABI 传递。

   多模块合并：appear_missing / read_only 取并集；real_path 取首次重定向；
   pkg / is_ftp / monitor_on / virtual_kind 由首个 valid 模块独占。 */
typedef struct NspPathDecision {
    bool valid;          /* false = 模块无法解析该路径，框架回退默认行为 */
    bool appear_missing; /* 视为不存在 → 框架在**所有**回调统一返回 ENOENT */
    bool read_only;      /* 只读 → 框架在所有变更操作统一返回 EROFS
                            （root 豁免等策略由框架持有） */
    /* 属性覆盖（可选）：attr_override 的位决定 mode/uid/gid 是否被采用。
       mode 只取 07777 权限位，S_IFMT 类型位一律忽略——文件类型始终取自真实
       属性（声明 S_IFDIR 也不会把文件变成目录；要让路径"表现成目录"应走重定向/
       虚拟目录，而不是改类型位）。 */
    uint32_t attr_override; /* NSP_OV_* 位图，0 = 不改任何属性 */
    uint32_t mode;          /* NSP_OV_MODE 置位时生效 */
    int32_t uid;            /* NSP_OV_UID 置位时生效 */
    int32_t gid;            /* NSP_OV_GID 置位时生效 */
    uint8_t virtual_kind; /* NspVirtualKind：合成目录判定 */
    char pkg[128];        /* uid 解析出的包名（日志/沙箱用）。
                             留在结果内是因为它随 resolve 一次返回；移到框架侧
                             需要每个请求额外一次 get_pkg 模块调用（围栏+校验
                             开销），得不偿失 */
    /* 最终真实路径（模块负责把以上决策落实为最终可操作路径；
       未命中任何规则时为默认存储路径 STORAGE_BASE/<uid><sub>） */
    char real_path[PATH_MAX];
    bool is_redirect; /* 最终路径是否经重定向（日志/权限处理用） */
    /* FTP 后端规则命中（injector.conf 的 `FTP <虚拟前缀> <段名>` 规则）：
       规则所在段决定作用域（[GLOBAL]=全局，[应用段]=仅该应用）；
       命中后框架将该路径操作分派给对应 FTP 后端模块。
       ⚠ 过渡字段：FTP 归属迁移到 ftp_module 后删除（见 docs/modules.md）。 */
    bool is_ftp;
    bool monitor_on; /* 模块配置的 MONITOR 状态（框架 I/O 日志开关） */
} NspPathDecision;


/* ================= readdir 虚拟目录补充 =================
   模块填充条目数组，框架负责 filler 与去重（不依赖 fuse 类型，便于解耦）。 */

typedef struct NspDirEntry {
    char name[256];
    bool is_dir;
} NspDirEntry;

/* ================= 轻量路径探测 =================
   readdir 逐条目过滤用（性能敏感）：只判 appear_missing/虚拟目录性质/
   跨应用隔离，不构建最终真实路径、不触发 sandbox 目录创建等副作用。 */

typedef struct NspProbeResult {
    bool valid;              /* false = 模块无法解析，框架视为不过滤 */
    bool appear_missing;     /* 条目应视为不存在 → 跳过 */
    uint8_t virtual_kind;    /* NspVirtualKind：TARGET 条目跳过（避免与虚拟目录重复） */
    bool is_other_app_pkg;   /* 跨应用隔离 */
} NspProbeResult;

/* ================= 模块接口表（模块 → 框架） =================
   所有字段可选，未实现置 NULL；框架只调用模块 caps 声明过的能力。 */

typedef struct NspModuleOps {
    /* ---- 规则能力（对应 NSP_CAP_*）---- */
    /* 路径决策：一次调用返回全部决策（见 NspPathDecision）。返回 0 成功；负值错误码。 */
    int (*resolve)(const NspQueryCtx* q, NspPathDecision* out);
    /* 轻量路径探测（readdir 逐条目过滤，性能敏感）：只判 hidden/重定向目标/
       虚拟目录标志，不构建真实路径、不触发 sandbox 目录创建。返回 0 成功。 */
    int (*probe)(const NspQueryCtx* q, NspProbeResult* out);
    /* readdir 虚拟目录补充：向 out 填充最多 max 个虚拟条目，返回条目数。 */
    int (*readdir_extra)(const NspQueryCtx* q, const char* sub_path, int user_id, const char* pkg,
                         bool is_root, NspDirEntry* out, int max);

    /* ---- 后端能力（NSP_MODULE_TYPE_BACKEND）---- */

    /* 后端 I/O（NSP_CAP_BACKEND_IO）：路径命中（backend_match 返回 1）时，
       框架不再操作本地文件系统，改调模块方法。path 为框架解析后的真实路径
       （如 /mnt/nsp_ftp/云盘/xxx），模块自行剥离前缀映射到目标存储。
       句柄 h 由模块分配/释放（uint64_t），框架透传。返回 0 成功，负值 errno 风格。 */
    int (*backend_match)(const char* path); /* 1=管理该路径 0=否 */
    int (*backend_getattr)(const char* path, struct stat* st);
    int (*backend_readdir)(const char* path, NspDirEntry* entries, int max);
    int (*backend_open)(const char* path, int flags, uint64_t* h);
    int (*backend_read)(uint64_t h, char* buf, size_t size, off_t off, size_t* got);
    int (*backend_write)(uint64_t h, const char* buf, size_t size, off_t off, size_t* wrote);
    /* 数据收尾（FUSE FLUSH，close() 同步等待）：写模式完成上传但**不销毁
       句柄**（FLUSH 可因 dup/fork 多次调用，销毁须等 RELEASE）；可为 NULL
       （NULL 时 FLUSH 仅做缓存失效）。返回 0 成功。 */
    int (*backend_flush)(uint64_t h);
    int (*backend_release)(uint64_t h);
    int (*backend_create)(const char* path, mode_t mode, uint64_t* h);
    int (*backend_unlink)(const char* path);
    int (*backend_mkdir)(const char* path, mode_t mode);
    int (*backend_rmdir)(const char* path);
    int (*backend_rename)(const char* from, const char* to);
    int (*backend_truncate)(const char* path, off_t size);

    /* ---- 通用 ---- */
    /* uid → 包名解析（框架日志等场景使用；返回 0 成功，pkg 最多 127 字节） */
    int (*get_pkg)(uid_t uid, pid_t tid, char* pkg_out, size_t pkg_size);
} NspModuleOps;

/* ================= 模块信息（静态导出） ================= */

typedef struct NspModuleInfo {
    uint32_t magic;                          /* 必须 == NSP_MODULE_MAGIC */
    uint32_t abi_version;                    /* 必须 == NSP_MODULE_ABI_VERSION */
    uint32_t type;                           /* NspModuleType */
    uint32_t caps;                           /* 能力位图 */
    const char* name;                        /* 模块名（[a-z0-9_-]） */
    const char* version;                     /* 模块自身版本字符串 */
    int (*init)(const NspFrameworkApi* api); /* 初始化，成功返回 0 */
    void (*exit)(void);                      /* 清理（可为 NULL） */
    const NspModuleOps* ops;                 /* 接口表（可为 NULL，须与 caps 一致） */
} NspModuleInfo;

/* 模块必须导出的符号名 */
#define NSP_MODULE_INFO_SYMBOL "nsp_module_info"

/* ================= 模块公共运行时 ABI =================
   以下设施经主程序导出符号表（fuse_daemon 链接 -Wl,--export-dynamic）
   在 dlopen 时解析：模块源码层面仅依赖本头（+ 标准库），不 include 任何
   框架内部头、不编译框架源码——模块间仅 ABI 兼容，可互相独立源码开发。
   日志声明与级别由 nsp_log.h 统一提供（0=DEBUG 1=INFO 2=WARN 3=ERROR）。 */

/* 框架 TU（未定义 NSP_MODULE_BUILD）跳过本段：声明/宏以 common.h 为准，
   避免 conflicting types 与宏重定义（与 include 顺序无关）；仅模块编译
   （meson 模块 target 加 -DNSP_MODULE_BUILD）激活本 ABI 段。 */
#ifdef NSP_MODULE_BUILD

#include <stdarg.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <dirent.h>
#include <libgen.h>

#include "nsp_constants.h"

/* 框架导出符号（模块经主程序导出表解析） */
extern _Atomic(bool) g_log_shutdown;

int mkdir_recursive(const char* dir);
int mkdir_recursive_p(const char* path, mode_t mode);
void path_sanitize(char* out, size_t size, const char* path);
bool path_contains_invalid_chars(const char* path);
/* 存储路径合成统一出口（common.c 实现，经主程序导出表解析；语义见 common.h） */
void common_default_real_path(int user_id, const char* sub_path, char* out, size_t sz);
int common_sandbox_path(int uid, const char* pkg, char* out, size_t sz);

#include "nsp_log.h"

#define CONFIG_DIR   NSP_CONFIG_DIR
#define STORAGE_BASE NSP_STORAGE_BASE
#define LOG_DIR      NSP_LOG_DIR

#endif /* NSP_MODULE_BUILD（模块独立 ABI；框架 TU 用 common.h 声明） */

#endif /* NSP_MODULE_H */
