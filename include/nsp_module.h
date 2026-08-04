#ifndef NSP_MODULE_H
#define NSP_MODULE_H
/*
 * nsp_module.h — Fuse-Proxy 热插拔模块 ABI
 *
 * 设计目标：
 *   1. 框架（fuse_daemon）与模块完全解耦：框架通过「能力位图」了解模块
 *      支持什么，只调用模块声明过的接口；模块通过「框架服务表」使用框架
 *      提供的设施（日志等），不依赖主程序符号表。
 *   2. 可扩展：能力位图（32 位）与接口表按 ABI 版本演进；旧模块在框架
 *      升级后仍可加载（版本兼容检查），新能力通过新增位 + 新增接口字段
 *      逐步加入，不破坏既有模块。
 *   3. 高性能：规则决策是 FUSE 热路径，一次 resolve 调用返回全部决策
 *      （hidden/ro/allow/redir/sandbox/最终真实路径），避免多次查询；
 *      框架在无模块注册时走快速路径，不产生任何函数指针调用开销。
 *
 * 模块约定：
 *   - 模块为共享库（.so），放在 MODULES_DIR/<模块名>/<模块名>.so
 *   - 每个模块必须导出静态符号 nsp_module_info（NspModuleInfo 结构）
 *   - 加载流程：dlopen → dlsym(nsp_module_info) → 魔数/ABI 校验 →
 *     登记能力 → 调 init(api) → 注册完成；卸载流程：调 exit → dlclose
 *   - 模块名仅含 [a-z0-9_-]，目录名 = 模块名
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
#include <limits.h>

/* ================= ABI 版本与魔数 ================= */

#define NSP_MODULE_ABI_VERSION  1u
#define NSP_MODULE_MAGIC        0x4E53504Du   /* "NSPM" */

/* ================= 模块类型 ================= */

typedef enum {
    NSP_MODULE_TYPE_RULES   = 1,  /* 规则模块：参与路径决策（REDIRECT/HIDE/RO/ALLOW/SANDBOX） */
    NSP_MODULE_TYPE_BACKEND = 2,  /* 存储后端模块：提供新的存储后端（如 FTP），挂载到本地路径 */
} NspModuleType;

/* ================= 能力位图（32 位，按类型分组） ================= */

/* ---- 规则能力（NSP_MODULE_TYPE_RULES）---- */
#define NSP_CAP_REDIRECT        (1u << 0)   /* 支持 REDIRECT 重定向 */
#define NSP_CAP_SANDBOX         (1u << 1)   /* 支持 SANDBOX 沙箱 */
#define NSP_CAP_HIDE            (1u << 2)   /* 支持 HIDE 隐藏 */
#define NSP_CAP_ALLOW           (1u << 3)   /* 支持 ALLOW 豁免 */
#define NSP_CAP_RO              (1u << 4)   /* 支持 RO 只读 */
#define NSP_CAP_READDIR_EXTRA   (1u << 5)   /* 支持 readdir 虚拟目录补充 */
#define NSP_CAP_VIRTUAL_DIR     (1u << 6)   /* 支持虚拟目录合成（is_virtual_ancestor 等） */

/* ---- 后端能力（NSP_MODULE_TYPE_BACKEND）---- */
#define NSP_CAP_MOUNT_POINT     (1u << 10)  /* 提供本地挂载点路径 */
#define NSP_CAP_VAR             (1u << 11)  /* 向框架注册变量（如 FTP_云盘=/mnt/nsp_ftp/云盘） */

/* ================= 框架服务表（框架 → 模块） =================
   模块 init 时收到该表，仅通过它使用框架设施。
   版本化：新增字段追加在结构尾部，旧模块按 api_version 决定是否访问。 */

typedef struct NspFrameworkApi {
    uint32_t api_version;                     /* 当前 NSP_FRAMEWORK_API_VERSION */
    void (*log)(int level, const char* fmt, ...);      /* 日志（level 见 common.h LogLevel） */
    const char* (*get_real_root)(void);       /* 真实存储根（--root 参数） */
    const char* (*get_rules_path)(void);      /* 规则配置文件路径（--rules= 参数） */
    uint32_t (*get_flags)(void);              /* 框架启动标志（NSP_FLAG_*） */
} NspFrameworkApi;

#define NSP_FRAMEWORK_API_VERSION 2u

/* 框架启动标志（get_flags 返回） */
#define NSP_FLAG_DISABLE_SANDBOX  (1u << 0)   /* --disable-sandbox */

/* ================= 路径决策上下文（框架 → 模块） ================= */

typedef struct NspQueryCtx {
    uid_t uid;                /* 触发 FUSE 操作的进程 uid */
    pid_t pid;                /* 触发 FUSE 操作的进程 pid */
    gid_t gid;
    const char* path;         /* FUSE 原始路径（含 /0/ user_id 前缀） */
} NspQueryCtx;

/* ================= 决策结果（模块 → 框架） ================= */

typedef struct NspResolveResult {
    bool valid;               /* false = 模块无法解析该路径，框架回退默认行为 */
    int  user_id;             /* 剥离 /0/ 前缀后的 user id */
    char sub_path[PATH_MAX];  /* 剥离后的虚拟路径（规则匹配使用） */
    char pkg[128];            /* uid 解析出的包名（可能为 unknown/system） */

    /* HIDE / RO / ALLOW（豁免） */
    bool hidden;              /* HIDE 命中 → 框架返回 ENOENT */
    bool ro;                  /* RO 命中 → 写操作返回 EROFS */
    bool allow;               /* ALLOW 豁免命中（等价自身存储） */

    /* REDIRECT（含 ALLOW 的 ? 内部形式；has_redir 且非 allow 为真实重定向） */
    bool has_redir;
    char redir_target[PATH_MAX];   /* 重定向目标（可能含变量，需框架或模块已展开） */

    /* SANDBOX */
    bool has_sandbox;
    char sandbox_target[PATH_MAX];

    /* 最终真实路径（模块负责把以上决策落实为最终可操作路径；
       未命中任何规则时为默认存储路径 STORAGE_BASE/<uid><sub>） */
    char real_path[PATH_MAX];
    bool is_redir;            /* 最终路径是否经重定向（日志/权限处理用） */

    /* 虚拟目录合成辅助（NSP_CAP_VIRTUAL_DIR） */
    bool is_virtual_ancestor; /* 路径是某 REDIRECT 前缀的祖先（合成目录） */
    bool is_redirect_target;  /* 路径本身是某 REDIRECT 的真实目标 */
    bool is_other_app_pkg;    /* 路径含其他应用包名（跨应用隔离隐藏） */
    bool monitor_on;          /* 模块配置的 MONITOR 状态（框架 I/O 日志开关） */
} NspResolveResult;

/* ================= readdir 虚拟目录补充 =================
   模块填充条目数组，框架负责 filler 与去重（不依赖 fuse 类型，便于解耦）。 */

typedef struct NspDirEntry {
    char name[256];
    bool is_dir;
} NspDirEntry;

/* ================= 轻量路径探测 =================
   readdir 逐条目过滤用（性能敏感）：只判 hidden/重定向目标/虚拟目录标志，
   不构建最终真实路径、不触发 sandbox 目录创建等副作用。 */

typedef struct NspProbeResult {
    bool valid;               /* false = 模块无法解析，框架视为不过滤 */
    bool hidden;              /* HIDE 命中 → 条目跳过 */
    bool is_redirect_target;  /* 条目是重定向目标 → 跳过（避免与虚拟目录重复） */
    bool is_virtual_ancestor; /* 条目是重定向前缀祖先 */
    bool is_other_app_pkg;    /* 跨应用隔离 */
} NspProbeResult;

/* ================= 模块接口表（模块 → 框架） =================
   所有字段可选，未实现置 NULL；框架只调用模块 caps 声明过的能力。 */

typedef struct NspModuleOps {
    /* ---- 规则能力（对应 NSP_CAP_*）---- */
    /* 路径决策：一次调用返回全部结果。返回 0 成功；负值错误码。 */
    int  (*resolve)(const NspQueryCtx* q, NspResolveResult* out);
    /* 轻量路径探测（readdir 逐条目过滤，性能敏感）：只判 hidden/重定向目标/
       虚拟目录标志，不构建真实路径、不触发 sandbox 目录创建。返回 0 成功。 */
    int  (*probe)(const NspQueryCtx* q, NspProbeResult* out);
    /* readdir 虚拟目录补充：向 out 填充最多 max 个虚拟条目，返回条目数。 */
    int  (*readdir_extra)(const NspQueryCtx* q, const char* sub_path, int user_id,
                          const char* pkg, bool is_root, NspDirEntry* out, int max);

    /* ---- 后端能力（NSP_MODULE_TYPE_BACKEND）---- */
    /* 变量注册：返回模块提供的变量（name=value 字符串数组）。 */
    int  (*get_vars)(const char*** names, const char*** values, int* count);

    /* ---- 通用 ---- */
    /* 配置热重载通知（框架检测到配置变更时调用，模块自行决定是否重建索引）。 */
    int  (*reload)(void);
    /* uid → 包名解析（框架日志等场景使用；返回 0 成功，pkg 最多 127 字节） */
    int  (*get_pkg)(uid_t uid, pid_t tid, char* pkg_out, size_t pkg_size);
} NspModuleOps;

/* ================= 模块信息（静态导出） ================= */

typedef struct NspModuleInfo {
    uint32_t magic;           /* 必须 == NSP_MODULE_MAGIC */
    uint32_t abi_version;     /* 必须 == NSP_MODULE_ABI_VERSION */
    uint32_t type;            /* NspModuleType */
    uint32_t caps;            /* 能力位图 */
    const char* name;         /* 模块名（[a-z0-9_-]） */
    const char* version;      /* 模块自身版本字符串 */
    int  (*init)(const NspFrameworkApi* api);   /* 初始化，成功返回 0 */
    void (*exit)(void);                          /* 清理（可为 NULL） */
    const NspModuleOps* ops;  /* 接口表（可为 NULL，须与 caps 一致） */
} NspModuleInfo;

/* 模块必须导出的符号名 */
#define NSP_MODULE_INFO_SYMBOL "nsp_module_info"

#endif /* NSP_MODULE_H */
