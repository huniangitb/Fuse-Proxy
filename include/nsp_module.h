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
 *   1. **模块只做后端**：V4 起模块的唯一形态是「存储后端提供者」（如 FTP），
 *      即 `NspModuleOps` 里的 `backend_*` 方法。路径决策（REDIRECT/SANDBOX/
 *      HIDE/ALLOW/RO）、uid→包名、MONITOR 开关都是框架能力，见
 *      `src/daemon/fw_rules.c` / `fw_pkg.c` / `fw_config.c`——放进模块会让
 *      「模块缺席 ⇒ 规则与监控一起失效」。
 *   2. 因此模块开发面收窄到「实现几个 backend_* 方法 + 导出 nsp_module_info」：
 *      没有能力位图、没有模块类型、没有规则决策结构要填。
 *   3. 模块通过「框架服务表」取启动参数、订阅配置；日志与路径工具经公开运行时
 *      导出表解析。接口表与框架表按 ABI 版本演进，版本不匹配即拒绝加载。
 *
 * 模块约定：
 *   - 模块为共享库（.so），放在 MODULES_DIR/<模块名>/<模块名>.so
 *   - 每个模块必须导出静态符号 nsp_module_info（NspModuleInfo 结构）
 *   - 加载流程：dlopen → dlsym(nsp_module_info) → 魔数/ABI 校验 →
 *     调 init(api) → 注册完成；卸载流程：调 exit → dlclose
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
 * 规则类型（HIDE/RO/REDIRECT/ALLOW/SANDBOX/MONITOR/GLOBAL_INJECT/
 * SKIP_SYSTEM_APPS）由框架内建引擎解释，与模块无关；模块自带 <模块名>.rules
 * 只是让 rule_server 认得该模块自己新增的规则类型（如 FTP），便于前端编辑。
 */
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h> /* struct stat（后端 getattr，系统类型与 fuse 无关） */
#include <limits.h>
#include <linux/limits.h> /* Linux/Android ABI 的 PATH_MAX，不依赖 libc 特性宏。 */
#include "nsp_cfg_view.h" /* 配置扁平视图（框架下发规则/变量给模块） */

/* ================= ABI 版本与魔数 ================= */

/* V4 是**模块面收窄**的不兼容变更：规则决策引擎搬进框架
   （`src/daemon/fw_rules.c`），于是
     - `NspModuleOps` 只剩 `backend_*`（删 `resolve`/`probe`/`readdir_extra`/
       `get_pkg`），`NspModuleInfo` 删 `type`/`caps`（后端口径由 ops 自身决定），
       `NspFrameworkApi` 删 `get_flags`（唯一消费者是规则模块）；
     - `NspQueryCtx`/`NspPathDecision`/`NspProbeResult`/`NspVirtualKind`
       不再是 ABI——它们随引擎住进 `src/daemon/fw_rules.h`。跨 ABI 只剩
       `NspDirEntry`（后端 readdir 回传条目用）。
   加载器按 `abi_version` 精确匹配，**V1/V2/V3 模块一律拒载**，须按本头重编译。
   本次未发布过旧 V4 头，故版本号仍为 4（详见 docs/modules.md §3/§6.5）。
   V5 是**截断收敛**的不兼容变更（开发阶段，旧版本无存量负担）：
     - `backend_readdir` 追加 `offset` 分页参数：框架按页拉取，大目录不再
       顶满 512 即静默丢尾（V4 的整批上限）；V4 模块（无 offset）一律拒载；
     - `NspDirEntry.name` 保持 256（内核 NAME_MAX=255 的硬约束，不是框架
       截断）：超长名后端必须整条跳过，禁止截断安装（截断会制造重名混淆）。
   详见 docs/modules.md §3/§6.5。 */
#define NSP_MODULE_ABI_VERSION 5u
#define NSP_MODULE_MAGIC       0x4E53504Du /* "NSPM" */

/* ================= 模块形态 =================
   V4 起只有一种模块：**后端存储提供者**。规则决策（REDIRECT/SANDBOX/HIDE/
   ALLOW/RO）已由框架内建引擎承担（`src/daemon/fw_rules.c`），故不再有"规则
   模块"这一形态，`NspModuleInfo` 的 `type`/`caps` 一并取消——模块是什么由它的
   `ops` 决定（声明了 `backend_match` 即后端模块），不再需要两处声明保持一致。 */

/* ================= 框架服务表（框架 → 模块） =================
   模块 init 时收到该表，仅通过它使用框架设施。
   版本化：新增字段追加在结构尾部，旧模块按 api_version 决定是否访问。 */

typedef struct NspFrameworkApi {
    uint32_t api_version;                /* 当前 NSP_FRAMEWORK_API_VERSION */
    const char* (*get_rules_path)(void); /* 规则配置文件路径（--rules= 参数） */

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

/* ================= readdir 虚拟目录补充 =================
   模块填充条目数组，框架负责 filler 与去重（不依赖 fuse 类型，便于解耦）。
   name 上限 256（含 NUL，即最多 255 字节名——内核 NAME_MAX 的硬约束）：
   超长名后端必须整条跳过，禁止截断安装（同前缀长名截断后会互相覆盖，
   且与 getattr 的 stat 缓存 key 错位）。 */

typedef struct NspDirEntry {
    char name[256];
    bool is_dir;
} NspDirEntry;

/* ================= 模块接口表（模块 → 框架） =================
   所有字段可选，未实现置 NULL；框架只调用模块 caps 声明过的能力。 */

typedef struct NspModuleOps {
    /* 后端 I/O：路径命中（backend_match 返回 1）时，框架不再操作本地文件
       系统，改调模块方法。path 为框架解析后的真实路径（如 /mnt/nsp_ftp/云盘/xxx），
       模块自行剥离前缀映射到目标存储。句柄 h 由模块分配/释放（uint64_t），框架
       透传。返回 0 成功，负值 errno 风格（业务失败不触发熔断，见 modules.md §5）。
       声明了 backend_match 即视为后端模块——V4 起没有别的模块形态。 */
    int (*backend_match)(const char* path); /* 1=管理该路径 0=否 */
    /* 成功时 st 必须含有效类型位（S_IFDIR/S_IFREG 等 S_IFMT 成员）：缺失时框架
       判契约违规（EIO + 熔断计数），不把无类型 stat 送进内核（目录会被识别成
       文件）。ino 为 0 时框架按路径派生兜底；uid/gid 全 0 时继承存储根属主。 */
    int (*backend_getattr)(const char* path, struct stat* st);
    /* 分页列目录：跳过前 offset 条，填充至多 max 条；返回本次填充数，
       0 表到末尾，负值 errno 风格。框架按 offset 累加逐页拉取直到短页/0 页，
       故大目录无条数上限（V4 的 512 整批上限已删除）；offset 超出末尾返回 0。
       max<=0 时返回 0（框架恒传正数页大小）。后端应对 offset 做钳制，
       不得因超大 offset 崩溃（返回 0 即可）。 */
    int (*backend_readdir)(const char* path, NspDirEntry* entries, int max, uint64_t offset);
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
} NspModuleOps;

/* ================= 模块信息（静态导出） ================= */

typedef struct NspModuleInfo {
    uint32_t magic;                          /* 必须 == NSP_MODULE_MAGIC */
    uint32_t abi_version;                    /* 必须 == NSP_MODULE_ABI_VERSION */
    const char* name;                        /* 模块名（[a-z0-9_-]） */
    const char* version;                     /* 模块自身版本字符串 */
    int (*init)(const NspFrameworkApi* api); /* 初始化，成功返回 0 */
    void (*exit)(void);                      /* 清理（可为 NULL） */
    const NspModuleOps* ops;                 /* 后端方法表（可为 NULL = 无后端能力） */
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
