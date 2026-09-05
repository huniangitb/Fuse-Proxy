#ifndef MODULE_LOADER_H
#define MODULE_LOADER_H
/*
 * module_loader.h — 框架侧（fuse_daemon）热插拔模块加载器接口
 *
 * 职责：
 *   - 扫描 MODULES_DIR/<模块名>/<模块名>.so，dlopen 加载并校验 ABI
 *   - 维护注册表（能力位 → 模块链），供分派器按能力调用
 *   - inotify 监听模块目录实现热插拔（放入=加载，删除=卸载，覆盖=重载）
 *   - 提供规则决策 / readdir 补充的聚合分派入口（无模块时快速路径）
 */
#include <stdbool.h>
#include <stdint.h>
#include "nsp_module.h"

#define MAX_MODULES 16

/* 分派返回值 */
#define NSP_DISPATCH_NONE 0   /* 无规则模块注册 / 无命中 → 框架回退默认路径 */
#define NSP_DISPATCH_OK   1   /* 已填充决策结果 */

/* 初始化：mkdir 模块目录 + 全量扫描 + 启动热插拔监控线程。
   rules_path 为框架规则配置路径（--rules=），modules_dir 为模块目录
   （NULL 用默认 MODULES_DIR，可经 --modules-dir 覆盖），flags 为启动标志
   （NSP_FLAG_*），均经 NspFrameworkApi 提供给模块。 */
int module_system_init(const char* rules_path, const char* modules_dir, uint32_t flags);
/* 卸载全部模块并停止监控 */
void module_system_shutdown(void);

/* 规则决策分派：遍历注册了规则能力（REDIRECT/SANDBOX/HIDE/ALLOW/RO）的模块，
   聚合填充 out。返回 NSP_DISPATCH_OK / NSP_DISPATCH_NONE。 */
int module_dispatch_resolve(const NspQueryCtx* q, NspResolveResult* out);

/* 轻量路径探测分派：readdir 逐条目过滤用（只判 hidden/redirect_target 等，
   无模块时返回 NSP_DISPATCH_NONE）。 */
int module_dispatch_probe(const NspQueryCtx* q, NspProbeResult* out);

/* readdir 批量过滤：循环外取一次模块读锁（module_probe_lock），循环内复用
   locked 版本逐条目探测，结束时 unlock——大目录省 O(n) 次 rwlock 往返。
   module_probe_lock 返回 0 成功（调用方须配对 unlock）；-1 = 无规则模块，
   调用方可跳过探测（不须 unlock）。 */
int module_probe_lock(void);
void module_probe_unlock(void);
int module_dispatch_probe_locked(const NspQueryCtx* q, NspProbeResult* out);

/* readdir 虚拟目录补充：遍历声明 READDIR_EXTRA 的模块合并条目，返回总条目数 */
int module_dispatch_readdir(const NspQueryCtx* q, const char* sub_path, int user_id,
                            const char* pkg, bool is_root, NspDirEntry* out, int max);

/* uid → 包名解析（框架日志用）：遍历声明 get_pkg 的模块，第一个成功返回 0 */
int module_dispatch_get_pkg(uid_t uid, pid_t tid, char* pkg_out, size_t pkg_size);

/* 已加载模块快照（供 IPC LIST_MODULES）：填充 names，返回数量 */
int module_snapshot(char names[][64], int max);

/* 模块健康快照（Phase 1c：前端模块列表展示健康度/ban 原因）。
   填充 info（动态数组，调用方 free），返回数量；含非活跃槽位的
   banned 模块（规则已失效但仍需展示 ban 状态），active 标志区分。 */
typedef struct {
    char name[64];
    char version[32];       /* 模块自述版本字符串（NspModuleInfo.version） */
    uint32_t caps;
    bool active;
    unsigned err_count;     /* 当前滑动窗口内错误数 */
    unsigned err_total;     /* 本加载周期累计错误数 */
    bool banned;
    char ban_reason[96];
    time_t last_err_time;
} NspModuleHealth;
int module_health_snapshot(NspModuleHealth** info_out);

/* 是否有任何活跃模块 */
bool module_any_loaded(void);

/* 槽位模块名查询（module_guard 日志用；无锁读，槽位无效返回 "slotN"） */
const char* module_slot_name(int slot);

/* 模块置毒（崩溃恢复/熔断触发的强制卸载）：槽位快照置空（规则立即失效）
   → 等在途引用归零 → dlclose → 落盘 ban 记录（同哈希 .so 不再重载）。
   幂等；由 module_guard 在确认故障后调用。0 成功，-1 槽位无效。 */
int module_fault_poison(int slot, const char* reason);

/* 是否有活跃后端 I/O 模块（快速路径：无后端时框架直接本地文件系统，零开销） */
bool module_backend_active(void);

/* 后端 I/O 分派：path（框架解析后的真实路径）命中 BACKEND+BACKEND_IO 模块
   （backend_match==1）时返回其 ops，否则 -1。框架 vfs 回调据此改调模块方法
   完成文件操作（模块只提供方法，执行仍由框架 FUSE 回调驱动）。 */
int module_backend_lookup(const char* path, const NspModuleOps** ops_out);

/* 后端查找变体：额外输出命中模块的槽位索引（open/create 绑定 fh 用，
   fh 高位编码槽位后，后续 read/write 经 module_backend_acquire_slot 免
   路径解析/线性扫描/backend_match 前缀比较）。返回 0 且 *ops_out 有效
   （调用方须在 backend_* 完成后 module_backend_put）。 */
int module_backend_lookup_slot(const char* path, int* slot_out, const NspModuleOps** ops_out);

/* 释放后端 ops 在途引用（与 module_backend_lookup / module_backend_lookup_slot
   配对；调用方在 backend_* 方法完成后调用，防止热卸载 dlclose 造成函数指针悬垂） */
void module_backend_put(const NspModuleOps* ops);

/* 槽位快速分派（open 绑定槽位后 read/write/flush/release/fsync 热路径用）：
   无锁读原子槽位快照 + 在途引用，等价 module_backend_lookup 的引用语义但
   免路径解析与线性扫描。返回 0 且 *ops_out 有效（配对 module_backend_release_slot），
   -1 = 槽位无效 / 模块已卸载。热卸载安全性：unload 先原子置空槽位快照再等待
   引用归零，acquire 二次确认快照未变，保证不会在 dlclose 后调用函数指针。 */
int module_backend_acquire_slot(int slot, const NspModuleOps** ops_out);
void module_backend_release_slot(int slot);

/* ops 指针 → 槽位索引反查（module_guard 围栏上报用；快照匹配则返回槽位号，
   否则 -1。无锁原子读，O(MAX_MODULES)——仅日志/上报路径调用，不在热路径） */
int module_ops_slot(const NspModuleOps* ops);

#endif /* MODULE_LOADER_H */
