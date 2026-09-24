#ifndef FAULT_FENCE_H
#define FAULT_FENCE_H
/*
 * fault_fence.h — 模块调用围栏（框架层崩溃隔离）
 *
 * 背景：热插拔模块 dlopen 在同一地址空间，模块内的野指针/栈破坏等
 * 严重错误无法被 C 语言"预防"。本围栏把"模块只在框架调它的窗口期
 * 作恶"这一事实转化为防御手段：
 *
 *   1. 框架把全部模块调用点（init/exit/resolve/probe/
 *      readdir_extra/get_pkg/backend_*）收口到 nsp_fence_*()：
 *         登记"本线程正在调用模块 slot 的 op"（TLS）
 *         → sigsetjmp 布防 → 调 ops → 注销。
 *   2. 崩溃信号处理器（crash_dump 改造，fence 处理器包在原处理器外层）
 *      发现肇事线程处于模块调用窗口 → 不 re-raise，siglongjmp 回该
 *      线程的围栏——daemon 存活；围栏返回 NSP_FENCE_FAULT，由
 *      module_guard 置毒卸载该模块（规则自动失效）并落盘 ban。
 *   3. 归因失败（如延迟的堆损坏在框架自己代码里爆发）→ 委托原处理器
 *      （完整 dump + re-raise），维持现有 crash_dump/injector 兜底链。
 *
 * 安全性前提（框架不变量，review 时须检查）：
 *   - 跨模块调用不得持有任何框架锁：longjmp 跳过解锁路径会死锁。
 *     现有 S2 无锁分派（槽位原子快照 + 在途引用）已满足——引用计数
 *     的 release 由围栏返回路径显式补做（见 module_guard）；
 *     module_dispatch_readdir/get_pkg 原持 g_module_lock 读锁，
 *     接入围栏时把锁的语义改为"仅用于枚举槽位快照，ops 调用不持锁"。
 *   - sigsetjmp/siglongjmp 只影响肇事线程（TLS），其余 FUSE worker
 *     线程不受影响。
 *   - 处理器运行于 init 时设置的全局 sigaltstack（256KB）：模块踩坏
 *     自身栈帧后处理器栈仍可用；longjmp 目标 sigjmp_buf 在 TLS 堆块
 *     中，不依赖被踩的栈。
 *
 * 返回值约定：nsp_fence_* 正常时**透传模块返回码**（0 成功/负值错误，
 * 与 NspModuleOps 回调约定一致）；围栏自身异常返回 NSP_FENCE_FAULT /
 * NSP_FENCE_BADFN（取值见下方定义，远离模块合法返回值域）。调用方判定：
 *   rc == NSP_FENCE_FAULT → 崩溃恢复，上报 nsp_module_fault_report；
 *   rc == NSP_FENCE_BADFN → 函数指针缺失（防御，按未实现处理）；
 *   其余 → 按模块返回码语义处理。
 */
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include "nsp_module.h"

/* 围栏调用返回值（仅围栏自身产生，与模块返回码空间严格区分）。
   ⚠ 哨兵值必须远离模块的合法返回值域：backend_match 成功返回 1，
   readdir_extra / backend_readdir 成功返回**条目数**（≥1，上界为调用方
   传入的 max，数千量级）。历史上哨兵取小正数 1/2，与这两类成功返回
   碰撞——每次 FTP 路径命中都被误判为"崩溃被围栏恢复"，既错误累积熔断
   计数（终致置毒 ban + 卸载模块），又使 `rc == 1` 的命中分支永不可达
   （后端形同未注册）。故取远高于任何计数/标志上界的正值，同时保持
   "正数族"以维持既有 `rc < 0 ? rc : -EIO` 泄漏路径的降级行为。 */
#define NSP_FENCE_OK    0               /* = 模块返回码 0（成功）；透传 */
#define NSP_FENCE_FAULT (1 << 24)       /* 模块崩溃被围栏恢复：out 参数视为已破坏 */
#define NSP_FENCE_BADFN ((1 << 24) + 1) /* 函数指针为 NULL（防御）：未调用 */

/* 初始化：设置全局 sigaltstack，安装归因处理器（包在 install_crash_handlers
   原处理器外层）。须在 install_crash_handlers() 之前调用——原处理器
   经 fault_fence_set_orig_handler 注入，归因失败时委托其完整 dump+死亡。 */
void fault_fence_init(void);
/* 重装 fence 处理器为活动处理器：须在 libfuse fuse_set_signal_handlers
   **之后**调用——libfuse 会接管 SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT
   （fail_sigs[]），先装 fence 会被覆盖而失效（模块崩溃将带崩框架）。
   SIGINT/SIGTERM 不在故障信号集内，保持 libfuse 安装。幂等可重复调用。 */
void fault_fence_rearm(void);
/* crash_dump 注册原处理器后调用（签名同 crash_handler） */
typedef void (*NspOrigCrashHandler)(int sig, siginfo_t* info, void* uctx);
void fault_fence_set_orig_handler(NspOrigCrashHandler h);

/* 围栏槽位表容量：MAX_MODULES 个模块槽位（索引 0..MAX_MODULES-1，与 loader
   槽位一一对应）+ 1 个未绑定槽位（见下）。 */
#define NSP_FENCE_MAX_SLOTS 17
/* 未绑定槽位索引：供"尚无正式模块槽位"的过渡期调用归因——init 试探期与
   commit 失败（注册表满）时的 exit。与任何模块槽位不重叠，故不会覆盖在册
   模块的归因信息；过渡期调用串行（仅 monitor 线程），单槽位足够。
   fault_fence.c 以 _Static_assert 与 MAX_MODULES 对齐。 */
#define NSP_FENCE_UNBOUND_SLOT 16

/* 模块加载/卸载时更新静态注册表（信号安全），供崩溃恢复日志与
   归因查询输出模块名。dl_handle 保留供映射段判定扩展。 */
void fault_fence_register_slot(int slot, const char* name, void* dl_handle);
void fault_fence_unregister_slot(int slot);

/* 崩溃处理器钩子（fence 处理器内调用）：
 * 返回 true = 已 siglongjmp（调用方不可达）；
 * 返回 false = 归因失败（不在模块调用窗口），调用方委托原处理器。 */
bool fault_fence_handle_fault(void);

/* 崩溃归因查询（信号安全：仅读 TLS 与静态注册表）。
 * 处理器线程 == 肇事线程（Linux 信号投递到肇事线程），读本线程 TLS。
 * slot 输出 -1 = 不在窗口。name 指向 loader 静态槽位数组（恒有效）。 */
void fault_fence_attribution(int* slot_out, const char** op_out, const char** name_out);

/* ================= 围栏调用（签名与 NspModuleOps 回调一一对应） ========= */
/* 模板：登记窗口 → sigsetjmp 布防 → fn(...) → 注销。故障恢复后 out 参数
 * 状态未知（模块写了一半）：调用方须视其未初始化，按错误路径处理。
 * 函数指针 NULL 时返回 NSP_FENCE_BADFN（不置窗口）。 */

/* ---- 规则能力 ---- */
int nsp_fence_resolve(int slot, const char* op_name,
                      int (*fn)(const NspQueryCtx*, NspResolveResult*), const NspQueryCtx* q,
                      NspResolveResult* out);
int nsp_fence_probe(int slot, const char* op_name, int (*fn)(const NspQueryCtx*, NspProbeResult*),
                    const NspQueryCtx* q, NspProbeResult* out);
int nsp_fence_readdir_extra(int slot, const char* op_name,
                            int (*fn)(const NspQueryCtx*, const char*, int, const char*, bool,
                                      NspDirEntry*, int),
                            const NspQueryCtx* q, const char* sub_path, int user_id,
                            const char* pkg, bool is_root, NspDirEntry* out, int max);
int nsp_fence_get_pkg(int slot, const char* op_name, int (*fn)(uid_t, pid_t, char*, size_t),
                      uid_t uid, pid_t tid, char* out, size_t sz);

/* ---- 后端能力（NspModuleOps 一一对应） ---- */
int nsp_fence_backend_match(int slot, const char* op_name, int (*fn)(const char*),
                            const char* path);
int nsp_fence_backend_getattr(int slot, const char* op_name, int (*fn)(const char*, struct stat*),
                              const char* path, struct stat* st);
int nsp_fence_backend_readdir(int slot, const char* op_name,
                              int (*fn)(const char*, NspDirEntry*, int), const char* path,
                              NspDirEntry* entries, int max);
int nsp_fence_backend_open(int slot, const char* op_name, int (*fn)(const char*, int, uint64_t*),
                           const char* path, int flags, uint64_t* h);
int nsp_fence_backend_read(int slot, const char* op_name,
                           int (*fn)(uint64_t, char*, size_t, off_t, size_t*), uint64_t h,
                           char* buf, size_t size, off_t off, size_t* got);
int nsp_fence_backend_write(int slot, const char* op_name,
                            int (*fn)(uint64_t, const char*, size_t, off_t, size_t*), uint64_t h,
                            const char* buf, size_t size, off_t off, size_t* wrote);
int nsp_fence_backend_flush(int slot, const char* op_name, int (*fn)(uint64_t), uint64_t h);
int nsp_fence_backend_release(int slot, const char* op_name, int (*fn)(uint64_t), uint64_t h);
int nsp_fence_backend_create(int slot, const char* op_name,
                             int (*fn)(const char*, mode_t, uint64_t*), const char* path,
                             mode_t mode, uint64_t* h);
int nsp_fence_backend_simple(int slot, const char* op_name, int (*fn)(const char*),
                             const char* path);
/* 用于 backend_unlink / backend_rmdir */
int nsp_fence_backend_mkdir(int slot, const char* op_name, int (*fn)(const char*, mode_t),
                            const char* path, mode_t mode);
int nsp_fence_backend_rename(int slot, const char* op_name, int (*fn)(const char*, const char*),
                             const char* from, const char* to);
int nsp_fence_backend_truncate(int slot, const char* op_name, int (*fn)(const char*, off_t),
                               const char* path, off_t size);

/* ---- 生命周期（init/exit 也围栏：崩溃=加载/卸载失败，不崩框架） ---- */
int nsp_fence_init_call(int slot, const char* op_name, int (*fn)(const NspFrameworkApi*),
                        const NspFrameworkApi* api);
/* void 返回型：正常返回 0；崩溃返回 NSP_FENCE_FAULT */
int nsp_fence_exit_call(int slot, const char* op_name, void (*fn)(void));

#endif /* FAULT_FENCE_H */
