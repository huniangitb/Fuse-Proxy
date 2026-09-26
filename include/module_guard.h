#ifndef MODULE_GUARD_H
#define MODULE_GUARD_H
/*
 * module_guard.h — 模块调用守卫（Phase 1b：校验 + 熔断）
 *
 * 职责：
 *   1. 输出完整性校验：模块返回的结构体字符串字段 NUL 终止检查、
 *      数值字段值域检查、结构体前后 canary（防整块越界写）
 *   2. 错误记账 + 熔断器：每模块滑动窗口（默认 10s 内 5 次错误）
 *      触发 → module_fault_poison（槽位置空 = 规则自动失效 + ban 落盘）
 *   3. 崩溃上报（围栏 NSP_FENCE_FAULT 路径）：单次崩溃即置毒
 *      （模块内存状态不可信，无需计数）
 *   4. MOD_ERR 结构化日志（限流：窗口内前 5 条明细 + 每 100 条汇总）
 *
 * 日志格式（log_ctl search-sys --level 2 MOD_ERR <模块名> 可查）：
 *   [MOD_ERR] module=<名> op=<op> rc=<模块返回码> path=<路径> detail=<原因>
 */
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "nsp_module.h"

/* ================= 输出/入参校验 =================
   规则决策不再跨 ABI（引擎已内建，见 src/daemon/fw_rules.h），故决策结构的
   canary 守卫与值域校验随之删除；跨 ABI 的字符串只剩后端 readdir 的条目名。 */

/* ================= 输出/入参校验 ================= */
/* 字符串 NUL 终止检查：s 前 len 字节内存在 NUL = 合法 */
bool nsp_guard_str_ok(const char* s, size_t len);
/* 后端 readdir 单条目校验：name NUL 终止 */
bool nsp_guard_dir_entry_ok(const NspDirEntry* e);

/* ================= 错误上报 / 熔断 ================= */
/* 初始化（module_system_init 调用）：读取环境变量覆盖默认阈值——
   NSP_GUARD_WINDOW_SEC（默认 10）、NSP_GUARD_ERR_MAX（默认 5） */
void module_guard_init(void);
/* 复位某槽位记账（模块卸载/热重载 commit 时调用） */
void module_guard_reset(int slot);

/* 模块错误上报（逻辑错误路径：rc 异常/输出校验失败/canary 破坏）。
   限流 MOD_ERR 日志 + 滑动窗口计数；窗口内达阈值 → 熔断置毒
   （module_fault_poison：规则立即失效 + ban 落盘）。幂等安全。 */
void module_guard_error(int slot, const char* op, int rc, const char* path, const char* detail);
/* 模块崩溃上报（围栏恢复路径）：单次即置毒（不计数）+ 高危日志 */
void module_guard_fault(int slot, const char* op, const char* path);

/* 健康查询（Phase 1c 快照接口用）：填充当前窗口错误数/累计错误数/
   最近错误时刻。slot 无效时全 0 返回。 */
void module_guard_health(int slot, unsigned* err_count, unsigned* err_total, time_t* last_err_time);

#endif /* MODULE_GUARD_H */
