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

/* ================= 输出守卫（canary） =================
 * NspPathDecision：调用方（FUSE 回调栈）用本守卫包裹，
 * 前后 canary 被模块整块越界写破坏时 loader 逐模块调用后检测——
 * 破坏精确归因到"刚调用完的模块"。canary 值取黄金比例常量，
 * 与正常数据碰撞概率可忽略。 */
#define NSP_GUARD_CANARY 0x9E3779B97F4A7C15ULL
typedef struct {
    uint64_t front;
    NspPathDecision r;
    uint64_t back;
} NspDecisionGuard;

/* 标量与字符串首字节必须在每次分派、直通回退前重置；回调也会在无命中时
   读取 read_only/is_ftp/虚拟目录性质，不能只重置 valid。 */
static inline void nsp_decision_init(NspPathDecision* r) {
    r->valid = false;
    r->appear_missing = false;
    r->read_only = false;
    r->attr_override = 0;
    r->mode = 0;
    r->uid = 0;
    r->gid = 0;
    r->virtual_kind = NSP_VK_NONE;
    r->real_path[0] = '\0';
    r->is_redirect = false;
    r->is_ftp = false;
}

static inline void nsp_guard_decision_init(NspDecisionGuard* g) {
    g->front = NSP_GUARD_CANARY;
    g->back = NSP_GUARD_CANARY;
    nsp_decision_init(&g->r);
}
/* canary 完整性检查（loader 每次模块调用后调用） */
static inline bool nsp_guard_decision_ok(const NspDecisionGuard* g) {
    return g->front == NSP_GUARD_CANARY && g->back == NSP_GUARD_CANARY;
}

/* ================= 输出/入参校验 ================= */
/* 字符串 NUL 终止检查：s 前 len 字节内存在 NUL = 合法 */
bool nsp_guard_str_ok(const char* s, size_t len);
/* 路径入参检查：非 NULL 且长度 < PATH_MAX */
bool nsp_guard_path_ok(const char* p);
/* decision 输出校验：字符串字段 NUL 终止 + virtual_kind 值域 +
   attr_override 未知位与置位字段值域。返回 0 通过；非 0 = 失败字段编号
   （detail 经 out 输出，可 NULL） */
int nsp_guard_validate_decision(const NspPathDecision* r, char* detail, size_t dsz);
/* readdir_extra 单条目校验：name NUL 终止 */
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
