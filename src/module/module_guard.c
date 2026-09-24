#define _GNU_SOURCE
/*
 * module_guard.c — 模块调用守卫实现（校验 + 熔断 + MOD_ERR 日志）
 *
 * 运行上下文：FUSE worker 线程（热路径）与 monitor 线程。
 * 热路径约束：
 *   - 无锁：熔断计数用每槽位原子（_Atomic）；模块名查询经
 *     module_slot_name（loader 读锁，仅日志路径）；
 *   - 无每请求堆分配（detail 用调用方栈缓冲或固定字符串）；
 *   - 限流：窗口内前 GUARD_LOG_BURST 条明细全打，之后每
 *     GUARD_LOG_THROTTLE 条打 1 条汇总，防止坏模块错误风暴淹没日志。
 *
 * 死锁约束（重要）：module_guard_error/fault 会经 module_fault_poison
 * 取 g_module_lock 写锁——调用方不得持有 g_module_lock（任何锁）时
 * 调用本文件函数。loader 的 readdir_extra/get_pkg 路径在释放读锁后
 * 才上报。
 */
#include "module_guard.h"
#include "module_loader.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>

/* ================= 熔断参数（env 可覆盖，默认 10s/5 次） ================= */
static int g_guard_window_sec = 10;
static int g_guard_err_max = 5;

/* 限流参数 */
#define GUARD_LOG_BURST    5   /* 窗口内前 N 条明细全打 */
#define GUARD_LOG_THROTTLE 100 /* 之后每 N 条打 1 条汇总 */

typedef struct {
    _Atomic unsigned err_count;   /* 当前滑动窗口内计数 */
    _Atomic time_t window_start;  /* 窗口起点（0=无活动窗口） */
    _Atomic unsigned total_count; /* 本加载周期累计（限流驱动 + 健康快照） */
    char last_op[32];             /* 最近错误 op（展示用；撕裂可接受） */
    _Atomic time_t last_err_time; /* 最近错误时刻（多线程读写，需原子访问） */
} GuardSlot;

static GuardSlot g_guard[MAX_MODULES];

void module_guard_init(void) {
    const char* ws = getenv("NSP_GUARD_WINDOW_SEC");
    const char* em = getenv("NSP_GUARD_ERR_MAX");
    if (ws && atoi(ws) > 0) g_guard_window_sec = atoi(ws);
    if (em && atoi(em) > 0) g_guard_err_max = atoi(em);
    for (int i = 0; i < MAX_MODULES; i++) module_guard_reset(i);
    LOG_DBG(
        "module_guard: 熔断参数 window=%ds max=%d (env: NSP_GUARD_WINDOW_SEC/NSP_GUARD_ERR_MAX)",
        g_guard_window_sec, g_guard_err_max);
}

void module_guard_reset(int slot) {
    if (slot < 0 || slot >= MAX_MODULES) return;
    GuardSlot* g = &g_guard[slot];
    atomic_store_explicit(&g->err_count, 0, memory_order_relaxed);
    atomic_store_explicit(&g->window_start, 0, memory_order_relaxed);
    atomic_store_explicit(&g->total_count, 0, memory_order_relaxed);
    g->last_op[0] = '\0';
    atomic_store_explicit(&g->last_err_time, 0, memory_order_relaxed);
}

/* ================= 输出/入参校验 ================= */

bool nsp_guard_str_ok(const char* s, size_t len) {
    if (!s) return false;
    for (size_t i = 0; i < len; i++)
        if (s[i] == '\0') return true;
    return false;
}

bool nsp_guard_path_ok(const char* p) {
    if (!p) return false;
    size_t l = strlen(p);
    return l > 0 && l < PATH_MAX;
}

int nsp_guard_validate_resolve(const NspResolveResult* r, char* detail, size_t dsz) {
    if (!r) return 8;
    /* 字符串字段 NUL 终止检查（模块写坏终止符 = 野指针/越界写指纹） */
    if (!nsp_guard_str_ok(r->sub_path, PATH_MAX)) {
        if (detail) snprintf(detail, dsz, "sub_path 未终止");
        return 1;
    }
    if (!nsp_guard_str_ok(r->pkg, 128)) {
        if (detail) snprintf(detail, dsz, "pkg 未终止");
        return 2;
    }
    if (!nsp_guard_str_ok(r->real_path, PATH_MAX)) {
        if (detail) snprintf(detail, dsz, "real_path 未终止");
        return 5;
    }
    if (r->user_id < -1 || r->user_id > 0x7FFFFFFF) {
        if (detail) snprintf(detail, dsz, "user_id 值域非法");
        return 7;
    }
    return 0;
}

bool nsp_guard_dir_entry_ok(const NspDirEntry* e) {
    if (!e) return false;
    return nsp_guard_str_ok(e->name, sizeof e->name);
}

/* ================= 高危事件落盘（module_errors.log） =================
 * 仅低频高危事件（熔断/崩溃）无条件追加，仿 persistent_io.log 模式：
 * log_monitor/UDS 链路中断时仍可事后查询。普通 MOD_ERR 只进 SYS 环。 */
static pthread_mutex_t g_persist_mu = PTHREAD_MUTEX_INITIALIZER;
static void persist_module_error(const char* mod_name, const char* kind, const char* reason) {
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/module_errors.log", LOG_DIR);
    mkdir_recursive(LOG_DIR);
    pthread_mutex_lock(&g_persist_mu);
    FILE* fp = fopen(path, "a");
    if (fp) {
        time_t now = time(NULL);
        char ts[32] = {0};
        struct tm tmv;
        localtime_r(&now, &tmv);
        strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmv);
        fprintf(fp, "%s [MOD] module=%s kind=%s reason=%s\n", ts, mod_name ? mod_name : "?",
                kind ? kind : "?", reason ? reason : "?");
        fclose(fp);
    }
    pthread_mutex_unlock(&g_persist_mu);
}

/* ================= 错误上报 / 熔断 ================= */

/* MOD_ERR 日志限流：total（本加载周期累计）驱动——
 * total <= BURST：明细全打；total % THROTTLE == 0：打 1 条汇总；其余抑制。 */
static void guard_log_mod_err(const char* mod_name, const char* op, int rc, const char* path,
                              const char* detail, unsigned total) {
    if (total <= GUARD_LOG_BURST) {
        LOG_WRN("[MOD_ERR] module=%s op=%s rc=%d path=%s detail=%s", mod_name, op, rc,
                path ? path : "(null)", detail ? detail : "(null)");
        return;
    }
    if (total % GUARD_LOG_THROTTLE == 0) {
        LOG_WRN(
            "[MOD_ERR] module=%s op=%s rc=%d path=%s detail=已抑制 %u 条同类错误(每%d条汇总),熔断阈值 %d 次/%ds",
            mod_name, op, rc, path ? path : "(null)", total - GUARD_LOG_BURST, GUARD_LOG_THROTTLE,
            g_guard_err_max, g_guard_window_sec);
    }
}

void module_guard_error(int slot, const char* op, int rc, const char* path, const char* detail) {
    if (slot < 0 || slot >= MAX_MODULES) return;
    GuardSlot* g = &g_guard[slot];
    time_t now = time(NULL);
    unsigned total = atomic_fetch_add_explicit(&g->total_count, 1, memory_order_relaxed) + 1;

    /* 滑动窗口：窗口过期则重置计数。
       TOCTOU 修复：用 CAS 更新窗口起点，减少并发线程同时重置时的计数丢失。
       CAS 成功者负责重置计数；CAS 失败者视为新窗口已就绪，直接累加。 */
    time_t ws = atomic_load_explicit(&g->window_start, memory_order_relaxed);
    unsigned count;
    if (ws == 0 || (now - ws) >= g_guard_window_sec) {
        if (atomic_compare_exchange_strong_explicit(&g->window_start, &ws, now,
                                                    memory_order_relaxed, memory_order_relaxed)) {
            /* 本线程赢得 CAS：重置计数 */
            atomic_store_explicit(&g->err_count, 1, memory_order_relaxed);
            count = 1;
        } else {
            /* CAS 失败：另一线程已重置窗口，直接累加 */
            count = atomic_fetch_add_explicit(&g->err_count, 1, memory_order_relaxed) + 1;
        }
    } else {
        count = atomic_fetch_add_explicit(&g->err_count, 1, memory_order_relaxed) + 1;
    }
    atomic_store_explicit(&g->last_err_time, now, memory_order_relaxed);
    if (op && op[0]) {
        strncpy(g->last_op, op, sizeof g->last_op - 1);
        g->last_op[sizeof g->last_op - 1] = '\0';
    }

    char mod_name[64];
    snprintf(mod_name, sizeof mod_name, "%s", module_slot_name(slot));
    guard_log_mod_err(mod_name, op ? op : "(null)", rc, path, detail, total);

    if (count >= (unsigned)g_guard_err_max) {
        /* 熔断：滑动窗口内错误达阈值 → 置毒卸载（规则自动失效 + ban 落盘） */
        char reason[96];
        snprintf(reason, sizeof reason, "circuit:%u errs in %ds(op=%s)", count, g_guard_window_sec,
                 g->last_op[0] ? g->last_op : "?");
        LOG_ERR("[MOD_ERR] module=%s op=%s rc=%d path=%s detail=熔断触发(%s),立即卸载:规则全部失效",
                mod_name, g->last_op[0] ? g->last_op : (op ? op : "?"), rc, path ? path : "(null)",
                reason);
        persist_module_error(mod_name, "circuit_break", reason);
        module_fault_poison(slot, reason);
        atomic_store_explicit(&g->err_count, 0, memory_order_relaxed);
    }
}

void module_guard_health(int slot, unsigned* err_count, unsigned* err_total,
                         time_t* last_err_time) {
    if (err_count) *err_count = 0;
    if (err_total) *err_total = 0;
    if (last_err_time) *last_err_time = 0;
    if (slot < 0 || slot >= MAX_MODULES) return;
    GuardSlot* g = &g_guard[slot];
    if (err_count) *err_count = atomic_load_explicit(&g->err_count, memory_order_relaxed);
    if (err_total) *err_total = atomic_load_explicit(&g->total_count, memory_order_relaxed);
    if (last_err_time)
        *last_err_time = atomic_load_explicit(&g->last_err_time, memory_order_relaxed);
}

void module_guard_fault(int slot, const char* op, const char* path) {
    if (slot < 0 || slot >= MAX_MODULES) return;
    GuardSlot* g = &g_guard[slot];
    atomic_fetch_add_explicit(&g->total_count, 1, memory_order_relaxed);
    atomic_store_explicit(&g->last_err_time, time(NULL), memory_order_relaxed);
    if (op && op[0]) {
        strncpy(g->last_op, op, sizeof g->last_op - 1);
        g->last_op[sizeof g->last_op - 1] = '\0';
    }
    char mod_name[64];
    snprintf(mod_name, sizeof mod_name, "%s", module_slot_name(slot));

    char reason[96];
    snprintf(reason, sizeof reason, "crash:op=%s 崩溃被围栏恢复", op ? op : "?");
    LOG_ERR(
        "[MOD_ERR] module=%s op=%s rc=-EIO path=%s detail=模块崩溃(SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT)被调用围栏恢复,立即卸载:规则全部失效",
        mod_name, op ? op : "(null)", path ? path : "(null)");
    persist_module_error(mod_name, "crash", reason);
    module_fault_poison(slot, reason);
}
