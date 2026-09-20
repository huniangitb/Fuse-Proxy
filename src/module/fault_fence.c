#define _GNU_SOURCE
/*
 * fault_fence.c — 模块调用围栏实现（崩溃→错误转换）
 *
 * 三支柱：
 *   1. TLS sigsetjmp 围栏：每个 FUSE worker 线程独立一套 sigjmp_buf +
 *      窗口标记（in_window/slot/op）。信号只投递到肇事线程，longjmp
 *      只影响肇事线程，其余 worker 照常处理请求。
 *   2. fence 处理器（包在 crash_dump 原处理器外层）：肇事线程处于
 *      模块调用窗口 → siglongjmp 回围栏（daemon 存活）；否则委托
 *      原处理器（完整 dump + re-raise，维持现有 injector 兜底链）。
 *   3. SA_SIGINFO 处理器运行于 init 时设置的全局 sigaltstack（256KB）：
 *      模块踩坏自身栈帧后处理器栈仍可用；longjmp 目标 sigjmp_buf
 *      在 TLS 堆块中，不依赖被踩栈。
 *
 * 信号安全边界：处理器内只做 volatile 读、静态数组读、siglongjmp；
 * 归因失败委托原处理器后由其完成 dump（原处理器自身信号安全设计不变）。
 */
#include "fault_fence.h"
#include "common.h"
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <errno.h>

#define FENCE_ALTSTACK_SIZE (256 * 1024)

/* ================= 每线程围栏状态（TLS） ================= */

typedef struct {
    sigjmp_buf jb;
    /* volatile：信号处理器（本线程）安全读取；窗口登记只在普通上下文 */
    volatile int in_window;
    volatile int slot;
    volatile const char* op;
} FenceTls;

/* sigjmp_buf 较大（含 ucontext），放堆块避免占用线程栈（模块深递归时
   栈空间宝贵；且栈溢出场景下栈内 jmp_buf 本身不可靠） */
static __thread FenceTls* tls_fence = NULL;

static FenceTls* ensure_fence(void) {
    if (!tls_fence) {
        FenceTls* f = calloc(1, sizeof(FenceTls));
        if (f) {
            f->slot = -1;
            tls_fence = f;
        } /* 必须回写 TLS 指针：
            信号处理器经 tls_fence 定位窗口，漏写则归因恒 NULL，围栏失效 */

        /* P1 修复：sigaltstack 是 per-thread 的（非全局），FUSE worker
           线程不继承主线程的 altstack。此处为每个首次调用围栏的线程
           设置独立 altstack（TLS 静态缓冲），确保模块踩坏线程栈后
           崩溃处理器仍可运行于独立栈上。 */
        static __thread char tls_altstack[FENCE_ALTSTACK_SIZE] __attribute__((aligned(16)));
        stack_t ss = {.ss_sp = tls_altstack, .ss_size = sizeof(tls_altstack), .ss_flags = 0};
        sigaltstack(&ss, NULL);

        return f;
    }
    return tls_fence;
}

/* ================= 静态槽位注册表（信号安全） ================= */

#define FENCE_MAX_SLOTS 16 /* 与 MAX_MODULES 一致（module_loader.h） */

typedef struct {
    char name[64];
    void* handle;
} FenceSlot;

static FenceSlot g_slots[FENCE_MAX_SLOTS];

void fault_fence_register_slot(int slot, const char* name, void* dl_handle) {
    if (slot < 0 || slot >= FENCE_MAX_SLOTS) return;
    memset(&g_slots[slot], 0, sizeof(FenceSlot));
    if (name) strncpy(g_slots[slot].name, name, sizeof(g_slots[slot].name) - 1);
    g_slots[slot].handle = dl_handle;
}
void fault_fence_unregister_slot(int slot) {
    if (slot < 0 || slot >= FENCE_MAX_SLOTS) return;
    g_slots[slot].handle = NULL;
    g_slots[slot].name[0] = '\0';
}

void fault_fence_attribution(int* slot_out, const char** op_out, const char** name_out) {
    FenceTls* f = tls_fence;
    if (!f || !f->in_window) {
        if (slot_out) *slot_out = -1;
        if (op_out) *op_out = NULL;
        if (name_out) *name_out = NULL;
        return;
    }
    int slot = f->slot;
    if (slot_out) *slot_out = slot;
    if (op_out) *op_out = f->op;
    if (name_out)
        *name_out = (slot >= 0 && slot < FENCE_MAX_SLOTS && g_slots[slot].name[0])
                        ? g_slots[slot].name
                        : "(unknown)";
}

/* ================= 崩溃处理器（外层包壳） ================= */

typedef void (*NspOrigCrashHandler)(int, siginfo_t*, void*);
static _Atomic(NspOrigCrashHandler) g_orig_handler = NULL;

void fault_fence_set_orig_handler(NspOrigCrashHandler h) {
    atomic_store_explicit(&g_orig_handler, h, memory_order_release);
}

/* 重入守卫（TLS）：handler 内再次收到崩溃时直接 SIG_DFL 死亡，
   杜绝 handler 内无限递归。longjmp 会跳过 handler 尾部的 in_handler=0，
   故必须在 longjmp 前清零，否则该 worker 线程余生 in_handler 恒 1，
   下次可恢复崩溃也被误判为重入而直接死亡（一次性围栏）。 */
static __thread volatile int in_handler = 0;

bool fault_fence_handle_fault(void) {
    int slot = -1;
    const char *op = NULL, *name = NULL;
    fault_fence_attribution(&slot, &op, &name);
    if (slot < 0 || slot >= FENCE_MAX_SLOTS) return false;
    FenceTls* f = tls_fence;
    if (!f) return false;
    /* longjmp 回本线程围栏。此后 nsp_fence_* 宏返回 NSP_FENCE_FAULT，
       调用方释放槽位在途引用、上报 module_guard 置毒卸载。
       不变量：窗口内不持有任何框架锁（见 fault_fence.h）。 */
    in_handler = 0;
    siglongjmp(f->jb, 1);
    return true; /* 不可达 */
}

static void fence_sigdie(int sig) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(sig, &sa, NULL);
    raise(sig);
}

static void fence_crash_handler(int sig, siginfo_t* info, void* uctx) {
    if (in_handler) {
        fence_sigdie(sig);
    }
    in_handler = 1;
    if (fault_fence_handle_fault()) return; /* 不可达（longjmp，前已清零） */
    in_handler = 0;
    /* 归因失败：委托原处理器（dump + re-raise），行为与改造前一致 */
    NspOrigCrashHandler h = atomic_load_explicit(&g_orig_handler, memory_order_acquire);
    if (h)
        h(sig, info, uctx);
    else {
        fence_sigdie(sig);
    }
    /* 不可达 */
}

/* 安装/重装 fence 处理器为活动处理器（覆盖 libfuse 对故障信号的安装）。
   libfuse fuse_set_signal_handlers 会接管 SIGSEGV/SIGBUS/SIGFPE/SIGILL/
   SIGABRT（fail_sigs[]），必须在其**之后**调用本函数使 fence 位于外层：
   窗口内崩溃 longjmp 恢复；窗口外委托 crash_handler。SIGINT/SIGTERM 不
   在故障信号集内，保持 libfuse 安装（干净 unmount 退出）。 */
void fault_fence_rearm(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fence_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
}

void fault_fence_init(void) {
    /* 全局 sigaltstack：处理器栈独立于各线程栈。模块踩坏自身栈帧后
       处理器仍可运行（sigaction SA_ONSTACK 优先使用 altstack）。 */
    static char alt[FENCE_ALTSTACK_SIZE] __attribute__((aligned(16)));
    stack_t ss;
    ss.ss_sp = alt;
    ss.ss_size = sizeof(alt);
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);
    fault_fence_rearm();
    LOG_DBG("fault_fence: 调用围栏已启用（全局 sigaltstack 256KB，崩溃归因→longjmp 恢复）");
}

/* ================= 围栏调用模板 ================= */

/*
 * NSP_FENCE_WRAP：登记窗口 → 布防 → fn(...) → 注销窗口。
 * 恢复路径（sigsetjmp 返回 1）：out 参数状态未知，调用方按错误处理；
 * 返回 NSP_FENCE_FAULT（崩溃时模块返回码无意义，不透传）。
 * 正常路径透传模块返回码（0/负值）。
 */
#define NSP_FENCE_WRAP(slot, op_name, fn_call_expr)                            \
    do {                                                                       \
        FenceTls* __f = ensure_fence();                                        \
        if (!__f) return NSP_FENCE_BADFN; /* calloc 失败（OOM）：防御性失败 */ \
        __f->slot = (slot);                                                    \
        __f->op = (op_name);                                                   \
        __f->in_window = 1;                                                    \
        if (sigsetjmp(__f->jb, 1) != 0) {                                      \
            __f->in_window = 0;                                                \
            __f->slot = -1;                                                    \
            __f->op = NULL;                                                    \
            return NSP_FENCE_FAULT;                                            \
        }                                                                      \
        int __rc = (fn_call_expr);                                             \
        __f->in_window = 0;                                                    \
        __f->slot = -1;                                                        \
        __f->op = NULL;                                                        \
        return (int)(__rc);                                                    \
    } while (0)

/* void 返回型模板：正常返回 0 */
#define NSP_FENCE_WRAP_VOID(slot, op_name, fn_call_expr) \
    do {                                                 \
        FenceTls* __f = ensure_fence();                  \
        if (!__f) return NSP_FENCE_BADFN;                \
        __f->slot = (slot);                              \
        __f->op = (op_name);                             \
        __f->in_window = 1;                              \
        if (sigsetjmp(__f->jb, 1) != 0) {                \
            __f->in_window = 0;                          \
            __f->slot = -1;                              \
            __f->op = NULL;                              \
            return NSP_FENCE_FAULT;                      \
        }                                                \
        (fn_call_expr);                                  \
        __f->in_window = 0;                              \
        __f->slot = -1;                                  \
        __f->op = NULL;                                  \
        return 0;                                        \
    } while (0)

/* ================= 规则能力 ================= */

int nsp_fence_resolve(int slot, const char* op_name,
                      int (*fn)(const NspQueryCtx*, NspResolveResult*), const NspQueryCtx* q,
                      NspResolveResult* out) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(q, out));
}
int nsp_fence_probe(int slot, const char* op_name, int (*fn)(const NspQueryCtx*, NspProbeResult*),
                    const NspQueryCtx* q, NspProbeResult* out) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(q, out));
}
int nsp_fence_readdir_extra(int slot, const char* op_name,
                            int (*fn)(const NspQueryCtx*, const char*, int, const char*, bool,
                                      NspDirEntry*, int),
                            const NspQueryCtx* q, const char* sub_path, int user_id,
                            const char* pkg, bool is_root, NspDirEntry* out, int max) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(q, sub_path, user_id, pkg, is_root, out, max));
}
int nsp_fence_get_pkg(int slot, const char* op_name, int (*fn)(uid_t, pid_t, char*, size_t),
                      uid_t uid, pid_t tid, char* out, size_t sz) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(uid, tid, out, sz));
}

/* ================= 后端能力 ================= */

int nsp_fence_backend_match(int slot, const char* op_name, int (*fn)(const char*),
                            const char* path) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(path));
}
int nsp_fence_backend_getattr(int slot, const char* op_name, int (*fn)(const char*, struct stat*),
                              const char* path, struct stat* st) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(path, st));
}
int nsp_fence_backend_readdir(int slot, const char* op_name,
                              int (*fn)(const char*, NspDirEntry*, int), const char* path,
                              NspDirEntry* entries, int max) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(path, entries, max));
}
int nsp_fence_backend_open(int slot, const char* op_name, int (*fn)(const char*, int, uint64_t*),
                           const char* path, int flags, uint64_t* h) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(path, flags, h));
}
int nsp_fence_backend_read(int slot, const char* op_name,
                           int (*fn)(uint64_t, char*, size_t, off_t, size_t*), uint64_t h,
                           char* buf, size_t size, off_t off, size_t* got) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(h, buf, size, off, got));
}
int nsp_fence_backend_write(int slot, const char* op_name,
                            int (*fn)(uint64_t, const char*, size_t, off_t, size_t*), uint64_t h,
                            const char* buf, size_t size, off_t off, size_t* wrote) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(h, buf, size, off, wrote));
}
int nsp_fence_backend_flush(int slot, const char* op_name, int (*fn)(uint64_t), uint64_t h) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(h));
}
int nsp_fence_backend_release(int slot, const char* op_name, int (*fn)(uint64_t), uint64_t h) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(h));
}
int nsp_fence_backend_create(int slot, const char* op_name,
                             int (*fn)(const char*, mode_t, uint64_t*), const char* path,
                             mode_t mode, uint64_t* h) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(path, mode, h));
}
int nsp_fence_backend_simple(int slot, const char* op_name, int (*fn)(const char*),
                             const char* path) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(path));
}
int nsp_fence_backend_mkdir(int slot, const char* op_name, int (*fn)(const char*, mode_t),
                            const char* path, mode_t mode) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(path, mode));
}
int nsp_fence_backend_rename(int slot, const char* op_name, int (*fn)(const char*, const char*),
                             const char* from, const char* to) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(from, to));
}
int nsp_fence_backend_truncate(int slot, const char* op_name, int (*fn)(const char*, off_t),
                               const char* path, off_t size) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(path, size));
}

/* ================= 生命周期 ================= */

int nsp_fence_init_call(int slot, const char* op_name, int (*fn)(const NspFrameworkApi*),
                        const NspFrameworkApi* api) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn(api));
}
int nsp_fence_exit_call(int slot, const char* op_name, void (*fn)(void)) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP_VOID(slot, op_name, fn());
}
int nsp_fence_reload_call(int slot, const char* op_name, int (*fn)(void)) {
    if (!fn) return NSP_FENCE_BADFN;
    NSP_FENCE_WRAP(slot, op_name, fn());
}
