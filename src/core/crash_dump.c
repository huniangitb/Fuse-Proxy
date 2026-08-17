#define _GNU_SOURCE
#include "crash_dump.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <dlfcn.h>
#include <unwind.h> /* 引入 Android 原生支持的 unwind 接口 */
#define CRASH_BT_MAX 128
/* Android 信号安全的栈回溯状态结构体 */
struct AndroidUnwindState {
    void **current;
    void **end;
};
static _Unwind_Reason_Code android_unwind_callback(struct _Unwind_Context* context, void* arg) {
    struct AndroidUnwindState* state = (struct AndroidUnwindState*)arg;
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc) {
        if (state->current >= state->end) {
            return _URC_END_OF_STACK;
        } else {
            *state->current++ = (void*)pc;
        }
    }
    return _URC_NO_REASON;
}
/* =========================================================================
 * 核心解决方案：
 * 直接在本地实现标准的 backtrace、backtrace_symbols_fd 和 backtrace_symbols 符号。
 * 这将静态解决 libfuse3.a 内部对 execinfo.h 的符号依赖，阻止链接器将其导出为动态引用。
 * ========================================================================= */
int backtrace(void **buffer, int size) {
    if (size <= 0 || !buffer) return 0;
    struct AndroidUnwindState state = {buffer, buffer + size};
    _Unwind_Backtrace(android_unwind_callback, &state);
    return (int)(state.current - buffer);
}
void backtrace_symbols_fd(void *const *buffer, int size, int fd) {
    if (size <= 0 || !buffer || fd < 0) return;
    for (int i = 0; i < size; i++) {
        /* 采用异步信号安全的直写方式输出地址 */
        safe_printf(fd, "  #%02d pc %p\n", i, buffer[i]);
    }
}
/* 
 * 静态实现标准的 backtrace_symbols 符号：
 * 按照 POSIX 规范，它必须返回一个在堆上分配的指针数组，且字符串内容和数组存放在同一块内存中，
 * 这样调用方只需通过 free(result) 即可一次性安全释放。
 */
char **backtrace_symbols(void *const *buffer, int size) {
    if (size <= 0 || !buffer) return NULL;
    /* 预估空间：指针数组空间 + 字符串缓存空间 (每个符号描述预留 48 字节) */
    size_t ptrs_size = (size_t)size * sizeof(char *);
    size_t strings_size = (size_t)size * 48;
    char **res = malloc(ptrs_size + strings_size);
    if (!res) return NULL;
    char *str_buf = (char *)res + ptrs_size;
    for (int i = 0; i < size; i++) {
        res[i] = str_buf;
        int len = snprintf(str_buf, 48, "  #%02d pc %p", i, buffer[i]);
        if (len < 0) len = 0;
        else if (len >= 48) len = 47;
        str_buf += (len + 1); /* 移向下一个槽位（跳过 null 终止符） */
    }
    return res;
}
/* ========================================================================= */
void safe_printf(int fd, const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len > 0) {
        if (len > (int)sizeof(buf) - 1) len = (int)sizeof(buf) - 1;
        write(fd, buf, len);
    }
}
/* 崩溃时转储 /proc/self/maps 的可执行映射基址，并计算每帧相对偏移：
   PIE 二进制地址是 ASLR 随机的，仅凭绝对地址无法定位符号；
   输出 base + offset 后可用 addr2line -e <elf> <offset> 直接定位函数。
   全部使用 open/read/write/sscanf 等无锁系统调用级操作（信号安全）。 */
static void dump_maps_and_offsets(int fd, void* const* bt, int nframes) {
    int mfd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (mfd < 0) return;
    char maps[16384];
    ssize_t total = 0, got;
    while ((got = read(mfd, maps + total, sizeof(maps) - 1 - total)) > 0)
        total += got;
    close(mfd);
    if (total <= 0) return;
    maps[total] = '\0';

    safe_printf(fd, "Memory map (backtrace 解析用基址 + 偏移):\n");
    char* line = maps;
    while (line && *line) {
        char* nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        char path[256] = {0};
        if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %255s",
                   &start, &end, perms, path) >= 3 && perms[2] == 'x') {
            /* 可执行段：打印基址，并对落在该段的 backtrace 帧计算偏移 */
            safe_printf(fd, "  base 0x%lx %s\n", start, path[0] ? path : "(anon)");
            for (int i = 0; i < nframes; i++) {
                uintptr_t pc = (uintptr_t)bt[i];
                if (pc >= start && pc < end)
                    safe_printf(fd, "    #%02d pc 0x%lx -> offset +0x%lx in %s\n",
                                i, (unsigned long)pc, (unsigned long)(pc - start),
                                path[0] ? path : "(anon)");
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    safe_printf(fd, "End memory map\n");
}

static void crash_handler(int sig, siginfo_t *info, void *ctx) {
    signal(sig, SIG_DFL);
    const char* sig_name = "UNKNOWN";
    switch (sig) {
        case SIGSEGV: sig_name = "SIGSEGV (segment fault)"; break;
        case SIGABRT: sig_name = "SIGABRT (aborted)"; break;
        case SIGBUS:  sig_name = "SIGBUS (bus error)"; break;
        case SIGFPE:  sig_name = "SIGFPE (arithmetic exception)"; break;
        case SIGILL:  sig_name = "SIGILL (illegal instruction)"; break;
        case SIGSYS:  sig_name = "SIGSYS (bad syscall)"; break;
    }
    int err_fd = open(ERROR_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    if (err_fd >= 0) {
        safe_printf(err_fd, "FUSE Daemon Crashed - Signal: %d - %s\n", sig, sig_name);
        close(err_fd);
    }
    int out_fd = STDERR_FILENO;
    char sep[] = "\n========================================\n";
    write(out_fd, sep, sizeof(sep) - 1);
#ifdef SYS_gettid
    safe_printf(out_fd, "FUSE DAEMON CRASH - PID: %d, TID: %ld\n", getpid(), syscall(SYS_gettid));
#else
    safe_printf(out_fd, "FUSE DAEMON CRASH - PID: %d\n", getpid());
#endif
    safe_printf(out_fd, "Signal: %d - %s\n", sig, sig_name);
    if (sig == SIGSEGV || sig == SIGBUS) {
        safe_printf(out_fd, "Fault address: %p\n", info->si_addr);
        if (sig == SIGSEGV) {
            const char *reason = (info->si_code == SEGV_MAPERR) ? "SEGV_MAPERR" :
                                 (info->si_code == SEGV_ACCERR) ? "SEGV_ACCERR" : "unknown/other";
            safe_printf(out_fd, "Fault reason: %s\n", reason);
        }
    }
#if defined(__aarch64__)
    ucontext_t *uc = (ucontext_t *)ctx;
    safe_printf(out_fd, "Program counter: 0x%lx\n", uc->uc_mcontext.pc);
    safe_printf(out_fd, "Stack pointer: 0x%lx\n", uc->uc_mcontext.sp);
    safe_printf(out_fd, "Link register: 0x%lx\n", uc->uc_mcontext.regs[30]);
#elif defined(__x86_64__)
    ucontext_t *uc = (ucontext_t *)ctx;
    safe_printf(out_fd, "Program counter: 0x%llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RIP]);
    safe_printf(out_fd, "Stack pointer: 0x%llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RSP]);
#endif
    /* 统一调用本地安全的 backtrace 接口 */
    void *bt[CRASH_BT_MAX];
    int actual_frames = backtrace(bt, CRASH_BT_MAX);
    safe_printf(out_fd, "Backtrace (%d frames):\n", actual_frames);
    if (actual_frames > 0) {
        backtrace_symbols_fd(bt, actual_frames, out_fd);
        /* 输出可执行映射基址 + 每帧相对偏移，供 addr2line 定位符号 */
        dump_maps_and_offsets(out_fd, bt, actual_frames);
    }
    write(out_fd, sep, sizeof(sep) - 1);
    raise(sig);
}
void install_crash_handlers() {
    struct sigaction sa;
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGBUS,  &sa, nullptr);
    sigaction(SIGFPE,  &sa, nullptr);
    sigaction(SIGILL,  &sa, nullptr);
#ifdef SIGSYS
    sigaction(SIGSYS,  &sa, nullptr);
#endif
    LOG_DBG("crash_dump: 安装完成，动态劫持并本地实现了标准的 backtrace / backtrace_symbols 接口");
}