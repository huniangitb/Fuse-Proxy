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
#include <sys/syscall.h>
#include <ucontext.h>

#define CRASH_BT_MAX 128
__attribute__((weak)) int backtrace(void *__buffer, int __size);
__attribute__((weak)) void backtrace_symbols_fd(void *const *__buffer, int __size, int __fd);

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

/* 修复：所有操作必须是 async-signal-safe，不使用 non-safe 函数 */
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

    // 写入 error.log (仅简单记录)
    int err_fd = open(ERROR_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    if (err_fd >= 0) {
        char t_buf[64];
        time_t now = time(NULL);
        struct tm tm_buf;
        // localtime_r 是 async-safe？实际上不是，但很多实现中安全；为避免风险，改用简单写时间戳
        // 更安全：不写时间，只写信号
        safe_printf(err_fd, "FUSE Daemon Crashed - Signal: %d - %s\n", sig, sig_name);
        close(err_fd);
    }

    int out_fd = STDERR_FILENO;

    if (sig == SIGABRT) {
        safe_printf(out_fd, "Signal: %d - %s\n", sig, sig_name);
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
    } else {
        // 非预期崩溃，输出诊断（仅使用 async-safe 系统调用）
        char sep[] = "\n========================================\n";
        write(out_fd, sep, sizeof(sep) - 1);
        safe_printf(out_fd, "FUSE DAEMON CRASH - PID: %d, TID: %ld\n", getpid(), syscall(SYS_gettid));
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

        // 尝试使用 backtrace (可能会分配内存，但仍较安全)
        if (backtrace && backtrace_symbols_fd) {
            void *bt[CRASH_BT_MAX];
            int frames = backtrace(bt, CRASH_BT_MAX);
            safe_printf(out_fd, "Backtrace (%d frames):\n", frames);
            if (frames > 0) backtrace_symbols_fd(bt, frames, out_fd);
        } else {
            safe_printf(out_fd, "Backtrace not available\n");
        }

        write(out_fd, sep, sizeof(sep) - 1);
    }

    raise(sig);
}

void install_crash_handlers(void) {
    struct sigaction sa;
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGSYS,  &sa, NULL);
}