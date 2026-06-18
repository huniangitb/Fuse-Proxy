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
#include <dlfcn.h>

#define CRASH_BT_MAX 128

/* 运行时通过 dlsym 探测 backtrace 可用性，避免旧平台弱符号解析不可靠 */
static int (*g_backtrace_fn)(void**, int) = NULL;
static void (*g_backtrace_symbols_fd_fn)(void* const*, int, int) = NULL;

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

        // 尝试使用 backtrace（运行时已探测）
        if (g_backtrace_fn && g_backtrace_symbols_fd_fn) {
            void *bt[CRASH_BT_MAX];
            int frames = g_backtrace_fn(bt, CRASH_BT_MAX);
            safe_printf(out_fd, "Backtrace (%d frames):\n", frames);
            if (frames > 0) g_backtrace_symbols_fd_fn(bt, frames, out_fd);
        } else {
            safe_printf(out_fd, "Backtrace not available\n");
        }

        write(out_fd, sep, sizeof(sep) - 1);
    }

    raise(sig);
}

void install_crash_handlers() {
    /* 运行时探测 backtrace 是否可用（dlsym 比弱符号更可靠） */
    *(void**)(&g_backtrace_fn) = dlsym(RTLD_DEFAULT, "backtrace");
    *(void**)(&g_backtrace_symbols_fd_fn) = dlsym(RTLD_DEFAULT, "backtrace_symbols_fd");

    struct sigaction sa;
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    /* 逐个安装，失败静默跳过（低API等级可能不支持部分信号） */
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGBUS,  &sa, nullptr);
    sigaction(SIGFPE,  &sa, nullptr);
    sigaction(SIGILL,  &sa, nullptr);
#ifdef SIGSYS
    sigaction(SIGSYS,  &sa, nullptr);
#endif
    LOG_DBG("crash_dump: 安装完成, backtrace=%s",
            g_backtrace_fn ? "可用" : "不可用");
}