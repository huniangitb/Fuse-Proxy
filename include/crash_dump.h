#ifndef CRASH_DUMP_H
#define CRASH_DUMP_H

#include <stdarg.h>
#include <signal.h>

void safe_printf(int fd, const char* fmt, ...);
void install_crash_handlers();
/* 崩溃转储原处理器（fault_fence 启用时由 fence 处理器包在外层；
   归因失败时委托本函数做完整 dump + re-raise） */
void crash_handler(int sig, siginfo_t *info, void *ctx);

#endif