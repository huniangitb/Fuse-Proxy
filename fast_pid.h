#ifndef FAST_PID_H
#define FAST_PID_H

#include <sys/types.h>

int fast_pid_init(void);
void fast_pid_cleanup(void);
int fast_pid_find(const char* target_package);

// 新增：遍历所有进程的回调定义
// 返回 0 继续遍历并缓存，返回 1 停止遍历，返回 2 继续遍历但不缓存
typedef int (*pid_callback_t)(int pid, const char* cmdline, void* data);
void fast_pid_each(pid_callback_t callback, void* data);

// 清除 PID 缓存，强制下次 fast_pid_each 执行完整扫描
void fast_pid_cache_clear(void);

#endif