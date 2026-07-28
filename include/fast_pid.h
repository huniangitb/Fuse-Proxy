#ifndef FAST_PID_H
#define FAST_PID_H

#include <stdbool.h>
#include <sys/types.h>

/* 直接使用原始 getdents64 系统调用所需的 Linux 目录项结构 */
struct linux_dirent64 {
    unsigned long  d_ino;
    long           d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

int fast_pid_init();
void fast_pid_cleanup();
int fast_pid_find(const char* target_package);

// 遍历所有进程的回调定义
// 返回 0 继续遍历并缓存，返回 1 停止遍历，返回 2 继续遍历但不缓存
typedef int (*pid_callback_t)(int pid, const char* cmdline, void* data);
void fast_pid_each(pid_callback_t callback, void* data);

// 清除 PID 缓存，强制下次 fast_pid_each 执行完整扫描
void fast_pid_cache_clear();

/* 从 /proc/[pid]/cmdline 读取进程命令行 */
bool proc_get_cmdline(int pid, char* buf, size_t size);

#endif