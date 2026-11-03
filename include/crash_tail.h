#ifndef CRASH_TAIL_H
#define CRASH_TAIL_H
/*
 * crash_tail.h — 崩溃诊断的读取窗口
 *
 * fuse_crash.log 是 append 打开的长期文件：每次 fuse_daemon 启动都会接着往里写，
 * 历次启动的 linker 报错、backtrace 与退出原因都留在同一个文件里。诊断若直接摊
 * 尾部固定字节数，早先启动的失败记录会被读成「本次崩溃原因」（现场就出现过把
 * 上一次启动的 linker 报错当成崩溃主因的情况）。
 *
 * 因此窗口必须锚在「本次守护进程启动时的文件大小」上：只读这个偏移之后的内容。
 * 本模块只有这一条纯函数，I/O 留在调用方（injector）。
 */
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

typedef struct {
    off_t start;          /* 读取起点（文件偏移） */
    size_t len;           /* 可读字节数 */
    bool drop_first_line; /* 起点落在行中间：丢弃该残行，避免半截 backtrace 帧 */
} CrashTailWindow;

/* 计算读取窗口。
 *   file_size  当前文件大小
 *   run_start  本次守护进程启动时的文件大小；-1 表示未知（stat 失败）
 *   cap        最多读多少字节
 * 返回 false 表示本次启动之后没有任何输出（没有可诊断的内容）。
 *
 * run_start 未知或大于当前大小（文件被截断/轮转）时退回「只读尾部」：此时偏移已
 * 失去意义，但读到的也只可能是新内容，标记 drop_first_line 以免输出半行。 */
bool crash_tail_window(off_t file_size, off_t run_start, size_t cap, CrashTailWindow* out);

#endif /* CRASH_TAIL_H */