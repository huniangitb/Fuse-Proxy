/* backend_bad.c — 故障注入用后端模块（熔断/围栏/输出校验回归的载体）
 *
 * V4 起模块只剩后端形态，故「规则模块崩溃/契约违规」这类故障注入必须改由
 * backend_* 承载。按路径关键字选择故障：
 *   berr            → backend_getattr 返回**非 errno 契约**的码（+0x7fffffff）：
 *                     契约违规，计入熔断窗口，5 次触发置毒卸载
 *   bovf            → backend_readdir 谎报 max+10 条（越界写指纹）：
 *                     框架丢弃整批并计错误，不得越界读
 *   breaddir_crash  → backend_readdir 内 SIGSEGV：围栏恢复 + 单次置毒
 *   bmatch          → 正常认领（伪造目录 stat + 空目录）：作为"健康后端"基线
 * 其余路径返回 0 不认领（直通本地）。用 -DFIXED 编译时 berr/bovf 退化为正常，
 * 供「同哈希 ban 自愈 / 槽位复用」用例换同名修复版 .so 使用。
 *
 * 触发前置：injector.conf 需有 `FTP /<关键字> seg1`（FTP 规则使引擎置 is_ftp，
 * 框架才会走后端查找）。
 *
 * 编译：gcc -shared -fPIC -O1 -g -DNSP_MODULE_BUILD -Iinclude backend_bad.c -o backend_bad.so
 */
#define _GNU_SOURCE
#include "nsp_module.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

static int bb_match(const char* path) {
    if (!path) return 0;
    if (strstr(path, "berr") || strstr(path, "bovf") || strstr(path, "breaddir_crash") ||
        strstr(path, "bhealth"))
        return 1;
    return 0;
}

static int bb_getattr(const char* path, struct stat* st) {
    if (!st) return -EINVAL;
#ifdef FIXED
    (void)path;
#else
    /* 非 errno 范围的正数 = 契约违规（后端只允许 0 或 -1..-4095） */
    if (path && strstr(path, "berr")) return 0x7fffffff;
#endif
    memset(st, 0, sizeof *st);
    st->st_mode = S_IFDIR | 0755;
    st->st_nlink = 2;
    return 0;
}

static int bb_readdir(const char* path, NspDirEntry* entries, int max) {
    (void)path;
    (void)entries;
    (void)max;
#ifndef FIXED
    if (path && strstr(path, "bovf")) {
        /* 谎报条数：调用方必须按 max 钳制/整批丢弃，绝不能按 n 循环填充 */
        return max + 10;
    }
    if (path && strstr(path, "breaddir_crash")) {
        volatile int* p = (int*)0;
        *p = 1; /* SIGSEGV → 围栏恢复 + 置毒 */
        return 0;
    }
#endif
    return 0;
}

static const NspModuleOps bb_ops = {
    .backend_match = bb_match,
    .backend_getattr = bb_getattr,
    .backend_readdir = bb_readdir,
};

const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .name = "backend_bad",
    .version = "1.0",
    .init = NULL,
    .exit = NULL,
    .ops = &bb_ops,
};
