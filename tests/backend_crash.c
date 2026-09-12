/* backend_crash.c — backend_match 崩溃围栏回归（裸调用野指针）：
 *   - backend_match("/bcrash...") → 直接 SIGSEGV（修复前裸调用带崩 daemon；
 *     修复后围栏恢复+置毒，daemon 存活）
 *   - backend_match("/bmatch...") → 返回 1（认领，供 getattr/readdir 走后端路径）
 *   - backend_getattr → 伪造目录 stat；backend_readdir → 空目录（. / .. 由框架补）
 *   - 其余路径 → 返回 0（不认领，直通本地）
 *
 * 触发前置：injector.conf 需有 `FTP /bcrash seg1` / `FTP /bmatch seg1`
 * 使 basic_rules 置 rr.is_ftp，框架才走 backend_scan_match。
 *
 * 编译：gcc -shared -fPIC -O1 -g -DNSP_MODULE_BUILD -Iinclude backend_crash.c -o backend_crash.so
 */
#define _GNU_SOURCE
#include "nsp_module.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

static int bc_match(const char* path) {
    if (!path) return 0;
    if (strstr(path, "bcrash") != NULL) {
        volatile int* p = (int*)0;
        *p = 1;                /* SIGSEGV → 围栏恢复（修复前此处带崩框架） */
        return 1;
    }
    if (strstr(path, "bmatch") != NULL) return 1;
    return 0;
}

static int bc_getattr(const char* path, struct stat* st) {
    (void)path;
    if (!st) return -22; /* -EINVAL */
    memset(st, 0, sizeof *st);
    st->st_mode = 0040755; /* S_IFDIR|0755 */
    st->st_nlink = 2;
    return 0;
}

static int bc_readdir(const char* path, NspDirEntry* entries, int max) {
    (void)path; (void)entries; (void)max;
    return 0; /* 空目录 */
}

static const NspModuleOps bc_ops = {
    .backend_match   = bc_match,
    .backend_getattr = bc_getattr,
    .backend_readdir = bc_readdir,
};

const NspModuleInfo nsp_module_info = {
    .magic       = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .type        = NSP_MODULE_TYPE_BACKEND,
    .caps        = NSP_CAP_BACKEND_IO,
    .name        = "backend_crash",
    .version     = "1.0",
    .init        = NULL,
    .exit        = NULL,
    .ops         = &bc_ops,
};
