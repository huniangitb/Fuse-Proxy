/* backend_bad.c — 故障注入用后端模块（熔断/围栏/输出校验回归的载体）
 *
 * V4 起模块只剩后端形态，故「规则模块崩溃/契约违规」这类故障注入必须改由
 * backend_* 承载。按路径关键字选择故障：
 *   berr            → backend_getattr 返回**非 errno 契约**的码（+0x7fffffff）：
 *                     契约违规，计入熔断窗口，5 次触发置毒卸载
 *   bovf            → backend_readdir 谎报 max+10 条（越界写指纹）：
 *                     框架丢弃整批并计错误，不得越界读
 *   brovf           → backend_read 回传 got=size+64（越界读指纹）：
 *                     框架必须拒绝并计错误——旧实现直接 (int)got 回包，
 *                     libfuse 从只有 size 字节的读缓冲取数（堆越界读）
 *   bwovf           → backend_write 回传 wrote=size+64（越界写指纹）：
 *                     框架必须拒绝并计错误——旧实现回报「写入量大于请求量」
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

/* 越界指纹路径：这两个是「普通文件」语义（供 open/read/write 走到后端） */
static int bb_is_oversize_file(const char* path) {
    return path && (strstr(path, "brovf") || strstr(path, "bwovf"));
}

static int bb_match(const char* path) {
    if (!path) return 0;
    if (strstr(path, "berr") || strstr(path, "bovf") || strstr(path, "breaddir_crash") ||
        strstr(path, "brovf") || strstr(path, "bwovf") || strstr(path, "bhealth"))
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
    if (bb_is_oversize_file(path)) {
        st->st_mode = S_IFREG | 0644;
        st->st_nlink = 1;
        st->st_size = 4096;
        return 0;
    }
    st->st_mode = S_IFDIR | 0755;
    st->st_nlink = 2;
    return 0;
}

static int bb_open(const char* path, int flags, uint64_t* h) {
    (void)path;
    (void)flags;
    if (h) *h = 0xBADC0DEull;
    return 0;
}

static int bb_read(uint64_t h, char* buf, size_t size, off_t off, size_t* got) {
    (void)h;
    (void)off;
#ifndef FIXED
    /* 谎报读取量：调用方必须拒绝（got > size 时按契约违规处置），绝不能
       直接 (int)got 回包——libfuse 只为本次读备了 size 字节缓冲 */
    if (got) *got = size + 64;
#else
    if (got) *got = size;
#endif
    if (buf && size) memset(buf, 'R', size); /* 只在合法范围内写 */
    return 0;
}

static int bb_write(uint64_t h, const char* buf, size_t size, off_t off, size_t* wrote) {
    (void)h;
    (void)buf;
    (void)off;
#ifndef FIXED
    /* 谎报写入量：调用方必须拒绝（wrote > size 会让内核认为多写了字节） */
    if (wrote) *wrote = size + 64;
#else
    if (wrote) *wrote = size;
#endif
    return 0;
}

static int bb_release(uint64_t h) {
    (void)h;
    return 0;
}

static int bb_readdir(const char* path, NspDirEntry* entries, int max, uint64_t offset) {
    (void)path;
    (void)entries;
    (void)max;
    (void)offset;
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
    .backend_open = bb_open,
    .backend_read = bb_read,
    .backend_write = bb_write,
    .backend_release = bb_release,
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
