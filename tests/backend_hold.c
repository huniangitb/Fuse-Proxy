/* backend_hold.c — A12「置毒时的 quiescence 门控」回归载体
 *
 * 建模真实 FTP 模块的线程形态：
 *   - init 起一个**配置监听**线程（exit 内 join —— 模块自己起的线程自己收）；
 *   - 另有由「打开句柄」拥有的**数据面**线程（exit **不** join —— 真实 FTP 模块
 *     里它由每个句柄的 release 收尾，exit 无从知道句柄何时关闭）。
 * `nsp_module_active_handles()` 在标记文件存在时返回 1，模拟「应用仍持有打开的
 * 文件」。因此：置毒/关停时若仍 dlclose，数据面线程会执行已解除映射的代码 →
 * 该线程不在任何围栏窗口内 → 归因失败 → 整个 daemon 死（旧实现 rc=-11）。
 * 框架侧正确的做法是 quiescence 门控：active_handles > 0 时只置空槽位、不 dlclose。
 *
 * 路径语义（触发前置：injector.conf 需有 `FTP /<关键字> seg1`）：
 *   bhbad → backend_getattr 返回**非 errno 契约**码：窗口内 5 次触发熔断置毒
 *   bhok  → 正常认领（健康基线，用于断言模块在册）
 *
 * 环境：NSP_TEST_ACTIVE = 标记文件路径（存在即 active_handles 返回 1）
 *
 * 编译：gcc -shared -fPIC -O1 -g -DNSP_MODULE_BUILD -pthread -Iinclude backend_hold.c -o backend_hold.so
 */
#define _GNU_SOURCE
#include "nsp_module.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static pthread_t g_cfg_tid;
static int g_cfg_started = 0;
static volatile int g_cfg_stop = 0;

static pthread_t g_dl_tid;
static int g_dl_started = 0;
static volatile int g_dl_stop = 0;

/* 模块自有代码地址：数据面线程反复触碰它——dlclose 后该页失效，一碰即 SIGSEGV */
static volatile int g_tick = 0;
static void hold_touch(void) {
    g_tick++;
}

/* 配置监听线程：exit 内 join（模块自己起的线程自己收） */
static void* hold_cfg_thread(void* arg) {
    (void)arg;
    while (!g_cfg_stop) {
        hold_touch();
        usleep(2000);
    }
    return NULL;
}

/* 数据面线程：由「句柄」拥有，exit **不** join（模型 FTP 的 nsp_ftpdl/nsp_ftpup） */
static void* hold_dl_thread(void* arg) {
    (void)arg;
    while (!g_dl_stop) {
        hold_touch();
        usleep(2000);
    }
    return NULL;
}

static int hold_match(const char* path) {
    if (!path) return 0;
    return (strstr(path, "bhbad") || strstr(path, "bhok")) ? 1 : 0;
}

static int hold_getattr(const char* path, struct stat* st) {
    if (!st) return -EINVAL;
    /* 非 errno 范围的正数 = 契约违规（后端只允许 0 或 -1..-4095）→ 计熔断窗口 */
    if (path && strstr(path, "bhbad")) return 0x7fffffff;
    memset(st, 0, sizeof *st);
    st->st_mode = S_IFDIR | 0755;
    st->st_nlink = 2;
    return 0;
}

static int hold_readdir(const char* path, NspDirEntry* entries, int max, uint64_t offset) {
    (void)path;
    (void)entries;
    (void)max;
    (void)offset;
    return 0;
}

static int hold_init(const NspFrameworkApi* api) {
    (void)api;
    g_cfg_stop = 0;
    if (pthread_create(&g_cfg_tid, NULL, hold_cfg_thread, NULL) == 0) g_cfg_started = 1;
    g_dl_stop = 0;
    if (pthread_create(&g_dl_tid, NULL, hold_dl_thread, NULL) == 0) g_dl_started = 1;
    return 0;
}

static void hold_exit(void) {
    /* 只收「自己起的」配置线程；数据面线程归句柄 release 收尾（本模块故意不收） */
    g_cfg_stop = 1;
    if (g_cfg_started) {
        pthread_join(g_cfg_tid, NULL);
        g_cfg_started = 0;
    }
}

static const NspModuleOps hold_ops = {
    .backend_match = hold_match,
    .backend_getattr = hold_getattr,
    .backend_readdir = hold_readdir,
};

const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .name = "backend_hold",
    .version = "1.0",
    .init = hold_init,
    .exit = hold_exit,
    .ops = &hold_ops,
};

/* 框架经 dlsym 查找：活跃句柄数。标记文件存在即视为「应用仍持有打开的文件」 */
int nsp_module_active_handles(void) {
    const char* p = getenv("NSP_TEST_ACTIVE");
    if (!p || !p[0]) return 0;
    struct stat st;
    return (stat(p, &st) == 0) ? 1 : 0;
}
