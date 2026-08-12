/* 热路径微基准：dlopen basic_rules.so 后多线程压 resolve/probe。
   目的：量化锁竞争（module 锁 + config rwlock）、trie 下降、16KB memset
   在纯规则引擎层的每请求成本与线程扩展性（FUSE 层开销已被剥离）。

   用法：
     gcc -O2 -pthread -Iinclude -o /tmp/bench_resolve tests/bench_resolve.c -ldl -Wl,--export-dynamic
     /tmp/bench_resolve [rules.conf] [threads...] [模块.so]
   模块路径也可用环境变量 BENCH_MODULE 指定（默认 build_gnu/basic_rules.so）。
   输出：各线程数下 resolve/probe 的 ops/s 与单次均值（ns）。
*/
#define _GNU_SOURCE
#include "nsp_module.h"
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>

/* ---- 框架符号桩：basic_rules.so 运行时依赖，由主程序导出解析 ----
   注意：必须非 static，且编译加 -Wl,--export-dynamic，dlopen 才能解析 */
volatile int g_log_shutdown;
const char* g_real_root = "/tmp/fuse_rules_test/storage";
int is_media_provider(const char* p) { (void)p; return 0; }
void log_internal(int level, const char* fmt, ...) { (void)level; (void)fmt; }
int mkdir_recursive_p(const char* p) { (void)p; return 0; }
int path_contains_invalid_chars(const char* p) { (void)p; return 0; }
int path_sanitize(char* dst, size_t n, const char* src) {
    (void)n; snprintf(dst, n, "%s", src); return 0;
}
/* nsp_module.h 的 LOG 宏转发到 log_internal（桩已提供） */

static const char* g_rules_path = "/tmp/fuse_rules_test/injector.conf";
static const char* api_get_rules_path(void) { return g_rules_path; }
static uint32_t api_get_flags(void) { return 0; }
static void api_log(int level, const char* fmt, ...) { (void)level; (void)fmt; }

static const NspModuleOps* g_ops = NULL;

/* ---- 压测参数 ---- */
#define QN 100000       /* 每线程 resolve 次数 */
#define PN 200000       /* 每线程 probe 次数 */
static const char* g_paths[] = {
    "/0/云盘/photo.jpg",          /* REDIRECT 命中（全局） */
    "/0/Download/Pics/a.jpg",     /* RO 命中 */
    "/0/secret/x.txt",            /* HIDE 命中 */
    "/0/Download/Music/s.mp3",    /* ALLOW 命中 */
    "/0/DCIM/camera/IMG_1.jpg",   /* 未命中规则：默认路径 */
    "/0/Android/data/com.other.app/files/a.txt", /* 其他应用 */
    "/10123/Download/f.mp4",      /* app uid + 无规则 */
    "/0/",                        /* 根 */
};
#define NPATH (int)(sizeof(g_paths) / sizeof(g_paths[0]))
static const uid_t g_uids[] = { 2000, 10123, 10123, 2000, 10123, 2000, 10123, 10123 };

static pthread_barrier_t g_bar;
static atomic_ullong g_total_ns;

static double now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static void* resolve_worker(void* arg) {
    long seed = (long)arg;
    pthread_barrier_wait(&g_bar);
    double t0 = now_ns();
    NspResolveResult out;
    for (int i = 0; i < QN; i++) {
        int k = (int)((seed * 31 + i) % NPATH);
        NspQueryCtx q = { .uid = g_uids[k], .pid = (pid_t)getpid(),
                          .gid = 0, .path = g_paths[k] };
        g_ops->resolve(&q, &out);
    }
    double dt = now_ns() - t0;
    atomic_fetch_add_explicit(&g_total_ns, (unsigned long long)dt, memory_order_relaxed);
    return NULL;
}

static void* probe_worker(void* arg) {
    long seed = (long)arg;
    pthread_barrier_wait(&g_bar);
    double t0 = now_ns();
    NspProbeResult out;
    for (int i = 0; i < PN; i++) {
        int k = (int)((seed * 17 + i) % NPATH);
        NspQueryCtx q = { .uid = g_uids[k], .pid = (pid_t)getpid(),
                          .gid = 0, .path = g_paths[k] };
        g_ops->probe(&q, &out);
    }
    double dt = now_ns() - t0;
    atomic_fetch_add_explicit(&g_total_ns, (unsigned long long)dt, memory_order_relaxed);
    return NULL;
}

static void run_bench(const char* name, void* (*fn)(void*), int n, long iters) {
    pthread_t th[64];
    atomic_store_explicit(&g_total_ns, 0, memory_order_relaxed);
    pthread_barrier_init(&g_bar, NULL, n);
    double wall0 = now_ns();
    for (int i = 0; i < n; i++) pthread_create(&th[i], NULL, fn, (void*)(long)(i + 1));
    for (int i = 0; i < n; i++) pthread_join(th[i], NULL);
    double wall = now_ns() - wall0;
    pthread_barrier_destroy(&g_bar);
    double total_work = (double)n * (double)iters;
    double ops = total_work / (wall / 1e9);
    double per = (double)g_total_ns / total_work;
    printf("  %-8s %2d 线程: %10.0f ops/s   单次均值 %7.0f ns   墙钟 %6.3f s\n",
           name, n, ops, per, wall / 1e9);
    fflush(stdout);
}

int main(int argc, char** argv) {
    if (argc > 1) g_rules_path = argv[1];
    /* P3#5：模块路径可配置（argv[3] > BENCH_MODULE > 默认 build 目录），
       移除作者机器硬编码路径，换 checkout 即可运行 */
    const char* module_path = NULL;
    if (argc > 3) module_path = argv[3];
    if (!module_path) module_path = getenv("BENCH_MODULE");
    if (!module_path) module_path = "build_gnu/basic_rules.so";
    void* h = dlopen(module_path, RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen 失败(%s): %s\n", module_path, dlerror()); return 1; }
    NspModuleInfo* info = (NspModuleInfo*)dlsym(h, "nsp_module_info");
    if (!info) { fprintf(stderr, "dlsym 失败\n"); return 1; }
    NspFrameworkApi api = {
        .api_version = NSP_FRAMEWORK_API_VERSION,
        .log = api_log,
        .get_real_root = NULL,
        .get_rules_path = api_get_rules_path,
        .get_flags = api_get_flags,
    };
    if (info->init(&api) != 0) { fprintf(stderr, "模块 init 失败\n"); return 1; }
    g_ops = info->ops;
    printf("规则引擎: %s (rules=%s)\n", info->name, g_rules_path);

    int threads[] = { 1, 2, 4, 8 };
    int nt = (argc > 2) ? atoi(argv[2]) : 4;
    printf("resolve 压测（每线程 %d 次）:\n", QN);
    for (int i = 0; i < nt; i++) run_bench("resolve", resolve_worker, threads[i], QN);
    printf("probe 压测（readdir 条目级，每线程 %d 次）:\n", PN);
    for (int i = 0; i < nt; i++) run_bench("probe", probe_worker, threads[i], PN);

    if (info->exit) info->exit();
    dlclose(h);
    return 0;
}
