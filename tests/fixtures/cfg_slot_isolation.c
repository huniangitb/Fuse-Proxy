/*
 * test_cfg_slot_isolation.py 专用驱动（fixture）：配置读槽 × 慢能力查询。
 *
 * 由 Python 脚本连同实际源码（fw_rules.c / fw_pkg.c / config_parser.c 及其依赖，
 * 不经 Meson）临时编译——与 test_rules.py 的跨应用隔离段同一罐装配方。
 *
 * 被测机制：跨应用隔离的能力事实（MANAGE_EXTERNAL_STORAGE / INSTALL_PACKAGES）
 * 在生产里来自一次外部命令（cmd appops get）。若这次慢查询落在
 * config_read_begin/end 读槽内，配置发布者排空旧读者时被它拖住，进而让此后
 * 进入决策的每个 worker 都在 config_read_begin 上自旋——单次慢查询放大成整池
 * 停顿。宿主没有 /system/bin/cmd，故用测试钩子（fw_pkg_set_manage_external_probe，
 * 生产 API 的测试替换点）把查询替换成可计时睡眠：除外部命令本身，其余全为真实
 * 代码路径（真实 packages.list 解析、真实 ext 槽缓存、真实 br_xapp_facts、
 * 真实 fw_rules_resolve/probe 与真实 config 代际协议）。
 *
 * 用法：cfg_slot_isolation <mode> <conf> [slow_ms] [path...]
 *   publish <conf> <slow_ms> [path]  线程 A 在槽内/槽前做慢查询，主线程走 published
 *                             begin→drain→end 协议，打印三段耗时
 *   matrix  <conf> <path...>  逐路径裁决 + 能力查询次数（slow_ms 固定 0）
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "config_parser.h"
#include "fw_pkg.h"
#include "fw_rules.h"
#include "injector.h"
#include "nsp_util.h"

/* injector 全局符号：config_publisher.c 引用（本夹具不链接 injector.c） */
struct GlobalFuseInfo g_global_fuse;
struct GlobalFuseInfo g_media_fuse;
volatile sig_atomic_t g_should_exit = 0;
volatile sig_atomic_t g_reload_config = 0;
volatile sig_atomic_t g_passive_mode = 0;
volatile sig_atomic_t g_fuse_ready = 0;
int g_epoll_fd = -1;
int g_global_root_fd = -1;
InjectMethod g_inject_method = INJECT_METHOD_V1;

static int g_slow_ms;
static _Atomic int g_queries;

static unsigned long long now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000000ull + (unsigned long long)t.tv_nsec / 1000ull;
}

/* 生产查询的替身：唯一差别是不 fork 外部命令，行为上只"耗时且判 false"。 */
static bool slow_manage_external(const char* pkg) {
    (void)pkg;
    atomic_fetch_add(&g_queries, 1);
    if (g_slow_ms > 0) {
        struct timespec d = {0, (long)g_slow_ms * 1000000L};
        while (nanosleep(&d, &d) != 0) {}
    }
    return false;
}

typedef struct {
    const char* path;
    bool blocked;
    bool probed;
} ResolveJob;

static void* resolve_thread(void* arg) {
    ResolveJob* j = arg;
    NspQueryCtx q = {.uid = 10123, .pid = getpid(), .gid = 0, .path = j->path};
    NspPathDecision d;
    memset(&d, 0, sizeof d);
    fw_rules_resolve(&q, &d);
    NspProbeResult p;
    memset(&p, 0, sizeof p);
    fw_rules_probe(&q, &p);
    j->blocked = d.appear_missing;
    j->probed = p.appear_missing;
    return NULL;
}

typedef struct {
    unsigned long long wait_us;
} LateReader;

static void* late_reader(void* arg) {
    LateReader* lr = arg;
    unsigned long long t0 = now_us();
    uint64_t gen = config_read_begin();
    lr->wait_us = now_us() - t0;
    (void)config_read_end(gen);
    return NULL;
}

static void setup(const char* conf) {
    config_set_allow_app_rules_mkdir(false);
    load_config_rules(conf);
    const char* real_root = getenv("NSP_REAL_ROOT");
    if (real_root) snprintf(g_real_root, sizeof g_real_root, "%s", real_root);
    const char* plist = getenv("NSP_PACKAGELIST");
    if (plist) fw_pkg_set_packagelist_path(plist);
    fw_pkg_set_manage_external_probe(slow_manage_external);
    fw_pkg_reload();
    config_init_lock();
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <publish|matrix> <conf> [slow_ms] [path...]\n", argv[0]);
        return 2;
    }
    const char* mode = argv[1];
    const char* conf = argv[2];
    if (strcmp(mode, "publish") == 0) {
        if (argc < 4) {
            fprintf(stderr, "publish 需要 slow_ms\n");
            return 2;
        }
        g_slow_ms = atoi(argv[3]);
        /* 可选路径：用来复现「原始写法与判定口径不一致」的输入（如删字节才凑出
           /Android/data/ 前缀的路径）。缺省用他包 data 的常规写法。 */
        const char* target_path = argc >= 5 ? argv[4] : "/0/Android/data/com.other.app/files/x";
        setup(conf);
        ResolveJob job = {.path = target_path};
        pthread_t a;
        if (pthread_create(&a, NULL, resolve_thread, &job) != 0) return 3;
        struct timespec nap = {0, 30 * 1000000L};
        while (nanosleep(&nap, &nap) != 0) {}
        unsigned long long t_begin = now_us();
        uint64_t old_gen = config_publish_begin();
        LateReader lr = {0};
        pthread_t b;
        if (pthread_create(&b, NULL, late_reader, &lr) != 0) return 3;
        config_drain_readers(old_gen);
        unsigned long long t_drain = now_us();
        config_publish_end(old_gen);
        unsigned long long t_end = now_us();
        pthread_join(b, NULL);
        pthread_join(a, NULL);
        printf("drain_us=%llu publish_us=%llu late_reader_us=%llu queries=%d blocked=%d probed=%d\n",
               t_drain - t_begin, t_end - t_begin, lr.wait_us, atomic_load(&g_queries),
               job.blocked ? 1 : 0, job.probed ? 1 : 0);
        config_destroy_lock();
        return 0;
    }
    if (strcmp(mode, "matrix") == 0) {
        if (argc < 4) return 2;
        g_slow_ms = 0;
        const char* uid_arg = getenv("NSP_ISO_UID");
        setup(conf);
        uid_t uid = uid_arg ? (uid_t)strtoul(uid_arg, NULL, 10) : (uid_t)10123;
        for (int i = 3; i < argc; i++) {
            NspQueryCtx q = {.uid = uid, .pid = getpid(), .gid = 0, .path = argv[i]};
            int q0 = atomic_load(&g_queries);
            NspPathDecision d;
            memset(&d, 0, sizeof d);
            fw_rules_resolve(&q, &d);
            int q1 = atomic_load(&g_queries);
            NspProbeResult p;
            memset(&p, 0, sizeof p);
            fw_rules_probe(&q, &p);
            int q2 = atomic_load(&g_queries);
            NspPathDecision d2;
            memset(&d2, 0, sizeof d2);
            fw_rules_resolve(&q, &d2);
            int q3 = atomic_load(&g_queries);
            printf("%s resolve=%d probe=%d q0=%d q1=%d q2=%d q3=%d\n", argv[i],
                   d.appear_missing ? 1 : 0, p.appear_missing ? 1 : 0, q0, q1, q2, q3);
        }
        config_destroy_lock();
        return 0;
    }
    fprintf(stderr, "未知模式 %s\n", mode);
    return 2;
}
