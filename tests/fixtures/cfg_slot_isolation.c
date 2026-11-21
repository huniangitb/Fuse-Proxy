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
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
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
/* packages.list 打开观测：--wrap=fopen 统计「打开时本线程是否正持配置读槽」。
   生产里这份文件由 open_packagelist() 唯一打开（uid→包名、包名→uid、特权三处），
   它落在读槽内就会拖住发布者排空读者——与 appops 查询同一条放大链。 */
static const char* g_plist_path;
static _Atomic int g_pkgl_opens;
static _Atomic int g_pkgl_in_slot;
/* 「持读槽时读清单且读取真的慢」——放大机制的精确信号。FIFO 提供者可能让某次
   读到空清单（写方已关、缓冲已读完），那种读是瞬时的、不会拖住发布；计数为 0 才
   说明槽内没有慢文件读。 */
static _Atomic int g_pkgl_slow_in_slot;
static _Thread_local FILE* t_plist_stream;
extern FILE* __real_fopen(const char* path, const char* mode);
FILE* __wrap_fopen(const char* path, const char* mode) {
    if (g_plist_path && path && strcmp(path, g_plist_path) == 0) {
        atomic_fetch_add(&g_pkgl_opens, 1);
        if (config_read_in_slot()) atomic_fetch_add(&g_pkgl_in_slot, 1);
        FILE* stream = __real_fopen(path, mode);
        t_plist_stream = stream; /* 本线程最近打开的清单流：供 fgets 侧计时 */
        return stream;
    }
    return __real_fopen(path, mode);
}

static unsigned long long now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000000ull + (unsigned long long)t.tv_nsec / 1000ull;
}

/* 清单读的时长：持读槽时读了 ≥50ms 才记为「槽内慢读」。空清单/已读完的 EOF
   读是瞬时的，不算放大信号 */
extern char* __real_fgets(char* buf, int size, FILE* stream);
char* __wrap_fgets(char* buf, int size, FILE* stream) {
    const bool watch = (stream != NULL && stream == t_plist_stream) && config_read_in_slot();
    const unsigned long long t0 = watch ? now_us() : 0;
    char* ret = __real_fgets(buf, size, stream);
    if (watch && now_us() - t0 >= 50000ull) atomic_store(&g_pkgl_slow_in_slot, 1);
    return ret;
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
    uid_t uid;
    bool blocked;
    bool probed;
    bool probe_first; /* 先 probe 再 resolve：probe 冷路径也要走一遍身份解析 */
    unsigned long long resolve_us;
    unsigned long long probe_us;
} ResolveJob;

static void* resolve_thread(void* arg) {
    ResolveJob* j = arg;
    NspQueryCtx q = {.uid = j->uid ? j->uid : (uid_t)10123, .pid = getpid(), .gid = 0,
                     .path = j->path};
    NspProbeResult p;
    memset(&p, 0, sizeof p);
    if (j->probe_first) {
        /* 先 probe：此时 uid→包名缓存全冷，身份解析只能由 probe 自己做 */
        unsigned long long tp0 = now_us();
        fw_rules_probe(&q, &p);
        j->probe_us = now_us() - tp0;
    }
    unsigned long long t0 = now_us();
    NspPathDecision d;
    memset(&d, 0, sizeof d);
    fw_rules_resolve(&q, &d);
    unsigned long long t1 = now_us();
    if (!j->probe_first) {
        unsigned long long tp0 = now_us();
        fw_rules_probe(&q, &p);
        j->probe_us = now_us() - tp0;
    }
    j->resolve_us = t1 - t0;
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

/* packages.list 的"慢读"提供者：把 override 路径做成 FIFO。读方的 open 一直等到
   写方打开；写方先睡 delay_ms 再写入一份合法清单后关闭，读方的 fgets 于是先读到
   三行、再读到 EOF。每次读都真切地慢 delay_ms（open/read/close 全是真文件 IO）。
   两条必须守住的时序：① 写完立刻关闭——数据留在管道里仍可读，关闭最后写端才
   给出 EOF；② 关后隔 2ms 再开下一轮——立刻重开写端会让读方的 fgets 永远等不到
   EOF（实测整段挂死），也避免新读方挂到"已经写完"的写端上读到空文件（那会让
   生产代码把清单判成读失败）。 */
typedef struct {
    const char* fifo;
    int delay_ms;
    _Atomic bool stop;
} PkglProvider;

static void* pkgl_provider(void* arg) {
    PkglProvider* p = arg;
    static const char kLines[] =
        "com.sys.app 1000 0 /data/user/0/com.sys.app platform:privapp:targetSdkVersion=34\n"
        "com.demo.app 10123 0 /data/user/0/com.demo.app default:targetSdkVersion=34\n"
        "com.other.app 10151 0 /data/user/0/com.other.app default:targetSdkVersion=34\n";
    while (!atomic_load(&p->stop)) {
        int fd = open(p->fifo, O_WRONLY); /* 阻塞：读方 open 之后才返回 */
        if (fd < 0) break;
        struct timespec d = {0, (long)p->delay_ms * 1000000L};
        while (nanosleep(&d, &d) != 0) {}
        ssize_t w = write(fd, kLines, sizeof kLines - 1);
        (void)w; /* 读方可能拿够行就关掉：EPIPE 由 main 的 SIG_IGN 兜住 */
        close(fd); /* 数据留在管道里可读，关闭最后写端让读方 fgets 看到 EOF */
        /* 关后停 2ms 再开下一次：读方把 233 字节读完 + 读到 EOF + fclose 只需
           微秒；若立刻重开写端，读方可能永远等不到 EOF（实测整段挂死），而
           读方在空档里 open 会阻塞到下一次 open 成功——两侧都不会互等。 */
        struct timespec gap = {0, 2000000L};
        while (nanosleep(&gap, &gap) != 0 && errno == EINTR) {}
    }
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

/* 发布器与「正在做 packages.list 慢读」的请求并发：publish-pkgs 先 resolve、
   probe-pkgs 先 probe（此时身份缓存全冷）。两者共用同一套观测与打印。 */
static int run_publish_pkgs(const char* conf, const char* fifo, int slow_ms,
                           const char* target_path, bool probe_first) {
    g_slow_ms = slow_ms;
    signal(SIGPIPE, SIG_IGN);
    setup(conf); /* 先把正常清单装好（reload 会读它），再切到 FIFO */
    fw_pkg_set_packagelist_path(fifo);
    g_plist_path = fifo;
    PkglProvider prov = {.fifo = fifo, .delay_ms = g_slow_ms};
    atomic_init(&prov.stop, false);
    pthread_t pr;
    if (pthread_create(&pr, NULL, pkgl_provider, &prov) != 0) return 3;
    pthread_detach(pr); /* 提供者在 FIFO 上阻塞等读方，进程退出即回收 */
    ResolveJob job = {.path = target_path, .uid = 0, .probe_first = probe_first};
    pthread_t a;
    if (pthread_create(&a, NULL, resolve_thread, &job) != 0) return 3;
    /* 发布起始偏移可调：要撞上「请求正持读槽且槽内有慢文件 IO」的窗口 */
    const char* delay_env = getenv("NSP_PUBLISH_DELAY_MS");
    long delay_ms = delay_env ? strtol(delay_env, NULL, 10) : 30;
    struct timespec nap = {delay_ms / 1000, (delay_ms % 1000) * 1000000L};
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
    printf("drain_us=%llu publish_us=%llu late_reader_us=%llu resolve_us=%llu probe_us=%llu "
           "pkgl_opens=%d pkgl_in_slot=%d pkgl_slow_in_slot=%d blocked=%d probed=%d\n",
           t_drain - t_begin, t_end - t_begin, lr.wait_us, job.resolve_us, job.probe_us,
           atomic_load(&g_pkgl_opens), atomic_load(&g_pkgl_in_slot),
           atomic_load(&g_pkgl_slow_in_slot), job.blocked ? 1 : 0, job.probed ? 1 : 0);
    config_destroy_lock();
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <publish|publish-pkgs|probe-pkgs|matrix> <conf> [slow_ms] [path...]\n",
                argv[0]);
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
    if (strcmp(mode, "publish-pkgs") == 0 || strcmp(mode, "probe-pkgs") == 0) {
        if (argc < 4) {
            fprintf(stderr, "%s 需要 slow_ms\n", mode);
            return 2;
        }
        const char* fifo = getenv("NSP_PKGLIST_FIFO");
        if (!fifo) {
            fprintf(stderr, "%s 需要 NSP_PKGLIST_FIFO\n", mode);
            return 2;
        }
        return run_publish_pkgs(conf, fifo, atoi(argv[3]),
                                argc >= 5 ? argv[4] : "/0/Android/data/com.other.app/files/x",
                                strcmp(mode, "probe-pkgs") == 0);
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
