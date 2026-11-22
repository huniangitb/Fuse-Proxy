/*
 * test_acl_whitelist_lifetime.py 专用驱动（fixture）：跨应用白名单数组的
 * 槽外借用 × 配置发布释放。
 *
 * 由 Python 脚本连同实际源码（fw_acl.c / fw_rules.c / fw_pkg.c / config_parser.c
 * 及其依赖，不经 Meson）临时编译。
 *
 * 被测机制：配置发布（config_publish）在排空旧代际读者后释放旧白名单数组
 * （含每个条目的 strdup 内存）。读槽只保护持槽读者；槽外调用者若在比较途中
 * 被发布穿插，就会在已释放内存上做 strlen/strncmp。两处生产调用者：
 *   - fw_acl_identity 组装身份（每请求）
 *   - readdir 条目可见性里的跨应用判据（fw_rules_cross_app_access）
 *
 * 现场还原：--wrap=strlen 在"白名单条目第一次被量长度"的瞬间把读线程停住
 * （只停一次、只针对被观测的那一条），主控随后按真实发布顺序
 * begin→drain→swap→end→free 释放旧数组，再放行读线程。判定逻辑一行不改。
 *
 * 用法：acl_whitelist_lifetime lifetime <conf>
 *       acl_whitelist_lifetime nested <conf>
 * nested：本线程先持读槽，再让发布者开始发布（它卡在排空本线程的槽），
 * 然后在持槽状态下调快照入口。正确实现直接裸读（外层槽已钉住配置）并
 * 立即返回；再取一层槽的实现会与外层槽的排空互等而挂死（alarm(5) 收场）。
 * 判别：编译期 -DACL_WL_LEGACY_CALL=1 时第二个窗口调槽外入口
 *       fw_rules_cross_app_access（旧实现/旧调用者），否则调 _snapshot。
 *       -DACL_WL_HAS_SNAPSHOT=0 表示源里没有快照入口（旧源判别构建），
 *       nested 模式跳过嵌套调用只报 -2。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <signal.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "config_parser.h"
#include "fw_acl.h"
#include "fw_pkg.h"
#include "fw_rules.h"
#include "injector.h"

#ifndef ACL_WL_LEGACY_CALL
#define ACL_WL_LEGACY_CALL 0
#endif

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

/* ---- 观测钩子 ---- */
static const char* g_watch_entry; /* 被观测的白名单条目（本轮 live 配置里的那一条） */
static const char* g_freed_entry; /* 发布时释放掉的条目 */
static char** g_freed_array;      /* 发布时释放掉的数组块 */
static _Atomic int g_freed_reads;
static _Atomic int g_stop_once;   /* 停读线程的闸：每次窗口只停一次 */
static sem_t g_captured;          /* 读线程已停在条目上 */
static sem_t g_release;           /* 主控放行 */

size_t __real_strlen(const char* s);
int __real_strncmp(const char* a, const char* b, size_t n);

static void note_pointer(const void* p) {
    if (!p) return;
    if (g_freed_entry && p == (const void*)g_freed_entry) atomic_fetch_add(&g_freed_reads, 1);
    else if (g_freed_array && p == (const void*)&g_freed_array[0]) atomic_fetch_add(&g_freed_reads, 1);
}

size_t __wrap_strlen(const char* s) {
    if (s && s == g_watch_entry && atomic_exchange(&g_stop_once, 1) == 0) {
        sem_post(&g_captured); /* 已取到条目指针、尚未比较：真实竞态窗口就在这里 */
        sem_wait(&g_release);
    }
    note_pointer(s);
    return __real_strlen(s);
}

int __wrap_strncmp(const char* a, const char* b, size_t n) {
    note_pointer(a);
    note_pointer(b);
    return __real_strncmp(a, b, n);
}

/* ---- 装配（与 test_rules.py 跨应用隔离段同一配方） ---- */
static void setup(const char* conf) {
    config_set_allow_app_rules_mkdir(false);
    load_config_rules(conf);
    const char* real_root = getenv("NSP_REAL_ROOT");
    if (real_root) snprintf(g_real_root, sizeof g_real_root, "%s", real_root);
    const char* plist = getenv("NSP_PACKAGELIST");
    if (plist) fw_pkg_set_packagelist_path(plist);
    fw_pkg_reload();
    config_init_lock();
}

static char** make_list(const char* const* items, int count) {
    char** arr = calloc((size_t)count, sizeof *arr);
    if (!arr) abort();
    for (int i = 0; i < count; i++) {
        arr[i] = strdup(items[i]);
        if (!arr[i]) abort();
    }
    return arr;
}

static void install_list(char** list, int count) {
    g_global_cfg.allow_cross_pkgs = list;
    g_global_cfg.allow_cross_pkg_count = count;
}

/* 真实发布顺序（见 src/config/config_parser.c 的 config_publish）：封锁新读者 →
   排空旧代际读者 → 非原子交换 → 放行新读者 → 释放旧配置。 */
typedef struct {
    char** fresh;
    int count;
    char** old;
    int old_count;
    _Atomic int swapped;
} Publisher;

static void* publisher_thread(void* arg) {
    Publisher* p = arg;
    uint64_t gen = config_publish_begin();
    config_drain_readers(gen);
    install_list(p->fresh, p->count);
    config_publish_end(gen);
    atomic_store(&p->swapped, 1);
    g_freed_entry = p->old[0];
    g_freed_array = p->old;
    for (int i = 0; i < p->old_count; i++) free(p->old[i]);
    free(p->old);
    return NULL;
}

static int acl_verdict(void) {
    NspAclIdentity id;
    memset(&id, 0, sizeof id);
    fw_acl_identity(10123, 0, &id);
    return id.cross_app_allowed ? 1 : 0;
}

static int access_verdict(void) {
#if ACL_WL_LEGACY_CALL
    return fw_rules_cross_app_access("com.demo.app", 10123, false) != NSP_XAPP_NONE;
#else
    return fw_rules_cross_app_access_snapshot("com.demo.app", 10123, false) != NSP_XAPP_NONE;
#endif
}

typedef struct {
    int (*fn)(void);
    int verdict;
} Reader;

static void* reader_thread(void* arg) {
    Reader* r = arg;
    r->verdict = r->fn();
    return NULL;
}

/* 一个"读途中被发布穿插"的窗口：返回发布是否被读者挡住、读者在已释放条目上比较的次数、
   读者裁决。blocked=-1 表示读者没进窗口（超时）。 */
static void run_window(char** fresh, int fresh_count, char** old, int old_count, int (*fn)(void),
                       int* verdict, int* blocked, int* freed_delta) {
    *verdict = -1;
    *blocked = -1;
    *freed_delta = -1;
    g_watch_entry = old[0];
    atomic_store(&g_stop_once, 0);
    const int before = atomic_load(&g_freed_reads);
    Reader r = {.fn = fn, .verdict = -1};
    pthread_t rt;
    if (pthread_create(&rt, NULL, reader_thread, &r) != 0) return;
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 5;
    if (sem_timedwait(&g_captured, &deadline) != 0) {
        pthread_join(rt, NULL);
        return;
    }
    Publisher pub = {.fresh = fresh, .count = fresh_count, .old = old, .old_count = old_count};
    pthread_t pt;
    if (pthread_create(&pt, NULL, publisher_thread, &pub) != 0) {
        sem_post(&g_release);
        pthread_join(rt, NULL);
        return;
    }
    /* 等 200ms 看发布者能不能越过 drain：持槽实现被读者挡住（正确），槽外实现直接过 */
    const struct timespec nap = {0, 200 * 1000 * 1000};
    nanosleep(&nap, NULL);
    *blocked = atomic_load(&pub.swapped) ? 0 : 1;
    sem_post(&g_release);
    pthread_join(rt, NULL);
    pthread_join(pt, NULL);
    *verdict = r.verdict;
    *freed_delta = atomic_load(&g_freed_reads) - before;
}


/* 嵌套窗口：本线程已持读槽，再让发布者开始发布（它卡在排空本线程的槽），
   随后在持槽状态下调快照入口。正确实现走"槽内直接读"立即返回；再取一层
   槽的实现会与外层槽的排空互等而挂死，5s 后由 alarm 终止（退出码非 0）。 */
static void run_nested(char** fresh, int fresh_count, char** old, int old_count) {
    alarm(5);
    install_list(old, old_count); /* 当前配置含调用方包名 */
    const uint64_t gen = config_read_begin(); /* 本线程持槽 */
    Publisher pub = {.fresh = fresh, .count = fresh_count, .old = old, .old_count = old_count};
    pthread_t pt;
    uint64_t nested_us = 0;
    int nested_verdict = -1;
    int swapped = 0;
    if (pthread_create(&pt, NULL, publisher_thread, &pub) == 0) {
        const struct timespec nap = {0, 100 * 1000 * 1000};
        nanosleep(&nap, NULL); /* 发布者此时应已卡在 drain */
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
#if ACL_WL_HAS_SNAPSHOT
        nested_verdict = fw_rules_cross_app_pkg_allowed_snapshot("com.demo.app") ? 1 : 0;
#else
        nested_verdict = -2; /* 旧实现没有快照入口，不可做嵌套判别 */
#endif
        clock_gettime(CLOCK_MONOTONIC, &t1);
        nested_us = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000u +
                    (uint64_t)((t1.tv_nsec - t0.tv_nsec) / 1000);
        config_read_end(gen); /* 放行发布者 */
        pthread_join(pt, NULL);
        swapped = atomic_load(&pub.swapped);
    } else {
        config_read_end(gen);
    }
    alarm(0);
    printf("nested_us=%llu nested_verdict=%d nested_swapped=%d\n",
           (unsigned long long)nested_us, nested_verdict, swapped);
}

int main(int argc, char** argv) {
    const bool nested = argc >= 2 && strcmp(argv[1], "nested") == 0;
    if (argc < 3 || (!nested && strcmp(argv[1], "lifetime") != 0)) {
        fprintf(stderr, "usage: %s lifetime|nested <conf>\n", argv[0]);
        return 2;
    }
    setup(argv[2]);
    sem_init(&g_captured, 0, 0);
    sem_init(&g_release, 0, 0);
    if (nested) {
        static const char* const live_items[] = {"com.demo.app"};
        static const char* const fresh_items[] = {"com.other.app"};
        run_nested(make_list(fresh_items, 1), 1, make_list(live_items, 1), 1);
        return 0;
    }
    /* 阶段 A：live 白名单含调用方包名 —— 身份应判"已放行"（顺序路径，无重载） */
    static const char* const first_items[] = {"com.demo.app"};
    static const char* const second_items[] = {"com.other.app"};
    static const char* const third_items[] = {"com.demo.app"};
    char** first = make_list(first_items, 1);
    install_list(first, 1);
    const int before = acl_verdict();
    /* 阶段 B：ACL 身份组装在比较条目途中被停住，主控按真实发布顺序释放旧数组 */
    char** second = make_list(second_items, 1);
    int acl_blocked = -1, acl_freed = -1, acl_verdict_after = -1;
    run_window(second, 1, first, 1, acl_verdict, &acl_verdict_after, &acl_blocked, &acl_freed);
    /* 阶段 C：再重载一次把条目加回来 —— 断言读的是当前配置而不是任何缓存副本 */
    char** third = make_list(third_items, 1);
    install_list(third, 1);
    const int again = acl_verdict();
    /* 阶段 D：readdir 侧的跨应用判据（旧实现直接调槽外入口） */
    char** fourth = make_list(second_items, 1);
    int access_blocked = -1, access_freed = -1, access_after = -1;
    run_window(fourth, 1, third, 1, access_verdict, &access_after, &access_blocked, &access_freed);
    printf("before_allowed=%d acl_blocked=%d acl_freed=%d acl_after=%d again_allowed=%d\n",
           before, acl_blocked, acl_freed, acl_verdict_after, again);
    printf("access_blocked=%d access_freed=%d access_after=%d legacy_call=%d\n",
           access_blocked, access_freed, access_after, ACL_WL_LEGACY_CALL);
    return 0;
}
