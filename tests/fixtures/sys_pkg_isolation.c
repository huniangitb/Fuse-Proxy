/* 原 sys_pkg/config_parser TU + 可释放 libc gate：锁实现和发布逻辑不打桩。
 * pm 查询替身：新接缝是 common_run_cmd_lines（按行回调，见文件末尾），旧实现的
 * popen/pclose 替身也保留（SYS_PKG_SRC 负控要跑旧源），两者都回放同一份 pm_text。
 * 每个 gate 最长4秒自释放，失败断言后仍 release/join；不取消线程/越权close。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "sys_pkg.h"
#include "common.h"
#include "config_parser.h"
#include "path_trie.h"
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static bool entered, released;
static _Thread_local int gate_role;
static _Thread_local FILE* target;
static _Thread_local const char* pm_text;
static int fail, pass;
/* 冷缓存磁盘读观测：--wrap=fopen 统计「打开 sys_pkgs.cache 时本线程是否持配置读槽」，
   并可选地把这次打开停在 gate 上（模拟慢 f2fs 读）。g_gate_cache 打开时，任何线程
   读 cache 都会停在 gate —— 于是「谁在读盘」变成可观测事实。 */
static _Atomic int g_cache_reads, g_cache_reads_in_slot, g_gate_cache;
static pthread_t g_gate_owner;
static bool g_gate_owner_set;
static unsigned long long now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000000ull + (unsigned long long)t.tv_nsec / 1000ull;
}
static int tasks(void) {
    DIR* d = opendir("/proc/self/task");
    if (!d) abort();
    int count = 0;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) count++;
    }
    closedir(d);
    return count;
}
FILE* __real_fopen(const char*, const char*);
char* __real_fgets(char*, int, FILE*);
int __real_fclose(FILE*);

static struct timespec deadline(int ms) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_sec += ms / 1000;
    t.tv_nsec += (ms % 1000) * 1000000L;
    if (t.tv_nsec >= 1000000000L) { t.tv_nsec -= 1000000000L; t.tv_sec++; }
    return t;
}
static void gate(void) {
    pthread_mutex_lock(&mu);
    g_gate_owner = pthread_self();
    g_gate_owner_set = true;
    entered = true;
    pthread_cond_broadcast(&cv);
    struct timespec d = deadline(4000);
    while (!released && pthread_cond_timedwait(&cv, &mu, &d) == 0) {}
    pthread_mutex_unlock(&mu);
}
static void reset_gate(void) {
    pthread_mutex_lock(&mu); entered = released = false; pthread_mutex_unlock(&mu);
}
static bool await_gate(void) {
    pthread_mutex_lock(&mu);
    struct timespec d = deadline(1000);
    while (!entered && pthread_cond_timedwait(&cv, &mu, &d) == 0) {}
    bool ok = entered; pthread_mutex_unlock(&mu); return ok;
}
static void release_gate(void) {
    pthread_mutex_lock(&mu); released = true; pthread_cond_broadcast(&cv); pthread_mutex_unlock(&mu);
}
FILE* __wrap_fopen(const char* p, const char* mode) {
    if (strcmp(p, CONFIG_DIR "/sys_pkgs.cache") == 0 && mode[0] == 'r') {
        atomic_fetch_add(&g_cache_reads, 1);
        if (config_read_in_slot()) atomic_fetch_add(&g_cache_reads_in_slot, 1);
        if (atomic_load(&g_gate_cache)) gate(); /* 慢盘：停在 gate 上直到测试放行 */
    }
    FILE* fp = __real_fopen(p, mode);
    if (gate_role == 1 && strcmp(p, CONFIG_DIR "/sys_pkgs.cache") == 0 && mode[0] == 'r') target = fp;
    if (gate_role == 2 && strstr(p, "/sys_pkgs.cache.tmp") && mode[0] == 'w') target = fp;
    return fp;
}
char* __wrap_fgets(char* p, int n, FILE* fp) {
    if (gate_role == 1 && fp == target) { target = NULL; gate(); }
    return __real_fgets(p, n, fp);
}
int __wrap_fclose(FILE* fp) {
    if (gate_role == 2 && fp == target) { target = NULL; gate(); }
    return __real_fclose(fp);
}
static _Atomic int g_joins; /* --wrap=pthread_join 计数：装载线程真被回收几次 */
int __real_pthread_join(pthread_t th, void** ret);
int __wrap_pthread_join(pthread_t th, void** ret) {
    atomic_fetch_add(&g_joins, 1);
    return __real_pthread_join(th, ret);
}

FILE* __wrap_popen(const char* command, const char* mode) {
    (void)command; (void)mode;
    FILE* fp = tmpfile();
    if (fp) { fputs(pm_text ? pm_text : "package:com.system.old\n", fp); rewind(fp); }
    return fp;
}
int __wrap_pclose(FILE* fp) { return __real_fclose(fp); }
/* 新接缝：sys_pkg 的 pm 查询改走 common_run_cmd_lines（有界执行）。这里按行回放
   pm_text（默认一行旧系统包），timed_out 保持 false——超时分支由
   test_cmd_bounded_pm.py 用真 fork 覆盖；保留上面的 popen 替身是为了让
   SYS_PKG_SRC 指向旧实现时仍能注入同一份假 pm 输出。 */
int __wrap_common_run_cmd_lines(const char* shell_cmd, int budget_ms, NspCmdLineFn on_line,
                               void* ctx, bool* timed_out) {
    (void)shell_cmd;
    (void)budget_ms;
    if (timed_out) *timed_out = false;
    const char* text = pm_text ? pm_text : "package:com.system.old\n";
    const char* p = text;
    while (*p) {
        const char* nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        char line[128];
        if (len >= sizeof line) len = sizeof line - 1;
        memcpy(line, p, len);
        line[len] = '\0';
        if (on_line) on_line(line, ctx);
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}
static void check(bool ok, const char* name) {
    printf("%s %s\n", ok ? "PASS" : "FAIL", name); if (ok) pass++; else fail++;
}
static void write_cache(const char* text) {
    FILE* fp = __real_fopen(CONFIG_DIR "/sys_pkgs.next", "w");
    if (!fp || fputs(text, fp) < 0 || __real_fclose(fp) ||
        rename(CONFIG_DIR "/sys_pkgs.next", CONFIG_DIR "/sys_pkgs.cache")) abort();
}
static int fds(void) {
    DIR* d = opendir("/proc/self/fd"); if (!d) abort();
    int count = 0; struct dirent* e;
    while ((e = readdir(d))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) count++;
    closedir(d); return count;
}
typedef struct Job {
    atomic_bool done;
    int action, role;
    bool hit;
    const char* pkg;
    const char* pm;
} Job;
/* action0 refresh,1 init(false),2 snapshot+query,3 build,4 pure snapshot,5 cleanup */
static void* run(void* data) {
    Job* j = data; gate_role = j->role; pm_text = j->pm;
    if (j->action == 0) sys_pkg_refresh();
    else if (j->action == 1) sys_pkg_init(false);
    else if (j->action == 2) {
        uint64_t gen = config_read_begin(); j->hit = sys_pkg_is_system(j->pkg); config_read_end(gen);
    } else if (j->action == 3) config_build_from_view(NULL, 0);
    else if (j->action == 4) { uint64_t gen = config_read_begin(); config_read_end(gen); }
    else if (j->action == 5) sys_pkg_cleanup();
    atomic_store(&j->done, true);
    pthread_mutex_lock(&mu); pthread_cond_broadcast(&cv); pthread_mutex_unlock(&mu);
    return NULL;
}
static pthread_t start(Job* j) {
    pthread_t t; if (pthread_create(&t, NULL, run, j)) abort(); return t;
}
static bool done(Job* j, int ms) {
    pthread_mutex_lock(&mu); struct timespec d = deadline(ms);
    while (!atomic_load(&j->done) && pthread_cond_timedwait(&cv, &mu, &d) == 0) {}
    bool ok = atomic_load(&j->done); pthread_mutex_unlock(&mu); return ok;
}
static void isolation(int role) {
    sys_pkg_cleanup(); write_cache("com.system.old\n"); sys_pkg_init(role == 2);
    reset_gate();
    Job slow = {.role=role, .pm="package:com.system.new:proc  \n"};
    pthread_t s = start(&slow); check(await_gate(), role == 1 ? "read gate entered" : "save gate entered");
    Job reader = {.action=2, .pkg="com.system.old:worker"}; pthread_t r = start(&reader);
    bool reader_ok = done(&reader, 300);
    check(reader_ok && reader.hit, "cached unrelated query retains old table before disk completes");
    Job writer = {.action=3}; pthread_t w = start(&writer);
    bool writer_ok = done(&writer, 300);
    check(writer_ok, "config publication not held by sys_pkg disk reader");
    Job pure = {.action=4}; pthread_t p = start(&pure);
    check(done(&pure, 300), "new unrelated snapshot completes while disk gate held");
    release_gate(); pthread_join(s, NULL); pthread_join(r, NULL); pthread_join(w, NULL); pthread_join(p, NULL);
    check(role == 1 ? sys_pkg_is_system("com.system.old") : sys_pkg_is_system("com.system.new:worker"),
          "refresh publishes full table after release");
    if (role == 2) {
        sys_pkg_cleanup(); sys_pkg_init(false);
        check(sys_pkg_is_system("com.system.new"), "pm table atomically saved for file-only reader");
    }
}
static void cold_init(void) {
    sys_pkg_cleanup(); write_cache("com.system.old\n"); reset_gate();
    Job init = {.action=1, .role=1}; pthread_t t = start(&init); check(await_gate(), "cold init read gate entered");
    Job query = {.action=2, .pkg="com.system.old"}; pthread_t q = start(&query);
    check(done(&query, 300) && !query.hit, "concurrent cold reader returns unknown without waiting");
    release_gate(); pthread_join(t, NULL); pthread_join(q, NULL);
    check(sys_pkg_is_system("com.system.old"), "cold init eventually visible");
}
/* 生产形状：查询落在配置读槽/读锁内（mount_manager 的 app_has_active_rules、
   perform_app_mount，config_parser 的 print_active_rules，inject_target 的
   is_target_app，fw_rules 的 br_pick_category，fw_config 的 monitor_uncached）。
   冷缓存的磁盘读若发生在这里，就把配置写者与发布者排空一起冻住。断言：槽内一次
   都不打开 cache、查询毫秒级返回、磁盘读发生在别的线程、后台装载把表补齐。 */
static void cold_query_async(void) {
    sys_pkg_cleanup();
    write_cache("com.system.old\n");
    reset_gate();
    atomic_store(&g_cache_reads, 0);
    atomic_store(&g_cache_reads_in_slot, 0);
    atomic_store(&g_gate_cache, 1);
    pthread_mutex_lock(&mu); g_gate_owner_set = false; pthread_mutex_unlock(&mu);
    unsigned long long t0 = now_us();
    uint64_t gen = config_read_begin();
    bool first = sys_pkg_is_system("com.system.old");
    unsigned long long in_slot_us = now_us() - t0;
    config_read_end(gen);
    /* 首次构建未完成 = 按无表回答 false（既有语义），不是「无此包」的结论 */
    check(!first, "cold query inside config slot answers unknown without building");
    check(in_slot_us < 20000ull, "cold query inside config slot returns without waiting for disk");
    check(atomic_load(&g_cache_reads_in_slot) == 0,
          "no sys_pkgs.cache read while the config read slot is held");
    check(await_gate(), "background loader reaches the slow cache read");
    bool same_thread;
    pthread_mutex_lock(&mu);
    same_thread = g_gate_owner_set && pthread_equal(g_gate_owner, pthread_self());
    pthread_mutex_unlock(&mu);
    check(!same_thread, "the cache read runs on the loader thread, not on the query thread");
    release_gate();
    bool healed = false;
    for (int i = 0; i < 400 && !healed; i++) {
        usleep(5000);
        healed = sys_pkg_is_system("com.system.old");
    }
    check(healed, "background load heals the table asynchronously");
    check(atomic_load(&g_cache_reads) >= 1, "healing actually read the cache file");
    atomic_store(&g_gate_cache, 0);
    sys_pkg_cleanup();
    check(tasks() == 1, "cleanup joins the loader thread (no stray worker left)");
}

/* 连续多轮「1s 复查到期 → 新装载」之间不 cleanup：上一轮的装载线程必须在下次请求时
 * 被 join 回收。不回收的话每轮留下一个已退出未 join 的线程（8MB 栈映射），空 cache
 * 的 daemon 每秒复查一次会稳定漏上去。 */
/* 连续多轮「1s 复查到期 → 新装载」之间不 cleanup：上一轮的装载线程必须在下次请求时
 * 被 join 回收。POSIX 只在线程被 join 时释放它的资源（不管它是否已经退出），空 cache
 * 的 daemon 每秒复查一次，不回收就是稳定漏。用 --wrap=pthread_join 数真实回收次数。 */
static void loader_reap(void) {
    sys_pkg_cleanup();
    FILE* fp = fopen(CONFIG_DIR "/sys_pkgs.cache", "w"); /* 空 cache：发布空表并登记复查 */
    if (fp) fclose(fp);
    sys_pkg_init(false);
    const int joins_before = atomic_load(&g_joins);
    int loads = 0;
    for (int i = 0; i < 3; i++) {
        const int reads_before = atomic_load(&g_cache_reads);
        struct timespec ts = {.tv_sec = 1, .tv_nsec = 100 * 1000000L};
        nanosleep(&ts, NULL);
        (void)sys_pkg_is_system("com.android.systemui"); /* 复查到期 → 起新一轮装载 */
        for (int w = 0; w < 200 && atomic_load(&g_cache_reads) == reads_before; w++) usleep(1000);
        if (atomic_load(&g_cache_reads) > reads_before) loads++;
    }
    const int reaps = atomic_load(&g_joins) - joins_before;
    check(loads == 3, "each recheck starts a new background load");
    check(reaps >= 2, "each background load reaps the previous loader thread");
    sys_pkg_cleanup();
}
static void cleanup_epoch(bool init) {
    sys_pkg_cleanup(); write_cache("com.system.old\n"); if (!init) sys_pkg_init(false); reset_gate();
    Job slow = {.role=1, .action=init ? 1 : 0}; pthread_t s = start(&slow); check(await_gate(), "cleanup epoch read gate entered");
    Job cleanup = {.action=5}; pthread_t c = start(&cleanup);
    check(done(&cleanup, 300), "cleanup detaches table without waiting for disk");
    release_gate(); pthread_join(s, NULL); pthread_join(c, NULL);
    write_cache("com.system.after\n");
    /* 旧代际的 refresh 不得复活旧表；新内容由后台装载补齐（异步，故有界等待） */
    bool stale_gone = !sys_pkg_is_system("com.system.old");
    bool fresh = false;
    for (int i = 0; i < 400 && !fresh; i++) {
        usleep(5000);
        fresh = sys_pkg_is_system("com.system.after");
    }
    check(stale_gone && fresh, "stale refresh cannot resurrect table after cleanup");
}
static void latest_epoch(bool init) {
    sys_pkg_cleanup(); write_cache("com.system.old\n"); if (!init) sys_pkg_init(false); reset_gate();
    Job slow = {.role=1, .action=init ? 1 : 0}; pthread_t s = start(&slow); check(await_gate(), "latest epoch old file captured");
    write_cache("com.system.latest\n"); Job newer = {0}; pthread_t n = start(&newer);
    check(done(&newer, 300), "new refresh not queued behind unrelated slow read");
    release_gate(); pthread_join(s, NULL); pthread_join(n, NULL);
    check(!sys_pkg_is_system("com.system.old") && sys_pkg_is_system("com.system.latest"),
          "late older refresh cannot overwrite newer table");
}
static void* stress_reader(void* arg) {
    (void)arg;
    for (int i = 0; i < 10000; i++) {
        sys_pkg_is_system("com.system.old:worker");
        sys_pkg_is_system("com.unknown");
    }
    return NULL;
}
static void lifecycle_stress(void) {
    sys_pkg_cleanup(); write_cache("com.system.old\n"); sys_pkg_init(false);
    pthread_t readers[4];
    for (int i = 0; i < 4; i++) if (pthread_create(&readers[i], NULL, stress_reader, NULL)) abort();
    for (int i = 0; i < 100; i++) { sys_pkg_refresh(); sys_pkg_cleanup(); sys_pkg_init(false); }
    for (int i = 0; i < 4; i++) pthread_join(readers[i], NULL);
    check(sys_pkg_is_system("com.system.old"), "concurrent queries refresh cleanup retain valid final table");
}
static void cache_unchanged(void) {
    sys_pkg_cleanup(); sys_pkg_init(true);
    struct stat a, b;
    if (stat(CONFIG_DIR "/sys_pkgs.cache", &a)) abort();
    sys_pkg_refresh();
    if (stat(CONFIG_DIR "/sys_pkgs.cache", &b)) abort();
    check(a.st_ino == b.st_ino && a.st_mtim.tv_sec == b.st_mtim.tv_sec &&
          a.st_mtim.tv_nsec == b.st_mtim.tv_nsec, "identical pm content does not rename cache (inotify loop guard)");
}
int main(void) {
    int before = fds(); config_init_lock();
    isolation(1); isolation(2); cold_init(); cold_query_async(); loader_reap();
    cleanup_epoch(false); cleanup_epoch(true); latest_epoch(false); latest_epoch(true);
    lifecycle_stress(); cache_unchanged();
    check(!sys_pkg_is_system(NULL) && !sys_pkg_is_system("") && !sys_pkg_is_system("com.unknown"), "unknown NULL empty semantics");
    sys_pkg_cleanup(); unlink(CONFIG_DIR "/sys_pkgs.cache"); sys_pkg_init(false);
    check(!sys_pkg_is_system("com.system.latest"), "missing cache returns false");
    sys_pkg_cleanup(); trie_free(g_global_cfg.trie_root); g_global_cfg.trie_root = NULL; config_destroy_lock();
    int after = fds(); check(before == after, "all FILE/fd reclaimed and every worker joined");
    pthread_cond_destroy(&cv); pthread_mutex_destroy(&mu);
    printf("SUMMARY pass=%d fail=%d fd=%d->%d child=0\n", pass, fail, before, after);
    return fail ? 1 : 0;
}