#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "sys_pkg.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>

/* 系统应用包名缓存：原 inject_target.c 内联实现跨进程共享抽取。
 * 语义不变：pm list packages -s → "package:" 行；失败/无表回退 uid<10000
 * （由调用方判定，本文件只答"包名是否在系统表"）。 */
#define SYS_PKG_HASH_SIZE 1024
#define SYS_PKG_MAX_LINES 8192
#define SYS_PKG_LINE_MAX  512 /* pm 单行最长（与旧 fgets 缓冲区同宽） */
typedef struct SysPkgEntry {
    char pkg[128];
    struct SysPkgEntry* next;
} SysPkgEntry;

typedef struct SysPkgTable {
    SysPkgEntry* hash[SYS_PKG_HASH_SIZE];
} SysPkgTable;

/* 读者只在此锁内借用 table；构建、日志、文件 I/O 和旧表回收全部在锁外。 */
static SysPkgTable* g_sys_pkg_table;
/* pm 查询冷却截止时刻（单调毫秒，0 = 无冷却）：见 SYS_PKG_PM_COOLDOWN_MS */
static _Atomic uint64_t g_sys_pkg_pm_retry_at_ms;
/* 降级读到空 cache 后的复查时刻（0 = 不需要复查） */
static _Atomic uint64_t g_sys_pkg_recheck_at_ms;
static pthread_mutex_t g_sys_pkg_mutex = PTHREAD_MUTEX_INITIALIZER;
/* 固定 .tmp 文件名是 inotify 协议；只序列化写者，查询永不取此锁。 */
static pthread_mutex_t g_sys_pkg_save_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_sys_pkg_loaded = false;
static bool g_sys_pkg_loading = false;
static bool g_sys_pkg_allow_pm = false;
static uint64_t g_sys_pkg_epoch;

static unsigned int sys_pkg_hash(const char* pkg) {
    unsigned int h = 5381;
    while (*pkg) h = ((h << 5) + h) + (unsigned char)*pkg++;
    return h % SYS_PKG_HASH_SIZE;
}

static void sys_pkg_free_table(SysPkgTable* table) {
    if (!table) return;
    for (int i = 0; i < SYS_PKG_HASH_SIZE; i++) {
        SysPkgEntry* e = table->hash[i];
        while (e) {
            SysPkgEntry* n = e->next;
            free(e);
            e = n;
        }
    }
    free(table);
}

static void sys_pkg_add(SysPkgTable* table, const char* pkg) {
    if (!pkg || !pkg[0]) return;
    unsigned int h = sys_pkg_hash(pkg);
    for (SysPkgEntry* e = table->hash[h]; e; e = e->next) {
        if (strcmp(e->pkg, pkg) == 0) return;
    }
    SysPkgEntry* n = malloc(sizeof(SysPkgEntry));
    if (!n) return;
    strncpy(n->pkg, pkg, sizeof(n->pkg) - 1);
    n->pkg[sizeof(n->pkg) - 1] = '\0';
    n->next = table->hash[h];
    table->hash[h] = n;
}

static void sys_pkg_cache_path(char* out, size_t sz) {
    snprintf(out, sz, "%s/sys_pkgs.cache", CONFIG_DIR);
}

/* 原子落盘：tmp 写 + rename，避免 fuse_daemon 读到半截文件 */
/* 两文件内容是否一致（任一不可读 → false，按"需要写"处理） */
static bool sys_pkg_same_content(const char* a, const char* b) {
    FILE* fa = fopen(a, "rb");
    if (!fa) return false;
    FILE* fb = fopen(b, "rb");
    if (!fb) {
        fclose(fa);
        return false;
    }
    bool same = true;
    for (;;) {
        char ba[512], bb[512];
        size_t na = fread(ba, 1, sizeof ba, fa);
        size_t nb = fread(bb, 1, sizeof bb, fb);
        if (na != nb || (na && memcmp(ba, bb, na) != 0)) {
            same = false;
            break;
        }
        if (na < sizeof ba) break; /* 两边同时到达 EOF */
    }
    fclose(fa);
    fclose(fb);
    return same;
}

static void sys_pkg_save_file(const SysPkgTable* table) {
    char path[PATH_MAX], tmp[PATH_MAX];
    sys_pkg_cache_path(path, sizeof path);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE* fp = fopen(tmp, "w");
    if (!fp) {
        LOG_WRN("sys_pkgs.cache 落盘失败: %s", tmp);
        return;
    }
    for (int i = 0; i < SYS_PKG_HASH_SIZE; i++) {
        for (SysPkgEntry* e = table->hash[i]; e; e = e->next) fprintf(fp, "%s\n", e->pkg);
    }
    fclose(fp);
    /* 内容与目标一致则不动目标文件：避免「刷新 → 落盘 → inotify 事件 → 再刷新」的
       自激环（fw_config 按 ev->name 把 sys_pkgs.cache 事件分流为「只刷新」，见 C11） */
    if (sys_pkg_same_content(tmp, path)) {
        unlink(tmp);
        return;
    }
    if (rename(tmp, path) != 0) {
        LOG_WRN("sys_pkgs.cache 原子换入失败");
        unlink(tmp);
    }
}

static void sys_pkg_load_file(SysPkgTable* table) {
    char path[PATH_MAX];
    sys_pkg_cache_path(path, sizeof path);
    FILE* fp = fopen(path, "r");
    if (!fp) return; /* 无表 = pm 查询失败语义，调用方回退 uid<10000 */
    char line[160];
    int n = 0;
    while (n < SYS_PKG_MAX_LINES && fgets(line, sizeof line, fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        if (line[0]) {
            sys_pkg_add(table, line);
            n++;
        }
    }
    fclose(fp);
}

/* pm 查询及候选表构建都在读者锁外；查询期间继续使用已发布表。 */
typedef struct SysPkgTmp {
    char pkg[128];
    struct SysPkgTmp* next;
} SysPkgTmp;

static void sys_pkg_free_tmp(SysPkgTmp* head); /* 前置声明：失败路径回收已收集部分 */

/* pm list packages 的预算：命令走 binder 到 system_server（实测 0.2~1s，慢机型更久），
   旧 popen+fgets 没有上界——一次挂起就冻住注入器事件循环与 daemon 热重载线程，
   并把 FUSE/挂载响应一起拖住。3s 对慢设备足够；超预算按「这次查不到」处理，但
   调用点**不发布空表**（空表会写空 sys_pkgs.cache，冷启动回退 uid<10000 判定）。 */
#define SYS_PKG_PM_BUDGET_MS 3000
/* 超预算后的 pm 冷却：不冷却的话「一次慢」会变成「每次都慢」——注入器冷启动
   sys_pkg_init(true) 超时后没有发布表，紧跟的 is_system（生产里在 config 读锁内）
   会各自再付一遍预算，把整条存储视图链路按 3s 一档拖住。冷却期直接读磁盘 cache。 */
#define SYS_PKG_PM_COOLDOWN_MS 30000u

typedef struct {
    SysPkgTmp* head;
    int count;
} SysPkgPmCtx;

/* 逐行解析 pm 输出（旧实现 fgets 逐行，语义一致；切行由 common_run_cmd_lines 做） */
static void sys_pkg_pm_line(const char* line, void* ctx) {
    SysPkgPmCtx* c = ctx;
    if (strncmp(line, "package:", 8) != 0) return;
    char pkg[SYS_PKG_LINE_MAX];
    snprintf(pkg, sizeof pkg, "%s", line + 8);
    size_t len = strlen(pkg);
    while (len > 0 && (pkg[len - 1] == '\n' || pkg[len - 1] == '\r' || pkg[len - 1] == ' '))
        pkg[--len] = '\0';
    char* colon = strchr(pkg, ':'); /* P2：与旧版一致截断冒号后缀 */
    if (colon) *colon = '\0';
    if (!pkg[0]) return;
    SysPkgTmp* n = malloc(sizeof(SysPkgTmp));
    if (!n) return;
    strncpy(n->pkg, pkg, sizeof(n->pkg) - 1);
    n->pkg[sizeof(n->pkg) - 1] = '\0';
    n->next = c->head;
    c->head = n;
    c->count++;
}

static SysPkgTmp* sys_pkg_collect_pm(bool* timed_out) {
    SysPkgPmCtx c = {.head = NULL, .count = 0};
    if (timed_out) *timed_out = false;
    if (common_run_cmd_lines("pm list packages -s 2>/dev/null", SYS_PKG_PM_BUDGET_MS, sys_pkg_pm_line,
                             &c, timed_out) != 0) {
        LOG_WRN("sys_pkg: pm list packages -s 执行失败，回退到 UID 判断");
        sys_pkg_free_tmp(c.head);
        return NULL;
    }
    if (timed_out && *timed_out) {
        /* 半截输出不可信：丢弃并返回 NULL（绝不给调用方一个已释放的 head） */
        sys_pkg_free_tmp(c.head);
        return NULL;
    }
    LOG_DBG("sys_pkg: pm 加载了 %d 个系统应用包名", c.count);
    return c.head;
}

/* 单调毫秒；时钟不可用时返回 0（调用方按「不冷却」处理，宁可多试一次也不能卡死） */
static uint64_t sys_pkg_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static bool sys_pkg_pm_cooling(void) {
    uint64_t until = atomic_load_explicit(&g_sys_pkg_pm_retry_at_ms, memory_order_acquire);
    uint64_t now = sys_pkg_now_ms();
    if (until == 0 || now == 0) return false;
    return now < until;
}

static void sys_pkg_set_pm_cooldown(void) {
    uint64_t now = sys_pkg_now_ms();
    if (now == 0) return;
    atomic_store_explicit(&g_sys_pkg_pm_retry_at_ms, now + SYS_PKG_PM_COOLDOWN_MS,
                          memory_order_release);
}

/* 表里是否至少有一个包名（降级读 cache 失败时判「空表」用） */
static bool sys_pkg_table_nonempty(const SysPkgTable* table) {
    if (!table) return false;
    for (int i = 0; i < SYS_PKG_HASH_SIZE; i++) {
        if (table->hash[i]) return true;
    }
    return false;
}

/* 空表复查：cache 由 injector 的 pm 成功后写回，查询侧到点自动重读（只读盘，
   永不 fork pm）。间隔一秒：既不每查询一次 fopen，也不让空表一直钉住。 */
#define SYS_PKG_CACHE_RETRY_MS 1000u

static void sys_pkg_set_recheck(void) {
    uint64_t now = sys_pkg_now_ms();
    if (now == 0) return;
    atomic_store_explicit(&g_sys_pkg_recheck_at_ms, now + SYS_PKG_CACHE_RETRY_MS,
                          memory_order_release);
}

static void sys_pkg_clear_recheck(void) {
    atomic_store_explicit(&g_sys_pkg_recheck_at_ms, 0, memory_order_release);
}

static bool sys_pkg_recheck_due(void) {
    uint64_t at = atomic_load_explicit(&g_sys_pkg_recheck_at_ms, memory_order_acquire);
    if (at == 0) return false;
    uint64_t now = sys_pkg_now_ms();
    if (now == 0) return false;
    return now >= at;
}

static void sys_pkg_free_tmp(SysPkgTmp* head) {
    while (head) {
        SysPkgTmp* n = head->next;
        free(head);
        head = n;
    }
}

/* 构建者独占候选表，无需读者锁。 */
static void sys_pkg_merge_tmp(SysPkgTable* table, SysPkgTmp* head) {
    for (SysPkgTmp* t = head; t; t = t->next) sys_pkg_add(table, t->pkg);
}

/* from_query：构建由查询侧（sys_pkg_is_system，生产里在 config_lock_read 内）触发。
   查询侧**永不 fork pm**：pm 可能挂住整个预算，查询侧只允许读 cache（µs 级），
   pm 只有在初始化/显式 refresh 时才跑。 */
static void sys_pkg_build_and_publish(uint64_t epoch, bool allow_pm, bool from_query) {
    SysPkgTable* table = calloc(1, sizeof(*table));
    bool degraded = false;   /* 本批没跑 pm（查询侧 / 冷却 / pm 失败），表内容只来自 cache */
    bool cache_empty = false; /* 降级后 cache 也是空的：表虽然只有一个空桶，但要登记复查 */
    if (table) {
        /* pm 冷却期内不再 fork 第二个 pm：直接按「无 pm」读 cache（快），
           把「一次超预算」限制成一次。 */
        bool use_pm = allow_pm && !from_query && !sys_pkg_pm_cooling();
        if (use_pm) {
            bool pm_timed_out = false;
            SysPkgTmp* tmp = sys_pkg_collect_pm(&pm_timed_out);
            if (pm_timed_out) {
                /* 超预算 ≠ 没有系统应用：不发布空表、也不落盘空 cache（cache 是下次
                   加载的 hint，写空会让冷启动退回 uid<10000 判定）。降级读 cache
                   并进入冷却，避免下一次（含持 config 读锁的懒构建）再付一遍预算。 */
                LOG_WRN("sys_pkg: pm 查询超预算 %dms，降级读缓存并冷却 %us",
                        SYS_PKG_PM_BUDGET_MS, SYS_PKG_PM_COOLDOWN_MS / 1000u);
                sys_pkg_set_pm_cooldown();
                sys_pkg_load_file(table);
                degraded = true;
                cache_empty = !sys_pkg_table_nonempty(table);
            } else if (!tmp) {
                /* 非超时失败（fork/pipe/读错误/单调钟失效）：同样不发布空表、不落盘空
                   cache（写空会覆盖好 hint，让下次冷启动退回 uid<10000 判定）。 */
                LOG_WRN("sys_pkg: pm 查询失败，降级读缓存");
                sys_pkg_load_file(table);
                degraded = true;
                cache_empty = !sys_pkg_table_nonempty(table);
            } else {
                sys_pkg_merge_tmp(table, tmp);
                pthread_mutex_lock(&g_sys_pkg_save_mutex);
                pthread_mutex_lock(&g_sys_pkg_mutex);
                bool current = epoch == g_sys_pkg_epoch && allow_pm == g_sys_pkg_allow_pm;
                pthread_mutex_unlock(&g_sys_pkg_mutex);
                /* 已进入内核的缓存写不可撤销；cache 是下次加载的 hint，
                 * 内存表仍由下方 epoch 检查拒绝迟到发布。 */
                if (current) sys_pkg_save_file(table);
                pthread_mutex_unlock(&g_sys_pkg_save_mutex);
            }
            sys_pkg_free_tmp(tmp);
        } else {
            sys_pkg_load_file(table);
            degraded = true;
            cache_empty = !sys_pkg_table_nonempty(table);
        }
    }
    SysPkgTable* old = NULL;
    pthread_mutex_lock(&g_sys_pkg_mutex);
    if (epoch == g_sys_pkg_epoch && allow_pm == g_sys_pkg_allow_pm) {
        if (table) {
            old = g_sys_pkg_table;
            g_sys_pkg_table = table;
            table = NULL;
            g_sys_pkg_loaded = true;
            /* 降级且 cache 为空：空表不能钉住（cache 由 injector 的 pm 成功后写回）。
               登记复查时刻，查询侧到点自动重读 cache（µs 级，永不 fork pm）。 */
            if (degraded && cache_empty) {
                sys_pkg_set_recheck();
            } else {
                sys_pkg_clear_recheck();
            }
        }
        g_sys_pkg_loading = false;
    }
    pthread_mutex_unlock(&g_sys_pkg_mutex);
    /* 读者不把节点带出 mutex，换表时旧表已无读者。迟到构建也在此回收。 */
    sys_pkg_free_table(old);
    sys_pkg_free_table(table);
}

void sys_pkg_init(bool allow_pm) {
    pthread_mutex_lock(&g_sys_pkg_mutex);
    if (g_sys_pkg_allow_pm != allow_pm) {
        g_sys_pkg_allow_pm = allow_pm;
        ++g_sys_pkg_epoch;
        g_sys_pkg_loading = false;
    }
    if (g_sys_pkg_loaded || g_sys_pkg_loading) {
        pthread_mutex_unlock(&g_sys_pkg_mutex);
        return;
    }
    g_sys_pkg_loading = true;
    uint64_t epoch = ++g_sys_pkg_epoch;
    pthread_mutex_unlock(&g_sys_pkg_mutex);
    sys_pkg_build_and_publish(epoch, allow_pm, false);
}

/* 后台装载线程：查询路径只查已发布表，冷缓存与迟到复查的磁盘读在这里做。
 *
 * 为什么必须搬走：查询在生产里常常落在配置读锁/读槽内（mount_manager 的
 * app_has_active_rules/perform_app_mount、config_parser 的 print_active_rules、
 * inject_target 的 is_target_app、fw_rules 的 br_pick_category、fw_config 的
 * monitor_uncached）。一次慢 f2fs 读占着那把锁，配置写者（重载、控制编辑）与
 * 发布者的读者排空就一起被冻住——单次慢调用放大成整池停顿。
 *
 * 装载线程只碰本文件的静态量：不取任何调用方的锁，发布仍走 g_sys_pkg_mutex +
 * epoch 守卫（cleanup 之后迟到发布被拒，不会碰已释放的表）。 */
static pthread_t g_sys_pkg_loader_thread;
static bool g_sys_pkg_loader_running; /* 受 g_sys_pkg_mutex 保护 */

/* 冷缓存/复查到期时的装载：只读 cache（from_query 语义，永不 fork pm）。 */
static void sys_pkg_load_due(void) {
    pthread_mutex_lock(&g_sys_pkg_mutex);
    bool recheck = sys_pkg_recheck_due();
    bool due = (!g_sys_pkg_loaded || recheck) && !g_sys_pkg_loading;
    bool allow = g_sys_pkg_allow_pm;
    uint64_t epoch = 0;
    if (due) {
        if (recheck) sys_pkg_clear_recheck();
        g_sys_pkg_loading = true;
        epoch = ++g_sys_pkg_epoch;
    }
    pthread_mutex_unlock(&g_sys_pkg_mutex);
    if (due) sys_pkg_build_and_publish(epoch, allow, true);
}

static void* sys_pkg_loader_main(void* unused) {
    (void)unused;
    sys_pkg_load_due();
    pthread_mutex_lock(&g_sys_pkg_mutex);
    g_sys_pkg_loader_running = false;
    pthread_mutex_unlock(&g_sys_pkg_mutex);
    return NULL;
}

/* 请求后台装载：幂等、非阻塞。查询线程绝不在这里等磁盘。
 * 线程起不来（资源耗尽）时退回同步读盘——宁可慢一次，也不能给调用方一个
 * 「永远无表」的假答案（那会把系统应用判成普通应用，类别段直接错判）。 */
static void sys_pkg_request_load(void) {
    pthread_mutex_lock(&g_sys_pkg_mutex);
    if (g_sys_pkg_loader_running) {
        pthread_mutex_unlock(&g_sys_pkg_mutex);
        return;
    }
    g_sys_pkg_loader_running = true;
    /* tid 在放锁前就记账：否则 cleanup 可能看到 running=true 却 join 一个空 tid，
     * 那个装载线程随后才发布，cleanup 的「之后没有表」就漏掉它（还漏 join）。 */
    pthread_t th;
    if (pthread_create(&th, NULL, sys_pkg_loader_main, NULL) == 0) {
        g_sys_pkg_loader_thread = th;
        pthread_mutex_unlock(&g_sys_pkg_mutex);
        return;
    }
    g_sys_pkg_loader_running = false;
    pthread_mutex_unlock(&g_sys_pkg_mutex);
    sys_pkg_load_due();
}

void sys_pkg_cleanup(void) {
    pthread_t loader = {0};
    bool join_loader;
    pthread_mutex_lock(&g_sys_pkg_mutex);
    ++g_sys_pkg_epoch; /* 先关迟到发布路径，再回收表 */
    join_loader = g_sys_pkg_loader_running;
    loader = g_sys_pkg_loader_thread;
    SysPkgTable* old = g_sys_pkg_table;
    g_sys_pkg_table = NULL;
    g_sys_pkg_loaded = false;
    g_sys_pkg_loading = false;
    pthread_mutex_unlock(&g_sys_pkg_mutex);
    /* cleanup 之后不留装载线程：它只碰本文件静态量，等它退出不会拖调用方的锁。
       代价是磁盘挂住时 cleanup 跟着等（与日志 worker 的 join 同一类边界）。 */
    if (join_loader) pthread_join(loader, NULL);
    /* 装载线程可能在上面放掉锁之后才真正开始装载（那时它的 epoch 已是最新，发布
       会成功）。cleanup 的语义是「之后没有表」，所以 join 完再摘一次：否则
       cleanup 之后仍留着一张没人要的旧视图，紧随的 init 会提前返回。 */
    pthread_mutex_lock(&g_sys_pkg_mutex);
    SysPkgTable* late = g_sys_pkg_table;
    g_sys_pkg_table = NULL;
    g_sys_pkg_loaded = false;
    pthread_mutex_unlock(&g_sys_pkg_mutex);
    sys_pkg_free_table(old);
    sys_pkg_free_table(late);
}

void sys_pkg_refresh(void) {
    pthread_mutex_lock(&g_sys_pkg_mutex);
    bool allow = g_sys_pkg_allow_pm;
    g_sys_pkg_loading = true;
    uint64_t epoch = ++g_sys_pkg_epoch;
    pthread_mutex_unlock(&g_sys_pkg_mutex);
    sys_pkg_build_and_publish(epoch, allow, false);
}

bool sys_pkg_is_system(const char* pkg) {
    if (!pkg || !pkg[0]) return false;
    /* P1/P2：查询侧统一归一（去 :process 后缀），调用方无需各自剥离 */
    const char* q = pkg;
    char base[128];
    const char* colon = strchr(pkg, ':');
    if (colon) {
        size_t blen = (size_t)(colon - pkg);
        if (blen >= sizeof(base)) blen = sizeof(base) - 1;
        memcpy(base, pkg, blen);
        base[blen] = '\0';
        q = base;
    }
    pthread_mutex_lock(&g_sys_pkg_mutex);
    /* 查询路径**永不读盘**：冷缓存/复查到期只登记后台装载，本线程立刻按当前
       已发布表回答（首次构建未完成时按无表回答 false，与既有语义一致）。 */
    bool want_load = (!g_sys_pkg_loaded || sys_pkg_recheck_due()) && !g_sys_pkg_loading;
    unsigned int h = sys_pkg_hash(q);
    bool hit = false;
    /* 首次构建未完成时仍按无表回答 false，不让其它请求排队等磁盘。 */
    SysPkgEntry* first = g_sys_pkg_table ? g_sys_pkg_table->hash[h] : NULL;
    for (SysPkgEntry* e = first; e; e = e->next) {
        if (strcmp(e->pkg, q) == 0) {
            hit = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_sys_pkg_mutex);
    /* 锁外请求（pthread_create 也在锁外）：装载线程的磁盘读不占任何调用方锁。 */
    if (want_load) sys_pkg_request_load();
    return hit;
}
