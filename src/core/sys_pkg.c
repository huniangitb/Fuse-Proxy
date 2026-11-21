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

/* 系统应用包名缓存：原 inject_target.c 内联实现跨进程共享抽取。
 * 语义不变：pm list packages -s → "package:" 行；失败/无表回退 uid<10000
 * （由调用方判定，本文件只答"包名是否在系统表"）。 */
#define SYS_PKG_HASH_SIZE 1024
#define SYS_PKG_MAX_LINES 8192
typedef struct SysPkgEntry {
    char pkg[128];
    struct SysPkgEntry* next;
} SysPkgEntry;

typedef struct SysPkgTable {
    SysPkgEntry* hash[SYS_PKG_HASH_SIZE];
} SysPkgTable;

/* 读者只在此锁内借用 table；构建、日志、文件 I/O 和旧表回收全部在锁外。 */
static SysPkgTable* g_sys_pkg_table;
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

static SysPkgTmp* sys_pkg_collect_pm(void) {
    FILE* fp = popen("pm list packages -s 2>/dev/null", "r");
    if (!fp) {
        LOG_WRN("sys_pkg: pm list packages -s 执行失败，回退到 UID 判断");
        return NULL;
    }
    SysPkgTmp* head = NULL;
    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "package:", 8) == 0) {
            char* pkg = line + 8;
            size_t len = strlen(pkg);
            while (len > 0 && (pkg[len - 1] == '\n' || pkg[len - 1] == '\r' || pkg[len - 1] == ' '))
                pkg[--len] = '\0';
            char* colon = strchr(pkg, ':'); /* P2：与旧版一致截断冒号后缀 */
            if (colon) *colon = '\0';
            if (pkg[0]) {
                SysPkgTmp* n = malloc(sizeof(SysPkgTmp));
                if (!n) break;
                strncpy(n->pkg, pkg, sizeof(n->pkg) - 1);
                n->pkg[sizeof(n->pkg) - 1] = '\0';
                n->next = head;
                head = n;
                count++;
            }
        }
    }
    pclose(fp);
    LOG_DBG("sys_pkg: pm 加载了 %d 个系统应用包名", count);
    return head;
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

static void sys_pkg_build_and_publish(uint64_t epoch, bool allow_pm) {
    SysPkgTable* table = calloc(1, sizeof(*table));
    if (table) {
        if (allow_pm) {
            SysPkgTmp* tmp = sys_pkg_collect_pm();
            sys_pkg_merge_tmp(table, tmp);
            sys_pkg_free_tmp(tmp);
            pthread_mutex_lock(&g_sys_pkg_save_mutex);
            pthread_mutex_lock(&g_sys_pkg_mutex);
            bool current = epoch == g_sys_pkg_epoch && allow_pm == g_sys_pkg_allow_pm;
            pthread_mutex_unlock(&g_sys_pkg_mutex);
            /* 已进入内核的缓存写不可撤销；cache 是下次加载的 hint，
             * 内存表仍由下方 epoch 检查拒绝迟到发布。 */
            if (current) sys_pkg_save_file(table);
            pthread_mutex_unlock(&g_sys_pkg_save_mutex);
        } else {
            sys_pkg_load_file(table);
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
    sys_pkg_build_and_publish(epoch, allow_pm);
}

void sys_pkg_cleanup(void) {
    pthread_mutex_lock(&g_sys_pkg_mutex);
    ++g_sys_pkg_epoch;
    SysPkgTable* old = g_sys_pkg_table;
    g_sys_pkg_table = NULL;
    g_sys_pkg_loaded = false;
    g_sys_pkg_loading = false;
    pthread_mutex_unlock(&g_sys_pkg_mutex);
    sys_pkg_free_table(old);
}

void sys_pkg_refresh(void) {
    pthread_mutex_lock(&g_sys_pkg_mutex);
    bool allow = g_sys_pkg_allow_pm;
    g_sys_pkg_loading = true;
    uint64_t epoch = ++g_sys_pkg_epoch;
    pthread_mutex_unlock(&g_sys_pkg_mutex);
    sys_pkg_build_and_publish(epoch, allow);
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
    if (!g_sys_pkg_loaded && !g_sys_pkg_loading) {
        bool allow = g_sys_pkg_allow_pm;
        g_sys_pkg_loading = true;
        uint64_t epoch = ++g_sys_pkg_epoch;
        pthread_mutex_unlock(&g_sys_pkg_mutex);
        sys_pkg_build_and_publish(epoch, allow);
        pthread_mutex_lock(&g_sys_pkg_mutex);
    }
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
    return hit;
}
