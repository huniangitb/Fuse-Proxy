#define _GNU_SOURCE
/*
 * fw_pkg.c — 框架侧 uid → 包名解析（见 fw_pkg.h）
 *
 * 解析顺序与模块 br_get_app_cfg 保持一致（uid.map → /proc），使框架与模块对同一
 * 请求得到同一个包名；差别只在本文件不做 AppConfig 关联（那是 fw_config 的事）。
 */
#include "fw_pkg.h"
#include "common.h"
#include "nsp_constants.h"
#include "uid_map.h"
#include "fast_pid.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FW_PKG_CACHE_SIZE 2048
#define FW_PKG_NAME_MAX 128

/* 槽位：uid→包名是进程事实，规则重载只使代际失效（gen 不匹配即重新解析）。
   热路径（每次 FUSE 请求读 current_pkg）用 seqlock 无锁读，填充走互斥锁。 */
typedef struct {
    _Atomic uint64_t seq; /* 奇数 = 写者进行中 */
    uint64_t gen;
    uid_t uid;
    bool lookup_ok;
    char pkg[FW_PKG_NAME_MAX];
} FwPkgSlot;

static FwPkgSlot g_slots[FW_PKG_CACHE_SIZE];
static pthread_mutex_t g_fill_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic uint64_t g_gen = 1;

static UidMapEntry* g_uid_maps = nullptr;
static int g_uid_map_count = 0;

/* uid.map 条目数随已启动应用增长：按需扩容装载（同模块 load_uid_map） */
static void load_uid_map(void) {
    int cap = UID_MAP_INIT_CAPACITY;
    UidMapEntry* maps = malloc((size_t)cap * sizeof(UidMapEntry));
    if (!maps) return;
    int count = uid_map_load(maps, cap);
    while (count > 0 && count == cap) {
        cap *= 2;
        UidMapEntry* bigger = realloc(maps, (size_t)cap * sizeof(UidMapEntry));
        if (!bigger) break; /* 扩容失败：用已装载部分，缺失项走 /proc 回退 */
        maps = bigger;
        count = uid_map_load(maps, cap);
    }
    UidMapEntry* old = g_uid_maps;
    g_uid_maps = maps;
    g_uid_map_count = count;
    free(old);
}

void fw_pkg_reload(void) {
    load_uid_map();
    atomic_fetch_add_explicit(&g_gen, 1, memory_order_release);
}

void fw_pkg_shutdown(void) {
    free(g_uid_maps);
    g_uid_maps = nullptr;
    g_uid_map_count = 0;
}

/* 取展示包名并判定其可否用于段匹配（等价模块 br_get_app_cfg 的不可解析分支：
   过短 / zygote / <pre- 一律只能命中 GLOBAL） */
static void resolve_uncached(uid_t uid, pid_t tid, char* out, size_t size, bool* lookup_ok) {
    char pkg[FW_PKG_NAME_MAX] = {0};
    const char* mapped = uid_map_lookup(g_uid_maps, g_uid_map_count, uid);
    if (mapped) {
        snprintf(pkg, sizeof pkg, "%s", mapped);
    } else if (tid > 0) {
        /* 主线程 id 取自 /proc/<tid>/status 的 Tgid：应用线程的 cmdline 就是包名，
           但只保证主线程可读（zygote fork 后线程组细节），故先定位 Tgid */
        pid_t main_pid = tid;
        char status_path[64];
        snprintf(status_path, sizeof status_path, "/proc/%d/status", tid);
        FILE* fp = fopen(status_path, "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof line, fp)) {
                if (strncmp(line, "Tgid:", 5) == 0) {
                    main_pid = (pid_t)atoi(line + 5);
                    break;
                }
            }
            fclose(fp);
        }
        proc_get_cmdline(main_pid, pkg, sizeof pkg);
    }
    /* 多开/隔离进程形如 <pkg>:<suffix>：段匹配与展示都取基础包名 */
    char* colon = strchr(pkg, ':');
    if (colon) *colon = '\0';
    if (pkg[0] == '\0') snprintf(pkg, sizeof pkg, "unknown");

    *lookup_ok = !(strlen(pkg) < 3 || strstr(pkg, "zygote") || strstr(pkg, "<pre-"));
    snprintf(out, size, "%s", pkg);
}

bool fw_pkg_resolve(uid_t uid, pid_t tid, char* out, size_t size) {
    if (!out || size == 0) return false;
    if (uid < NSP_SYSTEM_APP_UID_MIN) {
        snprintf(out, size, "system");
        return false; /* system 伪包只参与 SYSTEM_APPS 类别层，不属于应用段 */
    }
    FwPkgSlot* s = &g_slots[uid % FW_PKG_CACHE_SIZE];
    uint64_t gen = atomic_load_explicit(&g_gen, memory_order_acquire);
    for (;;) {
        uint64_t s1 = atomic_load_explicit(&s->seq, memory_order_acquire);
        if (s1 & 1) continue; /* 填充进行中：重试 */
        uid_t suid = s->uid;
        uint64_t sgen = s->gen;
        bool sok = s->lookup_ok;
        char spkg[FW_PKG_NAME_MAX];
        memcpy(spkg, s->pkg, sizeof spkg);
        uint64_t s2 = atomic_load_explicit(&s->seq, memory_order_acquire);
        if (s1 != s2) continue; /* 快照撕裂：重试 */
        if (suid == uid && sgen == gen) {
            snprintf(out, size, "%s", spkg);
            return sok;
        }
        break;
    }

    char pkg[FW_PKG_NAME_MAX];
    bool lookup_ok = false;
    resolve_uncached(uid, tid, pkg, sizeof pkg, &lookup_ok);

    pthread_mutex_lock(&g_fill_lock);
    uint64_t seq = atomic_load_explicit(&s->seq, memory_order_relaxed);
    atomic_store_explicit(&s->seq, seq + 1, memory_order_release);
    s->uid = uid;
    s->gen = gen;
    s->lookup_ok = lookup_ok;
    memcpy(s->pkg, pkg, sizeof s->pkg);
    atomic_store_explicit(&s->seq, seq + 2, memory_order_release);
    pthread_mutex_unlock(&g_fill_lock);

    snprintf(out, size, "%s", pkg);
    return lookup_ok;
}
