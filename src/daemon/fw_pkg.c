#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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

/* /data/system/packages.list：Android 全量已装应用清单（"pkg uid ..."），
   系统共享 uid（1000 等）的包名唯一可靠来源（uid.map 无条目、caller pid 不可得）。
   找到返回 true 并写入 out；找不到/打不开返回 false。seinfo 非空时顺带带回
   该行的 MAC 权限标签（如 "platform:privapp:targetSdkVersion=36"），供特权
   判定（fw_pkg_is_privileged）使用。路径可用 fw_pkg_set_packagelist_path
   注入（仅测试；生产恒为 /data/system/packages.list）。 */
static const char g_packagelist_path[] = "/data/system/packages.list";
static const char* g_packagelist_override = nullptr;

void fw_pkg_set_packagelist_path(const char* path) { g_packagelist_override = path; }

/* packages.list 的唯一打开点：uid→包名、包名→uid、特权判定三处共用同一个
   路径钩子（测试注入一份夹具就同时覆盖三个查询）。 */
static FILE* open_packagelist(void) {
    return fopen(g_packagelist_override ? g_packagelist_override : g_packagelist_path, "re");
}

static bool resolve_sys_pkg_from_packagelist(uid_t uid, char* out, size_t size,
                                             char* seinfo, size_t seinfo_size) {
    FILE* fp = open_packagelist();
    if (!fp) return false;
    bool found = false;
    char line[1024];
    while (fgets(line, sizeof line, fp)) {
        char name[FW_PKG_NAME_MAX];
        unsigned int puid = 0;
        if (sscanf(line, "%127s %u", name, &puid) == 2 && puid == (unsigned int)uid) {
            snprintf(out, size, "%s", name);
            if (seinfo && seinfo_size > 0) {
                /* 第 4 字段 dataDir 第 5 字段 seinfo："pkg uid debug dataDir seinfo ..." */
                seinfo[0] = '\0';
                char datadir[256];
                if (sscanf(line, "%*127s %*u %*u %255s %127s", datadir, seinfo) != 2)
                    seinfo[0] = '\0';
            }
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

/* uid 是否为特权应用（Android 权限体系自动判定，见 fw_pkg.h）。缓存独立于
   包名解析槽位：privileged 是"uid → 布尔"的稳定事实（packages.list 只在
   应用安装/升级时变化），包名缓存 gen 失效不影响它。 */
typedef struct {
    _Atomic uint64_t seq; /* 奇数 = 写者进行中 */
    uint64_t gen;
    uid_t uid;
    bool known; /* packages.list 有该 uid 的行（不可读/未命中 = false） */
    bool priv;
} FwPkgPrivSlot;

static FwPkgPrivSlot g_priv_slots[FW_PKG_CACHE_SIZE];
static pthread_mutex_t g_priv_fill_lock = PTHREAD_MUTEX_INITIALIZER;

/* seinfo 以 "platform" 开头 = platform 签名（system/priv-app/签名共享）。
   实测 packages.list：DocumentsUI "platform:privapp:…"、Settings "platform:privapp:…"、
   系统签名覆盖层 "platform:targetSdkVersion=…"；普通应用恒为 "default:…"。
   "privapp" 子串单独判会漏掉纯 platform 签名应用，故判前缀。 */
static bool seinfo_is_privileged(const char* seinfo) {
    return strncmp(seinfo, "platform", 8) == 0 &&
           (seinfo[8] == '\0' || seinfo[8] == ':');
}

bool fw_pkg_is_privileged(uid_t uid) {
    FwPkgPrivSlot* s = &g_priv_slots[uid % FW_PKG_CACHE_SIZE];
    uint64_t gen = atomic_load_explicit(&g_gen, memory_order_acquire);
    for (;;) {
        uint64_t v1 = atomic_load_explicit(&s->seq, memory_order_acquire);
        if (!(v1 & 1)) {
            if (v1 == s->seq && s->gen == gen && s->uid == uid && s->known)
                return s->priv;
        }
        if (atomic_load_explicit(&s->seq, memory_order_acquire) & 1) continue;
        pthread_mutex_lock(&g_priv_fill_lock);
        char pkg[FW_PKG_NAME_MAX];
        char seinfo[128];
        bool known = resolve_sys_pkg_from_packagelist(uid, pkg, sizeof pkg, seinfo,
                                                      sizeof seinfo);
        bool priv = known && seinfo_is_privileged(seinfo);
        /* 槽位写回只依赖 g_priv_fill_lock（本函数独占路径）+ 自身 seqlock 标记；
           绝不碰 g_fill_lock——包名填充路径（g_fill_lock）会调用本函数，嵌套即死锁 */
        atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                              memory_order_release); /* 奇：写中 */
        s->uid = uid;
        s->known = known;
        s->priv = priv;
        s->gen = gen;
        atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                              memory_order_release); /* 偶：写完 */
        pthread_mutex_unlock(&g_priv_fill_lock);
        return priv;
    }
}

/* ---- 包名 → uid（FUSE 事件通道的白名单自动解析用） ----
   与上面两条缓存三足鼎立、互不嵌套：本组只用 g_pkguid_fill_lock，且函数体内
   只解析 packages.list（fopen/fgets，不取任何锁），**不**调用 resolve_uncached
   → g_fill_lock、也不调用 fw_pkg_is_privileged → g_priv_fill_lock。反过来那两条
   路径完全不会进本函数，故不存在「持一把锁再取另一把」的环。 */
typedef struct {
    uint64_t gen;
    char pkg[FW_PKG_NAME_MAX];
    bool known; /* packages.list 有该包名的行 */
    uid_t uid;
} FwPkgUidSlot;

#define FW_PKG_UID_SLOTS 8 /* 只有固定的两个 MediaProvider 包名会来查，留余量 */

static FwPkgUidSlot g_pkguid_slots[FW_PKG_UID_SLOTS];
static pthread_mutex_t g_pkguid_fill_lock = PTHREAD_MUTEX_INITIALIZER;

/* 按包名扫 packages.list 取 uid（"pkg uid ..."）。找不到/打不开返回 false。 */
static bool resolve_uid_from_packagelist(const char* pkg, uid_t* out) {
    FILE* fp = open_packagelist();
    if (!fp) return false;
    bool found = false;
    char line[1024];
    while (fgets(line, sizeof line, fp)) {
        char name[FW_PKG_NAME_MAX];
        unsigned int puid = 0;
        if (sscanf(line, "%127s %u", name, &puid) == 2 && strcmp(name, pkg) == 0) {
            *out = (uid_t)puid;
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

bool fw_pkg_uid_for_package(const char* pkg, uid_t* out) {
    if (!pkg || !pkg[0]) return false;
    uint64_t gen = atomic_load_explicit(&g_gen, memory_order_acquire);
    pthread_mutex_lock(&g_pkguid_fill_lock);
    int use = -1;
    for (int i = 0; i < FW_PKG_UID_SLOTS && use < 0; i++) {
        if (g_pkguid_slots[i].gen == gen && strcmp(g_pkguid_slots[i].pkg, pkg) == 0) use = i;
    }
    if (use < 0) {
        /* 未命中：先找本代外的空槽（代际失效即空槽），都被占则用 0 号 */
        use = 0;
        for (int i = 0; i < FW_PKG_UID_SLOTS; i++) {
            if (g_pkguid_slots[i].gen != gen) {
                use = i;
                break;
            }
        }
        FwPkgUidSlot* s = &g_pkguid_slots[use];
        snprintf(s->pkg, sizeof s->pkg, "%s", pkg);
        s->known = resolve_uid_from_packagelist(pkg, &s->uid); /* 失败也缓存，直到下次重载 */
        s->gen = gen;
    }
    bool known = g_pkguid_slots[use].known;
    uid_t uid = g_pkguid_slots[use].uid;
    pthread_mutex_unlock(&g_pkguid_fill_lock);
    if (known && out) *out = uid;
    return known;
}

/* 取展示包名并判定其可否用于段匹配（等价模块 br_get_app_cfg 的不可解析分支：
   过短 / zygote / <pre- 一律只能命中 GLOBAL） */
static void resolve_uncached(uid_t uid, pid_t tid, char* out, size_t size, bool* lookup_ok) {
    char pkg[FW_PKG_NAME_MAX] = {0};
    const char* mapped = uid_map_lookup(g_uid_maps, g_uid_map_count, uid);
    if (mapped) {
        snprintf(pkg, sizeof pkg, "%s", mapped);
    } else if (uid < NSP_SYSTEM_APP_UID_MIN) {
        /* 系统共享 uid（1000 等）在 uid.map 里通常没有条目（injector 只在应用
           REPORT 时写入），而 FUSE 请求侧拿不到 caller pid（q->pid 是 daemon
           伪造的连接标识），cmdline 回退也不可用——实机验证：系统应用的显式
           应用段（[com.android.settings] 等）永不命中，而 GLOBAL/类别段正常。
           /data/system/packages.list 的 "pkg uid ..." 行覆盖全部已装应用，
           按 uid 取第一个匹配包名。共享 uid（android.uid.system 下多个包）只取
           其一，其余包的应用段规则要生效需等 uid.map 随 REPORT 增长补上；
           伪包 "system" 的 SYSTEM_APPS 类别层判定不受影响。 */
        resolve_sys_pkg_from_packagelist(uid, pkg, sizeof pkg, nullptr, 0);
        if (pkg[0] == '\0' && tid > 0) {
            /* packages.list 不可读（非 Android 环境）时退回 cmdline */
            goto cmdline_fallback;
        }
    } else if (tid > 0) {
      cmdline_fallback:;
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
    return fw_pkg_resolve_exact(uid, tid, out, size);
}

bool fw_pkg_resolve_exact(uid_t uid, pid_t tid, char* out, size_t size) {
    if (!out || size == 0) return false;
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
