#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * fw_config.c — 框架侧配置持有者（见 fw_config.h）
 *
 * 读取（文件 I/O + inotify + 词法/段头识别）全部在此完成；模块经订阅拿到
 * 过滤后的扁平视图，自行建索引。框架不建 AppConfig（不需要规则对象/trie）。
 */
#include "fw_config.h"
#include "config_parser.h"
#include "common.h"
#include "fw_pkg.h"        /* 框架自算 uid→包名（MONITOR 三层合并的输入） */
#include "fw_rules.h"      /* 内建规则引擎（索引换入后通知它作废缓存） */
#include "nsp_constants.h" /* NSP_SYSTEM_APP_UID_MIN / NSP_PER_USER_UID_STRIDE */
#include "module_loader.h" /* MAX_MODULES */
#include "path_vars.h"     /* pkg_resolvable（类别段判据，与模块同源） */
#include "sys_pkg.h"       /* sys_pkg_is_system（SYSTEM_APPS 类别判定） */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>
#include "nsp_util.h" /* nsp_is_app_rules_dirname */
#include "cfg_watch.h" /* App-rules 子目录 watch 对账（inotify 不递归） */

/* 下发视图：**不可变 + 引用计数 + 自持字符串**的快照。
   旧实现每个 ModuleSub 持一份「浅拷贝数组 + 借用主视图字符串」，而该数组在
   fw_config_view_for 解锁后才交出去、reload_once 又在配置线程原地 free 同一
   数组——模块监听线程（loader 推送 config_update）与配置线程并发即读已释放
   数组（A14）。改为：每次重载为每个订阅者建一份新快照，记录里的字符串一并
   strdup 归本快照所有，故快照自包含、与主视图生命周期解耦；快照不可变，
   重建只换指针，旧快照延迟到最后一个持有者释放才 free。 */
typedef struct ConfigView {
    _Atomic int refs;    /* 订阅表 1 份 + 每个在飞回调 1 份 */
    NspCfgRec* recs;     /* 深拷贝的记录数组（字符串归本视图所有） */
    int count;
    NspModuleConfig cfg; /* cfg.recs/count 指向本视图自有数组 */
} ConfigView;

/* 每个模块的订阅与下发视图 */
typedef struct {
    bool used;
    char name[64];
    char** types; /* 订阅的规则类型名（strdup 归本结构所有） */
    int type_count;
    void (*listener)(const NspModuleConfig*);
    ConfigView* view; /* 当前下发视图（订阅表持 1 份引用） */
} ModuleSub;

static ModuleSub g_subs[MAX_MODULES];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static NspCfgRec* g_recs = nullptr; /* 主视图（拥有字符串） */
static int g_rec_count = 0;
static _Atomic uint64_t g_gen = 0;

static char g_rules_path[PATH_MAX] = {0};
static void (*g_reload_hook)(void) = nullptr;

/* IO 监控开关缓存：按 uid 存三层合并结果。热路径（每次 FUSE 请求）只做一次
   原子 load + 定长比较，避免每请求解析 uid→包名并线性扫 g_app_cfgs。
   重载时 g_gen 递增即整体失效（不需遍历清理），与配置索引同代际。 */
#define FW_MON_CACHE_SIZE 2048
typedef struct {
    _Atomic uint64_t seq; /* 奇数 = 写者进行中 */
    uint64_t gen;
    uid_t uid;
    bool monitor;
} FwMonSlot;

static FwMonSlot g_mon_slots[FW_MON_CACHE_SIZE];
static pthread_mutex_t g_mon_fill_lock = PTHREAD_MUTEX_INITIALIZER;

/* 三层合并：应用显式 > 类别显式 > 全局（模块侧 config_parser 的 print_active_rules
   用同一套优先级，改这里须同步核对）。
   包名不可解析时模块侧只认 GLOBAL，此处同口径：lookup_ok=false 时不做
   应用段/类别段匹配（uid<10000 例外——system 伪包仍参与 SYSTEM_APPS）。 */
static bool monitor_uncached(uid_t uid, pid_t tid) {
    char pkg[128];
    bool lookup_ok = fw_pkg_resolve(uid, tid, pkg, sizeof pkg);
    int user_id = (int)(uid / NSP_PER_USER_UID_STRIDE);
    bool is_sys = (uid < NSP_SYSTEM_APP_UID_MIN);
    for (;;) {
        uint64_t gen = config_read_begin();
        AppConfig* cfg = nullptr;
        AppConfig* cat = nullptr;
        if (is_sys) {
            cat = find_category_cfg_locked(true, user_id);
        } else if (lookup_ok) {
            cfg = find_app_cfg_locked(pkg, user_id);
            /* 类别层另需 pkg_resolvable：system/unknown 这类伪包不参与类别匹配
               （否则"解析不出包名"会误命中 [USER_APPS:*]）——与模块
               br_pick_category 的判据逐字一致 */
            if (pkg_resolvable(pkg)) {
                cat = sys_pkg_is_system(pkg) ? find_category_cfg_locked(true, user_id)
                                             : find_category_cfg_locked(false, user_id);
            }
        }
        bool on = (cfg && cfg->monitor_explicit) ? cfg->monitor
                  : (cat && cat->monitor_explicit) ? cat->monitor
                                                   : g_global_cfg.monitor;
        if (config_read_end(gen)) return on; /* 读期间发生发布：整体重试 */
    }
}

bool fw_config_monitor_for(uid_t uid, pid_t tid) {
    FwMonSlot* s = &g_mon_slots[uid % FW_MON_CACHE_SIZE];
    uint64_t gen = atomic_load_explicit(&g_gen, memory_order_acquire);
    for (;;) {
        uint64_t s1 = atomic_load_explicit(&s->seq, memory_order_acquire);
        if (s1 & 1) continue; /* 填充进行中：重试 */
        uid_t suid = s->uid;
        uint64_t sgen = s->gen;
        bool smon = s->monitor;
        uint64_t s2 = atomic_load_explicit(&s->seq, memory_order_acquire);
        if (s1 != s2) continue; /* 快照撕裂：重试 */
        if (suid == uid && sgen == gen) return smon;
        break;
    }

    bool on = monitor_uncached(uid, tid);
    pthread_mutex_lock(&g_mon_fill_lock);
    uint64_t seq = atomic_load_explicit(&s->seq, memory_order_relaxed);
    atomic_store_explicit(&s->seq, seq + 1, memory_order_release);
    s->uid = uid;
    s->gen = gen;
    s->monitor = on;
    atomic_store_explicit(&s->seq, seq + 2, memory_order_release);
    pthread_mutex_unlock(&g_mon_fill_lock);
    return on;
}

static volatile bool g_stop = false;
static pthread_t g_monitor_tid;
static bool g_thread_started = false;
/* 自唤醒管道：监听线程用 poll(...,5000) 等 inotify，只在循环顶部看 g_stop——
   不唤醒的话 shutdown 的 join 要干等最长 5s（实测每次启停多花 5s）。管道让
   关闭即时可见，join 立即返回。 */
static int g_wake[2] = {-1, -1};

static ModuleSub* find_sub(const char* name) {
    if (!name) return nullptr;
    for (int i = 0; i < MAX_MODULES; i++) {
        if (g_subs[i].used && strcmp(g_subs[i].name, name) == 0) return &g_subs[i];
    }
    return nullptr;
}

static ModuleSub* get_or_create_sub(const char* name) {
    ModuleSub* s = find_sub(name);
    if (s) return s;
    for (int i = 0; i < MAX_MODULES; i++) {
        if (!g_subs[i].used) {
            memset(&g_subs[i], 0, sizeof g_subs[i]);
            g_subs[i].used = true;
            strncpy(g_subs[i].name, name, sizeof g_subs[i].name - 1);
            return &g_subs[i];
        }
    }
    return nullptr;
}

/* 记录是否需要下发给该订阅。三类规则：
   - 结构记录（段头 / App-rules 文件归属）恒需要（规则要靠它们解释作用域）；
   - 规则记录按订阅的类型名过滤（订阅为空 = 申请全部）；
   - **模块自有配置记录按 owner 过滤**：MODULE_FILE 标记「以下属于哪个模块」，
     只有同名模块收得到（模块间配置隔离与规则隔离同等要求）。订阅只作用于 RULE，
     模块必须能拿回自己的配置，否则「模块不读文件」这条 ABI 约定无从落地。
   owner 由调用方跨记录维持（记录顺序即语义顺序）。 */
static bool rec_wanted(const ModuleSub* s, const NspCfgRec* r, const char** owner) {
    if (r->kind == NSP_CFG_REC_MODULE_FILE) {
        *owner = r->text;
        return *owner && strcmp(*owner, s->name) == 0;
    }
    if (r->kind == NSP_CFG_REC_MODULE_LINE)
        return *owner && strcmp(*owner, s->name) == 0;
    *owner = nullptr; /* 非模块配置记录：owner 段结束 */
    if (r->kind != NSP_CFG_REC_RULE) return true;
    if (s->type_count == 0) return true;
    if (!r->type) return false;
    for (int i = 0; i < s->type_count; i++) {
        if (strcmp(s->types[i], r->type) == 0) return true;
    }
    return false;
}

static char* rec_dup(const char* s) { return s ? strdup(s) : nullptr; }

static void view_free(ConfigView* v) {
    if (!v) return;
    for (int i = 0; i < v->count; i++) {
        free((char*)v->recs[i].file);
        free((char*)v->recs[i].type);
        free((char*)v->recs[i].text);
    }
    free(v->recs);
    free(v);
}

/* 用当前主视图新建一份自包含快照（记录与字符串均深拷贝）。OOM 返回 NULL
   （调用方置空视图，绝不交出半成品/已释放指针）。订阅为空 = 不过滤。 */
static ConfigView* view_create(const ModuleSub* s) {
    const char* owner = nullptr;
    int n = 0;
    for (int i = 0; i < g_rec_count; i++) {
        if (rec_wanted(s, &g_recs[i], &owner)) n++;
    }
    ConfigView* v = calloc(1, sizeof *v);
    if (!v) return nullptr;
    atomic_init(&v->refs, 1); /* 订阅表自持 1 份 */
    v->cfg.version = NSP_CFG_VIEW_VERSION;
    v->cfg.generation = atomic_load_explicit(&g_gen, memory_order_acquire);
    if (n == 0) return v;
    v->recs = calloc((size_t)n, sizeof(NspCfgRec));
    if (!v->recs) {
        free(v);
        return nullptr;
    }
    int k = 0;
    owner = nullptr; /* 第二遍必须重置：owner 是顺序状态，两遍要逐字一致 */
    for (int i = 0; i < g_rec_count; i++) {
        if (!rec_wanted(s, &g_recs[i], &owner)) continue;
        NspCfgRec r = g_recs[i];
        r.file = rec_dup(g_recs[i].file);
        r.type = rec_dup(g_recs[i].type);
        r.text = rec_dup(g_recs[i].text);
        if ((g_recs[i].file && !r.file) || (g_recs[i].type && !r.type) ||
            (g_recs[i].text && !r.text)) {
            v->count = k; /* 只释放已填条目，view_free 按 count 遍历 */
            view_free(v);
            return nullptr;
        }
        v->recs[k++] = r;
    }
    v->count = n;
    v->cfg.recs = v->recs;
    v->cfg.count = v->count;
    return v;
}

static void view_release(ConfigView* v) {
    if (!v) return;
    if (atomic_fetch_sub_explicit(&v->refs, 1, memory_order_acq_rel) == 1) view_free(v);
}

/* 用当前主视图重建某模块的下发视图（新快照，旧快照按引用延迟释放） */
static void rebuild_filter(ModuleSub* s) {
    ConfigView* nv = view_create(s);
    ConfigView* old = s->view;
    s->view = nv;
    view_release(old);
}

/* 两份主视图是否逐字相同（C11「无变化则跳过发布」的判据）。
   任一项不同即视为变化——**宁可多发布一次，不可漏发布**：漏发布 = 规则静默不
   生效。line_no 一并比对（App-rules 目录列举顺序变化会改变记录顺序，从而判为
   变化，只损失一次优化，不影响正确性）。 */
static bool recs_identical(const NspCfgRec* a, int an, const NspCfgRec* b, int bn) {
    if (an != bn) return false;
    for (int i = 0; i < an; i++) {
        if (a[i].kind != b[i].kind || a[i].enabled != b[i].enabled ||
            a[i].uid != b[i].uid || a[i].line_no != b[i].line_no)
            return false;
        const char* av[3] = {a[i].file, a[i].type, a[i].text};
        const char* bv[3] = {b[i].file, b[i].type, b[i].text};
        for (int k = 0; k < 3; k++) {
            if ((av[k] == nullptr) != (bv[k] == nullptr)) return false;
            if (av[k] && strcmp(av[k], bv[k]) != 0) return false;
        }
    }
    return true;
}

/* 读出主视图并换入；旧视图与旧过滤视图在推送完成后释放（见 publish）。
   also_nonrule：本批 inotify 事件里还含 uid.map / sys_pkgs.cache（非规则产物）——
   此时即便规则视图逐字未变也不能跳过：那两个全局表仍需刷新（见 C11 分流）。 */
static void reload_once(bool also_nonrule) {
    NspCfgRec* new_recs = nullptr;
    int new_count = 0;
    config_read_view(g_rules_path, &new_recs, &new_count);

    /* C11：重解析结果与当前发布视图逐字相同 → 整条发布路径（代际递增 / 索引
       重建 / 过滤视图重建 / 模块推送）都无意义，直接返回。首次装载
       （g_recs == nullptr）必须发布，否则模块拿不到初始配置。
       g_recs/g_rec_count 仅本线程与关停路径写，此处裸读安全。 */
    if (!also_nonrule && g_recs != nullptr &&
        recs_identical(new_recs, new_count, g_recs, g_rec_count)) {
        config_free_view(new_recs, new_count);
        return;
    }

    /* 先递增代际使框架侧派生缓存（monitor 决策）失效，再换入新索引：
       config_build_from_view 的 COW 发布会释放旧 AppConfig，缓存若仍以旧代际
       命中就会读到悬垂段指针（与模块 br_rules_apply_config 同序）。
       uid.map 变化已有独立事件分流（见 C11），此处重读仅作兜底。 */
    atomic_fetch_add_explicit(&g_gen, 1, memory_order_release);
    fw_pkg_reload();
    config_lock_write();
    config_build_from_view(new_recs, new_count);
    sys_pkg_refresh(); /* 重读 sys_pkgs.cache（injector 可能已更新落盘） */
    config_unlock_write();
    /* 内建规则引擎的 uid→AppConfig 指针缓存不在这里作废：容器会在发布临界区
       （旧读者已排空、新读者仍封锁）内经 config_set_publish_invalidate_hook
       自动作废——发布后补调会留出「命中已释放指针」的窗口 */

    pthread_mutex_lock(&g_lock);
    NspCfgRec* old_recs = g_recs;
    int old_count = g_rec_count;
    g_recs = new_recs;
    g_rec_count = new_count;
    /* 旧快照自包含（字符串深拷贝），换指针即可；持有者（在飞回调）按引用计数
       延迟释放，故此处 release 不会打断任何并发读 */
    for (int i = 0; i < MAX_MODULES; i++) {
        if (g_subs[i].used) rebuild_filter(&g_subs[i]);
    }
    pthread_mutex_unlock(&g_lock);

    /* 推送：钩子内新旧视图都有效（loader 遍历活跃模块调用各自监听器） */
    if (g_reload_hook) g_reload_hook();

    config_free_view(old_recs, old_count);
}

/* ---- 事件分流（C11）----
   配置目录里除规则文件外还有两个**非规则**产物：uid.map（injector 每启动一个应用
   就 tmp+rename 写入，高峰期密集）与 sys_pkgs.cache。旧实现对任一事件都做整份
   重解析 + 重建 Trie + 作废 2048 槽 uid 缓存 + 推送所有模块——应用启动高峰期会把
   FUSE 热路径的缓存持续冷启。故按 ev->name 分流：只有规则类事件才走全量 reload_once。 */

typedef enum {
    CFG_EV_PKG = 0, /* uid.map：只重装 uid→包名映射 */
    CFG_EV_SYS_PKG, /* sys_pkgs.cache：只刷新系统包缓存 */
    CFG_EV_RULES,   /* 其余（含无名/目录级事件）：全量重载（保守） */
} CfgEvKind;

static CfgEvKind cfg_ev_classify(const char* name) {
    if (!name || !name[0]) return CFG_EV_RULES; /* 无名事件（目录级）→ 保守全量 */
    if (strcmp(name, "uid.map") == 0 || strcmp(name, "uid.map.tmp") == 0) return CFG_EV_PKG;
    if (strcmp(name, "sys_pkgs.cache") == 0 || strcmp(name, "sys_pkgs.cache.tmp") == 0)
        return CFG_EV_SYS_PKG;
    return CFG_EV_RULES;
}

/* 非规则产物的轻量刷新：只更新对应全局表并递增代际，让 monitor 决策缓存失效
   （uid→包名 / 系统包集合变化会改变三层合并结果），**不**重解析规则、不重建索引、
   不推送模块。 */
static void reload_pkg_only(void) {
    atomic_fetch_add_explicit(&g_gen, 1, memory_order_release);
    fw_pkg_reload();
}

static void reload_sys_pkg_only(void) {
    atomic_fetch_add_explicit(&g_gen, 1, memory_order_release);
    sys_pkg_refresh();
}

/* 模块目录 watch 对账。模块目录**可能不存在**（部署里没有模块），此时无 watch
   可挂但不算「未就位」——否则定时兜底会每 10s 白做一次全量重载。 */
static bool mod_watch_sync(int ifd, CfgDirWatch* ws, int* n) {
    const char* d = config_modules_dir();
    if (!d || access(d, F_OK) != 0) {
        *n = 0;
        return true;
    }
    return cfg_watch_sync_subdirs(ifd, d, ws, n);
}

/* 监听规则文件所在目录 + 各 App-rules* 子目录 + 模块目录（各 <模块名>/ 子目录，
   模块自有配置 <模块名>.conf 就在其中——模块自己不再跑 inotify，热重载靠这里） */
static void* config_monitor_thread(void* arg) {
    (void)arg;
    int inotify_fd = -1;
    int wd = -1;
    int wd_mod = -1; /* 模块目录顶层：只看子目录增删，用于重挂各模块目录的 watch */
    CfgDirWatch appw[CFG_WATCH_MAX];
    int appn = 0;
    bool appw_ok = false;
    CfgDirWatch modw[CFG_WATCH_MAX];
    int modn = 0;
    bool modw_ok = false;
    time_t last_fallback = 0;
    while (!g_stop && !g_log_shutdown) {
        if (inotify_fd < 0) {
            inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
            if (inotify_fd < 0) {
                sleep(2);
                continue;
            }
            appn = 0; /* 新 fd：旧 watch 全部作废，重新对账 */
            modn = 0;
            wd = -1;
            wd_mod = -1;
            appw_ok = false;
            modw_ok = false;
        }
        if (wd_mod < 0) {
            wd_mod = inotify_add_watch(inotify_fd, config_modules_dir(), NSP_CFG_WATCH_MASK);
            /* 模块目录不存在不是错误（无模块部署）：保持 -1，靠 modw 对账与
               定时兜底；不因此关掉整个监听 fd（规则文件仍要监听） */
        }
        if (wd < 0) {
            char dir[PATH_MAX];
            strncpy(dir, g_rules_path, sizeof(dir) - 1);
            dir[sizeof(dir) - 1] = '\0';
            char* slash = strrchr(dir, '/');
            if (!slash) {
                close(inotify_fd);
                inotify_fd = -1;
                sleep(2);
                continue;
            }
            *slash = '\0';
            wd = inotify_add_watch(inotify_fd, dir, NSP_CFG_WATCH_MASK);
            if (wd < 0) {
                close(inotify_fd);
                inotify_fd = -1;
                sleep(2);
                continue;
            }
        }
        if (!appw_ok) appw_ok = cfg_watch_sync(inotify_fd, CONFIG_DIR, appw, &appn);
        if (!modw_ok) modw_ok = mod_watch_sync(inotify_fd, modw, &modn);
        struct pollfd pfds[2] = {{.fd = inotify_fd, .events = POLLIN},
                                 {.fd = g_wake[0], .events = POLLIN}};
        int pr = poll(pfds, 2, 5000);
        if (pr >= 0 && pfds[1].revents) break; /* 关闭唤醒：立即退出，不等超时 */
        if (pr < 0) {
            if (errno == EINTR) continue;
            if (wd >= 0) inotify_rm_watch(inotify_fd, wd);
            close(inotify_fd);
            inotify_fd = -1;
            continue;
        }
        if (pr == 0) {
            /* 超时：App-rules / 模块目录 watch 未就位时重试对账；仍不齐则定时重扫
               兜底（节流到 10s，避免 watch 超限时持续整份重载 + 下发模块） */
            if (!appw_ok || !modw_ok) {
                appw_ok = cfg_watch_sync(inotify_fd, CONFIG_DIR, appw, &appn);
                modw_ok = mod_watch_sync(inotify_fd, modw, &modn);
                time_t now = time(nullptr);
                if ((!appw_ok || !modw_ok) && now - last_fallback >= 10) {
                    last_fallback = now;
                    reload_once(false); /* 定时兜底重扫：无并发的非规则事件 */
                }
            }
            continue;
        }
        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t len = read(inotify_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            if (wd >= 0) inotify_rm_watch(inotify_fd, wd);
            close(inotify_fd);
            inotify_fd = -1;
            continue;
        }
        if (len == 0) continue;
        int inval_wd = -1;
        bool top_change = false;
        bool mod_top_change = false;
        bool ev_rules = false, ev_pkg = false, ev_sys = false;
        for (char* p = buf; p < buf + len;) {
            struct inotify_event* ev = (struct inotify_event*)p;
            if (ev->mask & IN_IGNORED) inval_wd = ev->wd;
            if (ev->wd == wd) {
                if (ev->mask & (IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM))
                    top_change = true; /* App-rules 目录可能新增/移除：重新对账 watch */
                switch (cfg_ev_classify(ev->name)) {
                case CFG_EV_PKG:
                    ev_pkg = true;
                    break;
                case CFG_EV_SYS_PKG:
                    ev_sys = true;
                    break;
                default:
                    ev_rules = true;
                    break;
                }
            } else if (ev->wd == wd_mod) {
                /* 模块目录顶层：模块可能被增删 → 重新对账各模块目录的 watch；
                   模块目录名即模块名，配置随之增删，保守走全量重载 */
                mod_top_change = true;
                ev_rules = true;
            } else {
                /* App-rules / 模块目录内的事件即配置变更；队列溢出 / IN_IGNORED
                   （wd 对不上）也落这里——保守按规则处理 */
                ev_rules = true;
            }
            p += sizeof(struct inotify_event) + ev->len;
        }
        sleep(1); /* 归并写者连击：等待写者落定再读 */
        if (ev_rules)
            /* 规则类：全量重解析 + 重建索引 + 推送所有模块。同批若还含
               uid.map / sys_pkgs.cache 事件则即便规则视图未变也不跳过
               （那两个全局表仍需刷新） */
            reload_once(ev_pkg || ev_sys);
        else if (ev_pkg)
            reload_pkg_only();
        else if (ev_sys)
            reload_sys_pkg_only();
        if (inval_wd == wd) wd = -1;
        if (inval_wd == wd_mod) wd_mod = -1;
        for (int i = 0; i < appn; i++)
            if (appw[i].wd == inval_wd) appw[i].wd = -1;
        for (int i = 0; i < modn; i++)
            if (modw[i].wd == inval_wd) modw[i].wd = -1;
        if (top_change) appw_ok = cfg_watch_sync(inotify_fd, CONFIG_DIR, appw, &appn);
        if (mod_top_change || !modw_ok) modw_ok = mod_watch_sync(inotify_fd, modw, &modn);
    }
    if (inotify_fd >= 0) {
        if (wd >= 0) inotify_rm_watch(inotify_fd, wd);
        if (wd_mod >= 0) inotify_rm_watch(inotify_fd, wd_mod);
        for (int i = 0; i < appn; i++)
            if (appw[i].wd >= 0) inotify_rm_watch(inotify_fd, appw[i].wd);
        for (int i = 0; i < modn; i++)
            if (modw[i].wd >= 0) inotify_rm_watch(inotify_fd, modw[i].wd);
        close(inotify_fd);
    }
    return nullptr;
}

int fw_config_init(const char* rules_path) {
    strncpy(g_rules_path, rules_path ? rules_path : "", sizeof(g_rules_path) - 1);
    /* 只读消费方：不创建 App-rules 目录、不做 pm 探测（pm list users 需 binder
       通信 system_server，在 fuse_daemon 受限环境会挂起，而配置加载在
       FUSE 会话启动前同步执行 → 会话永不启动；热重载同理会卡死） */
    config_set_allow_app_rules_mkdir(false);
    config_set_scan_users_skip_pm(true);
    /* 框架自建索引所需的两项初始化（与模块 br_rules_init 同一套）：
       - sys_pkg_init(false)：SYSTEM_APPS 类别判定只读 sys_pkgs.cache，永不 popen；
       - config_init_lock()：自建索引走 config_lock_write 与冷路径读者互斥；
       - fw_pkg_reload()：装载 uid.map，供 uid→包名与 require 的 MONITOR 合并。 */
    sys_pkg_init(false);
    config_init_lock();
    fw_pkg_reload();
    if (g_rules_path[0] == '\0') {
        LOG_WRN("未提供 --rules= 路径，框架配置视图为空（模块将收不到任何规则）");
        return 0;
    }
    reload_once(false); /* 首次装载：g_recs == nullptr，必发布初始视图 */
    g_stop = false;
    if (pipe2(g_wake, O_NONBLOCK | O_CLOEXEC) != 0) g_wake[0] = g_wake[1] = -1;
    if (pthread_create(&g_monitor_tid, nullptr, config_monitor_thread, nullptr) == 0) {
        g_thread_started = true;
    } else {
        LOG_WRN("配置监控线程创建失败，规则热重载不可用");
    }
    LOG("框架配置已加载: %d 条记录 (rules=%s)", g_rec_count, g_rules_path);
    return 0;
}

void fw_config_shutdown(void) {
    g_stop = true;
    if (g_wake[1] >= 0) (void)!write(g_wake[1], "x", 1); /* 唤醒 poll，避免 join 干等 */
    if (g_thread_started) {
        pthread_join(g_monitor_tid, nullptr);
        g_thread_started = false;
    }
    if (g_wake[0] >= 0) close(g_wake[0]);
    if (g_wake[1] >= 0) close(g_wake[1]);
    g_wake[0] = g_wake[1] = -1;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < MAX_MODULES; i++) {
        if (!g_subs[i].used) continue;
        view_release(g_subs[i].view);
        g_subs[i].view = nullptr;
        for (int t = 0; t < g_subs[i].type_count; t++) free(g_subs[i].types[t]);
        free(g_subs[i].types);
        g_subs[i].types = nullptr;
        g_subs[i].type_count = 0;
        g_subs[i].used = false;
    }
    NspCfgRec* recs = g_recs;
    int count = g_rec_count;
    g_recs = nullptr;
    g_rec_count = 0;
    pthread_mutex_unlock(&g_lock);
    config_free_view(recs, count);
    fw_pkg_shutdown();
}

const NspModuleConfig* fw_config_view_acquire(const char* module_name) {
    if (!module_name) return nullptr;
    pthread_mutex_lock(&g_lock);
    ModuleSub* s = find_sub(module_name);
    /* 已注册但尚未建视图（只设了监听器、未订阅；或重载前的首份推送）时补建：
       「订阅为空 = 不过滤（申请全部）」是契约，故空订阅视图 = 全量记录。
       旧实现在此交出未构建的 s->cfg（空视图），契约不符且首次推送拿不到规则。 */
    if (s && !s->view) s->view = view_create(s);
    const NspModuleConfig* out = nullptr;
    if (s && s->view) {
        /* 快照不可变、代际在创建时固化；取用时抬引用，回调期间不会被释放 */
        atomic_fetch_add_explicit(&s->view->refs, 1, memory_order_relaxed);
        out = &s->view->cfg;
    }
    pthread_mutex_unlock(&g_lock);
    return out;
}

void fw_config_view_release(const NspModuleConfig* view) {
    if (!view) return;
    /* NspModuleConfig 是 ConfigView 的末成员：经容器偏移回退取宿主 */
    ConfigView* v = (ConfigView*)(void*)((char*)(uintptr_t)view - offsetof(ConfigView, cfg));
    view_release(v);
}

void fw_config_set_subscription(const char* module_name, const char* const* types, int count) {
    if (!module_name) return;
    pthread_mutex_lock(&g_lock);
    ModuleSub* s = get_or_create_sub(module_name);
    if (s && s->type_count == 0 && count > 0) {
        s->types = calloc((size_t)count, sizeof(char*));
        if (s->types) {
            for (int i = 0; i < count; i++) s->types[i] = types[i] ? strdup(types[i]) : nullptr;
            s->type_count = count;
            rebuild_filter(s);
        }
    }
    pthread_mutex_unlock(&g_lock);
}

void fw_config_set_listener(const char* module_name, void (*cb)(const NspModuleConfig*)) {
    if (!module_name) return;
    pthread_mutex_lock(&g_lock);
    ModuleSub* s = get_or_create_sub(module_name);
    if (s) s->listener = cb;
    pthread_mutex_unlock(&g_lock);
}

void (*fw_config_listener_for(const char* module_name))(const NspModuleConfig*) {
    if (!module_name) return nullptr;
    pthread_mutex_lock(&g_lock);
    ModuleSub* s = find_sub(module_name);
    void (*cb)(const NspModuleConfig*) = s ? s->listener : nullptr;
    pthread_mutex_unlock(&g_lock);
    return cb;
}

void fw_config_forget_module(const char* module_name) {
    if (!module_name) return;
    pthread_mutex_lock(&g_lock);
    ModuleSub* s = find_sub(module_name);
    if (s) {
        view_release(s->view);
        for (int t = 0; t < s->type_count; t++) free(s->types[t]);
        free(s->types);
        memset(s, 0, sizeof *s);
    }
    pthread_mutex_unlock(&g_lock);
}

void fw_config_set_reload_hook(void (*hook)(void)) {
    g_reload_hook = hook;
}
