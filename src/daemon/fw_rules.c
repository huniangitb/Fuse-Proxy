#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * fw_rules.c — 框架内建规则引擎（见 fw_rules.h）
 *
 * 由原 basic_rules 模块的 br_rules.c 原样搬入：规则匹配语义逐行未改，
 * 只做两件事——① uid→包名改由框架统一解析（fw_pkg.c）而非模块自带
 * uid.map/proc 双份实现；② 配置索引由 fw_config 构建，本文件只在重载时
 * 作废自有指针缓存。
 *
 * 内部符号沿用 `br_` 前缀（basic_rules 时代的命名）——它们是本文件私有的
 * static 量与私有结构，不跨文件、不跨 ABI，故不做批量改名以免噪音。
 */
#include "fw_rules.h"      /* NspQueryCtx/NspPathDecision + nsp_module.h（LOG 宏） */
#include "fw_pkg.h"        /* fw_pkg_resolve：包名解析归框架 */
#include "config_parser.h" /* AppConfig / find_*_cfg_locked / config_read_* */
#include "path_vars.h"     /* pkg_resolvable / has_path_var / expand_path_vars */
#include "sys_pkg.h"       /* sys_pkg_is_system（SYSTEM_APPS 类别判定） */
#include "common.h"        /* LOG 宏 / common_default_real_path / common_sandbox_path */
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fnmatch.h>
#include <pthread.h>
#include <dirent.h>

/* ============ 引擎内部状态（从 vfs_core.c 适配，不再依赖 fuse_context） ============ */

static char g_br_rules_path[PATH_MAX] = {0};
static bool g_br_disable_sandbox = false;
/* 无自有监控线程：配置读取与监听已收归框架（fw_config），模块经
   config_update 监听器被动接收下发的视图——dlclose 前无需 join 任何线程 */

#define UID_CACHE_SIZE 2048
/* uid → AppConfig 缓存槽。热路径（每次 resolve/probe 均查）用 seqlock 无锁读：
   - seq：_Atomic 序号，奇数=写者进行中（读者重试），偶数=稳定快照。
     读者零原子写，多线程并发读不产生缓存行颠簸（原 rwlock 读路径每次
     rdlock/unlock 均原子改写同一缓存行，高并发下成瓶颈）；
   - 写者（缓存填充/重载失效）取 wlock 互斥 + seq 奇数/偶数翻转。
   所有调用方（fw_rules_resolve/fw_rules_probe）均持 config_lock_read，
   cfg 指针不会被重载并发释放；seqlock 仅需防止并发填充互相撕裂。 */
typedef struct {
    pthread_mutex_t wlock; /* 写者互斥（填充/失效），读侧无锁 */
    _Atomic uint64_t seq;  /* seqlock 序号 */
    uid_t uid;
    AppConfig* cfg;
    AppConfig* cat; /* 命中的类别段（USER_APPS/SYSTEM_APPS，可 NULL；
                                     与 cfg 同代际、同样仅作废不保留） */
    uint64_t gen;   /* 填充时的配置代际（g_br_cfg_gen）：重载后即过期 */
} UidCacheSlot;
static UidCacheSlot g_uid_cache[UID_CACHE_SIZE];

/* ============ readdir 目录级 probe 缓存 ============
   fw_rules_probe 是 readdir 逐条目过滤的热路径：同一父目录的连续条目共享一次
   「根→父目录」trie 下降与 uid→cfg 解析，命中后仅按最后一段查子节点，
   避免每条目重复全路径 trie 遍历与 uid 缓存锁（大目录 O(n) 锁风暴）。
   线程私有（FUSE 多线程各自独立，readdir 循环在单线程内顺序执行）；
   配置重载（g_br_cfg_gen 递增，写锁内）后失效，杜绝 trie/cfg 悬垂。 */
typedef struct {
    bool valid;
    uint64_t gen; /* 配置代际（发布期钩子 fw_rules_invalidate_caches 递增） */
    uid_t uid;
    pid_t pid;
    char dir[PATH_MAX]; /* 父目录 sub_path（"/" 或 "/a/b"） */
    AppConfig* cfg;     /* 命中的应用段（可 NULL=system） */
    AppConfig* cat;     /* 命中的类别段（可 NULL），与 cfg 同代际 */
    char current_pkg[128];
    const TrieNode* app_dir_node; /* app trie 父目录最深节点（可 NULL） */
    bool app_dir_hidden;          /* 根→父目录累积 hidden（app） */
    const TrieNode* cat_dir_node; /* 类别 trie 父目录最深节点（可 NULL） */
    bool cat_dir_hidden;          /* 根→父目录累积 hidden（类别） */
    const TrieNode* g_dir_node;   /* global trie 父目录最深节点（可 NULL） */
    bool g_dir_hidden;            /* 根→父目录累积 hidden（global） */
} BrProbeDirCache;

static _Thread_local BrProbeDirCache g_probe_dir_cache;
static _Atomic(uint64_t) g_br_cfg_gen = 0; /* 配置代际：重载（写锁内）递增，
                                                probe 缓存命中无锁路径据此校验 */

static void clear_uid_cache(void) {
    for (int i = 0; i < UID_CACHE_SIZE; i++) {
        UidCacheSlot* s = &g_uid_cache[i];
        pthread_mutex_lock(&s->wlock);
        /* 写者进入：seq → 奇数（读者重试） */
        atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                              memory_order_release);
        /* 作废 cfg/cat（重载后旧 AppConfig 已被 COW 发布释放，留着即悬垂）
           + gen=0 标记过期。包名不在此缓存：它归 fw_pkg.c，自带跨重载缓存 */
        s->cfg = nullptr;
        s->cat = nullptr; /* 类别指针同代际，同样作废（防悬垂） */
        s->gen = 0;
        atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                              memory_order_release);
        pthread_mutex_unlock(&s->wlock);
    }
}

/* 配置发布临界区内的派生缓存作废：经 config_set_publish_invalidate_hook 注册，
   由 config_publish 在「旧代际读者已排空、新读者仍被封锁」的窗口内调用（见
   config_parser.h 的钩子契约）。这是唯一的作废安全窗口：发布前作废，读者会把
   旧 AppConfig 指针以新代际重新缓存（COW 释放后即悬垂）；发布后作废，则留出
   命中已释放指针的窗口。
   调用方已持 config 写锁，此处**不得**再取 config 锁。
   作废范围：uid→(AppConfig, 类别) 指针缓存（seqlock 读者按代际校验）；线程本地
   的 readdir probe 目录缓存（_Thread_local，本线程清不到）靠同一代际失配失效。 */
void fw_rules_invalidate_caches(void) {
    atomic_fetch_add_explicit(&g_br_cfg_gen, 1, memory_order_release);
    clear_uid_cache();
}

int fw_rules_init(const char* rules_path, bool disable_sandbox) {
    strncpy(g_br_rules_path, rules_path ? rules_path : "", sizeof(g_br_rules_path) - 1);
    g_br_disable_sandbox = disable_sandbox;
    for (int i = 0; i < UID_CACHE_SIZE; i++) {
        pthread_mutex_init(&g_uid_cache[i].wlock, nullptr);
        atomic_store_explicit(&g_uid_cache[i].seq, 0, memory_order_relaxed);
        g_uid_cache[i].uid = 0;
        g_uid_cache[i].cfg = nullptr;
        g_uid_cache[i].cat = nullptr;
        g_uid_cache[i].gen = 0;
    }
    /* 配置不在此读取：fw_config 在 init 之后（同一次启动流程内）构建索引并
       触发发布，本引擎的派生缓存作废挂在发布临界区内（钩子）。
       sys_pkg/config lock 的初始化也归 fw_config。 */
    config_set_publish_invalidate_hook(fw_rules_invalidate_caches);
    LOG("规则引擎已就绪 (rules=%s, sandbox=%s)",
        g_br_rules_path[0] ? g_br_rules_path : "(none)", disable_sandbox ? "off" : "on");
    return 0;
}

void fw_rules_exit(void) {
    /* 无自有线程、无自有索引：索引与锁归 fw_config，配置内存由它释放 */
}

/* ============ uid → AppConfig 解析（适配 vfs_get_app_cfg） ============ */

/* 类别段拾取（三层合并应用>类别>全局的中间层）：
 * - uid<10000 / pkg=="system" → 系统 → SYSTEM_APPS（忽略 user_id，
 *   对所有用户系统应用生效）；
 * - 可解析包名 → pm 系统表命中（GMS 类高 uid 系统应用）归 SYSTEM_APPS，
 *   否则 USER_APPS[user_id]，无则 USER_APPS[-1] 跨用户 fallback；
 * - 不可解析（unknown/zygote/过短）→ NULL（仅 GLOBAL，fail-safe）。
 * 无类别段时直接 NULL：零额外开销、行为与旧版一致 */
static AppConfig* br_pick_category(uid_t uid, int user_id, const char* base_pkg) {
    if (!config_has_category_rules()) return nullptr;
    if (uid < NSP_SYSTEM_APP_UID_MIN || strcmp(base_pkg, "system") == 0)
        return find_category_cfg_locked(true, user_id);
    if (!pkg_resolvable(base_pkg)) return nullptr;
    if (sys_pkg_is_system(base_pkg)) return find_category_cfg_locked(true, user_id);
    return find_category_cfg_locked(false, user_id);
}

/* uid → (应用段, 类别段)。包名由框架统一解析（fw_pkg.c：uid.map → /proc 回退，
   与模块时代同源同序），本函数只做段匹配 + 指针缓存：
   命中路径（含负面结果）缓存 uid→(cfg,cat)，避免每请求线性扫 g_app_cfgs。 */
static AppConfig* br_get_app_cfg(uid_t uid, pid_t tid, char* current_pkg_out, AppConfig** cat_out) {
    if (cat_out) *cat_out = nullptr;
    char pkg[128];
    bool lookup_ok = fw_pkg_resolve(uid, tid, pkg, sizeof pkg);
    strncpy(current_pkg_out, pkg, 127);
    current_pkg_out[127] = '\0';

    if (uid < NSP_SYSTEM_APP_UID_MIN) {
        /* 系统伪包（uid<10000，fw_pkg 已给出 "system"）：默认只参与 SYSTEM_APPS
           类别层。但用户会在 injector.conf 里给系统应用写显式应用段（如
           [com.android.settings] HIDE ...），而伪包名永远匹配不到应用段——
           实机验证：GLOBAL/类别段 HIDE 生效、应用段不生效。这里用
           fw_pkg_resolve_exact 解析真实包名（uid.map → cmdline）后再匹配
           应用段；解析不出或未命中时维持伪包口径。 */
        int user_id = (int)(uid / NSP_PER_USER_UID_STRIDE);
        char exact[128];
        if (fw_pkg_resolve_exact(uid, tid, exact, sizeof exact) && pkg_resolvable(exact)) {
            AppConfig* sys_matched = find_app_cfg_locked(exact, user_id);
            if (sys_matched) {
                strncpy(current_pkg_out, exact, 127);
                current_pkg_out[127] = '\0';
                if (cat_out) *cat_out = br_pick_category(uid, user_id, exact);
                return sys_matched;
            }
        }
        if (cat_out)
            *cat_out = br_pick_category(uid, user_id, pkg);
        return nullptr;
    }

    int slot = uid % UID_CACHE_SIZE;
    UidCacheSlot* s = &g_uid_cache[slot];
    uint64_t cur_gen = atomic_load_explicit(&g_br_cfg_gen, memory_order_acquire);

    /* seqlock 无锁读：seq 偶数且两次读相等 = 稳定快照（读者零原子写，
       多线程并发读无缓存行颠簸）。命中（含负面：scfg 可为 NULL）直接返回；
       代际过期则落到下方重算（重载后旧 AppConfig 已释放，不可复用指针）。 */
    for (;;) {
        uint64_t s1 = atomic_load_explicit(&s->seq, memory_order_acquire);
        if (s1 & 1) continue; /* 写者进行中：重试 */
        uid_t suid = s->uid;
        AppConfig* scfg = s->cfg;
        AppConfig* scat = s->cat;
        uint64_t sgen = s->gen;
        uint64_t s2 = atomic_load_explicit(&s->seq, memory_order_acquire);
        if (s1 != s2) continue; /* 快照不一致：重试 */
        if (suid == uid && sgen == cur_gen) {
            if (cat_out) *cat_out = scat;
            return scfg;
        }
        break;
    }

    int user_id = (int)(uid / NSP_PER_USER_UID_STRIDE);
    AppConfig* matched = nullptr;
    AppConfig* cat = nullptr;
    if (lookup_ok) {
        /* 包名不可解析（过短/zygote/<pre-）时 lookup_ok=false，类别层与
           应用段都不参与，仅 [GLOBAL] 生效——与旧实现同一 fail-safe 口径 */
        matched = find_app_cfg_locked(pkg, user_id);
        if (pkg_resolvable(pkg)) cat = br_pick_category(uid, user_id, pkg);
    }
    if (cat_out) *cat_out = cat;

    pthread_mutex_lock(&s->wlock);
    atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                          memory_order_release);
    s->uid = uid;
    s->cfg = matched;
    s->cat = cat;
    s->gen = cur_gen;
    atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                          memory_order_release);
    pthread_mutex_unlock(&s->wlock);
    return matched;
}

/* ============ 规则决策（适配 vfs_core 的 Trie + 线性通道） ============ */

/* 包名基础名比较：调用方 cmdline 可能带进程后缀（com.x:push），而
   /Android/data 下的目录名恒为包名本身——不比基础名会把"自己"判成"他包"，
   让应用连自己的 data 都打不开 */
static bool br_pkg_same_base(const char* a, const char* b) {
    if (!a || !b) return false;
    size_t la = strcspn(a, ":");
    size_t lb = strcspn(b, ":");
    return la == lb && la > 0 && strncmp(a, b, la) == 0;
}

/* 跨应用隔离：/Android/data/<包>|/Android/obb/<包> 下的**他包**条目对当前
   调用方既不可列举也不可打开（resolve 与 probe 同口径，与 HIDE 的"看不见 =
   打不开"一致）。旧实现只在 probe（readdir 条目过滤）生效，任何按名打开的
   命令（ls /sdcard/Android/data/<他包>、cat、copy、find -exec…）都能读到内容
   ——用户报障的绕过点即在此，故 resolve 侧必须同样判。
   不隔离的情形：调用方包名不可解析（空/system/unknown，root 与系统工具）、
   [GLOBAL] ALLOW_CROSS_APP_DATA ON（用户显式放行，等于恢复旧行为）。 */
bool fw_rules_cross_app_isolated(void) { return !g_global_cfg.allow_cross_app_data; }

static bool br_is_other_app_pkg(const char* sub_path, const char* current_pkg) {
    if (!current_pkg || !current_pkg[0]) return false;
    if (strcmp(current_pkg, "system") == 0 || strcmp(current_pkg, "unknown") == 0) return false;
    if (g_global_cfg.allow_cross_app_data) return false;
    const char* prefixes[] = {"/Android/data/", "/Android/obb/"};
    for (int i = 0; i < 2; i++) {
        size_t plen = strlen(prefixes[i]);
        if (strncmp(sub_path, prefixes[i], plen) == 0) {
            const char* pkg_start = sub_path + plen;
            if (*pkg_start == '\0') return false;
            const char* slash = strchr(pkg_start, '/');
            size_t pkg_len = slash ? (size_t)(slash - pkg_start) : strlen(pkg_start);
            if (pkg_len > 0 && pkg_len < 256) {
                char target_pkg[256];
                memcpy(target_pkg, pkg_start, pkg_len);
                target_pkg[pkg_len] = '\0';
                if (!br_pkg_same_base(target_pkg, current_pkg)) return true;
            }
            break;
        }
    }
    return false;
}

static void br_trie_resolve(AppConfig* cfg, AppConfig* cat, const char* sub_path, FwRulesTrieMatch* out) {
    if (!out) return;
    out->valid = true;
    out->hidden = false;
    out->ro = false;
    out->has_redir = false;
    out->redir_scope = BR_SCOPE_NONE;
    out->redir[0] = '\0';
    out->ftp_app[0] = '\0';
    out->ftp_cat[0] = '\0';
    out->ftp_global[0] = '\0';
    out->app_node = NULL;
    out->cat_node = NULL;
    out->global_node = NULL;
    if (cfg && cfg->trie_root) {
        bool h = false, r = false;
        char redir[PATH_MAX];
        redir[0] = '\0';
        char ftp[64];
        ftp[0] = '\0';
        /* trie_lookup_full：一次下降同时取得 hidden/ro/redir/ftp 与完整匹配节点，
           供 resolve 复用判定 virtual_ancestor/redirect_target（省重复遍历） */
        out->app_node = trie_lookup_full(cfg->trie_root, sub_path, &h, &r, redir, sizeof(redir),
                                         ftp, sizeof(ftp));
        if (h) out->hidden = true;
        if (r) out->ro = true;
        if (ftp[0] != '\0') {
            strcpy(out->ftp_app, ftp); /* 源为 64B 栈缓冲，NUL 结尾 */
        }
        if (redir[0] != '\0') {
            out->has_redir = true;
            out->redir_scope = BR_SCOPE_APP; /* 记录作用域：供 br_to_real_path 与
                                                线性通道按「作用域优先」比较 */
            strcpy(out->redir, redir); /* 源为 PATH_MAX 栈缓冲，NUL 结尾 */
        }
    }
    /* 类别层（USER_APPS/SYSTEM_APPS）：hidden/ro 取并集，redir 仅 app 未命中时补 */
    if (cat && cat->trie_root) {
        bool h = false, r = false;
        char redir[PATH_MAX];
        redir[0] = '\0';
        char ftp[64];
        ftp[0] = '\0';
        out->cat_node = trie_lookup_full(cat->trie_root, sub_path, &h, &r, redir, sizeof(redir),
                                         ftp, sizeof(ftp));
        if (h) out->hidden = true;
        if (r) out->ro = true;
        if (ftp[0] != '\0') {
            strcpy(out->ftp_cat, ftp);
        }
        if (!out->has_redir && redir[0] != '\0') {
            out->has_redir = true;
            out->redir_scope = BR_SCOPE_CAT;
            strcpy(out->redir, redir); /* 源为 PATH_MAX 栈缓冲，NUL 结尾 */
        }
    }
    if (g_global_cfg.trie_root) {
        bool h = false, r = false;
        char redir[PATH_MAX];
        redir[0] = '\0';
        char ftp[64];
        ftp[0] = '\0';
        out->global_node = trie_lookup_full(g_global_cfg.trie_root, sub_path, &h, &r, redir,
                                            sizeof(redir), ftp, sizeof(ftp));
        if (h) out->hidden = true;
        if (r) out->ro = true;
        if (ftp[0] != '\0') {
            strcpy(out->ftp_global, ftp); /* 源为 64B 栈缓冲，NUL 结尾 */
        }
        if (!out->has_redir && redir[0] != '\0') {
            out->has_redir = true;
            out->redir_scope = BR_SCOPE_GLOBAL;
            strcpy(out->redir, redir); /* 源为 PATH_MAX 栈缓冲，NUL 结尾 */
        }
    }
}

/* 作用域 → 该层的 AppConfig（应用段/类别段/[GLOBAL]） */
static AppConfig* br_scope_cfg(AppConfig* cfg, AppConfig* cat, BrRuleScope scope) {
    switch (scope) {
        case BR_SCOPE_APP: return cfg;
        case BR_SCOPE_CAT: return cat;
        case BR_SCOPE_GLOBAL: return &g_global_cfg;
        default: return NULL;
    }
}

/* 隐藏判定的静态部分（不触碰 cfg/g_global_cfg 数据，锁外安全）：
   CONFIG_DIR 前缀恒隐藏；Android 骨架目录恒不隐藏（is_skel_out 输出）；
   tm.hidden（trie 结果）。
   动态 hide 线性扫描（访问 hide_rules 数组）不在此列。
   注意：跨应用隔离（br_is_other_app_pkg）与隐藏**同口径**，但不在本函数
   判定——隐藏是"所有访问者一视同仁"的静态事实，隔离依赖调用方身份与沙盒
   状态：resolve 侧走 br_isolation_blocks()（沙盒生效时让位），probe 侧各路径
   显式叠加同一判据（readdir 条目过滤）。旧实现只在 probe 过滤列举、resolve
   放过，等于任何按名打开都能读到 /Android/data/<他包>/ 的内容。 */
static bool br_hidden_static_part(const char* sub_path, const char* current_pkg,
                                  const FwRulesTrieMatch* tm, bool* is_skel_out) {
    if (is_skel_out) *is_skel_out = false;
    if (strncmp(sub_path, CONFIG_DIR, strlen(CONFIG_DIR)) == 0) return true;
    if (strcmp(sub_path, "/Android") == 0 || strcmp(sub_path, "/Android/") == 0 ||
        strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0 ||
        strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0) {
        if (is_skel_out) *is_skel_out = true;
        return false;
    }
    if (tm && tm->valid && tm->hidden) return true;
    return false;
}

/* 线性（通配/变量）规则匹配的**单点实现**：hide 与 ro 共用，应用/类别/全局三层
   共用同一段逻辑（原先是 6 份逐字复制——A9/C7 式的漂移源，一处语义改动会漏改其余）。
   scope 是变量展开的**专属作用域**：类别段传 cat，应用段与 GLOBAL 段规则传 cfg
   （三层变量可见性语义见 docs/config.md §5——应用变量对类别/GLOBAL 规则不可见）。
   展开放不下（截断）一律丢弃该规则：截断成更短前缀会放大命中范围。 */
static bool br_linear_match(char* const* rules, int count, const char* sub_path,
                            const char* current_pkg, AppConfig* scope) {
    for (int i = 0; i < count; i++) {
        if (!rules[i]) continue;
        const char* rule = rules[i];
        char expanded[PATH_MAX];
        const char* match_str = rule;
        if (has_path_var(rule)) {
            if (!pkg_resolvable(current_pkg)) continue;
            if (!expand_path_vars(rule, expanded, sizeof expanded, scope, &g_global_cfg,
                                  current_pkg))
                continue;
            match_str = expanded;
        }
        if (fnmatch(match_str, sub_path, 0) == 0) return true;
        size_t len = strlen(match_str);
        if (strncmp(sub_path, match_str, len) == 0 &&
            (sub_path[len] == '\0' || sub_path[len] == '/'))
            return true;
    }
    return false;
}

/* 类别 hide 线性扫描（USER_APPS/SYSTEM_APPS 动态规则）：变量展开以类别段
   为专属作用域（覆盖全局同名），与 app/global 展开对称 */
static bool br_cat_hide_linear(AppConfig* cat, const char* sub_path, const char* current_pkg) {
    if (!(cat && cat->hide_rules && cat->dyn_hide)) return false;
    return br_linear_match(cat->hide_rules, cat->hide_count, sub_path, current_pkg, cat);
}

static bool br_is_path_hidden_internal(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                                       const char* current_pkg, const FwRulesTrieMatch* tm) {
    bool is_skel = false;
    if (br_hidden_static_part(sub_path, current_pkg, tm, &is_skel)) return true;
    if (is_skel) return false; /* 骨架目录恒不隐藏（原逻辑提前返回，不扫 hide） */
    if (!(tm && tm->valid)) {
        bool hidden = false;
        bool dummy_ro = false;
        if (cfg && cfg->trie_root) {
            if (trie_lookup(cfg->trie_root, sub_path, &hidden, &dummy_ro, NULL, 0)) {
                if (hidden) return true;
            }
        }
        if (cat && cat->trie_root) {
            bool cat_hidden = false;
            if (trie_lookup(cat->trie_root, sub_path, &cat_hidden, &dummy_ro, NULL, 0)) {
                if (cat_hidden) return true;
            }
        }
        if (g_global_cfg.trie_root) {
            bool global_hidden = false;
            if (trie_lookup(g_global_cfg.trie_root, sub_path, &global_hidden, &dummy_ro, NULL, 0)) {
                if (global_hidden) return true;
            }
        }
    }
    if (cfg && cfg->hide_rules && cfg->dyn_hide &&
        br_linear_match(cfg->hide_rules, cfg->hide_count, sub_path, current_pkg, cfg))
        return true;
    if (br_cat_hide_linear(cat, sub_path, current_pkg)) return true;
    if (g_global_cfg.hide_rules && g_global_cfg.dyn_hide &&
        br_linear_match(g_global_cfg.hide_rules, g_global_cfg.hide_count, sub_path, current_pkg,
                        cfg))
        return true;
    return false;
}

/* 剥离 /<user_id>/ 前缀 + 非法字符清理，得到 sub_path。
   返回 0 成功；-ENOENT 表示清理后为空（路径无效，调用方视为不可解析）。 */
static int br_strip_and_sanitize(const char* path, int* path_user_id_out, char* sub_path_out,
                                 size_t sub_path_size) {
    if (!path) return -ENOENT;
    const char* sub_path_orig = path;
    /* 用户层剥离与框架路由共用 common_parse_user_layer（唯一实现）：仅当完整
       user_id 目录（/数字 或 /数字/...）才剥离——与框架 vfs_readdir 的 uid_dir
       判定一致。若数字后不是 '/' 或结尾（如 /1_abc.txt、/12_34 这类普通文件/
       目录名），不得剥离：否则 sub_path 被截成 "/"，规则判定（hidden/
       redirect_target）基于错误路径，沙盒+应用上下文中数字前缀条目会被误过滤
       （用户报告：数字 x_ 前缀文件/文件夹不显示，字母前缀正常）。
       返回 -1 = 数字串溢出 int（atoi 别名会让 /4294967296/x 落到 /0/x）：
       fail-closed，按不存在处理。 */
    int uid_parsed = -1;
    int pr = common_parse_user_layer(path, &uid_parsed, &sub_path_orig);
    if (pr < 0) return -ENOENT;
    if (pr > 0 && path_user_id_out) *path_user_id_out = uid_parsed;
    if (path_contains_invalid_chars(sub_path_orig)) {
        path_sanitize(sub_path_out, sub_path_size, sub_path_orig);
        if (sub_path_out[0] == '\0') return -ENOENT;
    } else {
        strncpy(sub_path_out, sub_path_orig, sub_path_size - 1);
        sub_path_out[sub_path_size - 1] = '\0';
    }
    return 0;
}

/* 隔离拒绝的限速观测（DEBUG）：隔离与 HIDE 一样静默返回 ENOENT，现场很难
   判断是规则、ROM 还是我们在拦——首个命中与每 1024 次各记一条，带调用方
   包名与判定路径（用户凭日志即可确认是隔离，并以 [GLOBAL]
   ALLOW_CROSS_APP_DATA ON 放行） */
static void br_note_isolation(const char* current_pkg, const char* sub_path) {
    static atomic_ulong seq;
    unsigned long n = atomic_fetch_add_explicit(&seq, 1, memory_order_relaxed) + 1;
    if (n == 1 || (n & 1023u) == 0)
        LOG_DBG("跨应用隔离: 拒绝 %s → %s（累计 %lu 次；[GLOBAL] ALLOW_CROSS_APP_DATA ON 可放行）",
                current_pkg, sub_path, n);
}

/* 该调用方的沙盒是否生效（三层合并，口径与 br_to_real_path 的 sandbox 分支
   一致）：应用显式 OFF 否决类别与全局；类别显式 OFF 否决全局；
   --disable-sandbox 全局关闭。沙盒生效时 data/obb 下的他包访问会被重定向到
   **自己的**沙盒镜像（读不到他包内容），故隔离让位（见 br_isolation_blocks）。 */
static bool br_sandbox_active(AppConfig* cfg, AppConfig* cat) {
    if (g_br_disable_sandbox) return false;
    if (cfg && cfg->sandbox_explicit && !cfg->sandbox) return false;
    if (cfg && cfg->sandbox) return true;
    if (cat) {
        if (cat->sandbox_explicit) return cat->sandbox;
        if (cat->sandbox) return true;
    }
    return g_global_cfg.sandbox;
}

/* 跨应用隔离是否拦下本路径（resolve 侧唯一调用点）：沙盒生效时放行——此时的
   "他包 data" 已被 br_to_real_path 改写成自己的沙盒镜像，读不到他包内容，
   把它判成 ENOENT 会让沙盒镜像整体不可用（test_monitor_layers 守护）。
   特权应用（platform 签名，packages.list seinfo 判定）自动豁免——DocumentsUI
   等文件中介的本职是访问他包 /Android/data，与 Android 权限体系对齐而非逐包
   手工规则。其余情形：看不见 = 打不开（与 probe 列举过滤同口径）。 */
static bool br_isolation_blocks(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                                const char* current_pkg, uid_t uid) {
    if (!br_is_other_app_pkg(sub_path, current_pkg)) return false;
    if (br_sandbox_active(cfg, cat)) return false;
    if (fw_pkg_is_privileged(uid)) return false;
    br_note_isolation(current_pkg, sub_path);
    return true;
}

static int br_sanitize_and_check_hidden(AppConfig* cfg, AppConfig* cat, const char* path,
                                        int* path_user_id_out, char* sub_path_out,
                                        size_t sub_path_size, const char* current_pkg, uid_t uid,
                                        FwRulesTrieMatch* tm_out) {
    (void)uid;
    if (br_strip_and_sanitize(path, path_user_id_out, sub_path_out, sub_path_size) != 0)
        return -ENOENT;
    if (tm_out) br_trie_resolve(cfg, cat, sub_path_out, tm_out);
    /* 隐藏判定对所有访问者生效（含 root，与 vfs_readdir probe 过滤一致）：
       HIDE 规则配置后，root ls 也不应看到被隐藏条目 */
    if (br_is_path_hidden_internal(cfg, cat, sub_path_out, current_pkg, tm_out)) return -ENOENT;
    return 0;
}

/* check_redir_rule：uid 由调用方传入，不再依赖 fuse_get_context */
/* 通配符检测（与 config_parser.c 的 is_wildcard_string 语义一致，该函数为
   static 不可跨翻译单元复用）：`?` 作为首字符是项目自定义的"相对当前 user
   存储"前缀（非 fnmatch 通配），仅从第二字符起检测真正的通配符 * ? [ ] */
static bool br_is_wildcard(const char* str) {
    if (!str || !str[0]) return false;
    const char* p = (str[0] == '?') ? str + 1 : str;
    return strpbrk(p, "*?[]") != NULL;
}

static bool br_check_redir_rule(AppConfig* c, const char* sub_path, char* temp, int user_id,
                                const char* current_pkg, bool skip_sandbox, size_t temp_size,
                                uid_t uid, char* mkdir_out, size_t mkdir_sz) {
    if (!c) return false;
    bool matched = false;
    if (c->redir_rules && c->redir_count > 0) {
        for (int i = 0; i < c->redir_count; i++) {
            const char* prefix = c->redir_rules[i].virtual_prefix;
            bool rule_hit;
            if (br_is_wildcard(prefix)) {
                /* 通配规则：fnmatch 全路径匹配（与 HIDE/RO 动态规则一致） */
                rule_hit = (fnmatch(prefix, sub_path, 0) == 0);
            } else {
                size_t len = strlen(prefix);
                rule_hit =
                    (strcmp(prefix, "/") == 0 || (strncmp(sub_path, prefix, len) == 0 &&
                                                  (sub_path[len] == '\0' || sub_path[len] == '/')));
            }
            if (!rule_hit) continue;
            if (c->redir_rules[i].is_allow) {
                /* ALLOW 豁免：放行到自身存储并阻止 sandbox 重定向。
                   real_target 是 "?<prefix>" 自引用形式（通配时含 * 等字面符，
                   不能经 build_real_base_from_target 展开），直接构造默认路径
                   STORAGE_BASE/<uid><sub_path>——语义 = 不重定向（与静态 ALLOW
                   经 trie 自引用命中后的效果一致） */
                common_default_real_path(user_id, sub_path, temp, temp_size);
                matched = true;
                break;
            }
            const char* suffix;
            if (br_is_wildcard(prefix)) {
                /* 命中后取 prefix 中首个通配符之前的字面前缀长度切 suffix，
                   使 /Download/<name>.mp3 命中 /Download/a.mp3 → suffix="a.mp3" */
                const char* wp = prefix;
                while (*wp && !strchr("*?[", *wp)) wp++;
                suffix = sub_path + (size_t)(wp - prefix);
            } else {
                size_t len = strlen(prefix);
                bool is_root = (strcmp(prefix, "/") == 0);
                suffix = is_root ? sub_path : (sub_path + len);
            }
            char real_base[PATH_MAX];
            const char* target = c->redir_rules[i].real_target;
            if (!build_real_base_from_target(target, (user_id >= 0 ? user_id : 0), real_base,
                                             sizeof real_base, c, &g_global_cfg, current_pkg)) {
                continue;
            }
            size_t tlen = strlen(real_base);
            bool t_slash = (tlen > 0 && real_base[tlen - 1] == '/');
            bool s_slash = (suffix[0] == '/');
            int w;
            if (t_slash && s_slash)
                w = snprintf(temp, temp_size, "%s%s", real_base, suffix + 1);
            else if (!t_slash && !s_slash) {
                if (suffix[0] == '\0')
                    w = snprintf(temp, temp_size, "%s", real_base);
                else
                    w = snprintf(temp, temp_size, "%s/%s", real_base, suffix);
            } else
                w = snprintf(temp, temp_size, "%s%s", real_base, suffix);
            if (w < 0 || (size_t)w >= temp_size) continue; /* 超截断 fail-closed：不用错路径 */
            matched = true;
            break;
        }
    }
    if (matched) return true;

    if (!skip_sandbox && c->sandbox && current_pkg[0] && strcmp(current_pkg, "system") != 0 &&
        strcmp(current_pkg, "unknown") != 0) {
        if (strncmp(sub_path, "/Android", 8) == 0) {
            if (sub_path[8] == '\0' || sub_path[8] == '/') {
                bool is_data = (strncmp(sub_path, "/Android/data", 13) == 0 &&
                                (sub_path[13] == '\0' || sub_path[13] == '/'));
                bool is_obb = (strncmp(sub_path, "/Android/obb", 12) == 0 &&
                               (sub_path[12] == '\0' || sub_path[12] == '/'));
                if (!is_data && !is_obb) return false;
            }
        }
        char exp_data[MAX_PATH_LEN], exp_obb[MAX_PATH_LEN];
        snprintf(exp_data, sizeof(exp_data), "/Android/data/%s", current_pkg);
        snprintf(exp_obb, sizeof(exp_obb), "/Android/obb/%s", current_pkg);
        size_t elen_data = strlen(exp_data), elen_obb = strlen(exp_obb);
        if (strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0 ||
            strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0 ||
            (strncmp(sub_path, exp_data, elen_data) == 0 &&
             (sub_path[elen_data] == '\0' || sub_path[elen_data] == '/')) ||
            (strncmp(sub_path, exp_obb, elen_obb) == 0 &&
             (sub_path[elen_obb] == '\0' || sub_path[elen_obb] == '/'))) {
            return false;
        }
        int effective_uid = user_id;
        if (effective_uid < 0) {
            if (uid >= NSP_SYSTEM_APP_UID_MIN) effective_uid = (int)(uid / NSP_PER_USER_UID_STRIDE);
        }
        if (effective_uid < 0) effective_uid = 0;
        char sandbox_target[MAX_PATH_LEN];
        if (common_sandbox_path(effective_uid, current_pkg, sandbox_target,
                                sizeof(sandbox_target)) != 0) {
            LOG_WRN("sandbox 路径过长，放弃沙盒重定向: pkg=%s", current_pkg);
            return false;
        }
        /* 沙盒落点**不在此创建**：本函数在 config_read_begin 持槽期间被调用，持槽内
           做 access()/mkdir_recursive_p() 会在慢存储上放大发布线程等读者归零的全局
           停顿（C1），且给 resolve 热路径引入副作用与 TOCTOU。只把待建目录交给出参，
           由调用方在出槽后补建（见 br_ensure_sandbox_dir）。 */
        if (mkdir_out && mkdir_sz) snprintf(mkdir_out, mkdir_sz, "%s", sandbox_target);
        int sw = snprintf(temp, temp_size, "%s%s", sandbox_target, sub_path);
        if (sw < 0 || (size_t)sw >= temp_size) return false; /* 超截断 fail-closed */
        return true;
    }
    return false;
}

/* 沙盒落点补建（**槽外**）：决策阶段（config_read_begin 持槽内）只记录待建目录，
   出槽后在此补建——持槽内做 FS 操作会在慢存储上放大发布线程等读者归零的全局停顿
   （C1），也避免给 resolve 热路径引入副作用与 TOCTOU。目录已存在或补建失败都不影响
   已算出的真实路径：后续 open/mkdir 以真实 errno 裁决。 */
static void br_ensure_sandbox_dir(const char* dir) {
    if (!dir || !dir[0]) return;
    /* 落点经守卫出口补建：effective_uid 来自路径解析（无存在性校验的历史形态），
       若一级组件缺失不得替应用在存储根下 materialize 出目录（见 common.h）。
       非存储根落点（自定义 REDIRECT 目标）照旧递归创建。 */
    if (access(dir, F_OK) != 0) common_mkdir_within_storage(dir, 0775);
}

static int br_to_real_path(AppConfig* cfg, AppConfig* cat, const char* sub_path, char* out_buf,
                           size_t size, int user_id, bool* is_redir_out, const char* current_pkg,
                           const FwRulesTrieMatch* tm, uid_t uid, char* mkdir_out,
                           size_t mkdir_sz) {
    char temp[PATH_MAX] = {0};
    bool redir = false;

    /* 重定向解析：**作用域优先**——应用段 > 类别段 > [GLOBAL]（docs/config.md §2）。
       同一作用域内静态（Trie）与线性（通配/变量）通道等价：Trie 只是静态规则的
       加速索引，不是更高的优先级层，故同层内先看静态命中、再看该层线性规则。
       旧实现先取「任一作用域的静态命中」、再无条件跳到线性，于是 [GLOBAL] 的静态
       REDIRECT 会压过应用/类别段的动态规则（与文档优先级相反）。 */
    const bool tm_ok = (tm && tm->valid);
    const bool static_hit = tm_ok && tm->has_redir;
    for (int layer = BR_SCOPE_APP; layer >= BR_SCOPE_GLOBAL && !redir; layer--) {
        AppConfig* c = br_scope_cfg(cfg, cat, (BrRuleScope)layer);
        if (static_hit && (int)tm->redir_scope == layer) {
            strncpy(temp, tm->redir, sizeof(temp) - 1);
            temp[sizeof(temp) - 1] = '\0';
            redir = true;
            break;
        }
        /* tm 无效（调用方未给缓存）时逐层现查 trie，保持旧 else 分支的兜底语义 */
        if (!tm_ok && c && c->trie_root) {
            bool dummy_hidden = false;
            bool dummy_ro = false;
            char static_tgt[PATH_MAX];
            static_tgt[0] = '\0';
            if (trie_lookup(c->trie_root, sub_path, &dummy_hidden, &dummy_ro, static_tgt,
                            sizeof(static_tgt)) &&
                static_tgt[0] != '\0') {
                strncpy(temp, static_tgt, sizeof(temp) - 1);
                temp[sizeof(temp) - 1] = '\0';
                redir = true;
                break;
            }
        }
        if (c && c->dyn_redir) {
            redir = br_check_redir_rule(c, sub_path, temp, user_id, current_pkg, true,
                                        sizeof(temp), uid, mkdir_out, mkdir_sz);
        }
    }

    if (redir && temp[0] == '?') {
        int effective_uid = user_id >= 0 ? user_id : 0;
        char real_base[1024];
        common_default_real_path(effective_uid, temp + 1, real_base, sizeof(real_base));
        strncpy(temp, real_base, sizeof(temp) - 1);
        temp[sizeof(temp) - 1] = '\0';
    }

    /* redir 线性兜底仅当存在通配/变量规则（未入 trie）时执行；
       全静态规则已由上方 trie（tm.has_redir）覆盖，跳过 O(N) 扫描。
       顺序：应用 > 类别 > 全局（类别变量展开以类别段为专属作用域） */
    if (!redir && cfg && cfg->dyn_redir)
        redir =
            br_check_redir_rule(cfg, sub_path, temp, user_id, current_pkg, true, sizeof(temp), uid, mkdir_out, mkdir_sz);
    if (!redir && cat && cat->dyn_redir)
        redir =
            br_check_redir_rule(cat, sub_path, temp, user_id, current_pkg, true, sizeof(temp), uid, mkdir_out, mkdir_sz);
    if (!redir && g_global_cfg.dyn_redir)
        redir = br_check_redir_rule(&g_global_cfg, sub_path, temp, user_id, current_pkg, true,
                                    sizeof(temp), uid, mkdir_out, mkdir_sz);
    /* sandbox 三层：应用显式 OFF 否决类别+全局；类别显式 OFF 否决全局；
       应用显式 ON（或类别显式 ON 且应用未显式）时各自 sandbox 生效 */
    bool app_sandbox_off = (cfg && cfg->sandbox_explicit && !cfg->sandbox);
    bool cat_sandbox_off = (!app_sandbox_off && cat && cat->sandbox_explicit && !cat->sandbox);
    if (!redir && !g_br_disable_sandbox) {
        if (!app_sandbox_off)
            redir = br_check_redir_rule(cfg, sub_path, temp, user_id, current_pkg, false,
                                        sizeof(temp), uid, mkdir_out, mkdir_sz);
    }
    if (!redir && !g_br_disable_sandbox) {
        if (!app_sandbox_off)
            redir = br_check_redir_rule(cat, sub_path, temp, user_id, current_pkg, false,
                                        sizeof(temp), uid, mkdir_out, mkdir_sz);
    }
    if (!redir && !g_br_disable_sandbox) {
        if (!app_sandbox_off && !cat_sandbox_off)
            redir = br_check_redir_rule(&g_global_cfg, sub_path, temp, user_id, current_pkg, false,
                                        sizeof(temp), uid, mkdir_out, mkdir_sz);
    }
    if (!redir) {
        common_default_real_path(user_id, sub_path, temp, sizeof(temp));
    }
    strncpy(out_buf, temp, size - 1);
    out_buf[size - 1] = '\0';
    if (is_redir_out) *is_redir_out = redir;
    if (out_buf[0] == '\0') return -ENOENT;
    return 0;
}

/* 类别 RO 线性扫描：变量展开以类别段为专属作用域 */
static bool br_cat_ro_linear(AppConfig* cat, const char* sub_path, const char* current_pkg) {
    if (!(cat && cat->ro_rules && cat->dyn_ro)) return false;
    return br_linear_match(cat->ro_rules, cat->ro_count, sub_path, current_pkg, cat);
}

static bool br_is_path_ro(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                          const char* current_pkg, const FwRulesTrieMatch* tm) {
    if (tm && tm->valid) {
        if (tm->ro) return true;
    } else {
        bool dummy_hidden = false;
        bool ro = false;
        if (cfg && cfg->trie_root) {
            if (trie_lookup(cfg->trie_root, sub_path, &dummy_hidden, &ro, NULL, 0)) {
                if (ro) return true;
            }
        }
        if (cat && cat->trie_root) {
            bool cat_ro = false;
            if (trie_lookup(cat->trie_root, sub_path, &dummy_hidden, &cat_ro, NULL, 0)) {
                if (cat_ro) return true;
            }
        }
        if (g_global_cfg.trie_root) {
            bool global_ro = false;
            if (trie_lookup(g_global_cfg.trie_root, sub_path, &dummy_hidden, &global_ro, NULL, 0)) {
                if (global_ro) return true;
            }
        }
    }
    if (cfg && cfg->ro_rules && cfg->dyn_ro &&
        br_linear_match(cfg->ro_rules, cfg->ro_count, sub_path, current_pkg, cfg))
        return true;
    if (br_cat_ro_linear(cat, sub_path, current_pkg)) return true;
    if (g_global_cfg.ro_rules && g_global_cfg.dyn_ro &&
        br_linear_match(g_global_cfg.ro_rules, g_global_cfg.ro_count, sub_path, current_pkg, cfg))
        return true;
    return false;
}

/* ============ 虚拟目录合成 ============ */

static bool br_get_virtual_child(const char* parent, const char* desc, char* name, size_t max_len) {
    if (!parent || !desc) return false;
    size_t plen = strlen(parent);
    if (strcmp(parent, "/") == 0) plen = 0;
    /* 防越界读：desc 短于 plen 时 strncmp 会读过 '\0'，先判长度 */
    size_t dlen = strlen(desc);
    if (dlen < plen) return false;
    if (strncmp(parent, desc, plen) != 0) return false;
    if (plen > 0 && desc[plen] != '/' && desc[plen] != '\0') return false;
    const char* p = desc + plen;
    if (*p == '/') p++;
    if (*p == '\0') return false;
    const char* slash = strchr(p, '/');
    size_t nlen = slash ? (size_t)(slash - p) : strlen(p);
    if (nlen == 0) return false;
    if (name && max_len > 0) {
        size_t copy_len = nlen < (max_len - 1) ? nlen : (max_len - 1);
        strncpy(name, p, copy_len);
        name[copy_len] = '\0';
    }
    return true;
}

/* 虚拟祖先判定的线性规则部分（redir/ftp 前缀的祖先检查，不含 trie）——
   readdir 目录级缓存命中时复用，避免每条目重复全路径 trie 遍历 */
/* 类别 redir/ftp 前缀的虚拟子目录判定（br_process_cfg_dirs 的线性版对应） */
static bool br_cat_virtual_child(AppConfig* cat, const char* sub_path) {
    if (!cat || !sub_path) return false;
    if (cat->redir_rules) {
        for (int i = 0; i < cat->redir_count; i++) {
            if (strlen(sub_path) < strlen(cat->redir_rules[i].virtual_prefix)) {
                if (br_get_virtual_child(sub_path, cat->redir_rules[i].virtual_prefix, nullptr, 0))
                    return true;
            }
        }
    }
    if (cat->ftp_rules) {
        for (int i = 0; i < cat->ftp_count; i++) {
            if (strlen(sub_path) < strlen(cat->ftp_rules[i].virtual_prefix)) {
                if (br_get_virtual_child(sub_path, cat->ftp_rules[i].virtual_prefix, nullptr, 0))
                    return true;
            }
        }
    }
    return false;
}

static bool br_virtual_ancestor_linear(AppConfig* cfg, AppConfig* cat, const char* sub_path) {
    bool res = false;
    if (!sub_path) return false;
    if (cfg) {
        if (cfg->redir_rules) {
            for (int i = 0; i < cfg->redir_count; i++) {
                if (strlen(sub_path) < strlen(cfg->redir_rules[i].virtual_prefix)) {
                    if (br_get_virtual_child(sub_path, cfg->redir_rules[i].virtual_prefix, nullptr,
                                             0)) {
                        res = true;
                        break;
                    }
                }
            }
        }
        if (!res && cfg->ftp_rules) {
            for (int i = 0; i < cfg->ftp_count; i++) {
                if (strlen(sub_path) < strlen(cfg->ftp_rules[i].virtual_prefix)) {
                    if (br_get_virtual_child(sub_path, cfg->ftp_rules[i].virtual_prefix, nullptr,
                                             0)) {
                        res = true;
                        break;
                    }
                }
            }
        }
    }
    if (!res) res = br_cat_virtual_child(cat, sub_path);
    if (!res) {
        if (g_global_cfg.redir_rules) {
            for (int i = 0; i < g_global_cfg.redir_count; i++) {
                if (strlen(sub_path) < strlen(g_global_cfg.redir_rules[i].virtual_prefix)) {
                    if (br_get_virtual_child(sub_path, g_global_cfg.redir_rules[i].virtual_prefix,
                                             nullptr, 0)) {
                        res = true;
                        break;
                    }
                }
            }
        }
        if (!res && g_global_cfg.ftp_rules) {
            for (int i = 0; i < g_global_cfg.ftp_count; i++) {
                if (strlen(sub_path) < strlen(g_global_cfg.ftp_rules[i].virtual_prefix)) {
                    if (br_get_virtual_child(sub_path, g_global_cfg.ftp_rules[i].virtual_prefix,
                                             nullptr, 0)) {
                        res = true;
                        break;
                    }
                }
            }
        }
    }
    return res;
}

/* redirect_target 判定的线性规则部分（redir 前缀精确匹配 + 根 sandbox），不含 trie */
static bool br_redirect_target_linear(AppConfig* cfg, AppConfig* cat, const char* sub_path) {
    bool res = false;
    if (cfg) {
        if (cfg->redir_rules) {
            for (int i = 0; i < cfg->redir_count; i++) {
                if (strcmp(sub_path, cfg->redir_rules[i].virtual_prefix) == 0) {
                    res = true;
                    break;
                }
            }
        }
        if (!res && cfg->sandbox && strcmp(sub_path, "/") == 0) res = true;
    }
    if (!res && cat) {
        if (cat->redir_rules) {
            for (int i = 0; i < cat->redir_count; i++) {
                if (strcmp(sub_path, cat->redir_rules[i].virtual_prefix) == 0) {
                    res = true;
                    break;
                }
            }
        }
        /* 类别 sandbox 根判定：应用显式设置时以应用为准（与全局层对称） */
        if (!res && !(cfg && cfg->sandbox_explicit) && cat->sandbox && strcmp(sub_path, "/") == 0)
            res = true;
    }
    if (!res) {
        if (g_global_cfg.redir_rules) {
            for (int i = 0; i < g_global_cfg.redir_count; i++) {
                if (strcmp(sub_path, g_global_cfg.redir_rules[i].virtual_prefix) == 0) {
                    res = true;
                    break;
                }
            }
        }
        bool sandbox_veto = (cfg && cfg->sandbox_explicit) || (cat && cat->sandbox_explicit);
        if (!res && !sandbox_veto && g_global_cfg.sandbox && strcmp(sub_path, "/") == 0) res = true;
    }
    return res;
}

static bool br_is_virtual_ancestor(AppConfig* cfg, AppConfig* cat, const char* sub_path) {
    bool res = false;
    if (cfg && cfg->trie_root) res = trie_is_ancestor(cfg->trie_root, sub_path);
    if (!res && cat && cat->trie_root) res = trie_is_ancestor(cat->trie_root, sub_path);
    if (!res && g_global_cfg.trie_root) res = trie_is_ancestor(g_global_cfg.trie_root, sub_path);
    /* 线性兜底仅覆盖通配/变量 redir（FTP 已入 trie 且 trie_node_has_rules
       覆盖 ftp_backend），全静态时跳过 O(N) 扫描 */
    if (!res) {
        bool dyn_any = (cfg && cfg->dyn_redir) || (cat && cat->dyn_redir) || g_global_cfg.dyn_redir;
        if (dyn_any) res = br_virtual_ancestor_linear(cfg, cat, sub_path);
    }
    return res;
}

static bool br_is_redirect_target(AppConfig* cfg, AppConfig* cat, const char* sub_path) {
    bool res = false;
    if (cfg && cfg->trie_root) res = trie_is_redirect_target(cfg->trie_root, sub_path);
    if (!res && cat && cat->trie_root) res = trie_is_redirect_target(cat->trie_root, sub_path);
    if (!res && g_global_cfg.trie_root)
        res = trie_is_redirect_target(g_global_cfg.trie_root, sub_path);
    if (!res) {
        bool dyn_any = (cfg && cfg->dyn_redir) || (cat && cat->dyn_redir) || g_global_cfg.dyn_redir;
        if (dyn_any) res = br_redirect_target_linear(cfg, cat, sub_path);
    }
    return res;
}

/* ============ 核心决策入口 ============ */

/* 字符串仅需首字节清零；成功路径负责覆盖，隐藏路径保留空串。 */
static inline void br_result_init(NspPathDecision* out) {
    out->valid = false;
    out->appear_missing = false;
    out->read_only = false;
    out->real_path[0] = '\0';
    out->is_redirect = false;
    out->virtual_kind = NSP_VK_NONE;
    out->is_ftp = false;
}

/* 路径是否含 <uid>/ 用户层（如 /0/foo、/10/、或 /0 本身）：挂载点根（/、/obb
   等非 uid 顶层）不进行任何规则合成，仅 <uid>/ 之后的路径才参与规则——从框架
   源头规避挂载点根下出现额外虚拟目录（如 FTP 前缀条目被合到根下）。 */
bool fw_rules_path_has_uid_layer(const char* path) {
    if (!path || path[0] != '/' || path[1] < '0' || path[1] > '9') return false;
    const char* d = path + 1;
    while (*d >= '0' && *d <= '9') d++;
    return (*d == '\0' || *d == '/');
}

void fw_rules_resolve(const NspQueryCtx* q, NspPathDecision* out) {
    if (!out) return;
    br_result_init(out);
    if (!q || !fw_rules_path_has_uid_layer(q->path)) return; /* 直通：不参与规则 */
    /* S1 无锁快照读：替代 rwlock 读锁。config_read_begin 持槽期间旧配置
       不会被发布者释放；config_read_end 返回 false（读期间发生发布）则
       整体重试——热重载极低频，重试代价可忽略 */
    for (;;) {
        uint64_t cfg_gen = config_read_begin();
        br_result_init(out);
        char current_pkg[128] = "unknown";
        AppConfig* cat = nullptr;
        AppConfig* cfg = br_get_app_cfg(q->uid, q->pid, current_pkg, &cat);

        int path_user_id = -1;
        char sub_path[PATH_MAX];
        FwRulesTrieMatch tm;
        if (br_sanitize_and_check_hidden(cfg, cat, q->path, &path_user_id, sub_path,
                                         sizeof sub_path, current_pkg, q->uid, &tm) != 0 ||
            br_isolation_blocks(cfg, cat, sub_path, current_pkg, q->uid)) {
            out->valid = true;
            out->appear_missing = true;
            if (config_read_end(cfg_gen)) return;
            continue;
        }
        char p[PATH_MAX];
        char sandbox_mkdir[MAX_PATH_LEN];
        sandbox_mkdir[0] = '\0';
        bool is_redir = false;
        if (br_to_real_path(cfg, cat, sub_path, p, sizeof p, path_user_id, &is_redir, current_pkg,
                            &tm, q->uid, sandbox_mkdir, sizeof sandbox_mkdir) != 0) {
            out->valid = false;
            if (config_read_end(cfg_gen)) return;
            continue;
        }
        out->valid = true;
        out->read_only = br_is_path_ro(cfg, cat, sub_path, current_pkg, &tm);
        out->is_redirect = is_redir;
        strcpy(out->real_path, p); /* 源为 PATH_MAX 栈缓冲，NUL 结尾 */
        /* 复用 br_trie_resolve 已完成的 trie 下降结果（app/类别/global 完整匹配节点），
       直接判定虚拟目录性质，避免各自再全路径遍历：
       - ANCESTOR：最深节点下存在带规则子节点（trie_is_ancestor 语义）
       - TARGET：最深节点**本身**是 REDIRECT 的虚拟前缀（trie_is_redirect_target
         语义——函数名沿用历史，判的不是"真实目标"；见 fw_rules.h 的 NspVirtualKind）
       （节点为 NULL = 路径未完整命中，两语义均为 false，与 trie_* 一致）
       线性兜底仅覆盖通配/变量 redir 规则（未入 trie），全静态时跳过。
       ANCESTOR 优先于 TARGET：祖先性质决定是否合成目录，语义更强 */
        bool dyn_any = (cfg && cfg->dyn_redir) || (cat && cat->dyn_redir) || g_global_cfg.dyn_redir;
        bool is_ancestor = ((tm.app_node && trie_any_child_has_rules(tm.app_node)) ||
                            (tm.cat_node && trie_any_child_has_rules(tm.cat_node)) ||
                            (tm.global_node && trie_any_child_has_rules(tm.global_node))) ||
                           (dyn_any && br_virtual_ancestor_linear(cfg, cat, sub_path));
        bool is_target = ((tm.app_node && tm.app_node->redir_target) ||
                          (tm.cat_node && tm.cat_node->redir_target) ||
                          (tm.global_node && tm.global_node->redir_target)) ||
                         (dyn_any && br_redirect_target_linear(cfg, cat, sub_path));
        out->virtual_kind = is_ancestor ? NSP_VK_ANCESTOR
                                        : (is_target ? NSP_VK_TARGET : NSP_VK_NONE);
        /* FTP 规则（`FTP <虚拟前缀> <段名>`）：应用 > 类别 > GLOBAL
       （与 REDIRECT 作用域语义一致）；命中结果由 br_trie_resolve 的 trie
       下降一次取得（替代早期的每请求 O(N) 线性扫描）；
       命中后由框架分派给 FTP 后端模块 */
        out->is_ftp = tm.ftp_app[0] || tm.ftp_cat[0] || tm.ftp_global[0];
        if (config_read_end(cfg_gen)) {
            br_ensure_sandbox_dir(sandbox_mkdir); /* 槽外补建沙盒落点（C1） */
            return;
        }
        /* 读期间发生发布：整体重试（下次循环重新决策、重新记录待建目录） */
    }
}

/* 轻量探测：readdir 逐条目过滤用。只做 sanitize + hidden/redirect_target/
   虚拟目录判断，不构建真实路径、不触发 sandbox 目录创建（性能敏感） */
void fw_rules_probe(const NspQueryCtx* q, NspProbeResult* out) {
    if (!out) return;
    memset(out, 0, sizeof *out);
    out->valid = false;
    if (!q || !fw_rules_path_has_uid_layer(q->path)) return; /* 直通：不过滤 */
    /* S1 无锁快照读：替代 rwlock 读锁。config_read_begin 持槽期间旧配置
       不会被发布者释放；config_read_end 返回 false（读期间发生发布）则
       整体重试（probe 是 readdir 条目级热路径，重载极低频可忽略） */
    for (;;) {
        uint64_t cfg_gen = config_read_begin();
        memset(out, 0, sizeof *out);
        char current_pkg[128] = "unknown";
        uint64_t gen = atomic_load_explicit(&g_br_cfg_gen, memory_order_acquire);
        AppConfig* cfg = NULL;

        int path_user_id = -1;
        char sub_path[PATH_MAX];
        if (br_strip_and_sanitize(q->path, &path_user_id, sub_path, sizeof sub_path) != 0) {
            if (config_read_end(cfg_gen)) return; /* 无效路径：out->valid=false，框架不过滤 */
            continue;
        }

        /* 提取父目录与条目名："/a/b" → 父 "/a"、名 "b"；"/xxx" → 父 "/"、名 "xxx" */
        char dir[PATH_MAX];
        const char* name;
        size_t name_len;
        {
            const char* last = strrchr(sub_path, '/');
            if (!last) { /* 无 '/'（防御） */
                strncpy(dir, "/", sizeof dir - 1);
                dir[sizeof dir - 1] = '\0';
                name = sub_path;
            } else if (last == sub_path) { /* "/xxx" → 父目录 "/" */
                strncpy(dir, "/", sizeof dir - 1);
                dir[sizeof dir - 1] = '\0';
                name = last + 1;
            } else {
                size_t dlen = (size_t)(last - sub_path);
                if (dlen >= sizeof dir) dlen = sizeof dir - 1;
                memcpy(dir, sub_path, dlen);
                dir[dlen] = '\0';
                name = last + 1;
            }
            name_len = strlen(name);
        }

        BrProbeDirCache* pc = &g_probe_dir_cache;
        /* 缓存命中：同线程同一 (uid,pid,父目录) 的连续条目共享一次
       「根→父目录」trie 下降与 uid→cfg 解析，这里只按最后一段查子节点 */
        if (pc->valid && pc->gen == gen && pc->uid == q->uid && pc->pid == q->pid &&
            strcmp(pc->dir, dir) == 0) {
            cfg = pc->cfg;
            AppConfig* cat = pc->cat;
            strncpy(current_pkg, pc->current_pkg, 127);
            current_pkg[127] = '\0';
            /* 无锁快速路径：全静态规则（redir/hide/ro 均无通配/变量）+ 父目录无
           规则子节点——判定只用线程私有缓存字段与纯字符串，不触碰 cfg/trie
           指针（重载在写锁内原地重建 g_global_cfg，锁外读取有撕裂/UAF 风险，
           故不得进入任何线性规则扫描）。重载递增 gen（release），此处锁内
           acquire 读 gen 相等即自缓存填充以来无重载；缓存为线程私有无并发写。 */
            bool all_static = !g_global_cfg.dyn_redir && !g_global_cfg.dyn_hide &&
                              !g_global_cfg.dyn_ro &&
                              !(cfg && (cfg->dyn_redir || cfg->dyn_hide || cfg->dyn_ro)) &&
                              !(cat && (cat->dyn_redir || cat->dyn_hide || cat->dyn_ro)) &&
                              !pc->app_dir_node && !pc->cat_dir_node && !pc->g_dir_node;
            if (all_static) {
                FwRulesTrieMatch tm;
                tm.valid = true;
                tm.hidden = pc->app_dir_hidden || pc->cat_dir_hidden || pc->g_dir_hidden;
                bool is_skel = false;
                /* 跨应用隔离与隐藏同口径（br_sanitize_and_check_hidden 亦判，
               此处为同一判据的读取侧：列举过滤走本路径） */
                bool iso = br_is_other_app_pkg(sub_path, current_pkg) &&
                           !fw_pkg_is_privileged(q->uid);
                bool hidden = br_hidden_static_part(sub_path, current_pkg, &tm, &is_skel) || iso;
                out->valid = true;
                out->appear_missing = hidden;
                out->is_other_app_pkg = iso;
                if (config_read_end(cfg_gen)) return;
                continue;
            }
            const TrieNode* ca = trie_find_child(pc->app_dir_node, name, name_len);
            const TrieNode* cc = trie_find_child(pc->cat_dir_node, name, name_len);
            const TrieNode* cg = trie_find_child(pc->g_dir_node, name, name_len);
            bool trie_hidden = pc->app_dir_hidden || pc->cat_dir_hidden || pc->g_dir_hidden;
            if (ca && ca->is_hidden) trie_hidden = true;
            if (cc && cc->is_hidden) trie_hidden = true;
            if (cg && cg->is_hidden) trie_hidden = true;
            FwRulesTrieMatch tm;
            tm.valid = true;
            tm.hidden = trie_hidden;
            /* 完整隐藏判定（CONFIG_DIR/Android 骨架/跨应用/hide 规则），
           trie 部分用缓存值（tm.valid 使其跳过内部 trie 查询）。
           对所有访问者生效（含 root）：与 br_sanitize_and_check_hidden
           及 vfs_readdir probe 过滤语义一致，HIDE 后 root ls 也看不见。
          跨应用隔离同样在此叠加（与 resolve 侧 br_sanitize_and_check_hidden
           同判据：看不见 = 打不开） */
            bool iso = br_is_other_app_pkg(sub_path, current_pkg) &&
                       !fw_pkg_is_privileged(q->uid);
            if (br_is_path_hidden_internal(cfg, cat, sub_path, current_pkg, &tm) || iso) {
                out->valid = true;
                out->appear_missing = true;
                if (config_read_end(cfg_gen)) return;
                continue;
            }
            out->valid = true;
            out->appear_missing = trie_hidden || iso;
            bool dyn_any =
                (cfg && cfg->dyn_redir) || (cat && cat->dyn_redir) || g_global_cfg.dyn_redir;
            bool p_target = ((ca && ca->redir_target) || (cc && cc->redir_target) ||
                             (cg && cg->redir_target)) ||
                            (dyn_any && br_redirect_target_linear(cfg, cat, sub_path));
            bool p_ancestor =
                ((ca && trie_any_child_has_rules(ca)) || (cc && trie_any_child_has_rules(cc)) ||
                 (cg && trie_any_child_has_rules(cg))) ||
                (dyn_any && br_virtual_ancestor_linear(cfg, cat, sub_path));
            out->virtual_kind = p_ancestor ? NSP_VK_ANCESTOR
                                           : (p_target ? NSP_VK_TARGET : NSP_VK_NONE);
            out->is_other_app_pkg = iso;
            if (config_read_end(cfg_gen)) return;
            continue;
        }

        /* 未命中：完整路径解析（原逻辑）+ 填充目录缓存 */
        AppConfig* cat = nullptr;
        cfg = br_get_app_cfg(q->uid, q->pid, current_pkg, &cat);
        FwRulesTrieMatch tm;
        if (br_sanitize_and_check_hidden(cfg, cat, q->path, &path_user_id, sub_path,
                                         sizeof sub_path, current_pkg, q->uid, &tm) != 0 ||
            (br_is_other_app_pkg(sub_path, current_pkg) && !fw_pkg_is_privileged(q->uid))) {
            out->valid = true;
            out->appear_missing = true;
            if (config_read_end(cfg_gen)) return;
            continue;
        }
        out->valid = true;
        out->appear_missing = tm.hidden;
        out->virtual_kind = br_is_virtual_ancestor(cfg, cat, sub_path)
                                ? NSP_VK_ANCESTOR
                                : (br_is_redirect_target(cfg, cat, sub_path) ? NSP_VK_TARGET
                                                                            : NSP_VK_NONE);
        out->is_other_app_pkg = br_is_other_app_pkg(sub_path, current_pkg);

        /* 填充目录缓存（trie 沿父目录一次下降，后续条目复用） */
        memset(pc, 0, sizeof *pc);
        pc->valid = true;
        pc->gen = gen;
        pc->uid = q->uid;
        pc->pid = q->pid;
        strncpy(pc->dir, dir, sizeof pc->dir - 1);
        pc->dir[sizeof pc->dir - 1] = '\0';
        pc->cfg = cfg;
        pc->cat = cat;
        strncpy(pc->current_pkg, current_pkg, sizeof pc->current_pkg - 1);
        pc->current_pkg[sizeof pc->current_pkg - 1] = '\0';
        bool h = false, r = false;
        pc->app_dir_node =
            (cfg && cfg->trie_root) ? trie_walk_to(cfg->trie_root, dir, &h, &r) : NULL;
        pc->app_dir_hidden = h;
        h = false;
        r = false;
        pc->cat_dir_node =
            (cat && cat->trie_root) ? trie_walk_to(cat->trie_root, dir, &h, &r) : NULL;
        pc->cat_dir_hidden = h;
        h = false;
        r = false;
        pc->g_dir_node =
            g_global_cfg.trie_root ? trie_walk_to(g_global_cfg.trie_root, dir, &h, &r) : NULL;
        pc->g_dir_hidden = h;
        if (config_read_end(cfg_gen)) return;
        /* 读期间发生发布：整体重试 */
    }
}

/* ============ readdir 虚拟目录补充 ============ */

/* 处理单个配置（app 或 global）的 REDIRECT 前缀虚拟子目录。
   函数化替代宏：避免对 &g_global_cfg 这类常量地址判空触发 -Waddress */
static int br_process_cfg_dirs(AppConfig* c, const char* sub_path, int user_id, const char* pkg,
                               bool is_root, NspDirEntry* out, int max, int n) {
    if (!c || !sub_path || !out || n >= max) return n;
    /* REDIRECT 虚拟目录合成 */
    if (c->redir_rules) {
        for (int i = 0; i < c->redir_count && n < max; i++) {
            char name[256];
            if (br_get_virtual_child(sub_path, c->redir_rules[i].virtual_prefix, name,
                                     sizeof(name))) {
                char full_vpath[PATH_MAX];
                if (is_root)
                    snprintf(full_vpath, PATH_MAX, "/%s", name);
                else
                    snprintf(full_vpath, PATH_MAX, "%s/%s", sub_path, name);
                if (strcmp(full_vpath, c->redir_rules[i].virtual_prefix) == 0) {
                    char dummy[PATH_MAX];
                    if (!build_real_base_from_target(
                            c->redir_rules[i].real_target, (user_id >= 0 ? user_id : 0), dummy,
                            sizeof dummy, c, &g_global_cfg, pkg && pkg[0] ? pkg : "unknown"))
                        continue;
                }
                bool dup = false;
                for (int k = 0; k < n; k++) {
                    if (strcmp(out[k].name, name) == 0) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) {
                    strncpy(out[n].name, name, sizeof out[n].name - 1);
                    out[n].name[sizeof out[n].name - 1] = '\0';
                    out[n].is_dir = true;
                    n++;
                }
            }
        }
    }
    /* FTP 虚拟目录合成：FTP <虚拟前缀> <段名> 规则的前缀条目（如 /0/ 下显示"云盘"） */
    if (c->ftp_rules) {
        for (int i = 0; i < c->ftp_count && n < max; i++) {
            char name[256];
            if (br_get_virtual_child(sub_path, c->ftp_rules[i].virtual_prefix, name, sizeof name)) {
                bool dup = false;
                for (int k = 0; k < n; k++) {
                    if (strcmp(out[k].name, name) == 0) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) {
                    strncpy(out[n].name, name, sizeof out[n].name - 1);
                    out[n].name[sizeof out[n].name - 1] = '\0';
                    out[n].is_dir = true;
                    n++;
                }
            }
        }
    }
    return n;
}

int fw_rules_readdir_extra(const NspQueryCtx* q, const char* sub_path, int user_id, const char* pkg,
                     bool is_root, NspDirEntry* out, int max) {
    if (!q || !out || max <= 0 || !sub_path) return 0;
    /* S1 无锁快照读：替代 rwlock 读锁（与 fw_rules_resolve 一致，发布发生则重试） */
    for (;;) {
        uint64_t cfg_gen = config_read_begin();
        char pkg_buf[128];
        (void)pkg;
        AppConfig* cat = nullptr;
        AppConfig* cfg = br_get_app_cfg(q->uid, q->pid, pkg_buf, &cat);

        int n = 0;
        n = br_process_cfg_dirs(cfg, sub_path, user_id, pkg_buf, is_root, out, max, n);
        n = br_process_cfg_dirs(cat, sub_path, user_id, pkg_buf, is_root, out, max, n);
        n = br_process_cfg_dirs(&g_global_cfg, sub_path, user_id, pkg_buf, is_root, out, max, n);
        if (config_read_end(cfg_gen)) return n;
        /* 读期间发生发布：重试 */
    }
}

/* ============ backing 直通仲裁（见 fw_rules.h 声明注释） ============ */
/* 规则侧路径与 data/obb 是否相交：其下/其本身（字面量子串）、其祖先
   （"/" 或 "/Android"，剥尾部 '/' 后以前缀判定，"/AndroidData" 类
   相似名因 '/' 边界检查而排除）。 */
static bool br_data_overlap(const char* s) {
    if (!s || !*s) return false;
    char t[PATH_MAX];
    size_t n = strlen(s);
    if (n >= sizeof t) n = sizeof t - 1;
    memcpy(t, s, n);
    t[n] = '\0';
    while (n > 1 && t[n - 1] == '/') t[--n] = '\0';
    if (strcmp(t, "/") == 0) return true; /* 覆盖一切 */
    if (strstr(t, "Android/data") || strstr(t, "Android/obb")) return true;
    /* 祖先："/Android/data" 以 t+"/" 开头 */
    size_t tl = strlen(t);
    if (strncmp("/Android/data", t, tl) == 0 && "/Android/data"[tl] == '/') return true;
    if (strncmp("/Android/obb", t, tl) == 0 && "/Android/obb"[tl] == '/') return true;
    return false;
}

/* 规则字面量含 $变量时追查其展开值（resolved 优先，回退原始值；变量名存储
   不含 '$'，needle 须带 '$' 前缀，"${V}" 形式天然包含 "$V"）。$package 展开
   为纯包名（无 '/'），不改变相交性，无须特殊处理。 */
static bool br_rule_touches_data(const AppConfig* c, const char* rule) {
    if (!rule || !*rule) return false;
    if (br_data_overlap(rule)) return true;
    if (!strchr(rule, '$') || !c) return false;
    for (int i = 0; i < c->var_count; i++) {
        const char* vn = (c->var_names && c->var_names[i]) ? c->var_names[i] : NULL;
        if (!vn || !*vn) continue;
        char needle[136];
        needle[0] = '$';
        strncpy(needle + 1, vn, sizeof needle - 2);
        needle[sizeof needle - 1] = '\0';
        if (!strstr(rule, needle)) continue;
        const char* v = (c->var_resolved && c->var_resolved[i]) ? c->var_resolved[i]
                        : (c->var_values ? c->var_values[i] : NULL);
        if (!v || !*v) continue;
        if (strlen(v) <= 1 || br_data_overlap(v)) return true; /* "/" 值展开后覆盖一切 */
    }
    return false;
}

static bool br_cfg_touches_data(const AppConfig* c) {
    if (!c) return false;
    /* MONITOR ON（B1）：该段调用者的 IO 要进 io.log，而 backing 直通后内核绕过
       daemon、vfs_log_io 静默归零——故监控优先，本子树不做 backing 直通（牺牲
       部分加速）。门原先只扫 sandbox/hide/ro/redir/ftp，遗漏了监控这一维。 */
    if (c->monitor) return true;
    /* 任一段 SANDBOX ON：共享目录重定向目标落进 data 沙盒，且跨应用隔离
       过滤依赖 daemon，必须仲裁（--disable-sandbox 全局关闭时除外） */
    if (c->sandbox && !g_br_disable_sandbox) return true;
    for (int i = 0; i < c->hide_count; i++)
        if (c->hide_rules && br_rule_touches_data(c, c->hide_rules[i])) return true;
    for (int i = 0; i < c->ro_count; i++)
        if (c->ro_rules && br_rule_touches_data(c, c->ro_rules[i])) return true;
    for (int i = 0; i < c->redir_count; i++) {
        if (!c->redir_rules || c->redir_rules[i].is_allow) continue; /* ALLOW 即直通 */
        if (br_rule_touches_data(c, c->redir_rules[i].virtual_prefix) ||
            br_rule_touches_data(c, c->redir_rules[i].real_target))
            return true;
    }
    for (int i = 0; i < c->ftp_count; i++)
        if (c->ftp_rules && br_rule_touches_data(c, c->ftp_rules[i].virtual_prefix)) return true;
    return false;
}

bool fw_data_mediation_required(void) {
    /* S1 无锁快照读（与 fw_rules_resolve 同协议，发布发生则重试） */
    for (;;) {
        uint64_t cfg_gen = config_read_begin();
        /* 跨应用隔离（默认生效）让 data/obb 子树的可见性取决于调用方，
           backing 直通（daemon 凭证 + 内核绕过 daemon）无法 per-caller 裁决，
           故整树交 daemon 仲裁；ALLOW_CROSS_APP_DATA ON 时退回按规则判定 */
        bool need = !g_global_cfg.allow_cross_app_data || br_cfg_touches_data(&g_global_cfg);
        if (!need) {
            for (int i = 0; i < g_app_cfg_count; i++) {
                if (g_app_cfgs && br_cfg_touches_data(g_app_cfgs[i])) {
                    need = true;
                    break;
                }
            }
        }
        if (config_read_end(cfg_gen)) return need;
    }
}

/* ============ backing 按路径仲裁（细粒度门） ============ */
/* 查询归一：剥离 /<uid>/ 层（/0、/10/...，与 br_strip_and_sanitize 同口径），
   去尾部 '/'（根保留 "/"），无前导 '/' 则补 '/'. */
static void backing_norm_query(const char* p, char* out, size_t cap) {
    if (!out || cap == 0) return;
    const char* sub = (p && p[0]) ? p : "/";
    if (sub[0] == '/' && sub[1] >= '0' && sub[1] <= '9') {
        const char* d = sub + 1;
        while (*d >= '0' && *d <= '9') d++;
        if (*d == '\0' || *d == '/') {
            const char* slash = strchr(sub + 1, '/');
            sub = slash ? slash : "/";
        }
    }
    size_t n = strlen(sub);
    if (n >= cap) n = cap - 1;
    memcpy(out, sub, n);
    out[n] = '\0';
    while (n > 1 && out[n - 1] == '/') out[--n] = '\0';
    if (out[0] != '/') {
        /* 非绝对规则值：原样保留（调用方判定跳过），避免误判 */
        out[0] = '\0';
    }
}

/* query 是否在 rule 之下（含相等；rule=="/" 覆盖一切） */
static bool backing_under_or_eq(const char* query, const char* rule) {
    if (!query || !rule || !query[0] || !rule[0]) return false;
    if (strcmp(rule, "/") == 0) return true;
    size_t rl = strlen(rule);
    if (strcmp(query, rule) == 0) return true;
    return strncmp(query, rule, rl) == 0 && query[rl] == '/';
}

/* query 是否为 rule 的直接父目录（readdir 会列出受影响名） */
static bool backing_is_parent(const char* query, const char* rule) {
    if (!query || !rule || strcmp(rule, "/") == 0) return false;
    const char* last = strrchr(rule, '/');
    if (!last) return false;
    if (last == rule) return strcmp(query, "/") == 0;
    size_t pl = (size_t)(last - rule);
    return strlen(query) == pl && strncmp(query, rule, pl) == 0;
}

/* 通配符静态前缀：截到首个 *?[( 为止，再回退到最后 '/'（至少保留 "/"）。
   无通配符则去尾 '/' 后整体返回。 */
static void backing_static_prefix(const char* rule, char* out, size_t cap) {
    if (!out || cap == 0) return;
    size_t n = strlen(rule);
    size_t cut = n;
    for (size_t i = 0; i < n; i++) {
        if (rule[i] == '*' || rule[i] == '?' || rule[i] == '[') {
            cut = i;
            break;
        }
    }
    if (cut >= cap) cut = cap - 1;
    memcpy(out, rule, cut);
    out[cut] = '\0';
    if (cut == n) {
        while (cut > 1 && out[cut - 1] == '/') out[--cut] = '\0';
        return;
    }
    char* last = strrchr(out, '/');
    if (!last) {
        out[0] = '\0';
        return;
    }
    if (last == out) {
        out[1] = '\0';
        return;
    }
    *last = '\0';
}

/* 字面量（含通配符）与查询是否相交：相等/其下必中；其上仅直接父中
   （远祖先只列出中间名，无 per-caller 差异）；fnmatch 命中亦中。 */
static bool backing_literal_hits(const char* rule, const char* query) {
    if (!rule || !*rule || !query || !query[0]) return false;
    if (fnmatch(rule, query, 0) == 0) return true;
    char sp[PATH_MAX];
    backing_static_prefix(rule, sp, sizeof sp);
    if (!sp[0]) return false;
    if (sp[0] != '/') return false;
    if (strcmp(sp, query) == 0) return true;
    if (backing_under_or_eq(query, sp)) return true;
    if (backing_under_or_eq(sp, query)) return backing_is_parent(query, sp);
    return false;
}

/* 规则中 $变量展开值与查询是否相交（$package 展开无 '/'，天然不中）。
   只查被规则字面量实际引用的变量（needle 须带 '$' 前缀）。 */
static bool backing_var_hits(const AppConfig* c, const char* rule, const char* query) {
    if (!c || !rule || !strchr(rule, '$')) return false;
    for (int i = 0; i < c->var_count; i++) {
        const char* vn = (c->var_names && c->var_names[i]) ? c->var_names[i] : NULL;
        if (!vn || !*vn) continue;
        char needle[136];
        needle[0] = '$';
        strncpy(needle + 1, vn, sizeof needle - 2);
        needle[sizeof needle - 1] = '\0';
        if (!strstr(rule, needle)) continue;
        const char* v = (c->var_resolved && c->var_resolved[i]) ? c->var_resolved[i]
                        : (c->var_values ? c->var_values[i] : NULL);
        if (!v || !*v || v[0] != '/') continue;
        char t[PATH_MAX];
        size_t n = strlen(v);
        if (n >= sizeof t) n = sizeof t - 1;
        memcpy(t, v, n);
        t[n] = '\0';
        while (n > 1 && t[n - 1] == '/') t[--n] = '\0';
        if (strcmp(t, "/") == 0) return true;
        if (strcmp(t, query) == 0) return true;
        if (backing_under_or_eq(query, t)) return true;
        if (backing_under_or_eq(t, query)) {
            if (backing_is_parent(query, t)) return true;
        }
    }
    return false;
}

static bool backing_rule_hits(const AppConfig* c, const char* rule, const char* query) {
    return backing_literal_hits(rule, query) || backing_var_hits(c, rule, query);
}

/* 单段配置是否在该查询路径上产生 per-caller 差异 */
static bool br_cfg_mediates_path(const AppConfig* c, const char* query) {
    if (!c || !query || !query[0]) return false;
    /* MONITOR ON：该段调用者的 IO 需要 daemon 记录（见 br_cfg_touches_data 说明），
       故本子树整体需要仲裁 */
    if (c->monitor) return true;
    /* SANDBOX ON：共享目录重定向 + 跨应用隔离影响整树，任一查询均需仲裁 */
    if (c->sandbox && !g_br_disable_sandbox) return true;
    for (int i = 0; i < c->hide_count; i++) {
        if (!c->hide_rules || !c->hide_rules[i]) continue;
        if (backing_rule_hits(c, c->hide_rules[i], query)) return true;
    }
    for (int i = 0; i < c->ro_count; i++) {
        if (!c->ro_rules || !c->ro_rules[i]) continue;
        if (backing_rule_hits(c, c->ro_rules[i], query)) return true;
    }
    for (int i = 0; i < c->redir_count; i++) {
        if (!c->redir_rules || c->redir_rules[i].is_allow) continue; /* ALLOW 即直通 */
        if (backing_rule_hits(c, c->redir_rules[i].virtual_prefix, query)) return true;
    }
    for (int i = 0; i < c->ftp_count; i++) {
        /* virtual_prefix 是 char[MAX_PATH_LEN]（恒非 NULL），空串由
           backing_rule_hits 内部（backing_literal_hits/backing_var_hits）
           直接判否——此处只需判规则数组本身 */
        if (!c->ftp_rules) continue;
        if (backing_rule_hits(c, c->ftp_rules[i].virtual_prefix, query)) return true;
    }
    return false;
}

bool fw_backing_mediation_required_for(const char* fuse_path) {
    char query[PATH_MAX];
    backing_norm_query(fuse_path, query, sizeof query);
    if (!query[0]) return true; /* 归一失败 fail-closed */
    for (;;) {
        uint64_t cfg_gen = config_read_begin();
        bool need = br_cfg_mediates_path(&g_global_cfg, query);
        if (!need) {
            for (int i = 0; i < g_app_cfg_count; i++) {
                if (g_app_cfgs && br_cfg_mediates_path(g_app_cfgs[i], query)) {
                    need = true;
                    break;
                }
            }
        }
        if (!need && !g_global_cfg.allow_cross_app_data) {
            /* 跨应用隔离（默认生效）：data/obb 子树必须 daemon 仲裁。
               命中判定与规则同口径（自身/其下/直接父），故 /Android 这一层
               也要求仲裁——readdir 要按调用方过滤 data/obb 下的包名 */
            need = backing_literal_hits("/Android/data", query) ||
                   backing_literal_hits("/Android/obb", query);
        }
        if (config_read_end(cfg_gen)) return need;
    }
}
