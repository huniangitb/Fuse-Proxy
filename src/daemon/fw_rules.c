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
#include "nsp_hide_errno.h"
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
   所有调用方（fw_rules_resolve/fw_rules_probe 及其槽内辅助）都持配置读槽
   （config_read_begin），cfg 指针不会被重载并发释放；seqlock 仅需防止并发
   填充互相撕裂。槽外借用白名单等配置指针须走 *_snapshot 入口。 */
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
   ——这就是绕过点，故 resolve 侧必须同样判。
   不隔离的情形：调用方包名不可解析（空/system/unknown，root 与系统工具）、
   目录属主包与调用方**同 uid**（sharedUserId / 系统同进程宿主：Linux DAC 里就是
   同一个 app 身份，只按包名比较会把 android.process.media 读 Downloads 私有目录
   判成跨应用）、[GLOBAL] ALLOW_CROSS_APP_DATA ON（用户显式放行，等于恢复旧行为）。 */
bool fw_rules_cross_app_isolated(void) { return !g_global_cfg.allow_cross_app_data; }

/* 白名单按调用方**自身**包名比较（包名带 ':' 进程后缀时只比基础包名）。
   不做 uid 兜底：uid 相同只说明是同一个 Linux 身份，不说明用户同意它们互读
   私有目录——共享 uid 的兄弟包要跨应用访问，也得各自写进白名单。 */
bool fw_rules_cross_app_pkg_allowed(const char* pkg) {
    if (!pkg || !pkg[0] || g_global_cfg.allow_cross_pkg_count <= 0) return false;
    size_t len = strcspn(pkg, ":");
    if (len == 0) return false;
    for (int i = 0; i < g_global_cfg.allow_cross_pkg_count; i++) {
        const char* entry = g_global_cfg.allow_cross_pkgs[i];
        if (entry && strlen(entry) == len && strncmp(entry, pkg, len) == 0) return true;
    }
    return false;
}

/* 槽内取白名单决定：内部按配置读槽读、重载窗口内重试。
   槽外调用者（如 fw_acl_identity 组装身份）必须用这个入口——白名单数组在
   config_publish 排空旧读者后即随旧配置一起释放，裸读 fw_rules_cross_app_pkg_allowed
   会在重载窗口里比较已释放的条目（现场：一个 FUSE 请求正在 strlen 条目，发布把
   旧数组 free 掉）。持槽后发布者的 config_drain_readers 会等它读完，读到的必是活配置。
   契约：不得在持配置写锁（发布临界区）的线程上调用——那时代际为奇数，
   config_read_begin 会自旋等发布结束，而发布正等本线程。
   本线程**已持读槽**时不能再取一层：外层槽仍被本线程占着，发布者的
   config_drain_readers 等它归零，而内层 config_read_begin 又在等发布结束
   ——两者互等（实测 3s 仍卡在 config_read_begin）。此时外层槽已经把当前配置
   钉住（发布者在排空它之前不会释放旧配置），直接裸读即可，语义等价。 */
bool fw_rules_cross_app_pkg_allowed_snapshot(const char* pkg) {
    if (!pkg || !pkg[0]) return false;
    if (config_read_in_slot()) return fw_rules_cross_app_pkg_allowed(pkg);
    for (;;) {
        uint64_t gen = config_read_begin();
        const bool allowed = fw_rules_cross_app_pkg_allowed(pkg);
        if (config_read_end(gen)) return allowed;
    }
}

bool fw_rules_cross_app_capability(void) { return g_global_cfg.allow_cross_by_capability; }

/* 现场取能力事实：白名单/特权命中就不再问 appops——那是一次 fork 子进程的代价
   （虽然按 uid 缓存 30s），不该为已被前几档否决的判定去付。
   have_whitelist=true 时白名单决定由调用方在槽内先取（槽外调用者必须如此：
   白名单数组随旧配置在发布排空后释放）；组合顺序仍只写在本函数一处。 */
static NspXAppFacts br_xapp_facts_common(const char* pkg, uid_t uid, bool is_obb,
                                         bool whitelisted, bool have_whitelist) {
    NspXAppFacts f = {0};
    f.is_obb = is_obb;
    f.whitelisted = have_whitelist ? whitelisted : fw_rules_cross_app_pkg_allowed(pkg);
    if (f.whitelisted) return f;
    f.privileged = fw_pkg_is_privileged(uid);
    if (f.privileged) return f;
    f.gate = fw_rules_cross_app_capability();
    if (!f.gate) return f;
    f.manage_external = fw_pkg_manages_external(uid);
    if (f.manage_external) return f;
    f.installer = fw_pkg_can_install_packages(uid);
    return f;
}

static NspXAppFacts br_xapp_facts(const char* pkg, uid_t uid, bool is_obb) {
    return br_xapp_facts_common(pkg, uid, is_obb, false, false);
}

NspXAppAccess fw_rules_cross_app_access(const char* pkg, uid_t uid, bool is_obb) {
    NspXAppFacts f = br_xapp_facts(pkg, uid, is_obb);
    return nsp_xapp_access_of(&f);
}

NspXAppAccess fw_rules_cross_app_access_snapshot(const char* pkg, uid_t uid, bool is_obb) {
    /* 只有白名单一档持有配置指针，故只在槽内取这一档；特权/能力查询是外部命令，
       必须留在槽外——把 appops 放回槽里就是本轮修掉的整池停顿。 */
    const bool whitelisted = fw_rules_cross_app_pkg_allowed_snapshot(pkg);
    NspXAppFacts f = br_xapp_facts_common(pkg, uid, is_obb, whitelisted, true);
    return nsp_xapp_access_of(&f);
}

static int br_strip_and_sanitize(const char* path, int* path_user_id_out, char* sub_path_out,
                                 size_t sub_path_size);

/* 槽外预取（实现见 fw_pkg_prefetch_isolation_facts）：能力事实来自一次外部
   命令查询（实测 40ms 量级），放在 config_read_begin/end 槽里就会拖住配置发布
   的读者排空，让之后进入决策的**每个** worker 在 config_read_begin 上自旋——
   单次慢查询放大成整池停顿。故在取槽之前预取。

   预取必须比判定更保守地"少付代价"，否则会把常态请求变成子进程风暴：
   1. 两个总闸（跨应用隔离、按能力放行）关掉时判定根本不问能力，直接不预取；
   2. 调用方自己的子树（含 sharedUserId 兄弟包）在 br_isolation_impl 第一档就
      放行，从不问能力，故先用只读 uid.map 的廉价命名（无 IO）判同包，同名跳过；
      命名拿不到时保守预取——代价只是一次按 uid 缓存 30s 的查询，漏预取却会把
      慢查询放回槽里；
   3. 路径必须按判定同一口径清理后再认前缀：判定用的是 br_strip_and_sanitize
      的 sub_path，而 path_sanitize 会删字节，直接扫原始路径会漏掉"删字节才凑出
      /Android/data/ 前缀"的写法，那种写法能把慢查询原样送回槽内。 */
static void br_prefetch_xapp_facts(const NspQueryCtx* q, const char* path) {
    if (!q || !path) return;
    /* 两个总闸在槽外读：它们在重载窗口内可能正被整结构体发布（撕裂读），
       但这里只读两个 bool，最坏是窗口内多付或少付一次预取（少付那次即修复前
       行为），裁决仍在槽内重读同一开关，不受影响。 */
    if (!fw_rules_cross_app_isolated() || !fw_rules_cross_app_capability()) return;
    char sub_path[PATH_MAX];
    if (br_strip_and_sanitize(path, NULL, sub_path, sizeof sub_path) != 0) return;
    const char* prefixes[] = {"/Android/data/", "/Android/obb/"};
    const char* target = nullptr;
    for (int i = 0; i < 2 && !target; i++) {
        const size_t plen = strlen(prefixes[i]);
        if (strncmp(sub_path, prefixes[i], plen) == 0) target = sub_path + plen;
    }
    /* 容器本身（"…/Android/data"）不预取：条目级 readdir 与按名打开都走
       fw_rules_probe/resolve（已在上面预取），容器级的 fw_rules_readdir_extra
       只处理配置声明的虚拟目录、从不问能力（能力过滤在 fuse_daemon 的槽外），
       故为容器常态 fork 一次不划算。 */
    if (!target) return;
    size_t len = strcspn(target, "/");
    if (len == 0 || len >= 256) return;
    /* .nomedia 是 Android 认的标记名而不是包名：判定在 br_path_other_app_subtree
       里直接当"不是他包"放行、从不问能力，预取也不该为它 fork。 */
    if (len == sizeof(".nomedia") - 1 && memcmp(target, ".nomedia", len) == 0) return;
    char want[256];
    memcpy(want, target, len);
    want[len] = '\0';
    char self[128];
    if (fw_pkg_uid_map_name(q->uid, self, sizeof self) && br_pkg_same_base(want, self)) return;
    fw_pkg_prefetch_isolation_facts(q->uid);
}

/* 纯路径判定：是否指向**他包**的 Android/data|obb 子树。不看开关也不看能力——
   沙盒让位与跨应用隔离都要先认出这条路径形状，两处必须同一口径。
   .nomedia 是 Android 认的标记名而不是包名，不算他包（原生同样放行它）。
   target_out 回填属主包名（可为 NULL），供调用方查 uid。 */
static bool br_path_other_app_subtree(const char* sub_path, const char* current_pkg,
                                      char* target_out, size_t target_size) {
    if (target_out && target_size) target_out[0] = '\0';
    if (!sub_path || !current_pkg || !current_pkg[0]) return false;
    if (strcmp(current_pkg, "system") == 0 || strcmp(current_pkg, "unknown") == 0) return false;
    const char* prefixes[] = {"/Android/data/", "/Android/obb/"};
    for (int i = 0; i < 2; i++) {
        size_t plen = strlen(prefixes[i]);
        if (strncmp(sub_path, prefixes[i], plen) != 0) continue;
        const char* pkg_start = sub_path + plen;
        const char* slash = strchr(pkg_start, '/');
        size_t pkg_len = slash ? (size_t)(slash - pkg_start) : strlen(pkg_start);
        if (pkg_len == 0 || pkg_len >= 256) return false;
        char target[256];
        memcpy(target, pkg_start, pkg_len);
        target[pkg_len] = '\0';
        if (strcmp(target, ".nomedia") == 0) return false;
        if (target_out && target_size > pkg_len) snprintf(target_out, target_size, "%s", target);
        return !br_pkg_same_base(target, current_pkg);
    }
    return false;
}

/* Android 树里必须留在真实目录上的部分——沙盒不接管，落回原生裁决：
   1. `/Android/data|obb|media` 三个容器本身：ACL 当骨架目录（readdir 由 ACL
      拒绝），容器内每个 `<pkg>` 要单独按调用方能力裁决，镜像化后这些裁决全部
      对着空目录做，等于把容器的语义抹掉；
   2. 调用方自己在三个容器里的私有目录：原生在这里提供挂载点、引用、媒体扫描
      等行为，镜像会把它降级成一个普通目录；
   3. 他包 `Android/data|obb` 子树：由调用方另行经 br_path_other_app_subtree
      让位，交回隔离判据（沙盒不参与跨应用裁决）。

   `/Android` 本身不在让位之列：它必须和应用新建的条目一样指向镜像，否则应用
   创建完再列举会发现条目不见了（镜像里有、真实目录里没有）。 */
static bool br_path_android_passthrough(const char* sub_path, const char* current_pkg) {
    if (!sub_path || !current_pkg || !current_pkg[0]) return false;
    if (strncmp(sub_path, "/Android", 8) != 0) return false;
    if (sub_path[8] != '\0' && sub_path[8] != '/') return false;
    static const char* const k_containers[] = {"/Android/data", "/Android/obb", "/Android/media"};
    const size_t pkg_len = strlen(current_pkg);
    for (size_t i = 0; i < sizeof(k_containers) / sizeof(k_containers[0]); i++) {
        const char* container = k_containers[i];
        const size_t clen = strlen(container);
        if (strncmp(sub_path, container, clen) != 0) continue;
        if (sub_path[clen] == '\0' || (sub_path[clen] == '/' && sub_path[clen + 1] == '\0'))
            return true; /* 容器本身（含尾斜杠写法） */
        if (sub_path[clen] != '/') continue; /* /Android/database 之类：不是这个容器 */
        const char* rest = sub_path + clen + 1;
        if (strncmp(rest, current_pkg, pkg_len) == 0 &&
            (rest[pkg_len] == '\0' || rest[pkg_len] == '/'))
            return true; /* 自己包名的私有目录 */
    }
    return false;
}

/* 目标是否落在 Android/obb 下：安装器那一档的放行面只有这一类。 */
static bool br_path_is_obb_subtree(const char* sub_path) {
    return sub_path && strncmp(sub_path, "/Android/obb/", 13) == 0;
}

static bool br_is_other_app_pkg(const char* sub_path, const char* current_pkg, uid_t uid) {
    char target_pkg[256];
    if (!br_path_other_app_subtree(sub_path, current_pkg, target_pkg, sizeof target_pkg))
        return false;
    if (g_global_cfg.allow_cross_app_data) return false;
    /* 同 uid 多包 = 同一 app 身份（见上方注释）：目标目录属主 uid 等于调用方 uid
       时不算"他应用"。解析不到属主 uid 则维持隔离。 */
    uid_t owner_uid = 0;
    if (fw_pkg_uid_for_package(target_pkg, &owner_uid) && owner_uid == uid) return false;
    return true;
}

static void br_trie_resolve(AppConfig* cfg, AppConfig* cat, const char* sub_path, FwRulesTrieMatch* out) {
    if (!out) return;
    out->valid = true;
    out->hidden = false;
    out->ro = false;
    out->hidden_app = out->hidden_cat = out->hidden_global = false;
    out->ro_app = out->ro_cat = out->ro_global = false;
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
        if (h) {
            out->hidden = true;
            out->hidden_app = true;
        }
        if (r) {
            out->ro = true;
            out->ro_app = true;
        }
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
    /* 类别层（USER_APPS/SYSTEM_APPS）：逐作用域记录 hidden/ro（供作用域优先比较，不再
       并集），redir 仅 app 未命中时补 */
    if (cat && cat->trie_root) {
        bool h = false, r = false;
        char redir[PATH_MAX];
        redir[0] = '\0';
        char ftp[64];
        ftp[0] = '\0';
        out->cat_node = trie_lookup_full(cat->trie_root, sub_path, &h, &r, redir, sizeof(redir),
                                         ftp, sizeof(ftp));
        if (h) {
            out->hidden = true;
            out->hidden_cat = true;
        }
        if (r) {
            out->ro = true;
            out->ro_cat = true;
        }
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
        if (h) {
            out->hidden = true;
            out->hidden_global = true;
        }
        if (r) {
            out->ro = true;
            out->ro_global = true;
        }
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
   判定——隐藏是"所有访问者一视同仁"的静态事实，隔离依赖调用方身份与能力档：
   resolve 侧走 br_isolation_blocks()，probe 侧走 br_isolation_hides()，两者
   只是同一实现（br_isolation_impl）的两个入口，差别仅在隔离命中时记不记日志。
   旧实现只在 probe 过滤列举、resolve 放过，等于任何按名打开都能读到
   /Android/data/<他包>/ 的内容。 */
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
        char normalized[PATH_MAX];
        const char* match_str = rule;
        if (has_path_var(rule)) {
            if (!pkg_resolvable(current_pkg)) continue;
            if (!expand_path_vars(rule, expanded, sizeof expanded, scope, &g_global_cfg,
                                  current_pkg))
                continue;
            /* 展开结果须与静态规则同形态（变量值可能自带前导 '/'、或写
               /sdcard、/storage/emulated/0 前缀）——不归一会得到 "//storage/..." */
            if (!normalize_expanded_rule_path(expanded, normalized, sizeof normalized)) continue;
            match_str = normalized;
        }
        if (fnmatch(match_str, sub_path, 0) == 0) return true;
        size_t len = strlen(match_str);
        if (strncmp(sub_path, match_str, len) == 0 &&
            (sub_path[len] == '\0' || sub_path[len] == '/'))
            return true;
    }
    return false;
}

/* ============ 作用域优先声明解析（前置声明） ============
   定义在 br_check_redir_rule 之后（线性通道的 ALLOW/REDIRECT 判定要复用同一匹配
   实现，见 docs/config.md §2「应用专属 > 类别 > GLOBAL」）。hide/ro 判定在文件
   更早处就要用到它，故此处先声明。 */
typedef struct {
    bool hide;      /* 该层声明 HIDE */
    bool allow;     /* 该层声明 ALLOW（放行到真实路径） */
    bool ro;        /* 该层声明 RO */
    bool has_redir; /* 该层声明 REDIRECT：目标已填入 redir */
    char redir[PATH_MAX];
} BrScopeDecl;

/* 查询轴：ALLOW 在三条轴上都是声明（放行 = 可见 + 非只读 + 真实路径），
   故一律终止；其余三种各属一条轴，跨轴不互相遮蔽，避免「应用段 RO 顺手把
   GLOBAL 的 HIDE 也顶掉」这类意外（隐私面宁可保守）。 */
enum {
    BR_WANT_VIS = 1u << 0, /* 可见性：HIDE */
    BR_WANT_RO = 1u << 1,  /* 只读：RO（与 BR_WANT_LOC 合用，令高作用域 REDIRECT 遮蔽低作用域 RO） */
    BR_WANT_LOC = 1u << 2, /* 落点：REDIRECT */
};

/* 逐层询问后取**最高**声明作用域；本轴在三层都无声明时 *scope_out = BR_SCOPE_NONE。
   want 见上面的 BR_WANT_*。 */
static void br_resolve_decl(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                            const char* current_pkg, const FwRulesTrieMatch* tm, int user_id,
                            uid_t uid, char* mkdir_out, size_t mkdir_sz, unsigned want,
                            BrRuleScope* scope_out, BrScopeDecl* out);

/* 生效沙盒的**声明作用域**（BR_SCOPE_NONE = 沙盒不生效）。ALLOW 能否豁免沙盒要用
   它：只有「不低於沙盒声明作用域」的 ALLOW 才放行——应用段显式 SANDBOX ON 时，
   [GLOBAL] 的 ALLOW 不得在该应用里凿洞（否则全局 ALLOW 一动，应用段沙盒/
   HIDE 就全体失效）。 */
static BrRuleScope br_sandbox_scope(AppConfig* cfg, AppConfig* cat, const char* current_pkg);

static void br_note_hide_rule(uid_t uid, const char* pkg, const char* sub_path);

/* 隐藏判定：作用域优先（应用段 > 类别段 > [GLOBAL]）。
   每层按 ALLOW > HIDE > RO > REDIRECT 取一个结论（同层放行优先，见 br_scope_decl）；
   **第一个有声明的作用域说了算**，下层的声明不再参与。旧实现把三层 HIDE 做并集，
   于是 GLOBAL 恒赢、应用段 ALLOW 永远无法取消下层 HIDE（docs/config.md §2 的优先级
   只在 REDIRECT 上落实过）。scope_out 回填给出该结论的作用域（骨架/CONFIG_DIR 等
   内建隐藏不属于任何规则作用域，保持 BR_SCOPE_NONE）。 */
static bool br_is_path_hidden_internal(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                                       const char* current_pkg, const FwRulesTrieMatch* tm,
                                       uid_t uid, BrRuleScope* scope_out) {
    if (scope_out) *scope_out = BR_SCOPE_NONE;
    bool is_skel = false;
    /* 静态部分只保留 CONFIG_DIR 前缀与 Android 骨架两支：**不能**传 tm 下去，因为
       br_hidden_static_part 内部的 tm->hidden 是跨作用域并集，会让全局 HIDE 在逐层
       判定之前就短路成 hidden（应用段/类别段的 ALLOW 再也取消不掉 → 违反作用域优先）。
       隐藏结论统一由下面的 br_resolve_decl 按 应用 > 类别 > GLOBAL 给出。 */
    if (br_hidden_static_part(sub_path, current_pkg, NULL, &is_skel)) return true;
    if (is_skel) return false; /* 骨架目录恒不隐藏（原逻辑提前返回，不扫 hide） */
    BrRuleScope scope = BR_SCOPE_NONE;
    BrScopeDecl decl;
    br_resolve_decl(cfg, cat, sub_path, current_pkg, tm, -1, 0, NULL, 0, BR_WANT_VIS, &scope,
                    &decl);
    if (decl.hide) {
        br_note_hide_rule(uid, current_pkg, sub_path);
        if (scope_out) *scope_out = scope;
    }
    return decl.hide;
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

/* 隐藏规则命中的限速观测（WARN）：命中 HIDE 是**静默 ENOENT**，现场只看到文件
   不存在，分不清是规则拦的还是真没有（Photo Picker 读 `/.picker_transcoded`
   这类缓存目录时尤其难查）。首个命中与每 1024 次各一条，带调用方 uid/包名与
   判定路径。骨架/CONFIG_DIR 等内部隐藏不在此列，只记用户规则命中。 */
static void br_note_hide_rule(uid_t uid, const char* pkg, const char* sub_path) {
    static atomic_ulong seq;
    static atomic_uint callers; /* 按包名哈希的位图：每个调用方首次命中各记一条 */
    const char* name = pkg && pkg[0] ? pkg : "?";
    unsigned long n = atomic_fetch_add_explicit(&seq, 1, memory_order_relaxed) + 1;
    unsigned hash = 2166136261u;
    for (const char* p = name; *p; p++) hash = (hash ^ (unsigned char)*p) * 16777619u;
    unsigned bit = hash & 31u;
    unsigned seen = atomic_fetch_or_explicit(&callers, 1u << bit, memory_order_relaxed);
    if (!(seen & (1u << bit)) || (n & 1023u) == 0)
        LOG_WRN("隐藏规则命中: uid=%u 包名=%s %s（累计 %lu 次）", (unsigned)uid, name, sub_path,
                n);
}

/* 媒体提供者（\`com.android.providers.media*\`，含 \`.module\`）不参与沙盒裁决：
   它的存储视图是第三方应用取字节的通道（Photo Picker、缩略图、转码），把它的
   打开请求重定向进空沙盒目录会让所有未被 ALLOW 覆盖的媒体 ENOENT。v1 按应用
   挂载时本就不给媒体提供者挂 FUSE 实例（mount_manager 的 use_global_sandbox
   口径），此处与之对齐。 */
static bool br_media_provider_exempt(const char* pkg) {
    return pkg && pkg[0] && is_media_provider(pkg);
}

/* 媒体提供者显式写 SANDBOX ON：语义上无法实现（picker 必然 ENOENT），不能静默
   吞掉。选择告警后忽略而不是拒绝加载整份配置——后者会让该设备上其余应用的规则
   一并失效，代价远大于一个被忽略的开关。每进程一条，避免配置热重载刷屏。 */
static void br_note_media_sandbox_ignored(const char* pkg) {
    static atomic_flag once = ATOMIC_FLAG_INIT;
    if (!atomic_flag_test_and_set_explicit(&once, memory_order_relaxed))
        LOG_WRN("媒体提供者不参与沙盒：忽略 %s 的 SANDBOX ON（picker 取字节会 ENOENT）", pkg);
}

/* 生效沙盒的**声明作用域**（三层合并：应用显式 > 应用非显式 ON > 类别显式 >
   类别 ON > [GLOBAL]；--disable-sandbox 全局关闭；媒体提供者恒不生效）。
   BR_SCOPE_NONE =
   沙盒不生效。供 br_to_real_path 比较「ALLOW 能否豁免沙盒」：ALLOW 的作用域必须
   不低于沙盒的声明作用域，否则全局 ALLOW 会把应用段显式声明的沙盒整个取消。 */
static BrRuleScope br_sandbox_scope(AppConfig* cfg, AppConfig* cat, const char* current_pkg) {
    if (g_br_disable_sandbox) return BR_SCOPE_NONE;
    if (br_media_provider_exempt(current_pkg)) {
        if ((cfg && cfg->sandbox_explicit && cfg->sandbox) ||
            (cat && cat->sandbox_explicit && cat->sandbox))
            br_note_media_sandbox_ignored(current_pkg);
        return BR_SCOPE_NONE;
    }
    if (cfg && cfg->sandbox_explicit) return cfg->sandbox ? BR_SCOPE_APP : BR_SCOPE_NONE;
    if (cfg && cfg->sandbox) return BR_SCOPE_APP;
    if (cat && cat->sandbox_explicit) return cat->sandbox ? BR_SCOPE_CAT : BR_SCOPE_NONE;
    if (cat && cat->sandbox) return BR_SCOPE_CAT;
    return g_global_cfg.sandbox ? BR_SCOPE_GLOBAL : BR_SCOPE_NONE;
}

/* 前向声明：隔离判定要问「这条路径上有没有显式声明」，实现排在规则求值函数
   （br_scope_decl 是"某作用域对某路径的结论"的唯一出口）之后。 */
static bool br_decl_present(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                            const char* current_pkg, const FwRulesTrieMatch* tm, int user_id,
                            uid_t uid);

/* 跨应用隔离是否拦下本路径。resolve 与列举共用同一份实现，只差"要不要记一条
   拒绝日志"，故两处判定不会分叉（分叉的现场表现：列表看得到、按名打开却 ENOENT）。

   放行链，顺序即优先级，每一档都对应原生的一条判据：
   1. 不是他包路径 → 不归这条规则管；
   2. 媒体提供者 → 不参与（它按设计读 /Android/data 里的媒体内容，拦下会让
      picker 取不到字节）；
   3. **显式声明优先**：该路径上任何作用域写了 ALLOW / HIDE / RO / REDIRECT，
      隔离让位，交给规则层自己裁决——隔离是"没有规则时的默认边界"，不是能压过
      用户配置的硬墙；
   4. 能力档（NspXAppAccess）：显式白名单、platform 签名、MANAGE_EXTERNAL_STORAGE
      全放，能装包的应用只放 Android/obb；组合排序只写在 nsp_xapp_access_of 一处。
   同 uid 内的多包（sharedUserId / 系统同进程宿主）在 br_is_other_app_pkg 里已按
   uid 视为同一应用。其余情形：看不见 = 打不开（与 HIDE 同口径）。 */
static bool br_isolation_impl(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                              const char* current_pkg, uid_t uid, const FwRulesTrieMatch* tm,
                              int user_id, bool note) {
    if (!br_is_other_app_pkg(sub_path, current_pkg, uid)) return false;
    if (br_media_provider_exempt(current_pkg)) return false;
    if (br_decl_present(cfg, cat, sub_path, current_pkg, tm, user_id, uid)) return false;
    if (fw_rules_cross_app_access(current_pkg, uid, br_path_is_obb_subtree(sub_path)) !=
        NSP_XAPP_NONE)
        return false;
    if (note) br_note_isolation(current_pkg, sub_path);
    return true;
}

static bool br_isolation_blocks(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                                const char* current_pkg, uid_t uid, const FwRulesTrieMatch* tm,
                                int user_id) {
    return br_isolation_impl(cfg, cat, sub_path, current_pkg, uid, tm, user_id, true);
}

static bool br_isolation_hides(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                               const char* current_pkg, uid_t uid, const FwRulesTrieMatch* tm,
                               int user_id) {
    return br_isolation_impl(cfg, cat, sub_path, current_pkg, uid, tm, user_id, false);
}

static int br_sanitize_and_check_hidden(AppConfig* cfg, AppConfig* cat, const char* path,
                                        int* path_user_id_out, char* sub_path_out,
                                        size_t sub_path_size, const char* current_pkg, uid_t uid,
                                        FwRulesTrieMatch* tm_out, BrRuleScope* scope_out) {
    if (scope_out) *scope_out = BR_SCOPE_NONE;
    if (br_strip_and_sanitize(path, path_user_id_out, sub_path_out, sub_path_size) != 0)
        return -ENOENT;
    if (tm_out) br_trie_resolve(cfg, cat, sub_path_out, tm_out);
    /* 隐藏判定对所有访问者生效（含 root，与 vfs_readdir probe 过滤一致）：
       HIDE 规则配置后，root ls 也不应看到被隐藏条目 */
    if (br_is_path_hidden_internal(cfg, cat, sub_path_out, current_pkg, tm_out, uid, scope_out))
        return -nsp_hide_errno_of(g_global_cfg.hide_errno);
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

/* sandbox_out：命中来源于 SANDBOX 重定向（而非显式 REDIRECT 规则）。调用方
   （fw_rules_resolve → NspPathDecision.is_sandbox）据此向外部通道如实报告成因——
   沙盒路径与普通重定向路径对扫描侧的意义不同（前者是应用私有副本）。
   skip_sandbox=true 的调用（专用沙盒查询）传 NULL。 */
static bool br_check_redir_rule(AppConfig* c, const char* sub_path, char* temp, int user_id,
                                const char* current_pkg, bool skip_sandbox, size_t temp_size,
                                uid_t uid, char* mkdir_out, size_t mkdir_sz, bool* sandbox_out,
                                bool* allow_out) {
    if (allow_out) *allow_out = false;
    if (!c) return false;
    bool matched = false;
    if (c->redir_rules && c->redir_count > 0) {
        /* 两趟：先 REDIRECT 后 ALLOW。同一虚拟前缀上同时写了 ALLOW 与 REDIRECT 时
           REDIRECT 胜——ALLOW 的语义是「不重定向（放行到自身）」，显式改写目标更具体；
           这与旧实现「同节点后写覆盖先写」（trie_insert 用同一虚拟前缀覆盖 target）
           的观测结果一致，test_rules 的 ALLOW+REDIRECT 用例按此断言。 */
        for (int pass = 0; pass < 2 && !matched; pass++)
        for (int i = 0; i < c->redir_count; i++) {
            const bool want = (pass == 0) ? !c->redir_rules[i].is_allow : c->redir_rules[i].is_allow;
            if (!want) continue;
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
                if (allow_out) *allow_out = true;
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
        /* /Android 只有四处让位真实目录，其余整树进镜像——判据只在
           br_path_android_passthrough 一处，没有第二套口径。 */
        if (br_path_android_passthrough(sub_path, current_pkg)) return false;
        /* 他包 Android/data|obb 子树不归沙盒管：原生这里由 MediaProvider 按调用方
           能力/挂载模式裁决（放行，或者 ENOENT），沙盒把它改写成自己的镜像会掩盖
           那个裁决——能力放行者读到空目录，非放行者拿到的 ENOENT 也不是原生的原因。
           交回隔离层按同一套能力判据裁决（见 br_isolation_impl）。 */
        if (br_path_other_app_subtree(sub_path, current_pkg, NULL, 0)) return false;
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
        if (sandbox_out) *sandbox_out = true;
        return true;
    }
    return false;
}

/* 单作用域对该路径的声明（作用域优先判定的原子结论）。整合该层静态（Trie）与线性
   （通配/变量）两个通道——Trie 只是静态规则的加速索引，**不是**更高的优先级层。
   同层冲突按 ALLOW > HIDE > RO > REDIRECT 裁决：同一层里 ALLOW 与 HIDE 同时命中时
   放行生效。放行是"用户点名要这条路径可用"的声明，比拒绝更具体；反过来让 HIDE 压过
   ALLOW，同层一条路级 HIDE 就能把精心写的 ALLOW 全部作废（跨进程两侧也因此对同一份
   配置给出相反结论——MPM 侧本就是放行优先）。**作用域次序不受影响**：应用段 HIDE
   仍然压过 [GLOBAL] ALLOW，只有同一层内部的冲突按本规则裁决。 */
static void br_scope_decl(AppConfig* c, BrRuleScope scope, const char* sub_path,
                          const char* current_pkg, const FwRulesTrieMatch* tm, int user_id,
                          uid_t uid, char* mkdir_out, size_t mkdir_sz, BrScopeDecl* out) {
    memset(out, 0, sizeof *out);
    if (!c) return;
    bool static_hide = false;
    bool static_ro = false;
    if (tm && tm->valid) {
        switch (scope) {
            case BR_SCOPE_APP:
                static_hide = tm->hidden_app;
                static_ro = tm->ro_app;
                break;
            case BR_SCOPE_CAT:
                static_hide = tm->hidden_cat;
                static_ro = tm->ro_cat;
                break;
            case BR_SCOPE_GLOBAL:
                static_hide = tm->hidden_global;
                static_ro = tm->ro_global;
                break;
            default: break;
        }
    } else if (c->trie_root) {
        /* tm 无效（调用方未给缓存）时逐层现查 trie，保持旧兜底语义 */
        bool h = false;
        bool r = false;
        char tgt[PATH_MAX];
        tgt[0] = '\0';
        if (trie_lookup(c->trie_root, sub_path, &h, &r, tgt, sizeof tgt)) {
            static_hide = h;
            static_ro = r;
        }
    }
    /* 落点（ALLOW / REDIRECT）**不取 trie 目标字符串**：parse 期两者都编码成
       "?<path>" 内部前缀（parse_redirect_rule 的 else 分支、parse_allow_rule 同一
       形态），从字符串上区分不出「放行到自身真实路径」与「重写到另一路径」。二者
       语义不同（只有 ALLOW 才是可被高作用域沙盒压过的"透传"，REDIRECT 永远改写），
       故落点一律走线性实现 br_check_redir_rule —— 它的 is_allow 是唯一权威。
       代价：该层有 redir 规则时每请求一次 O(redir_count) 线性扫描；无 redir 规则
       时零成本。静态隐藏命中也要扫这一遍——跳过就不知道这一层有没有点名放行。 */
    bool dyn_hide = false;
    bool dyn_ro = false;
    bool dyn_allow = false;
    char dyn_redir[PATH_MAX];
    dyn_redir[0] = '\0';
    /* ALLOW 先算，且**不受 static_hide 短路**：放行压过同层隐藏，静态隐藏命中时仍要
       知道这一层有没有点名放行（旧实现在此处整段跳过动态判定，于是「静态 HIDE +
       通配/变量 ALLOW」永远落在 HIDE，同层放行优先根本无从生效）。 */
    if (c->redir_rules && c->redir_count > 0) {
        bool is_allow = false;
        if (br_check_redir_rule(c, sub_path, dyn_redir, user_id, current_pkg, true,
                                sizeof dyn_redir, uid, mkdir_out, mkdir_sz, NULL, &is_allow)) {
            if (is_allow) {
                dyn_redir[0] = '\0';
                dyn_allow = true;
            }
        }
    }
    if (!dyn_allow) {
        if (c->dyn_hide && c->hide_rules)
            dyn_hide = br_linear_match(c->hide_rules, c->hide_count, sub_path, current_pkg, c);
        if (!static_hide && !dyn_hide && c->dyn_ro && c->ro_rules)
            dyn_ro = br_linear_match(c->ro_rules, c->ro_count, sub_path, current_pkg, c);
    }
    if (dyn_allow) {
        out->allow = true;
        return;
    }
    if (static_hide || dyn_hide) {
        out->hide = true;
        return;
    }
    out->ro = static_ro || dyn_ro;
    if (dyn_redir[0] != '\0') {
        out->has_redir = true;
        snprintf(out->redir, sizeof out->redir, "%s", dyn_redir);
    }
}

/* 三个作用域里有没有显式声明（只问"有/无"，不问是哪一种）：跨应用隔离用它在
   隔离与放行之间做第一道分岔。逐层独立求值而不是取合并视图——低作用域的规则
   同样算"用户说过话"，不该被 [GLOBAL] 的沉默抹掉。 */
static bool br_decl_present(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                            const char* current_pkg, const FwRulesTrieMatch* tm, int user_id,
                            uid_t uid) {
    static const BrRuleScope k_order[] = {BR_SCOPE_APP, BR_SCOPE_CAT, BR_SCOPE_GLOBAL};
    for (size_t i = 0; i < sizeof(k_order) / sizeof(k_order[0]); i++) {
        AppConfig* c = br_scope_cfg(cfg, cat, k_order[i]);
        if (!c) continue;
        BrScopeDecl d;
        br_scope_decl(c, k_order[i], sub_path, current_pkg, tm, user_id, uid, NULL, 0, &d);
        if (d.allow || d.hide || d.ro || d.has_redir) return true;
    }
    return false;
}

/* 作用域优先（docs/config.md §2）：从应用段向 [GLOBAL] 逐层询问，**第一个**在查询轴
   上"说了话"的作用域决定结果。旧实现把 HIDE/RO 做三层并集、只有 REDIRECT 逐层比较，
   于是「[GLOBAL] 的 HIDE 恒赢」——应用段 ALLOW 永远取消不掉全局 HIDE，看起来
   就像单应用规则的优先级低于全局。 */
static void br_resolve_decl(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                            const char* current_pkg, const FwRulesTrieMatch* tm, int user_id,
                            uid_t uid, char* mkdir_out, size_t mkdir_sz, unsigned want,
                            BrRuleScope* scope_out, BrScopeDecl* out) {
    static const BrRuleScope k_order[] = {BR_SCOPE_APP, BR_SCOPE_CAT, BR_SCOPE_GLOBAL};
    if (scope_out) *scope_out = BR_SCOPE_NONE;
    memset(out, 0, sizeof *out);
    for (size_t i = 0; i < sizeof(k_order) / sizeof(k_order[0]); i++) {
        AppConfig* c = br_scope_cfg(cfg, cat, k_order[i]);
        if (!c) continue;
        BrScopeDecl d;
        br_scope_decl(c, k_order[i], sub_path, current_pkg, tm, user_id, uid, mkdir_out, mkdir_sz,
                      &d);
        bool hit = d.allow || (d.hide && (want & BR_WANT_VIS)) || (d.ro && (want & BR_WANT_RO)) ||
                   (d.has_redir && (want & BR_WANT_LOC));
        if (!hit) continue;
        if (scope_out) *scope_out = k_order[i];
        *out = d;
        return;
    }
}

/* 沙盒落点补建（**槽外**）：决策阶段（config_read_begin 持槽内）只记录待建目录，
   出槽后在此补建——持槽内做 FS 操作会在慢存储上放大发布线程等读者归零的全局停顿
   （C1），也避免给 resolve 热路径引入副作用与 TOCTOU。目录已存在或补建失败都不影响
   已算出的真实路径：后续 open/mkdir 以真实 errno 裁决。 */
static void br_ensure_sandbox_dir(const char* dir) {
    if (!dir || !dir[0]) return;
    /* Android 根参与沙盒镜像，须在内核 lookup 父目录之前补建。先检查完整路径，
       放不下就不做 FS 操作；不缓存“已建好”，同线程删除/重载后仍须修复。 */
    char sub_android[PATH_MAX];
    if (common_storage_child_path(dir, "Android", sub_android, sizeof sub_android) < 0) return;
    /* 落点经守卫出口补建：effective_uid 来自路径解析（无存在性校验的历史形态），
       若一级组件缺失不得替应用在存储根下 materialize 出目录（见 common.h）。 */
    const char* failed_dir = dir;
    if (access(dir, F_OK) == 0 || common_mkdir_within_storage(dir, 0775) == 0) {
        /* 只补 Android 本身；data/obb/media 容器及自家私有目录仍让位真实树。
           新增子目录只走逐组件 nofollow/dirfd 出口，避免 root/祖先/child 链接向外写。 */
        if (common_mkdir_storage_child(dir, "Android", 0775) == 0) return;
        failed_dir = sub_android;
    }
    /* 补建失败不改裁决（后续 open/mkdir 以真实 errno 收场），但要留观测：
       落点是我们自己改写的，应用侧只会看到「文件不在」，分不清是规则问题还是
       目录没建起来。限速与本文件其它观测同节奏：首个命中与每 1024 次各一条。 */
    int mkdir_errno = errno;
    static atomic_ulong fail_seq;
    unsigned long n = atomic_fetch_add_explicit(&fail_seq, 1, memory_order_relaxed) + 1;
    if (n == 1 || (n & 1023u) == 0)
        LOG_WRN("沙盒落点补建失败: %s errno=%d（累计 %lu 次）", failed_dir, mkdir_errno, n);
}

/* 沙盒重定向的限速观测（WARN）：现场遇到 ENOENT 时先看这里——路径是被我们改写
   进沙盒镜像的，不是文件不在。首个命中与每 1024 次各一条，带调用方 uid/包名、
   原路径与落点（日志在槽外异步投递，与 br_note_isolation 同一节奏）。 */
static void br_note_sandbox_redirect(uid_t uid, const char* pkg, const char* sub_path,
                                     const char* target) {
    static atomic_ulong seq;
    unsigned long n = atomic_fetch_add_explicit(&seq, 1, memory_order_relaxed) + 1;
    if (n == 1 || (n & 1023u) == 0)
        LOG_WRN("沙盒重定向: uid=%u 包名=%s %s → %s（累计 %lu 次）", (unsigned)uid,
                pkg && pkg[0] ? pkg : "?", sub_path, target, n);
}

/* scope_out/kind_out：回填"落点结论由哪个作用域、哪类规则给出"（对外通道的
   归因，不参与决策）。ALLOW 与 REDIRECT 在 is_redir_out 上都是 true——两者都改写了
   落点，只有本函数的 kind_out 能把"放行到自身"与"改写到别处"分开。 */
static int br_to_real_path(AppConfig* cfg, AppConfig* cat, const char* sub_path, char* out_buf,
                           size_t size, int user_id, bool* is_redir_out, bool* is_sandbox_out,
                           const char* current_pkg, const FwRulesTrieMatch* tm, uid_t uid,
                           char* mkdir_out, size_t mkdir_sz, BrRuleScope* scope_out,
                           uint8_t* kind_out) {
    char temp[PATH_MAX] = {0};
    bool redir = false;
    bool sandbox = false;
    if (is_sandbox_out) *is_sandbox_out = false;
    if (scope_out) *scope_out = BR_SCOPE_NONE;
    if (kind_out) *kind_out = NSP_RULE_NONE;

    /* 落点解析：作用域优先（docs/config.md §2）。先取「最高声明作用域」的落点结论：
       ALLOW → 放行到自身存储；REDIRECT → 改写目标；都没有 → 按 sandbox 三层
       （顺序与旧实现一致）或默认真实路径。
       关键修正：**低作用域的 ALLOW 不得豁免高作用域声明的沙盒**——应用段显式
       SANDBOX ON 时，[GLOBAL] 的 ALLOW 不能在该应用里凿洞（旧实现只要 phase ①
       命中 ANY ALLOW 就整体跳过 sandbox 分支，于是全局 ALLOW 一动，全局/应用段
       声明的沙盒对同路径全线失效，应用段看起来就继承不到全局沙盒）。 */
    BrRuleScope decl_scope = BR_SCOPE_NONE;
    BrScopeDecl decl;
    br_resolve_decl(cfg, cat, sub_path, current_pkg, tm, user_id, uid, mkdir_out, mkdir_sz,
                    BR_WANT_LOC, &decl_scope, &decl);
    const BrRuleScope sandbox_scope = br_sandbox_scope(cfg, cat, current_pkg);
    bool allow_effective =
        decl.allow && (sandbox_scope == BR_SCOPE_NONE || decl_scope >= sandbox_scope);
    if (decl.allow && !allow_effective) {
        /* 被更高作用域的沙盒压过：按「无落点声明」处理，落回 sandbox 分支 */
        memset(&decl, 0, sizeof decl);
        decl_scope = BR_SCOPE_NONE;
    }
    if (decl.allow) {
        /* 与旧实现一致：ALLOW 记为「重定向」，真实路径就是默认路径 */
        common_default_real_path(user_id, sub_path, temp, sizeof(temp));
        redir = true;
        if (scope_out) *scope_out = decl_scope;
        if (kind_out) *kind_out = NSP_RULE_ALLOW;
    } else if (decl.has_redir) {
        snprintf(temp, sizeof temp, "%s", decl.redir);
        redir = true;
        if (scope_out) *scope_out = decl_scope;
        if (kind_out) *kind_out = NSP_RULE_REDIRECT;
    } else if (decl.hide) {
        return -ENOENT; /* 防御：隐藏应由调用方先行判定，走到这里说明判定被绕过 */
    }
    if (redir && temp[0] == '?') {
        int effective_uid = user_id >= 0 ? user_id : 0;
        char real_base[1024];
        common_default_real_path(effective_uid, temp + 1, real_base, sizeof(real_base));
        snprintf(temp, sizeof temp, "%s", real_base);
    }
    /* sandbox 三层：应用显式 OFF 否决类别+全局；类别显式 OFF 否决全局；
       应用显式 ON（或类别显式 ON 且应用未显式）时各自 sandbox 生效 */
    bool app_sandbox_off = (cfg && cfg->sandbox_explicit && !cfg->sandbox);
    bool cat_sandbox_off = (!app_sandbox_off && cat && cat->sandbox_explicit && !cat->sandbox);
    if (!redir && sandbox_scope != BR_SCOPE_NONE) {
        if (!app_sandbox_off)
            redir = br_check_redir_rule(cfg, sub_path, temp, user_id, current_pkg, false,
                                        sizeof(temp), uid, mkdir_out, mkdir_sz, &sandbox, NULL);
        if (!redir && !app_sandbox_off)
            redir = br_check_redir_rule(cat, sub_path, temp, user_id, current_pkg, false,
                                        sizeof(temp), uid, mkdir_out, mkdir_sz, &sandbox, NULL);
        if (!redir && !app_sandbox_off && !cat_sandbox_off)
            redir = br_check_redir_rule(&g_global_cfg, sub_path, temp, user_id, current_pkg, false,
                                        sizeof(temp), uid, mkdir_out, mkdir_sz, &sandbox, NULL);
    }
    if (!redir) {
        common_default_real_path(user_id, sub_path, temp, sizeof(temp));
    } else if (sandbox) {
        /* 沙盒分支产出的落点与显式 REDIRECT 同形（都是改写），成因用沙盒声明作用域
           标注；显式规则的落点已在上面写好，这里只覆盖沙盒成因 */
        if (scope_out) *scope_out = sandbox_scope;
        if (kind_out) *kind_out = NSP_RULE_SANDBOX;
    }
    strncpy(out_buf, temp, size - 1);
    out_buf[size - 1] = '\0';
    if (is_redir_out) *is_redir_out = redir;
    if (is_sandbox_out) *is_sandbox_out = sandbox && redir;
    if (sandbox && redir) br_note_sandbox_redirect(uid, current_pkg, sub_path, out_buf);
    if (out_buf[0] == '\0') return -ENOENT;
    return 0;
}

/* 只读判定：同样作用域优先（应用段 > 类别段 > [GLOBAL]）。
   BR_WANT_RO|BR_WANT_LOC 的用意：高作用域的 REDIRECT 也遮蔽低作用域的 RO（路径已被
   改写成别处，低层再判只读没有意义），但 HIDE 不参与本查询——它已在可见性判定里
   先行返回 ENOENT，此处不必重复。 */
static bool br_is_path_ro(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                          const char* current_pkg, const FwRulesTrieMatch* tm,
                          BrRuleScope* scope_out) {
    BrRuleScope scope = BR_SCOPE_NONE;
    BrScopeDecl decl;
    br_resolve_decl(cfg, cat, sub_path, current_pkg, tm, -1, 0, NULL, 0,
                    BR_WANT_RO | BR_WANT_LOC, &scope, &decl);
    if (scope_out && decl.ro) *scope_out = scope;
    return decl.ro;
}

/* 该路径上有没有显式声明（对外口径，ACL 侧在拒绝前回查）。守卫与 resolve 同款：
   没有 <uid>/ 层的路径不参与规则，也就不存在"声明"。读配置走快照协议（
   config_read_begin/end），读取期间发生发布则整体重试——与 fw_rules_resolve 同一套
   无锁读约定，故本函数可以在 ACL 回调里安全调用。 */
bool fw_rules_path_declared(uid_t uid, pid_t pid, const char* path) {
    if (!path || !fw_rules_path_has_uid_layer(path)) return false;
    for (;;) {
        uint64_t cfg_gen = config_read_begin();
        char current_pkg[128] = "unknown";
        AppConfig* cat = nullptr;
        AppConfig* cfg = br_get_app_cfg(uid, pid, current_pkg, &cat);
        int path_user_id = -1;
        char sub_path[PATH_MAX];
        bool declared = false;
        if (br_strip_and_sanitize(path, &path_user_id, sub_path, sizeof sub_path) == 0) {
            FwRulesTrieMatch tm;
            memset(&tm, 0, sizeof tm);
            br_trie_resolve(cfg, cat, sub_path, &tm);
            declared = br_decl_present(cfg, cat, sub_path, current_pkg, &tm, path_user_id, uid);
        }
        if (config_read_end(cfg_gen)) return declared;
    }
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
    out->is_other_app_pkg = false;
    out->deny_errno = 0;
    out->read_only = false;
    out->real_path[0] = '\0';
    out->is_redirect = false;
    out->is_sandbox = false;
    out->virtual_kind = NSP_VK_NONE;
    out->is_ftp = false;
    out->rule_scope = BR_SCOPE_NONE;
    out->rule_kind = NSP_RULE_NONE;
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
    br_prefetch_xapp_facts(q, q->path); /* 槽外预取：慢查询不许落在读槽里 */
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
        BrRuleScope hidden_scope = BR_SCOPE_NONE;
        bool hidden = br_sanitize_and_check_hidden(cfg, cat, q->path, &path_user_id, sub_path,
                                                  sizeof sub_path, current_pkg, q->uid, &tm,
                                                  &hidden_scope) != 0;
        /* 隔离只在未命中隐藏时判定（保持原短路语义），并单独标注成因 */
        bool isolated =
            !hidden && br_isolation_blocks(cfg, cat, sub_path, current_pkg, q->uid, &tm,
                                           path_user_id);
        if (hidden || isolated) {
            out->valid = true;
            out->appear_missing = true;
            out->is_other_app_pkg = isolated;
            out->rule_scope = hidden ? hidden_scope : BR_SCOPE_NONE;
            out->rule_kind = hidden ? NSP_RULE_HIDE : NSP_RULE_ISOLATION;
            /* 只有 HIDE 规则命中才改返回码；隔离恒 ENOENT（见 fw_rules.h 字段注释） */
            out->deny_errno = hidden ? nsp_hide_errno_of(g_global_cfg.hide_errno) : 0;
            if (config_read_end(cfg_gen)) return;
            continue;
        }
        char p[PATH_MAX];
        char sandbox_mkdir[MAX_PATH_LEN];
        sandbox_mkdir[0] = '\0';
        bool is_redir = false;
        bool is_sandbox = false;
        BrRuleScope loc_scope = BR_SCOPE_NONE;
        uint8_t loc_kind = NSP_RULE_NONE;
        if (br_to_real_path(cfg, cat, sub_path, p, sizeof p, path_user_id, &is_redir, &is_sandbox,
                            current_pkg, &tm, q->uid, sandbox_mkdir, sizeof sandbox_mkdir,
                            &loc_scope, &loc_kind) != 0) {
            out->valid = false;
            if (config_read_end(cfg_gen)) return;
            continue;
        }
        out->valid = true;
        BrRuleScope ro_scope = BR_SCOPE_NONE;
        out->read_only = br_is_path_ro(cfg, cat, sub_path, current_pkg, &tm, &ro_scope);
        /* 归因只报一条：落点结论优先（ALLOW/沙盒/REDIRECT），无落点声明时才归到 RO。
           两者同时成立时（例如只读 + 重定向）以落点为准——对端关心的是"文件在哪"，
           写侧另有 read_only 位单独表达 */
        if (loc_kind != NSP_RULE_NONE) {
            out->rule_scope = loc_scope;
            out->rule_kind = loc_kind;
        } else if (out->read_only) {
            out->rule_scope = ro_scope;
            out->rule_kind = NSP_RULE_RO;
        }
        out->is_redirect = is_redir;
        out->is_sandbox = is_sandbox;
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
    br_prefetch_xapp_facts(q, q->path); /* 槽外预取：慢查询不许落在读槽里 */
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
                /* 跨应用隔离与隐藏同口径（br_sanitize_and_check_hidden 亦判，
               此处为同一判据的读取侧：列举过滤走本路径）。tm 传 NULL：快路径本就不
               建 trie 匹配视图，由被判据自己按层现查 */
                bool iso =
                    br_isolation_hides(cfg, cat, sub_path, current_pkg, q->uid, NULL, path_user_id);
                /* 作用域优先语义下**不能**再用合并视图（tm.hidden 并集）做静态短路：
                   GLOBAL 的 HIDE 会因此压过应用段 ALLOW，列举与打开判定分叉。all_static
                   下无线性规则扫描，逐层现查 trie（每作用域一次下降）的成本远低于一次
                   syscall，故直接走权威判定 */
                bool hidden =
                    br_is_path_hidden_internal(cfg, cat, sub_path, current_pkg, NULL, q->uid, NULL) ||
                    iso;
                out->valid = true;
                out->appear_missing = hidden;
                out->is_other_app_pkg = iso;
                if (config_read_end(cfg_gen)) return;
                continue;
            }
            const TrieNode* ca = trie_find_child(pc->app_dir_node, name, name_len);
            const TrieNode* cc = trie_find_child(pc->cat_dir_node, name, name_len);
            const TrieNode* cg = trie_find_child(pc->g_dir_node, name, name_len);
            /* 完整隐藏判定（CONFIG_DIR/Android 骨架/跨应用/hide 规则）：与 resolve 侧
               同一函数、同一 tm 数据源（作用域优先：应用段 > 类别段 > [GLOBAL]），故
               列举与打开不会分叉。旧实现用 tm.hidden 合并视图短路，"GLOBAL 恒赢"，
               应用段 ALLOW 取消不掉全局 HIDE。ca/cc/cg 只留给下面的虚拟目录判定。
               跨应用隔离同样在此叠加（与 resolve 侧 br_sanitize_and_check_hidden
               同判据：看不见 = 打不开） */
            bool iso = br_isolation_hides(cfg, cat, sub_path, current_pkg, q->uid, NULL,
                                          path_user_id);
            if (br_is_path_hidden_internal(cfg, cat, sub_path, current_pkg, NULL, q->uid, NULL) ||
                iso) {
                out->valid = true;
                out->appear_missing = true;
                if (config_read_end(cfg_gen)) return;
                continue;
            }
            out->valid = true;
            out->appear_missing = false;
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
                                         sizeof sub_path, current_pkg, q->uid, &tm, NULL) != 0 ||
            br_isolation_hides(cfg, cat, sub_path, current_pkg, q->uid, &tm, path_user_id)) {
            out->valid = true;
            out->appear_missing = true;
            if (config_read_end(cfg_gen)) return;
            continue;
        }
        out->valid = true;
        /* 隐藏已由上面 br_sanitize_and_check_hidden 提前返回，此处恒为可见 */
        out->appear_missing = false;
        out->virtual_kind = br_is_virtual_ancestor(cfg, cat, sub_path)
                                ? NSP_VK_ANCESTOR
                                : (br_is_redirect_target(cfg, cat, sub_path) ? NSP_VK_TARGET
                                                                            : NSP_VK_NONE);
        out->is_other_app_pkg = br_is_other_app_pkg(sub_path, current_pkg, q->uid);

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
        /* ALLOW 同样算「规则触及」：它声明的是**这一层放行**，而下层 backing
           直通会把 I/O 交给内核按调用方凭证做 DAC（/data/media 归 MediaProvider，
           应用一律 EACCES），故 ALLOW 路径也必须由 daemon 代理。旧实现把 ALLOW
           当直通跳过 → 应用段只写 ALLOW 时该路径仍挂 backing，用户观感「注入后
           写不进 /Download」。 */
        if (!c->redir_rules) continue;
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
        /* ALLOW 也要求仲裁：命中 ALLOW 的路径由 daemon 代理 IO，不能挂 backing
           直通——下层 DAC 按调用方凭证判，应用对 /data/media 一律 EACCES
           （与 br_cfg_touches_data 同一理由）。 */
        if (!c->redir_rules) continue;
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
