#define _GNU_SOURCE
#include "br_rules.h"
#include "nsp_module.h" /* LOG_*、g_log_shutdown、g_real_root、STORAGE_BASE 等 */
#include "nsp_constants.h"
#include "path_vars.h"
#include "uid_map.h"
#include "fast_pid.h"
#include "sys_pkg.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fnmatch.h>
#include <pthread.h>
#include <dirent.h>

/* ============ 模块内部状态（从 vfs_core.c 适配，不再依赖 fuse_context） ============ */

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
   所有调用方（br_resolve/br_get_pkg/br_probe）均持 config_lock_read，
   cfg 指针不会被重载并发释放；seqlock 仅需防止并发填充互相撕裂。 */
typedef struct {
    pthread_mutex_t wlock; /* 写者互斥（填充/失效），读侧无锁 */
    _Atomic uint64_t seq;  /* seqlock 序号 */
    uid_t uid;
    AppConfig* cfg;
    AppConfig* cat; /* 命中的类别段（USER_APPS/SYSTEM_APPS，可 NULL；
                                     与 cfg 同代际、同样仅作废不保留） */
    uint64_t gen;   /* 填充时的配置代际（g_br_cfg_gen）：
                                     重载后过期 → 走 pkg 复用路径（见下） */
    char pkg[128];  /* pkg 为进程事实，不随规则重载变化：
                                     重载仅作废 cfg（置 NULL + gen=0），
                                     保留 uid/pkg，下次命中免 /proc 重解析 */
} UidCacheSlot;
static UidCacheSlot g_uid_cache[UID_CACHE_SIZE];
static UidMapEntry* g_uid_maps = NULL;
static int g_uid_map_count = 0;

/* ============ readdir 目录级 probe 缓存 ============
   br_probe 是 readdir 逐条目过滤的热路径：同一父目录的连续条目共享一次
   「根→父目录」trie 下降与 uid→cfg 解析，命中后仅按最后一段查子节点，
   避免每条目重复全路径 trie 遍历与 uid 缓存锁（大目录 O(n) 锁风暴）。
   线程私有（FUSE 多线程各自独立，readdir 循环在单线程内顺序执行）；
   配置重载（g_br_cfg_gen 递增，写锁内）后失效，杜绝 trie/cfg 悬垂。 */
typedef struct {
    bool valid;
    uint64_t gen; /* 配置代际（br_rules_apply_config 递增） */
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

static void load_uid_map(void) {
    /* S1 COW：构建新映射到临时数组，发布时整体换入，旧数组延迟释放
       （无锁读者可能正读 g_uid_maps，就地 free 会 UAF） */
    int cap = UID_MAP_INIT_CAPACITY;
    UidMapEntry* new_maps = malloc((size_t)cap * sizeof(UidMapEntry));
    if (!new_maps) {
        LOG_ERR("load_uid_map: malloc(%d) 失败", cap);
        return;
    }
    int new_count = uid_map_load(new_maps, cap);
    while (new_count > 0 && new_count == cap) {
        cap *= 2;
        UidMapEntry* nm = realloc(new_maps, (size_t)cap * sizeof(UidMapEntry));
        if (!nm) {
            LOG_ERR("load_uid_map: realloc(%d) 失败", cap);
            free(new_maps);
            return;
        }
        new_maps = nm;
        new_count = uid_map_load(new_maps, cap);
    }
    uint64_t old_gen = config_publish_begin();
    /* P1 修复：先排空旧代际读者再交换指针/count（否则 uid_map_lookup
       可能对新数组 + 旧 count 做二分 → 越界读） */
    config_drain_readers(old_gen);
    UidMapEntry* old_maps = g_uid_maps;
    g_uid_maps = new_maps;
    g_uid_map_count = new_count;
    config_publish_end(old_gen);
    free(old_maps); /* 旧代际读者已归零 */
    LOG_DBG("uid.map 已加载: %d 条映射 (容量 %d)", new_count, cap);
}

static void clear_uid_cache(void) {
    for (int i = 0; i < UID_CACHE_SIZE; i++) {
        UidCacheSlot* s = &g_uid_cache[i];
        pthread_mutex_lock(&s->wlock);
        /* 写者进入：seq → 奇数（读者重试） */
        atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                              memory_order_release);
        /* 仅作废 cfg（重载后旧 AppConfig 已释放，指针悬垂）+ gen=0 标记过期；
           保留 uid/pkg——pkg 为进程事实不随规则重载变化，下次同 uid 命中
           可复用 pkg 免 /proc 重解析（热重载后不再全量 uid /proc 风暴） */
        s->cfg = nullptr;
        s->cat = nullptr; /* 类别指针同代际，同样作废（防悬垂） */
        s->gen = 0;
        atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                              memory_order_release);
        pthread_mutex_unlock(&s->wlock);
    }
}

/* 应用框架下发的配置视图：重建索引 + 失效缓存。
   由 basic_rules.c 的 config_update 监听器在框架推送时调用（init 期间一次，
   之后每次热重载一次）。框架已完成文件读取与词法/段头识别，本函数只做
   "行 → 规则对象 → trie" 的索引构建，语义与原自读实现完全一致。 */
void br_rules_apply_config(const NspModuleConfig* cfg) {
    if (!cfg) return;
    config_lock_write();
    /* S1：先失效 uid 缓存与目录级 probe 缓存（g_br_cfg_gen++），再重建配置——
       config_build_from_view 的 COW 发布会释放旧 AppConfig，必须在此之前让
       缓存作废，否则无锁读者可能命中悬垂指针 */
    atomic_fetch_add_explicit(&g_br_cfg_gen, 1, memory_order_release);
    clear_uid_cache();
    config_build_from_view(cfg->recs, cfg->count);
    load_uid_map();
    sys_pkg_refresh(); /* 重读 sys_pkgs.cache（injector 可能已更新落盘） */
    config_unlock_write();
    LOG_DBG("已应用框架下发的配置 (代际 %llu, %d 条记录)，全局监控状态: %s",
            (unsigned long long)cfg->generation, cfg->count,
            g_global_cfg.monitor ? "开启" : "关闭");
}

int br_rules_init(const char* rules_path, bool disable_sandbox) {
    strncpy(g_br_rules_path, rules_path ? rules_path : "", sizeof(g_br_rules_path) - 1);
    g_br_disable_sandbox = disable_sandbox;
    /* 只读消费系统应用表（injector 落盘的 sys_pkgs.cache）：本进程永不
       popen pm（binder 挂起风险），无表时回退 uid<10000 */
    sys_pkg_init(false);
    config_init_lock();
    for (int i = 0; i < UID_CACHE_SIZE; i++) {
        pthread_mutex_init(&g_uid_cache[i].wlock, nullptr);
        atomic_store_explicit(&g_uid_cache[i].seq, 0, memory_order_relaxed);
        g_uid_cache[i].uid = 0;
        g_uid_cache[i].cfg = nullptr;
        g_uid_cache[i].gen = 0;
        g_uid_cache[i].pkg[0] = '\0';
    }
    /* 配置不在此读取：框架在 init 返回后经 config_update 监听器下发首份视图
       （见 basic_rules.c 的 subscribe + set_config_listener） */
    LOG("basic_rules: 规则引擎已就绪 (rules=%s, sandbox=%s)，等待框架下发配置",
        g_br_rules_path[0] ? g_br_rules_path : "(none)", disable_sandbox ? "off" : "on");
    return 0;
}

void br_rules_exit(void) {
    /* 无自有线程（配置监听已收归框架），直接销毁锁与释放内存 */
    config_destroy_lock();
    sys_pkg_cleanup();
    free(g_uid_maps);
    g_uid_maps = NULL;
    g_uid_map_count = 0;
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

static AppConfig* br_get_app_cfg(uid_t uid, pid_t tid, char* current_pkg_out, AppConfig** cat_out) {
    if (cat_out) *cat_out = nullptr;
    if (uid < NSP_SYSTEM_APP_UID_MIN) {
        strncpy(current_pkg_out, "system", 127);
        current_pkg_out[127] = '\0';
        /* 系统伪包同样参与类别层：SYSTEM_APPS 对 uid<10000 生效 */
        if (cat_out)
            *cat_out = br_pick_category(uid, (int)(uid / NSP_PER_USER_UID_STRIDE), "system");
        return nullptr;
    }
    int slot = uid % UID_CACHE_SIZE;
    UidCacheSlot* s = &g_uid_cache[slot];
    uint64_t cur_gen = atomic_load_explicit(&g_br_cfg_gen, memory_order_acquire);

    /* seqlock 无锁读：seq 偶数且两次读相等 = 稳定快照（读者零原子写，
       多线程并发读无缓存行颠簸）。命中（含 negative：scfg 可为 NULL）
       直接返回；代际过期则保留缓存 pkg 走下方复用路径（免 /proc） */
    char reuse_pkg[128] = {0};
    bool reuse_ok = false;
    for (;;) {
        uint64_t s1 = atomic_load_explicit(&s->seq, memory_order_acquire);
        if (s1 & 1) continue; /* 写者进行中：重试 */
        uid_t suid = s->uid;
        AppConfig* scfg = s->cfg;
        AppConfig* scat = s->cat;
        uint64_t sgen = s->gen;
        memcpy(reuse_pkg, s->pkg, sizeof reuse_pkg);
        uint64_t s2 = atomic_load_explicit(&s->seq, memory_order_acquire);
        if (s1 != s2) continue; /* 快照不一致：重试 */
        if (suid == uid) {
            if (sgen == cur_gen) {
                strncpy(current_pkg_out, reuse_pkg, 127);
                current_pkg_out[127] = '\0';
                if (cat_out) *cat_out = scat;
                return scfg;
            }
            /* 代际过期（热重载后）：pkg 为进程事实仍有效，可复用免 /proc */
            reuse_ok = (reuse_pkg[0] != '\0');
        }
        break;
    }

    int user_id = uid / NSP_PER_USER_UID_STRIDE;
    char final_pkg[256] = {0};
    pid_t main_pid = tid;
    const char* mapped = uid_map_lookup(g_uid_maps, g_uid_map_count, uid);
    if (mapped) strncpy(final_pkg, mapped, 255);
    /* 热重载后复用缓存 pkg（不随规则变化），免全量 uid /proc 解析风暴 */
    if (final_pkg[0] == '\0' && reuse_ok) strncpy(final_pkg, reuse_pkg, 255);
    if (final_pkg[0] == '\0') {
        char status_path[64];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", tid);
        FILE* fp = fopen(status_path, "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "Tgid:", 5) == 0) {
                    main_pid = atoi(line + 5);
                    break;
                }
            }
            fclose(fp);
        }
        proc_get_cmdline(main_pid, final_pkg, sizeof(final_pkg));
    }
    char base_pkg[256];
    strncpy(base_pkg, final_pkg, sizeof(base_pkg) - 1);
    base_pkg[sizeof(base_pkg) - 1] = '\0';
    char* colon = strchr(base_pkg, ':');
    if (colon) *colon = 0;
    strncpy(current_pkg_out, base_pkg, 127);
    current_pkg_out[127] = '\0';

    if (strlen(base_pkg) < 3 || strstr(base_pkg, "zygote") != nullptr ||
        strstr(base_pkg, "<pre-") != nullptr) {
        if (base_pkg[0] == '\0') {
            strncpy(base_pkg, "unknown", sizeof(base_pkg) - 1);
            base_pkg[sizeof(base_pkg) - 1] = '\0';
        }
        strncpy(current_pkg_out, base_pkg, 127);
        current_pkg_out[127] = '\0';
        /* 写缓存：wlock 互斥 + seq 奇数/偶数翻转（读者重试/恢复） */
        pthread_mutex_lock(&s->wlock);
        atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                              memory_order_release);
        s->uid = uid;
        s->cfg = nullptr;
        s->cat = nullptr; /* 不可解析包名：类别层不同时生效（仅 GLOBAL） */
        s->gen = cur_gen;
        strncpy(s->pkg, base_pkg, 127);
        s->pkg[127] = '\0';
        atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                              memory_order_release);
        pthread_mutex_unlock(&s->wlock);
        return nullptr;
    }

    AppConfig* matched = find_app_cfg_locked(final_pkg, user_id);
    AppConfig* cat = br_pick_category(uid, user_id, base_pkg);
    if (cat_out) *cat_out = cat;
    pthread_mutex_lock(&s->wlock);
    atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                          memory_order_release);
    s->uid = uid;
    s->cfg = matched;
    s->cat = cat;
    s->gen = cur_gen;
    strncpy(s->pkg, current_pkg_out, 127);
    s->pkg[127] = '\0';
    atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                          memory_order_release);
    pthread_mutex_unlock(&s->wlock);
    return matched;
}

/* ============ 规则决策（适配 vfs_core 的 Trie + 线性通道） ============ */

static bool br_is_other_app_pkg(const char* sub_path, const char* current_pkg) {
    if (!current_pkg[0] || strcmp(current_pkg, "system") == 0 ||
        strcmp(current_pkg, "unknown") == 0)
        return false;
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
                if (strcmp(target_pkg, current_pkg) != 0) return true;
            }
            break;
        }
    }
    return false;
}

static void br_trie_resolve(AppConfig* cfg, AppConfig* cat, const char* sub_path, TrieMatch* out) {
    if (!out) return;
    out->valid = true;
    out->hidden = false;
    out->ro = false;
    out->has_redir = false;
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
            strcpy(out->redir, redir);
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
            strcpy(out->redir, redir); /* 源为 PATH_MAX 栈缓冲，NUL 结尾 */
        }
    }
}

/* 隐藏判定的静态部分（不触碰 cfg/g_global_cfg 数据，锁外安全）：
   CONFIG_DIR 前缀恒隐藏；Android 骨架目录恒不隐藏（is_skel_out 输出）；
   tm.hidden（trie 结果）。
   动态 hide 线性扫描（访问 hide_rules 数组）不在此列。
   注意：跨应用隔离（br_is_other_app_pkg）不在本函数判定——resolve
   （getattr/open）不得隐藏其他应用的 /Android/data 路径，否则列表可见
   但打开报 ENOENT（MT 管理器访问 /Android/data/<他包>/ 场景）；该隔离
   只由 br_probe（readdir 条目过滤）显式追加，实现"限制列举、不限制打开"。 */
static bool br_hidden_static_part(const char* sub_path, const char* current_pkg,
                                  const TrieMatch* tm, bool* is_skel_out) {
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

/* 类别 hide 线性扫描（USER_APPS/SYSTEM_APPS 动态规则）：变量展开以类别段
   为专属作用域（覆盖全局同名），与 app/global 展开对称 */
static bool br_cat_hide_linear(AppConfig* cat, const char* sub_path, const char* current_pkg) {
    if (!(cat && cat->hide_rules && cat->dyn_hide)) return false;
    for (int i = 0; i < cat->hide_count; i++) {
        if (cat->hide_rules[i]) {
            const char* rule = cat->hide_rules[i];
            char expanded[PATH_MAX];
            const char* match_str = rule;
            if (has_path_var(rule)) {
                if (!pkg_resolvable(current_pkg)) continue;
                expand_path_vars(rule, expanded, sizeof expanded, cat, &g_global_cfg, current_pkg);
                match_str = expanded;
            }
            if (fnmatch(match_str, sub_path, 0) == 0) return true;
            size_t len = strlen(match_str);
            if (strncmp(sub_path, match_str, len) == 0 &&
                (sub_path[len] == '\0' || sub_path[len] == '/'))
                return true;
        }
    }
    return false;
}

static bool br_is_path_hidden_internal(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                                       const char* current_pkg, const TrieMatch* tm) {
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
    if (cfg && cfg->hide_rules && cfg->dyn_hide) {
        for (int i = 0; i < cfg->hide_count; i++) {
            if (cfg->hide_rules[i]) {
                const char* rule = cfg->hide_rules[i];
                char expanded[PATH_MAX];
                const char* match_str = rule;
                if (has_path_var(rule)) {
                    if (!pkg_resolvable(current_pkg)) continue;
                    expand_path_vars(rule, expanded, sizeof expanded, cfg, &g_global_cfg,
                                     current_pkg);
                    match_str = expanded;
                }
                if (fnmatch(match_str, sub_path, 0) == 0) return true;
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 &&
                    (sub_path[len] == '\0' || sub_path[len] == '/'))
                    return true;
            }
        }
    }
    if (br_cat_hide_linear(cat, sub_path, current_pkg)) return true;
    if (g_global_cfg.hide_rules && g_global_cfg.dyn_hide) {
        for (int i = 0; i < g_global_cfg.hide_count; i++) {
            if (g_global_cfg.hide_rules[i]) {
                const char* rule = g_global_cfg.hide_rules[i];
                char expanded[PATH_MAX];
                const char* match_str = rule;
                if (has_path_var(rule)) {
                    if (!pkg_resolvable(current_pkg)) continue;
                    expand_path_vars(rule, expanded, sizeof expanded, cfg, &g_global_cfg,
                                     current_pkg);
                    match_str = expanded;
                }
                if (fnmatch(match_str, sub_path, 0) == 0) return true;
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 &&
                    (sub_path[len] == '\0' || sub_path[len] == '/'))
                    return true;
            }
        }
    }
    return false;
}

/* 剥离 /<user_id>/ 前缀 + 非法字符清理，得到 sub_path。
   返回 0 成功；-ENOENT 表示清理后为空（路径无效，调用方视为不可解析）。 */
static int br_strip_and_sanitize(const char* path, int* path_user_id_out, char* sub_path_out,
                                 size_t sub_path_size) {
    if (!path) return -ENOENT;
    const char* sub_path_orig = path;
    /* 仅当完整 user_id 目录（/数字 或 /数字/...）才剥离数字前缀——与框架
       vfs_readdir 的 uid_dir 判定一致。若数字后不是 '/' 或结尾（如 /1_abc.txt、
       /12_34 这类普通文件/目录名），不得剥离：否则 sub_path 被截成 "/"，
       规则判定（hidden/redirect_target）基于错误路径，沙盒+应用上下文中
       数字前缀条目会被误过滤（用户报告：数字 x_ 前缀文件/文件夹不显示，
       字母前缀正常） */
    if (path[0] == '/' && isdigit((unsigned char)path[1])) {
        /* 数字序列后必须是结尾或 '/' 才是完整 user_id 目录（/0、/10、
           /100/...）；普通数字前缀文件名（/1_abc.txt、/12_34）不剥离 */
        const char* d = path + 1;
        while (isdigit((unsigned char)*d)) d++;
        if (*d == '\0' || *d == '/') {
            if (path_user_id_out) *path_user_id_out = atoi(path + 1);
            const char* slash = strchr(path + 1, '/');
            sub_path_orig = slash ? slash : "/";
        }
    }
    if (path_contains_invalid_chars(sub_path_orig)) {
        path_sanitize(sub_path_out, sub_path_size, sub_path_orig);
        if (sub_path_out[0] == '\0') return -ENOENT;
    } else {
        strncpy(sub_path_out, sub_path_orig, sub_path_size - 1);
        sub_path_out[sub_path_size - 1] = '\0';
    }
    return 0;
}

static int br_sanitize_and_check_hidden(AppConfig* cfg, AppConfig* cat, const char* path,
                                        int* path_user_id_out, char* sub_path_out,
                                        size_t sub_path_size, const char* current_pkg, uid_t uid,
                                        TrieMatch* tm_out) {
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
                                uid_t uid) {
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
                   使 /Download/*.mp3 命中 /Download/a.mp3 → suffix="a.mp3" */
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
            if (t_slash && s_slash)
                snprintf(temp, temp_size, "%s%s", real_base, suffix + 1);
            else if (!t_slash && !s_slash) {
                if (suffix[0] == '\0')
                    snprintf(temp, temp_size, "%s", real_base);
                else
                    snprintf(temp, temp_size, "%s/%s", real_base, suffix);
            } else
                snprintf(temp, temp_size, "%s%s", real_base, suffix);
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
        if (access(sandbox_target, F_OK) != 0) mkdir_recursive_p(sandbox_target, 0775);
        snprintf(temp, temp_size, "%s%s", sandbox_target, sub_path);
        return true;
    }
    return false;
}

static int br_to_real_path(AppConfig* cfg, AppConfig* cat, const char* sub_path, char* out_buf,
                           size_t size, int user_id, bool* is_redir_out, const char* current_pkg,
                           const TrieMatch* tm, uid_t uid) {
    char temp[PATH_MAX] = {0};
    bool redir = false;

    if (tm && tm->valid) {
        if (tm->has_redir) {
            strncpy(temp, tm->redir, sizeof(temp) - 1);
            temp[sizeof(temp) - 1] = '\0';
            redir = true;
        }
    } else {
        bool dummy_hidden = false;
        bool dummy_ro = false;
        if (cfg && cfg->trie_root) {
            if (trie_lookup(cfg->trie_root, sub_path, &dummy_hidden, &dummy_ro, temp,
                            sizeof(temp))) {
                if (temp[0] != '\0') redir = true;
            }
        }
        if (!redir && cat && cat->trie_root) {
            temp[0] = '\0';
            if (trie_lookup(cat->trie_root, sub_path, &dummy_hidden, &dummy_ro, temp,
                            sizeof(temp))) {
                if (temp[0] != '\0') redir = true;
            }
        }
        if (!redir && g_global_cfg.trie_root) {
            temp[0] = '\0';
            if (trie_lookup(g_global_cfg.trie_root, sub_path, &dummy_hidden, &dummy_ro, temp,
                            sizeof(temp))) {
                if (temp[0] != '\0') redir = true;
            }
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
            br_check_redir_rule(cfg, sub_path, temp, user_id, current_pkg, true, sizeof(temp), uid);
    if (!redir && cat && cat->dyn_redir)
        redir =
            br_check_redir_rule(cat, sub_path, temp, user_id, current_pkg, true, sizeof(temp), uid);
    if (!redir && g_global_cfg.dyn_redir)
        redir = br_check_redir_rule(&g_global_cfg, sub_path, temp, user_id, current_pkg, true,
                                    sizeof(temp), uid);
    /* sandbox 三层：应用显式 OFF 否决类别+全局；类别显式 OFF 否决全局；
       应用显式 ON（或类别显式 ON 且应用未显式）时各自 sandbox 生效 */
    bool app_sandbox_off = (cfg && cfg->sandbox_explicit && !cfg->sandbox);
    bool cat_sandbox_off = (!app_sandbox_off && cat && cat->sandbox_explicit && !cat->sandbox);
    if (!redir && !g_br_disable_sandbox) {
        if (!app_sandbox_off)
            redir = br_check_redir_rule(cfg, sub_path, temp, user_id, current_pkg, false,
                                        sizeof(temp), uid);
    }
    if (!redir && !g_br_disable_sandbox) {
        if (!app_sandbox_off)
            redir = br_check_redir_rule(cat, sub_path, temp, user_id, current_pkg, false,
                                        sizeof(temp), uid);
    }
    if (!redir && !g_br_disable_sandbox) {
        if (!app_sandbox_off && !cat_sandbox_off)
            redir = br_check_redir_rule(&g_global_cfg, sub_path, temp, user_id, current_pkg, false,
                                        sizeof(temp), uid);
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
    for (int i = 0; i < cat->ro_count; i++) {
        if (cat->ro_rules[i]) {
            const char* rule = cat->ro_rules[i];
            char expanded[PATH_MAX];
            const char* match_str = rule;
            if (has_path_var(rule)) {
                if (!pkg_resolvable(current_pkg)) continue;
                expand_path_vars(rule, expanded, sizeof expanded, cat, &g_global_cfg, current_pkg);
                match_str = expanded;
            }
            if (fnmatch(match_str, sub_path, 0) == 0) return true;
            size_t len = strlen(match_str);
            if (strncmp(sub_path, match_str, len) == 0 &&
                (sub_path[len] == '\0' || sub_path[len] == '/'))
                return true;
        }
    }
    return false;
}

static bool br_is_path_ro(AppConfig* cfg, AppConfig* cat, const char* sub_path,
                          const char* current_pkg, const TrieMatch* tm) {
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
    if (cfg && cfg->ro_rules && cfg->dyn_ro) {
        for (int i = 0; i < cfg->ro_count; i++) {
            if (cfg->ro_rules[i]) {
                const char* rule = cfg->ro_rules[i];
                char expanded[PATH_MAX];
                const char* match_str = rule;
                if (has_path_var(rule)) {
                    if (!pkg_resolvable(current_pkg)) continue;
                    expand_path_vars(rule, expanded, sizeof expanded, cfg, &g_global_cfg,
                                     current_pkg);
                    match_str = expanded;
                }
                if (fnmatch(match_str, sub_path, 0) == 0) return true;
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 &&
                    (sub_path[len] == '\0' || sub_path[len] == '/'))
                    return true;
            }
        }
    }
    if (br_cat_ro_linear(cat, sub_path, current_pkg)) return true;
    if (g_global_cfg.ro_rules && g_global_cfg.dyn_ro) {
        for (int i = 0; i < g_global_cfg.ro_count; i++) {
            if (g_global_cfg.ro_rules[i]) {
                const char* rule = g_global_cfg.ro_rules[i];
                char expanded[PATH_MAX];
                const char* match_str = rule;
                if (has_path_var(rule)) {
                    if (!pkg_resolvable(current_pkg)) continue;
                    expand_path_vars(rule, expanded, sizeof expanded, cfg, &g_global_cfg,
                                     current_pkg);
                    match_str = expanded;
                }
                if (fnmatch(match_str, sub_path, 0) == 0) return true;
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 &&
                    (sub_path[len] == '\0' || sub_path[len] == '/'))
                    return true;
            }
        }
    }
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

/* MONITOR 三层合并：应用显式 > 类别显式 > 全局 */
static bool br_effective_monitor(AppConfig* cfg, AppConfig* cat) {
    if (cfg && cfg->monitor_explicit) return cfg->monitor;
    if (cat && cat->monitor_explicit) return cat->monitor;
    return g_global_cfg.monitor;
}

/* ============ 核心决策入口 ============ */

/* 字符串仅需首字节清零；成功路径负责覆盖，隐藏路径保留空串。 */
static inline void br_result_init(BrResult* out) {
    out->valid = false;
    out->appear_missing = false;
    out->read_only = false;
    out->attr_override = 0;
    out->mode = 0;
    out->uid = 0;
    out->gid = 0;
    out->pkg[0] = '\0';
    out->real_path[0] = '\0';
    out->is_redirect = false;
    out->virtual_kind = NSP_VK_NONE;
    out->is_ftp = false;
    out->monitor_on = false;
}

void br_resolve(const BrQuery* q, BrResult* out) {
    if (!q || !out) return;
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
        TrieMatch tm;
        if (br_sanitize_and_check_hidden(cfg, cat, q->path, &path_user_id, sub_path,
                                         sizeof sub_path, current_pkg, q->uid, &tm) != 0) {
            out->valid = true;
            out->appear_missing = true;
            strcpy(out->pkg, current_pkg); /* 源为 128B 栈缓冲，NUL 结尾 */
            out->monitor_on = br_effective_monitor(cfg, cat);
            if (config_read_end(cfg_gen)) return;
            continue;
        }
        char p[PATH_MAX];
        bool is_redir = false;
        if (br_to_real_path(cfg, cat, sub_path, p, sizeof p, path_user_id, &is_redir, current_pkg,
                            &tm, q->uid) != 0) {
            out->valid = false;
            if (config_read_end(cfg_gen)) return;
            continue;
        }
        out->valid = true;
        strcpy(out->pkg, current_pkg); /* 源为 128B 栈缓冲，NUL 结尾 */
        out->read_only = br_is_path_ro(cfg, cat, sub_path, current_pkg, &tm);
        out->is_redirect = is_redir;
        strcpy(out->real_path, p); /* 源为 PATH_MAX 栈缓冲，NUL 结尾 */
        /* 复用 br_trie_resolve 已完成的 trie 下降结果（app/类别/global 完整匹配节点），
       直接判定虚拟目录性质，避免各自再全路径遍历：
       - ANCESTOR：最深节点下存在带规则子节点（trie_is_ancestor 语义）
       - TARGET：最深节点本身是重定向目标（trie_is_redirect_target 语义）
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
       下降一次取得（替代 config_ftp_match 每请求 O(N) 线性扫描）；
       命中后由框架分派给 FTP 后端模块 */
        out->is_ftp = tm.ftp_app[0] || tm.ftp_cat[0] || tm.ftp_global[0];
        out->monitor_on = br_effective_monitor(cfg, cat);
        if (config_read_end(cfg_gen)) return;
        /* 读期间发生发布：整体重试 */
    }
}

/* uid → 包名解析（框架日志用），语义与 br_get_app_cfg 的 pkg 输出一致 */
int br_get_pkg(uid_t uid, pid_t tid, char* pkg_out, size_t pkg_size) {
    if (!pkg_out || pkg_size == 0) return -1;
    for (;;) {
        uint64_t cfg_gen = config_read_begin();
        char pkg[128];
        br_get_app_cfg(uid, tid, pkg, NULL); /* 仅需包名，类别层不需要 */
        if (config_read_end(cfg_gen)) {
            strncpy(pkg_out, pkg, pkg_size - 1);
            pkg_out[pkg_size - 1] = '\0';
            return 0;
        }
        /* 读期间发生发布：重试 */
    }
}

/* 轻量探测：readdir 逐条目过滤用。只做 sanitize + hidden/redirect_target/
   虚拟目录判断，不构建真实路径、不触发 sandbox 目录创建（性能敏感） */
void br_probe(const BrQuery* q, BrProbeResult* out) {
    if (!q || !out) return;
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
                TrieMatch tm;
                tm.valid = true;
                tm.hidden = pc->app_dir_hidden || pc->cat_dir_hidden || pc->g_dir_hidden;
                bool is_skel = false;
                /* 跨应用隔离仅在此（probe/readdir 列举过滤）显式生效：
               resolve 不再判 hidden（见 br_hidden_static_part 注释），
               保证 /Android/data/<他包>/ 下列表可见、打开可访问 */
                bool hidden = br_hidden_static_part(sub_path, current_pkg, &tm, &is_skel) ||
                              br_is_other_app_pkg(sub_path, current_pkg);
                out->valid = true;
                out->appear_missing = hidden;
                out->is_other_app_pkg = br_is_other_app_pkg(sub_path, current_pkg);
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
            TrieMatch tm;
            tm.valid = true;
            tm.hidden = trie_hidden;
            /* 完整隐藏判定（CONFIG_DIR/Android 骨架/跨应用/hide 规则），
           trie 部分用缓存值（tm.valid 使其跳过内部 trie 查询）。
           对所有访问者生效（含 root）：与 br_sanitize_and_check_hidden
           及 vfs_readdir probe 过滤语义一致，HIDE 后 root ls 也看不见。
           跨应用隔离在此显式叠加（resolve 不再判 hidden，见
           br_hidden_static_part 注释） */
            if (br_is_path_hidden_internal(cfg, cat, sub_path, current_pkg, &tm) ||
                br_is_other_app_pkg(sub_path, current_pkg)) {
                out->valid = true;
                out->appear_missing = true;
                if (config_read_end(cfg_gen)) return;
                continue;
            }
            out->valid = true;
            out->appear_missing = trie_hidden || br_is_other_app_pkg(sub_path, current_pkg);
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
            out->is_other_app_pkg = br_is_other_app_pkg(sub_path, current_pkg);
            if (config_read_end(cfg_gen)) return;
            continue;
        }

        /* 未命中：完整路径解析（原逻辑）+ 填充目录缓存 */
        AppConfig* cat = nullptr;
        cfg = br_get_app_cfg(q->uid, q->pid, current_pkg, &cat);
        TrieMatch tm;
        if (br_sanitize_and_check_hidden(cfg, cat, q->path, &path_user_id, sub_path,
                                         sizeof sub_path, current_pkg, q->uid, &tm) != 0 ||
            br_is_other_app_pkg(sub_path, current_pkg)) {
            out->valid = true;
            out->appear_missing = true;
            if (config_read_end(cfg_gen)) return;
            continue;
        }
        out->valid = true;
        out->appear_missing = tm.hidden || br_is_other_app_pkg(sub_path, current_pkg);
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

int br_readdir_extra(const BrQuery* q, const char* sub_path, int user_id, const char* pkg,
                     bool is_root, NspDirEntry* out, int max) {
    if (!q || !out || max <= 0 || !sub_path) return 0;
    /* S1 无锁快照读：替代 rwlock 读锁（与 br_resolve 一致，发布发生则重试） */
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
