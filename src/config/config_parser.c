#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "config_parser.h"
#include "nsp_constants.h"
#include "common.h"
#include "nsp_util.h"
#include "path_vars.h"
#include "sys_pkg.h"
#include <sys/stat.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <ctype.h>
#include <fnmatch.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
AppConfig g_global_cfg;
AppConfig** g_app_cfgs = nullptr;
int g_app_cfg_count = 0;
int g_app_cfg_capacity = 0;
/* S1 COW 暂存区：load_config_rules 构建的新配置（发布后成为 live，
   旧 live 延迟释放——无锁读者可能正读旧 trie/cfg） */
static AppConfig g_global_cfg_stage;
static AppConfig** g_app_cfgs_stage = nullptr;
static int g_app_cfg_count_stage = 0;
static int g_app_cfg_capacity_stage = 0;
/* 是否存在类别段（config_publish 扫描 live 设置，config_has_category_rules 读） */
static bool g_has_category_rules = false;
int g_active_users[MAX_USERS];
int g_active_user_count = 0;
/* 应用规则目录创建权限：默认只读（false）——只有 injector 能创建
   App-rules / App-rules-<uid>（经 config_set_allow_app_rules_mkdir 开启）；
   fuse_daemon（内建规则引擎）、log_ctl 等进程加载配置时只读，
   避免将 scan_active_users 误判出的伪用户固化为目录 */
static bool g_allow_app_rules_mkdir = false;
/* pm 探测开关：scan_active_users 默认经 popen("pm list users") 枚举活跃
   用户——该命令需 binder 通信 system_server，在 fuse_daemon 等受限环境
   可能长时间挂起（启动/热重载持写锁阻塞 → FUSE 无响应）。只读加载方
   （fuse_daemon/log_ctl）经 config_set_scan_users_skip_pm 跳过，改由
   /data/media 与已存在的 App-rules-<uid> 目录推导（无 popen，不会阻塞） */
static bool g_scan_users_skip_pm = false;
static pthread_rwlock_t g_rules_lock;
#include <sched.h>
#include <stdatomic.h>

/* ============ 配置代际 + 读者计数（S1 无锁快照，per-thread 计数） ============
   热路径（br_resolve/br_probe）不再取 rwlock 读锁，改走 seqlock：
   - g_cfg_gen：偶数 = 稳定代际；奇数 = 写者进行中（读者自旋等待）
   - g_cfg_readers[i][slot]：per-thread 读者计数，按代际奇偶分槽
     (slot = (gen>>1)&1)。每行 64B 缓存行对齐、每线程独占一行（首次调用
     经 g_cfg_reader_next 原子分配槽位）——8+ 线程并发时读者各自 RMW
     自己的缓存行，消除共享原子上的缓存行颠簸（原 g_cfg_readers[2] 在
     多线程下是热路径竞争点）。
   协议：
     读者 config_read_begin()：循环读 gen（偶数）→ 本线程行槽自增 →
     二次读 gen 相等即持槽成功（若写者插队则回滚重试）；持槽期间旧配置
     不会被写者释放，可无锁读 trie/cfg。
     读者 config_read_end(gen)：本线程行槽自减；返回 gen 是否未变（false =
     读期间发生发布 → 调用方必须重试整个 resolve）。
     写者 config_publish_begin()：返回旧 gen 并置奇数（封锁新读者）。
     写者 config_publish_end(old_gen)：置偶数（放行）+ 扫描全部读者行
     等旧槽归零（热重载极低频，O(读者行数) 可接受）。
   注意：冷路径（log_ctl/config_publisher 查询）仍走 rwlock 读锁；
   写者仍持 rwlock 写锁（互斥 + 冷读者保护），无锁协议只叠加于热路径。 */
#define CFG_READER_MAX 64
typedef struct {
    _Atomic int cnt[2]; /* 按代际奇偶分槽 */
    char _pad[56];      /* 补齐到 64B，每行独占缓存行（免假共享） */
} CfgReaderCell;
static _Alignas(64) CfgReaderCell g_cfg_readers[CFG_READER_MAX];
static _Atomic(int) g_cfg_reader_next = 0;       /* 下一个可分配读者槽位 */
static _Thread_local int g_cfg_reader_slot = -1; /* 本线程读者槽（首次调用分配） */
static _Atomic(uint64_t) g_cfg_gen = 0;

/* 获取本线程读者槽：首次调用经 fetch_add 分配（热路径此后只读 TLS）。
   槽位耗尽时共享最后一个槽（正确性不变，仅退化回有竞争——实际线程数
   （FUSE 线程池 + 监控线程）远小于 CFG_READER_MAX） */
static int cfg_reader_slot(void) {
    int s = g_cfg_reader_slot;
    if (s < 0) {
        s = atomic_fetch_add_explicit(&g_cfg_reader_next, 1, memory_order_acq_rel);
        if (s >= CFG_READER_MAX) s = CFG_READER_MAX - 1;
        g_cfg_reader_slot = s;
    }
    return s;
}

uint64_t config_read_begin(void) {
    int s = cfg_reader_slot();
    for (;;) {
        uint64_t g1 = atomic_load_explicit(&g_cfg_gen, memory_order_acquire);
        if (g1 & 1) {
            sched_yield();
            continue;
        } /* 写者进行中 */
        int slot = (int)((g1 >> 1) & 1);
        atomic_fetch_add_explicit(&g_cfg_readers[s].cnt[slot], 1, memory_order_acq_rel);
        if (atomic_load_explicit(&g_cfg_gen, memory_order_acquire) == g1)
            return g1; /* 稳定快照，持槽 */
        atomic_fetch_sub_explicit(&g_cfg_readers[s].cnt[slot], 1, memory_order_release);
    }
}

bool config_read_end(uint64_t gen) {
    int slot = (int)((gen >> 1) & 1);
    atomic_fetch_sub_explicit(&g_cfg_readers[cfg_reader_slot()].cnt[slot], 1, memory_order_release);
    return atomic_load_explicit(&g_cfg_gen, memory_order_acquire) == gen;
}

uint64_t config_publish_begin(void) {
    uint64_t g = atomic_load_explicit(&g_cfg_gen, memory_order_relaxed);
    atomic_store_explicit(&g_cfg_gen, g + 1, memory_order_release);
    return g;
}

/* 等待旧代际读者归零（写者交换前调用）：gen 已置奇数封锁新读者，
   旧代际读者读完自动归零；归零后无读者在途，方可安全执行非原子交换。
   新读者进新槽（(new_gen>>1)&1 ≠ old_slot）不阻塞写者——无饥饿。 */
void config_drain_readers(uint64_t old_gen) {
    int old_slot = (int)((old_gen >> 1) & 1);
    for (;;) {
        bool busy = false;
        for (int i = 0; i < CFG_READER_MAX; i++) {
            if (atomic_load_explicit(&g_cfg_readers[i].cnt[old_slot], memory_order_acquire) != 0) {
                busy = true;
                break;
            }
        }
        if (!busy) break;
        sched_yield();
    }
}

void config_publish_end(uint64_t old_gen) {
    atomic_store_explicit(&g_cfg_gen, old_gen + 2, memory_order_release);
    int old_slot = (int)((old_gen >> 1) & 1);
    /* 扫描全部读者行等旧代际槽归零（无条件扫 MAX 行，规避槽位分配
       可见性竞态；热重载极低频，64×acquire load 开销可忽略）。
       新读者进新槽（(new_gen>>1)&1 ≠ old_slot）不阻塞写者——无饥饿。 */
    for (;;) {
        bool busy = false;
        for (int i = 0; i < CFG_READER_MAX; i++) {
            if (atomic_load_explicit(&g_cfg_readers[i].cnt[old_slot], memory_order_acquire) != 0) {
                busy = true;
                break;
            }
        }
        if (!busy) break;
        sched_yield();
    }
}
static bool is_wildcard_string(const char* str) {
    /* `?` 作为首字符是项目自定义的"相对当前 user 存储"前缀，非 fnmatch 通配；
       仅从第二字符起检测真正的通配符 * ? [ ]，避免 ALLOW/REDIRECT 的 ? 前缀路径被误判跳过 trie */
    if (!str || !str[0]) return false;
    const char* p = (str[0] == '?') ? str + 1 : str;
    return strpbrk(p, "*?[]") != NULL;
}
void config_init_lock() {
    pthread_rwlock_init(&g_rules_lock, nullptr);
}
void config_destroy_lock() {
    pthread_rwlock_destroy(&g_rules_lock);
}
void config_lock_read() {
    pthread_rwlock_rdlock(&g_rules_lock);
}
void config_unlock_read() {
    pthread_rwlock_unlock(&g_rules_lock);
}
void config_lock_write() {
    pthread_rwlock_wrlock(&g_rules_lock);
}
void config_unlock_write() {
    pthread_rwlock_unlock(&g_rules_lock);
}
static void free_app_config_rules(AppConfig* cfg) {
    if (!cfg) return;
    if (cfg->trie_root) {
        trie_free(cfg->trie_root);
        cfg->trie_root = nullptr;
    }
    if (cfg->hide_rules) {
        for (int i = 0; i < cfg->hide_count; i++) free(cfg->hide_rules[i]);
        free(cfg->hide_rules);
        cfg->hide_rules = nullptr;
    }
    cfg->hide_count = 0;
    cfg->hide_capacity = 0;
    if (cfg->allow_cross_pkgs) {
        for (int i = 0; i < cfg->allow_cross_pkg_count; i++) free(cfg->allow_cross_pkgs[i]);
        free(cfg->allow_cross_pkgs);
        cfg->allow_cross_pkgs = nullptr;
    }
    cfg->allow_cross_pkg_count = 0;
    cfg->allow_cross_pkg_capacity = 0;
    if (cfg->ro_rules) {
        for (int i = 0; i < cfg->ro_count; i++) free(cfg->ro_rules[i]);
        free(cfg->ro_rules);
        cfg->ro_rules = nullptr;
    }
    cfg->ro_count = 0;
    cfg->ro_capacity = 0;
    if (cfg->redir_rules) {
        free(cfg->redir_rules);
        cfg->redir_rules = nullptr;
    }
    cfg->redir_count = 0;
    cfg->redir_capacity = 0;
    if (cfg->ftp_rules) {
        free(cfg->ftp_rules);
        cfg->ftp_rules = nullptr;
    }
    cfg->ftp_count = 0;
    cfg->ftp_capacity = 0;
    if (cfg->var_names) {
        for (int i = 0; i < cfg->var_count; i++) free(cfg->var_names[i]);
        free(cfg->var_names);
        cfg->var_names = nullptr;
    }
    if (cfg->var_values) {
        for (int i = 0; i < cfg->var_count; i++) free(cfg->var_values[i]);
        free(cfg->var_values);
        cfg->var_values = nullptr;
    }
    if (cfg->var_resolved) {
        for (int i = 0; i < cfg->var_count; i++) free(cfg->var_resolved[i]);
        free(cfg->var_resolved);
        cfg->var_resolved = nullptr;
    }
    if (cfg->var_is_static) {
        free(cfg->var_is_static);
        cfg->var_is_static = nullptr;
    }
    cfg->var_count = 0;
    cfg->var_capacity = 0;
}
/* 发布期派生缓存作废钩子（见 config_parser.h）：单一注册者，写者线程在
   排空旧读者后、放行新读者前调用，此时无读者能重算并缓存旧配置指针 */
static void (*g_publish_invalidate_hook)(void);

void config_set_publish_invalidate_hook(void (*fn)(void)) {
    g_publish_invalidate_hook = fn;
}

/* COW 发布：把暂存区构建的新配置整体换入 live（g_global_cfg/g_app_cfgs），
   旧配置在旧代际读者归零后延迟释放。调用方须持 config_lock_write。 */
static void config_publish(void) {
    uint64_t old_gen = config_publish_begin();
    /* P1 修复：封锁新读者后先排空旧代际读者，再做非原子交换——
       否则读者可能观察到半换入的指针/count 配对（新数组+旧 count 越界读，
       或新 trie+旧规则的错误决策窗口）。config_publish_end 的排空仅用于
       延迟释放判定，无法撤销已发生的撕裂读 */
    config_drain_readers(old_gen);
    /* 派生缓存作废的**唯一安全窗口**：旧读者已全部离开、新读者仍被封锁
       （代际为奇数），此刻既不会有人把旧配置指针以新代际缓存下来，也没有
       读者还持着旧指针——见 config_parser.h 的钩子契约 */
    if (g_publish_invalidate_hook) g_publish_invalidate_hook();
    /* 快照旧 live（浅拷贝结构体，指针指向待释放内存） */
    AppConfig old_global = g_global_cfg;
    AppConfig** old_apps = g_app_cfgs;
    int old_count = g_app_cfg_count;
    /* 换入新配置 */
    g_global_cfg = g_global_cfg_stage;
    /* 沙盒目录名单点下发：common_sandbox_path 是唯一合成出口，
       配置发布时同步覆盖其目录名（热重载生效） */
    common_set_sandbox_dirname(g_global_cfg.sandbox_dir[0] ? g_global_cfg.sandbox_dir
                                                           : NSP_SANDBOX_DIRNAME);
    g_app_cfgs = g_app_cfgs_stage;
    g_app_cfg_count = g_app_cfg_count_stage;
    g_app_cfg_capacity = g_app_cfg_capacity_stage;
    /* 类别段存在性：扫描 live（publish 后调用方持写锁，赋值原子可见性
       由后续 config_publish_end 的 release 保证；读者经代际重试） */
    bool has_cat = false;
    for (int i = 0; i < g_app_cfg_count && !has_cat; i++) {
        if (g_app_cfgs[i] && (strcmp(g_app_cfgs[i]->pkg_name, "USER_APPS") == 0 ||
                              strcmp(g_app_cfgs[i]->pkg_name, "SYSTEM_APPS") == 0))
            has_cat = true;
    }
    g_has_category_rules = has_cat;
    /* 重置暂存区（指针已移交 live，不得再触碰） */
    memset(&g_global_cfg_stage, 0, sizeof(AppConfig));
    g_app_cfgs_stage = nullptr;
    g_app_cfg_count_stage = 0;
    g_app_cfg_capacity_stage = 0;
    config_publish_end(old_gen);
    /* 旧代际读者已归零：释放旧配置 */
    free_app_config_rules(&old_global);
    if (old_apps) {
        for (int i = 0; i < old_count; i++) {
            free_app_config_rules(old_apps[i]);
            free(old_apps[i]);
        }
        free(old_apps);
    }
}
char* clean_path_string(char* str) {
    /* 首尾空白经 nsp_util 公共库复用（nsp_str_trim，禁手写去空白循环）；
       \r\n 行尾截断为本函数特有语义（配置文件行处理） */
    if (!str) return nullptr;
    char* s = nsp_str_trim(str);
    for (int i = 0; s[i]; i++) {
        if (s[i] == '\r' || s[i] == '\n') {
            s[i] = '\0';
            break;
        }
    }
    return s;
}
void strip_trailing_slash(char* path) {
    /* 剥尾随 '/'，但保留 "?/"——'?' 后必跟 '/' 是内部前缀语义（见 docs/config.md），
       剥成裸 '?' 会使 Trie 命中根 redirect 时拼出 ?Android 而非 ?/Android，
       导致 vfs_to_real_path 还原成 /data/media/0Android（缺分隔符） */
    size_t len = strlen(path);
    if (len > 1 && path[len - 1] == '/' && !(len == 2 && path[0] == '?')) path[len - 1] = '\0';
}
/* mkdir_recursive_p / inherit_from_parent / sync_attributes 已迁移至 common.c（公共工具） */
static char* get_next_token(char** ptr) {
    char* p = *ptr;
    if (!p) return nullptr;
    while (isspace((unsigned char)*p)) p++;
    if (*p == '\0') {
        *ptr = nullptr;
        return nullptr;
    }
    char* start;
    if (*p == '"') {
        start = ++p;
        while (*p && *p != '"') p++;
        if (*p == '"') {
            *p = '\0';
            *ptr = p + 1;
        } else
            *ptr = p;
    } else {
        start = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        if (*p != '\0') {
            *p = '\0';
            *ptr = p + 1;
        } else
            *ptr = p;
    }
    return start;
}
/* 存储根别名剥离统一实现在 path_vars.c（/storage/emulated/<N>、/sdcard、
   /mnt/sdcard）——重定向目标的运行期合成都用同一份，避免两处漂移。 */
static const char* strip_storage_prefix(const char* path) {
    return nsp_strip_storage_prefix(path);
}
static int cmp_redir(const void* a, const void* b) {
    return (int)strlen(((const RedirectRule*)b)->virtual_prefix) -
           (int)strlen(((const RedirectRule*)a)->virtual_prefix);
}
static int cmp_hide(const void* a, const void* b) {
    const char* str_a = *(const char**)a;
    const char* str_b = *(const char**)b;
    return (int)strlen(str_b) - (int)strlen(str_a);
}
/* ============ 规则解析辅助（按类型拆分后的公共收敛点） ============
   parse_config_line 只做类型分派；每类规则的路径归一、数组增长、trie 插入/
   动态兜底逻辑收敛到下列函数，避免 HIDE/RO、ALLOW/REDIRECT 及四处 realloc
   增长分支各写一份。 */

/* 规则数组容量倍增：count < *cap 时原样返回；否则 realloc 到 2 倍并回写 *cap。
   失败返回 NULL（*cap 与调用方原指针均不变，不丢数据）。 */
static void* grow_rule_array(void* arr, int* cap, int count, size_t elem_size) {
    if (count < *cap) return arr;
    int new_cap = *cap == 0 ? 8 : *cap * 2;
    void* grown = realloc(arr, (size_t)new_cap * elem_size);
    if (!grown) return NULL;
    *cap = new_cap; /* 必须回写：否则下次仍按旧容量判断，越界写入 */
    return grown;
}

/* 定长缓冲写入（放不下即失败）：返回 false 时 out 已置空，调用方须丢弃该规则。
   规则路径被静默截断会变成更短的前缀，HIDE/RO 命中范围随之**放大**——违反
   AGENTS 红线「MAX_PATH_LEN 放不下返回 -1 而非截断」，故配置面一律 fail-closed。 */
static bool path_fmt(char* out, size_t outsz, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out, outsz, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= outsz) {
        if (outsz) out[0] = '\0';
        return false;
    }
    return true;
}

/* 规则路径前缀归一（HIDE/RO/ALLOW/REDIRECT 共用）：剥离 /storage/emulated/<uid>、
   补前导 '/'、不含通配符时去尾斜杠。keep_star_head=true 保留以 '*' 开头的写法
   （HIDE/RO 语义：'*' 视为通配起始，不补 '/'）。
   返回 false = 放不下 out（已置空），调用方须告警并忽略该行。 */
static bool normalize_rule_path(const char* in, char* out, size_t outsz, bool keep_star_head) {
    const char* p = strip_storage_prefix(in);
    bool ok = (p[0] == '/' || (keep_star_head && p[0] == '*')) ? path_fmt(out, outsz, "%s", p)
                                                               : path_fmt(out, outsz, "/%s", p);
    if (!ok) return false;
    if (strpbrk(out, "*?[]") == nullptr) strip_trailing_slash(out);
    return true;
}

/* 展开后的规则路径归一（br_linear_match 用）：变量值可能自带前导 '/'，而
   「以变量开头」的规则在解析期已被补上一个 '/'（normalize_rule_path），展开
   会拼出 "//storage/..."，与剥层后的 sub_path 永不相等；变量值也可能写成
   /sdcard/... 或 /storage/emulated/0/...。故在匹配前把展开结果按静态规则的
   同一套口径再归一一次：折叠开头重复 '/'、剥离存储根别名、补前导 '/'、无
   通配符时去尾斜杠。只折叠**开头**的重复斜杠——路径内部的 "//" 可能与真实
   文件名有关，不得改动。返回 false = 放不下 out（已置空，调用方丢弃该规则）。 */
bool normalize_expanded_rule_path(const char* in, char* out, size_t outsz) {
    if (!in || !out || outsz == 0) return false;
    while (in[0] == '/' && in[1] == '/') in++;
    const char* p = strip_storage_prefix(in);
    bool ok = (p[0] == '/' || p[0] == '*') ? path_fmt(out, outsz, "%s", p)
                                          : path_fmt(out, outsz, "/%s", p);
    if (!ok) return false;
    if (strpbrk(out, "*?[]") == nullptr) strip_trailing_slash(out);
    return true;
}

/* FTP 前缀归一：FTP 虚拟前缀是后端段名入口而非存储路径，故不做
   /storage/emulated 剥离，仅补前导 '/' 并无条件去尾斜杠。
   返回 false = 放不下 out（已置空）。 */
static bool normalize_ftp_prefix(const char* in, char* out, size_t outsz) {
    if (!path_fmt(out, outsz, "%s%s", in[0] == '/' ? "" : "/", in)) return false;
    strip_trailing_slash(out);
    if (out[0] == '\0') snprintf(out, outsz, "/");
    return true;
}

/* 追加字符串规则到 char** 数组（HIDE/RO 共用）：false = 增长或 strdup 失败
   （失败时不递增 count，避免把 NULL 计入规则数） */
static bool append_str_rule(char*** rules, int* count, int* capacity, const char* value) {
    char** grown = grow_rule_array(*rules, capacity, *count, sizeof(char*));
    if (!grown) return false;
    *rules = grown; /* 先接管新缓冲：strdup 失败时旧指针已失效，不能悬垂 */
    char* copy = strdup(value);
    if (!copy) return false;
    (*rules)[(*count)++] = copy;
    return true;
}

/* HIDE/RO：追加路径规则 + trie 插入（含通配/变量时仅线性兜底） */
static void append_path_rule(AppConfig* cur, const char* path, bool is_hide, int line_num,
                             const char* file_path) {
    bool ok = is_hide
                  ? append_str_rule(&cur->hide_rules, &cur->hide_count, &cur->hide_capacity, path)
                  : append_str_rule(&cur->ro_rules, &cur->ro_count, &cur->ro_capacity, path);
    if (!ok) {
        LOG_ERR("追加 %s_rules 失败（内存不足） (行 %d, 文件 %s)", is_hide ? "hide" : "ro",
                line_num, file_path);
        return;
    }
    if (!is_wildcard_string(path) && !has_path_var(path)) {
        trie_insert(cur->trie_root, path, NULL, is_hide, !is_hide);
    } else if (is_hide) {
        cur->dyn_hide = true; /* 通配/变量规则未入 trie，须线性兜底 */
    } else {
        cur->dyn_ro = true;
    }
}

/* REDIRECT/ALLOW：追加重定向规则 + trie 插入（含通配/变量时仅线性兜底） */
static void append_redirect_rule(AppConfig* cur, const char* virtual_prefix,
                                 const char* real_target, bool is_allow, int line_num,
                                 const char* file_path) {
    RedirectRule* grown = grow_rule_array(cur->redir_rules, &cur->redir_capacity, cur->redir_count,
                                          sizeof(RedirectRule));
    if (!grown) {
        LOG_ERR("realloc redir_rules 失败 (行 %d, 文件 %s)", line_num, file_path);
        return;
    }
    cur->redir_rules = grown;
    RedirectRule* r = &cur->redir_rules[cur->redir_count++];
    snprintf(r->virtual_prefix, sizeof(r->virtual_prefix), "%s", virtual_prefix);
    snprintf(r->real_target, sizeof(r->real_target), "%s", real_target);
    r->is_allow = is_allow;
    if (!is_wildcard_string(virtual_prefix) && !is_wildcard_string(real_target) &&
        !has_path_var(virtual_prefix) && !has_path_var(real_target)) {
        trie_insert(cur->trie_root, virtual_prefix, real_target, false, false);
    } else {
        cur->dyn_redir = true; /* 通配/变量 redir 未入 trie，须线性兜底 */
    }
}

/* 变量四平行数组增长：全部新数组分配成功才替换（realloc 就地扩展会使旧
   指针失效，逐个 realloc 在部分失败时留下悬垂指针）。false = OOM。 */
static bool grow_var_arrays(AppConfig* cur) {
    if (cur->var_count < cur->var_capacity) return true;
    int new_cap = cur->var_capacity == 0 ? 8 : cur->var_capacity * 2;
    char** names = malloc((size_t)new_cap * sizeof(char*));
    char** values = malloc((size_t)new_cap * sizeof(char*));
    char** resolved = malloc((size_t)new_cap * sizeof(char*));
    bool* is_static = malloc((size_t)new_cap * sizeof(bool));
    if (!names || !values || !resolved || !is_static) {
        free(names);
        free(values);
        free(resolved);
        free(is_static);
        return false;
    }
    if (cur->var_count > 0) {
        memcpy(names, cur->var_names, (size_t)cur->var_count * sizeof(char*));
        memcpy(values, cur->var_values, (size_t)cur->var_count * sizeof(char*));
        memcpy(resolved, cur->var_resolved, (size_t)cur->var_count * sizeof(char*));
        memcpy(is_static, cur->var_is_static, (size_t)cur->var_count * sizeof(bool));
    }
    free(cur->var_names);
    free(cur->var_values);
    free(cur->var_resolved);
    free(cur->var_is_static);
    cur->var_names = names;
    cur->var_values = values;
    cur->var_resolved = resolved;
    cur->var_is_static = is_static;
    cur->var_capacity = new_cap;
    return true;
}

/* NAME=VALUE 赋值（紧凑形式，无空格围绕 =）：识别即返回 true（含保留名告警） */
static bool parse_variable_rule(AppConfig* cur, const char* line, int line_num,
                                const char* file_path) {
    char vname[128], vvalue[MAX_PATH_LEN];
    int vr = parse_var_assignment(line, vname, sizeof vname, vvalue, sizeof vvalue);
    if (vr == 0) return false; /* 非赋值行，按规则行继续解析 */
    if (vr < 0) {
        /* 值放不下：拒绝该行。截断的值会让引用它的 $变量 展开出更短前缀，
           HIDE/RO 命中范围被放大——fail-closed，与路径规则同一红线 */
        LOG_WRN("变量值过长（限 %d 字节），该行已忽略 (行 %d, 文件 %s)", (int)MAX_PATH_LEN - 1,
                line_num, file_path);
        return true; /* 已识别为赋值行：不再交给规则分派 */
    }
    if (strcmp(vname, "package") == 0) {
        LOG_WRN("不允许覆盖系统保留变量 package (行 %d, 文件 %s)", line_num, file_path);
        return true;
    }
    if (!grow_var_arrays(cur)) {
        LOG_ERR("realloc 变量数组失败 (行 %d)", line_num);
        return true;
    }
    /* strdup 失败时不递增 var_count，避免把 NULL 计入变量数 */
    char* name_copy = strdup(vname);
    char* value_copy = strdup(vvalue);
    if (!name_copy || !value_copy) {
        free(name_copy);
        free(value_copy);
        LOG_ERR("strdup 变量失败（内存不足） (行 %d, 文件 %s)", line_num, file_path);
        return true;
    }
    cur->var_names[cur->var_count] = name_copy;
    cur->var_values[cur->var_count] = value_copy;
    cur->var_resolved[cur->var_count] = NULL;
    cur->var_is_static[cur->var_count] = false;
    cur->var_count++;
    return true;
}

/* MONITOR / SANDBOX：取 ON/1 为开（词法唯一出处 nsp_switch_on），其余（含缺省）
   为关；写一次即标记 explicit */
static void parse_switch_rule(bool* field, bool* explicit_flag, char* p_ptr) {
    char* val = get_next_token(&p_ptr);
    *field = nsp_switch_on(val);
    *explicit_flag = true;
}

/* GLOBAL_INJECT / SKIP_SYSTEM_APPS：仅 [GLOBAL] 段有效，写在别处忽略并告警 */
static void parse_global_switch_rule(AppConfig* cur, bool* field, const char* name, char* p_ptr,
                                     int line_num, const char* file_path) {
    char* val = get_next_token(&p_ptr);
    if (cur != &g_global_cfg_stage) {
        LOG_WRN("%s 仅 [GLOBAL] 段有效（行 %d, 文件 %s），已忽略", name, line_num, file_path);
        return;
    }
    *field = nsp_switch_on(val);
}

/* FUSE_EXTRA_ARGS：仅 [GLOBAL] 段有效；取行尾原样内容（不分词，上限 512 字节） */
static void parse_fuse_extra_args_rule(AppConfig* cur, char* p_ptr, int line_num,
                                       const char* file_path) {
    if (cur != &g_global_cfg_stage) {
        LOG_WRN("FUSE_EXTRA_ARGS 仅 [GLOBAL] 段有效（行 %d, 文件 %s），已忽略", line_num,
                file_path);
        return;
    }
    char* p = p_ptr;
    while (p && isspace((unsigned char)*p)) p++;
    if (!p || !*p) return;
    size_t len = strlen(p);
    while (len > 0 && isspace((unsigned char)p[len - 1])) len--;
    if (len == 0) return;
    size_t copy_len =
        len < sizeof(cur->fuse_extra_args) - 1 ? len : sizeof(cur->fuse_extra_args) - 1;
    memcpy(cur->fuse_extra_args, p, copy_len);
    cur->fuse_extra_args[copy_len] = '\0';
}

/* SANDBOX_DIR <目录名>：仅 [GLOBAL] 段有效；沙盒落点目录名（不含路径分隔符），
   空值/超长/含分隔符告警忽略（保持默认 "sandbox"） */
static void parse_sandbox_dir_rule(AppConfig* cur, char* p_ptr, int line_num,
                                   const char* file_path) {
    if (cur != &g_global_cfg_stage) {
        LOG_WRN("SANDBOX_DIR 仅 [GLOBAL] 段有效（行 %d, 文件 %s），已忽略", line_num,
                file_path);
        return;
    }
    char* val = get_next_token(&p_ptr);
    if (!val || !val[0]) {
        LOG_WRN("SANDBOX_DIR 缺少目录名（行 %d, 文件 %s），已忽略", line_num, file_path);
        return;
    }
    if (strchr(val, '/')) {
        LOG_WRN("SANDBOX_DIR 只接受单级目录名，不允许路径分隔符（行 %d, 文件 %s），已忽略",
                line_num, file_path);
        return;
    }
    if (strlen(val) >= sizeof(cur->sandbox_dir)) {
        LOG_WRN("SANDBOX_DIR 目录名过长（行 %d, 文件 %s），已忽略", line_num, file_path);
        return;
    }
    strcpy(cur->sandbox_dir, val);
}

/* FUSE_EVENTS_UIDS <uid>[,<uid>...]：仅 [GLOBAL] 段有效；向通道白名单**追加**
   uid（root/system/media_rw 恒在列，无需重复写）。逗号或空白分隔，最多
   sizeof(fuse_events_uids) 项；非法/超限项告警后跳过，不放弃整行
   （白名单少一项只是连不上，不该让整份配置读失败）。 */
static void parse_fuse_events_uids_rule(AppConfig* cur, char* p_ptr, int line_num,
                                        const char* file_path) {
    if (cur != &g_global_cfg_stage) {
        LOG_WRN("FUSE_EVENTS_UIDS 仅 [GLOBAL] 段有效（行 %d, 文件 %s），已忽略", line_num,
                file_path);
        return;
    }
    const int cap = (int)(sizeof(cur->fuse_events_uids) / sizeof(cur->fuse_events_uids[0]));
    cur->fuse_events_uid_count = 0;
    char* p = p_ptr;
    while (p && *p) {
        while (*p && (isspace((unsigned char)*p) || *p == ',')) p++;
        if (!*p) break;
        char* end = p;
        long v = strtol(p, &end, 10);
        if (end == p || v < 0 || v > INT_MAX) {
            LOG_WRN("FUSE_EVENTS_UIDS 含非法 uid \"%.*s\"（行 %d, 文件 %s），已跳过",
                    (int)(strcspn(p, ", \t")), p, line_num, file_path);
            while (*p && !isspace((unsigned char)*p) && *p != ',') p++;
            continue;
        }
        if (cur->fuse_events_uid_count >= cap) {
            LOG_WRN("FUSE_EVENTS_UIDS 超过 %d 项上限（行 %d, 文件 %s），多余项已忽略", cap,
                    line_num, file_path);
            break;
        }
        cur->fuse_events_uids[cur->fuse_events_uid_count++] = (int)v;
        p = end;
    }
}

/* ALLOW_CROSS_APP_PKGS <包名>[,<包名>...]：仅 [GLOBAL] 段有效；向跨应用放行
   白名单**追加**包名（重复项只留一条）。逗号或空白分隔；非法项（含路径分隔符、
   ':'、超长）告警后跳过，不放弃整行——白名单少一项只是该应用照常隔离，不该让
   整份配置读失败。 */
static void parse_allow_cross_app_pkgs_rule(AppConfig* cur, char* p_ptr, int line_num,
                                            const char* file_path) {
    if (cur != &g_global_cfg_stage) {
        LOG_WRN("ALLOW_CROSS_APP_PKGS 仅 [GLOBAL] 段有效（行 %d, 文件 %s），已忽略", line_num,
                file_path);
        return;
    }
    char* p = p_ptr;
    while (p && *p) {
        while (*p && (isspace((unsigned char)*p) || *p == ',')) p++;
        if (!*p) break;
        size_t len = strcspn(p, ", \t");
        /* 包名只允许 [A-Za-z0-9._]：路径分隔符/进程后缀（':'）会让精确比较永远
           落空，静默不生效比告警更糟 */
        bool bad = (len == 0 || len >= 128);
        for (size_t i = 0; !bad && i < len; i++) {
            unsigned char c = (unsigned char)p[i];
            if (!(isalnum(c) || c == '.' || c == '_')) bad = true;
        }
        if (bad) {
            LOG_WRN("ALLOW_CROSS_APP_PKGS 含非法包名 \"%.*s\"（行 %d, 文件 %s），已跳过",
                    (int)len, p, line_num, file_path);
            p += len;
            continue;
        }
        char pkg[128];
        memcpy(pkg, p, len);
        pkg[len] = '\0';
        bool dup = false;
        for (int i = 0; i < cur->allow_cross_pkg_count && !dup; i++)
            if (strcmp(cur->allow_cross_pkgs[i], pkg) == 0) dup = true;
        if (!dup && !append_str_rule(&cur->allow_cross_pkgs, &cur->allow_cross_pkg_count,
                                     &cur->allow_cross_pkg_capacity, pkg))
            LOG_WRN("ALLOW_CROSS_APP_PKGS 追加失败（行 %d, 文件 %s）", line_num, file_path);
        p += len;
    }
}

/* HIDE <path> / RO <path> */
static void parse_path_rule(AppConfig* cur, char* p_ptr, bool is_hide, int line_num,
                            const char* file_path) {
    char* val = get_next_token(&p_ptr);
    if (!val) return;
    char path[MAX_PATH_LEN];
    if (!normalize_rule_path(val, path, sizeof path, true)) {
        LOG_WRN("%s 路径过长（限 %d 字节），该规则已忽略 (行 %d, 文件 %s)",
                is_hide ? "HIDE" : "RO", (int)MAX_PATH_LEN - 1, line_num, file_path);
        return;
    }
    append_path_rule(cur, path, is_hide, line_num, file_path);
}

/* ALLOW <path>：等价"重定向回自身真实存储"，real_target 为 ?<path> 内部前缀 */
static void parse_allow_rule(AppConfig* cur, char* p_ptr, int line_num, const char* file_path) {
    char* val = get_next_token(&p_ptr);
    if (!val) return;
    char virtual_prefix[MAX_PATH_LEN];
    if (!normalize_rule_path(val, virtual_prefix, sizeof virtual_prefix, false)) {
        LOG_WRN("ALLOW 路径过长（限 %d 字节），该规则已忽略 (行 %d, 文件 %s)",
                (int)MAX_PATH_LEN - 1, line_num, file_path);
        return;
    }
    char real_target[MAX_PATH_LEN];
    if (!path_fmt(real_target, sizeof real_target, "?%s", virtual_prefix)) {
        LOG_WRN("ALLOW 路径过长（限 %d 字节），该规则已忽略 (行 %d, 文件 %s)",
                (int)MAX_PATH_LEN - 2, line_num, file_path);
        return;
    }
    if (strpbrk(real_target, "*?[]") == nullptr) strip_trailing_slash(real_target);
    append_redirect_rule(cur, virtual_prefix, real_target, true, line_num, file_path);
}

/* REDIRECT <vpath> <target>：目标含变量时原样存入（分类延迟到运行时
   build_real_base_from_target），否则按路径归一规则生成 ? 内部前缀 */
static void parse_redirect_rule(AppConfig* cur, char* p_ptr, int line_num, const char* file_path) {
    char* v1 = get_next_token(&p_ptr);
    char* v2 = get_next_token(&p_ptr);
    if (!v1 || !v2) return;
    char virtual_prefix[MAX_PATH_LEN];
    if (!normalize_rule_path(v1, virtual_prefix, sizeof virtual_prefix, false)) {
        LOG_WRN("REDIRECT 虚拟路径过长（限 %d 字节），该规则已忽略 (行 %d, 文件 %s)",
                (int)MAX_PATH_LEN - 1, line_num, file_path);
        return;
    }
    char real_target[MAX_PATH_LEN];
    bool ok;
    if (has_path_var(v2)) {
        ok = path_fmt(real_target, sizeof real_target, "%s", v2);
    } else if (strncmp(v2, NSP_ANDROID_EMULATED_ROOT "/",
                       sizeof(NSP_ANDROID_EMULATED_ROOT "/") - 1) == 0) {
        const char* p = v2 + sizeof(NSP_ANDROID_EMULATED_ROOT "/") - 1;
        while (*p && isdigit((unsigned char)*p)) p++;
        if (*p == '/') p++;
        ok = path_fmt(real_target, sizeof real_target, "?/%s", p);
    } else if (strip_storage_prefix(v2) != v2) {
        /* /sdcard、/mnt/sdcard、/storage/self/primary 是当前用户存储的别名：与
           /storage/emulated 分支同口径转成 "?<剩余路径>"，否则目标会被当成存储根
           下的子目录。用剥离函数的返回值判定，避免「/sdcardXxx」被误剥 */
        const char* p = strip_storage_prefix(v2);
        ok = path_fmt(real_target, sizeof real_target, "?%s", p);
    } else if (is_system_abs_path(v2)) {
        ok = path_fmt(real_target, sizeof real_target, "%s", v2);
    } else {
        ok = path_fmt(real_target, sizeof real_target, "?/%s", v2[0] == '/' ? v2 + 1 : v2);
    }
    if (!ok) {
        LOG_WRN("REDIRECT 目标路径过长（限 %d 字节），该规则已忽略 (行 %d, 文件 %s)",
                (int)MAX_PATH_LEN - 1, line_num, file_path);
        return;
    }
    if (strpbrk(real_target, "*?[]") == nullptr) strip_trailing_slash(real_target);
    append_redirect_rule(cur, virtual_prefix, real_target, false, line_num, file_path);
}

/* FTP <虚拟前缀> <段名>：虚拟前缀命中时由 FTP 后端（段名）提供。
   规则所在段决定作用域：GLOBAL=全局，应用段=仅该应用 */
static void parse_ftp_rule(AppConfig* cur, char* p_ptr, int line_num, const char* file_path) {
    char* v1 = get_next_token(&p_ptr);
    char* v2 = get_next_token(&p_ptr);
    if (!v1 || !v2) {
        LOG_WRN("FTP 规则缺少参数 (行 %d, 文件 %s)", line_num, file_path);
        return;
    }
    char virtual_prefix[MAX_PATH_LEN];
    if (!normalize_ftp_prefix(v1, virtual_prefix, sizeof virtual_prefix)) {
        LOG_WRN("FTP 虚拟前缀过长（限 %d 字节），该规则已忽略 (行 %d, 文件 %s)",
                (int)MAX_PATH_LEN - 1, line_num, file_path);
        return;
    }
    /* 段名放不下即拒绝：截断的段名会指向另一个（可能不存在的）后端配置，
       与「放不下返回错误而非截断」同一红线；先校验再占用数组槽位 */
    if (strlen(v2) >= sizeof(((FtpRule*)nullptr)->backend_name)) {
        LOG_WRN("FTP 段名过长（限 %d 字节），该规则已忽略 (行 %d, 文件 %s)",
                (int)sizeof(((FtpRule*)nullptr)->backend_name) - 1, line_num, file_path);
        return;
    }
    FtpRule* grown =
        grow_rule_array(cur->ftp_rules, &cur->ftp_capacity, cur->ftp_count, sizeof(FtpRule));
    if (!grown) {
        LOG_ERR("realloc ftp_rules 失败 (行 %d)", line_num);
        return;
    }
    cur->ftp_rules = grown;
    FtpRule* fr = &cur->ftp_rules[cur->ftp_count++];
    memset(fr, 0, sizeof *fr);
    snprintf(fr->virtual_prefix, sizeof fr->virtual_prefix, "%s", virtual_prefix);
    snprintf(fr->backend_name, sizeof fr->backend_name, "%s", v2);
    /* 同时入 trie：resolve 热路径经 trie 下降一次取得 FTP 命中
       （替代早期的每请求 O(N) 线性扫描）；
       FTP 前缀为静态字面段（无通配/变量），与线性匹配语义一致 */
    if (cur->trie_root) trie_insert_ftp(cur->trie_root, virtual_prefix, v2);
}

static void parse_config_line(AppConfig* cur, char* line, int user_id, int line_num,
                              const char* file_path) {
    (void)user_id;
    if (parse_variable_rule(cur, line, line_num, file_path)) return;
    char* p_ptr = line;
    char* tok = get_next_token(&p_ptr);
    if (!tok) return;
    /* 按规则类型分派：路径归一/数组增长/trie 插入收敛在各 parse_<type>_rule 内 */
    if (strcmp(tok, "MONITOR") == 0)
        parse_switch_rule(&cur->monitor, &cur->monitor_explicit, p_ptr);
    else if (strcmp(tok, "SANDBOX") == 0)
        parse_switch_rule(&cur->sandbox, &cur->sandbox_explicit, p_ptr);
    else if (strcmp(tok, "GLOBAL_INJECT") == 0)
        parse_global_switch_rule(cur, &cur->global_inject, tok, p_ptr, line_num, file_path);
    else if (strcmp(tok, "SKIP_SYSTEM_APPS") == 0)
        parse_global_switch_rule(cur, &cur->skip_system_apps, tok, p_ptr, line_num, file_path);
    else if (strcmp(tok, "ALLOW_CROSS_APP_DATA") == 0)
        parse_global_switch_rule(cur, &cur->allow_cross_app_data, tok, p_ptr, line_num, file_path);
    else if (strcmp(tok, "ALLOW_CROSS_APP_BY_CAPABILITY") == 0)
        parse_global_switch_rule(cur, &cur->allow_cross_by_capability, tok, p_ptr, line_num,
                                 file_path);
    else if (strcmp(tok, "ALLOW_CROSS_APP_PKGS") == 0)
        parse_allow_cross_app_pkgs_rule(cur, p_ptr, line_num, file_path);
    else if (strcmp(tok, "FUSE_EVENTS") == 0)
        parse_global_switch_rule(cur, &cur->fuse_events, tok, p_ptr, line_num, file_path);
    else if (strcmp(tok, "FUSE_EVENTS_UIDS") == 0)
        parse_fuse_events_uids_rule(cur, p_ptr, line_num, file_path);
    else if (strcmp(tok, "FUSE_EXTRA_ARGS") == 0)
        parse_fuse_extra_args_rule(cur, p_ptr, line_num, file_path);
    else if (strcmp(tok, "SANDBOX_DIR") == 0)
        parse_sandbox_dir_rule(cur, p_ptr, line_num, file_path);
    else if (strcmp(tok, "HIDE") == 0)
        parse_path_rule(cur, p_ptr, true, line_num, file_path);
    else if (strcmp(tok, "RO") == 0)
        parse_path_rule(cur, p_ptr, false, line_num, file_path);
    else if (strcmp(tok, "ALLOW") == 0)
        parse_allow_rule(cur, p_ptr, line_num, file_path);
    else if (strcmp(tok, "REDIRECT") == 0)
        parse_redirect_rule(cur, p_ptr, line_num, file_path);
    else if (strcmp(tok, "FTP") == 0)
        parse_ftp_rule(cur, p_ptr, line_num, file_path);
    else
        LOG_WRN("不支持的规则 \"%s\" (行 %d, 文件 %s)", tok, line_num, file_path);
}

/* 类别段（[USER_APPS[:uid]] / [SYSTEM_APPS]）段头归一：
 * - USER_APPS：uid 原样（无 :uid 则 -1，跨用户 fallback）；
 * - SYSTEM_APPS：对所有 uid 系统应用生效，user_id 恒 -1，带 :uid 归一并告警；
 * - GLOBAL/普通包：uid 原样。返回 true = 类别段（调用方跳过普通包分支）。 */
static bool classify_category_section(const char* pkg, int* uid_inout, const char* file, int line) {
    if (strcmp(pkg, "USER_APPS") == 0) return true;
    if (strcmp(pkg, "SYSTEM_APPS") == 0) {
        if (*uid_inout != -1) {
            LOG_WRN(
                "[SYSTEM_APPS] 不支持按用户隔离（行 %d, 文件 %s），:uid 已忽略（对所有用户系统应用生效）",
                line, file);
            *uid_inout = -1;
        }
        return true;
    }
    return false;
}

static AppConfig* get_or_create_app_cfg(const char* pkg, int user_id) {
    /* S1：构建进暂存区（live 由 config_publish 一次性换入） */
    if (strcmp(pkg, "GLOBAL") == 0) return &g_global_cfg_stage;
    for (int i = 0; i < g_app_cfg_count_stage; i++) {
        if (g_app_cfgs_stage[i]->user_id == user_id &&
            strcmp(g_app_cfgs_stage[i]->pkg_name, pkg) == 0)
            return g_app_cfgs_stage[i];
    }
    if (g_app_cfg_count_stage >= g_app_cfg_capacity_stage) {
        int new_cap = g_app_cfg_capacity_stage == 0 ? 8 : g_app_cfg_capacity_stage * 2;
        AppConfig** new_cfgs = realloc(g_app_cfgs_stage, new_cap * sizeof(AppConfig*));
        if (!new_cfgs) {
            LOG_ERR("realloc g_app_cfgs 失败，跳过应用 %s", pkg);
            return nullptr;
        }
        g_app_cfgs_stage = new_cfgs;
        g_app_cfg_capacity_stage = new_cap;
    }
    g_app_cfgs_stage[g_app_cfg_count_stage] = calloc(1, sizeof(AppConfig));
    strncpy(g_app_cfgs_stage[g_app_cfg_count_stage]->pkg_name, pkg, 127);
    g_app_cfgs_stage[g_app_cfg_count_stage]->user_id = user_id;
    g_app_cfgs_stage[g_app_cfg_count_stage]->inject_enable = false;
    g_app_cfgs_stage[g_app_cfg_count_stage]->trie_root = trie_create_node(NULL);
    return g_app_cfgs_stage[g_app_cfg_count_stage++];
}
/* 由磁盘上已存在的 App-rules-<uid> 目录补齐活跃用户列表。

   跳过 pm 探测的只读加载方（fuse_daemon 内建引擎、log_ctl）若某用户的
   /data/media/<uid> 不可读，该用户不会出现在 pm / /data/media 两轮扫描里，
   load_config_rules 后续的 App-rules-<uid>/<pkg>.conf 扫描就整段跳过——injector
   仍把这些应用当注入目标，而真正执行 HIDE/RO/REDIRECT 的进程却没有对应规则，
   静默失效且无任何报错。以磁盘上真实存在的规则目录为准可消除这一分叉，
   且纯只读、不 mkdir、不依赖 pm/binder。injector 侧同样执行以保持两端一致
   （目录既已存在，mkdir 分支不会触发） */
static void merge_users_from_app_rules_dirs(void) {
    DIR* dir = opendir(CONFIG_DIR);
    if (!dir) return;
    struct dirent* de;
    while ((de = readdir(dir)) != nullptr) {
        if (de->d_type != DT_DIR && de->d_type != DT_LNK) continue;
        if (strncmp(de->d_name, "App-rules-", 10) != 0) continue;
        const char* s = de->d_name + 10;
        if (!*s) continue;
        bool is_num = true;
        for (int i = 0; s[i]; i++) {
            if (!isdigit((unsigned char)s[i])) {
                is_num = false;
                break;
            }
        }
        if (!is_num) continue;
        int uid = atoi(s);
        if (uid < 0 || uid >= MAX_REASONABLE_UID) continue;
        bool seen = false;
        for (int i = 0; i < g_active_user_count; i++) {
            if (g_active_users[i] == uid) {
                seen = true;
                break;
            }
        }
        if (seen) continue;
        if (g_active_user_count >= MAX_USERS) break;
        g_active_users[g_active_user_count++] = uid;
        LOG_DBG("scan_active_users: 由规则目录补入用户 uid=%d", uid);
    }
    closedir(dir);
}

void scan_active_users() {
    g_active_user_count = 0;

    // 优先通过 pm list users 获取真实用户列表（跳过模式：只读加载方
    // 不执行 popen——pm 需 binder 通信 system_server，受限环境会挂起）
    if (!g_scan_users_skip_pm) {
        FILE* fp = popen("pm list users 2>/dev/null", "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                int uid = -1;
                if (sscanf(line, " UserInfo{%d:", &uid) == 1) {
                    if (uid >= 0 && g_active_user_count < MAX_USERS)
                        g_active_users[g_active_user_count++] = uid;
                }
            }
            pclose(fp);
        }
    } else {
        LOG_DBG("scan_active_users: 只读模式跳过 pm 探测，仅扫描 /data/media");
    }

    // pm 失败时回退到 /data/media/ 扫描
    if (g_active_user_count == 0) {
        DIR* dir = opendir("/data/media");
        if (dir) {
            struct dirent* de;
            while ((de = readdir(dir)) != nullptr) {
                if (de->d_type == DT_DIR || de->d_type == DT_LNK) {
                    bool is_num = true;
                    for (int i = 0; de->d_name[i]; i++) {
                        if (!isdigit(de->d_name[i])) {
                            is_num = false;
                            break;
                        }
                    }
                    if (is_num && g_active_user_count < MAX_USERS) {
                        int uid = atoi(de->d_name);
                        if (uid >= 0 && uid < MAX_REASONABLE_UID)
                            g_active_users[g_active_user_count++] = uid;
                    }
                }
            }
            closedir(dir);
        }
    }

    /* 无论 pm 是否成功都补扫规则目录：磁盘上有 App-rules-<uid> 就说明该用户
       有规则要加载，不能因 /data/media/<uid> 不可读而整段漏掉 */
    merge_users_from_app_rules_dirs();

    // 确保至少有 user 0
    if (g_active_user_count == 0) {
        g_active_users[0] = 0;
        g_active_user_count = 1;
    }

    LOG_DBG("scan_active_users: 发现 %d 个活跃用户", g_active_user_count);
    for (int i = 0; i < g_active_user_count; i++)
        LOG_DBG("  活跃用户[%d]: uid=%d", i, g_active_users[i]);
}

/* 应用规则目录创建权限开关：仅 injector 应开启（true）——App-rules 目录的
   创建权归属 injector 单一进程；fuse_daemon（内建引擎）、log_ctl 等
   只读加载方保持默认 false，加载配置时不得 mkdir（防止伪用户目录固化） */
void config_set_allow_app_rules_mkdir(bool allow) {
    g_allow_app_rules_mkdir = allow;
    LOG_DBG("应用规则目录创建权限: %s", allow ? "允许(仅injector)" : "只读");
}

/* pm 探测开关：只读加载方（fuse_daemon 内建引擎、log_ctl）置
   true——scan_active_users 跳过 popen("pm list users")，改由 /data/media 与
   已存在的 App-rules-<uid> 目录推导用户列表。
   pm 需 binder 通信 system_server，在 fuse_daemon 受限环境（SELinux/
   命名空间）可能长时间挂起，而 load_config_rules 在 config_lock_write
   写锁内执行：启动（br_rules_init，fuse_main 之前）与热重载（inotify
   线程）都会因 popen 阻塞而卡死 → FUSE 会话无响应。log_ctl 虽是短命 CLI
   不至于死锁，但每次 JSON API 调用都付一次 binder 开销同样无必要。
   injector 保持默认 false（主控进程有 pm 环境，需要完整用户列表） */
void config_set_scan_users_skip_pm(bool skip) {
    g_scan_users_skip_pm = skip;
    LOG_DBG("活跃用户 pm 探测: %s", skip ? "跳过(仅/data/media)" : "启用(pm list users)");
}

/* ================= 配置扁平视图：读取阶段 ================= */

typedef struct {
    NspCfgRec* recs;
    int count;
    int cap;
} ViewAcc;

/* 追加一条记录（text/type/file 各自 strdup 归视图所有）。OOM 时静默丢弃该记录：
   配置加载非热路径，且丢弃只影响该行规则，不破坏已收集部分的结构完整性。 */
static void view_push(ViewAcc* va, uint8_t kind, uint8_t enabled, int32_t uid, int32_t line_no,
                      const char* file, const char* type, const char* text) {
    if (va->count >= va->cap) {
        int ncap = va->cap == 0 ? 64 : va->cap * 2;
        NspCfgRec* grown = realloc(va->recs, (size_t)ncap * sizeof(NspCfgRec));
        if (!grown) return;
        va->recs = grown;
        va->cap = ncap;
    }
    NspCfgRec* r = &va->recs[va->count++];
    memset(r, 0, sizeof *r);
    r->kind = kind;
    r->enabled = enabled;
    r->uid = uid;
    r->line_no = line_no;
    if (file) r->file = strdup(file);
    if (type) r->type = strdup(type);
    if (text) r->text = strdup(text);
}

/* 首 token 作为规则类型名（供按模块订阅过滤）；含 '=' 视为变量定义行归一为 "VAR" */
static void view_first_token(const char* line, char* out, size_t sz) {
    size_t i = 0;
    while (line[i] && !isspace((unsigned char)line[i]) && i + 1 < sz) {
        out[i] = line[i];
        i++;
    }
    out[i] = '\0';
    if (strchr(out, '=')) snprintf(out, sz, "VAR");
}

/* 段头行 → (段名, :uid, ON/OFF)；非段头返回 false。
   段名与 :uid 就地切分（入参为可写行缓冲，调用方已在行内原地清理）。
   OFF/ON 后缀必须**整词**匹配（后接空白或行尾）：`[X] OFFX` 此前被当开关
   静默接受，与 nsp_rule_file.c 的边界口径不一致。 */
static bool view_token_is(const char* p, const char* word) {
    size_t n = strlen(word);
    if (strncmp(p, word, n) != 0) return false;
    char c = p[n];
    return c == '\0' || isspace((unsigned char)c);
}

static bool view_parse_section(char* p, char** name_out, int* uid_out, bool* enabled_out) {
    if (p[0] != '[') return false;
    char* end = strchr(p, ']');
    if (!end) return false;
    *end = '\0';
    char* sec = p + 1;
    char* after = end + 1;
    bool enabled = true;
    while (isspace((unsigned char)*after)) after++;
    if (view_token_is(after, "OFF"))
        enabled = false;
    else if (view_token_is(after, "ON"))
        enabled = true;
    /* 段头含 `:uid` 时校验数字：`[com.foo:abc]` 此前 atoi 静默成 uid 0（命中
       系统用户），规则落到错误的用户作用域。非数字整段视为无 uid 标记
       （uid=-1），并由调用方日志告警——比静默归 0 安全。 */
    int uid = -1;
    char* colon = strchr(sec, ':');
    if (colon) {
        *colon = '\0';
        const char* d = colon + 1;
        while (isspace((unsigned char)*d)) d++;
        bool numeric = (*d != '\0');
        for (const char* q = d; *q; q++)
            if (!isdigit((unsigned char)*q)) {
                numeric = false;
                break;
            }
        if (numeric) {
            long v = strtol(d, NULL, 10);
            if (v < 0 || v > 99999)
                numeric = false; /* 越界（含 atoi 溢出 UB）→ 无 uid 标记 */
            else
                uid = (int)v;
        }
        if (!numeric)
            LOG_WRN("段头 [%s] 的 uid 标记 \"%s\" 非法，按无 uid（-1）处理", sec, colon + 1);
    }
    *name_out = sec;
    *uid_out = uid;
    *enabled_out = enabled;
    return true;
}

/* 主文件：段头 → SECTION，其余行 → RULE。
   行读取经 nsp_getline_capped 有界动态拼装：超长行整行丢弃并告警
   （与 docs/config.md「单行 ≤2048 字节，超长行不参与匹配」对齐）。
   旧 fgets 固定缓冲会把长行切成多段、首段仍当规则生效 + 余段污染日志。 */
static void view_scan_main_file(ViewAcc* va, const char* path) {
    FILE* fp = fopen(path, "r");
    if (!fp) {
        LOG_ERR("无法打开主规则文件: %s (%s)", path, strerror(errno));
        return;
    }
    char* line = nullptr;
    size_t line_cap = 0;
    int line_num = 0;
    for (;;) {
        int r = nsp_getline_capped(fp, &line, &line_cap, NSP_CONFIG_LINE_MAX, NULL);
        if (r == 0) break;
        line_num++;
        if (r == -2) {
            LOG_WRN("规则文件 %s 第 %d 行超长（>%d 字节），整行跳过", path, line_num,
                    NSP_CONFIG_LINE_MAX);
            continue;
        }
        if (r < 0) break;
        char* p = clean_path_string(line);
        if (!p || p[0] == '#' || p[0] == 0) continue;
        char* sec = nullptr;
        int uid = -1;
        bool enabled = true;
        if (view_parse_section(p, &sec, &uid, &enabled)) {
            view_push(va, NSP_CFG_REC_SECTION, enabled ? 1 : 0, uid, line_num, path, nullptr, sec);
            continue;
        }
        char type[64];
        view_first_token(p, type, sizeof type);
        view_push(va, NSP_CFG_REC_RULE, 0, -1, line_num, path, type, p);
    }
    free(line);
    fclose(fp);
}

/* App-rules* 目录：<pkg>.conf → APP_FILE + 其内行；<pkg>.conf.disabled → APP_DISABLED */
static void view_scan_app_rules(ViewAcc* va) {
    for (int i = 0; i < g_active_user_count; i++) {
        int uid = g_active_users[i];
        char app_rules_dir[PATH_MAX];
        nsp_app_rule_dir(CONFIG_DIR, uid, app_rules_dir, sizeof(app_rules_dir));
        DIR* dir = opendir(app_rules_dir);
        if (!dir) continue;
        struct dirent* de;
        while ((de = readdir(dir)) != nullptr) {
            if (de->d_type != DT_REG && de->d_type != DT_LNK) continue;
            char* ext = strrchr(de->d_name, '.');
            if (ext && strcmp(ext, ".conf") == 0) {
                char pkg[128];
                size_t len = ext - de->d_name;
                if (len >= sizeof(pkg)) len = sizeof(pkg) - 1;
                strncpy(pkg, de->d_name, len);
                pkg[len] = '\0';
                char app_conf_path[PATH_MAX];
                snprintf(app_conf_path, sizeof(app_conf_path), "%s/%s", app_rules_dir, de->d_name);
                /* 存在 <pkg>.conf（未被重命名 .disabled）即启用该应用注入，不依赖段头 ON。
                   文件内若含 [pkg] OFF 段头会在后续 SECTION 记录处覆盖为 false */
                view_push(va, NSP_CFG_REC_APP_FILE, 0, uid, 0, app_conf_path, nullptr, pkg);
                FILE* afp = fopen(app_conf_path, "r");
                if (afp) {
                    char* line = nullptr;
                    size_t line_cap = 0;
                    int app_line_num = 0;
                    for (;;) {
                        int r =
                            nsp_getline_capped(afp, &line, &line_cap, NSP_CONFIG_LINE_MAX, NULL);
                        if (r == 0) break;
                        app_line_num++;
                        if (r == -2) {
                            LOG_WRN("规则文件 %s 第 %d 行超长（>%d 字节），整行跳过",
                                    app_conf_path, app_line_num, NSP_CONFIG_LINE_MAX);
                            continue;
                        }
                        if (r < 0) break;
                        char* p = clean_path_string(line);
                        if (!p || p[0] == '#' || p[0] == 0) continue;
                        char* sec = nullptr;
                        int sub_uid = uid; /* 分文件内段头默认归属该文件用户 */
                        bool enabled = true;
                        if (view_parse_section(p, &sec, &sub_uid, &enabled)) {
                            view_push(va, NSP_CFG_REC_SECTION, enabled ? 1 : 0, sub_uid,
                                      app_line_num, app_conf_path, nullptr, sec);
                            continue;
                        }
                        char type[64];
                        view_first_token(p, type, sizeof type);
                        view_push(va, NSP_CFG_REC_RULE, 0, uid, app_line_num, app_conf_path, type,
                                  p);
                    }
                    free(line);
                    fclose(afp);
                }
            } else if (ext && strcmp(ext, ".disabled") == 0) {
                /* 停用状态识别：<pkg>.conf.disabled = 该应用规则被停用
                   （rule_server INJECT_ENABLE OFF 重命名而来）。
                   仅当无对应 <pkg>.conf（未被启用）时才记停用——使 is_target_app
                   能识别停用状态并触发热卸载（此前 cfg 消失导致有通配符/全局注入时
                   停用应用仍被判为目标无法卸载） */
                size_t nlen = strlen(de->d_name);
                const char* suffix = ".conf.disabled";
                size_t slen = strlen(suffix);
                if (nlen > slen && strcmp(de->d_name + nlen - slen, suffix) == 0) {
                    char pkg[128];
                    size_t len = nlen - slen;
                    if (len >= sizeof(pkg)) len = sizeof(pkg) - 1;
                    strncpy(pkg, de->d_name, len);
                    pkg[len] = '\0';
                    char conf_path[PATH_MAX];
                    snprintf(conf_path, sizeof(conf_path), "%s/%s.conf", app_rules_dir, pkg);
                    if (access(conf_path, F_OK) != 0)
                        view_push(va, NSP_CFG_REC_APP_DISABLED, 0, uid, 0, nullptr, nullptr, pkg);
                }
            }
        }
        closedir(dir);
    }
}

/* ================= 模块配置文件（配置读取归属：框架读、模块不读） =================
 * 模块**不读文件、不跑 inotify**（见 nsp_module.h 的 NspFrameworkApi 注释与
 * docs/modules.md §6.1.1）：它自己的配置同样由框架读入后经扁平视图下发。
 * 约定位置与模块目录一致（目录名 = 模块名 = .so 名）：
 *     <modules_dir>/<模块名>/<模块名>.conf
 * 故框架无需任何模块专属知识——不存在硬编码的「哪个模块读哪个文件名」映射。
 *
 * 行文本只做「去 \r\n + 去首尾空白」下发，**不剥注释、不切键值**：注释边界与
 * 键值语法是模块的配置语法（如 FTP 模块配置的 `#` 只在行首/空白后起注释），框架
 * 越俎代庖会让模块语义随框架 lexer 漂移。 */

static char g_modules_dir[PATH_MAX] = MODULES_DIR;

/* 单轮扫描的模块配置上限（与 cfg_watch.c 的 CFG_WATCH_MAX 同量级）。
   超限只影响本轮下发并 loud 告警，不是静默丢弃。 */
#define CFG_MODULE_CONF_MAX 64

void config_set_modules_dir(const char* dir) {
    snprintf(g_modules_dir, sizeof g_modules_dir, "%s", (dir && dir[0]) ? dir : MODULES_DIR);
}

const char* config_modules_dir(void) {
    return g_modules_dir;
}

static int cmp_name_asc(const void* a, const void* b) {
    return strcmp(*(const char* const*)a, *(const char* const*)b);
}

/* 把视图截回 base 条（释放被撤记录各自 strdup 的字符串，不留泄漏）。 */
static void view_truncate(ViewAcc* va, int base) {
    for (int i = base; i < va->count; i++) {
        free((void*)va->recs[i].file);
        free((void*)va->recs[i].type);
        free((void*)va->recs[i].text);
    }
    if (va->count > base) va->count = base;
}

/* 追加某模块配置文件的全部行；无文件即无自有配置（多数模块不需要，非错误）。
   **标记无条件下发**（含期望路径）：文件缺失时模块也能从标记里拿到自己该有的
   路径，从而给出确切诊断，而不是猜一个路径或静默无后端。

   超长行（> NSP_CONFIG_LINE_MAX）= **该模块配置整份作废**：只保留标记、不下发
   任何 MODULE_LINE。模块直读文件时对同一行是整段作废（ftp_conf_parse_overlong
   → 段 bad），若这里只丢这一行，模块会拿其余行按默认 proto=ftp/21 注册——用户
   以为在连 SFTP，实际以明文 FTP 发送账号密码（docs/modules.md §7.1）。
   框架不实现模块的键值/段语义，故以「整份不可用」为两条路径的最小公共语义；
   模块侧 have=false 会清空后端表并 loud 报出确切路径。 */
static void view_scan_one_module_conf(ViewAcc* va, const char* mod_name) {
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/%s/%s.conf", g_modules_dir, mod_name, mod_name) >=
        (int)sizeof path)
        return;
    view_push(va, NSP_CFG_REC_MODULE_FILE, 0, -1, 0, path, nullptr, mod_name);
    int base = va->count; /* 标记之后的记录起点：超长时整段撤回到这里 */
    FILE* fp = fopen(path, "r");
    if (!fp) return;
    char* line = nullptr;
    size_t line_cap = 0;
    int line_num = 0;
    for (;;) {
        int r = nsp_getline_capped(fp, &line, &line_cap, NSP_CONFIG_LINE_MAX, NULL);
        if (r == 0) break;
        line_num++;
        if (r == -2) {
            LOG_WRN("模块配置 %s 第 %d 行超长（>%d 字节）：该模块配置整份作废",
                    path, line_num, NSP_CONFIG_LINE_MAX);
            view_truncate(va, base);
            break;
        }
        if (r < 0) break;
        char* p = clean_path_string(line);
        if (!p || !p[0]) continue;
        view_push(va, NSP_CFG_REC_MODULE_LINE, 0, -1, line_num, path, nullptr, p);
    }
    free(line);
    fclose(fp);
}

/* 扫描 <modules_dir>/<名>/<名>.conf。按目录名排序：readdir 顺序任意，而视图要
   参与 recs_identical 的逐字比对——顺序抖动会被判成「配置变了」，白推一轮。 */
static void view_scan_module_confs(ViewAcc* va) {
    DIR* d = opendir(g_modules_dir);
    if (!d) return;
    char* names[CFG_MODULE_CONF_MAX];
    int n = 0;
    struct dirent* de;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] == '.') continue;
        if (n >= CFG_MODULE_CONF_MAX) {
            LOG_WRN("模块目录 %s 子目录数超上限 %d，其余模块的配置本轮不下发",
                    g_modules_dir, CFG_MODULE_CONF_MAX);
            break;
        }
        char sub[PATH_MAX];
        if (snprintf(sub, sizeof sub, "%s/%s", g_modules_dir, de->d_name) >= (int)sizeof sub)
            continue;
        struct stat st;
        if (stat(sub, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        names[n] = strdup(de->d_name);
        if (names[n]) n++;
    }
    closedir(d);
    if (n > 1) qsort(names, (size_t)n, sizeof names[0], cmp_name_asc);
    for (int i = 0; i < n; i++) {
        view_scan_one_module_conf(va, names[i]);
        free(names[i]);
    }
}

int config_read_view(const char* main_path, NspCfgRec** out_recs, int* out_count) {
    if (out_recs) *out_recs = nullptr;
    if (out_count) *out_count = 0;
    if (!main_path) return -1;
    scan_active_users();
    /* App-rules 目录存在性检查：只读消费方（fuse_daemon/log_ctl）不创建目录，
       缺失目录由 injector 负责创建——仅记录反馈，不 mkdir */
    for (int i = 0; i < g_active_user_count; i++) {
        char app_rules_dir[PATH_MAX];
        nsp_app_rule_dir(CONFIG_DIR, g_active_users[i], app_rules_dir, sizeof(app_rules_dir));
        if (access(app_rules_dir, F_OK) != 0) {
            if (!g_allow_app_rules_mkdir) {
                LOG_DBG("只读模式跳过创建应用规则目录: %s（由 injector 创建）", app_rules_dir);
                continue;
            }
            mkdir(app_rules_dir, 0755);
            LOG("自动为多用户 %d 创建应用规则目录: %s", g_active_users[i], app_rules_dir);
        }
    }
    ViewAcc va = {.recs = nullptr, .count = 0, .cap = 0};
    view_scan_main_file(&va, main_path);
    view_scan_app_rules(&va);
    /* 模块自有配置最后追加：owner 标记随记录顺序生效（fw_config 按 owner 过滤） */
    view_scan_module_confs(&va);
    if (out_recs) *out_recs = va.recs;
    if (out_count) *out_count = va.count;
    return va.count;
}

void config_free_view(NspCfgRec* recs, int count) {
    if (!recs) return;
    for (int i = 0; i < count; i++) {
        free((void*)recs[i].file);
        free((void*)recs[i].type);
        free((void*)recs[i].text);
    }
    free(recs);
}

/* ================= 配置扁平视图：建索引阶段 ================= */

void config_build_from_view(const NspCfgRec* recs, int count) {
    /* S1 COW：构建进暂存区，末尾 config_publish 整体换入 live 并延迟释放旧配置 */
    memset(&g_global_cfg_stage, 0, sizeof(AppConfig));
    g_global_cfg_stage.trie_root = trie_create_node(NULL);
    g_global_cfg_stage.skip_system_apps = true; /* 默认跳过系统应用 */
    g_app_cfgs_stage = nullptr;
    g_app_cfg_count_stage = 0;
    g_app_cfg_capacity_stage = 0;

    AppConfig* cur = &g_global_cfg_stage;
    int current_user_id = -1;
    for (int i = 0; i < count; i++) {
        const NspCfgRec* r = &recs[i];
        switch (r->kind) {
        case NSP_CFG_REC_SECTION: {
            if (!r->text) break;
            char pkg[128];
            strncpy(pkg, r->text, sizeof(pkg) - 1);
            pkg[sizeof(pkg) - 1] = '\0';
            current_user_id = r->uid;
            if (strcmp(pkg, "GLOBAL") == 0) {
                cur = &g_global_cfg_stage;
            } else {
                /* 类别段经归一后与普通包同走 get_or_create（特殊 pkg 名天然去重）；
                   SYSTEM_APPS 带 :uid 在此归一为 -1 */
                classify_category_section(pkg, &current_user_id, r->file, r->line_no);
                cur = get_or_create_app_cfg(pkg, current_user_id);
                if (cur) cur->inject_enable = (r->enabled != 0);
            }
            break;
        }
        case NSP_CFG_REC_RULE: {
            if (!r->text) break;
            /* 复制后再解析：parse_config_line 及其下 parse_*_rule 会就地切分入参，
               视图须保持只读（模块可能持有框架下发的视图）。
               扫描侧已以 NSP_CONFIG_LINE_MAX 限长，此处仅防御性复核：
               超限（外来视图）即跳过，永不截断生效。 */
            if (strlen(r->text) >= (size_t)NSP_CONFIG_LINE_MAX) {
                LOG_WRN("规则文本超长（%s:%d），跳过", r->file ? r->file : "?", r->line_no);
                break;
            }
            char line[NSP_CONFIG_LINE_MAX];
            snprintf(line, sizeof(line), "%s", r->text);
            if (cur) parse_config_line(cur, line, current_user_id, r->line_no, r->file);
            break;
        }
        case NSP_CFG_REC_APP_FILE: {
            if (!r->text) break;
            AppConfig* file_cur = get_or_create_app_cfg(r->text, r->uid);
            if (!file_cur) break;
            file_cur->inject_enable = true;
            cur = file_cur;
            current_user_id = r->uid;
            break;
        }
        case NSP_CFG_REC_APP_DISABLED: {
            if (!r->text) break;
            AppConfig* file_cur = get_or_create_app_cfg(r->text, r->uid);
            if (file_cur) file_cur->inject_enable = false; /* 明确停用 */
            break;
        }
        default: break;
        }
    }
    /* qsort(NULL, 0, …) 是 UB：base 形参声明为 nonnull，规则为空时数组指针为
       NULL，UBSan（-fsanitize=undefined）会在每次空配置加载时报
       "null pointer passed as argument 1"。空表本就无需排序，按 uid_map.c
       同一写法加 count 守卫。 */
    if (g_global_cfg_stage.redir_count > 0)
        qsort(g_global_cfg_stage.redir_rules, g_global_cfg_stage.redir_count,
              sizeof(RedirectRule), cmp_redir);
    if (g_global_cfg_stage.hide_count > 0)
        qsort(g_global_cfg_stage.hide_rules, g_global_cfg_stage.hide_count, sizeof(char*), cmp_hide);
    if (g_global_cfg_stage.ro_count > 0)
        qsort(g_global_cfg_stage.ro_rules, g_global_cfg_stage.ro_count, sizeof(char*), cmp_hide);
    for (int i = 0; i < g_app_cfg_count_stage; i++) {
        if (g_app_cfgs_stage[i]->redir_count > 0)
            qsort(g_app_cfgs_stage[i]->redir_rules, g_app_cfgs_stage[i]->redir_count,
                  sizeof(RedirectRule), cmp_redir);
        if (g_app_cfgs_stage[i]->hide_count > 0)
            qsort(g_app_cfgs_stage[i]->hide_rules, g_app_cfgs_stage[i]->hide_count, sizeof(char*),
                  cmp_hide);
        if (g_app_cfgs_stage[i]->ro_count > 0)
            qsort(g_app_cfgs_stage[i]->ro_rules, g_app_cfgs_stage[i]->ro_count, sizeof(char*),
                  cmp_hide);
    }
    analyze_var_staticness(&g_global_cfg_stage, NULL);
    for (int i = 0; i < g_app_cfg_count_stage; i++) {
        analyze_var_staticness(g_app_cfgs_stage[i], &g_global_cfg_stage);
    }
    /* S1 COW 发布：暂存区 → live，旧配置延迟释放 */
    config_publish();
}

void load_config_rules(const char* path) {
    NspCfgRec* recs = nullptr;
    int count = 0;
    config_read_view(path, &recs, &count);
    config_build_from_view(recs, count);
    config_free_view(recs, count);
}
int reload_config_rules_diff(const char* path, ChangedPkg* out_changed, int max_changed) {
    /* S1：load_config_rules 内部完成 COW 发布（旧配置在发布后即被释放），
       diff 所需旧字段须在加载前快照（旧 AppConfig 指针发布后悬垂） */
    bool old_global_inject = g_global_cfg.global_inject;
    typedef struct {
        char pkg[128];
        int user_id;
        bool inject_enable;
    } OldAppSnap;
    int old_count = g_app_cfg_count;
    OldAppSnap* old_snap = old_count > 0 ? calloc((size_t)old_count, sizeof(OldAppSnap)) : NULL;
    if (old_snap) {
        for (int i = 0; i < old_count; i++) {
            if (!g_app_cfgs[i]) continue;
            strncpy(old_snap[i].pkg, g_app_cfgs[i]->pkg_name, 127);
            old_snap[i].pkg[127] = '\0';
            old_snap[i].user_id = g_app_cfgs[i]->user_id;
            old_snap[i].inject_enable = g_app_cfgs[i]->inject_enable;
        }
    }
    /* COW 发布：换入新配置并释放旧配置（含旧 g_app_cfgs 数组） */
    load_config_rules(path);
    // 遵循设计：injector不处理单个挂载树内的文件规则变化，仅处理全局挂载ON/OFF与应用开关
    bool global_changed = (old_global_inject != g_global_cfg.global_inject);
    int changed_count = 0;
    if (global_changed) {
        changed_count = -1;
    } else {
        for (int i = 0; i < g_app_cfg_count; i++) {
            AppConfig* new_cfg = g_app_cfgs[i];
            bool found = false;
            bool old_inject = false;
            for (int j = 0; j < old_count; j++) {
                if (old_snap && old_snap[j].user_id == new_cfg->user_id &&
                    strcmp(old_snap[j].pkg, new_cfg->pkg_name) == 0) {
                    found = true;
                    old_inject = old_snap[j].inject_enable;
                    break;
                }
            }
            if (!found || old_inject != new_cfg->inject_enable) {
                if (changed_count < max_changed) {
                    strncpy(out_changed[changed_count].pkg_name, new_cfg->pkg_name, 127);
                    out_changed[changed_count].pkg_name[127] = '\0';
                    out_changed[changed_count].user_id = new_cfg->user_id;
                    changed_count++;
                }
            }
        }
        for (int j = 0; j < old_count; j++) {
            if (!old_snap) continue;
            bool found = false;
            for (int i = 0; i < g_app_cfg_count; i++) {
                if (g_app_cfgs[i]->user_id == old_snap[j].user_id &&
                    strcmp(g_app_cfgs[i]->pkg_name, old_snap[j].pkg) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (changed_count < max_changed) {
                    strncpy(out_changed[changed_count].pkg_name, old_snap[j].pkg, 127);
                    out_changed[changed_count].pkg_name[127] = '\0';
                    out_changed[changed_count].user_id = old_snap[j].user_id;
                    changed_count++;
                }
            }
        }
    }
    free(old_snap);
    return changed_count;
}
AppConfig* find_app_cfg_locked(const char* pkg, int user_id) {
    char base_pkg[256];
    strncpy(base_pkg, pkg, sizeof(base_pkg) - 1);
    base_pkg[sizeof(base_pkg) - 1] = '\0';
    char* colon = strchr(base_pkg, ':');
    if (colon) *colon = '\0';
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == user_id &&
            (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 ||
             fnmatch(g_app_cfgs[i]->pkg_name, pkg, 0) == 0))
            return g_app_cfgs[i];
    }
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == -1 &&
            (fnmatch(g_app_cfgs[i]->pkg_name, base_pkg, 0) == 0 ||
             fnmatch(g_app_cfgs[i]->pkg_name, pkg, 0) == 0))
            return g_app_cfgs[i];
    }
    return NULL;
}
/* 类别段查找（供 br_resolve/is_target_app 三层合并）：
 * - 系统应用 → SYSTEM_APPS（user_id 恒 -1，忽略传入 user_id）；
 * - 用户应用 → USER_APPS[user_id] 精确，无则 USER_APPS[-1] 跨用户 fallback。
 * 精确 strcmp（不用 fnmatch）：通配段 [*] 只作用于应用层，不混入类别层。 */
AppConfig* find_category_cfg_locked(bool is_system_app, int user_id) {
    if (is_system_app) {
        for (int i = 0; i < g_app_cfg_count; i++) {
            if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == -1 &&
                strcmp(g_app_cfgs[i]->pkg_name, "SYSTEM_APPS") == 0)
                return g_app_cfgs[i];
        }
        return NULL;
    }
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == user_id &&
            strcmp(g_app_cfgs[i]->pkg_name, "USER_APPS") == 0)
            return g_app_cfgs[i];
    }
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == -1 &&
            strcmp(g_app_cfgs[i]->pkg_name, "USER_APPS") == 0)
            return g_app_cfgs[i];
    }
    return NULL;
}

/* 是否存在类别段：IO 热路径据此决定是否走系统/用户分类（含 sys_pkg
 * 查表），无类别段时零额外开销、行为与旧版一致 */
bool config_has_category_rules(void) {
    return g_has_category_rules;
}

/* 类别段是否有实质规则（注入判定用）：与 app_has_active_rules 口径一致
 *（redir/hide/ro/sandbox；MONITOR-only 不触发注入）。调用方须持读锁 */
bool category_has_rules_locked(bool is_system_app, int user_id) {
    AppConfig* cat = find_category_cfg_locked(is_system_app, user_id);
    if (!cat) return false;
    return cat->redir_count > 0 || cat->hide_count > 0 || cat->ro_count > 0 || cat->sandbox;
}

bool has_wildcard_enabled_locked(int user_id) {
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == user_id &&
            strcmp(g_app_cfgs[i]->pkg_name, "*") == 0 && g_app_cfgs[i]->inject_enable)
            return true;
    }
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == -1 &&
            strcmp(g_app_cfgs[i]->pkg_name, "*") == 0 && g_app_cfgs[i]->inject_enable)
            return true;
    }
    return false;
}
void print_active_rules(const char* pkg, int pid, uid_t linux_uid, const char* trigger_source) {
    config_lock_read();
    int user_id = linux_uid / NSP_PER_USER_UID_STRIDE;
    AppConfig* cfg = find_app_cfg_locked(pkg, user_id);
    /* 类别层归属（与 br_pick_category 同口径，sys_pkg 在各进程均可用） */
    bool is_sys = (linux_uid < NSP_SYSTEM_APP_UID_MIN) || (pkg && sys_pkg_is_system(pkg));
    AppConfig* cat = find_category_cfg_locked(is_sys, user_id);
    bool is_wildcard = (cfg == NULL) && has_wildcard_enabled_locked(user_id);
    int final_redir_count =
        (cfg ? cfg->redir_count : 0) + (cat ? cat->redir_count : 0) + g_global_cfg.redir_count;
    int final_hide_count =
        (cfg ? cfg->hide_count : 0) + (cat ? cat->hide_count : 0) + g_global_cfg.hide_count;
    int final_ro_count =
        (cfg ? cfg->ro_count : 0) + (cat ? cat->ro_count : 0) + g_global_cfg.ro_count;
    bool final_sandbox;
    if (cfg && cfg->sandbox_explicit) {
        final_sandbox = cfg->sandbox;
    } else if (cat && cat->sandbox_explicit) {
        final_sandbox = cat->sandbox;
    } else {
        final_sandbox = g_global_cfg.sandbox && !is_media_provider(pkg);
    }
    bool final_monitor;
    if (cfg && cfg->monitor_explicit) {
        final_monitor = cfg->monitor;
    } else if (cat && cat->monitor_explicit) {
        final_monitor = cat->monitor;
    } else {
        final_monitor = g_global_cfg.monitor;
    }
    if (cfg) {
        LOG("应用 %s (PID: %d, 用户: %d) 注入完毕 [%s] | 规则细节 -> MONITOR:%s SANDBOX:%s 重定向(通配):%d条 隐藏(通配):%d条 只读(通配):%d条",
            pkg, pid, user_id, trigger_source, final_monitor ? "ON" : "OFF",
            final_sandbox ? "ON" : "OFF", final_redir_count, final_hide_count, final_ro_count);
        for (int i = 0; i < cfg->redir_count; i++) {
        }
        for (int i = 0; i < cfg->hide_count; i++) {
        }
        for (int i = 0; i < cfg->ro_count; i++) {
        }
    } else {
        const char* match_desc =
            is_wildcard ? "命中通配符 [*]"
                        : (g_global_cfg.global_inject ? "命中 GLOBAL_INJECT" : "无匹配规则");
        LOG("应用 %s (PID: %d, 用户: %d) 注入完毕 [%s] | %s (全局 MONITOR:%s SANDBOX:%s)", pkg, pid,
            user_id, trigger_source, match_desc, final_monitor ? "ON" : "OFF",
            final_sandbox ? "ON" : "OFF");
    }
    if (g_global_cfg.redir_count > 0 || g_global_cfg.hide_count > 0 || g_global_cfg.ro_count > 0) {
        LOG_DBG("  [全局规则通配] MONITOR:%s SANDBOX:%s 重定向:%d条 隐藏:%d条 只读:%d条",
                g_global_cfg.monitor ? "ON" : "OFF", g_global_cfg.sandbox ? "ON" : "OFF",
                g_global_cfg.redir_count, g_global_cfg.hide_count, g_global_cfg.ro_count);
    }
    config_unlock_read();
}