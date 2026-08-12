#define _GNU_SOURCE
#include "config_parser.h"
#include "common.h"
#include "path_vars.h"
#include "inject_target.h"
#include <sys/stat.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <ctype.h>
#include <fnmatch.h>
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
int g_active_users[MAX_USERS];
int g_active_user_count = 0;
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
    _Atomic int cnt[2];      /* 按代际奇偶分槽 */
    char _pad[56];           /* 补齐到 64B，每行独占缓存行（免假共享） */
} CfgReaderCell;
static _Alignas(64) CfgReaderCell g_cfg_readers[CFG_READER_MAX];
static _Atomic(int) g_cfg_reader_next = 0;   /* 下一个可分配读者槽位 */
static _Thread_local int g_cfg_reader_slot = -1;  /* 本线程读者槽（首次调用分配） */
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
        if (g1 & 1) { sched_yield(); continue; }   /* 写者进行中 */
        int slot = (int)((g1 >> 1) & 1);
        atomic_fetch_add_explicit(&g_cfg_readers[s].cnt[slot], 1, memory_order_acq_rel);
        if (atomic_load_explicit(&g_cfg_gen, memory_order_acquire) == g1)
            return g1;                             /* 稳定快照，持槽 */
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
static bool is_wildcard_string(const char *str) {
    /* `?` 作为首字符是项目自定义的"相对当前 user 存储"前缀，非 fnmatch 通配；
       仅从第二字符起检测真正的通配符 * ? [ ]，避免 ALLOW/REDIRECT 的 ? 前缀路径被误判跳过 trie */
    if (!str || !str[0]) return false;
    const char *p = (str[0] == '?') ? str + 1 : str;
    return strpbrk(p, "*?[]") != NULL;
}
void config_init_lock() { pthread_rwlock_init(&g_rules_lock, nullptr); }
void config_destroy_lock() { pthread_rwlock_destroy(&g_rules_lock); }
void config_lock_read() { pthread_rwlock_rdlock(&g_rules_lock); }
void config_unlock_read() { pthread_rwlock_unlock(&g_rules_lock); }
void config_lock_write() { pthread_rwlock_wrlock(&g_rules_lock); }
void config_unlock_write() { pthread_rwlock_unlock(&g_rules_lock); }
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
/* COW 发布：把暂存区构建的新配置整体换入 live（g_global_cfg/g_app_cfgs），
   旧配置在旧代际读者归零后延迟释放。调用方须持 config_lock_write。 */
static void config_publish(void) {
    uint64_t old_gen = config_publish_begin();
    /* P1 修复：封锁新读者后先排空旧代际读者，再做非原子交换——
       否则读者可能观察到半换入的指针/count 配对（新数组+旧 count 越界读，
       或新 trie+旧规则的错误决策窗口）。config_publish_end 的排空仅用于
       延迟释放判定，无法撤销已发生的撕裂读 */
    config_drain_readers(old_gen);
    /* 快照旧 live（浅拷贝结构体，指针指向待释放内存） */
    AppConfig old_global = g_global_cfg;
    AppConfig** old_apps = g_app_cfgs;
    int old_count = g_app_cfg_count;
    /* 换入新配置 */
    g_global_cfg = g_global_cfg_stage;
    g_app_cfgs = g_app_cfgs_stage;
    g_app_cfg_count = g_app_cfg_count_stage;
    g_app_cfg_capacity = g_app_cfg_capacity_stage;
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
    if (!str) return nullptr;
    while(isspace((unsigned char)*str)) str++; if(*str == 0) return str;
    char* end = str + strlen(str) - 1; while(end > str && isspace((unsigned char)*end)) end--;
    *(end+1) = 0;
    for (int i = 0; str[i]; i++) { if (str[i] == '\r' || str[i] == '\n') { str[i] = '\0'; break; } }
    return str;
}
void strip_trailing_slash(char* path) {
    /* 剥尾随 '/'，但保留 "?/"——'?' 后必跟 '/' 是内部前缀语义（见 docs/path-variables.md），
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
    if (*p == '\0') { *ptr = nullptr; return nullptr; }
    char* start;
    if (*p == '"') {
        start = ++p;
        while (*p && *p != '"') p++;
        if (*p == '"') { *p = '\0'; *ptr = p + 1; } 
        else *ptr = p;
    } else {
        start = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        if (*p != '\0') { *p = '\0'; *ptr = p + 1; } 
        else *ptr = p;
    }
    return start;
}
static char* strip_storage_prefix(char* path) {
    if (strncmp(path, "/storage/emulated/", 18) == 0) {
        char* p = path + 18;
        while (*p && isdigit((unsigned char)*p)) p++;
        if (*p == '/') return p;       /* /storage/emulated/0/Download -> /Download */
        if (*p == '\0') return "/";    /* /storage/emulated/0 -> / */
        /* 异常形态:缺数字 user_id 或后跟非数字(如 /storage/emulated/Download)。
           把 p 退回非数字起始位置,前面补 '/',让残留当子路径(与正常 emulated 剥离一致)。 */
        return p - 1;
    }
    return path;
}
static int cmp_redir(const void* a, const void* b) {
    return (int)strlen(((const RedirectRule*)b)->virtual_prefix) - (int)strlen(((const RedirectRule*)a)->virtual_prefix);
}
static int cmp_hide(const void* a, const void* b) {
    const char* str_a = *(const char**)a;
    const char* str_b = *(const char**)b;
    return (int)strlen(str_b) - (int)strlen(str_a);
}
static void parse_config_line(AppConfig* cur, char* line, int user_id, int line_num, const char* file_path) {
    (void)user_id;
    char* p_ptr = line;
    /* 先尝试 NAME=VALUE 赋值（紧凑形式，无空格围绕 =） */
    {
        char vname[128], vvalue[MAX_PATH_LEN];
        if (parse_var_assignment(line, vname, sizeof vname, vvalue, sizeof vvalue)) {
            if (strcmp(vname, "package") == 0) {
                LOG_WRN("不允许覆盖系统保留变量 package (行 %d, 文件 %s)", line_num, file_path);
            } else {
                if (cur->var_count >= cur->var_capacity) {
                    int newcap = cur->var_capacity == 0 ? 8 : cur->var_capacity * 2;
                    char **new_names = realloc(cur->var_names, newcap * sizeof(char*));
                    char **new_values = realloc(cur->var_values, newcap * sizeof(char*));
                    char **new_resolved = realloc(cur->var_resolved, newcap * sizeof(char*));
                    bool *new_is_static = realloc(cur->var_is_static, newcap * sizeof(bool));
                    if (!new_names || !new_values || !new_resolved || !new_is_static) {
                        LOG_ERR("realloc 变量数组失败 (行 %d)", line_num);
                        free(new_names); free(new_values);
                        free(new_resolved); free(new_is_static);
                        return;
                    }
                    cur->var_names   = new_names;
                    cur->var_values  = new_values;
                    cur->var_resolved= new_resolved;
                    cur->var_is_static = new_is_static;
                    cur->var_capacity = newcap;
                }
                cur->var_names[cur->var_count] = strdup(vname);
                cur->var_values[cur->var_count] = strdup(vvalue);
                cur->var_resolved[cur->var_count] = NULL;
                cur->var_is_static[cur->var_count] = false;
                cur->var_count++;
            }
            return;
        }
    }
    char* tok = get_next_token(&p_ptr);
    if (!tok) return;
    if (strcmp(tok, "MONITOR") == 0) {
        char* val = get_next_token(&p_ptr);
        cur->monitor = (val && (strcmp(val, "ON") == 0 || strcmp(val, "1") == 0));
        cur->monitor_explicit = true;
    } else if (strcmp(tok, "SANDBOX") == 0) {
        char* val = get_next_token(&p_ptr);
        cur->sandbox = (val && (strcmp(val, "ON") == 0 || strcmp(val, "1") == 0));
        cur->sandbox_explicit = true;
    } else if (strcmp(tok, "GLOBAL_INJECT") == 0) {
        char* val = get_next_token(&p_ptr);
        cur->global_inject = (val && (strcmp(val, "ON") == 0 || strcmp(val, "1") == 0));
    } else if (strcmp(tok, "FUSE_DIRECT") == 0) {
        char* val = get_next_token(&p_ptr);
        cur->fuse_direct = (val && (strcmp(val, "ON") == 0 || strcmp(val, "1") == 0));
    } else if (strcmp(tok, "SKIP_SYSTEM_APPS") == 0) {
        char* val = get_next_token(&p_ptr);
        cur->skip_system_apps = (val && (strcmp(val, "ON") == 0 || strcmp(val, "1") == 0));
    } else if (strcmp(tok, "FUSE_EXTRA_ARGS") == 0) {
        /* 读取行尾剩余全部内容，不做分词（原样透传给 fuse_daemon） */
        char* p = p_ptr;
        while (p && isspace((unsigned char)*p)) p++;
        if (p && *p) {
            size_t len = strlen(p);
            while (len > 0 && isspace((unsigned char)p[len - 1])) len--;
            if (len > 0) {
                size_t copy_len = len < sizeof(cur->fuse_extra_args) - 1 ? len : sizeof(cur->fuse_extra_args) - 1;
                memcpy(cur->fuse_extra_args, p, copy_len);
                cur->fuse_extra_args[copy_len] = '\0';
            }
        }
    } else if (strcmp(tok, "HIDE") == 0) {
        char* val = get_next_token(&p_ptr);
        if (val) {
            char *v_ptr = strip_storage_prefix(val);
            char clean_rule[MAX_PATH_LEN];
            if (v_ptr[0] != '/' && v_ptr[0] != '*') snprintf(clean_rule, MAX_PATH_LEN, "/%s", v_ptr);
            else {
                strncpy(clean_rule, v_ptr, MAX_PATH_LEN - 1);
                clean_rule[MAX_PATH_LEN - 1] = '\0';
            }
            if (strpbrk(clean_rule, "*?[]") == nullptr) strip_trailing_slash(clean_rule);
            if (cur->hide_count >= cur->hide_capacity) {
                int new_cap = cur->hide_capacity == 0 ? 8 : cur->hide_capacity * 2;
                char **new_hide = realloc(cur->hide_rules, new_cap * sizeof(char*));
                if (!new_hide) {
                    LOG_ERR("realloc hide_rules 失败");
                    return;
                }
                cur->hide_rules = new_hide;
                cur->hide_capacity = new_cap;
            }
            cur->hide_rules[cur->hide_count] = strdup(clean_rule);
            cur->hide_count++;
            if (!is_wildcard_string(clean_rule) && !has_path_var(clean_rule)) {
                trie_insert(cur->trie_root, clean_rule, NULL, true, false);
            } else {
                cur->dyn_hide = true;   /* 通配/变量规则未入 trie，须线性兜底 */
            }
        }
    } else if (strcmp(tok, "RO") == 0) {
        char* val = get_next_token(&p_ptr);
        if (val) {
            char *v_ptr = strip_storage_prefix(val);
            char clean_rule[MAX_PATH_LEN];
            if (v_ptr[0] != '/' && v_ptr[0] != '*') snprintf(clean_rule, MAX_PATH_LEN, "/%s", v_ptr);
            else {
                strncpy(clean_rule, v_ptr, MAX_PATH_LEN - 1);
                clean_rule[MAX_PATH_LEN - 1] = '\0';
            }
            if (strpbrk(clean_rule, "*?[]") == nullptr) strip_trailing_slash(clean_rule);
            if (cur->ro_count >= cur->ro_capacity) {
                int new_cap = cur->ro_capacity == 0 ? 8 : cur->ro_capacity * 2;
                char **new_ro = realloc(cur->ro_rules, new_cap * sizeof(char*));
                if (!new_ro) {
                    LOG_ERR("realloc ro_rules 失败");
                    return;
                }
                cur->ro_rules = new_ro;
                cur->ro_capacity = new_cap;
            }
            cur->ro_rules[cur->ro_count] = strdup(clean_rule);
            cur->ro_count++;
            if (!is_wildcard_string(clean_rule) && !has_path_var(clean_rule)) {
                trie_insert(cur->trie_root, clean_rule, NULL, false, true);
            } else {
                cur->dyn_ro = true;     /* 通配/变量规则未入 trie，须线性兜底 */
            }
        }
    } else if (strcmp(tok, "ALLOW") == 0) {
        char* val = get_next_token(&p_ptr);
        if (val) {
            char *v_ptr = strip_storage_prefix(val);
            char virtual_prefix[MAX_PATH_LEN];
            if (v_ptr[0] == '\0') strcpy(virtual_prefix, "/"); 
            else {
                if (v_ptr[0] != '/') snprintf(virtual_prefix, MAX_PATH_LEN, "/%s", v_ptr);
                else {
                    strncpy(virtual_prefix, v_ptr, MAX_PATH_LEN - 1);
                    virtual_prefix[MAX_PATH_LEN - 1] = '\0';
                }
            }
            /* 通配规则（含 * ? [ ]）不 strip 尾斜杠：尾斜杠是通配模式的组成部分
               （如 /Download/*.mp3/ 与 /Download/*.mp3 语义不同），与 HIDE/RO 一致 */
            if (strpbrk(virtual_prefix, "*?[]") == nullptr) strip_trailing_slash(virtual_prefix);
            char real_target[MAX_PATH_LEN];
            snprintf(real_target, MAX_PATH_LEN - 1, "?%s", virtual_prefix);
            if (strpbrk(real_target, "*?[]") == nullptr) strip_trailing_slash(real_target);
            if (cur->redir_count >= cur->redir_capacity) {
                int new_cap = cur->redir_capacity == 0 ? 8 : cur->redir_capacity * 2;
                RedirectRule *new_redir = realloc(cur->redir_rules, new_cap * sizeof(RedirectRule));
                if (!new_redir) {
                    LOG_ERR("realloc redir_rules 失败 (ALLOW)");
                    return;
                }
                cur->redir_rules = new_redir;
                cur->redir_capacity = new_cap;
            }
            RedirectRule* r = &cur->redir_rules[cur->redir_count++];
            strncpy(r->virtual_prefix, virtual_prefix, sizeof(r->virtual_prefix) - 1);
            r->virtual_prefix[sizeof(r->virtual_prefix) - 1] = '\0';
            strncpy(r->real_target, real_target, sizeof(r->real_target) - 1);
            r->real_target[sizeof(r->real_target) - 1] = '\0';
            r->is_allow = true;
            if (!is_wildcard_string(virtual_prefix) && !has_path_var(virtual_prefix)) {
                trie_insert(cur->trie_root, virtual_prefix, real_target, false, false);
            } else {
                cur->dyn_redir = true;  /* 通配/变量 redir 未入 trie，须线性兜底 */
            }
        }
    } else if (strcmp(tok, "REDIRECT") == 0) {
        char* v1 = get_next_token(&p_ptr);
        char* v2 = get_next_token(&p_ptr);
        if (v1 && v2) {
            char *v_ptr = strip_storage_prefix(v1);
            char virtual_prefix[MAX_PATH_LEN];
            if (v_ptr[0] == '\0') strcpy(virtual_prefix, "/"); 
            else {
                if (v_ptr[0] != '/') snprintf(virtual_prefix, MAX_PATH_LEN, "/%s", v_ptr);
                else {
                    strncpy(virtual_prefix, v_ptr, MAX_PATH_LEN - 1);
                    virtual_prefix[MAX_PATH_LEN - 1] = '\0';
                }
            }
            /* 通配规则（含 * ? [ ]）不 strip 尾斜杠（尾斜杠是模式组成部分） */
            if (strpbrk(virtual_prefix, "*?[]") == nullptr) strip_trailing_slash(virtual_prefix);
            char real_target[MAX_PATH_LEN];
            if (has_path_var(v2)) {
                /* 含变量：原样存入，路径分类延迟到运行时 build_real_base_from_target */
                strncpy(real_target, v2, MAX_PATH_LEN - 1);
                real_target[MAX_PATH_LEN - 1] = '\0';
            }
            else if (strncmp(v2, "/storage/emulated/", 18) == 0) {
                char* p = v2 + 18;
                while (*p && isdigit((unsigned char)*p)) p++;
                if (*p == '/') p++;
                snprintf(real_target, MAX_PATH_LEN - 1, "?/%s", p);
            }
            else if (is_system_abs_path(v2)) {
                strncpy(real_target, v2, MAX_PATH_LEN - 1);
                real_target[MAX_PATH_LEN - 1] = '\0';
            }
            else {
                snprintf(real_target, MAX_PATH_LEN - 1, "?/%s", v2[0] == '/' ? v2 + 1 : v2);
            }
            if (strpbrk(real_target, "*?[]") == nullptr) strip_trailing_slash(real_target);
            if (cur->redir_count >= cur->redir_capacity) {
                int new_cap = cur->redir_capacity == 0 ? 8 : cur->redir_capacity * 2;
                RedirectRule *new_redir = realloc(cur->redir_rules, new_cap * sizeof(RedirectRule));
                if (!new_redir) {
                    LOG_ERR("realloc redir_rules 失败 (ALLOW)");
                    return;
                }
                cur->redir_rules = new_redir;
                cur->redir_capacity = new_cap;
            }
            RedirectRule* r = &cur->redir_rules[cur->redir_count++];
            strncpy(r->virtual_prefix, virtual_prefix, sizeof(r->virtual_prefix) - 1);
            r->virtual_prefix[sizeof(r->virtual_prefix) - 1] = '\0';
            strncpy(r->real_target, real_target, sizeof(r->real_target) - 1);
            r->real_target[sizeof(r->real_target) - 1] = '\0';
            r->is_allow = false;
            if (!is_wildcard_string(virtual_prefix) && !is_wildcard_string(real_target) && !has_path_var(virtual_prefix) && !has_path_var(real_target)) {
                trie_insert(cur->trie_root, virtual_prefix, real_target, false, false);
            } else {
                cur->dyn_redir = true;  /* 通配/变量 redir 未入 trie，须线性兜底 */
            }
        }
    } else if (strcmp(tok, "FTP") == 0) {
        /* FTP <虚拟前缀> <段名>：虚拟前缀命中时由 FTP 后端（段名）提供。
           规则所在段决定作用域：GLOBAL=全局，应用段=仅该应用 */
        char* v1 = get_next_token(&p_ptr);
        char* v2 = get_next_token(&p_ptr);
        if (!v1 || !v2) {
            LOG_WRN("FTP 规则缺少参数 (行 %d, 文件 %s)", line_num, file_path);
            return;
        }
        char virtual_prefix[MAX_PATH_LEN];
        if (v1[0] != '/') snprintf(virtual_prefix, MAX_PATH_LEN, "/%s", v1);
        else { strncpy(virtual_prefix, v1, MAX_PATH_LEN - 1); virtual_prefix[MAX_PATH_LEN - 1] = '\0'; }
        strip_trailing_slash(virtual_prefix);
        if (virtual_prefix[0] == '\0') strcpy(virtual_prefix, "/");
        if (cur->ftp_count >= cur->ftp_capacity) {
            int newcap = cur->ftp_capacity == 0 ? 8 : cur->ftp_capacity * 2;
            FtpRule* new_rules = realloc(cur->ftp_rules, newcap * sizeof(FtpRule));
            if (!new_rules) { LOG_ERR("realloc ftp_rules 失败 (行 %d)", line_num); return; }
            cur->ftp_rules = new_rules;
            cur->ftp_capacity = newcap;
        }
        FtpRule* fr = &cur->ftp_rules[cur->ftp_count++];
        memset(fr, 0, sizeof *fr);
        strncpy(fr->virtual_prefix, virtual_prefix, sizeof fr->virtual_prefix - 1);
        fr->virtual_prefix[sizeof fr->virtual_prefix - 1] = '\0';
        strncpy(fr->backend_name, v2, sizeof fr->backend_name - 1);
        fr->backend_name[sizeof fr->backend_name - 1] = '\0';
        /* 同时入 trie：resolve 热路径经 trie 下降一次取得 FTP 命中
           （替代 config_ftp_match 每请求 O(N) 线性扫描）；
           FTP 前缀为静态字面段（无通配/变量），与线性匹配语义一致 */
        if (cur->trie_root)
            trie_insert_ftp(cur->trie_root, virtual_prefix, v2);
    } else {
        LOG_WRN("不支持的规则 \"%s\" (行 %d, 文件 %s)", tok, line_num, file_path);
    }
}

/* FTP 规则最长前缀优先匹配：sub_path 命中 FTP 规则时输出后端段名 */
bool config_ftp_match(const AppConfig* cfg, const char* sub_path, char* backend_out, size_t sz) {
    if (!cfg || !sub_path || cfg->ftp_count <= 0) return false;
    FtpRule* best = NULL;
    size_t best_len = 0;
    for (int i = 0; i < cfg->ftp_count; i++) {
        const char* p = cfg->ftp_rules[i].virtual_prefix;
        size_t plen = strlen(p);
        if (plen > best_len && strncmp(p, sub_path, plen) == 0 &&
            (sub_path[plen] == '\0' || sub_path[plen] == '/')) {
            best = &cfg->ftp_rules[i];
            best_len = plen;
        }
    }
    if (best && backend_out && sz) {
        strncpy(backend_out, best->backend_name, sz - 1);
        backend_out[sz - 1] = '\0';
    }
    return best != NULL;
}
static AppConfig* get_or_create_app_cfg(const char* pkg, int user_id) {
    /* S1：构建进暂存区（live 由 config_publish 一次性换入） */
    if (strcmp(pkg, "GLOBAL") == 0) return &g_global_cfg_stage;
    for (int i = 0; i < g_app_cfg_count_stage; i++) {
        if (g_app_cfgs_stage[i]->user_id == user_id && strcmp(g_app_cfgs_stage[i]->pkg_name, pkg) == 0) 
            return g_app_cfgs_stage[i];
    }
    if (g_app_cfg_count_stage >= g_app_cfg_capacity_stage) {
        int new_cap = g_app_cfg_capacity_stage == 0 ? 8 : g_app_cfg_capacity_stage * 2;
        AppConfig **new_cfgs = realloc(g_app_cfgs_stage, new_cap * sizeof(AppConfig*));
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
void scan_active_users() {
    g_active_user_count = 0;

    // 优先通过 pm list users 获取真实用户列表
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

    // pm 失败时回退到 /data/media/ 扫描
    if (g_active_user_count == 0) {
        DIR* dir = opendir("/data/media");
        if (dir) {
            struct dirent* de;
            while ((de = readdir(dir)) != nullptr) {
                if (de->d_type == DT_DIR || de->d_type == DT_LNK) {
                    bool is_num = true;
                    for (int i = 0; de->d_name[i]; i++) {
                        if (!isdigit(de->d_name[i])) { is_num = false; break; }
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

    // 确保至少有 user 0
    if (g_active_user_count == 0) {
        g_active_users[0] = 0;
        g_active_user_count = 1;
    }

    LOG_DBG("scan_active_users: 发现 %d 个活跃用户", g_active_user_count);
    for (int i = 0; i < g_active_user_count; i++)
        LOG_DBG("  活跃用户[%d]: uid=%d", i, g_active_users[i]);
}
void load_config_rules(const char* path) {
    /* S1 COW：构建进暂存区，末尾 config_publish 整体换入 live 并延迟释放旧配置 */
    memset(&g_global_cfg_stage, 0, sizeof(AppConfig)); 
    g_global_cfg_stage.trie_root = trie_create_node(NULL);
    g_global_cfg_stage.skip_system_apps = true; /* 默认跳过系统应用 */
    g_app_cfgs_stage = nullptr;
    g_app_cfg_count_stage = 0;
    g_app_cfg_capacity_stage = 0;
    scan_active_users();
    for (int i = 0; i < g_active_user_count; i++) {
        int uid = g_active_users[i];
        char app_rules_dir[PATH_MAX];
        if (uid == 0) snprintf(app_rules_dir, sizeof(app_rules_dir), "%s/App-rules", CONFIG_DIR);
        else snprintf(app_rules_dir, sizeof(app_rules_dir), "%s/App-rules-%d", CONFIG_DIR, uid);
        if (access(app_rules_dir, F_OK) != 0) {
            mkdir(app_rules_dir, 0755);
            LOG("自动为多用户 %d 创建应用规则目录: %s", uid, app_rules_dir);
        }
    }
    FILE* fp = fopen(path, "r");
    if (fp) {
        AppConfig* cur = &g_global_cfg_stage; char line[2048];
        int current_user_id = -1;
        int line_num = 0;
        while (fgets(line, sizeof(line), fp)) {
            line_num++;
            char* p = clean_path_string(line); if (!p || p[0] == '#' || p[0] == 0) continue;
            if (p[0] == '[') {
                char* end = strchr(p, ']');
                if (end) {
                    *end = '\0';
                    char* sec = p + 1;
                    char* after = end + 1;
                    bool enabled = true;
                    while (isspace(*after)) after++;
                    if (strncmp(after, "OFF", 3) == 0) enabled = false;
                    else if (strncmp(after, "ON", 2) == 0) enabled = true;
                    char pkg[128];
                    current_user_id = -1; 
                    char* colon = strchr(sec, ':');
                    if (colon) {
                        *colon = '\0';
                        current_user_id = atoi(colon + 1);
                    }
                    strncpy(pkg, sec, sizeof(pkg)-1);
                    if (strcmp(pkg, "GLOBAL") == 0) {
                        cur = &g_global_cfg_stage;
                    } else {
                        cur = get_or_create_app_cfg(pkg, current_user_id);
                        if (cur) cur->inject_enable = enabled;
                    }
                }
                continue;
            }
            if (cur) parse_config_line(cur, p, current_user_id, line_num, path);
        }
        fclose(fp);
    } else {
        LOG_ERR("无法打开主规则文件: %s (%s)", path, strerror(errno));
    }
    for (int i = 0; i < g_active_user_count; i++) {
        int uid = g_active_users[i];
        char app_rules_dir[PATH_MAX];
        if (uid == 0) snprintf(app_rules_dir, sizeof(app_rules_dir), "%s/App-rules", CONFIG_DIR);
        else snprintf(app_rules_dir, sizeof(app_rules_dir), "%s/App-rules-%d", CONFIG_DIR, uid);
        DIR* dir = opendir(app_rules_dir);
        if (dir) {
            struct dirent* de;
            while ((de = readdir(dir)) != nullptr) {
                if (de->d_type == DT_REG || de->d_type == DT_LNK) {
                    char* ext = strrchr(de->d_name, '.');
                    if (ext && strcmp(ext, ".conf") == 0) {
                        char pkg[128];
                        size_t len = ext - de->d_name;
                        if (len >= sizeof(pkg)) len = sizeof(pkg) - 1;
                        strncpy(pkg, de->d_name, len);
                        pkg[len] = '\0';
                        AppConfig* file_cur = get_or_create_app_cfg(pkg, uid);
                        /* 存在 <pkg>.conf（未被重命名 .disabled）即启用该应用注入：
                           与 rule-server-api 文档语义一致，不依赖段头 ON。
                           文件内若含 [pkg] OFF 段头会在下方解析时覆盖为 false */
                        file_cur->inject_enable = true;
                        AppConfig* cur = file_cur; 
                        char app_conf_path[PATH_MAX];
                        snprintf(app_conf_path, sizeof(app_conf_path), "%s/%s", app_rules_dir, de->d_name);
                        FILE* afp = fopen(app_conf_path, "r");
                        if (afp) {
                            char line[2048];
                            int app_line_num = 0;
                            while (fgets(line, sizeof(line), afp)) {
                                app_line_num++;
                                char* p = clean_path_string(line);
                                if (!p || p[0] == '#' || p[0] == 0) continue;
                                if (p[0] == '[') {
                                    char* end = strchr(p, ']');
                                    if (end) {
                                        *end = '\0';
                                        char* sec = p + 1;
                                        char* after = end + 1;
                                        bool enabled = true;
                                        while (isspace(*after)) after++;
                                        if (strncmp(after, "OFF", 3) == 0) enabled = false;
                                        else if (strncmp(after, "ON", 2) == 0) enabled = true;
                                        char sub_pkg[128];
                                        int sub_uid = uid; 
                                        char* colon = strchr(sec, ':');
                                        if (colon) { *colon = '\0'; sub_uid = atoi(colon + 1); }
                                        strncpy(sub_pkg, sec, sizeof(sub_pkg)-1);
                                        if (strcmp(sub_pkg, "GLOBAL") == 0) cur = &g_global_cfg_stage;
                                        else { cur = get_or_create_app_cfg(sub_pkg, sub_uid); if (cur) cur->inject_enable = enabled; }
                                    }
                                    continue;
                                }
                                if (cur) parse_config_line(cur, p, uid, app_line_num, app_conf_path);
                            }
                            fclose(afp);
                        }
                    } else if (ext && strcmp(ext, ".disabled") == 0) {
                        /* 停用状态识别：<pkg>.conf.disabled = 该应用规则被停用
                           （rule_server INJECT_ENABLE OFF 重命名而来）。
                           仅当无对应 <pkg>.conf（未被启用）时创建 cfg 并置
                           inject_enable=false——使 is_target_app 能识别停用
                           状态并触发热卸载（此前 cfg 消失导致有通配符/全局
                           注入时停用应用仍被判为目标无法卸载） */
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
                            if (access(conf_path, F_OK) != 0) {
                                AppConfig* file_cur = get_or_create_app_cfg(pkg, uid);
                                file_cur->inject_enable = false;   /* 明确停用 */
                            }
                        }
                    }
                }
            }
            closedir(dir);
        }
    }
    qsort(g_global_cfg_stage.redir_rules, g_global_cfg_stage.redir_count, sizeof(RedirectRule), cmp_redir);
    qsort(g_global_cfg_stage.hide_rules, g_global_cfg_stage.hide_count, sizeof(char*), cmp_hide);
    qsort(g_global_cfg_stage.ro_rules, g_global_cfg_stage.ro_count, sizeof(char*), cmp_hide);
    for(int i = 0; i < g_app_cfg_count_stage; i++) {
        qsort(g_app_cfgs_stage[i]->redir_rules, g_app_cfgs_stage[i]->redir_count, sizeof(RedirectRule), cmp_redir);
        qsort(g_app_cfgs_stage[i]->hide_rules, g_app_cfgs_stage[i]->hide_count, sizeof(char*), cmp_hide);
        qsort(g_app_cfgs_stage[i]->ro_rules, g_app_cfgs_stage[i]->ro_count, sizeof(char*), cmp_hide);
    }
    analyze_var_staticness(&g_global_cfg_stage, NULL);
    for (int i = 0; i < g_app_cfg_count_stage; i++) {
        analyze_var_staticness(g_app_cfgs_stage[i], &g_global_cfg_stage);
    }
    /* S1 COW 发布：暂存区 → live，旧配置延迟释放 */
    config_publish();
}
int reload_config_rules_diff(const char* path, ChangedPkg* out_changed, int max_changed) {
    /* S1：load_config_rules 内部完成 COW 发布（旧配置在发布后即被释放），
       diff 所需旧字段须在加载前快照（旧 AppConfig 指针发布后悬垂） */
    bool old_global_inject = g_global_cfg.global_inject;
    typedef struct { char pkg[128]; int user_id; bool inject_enable; } OldAppSnap;
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
bool has_wildcard_enabled_locked(int user_id) {
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == user_id &&
            strcmp(g_app_cfgs[i]->pkg_name, "*") == 0 &&
            g_app_cfgs[i]->inject_enable)
            return true;
    }
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == -1 &&
            strcmp(g_app_cfgs[i]->pkg_name, "*") == 0 &&
            g_app_cfgs[i]->inject_enable)
            return true;
    }
    return false;
}
void print_active_rules(const char* pkg, int pid, uid_t linux_uid, const char* trigger_source) {
    config_lock_read();
    int user_id = linux_uid / 100000;
    AppConfig* cfg = find_app_cfg_locked(pkg, user_id);
    bool is_wildcard = (cfg == NULL) && has_wildcard_enabled_locked(user_id);
    int final_redir_count = (cfg ? cfg->redir_count : 0) + g_global_cfg.redir_count;
    int final_hide_count = (cfg ? cfg->hide_count : 0) + g_global_cfg.hide_count;
    int final_ro_count = (cfg ? cfg->ro_count : 0) + g_global_cfg.ro_count;
    bool final_sandbox;
    if (cfg && cfg->sandbox_explicit) {
        final_sandbox = cfg->sandbox;
    } else {
        final_sandbox = g_global_cfg.sandbox && !is_media_provider(pkg);
    }
    bool final_monitor;
    if (cfg && cfg->monitor_explicit) {
        final_monitor = cfg->monitor;
    } else {
        final_monitor = g_global_cfg.monitor;
    }
    if (cfg) {
        LOG("应用 %s (PID: %d, 用户: %d) 注入完毕 [%s] | 规则细节 -> MONITOR:%s SANDBOX:%s 重定向(通配):%d条 隐藏(通配):%d条 只读(通配):%d条",
            pkg, pid, user_id, trigger_source,
            final_monitor ? "ON" : "OFF",
            final_sandbox ? "ON" : "OFF",
            final_redir_count, final_hide_count, final_ro_count);
        for (int i = 0; i < cfg->redir_count; i++) {
            //LOG_DBG("  [重定向通配] %s -> %s", cfg->redir_rules[i].virtual_prefix, cfg->redir_rules[i].real_target);
        }
        for (int i = 0; i < cfg->hide_count; i++) {
            //LOG_DBG("  [隐藏通配]   %s", cfg->hide_rules[i]);
        }
        for (int i = 0; i < cfg->ro_count; i++) {
            //LOG_DBG("  [只读通配]   %s", cfg->ro_rules[i]);
        }
    } else {
        const char* match_desc = 
            is_wildcard ? "命中通配符 [*]" :
            (g_global_cfg.global_inject ? "命中 GLOBAL_INJECT" : "无匹配规则");
        LOG("应用 %s (PID: %d, 用户: %d) 注入完毕 [%s] | %s (全局 MONITOR:%s SANDBOX:%s)",
            pkg, pid, user_id, trigger_source, match_desc,
            final_monitor ? "ON" : "OFF",
            final_sandbox ? "ON" : "OFF");
    }
    if (g_global_cfg.redir_count > 0 || g_global_cfg.hide_count > 0 || g_global_cfg.ro_count > 0) {
        LOG_DBG("  [全局规则通配] MONITOR:%s SANDBOX:%s 重定向:%d条 隐藏:%d条 只读:%d条",
            g_global_cfg.monitor ? "ON" : "OFF",
            g_global_cfg.sandbox ? "ON" : "OFF",
            g_global_cfg.redir_count, g_global_cfg.hide_count, g_global_cfg.ro_count);
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            LOG_DBG("  [全局重定向通配] %s -> %s", g_global_cfg.redir_rules[i].virtual_prefix, g_global_cfg.redir_rules[i].real_target);
        }
        for (int i = 0; i < g_global_cfg.hide_count; i++) {
            LOG_DBG("  [全局隐藏通配]   %s", g_global_cfg.hide_rules[i]);
        }
        for (int i = 0; i < g_global_cfg.ro_count; i++) {
            LOG_DBG("  [全局只读通配]   %s", g_global_cfg.ro_rules[i]);
        }
    }
    config_unlock_read();
}