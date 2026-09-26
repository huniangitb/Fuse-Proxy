#define _GNU_SOURCE
/*
 * fw_config.c — 框架侧配置持有者（见 fw_config.h）
 *
 * 读取（文件 I/O + inotify + 词法/段头识别）全部在此完成；模块经订阅拿到
 * 过滤后的扁平视图，自行建索引。框架不建 AppConfig（不需要规则对象/trie）。
 */
#include "fw_config.h"
#include "config_parser.h"
#include "common.h"
#include "module_loader.h" /* MAX_MODULES */
#include "nsp_util.h"      /* nsp_switch_on */

#include <errno.h>
#include <ctype.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

/* 每个模块的订阅与下发视图 */
typedef struct {
    bool used;
    char name[64];
    char** types; /* 订阅的规则类型名（strdup 归本结构所有） */
    int type_count;
    void (*listener)(const NspModuleConfig*);
    NspCfgRec* filtered; /* 浅拷贝自主视图（字符串指向主视图，不拥有） */
    int filtered_count;
    NspModuleConfig cfg;
} ModuleSub;

static ModuleSub g_subs[MAX_MODULES];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static NspCfgRec* g_recs = nullptr; /* 主视图（拥有字符串） */
static int g_rec_count = 0;
static _Atomic uint64_t g_gen = 0;

static char g_rules_path[PATH_MAX] = {0};
static void (*g_reload_hook)(void) = nullptr;

/* 全局 MONITOR 快照（fw_config_global_monitor 读取）：reload_once 内随视图
   换入重算，读者只做原子 load——兜底值若每次 FUSE 请求都持 g_lock 扫视图，
   会在「规则模块缺失」这种本就异常的场景里把锁竞争引入热路径。 */
static _Atomic bool g_global_monitor = false;

/* 从扁平视图算出 `[GLOBAL]` 段内最后一条 MONITOR 记录的开关值（无记录 = 关）。
   仅认 GLOBAL 段：类别/应用段的否决需要 uid→包名映射，那是模块的索引职责，
   框架不在这里重复实现三层合并（见 fw_config.h 语义边界）。 */
static bool scan_global_monitor(const NspCfgRec* recs, int count) {
    bool in_global = false;
    bool on = false;
    for (int i = 0; i < count; i++) {
        const NspCfgRec* r = &recs[i];
        if (r->kind == NSP_CFG_REC_SECTION) {
            in_global = r->text && strcmp(r->text, "GLOBAL") == 0;
            continue;
        }
        if (!in_global || r->kind != NSP_CFG_REC_RULE || !r->type || !r->text) continue;
        if (strcmp(r->type, "MONITOR") != 0) continue;
        /* r->text 是去注释/首尾空白的整行（"MONITOR ON"）：跳过首 token 取开关值 */
        const char* p = r->text;
        while (*p && !isspace((unsigned char)*p)) p++;
        while (*p && isspace((unsigned char)*p)) p++;
        char val[8] = {0};
        on = (sscanf(p, "%7s", val) == 1) && nsp_switch_on(val);
    }
    return on;
}

static volatile bool g_stop = false;
static pthread_t g_monitor_tid;
static bool g_thread_started = false;

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

/* 记录是否需要下发给该订阅：结构记录（段头/文件归属）恒需要（规则要靠它们
   解释作用域）；规则记录按订阅的类型名过滤。订阅为空 = 申请全部。 */
static bool rec_wanted(const ModuleSub* s, const NspCfgRec* r) {
    if (r->kind != NSP_CFG_REC_RULE) return true;
    if (s->type_count == 0) return true;
    if (!r->type) return false;
    for (int i = 0; i < s->type_count; i++) {
        if (strcmp(s->types[i], r->type) == 0) return true;
    }
    return false;
}

/* 用当前主视图重建某模块的过滤视图（浅拷贝记录，不复制字符串） */
static void rebuild_filter(ModuleSub* s) {
    free(s->filtered);
    s->filtered = nullptr;
    s->filtered_count = 0;
    int n = 0;
    for (int i = 0; i < g_rec_count; i++) {
        if (rec_wanted(s, &g_recs[i])) n++;
    }
    if (n > 0) {
        s->filtered = malloc((size_t)n * sizeof(NspCfgRec));
        if (!s->filtered) return;
        int k = 0;
        for (int i = 0; i < g_rec_count; i++) {
            if (rec_wanted(s, &g_recs[i])) s->filtered[k++] = g_recs[i];
        }
    }
    s->filtered_count = n;
    s->cfg.version = NSP_CFG_VIEW_VERSION;
    s->cfg.generation = atomic_load_explicit(&g_gen, memory_order_acquire);
    s->cfg.recs = s->filtered;
    s->cfg.count = s->filtered_count;
}

/* 读出主视图并换入；旧视图与旧过滤视图在推送完成后释放（见 publish） */
static void reload_once(void) {
    NspCfgRec* new_recs = nullptr;
    int new_count = 0;
    config_read_view(g_rules_path, &new_recs, &new_count);

    pthread_mutex_lock(&g_lock);
    NspCfgRec* old_recs = g_recs;
    int old_count = g_rec_count;
    /* 旧过滤视图的字符串指向旧主视图：先整体丢弃（模块索引已自持副本），
       推送完成后旧主视图才释放，故此处丢弃是安全的 */
    for (int i = 0; i < MAX_MODULES; i++) {
        if (g_subs[i].used) {
            free(g_subs[i].filtered);
            g_subs[i].filtered = nullptr;
            g_subs[i].filtered_count = 0;
        }
    }
    g_recs = new_recs;
    g_rec_count = new_count;
    /* 全局 MONITOR 快照随视图一起换入：热路径只做一次原子 load，
       不为兜底开关在每个 FUSE 请求上抢 g_lock */
    atomic_store_explicit(&g_global_monitor, scan_global_monitor(new_recs, new_count),
                          memory_order_release);
    atomic_fetch_add_explicit(&g_gen, 1, memory_order_release);
    for (int i = 0; i < MAX_MODULES; i++) {
        if (g_subs[i].used) rebuild_filter(&g_subs[i]);
    }
    pthread_mutex_unlock(&g_lock);

    /* 推送：钩子内新旧视图都有效（loader 遍历活跃模块调用各自监听器） */
    if (g_reload_hook) g_reload_hook();

    config_free_view(old_recs, old_count);
}

/* 监听规则文件所在目录（沿用原模块内 watch 重建/归并模式） */
static void* config_monitor_thread(void* arg) {
    (void)arg;
    int inotify_fd = -1;
    int wd = -1;
    while (!g_stop && !g_log_shutdown) {
        if (inotify_fd < 0) {
            inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
            if (inotify_fd < 0) {
                sleep(2);
                continue;
            }
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
            wd = inotify_add_watch(inotify_fd, dir,
                                   IN_CLOSE_WRITE | IN_MODIFY | IN_MOVED_TO | IN_MOVED_FROM |
                                       IN_CREATE | IN_DELETE | IN_DELETE_SELF);
            if (wd < 0) {
                close(inotify_fd);
                inotify_fd = -1;
                sleep(2);
                continue;
            }
        }
        struct pollfd pfd = {.fd = inotify_fd, .events = POLLIN};
        int pr = poll(&pfd, 1, 5000);
        if (pr < 0) {
            if (errno == EINTR) continue;
            inotify_rm_watch(inotify_fd, wd);
            wd = -1;
            close(inotify_fd);
            inotify_fd = -1;
            continue;
        }
        if (pr == 0) continue;
        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t len = read(inotify_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            inotify_rm_watch(inotify_fd, wd);
            wd = -1;
            close(inotify_fd);
            inotify_fd = -1;
            continue;
        }
        if (len == 0) continue;
        bool watch_invalidated = false;
        for (char* p = buf; p < buf + len;) {
            struct inotify_event* ev = (struct inotify_event*)p;
            if (ev->mask & IN_IGNORED) watch_invalidated = true;
            p += sizeof(struct inotify_event) + ev->len;
        }
        sleep(1); /* 归并写者连击：等待写者落定再读 */
        reload_once();
        if (watch_invalidated) wd = -1;
    }
    if (inotify_fd >= 0) {
        if (wd >= 0) inotify_rm_watch(inotify_fd, wd);
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
    if (g_rules_path[0] == '\0') {
        LOG_WRN("未提供 --rules= 路径，框架配置视图为空（模块将收不到任何规则）");
        return 0;
    }
    reload_once();
    g_stop = false;
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
    if (g_thread_started) {
        pthread_join(g_monitor_tid, nullptr);
        g_thread_started = false;
    }
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < MAX_MODULES; i++) {
        if (!g_subs[i].used) continue;
        free(g_subs[i].filtered);
        g_subs[i].filtered = nullptr;
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
    atomic_store_explicit(&g_global_monitor, false, memory_order_release);
    pthread_mutex_unlock(&g_lock);
    config_free_view(recs, count);
}

const NspCfgRec* fw_config_recs(int* count_out) {
    if (count_out) *count_out = g_rec_count;
    return g_recs;
}

uint64_t fw_config_generation(void) {
    return atomic_load_explicit(&g_gen, memory_order_acquire);
}

bool fw_config_global_monitor(void) {
    return atomic_load_explicit(&g_global_monitor, memory_order_acquire);
}

const NspModuleConfig* fw_config_view_for(const char* module_name) {
    pthread_mutex_lock(&g_lock);
    ModuleSub* s = find_sub(module_name);
    const NspModuleConfig* out = nullptr;
    if (s) {
        s->cfg.generation = atomic_load_explicit(&g_gen, memory_order_acquire);
        out = &s->cfg;
    }
    pthread_mutex_unlock(&g_lock);
    return out;
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
        free(s->filtered);
        for (int t = 0; t < s->type_count; t++) free(s->types[t]);
        free(s->types);
        memset(s, 0, sizeof *s);
    }
    pthread_mutex_unlock(&g_lock);
}

void fw_config_set_reload_hook(void (*hook)(void)) {
    g_reload_hook = hook;
}
