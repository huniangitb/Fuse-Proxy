#define _GNU_SOURCE
#include "module_loader.h"
#include "common.h"
#include <dlfcn.h>
#include <dirent.h>
#include <sys/inotify.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdatomic.h>

/* ================= 注册表 ================= */

typedef struct {
    char name[64];
    void* handle;              /* dlopen 句柄 */
    NspModuleInfo info;        /* 静态信息拷贝 */
    time_t mtime;              /* .so 文件 mtime，热重载检测 */
    bool active;
    _Atomic int backend_refs;  /* 后端 ops 在途引用计数（防热卸载 dlclose 悬垂） */
} ModuleEntry;

static ModuleEntry g_modules[MAX_MODULES];
static int g_module_count = 0;
static pthread_rwlock_t g_module_lock = PTHREAD_RWLOCK_INITIALIZER;

/* 能力位 → 模块索引链（bit 序号 0..31） */
static int g_cap_chain[32][MAX_MODULES];
static int g_cap_chain_count[32];

/* 注册了规则能力的活跃模块数：分派快速路径用（无锁读） */
static volatile int g_active_rules_count = 0;
/* 初始扫描是否完成：完成前不向 injector 上报模块变更（避免启动时误触发全量重挂） */
static volatile sig_atomic_t g_boot_scan_done = 0;

/* ================= 框架服务表 ================= */

static void api_log(int level, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    size_t l = strlen(buf);
    /* 仅当换行放得下才追加，防止 buf 满（l==1023）时 buf[1024]='\0' 越界 1 字节 */
    if (l > 0 && l + 1 < sizeof buf && buf[l - 1] != '\n') {
        buf[l] = '\n';
        buf[l + 1] = '\0';
    }
    log_internal((LogLevel)level, "%s", buf);
}

static const char* api_get_real_root(void) { return g_real_root; }

/* 框架参数（module_system_init 传入） */
static char g_fw_rules_path[PATH_MAX] = {0};
static uint32_t g_fw_flags = 0;
/* 模块目录（默认 MODULES_DIR 宏，可经 --modules-dir 覆盖） */
static char g_modules_dir[PATH_MAX] = MODULES_DIR;

static const char* api_get_rules_path(void) { return g_fw_rules_path[0] ? g_fw_rules_path : NULL; }
static uint32_t api_get_flags(void) { return g_fw_flags; }

static const NspFrameworkApi g_api = {
    .api_version = NSP_FRAMEWORK_API_VERSION,
    .log = api_log,
    .get_real_root = api_get_real_root,
    .get_rules_path = api_get_rules_path,
    .get_flags = api_get_flags,
};

/* ================= 工具 ================= */

static bool is_valid_module_name(const char* n) {
    if (!n || !n[0] || strlen(n) >= 64) return false;
    for (const char* p = n; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
              *p == '_' || *p == '-'))
            return false;
    }
    return true;
}

#define RULE_CAPS (NSP_CAP_REDIRECT | NSP_CAP_SANDBOX | NSP_CAP_HIDE | \
                   NSP_CAP_ALLOW | NSP_CAP_RO)

static int find_slot(const char* name) {
    for (int i = 0; i < g_module_count; i++)
        if (g_modules[i].active && strcmp(g_modules[i].name, name) == 0) return i;
    return -1;
}

static void chain_add(uint32_t caps, int slot) {
    for (uint32_t bit = 1u; bit; bit <<= 1u) {
        if (caps & bit) {
            int bi = __builtin_ctz(bit);
            if (bi >= 0 && bi < 32 && g_cap_chain_count[bi] < MAX_MODULES)
                g_cap_chain[bi][g_cap_chain_count[bi]++] = slot;
        }
    }
}

static void chain_remove(int slot) {
    for (int bi = 0; bi < 32; bi++) {
        int n = g_cap_chain_count[bi];
        for (int i = 0; i < n; i++) {
            if (g_cap_chain[bi][i] == slot) {
                g_cap_chain[bi][i] = g_cap_chain[bi][n - 1];
                g_cap_chain_count[bi] = n - 1;
                break;
            }
        }
    }
}

/* ================= 加载 / 卸载 ================= */

static int module_load_one(const char* name) {
    if (!is_valid_module_name(name)) {
        LOG_WRN("模块名非法，跳过: %s", name);
        return -1;
    }
    char so_path[PATH_MAX];
    snprintf(so_path, sizeof so_path, "%s/%s/%s.so", g_modules_dir, name, name);
    void* h = dlopen(so_path, RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        LOG_ERR("模块加载失败 %s: %s", so_path, dlerror());
        return -1;
    }
    NspModuleInfo* info = (NspModuleInfo*)dlsym(h, NSP_MODULE_INFO_SYMBOL);
    if (!info) {
        LOG_ERR("模块 %s 未导出 %s 符号", name, NSP_MODULE_INFO_SYMBOL);
        dlclose(h);
        return -2;
    }
    if (info->magic != NSP_MODULE_MAGIC || info->abi_version != NSP_MODULE_ABI_VERSION) {
        LOG_ERR("模块 %s ABI 不匹配 (magic=0x%x abi=%u，期望 0x%x/%u)",
                name, info->magic, info->abi_version, NSP_MODULE_MAGIC, NSP_MODULE_ABI_VERSION);
        dlclose(h);
        return -3;
    }
    if (!info->name || strcmp(info->name, name) != 0) {
        LOG_ERR("模块 %s 内部 name=%s 与目录名不一致", name, info->name ? info->name : "(null)");
        dlclose(h);
        return -4;
    }
    /* init 在锁外调用，成功后才登记 */
    if (info->init) {
        if (info->init(&g_api) != 0) {
            LOG_ERR("模块 %s init 失败", name);
            dlclose(h);
            return -5;
        }
    }
    pthread_rwlock_wrlock(&g_module_lock);
    if (g_module_count >= MAX_MODULES) {
        pthread_rwlock_unlock(&g_module_lock);
        LOG_ERR("模块注册表已满，拒绝 %s", name);
        if (info->exit) info->exit();
        dlclose(h);
        return -6;
    }
    int slot = g_module_count++;
    ModuleEntry* m = &g_modules[slot];
    memset(m, 0, sizeof *m);
    strncpy(m->name, name, sizeof m->name - 1);
    m->handle = h;
    m->info = *info;          /* 浅拷贝：info->ops 指针有效 */
    m->active = true;
    struct stat st;
    if (stat(so_path, &st) == 0) m->mtime = st.st_mtime;
    chain_add(m->info.caps, slot);
    if (m->info.caps & RULE_CAPS) g_active_rules_count++;
    pthread_rwlock_unlock(&g_module_lock);

    LOG("模块已加载: %s v%s (类型=%u caps=0x%x)", name,
        info->version ? info->version : "?", info->type, info->caps);
    return 0;
}

static int module_unload_one(const char* name) {
    pthread_rwlock_wrlock(&g_module_lock);
    int slot = find_slot(name);
    if (slot < 0) {
        pthread_rwlock_unlock(&g_module_lock);
        return -1;
    }
    ModuleEntry* m = &g_modules[slot];
    void* h = m->handle;
    NspModuleInfo info = m->info;
    if (info.caps & RULE_CAPS) {
        if (g_active_rules_count > 0) g_active_rules_count--;
    }
    chain_remove(slot);
    m->active = false;
    m->handle = NULL;
    pthread_rwlock_unlock(&g_module_lock);

    /* 等待后端在途调用完成（防 ops 指针悬垂 SIGSEGV；最多 ~100ms） */
    for (int i = 0; i < 100; i++) {
        bool busy = false;
        pthread_rwlock_rdlock(&g_module_lock);
        busy = (m->backend_refs > 0);
        pthread_rwlock_unlock(&g_module_lock);
        if (!busy) break;
        usleep(1000);
    }

    if (info.exit) info.exit();
    dlclose(h);
    LOG("模块已卸载: %s", name);
    return 0;
}

/* 通知 injector 模块变更（热插拔事件，经 IPC socket 上报） */
static void notify_module_changed(const char* name) {
    char msg[256];
    snprintf(msg, sizeof msg, "MODULE_CHANGED %s", name ? name : "?");
    send_ipc_message(msg);
}

/* ================= 全量扫描（启动 + 热插拔差异） ================= */

static void module_scan_diff(void) {
    DIR* d = opendir(g_modules_dir);
    if (!d) {
        /* 目录不存在时尝试创建后重试一次 */
        if (errno == ENOENT) {
            mkdir_recursive(g_modules_dir);
            d = opendir(g_modules_dir);
        }
        if (!d) return;
    }
    char present[MAX_MODULES][64];
    int pcount = 0;
    struct dirent* de;
    while ((de = readdir(d)) && pcount < MAX_MODULES) {
        if (de->d_name[0] == '.') continue;
        if (!is_valid_module_name(de->d_name)) continue;
        char so[PATH_MAX];
        snprintf(so, sizeof so, "%s/%s/%s.so", g_modules_dir, de->d_name, de->d_name);
        if (access(so, F_OK) == 0)
            strncpy(present[pcount++], de->d_name, 63);
    }
    closedir(d);

    /* 1. 卸载目录中已消失的模块 */
    for (int i = 0; i < g_module_count; i++) {
        if (!g_modules[i].active) continue;
        bool found = false;
        for (int p = 0; p < pcount; p++) {
            if (strcmp(present[p], g_modules[i].name) == 0) { found = true; break; }
        }
        if (!found) {
            LOG("检测到模块目录移除: %s", g_modules[i].name);
            module_unload_one(g_modules[i].name);
            if (g_boot_scan_done) notify_module_changed(g_modules[i].name);
        }
    }
    /* 2. 加载新增 / 重载文件更新的模块 */
    for (int p = 0; p < pcount; p++) {
        int slot = find_slot(present[p]);
        if (slot < 0) {
            LOG("检测到新模块: %s", present[p]);
            module_load_one(present[p]);
            if (g_boot_scan_done) notify_module_changed(present[p]);
        } else {
            char so[PATH_MAX];
            snprintf(so, sizeof so, "%s/%s/%s.so", g_modules_dir, present[p], present[p]);
            struct stat st;
            if (stat(so, &st) == 0 && st.st_mtime != g_modules[slot].mtime) {
                LOG("模块文件已更新，热重载: %s", present[p]);
                module_unload_one(present[p]);
                module_load_one(present[p]);
                if (g_boot_scan_done) notify_module_changed(present[p]);
            }
        }
    }
}

/* ================= 热插拔监控线程 ================= */

static void* module_monitor_thread(void* arg) {
    (void)arg;
    int inotify_fd = -1;
    int wd = -1;
    while (!g_log_shutdown) {
        if (inotify_fd < 0) {
            inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
            if (inotify_fd < 0) { sleep(2); continue; }
        }
        if (wd < 0) {
            wd = inotify_add_watch(inotify_fd, g_modules_dir,
                IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM |
                IN_CLOSE_WRITE | IN_DELETE_SELF);
            if (wd < 0) {
                close(inotify_fd);
                inotify_fd = -1;
                sleep(2);
                continue;
            }
        }
        struct pollfd pfd = { .fd = inotify_fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 5000);
        if (pr < 0) {
            if (errno == EINTR) continue;
            inotify_rm_watch(inotify_fd, wd);
            wd = -1;
            close(inotify_fd);
            inotify_fd = -1;
            continue;
        }
        if (pr == 0) {
            /* 周期兜底扫描：inotify watch 不递归模块子目录，.so 增删事件
               （子目录内）收不到，靠定时全量扫描发现（每 5s 一次，开销极小） */
            module_scan_diff();
            continue;
        }
        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t len = read(inotify_fd, buf, sizeof buf);
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
        for (char* p = buf; p < buf + len; ) {
            struct inotify_event* ev = (struct inotify_event*)p;
            if (ev->mask & IN_IGNORED) watch_invalidated = true;
            p += sizeof(struct inotify_event) + ev->len;
        }
        sleep(1);   /* 归并窗口：多个叠加事件只重扫一次 */
        module_scan_diff();
        if (watch_invalidated) wd = -1;
    }
    if (inotify_fd >= 0) {
        if (wd >= 0) inotify_rm_watch(inotify_fd, wd);
        close(inotify_fd);
    }
    return NULL;
}

/* ================= 对外接口 ================= */

int module_system_init(const char* rules_path, const char* modules_dir, uint32_t flags) {
    if (rules_path)
        strncpy(g_fw_rules_path, rules_path, sizeof g_fw_rules_path - 1);
    if (modules_dir && modules_dir[0])
        strncpy(g_modules_dir, modules_dir, sizeof g_modules_dir - 1);
    g_fw_flags = flags;
    mkdir_recursive(g_modules_dir);
    module_scan_diff();
    pthread_t tid;
    if (pthread_create(&tid, NULL, module_monitor_thread, NULL) == 0)
        pthread_detach(tid);
    /* 初始扫描完成后标记，后续热插拔变更才通知 injector */
    g_boot_scan_done = 1;
    int active = 0;
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count; i++)
        if (g_modules[i].active) active++;
    pthread_rwlock_unlock(&g_module_lock);
    LOG("模块系统已初始化: 目录 %s, 已加载 %d 个模块", g_modules_dir, active);
    return 0;
}

void module_system_shutdown(void) {
    for (int i = g_module_count - 1; i >= 0; i--) {
        if (g_modules[i].active) module_unload_one(g_modules[i].name);
    }
    g_module_count = 0;
}

int module_dispatch_resolve(const NspQueryCtx* q, NspResolveResult* out) {
    if (!q || !out) return NSP_DISPATCH_NONE;
    /* 快速路径：无规则模块注册，零开销回退默认路径 */
    if (g_active_rules_count == 0) return NSP_DISPATCH_NONE;

    pthread_rwlock_rdlock(&g_module_lock);
    bool any = false;
    bool first = true;
    for (int i = 0; i < g_module_count; i++) {
        ModuleEntry* m = &g_modules[i];
        if (!m->active || !(m->info.caps & RULE_CAPS)) continue;
        if (!m->info.ops || !m->info.ops->resolve) continue;
        NspResolveResult r;
        memset(&r, 0, sizeof r);
        if (m->info.ops->resolve(q, &r) != 0) continue;
        if (!r.valid) continue;
        if (first) {
            *out = r;
            first = false;
            any = true;
            continue;
        }
        /* 多模块并集聚合：hidden/ro/allow 任一命中即生效；
           redir/sandbox 取第一个命中（模块注册顺序即优先级） */
        out->hidden = out->hidden || r.hidden;
        out->ro = out->ro || r.ro;
        out->allow = out->allow || r.allow;
        if (!out->has_redir && r.has_redir) {
            out->has_redir = true;
            strncpy(out->redir_target, r.redir_target, sizeof out->redir_target - 1);
            out->redir_target[sizeof out->redir_target - 1] = '\0';
        }
        if (!out->has_sandbox && r.has_sandbox) {
            out->has_sandbox = true;
            strncpy(out->sandbox_target, r.sandbox_target, sizeof out->sandbox_target - 1);
            out->sandbox_target[sizeof out->sandbox_target - 1] = '\0';
        }
        if (!out->is_redir && r.is_redir) {
            out->is_redir = true;
            strncpy(out->real_path, r.real_path, sizeof out->real_path - 1);
            out->real_path[sizeof out->real_path - 1] = '\0';
        }
        out->is_virtual_ancestor = out->is_virtual_ancestor || r.is_virtual_ancestor;
        out->is_redirect_target = out->is_redirect_target || r.is_redirect_target;
        out->is_other_app_pkg = out->is_other_app_pkg || r.is_other_app_pkg;
    }
    pthread_rwlock_unlock(&g_module_lock);
    return any ? NSP_DISPATCH_OK : NSP_DISPATCH_NONE;
}

int module_dispatch_probe(const NspQueryCtx* q, NspProbeResult* out) {
    if (!q || !out) return NSP_DISPATCH_NONE;
    /* 快速路径：无规则模块注册，零开销回退（不过滤任何条目） */
    if (g_active_rules_count == 0) return NSP_DISPATCH_NONE;

    pthread_rwlock_rdlock(&g_module_lock);
    bool any = false;
    for (int i = 0; i < g_module_count; i++) {
        ModuleEntry* m = &g_modules[i];
        if (!m->active || !(m->info.caps & RULE_CAPS)) continue;
        if (!m->info.ops || !m->info.ops->probe) continue;
        NspProbeResult r;
        memset(&r, 0, sizeof r);
        if (m->info.ops->probe(q, &r) != 0) continue;
        if (!r.valid) continue;
        if (!any) {
            *out = r;
            any = true;
            continue;
        }
        /* 多模块并集：hidden/redirect_target 任一命中即生效 */
        out->hidden = out->hidden || r.hidden;
        out->is_redirect_target = out->is_redirect_target || r.is_redirect_target;
        out->is_virtual_ancestor = out->is_virtual_ancestor || r.is_virtual_ancestor;
        out->is_other_app_pkg = out->is_other_app_pkg || r.is_other_app_pkg;
    }
    pthread_rwlock_unlock(&g_module_lock);
    return any ? NSP_DISPATCH_OK : NSP_DISPATCH_NONE;
}

int module_backend_lookup(const char* path, const NspModuleOps** ops_out) {
    if (!path || !ops_out) return -1;
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count; i++) {
        ModuleEntry* m = &g_modules[i];
        if (!m->active || m->info.type != NSP_MODULE_TYPE_BACKEND) continue;
        if (!(m->info.caps & NSP_CAP_BACKEND_IO)) continue;
        if (!m->info.ops || !m->info.ops->backend_match) continue;
        if (m->info.ops->backend_match(path) == 1) {
            *ops_out = m->info.ops;
            /* 在途引用：原子自增（调用方须在 backend_* 完成后 put） */
            __atomic_fetch_add(&m->backend_refs, 1, __ATOMIC_ACQ_REL);
            pthread_rwlock_unlock(&g_module_lock);
            return 0;
        }
    }
    pthread_rwlock_unlock(&g_module_lock);
    return -1;
}

/* 释放 backend_* 在途引用（与 module_backend_lookup 配对；热卸载等待其归零）。
   用读锁而非写锁：backend_refs 是原子计数，写锁只留给加载/卸载，
   避免每次后端 IO 的 put 与其它读路径互斥（后端并发读写不被串行化） */
void module_backend_put(const NspModuleOps* ops) {
    if (!ops) return;
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count; i++) {
        ModuleEntry* m = &g_modules[i];
        if (m->active && m->info.ops == ops) {
            int prev = __atomic_fetch_sub(&m->backend_refs, 1, __ATOMIC_ACQ_REL);
            if (prev <= 0) /* 防御：不出现负数（正常配对下不会发生） */
                __atomic_store_n(&m->backend_refs, 0, __ATOMIC_RELAXED);
            break;
        }
    }
    pthread_rwlock_unlock(&g_module_lock);
}

bool module_backend_active(void) {
    bool any = false;
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count; i++) {
        ModuleEntry* m = &g_modules[i];
        if (m->active && m->info.type == NSP_MODULE_TYPE_BACKEND &&
            (m->info.caps & NSP_CAP_BACKEND_IO)) {
            any = true;
            break;
        }
    }
    pthread_rwlock_unlock(&g_module_lock);
    return any;
}

int module_dispatch_readdir(const NspQueryCtx* q, const char* sub_path, int user_id,
                            const char* pkg, bool is_root, NspDirEntry* out, int max) {
    if (!q || !out || max <= 0) return 0;
    if (g_module_count == 0) return 0;
    pthread_rwlock_rdlock(&g_module_lock);
    int n = 0;
    for (int i = 0; i < g_module_count && n < max; i++) {
        ModuleEntry* m = &g_modules[i];
        if (!m->active || !(m->info.caps & NSP_CAP_READDIR_EXTRA)) continue;
        if (!m->info.ops || !m->info.ops->readdir_extra) continue;
        int got = m->info.ops->readdir_extra(q, sub_path, user_id, pkg, is_root,
                                             out + n, max - n);
        if (got > 0) n += got;
    }
    pthread_rwlock_unlock(&g_module_lock);
    return n;
}

void module_notify_reload(void) {
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count; i++) {
        ModuleEntry* m = &g_modules[i];
        if (m->active && m->info.ops && m->info.ops->reload)
            m->info.ops->reload();
    }
    pthread_rwlock_unlock(&g_module_lock);
}

int module_dispatch_get_pkg(uid_t uid, pid_t tid, char* pkg_out, size_t pkg_size) {
    if (!pkg_out || pkg_size == 0) return -1;
    pthread_rwlock_rdlock(&g_module_lock);
    int rc = -1;
    for (int i = 0; i < g_module_count; i++) {
        ModuleEntry* m = &g_modules[i];
        if (!m->active || !m->info.ops || !m->info.ops->get_pkg) continue;
        if (m->info.ops->get_pkg(uid, tid, pkg_out, pkg_size) == 0) { rc = 0; break; }
    }
    pthread_rwlock_unlock(&g_module_lock);
    if (rc != 0) {
        strncpy(pkg_out, "unknown", pkg_size - 1);
        pkg_out[pkg_size - 1] = '\0';
    }
    return rc;
}

int module_snapshot(char names[][64], int max) {
    int n = 0;
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count && n < max; i++) {
        if (g_modules[i].active)
            strncpy(names[n++], g_modules[i].name, 63);
    }
    pthread_rwlock_unlock(&g_module_lock);
    return n;
}

bool module_any_loaded(void) {
    bool any = false;
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count; i++)
        if (g_modules[i].active) { any = true; break; }
    pthread_rwlock_unlock(&g_module_lock);
    return any;
}
