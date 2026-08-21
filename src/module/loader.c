#define _GNU_SOURCE
#include "module_loader.h"
#include "common.h"
#include "../core/sha256.h"
#include <dlfcn.h>
#include <dirent.h>
#include <ctype.h>
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

/* 路径是否含 <uid>/ 用户层（如 /0/foo、/10/、或 /0 本身）：
   FUSE 挂载点根（/、/obb 等非 uid 顶层）不进行任何规则合成，
   仅 <uid>/ 之后的路径才允许规则模块响应——从框架源头规避
   挂载点根下出现额外虚拟目录（如 FTP 前缀条目被合到根下） */
static bool path_has_uid_layer(const char* path) {
    if (!path || path[0] != '/' || path[1] < '0' || path[1] > '9') return false;
    const char* d = path + 1;
    while (*d >= '0' && *d <= '9') d++;
    return (*d == '\0' || *d == '/');
}

typedef struct {
    char name[64];
    void* handle;              /* dlopen 句柄 */
    NspModuleInfo info;        /* 静态信息拷贝 */
    time_t mtime;              /* .so 文件 mtime，热重载检测 */
    bool active;
    _Atomic int backend_refs;  /* 后端 ops 在途引用计数（防热卸载 dlclose 悬垂） */
    int (*active_handles_fn)(void);  /* 可选：活跃句柄查询（模块导出 nsp_module_active_handles），
                                        热重载 quiescence 门控——有应用 open 时延迟卸载/重载 */
    char hash[65];                   /* 已加载 .so 文件的 SHA-256（框架计算，加载时存入）：
                                        热重载时与磁盘哈希比对——一致则内容未变化，跳过热加载 */
} ModuleEntry;

static ModuleEntry g_modules[MAX_MODULES];
static int g_module_count = 0;
static pthread_rwlock_t g_module_lock = PTHREAD_RWLOCK_INITIALIZER;

/* 能力位 → 模块索引链（bit 序号 0..31） */
static int g_cap_chain[32][MAX_MODULES];
static int g_cap_chain_count[32];

/* 注册了规则能力的活跃模块数：分派快速路径用（无锁读） */
static volatile int g_active_rules_count = 0;
/* 活跃后端 I/O 模块数：vfs_read/write 快速路径无锁读（原子），
   模块加载/卸载（写锁内）时更新 */
static _Atomic(int) g_backend_active_count = 0;
/* 后端槽位原子快照：module_load_one（写锁内）置 ops；module_unload_one
   先置 NULL 再等待引用归零。read/write 热路径经 module_backend_acquire_slot
   无锁读取，免 rwlock + 线性扫描 + backend_match 前缀比较。
   槽位号由 open 时编码进 fh 高位（见 fuse_daemon.c NSP_FH_BACKEND_SLOT_*）。 */
static _Atomic(const NspModuleOps*) g_backend_slot_ops[MAX_MODULES];
static _Atomic(int) g_backend_slot_refs[MAX_MODULES];  /* 槽位在途引用（acquire 配对 release） */
/* 规则模块槽位原子快照：与后端槽位同模式，供 resolve 分派无锁读取——
   消除每请求 g_module_lock rwlock 往返（S2 热路径优化）。
   load 写锁内置 ops；unload 先置 NULL 再等 g_rule_slot_refs 归零后 dlclose。
   调用方 acquire 在途引用 → 二次确认快照未变 → 调用 ops → release。 */
static _Atomic(const NspModuleOps*) g_rule_slot_ops[MAX_MODULES];
static _Atomic(int) g_rule_slot_refs[MAX_MODULES];
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

/* 加载并校验新模块（不注册）：0.5s 稳定性校验 + 框架文件哈希 + dlopen +
   ABI/自哈希校验 + init。全部通过才返回（h_out/info_out/hash_out 有效，
   调用方负责 dlclose 或 module_commit）；任一失败返回负值（已 dlclose）。
   设计：热重载"先验后换"——先加载校验新模块，通过才卸载旧模块并登记，
   校验失败保留内存中的旧模块。 */
static int module_prepare(const char* name, void** h_out, NspModuleInfo* info_out,
                          char hash_out[65]) {
    char so_path[PATH_MAX];
    snprintf(so_path, sizeof so_path, "%s/%s/%s.so", g_modules_dir, name, name);
    /* 热加载防御：dlopen 前校验 .so 文件稳定性（两次 stat 大小/时间一致）。
       模块 .so 正在被替换/拷贝时（inotify 触发扫描与文件写入竞态），
       dlopen 可能加载半写入的文件 → NspModuleInfo/init/ops 指针为垃圾值
       → 间接调用跳转未映射地址 → SIGSEGV（热加载崩溃现场 PC=垃圾地址）。
       校验窗口 0.5s：使用场景不要求低延迟热加载，稳定性优先——半写入
       窗口内一律延迟加载（延迟到下一次扫描）。 */
    struct stat st1, st2;
    if (stat(so_path, &st1) == 0) {
        usleep(500000);
        if (stat(so_path, &st2) != 0 || st1.st_size != st2.st_size ||
            st1.st_mtime != st2.st_mtime) {
            LOG_WRN("模块 %s 的 .so 正在写入（大小/时间不稳定），延迟加载", name);
            return -1;
        }
    }
    /* 框架计算文件 SHA-256（open/read/close，fd 用后即关，不长期持有
       磁盘模块文件句柄）；失败仅告警，不阻断加载 */
    if (sha256_file_hex(so_path, hash_out) != 0) {
        LOG_WRN("模块 %s 文件哈希计算失败，跳过哈希校验", name);
        hash_out[0] = '\0';
    }
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
    /* 模块加载兼容性 API（可选）：框架计算的文件哈希 vs 模块上报的自哈希——
       不一致（加载窗口内文件被写入/替换/篡改）→ 拒绝加载；模块未导出该
       符号时跳过校验（兼容旧模块）。 */
    if (hash_out[0] != '\0') {
        const char* (*self_hash)(void) = (const char* (*)(void))dlsym(h, "nsp_module_self_hash");
        if (self_hash) {
            const char* mh = self_hash();
            if (!mh || strcmp(mh, hash_out) != 0) {
                LOG_ERR("模块 %s 自哈希与文件哈希不一致（文件被修改/替换？），拒绝加载",
                        name);
                dlclose(h);
                return -7;
            }
        }
    }
    /* init 在锁外调用，成功后才登记 */
    if (info->init) {
        if (info->init(&g_api) != 0) {
            LOG_ERR("模块 %s init 失败", name);
            dlclose(h);
            return -5;
        }
    }
    *h_out = h;
    *info_out = *info;
    return 0;
}

/* 登记已校验模块到槽位（写锁内发布原子快照/链），并存入文件哈希 */
static int module_commit(const char* name, void* h, const NspModuleInfo* info,
                         const char* hash) {
    char so_path[PATH_MAX];
    snprintf(so_path, sizeof so_path, "%s/%s/%s.so", g_modules_dir, name, name);
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
    /* 可选活跃句柄查询（热重载 quiescence 门控）：模块导出则使用，缺省视为 0 */
    m->active_handles_fn = (int (*)(void))dlsym(h, "nsp_module_active_handles");
    if (hash && hash[0]) strncpy(m->hash, hash, sizeof m->hash - 1);
    m->active = true;
    struct stat st;
    if (stat(so_path, &st) == 0) m->mtime = st.st_mtime;
    chain_add(m->info.caps, slot);
    if (m->info.caps & RULE_CAPS) {
        g_active_rules_count++;
        /* 规则槽位快照：写锁内发布，resolve 分派无锁读取 */
        atomic_store_explicit(&g_rule_slot_ops[slot], m->info.ops, memory_order_release);
    }
    if (m->info.type == NSP_MODULE_TYPE_BACKEND && (m->info.caps & NSP_CAP_BACKEND_IO)) {
        atomic_fetch_add_explicit(&g_backend_active_count, 1, memory_order_release);
        /* 槽位快照：写锁内发布，read/write 热路径无锁读取 */
        atomic_store_explicit(&g_backend_slot_ops[slot], m->info.ops, memory_order_release);
    }
    pthread_rwlock_unlock(&g_module_lock);

    LOG("模块已加载: %s v%s (类型=%u caps=0x%x)", name,
        info->version ? info->version : "?", info->type, info->caps);
    return 0;
}

static int module_load_one(const char* name) {
    if (!is_valid_module_name(name)) {
        LOG_WRN("模块名非法，跳过: %s", name);
        return -1;
    }
    /* 卸载回滚防御：module_unload_one 在途引用未归零时回滚（模块仍 active），
       module_scan_diff 随即会再调 load_one——若已存在同名活跃槽位则跳过，
       避免重复加载（重复 resolve/backend 分派）。仅更新 mtime 供后续热重载。 */
    pthread_rwlock_wrlock(&g_module_lock);
    int existing = find_slot(name);
    if (existing >= 0 && g_modules[existing].active) {
        char so_path0[PATH_MAX];
        snprintf(so_path0, sizeof so_path0, "%s/%s/%s.so", g_modules_dir, name, name);
        struct stat st0;
        if (stat(so_path0, &st0) == 0) g_modules[existing].mtime = st0.st_mtime;
        pthread_rwlock_unlock(&g_module_lock);
        LOG_WRN("模块 %s 已加载（上次卸载延迟回滚），跳过重复加载", name);
        return 0;
    }
    pthread_rwlock_unlock(&g_module_lock);
    void* h = NULL;
    NspModuleInfo info;
    char hash[65] = {0};
    if (module_prepare(name, &h, &info, hash) != 0)
        return -1;
    return module_commit(name, h, &info, hash);
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
    if (info.type == NSP_MODULE_TYPE_BACKEND && (info.caps & NSP_CAP_BACKEND_IO))
        atomic_fetch_sub_explicit(&g_backend_active_count, 1, memory_order_release);
    /* 先置空槽位快照（写锁内）：后续 acquire 立即失败，不再获得新引用；
       在途 acquire（已取到 ops 且二次确认未变）持有 g_backend_slot_refs /
       g_rule_slot_refs，由下方等待循环保证归零后才 dlclose，杜绝函数指针悬垂 */
    atomic_store_explicit(&g_backend_slot_ops[slot], NULL, memory_order_release);
    if (info.caps & RULE_CAPS)
        atomic_store_explicit(&g_rule_slot_ops[slot], NULL, memory_order_release);
    chain_remove(slot);
    m->active = false;
    m->handle = NULL;
    pthread_rwlock_unlock(&g_module_lock);

    /* 等待后端在途调用完成（防 ops 指针悬垂 SIGSEGV）。FTP 等后端网络操作
       可能远超 100ms（弱网/指数退避重试），若等待超时仍强行 dlclose，会让
       在途 backend_* 调用执行已卸载 .so 的代码 → SIGSEGV（热重载崩溃根因）。
       故等待加长至 ~2s；仍忙则完整回滚（恢复 active/handle/链），放弃本次
       卸载，由下次模块变更再次触发——宁可延迟卸载，绝不 dlclose 在途模块 */
    bool drained = false;
    for (int i = 0; i < 2000; i++) {
        bool busy = false;
        pthread_rwlock_rdlock(&g_module_lock);
        busy = (m->backend_refs > 0);
        pthread_rwlock_unlock(&g_module_lock);
        if (!busy && atomic_load_explicit(&g_backend_slot_refs[slot], memory_order_acquire) == 0 &&
            atomic_load_explicit(&g_rule_slot_refs[slot], memory_order_acquire) == 0) {
            drained = true;
            break;
        }
        usleep(1000);
    }
    if (!drained) {
        /* 仍有在途调用：回滚标记，保持模块加载，绝不 dlclose */
        pthread_rwlock_wrlock(&g_module_lock);
        if (info.caps & RULE_CAPS) {
            g_active_rules_count++;
            atomic_store_explicit(&g_rule_slot_ops[slot], info.ops, memory_order_release);
        }
        if (info.type == NSP_MODULE_TYPE_BACKEND && (info.caps & NSP_CAP_BACKEND_IO)) {
            atomic_fetch_add_explicit(&g_backend_active_count, 1, memory_order_release);
            atomic_store_explicit(&g_backend_slot_ops[slot], info.ops, memory_order_release);
        }
        chain_add(info.caps, slot);
        m->active = true;
        m->handle = h;
        pthread_rwlock_unlock(&g_module_lock);
        LOG_WRN("模块 %s 有在途调用（refs 未归零），延迟卸载", name);
        return -1;
    }

    if (info.exit) info.exit();
    dlclose(h);
    LOG("模块已卸载: %s", name);
    return 0;
}

/* 模块热插拔变更由 fuse_daemon 自动处理（原子快照分派实时生效），
   不再通知 injector 全量重挂追踪应用 */

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
            /* quiescence 门控：模块仍有活跃句柄（应用 open 中）则延迟卸载，
               等下次扫描（无应用持有）再执行——避免热重载竞态崩溃 */
            if (g_modules[i].active_handles_fn &&
                g_modules[i].active_handles_fn() > 0) {
                LOG_WRN("模块 %s 仍有活跃句柄（应用使用中），延迟卸载",
                        g_modules[i].name);
                continue;
            }
            LOG("检测到模块目录移除: %s", g_modules[i].name);
            module_unload_one(g_modules[i].name);
        }
    }
    /* 2. 加载新增 / 重载文件更新的模块 */
    for (int p = 0; p < pcount; p++) {
        int slot = find_slot(present[p]);
        if (slot < 0) {
            LOG("检测到新模块: %s", present[p]);
            module_load_one(present[p]);
        } else {
            char so[PATH_MAX];
            snprintf(so, sizeof so, "%s/%s/%s.so", g_modules_dir, present[p], present[p]);
            struct stat st;
            if (stat(so, &st) == 0 && st.st_mtime != g_modules[slot].mtime) {
                /* quiescence 门控：模块仍有活跃句柄（应用 open 中）则延迟
                   热重载，等下次扫描再执行——"无应用 open、写入完成后才热加载" */
                if (g_modules[slot].active_handles_fn &&
                    g_modules[slot].active_handles_fn() > 0) {
                    LOG_WRN("模块 %s 仍有活跃句柄（应用使用中），延迟热重载",
                            present[p]);
                    continue;
                }
                /* 哈希判定：磁盘内容与已加载模块哈希一致（mtime 变化但内容
                   未变——chmod/触摸/重复复制同一文件）→ 跳过热加载 */
                char fhash[65];
                if (sha256_file_hex(so, fhash) == 0 && g_modules[slot].hash[0] &&
                    strcmp(fhash, g_modules[slot].hash) == 0) {
                    LOG_DBG("模块 %s 文件内容未变化（哈希一致），跳过热重载", present[p]);
                    g_modules[slot].mtime = st.st_mtime;
                    continue;
                }
                LOG("模块文件已更新，热重载: %s", present[p]);
                /* 先验后换：先加载校验新模块，通过才卸载旧模块——
                   校验失败/旧模块在途调用未归零时保留内存中的旧模块 */
                void* nh = NULL;
                NspModuleInfo ninfo;
                char nhash[65] = {0};
                if (module_prepare(present[p], &nh, &ninfo, nhash) != 0) {
                    LOG_ERR("模块 %s 校验未通过，保留内存中的旧模块", present[p]);
                    continue;
                }
                if (module_unload_one(present[p]) != 0) {
                    dlclose(nh);   /* 旧模块在途引用未归零（回滚保留旧）→ 放弃新模块 */
                    LOG_WRN("模块 %s 旧实例仍有在途调用，热重载放弃（保留旧模块）",
                            present[p]);
                    continue;
                }
                module_commit(present[p], nh, &ninfo, nhash);
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

/* NspResolveResult 按需初始化（≈16.5KB 结构免全量 memset）：
   只清零标量字段与各字符串首字节，保证模块未写字段（如 basic_rules 不
   输出的 allow）有定义值；字符串本体由模块 resolve 写入后才被框架读取。 */
static inline void nsp_resolve_result_init(NspResolveResult* r) {
    r->valid = false;
    r->user_id = -1;
    r->sub_path[0] = '\0';
    r->pkg[0] = '\0';
    r->hidden = false;
    r->ro = false;
    r->allow = false;
    r->has_redir = false;
    r->redir_target[0] = '\0';
    r->has_sandbox = false;
    r->sandbox_target[0] = '\0';
    r->real_path[0] = '\0';
    r->is_redir = false;
    r->is_virtual_ancestor = false;
    r->is_redirect_target = false;
    r->is_other_app_pkg = false;
    r->is_ftp = false;
    r->ftp_backend[0] = '\0';
    r->monitor_on = false;
}

int module_dispatch_resolve(const NspQueryCtx* q, NspResolveResult* out) {
    if (!q || !out) return NSP_DISPATCH_NONE;
    /* 快速路径：无规则模块注册，零开销回退默认路径（先于 uid 层判断，
       避免无规则模块时每个请求都做路径扫描） */
    if (g_active_rules_count == 0) return NSP_DISPATCH_NONE;
    /* 框架源头规避：无 <uid>/ 用户层（挂载点根）不进行任何规则合成，
       仅 <uid>/ 之后的路径才允许规则模块响应 */
    if (!path_has_uid_layer(q->path)) return NSP_DISPATCH_NONE;

    /* S2 无锁分派：规则模块 ops 由加载/卸载（写锁内）发布进 g_rule_slot_ops
       原子快照，此处无锁遍历（免每请求 g_module_lock rwlock 往返）：
       acquire 在途引用 + 二次确认快照未变后才调用 ops（unload 置空则放弃），
       调用后 release——unload 等待引用归零后才 dlclose，杜绝悬垂调用 */
    bool any = false;
    bool first = true;
    for (int i = 0; i < MAX_MODULES; i++) {
        const NspModuleOps* ops = atomic_load_explicit(&g_rule_slot_ops[i], memory_order_acquire);
        if (!ops || !ops->resolve) continue;
        atomic_fetch_add_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
        if (atomic_load_explicit(&g_rule_slot_ops[i], memory_order_acquire) != ops) {
            /* 快照刚被 unload 置空：放弃引用，不调用 ops */
            atomic_fetch_sub_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
            continue;
        }
        if (first) {
            /* 单/首模块：直接写入调用方 out——免每模块 16KB 局部缓冲 +
               16KB 整结构拷贝（*out = r）。out 先按需初始化，保证模块
               未写字段（如 basic_rules 不输出的 allow）有定义值。 */
            nsp_resolve_result_init(out);
            int rc = ops->resolve(q, out);
            atomic_fetch_sub_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
            if (rc != 0) continue;
            if (!out->valid) continue;
            first = false;
            any = true;
            continue;
        }
        NspResolveResult r;
        nsp_resolve_result_init(&r);
        int rc = ops->resolve(q, &r);
        atomic_fetch_sub_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
        if (rc != 0) continue;
        if (!r.valid) continue;
        /* 多模块并集聚合：hidden/ro/allow 任一命中即生效；
           redir/sandbox 取第一个命中（模块注册顺序即优先级） */
        out->hidden = out->hidden || r.hidden;
        out->ro = out->ro || r.ro;
        out->allow = out->allow || r.allow;
        if (!out->has_redir && r.has_redir) {
            out->has_redir = true;
            strcpy(out->redir_target, r.redir_target);   /* 模块 out 字段，NUL 结尾 */
        }
        if (!out->has_sandbox && r.has_sandbox) {
            out->has_sandbox = true;
            strcpy(out->sandbox_target, r.sandbox_target);
        }
        if (!out->is_redir && r.is_redir) {
            out->is_redir = true;
            strcpy(out->real_path, r.real_path);
        }
        out->is_virtual_ancestor = out->is_virtual_ancestor || r.is_virtual_ancestor;
        out->is_redirect_target = out->is_redirect_target || r.is_redirect_target;
        out->is_other_app_pkg = out->is_other_app_pkg || r.is_other_app_pkg;
    }
    return any ? NSP_DISPATCH_OK : NSP_DISPATCH_NONE;
}

int module_dispatch_probe(const NspQueryCtx* q, NspProbeResult* out) {
    if (!q || !out) return NSP_DISPATCH_NONE;
    /* 快速路径：无规则模块注册，零开销回退（不过滤任何条目） */
    if (g_active_rules_count == 0) return NSP_DISPATCH_NONE;
    /* 注意：不做 path_has_uid_layer 拦截——vfs_readdir 的条目级 probe 传入
       的是剥离 <uid>/ 后的条目路径（如 /secret.txt），拦截会误伤隐藏判定；
       probe 只判 hidden/redirect_target，不合成虚拟目录，挂载点根由
       resolve/readdir_extra 的拦截兜底 */
    /* S2：probe 已无锁化（规则槽位快照），直接复用 locked 实现 */
    return module_dispatch_probe_locked(q, out);
}

/* readdir 批量过滤：S2 无锁化后不再持有模块锁（槽位快照自保护），
   返回 0 成功（调用方仍须配对 module_probe_unlock，现为空操作）；
   -1 = 无规则模块。 */
int module_probe_lock(void) {
    if (g_active_rules_count == 0) return -1;
    return 0;
}

void module_probe_unlock(void) {
    /* S2：无锁化后无需解锁 */
}

/* 条目级探测：基于规则槽位原子快照无锁分派（免 readdir 循环持有
   g_module_lock）。acquire 在途引用 + 二次确认快照未变后才调用 ops，
   调用后 release——unload 等待引用归零后才 dlclose */
int module_dispatch_probe_locked(const NspQueryCtx* q, NspProbeResult* out) {
    if (!q || !out) return NSP_DISPATCH_NONE;
    if (g_active_rules_count == 0) return NSP_DISPATCH_NONE;
    bool any = false;
    for (int i = 0; i < MAX_MODULES; i++) {
        const NspModuleOps* ops = atomic_load_explicit(&g_rule_slot_ops[i], memory_order_acquire);
        if (!ops || !ops->probe) continue;
        atomic_fetch_add_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
        if (atomic_load_explicit(&g_rule_slot_ops[i], memory_order_acquire) != ops) {
            /* 快照刚被 unload 置空：放弃引用，不调用 ops */
            atomic_fetch_sub_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
            continue;
        }
        NspProbeResult r;
        memset(&r, 0, sizeof r);
        int rc = ops->probe(q, &r);
        atomic_fetch_sub_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
        if (rc != 0) continue;
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
    return any ? NSP_DISPATCH_OK : NSP_DISPATCH_NONE;
}

/* 后端路径查找：基于后端槽位原子快照无锁分派（免每请求 rwlock + 线性扫描）。
   acquire 槽位在途引用（g_backend_slot_refs）→ 二次确认快照未变 → 调
   backend_match → 命中则返回并持引用（调用方须 module_backend_put），
   未命中则释放继续。unload 先置空快照再等引用归零，杜绝 ops 悬垂调用。 */
static int backend_scan_match(const char* path, int* slot_out, const NspModuleOps** ops_out) {
    if (!path || !ops_out) return -1;
    for (int i = 0; i < MAX_MODULES; i++) {
        const NspModuleOps* ops = atomic_load_explicit(&g_backend_slot_ops[i], memory_order_acquire);
        if (!ops || !ops->backend_match) continue;
        atomic_fetch_add_explicit(&g_backend_slot_refs[i], 1, memory_order_acq_rel);
        if (atomic_load_explicit(&g_backend_slot_ops[i], memory_order_acquire) != ops) {
            /* 快照刚被 unload 置空：放弃引用，不调用 ops */
            atomic_fetch_sub_explicit(&g_backend_slot_refs[i], 1, memory_order_acq_rel);
            continue;
        }
        if (ops->backend_match(path) == 1) {
            if (slot_out) *slot_out = i;
            *ops_out = ops;
            return 0;   /* 引用已持（g_backend_slot_refs[i]），调用方须 put */
        }
        atomic_fetch_sub_explicit(&g_backend_slot_refs[i], 1, memory_order_acq_rel);
    }
    return -1;
}

int module_backend_lookup(const char* path, const NspModuleOps** ops_out) {
    return backend_scan_match(path, NULL, ops_out);
}

int module_backend_lookup_slot(const char* path, int* slot_out, const NspModuleOps** ops_out) {
    return backend_scan_match(path, slot_out, ops_out);
}

/* 槽位快速分派：无锁读原子快照 + 在途引用（免路径解析/线性扫描/backend_match）。
   安全性：unload 先原子置空快照再等待引用归零（见 module_unload_one），
   acquire 在取引用后二次确认快照未变——若快照刚被置空则放弃引用返回 -1，
   保证调用方绝不会在 dlclose 之后使用 ops 函数指针。 */
int module_backend_acquire_slot(int slot, const NspModuleOps** ops_out) {
    if (!ops_out || slot < 0 || slot >= MAX_MODULES) return -1;
    const NspModuleOps* ops = atomic_load_explicit(&g_backend_slot_ops[slot], memory_order_acquire);
    if (!ops) return -1;
    atomic_fetch_add_explicit(&g_backend_slot_refs[slot], 1, memory_order_acq_rel);
    if (atomic_load_explicit(&g_backend_slot_ops[slot], memory_order_acquire) != ops) {
        /* 快照刚被 unload 置空：放弃引用，不调用 ops */
        atomic_fetch_sub_explicit(&g_backend_slot_refs[slot], 1, memory_order_acq_rel);
        return -1;
    }
    *ops_out = ops;
    return 0;
}

void module_backend_release_slot(int slot) {
    if (slot < 0 || slot >= MAX_MODULES) return;
    atomic_fetch_sub_explicit(&g_backend_slot_refs[slot], 1, memory_order_acq_rel);
}

/* 释放 backend_* 在途引用（与 module_backend_lookup / acquire_slot 配对；
   热卸载等待 g_backend_slot_refs 归零后才 dlclose）。
   快路径：槽位原子快照中按 ops 指针定位并递减（模块仍加载，免 rwlock）。
   慢路径：槽位已被 unload 置空（模块卸载中、在途 lookup 尚未 put）——
   ops 指针比较不 deref；模块条目在引用归零前不会被 dlclose，读锁下扫描
   g_modules 定位槽位索引（槽位号 == g_modules 下标）后递减。 */
void module_backend_put(const NspModuleOps* ops) {
    if (!ops) return;
    for (int i = 0; i < MAX_MODULES; i++) {
        if (atomic_load_explicit(&g_backend_slot_ops[i], memory_order_acquire) == ops) {
            atomic_fetch_sub_explicit(&g_backend_slot_refs[i], 1, memory_order_acq_rel);
            return;
        }
    }
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count; i++) {
        if (g_modules[i].info.ops == ops) {
            atomic_fetch_sub_explicit(&g_backend_slot_refs[i], 1, memory_order_acq_rel);
            break;
        }
    }
    pthread_rwlock_unlock(&g_module_lock);
}

bool module_backend_active(void) {
    /* 无锁读：计数由模块加载/卸载（写锁内）维护，vfs_read/write 热路径
       每请求免一次 rwlock 往返（绝大多数本地文件场景计数为 0 直接短路） */
    return atomic_load_explicit(&g_backend_active_count, memory_order_acquire) > 0;
}

int module_dispatch_readdir(const NspQueryCtx* q, const char* sub_path, int user_id,
                            const char* pkg, bool is_root, NspDirEntry* out, int max) {
    if (!q || !out || max <= 0) return 0;
    /* 框架源头规避：无 <uid>/ 用户层（挂载点根，user_id<0）不合成任何模块
       虚拟目录条目，仅 <uid>/ 之后的路径才允许模块 readdir_extra 响应。
       注意：此处用 user_id 判断而非 q->path——vfs_readdir 传入的 q->path 是
       剥离 <uid>/ 后的 sub_path（如 /0/ → /），不能反映是否在用户层内 */
    if (user_id < 0) return 0;
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
