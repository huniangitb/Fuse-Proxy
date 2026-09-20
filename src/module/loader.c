#define _GNU_SOURCE
#include "module_loader.h"
#include "common.h"
#include "nsp_util.h"
#include "fault_fence.h"
#include "module_guard.h"
#include "../core/sha256.h"
#include <dlfcn.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/inotify.h>
#include <sys/file.h>
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
    void* handle;       /* dlopen 句柄 */
    NspModuleInfo info; /* 静态信息拷贝 */
    time_t mtime;       /* .so 文件 mtime，热重载检测 */
    bool active;
    _Atomic int backend_refs; /* 后端 ops 在途引用计数（防热卸载 dlclose 悬垂） */
    int (*active_handles_fn)(void); /* 可选：活跃句柄查询（模块导出 nsp_module_active_handles），
                                        热重载 quiescence 门控——有应用 open 时延迟卸载/重载 */
    char hash[65]; /* 已加载 .so 文件的 SHA-256（框架计算，加载时存入）：
                                        热重载时与磁盘哈希比对——一致则内容未变化，跳过热加载 */
    /* ---- 熔断/ban（Phase 1a/1b）：module_guard 维护 ---- */
    _Atomic unsigned err_count;      /* 滑动窗口内错误计数（1b 熔断器） */
    _Atomic time_t err_window_start; /* 窗口起点（首次错误时刻） */
    _Atomic bool banned;             /* 已 ban：崩溃恢复/熔断触发后置位，
                                        扫描线程见 .so 哈希与 ban 记录一致则不重载 */
    char ban_reason[96];             /* ban 原因（日志/健康快照展示） */
} ModuleEntry;

/* 模块故障上报（围栏 NSP_FENCE_FAULT / 校验失败汇聚点）：
   槽位置毒（原子置空快照，规则立即失效）→ 等待在途引用归零 →
   exit/dlclose → 落盘 ban 记录。
   由 module_guard 在确认故障后调用（一次）；本函数幂等（banned/active
   标志去重）。返回 0 成功，-1 失败（已记日志）。 */
int module_fault_poison(int slot, const char* reason);

/* ban 记录文件：<modules_dir>/.banned，每行 `模块名|SHA256|原因|时间戳`。
   加载/热重载前查询：哈希一致 → 拒绝加载（防崩溃-重载震荡）；
   哈希变化（新 .so）→ 移除该记录并允许加载（版本更新自愈）。 */
static bool module_ban_lookup(const char* name, const char* hash, char reason_out[96]);
static void module_ban_record(const char* name, const char* hash, const char* reason);

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
static _Atomic(int) g_backend_slot_refs[MAX_MODULES]; /* 槽位在途引用（acquire 配对 release） */
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

static const char* api_get_real_root(void) {
    return g_real_root;
}

/* 框架参数（module_system_init 传入） */
static char g_fw_rules_path[PATH_MAX] = {0};
static uint32_t g_fw_flags = 0;
/* 模块目录（默认 MODULES_DIR 宏，可经 --modules-dir 覆盖） */
static char g_modules_dir[PATH_MAX] = MODULES_DIR;

static const char* api_get_rules_path(void) {
    return g_fw_rules_path[0] ? g_fw_rules_path : NULL;
}
static uint32_t api_get_flags(void) {
    return g_fw_flags;
}

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
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-'))
            return false;
    }
    return true;
}

#define RULE_CAPS (NSP_CAP_REDIRECT | NSP_CAP_SANDBOX | NSP_CAP_HIDE | NSP_CAP_ALLOW | NSP_CAP_RO)

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
        LOG_ERR("模块 %s ABI 不匹配 (magic=0x%x abi=%u，期望 0x%x/%u)", name, info->magic,
                info->abi_version, NSP_MODULE_MAGIC, NSP_MODULE_ABI_VERSION);
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
                LOG_ERR("模块 %s 自哈希与文件哈希不一致（文件被修改/替换？），拒绝加载", name);
                dlclose(h);
                return -7;
            }
        }
    }
    /* init 在锁外调用（经调用围栏：init 崩溃被 longjmp 恢复而非带崩
       框架），成功后才登记。init 尚未 commit（无正式槽位），用试探槽位
       g_module_count 注册归因（monitor 线程单线程扫描，与 commit 无竞态）。
       init 崩溃落盘 ban：防 5s 扫描循环反复重试加载崩溃模块。 */
    if (info->init) {
        int tent_slot = g_module_count < MAX_MODULES ? g_module_count : 0;
        fault_fence_register_slot(tent_slot, name, h);
        int irc = nsp_fence_init_call(tent_slot, "init", info->init, &g_api);
        if (irc == NSP_FENCE_FAULT) {
            LOG_ERR(
                "[MOD_ERR] module=%s op=init reason=init 崩溃被围栏恢复 detail=拒绝加载并落盘 ban",
                name);
            module_ban_record(name, hash_out, "init crash");
            fault_fence_unregister_slot(tent_slot);
            dlclose(h);
            return -5;
        }
        if (irc != 0) {
            LOG_ERR("模块 %s init 失败 (rc=%d)", name, irc);
            fault_fence_unregister_slot(tent_slot);
            dlclose(h);
            return -5;
        }
        fault_fence_unregister_slot(tent_slot); /* commit 时按正式槽位再注册 */
    }
    *h_out = h;
    *info_out = *info;
    return 0;
}

/* 登记已校验模块到槽位（写锁内发布原子快照/链），并存入文件哈希 */
static int module_commit(const char* name, void* h, const NspModuleInfo* info, const char* hash) {
    char so_path[PATH_MAX];
    snprintf(so_path, sizeof so_path, "%s/%s/%s.so", g_modules_dir, name, name);
    pthread_rwlock_wrlock(&g_module_lock);
    /* 槽位复用：毒化/卸载后的非活跃槽位可复用，否则反复 ban→更新→新槽
       16 次后注册表满拒绝一切新模块（DoS 上限）。优先复用同名非活跃槽。
       置毒超时（在途引用未归零、跳过 dlclose）槽位不可复用：.so 仍映射且
       有在途调用，复用会混淆引用计数与快照。 */
    int slot = -1;
    for (int i = 0; i < g_module_count; i++) {
        if (!g_modules[i].active && strcmp(g_modules[i].name, name) == 0 &&
            atomic_load_explicit(&g_backend_slot_refs[i], memory_order_acquire) == 0 &&
            atomic_load_explicit(&g_rule_slot_refs[i], memory_order_acquire) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        for (int i = 0; i < g_module_count; i++) {
            if (!g_modules[i].active &&
                atomic_load_explicit(&g_backend_slot_refs[i], memory_order_acquire) == 0 &&
                atomic_load_explicit(&g_rule_slot_refs[i], memory_order_acquire) == 0) {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0) {
        if (g_module_count >= MAX_MODULES) {
            pthread_rwlock_unlock(&g_module_lock);
            LOG_ERR("模块注册表已满，拒绝 %s", name);
            if (info->exit) info->exit();
            dlclose(h);
            return -6;
        }
        slot = g_module_count++;
    } else {
        /* 复用槽位：清零残留 guard/ban 状态（旧错误不跨加载周期继承） */
        module_guard_reset(slot);
    }
    ModuleEntry* m = &g_modules[slot];
    memset(m, 0, sizeof *m);
    strncpy(m->name, name, sizeof m->name - 1);
    m->handle = h;
    m->info = *info; /* 浅拷贝：info->ops 指针有效 */
    /* 可选活跃句柄查询（热重载 quiescence 门控）：模块导出则使用，缺省视为 0 */
    m->active_handles_fn = (int (*)(void))dlsym(h, "nsp_module_active_handles");
    if (hash && hash[0]) strncpy(m->hash, hash, sizeof m->hash - 1);
    m->active = true;
    struct stat st;
    if (stat(so_path, &st) == 0) m->mtime = st.st_mtime;
    fault_fence_register_slot(slot, name, h);
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

    LOG("模块已加载: %s v%s (类型=%u caps=0x%x)", name, info->version ? info->version : "?",
        info->type, info->caps);
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
    if (module_prepare(name, &h, &info, hash) != 0) return -1;
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

    /* exit 经围栏：正常模块 exit 崩溃概率极低，但崩溃同样不可带崩
       框架（longjmp 恢复后继续 dlclose）。注意：此处 slot 仍有效
       （槽位快照已置空但注册表保留至 dlclose 后注销）。 */
    if (info.exit) {
        int erc = nsp_fence_exit_call(slot, "exit", info.exit);
        if (erc == NSP_FENCE_FAULT)
            LOG_WRN(
                "[MOD_ERR] module=%s op=exit reason=exit 崩溃被围栏恢复 detail=跳过 exit 直接 dlclose",
                name);
    }
    dlclose(h);
    fault_fence_unregister_slot(slot);
    /* 复位熔断器记账：重载时窗口计数/累计错误不应继承上一轮加载周期的数据，
       否则旧错误会跨加载周期累积，误触熔断 */
    module_guard_reset(slot);
    LOG("模块已卸载: %s", name);
    return 0;
}

/* ================= ban 记录（崩溃/熔断后防重载震荡） =================
 * <modules_dir>/.banned，每行: 模块名|SHA256|原因(不含|)|时间戳
 * 查询语义：同名记录存在且哈希一致 → ban 生效；哈希不同（.so 已更新）
 * → 记录失效，重写文件移除该行并允许加载（版本更新自愈）。
 * 运行上下文：monitor 线程 / FUSE 线程（普通上下文，可文件 I/O）。 */

static char g_banned_path[PATH_MAX] = {0};

static void banned_path_init(void) {
    if (!g_banned_path[0])
        snprintf(g_banned_path, sizeof g_banned_path, "%s/.banned", g_modules_dir);
}

static bool module_ban_lookup(const char* name, const char* hash, char reason_out[96]) {
    banned_path_init();
    if (!name || !name[0]) return false;
    FILE* fp = fopen(g_banned_path, "r");
    if (!fp) return false; /* 无 ban 记录 */
    /* 共享锁：防与置毒线程追加/重写并发读到半行 */
    flock(fileno(fp), LOCK_SH);
    char line[512];
    /* rewrite 缓冲放大到 64KB：ban 多时不静默丢行；仍溢出则放弃重写保旧文件 */
    static char rewrite[65536];
    rewrite[0] = '\0';
    size_t rl = 0;
    bool found = false, stale = false, overflow = false, has_name = false;
    bool hash_empty = (!hash || !hash[0]);
    while (fgets(line, sizeof line, fp)) {
        size_t len = strlen(line);
        /* fgets 截断（行超 511 且无换行）：残片当新行会误判，整行丢弃 */
        if (len == sizeof line - 1 && line[len - 1] != '\n') {
            int c;
            do {
                c = fgetc(fp);
            } while (c != '\n' && c != EOF);
            continue;
        }
        if (len && line[len - 1] == '\n') line[--len] = '\0';
        /* 保存原始完整行（含 hash|reason|timestamp），防止截断后丢失 */
        char original[512];
        strncpy(original, line, sizeof original - 1);
        original[sizeof original - 1] = '\0';
        char* l1 = strchr(line, '|');
        if (!l1) continue;
        *l1 = '\0';
        char* lname = line;
        if (strcmp(lname, name) != 0) {
            /* 用原始完整行写入 rewrite（非截断后的仅模块名） */
            size_t olen = strlen(original);
            if (rl + olen + 2 < sizeof rewrite) {
                strcat(rewrite, original);
                strcat(rewrite, "\n");
                rl = strlen(rewrite);
            } else
                overflow = true;
            continue;
        }
        has_name = true;
        /* 同名：比对哈希 */
        char* l2 = strchr(l1 + 1, '|');
        char lhash[65] = {0};
        if (l2) {
            size_t hl = (size_t)(l2 - (l1 + 1));
            if (hl >= sizeof lhash) hl = sizeof lhash - 1;
            memcpy(lhash, l1 + 1, hl);
        }
        bool same_hash = (hash && hash[0] && lhash[0] && strcmp(hash, lhash) == 0);
        if (same_hash) {
            found = true;
            if (reason_out && l2) {
                char* l3 = strchr(l2 + 1, '|');
                size_t rl2 = l3 ? (size_t)(l3 - (l2 + 1)) : strlen(l2 + 1);
                if (rl2 >= 96) rl2 = 95;
                memcpy(reason_out, l2 + 1, rl2);
                reason_out[rl2] = '\0';
            }
            /* 命中行同样保留进 rewrite（ban 未解除，不删除） */
            size_t olen = strlen(original);
            if (rl + olen + 2 < sizeof rewrite) {
                strcat(rewrite, original);
                strcat(rewrite, "\n");
                rl = strlen(rewrite);
            } else
                overflow = true;
        } else {
            /* 哈希为空（sha 失败）时不判 stale：保守命中防坏模块无限重载 */
            if (hash_empty) {
                found = true;
                if (reason_out) snprintf(reason_out, 96, "hash-unavailable 保守命中");
                size_t olen = strlen(original);
                if (rl + olen + 2 < sizeof rewrite) {
                    strcat(rewrite, original);
                    strcat(rewrite, "\n");
                    rl = strlen(rewrite);
                } else
                    overflow = true;
            } else {
                stale = true; /* 哈希变化：记录失效，重写时丢弃该行 */
            }
        }
    }
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
    if (stale && !found && !overflow) {
        /* 原子重写：tmp+rename，崩溃掉电不丢全部 ban */
        char tmp[PATH_MAX + 8];
        snprintf(tmp, sizeof tmp, "%s.tmp", g_banned_path);
        FILE* w = fopen(tmp, "w");
        if (w) {
            flock(fileno(w), LOCK_EX);
            fputs(rewrite, w);
            fflush(w);
            int fd = fileno(w);
            fsync(fd);
            flock(fileno(w), LOCK_UN);
            fclose(w);
            rename(tmp, g_banned_path);
        }
    }
    (void)has_name;
    return found;
}

static void module_ban_record(const char* name, const char* hash, const char* reason) {
    banned_path_init();
    if (!name || !name[0]) return;
    FILE* fp = fopen(g_banned_path, "a");
    if (!fp) return;
    flock(fileno(fp), LOCK_EX);
    time_t now = time(NULL);
    /* reason 为固定串（不含 '|'），name 受 is_valid_module_name 约束，防格式破坏 */
    fprintf(fp, "%s|%s|%s|%ld\n", name, hash ? hash : "", reason ? reason : "unknown", (long)now);
    fflush(fp);
    fsync(fileno(fp));
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
}

/* ================= 模块置毒（崩溃恢复/熔断触发的强制卸载） ================= */
/*
 * 与 module_unload_one 的语义差异（崩溃不可回滚）：
 *   - 在途引用等待超时不恢复模块：槽位快照保持置空（规则持续失效），
 *     跳过 dlclose（.so 保持映射，待引用自然归零后无人使用）
 *   - exit 仍须经围栏调用（模块自有线程只能由 exit 停掉，否则 dlclose 后
 *     残留线程踩空即带崩 daemon）；仅当 exit 自身崩溃（无法确认线程已停）
 *     才保持 .so 映射不 dlclose
 *   - 落盘 ban 记录：同哈希 .so 在本 daemon 生命周期内不再加载
 * 幂等：banned/active 标志去重，重复上报直接返回 0。
 */
int module_fault_poison(int slot, const char* reason) {
    if (slot < 0 || slot >= MAX_MODULES) return -1;
    pthread_rwlock_rdlock(&g_module_lock);
    if (slot >= g_module_count) {
        pthread_rwlock_unlock(&g_module_lock);
        return -1;
    }
    ModuleEntry* m = &g_modules[slot];
    if (atomic_load_explicit(&m->banned, memory_order_acquire)) {
        pthread_rwlock_unlock(&g_module_lock);
        return 0; /* 已置毒，幂等 */
    }
    /* 拷贝卸载所需信息（锁外等待） */
    char name[64] = {0}, hash[65] = {0};
    strncpy(name, m->name, sizeof name - 1);
    if (m->hash[0]) strncpy(hash, m->hash, sizeof hash - 1);
    void* h = m->handle;
    NspModuleInfo info = m->info;
    bool was_active = m->active;
    pthread_rwlock_unlock(&g_module_lock);

    /* 关键顺序（修复重载竞态）：ban 记录必须**先于槽位置空**落盘。
       置毒会把 active 置 false → find_slot 返回 -1 → 扫描线程走
       "加载新模块"分支；而 .banned 写入被 inotify 监听的 modules 目录
       会触发扫描。若 ban 落盘晚于槽位置空，扫描可能读到空/不完整的
       .banned（fclose 前）而放行重载，把刚熔断/崩溃恢复的坏模块重新
       加载回来，规则复活——熔断/崩溃防护失效。先落盘 ban 保证：槽位
       变为可重载时 ban 已完整在盘，任何后续扫描均命中跳过。
       早期 IN_CREATE 触发的扫描此刻槽位仍 active → 走"热重载"分支 →
       mtime 未变 → 跳过，安全。 */
    atomic_store_explicit(&m->banned, true, memory_order_release);
    if (reason) {
        strncpy(m->ban_reason, reason, sizeof m->ban_reason - 1);
        m->ban_reason[sizeof m->ban_reason - 1] = '\0';
    }
    module_ban_record(name, hash, reason);

    if (!was_active || !h) {
        /* 槽位本就不活跃（加载失败路径）：ban 已落盘，无需进一步处理 */
        LOG_ERR("[MOD_ERR] module=%s op=poison reason=%s detail=槽位非活跃,ban 已落盘", name,
                reason ? reason : "(null)");
        return 0;
    }

    LOG_ERR("[MOD_ERR] module=%s op=poison reason=%s detail=置毒卸载:槽位快照置空,规则立即失效",
            name, reason ? reason : "(null)");

    /* 写锁内：计数回退 + 快照置空 + 摘链（与 unload 同序，防在途 acquire） */
    pthread_rwlock_wrlock(&g_module_lock);
    if (info.caps & RULE_CAPS) {
        if (g_active_rules_count > 0) g_active_rules_count--;
    }
    if (info.type == NSP_MODULE_TYPE_BACKEND && (info.caps & NSP_CAP_BACKEND_IO))
        atomic_fetch_sub_explicit(&g_backend_active_count, 1, memory_order_release);
    atomic_store_explicit(&g_backend_slot_ops[slot], NULL, memory_order_release);
    if (info.caps & RULE_CAPS)
        atomic_store_explicit(&g_rule_slot_ops[slot], NULL, memory_order_release);
    chain_remove(slot);
    m->active = false;
    m->handle = NULL;
    pthread_rwlock_unlock(&g_module_lock);

    /* 等待在途引用归零（崩溃线程已 longjmp 返回会释放；其他线程的合法
       在途 backend 调用完成即释放）。超时不恢复（区别于 unload） */
    bool drained = false;
    for (int i = 0; i < 2000; i++) {
        if (atomic_load_explicit(&g_backend_slot_refs[slot], memory_order_acquire) == 0 &&
            atomic_load_explicit(&g_rule_slot_refs[slot], memory_order_acquire) == 0) {
            drained = true;
            break;
        }
        usleep(1000);
    }
    if (!drained) {
        LOG_WRN("模块 %s 置毒后在途引用未归零，跳过 dlclose（.so 保持映射,规则持续失效）", name);
        fault_fence_unregister_slot(slot);
        return 0; /* ban 已在槽位置空前落盘 */
    }

    /* exit 必须调（经围栏）才能 dlclose：模块可能持有**仍在运行的 pthread**
       （如 ftp_module 的 ftp.conf 监视线程），而 exit 是模块停掉它们的唯一
       途径（约定由模块在 exit 内 join）。dlclose 解除镜像映射后，残留线程
       继续执行失效代码即 SIGSEGV——且该线程不在任何围栏窗口内（非框架发起
       的调用），归因失败 → 走原崩溃处理器 dump + re-raise → 整个 daemon
       死亡（历史现象：置毒后 daemon 必崩，崩溃线程名恒为模块自有线程）。
       "崩溃模块代码不可信"不构成跳过 exit 的理由：nsp_fence_exit_call 正是
       为安全调用不可信模块代码而设，exit 内二次崩溃被 longjmp 收敛。
       唯一不能 dlclose 的情形是 exit 自身崩溃——那说明无法确认线程已停，
       此时保持 .so 映射（同 !drained 分支的"绝不 dlclose 存活模块"）。
       exit 缺失视为模块声明无清理需求，与优雅卸载路径同样直接 dlclose。 */
    bool can_unload = true;
    if (info.exit) {
        int erc = nsp_fence_exit_call(slot, "exit", info.exit);
        if (erc == NSP_FENCE_FAULT) {
            can_unload = false;
            LOG_WRN("[MOD_ERR] module=%s op=exit reason=exit 崩溃被围栏恢复 "
                    "detail=无法确认模块线程已停,保持 .so 映射不 dlclose",
                    name);
        }
    }
    if (!can_unload) {
        fault_fence_unregister_slot(slot);
        LOG_ERR("[MOD_ERR] module=%s op=poison reason=%s detail=槽位已置空,规则立即失效,"
                ".so 保持映射（exit 崩溃故不 dlclose）",
                name, reason ? reason : "(null)");
        return 0;
    }
    dlclose(h);
    fault_fence_unregister_slot(slot);
    LOG_ERR("[MOD_ERR] module=%s op=poison reason=%s detail=exit 完成,dlclose 完成,ban 已落盘",
            name, reason ? reason : "(null)");
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
        if (access(so, F_OK) == 0) {
            strncpy(present[pcount], de->d_name, sizeof present[pcount] - 1);
            present[pcount][sizeof present[pcount] - 1] = '\0';
            pcount++;
        }
    }
    closedir(d);

    /* 1. 卸载目录中已消失的模块 */
    for (int i = 0; i < g_module_count; i++) {
        if (!g_modules[i].active) continue;
        bool found = false;
        for (int p = 0; p < pcount; p++) {
            if (strcmp(present[p], g_modules[i].name) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            /* quiescence 门控：模块仍有活跃句柄（应用 open 中）则延迟卸载，
               等下次扫描（无应用持有）再执行——避免热重载竞态崩溃 */
            if (g_modules[i].active_handles_fn && g_modules[i].active_handles_fn() > 0) {
                LOG_WRN("模块 %s 仍有活跃句柄（应用使用中），延迟卸载", g_modules[i].name);
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
            /* ban 检查：崩溃/熔断被卸载的模块，.so 哈希与 ban 记录一致时
               不重载（防崩溃-重载震荡）；哈希变化（版本更新）放行 */
            char so[PATH_MAX];
            snprintf(so, sizeof so, "%s/%s/%s.so", g_modules_dir, present[p], present[p]);
            char dhash[65] = {0};
            if (sha256_file_hex(so, dhash) != 0) {
                /* 哈希失败（I/O 错误/文件正写入）：延迟到下次扫描，不绕过 ban 直接加载 */
                LOG_WRN("模块 %s 哈希计算失败，延迟加载（等下次扫描）", present[p]);
                continue;
            }
            {
                char br[96] = {0};
                if (module_ban_lookup(present[p], dhash, br)) {
                    LOG_WRN(
                        "[MOD_ERR] module=%s op=scan reason=%s detail=ban 名单命中(哈希一致),跳过加载",
                        present[p], br[0] ? br : "unknown");
                    continue;
                }
            }
            LOG("检测到新模块: %s", present[p]);
            module_load_one(present[p]);
        } else {
            char so[PATH_MAX];
            snprintf(so, sizeof so, "%s/%s/%s.so", g_modules_dir, present[p], present[p]);
            struct stat st;
            if (stat(so, &st) == 0 && st.st_mtime != g_modules[slot].mtime) {
                /* quiescence 门控：模块仍有活跃句柄（应用 open 中）则延迟
                   热重载，等下次扫描再执行——"无应用 open、写入完成后才热加载" */
                if (g_modules[slot].active_handles_fn && g_modules[slot].active_handles_fn() > 0) {
                    LOG_WRN("模块 %s 仍有活跃句柄（应用使用中），延迟热重载", present[p]);
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
                    dlclose(nh); /* 旧模块在途引用未归零（回滚保留旧）→ 放弃新模块 */
                    LOG_WRN("模块 %s 旧实例仍有在途调用，热重载放弃（保留旧模块）", present[p]);
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
    nsp_set_thread_name("nsp_modmon");
    int inotify_fd = -1;
    int wd = -1;
    while (!g_log_shutdown) {
        if (inotify_fd < 0) {
            inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
            if (inotify_fd < 0) {
                sleep(2);
                continue;
            }
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
        for (char* p = buf; p < buf + len;) {
            struct inotify_event* ev = (struct inotify_event*)p;
            if (ev->mask & IN_IGNORED) watch_invalidated = true;
            p += sizeof(struct inotify_event) + ev->len;
        }
        sleep(1); /* 归并窗口：多个叠加事件只重扫一次 */
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
    if (rules_path) strncpy(g_fw_rules_path, rules_path, sizeof g_fw_rules_path - 1);
    if (modules_dir && modules_dir[0])
        strncpy(g_modules_dir, modules_dir, sizeof g_modules_dir - 1);
    g_fw_flags = flags;
    mkdir_recursive(g_modules_dir);
    module_scan_diff();
    pthread_t tid;
    if (pthread_create(&tid, NULL, module_monitor_thread, NULL) == 0) pthread_detach(tid);
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

    /* S2 无锁分派 + Phase 1b 守卫：规则模块 ops 由加载/卸载（写锁内）
       发布进 g_rule_slot_ops 原子快照，此处无锁遍历（免每请求 rwlock
       往返）：acquire 在途引用 + 二次确认快照未变 → 围栏调用（崩溃
       longjmp 恢复）→ canary/字符串/值域校验（野指针/越界写指纹）→
       异常计入熔断器（窗口内达阈值 → 置毒卸载，规则自动失效）。
       结果统一经 canary 守卫缓冲中转：模块越界写破坏 canary 即弃用
       该模块结果（16KB 拷贝仅在模块命中时发生，代价 ~1µs，换取对
       调用方栈缓冲的完整性保护——原"首模块直写 out"快路径移除。
       调用方约定：out 已置 rr.valid=false（VFS_SETUP_CORE），首模块
       命中时整结构拷贝覆盖全部字段，无需额外初始化。 */
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
        NspResolveGuard gd;
        nsp_guard_resolve_init(&gd);
        int rc = nsp_fence_resolve(i, "resolve", ops->resolve, q, &gd.r);
        atomic_fetch_sub_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
        if (rc == NSP_FENCE_FAULT) {
            module_guard_fault(i, "resolve", q->path); /* 崩溃：单次即置毒 */
            continue;
        }
        if (rc != 0) {
            /* 负值错误码 / 围栏 BADFN（防御）：计入熔断窗口 */
            module_guard_error(i, "resolve", rc, q->path, "模块返回异常");
            continue;
        }
        if (!nsp_guard_resolve_ok(&gd)) {
            module_guard_error(i, "resolve", 0, q->path, "输出 canary 破坏(越界写)");
            continue;
        }
        char det[64];
        if (nsp_guard_validate_resolve(&gd.r, det, sizeof det) != 0) {
            module_guard_error(i, "resolve", 0, q->path, det);
            continue;
        }
        if (!gd.r.valid) continue;
        if (first) {
            /* 首个命中模块：整结构拷贝到调用方 out（canary 校验通过后） */
            *out = gd.r;
            first = false;
            any = true;
            continue;
        }
        const NspResolveResult* r = &gd.r;
        /* 多模块并集聚合：hidden/ro/allow 任一命中即生效；
           redir/sandbox 取第一个命中（模块注册顺序即优先级） */
        out->hidden = out->hidden || r->hidden;
        out->ro = out->ro || r->ro;
        out->allow = out->allow || r->allow;
        if (!out->has_redir && r->has_redir) {
            out->has_redir = true;
            strcpy(out->redir_target, r->redir_target); /* 模块 out 字段，NUL 结尾（已校验） */
        }
        if (!out->has_sandbox && r->has_sandbox) {
            out->has_sandbox = true;
            strcpy(out->sandbox_target, r->sandbox_target);
        }
        if (!out->is_redir && r->is_redir) {
            out->is_redir = true;
            strcpy(out->real_path, r->real_path);
        }
        out->is_virtual_ancestor = out->is_virtual_ancestor || r->is_virtual_ancestor;
        out->is_redirect_target = out->is_redirect_target || r->is_redirect_target;
        out->is_other_app_pkg = out->is_other_app_pkg || r->is_other_app_pkg;
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
   g_module_lock）+ Phase 1b 守卫（围栏 + 熔断）。probe 输出为 5 个
   bool 的小结构体，无字符串字段——越界写由栈 canary 之外的 rc/值域
   检查兜底（bool 字段被写坏只会影响过滤判定，不构成崩溃风险） */
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
        int rc = nsp_fence_probe(i, "probe", ops->probe, q, &r);
        atomic_fetch_sub_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
        if (rc == NSP_FENCE_FAULT) {
            module_guard_fault(i, "probe", q->path);
            continue;
        }
        if (rc != 0) {
            module_guard_error(i, "probe", rc, q->path, "模块返回异常");
            continue;
        }
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
        const NspModuleOps* ops =
            atomic_load_explicit(&g_backend_slot_ops[i], memory_order_acquire);
        if (!ops || !ops->backend_match) continue;
        atomic_fetch_add_explicit(&g_backend_slot_refs[i], 1, memory_order_acq_rel);
        if (atomic_load_explicit(&g_backend_slot_ops[i], memory_order_acquire) != ops) {
            /* 快照刚被 unload 置空：放弃引用，不调用 ops */
            atomic_fetch_sub_explicit(&g_backend_slot_refs[i], 1, memory_order_acq_rel);
            continue;
        }
        /* 围栏包裹：裸调用悬垂 ops 即野指针跳转（PC=fault_addr），必须经 fence */
        int mrc = nsp_fence_backend_match(i, "backend_match", ops->backend_match, path);
        if (mrc == NSP_FENCE_FAULT) {
            atomic_fetch_sub_explicit(&g_backend_slot_refs[i], 1, memory_order_acq_rel);
            module_guard_fault(i, "backend_match", path);
            continue;
        }
        if (mrc == NSP_FENCE_BADFN) {
            atomic_fetch_sub_explicit(&g_backend_slot_refs[i], 1, memory_order_acq_rel);
            continue;
        }
        if (mrc == 1) {
            if (slot_out) *slot_out = i;
            *ops_out = ops;
            return 0; /* 引用已持（g_backend_slot_refs[i]），调用方须 put */
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
    /* Phase 1b：读锁仅用于枚举快照（槽位号/能力位），ops 调用本身不持锁
       （围栏调用窗口内不得持锁——longjmp 会跳过解锁）。
       崩溃/错误经围栏+熔断上报（此时已释放读锁，无死锁风险）。 */
    int active_slots[MAX_MODULES];
    const NspModuleOps* active_ops[MAX_MODULES];
    int scount = 0;
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count && scount < MAX_MODULES; i++) {
        ModuleEntry* m = &g_modules[i];
        if (!m->active || !(m->info.caps & NSP_CAP_READDIR_EXTRA)) continue;
        if (!m->info.ops || !m->info.ops->readdir_extra) continue;
        active_slots[scount] = i;
        active_ops[scount] = m->info.ops;
        scount++;
    }
    pthread_rwlock_unlock(&g_module_lock);
    int n = 0;
    for (int s = 0; s < scount && n < max; s++) {
        int i = active_slots[s];
        const NspModuleOps* ops = active_ops[s];
        /* 槽位快照二次确认（unload 置空则跳过，与 S2 分派一致） */
        if (atomic_load_explicit(&g_rule_slot_ops[i], memory_order_acquire) != ops) continue;
        atomic_fetch_add_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
        if (atomic_load_explicit(&g_rule_slot_ops[i], memory_order_acquire) != ops) {
            atomic_fetch_sub_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
            continue;
        }
        int got = nsp_fence_readdir_extra(i, "readdir_extra", ops->readdir_extra, q, sub_path,
                                          user_id, pkg, is_root, out + n, max - n);
        atomic_fetch_sub_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
        if (got == NSP_FENCE_FAULT) {
            module_guard_fault(i, "readdir_extra", sub_path);
            continue;
        }
        if (got == NSP_FENCE_BADFN) continue; /* 函数指针 NULL：未实现，静默跳过 */
        if (got < 0) {
            module_guard_error(i, "readdir_extra", got, sub_path, "模块返回异常");
            continue;
        }
        if (got > 0) {
            /* 越界钳制：模块超额返回时已越界写 out+n，必须丢弃整批并熔断，
               否则上层栈数组 vn 累加超 max 导致栈越界读+filler 垃圾 */
            if (got > max - n) {
                module_guard_error(i, "readdir_extra", 0, sub_path, "返回条目数超限(越界写)");
                continue;
            }
            /* 条目校验：坏条目名（未终止）丢弃该批次（计入熔断） */
            bool entries_ok = true;
            for (int k = 0; k < got; k++)
                if (!nsp_guard_dir_entry_ok(out + n + k)) {
                    entries_ok = false;
                    break;
                }
            if (!entries_ok) {
                module_guard_error(i, "readdir_extra", 0, sub_path, "条目名未终止(越界写)");
                continue;
            }
            n += got;
        }
    }
    return n;
}

int module_dispatch_get_pkg(uid_t uid, pid_t tid, char* pkg_out, size_t pkg_size) {
    if (!pkg_out || pkg_size == 0) return -1;
    /* Phase 1b：同 readdir_extra——读锁仅枚举，ops 调用不持锁（围栏窗口
       内禁锁），异常经熔断上报（日志降级路径，崩溃恢复后返回 "unknown"） */
    int active_slots[MAX_MODULES];
    const NspModuleOps* active_ops[MAX_MODULES];
    int scount = 0;
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count && scount < MAX_MODULES; i++) {
        ModuleEntry* m = &g_modules[i];
        if (!m->active || !m->info.ops || !m->info.ops->get_pkg) continue;
        active_slots[scount] = i;
        active_ops[scount] = m->info.ops;
        scount++;
    }
    pthread_rwlock_unlock(&g_module_lock);
    int rc = -1;
    for (int s = 0; s < scount && rc != 0; s++) {
        int i = active_slots[s];
        const NspModuleOps* ops = active_ops[s];
        if (atomic_load_explicit(&g_rule_slot_ops[i], memory_order_acquire) != ops) continue;
        atomic_fetch_add_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
        if (atomic_load_explicit(&g_rule_slot_ops[i], memory_order_acquire) != ops) {
            atomic_fetch_sub_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
            continue;
        }
        pkg_out[0] = '\0';
        int crc = nsp_fence_get_pkg(i, "get_pkg", ops->get_pkg, uid, tid, pkg_out, pkg_size);
        atomic_fetch_sub_explicit(&g_rule_slot_refs[i], 1, memory_order_acq_rel);
        if (crc == NSP_FENCE_FAULT) {
            module_guard_fault(i, "get_pkg", NULL);
            continue;
        }
        if (crc == NSP_FENCE_BADFN) continue; /* 函数指针 NULL：未实现，静默跳过 */
        if (crc != 0) {
            module_guard_error(i, "get_pkg", crc, NULL, "模块返回异常");
            continue;
        }
        if (!nsp_guard_str_ok(pkg_out, pkg_size)) {
            module_guard_error(i, "get_pkg", 0, NULL, "pkg 输出未终止");
            continue;
        }
        rc = 0;
    }
    if (rc != 0) {
        strncpy(pkg_out, "unknown", pkg_size - 1);
        pkg_out[pkg_size - 1] = '\0';
    }
    return rc;
}

/* 健康快照（Phase 1c）：含 banned 非活跃槽位（规则已失效仍需展示） */
int module_health_snapshot(NspModuleHealth** info_out) {
    if (!info_out) return -1;
    *info_out = NULL;
    pthread_rwlock_rdlock(&g_module_lock);
    if (g_module_count == 0) {
        pthread_rwlock_unlock(&g_module_lock);
        return 0;
    }
    NspModuleHealth* arr = calloc(g_module_count, sizeof(NspModuleHealth));
    if (!arr) {
        pthread_rwlock_unlock(&g_module_lock);
        return -1;
    }
    int n = 0;
    for (int i = 0; i < g_module_count; i++) {
        ModuleEntry* m = &g_modules[i];
        if (!m->active && !atomic_load_explicit(&m->banned, memory_order_acquire))
            continue; /* 从未加载/正常卸载且无 ban 的槽位不展示 */
        NspModuleHealth* h = &arr[n];
        memset(h, 0, sizeof *h);
        strncpy(h->name, m->name, sizeof h->name - 1);
        if (m->info.version) strncpy(h->version, m->info.version, sizeof h->version - 1);
        h->caps = m->info.caps;
        h->active = m->active;
        h->banned = atomic_load_explicit(&m->banned, memory_order_acquire);
        strncpy(h->ban_reason, m->ban_reason, sizeof h->ban_reason - 1);
        h->ban_reason[sizeof h->ban_reason - 1] = '\0';
        module_guard_health(i, &h->err_count, &h->err_total, &h->last_err_time);
        n++;
    }
    pthread_rwlock_unlock(&g_module_lock);
    *info_out = arr;
    return n;
}

int module_snapshot(char names[][64], int max) {
    int n = 0;
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count && n < max; i++) {
        if (g_modules[i].active) strncpy(names[n++], g_modules[i].name, 63);
    }
    pthread_rwlock_unlock(&g_module_lock);
    return n;
}

bool module_any_loaded(void) {
    bool any = false;
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count; i++)
        if (g_modules[i].active) {
            any = true;
            break;
        }
    pthread_rwlock_unlock(&g_module_lock);
    return any;
}

int module_ops_slot(const NspModuleOps* ops) {
    if (!ops) return -1;
    for (int i = 0; i < MAX_MODULES; i++) {
        if (atomic_load_explicit(&g_backend_slot_ops[i], memory_order_acquire) == ops ||
            atomic_load_explicit(&g_rule_slot_ops[i], memory_order_acquire) == ops)
            return i;
    }
    return -1;
}

const char* module_slot_name(int slot) {
    static char slot_names[MAX_MODULES][16]; /* "slotN" 占位（无锁安全） */
    if (slot < 0 || slot >= MAX_MODULES) return "unknown";
    static _Atomic(bool) names_ready = false;
    if (!atomic_load_explicit(&names_ready, memory_order_relaxed)) {
        for (int i = 0; i < MAX_MODULES; i++)
            snprintf(slot_names[i], sizeof slot_names[i], "slot%d", i);
        atomic_store_explicit(&names_ready, true, memory_order_relaxed);
    }
    pthread_rwlock_rdlock(&g_module_lock);
    if (slot < g_module_count && g_modules[slot].active) {
        pthread_rwlock_unlock(&g_module_lock);
        return g_modules[slot].name;
    }
    pthread_rwlock_unlock(&g_module_lock);
    return slot_names[slot];
}
