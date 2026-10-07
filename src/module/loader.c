#define _GNU_SOURCE
#include "module_loader.h"
#include "common.h"
#include "nsp_util.h"
#include "fault_fence.h"
#include "module_guard.h"
#include "../daemon/fw_config.h"
#include "../daemon/fw_rules.h"
#include <dlfcn.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/inotify.h>
#include <sys/file.h>
#include <sys/mman.h> /* memfd_create：模块从内存副本加载 */
#include <fcntl.h>
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
    void* handle;       /* dlopen 句柄 */
    NspModuleInfo info; /* 静态信息拷贝 */
    time_t mtime;       /* .so 文件 mtime，热重载检测 */

    bool active;
    int mfd; /* 模块映像的 memfd（-1 = 无）：加载成功后保持打开到模块卸载——
                内存副本是模块的唯一可执行映像，提前 close 虽不解除已 dlopen 的
                映射，但会让 maps 失去 `memfd:nsp_module_<名>` 可观测证据。 */
    int (*active_handles_fn)(void); /* 可选：活跃句柄查询（模块导出 nsp_module_active_handles），
                                        热重载 quiescence 门控——有应用 open 时延迟卸载/重载 */
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

/* ban 记录文件：<modules_dir>/.banned，每行 `模块名|mtime|原因|时间戳`。
   加载/热重载前查询：mtime 一致 → 拒绝加载（防崩溃-重载震荡）；
   mtime 变化（新 .so）→ 移除该记录并允许加载（版本更新自愈）。 */
static bool module_ban_lookup(const char* name, time_t cur_mtime, char reason_out[96]);
static void module_ban_record(const char* name, time_t mtime, const char* reason);

static ModuleEntry* g_modules = NULL; /* 注册表本体：写锁内动态翻倍
                                                   （初容 MODULE_INIT_CAP） */
static int g_module_count = 0;                /* 已用槽位数（含非活跃复用槽） */
static int g_module_cap = 0;                  /* 本体容量 */
static pthread_rwlock_t g_module_lock = PTHREAD_RWLOCK_INITIALIZER;

/* 活跃后端 I/O 模块数：vfs_read/write 快速路径无锁读（原子），
   模块加载/卸载（写锁内）时更新 */
static _Atomic(int) g_backend_active_count = 0;
/* 后端槽位原子快照：module_load_one（写锁内）置 ops；module_unload_one
   先置 NULL 再等待引用归零。read/write 热路径经 module_backend_acquire_slot
   无锁读取，免 rwlock + 线性扫描 + backend_match 前缀比较。
   槽位号由 open 时编码进 fh 高位（见 fuse_daemon.c NSP_FH_BACKEND_SLOT_*）。 */
static _Atomic(const NspModuleOps*) g_backend_slot_ops[MAX_MODULES];
static _Atomic(int) g_backend_slot_refs[MAX_MODULES]; /* 槽位在途引用（acquire 配对 release） */
/* 后端槽位高水位（单调只增，写锁内发布）：无锁扫描（backend_scan_match/put/
   ops_slot）只扫 0..hwm，不扫 1024 空槽。unload 不收缩——收缩会让并发无锁读
   越界，hwm 常驻是正确性代价（一个 int）。 */
static _Atomic(int) g_backend_hwm = 0;

/* ================= 框架服务表 ================= */

/* 框架参数（module_system_init 传入） */
static char g_fw_rules_path[PATH_MAX] = {0};
/* 模块目录（默认 MODULES_DIR 宏，可经 --modules-dir 覆盖） */
static char g_modules_dir[PATH_MAX] = MODULES_DIR;
/* 监听线程停止标志与自唤醒管道（同 fw_config.c 机制）：shutdown 需要**立即**
   停住扫描线程再卸载模块，否则退出期间仍有扫描在 dlopen。 */
static volatile bool g_mod_stop = false;
static int g_mod_wake[2] = {-1, -1};
static pthread_t g_mod_tid;
static bool g_mod_thread_started = false;

/* 子目录监听：inotify 不递归，`<名>/<名>.so` 的写入事件只落在子目录上，顶层
   watch 收不到——这正是此前需要 5s 周期兜底扫描的原因。现改为两层监听：
   顶层管子目录增删（+ `.banned` 等顶层文件），每个合法模块子目录各一个 watch
   管各自 `.so` 变更；任何变更必有事件，扫描只由事件触发。稳态零唤醒。
   watch 表静态（g_subw[MAX_MODULES]=1024 项，72KB .bss），注册表本体动态；
   条目按名线性管理（数量极小）：IN_IGNORED 到达时按 wd 移除，
   每次扫描后 sync 按现存目录对账补齐。 */
static struct {
    int wd;
    char name[64];
} g_subw[MAX_MODULES];
static int g_subw_count = 0;
/* 子目录事件掩码：CLOSE_WRITE/MODIFY 覆盖拷贝写入全程，MOVED_TO/CREATE 覆盖
   原子替换与新建，DELETE/MOVED_FROM 覆盖删除，ATTRIB 覆盖 chmod/touch，
   DELETE_SELF/MOVE_SELF 覆盖子目录自身被删/移走。 */
#define NSP_SUBW_MASK                                                            \
    (IN_CLOSE_WRITE | IN_MODIFY | IN_MOVED_TO | IN_MOVED_FROM | IN_CREATE |      \
     IN_DELETE | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF)
/* 顶层掩码：子目录增删 + 顶层文件（`.banned` 追加/重写）变更 + 自身删除 */
#define NSP_TOPW_MASK                                                            \
    (IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM | IN_CLOSE_WRITE |      \
     IN_DELETE_SELF)

static const char* api_get_rules_path(void) {
    return g_fw_rules_path[0] ? g_fw_rules_path : NULL;
}

/* 正在初始化的模块名：subscribe_rules / set_config_listener 只在 init 内调用，
   框架以本变量为上下文归属（无需模块传名；加载由 monitor 线程串行执行） */
static char g_preparing_name[64] = {0};

static void api_subscribe_rules(const char* const* types, int count) {
    if (g_preparing_name[0]) fw_config_set_subscription(g_preparing_name, types, count);
}
static void api_set_config_listener(void (*cb)(const NspModuleConfig*)) {
    if (g_preparing_name[0]) fw_config_set_listener(g_preparing_name, cb);
}

static const NspFrameworkApi g_api = {
    .api_version = NSP_FRAMEWORK_API_VERSION,
    .get_rules_path = api_get_rules_path,
    .subscribe_rules = api_subscribe_rules,
    .set_config_listener = api_set_config_listener,
};

/* ================= 配置下发（框架读取 → 模块建索引） ================= */

/* 向单个模块推送当前过滤视图。经围栏调用模块监听器（模块代码可能崩溃）。
   返回 0 = 已推送或该模块未注册监听器；NSP_FENCE_FAULT = 监听器崩溃。 */
static int push_config_to_slot(int slot, const char* name) {
    void (*cb)(const NspModuleConfig*) = fw_config_listener_for(name);
    if (!cb) return 0;
    /* 取用即持引用：回调期间视图不会被并发重载释放（围栏 longjmp 恢复后仍走到
       release，故崩溃路径不泄漏引用） */
    const NspModuleConfig* cfg = fw_config_view_acquire(name);
    if (!cfg) return 0;
    int rc = nsp_fence_config_update(slot, "config_update", cb, cfg);
    fw_config_view_release(cfg);
    if (rc == NSP_FENCE_FAULT) {
        module_guard_fault(slot, "config_update", name);
        return rc;
    }
    if (rc != 0 && rc != NSP_FENCE_BADFN)
        module_guard_error(slot, "config_update", rc, name, "config_update 返回异常");
    return 0;
}

/* 配置重载钩子：遍历活跃模块推送新视图（fw_config 监听线程内同步调用）。
   跨模块调用不得持框架锁（围栏 longjmp 会跳过解锁 → 死锁），故在**读锁内**取
   槽位/名字快照并同时抬升槽位引用（unload 的排空会等待引用归零，避免推送期间
   模块被 dlclose），锁外逐个推送。 */
static void on_config_reload(void) {
    /* 快照堆分配（注册表动态化后计数无 16 上限，栈上 1024×(4+64)B=68KB
       对 FUSE 线程栈不友好；重载低频，堆快照成本可忽略） */
    int* slots = NULL;
    char (*names)[64] = NULL;
    int n = 0, cap = 0;
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count; i++) {
        if (!g_modules[i].active) continue;
        if (n >= cap) {
            int ncap = cap > 0 ? cap * 2 : 16;
            int* ns = realloc(slots, (size_t)ncap * sizeof *ns);
            char (*nn)[64] = realloc(names, (size_t)ncap * sizeof *nn);
            if (!ns || !nn) {
                free(ns == slots ? NULL : ns);
                free(nn == names ? NULL : nn);
                /* OOM：已抬升的引用逐个放下（见下），本次推送降级为部分 */
                break;
            }
            slots = ns;
            names = nn;
            cap = ncap;
        }
        atomic_fetch_add_explicit(&g_backend_slot_refs[i], 1, memory_order_acq_rel);
        slots[n] = i;
        strncpy(names[n], g_modules[i].name, sizeof(names[n]) - 1);
        names[n][sizeof(names[n]) - 1] = '\0';
        n++;
    }
    pthread_rwlock_unlock(&g_module_lock);
    for (int k = 0; k < n; k++) {
        push_config_to_slot(slots[k], names[k]);
        atomic_fetch_sub_explicit(&g_backend_slot_refs[slots[k]], 1, memory_order_acq_rel);
    }
    free(slots);
    free(names);
}

/* ================= 工具 ================= */

static bool is_valid_module_name(const char* n) {
    if (!n || !n[0] || strlen(n) >= 64) return false;
    for (const char* p = n; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-'))
            return false;
    }
    return true;
}

static int find_slot(const char* name) {
    for (int i = 0; i < g_module_count; i++)
        if (g_modules[i].active && strcmp(g_modules[i].name, name) == 0) return i;
    return -1;
}

/* ================= 加载 / 卸载 ================= */

/* 加载前拒绝的统一收口：释放映像 + 回收内存副本 fd。
   mfd 一旦创建就必须在**每条**失败路径经此回收——否则坏模块每次触发扫描
   会无界泄漏 memfd（实测：模块目录残留旧 ABI 的 .so 时每次扫描漏 1 个，累积到
   nofile 上限后 socket/open 全面 EMFILE）。h 传 NULL 表示保留 .so 映射
   （模块可能还有自有线程，见 init 崩溃路径）。 */
static int module_prepare_reject(void* h, int mfd, int rc) {
    if (h) dlclose(h);
    if (mfd >= 0) close(mfd);
    return rc;
}

/* 取 .so 文件 mtime（秒）：ban 记录的版本标识。stat 失败返回 -1——该值永不
   等于真实文件 mtime，ban 记录即不生效（fail-open），由加载尝试的瞬时失败
   路径定时重试兜底。 */
static time_t so_mtime(const char* so_path) {
    struct stat st;
    return (stat(so_path, &st) == 0) ? st.st_mtime : (time_t)-1;
}

/* 见定义处：init 已成功的实例被拒绝时的统一善后（须经围栏调 exit 再决定
   dlclose）。声明在前，因为 module_prepare 的配置下发崩溃路径就要用它。 */
static void module_reject_after_init(const char* name, void* h, const NspModuleInfo* info,
                                     int mfd, const char* why);

/* 加载并校验新模块（不注册）：0.5s 稳定性校验 + 读入内存副本 +
   dlopen + ABI/名字校验 + init。框架只校验"模块是否可用"，不做内容哈希
   （全文件 SHA-256 的算力与 I/O 相对热加载收益是无效工作；版本区分由 ban
   记录的 mtime 承担）。全部通过才返回（h_out/info_out 有效，调用方负责
   dlclose 或 module_commit）；任一失败返回负值（映像与 memfd
   均已回收，见 module_prepare_reject）。
   设计：热重载"先验后换"——先加载校验新模块，通过才卸载旧模块并登记，
   校验失败保留内存中的旧模块。 */
static int module_prepare(const char* name, void** h_out, NspModuleInfo* info_out,
                          int* mfd_out) {
    char so_path[PATH_MAX];
    snprintf(so_path, sizeof so_path, "%s/%s/%s.so", g_modules_dir, name, name);
    /* 热加载防御：dlopen 前校验 .so 文件稳定性（两次 stat 大小/时间一致）。
       模块 .so 正在被替换/拷贝时（inotify 触发扫描与文件写入竞态），
       dlopen 可能加载半写入的文件 → NspModuleInfo/init/ops 指针为垃圾值
       → 间接调用跳转未映射地址 → SIGSEGV（热加载崩溃现场 PC=垃圾地址）。
       校验窗口 0.5s：使用场景不要求低延迟热加载，稳定性优先——半写入
       窗口内一律延迟加载（延迟到下一次扫描）。 */
    struct stat st1, st2;
    memset(&st2, 0, sizeof st2);
    /* 首次 stat 失败（文件不存在/不可访问/正处替换间隙）：稳定性比对没有基准，
       继续加载等于放弃"半写入保护"（读取后的 st3 只能与未初始化的 st2 比）——
       本轮直接放弃，下一次扫描重试。旧实现用 `if (stat(...st1) == 0)` 包住整个
       稳定性块，stat 失败时 st2 保持未初始化却在下方与 st3 比较（UB）。 */
    if (stat(so_path, &st1) != 0) {
        LOG_WRN("模块 %s 的 .so 尚不可 stat（%s），放弃本轮加载", name, strerror(errno));
        return -1;
    }
    usleep(500000);
    if (stat(so_path, &st2) != 0 || st1.st_size != st2.st_size ||
        st1.st_mtime != st2.st_mtime) {
        LOG_WRN("模块 %s 的 .so 正在写入（大小/时间不稳定），延迟加载", name);
        return -1;
    }
    /* **从内存副本加载**（memfd + /proc/self/fd）：模块一旦加载，其映像就只属于
       本进程，磁盘上那份文件无论被原子替换还是**就地覆盖**（truncate + 重写）都
       伤不到运行中的模块。
       为何不能直接 dlopen(路径)：ELF 是按文件 mmap 的（file-backed），磁盘文件被
       truncate 时内核会连**已重定位**的私有页一起丢弃（unmap_mapping_range 的
       even_cows），再次访问从文件重新缺页得到的是**未重定位**的链接期值——函数
       指针变成 0x1166 之类，调用即野指针跳转；更糟的是这份损坏映像还会被 dlclose
       时的析构器（.fini_array）与进程退出时的 `_dl_fini` 再次调用，连"退出"都不
       安全（core dump 实测 `exit → _dl_fini → 0x10b0`）。内存副本彻底消除该路径。
       读入期间文件仍在写入（大小/时间与稳定性窗口观察到的不同）→ 放弃本次加载。 */
    /* memfd 名字带模块名：/proc/<pid>/maps 里呈现为 "memfd:nsp_module_<名>"，
       既能区分模块，也让"模块是否真卸载"有可观测证据（文件路径不再出现在 maps） */
    char mfd_name[128];
    snprintf(mfd_name, sizeof mfd_name, "nsp_module_%.100s", name);
    int mfd = memfd_create(mfd_name, MFD_CLOEXEC);
    if (mfd < 0) {
        LOG_ERR("模块 %s memfd_create 失败: %s", name, strerror(errno));
        return -1;
    }
    int src = open(so_path, O_RDONLY | O_CLOEXEC);
    if (src < 0) {
        LOG_ERR("模块 %s 打开失败: %s", so_path, strerror(errno));
        close(mfd);
        return -1;
    }
    char cbuf[65536];
    for (;;) {
        ssize_t rn = read(src, cbuf, sizeof cbuf);
        if (rn < 0) {
            if (errno == EINTR) continue;
            LOG_ERR("模块 %s 读取失败: %s", so_path, strerror(errno));
            close(src);
            close(mfd);
            return -1;
        }
        if (rn == 0) break;
        for (ssize_t off = 0; off < rn;) {
            ssize_t wn = write(mfd, cbuf + off, (size_t)(rn - off));
            if (wn < 0) {
                if (errno == EINTR) continue;
                LOG_ERR("模块 %s 写入内存副本失败: %s", name, strerror(errno));
                close(src);
                close(mfd);
                return -1;
            }
            off += wn;
        }
    }
    close(src);
    struct stat st3;
    if (stat(so_path, &st3) == 0 &&
        (st3.st_size != st2.st_size || st3.st_mtim.tv_sec != st2.st_mtim.tv_sec ||
         st3.st_mtim.tv_nsec != st2.st_mtim.tv_nsec)) {
        LOG_WRN("模块 %s 的 .so 在读取期间被写入，放弃本次加载", name);
        close(mfd);
        return -1;
    }
    char fdp[64];
    snprintf(fdp, sizeof fdp, "/proc/self/fd/%d", mfd);
    void* h = dlopen(fdp, RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        LOG_ERR("模块加载失败 %s(内存副本): %s", so_path, dlerror());
        close(mfd);
        return -1;
    }
    /* mfd 的所有权：**只在最终成功时**交给调用方（commit 记入 ModuleEntry，
       直到模块卸载才 close）。dlopen 之后到成功之前的每条失败路径都必须
       module_prepare_reject()，否则事件触发的每次扫描都会泄漏 memfd。 */
    NspModuleInfo* info = (NspModuleInfo*)dlsym(h, NSP_MODULE_INFO_SYMBOL);
    if (!info) {
        LOG_ERR("模块 %s 未导出 %s 符号", name, NSP_MODULE_INFO_SYMBOL);
        return module_prepare_reject(h, mfd, -2);
    }
    if (info->magic != NSP_MODULE_MAGIC || info->abi_version != NSP_MODULE_ABI_VERSION) {
        LOG_ERR("模块 %s ABI 不匹配 (magic=0x%x abi=%u，期望 0x%x/%u)", name, info->magic,
                info->abi_version, NSP_MODULE_MAGIC, NSP_MODULE_ABI_VERSION);
        /* 落 ban：本文件按 mtime 记住，扫描不再反复尝试（否则每次扫描一条 ERROR +
           一次 0.5s 稳定性等待 + 整份 .so 复制进新 memfd）；
           文件一变（真更新）即放行，不挡正常升级 */
        module_ban_record(name, so_mtime(so_path), "ABI mismatch");
        return module_prepare_reject(h, mfd, -3);
    }
    if (!info->name || strcmp(info->name, name) != 0) {
        LOG_ERR("模块 %s 内部 name=%s 与目录名不一致", name, info->name ? info->name : "(null)");
        module_ban_record(name, so_mtime(so_path), "name mismatch");
        return module_prepare_reject(h, mfd, -4);
    }
    /* init 在锁外调用（经调用围栏：init 崩溃被 longjmp 恢复而非带崩
       框架），成功后才登记。init 尚未 commit（无正式槽位），用**未绑定槽位**
       注册归因：它不与任何模块槽位重叠，故不会覆盖在册模块的归因信息
       （旧实现取 g_module_count，注册表满时该值等于 MAX_MODULES 而回退到 0，
       会覆盖槽位 0 并在 init 结束时清空它）。monitor 线程单线程扫描，与
       commit 无竞态。init 崩溃落盘 ban：防事件扫描反复重试加载崩溃模块。 */
    if (info->init) {
        const int tent_slot = NSP_FENCE_UNBOUND_SLOT;
        fault_fence_register_slot(tent_slot, name, h);
        /* 订阅/监听注册以"正在初始化的模块"为上下文（api_subscribe_rules /
           api_set_config_listener 只允许在 init 内调用），故此处设定归属名 */
        strncpy(g_preparing_name, name, sizeof g_preparing_name - 1);
        g_preparing_name[sizeof g_preparing_name - 1] = '\0';
        int irc = nsp_fence_init_call(tent_slot, "init", info->init, &g_api);
        g_preparing_name[0] = '\0';
        if (irc == NSP_FENCE_FAULT) {
            LOG_ERR(
                "[MOD_ERR] module=%s op=init reason=init 崩溃被围栏恢复 detail=拒绝加载并落盘 ban",
                name);
            module_ban_record(name, so_mtime(so_path), "init crash");
            /* init 崩溃时模块可能已创建自有线程（如 ftp_module 的 ftp.conf
               监视线程）——那是它唯一的停止途径，故仍须经围栏调 exit，否则
               dlclose 解除映射后残留线程踩空即带崩框架。exit 自身崩溃则无法
               确认线程已停，保持 .so 映射不 dlclose（同置毒路径策略）。 */
            bool can_unload = true;
            if (info->exit) {
                int erc = nsp_fence_exit_call(tent_slot, "exit", info->exit);
                if (erc == NSP_FENCE_FAULT) can_unload = false;
            }
            fault_fence_unregister_slot(tent_slot);
            if (!can_unload) {
                LOG_ERR("[MOD_ERR] module=%s op=exit reason=exit 崩溃被围栏恢复 "
                        "detail=无法确认模块线程已停,保持 .so 映射不 dlclose",
                        name);
            }
            /* 保留映射时 h 传 NULL：fd 仍须回收（映射不依赖它） */
            return module_prepare_reject(can_unload ? h : NULL, mfd, -5);
        }
        if (irc != 0) {
            /* init 返回非 0：模块自认初始化失败，清理责任在模块侧（约定不为
               失败路径留线程）。不调 exit——对半初始化状态再调模块代码可能
               造成重复清理。
               **必须落 ban**：否则扫描线程按"瞬时失败"（module_ban_has==false）
               每 5s 重试一轮，每轮 0.5s 稳定性等待 + 整份 .so 复制进新 memfd，
               永不收敛（init 恒返回同一个非 0 → 重试恒失败）。落 ban 后 mtime
               一致即不再尝试，模块更新（mtime 变）自然解禁。 */
            LOG_ERR("[MOD_ERR] module=%s op=init rc=%d detail=拒绝加载并落盘 ban", name, irc);
            module_ban_record(name, so_mtime(so_path), "init returned nonzero");
            fault_fence_unregister_slot(tent_slot);
            return module_prepare_reject(h, mfd, -5);
        }
        /* 首份配置推送：模块在 init 内 subscribe_rules + set_config_listener，
           框架此时立即下发一次过滤视图（模块据此建索引）。推送崩溃=模块建不了
           索引，按 init 失败处理并落盘 ban（否则每次扫描都会再崩一次）。 */
        if (push_config_to_slot(tent_slot, name) == NSP_FENCE_FAULT) {
            LOG_ERR("[MOD_ERR] module=%s op=config_update reason=配置下发监听器崩溃 "
                    "detail=拒绝加载并落盘 ban",
                    name);
            module_ban_record(name, so_mtime(so_path), "config_update crash");
            /* 先注销初始化归因槽位，再交给统一拒绝出口（后者自行注册未绑定
               槽位调 exit）：init 已成功、模块可能已起自有线程，dlclose 前必须停 */
            fault_fence_unregister_slot(tent_slot);
            module_reject_after_init(name, h, info, mfd, "配置下发监听器崩溃");
            return -5;
        }
        fault_fence_unregister_slot(tent_slot); /* commit 时按正式槽位再注册 */
    }
    *h_out = h;
    *info_out = *info;
    *mfd_out = mfd; /* 成功：fd 所有权交给调用方（commit 记入 ModuleEntry） */
    return 0;
}

/* init 已成功的模块被拒绝时的统一善后：模块可能已持有自有线程（如
   ftp_module 的 ftp.conf 监视线程），exit 必须调且必须过围栏（用未绑定槽位
   归因——正式槽位尚未分配，不能占用在册模块的槽位）。**任何"init 过了但
   最终没 commit"的路径都必须走这里**：直接 dlclose 会解除映射而留下仍在运行
   的模块线程，执行失效代码即带崩整个 daemon（档头 §热加载注释与置毒路径
   同一条铁律）。exit 崩溃则无法确认线程已停，保持 .so 映射不 dlclose。
   调用时须已释放 g_module_lock；why 用于日志定位拒绝原因。 */
static void module_reject_after_init(const char* name, void* h, const NspModuleInfo* info,
                                     int mfd, const char* why) {
    bool can_unload = true;
    if (info && info->exit) {
        fault_fence_register_slot(NSP_FENCE_UNBOUND_SLOT, name, h);
        int erc = nsp_fence_exit_call(NSP_FENCE_UNBOUND_SLOT, "exit", info->exit);
        if (erc == NSP_FENCE_FAULT) can_unload = false;
        fault_fence_unregister_slot(NSP_FENCE_UNBOUND_SLOT);
    }
    if (can_unload && h) {
        dlclose(h);
    } else if (!can_unload) {
        LOG_ERR("[MOD_ERR] module=%s op=exit reason=exit 崩溃被围栏恢复 "
                "detail=%s且无法确认模块线程已停,保持 .so 映射不 dlclose",
                name, why ? why : "");
    }
    /* mfd 所有权随拒绝一并回收：commit 失败即定时重试，不 close 则每次漏 1fd */
    if (mfd >= 0) close(mfd);
}

/* 登记已校验模块到槽位（写锁内发布原子快照/链） */
static int module_commit(const char* name, void* h, const NspModuleInfo* info, int mfd) {
    char so_path[PATH_MAX];
    snprintf(so_path, sizeof so_path, "%s/%s/%s.so", g_modules_dir, name, name);
    pthread_rwlock_wrlock(&g_module_lock);
    /* 槽位复用：毒化/卸载后的非活跃槽位可复用，否则反复 ban→更新→新槽，
       旧实现 16 次后注册表满拒绝一切新模块（DoS 上限）。现注册表动态翻倍
       （初容 MODULE_INIT_CAP），优先复用同名非活跃槽。
       置毒超时（在途引用未归零、跳过 dlclose）槽位不可复用：.so 仍映射且
       有在途调用，复用会混淆引用计数与快照。 */
    int slot = -1;
    for (int i = 0; i < g_module_count; i++) {
        if (!g_modules[i].active && strcmp(g_modules[i].name, name) == 0 &&
            atomic_load_explicit(&g_backend_slot_refs[i], memory_order_acquire) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        for (int i = 0; i < g_module_count; i++) {
            if (!g_modules[i].active &&
                atomic_load_explicit(&g_backend_slot_refs[i], memory_order_acquire) == 0) {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0) {
        if (g_module_count >= g_module_cap) {
            /* 无复用槽：翻倍扩容（写锁内；g_modules 仅锁内访问，realloc 安全）。
               OOM/硬上限即按旧语义拒绝（exit 仍须调，见 module_reject_after_init）。 */
            bool grown_ok = false;
            if (g_module_cap < MODULE_HARD_MAX) {
                int ncap = g_module_cap > 0 ? g_module_cap * 2 : MODULE_INIT_CAP;
                if (ncap > MODULE_HARD_MAX) ncap = MODULE_HARD_MAX;
                ModuleEntry* grown = realloc(g_modules, (size_t)ncap * sizeof *grown);
                if (grown) {
                    memset(grown + g_module_cap, 0,
                           ((size_t)ncap - (size_t)g_module_cap) * sizeof *grown);
                    g_modules = grown;
                    g_module_cap = ncap;
                    grown_ok = true;
                } else {
                    LOG_ERR("模块注册表扩容失败（OOM），拒绝 %s", name);
                }
            } else {
                LOG_ERR("模块注册表已达硬上限(%d)，拒绝 %s", MODULE_HARD_MAX, name);
            }
            if (!grown_ok) {
                pthread_rwlock_unlock(&g_module_lock);
                /* 注册表满/OOM 拒绝亦落 ban（mtime 版）：防定时重试每次漏 1fd + 反复全量加载 */
                module_ban_record(name, so_mtime(so_path), "registry full");
                module_reject_after_init(name, h, info, mfd, "注册表满");
                return -6;
            }
        }
        slot = g_module_count++;
        /* 高水位发布（release）：无锁扫描上界，单调只增 */
        int hwm = atomic_load_explicit(&g_backend_hwm, memory_order_relaxed);
        if (slot + 1 > hwm)
            atomic_store_explicit(&g_backend_hwm, slot + 1, memory_order_release);
    } else {
        /* 复用槽位：清零残留 guard/ban 状态（旧错误不跨加载周期继承） */
        module_guard_reset(slot);
    }
    ModuleEntry* m = &g_modules[slot];
    memset(m, 0, sizeof *m);
    strncpy(m->name, name, sizeof m->name - 1);
    m->handle = h;
    m->mfd = mfd;
    m->info = *info; /* 浅拷贝：info->ops 指针有效 */
    /* 可选活跃句柄查询（热重载 quiescence 门控）：模块导出则使用，缺省视为 0 */
    m->active_handles_fn = (int (*)(void))dlsym(h, "nsp_module_active_handles");
    m->active = true;
    struct stat st;
    if (stat(so_path, &st) == 0) m->mtime = st.st_mtime;
    fault_fence_register_slot(slot, name, h);
    /* 后端能力判定：声明了 backend_match 即视为后端模块（ABI V4 起不再有
       type/caps 声明，少两处必须与实现保持一致的冗余字段） */
    if (m->info.ops && m->info.ops->backend_match) {
        atomic_fetch_add_explicit(&g_backend_active_count, 1, memory_order_release);
        /* 槽位快照：写锁内发布，read/write 热路径无锁读取 */
        atomic_store_explicit(&g_backend_slot_ops[slot], m->info.ops, memory_order_release);
    }
    pthread_rwlock_unlock(&g_module_lock);

    LOG("模块已加载: %s v%s%s", name, info->version ? info->version : "?",
        (info->ops && info->ops->backend_match) ? " (后端 I/O)" : "");
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
    int mfd = -1;
    if (module_prepare(name, &h, &info, &mfd) != 0) return -1;
    return module_commit(name, h, &info, mfd);
}

/* quiescence 门控（唯一判定点）：模块仍有活跃句柄（应用 open 中）时**不得卸载/
 * dlclose**。理由：exit 只能停模块**自己起的**线程；而应用持有的句柄背后的
 * 数据面线程（如 FTP 的 nsp_ftpdl/nsp_ftpup）由该句柄的 release 收尾，exit 无从
 * 知道句柄何时关闭。dlclose 解除映射后这些线程继续执行失效代码，且它们不在任何
 * 围栏窗口内（非框架发起的调用）→ 归因失败 → 走原崩溃处理器 → 整个 daemon 死。
 * 三条卸载入口（扫描/置毒/关停）共用本判定，避免再漂移出漏网点。 */
static bool module_quiescent(const ModuleEntry* m) {
    return !(m->active_handles_fn && m->active_handles_fn() > 0);
}

static int module_unload_one(const char* name) {
    pthread_rwlock_wrlock(&g_module_lock);
    int slot = find_slot(name);
    if (slot < 0) {
        pthread_rwlock_unlock(&g_module_lock);
        return -1;
    }
    ModuleEntry* m = &g_modules[slot];
    /* quiescence 门控：仍有活跃句柄则放弃本次卸载（返回 1 = 已推迟，非失败），
       由调用方（扫描线程）定时重试；daemon 关停路径同样跳过——进程即将退出，
       保持 .so 映射比 dlclose 后带崩退出更安全。 */
    if (!module_quiescent(m)) {
        pthread_rwlock_unlock(&g_module_lock);
        LOG_WRN("模块 %s 仍有活跃句柄（应用使用中），跳过卸载（保持 .so 映射）", name);
        return 1;
    }
    void* h = m->handle;
    NspModuleInfo info = m->info;
    if (info.ops && info.ops->backend_match)
        atomic_fetch_sub_explicit(&g_backend_active_count, 1, memory_order_release);
    /* 先置空槽位快照（写锁内）：后续 acquire 立即失败，不再获得新引用；
       在途 acquire（已取到 ops 且二次确认未变）持有 g_backend_slot_refs，
       由下方等待循环保证归零后才 dlclose，杜绝函数指针悬垂。
       置空与下方归零读均用 seq_cst：须与 backend_scan_match/acquire_slot 的
       「取引用 + 复查快照」构成全序（弱序机器上否则可被重排而漏判） */
    atomic_store_explicit(&g_backend_slot_ops[slot], NULL, memory_order_seq_cst);
    int mfd = m->mfd;
    m->mfd = -1;
    m->active = false;
    m->handle = NULL;
    pthread_rwlock_unlock(&g_module_lock);
    /* mfd **不在此时关闭**：下面三段（drain 等待 / exit 围栏 / dlclose）都可能
       放弃本次卸载并让模块继续服务，提前 close 会让 maps 丢掉
       `memfd:nsp_module_<名>` 可观测证据而模块其实还活着（A23-1）。
       只在真正 dlclose 之后关；放弃卸载的分支须把 mfd 还回槽位。 */

    /* 等待后端在途调用完成（防 ops 指针悬垂 SIGSEGV）。FTP 等后端网络操作
       可能远超 100ms（弱网/指数退避重试），若等待超时仍强行 dlclose，会让
       在途 backend_* 调用执行已卸载 .so 的代码 → SIGSEGV（热重载崩溃根因）。
       故等待加长至 ~2s；仍忙则完整回滚（恢复 active/handle/链），放弃本次
       卸载，由下次模块变更再次触发——宁可延迟卸载，绝不 dlclose 在途模块 */
    bool drained = false;
    for (int i = 0; i < 2000; i++) {
        bool busy = atomic_load_explicit(&g_backend_slot_refs[slot], memory_order_seq_cst) != 0;
        if (!busy) {
            drained = true;
            break;
        }
        usleep(1000);
    }
    if (!drained) {
        /* 仍有在途调用：回滚标记，保持模块加载，绝不 dlclose */
        pthread_rwlock_wrlock(&g_module_lock);
        if (info.ops && info.ops->backend_match) {
            atomic_fetch_add_explicit(&g_backend_active_count, 1, memory_order_release);
            atomic_store_explicit(&g_backend_slot_ops[slot], info.ops, memory_order_release);
        }
        m->active = true;
        m->handle = h;
        m->mfd = mfd; /* 回滚必须复原 mfd：模块继续服务，memfd 可观测性不能丢 */
        pthread_rwlock_unlock(&g_module_lock);
        LOG_WRN("模块 %s 有在途调用（refs 未归零），延迟卸载", name);
        return -1;
    }

    /* exit 经围栏：正常模块 exit 崩溃概率极低，但崩溃同样不可带崩
       框架。注意：此处 slot 仍有效（槽位快照已置空但注册表保留至注销后）。
       exit 崩溃说明模块自有线程已无法确认停止，保持 .so 映射不 dlclose——
       否则残留线程执行失效代码即 SIGSEGV（同置毒路径策略，两条卸载路径
       对 exit 崩溃必须同策，否则热卸载会成为同一崩溃的另一入口）。 */
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
    if (can_unload) {
        dlclose(h);
        if (mfd >= 0) close(mfd); /* 映像已解除映射，memfd 不再有持有者 */
    } else {
        /* exit 崩溃 → 保持 .so 映射：memfd 同样要留着（可观测性 + 与 .so 同命） */
        pthread_rwlock_wrlock(&g_module_lock);
        m->mfd = mfd;
        pthread_rwlock_unlock(&g_module_lock);
    }
    fault_fence_unregister_slot(slot);
    /* 复位熔断器记账：重载时窗口计数/累计错误不应继承上一轮加载周期的数据，
       否则旧错误会跨加载周期累积，误触熔断 */
    module_guard_reset(slot);
    fw_config_forget_module(name); /* 注销订阅/监听与过滤视图 */
    if (can_unload) LOG("模块已卸载: %s", name);
    return 0;
}

/* ================= ban 记录（崩溃/熔断后防重载震荡） =================
 * <modules_dir>/.banned，每行: 模块名|mtime|原因(不含|)|时间戳
 * 查询语义：同名记录存在且 mtime 一致 → ban 生效；mtime 不同（.so 已更新）
 * → 记录失效，重写文件移除该行并允许加载（版本更新自愈）。
 * 旧格式行（第二字段为 64 位哈希而非纯数字 mtime）一律视为 stale 丢弃：
 * 内容哈希校验已弃用，旧 verdict 无参照意义，删后按新语义重建。
 * 运行上下文：monitor 线程 / FUSE 线程（普通上下文，可文件 I/O）。 */

static char g_banned_path[PATH_MAX] = {0};

static void banned_path_init(void) {
    if (!g_banned_path[0])
        snprintf(g_banned_path, sizeof g_banned_path, "%s/.banned", g_modules_dir);
}

/* 第二字段是否为新格式 mtime（纯数字且长度合理）：旧 64 位哈希行（极小概率
   全数字但长度 64 超限）一律判旧格式。 */
static bool ban_field_is_mtime(const char* f, size_t len) {
    if (len == 0 || len > 20) return false;
    for (size_t i = 0; i < len; i++)
        if (f[i] < '0' || f[i] > '9') return false;
    return true;
}

static bool module_ban_lookup(const char* name, time_t cur_mtime, char reason_out[96]) {
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
    bool found = false, stale = false, overflow = false;
    /* cur_mtime < 0（stat 失败，文件正处替换间隙）：无法比对，不阻挡（加载尝试
       会以瞬时失败定时重试），同名行原样保留 */
    bool comparable = (cur_mtime >= 0);
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
        /* 保存原始完整行（含 mtime|reason|timestamp），防止截断后丢失 */
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
        /* 同名：比对 mtime；旧哈希格式行直接判 stale（一次性迁移） */
        char* l2 = strchr(l1 + 1, '|');
        const char* mfield = l1 + 1;
        size_t mlen = l2 ? (size_t)(l2 - mfield) : strlen(mfield);
        char lreason[96] = {0};
        if (l2) {
            char* l3 = strchr(l2 + 1, '|');
            size_t rl2 = l3 ? (size_t)(l3 - (l2 + 1)) : strlen(l2 + 1);
            if (rl2 >= sizeof lreason) rl2 = sizeof lreason - 1;
            memcpy(lreason, l2 + 1, rl2);
        }
        if (!comparable) {
            /* stat 失败：保留该行，不阻挡 */
            size_t olen = strlen(original);
            if (rl + olen + 2 < sizeof rewrite) {
                strcat(rewrite, original);
                strcat(rewrite, "\n");
                rl = strlen(rewrite);
            } else
                overflow = true;
        } else if (!ban_field_is_mtime(mfield, mlen)) {
            stale = true; /* 旧哈希格式：记录失效，重写时丢弃该行 */
        } else if ((time_t)atoll(mfield) == cur_mtime) {
            found = true;
            if (reason_out && lreason[0]) {
                strncpy(reason_out, lreason, 95);
                reason_out[95] = '\0';
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
            stale = true; /* mtime 变化：记录失效，重写时丢弃该行 */
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
    return found;
}

static void module_ban_record(const char* name, time_t mtime, const char* reason) {
    banned_path_init();
    if (!name || !name[0]) return;
    FILE* fp = fopen(g_banned_path, "a");
    if (!fp) return;
    flock(fileno(fp), LOCK_EX);
    time_t now = time(NULL);
    /* reason 为固定串（不含 '|'），name 受 is_valid_module_name 约束，防格式破坏 */
    fprintf(fp, "%s|%ld|%s|%ld\n", name, (long)mtime, reason ? reason : "unknown",
            (long)now);
    fflush(fp);
    fsync(fileno(fp));
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
}

/* 按名查询 ban 记录是否存在（任意 mtime）：供扫描线程区分"永久拒绝"与"瞬时失败"。
   加载/prepare 失败后若本模块已有 ban 记录 → 永久拒绝，不做定时重试（等下一次
   文件变化事件；mtime 变了 ban 自然失效）；无记录 → 瞬时失败（拷贝中途），需定
   时重试。行首 `名|` 精确匹配：name 受 is_valid_module_name 约束不含 '|'，
   截断残行仍以行首判定，无误判。 */
static bool module_ban_has(const char* name) {
    banned_path_init();
    if (!name || !name[0]) return false;
    FILE* fp = fopen(g_banned_path, "r");
    if (!fp) return false;
    flock(fileno(fp), LOCK_SH);
    char line[512];
    size_t nlen = strlen(name);
    bool found = false;
    while (fgets(line, sizeof line, fp)) {
        if (strncmp(line, name, nlen) == 0 && line[nlen] == '|') {
            found = true;
            break;
        }
    }
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
    return found;
}

/* ============ 加载/热重载前的 ban 判定（扫描与热重载共用） ============
   命中（同名且文件 mtime 与 ban 记录一致）→ 调用方跳过，不加载也不重载。
   日志按 (name, 文件 mtime) 去重：事件突发（一次拷贝多个事件）时不去重就是连刷
   多条——残留旧 ABI 模块、崩溃后没修好的模块都会长期命中，而 sys.log 里 DEBUG
   都不受最小级别过滤，降级日志级别解决不了噪音。文件更新（真更新）后重新
   提示一次。调用上下文：仅 monitor 线程（与 module_scan_diff 同线程），
   故无需加锁。 */
#define MAX_BAN_QUIET 16
static struct {
    char name[64];
    char mt[32];
} g_ban_quiet[MAX_BAN_QUIET];
static int g_ban_quiet_count = 0;
static int g_ban_quiet_next = 0; /* 表满后的环形覆盖游标 */

/* 首次见到该 (name,mtime) 返回 true（应当记录），之后返回 false（静默跳过）。
   表满时环形覆盖最旧一项（等价 FIFO 淘汰），而不是"满后不再记录"——后者会让
   去重彻底失效，超过 16 个被 ban 的模块时每次扫描重打全部日志（正是本表要
   消灭的噪音）。环形覆盖的代价仅是极久未见的条目可能重复提示一次。 */
static bool ban_quiet_first(const char* name, const char* mt) {
    for (int i = 0; i < g_ban_quiet_count; i++) {
        if (strcmp(g_ban_quiet[i].name, name) == 0 && strcmp(g_ban_quiet[i].mt, mt) == 0)
            return false;
    }
    int slot;
    if (g_ban_quiet_count < MAX_BAN_QUIET) {
        slot = g_ban_quiet_count++;
    } else {
        slot = g_ban_quiet_next;
        g_ban_quiet_next = (g_ban_quiet_next + 1) % MAX_BAN_QUIET;
    }
    strncpy(g_ban_quiet[slot].name, name, sizeof g_ban_quiet[0].name - 1);
    g_ban_quiet[slot].name[sizeof g_ban_quiet[0].name - 1] = '\0';
    strncpy(g_ban_quiet[slot].mt, mt, sizeof g_ban_quiet[0].mt - 1);
    g_ban_quiet[slot].mt[sizeof g_ban_quiet[0].mt - 1] = '\0';
    return true;
}

static bool module_ban_blocks(const char* name, const char* so_path) {
    time_t cur = so_mtime(so_path);
    if (cur < 0) {
        /* stat 失败（文件正处替换间隙）：不绕过 ban 直接加载，靠事件/定时重试 */
        LOG_WRN("模块 %s 文件不可读，延迟加载（等下次扫描）", name);
        return true;
    }
    char mt[32];
    snprintf(mt, sizeof mt, "%ld", (long)cur);
    char br[96] = {0};
    if (!module_ban_lookup(name, cur, br)) return false;
    if (ban_quiet_first(name, mt))
        LOG_WRN("[MOD_ERR] module=%s op=scan reason=%s detail=ban 名单命中(mtime 一致),跳过加载",
                name, br[0] ? br : "unknown");
    return true;
}

/* ================= 模块置毒（崩溃恢复/熔断触发的强制卸载） ================= */
/*
 * 与 module_unload_one 的语义差异（崩溃不可回滚）：
 *   - 在途引用等待超时不恢复模块：槽位快照保持置空（规则持续失效），
 *     跳过 dlclose（.so 保持映射，待引用自然归零后无人使用）
 *   - exit 仍须经围栏调用（模块自有线程只能由 exit 停掉，否则 dlclose 后
 *     残留线程踩空即带崩 daemon）；仅当 exit 自身崩溃（无法确认线程已停）
 *     才保持 .so 映射不 dlclose
 *   - 落盘 ban 记录：同 mtime .so 在本 daemon 生命周期内不再加载
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
    char name[64] = {0};
    /* 置毒 ban 记已加载文件的 mtime（m->mtime 在 commit 时存入）：磁盘文件若在
       加载后被替换，新文件 mtime 不同即放行，只 ban 住肇事版本 */
    time_t ban_mt = 0;
    strncpy(name, m->name, sizeof name - 1);
    ban_mt = m->mtime;
    void* h = m->handle;
    NspModuleInfo info = m->info;
    bool was_active = m->active;
    /* 句柄门控判定所需的函数指针：在写锁内一并取出（指针加载后不变） */
    int (*active_handles_fn)(void) = m->active_handles_fn;
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
    module_ban_record(name, ban_mt, reason);

    if (!was_active || !h) {
        /* 槽位本就不活跃（加载失败路径）：ban 已落盘，无需进一步处理 */
        LOG_ERR("[MOD_ERR] module=%s op=poison reason=%s detail=槽位非活跃,ban 已落盘", name,
                reason ? reason : "(null)");
        return 0;
    }

    LOG_ERR("[MOD_ERR] module=%s op=poison reason=%s detail=置毒卸载:槽位快照置空,该模块立即失效",
            name, reason ? reason : "(null)");

    /* 写锁内：计数回退 + 快照置空 + 摘链（与 unload 同序，防在途 acquire） */
    pthread_rwlock_wrlock(&g_module_lock);
    if (info.ops && info.ops->backend_match)
        atomic_fetch_sub_explicit(&g_backend_active_count, 1, memory_order_release);
    /* 置空与下方归零读同用 seq_cst：与 backend_scan_match/acquire_slot 的
       「取引用 + 复查快照」构成全序（理由见 module_unload_one） */
    atomic_store_explicit(&g_backend_slot_ops[slot], NULL, memory_order_seq_cst);
    int mfd = m->mfd;
    m->mfd = -1;
    m->active = false;
    m->handle = NULL;
    pthread_rwlock_unlock(&g_module_lock);
    /* 同 unload：mfd 留到 dlclose 之后，见 module_unload_one 的注释（A23-1） */

    /* 等待在途引用归零（崩溃线程已 longjmp 返回会释放；其他线程的合法
       在途 backend 调用完成即释放）。超时不恢复（区别于 unload） */
    bool drained = false;
    for (int i = 0; i < 2000; i++) {
        if (atomic_load_explicit(&g_backend_slot_refs[slot], memory_order_seq_cst) == 0) {
            drained = true;
            break;
        }
        usleep(1000);
    }
    if (!drained) {
        LOG_WRN("模块 %s 置毒后在途引用未归零，跳过 dlclose（.so 保持映射,规则持续失效）", name);
        pthread_rwlock_wrlock(&g_module_lock);
        m->mfd = mfd; /* .so 仍映射：memfd 一并保留 */
        pthread_rwlock_unlock(&g_module_lock);
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
       exit 缺失视为模块声明无清理需求，与优雅卸载路径同样直接 dlclose。

       A12 quiescence 门控：exit 只能停模块**自己起的**线程；应用仍持有的句柄
       背后的数据面线程由该句柄的 release 收尾（FTP 的 nsp_ftpdl/nsp_ftpup），
       exit 不保证停它们 → 此时同样不 dlclose（exit 照调，让模块先收自己的线程）。 */
    bool quiescent = !(active_handles_fn && active_handles_fn() > 0);
    bool can_unload = quiescent;
    if (!quiescent) {
        LOG_WRN("[MOD_ERR] module=%s op=poison reason=%s detail=仍有活跃句柄,"
                ".so 保持映射不 dlclose（句柄由 release 收尾）",
                name, reason ? reason : "(null)");
    }
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
        pthread_rwlock_wrlock(&g_module_lock);
        m->mfd = mfd; /* .so 仍映射：memfd 一并保留 */
        pthread_rwlock_unlock(&g_module_lock);
        fault_fence_unregister_slot(slot);
        fw_config_forget_module(name); /* 注销订阅/监听与过滤视图 */
        LOG_ERR("[MOD_ERR] module=%s op=poison reason=%s detail=槽位已置空,规则立即失效,"
                ".so 保持映射（%s）",
                name, reason ? reason : "(null)",
                quiescent ? "exit 崩溃故不 dlclose" : "仍有活跃句柄故不 dlclose");
        return 0;
    }
    dlclose(h);
    if (mfd >= 0) close(mfd); /* 映像已解除映射，memfd 不再有持有者 */
    fault_fence_unregister_slot(slot);
    fw_config_forget_module(name); /* 注销订阅/监听与过滤视图 */
    LOG_ERR("[MOD_ERR] module=%s op=poison reason=%s detail=exit 完成,dlclose 完成,ban 已落盘",
            name, reason ? reason : "(null)");
    return 0;
}

/* 模块热插拔变更由 fuse_daemon 自动处理（原子快照分派实时生效），
   不再通知 injector 全量重挂追踪应用 */

/* ================= 全量扫描（启动 + 事件触发的热插拔差异） ================
   返回 true = 仍有延迟工作未完成（quiescence 门控推迟的卸载/重载，或拷贝中途
   的瞬时加载失败），调用方需定时重试；false = 稳态，可无限等待下一次事件。
   永久拒绝（已落 ban）不算延迟工作：等下一次文件变化事件，哈希变了 ban 自然失效。 */

static bool module_scan_diff(void) {
    bool pending = false;
    DIR* d = opendir(g_modules_dir);
    if (!d) {
        /* 目录不存在时尝试创建后重试一次 */
        if (errno == ENOENT) {
            mkdir_recursive(g_modules_dir);
            d = opendir(g_modules_dir);
        }
        if (!d) return false;
    }
    /* 在场名单堆收集（目录项数无上限，栈上 1024×64B=64KB 对监控线程栈不友好；
       扫描低频，堆成本可忽略）。失败（OOM）即放弃本轮扫描（下次事件重试）。 */
    char (*present)[64] = NULL;
    int pcount = 0, pcap = 0;
    struct dirent* de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        if (!is_valid_module_name(de->d_name)) continue;
        char so[PATH_MAX];
        snprintf(so, sizeof so, "%s/%s/%s.so", g_modules_dir, de->d_name, de->d_name);
        if (access(so, F_OK) == 0) {
            if (pcount >= pcap) {
                int ncap = pcap > 0 ? pcap * 2 : 16;
                char (*grown)[64] = realloc(present, (size_t)ncap * sizeof *grown);
                if (!grown) {
                    free(present);
                    closedir(d);
                    return true; /* OOM：pending 由调用方定时重试 */
                }
                present = grown;
                pcap = ncap;
            }
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
               返回 pending 由调用方定时重试——避免热重载竞态崩溃 */
            if (!module_quiescent(&g_modules[i])) {
                LOG_WRN("模块 %s 仍有活跃句柄（应用使用中），延迟卸载", g_modules[i].name);
                pending = true;
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
            /* ban 检查：崩溃/熔断被卸载的模块，以及 ABI/名字不匹配被
               拒的模块（module_prepare 内落 ban），mtime 一致时不重载；文件变化
               （版本更新）放行。日志按 (name,mtime) 去重，避免事件突发刷屏 */
            char so[PATH_MAX];
            snprintf(so, sizeof so, "%s/%s/%s.so", g_modules_dir, present[p], present[p]);
            if (module_ban_blocks(present[p], so)) continue;
            LOG("检测到新模块: %s", present[p]);
            /* 加载失败且尚未落 ban = 瞬时失败（拷贝中途），需定时重试；
               已落 ban = 永久拒绝，等下一次文件变化事件 */
            if (module_load_one(present[p]) != 0 && !module_ban_has(present[p]))
                pending = true;
        } else {
            char so[PATH_MAX];
            snprintf(so, sizeof so, "%s/%s/%s.so", g_modules_dir, present[p], present[p]);
            struct stat st;
            if (stat(so, &st) == 0 && st.st_mtime != g_modules[slot].mtime) {
                /* quiescence 门控：模块仍有活跃句柄（应用 open 中）则延迟
                   热重载，返回 pending 定时重试——"无应用 open、写入完成后才热加载" */
                if (!module_quiescent(&g_modules[slot])) {
                    LOG_WRN("模块 %s 仍有活跃句柄（应用使用中），延迟热重载", present[p]);
                    pending = true;
                    continue;
                }
                /* ban 检查（热重载路径同样适用）：磁盘上这份新文件若已被判为
                   坏文件（ABI 不匹配等），不必再走一遍 0.5s 稳定性等待 + 全量
                   哈希 + dlopen，直接静默保留内存中的旧模块——否则每次扫描一条
                   "校验未通过" ERROR，且 .banned 会被重复追加同一行 */
                if (module_ban_blocks(present[p], so)) continue;
                /* 文件已被替换即重载：**不能**用"内容哈希相同"做跳过判据。
                   就地覆盖（truncate + 重写，非 tmp+rename）会让已映射页失效——
                   MAP_PRIVATE 映射下页在文件被截断时被丢弃，再次访问从"正在写入"
                   的文件重新缺页，把半写内容固化成私有页且此后不再更新；模块的
                   ops 表若落在这类页上，函数指针会变成链接期残值 → 调用即野指针
                   跳转（实测 PC=垃圾地址）。换新映射是唯一解法：dlopen 新文件 +
                   dlclose 旧映射；延迟不敏感，故不做"哈希相同就跳过"的优化。 */
                LOG("模块文件已更新，热重载: %s", present[p]);
                /* 先验后换：先加载校验新模块，通过才卸载旧模块——
                   校验失败/旧模块在途调用未归零时保留内存中的旧模块 */
                void* nh = NULL;
                NspModuleInfo ninfo;
                int nmfd = -1;
                if (module_prepare(present[p], &nh, &ninfo, &nmfd) != 0) {
                    LOG_ERR("模块 %s 校验未通过，保留内存中的旧模块", present[p]);
                    /* 未落 ban = 瞬时失败（拷贝中途），定时重试；已落 ban =
                       永久拒绝，等文件变化事件 */
                    if (!module_ban_has(present[p])) pending = true;
                    continue;
                }
                if (module_unload_one(present[p]) != 0) {
                    /* 旧实例在途引用未归零 → 放弃新实例（回滚保留旧模块）。
                       新实例 init 已成功、可能已起自有线程，必须经围栏 exit/join
                       后再 dlclose，否则残留线程执行已解除映射的代码即带崩 daemon */
                    LOG_WRN("模块 %s 旧实例仍有在途调用，热重载放弃（保留旧模块）", present[p]);
                    module_reject_after_init(present[p], nh, &ninfo, nmfd,
                                             "旧实例在途引用未归零,热重载放弃");
                    pending = true;
                    continue;
                }
                module_commit(present[p], nh, &ninfo, nmfd);
            }
        }
    }
    free(present);
    return pending;
}

/* ================= 热插拔监控线程（事件驱动） =================
   两层 inotify：顶层 watch 管子目录增删，子 watch 管各自 `.so` 变更。
   poll 正常无限等待（稳态零唤醒）；仅当上次扫描返回 pending（延迟卸载/重载、
   拷贝中途的瞬时失败）时才带超时轮询重试。watch 建不全（超限/ENOSPC）时同样
   回退定时扫描，避免静默漏变更。 */

static int subw_find_by_wd(int wd) {
    for (int i = 0; i < g_subw_count; i++)
        if (g_subw[i].wd == wd) return i;
    return -1;
}

static bool subw_has_name(const char* name) {
    for (int i = 0; i < g_subw_count; i++)
        if (strcmp(g_subw[i].name, name) == 0) return true;
    return false;
}

static void subw_remove_at(int ifd, int idx) {
    if (idx < 0 || idx >= g_subw_count) return;
    /* 目录已删时内核自动摘 watch，此处 rm 失败（EINVAL/ENOENT）属正常，忽略 */
    inotify_rm_watch(ifd, g_subw[idx].wd);
    for (int i = idx; i + 1 < g_subw_count; i++) g_subw[i] = g_subw[i + 1];
    g_subw_count--;
}

/* 对账子 watch 与现存子目录：补新增、摘已删。返回 false = 有目录没 watch 上
   （超限/加 watch 失败），调用方回退定时扫描。注意顺序无关正确性：scan 本身
   是全量状态比对，任何时刻的现存状态都会被下一次扫描覆盖；watch 只保证"变更
   之后必有一次扫描被触发"。 */
static bool subwatch_sync(int ifd) {
    /* 在场目录堆收集（子目录数无上限；扫描低频，堆成本可忽略）。
       OOM 即返回 false（回退定时扫描，下次重试）。 */
    char (*present)[64] = NULL;
    int n = 0, pcap = 0;
    bool over = false;
    DIR* d = opendir(g_modules_dir);
    if (d) {
        struct dirent* de;
        while ((de = readdir(d))) {
            if (de->d_name[0] == '.') continue;
            if (!is_valid_module_name(de->d_name)) continue;
            bool isdir = (de->d_type == DT_DIR);
            if (de->d_type == DT_UNKNOWN) {
                char p[PATH_MAX];
                struct stat st;
                snprintf(p, sizeof p, "%s/%s", g_modules_dir, de->d_name);
                isdir = (stat(p, &st) == 0 && S_ISDIR(st.st_mode));
            }
            if (!isdir) continue;
            if (n >= pcap) {
                int ncap = pcap > 0 ? pcap * 2 : 16;
                char (*grown)[64] = realloc(present, (size_t)ncap * sizeof *grown);
                if (!grown) {
                    over = true;
                    break;
                }
                present = grown;
                pcap = ncap;
            }
            strncpy(present[n], de->d_name, sizeof present[n] - 1);
            present[n][sizeof present[n] - 1] = '\0';
            n++;
        }
        closedir(d);
    }
    for (int i = 0; i < g_subw_count;) {
        bool found = false;
        for (int j = 0; j < n; j++)
            if (strcmp(g_subw[i].name, present[j]) == 0) {
                found = true;
                break;
            }
        if (!found)
            subw_remove_at(ifd, i);
        else
            i++;
    }
    bool ok = !over;
    for (int j = 0; j < n; j++) {
        if (subw_has_name(present[j])) continue;
        /* watch 表按硬上限分配（g_subw[MAX_MODULES]，72KB .bss）：超限 loud
           告警 + 回退定时扫描（practically unreachable，见 module_loader.h） */
        if (g_subw_count >= MAX_MODULES) {
            ok = false;
            break;
        }
        char sub[PATH_MAX];
        snprintf(sub, sizeof sub, "%s/%s", g_modules_dir, present[j]);
        int wd = inotify_add_watch(ifd, sub, NSP_SUBW_MASK);
        if (wd < 0) {
            LOG_ERR("模块子目录监听失败 %s: %s（回退定时扫描）", sub, strerror(errno));
            ok = false;
            continue;
        }
        strncpy(g_subw[g_subw_count].name, present[j], sizeof g_subw[0].name - 1);
        g_subw[g_subw_count].name[sizeof g_subw[0].name - 1] = '\0';
        g_subw[g_subw_count].wd = wd;
        g_subw_count++;
    }
    if (over) LOG_ERR("模块子目录收集失败（OOM），部分变更监听不到（回退定时扫描）");
    free(present);
    return ok;
}

/* 排空 inotify 事件：IN_IGNORED 摘除对应 watch（顶层/子目录），IN_Q_OVERFLOW
   只告警——溢出本身已唤醒 poll，随后的全量扫描即自愈。返回 false = fd 出错，
   调用方重建监听。 */
static bool modmon_drain(int ifd, int* wd_top) {
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    for (;;) {
        ssize_t len = read(ifd, buf, sizeof buf);
        if (len < 0) {
            if (errno == EAGAIN || errno == EINTR) return true;
            return false;
        }
        if (len == 0) return true;
        for (char* p = buf; p < buf + len;) {
            struct inotify_event* ev = (struct inotify_event*)p;
            if (ev->mask & IN_Q_OVERFLOW)
                LOG_WRN("模块监听队列溢出，全量扫描自愈（可能的一次延迟加载）");
            if (ev->mask & IN_IGNORED) {
                if (ev->wd == *wd_top)
                    *wd_top = -1;
                else {
                    int idx = subw_find_by_wd(ev->wd);
                    if (idx >= 0) subw_remove_at(ifd, idx);
                }
            }
            p += sizeof(struct inotify_event) + ev->len;
        }
    }
}

/* 延迟工作重试间隔：仅 quiescence 推迟与拷贝中途瞬时失败时才轮询，稳态零开销 */
#define MOD_DEFERRED_RETRY_MS 5000
/* 事件归并窗口：一次拷贝产生 CREATE/MODIFY…/CLOSE_WRITE 多个事件，合并为一次重扫 */

static void* module_monitor_thread(void* arg) {
    (void)arg;
    nsp_set_thread_name("nsp_modmon");
    int inotify_fd = -1;
    int wd_top = -1;
    bool pending = false;
    while (!g_mod_stop && !g_log_shutdown) {
        if (inotify_fd < 0) {
            inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
            if (inotify_fd < 0) {
                sleep(2);
                continue;
            }
        }
        if (wd_top < 0) {
            wd_top = inotify_add_watch(inotify_fd, g_modules_dir, NSP_TOPW_MASK);
            if (wd_top < 0) {
                close(inotify_fd);
                inotify_fd = -1;
                g_subw_count = 0; /* fd 已关，子 watch 全失效，对账重建 */
                sleep(2);
                continue;
            }
        }
        bool watches_ok = subwatch_sync(inotify_fd);
        struct pollfd pfds[2] = {{.fd = inotify_fd, .events = POLLIN},
                                 {.fd = g_mod_wake[0], .events = POLLIN}};
        /* 稳态无限等待；有延迟工作或监听不全时才定时唤醒 */
        int pr = poll(pfds, 2, (pending || !watches_ok) ? MOD_DEFERRED_RETRY_MS : -1);
        if (pr >= 0 && pfds[1].revents) break; /* 关闭唤醒：退出前不再扫描 */
        if (pr < 0) {
            if (errno == EINTR) continue;
            if (wd_top >= 0) inotify_rm_watch(inotify_fd, wd_top);
            wd_top = -1;
            close(inotify_fd);
            inotify_fd = -1;
            g_subw_count = 0;
            continue;
        }
        if (pr == 0) {
            /* 定时重试：仅延迟工作未完成或监听不全时才会走到这里 */
            pending = module_scan_diff();
            continue;
        }
        if (!modmon_drain(inotify_fd, &wd_top)) {
            if (wd_top >= 0) inotify_rm_watch(inotify_fd, wd_top);
            wd_top = -1;
            close(inotify_fd);
            inotify_fd = -1;
            g_subw_count = 0;
            continue;
        }
        /* 归并窗口：多个叠加事件只重扫一次；关闭唤醒可提前打断 */
        struct pollfd cpfds[2] = {{.fd = inotify_fd, .events = POLLIN},
                                  {.fd = g_mod_wake[0], .events = POLLIN}};
        int cr = poll(cpfds, 2, 1000);
        if (cr > 0) {
            if (cpfds[1].revents) break; /* 关闭：退出前不再扫描 */
            if (cpfds[0].revents && !modmon_drain(inotify_fd, &wd_top)) {
                if (wd_top >= 0) inotify_rm_watch(inotify_fd, wd_top);
                wd_top = -1;
                close(inotify_fd);
                inotify_fd = -1;
                g_subw_count = 0;
                continue;
            }
        }
        pending = module_scan_diff();
    }
    if (inotify_fd >= 0) {
        if (wd_top >= 0) inotify_rm_watch(inotify_fd, wd_top);
        for (int i = 0; i < g_subw_count; i++) inotify_rm_watch(inotify_fd, g_subw[i].wd);
        g_subw_count = 0;
        close(inotify_fd);
    }
    return NULL;
}

/* ================= 对外接口 ================= */

int module_system_init(const char* rules_path, const char* modules_dir) {
    if (rules_path) strncpy(g_fw_rules_path, rules_path, sizeof g_fw_rules_path - 1);
    if (modules_dir && modules_dir[0])
        strncpy(g_modules_dir, modules_dir, sizeof g_modules_dir - 1);
    mkdir_recursive(g_modules_dir);
    /* 配置读取在框架侧完成：先建视图与监听，再扫描模块——模块 init 内
       subscribe/set_config_listener 后由 module_prepare 立即推送首份视图 */
    fw_config_set_reload_hook(on_config_reload);
    fw_config_init(g_fw_rules_path);
    module_scan_diff();
    if (pipe2(g_mod_wake, O_NONBLOCK | O_CLOEXEC) != 0) g_mod_wake[0] = g_mod_wake[1] = -1;
    if (pthread_create(&g_mod_tid, NULL, module_monitor_thread, NULL) == 0) {
        g_mod_thread_started = true; /* 不 detach：shutdown 要 join，确保退出前线程已停 */
    }
    /* 初始扫描完成后标记，后续热插拔变更才通知 injector */
    int active = 0;
    pthread_rwlock_rdlock(&g_module_lock);
    for (int i = 0; i < g_module_count; i++)
        if (g_modules[i].active) active++;
    pthread_rwlock_unlock(&g_module_lock);
    LOG("模块系统已初始化: 目录 %s, 已加载 %d 个模块", g_modules_dir, active);
    return 0;
}

void module_system_shutdown(void) {
    /* 先停扫描线程（唤醒 + join）：避免卸载/退出期间仍有扫描在 dlopen 模块 */
    g_mod_stop = true;
    if (g_mod_wake[1] >= 0) (void)!write(g_mod_wake[1], "x", 1);
    if (g_mod_thread_started) {
        pthread_join(g_mod_tid, nullptr);
        g_mod_thread_started = false;
    }
    if (g_mod_wake[0] >= 0) close(g_mod_wake[0]);
    if (g_mod_wake[1] >= 0) close(g_mod_wake[1]);
    g_mod_wake[0] = g_mod_wake[1] = -1;
    for (int i = g_module_count - 1; i >= 0; i--) {
        if (!g_modules[i].active) continue;
        module_unload_one(g_modules[i].name);
    }
    g_module_count = 0;
    /* 注册表本体随 daemon 生命期：此处不 free（g_module_cap 常驻），但清零
       条目（重 init 时健康快照不显示上轮残留 ban；commit 填充时也会逐槽
       memset，双保险）。进程退出时由 OS 回收。 */
    if (g_modules) memset(g_modules, 0, (size_t)g_module_cap * sizeof *g_modules);
    /* 模块已全部卸载（订阅/监听随之注销），最后停监听线程并释放视图，
       再退出内建规则引擎（缓存归零；索引内存由 fw_config 释放） */
    fw_config_shutdown();
    fw_rules_exit();
}

/* 后端路径查找：基于后端槽位原子快照无锁分派（免每请求 rwlock + 线性扫描）。
   acquire 槽位在途引用（g_backend_slot_refs）→ 二次确认快照未变 → 调
   backend_match → 命中则返回并持引用（调用方须 module_backend_put），
   未命中则释放继续。unload 先置空快照再等引用归零，杜绝 ops 悬垂调用。 */
static int backend_scan_match(const char* path, int* slot_out, const NspModuleOps** ops_out) {
    if (!path || !ops_out) return -1;
    int hwm = atomic_load_explicit(&g_backend_hwm, memory_order_acquire);
    for (int i = 0; i < hwm; i++) {
        const NspModuleOps* ops =
            atomic_load_explicit(&g_backend_slot_ops[i], memory_order_acquire);
        if (!ops) continue;
        /* 先取引用再解引用模块内存：ops 字段的读取必须处于引用保护之下。unload
           是「置空快照 → 等引用归零 → dlclose」，若在取引用前读 ops->backend_match，
           该窗口内被 dlclose 后即读未映射内存——且这发生在围栏之前，围栏救不了。
           两侧 seq_cst 配对（此处 + module_unload_one/module_guard_poison 的置空与
           归零读）：否则 ARM 弱序下 store/load 可重排，仍会出现「生产者没看到置空
           快照、卸载者没看到新引用」而 dlclose 在途模块。 */
        atomic_fetch_add_explicit(&g_backend_slot_refs[i], 1, memory_order_seq_cst);
        if (atomic_load_explicit(&g_backend_slot_ops[i], memory_order_seq_cst) != ops) {
            /* 快照刚被 unload 置空：放弃引用，不调用 ops */
            atomic_fetch_sub_explicit(&g_backend_slot_refs[i], 1, memory_order_acq_rel);
            continue;
        }
        if (!ops->backend_match) {
            /* 槽位未提供 match：不参与分派，释放引用继续 */
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
    /* seq_cst 与 backend_scan_match 同协议：须与 unload 的「置空 + 归零读」
       构成全序，才能保证「要么引用被卸载者看见、要么本线程看见置空」 */
    atomic_fetch_add_explicit(&g_backend_slot_refs[slot], 1, memory_order_seq_cst);
    if (atomic_load_explicit(&g_backend_slot_ops[slot], memory_order_seq_cst) != ops) {
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
    int hwm = atomic_load_explicit(&g_backend_hwm, memory_order_acquire);
    for (int i = 0; i < hwm; i++) {
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
    int hwm = atomic_load_explicit(&g_backend_hwm, memory_order_acquire);
    for (int i = 0; i < hwm; i++) {
        if (atomic_load_explicit(&g_backend_slot_ops[i], memory_order_acquire) == ops) return i;
    }
    return -1;
}

/* slot 占位名表（"slotN"，无锁读）：pthread_once 初始化，消并发首调写入竞态 */
static char g_slot_names[MAX_MODULES][16];
static void slot_names_init_once(void) {
    for (int i = 0; i < MAX_MODULES; i++)
        snprintf(g_slot_names[i], sizeof g_slot_names[i], "slot%d", i);
}
static pthread_once_t g_slot_names_once = PTHREAD_ONCE_INIT;

const char* module_slot_name(int slot) {
    /* "slotN" 占位静态表（无锁安全）：1024×16B=16KB .bss */
    if (slot < 0 || slot >= MAX_MODULES) return "unknown";
    pthread_once(&g_slot_names_once, slot_names_init_once);
    /* TLS 拷贝后返回：旧实现解锁后返回条目内部指针（UAF——unload 可复用/
       改写该槽）。本函数仅日志路径调用，TLS 开销可忽略。 */
    static _Thread_local char name_copy[64];
    pthread_rwlock_rdlock(&g_module_lock);
    if (slot < g_module_count && g_modules && g_modules[slot].active) {
        strncpy(name_copy, g_modules[slot].name, sizeof name_copy - 1);
        name_copy[sizeof name_copy - 1] = '\0';
        pthread_rwlock_unlock(&g_module_lock);
        return name_copy;
    }
    pthread_rwlock_unlock(&g_module_lock);
    return g_slot_names[slot];
}
