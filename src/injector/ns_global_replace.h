/* ================= 全局替换式挂载方案共享接口 =================
 * 本头声明 ns_global_replace.c（原 ns_utils.c 全局替换区拆出）的
 * 跨文件符号：mountinfo 枚举与族根工具（ns_read_mountinfo_pid 等）同时供
 * ns_utils.c 的 combined mount Step J preserve 恢复使用；log_ns_error
 * 定义于 ns_utils.c（非 static 导出）。
 */
#ifndef NS_GLOBAL_REPLACE_H
#define NS_GLOBAL_REPLACE_H

#include <stdbool.h>
#include <stddef.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct NsMountEntry {
    char mount_point[PATH_MAX];
    char source[PATH_MAX];
    char fstype[64];
    char dev[64]; /* major:minor，bind 与源共享 superblock，用于替换状态判断 */
    int depth;
} NsMountEntry;

/* 历史遗留的固定条目容量：仅剩少量固定大小数组还在用它，**读取路径已不再受它
   限制**（ns_read_mountinfo_pid 按需增长，见下方声明）。真实设备上条目数只与命名
   空间里挂了多少东西有关，卡一个数字就必然会在某台设备上截断族根。 */
#ifndef NS_MOUNTINFO_MAX
#define NS_MOUNTINFO_MAX 4096
#endif

/* 挂载点定长槽容量：所有 mountinfo 收集路径统一用它。超长条目一律「告警并跳过」
   而非静默截断——截断后的路径会 umount 到错误位置（A9/C7）。 */
#ifndef NS_MOUNT_PATH_MAX
#define NS_MOUNT_PATH_MAX 256
#endif

/* mountinfo 单行视图：字段指针指向**扫描函数的栈缓冲**，仅在本回调内有效，
   不得跨行留存（需保存请自行拷贝）。 */
typedef struct {
    const char* mount_point; /* 第 5 字段（挂载点） */
    const char* source;      /* " - " 之后第 2 字段（源/fsname），缺省 "" */
    const char* fstype;      /* " - " 之后第 1 字段（文件系统类型），缺省 "" */
    const char* dev;         /* 第 3 字段（major:minor） */
    int depth;               /* mount_point 中 '/' 的个数 */
} NsMountLine;

/* 逐行扫描回调：返回非 0 立即停止扫描（提前退出）。 */
typedef int (*NsMountinfoLineFn)(const NsMountLine* ln, void* ctx);

/* 一次扫描的规模快照（诊断）：mountinfo 段偏慢时用来区分「命名空间条目多」与
   「CPU 被抢」——两者处置完全不同（前者靠预筛/减少扫描次数，后者只能挪出关键
   路径），旧实现只有总耗时，永远在猜。字段由**最近一次**扫描填写。 */
typedef struct NsMountinfoStats {
    long lines;      /* 读到的行数（不含被丢弃的超长行） */
    long bytes;      /* 读到的字节数 */
    long candidates; /* 通过前缀预筛、真正做了字段解析的行数 */
    int64_t scan_us; /* 本次扫描墙钟耗时（含 fopen / 读 / 解析） */
    int64_t cpu_us;  /* 同期本进程 CPU 时间（user+sys）：远小于墙钟 = 被调度饿着 */
    long csw;        /* 同期非自愿上下文切换次数：持续上升同样是"CPU 被抢"的证据 */
    bool truncated;  /* 是否丢弃过超长行 */
} NsMountinfoStats;

/* mountinfo 解析的**唯一实现**（定义于 ns_utils.c，C7 收口）：逐行读取
 * /proc/<pid>/mountinfo，解析后逐条回调。超长行（≥ 4096 字节）整行丢弃并 loud
 * 告警——不静默裂成两条畸形条目（与配置读取的「超长整行丢弃」语义一致）。
 * 返回已回调的行数；-1 = 打开失败（errno 有效）。 */
int ns_scan_mountinfo(int pid, NsMountinfoLineFn cb, void* ctx);

/* 同上，但把本次扫描的规模快照写进 out（调用方自带，不会被并发扫描覆盖）。
   用于「这次读取有没有丢弃过超长行」这类必须按次判定的场景。 */
int ns_scan_mountinfo_stats(int pid, NsMountinfoLineFn cb, void* ctx, NsMountinfoStats* out);

/* 收集 base 之下（严格子路径，不含 base 自身）的挂载点，按扫描顺序写入 out。
 * 容量触顶或路径 ≥ NS_MOUNT_PATH_MAX 一律 loud 告警并拒绝（绝不静默截断）；
 * who 为告警前缀（如 "递归卸载"）。返回收集条数；-1 = 打开 mountinfo 失败。 */
int ns_collect_mounts_under_pid(int pid, const char* base, char (*out)[NS_MOUNT_PATH_MAX],
                                int max, const char* who);

/* 取最近一次扫描（进程内）的规模快照；out 为空则忽略。仅供诊断输出使用——
   判据一律由扫描结果本身给出，不得据此改变行为。 */
void ns_mountinfo_last_stats(NsMountinfoStats* out);

/* 多目标单次扫描的一个收集目标：语义与 ns_collect_mounts_under_pid 完全一致
   （严格子路径、不含 base 自身、容量触顶告警并拒绝截断）。 */
typedef struct NsCollectTarget {
    const char* base;               /* 子树根 */
    char (*out)[NS_MOUNT_PATH_MAX]; /* 输出槽 */
    int max;                        /* 槽容量 */
    const char* who;                /* 告警前缀 */
    int n;                          /* 输出：收集条数（入口不读） */
} NsCollectTarget;

/* 一次扫描收集多棵子树（上限 NS_COLLECT_TARGETS_MAX=4）：各目标互不影响，
   某个目标触顶不影响其它目标继续收集。返回 0 = 扫描完成（-1 = 打开失败）。 */
int ns_collect_mounts_multi(int pid, NsCollectTarget* targets, int ntargets);

/* 带前缀预筛的全量扫描：只有行内出现某个前缀（子串）才解析字段并回调。
   预筛是**必要非充分**条件，回调收到的行内容与 ns_scan_mountinfo 逐字一致，
   调用方仍需按 mount_point 做精确判定。用于"只关心某几棵子树"的既有扫描点
   （如 ns_find_native_submounts），把几千条无关挂载的解析成本省掉。 */
int ns_scan_mountinfo_prefixed(int pid, const char* const* prefixes, int nprefixes,
                               NsMountinfoLineFn cb, void* ctx);

/* 日志：定义于 ns_utils.c（ns 操作错误日志，写入 ERROR_LOG_PATH） */
void log_ns_error(const char* format, ...);

/* 命名空间执行原语：定义于 ns_utils.c（fork + setns + 状态管道同步），
   全局替换方案在目标命名空间内执行 replace/restore 时共用 */
int run_in_mnt_ns_timeout(int target_pid, int (*func)(void*), void* args, int* child_err,
                          int timeout_ms);

/* ---- mountinfo 枚举与族根工具（原 ns_utils.c static，拆分后跨文件共享） ----
   命名统一 ns_ 前缀（mount namespace 操作域），禁裸通用名污染全局命名空间 */
/* 读取指定进程的 mountinfo 全字段（只解析文件，不进入命名空间）。
 *
 * 条目数不设上限：内部按需增长（realloc），调用方不再预分配，也就不存在「读满
 * 就停」。条目数随多用户与嵌套视图增长，任何固定上限都会在某台设备上漏掉族根或
 * 目标挂载点。
 *
 * 返回条目数（>=0，0 = 该命名空间没有挂载条目）；-1 = **结论未知**（打开失败、
 * 内存不足、或扫描中丢弃过超长行——这份列表不完整）。调用方必须把 -1 当成
 * 「不知道」而不是「没有挂载」：后者会让决策路径去挂一个已经挂过的视图，或者把
 * 活着的视图判成「未替换」再替换一次。
 *
 * 成功时 *out 由本函数分配，调用方负责 free（返回 0 时 *out 为 NULL）。 */
int ns_read_mountinfo_pid(int pid, NsMountEntry** out);
bool ns_is_digit_char(char c);
bool ns_is_family_root(const char* mp);
int ns_parse_family_root(const char* mp, int* user_id);
int ns_gather_mounts_under(const NsMountEntry* all, int n, const char* base, bool include_self,
                           bool include_fuse, NsMountEntry* out, int max);
int ns_count_mounts_under(const NsMountEntry* all, int n, const char* base, bool include_self,
                          bool include_fuse);
void ns_sort_deepest_first(NsMountEntry* arr, int n);
void ns_sort_shallowest_first(NsMountEntry* arr, int n);
/* 备份点状态。读取 mountinfo 失败时返回 NS_BACKUP_UNKNOWN——既不能当「未挂载」
   （会往已有备份上再 bind 一层），也不能当「已挂载」（会信任不存在的备份）。 */
#define NS_BACKUP_UNKNOWN (-2)
#define NS_BACKUP_POLLUTED (-1)
#define NS_BACKUP_ABSENT 0
#define NS_BACKUP_VALID 1
int ns_backup_point_state(int pid, const char* path);

/* ---- 全局替换方案导出入口（injector / global_replace_ctl / mount_manager 调用） ---- */
/* 返回值：0=已替换；1=尚未就绪（命名空间内还没有任何 emulated 族根，vold 可能尚未
   建立该用户的卷）——调用方应退避重试，**不得当作成功**；<0=失败（已尽力回滚）。
   injector 的周期对账依赖这三态区分，见 injector.c 的 maybe_reconcile_global_replace()。 */
int ns_global_replace_system(int mnt_ns_pid, const char* fuse_src, const char* backup_root);
int ns_global_restore_system(int mnt_ns_pid, const char* backup_root);
int ns_restore_app_fuse(int app_pid, const char* fuse_src, const char* backup_root, int user_id);
int ns_global_status(int mnt_ns_pid, const char* fuse_src);
int ns_collect_mounts_under(int pid, const char* base_path, int include_self, int include_fuse,
                            char mount_points[][PATH_MAX], int max_count);

#endif /* NS_GLOBAL_REPLACE_H */
