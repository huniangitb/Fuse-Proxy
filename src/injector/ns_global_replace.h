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
#include <sys/types.h>

typedef struct NsMountEntry {
    char mount_point[PATH_MAX];
    char source[PATH_MAX];
    char fstype[64];
    char dev[64]; /* major:minor，bind 与源共享 superblock，用于替换状态判断 */
    int depth;
} NsMountEntry;

/* mountinfo 全量读取上限：真实设备（多用户 + 嵌套视图 + f2fs 直通）可达 1900+ 行，
   旧上限 512 会截断族根（行号 1894+）与 nsp_global（1934 行），导致替换静默失败 */
#ifndef NS_MOUNTINFO_MAX
#define NS_MOUNTINFO_MAX 4096
#endif

/* 日志：定义于 ns_utils.c（ns 操作错误日志，写入 ERROR_LOG_PATH） */
void log_ns_error(const char* format, ...);

/* 命名空间执行原语：定义于 ns_utils.c（fork + setns + 状态管道同步），
   全局替换方案在目标命名空间内执行 replace/restore 时共用 */
int run_in_mnt_ns_timeout(int target_pid, int (*func)(void*), void* args, int* child_err,
                          int timeout_ms);

/* ---- mountinfo 枚举与族根工具（原 ns_utils.c static，拆分后跨文件共享） ----
   命名统一 ns_ 前缀（mount namespace 操作域），禁裸通用名污染全局命名空间 */
int ns_read_mountinfo_pid(int pid, NsMountEntry* out, int max);
bool ns_is_digit_char(char c);
bool ns_is_family_root(const char* mp);
int ns_parse_family_root(const char* mp, int* user_id);
int ns_gather_mounts_under(const NsMountEntry* all, int n, const char* base, bool include_self,
                           bool include_fuse, NsMountEntry* out, int max);
int ns_count_mounts_under(const NsMountEntry* all, int n, const char* base, bool include_self,
                          bool include_fuse);
void ns_sort_deepest_first(NsMountEntry* arr, int n);
void ns_sort_shallowest_first(NsMountEntry* arr, int n);
int ns_backup_point_state(int pid, const char* path);

/* ---- 全局替换方案导出入口（injector / global_replace_ctl / mount_manager 调用） ---- */
int ns_global_replace_system(int mnt_ns_pid, const char* fuse_src, const char* backup_root);
int ns_global_restore_system(int mnt_ns_pid, const char* backup_root);
int ns_restore_app_fuse(int app_pid, const char* fuse_src, const char* backup_root, int user_id);
int ns_global_status(int mnt_ns_pid, const char* fuse_src);
int ns_collect_mounts_under(int pid, const char* base_path, int include_self, int include_fuse,
                            char mount_points[][PATH_MAX], int max_count);

#endif /* NS_GLOBAL_REPLACE_H */
