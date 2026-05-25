#ifndef NS_UTILS_H
#define NS_UTILS_H

#include <limits.h>
#include <sys/types.h>

/* 绑定挂载 */
int ns_bind_mount(int pid, const char* source, const char* target);

/* 递归卸载 */
int ns_umount_recursive(int pid, const char* target);

/* 卸载并删除目录 */
int ns_umount_and_rmdir(int pid, const char* target);

/* 检查是否已挂载 */
int ns_is_mounted(int pid, const char* target_mount, const char* match_fs_name);

/* 设置挂载点为共享 */
int ns_make_shared(int pid, const char* target);

/* 移动挂载 */
int ns_move_mount(int pid, const char* source, const char* target);

/* 查找原生子挂载点 */
int ns_find_native_submounts(int pid, const char* base_path,
                              char mount_points[][256], int max_count);

/* 带保留路径的绑定挂载 */
int ns_bind_mount_with_preserve(int pid, const char* source, const char* target,
                                 char preserve_paths[][256], int preserve_count);

#endif