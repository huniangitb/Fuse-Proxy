#ifndef MOUNT_MANAGER_H
#define MOUNT_MANAGER_H

#include <sys/types.h>

bool app_has_active_rules(const char* pkg, uid_t uid);
int perform_app_mount(const char* pkg, int pid, uid_t uid, const char* mnt_src, const char* trigger);

/* 同步版：阻塞等待挂载完成，返回真实结果，用于 IPC 线程 */
int perform_app_mount_sync(const char* pkg, int pid, uid_t uid, const char* mnt_src);

#endif