#ifndef MOUNT_MANAGER_H
#define MOUNT_MANAGER_H

#include <sys/types.h>

bool app_has_active_rules(const char* pkg, uid_t uid);
int perform_app_mount(const char* pkg, int pid, uid_t uid, const char* mnt_src, const char* trigger);

/* 同步版：阻塞等待挂载完成，返回真实结果，用于 IPC 线程。
   readiness_ms 见 ns_combined_mount：0 = 目标视图未就绪时立即失败（供 IPC 的
   pre-specialize 快速尝试），>0 = 在其内等待 /storage/emulated 出现。 */
int perform_app_mount_sync(const char* pkg, int pid, uid_t uid, const char* mnt_src,
                           int readiness_ms);

/* 全局替换模式：对非目标应用卸载项目 FUSE 并 bind 回该用户备份的系统视图（幂等） */
int perform_app_restore(const char* pkg, int pid, uid_t uid);

/* 注入状态检查（跨文件）：复用挂载状态缓存，未命中时读取一次并写入缓存 */
bool is_project_fuse_cached(int pid, const char* target_path);

#endif