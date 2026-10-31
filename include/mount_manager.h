#ifndef MOUNT_MANAGER_H
#define MOUNT_MANAGER_H

#include <sys/types.h>

bool app_has_active_rules(const char* pkg, uid_t uid);
int perform_app_mount(const char* pkg, int pid, uid_t uid, const char* mnt_src, const char* trigger);

/* 同步版：阻塞等待挂载完成，返回真实结果，用于 IPC 挂载线程。
   readiness_ms 见 ns_combined_mount：正预算（IPC_MOUNT_READINESS_MS）= 权威尝试，
   未就绪即 loud 失败并排重试；0 = 只查一次；负值（NSP_READINESS_QUIET）= 后台
   通道，未就绪属预期，日志按 DEBUG 处理、不记 ERROR。 */
int perform_app_mount_sync(const char* pkg, int pid, uid_t uid, const char* mnt_src,
                           int readiness_ms);

/* 全局替换模式：对非目标应用卸载项目 FUSE 并 bind 回该用户备份的系统视图（幂等） */
int perform_app_restore(const char* pkg, int pid, uid_t uid);

/* 注入状态检查（跨文件）：复用挂载状态缓存，未命中时读取一次并写入缓存 */
bool is_project_fuse_cached(int pid, const char* target_path);

#endif