#ifndef MOUNT_MANAGER_H
#define MOUNT_MANAGER_H

#include <sys/types.h>

bool app_has_active_rules(const char* pkg, uid_t uid);
int perform_app_mount(const char* pkg, int pid, uid_t uid, const char* mnt_src, const char* trigger);

/* perform_app_mount_sync 的第三种结果：**视图未就绪，本次挂载未完成**。
   与 -1（真实失败）区分开，调用方据此 fail-open：ACK 回 OK 让应用继续跑（此时
   它本来也读不到存储），把补挂载交给后台重试队列（快档 20ms 起）。
   判据：errno ∈ {ENOENT（目标条目还没被 vold 装配）, ENODEV（源 FUSE 还没传播
   进本 ns）, ETIMEDOUT（ns 子进程超时）} 或 readiness_ms < 0（后台通道）。
   真机依据：322 次挂载中 202 次 >100ms、59 次 >250ms，根因是 vold 装配 ~135ms，
   不是挂载本身失败——把"未就绪"当失败既白等又刷 error.log（31 条）。 */
#define NSP_MOUNT_DEFERRED 1

/* 同步版：阻塞等待挂载完成，返回真实结果，用于 IPC 挂载线程。
   返回 0 = 已挂上；NSP_MOUNT_DEFERRED = 未就绪（可 fail-open）；-1 = 真实失败。
   readiness_ms 见 ns_combined_mount：正预算 = 权威尝试；0 = 只查一次；负值
   （NSP_READINESS_QUIET）= 后台通道，未就绪属预期，日志按 DEBUG 处理。 */
int perform_app_mount_sync(const char* pkg, int pid, uid_t uid, const char* mnt_src,
                           int readiness_ms);

/* 全局替换模式：对非目标应用卸载项目 FUSE 并 bind 回该用户备份的系统视图（幂等） */
int perform_app_restore(const char* pkg, int pid, uid_t uid);

/* 注入状态检查（跨文件）：复用挂载状态缓存，未命中时读取一次并写入缓存 */
bool is_project_fuse_cached(int pid, const char* target_path);

/* 丢弃某 pid 的挂载状态缓存快照（配置热对账、卸载后必须调用）：缓存是
   「上次探测结果」，热路径在动作前后都要按真实 mountinfo 重新判定，
   否则卸载后会一直命中「已挂载」而永远不再挂载（旧实现的热卸载失效点）。 */
void invalidate_app_mount_cache(int pid);

#endif