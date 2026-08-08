#ifndef INJECTOR_H
#define INJECTOR_H

#include <sys/types.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>

struct GlobalFuseInfo {
    pid_t pid;
    pid_t fuse_pid;
    char mnt_path[128];
    int crash_count;
    time_t last_crash_time;
    bool disabled;
};

extern struct GlobalFuseInfo g_global_fuse;
extern struct GlobalFuseInfo g_media_fuse;
extern volatile sig_atomic_t g_should_exit;
extern volatile sig_atomic_t g_reload_config;
extern volatile sig_atomic_t g_passive_mode;
extern volatile sig_atomic_t g_fuse_ready;
extern int g_epoll_fd;
extern int g_global_root_fd;  /* 追加根目录 fd 的全局外部引用 */
/* 全局替换式挂载方案开关（--global-replace）：true 时以卸载优先替代逐应用挂载 */
extern bool g_global_replace_mode;

const char* get_active_mnt_src(void);
const char* get_media_mnt_src(void);
void notify_fuses(int sig);

/* 核心暴露：非阻塞异步控制接口 */
void register_fuse_ready_pipe(int fd, void* ctx);
bool register_async_mount_pipe(int fd, void* ctx);
void handle_fuse_ready_event(void *ptr);
void handle_async_mount_event(void *ptr);

/* 挂载失败重试：由 handle_async_mount_event 在异步挂载失败时调用 */
void schedule_retry_mount(const char* pkg, int pid);

#endif /* INJECTOR_H */