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
extern volatile sig_atomic_t g_should_exit;
extern volatile sig_atomic_t g_reload_config;
extern volatile sig_atomic_t g_passive_mode;
extern int g_epoll_fd;

const char* get_active_mnt_src();
void notify_fuses(int sig);

/* 核心暴露：非阻塞异步控制接口 */
void register_fuse_ready_pipe(int fd, void* ctx);
bool register_async_mount_pipe(int fd, void* ctx);
void handle_fuse_ready_event(void *ptr);
void handle_async_mount_event(void *ptr);

#endif /* INJECTOR_H */