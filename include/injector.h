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
/* ================= 注入方法（--inject-method=v1|v2|v3） =================
 *  v1 逐应用挂载（默认）：发现目标应用 → 进入其 mount namespace 挂载 FUSE。
 *  v2 全局替换：init 命名空间内把 emulated 三族族根整体替换为项目 FUSE，
 *     所有应用默认见代理视图；**非目标应用**（含系统应用）另行进入其命名
 *     空间卸载项目 FUSE 并 bind 回系统视图备份（卸载优先），故规则只对
 *     目标应用生效。
 *  v3 全局替换且不还原：基于 v2，但**不对非目标应用做任何还原/卸载**，
 *     等于默认全局挂载（含系统应用）。此时忽略 GLOBAL_INJECT 与
 *     SKIP_SYSTEM_APPS 两个全局参数（应用段/类别段头显式 OFF 仍生效）；
 *     FUSE 框架侧零改动——规则命中仍由框架按调用方 uid/pkg 判定。 */
typedef enum {
    INJECT_METHOD_V1 = 1,
    INJECT_METHOD_V2 = 2,
    INJECT_METHOD_V3 = 3,
} InjectMethod;
extern InjectMethod g_inject_method;
/* v2/v3 共用全局替换机制（族根整体替换，替代逐应用挂载） */
static inline bool inject_is_global_replace(void) {
    return g_inject_method >= INJECT_METHOD_V2;
}
/* 仅 v2 还原非目标应用；v3 一律保持全局代理视图 */
static inline bool inject_restore_nontarget(void) {
    return g_inject_method == INJECT_METHOD_V2;
}

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