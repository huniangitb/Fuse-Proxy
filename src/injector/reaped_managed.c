#include "reaped_managed.h"

#include <sys/wait.h>

/* 受管子进程数量极少（全局 FUSE + 媒体 FUSE），4 个槽位足够覆盖并发/竞态下的
   先后回收；与 injector.c 的 g_global_fuse/g_media_fuse 一一对应。 */
#define REAPED_MANAGED_SLOTS 4

static struct {
    pid_t pid;
    int status;
} g_reaped_managed[REAPED_MANAGED_SLOTS];

void reaped_managed_put(pid_t pid, int status) {
    if (pid <= 0) return;
    for (int i = 0; i < REAPED_MANAGED_SLOTS; i++) {
        if (g_reaped_managed[i].pid == 0 || g_reaped_managed[i].pid == pid) {
            g_reaped_managed[i].pid = pid;
            g_reaped_managed[i].status = status;
            return;
        }
    }
}

bool reaped_managed_exited(pid_t pid, int* status_out) {
    if (pid <= 0) return false;
    for (int i = 0; i < REAPED_MANAGED_SLOTS; i++) {
        if (g_reaped_managed[i].pid != pid) continue;
        if (status_out) *status_out = g_reaped_managed[i].status;
        g_reaped_managed[i].pid = 0;
        return true;
    }
    int st = 0;
    if (waitpid(pid, &st, WNOHANG) == pid) {
        if (status_out) *status_out = st;
        return true;
    }
    return false;
}
