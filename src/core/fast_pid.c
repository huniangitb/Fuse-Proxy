#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include "fast_pid.h"
#define DIRENT_BUF_SIZE (1024 * 1024)
static char* g_dirent_buf = nullptr;
#define MAX_CACHED_PIDS 65536
#define PID_BITMAP_MAX  1048576 // Android 常规 PID 支持最高至 1048575
static uint8_t* g_pid_bitmap = nullptr;
static int* g_cached_pids = nullptr;
static int g_cached_count = -1;
int fast_pid_init() {
    if (g_dirent_buf) return 0;
    g_dirent_buf = malloc(DIRENT_BUF_SIZE);
    if (!g_dirent_buf) return -1;
    // 分配 128KB 位图缓冲
    g_pid_bitmap = calloc(PID_BITMAP_MAX / 8, 1);
    if (!g_pid_bitmap) {
        free(g_dirent_buf);
        g_dirent_buf = nullptr;
        return -1;
    }
    return 0;
}
void fast_pid_cleanup() {
    if (g_dirent_buf) {
        free(g_dirent_buf);
        g_dirent_buf = nullptr;
    }
    if (g_pid_bitmap) {
        free(g_pid_bitmap);
        g_pid_bitmap = nullptr;
    }
    fast_pid_cache_clear();
}
void fast_pid_cache_clear() {
    if (g_cached_pids) {
        free(g_cached_pids);
        g_cached_pids = nullptr;
    }
    g_cached_count = -1;
    if (g_pid_bitmap) {
        memset(g_pid_bitmap, 0, PID_BITMAP_MAX / 8);
    }
}
/* 常数级时间复杂度 O(1) 的极速检查 */
static inline bool is_pid_cached(int pid) {
    if (!g_pid_bitmap || pid < 0 || pid >= PID_BITMAP_MAX) return false;
    return (g_pid_bitmap[pid / 8] & (1 << (pid % 8))) != 0;
}
/* 追加 PID 追踪至顺序清理列表并更新快速位图状态 */
static void cache_add_pid(int pid) {
    if (!g_pid_bitmap || pid < 0 || pid >= PID_BITMAP_MAX) return;
    if (is_pid_cached(pid)) return;
    g_pid_bitmap[pid / 8] |= (1 << (pid % 8));
    if (!g_cached_pids) {
        g_cached_pids = malloc(MAX_CACHED_PIDS * sizeof(int));
        if (!g_cached_pids) {
            g_cached_count = -1;
            return;
        }
        g_cached_count = 0;
    }
    if (g_cached_count >= MAX_CACHED_PIDS) return;
    g_cached_pids[g_cached_count++] = pid;
}
bool proc_get_cmdline(int pid, char* buf, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t len = read(fd, buf, size - 1);
    close(fd);
    if (len > 0) {
        buf[len] = '\0';
        return true;
    }
    return false;
}
static bool check_cmdline(int pid, const char* target) {
    char buf[256];
    if (proc_get_cmdline(pid, buf, sizeof(buf))) {
        if (strcmp(buf, target) == 0) return true;
    }
    return false;
}
int fast_pid_find(const char* target_package) {
    if (!g_dirent_buf) {
        if (fast_pid_init() != 0) return -1;
    }
    int proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd < 0) return -1;
    int found_pid = -1;
    while (true) {
        long nread = syscall(SYS_getdents64, proc_fd, g_dirent_buf, DIRENT_BUF_SIZE);
        if (nread == -1) {
            if (errno == EINTR) continue;
            break;
        }
        if (nread == 0) break;
        for (long bpos = 0; bpos < nread;) {
            struct linux_dirent64* d = (struct linux_dirent64*)(g_dirent_buf + bpos);
            if (d->d_reclen == 0) break;
            if (d->d_type == DT_DIR) {
                char first = d->d_name[0];
                if (first >= '1' && first <= '9') {
                    int pid = atoi(d->d_name);
                    if (check_cmdline(pid, target_package)) {
                        found_pid = pid;
                        goto cleanup;
                    }
                }
            }
            bpos += d->d_reclen;
        }
    }
cleanup:
    close(proc_fd);
    return found_pid;
}
void fast_pid_each(pid_callback_t callback, void* data) {
    if (!g_dirent_buf) {
        if (fast_pid_init() != 0) return;
    }
    int proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd < 0) return;
    char cmd_buf[256];
    while (true) {
        long nread = syscall(SYS_getdents64, proc_fd, g_dirent_buf, DIRENT_BUF_SIZE);
        if (nread == -1) {
            if (errno == EINTR) continue;
            break;
        }
        if (nread == 0) break;
        for (long bpos = 0; bpos < nread;) {
            struct linux_dirent64* d = (struct linux_dirent64*)(g_dirent_buf + bpos);
            if (d->d_reclen == 0) break;
            if (d->d_type == DT_DIR) {
                char first = d->d_name[0];
                if (first >= '1' && first <= '9') {
                    int pid = atoi(d->d_name);
                    if (is_pid_cached(pid)) {
                        bpos += d->d_reclen;
                        continue;
                    }
                    if (proc_get_cmdline(pid, cmd_buf, sizeof(cmd_buf))) {
                        int cb_ret = callback(pid, cmd_buf, data);
                        if (cb_ret != 2) cache_add_pid(pid);
                        if (cb_ret == 1) goto cleanup;
                    }
                }
            }
            bpos += d->d_reclen;
        }
    }
cleanup:
    close(proc_fd);
    // 释放和修剪已死亡进程缓存，同时清除位图中对应的标志位
    if (g_cached_pids && g_cached_count > 0) {
        for (int i = g_cached_count - 1; i >= 0; i--) {
            int pid = g_cached_pids[i];
            if (kill(pid, 0) != 0) {
                if (pid >= 0 && pid < PID_BITMAP_MAX && g_pid_bitmap) {
                    g_pid_bitmap[pid / 8] &= ~(1 << (pid % 8)); // 移除置位
                }
                g_cached_pids[i] = g_cached_pids[--g_cached_count];
            }
        }
    }
}