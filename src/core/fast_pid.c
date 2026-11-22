#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include "fast_pid.h"
/* getdents64 的缓冲区每次调用各一份（栈上 64KB）：原来是一块全文件共享的 1MB
   堆缓冲，两个线程同时遍历 /proc 会互相覆盖目录项，pid 集合会丢、会串。 */
#define DIRENT_BUF_SIZE (64 * 1024)
#define MAX_CACHED_PIDS 65536
#define PID_BITMAP_MAX  1048576 // Android 常规 PID 支持最高至 1048575
static uint8_t* g_pid_bitmap = nullptr;
static int* g_cached_pids = nullptr;
static int g_cached_count = -1;
/* 位图与 pid 缓存被多个线程共享：事件循环每轮调 fast_pid_cache_clear()，恢复
   worker 与启动扫描调 fast_pid_each()（内部 cache_add_pid、末段修剪、缓存重建）。
   旧实现默认「只有一个调用线程」，fast_pid_each 修剪时会改写并释放 g_cached_pids
   ——跨线程就是 use-after-free（ASan 实测：READ 命中修剪循环，freed by
   fast_pid_cache_clear）。锁只罩缓存访问：回调与 /proc 遍历一律在锁外，否则一次
   全进程扫描会把事件循环卡在 fast_pid_cache_clear 上，等于把慢活搬回循环。 */
static pthread_mutex_t g_fp_mu = PTHREAD_MUTEX_INITIALIZER;
int fast_pid_init() {
    pthread_mutex_lock(&g_fp_mu);
    if (g_pid_bitmap) {
        pthread_mutex_unlock(&g_fp_mu);
        return 0;
    }
    // 分配 128KB 位图缓冲
    g_pid_bitmap = calloc(PID_BITMAP_MAX / 8, 1);
    int rc = g_pid_bitmap ? 0 : -1;
    pthread_mutex_unlock(&g_fp_mu);
    return rc;
}
void fast_pid_cleanup() {
    pthread_mutex_lock(&g_fp_mu);
    free(g_pid_bitmap);
    g_pid_bitmap = nullptr;
    free(g_cached_pids);
    g_cached_pids = nullptr;
    g_cached_count = -1;
    pthread_mutex_unlock(&g_fp_mu);
}
void fast_pid_cache_clear() {
    pthread_mutex_lock(&g_fp_mu);
    free(g_cached_pids);
    g_cached_pids = nullptr;
    g_cached_count = -1;
    if (g_pid_bitmap) {
        memset(g_pid_bitmap, 0, PID_BITMAP_MAX / 8);
    }
    pthread_mutex_unlock(&g_fp_mu);
}
/* 常数级时间复杂度 O(1) 的极速检查（调用方须持锁） */
static bool is_pid_cached_locked(int pid) {
    if (!g_pid_bitmap || pid < 0 || pid >= PID_BITMAP_MAX) return false;
    return (g_pid_bitmap[pid / 8] & (1 << (pid % 8))) != 0;
}
static bool is_pid_cached(int pid) {
    pthread_mutex_lock(&g_fp_mu);
    const bool hit = is_pid_cached_locked(pid);
    pthread_mutex_unlock(&g_fp_mu);
    return hit;
}
/* 追加 PID 追踪至顺序清理列表并更新快速位图状态（调用方须持锁） */
static void cache_add_pid_locked(int pid) {
    if (!g_pid_bitmap || pid < 0 || pid >= PID_BITMAP_MAX) return;
    if (is_pid_cached_locked(pid)) return;
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
static void cache_add_pid(int pid) {
    pthread_mutex_lock(&g_fp_mu);
    cache_add_pid_locked(pid);
    pthread_mutex_unlock(&g_fp_mu);
}
/* 释放和修剪已死亡进程缓存，同时清除位图中对应的标志位 */
static void cache_prune_dead(void) {
    pthread_mutex_lock(&g_fp_mu);
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
    pthread_mutex_unlock(&g_fp_mu);
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
    if (fast_pid_init() != 0) return -1;
    char dirent_buf[DIRENT_BUF_SIZE];
    int proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd < 0) return -1;
    int found_pid = -1;
    while (true) {
        long nread = syscall(SYS_getdents64, proc_fd, dirent_buf, DIRENT_BUF_SIZE);
        if (nread == -1) {
            if (errno == EINTR) continue;
            break;
        }
        if (nread == 0) break;
        for (long bpos = 0; bpos < nread;) {
            struct linux_dirent64* d = (struct linux_dirent64*)(dirent_buf + bpos);
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
    if (fast_pid_init() != 0) return;
    char dirent_buf[DIRENT_BUF_SIZE];
    int proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd < 0) return;
    char cmd_buf[256];
    while (true) {
        long nread = syscall(SYS_getdents64, proc_fd, dirent_buf, DIRENT_BUF_SIZE);
        if (nread == -1) {
            if (errno == EINTR) continue;
            break;
        }
        if (nread == 0) break;
        for (long bpos = 0; bpos < nread;) {
            struct linux_dirent64* d = (struct linux_dirent64*)(dirent_buf + bpos);
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
    cache_prune_dead();
}