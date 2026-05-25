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
#include <ctype.h>
#include <errno.h>
#include <signal.h>

#include "fast_pid.h"

#define DIRENT_BUF_SIZE (1024 * 1024)

struct linux_dirent64 {
    unsigned long  d_ino;
    long           d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

static char* g_dirent_buf = NULL;

#define MAX_CACHED_PIDS 65536
static int* g_cached_pids = NULL;
static int g_cached_count = -1; 

int fast_pid_init(void) {
    if (g_dirent_buf) return 0;
    g_dirent_buf = malloc(DIRENT_BUF_SIZE);
    if (!g_dirent_buf) return -1;
    return 0;
}

void fast_pid_cleanup(void) {
    if (g_dirent_buf) {
        free(g_dirent_buf);
        g_dirent_buf = NULL;
    }
    fast_pid_cache_clear();
}

void fast_pid_cache_clear(void) {
    if (g_cached_pids) {
        free(g_cached_pids);
        g_cached_pids = NULL;
    }
    g_cached_count = -1;
}

static int is_pid_cached(int pid) {
    if (!g_cached_pids) return 0;
    for (int i = 0; i < g_cached_count; i++) {
        if (g_cached_pids[i] == pid) return 1;
    }
    return 0;
}

static void cache_add_pid(int pid) {
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

static int get_cmdline(int pid, char* buf, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t len = read(fd, buf, size - 1);
    close(fd);
    if (len > 0) {
        buf[len] = '\0';
        return 1;
    }
    return 0;
}

static int check_cmdline(int pid, const char* target) {
    char buf[256];
    if (get_cmdline(pid, buf, sizeof(buf))) {
        if (strcmp(buf, target) == 0) return 1;
    }
    return 0;
}

int fast_pid_find(const char* target_package) {
    if (!g_dirent_buf) {
        if (fast_pid_init() != 0) return -1;
    }
    int proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd < 0) return -1;
    int found_pid = -1;
    while (1) {
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
                    if (check_cmdline(pid, target_package)) { found_pid = pid; goto cleanup; }
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
    if (!g_dirent_buf) { if (fast_pid_init() != 0) return; }
    int proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd < 0) return;
    char cmd_buf[256];
    while (1) {
        long nread = syscall(SYS_getdents64, proc_fd, g_dirent_buf, DIRENT_BUF_SIZE);
        if (nread == -1) { if (errno == EINTR) continue; break; }
        if (nread == 0) break;
        for (long bpos = 0; bpos < nread;) {
            struct linux_dirent64* d = (struct linux_dirent64*)(g_dirent_buf + bpos);
            if (d->d_reclen == 0) break; 
            if (d->d_type == DT_DIR) {
                char first = d->d_name[0];
                if (first >= '1' && first <= '9') {
                    int pid = atoi(d->d_name);
                    if (is_pid_cached(pid)) { bpos += d->d_reclen; continue; }
                    if (get_cmdline(pid, cmd_buf, sizeof(cmd_buf))) {
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
    if (g_cached_pids && g_cached_count > 0) {
        for (int i = g_cached_count - 1; i >= 0; i--) {
            if (kill(g_cached_pids[i], 0) != 0) g_cached_pids[i] = g_cached_pids[--g_cached_count];
        }
    }
}