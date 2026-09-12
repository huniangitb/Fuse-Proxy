#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* pthread_setname_np 声明所需（模块侧无 -D_GNU_SOURCE 时） */
#endif
#include "nsp_util.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

char *nsp_str_trim(char *s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = '\0';
    return s;
}

void nsp_send_all(int fd, const char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;   /* 信号中断继续，防止大 JSON 应答截断 */
            return;
        }
        if (n == 0) return;
        buf += n;
        len -= (size_t)n;
    }
}

socklen_t nsp_uds_abstract_addr(struct sockaddr_un *addr, const char *name) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    addr->sun_path[0] = '\0';
    /* 长度按截断后实际写入计算（P2：旧版用截断前 strlen(name)，超长名会使
       bind/connect 的地址长度越过 sun_path 真实内容造成越界读） */
    strncpy(addr->sun_path + 1, name, sizeof(addr->sun_path) - 2);
    addr->sun_path[sizeof(addr->sun_path) - 1] = '\0';
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(addr->sun_path + 1));
}

int nsp_mkdir_p(const char *path, mode_t mode) {
    if (!path || !*path) return -1;
    char tmp[4096];
    size_t n = strlen(path);
    if (n >= sizeof(tmp)) return -1;   /* 拒绝超长输入，杜绝 snprintf 静默截断 */
    memcpy(tmp, path, n + 1);
    if (n > 0 && tmp[n - 1] == '/') tmp[n - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) { *p = '/'; return -1; }
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

void nsp_escape_cgroup(void) {
    char pid_s[32];
    snprintf(pid_s, sizeof(pid_s), "%d", (int)getpid());
    const char *targets[] = {
        "/sys/fs/cgroup/cgroup.procs", /* v2 根 cgroup */
        "/dev/cpuctl/tasks",           /* v1 cpu */
        "/dev/cpuset/tasks",           /* v1 cpuset */
        "/dev/stune/tasks"             /* v1 stune */
    };
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        int fd = open(targets[i], O_WRONLY | O_CLOEXEC);
        if (fd >= 0) {
            /* 静默吞掉写入失败：路径在不同版本/配置下可能不存在或无写权限 */
            (void)write(fd, pid_s, strlen(pid_s));
            close(fd);
        }
    }
}

void nsp_daemonize(int preserve_fd) {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);   /* 父进程退出，service.sh 无需 & 即返回 */
    setsid();
    pid = fork();           /* 二次 fork 确保不重新获得控制终端 */
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    /* SIGPIPE 忽略必须在 daemonize 后设置：fork 子进程继承信号表，
       第二次 fork 后的孙子进程才是实际 daemon，此时设置最稳 */
    signal(SIGPIPE, SIG_IGN);
    /* 钳制 close 范围上限：sysconf 在某些环境可能返回 -1 或极大值 */
    long max_fd_l = sysconf(_SC_OPEN_MAX);
    int max_fd = (max_fd_l <= 0 || max_fd_l > 4096) ? 4096 : (int)max_fd_l;
    for (int x = max_fd; x >= 0; x--) {
        if (x != preserve_fd) close(x);
    }
    int dev_null = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (dev_null >= 0) {
        dup2(dev_null, 0);
        dup2(dev_null, 1);
        dup2(dev_null, 2);
        if (dev_null > 2) close(dev_null);
    }
}

void nsp_set_thread_name(const char *name) {
    if (!name || !name[0]) return;
#ifdef __linux__
    /* TASK_COMM_LEN=16（含 NUL）：超长截断，调用方无需预处理 */
    char buf[16];
    snprintf(buf, sizeof(buf), "%.15s", name);
    pthread_setname_np(pthread_self(), buf);
#else
    (void)name;
#endif
}
