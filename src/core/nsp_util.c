#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* pthread_setname_np 声明所需（模块侧无 -D_GNU_SOURCE 时） */
#endif
#include "nsp_util.h"
#include "nsp_constants.h"
#include "nsp_log.h"
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
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

char* nsp_str_trim(char* s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    char* end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = '\0';
    return s;
}

void nsp_log_line_sanitize(const char* in, char* out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    size_t w = 0;
    if (in) {
        for (const unsigned char* p = (const unsigned char*)in; *p; p++) {
            char esc[5];
            size_t elen = 0;
            switch (*p) {
            case '\n': memcpy(esc, "\\n", 2); elen = 2; break;
            case '\r': memcpy(esc, "\\r", 2); elen = 2; break;
            case '\t': memcpy(esc, "\\t", 2); elen = 2; break;
            case '\\': memcpy(esc, "\\\\", 2); elen = 2; break;
            default:
                if (*p < 0x20 || *p == 0x7f) {
                    snprintf(esc, sizeof esc, "\\x%02x", *p);
                    elen = 4;
                } else {
                    esc[0] = (char)*p;
                    elen = 1;
                }
            }
            if (w + elen + 1 > out_sz) break; /* 放不下即止（不半截转义） */
            memcpy(out + w, esc, elen);
            w += elen;
        }
    }
    out[w] = '\0';
}

bool nsp_send_all(int fd, const char* buf, size_t len) {
    while (len > 0) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue; /* 信号中断继续，防止大 JSON 应答截断 */
            return false;
        }
        if (n == 0) return false; /* 对端已关闭 */
        buf += n;
        len -= (size_t)n;
    }
    return true;
}

socklen_t nsp_uds_abstract_addr(struct sockaddr_un* addr, const char* name) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    addr->sun_path[0] = '\0';
    /* 长度按截断后实际写入计算（P2：旧版用截断前 strlen(name)，超长名会使
       bind/connect 的地址长度越过 sun_path 真实内容造成越界读） */
    strncpy(addr->sun_path + 1, name, sizeof(addr->sun_path) - 2);
    addr->sun_path[sizeof(addr->sun_path) - 1] = '\0';
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(addr->sun_path + 1));
}

int nsp_mkdir_p(const char* path, mode_t mode) {
    if (!path || !*path) return -1;
    char tmp[4096];
    size_t n = strlen(path);
    if (n >= sizeof(tmp)) return -1; /* 拒绝超长输入，杜绝 snprintf 静默截断 */
    memcpy(tmp, path, n + 1);
    if (n > 0 && tmp[n - 1] == '/') tmp[n - 1] = '\0';
    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                *p = '/';
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

void nsp_escape_cgroup(void) {
    char pid_s[32];
    snprintf(pid_s, sizeof(pid_s), "%d", (int)getpid());
    const char* targets[] = {
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
    if (pid > 0) exit(0); /* 父进程退出，service.sh 无需 & 即返回 */
    setsid();
    pid = fork(); /* 二次 fork 确保不重新获得控制终端 */
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

void nsp_set_thread_name(const char* name) {
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

/* ==================== App-rules 路径合成 ==================== */
/* 语义见 nsp_util.h：config_dir 由调用方传入（模块侧不链接 common.c）。 */

void nsp_app_rule_dir(const char* config_dir, int uid, char* out, size_t sz) {
    if (!out || sz == 0) return;
    if (uid == 0)
        snprintf(out, sz, "%s/%s", config_dir, NSP_APP_RULES_DIRNAME);
    else
        snprintf(out, sz, "%s/%s-%d", config_dir, NSP_APP_RULES_DIRNAME, uid);
}

void nsp_app_rule_path(const char* config_dir, int uid, const char* pkg, char* out, size_t sz) {
    if (!out || sz == 0) return;
    if (uid == 0)
        snprintf(out, sz, "%s/%s/%s.conf", config_dir, NSP_APP_RULES_DIRNAME, pkg);
    else
        snprintf(out, sz, "%s/%s-%d/%s.conf", config_dir, NSP_APP_RULES_DIRNAME, uid, pkg);
}

bool nsp_switch_on(const char* val) { return val && (strcmp(val, "ON") == 0 || strcmp(val, "1") == 0); }

bool nsp_is_app_rules_dirname(const char* name) {
    /* "-" 后缀形态长度 = "App-rules-" 字面量长度（sizeof-1 = 10） */
    return name &&
           (strcmp(name, NSP_APP_RULES_DIRNAME) == 0 ||
            strncmp(name, NSP_APP_RULES_DIRNAME "-", sizeof(NSP_APP_RULES_DIRNAME "-") - 1) == 0);
}

/* ==================== 日志级别词法 ==================== */
/* 声明在 nsp_log.h（级别词汇的唯一出处），实现放这里——纯查表、无全局依赖，
   log_monitor/log_ctl 与不链接 common.c 的模块都能直接链接复用。log_monitor
   的落盘 / 查询 / 流式三处渲染共用，避免各写一份名称表。 */

const char* nsp_log_level_name(int level) {
    switch (level) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO: return "INFO";
        case LOG_WARN: return "WARN";
        case LOG_ERROR: return "ERROR";
        /* 通道标记（LOG_IO/LOG_LOGCAT）不经此渲染；越界值按 INFO 兜底，
           与 log_internal 对级别的宽容一致 */
        default: return "INFO";
    }
}

int nsp_log_level_parse(const char* name) {
    if (!name || !*name) return -1;
    const char* p = name;
    while (*p >= '0' && *p <= '9') p++;
    int level = -1;
    if (p != name && *p == '\0') {
        level = atoi(name); /* 旧落盘行：纯数字等级 */
    } else {
        for (int i = LOG_DEBUG; i <= LOG_ERROR; i++) {
            if (strcmp(name, nsp_log_level_name(i)) == 0) {
                level = i;
                break;
            }
        }
    }
    /* 越界（未知名称 / 损坏的数字字段）一律判为无效：若原样放行，`9` 会通过
       任何 `--level` 过滤、又被 nsp_log_level_name 渲染成 INFO，等级面全失真 */
    return (level >= LOG_DEBUG && level <= LOG_ERROR) ? level : -1;
}

/* ==================== 通用动态扩充（低内存快道 + 堆溢出） ==================== */

static size_t nsp_dyn_limit(size_t max) {
    size_t lim = NSP_DYN_FORMAT_MAX;
    if (max > 0 && max < lim) lim = max;
    return lim;
}

char* nsp_vformat_dynamic(size_t max, const char* fmt, va_list ap) {
    if (!fmt) {
        errno = EINVAL;
        return NULL;
    }
    size_t lim = nsp_dyn_limit(max);
    va_list aq;
    va_copy(aq, ap);
    int need = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);
    if (need < 0) return NULL;
    if ((size_t)need >= lim) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    char* out = malloc((size_t)need + 1);
    if (!out) {
        errno = ENOMEM;
        return NULL;
    }
    va_copy(aq, ap);
    int n2 = vsnprintf(out, (size_t)need + 1, fmt, aq);
    va_end(aq);
    if (n2 < 0 || n2 != need) {
        free(out);
        return NULL;
    }
    return out;
}

char* nsp_format_dynamic(size_t max, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char* r = nsp_vformat_dynamic(max, fmt, ap);
    va_end(ap);
    return r;
}

int nsp_snprintf_dyn(char* fixed, size_t fixed_sz, char** heap_out, size_t max,
                     const char* fmt, ...) {
    if (heap_out) *heap_out = NULL;
    if (!fmt) return -1;
    /* 纯堆路径（无栈缓冲）：算长 → 一次 malloc → 落定 */
    if (!fixed || fixed_sz == 0) {
        va_list ap;
        va_start(ap, fmt);
        va_list aq;
        va_copy(aq, ap);
        int need = vsnprintf(NULL, 0, fmt, aq);
        va_end(aq);
        if (need < 0) {
            va_end(ap);
            return -1;
        }
        if ((size_t)need >= nsp_dyn_limit(max)) {
            va_end(ap);
            errno = ENAMETOOLONG;
            return -1;
        }
        if (!heap_out) {
            va_end(ap);
            return need;
        }
        char* h = malloc((size_t)need + 1);
        if (!h) {
            va_end(ap);
            errno = ENOMEM;
            return -1;
        }
        int n2 = vsnprintf(h, (size_t)need + 1, fmt, ap);
        va_end(ap);
        if (n2 < 0 || n2 != need) {
            free(h);
            return -1;
        }
        *heap_out = h;
        return need;
    }
    /* 栈快道：一次 vsnprintf 试写；返回值 need 本就是“需要多大”，
       放不下才 malloc 精确大小（常见短输入零堆分配）。 */
    va_list ap, aq;
    va_start(ap, fmt);
    va_copy(aq, ap);
    int need = vsnprintf(fixed, fixed_sz, fmt, ap);
    va_end(ap);
    if (need < 0) {
        va_end(aq);
        return -1;
    }
    if ((size_t)need < fixed_sz) {
        va_end(aq);
        return need;
    }
    if ((size_t)need >= nsp_dyn_limit(max)) {
        va_end(aq);
        errno = ENAMETOOLONG;
        return -1;
    }
    if (!heap_out) {
        va_end(aq);
        return need;
    }
    char* h = malloc((size_t)need + 1);
    if (!h) {
        va_end(aq);
        errno = ENOMEM;
        return -1;
    }
    int n2 = vsnprintf(h, (size_t)need + 1, fmt, aq);
    va_end(aq);
    if (n2 < 0 || n2 != need) {
        free(h);
        return -1;
    }
    *heap_out = h;
    return need;
}

int nsp_getline_capped(FILE* fp, char** buf, size_t* cap, size_t max, size_t* out_len) {
    if (!fp || !buf || !cap) {
        errno = EINVAL;
        return -1;
    }
    if (*buf == NULL || *cap < 256) {
        char* nb = realloc(*buf, 256);
        if (!nb) {
            errno = ENOMEM;
            return -1;
        }
        *buf = nb;
        *cap = 256;
    }
    size_t len = 0;
    (*buf)[0] = '\0';
    for (;;) {
        if (!fgets(*buf + len, *cap - len, fp)) {
            /* 读失败但已有内容 = 末行无换行：仍算一行 */
            if (len > 0) {
                if (max > 0 && len > max) return -2;
                if (out_len) *out_len = len;
                return 1;
            }
            return feof(fp) ? 0 : -1;
        }
        len += strlen(*buf + len);
        if (len > 0 && (*buf)[len - 1] == '\n') {
            (*buf)[--len] = '\0';
            if (len > 0 && (*buf)[len - 1] == '\r') (*buf)[--len] = '\0';
            /* 超长但不大（整行已在缓冲内）：按调用方约定整行跳过。
               空行（len==0）是有效行，返回 1 而非 0（0 只表 EOF）。 */
            if (max > 0 && len > max) return -2;
            if (out_len) *out_len = len;
            return 1;
        }
        if (feof(fp)) {
            if (max > 0 && len > max) return -2;
            if (out_len) *out_len = len;
            return 1;
        }
        /* 缓冲满而行未完：超长则只消费不存，峰值 ≤ max+512 */
        if (max > 0 && len >= max) {
            char discard[512];
            for (;;) {
                if (!fgets(discard, sizeof discard, fp)) break;
                if (strchr(discard, '\n') || feof(fp)) break;
            }
            return ferror(fp) ? -1 : -2;
        }
        size_t ncap = *cap * 2;
        if (max > 0 && ncap > max + 2) ncap = max + 2;
        if (max == 0 && ncap > NSP_DYN_FORMAT_MAX) {
            errno = EFBIG;
            return -1;
        }
        if (ncap <= *cap) {
            /* max 极小（<256）导致无法扩容：转丢弃 */
            char discard[512];
            for (;;) {
                if (!fgets(discard, sizeof discard, fp)) break;
                if (strchr(discard, '\n') || feof(fp)) break;
            }
            return ferror(fp) ? -1 : -2;
        }
        char* nb = realloc(*buf, ncap);
        if (!nb) {
            errno = ENOMEM;
            return -1;
        }
        *buf = nb;
        *cap = ncap;
    }
}

