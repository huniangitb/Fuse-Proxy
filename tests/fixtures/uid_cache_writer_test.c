#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* 真实 src/injector/uid_cache_writer.c + src/core/uid_map.c。
   只替换 uid.map / uid.map.tmp 的路径（私有临时目录）、fsync（慢盘注入）与一点
   日志汇，不替身任何落盘逻辑：request 只置位唤醒、写者取快照整表重写、flush/shutdown
   的等待与收尾都走生产实现。
   判别目标：旧实现把「读全表 + 写 tmp + fsync + rename」整段放在 IPC ACK 路径上
   并持 uid 表锁；新实现把整段搬到落盘线程，请求路径只花 µs。 */
#include "uid_cache_writer.h"

#include "common.h"
#include "nsp_log.h"

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* 日志汇：落盘逻辑不经过它，只把生产宏的符号接上 */
LogLevel g_min_log_level = LOG_ERROR;
void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}

#define MAX_TABLE 256
static UidMapEntry g_table[MAX_TABLE];
static int g_table_count;
static pthread_mutex_t g_table_mu = PTHREAD_MUTEX_INITIALIZER;

static const char* g_map_path;
static const char* g_tmp_path;
static int g_fsync_delay_ms;
static _Atomic int g_fsync_calls;

int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    atomic_fetch_add(&g_fsync_calls, 1);
    if (g_fsync_delay_ms > 0) {
        struct timespec ts = {g_fsync_delay_ms / 1000, (long)(g_fsync_delay_ms % 1000) * 1000000L};
        nanosleep(&ts, NULL); /* 慢盘：让「同步落盘」的代价可测 */
    }
    return __real_fsync(fd);
}

FILE* __real_fopen(const char*, const char*);
FILE* __wrap_fopen(const char* path, const char* mode) {
    if (!strcmp(path, CONFIG_DIR "/uid.map"))
        path = g_map_path;
    else if (!strcmp(path, CONFIG_DIR "/uid.map.tmp"))
        path = g_tmp_path;
    return __real_fopen(path, mode);
}

int __real_rename(const char*, const char*);
int __wrap_rename(const char* from, const char* to) {
    if (!strcmp(from, CONFIG_DIR "/uid.map.tmp")) from = g_tmp_path;
    if (!strcmp(to, CONFIG_DIR "/uid.map")) to = g_map_path;
    return __real_rename(from, to);
}

int __real_unlink(const char*);
int __wrap_unlink(const char* path) {
    if (!strcmp(path, CONFIG_DIR "/uid.map"))
        path = g_map_path;
    else if (!strcmp(path, CONFIG_DIR "/uid.map.tmp"))
        path = g_tmp_path;
    return __real_unlink(path);
}

/* 内存表快照（等价于 injector 里 uid_map_snapshot 的角色） */
static UidMapEntry* snapshot(int* count_out) {
    if (count_out) *count_out = 0;
    pthread_mutex_lock(&g_table_mu);
    int count = g_table_count;
    UidMapEntry* copy = NULL;
    if (count > 0) {
        copy = malloc((size_t)count * sizeof(UidMapEntry));
        if (copy) {
            memcpy(copy, g_table, (size_t)count * sizeof(UidMapEntry));
        } else {
            count = 0;
        }
    }
    pthread_mutex_unlock(&g_table_mu);
    if (count_out) *count_out = count;
    return copy;
}

/* 模拟 update_uid_map_locked 的内存写入（生产里这段现在也是纯内存） */
static void table_put(uid_t uid, const char* pkg) {
    pthread_mutex_lock(&g_table_mu);
    bool updated = false;
    for (int i = 0; i < g_table_count; i++) {
        if (g_table[i].uid == uid) {
            snprintf(g_table[i].pkg, sizeof(g_table[i].pkg), "%s", pkg);
            updated = true;
            break;
        }
    }
    if (!updated && g_table_count < MAX_TABLE) {
        g_table[g_table_count].uid = uid;
        snprintf(g_table[g_table_count].pkg, sizeof(g_table[g_table_count].pkg), "%s", pkg);
        g_table_count++;
    }
    pthread_mutex_unlock(&g_table_mu);
}

static long long now_us(clockid_t cid) {
    struct timespec ts;
    clock_gettime(cid, &ts);
    return (long long)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static int count_lines(const char* path) {
    FILE* fp = fopen(path, "re");
    if (!fp) return -1;
    int lines = 0;
    char buf[256];
    while (fgets(buf, sizeof buf, fp)) lines++;
    fclose(fp);
    return lines;
}

static bool file_has(const char* path, const char* needle) {
    FILE* fp = fopen(path, "re");
    if (!fp) return false;
    bool found = false;
    char buf[256];
    while (fgets(buf, sizeof buf, fp)) {
        if (strstr(buf, needle)) {
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

static int tasks(void);

/* pthread_join 返回后，内核仍可能晚一拍才摘掉 /proc/self/task 里的条目（本仓其它
   线程数断言都踩过）：退出后的收尾断言要给一个有界收敛窗口，而不是立刻快照。 */
static int tasks_settle(void) {
    for (int i = 0; i < 400; i++) {
        int n = tasks();
        if (n <= 1) return n;
        usleep(5000);
    }
    return tasks();
}

static int tasks(void) {
    DIR* dir = opendir("/proc/self/task");
    if (!dir) return -1;
    int count = 0;
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') count++;
    }
    closedir(dir);
    return count;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <mode> <workdir>\n", argv[0]);
        return 2;
    }
    const char* mode = argv[1];
    static char map_path[512];
    static char tmp_path[512];
    snprintf(map_path, sizeof map_path, "%s/uid.map", argv[2]);
    snprintf(tmp_path, sizeof tmp_path, "%s/uid.map.tmp", argv[2]);
    g_map_path = map_path;
    g_tmp_path = tmp_path;

    if (!strcmp(mode, "ack")) {
        g_fsync_delay_ms = 200;
        table_put(50001, "com.new.app");
        uid_cache_write_init(snapshot);
        long long t0 = now_us(CLOCK_MONOTONIC);
        uid_cache_write_request(); /* 生产等价：ACK 路径上的落盘请求 */
        long long request_us = now_us(CLOCK_MONOTONIC) - t0;
        long long f0 = now_us(CLOCK_MONOTONIC);
        uid_cache_write_flush();
        long long flush_ms = (now_us(CLOCK_MONOTONIC) - f0) / 1000;
        int has = file_has(map_path, "com.new.app") ? 1 : 0;
        int calls = atomic_load(&g_fsync_calls);
        uid_cache_write_shutdown();
        printf("request_us=%lld flush_ms=%lld fsync_calls=%d file_has_entry=%d tasks=%d\n",
               request_us, flush_ms, calls, has, tasks_settle());
        return (request_us < 5000 && flush_ms >= 150 && calls >= 1 && has == 1) ? 0 : 1;
    }
    if (!strcmp(mode, "coalesce")) {
        g_fsync_delay_ms = 200;
        uid_cache_write_init(snapshot);
        for (int i = 0; i < 50; i++) {
            char pkg[64];
            snprintf(pkg, sizeof pkg, "com.burst.%d", i);
            table_put((uid_t)(50100 + i), pkg);
            uid_cache_write_request();
            usleep(1000); /* 落盘期间持续有新请求：必须合并，不得排队 50 次 fsync */
        }
        uid_cache_write_flush();
        int calls = atomic_load(&g_fsync_calls);
        int lines = count_lines(map_path);
        uid_cache_write_shutdown();
        printf("fsync_calls=%d entries_in_file=%d tasks=%d\n", calls, lines, tasks_settle());
        return (calls <= 4 && lines == 50) ? 0 : 1;
    }
    if (!strcmp(mode, "shutdown")) {
        table_put(50002, "com.exit.app");
        uid_cache_write_init(snapshot);
        uid_cache_write_request();
        uid_cache_write_shutdown(); /* 不先 flush：退出路径必须把已请求的一轮写完 */
        int has = file_has(map_path, "com.exit.app") ? 1 : 0;
        const int t = tasks_settle();
        printf("file_has_entry=%d tasks=%d\n", has, t);
        return (has == 1 && t == 1) ? 0 : 1;
    }
    if (!strcmp(mode, "inline-old")) {
        /* 旧实现：ACK 路径上直接 upsert（读全表 + tmp + fsync + rename）。
           同一条慢 fsync 下它花掉的时间就是旧实现每次新映射的代价。 */
        g_fsync_delay_ms = 200;
        long long t0 = now_us(CLOCK_MONOTONIC);
        int rc = uid_map_upsert(50009, "com.legacy.app");
        long long inline_ms = (now_us(CLOCK_MONOTONIC) - t0) / 1000;
        printf("rc=%d inline_ms=%lld fsync_calls=%d\n", rc, inline_ms,
               atomic_load(&g_fsync_calls));
        return (rc == 0 && inline_ms >= 150) ? 0 : 1;
    }
    fprintf(stderr, "unknown mode %s\n", mode);
    return 2;
}