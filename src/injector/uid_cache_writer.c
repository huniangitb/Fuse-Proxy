#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "uid_cache_writer.h"

#include "nsp_log.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

/* 落盘线程的唤醒协议：pending 由请求方置位、写者取走；writing 标记「正在写盘」，
 * 供 flush/shutdown 判断是否已经落地。stop 只由 shutdown 置位，写者会把已有的
 * pending 写完再退出——退出路径不留「置了位但没落盘」的窗口。 */
static pthread_mutex_t g_ucw_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_ucw_cv = PTHREAD_COND_INITIALIZER;
static pthread_t g_ucw_thread;
static UidCacheSnapshotFn g_ucw_snapshot;
static bool g_ucw_started;
static bool g_ucw_pending;
static bool g_ucw_writing;
static bool g_ucw_stop;

/* flush 的有界等待：条件变量默认 CLOCK_REALTIME，deadline 必须用同一时钟。 */
#define UCW_FLUSH_WAIT_MS 5000

static struct timespec ucw_realtime_deadline(int ms) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_sec += ms / 1000;
    t.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (t.tv_nsec >= 1000000000L) {
        t.tv_sec++;
        t.tv_nsec -= 1000000000L;
    }
    return t;
}

/* 写一轮：快照在锁外取（回调自己取表锁），落盘期间不持 g_ucw_mu，
 * 请求方随时可以继续置位（合并到下一轮）。 */
static void* ucw_main(void* unused) {
    (void)unused;
    pthread_mutex_lock(&g_ucw_mu);
    for (;;) {
        while (!g_ucw_pending && !g_ucw_stop) {
            pthread_cond_wait(&g_ucw_cv, &g_ucw_mu);
        }
        if (g_ucw_pending) {
            g_ucw_pending = false;
            g_ucw_writing = true;
            UidCacheSnapshotFn snapshot = g_ucw_snapshot;
            pthread_mutex_unlock(&g_ucw_mu);
            int count = 0;
            UidMapEntry* entries = snapshot ? snapshot(&count) : NULL;
            if (entries && count > 0) {
                int rc = uid_map_save(entries, count);
                if (rc != 0) {
                    /* 内存表仍是权威：盘上落后只会让下次启动多学一轮，不回退内存结果 */
                    LOG_WRN("uid.map 后台落盘失败 (rc=%d)，继续使用内存表", rc);
                }
            }
            free(entries);
            pthread_mutex_lock(&g_ucw_mu);
            g_ucw_writing = false;
            pthread_cond_broadcast(&g_ucw_cv);
            continue;
        }
        break; /* stop 且没有待写 */
    }
    pthread_mutex_unlock(&g_ucw_mu);
    return NULL;
}

void uid_cache_write_init(UidCacheSnapshotFn snapshot) {
    if (!snapshot) return;
    pthread_mutex_lock(&g_ucw_mu);
    g_ucw_snapshot = snapshot;
    bool failed = false;
    if (!g_ucw_started) {
        if (pthread_create(&g_ucw_thread, NULL, ucw_main, NULL) == 0) {
            g_ucw_started = true;
        } else {
            failed = true;
        }
    }
    pthread_mutex_unlock(&g_ucw_mu);
    if (failed) {
        LOG_ERR("uid.map 后台落盘线程创建失败，本次运行只维护内存表");
    }
}

void uid_cache_write_request(void) {
    pthread_mutex_lock(&g_ucw_mu);
    if (g_ucw_started) {
        g_ucw_pending = true;
        pthread_cond_signal(&g_ucw_cv);
    }
    pthread_mutex_unlock(&g_ucw_mu);
}

void uid_cache_write_flush(void) {
    pthread_mutex_lock(&g_ucw_mu);
    if (!g_ucw_started) {
        pthread_mutex_unlock(&g_ucw_mu);
        return;
    }
    struct timespec until = ucw_realtime_deadline(UCW_FLUSH_WAIT_MS);
    int rc = 0;
    while ((g_ucw_pending || g_ucw_writing) && rc == 0) {
        rc = pthread_cond_timedwait(&g_ucw_cv, &g_ucw_mu, &until);
    }
    bool still = g_ucw_pending || g_ucw_writing;
    pthread_mutex_unlock(&g_ucw_mu);
    if (still) {
        LOG_WRN("uid.map 落盘等待超时 (%dms%s)，继续退出", UCW_FLUSH_WAIT_MS,
                rc == ETIMEDOUT ? "，ETIMEDOUT" : "");
    }
}

void uid_cache_write_shutdown(void) {
    pthread_mutex_lock(&g_ucw_mu);
    if (!g_ucw_started) {
        pthread_mutex_unlock(&g_ucw_mu);
        return;
    }
    g_ucw_stop = true;
    pthread_cond_broadcast(&g_ucw_cv);
    pthread_mutex_unlock(&g_ucw_mu);
    pthread_join(g_ucw_thread, NULL);
    pthread_mutex_lock(&g_ucw_mu);
    g_ucw_started = false;
    pthread_mutex_unlock(&g_ucw_mu);
}