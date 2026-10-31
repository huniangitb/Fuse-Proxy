#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "retry_queue.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

static NspRetryEntry g_queue[NSP_RETRY_MAX_ENTRIES];
static int g_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

int nsp_retry_backoff_seconds(int attempts) {
    if (attempts <= 0) return 0; /* 首次入队立即尝试 */
    int step = attempts - 1;     /* 失败后：1s、2s、4s、8s… */
    if (step > 3) step = 3;
    int secs = 1 << step;
    return secs > NSP_RETRY_BACKOFF_CAP_S ? NSP_RETRY_BACKOFF_CAP_S : secs;
}

static int find_locked(int pid) {
    for (int i = 0; i < g_count; i++) {
        if (g_queue[i].pid == pid) return i;
    }
    return -1;
}

static void remove_locked(int idx) {
    if (idx < 0 || idx >= g_count) return;
    g_queue[idx] = g_queue[g_count - 1];
    g_count--;
    memset(&g_queue[g_count], 0, sizeof(g_queue[g_count]));
}

void nsp_retry_reset(void) {
    pthread_mutex_lock(&g_lock);
    g_count = 0;
    memset(g_queue, 0, sizeof(g_queue));
    pthread_mutex_unlock(&g_lock);
}

bool nsp_retry_schedule(const char* pkg, int pid) {
    if (pid <= 0) return false;
    bool ok = true;
    pthread_mutex_lock(&g_lock);
    int idx = find_locked(pid);
    if (idx >= 0) {
        /* 已在队列：保留尝试次数（这正是旧实现丢失的东西），只刷新包名 */
        if (pkg) snprintf(g_queue[idx].pkg, sizeof(g_queue[idx].pkg), "%s", pkg);
    } else if (g_count < NSP_RETRY_MAX_ENTRIES) {
        NspRetryEntry* e = &g_queue[g_count++];
        snprintf(e->pkg, sizeof(e->pkg), "%s", pkg ? pkg : "");
        e->pid = pid;
        e->attempts = 0;
        /* 新条目立即到期：attempts=0 → backoff 0 */
        e->last_attempt = time(NULL);
    } else {
        ok = false;
    }
    pthread_mutex_unlock(&g_lock);
    return ok;
}

bool nsp_retry_done(int pid) {
    bool hit = false;
    pthread_mutex_lock(&g_lock);
    int idx = find_locked(pid);
    if (idx >= 0) {
        remove_locked(idx);
        hit = true;
    }
    pthread_mutex_unlock(&g_lock);
    return hit;
}

int nsp_retry_next(NspRetryEntry* out, time_t now) {
    if (!out) return NSP_RETRY_NONE;
    int ret = NSP_RETRY_NONE;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_count; i++) {
        NspRetryEntry* e = &g_queue[i];
        if (e->attempts >= NSP_RETRY_MAX_ATTEMPTS) {
            *out = *e;
            remove_locked(i);
            ret = NSP_RETRY_GIVEUP;
            break;
        }
        int need = nsp_retry_backoff_seconds(e->attempts);
        if (need > 0 && now - e->last_attempt < (time_t)need) continue;
        e->attempts++;
        e->last_attempt = now;
        *out = *e;
        ret = NSP_RETRY_ATTEMPT;
        break;
    }
    pthread_mutex_unlock(&g_lock);
    return ret;
}

int nsp_retry_count(void) {
    pthread_mutex_lock(&g_lock);
    int n = g_count;
    pthread_mutex_unlock(&g_lock);
    return n;
}

int nsp_retry_attempts_of(int pid) {
    pthread_mutex_lock(&g_lock);
    int idx = find_locked(pid);
    int attempts = (idx >= 0) ? g_queue[idx].attempts : 0;
    pthread_mutex_unlock(&g_lock);
    return attempts;
}
