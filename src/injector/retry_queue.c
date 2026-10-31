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

int64_t nsp_retry_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int nsp_retry_backoff_ms(int attempts) {
    if (attempts <= 0) return 0; /* 首次入队立即尝试 */
    int step = attempts - 1;     /* 失败后：快档 → 中档 → 指数 */
    if (step < NSP_RETRY_FAST_STEPS) return NSP_RETRY_FAST_MS;
    step -= NSP_RETRY_FAST_STEPS;
    if (step < NSP_RETRY_MID_STEPS) return NSP_RETRY_MID_MS;
    step -= NSP_RETRY_MID_STEPS;
    if (step > 3) step = 3; /* 1/2/4/8s 封顶 */
    int ms = 1000 << step;
    return ms > NSP_RETRY_BACKOFF_CAP_MS ? NSP_RETRY_BACKOFF_CAP_MS : ms;
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
        /* 新条目立即到期：attempts=0 → backoff 0。last_attempt_ms 保持 0，
           不取当前时刻——调用方传的是它自己的时钟（单测用虚拟毫秒），
           这里读真实时钟会让"首次立即到期"依赖两套时钟的差值。 */
        e->last_attempt_ms = 0;
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

/* 该条目在 now_ms 时刻是否到期（纯判定，不改记账） */
static bool entry_due_locked(const NspRetryEntry* e, int64_t now_ms) {
    if (e->attempts >= NSP_RETRY_MAX_ATTEMPTS) return true; /* 该放弃了 */
    int need = nsp_retry_backoff_ms(e->attempts);
    if (need <= 0) return true;
    return now_ms - e->last_attempt_ms >= need;
}

int nsp_retry_next(NspRetryEntry* out, int64_t now_ms) {
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
        if (!entry_due_locked(e, now_ms)) continue;
        e->attempts++;
        e->last_attempt_ms = now_ms;
        *out = *e;
        ret = NSP_RETRY_ATTEMPT;
        break;
    }
    pthread_mutex_unlock(&g_lock);
    return ret;
}

int64_t nsp_retry_next_due_ms(int64_t now_ms) {
    int64_t best = -1;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_count; i++) {
        const NspRetryEntry* e = &g_queue[i];
        int64_t wait;
        if (e->attempts >= NSP_RETRY_MAX_ATTEMPTS) {
            wait = 0;
        } else {
            int need = nsp_retry_backoff_ms(e->attempts);
            wait = need <= 0 ? 0 : e->last_attempt_ms + need - now_ms;
            if (wait < 0) wait = 0;
        }
        if (best < 0 || wait < best) best = wait;
    }
    pthread_mutex_unlock(&g_lock);
    return best;
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
