/* Exercise the daemon's extracted backing and reclamation callbacks with real
 * directory opens, pthreads and closes. Only FUSE/routing context is substituted. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fd_reply_bridge.h"
#include "fd_close_queue.h"
#include "nsp_log.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int __real_pthread_key_create(pthread_key_t*, void (*)(void*));
int __real_pthread_setspecific(pthread_key_t, const void*);
int __real_pthread_mutex_init(pthread_mutex_t*, const pthread_mutexattr_t*);
void* __real_calloc(size_t, size_t);
/* The baseline queue logs its unreachable saturation fallback. Logging is an
 * external boundary; this stub never changes descriptor ownership. */
void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}
static int failure;
static int last_open_fd = -1;
int __real_open(const char*, int, ...);
int __wrap_open(const char* path, int flags, ...) {
    last_open_fd = __real_open(path, flags);
    return last_open_fd;
}
int __wrap_pthread_key_create(pthread_key_t* key, void (*destroy)(void*)) {
    return failure == 1 ? EAGAIN : __real_pthread_key_create(key, destroy);
}
int __wrap_pthread_setspecific(pthread_key_t key, const void* value) {
    return failure == 2 ? ENOMEM : __real_pthread_setspecific(key, value);
}
int __wrap_pthread_mutex_init(pthread_mutex_t* lock, const pthread_mutexattr_t* attr) {
    return failure == 4 ? EAGAIN : __real_pthread_mutex_init(lock, attr);
}
void* __wrap_calloc(size_t count, size_t size) {
    return failure == 3 ? NULL : __real_calloc(count, size);
}

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    const char* path;
    int fd;
    int setup_rc;
    unsigned closes;
    bool setup_done;
    bool allow_reply;
    bool close_entered;
    bool allow_close;
    bool other_done;
    bool slow;
} Run;
static Run* active;

static struct timespec deadline(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_nsec += 300000000L;
    ts.tv_sec += ts.tv_nsec / 1000000000L;
    ts.tv_nsec %= 1000000000L;
    return ts;
}
static int tracked_close(int fd) {
    Run* r = active;
    pthread_mutex_lock(&r->lock);
    if (fd == r->fd) {
        if (r->slow) {
            r->close_entered = true;
            pthread_cond_broadcast(&r->changed);
            while (!r->allow_close) pthread_cond_wait(&r->changed, &r->lock);
        }
        ++r->closes;
    }
    pthread_mutex_unlock(&r->lock);
    return close(fd);
}
static struct fuse_entry_param new_entry(void) {
    struct fuse_entry_param e = {0};
    e.attr.st_mode = S_IFDIR | 0750;
    return e;
}
static void* owner(void* raw) {
    Run* r = raw;
    struct fuse_entry_param e = new_entry();
    int rc = probe_setup(r->path, &e);
    pthread_mutex_lock(&r->lock);
    r->fd = (int)e.backing_fd;
    r->setup_rc = rc;
    r->setup_done = true;
    pthread_cond_broadcast(&r->changed);
    while (!r->allow_reply) pthread_cond_wait(&r->changed, &r->lock);
    pthread_mutex_unlock(&r->lock);
    /* In legacy libfuse this entry is only reached after the preceding lookup
     * reply has returned. The test deliberately gates that boundary. */
    probe_flush();
    return NULL;
}
static void* other(void* raw) {
    Run* r = raw;
    probe_flush();
    pthread_mutex_lock(&r->lock);
    r->other_done = true;
    pthread_cond_broadcast(&r->changed);
    pthread_mutex_unlock(&r->lock);
    return NULL;
}
static bool parallel_case(Run* r, bool slow) {
    r->slow = slow;
    pthread_t a, b;
    if (pthread_create(&a, NULL, owner, r) != 0) return false;
    pthread_mutex_lock(&r->lock);
    while (!r->setup_done) pthread_cond_wait(&r->changed, &r->lock);
    if (slow) {
        r->allow_reply = true;
        pthread_cond_broadcast(&r->changed);
        while (!r->close_entered) pthread_cond_wait(&r->changed, &r->lock);
    }
    pthread_mutex_unlock(&r->lock);
    bool made_b = pthread_create(&b, NULL, other, r) == 0;
    pthread_mutex_lock(&r->lock);
    struct timespec until = deadline();
    int rc = 0;
    while (made_b && !r->other_done && rc == 0)
        rc = pthread_cond_timedwait(&r->changed, &r->lock, &until);
    bool progress = r->other_done;
    bool not_early = r->closes == 0;
    printf("other_progress=%d owner_closed_before_reply_or_release=%u\n", progress, r->closes);
    r->allow_reply = r->allow_close = true;
    pthread_cond_broadcast(&r->changed);
    pthread_mutex_unlock(&r->lock);
    pthread_join(a, NULL);
    if (made_b) pthread_join(b, NULL);
    return made_b && progress && not_early && r->setup_rc == 0 && r->closes == 1;
}
static void* final_request(void* raw) {
    Run* r = raw;
    struct fuse_entry_param e = new_entry();
    r->setup_rc = probe_setup(r->path, &e);
    r->fd = (int)e.backing_fd;
    return NULL;
}
int main(int argc, char** argv) {
    alarm(8);
    if (argc != 3) return 2;
    Run r = {.lock = PTHREAD_MUTEX_INITIALIZER, .path = argv[2], .fd = -1};
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&r.changed, &attr);
    pthread_condattr_destroy(&attr);
    active = &r;
    fdq_set_close_fn(tracked_close);
    bool ok = false;
    if (strcmp(argv[1], "before-reply") == 0 || strcmp(argv[1], "slow-owner") == 0) {
        ok = parallel_case(&r, strcmp(argv[1], "slow-owner") == 0);
    } else if (strcmp(argv[1], "worker-exit") == 0) {
        pthread_t tid;
        if (pthread_create(&tid, NULL, final_request, &r) == 0) {
            pthread_join(tid, NULL);
            ok = r.setup_rc == 0 && r.closes == 1;
            /* Baseline cleanup occurs after the observation, not before it. */
            probe_flush();
        }
    } else {
        struct fuse_entry_param e = new_entry();
        if (strcmp(argv[1], "key-fail") == 0) failure = 1;
        if (strcmp(argv[1], "set-fail") == 0) failure = 2;
        if (strcmp(argv[1], "alloc-fail") == 0) failure = 3;
        if (strcmp(argv[1], "mutex-fail") == 0) failure = 4;
        int rc = probe_setup(r.path, &e);
        r.fd = (int)e.backing_fd;
        if (failure) {
            ok = rc == -ENOMEM && e.backing_action == 0 && e.backing_fd == 0 &&
                 fcntl(last_open_fd, F_GETFD) == -1 && errno == EBADF;
        } else if (strcmp(argv[1], "second-defer") == 0) {
            struct fuse_entry_param second = new_entry();
            int second_rc = probe_setup(r.path, &second);
            ok = rc == 0 && second_rc == -ENOMEM && second.backing_action == 0 &&
                 second.backing_fd == 0 && r.closes == 0 &&
                 fcntl(r.fd, F_GETFD) >= 0 && fcntl(last_open_fd, F_GETFD) == -1 &&
                 errno == EBADF;
        } else {
            ok = rc == 0 && r.closes == 0;
            probe_flush();
            ok = ok && r.closes == 1;
        }
        probe_flush();
    }
    fdq_set_close_fn(NULL);
    pthread_cond_destroy(&r.changed);
    pthread_mutex_destroy(&r.lock);
    printf("%s %s\n", ok ? "PASS" : "FAIL", argv[1]);
    return ok ? 0 : 1;
}
