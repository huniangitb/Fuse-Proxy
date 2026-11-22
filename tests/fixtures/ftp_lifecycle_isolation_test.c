/* Full production backend + real mux/libcurl. Only bounded gates/failures are
 * injected. Every successful/failed assertion path opens gates and joins users.
 * No FTP service, sockets, mounts, cancellation, or copied backend logic. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <dirent.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifndef FTP_BACKEND_SRC
#define FTP_BACKEND_SRC "ftp_backend_libcurl.c"
#endif
#include FTP_BACKEND_SRC

#include <sys/syscall.h>
#include <sys/wait.h>
#include <limits.h>
#define ID_CAP 4096
typedef struct { int ids[ID_CAP], n; } IdSet;
typedef struct {
    pthread_t handle;
    pid_t tid;
    void* (*fn)(void*);
    void* arg;
    bool started, exited, joined;
} ThreadRecord;
static ThreadRecord thread_records[ID_CAP];
static int thread_records_n;
static pthread_mutex_t registry_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t registry_cv = PTHREAD_COND_INITIALIZER;
static bool id_has(const IdSet* s, int id) {
    for (int i = 0; i < s->n; i++) if (s->ids[i] == id) return true;
    return false;
}
static void id_add(IdSet* s, int id) {
    if (id_has(s, id)) return;
    assert(s->n < ID_CAP); s->ids[s->n++] = id;
}
static bool id_equal(const IdSet* a, const IdSet* b) {
    if (a->n != b->n) return false;
    for (int i = 0; i < a->n; i++) if (!id_has(b, a->ids[i])) return false;
    return true;
}
static IdSet proc_ids(const char* path, bool skip_directory_fd) {
    IdSet s = {0}; DIR* d = opendir(path); assert(d);
    int own_fd = skip_directory_fd ? dirfd(d) : -1;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char* end; long id = strtol(e->d_name, &end, 10);
        assert(*end == 0 && id >= 0 && id <= INT_MAX);
        if (id != own_fd) id_add(&s, (int)id);
    }
    closedir(d); return s;
}
static void dump_ids(const char* label, const IdSet* s) {
    printf("%s={", label);
    for (int i = 0; i < s->n; i++) printf("%s%d", i ? "," : "", s->ids[i]);
    puts("}");
}
static void* record_start(void* arg) {
    ThreadRecord* r = arg;
    pthread_mutex_lock(&registry_mu);
    r->tid = (pid_t)syscall(SYS_gettid); r->started = true;
    pthread_cond_broadcast(&registry_cv);
    pthread_mutex_unlock(&registry_mu);
    void* result = r->fn(r->arg);
    pthread_mutex_lock(&registry_mu); r->exited = true;
    pthread_mutex_unlock(&registry_mu);
    return result;
}
int __real_pthread_create(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);
int __wrap_pthread_create(pthread_t* handle, const pthread_attr_t* attr,
                          void* (*fn)(void*), void* arg) {
    pthread_mutex_lock(&registry_mu);
    assert(thread_records_n < ID_CAP);
    ThreadRecord* r = &thread_records[thread_records_n++];
    r->fn = fn; r->arg = arg;
    int rc = __real_pthread_create(handle, attr, record_start, r);
    if (rc) { thread_records_n--; pthread_mutex_unlock(&registry_mu); return rc; }
    r->handle = *handle;
    while (!r->started) assert(pthread_cond_wait(&registry_cv, &registry_mu) == 0);
    pthread_mutex_unlock(&registry_mu);
    return 0;
}
int __real_pthread_join(pthread_t, void**);
static int record_join(pthread_t handle, void** result) {
    pthread_mutex_lock(&registry_mu); ThreadRecord* found = NULL;
    for (int i = thread_records_n - 1; i >= 0; i--) {
        ThreadRecord* r = &thread_records[i];
        if (!r->joined && pthread_equal(r->handle, handle)) { found = r; break; }
    }
    assert(found); pthread_mutex_unlock(&registry_mu);
    int rc = __real_pthread_join(handle, result);
    if (!rc) {
        pthread_mutex_lock(&registry_mu); assert(found->exited);
        found->joined = true; pthread_mutex_unlock(&registry_mu);
    }
    return rc;
}
static void registry_sets(IdSet* active, IdSet* joined) {
    *active = (IdSet){0}; *joined = (IdSet){0};
    id_add(active, (int)syscall(SYS_gettid));
    IdSet seen = {0}; pthread_mutex_lock(&registry_mu);
    for (int i = thread_records_n - 1; i >= 0; i--) {
        ThreadRecord* r = &thread_records[i];
        if (!r->started || id_has(&seen, r->tid)) continue;
        id_add(&seen, r->tid);
        if (r->joined && r->exited) id_add(joined, r->tid);
        else id_add(active, r->tid);
    }
    pthread_mutex_unlock(&registry_mu);
}

/* Only a real successful join of a returned user function permits a transient
 * /proc task entry. This 20ms clock is independent of all business gates. */
typedef enum { TASKS_OK, TASKS_UNKNOWN, TASKS_MISSING, TASKS_DEADLINE } TaskStatus;
typedef struct {
    TaskStatus status;
    IdSet actual;
    int samples, initial_count;
    long long elapsed_us;
} TaskCheck;
static long long monotonic_ns(void) {
    struct timespec ts; assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}
static TaskCheck settle_tasks(const IdSet* expected, const IdSet* joined) {
    long long start = monotonic_ns(), deadline = start + 20000000LL;
    TaskCheck result = {0};
    for (;;) {
        result.actual = proc_ids("/proc/self/task", false);
        result.samples++;
        if (result.samples == 1) result.initial_count = result.actual.n;
        result.elapsed_us = (monotonic_ns() - start) / 1000;
        for (int i = 0; i < expected->n; i++) {
            if (!id_has(&result.actual, expected->ids[i])) {
                result.status = TASKS_MISSING; return result;
            }
        }
        for (int i = 0; i < result.actual.n; i++) {
            int tid = result.actual.ids[i];
            if (!id_has(expected, tid) && !id_has(joined, tid)) {
                result.status = TASKS_UNKNOWN; return result;
            }
        }
        /* Once convergence is needed, a sample after the deadline cannot pass. */
        if (result.samples > 1 && monotonic_ns() >= deadline) {
            result.status = TASKS_DEADLINE; return result;
        }
        if (id_equal(&result.actual, expected)) {
            result.status = TASKS_OK; return result;
        }
        if (monotonic_ns() >= deadline) {
            result.status = TASKS_DEADLINE; return result;
        }
        usleep(100);
    }
}
static TaskCheck resource_tasks(const char* label, const IdSet* expected) {
    IdSet active, joined; registry_sets(&active, &joined);
    TaskCheck result = settle_tasks(expected, &joined);
    printf("TASK_RESOURCE label=%s status=%d initial=%d expected=%d final=%d samples=%d elapsed_us=%lld\n",
           label, result.status, result.initial_count, expected->n, result.actual.n,
           result.samples, result.elapsed_us);
    dump_ids("TASK_EXPECTED", expected); dump_ids("TASK_ACTUAL", &result.actual);
    if (result.status != TASKS_OK) {
        for (int i = 0; i < result.actual.n; i++) {
            int tid = result.actual.ids[i];
            if (!id_has(expected, tid))
                printf("TASK_EXTRA tid=%d joined_returned=%d\n", tid, id_has(&joined, tid));
        }
    }
    return result;
}

void log_internal(LogLevel level, const char* format, ...) {
    (void)level; (void)format;
}

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool entered, open;
} Gate;
#define GATE_INIT { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, false, false }
static Gate callback_gate = GATE_INIT, prelock_gate = GATE_INIT;
static Gate init_gate = GATE_INIT, join_gate = GATE_INIT, cleanup_gate = GATE_INIT;
static _Thread_local bool pause_find, in_clear;
static _Thread_local int metadata_depth;
static pthread_t slow_callback_tid; /* callback_gate 发布，join_gate只观察真实慢A join */
static _Atomic int init_mode, slow_under_metadata;
static _Atomic bool fail_table_allocation;
static _Atomic(CURL*) delayed_cleanup;
static int failures;

static void check(bool ok, const char* label) {
    printf("%s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) failures++;
}
static long long now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}
static void gate_signal(Gate* g) {
    pthread_mutex_lock(&g->mu);
    g->entered = true;
    pthread_cond_broadcast(&g->cv);
    pthread_mutex_unlock(&g->mu);
}
static void gate_wait(Gate* g, bool entering) {
    pthread_mutex_lock(&g->mu);
    if (entering) { g->entered = true; pthread_cond_broadcast(&g->cv); }
    struct timespec until; clock_gettime(CLOCK_REALTIME, &until); until.tv_sec += 15;
    while (!(entering ? g->open : g->entered)) {
        int rc = pthread_cond_timedwait(&g->cv, &g->mu, &until);
        assert(rc == 0); /* Infrastructure timeout, never counted as old red. */
    }
    pthread_mutex_unlock(&g->mu);
}
static void gate_open(Gate* g) {
    pthread_mutex_lock(&g->mu); g->open = true;
    pthread_cond_broadcast(&g->cv); pthread_mutex_unlock(&g->mu);
}
int __real_pthread_mutex_lock(pthread_mutex_t*);
int __real_pthread_mutex_unlock(pthread_mutex_t*);
int __wrap_pthread_mutex_lock(pthread_mutex_t* mu) {
    if (mu == &g_backend_glock && pause_find) {
        pause_find = false; gate_wait(&prelock_gate, true);
    }
    int rc = __real_pthread_mutex_lock(mu);
    if (!rc && mu == &g_backend_glock) metadata_depth++;
    return rc;
}
int __wrap_pthread_mutex_unlock(pthread_mutex_t* mu) {
    if (mu == &g_backend_glock) metadata_depth--;
    return __real_pthread_mutex_unlock(mu);
}
void* __real_calloc(size_t, size_t);
void* __wrap_calloc(size_t count, size_t size) {
    if (metadata_depth) atomic_fetch_add(&slow_under_metadata, 1);
    if (count >= FTP_BACKEND_MAX && size == sizeof(FtpBackend*) &&
        atomic_exchange(&fail_table_allocation, false)) { errno = ENOMEM; return NULL; }
    return __real_calloc(count, size);
}
/* The frozen implementation grows with realloc; fail the same table allocation
 * there too, so old-red is not caused by a calloc-only injection mismatch. */
void* __real_realloc(void*, size_t);
void* __wrap_realloc(void* ptr, size_t size) {
    if (metadata_depth) atomic_fetch_add(&slow_under_metadata, 1);
    if (ptr == g_backends && size >= FTP_BACKEND_MAX * sizeof(FtpBackend*) &&
        atomic_exchange(&fail_table_allocation, false)) { errno = ENOMEM; return NULL; }
    return __real_realloc(ptr, size);
}
CURLM* __real_curl_multi_init(void);
CURLM* __wrap_curl_multi_init(void) {
    if (metadata_depth) atomic_fetch_add(&slow_under_metadata, 1);
    int mode = atomic_exchange(&init_mode, 0);
    if (mode == 1) gate_wait(&init_gate, true);
    if (mode == 2) { errno = ENOMEM; return NULL; }
    return __real_curl_multi_init();
}
int __real_pthread_join(pthread_t, void**);
int __wrap_pthread_join(pthread_t tid, void** result) {
    if (in_clear) {
        if (metadata_depth) atomic_fetch_add(&slow_under_metadata, 1);
        if (pthread_equal(tid, slow_callback_tid)) gate_signal(&join_gate);
    }
    return record_join(tid, result);
}
void __real_curl_easy_cleanup(CURL*);
void __wrap_curl_easy_cleanup(CURL* c) {
    if (metadata_depth) atomic_fetch_add(&slow_under_metadata, 1);
    CURL* expected = c;
    if (c && atomic_compare_exchange_strong(&delayed_cleanup, &expected, NULL))
        gate_wait(&cleanup_gate, true);
    __real_curl_easy_cleanup(c);
}
static size_t local_write(char* p, size_t size, size_t count, void* userdata) {
    (void)p;
    if (userdata) {
        slow_callback_tid = pthread_self();
        gate_wait(&callback_gate, true);
    }
    return size * count;
}
static CURL* local_easy(const char* path, bool slow) {
    FtpServerCfg cfg = {0};
    CURL* c = ftp_easy_new(&cfg); assert(c);
    char url[8192]; int n = snprintf(url, sizeof url, "file://%s", path);
    assert(n > 0 && (size_t)n < sizeof url);
    assert(curl_easy_setopt(c, CURLOPT_URL, url) == CURLE_OK);
    assert(curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "file") == CURLE_OK);
    assert(curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, local_write) == CURLE_OK);
    assert(curl_easy_setopt(c, CURLOPT_WRITEDATA, slow ? (void*)1 : NULL) == CURLE_OK);
    return c;
}
static FtpServerCfg config(const char* name, int port) {
    FtpServerCfg cfg = {0}; snprintf(cfg.name, sizeof cfg.name, "%s", name);
    cfg.port = port; return cfg;
}
typedef struct {
    FtpBackend* bk;
    CURL* easy;
    FtpServerCfg cfg;
    const char* path;
    bool pause;
    int rc;
    _Atomic bool started, done;
} Work;
static void* match_thread(void* arg) {
    Work* w = arg; pause_find = w->pause; atomic_store(&w->started, true);
    w->rc = ftp_backend_match(w->path); atomic_store(&w->done, true); return NULL;
}
static void* clear_thread(void* arg) {
    Work* w = arg; in_clear = true; atomic_store(&w->started, true);
    ftp_backend_clear(); in_clear = false; atomic_store(&w->done, true); return NULL;
}
static void* add_thread(void* arg) {
    Work* w = arg; atomic_store(&w->started, true);
    w->rc = ftp_backend_add(&w->cfg); atomic_store(&w->done, true); return NULL;
}
static void* perform_thread(void* arg) {
    Work* w = arg; atomic_store(&w->started, true);
    w->rc = backend_perform(w->bk, w->easy); atomic_store(&w->done, true); return NULL;
}
static bool wait_done(Work* w, int ms) {
    long long until = now_ms() + ms;
    while (!atomic_load(&w->done) && now_ms() < until) usleep(1000);
    return atomic_load(&w->done);
}
static void launch(pthread_t* t, void* (*fn)(void*), Work* w) {
    assert(!pthread_create(t, NULL, fn, w));
}
static void join(pthread_t t) { assert(!pthread_join(t, NULL)); }
static void* short_thread(void* unused) { (void)unused; return NULL; }
static _Atomic int negative_tid;
static void* negative_thread(void* arg) {
    atomic_store(&negative_tid, (int)syscall(SYS_gettid));
    gate_wait(arg, true); return NULL;
}
static void resource_selftest(const IdSet* baseline) {
    bool ok = true; int residues = 0; long long max_us = 0;
    for (int i = 0; i < 100; i++) {
        pthread_t t; assert(pthread_create(&t, NULL, short_thread, NULL) == 0); join(t);
        IdSet active, joined; registry_sets(&active, &joined);
        TaskCheck r = settle_tasks(baseline, &joined);
        ok &= r.status == TASKS_OK;
        residues += r.initial_count > baseline->n;
        if (r.elapsed_us > max_us) max_us = r.elapsed_us;
    }
    printf("PURE_PTHREAD joins=100 residues=%d max_elapsed_us=%lld\n", residues, max_us);
    check(ok, "pure_pthread_exact_set_after_real_join");
    Gate g = GATE_INIT; pthread_t t;
    assert(pthread_create(&t, NULL, negative_thread, &g) == 0); gate_wait(&g, false);
    IdSet active, joined; registry_sets(&active, &joined);
    TaskCheck unknown = settle_tasks(baseline, &joined);
    check(unknown.status == TASKS_UNKNOWN && unknown.samples == 1,
          "negative_live_unjoined_tid_rejected_immediately");
    /* Deliberately forged allow-set is used only by this negative control. */
    id_add(&joined, atomic_load(&negative_tid));
    TaskCheck persistent = settle_tasks(baseline, &joined);
    printf("NEGATIVE_PERSISTENT status=%d samples=%d elapsed_us=%lld\n",
           persistent.status, persistent.samples, persistent.elapsed_us);
    check(persistent.status == TASKS_DEADLINE && persistent.elapsed_us >= 20000,
          "negative_persistent_fake_allow_rejected_at_20ms");
    gate_open(&g); join(t); pthread_cond_destroy(&g.cv); pthread_mutex_destroy(&g.mu);
    registry_sets(&active, &joined);
    IdSet missing = *baseline; id_add(&missing, INT_MAX);
    TaskCheck absent = settle_tasks(&missing, &joined);
    check(absent.status == TASKS_MISSING && absent.samples == 1,
          "negative_missing_expected_tid_rejected_immediately");
    IdSet fd_before = proc_ids("/proc/self/fd", true);
    int pipes[2]; assert(pipe(pipes) == 0);
    IdSet fd_leak = proc_ids("/proc/self/fd", true);
    check(!id_equal(&fd_before, &fd_leak), "negative_live_fd_set_rejected");
    assert(close(pipes[0]) == 0 && close(pipes[1]) == 0);
    TaskCheck final = resource_tasks("selftest_after_normal_joins", baseline);
    check(final.status == TASKS_OK, "resource_selftest_all_threads_joined");
}

static void free_immortal_for_test(void) {
    /* Only after all workers/muxes are joined; production intentionally keeps bk. */
    for (int i = 0; i < g_backend_slots; i++) {
        FtpBackend* bk = g_backends[i];
        pthread_mutex_destroy(&bk->lock); pthread_mutex_destroy(&bk->pool_lock);
        pthread_mutex_destroy(&bk->stat_lock); free(bk);
    }
    free(g_backends); g_backends = NULL;
    g_backend_slots = g_backend_cap = g_backend_count = 0;
}
int main(int argc, char** argv) {
    assert(argc == 2); setvbuf(stdout, NULL, _IOLBF, 0);
    assert(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
    IdSet fd_before = proc_ids("/proc/self/fd", true);
    IdSet thr_before = proc_ids("/proc/self/task", false);
    resource_selftest(&thr_before);
    FtpServerCfg cfg = config("D", 21); assert(ftp_backend_add(&cfg) == 0);
    Work add = {.cfg = config("C", 22)}, lookup = {.path = "/D/unrelated"};
    pthread_t ti, tl; atomic_store(&init_mode, 1); launch(&ti, add_thread, &add);
    gate_wait(&init_gate, false); launch(&tl, match_thread, &lookup);
    check(wait_done(&lookup, 500), "existing_match_before_new_release");
    check(!atomic_load(&add.done), "new_gate_still_held");
    gate_open(&init_gate); join(ti); join(tl);
    check(add.rc == 0 && lookup.rc == 1, "new_and_existing_match_results");
    atomic_store(&init_mode, 2); cfg = config("FAIL_INIT", 23);
    check(ftp_backend_add(&cfg) == -1, "real_mux_init_failure");
    check(ftp_backend_match("/FAIL_INIT/file") == 0, "failed_backend_not_published");
    cfg = config("A", 24); assert(ftp_backend_add(&cfg) == 0);
    cfg = config("B", 25); assert(ftp_backend_add(&cfg) == 0);
    FtpBackend* a = ftp_backend_find("/A/f"), *b = ftp_backend_find("/B/f"); assert(a && b);
    FtpMux* held_b = backend_mux_ref(b); assert(held_b);
    Work slow = {.bk = a, .easy = local_easy(argv[1], true)};
    Work raced = {.path = "/B/unrelated", .pause = true}, clear = {0};
    pthread_t ts, tm, tc;
    launch(&ts, perform_thread, &slow); gate_wait(&callback_gate, false);
    launch(&tm, match_thread, &raced); gate_wait(&prelock_gate, false);
    launch(&tc, clear_thread, &clear); gate_wait(&join_gate, false);
    gate_open(&prelock_gate);
    check(wait_done(&raced, 500), "raced_other_server_match_before_callback_release");
    check(!atomic_load(&clear.done), "real_shutdown_join_still_pending");
    check(backend_ready(b) == -1, "all_muxes_detached_before_slow_join");
    Work clear2 = {0}, replace = {.cfg = config("B", 26)};
    pthread_t tc2, tr; launch(&tc2, clear_thread, &clear2); launch(&tr, add_thread, &replace);
    check(!wait_done(&replace, 100), "add_serializes_with_clear_not_serving");
    gate_open(&callback_gate); join(ts); join(tc); join(tm); join(tc2); join(tr);
    check(raced.rc == 0, "raced_lookup_observes_retirement");
    check(replace.rc == 0 && b->cfg.port == 25, "old_cfg_immutable_across_add_clear");
    CURL* after = local_easy(argv[1], false);
    check(ftp_mux_perform(held_b, after) == CURLE_ABORTED_BY_CALLBACK,
          "held_old_mux_safe_and_aborted_after_shutdown");
    curl_easy_cleanup(after); ftp_mux_unref(held_b); curl_easy_cleanup(slow.easy);
    CURL* late = local_easy(argv[1], false); ftp_read_curl_release(b, late);
    pthread_mutex_lock(&b->pool_lock); int old_pool_count = b->read_pool_count;
    pthread_mutex_unlock(&b->pool_lock);
    check(old_pool_count == 0, "late_release_cannot_repopulate_retired_pool");
    /* Old backend stores late: acquire and destroy it to keep old-red cleanup complete. */
    if (old_pool_count) curl_easy_cleanup(ftp_read_curl_acquire(b));
    ftp_backend_clear(); cfg = config("POOL", 27); assert(ftp_backend_add(&cfg) == 0);
    FtpBackend* p = ftp_backend_find("/POOL/f"); assert(p);
    CURL* idle = local_easy(argv[1], false); ftp_read_curl_release(p, idle);
    atomic_store(&delayed_cleanup, idle); Work cleanup = {0}, pool_lookup = {.path = "/POOL/f"};
    pthread_t tp, tpl; launch(&tp, clear_thread, &cleanup); gate_wait(&cleanup_gate, false);
    launch(&tpl, match_thread, &pool_lookup);
    check(wait_done(&pool_lookup, 500), "match_before_easy_cleanup_release");
    int lock_rc = pthread_mutex_trylock(&p->pool_lock);
    check(lock_rc == 0, "easy_cleanup_outside_pool_lock");
    if (!lock_rc) pthread_mutex_unlock(&p->pool_lock);
    gate_open(&cleanup_gate); join(tp); join(tpl);
    check(pool_lookup.rc == 0, "cleanup_lookup_observes_retirement");
    /* Repeated real add/clear/find races, including growth past initial 16 slots. */
    for (int i = 0; i < 20; i++) {
        Work ca = {.cfg = config("RACE", 100 + i)}, cc = {0}, cf = {.path = "/RACE/f"};
        pthread_t ta, tcl, tf; launch(&ta, add_thread, &ca);
        launch(&tcl, clear_thread, &cc); launch(&tf, match_thread, &cf);
        join(ta); join(tcl); join(tf);
        check(ca.rc == 0 && (cf.rc == 0 || cf.rc == 1), "concurrent_add_clear_find");
    }
    /* Force a real table-growth allocation failure after mux_new started a real
       thread. The unpublished mux must shutdown/join, leaving no table entry. */
    while (g_backend_slots < g_backend_cap) {
        cfg = config("FILL", 200); assert(ftp_backend_add(&cfg) == 0);
    }
    IdSet before_failed_fd = proc_ids("/proc/self/fd", true);
    IdSet before_failed_thr, joined_before; registry_sets(&before_failed_thr, &joined_before);
    TaskCheck stable = resource_tasks("before_failed_growth", &before_failed_thr);
    check(stable.status == TASKS_OK, "failed_growth_baseline_exact_active_mux_set");
    int before_failed_slots = g_backend_slots;
    atomic_store(&fail_table_allocation, true); cfg = config("FAIL_TABLE", 201);
    check(ftp_backend_add(&cfg) == -1, "table_growth_allocation_failure");
    atomic_store(&fail_table_allocation, false);
    check(g_backend_slots == before_failed_slots && ftp_backend_match("/FAIL_TABLE/f") == 0,
          "failed_growth_not_published");
    IdSet after_failed_fd = proc_ids("/proc/self/fd", true);
    TaskCheck after_failed = resource_tasks("after_failed_growth", &before_failed_thr);
    check(id_equal(&after_failed_fd, &before_failed_fd) && after_failed.status == TASKS_OK,
          "failed_growth_mux_thread_and_fds_reclaimed");
    ftp_backend_clear(); check(ftp_backend_count() == 0, "final_active_count_zero");
    check(atomic_load(&slow_under_metadata) == 0, "no_new_join_cleanup_under_metadata");
    free_immortal_for_test(); curl_global_cleanup();
    IdSet fd_after = proc_ids("/proc/self/fd", true);
    TaskCheck final = resource_tasks("final", &thr_before);
    int joined_count = 0;
    pthread_mutex_lock(&registry_mu);
    for (int i = 0; i < thread_records_n; i++)
        joined_count += thread_records[i].joined && thread_records[i].exited;
    pthread_mutex_unlock(&registry_mu);
    errno = 0; pid_t child_rc = waitpid(-1, NULL, WNOHANG);
    bool no_children = child_rc == -1 && errno == ECHILD;
    printf("resource_fd=%d->%d resource_threads=%d->%d active_handles=%d joined=%d/%d child=%s\n",
           fd_before.n + 1, fd_after.n + 1, thr_before.n, final.actual.n,
           nsp_module_active_handles(), joined_count, thread_records_n,
           no_children ? "ECHILD" : "UNEXPECTED");
    dump_ids("FD_EXPECTED", &fd_before); dump_ids("FD_ACTUAL", &fd_after);
    check(id_equal(&fd_before, &fd_after) && final.status == TASKS_OK &&
          joined_count == thread_records_n && no_children && nsp_module_active_handles() == 0,
          "all_threads_children_and_fds_reclaimed");
    printf("LIFECYCLE_%s failures=%d\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
