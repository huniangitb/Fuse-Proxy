#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* Real fw_pkg TU; only packages.list I/O scheduling and unused uid.map load are injected. */
#include "fw_pkg.h"
#include "uid_map.h"
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static const char* packages;
static const char* edge;
static sem_t entered, release_gate;
static _Thread_local bool delayed;
static _Thread_local bool gated;
static _Atomic int opens, closes, failed_opens;
FILE* __real_fopen(const char*, const char*);
char* __real_fgets(char*, int, FILE*);
int __real_fclose(FILE*);
int uid_map_load(UidMapEntry* entries, int capacity) {
    (void)entries;
    (void)capacity;
    return 0;
}

static void gate(const char* at) {
    if (!delayed || gated || strcmp(edge, at)) return;
    gated = true;
    sem_post(&entered);
    while (sem_wait(&release_gate) && errno == EINTR) {}
}
FILE* __wrap_fopen(const char* path, const char* mode) {
    FILE* fp = __real_fopen(path, mode);
    if (!strcmp(path, packages)) {
        atomic_fetch_add(&opens, 1);
        if (!fp) atomic_fetch_add(&failed_opens, 1);
        gate("open"); /* FILE pins the old inode before the gate. */
    }
    return fp;
}
char* __wrap_fgets(char* buf, int size, FILE* fp) {
    gate("read");
    return __real_fgets(buf, size, fp);
}
int __wrap_fclose(FILE* fp) {
    gate("close");
    atomic_fetch_add(&closes, 1);
    return __real_fclose(fp);
}

static bool wait_ms(sem_t* sem, int ms) {
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += ms / 1000;
    until.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (until.tv_nsec >= 1000000000L) { until.tv_sec++; until.tv_nsec -= 1000000000L; }
    int rc;
    do { rc = sem_timedwait(sem, &until); } while (rc && errno == EINTR);
    return rc == 0;
}

typedef struct {
    bool priv, slow, ok;
    uid_t uid, result;
    pid_t tid;
    const char* pkg;
    sem_t done;
} Query;
static bool run_query(Query* q) {
    q->result = 999999;
    q->ok = q->priv ? fw_pkg_is_privileged(q->uid) : fw_pkg_uid_for_package(q->pkg, &q->result);
    return q->ok;
}
static void* worker(void* arg) {
    Query* q = arg;
    q->tid = (pid_t)syscall(SYS_gettid);
    delayed = q->slow;
    run_query(q);
    sem_post(&q->done);
    return NULL;
}
static int directory_entries(const char* path) {
    DIR* d = opendir(path);
    if (!d) return -1;
    int n = 0;
    struct dirent* e;
    while ((e = readdir(d))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++;
    closedir(d);
    return n;
}
/* Successful join observes CHILD_CLEARTID before Linux removes the task from /proc.
   Only the two successfully joined TIDs may linger; unknown threads fail immediately.
   This cleanup-only budget does not change the 300ms business gate. */
static int task_snapshot(const pid_t joined[2], bool* unknown) {
    DIR* d = opendir("/proc/self/task");
    if (!d) return -1;
    int count = 0;
    struct dirent* e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') {
        pid_t tid = (pid_t)strtol(e->d_name, NULL, 10);
        count++;
        if (tid != getpid() && tid != joined[0] && tid != joined[1]) *unknown = true;
    }
    closedir(d);
    return count;
}
static bool monotonic_us(uint64_t* value) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return false;
    *value = (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
    return true;
}
static int settle_tasks(const pid_t joined[2], int* first, uint64_t* elapsed, bool* unknown) {
    uint64_t start, now;
    if (!monotonic_us(&start)) return -1;
    int count = task_snapshot(joined, unknown);
    *first = count;
    for (;;) {
        if (!monotonic_us(&now)) return -1;
        *elapsed = now - start;
        if (count <= 1 || *unknown || *elapsed >= 20000u) return count;
        sched_yield();
        count = task_snapshot(joined, unknown);
    }
}
static bool replace_packages(unsigned phase, bool priv) {
    char next[4096];
    if (snprintf(next, sizeof next, "%s.next", packages) >= (int)sizeof next) return false;
    FILE* fp = __real_fopen(next, "we");
    if (!fp) return false;
    fprintf(fp, "com.slow %u 0 /private %s\n", phase && !priv ? 12008u + phase : 12000u,
            phase == 1 ? "default" : "platform");
    fputs("com.fast 12001 0 /private platform\ncom.zero 0 0 /private platform\n"
          "com.collision 14048 0 /private default\ncom.collision2 16096 0 /private default\n", fp);
    for (int i = 0; i < 8; i++) fprintf(fp, "com.seed%d %d 0 /private default\n", i, 18000 + i);
    if (__real_fclose(fp)) return false;
    return rename(next, packages) == 0;
}
static bool lookup(bool priv, uid_t uid, const char* pkg, bool expected, uid_t out) {
    Query q = {.priv=priv, .uid=uid, .pkg=pkg};
    run_query(&q);
    return q.ok == expected && (priv || q.result == (expected ? out : 999999));
}

int main(int argc, char** argv) {
    if (argc != 5) return 2;
    bool priv = !strcmp(argv[1], "priv");
    const char* mode = argv[2];
    edge = argv[3];
    packages = argv[4];
    int fd_before = directory_entries("/proc/self/fd");
    fw_pkg_set_packagelist_path(packages);
    if (!replace_packages(0, priv)) return 2;
    bool pass = true;
    pid_t joined_tids[2] = {0, 0};
    if (!strcmp(mode, "basic")) {
        pass &= lookup(priv, 0, "com.zero", true, 0); /* no initial-zero phantom cache hit */
        int before = atomic_load(&opens);
        pass &= lookup(priv, 0, "com.zero", true, 0);
        pass &= atomic_load(&opens) == before;
        pass &= lookup(priv, 12000, "com.slow", true, 12000);
        pass &= lookup(priv, 14048, "com.collision", priv ? false : true, 14048);
        before = atomic_load(&opens);
        pass &= lookup(priv, 77777, "com.missing", false, 0);
        pass &= lookup(priv, 77777, "com.missing", false, 0);
        pass &= atomic_load(&opens) == before + (priv ? 2 : 1); /* priv unknown retries; pkg negative caches */
        before = atomic_load(&opens);
        pass &= !fw_pkg_uid_for_package(NULL, NULL) && !fw_pkg_uid_for_package("", NULL);
        pass &= fw_pkg_uid_for_package("com.fast", NULL);
        pass &= atomic_load(&opens) == before + 1;
        char missing[4096];
        if (snprintf(missing, sizeof missing, "%s.saved", packages) >= (int)sizeof missing) return 2;
        pass &= rename(packages, missing) == 0;
        fw_pkg_reload();
        pass &= lookup(priv, 12000, "com.slow", false, 0);
        pass &= rename(missing, packages) == 0;
        fw_pkg_reload();
        pass &= lookup(priv, 12000, "com.slow", true, 12000);
        fw_pkg_reload();
        before = atomic_load(&opens);
        pass &= lookup(priv, 77777, "com.missing", false, 0);
        pass &= atomic_load(&opens) == before + 1;
    } else {
        if (!strcmp(mode, "hot")) pass &= lookup(priv, 12001, "com.fast", true, 12001);
        if (!strcmp(mode, "aba")) {
            if (priv) pass &= lookup(true, 14048, "com.collision", false, 0);
            else for (int i = 0; i < 8; i++) {
                char name[32]; snprintf(name, sizeof name, "com.seed%d", i);
                pass &= lookup(false, 0, name, true, (uid_t)(18000 + i));
            }
        }
        Query slow = {.priv=priv, .slow=true, .uid=12000, .pkg="com.slow"};
        Query fast = {.priv=priv, .uid=12001, .pkg="com.fast"};
        if (!strcmp(mode, "refresh") || !strcmp(mode, "same") || !strcmp(mode, "double-refresh")) {
            fast.uid = 12000; fast.pkg = "com.slow";
        } else if (!strcmp(mode, "collision") || !strcmp(mode, "aba")) {
            fast.uid = priv && !strcmp(mode, "aba") ? 16096 : 14048;
            fast.pkg = priv && !strcmp(mode, "aba") ? "com.collision2" : "com.collision";
        }
        sem_init(&entered, 0, 0); sem_init(&release_gate, 0, 0);
        sem_init(&slow.done, 0, 0); sem_init(&fast.done, 0, 0);
        pthread_t st, ft;
        if (pthread_create(&st, NULL, worker, &slow)) return 2;
        bool reached = wait_ms(&entered, 1000);
        pass &= reached;
        if (!strcmp(mode, "refresh") || !strcmp(mode, "same") || !strcmp(mode, "double-refresh")) {
            pass &= replace_packages(1, priv);
            if (strcmp(mode, "same")) fw_pkg_reload();
        } else if (!strcmp(mode, "refresh-unclaimed")) {
            pass &= replace_packages(1, priv);
            fw_pkg_reload();
        }
        fast.slow = !strcmp(mode, "double-refresh");
        if (pthread_create(&ft, NULL, worker, &fast)) {
            sem_post(&release_gate); pthread_join(st, NULL); return 2;
        }
        bool independent;
        if (!strcmp(mode, "double-refresh")) {
            independent = wait_ms(&entered, 1000);
            pass &= replace_packages(2, priv);
            fw_pkg_reload();
            if (independent) pass &= lookup(priv, 12000, "com.slow", true, 12010);
        } else independent = wait_ms(&fast.done, 300);
        pass &= independent;
        if (independent && !strcmp(mode, "aba")) {
            /* Restore the original slot key after an intervening publication: same gen/key is not a claim token. */
            pass &= lookup(priv, 14048, priv ? "com.collision" : "com.seed0", priv ? false : true, 18000);
        }
        sem_post(&release_gate);
        if (!strcmp(mode, "double-refresh")) sem_post(&release_gate);
        int join_slow = pthread_join(st, NULL);
        int join_fast = pthread_join(ft, NULL);
        if (join_slow || join_fast) {
            printf("FAIL join_rc=%d/%d\n", join_slow, join_fast);
            return 2;
        }
        joined_tids[0] = slow.tid; joined_tids[1] = fast.tid;
        if (!strcmp(mode, "double-refresh")) {
            pass &= !slow.ok && !fast.ok && slow.result == 999999 && fast.result == 999999;
            int before = atomic_load(&opens);
            pass &= lookup(priv, 12000, "com.slow", true, 12010);
            pass &= atomic_load(&opens) == before; /* neither older generation may overwrite newest slot */
        } else if (!strcmp(mode, "refresh-unclaimed")) {
            pass &= !slow.ok && slow.result == 999999;
            pass &= fast.ok && (priv || fast.result == 12001);
            pass &= lookup(priv, 12000, "com.slow", !priv, 12009);
        } else if (!strcmp(mode, "refresh")) {
            pass &= !slow.ok && slow.result == 999999; /* old generation must not grant identity/privilege */
            pass &= fast.ok == !priv && (priv || fast.result == 12009);
            pass &= lookup(priv, 12000, "com.slow", !priv, 12009);
        } else if (!strcmp(mode, "same")) {
            pass &= slow.ok == !priv && fast.ok == !priv;
            pass &= priv || (slow.result == 12009 && fast.result == 12009);
            pass &= lookup(priv, 12000, "com.slow", !priv, 12009);
        } else if (!strcmp(mode, "collision") || !strcmp(mode, "aba")) {
            int before = atomic_load(&opens);
            const char* key = !strcmp(mode, "aba") && !priv ? "com.seed0" : "com.collision";
            pass &= lookup(priv, 14048, key, !priv, !strcmp(mode, "aba") ? 18000 : 14048);
            pass &= atomic_load(&opens) == before; /* delayed miss must not overwrite a replaced/ABA slot */
            pass &= slow.ok && (priv || slow.result == 12000);
        } else {
            pass &= slow.ok && fast.ok && (priv || (slow.result == 12000 && fast.result == 12001));
        }
        printf("gate=%s reached=%d unrelated_completed_while_held=%d joined=2 join_rc=0/0\n", edge, reached, independent);
        sem_destroy(&entered); sem_destroy(&release_gate);
        sem_destroy(&slow.done); sem_destroy(&fast.done);
    }
    fw_pkg_shutdown();
    int fd_after = directory_entries("/proc/self/fd");
    int first_threads = -1;
    uint64_t cleanup_us = 0;
    bool unknown_threads = false;
    int threads = settle_tasks(joined_tids, &first_threads, &cleanup_us, &unknown_threads);
    int status;
    errno = 0;
    pid_t child = waitpid(-1, &status, WNOHANG);
    bool clean = fd_before >= 0 && fd_before == fd_after && threads == 1 && !unknown_threads && cleanup_us <= 20000u && child == -1 && errno == ECHILD;
    clean &= atomic_load(&opens) == atomic_load(&closes) + atomic_load(&failed_opens);
    printf("%s/%s/%s %s fd=%d->%d initial_tasks=%d final_tasks=%d elapsed_us=%llu unknown_tid=%d child=ECHILD opens=%d closes=%d failed_opens=%d\n",
           argv[1], mode, edge, pass && clean ? "PASS" : "FAIL", fd_before, fd_after, first_threads, threads, (unsigned long long)cleanup_us, unknown_threads,
           atomic_load(&opens), atomic_load(&closes), atomic_load(&failed_opens));
    return pass && clean ? 0 : 1;
}
