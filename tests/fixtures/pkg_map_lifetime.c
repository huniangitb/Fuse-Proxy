#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* 真实 fw_pkg.c / uid_map.c / fast_pid.c；只注入 uid.map 文件路径、一次调度门
   和 free 观测，不编造任何映射内容（表内容始终来自真实装载器）。
   判别目标：重载换表与 FUSE worker 借表并发时，旧实现直接 free → 读者读已释放
   堆（ASan: resolve_uncached heap-use-after-free）；修复后读者在锁内拷贝，换表
   与释放都不再与借用者重叠。 */
#include "common.h"
#include "fw_pkg.h"
#include "uid_map.h"
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_TRACKED_TIDS 8

static const char* map_path;
static pthread_mutex_t gate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cv;
static bool gate_entered;
static bool gate_open;
static _Atomic bool reload_done;
static _Atomic bool shutdown_done;
static _Atomic bool old_freed;
static _Atomic uintptr_t table_base;
static pid_t tracked_tids[MAX_TRACKED_TIDS];
static int tracked_count;
static _Thread_local bool park_lookup;
static _Thread_local bool park_load;

FILE* __real_fopen(const char*, const char*);
const char* __real_uid_map_lookup(const UidMapEntry*, int, uid_t);
void __real_free(void*);

static struct timespec ms_deadline(int ms) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    t.tv_sec += ms / 1000;
    t.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (t.tv_nsec >= 1000000000L) {
        t.tv_sec++;
        t.tv_nsec -= 1000000000L;
    }
    return t;
}

/* 只有显式登记的（真实创建的）线程 TID 可以在 join 之后短暂残留于 /proc/self/task。 */
static void track_tid(pid_t tid) {
    pthread_mutex_lock(&gate_lock);
    if (tracked_count < MAX_TRACKED_TIDS) tracked_tids[tracked_count++] = tid;
    pthread_mutex_unlock(&gate_lock);
}

static bool tid_known(pid_t tid) {
    bool known = false;
    pthread_mutex_lock(&gate_lock);
    for (int i = 0; i < tracked_count; i++)
        if (tracked_tids[i] == tid) known = true;
    pthread_mutex_unlock(&gate_lock);
    return known;
}

static void gate_park(void) {
    pthread_mutex_lock(&gate_lock);
    gate_entered = true;
    pthread_cond_broadcast(&gate_cv);
    while (!gate_open) pthread_cond_wait(&gate_cv, &gate_lock);
    pthread_mutex_unlock(&gate_lock);
}

static void gate_release(void) {
    pthread_mutex_lock(&gate_lock);
    gate_open = true;
    pthread_cond_broadcast(&gate_cv);
    pthread_mutex_unlock(&gate_lock);
}

static bool wait_entered(int ms) {
    struct timespec until = ms_deadline(ms);
    pthread_mutex_lock(&gate_lock);
    int rc = 0;
    while (!gate_entered && rc == 0) rc = pthread_cond_timedwait(&gate_cv, &gate_lock, &until);
    bool ok = gate_entered;
    pthread_mutex_unlock(&gate_lock);
    return ok;
}

static bool wait_flag(_Atomic bool* flag, int ms) {
    struct timespec until = ms_deadline(ms);
    pthread_mutex_lock(&gate_lock);
    int rc = 0;
    while (!atomic_load(flag) && rc == 0) rc = pthread_cond_timedwait(&gate_cv, &gate_lock, &until);
    bool ok = atomic_load(flag);
    pthread_mutex_unlock(&gate_lock);
    return ok;
}

static void flag_set(_Atomic bool* flag) {
    pthread_mutex_lock(&gate_lock);
    atomic_store(flag, true);
    pthread_cond_broadcast(&gate_cv);
    pthread_mutex_unlock(&gate_lock);
}

FILE* __wrap_fopen(const char* path, const char* mode) {
    if (!strcmp(path, CONFIG_DIR "/uid.map")) path = map_path;
    FILE* fp = __real_fopen(path, mode);
    if (park_load) {
        park_load = false;
        gate_park(); /* 慢磁盘：装载在锁外进行，读者必须仍能完成 */
    }
    return fp;
}

const char* __wrap_uid_map_lookup(const UidMapEntry* entries, int count, uid_t uid) {
    const char* hit = __real_uid_map_lookup(entries, count, uid);
    if (park_lookup && hit) {
        atomic_store(&table_base, (uintptr_t)entries);
        gate_park(); /* 停在「借出指针、尚未拷贝」的窗口内 */
    }
    return hit;
}

void __wrap_free(void* pointer) {
    if (pointer && (uintptr_t)pointer == atomic_load(&table_base))
        atomic_store(&old_freed, true);
    __real_free(pointer);
}

typedef struct {
    uid_t uid;
    bool ok;
    char name[128];
} Reader;

static void* reader_fn(void* arg) {
    Reader* r = arg;
    track_tid((pid_t)syscall(SYS_gettid));
    r->ok = fw_pkg_resolve(r->uid, 0, r->name, sizeof r->name);
    return NULL;
}

static void* slow_reader_fn(void* arg) {
    park_lookup = true;
    return reader_fn(arg);
}

static void* reload_fn(void* arg) {
    (void)arg;
    track_tid((pid_t)syscall(SYS_gettid));
    fw_pkg_reload();
    flag_set(&reload_done);
    return NULL;
}

static void* slow_load_fn(void* arg) {
    park_load = true;
    return reload_fn(arg);
}

static void* shutdown_fn(void* arg) {
    (void)arg;
    track_tid((pid_t)syscall(SYS_gettid));
    fw_pkg_shutdown();
    flag_set(&shutdown_done);
    return NULL;
}

static bool write_map(const char* name_50123) {
    FILE* fp = fopen(map_path, "we");
    if (!fp) return false;
    int rc = fprintf(fp, "50124 com.other.app\n1000 com.android.settings\n50123 %s\n", name_50123);
    int closed = fclose(fp);
    return rc > 0 && closed == 0;
}

static int count_fds(void) {
    DIR* d = opendir("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    struct dirent* e;
    while ((e = readdir(d)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++;
    closedir(d);
    return n;
}

/* join 返回早于 /proc 任务摘链（既有回归已证），只容已登记 TID 在 200ms 内收尾。 */
static bool tasks_settled(void) {
    struct timespec until = ms_deadline(200);
    for (;;) {
        DIR* d = opendir("/proc/self/task");
        if (!d) return false;
        struct dirent* e;
        int live = 0;
        bool unknown = false;
        pid_t self = getpid();
        while ((e = readdir(d))) {
            char* end = NULL;
            long tid = strtol(e->d_name, &end, 10);
            if (!end || *end || tid <= 0) continue;
            if ((pid_t)tid == self) {
                live++;
                continue;
            }
            if (!tid_known((pid_t)tid)) unknown = true;
        }
        closedir(d);
        if (unknown) return false;
        if (live == 1) return true;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > until.tv_sec ||
            (now.tv_sec == until.tv_sec && now.tv_nsec >= until.tv_nsec)) return false;
        sched_yield();
    }
}

static bool basic_semantics(void) {
    char out[128];
    if (!fw_pkg_resolve(50123, 0, out, sizeof out) || strcmp(out, "com.first.app")) return false;
    /* uid 1000 走 resolve 只得到系统伪包（返回 false），真实包名要走 resolve_exact */
    if (!fw_pkg_resolve_exact(1000, 0, out, sizeof out) || strcmp(out, "com.android.settings")) return false;
    if (fw_pkg_resolve(1000, 0, out, sizeof out) || strcmp(out, "system")) return false;
    if (!fw_pkg_resolve(50999, 0, out, sizeof out) || strcmp(out, "unknown")) return false;
    if (!write_map("com.after.app")) return false;
    fw_pkg_reload();
    if (!fw_pkg_resolve(50123, 0, out, sizeof out) || strcmp(out, "com.after.app")) return false;
    return true;
}

int main(int argc, char** argv) {
    alarm(20);
    if (argc != 3) {
        fprintf(stderr, "usage: %s <serial|reload-race|shutdown-race|load-io|stress> <private uid.map>\n", argv[0]);
        return 2;
    }
    const char* mode = argv[1];
    map_path = argv[2];
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr) != 0) return 2;
    if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0 ||
        pthread_cond_init(&gate_cv, &attr) != 0) return 2;
    pthread_condattr_destroy(&attr);
    if (!write_map("com.first.app")) return 2;
    fw_pkg_reload();
    int fd_before = count_fds();

    bool ok = true;
    bool entered = false;
    bool reload_early = false;
    bool freed_early = false;
    Reader reader = {.uid = 50123, .ok = false, .name = ""};
    pthread_t reader_thread, other_thread;
    int join_reader = 0, join_other = 0;

    if (!strcmp(mode, "serial")) {
        ok = basic_semantics();
    } else if (!strcmp(mode, "reload-race") || !strcmp(mode, "shutdown-race")) {
        bool shutdown_case = !strcmp(mode, "shutdown-race");
        if (pthread_create(&reader_thread, NULL, slow_reader_fn, &reader) != 0) return 2;
        entered = wait_entered(2000);
        if (!write_map("com.after.app")) return 2;
        void* (*other)(void*) = shutdown_case ? shutdown_fn : reload_fn;
        if (pthread_create(&other_thread, NULL, other, NULL) != 0) return 2;
        /* 2s 窗口：写者被调度饿住的概率远低于此（审查用 250ms 饿死实测），
           窗口内必须能观测到「换表/关停已完成且旧表已释放」——那才是旧实现的
           判别信号；新实现因锁内借用而根本不可能完成，故观测值为 0。 */
        reload_early = wait_flag(shutdown_case ? &shutdown_done : &reload_done, 2000);
        freed_early = atomic_load(&old_freed);
        gate_release();
        join_reader = pthread_join(reader_thread, NULL);
        join_other = pthread_join(other_thread, NULL);
        /* 换表/关停真的发生了吗：只在 200ms 窗口内观测「没发生」会被调度饿住
           的写者骗过（写者 250ms 才跑 → 读者拿旧名字也像正常），故释放后必须
           再证一次终态：重载后必须解析到新名字，关停后必须不再解析到旧名字。 */
        bool after_ok;
        if (shutdown_case) {
            /* 关停后 50123 的槽缓存仍可能留着旧名字（缓存与换表同代），故用
               本次运行从未解析过的 50124：关停真发生则它不再能来自 uid.map。 */
            char post[128];
            bool post_ok = fw_pkg_resolve(50124, 0, post, sizeof post);
            after_ok = post_ok && strcmp(post, "com.other.app") != 0;
        } else {
            char post[128];
            after_ok = fw_pkg_resolve(50123, 0, post, sizeof post) &&
                       strcmp(post, "com.after.app") == 0;
        }
        /* 旧实现：换表/关停立即 free，读者随后从已释放数组 snprintf。 */
        ok = entered && !reload_early && !freed_early && reader.ok &&
             !strcmp(reader.name, "com.first.app") && after_ok;
    } else if (!strcmp(mode, "load-io")) {
        if (pthread_create(&other_thread, NULL, slow_load_fn, NULL) != 0) return 2;
        entered = wait_entered(2000); /* 装载已停在 uid.map 打开之后，尚未换表 */
        char out[128];
        bool read_old = fw_pkg_resolve(50124, 0, out, sizeof out) && !strcmp(out, "com.other.app");
        gate_release();
        join_other = pthread_join(other_thread, NULL);
        ok = entered && read_old && join_other == 0;
    } else if (!strcmp(mode, "stress")) {
        Reader readers[4];
        pthread_t threads[4];
        for (int i = 0; i < 4; i++) {
            readers[i].uid = (i % 2) ? 50124 : 50123;
            readers[i].ok = false;
            readers[i].name[0] = '\0';
            if (pthread_create(&threads[i], NULL, reader_fn, &readers[i]) != 0) return 2;
        }
        for (int round = 0; round < 20; round++) {
            if (!write_map(round % 2 ? "com.first.app" : "com.after.app")) return 2;
            fw_pkg_reload();
        }
        for (int i = 0; i < 4; i++) join_reader |= pthread_join(threads[i], NULL);
        for (int i = 0; i < 4; i++) {
            /* 50124 在两次换表中不变；50123 只能是换表前或换表后的名字，不能是垃圾/空 */
            bool named = readers[i].uid == 50124
                             ? !strcmp(readers[i].name, "com.other.app")
                             : (!strcmp(readers[i].name, "com.first.app") ||
                                !strcmp(readers[i].name, "com.after.app"));
            ok = ok && readers[i].ok && named;
        }
    } else {
        return 2;
    }

    if (strcmp(mode, "shutdown-race")) fw_pkg_shutdown();
    int fd_after = count_fds();
    bool threads = tasks_settled();
    errno = 0;
    pid_t child = waitpid(-1, NULL, WNOHANG);
    bool children = child == -1 && errno == ECHILD;
    bool resources = fd_before >= 0 && fd_after == fd_before && join_reader == 0 &&
                     join_other == 0 && threads && children;
    pthread_cond_destroy(&gate_cv);
    pthread_mutex_destroy(&gate_lock);
    printf("mode=%s ok=%d entered=%d reload_or_shutdown_before_copy=%d old_table_freed_before_copy=%d "
           "name=%s join=%d/%d fd=%d->%d tasks=%d ECHILD=%d resources=%d\n",
           mode, ok, entered, reload_early, freed_early, reader.name[0] ? reader.name : "-",
           join_reader, join_other, fd_before, fd_after, threads, children, resources);
    return (ok && resources) ? 0 : 1;
}
