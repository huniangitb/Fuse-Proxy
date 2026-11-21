/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Actual injector/IPC functions + retry_queue.c; proc/ns/config boundaries mocked. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include "retry_queue.h"
#include "nsp_constants.h"
#include "ns_mnt_wait.h"
static void fixture_log(const char* format, ...) __attribute__((format(printf, 1, 2)));
static void fixture_log(const char* format, ...) { (void)format; }
#define LOG(...) fixture_log(__VA_ARGS__)
#define LOG_DBG(...) fixture_log(__VA_ARGS__)
#define LOG_WRN(...) fixture_log(__VA_ARGS__)
#define LOG_ERR(...) fixture_log(__VA_ARGS__)
#define IPC_POST_WAIT_MS 250
#define NSP_MOUNT_DEFERRED 1
static int g_fuse_ready = 1, g_passive_mode, g_pending_startup_scan;
static int mounts, sync_mounts, queued, removed, tracked, scans, armed, failures;
static uid_t uid, uid_after;
static int uid_reads, target_reads, parent_reads, target_ns_reads, parent_ns_reads;
static int observed_attempts;
static int parent_pid, mutation, unavailable, dead;
static bool target, switched, source_ready;
static const char* parent_name;
static ino_t target_ns, parent_ns;
static int fake_kill(int pid, int sig) { (void)pid; (void)sig; return dead ? -1 : 0; }
#define kill fake_kill
uid_t get_app_uid(int pid) {
    int attempts = nsp_retry_attempts_of(pid);
    if (attempts > observed_attempts) observed_attempts = attempts;
    return ++uid_reads > 1 ? uid_after : uid;
}
bool is_isolated_uid(uid_t value); /* 实现从当前 inject_target.c 原样抽取。 */
bool is_target_app(const char* pkg, uid_t value, int pid, bool quiet) {
    (void)pkg; (void)value; (void)pid; (void)quiet; return target;
}
const char* get_active_mnt_src(void) { return source_ready ? "/fake/fuse" : NULL; }
void arm_due_timer(void) { armed++; }
void add_tracked(int pid) { (void)pid; tracked++; }
void remove_tracked(int pid) { (void)pid; removed++; }
void schedule_retry_mount(const char* pkg, int pid) { queued++; nsp_retry_schedule(pkg, pid); }
void retry_mount_succeeded(int pid) { nsp_retry_done(pid); }
void mark_injected(int pid) { (void)pid; }
void print_active_rules(const char* pkg, int pid, uid_t value, const char* why) {
    (void)pkg; (void)pid; (void)value; (void)why;
}
void nsp_set_thread_name(const char* name) { (void)name; }
int perform_app_mount(const char* pkg, int pid, uid_t value, const char* category, const char* why) {
    (void)pkg; (void)pid; (void)value; (void)category; (void)why; mounts++; return 0;
}
int perform_app_mount_sync(const char* pkg, int pid, uid_t value, const char* category, int ms) {
    (void)pkg; (void)pid; (void)value; (void)category; (void)ms; sync_mounts++; return 0;
}
int repair_stale_app_mounts_at_startup(void) { scans++; return 2; }
long ns_mnt_wait_switch(int pid, dev_t dev, ino_t ino, long budget, bool* out) {
    (void)pid; (void)dev; (void)ino; (void)budget; *out = switched; return 250000;
}
/* /proc/stat has fields 1..22, including a comm with ')' and negative fields. */
char* read_file_dynamic(const char* path, size_t* out_size, size_t max_size) {
    (void)max_size;
    int pid = 0;
    if (unavailable == 1) return NULL;
    if (strstr(path, "/cmdline")) return strdup(parent_name);
    if (sscanf(path, "/proc/%d/stat", &pid) != 1) return NULL;
    bool child = pid == 1234;
    int read = child ? ++target_reads : ++parent_reads;
    int ppid = child ? parent_pid : 1;
    unsigned long long start = child ? 1000 : 500;
    if (child && read >= 2 && mutation == 1) ppid = 1;
    if (child && read >= 2 && mutation == 2) start++;
    if (!child && read >= 2 && mutation == 3) start++;
    if (child && read >= 3 && mutation == 6) start++;
    if (child && read >= 3 && mutation == 8) ppid = 200;
    if (!child && read >= 3 && mutation == 9) start++;
    char buf[512];
    snprintf(buf, sizeof buf, "%d (%s) S %d 0 0 0 0 0 0 0 0 0 0 0 -1 0 0 0 0 0 %llu\n",
             pid, child ? "app) worker" : parent_name, ppid, start);
    if (mutation == 5) snprintf(buf, sizeof buf, "%d (bad) S %d 0\n", pid, ppid);
    if (out_size) *out_size = strlen(buf);
    return strdup(buf);
}
bool ns_mnt_wait_capture(int pid, dev_t* dev, ino_t* ino) {
    bool child = pid == 1234;
    int read = child ? ++target_ns_reads : ++parent_ns_reads;
    if (unavailable == 2 || (unavailable == 3 && !child)) return false;
    *dev = 1; *ino = child ? target_ns : parent_ns;
    if (mutation == 4 && read >= 2) *ino += 10;
    if (child && read >= 3 && mutation == 7) *ino += 10;
    return true;
}
static int64_t fake_now_ms;
static int64_t fixture_now_ms(void) { return fake_now_ms; }
/* Only production clock calls use synthetic time; retry_queue.c stays unmodified. */
#define nsp_retry_now_ms fixture_now_ms
#include "production.inc"
#undef nsp_retry_now_ms
static void startup(void) {
#include "startup.inc"
}
static void reset(void) {
    nsp_retry_reset();
    fake_now_ms = 1000;
    observed_attempts = 0;
    mounts = sync_mounts = queued = removed = tracked = scans = armed = 0;
    uid_reads = target_reads = parent_reads = target_ns_reads = parent_ns_reads = 0;
    uid = uid_after = 10123; parent_pid = 100; mutation = unavailable = dead = 0;
    target = source_ready = true; switched = false; parent_name = "zygote64";
    target_ns = 22; parent_ns = 11; g_fuse_ready = 1; g_passive_mode = 0;
}
static void check(const char* label, bool ok) {
    printf("%s %s mounts=%d sync=%d queued=%d remaining=%d attempts=%d\n",
           ok ? "PASS" : "FAIL", label, mounts, sync_mounts, queued,
           nsp_retry_count(), nsp_retry_attempts_of(1234));
    if (!ok) failures++;
}
static void retry_case(const char* label, int want_mount, int want_remaining) {
    nsp_retry_schedule("com.target", 1234);
    retry_pending_mounts();
    check(label, mounts == want_mount && nsp_retry_count() == want_remaining);
}
static void post_case(const char* label, int want_queue) {
    IpcPostArg* arg = calloc(1, sizeof *arg);
    if (!arg) exit(2);
    strcpy(arg->pkg, "com.target"); arg->pid = 1234; arg->uid = 10123;
    ipc_post_mount_thread(arg);
    check(label, queued == want_queue && mounts == 0 && sync_mounts == 0 && removed == 1);
}
int main(void) {
    reset(); post_case("timeout enqueues without synchronous mount", 1);
    reset(); dead = 1; post_case("dead timeout clears", 0);
    reset(); uid = uid_after = 190123; post_case("isolated multiuser timeout clears", 0);
    reset(); uid = uid_after = 0; post_case("unknown timeout clears", 0);
    reset(); nsp_retry_schedule("com.target",1234); uid = uid_after = 190123;
    post_case("isolated timeout clears existing queue", 0); check("timeout queue cleared", nsp_retry_count() == 0);
    reset(); retry_case("private namespace dispatch retains accounting", 1, 1);
    check("dispatch is not success", nsp_retry_attempts_of(1234) == 1);
    reset(); target_ns = parent_ns; retry_case("zygote ns even with storage must not mount", 0, 1);
    check("namespace waiting still bounded accounting", nsp_retry_attempts_of(1234) == 1);
    reset(); target_ns = parent_ns; nsp_retry_schedule("com.target", 1234);
    int rounds = 0;
    while (nsp_retry_count() && rounds <= NSP_RETRY_MAX_ATTEMPTS) {
        fake_now_ms += NSP_RETRY_BACKOFF_CAP_MS;
        retry_pending_mounts();
        rounds++;
    }
    check("unknown ns converges after real queue cap without mounting",
          !mounts && !nsp_retry_count() && observed_attempts == NSP_RETRY_MAX_ATTEMPTS &&
          rounds == NSP_RETRY_MAX_ATTEMPTS);
    reset(); unavailable = 1; retry_case("stat unknown fail closed", 0, 1);
    reset(); unavailable = 2; retry_case("target ns unknown fail closed", 0, 1);
    reset(); unavailable = 3; retry_case("parent ns unknown fail closed", 0, 1);
    reset(); parent_pid = 1; retry_case("reparented init fail closed", 0, 1);
    reset(); parent_name = "untrusted"; retry_case("unknown parent fail closed", 0, 1);
    reset(); mutation = 1; retry_case("reparent during probe fail closed", 0, 1);
    reset(); mutation = 2; retry_case("target PID/starttime reuse fail closed", 0, 1);
    reset(); mutation = 3; retry_case("parent PID/starttime reuse fail closed", 0, 1);
    reset(); mutation = 4; retry_case("namespace changes during probe fail closed", 0, 1);
    reset(); mutation = 5; retry_case("short malformed stat fail closed", 0, 1);
    reset(); mutation = 6; retry_case("target PID reuse between stable helper calls", 0, 1);
    reset(); mutation = 7; retry_case("target ns changes between stable helper calls", 0, 1);
    reset(); mutation = 8; retry_case("reparent between stable helper calls", 0, 1);
    reset(); mutation = 9; retry_case("parent PID reuse between stable helper calls", 0, 1);
    reset(); target = false; retry_case("configuration canceled after namespace proof", 0, 0);
    reset(); uid_after = 190123; retry_case("UID becomes isolated after proof", 0, 0);
    reset(); uid_after = 10124; retry_case("normal UID change after proof defers", 0, 1);
    const uid_t values[] = {0, (uid_t)-1, 90000, 99999, 190000, 199999, 1090000, 1099999};
    for (size_t i = 0; i < sizeof values / sizeof *values; i++) {
        reset(); uid = uid_after = values[i]; retry_case("invalid/isolated retry clears queue", 0, 0);
    }
    const uid_t normal[] = {89999, 100000, 189999, 10123};
    for (size_t i = 0; i < sizeof normal / sizeof *normal; i++) {
        reset(); uid = uid_after = normal[i]; retry_case("nonisolated boundary can dispatch", 1, 1);
    }
    const char* parents[] = {"zygote", "usap32", "usap64", "com.example_zygote"};
    for (size_t i = 0; i < sizeof parents / sizeof *parents; i++) {
        reset(); parent_name = parents[i]; retry_case("recognized parent private ns", 1, 1);
    }
    reset(); g_pending_startup_scan = 1; startup(); startup();
    check("active startup repairs once", scans == 1 && !g_pending_startup_scan);
    reset(); g_passive_mode = 1; g_pending_startup_scan = 1; startup();
    g_passive_mode = 0; startup();
    check("passive startup consumes without repair or later toggle replay", scans == 0 && !g_pending_startup_scan);
    printf("import injector failures=%d\n", failures);
    return failures ? 1 : 0;
}
