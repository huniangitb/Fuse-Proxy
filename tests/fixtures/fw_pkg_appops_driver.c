#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fw_pkg.h"
#include "uid_map.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int output_fd, started_pipe[2], gate_pipe[2];
static _Atomic int queries;
static _Atomic unsigned joins;
static _Atomic long long clock_offset_ms;
static _Thread_local int thread_id = -1;
static _Thread_local bool announced_entry;
static sem_t entered_query;
static const char *scenario;

typedef struct {
    int id;
    uid_t uid;
    bool result;
    _Atomic bool done;
    long long elapsed_ms;
} Call;

static void require(bool ok, const char *label) {
    if (!ok) { dprintf(output_fd, "FAIL case=%s check=%s errno=%d\n", scenario, label, errno); exit(1); }
}
int __real_clock_gettime(clockid_t id, struct timespec *ts);
int __wrap_clock_gettime(clockid_t id, struct timespec *ts) {
    int rc = __real_clock_gettime(id, ts);
    if (rc == 0 && id == CLOCK_MONOTONIC) {
        long long ns = ts->tv_nsec + atomic_load(&clock_offset_ms) * 1000000LL;
        ts->tv_sec += ns / 1000000000LL;
        ts->tv_nsec = ns % 1000000000LL;
        if (thread_id >= 1 && !announced_entry) {
            announced_entry = true;
            sem_post(&entered_query);
        }
    }
    return rc;
}
static long long real_ms(void) {
    struct timespec ts;
    require(__real_clock_gettime(CLOCK_MONOTONIC, &ts) == 0, "real_clock");
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
int __wrap_uid_map_load(UidMapEntry *entries, int capacity) {
    (void)entries;
    (void)capacity;
    return 0;
}
int __real_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                      const posix_spawnattr_t *attributes, char *const argv[], char *const envp[]);
int __wrap_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                      const posix_spawnattr_t *attributes, char *const argv[], char *const envp[]) {
    int count = atomic_fetch_add(&queries, 1) + 1;
    int rc = __real_posix_spawn(pid, path, actions, attributes, argv, envp);
    dprintf(output_fd, "SPAWN case=%s worker=%d count=%d path=%s pkg=%s rc=%d child=%d\n",
            scenario, thread_id, count, path, argv[3], rc, rc == 0 ? *pid : -1);
    return rc;
}
int __real_pthread_join(pthread_t thread, void **result);
int __wrap_pthread_join(pthread_t thread, void **result) {
    atomic_fetch_add(&joins, 1);
    return __real_pthread_join(thread, result);
}
static void directory(const char *name) { require(mkdir(name, 0755) == 0, name); }
static void setup_root(const char *root, const char *fixture) {
    require(mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) == 0, "private_mount_propagation");
    require(mount("tmpfs", root, "tmpfs", MS_NOSUID, "mode=755,size=16m") == 0, "fixture_tmpfs");
    require(chdir(root) == 0, "chdir_fixture");
    directory("data"); directory("data/system"); directory("system"); directory("system/bin");
    directory("dev"); directory("proc"); directory("oldroot");
    int source = open(fixture, O_RDONLY);
    require(source >= 0, "open_static_cmd");
    int dest = open("system/bin/cmd", O_CREAT | O_EXCL | O_WRONLY, 0755);
    require(dest >= 0, "create_cmd");
    char buffer[8192];
    ssize_t got;
    while ((got = read(source, buffer, sizeof buffer)) > 0)
        require(write(dest, buffer, (size_t)got) == got, "copy_static_cmd");
    require(got == 0, "read_static_cmd");
    close(source); close(dest);
    dest = open("data/system/packages.list", O_CREAT | O_EXCL | O_WRONLY, 0644);
    require(dest >= 0, "create_packages_list");
    dprintf(dest, "com.repro.hold 12000 0 /data/user/0/com.repro.hold default none 0 0\n"
                  "com.repro.fast 12001 0 /data/user/0/com.repro.fast default none 0 0\n"
                  "com.repro.collision 14048 0 /data/user/0/com.repro.collision default none 0 0\n");
    close(dest);
    dest = open("dev/null", O_CREAT | O_EXCL | O_WRONLY, 0666);
    require(dest >= 0, "null_placeholder"); close(dest);
    require(mount("/dev/null", "dev/null", NULL, MS_BIND, NULL) == 0, "private_dev_null");
    require(mount("proc", "proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) == 0, "pidns_proc");
    require(syscall(SYS_pivot_root, ".", "oldroot") == 0, "pivot_root");
    require(chdir("/") == 0, "chdir_pivot");
    require(umount2("/oldroot", MNT_DETACH) == 0, "detach_oldroot");
    require(rmdir("/oldroot") == 0, "remove_oldroot");
    dprintf(output_fd, "ISOLATED pid=%d private_tmpfs=1 oldroot_detached=1\n", getpid());
}
static void environment(const char *key, const char *value) { require(setenv(key, value, 1) == 0, key); }
static void set_payload(const char *value) { environment("APPOPS_PAYLOAD", value); }
static void initialize_fixture(void) {
    require(pipe(started_pipe) == 0 && pipe(gate_pipe) == 0, "control_pipes");
    char number[32];
    snprintf(number, sizeof number, "%d", started_pipe[1]); environment("APPOPS_STARTED_FD", number);
    snprintf(number, sizeof number, "%d", gate_pipe[0]); environment("APPOPS_GATE_FD", number);
    environment("APPOPS_CASE", scenario);
    require(sem_init(&entered_query, 0, 0) == 0, "entry_semaphore");
    set_payload("allow");
}
static void *call_thread(void *arg) {
    Call *call = arg;
    thread_id = call->id;
    long long began = real_ms();
    dprintf(output_fd, "CALL_BEGIN worker=%d uid=%u\n", call->id, call->uid);
    call->result = fw_pkg_manages_external(call->uid);
    call->elapsed_ms = real_ms() - began;
    atomic_store(&call->done, true);
    dprintf(output_fd, "CALL_END worker=%d uid=%u result=%d elapsed_ms=%lld\n",
            call->id, call->uid, call->result, call->elapsed_ms);
    return NULL;
}
static void await_fixture(void) {
    char byte;
    ssize_t got;
    do { got = read(started_pipe[0], &byte, 1); } while (got < 0 && errno == EINTR);
    require(got == 1, "fixture_running_at_real_blocking_edge");
    dprintf(output_fd, "FIXTURE_BLOCKED case=%s\n", scenario);
}
static void assert_reaped(void) {
    int status;
    errno = 0;
    pid_t pid = waitpid(-1, &status, WNOHANG);
    require(pid == -1 && errno == ECHILD, "no_live_or_unreaped_cmd_child");
}
static void bounded_case(void) {
    Call leader = {.id = 0, .uid = 12000};
    Call other = {.id = 1, .uid = 12001};
    pthread_t first, second;
    require(pthread_create(&first, NULL, call_thread, &leader) == 0, "start_hung_uid");
    await_fixture();
    dprintf(output_fd, "PHASE OTHER_UID_MUST_NOT_WAIT_GLOBAL_LOCK\n");
    require(pthread_create(&second, NULL, call_thread, &other) == 0, "start_other_uid");
    require(pthread_join(second, NULL) == 0, "join_other_uid");
    require(other.result, "unrelated_uid_allow_result");
    require(!atomic_load(&leader.done), "other_uid_finishes_before_hung_query_deadline");
    dprintf(output_fd, "PHASE HUNG_QUERY_MUST_TIMEOUT_FAIL_CLOSED\n");
    require(pthread_join(first, NULL) == 0, "join_timeout_query");
    require(!leader.result, "timed_out_query_fail_closed");
    require(leader.elapsed_ms <= 1000, "250ms_query_budget_with_750ms_scheduler_slack");
    require(atomic_load(&queries) == 2, "one_query_per_distinct_uid");
    assert_reaped();
}
static void dedup_case(void) {
    Call calls[4] = {{.id=0,.uid=12000},{.id=1,.uid=12000},{.id=2,.uid=12000},{.id=3,.uid=12000}};
    pthread_t threads[4];
    require(pthread_create(&threads[0], NULL, call_thread, &calls[0]) == 0, "start_dedup_leader");
    await_fixture();
    dprintf(output_fd, "PHASE SAME_UID_PENDING_MUST_FAIL_CLOSED_WITHOUT_LOCK_WAIT\n");
    for (int i=1; i<4; i++) require(pthread_create(&threads[i], NULL, call_thread, &calls[i]) == 0, "start_dedup_follower");
    for (int i=1; i<4; i++) {
        require(sem_wait(&entered_query) == 0, "follower_entered_real_ext_clock");
        require(pthread_join(threads[i], NULL) == 0, "join_pending_follower");
        require(!calls[i].result, "inflight_uid_fail_closed");
    }
    require(atomic_load(&queries) == 1, "same_uid_inflight_only_one_spawn");
    require(!atomic_load(&calls[0].done), "pending_returns_before_leader_finishes");
    require(write(gate_pipe[1], "x", 1) == 1, "release_fast_success_leader");
    require(pthread_join(threads[0], NULL) == 0, "join_dedup_leader");
    require(calls[0].result, "leader_success_allow");
    require(fw_pkg_manages_external(12000) && fw_pkg_can_install_packages(12000), "success_cache_published_after_inflight");
    require(atomic_load(&queries) == 1, "one_spawn_after_success_cache_hit");
    assert_reaped();
}
static void failure_case(void) {
    set_payload("fail");
    for (int i=0; i<8; i++) require(!fw_pkg_manages_external(12000), "immediate_exit7_fail_closed");
    dprintf(output_fd, "FAILURE_CACHE calls=8 spawns=%d expected=1\n", atomic_load(&queries));
    require(atomic_load(&queries) == 1, "failure_cooldown_prevents_eight_spawns");
    assert_reaped();
}
static void ordinary_case(const char *payload, bool manage, bool installer) {
    set_payload(payload);
    require(fw_pkg_manages_external(12000) == manage, "ordinary_manage_result");
    require(fw_pkg_can_install_packages(12000) == installer, "ordinary_installer_result");
    require(fw_pkg_manages_external(12000) == manage, "ordinary_repeat_cached_result");
    require(atomic_load(&queries) == 1, "ordinary_two_ops_share_success_cache");
    assert_reaped();
}
static void ttl_case(bool failure) {
    set_payload(failure ? "fail" : "allow");
    require(fw_pkg_manages_external(12000) == !failure, "ttl_initial_result");
    set_payload(failure ? "allow" : "deny");
    atomic_fetch_add(&clock_offset_ms, failure ? 500 : 29000);
    require(fw_pkg_manages_external(12000) == !failure, "ttl_not_expired_uses_cache");
    require(atomic_load(&queries) == 1, "ttl_no_early_requery");
    atomic_fetch_add(&clock_offset_ms, failure ? 600 : 2000);
    require(fw_pkg_manages_external(12000) == failure, "ttl_expired_recovers_new_result");
    require(atomic_load(&queries) == 2, "ttl_expired_exactly_one_new_query");
    assert_reaped();
}
static void generation_case(void) {
    set_payload("fail");
    require(!fw_pkg_manages_external(12000), "gen_initial_failure");
    set_payload("allow"); fw_pkg_reload();
    require(fw_pkg_manages_external(12000), "gen_invalidates_failure_cooldown");
    set_payload("deny"); fw_pkg_reload();
    require(!fw_pkg_manages_external(12000), "gen_invalidates_success_cache");
    require(atomic_load(&queries) == 3, "gen_three_real_queries");
    assert_reaped();
    fw_pkg_shutdown();
}
static void held_start(Call *old, pthread_t *thread, const char *payload) {
    set_payload(payload); environment("APPOPS_HOLD", "1");
    require(pthread_create(thread, NULL, call_thread, old) == 0, "start_old_query");
    await_fixture();
    environment("APPOPS_HOLD", "0");
    dprintf(output_fd, "PHASE SAME_UID_PENDING_CACHE_MUST_NOT_BLOCK\n");
    require(!fw_pkg_manages_external(old->uid) && !fw_pkg_can_install_packages(old->uid), "both_ops_pending_fail_false");
    require(atomic_load(&queries) == 1 && !atomic_load(&old->done), "pending_dedup_before_old_completion");
}
static void held_release(Call *old, pthread_t thread, bool expected) {
    require(!atomic_load(&old->done), "old_still_pending_before_release");
    require(write(gate_pipe[1], "x", 1) == 1, "release_old_real_child");
    require(pthread_join(thread, NULL) == 0, "join_old_query");
    require(old->result == expected, "old_completion_result_current_generation_only");
}
static void gen_race_case(bool replace) {
    Call old = {.id=0, .uid=12000}; pthread_t thread;
    held_start(&old, &thread, "allow");
    fw_pkg_reload(); set_payload("deny");
    dprintf(output_fd, "PHASE RELOAD_WHILE_OLD_QUERY_PENDING replace=%d\n", replace);
    if (replace) {
        require(!fw_pkg_manages_external(12000) && !fw_pkg_can_install_packages(12000), "new_generation_deny");
        require(atomic_load(&queries) == 2, "new_generation_one_real_query");
    }
    held_release(&old, thread, false);
    require(!fw_pkg_manages_external(12000) && !fw_pkg_can_install_packages(12000), "stale_allow_never_authorizes");
    require(atomic_load(&queries) == 2, "old_completion_does_not_overwrite_new_generation");
    assert_reaped(); fw_pkg_shutdown();
}
static void collision_case(bool new_allow, bool aba) {
    Call old = {.id=0, .uid=12000}; pthread_t thread;
    held_start(&old, &thread, new_allow ? "deny" : "allow");
    set_payload(new_allow ? "allow" : "deny");
    dprintf(output_fd, "PHASE COLLISION uidA=12000 uidB=14048 delta=2048 aba=%d\n", aba);
    require(fw_pkg_manages_external(14048) == new_allow && fw_pkg_can_install_packages(14048) == new_allow, "new_collision_result");
    require(atomic_load(&queries) == 2 && !atomic_load(&old.done), "collision_query_finishes_before_old");
    uid_t current_uid = 14048; int expected_queries = 2;
    if (aba) {
        set_payload("deny"); current_uid = 12000; expected_queries = 3;
        require(!fw_pkg_manages_external(current_uid), "ABA_new_claim_deny");
    }
    held_release(&old, thread, !new_allow);
    bool expected = aba ? false : new_allow;
    require(fw_pkg_manages_external(current_uid) == expected && fw_pkg_can_install_packages(current_uid) == expected, "old_completion_preserves_new_collision_cache");
    dprintf(output_fd, "CACHE_AFTER_OLD uid=%u result=%d spawns=%d expected_spawns=%d\n", current_uid, expected, atomic_load(&queries), expected_queries);
    require(atomic_load(&queries) == expected_queries, "old_completion_must_not_evict_new_cache");
    assert_reaped(); fw_pkg_shutdown();
}
static void pause_ms(long ms) {
    struct timespec remaining = {.tv_sec=ms/1000, .tv_nsec=(ms%1000)*1000000};
    while (nanosleep(&remaining, &remaining) != 0) require(errno == EINTR, "real_nanosleep");
}
static void enoent_case(void) {
    require(rename("/system/bin/cmd", "/system/bin/cmd.saved") == 0, "hide_cmd_in_private_tmpfs");
    require(!fw_pkg_manages_external(12000), "real_spawn_ENOENT_fail_false");
    require(atomic_load(&queries) == 1, "one_ENOENT_attempt");
    require(rename("/system/bin/cmd.saved", "/system/bin/cmd") == 0, "restore_cmd_in_private_tmpfs");
    for (int i=0; i<8; i++) require(!fw_pkg_manages_external(12000) && !fw_pkg_can_install_packages(12000), "ENOENT_failure_cached_both_ops");
    pause_ms(500);
    require(!fw_pkg_manages_external(12000) && atomic_load(&queries) == 1, "ENOENT_cooldown_before_1s");
    pause_ms(650);
    require(fw_pkg_manages_external(12000) && fw_pkg_can_install_packages(12000), "ENOENT_cooldown_recovers_allow_after_1s");
    require(atomic_load(&queries) == 2, "ENOENT_recovery_one_retry");
    assert_reaped(); fw_pkg_shutdown();
}
static void shutdown_idle_case(void) {
    require(fw_pkg_manages_external(12000), "start_query_reaper_before_shutdown");
    assert_reaped();
    unsigned before = atomic_load(&joins);
    fw_pkg_shutdown();
    fw_pkg_shutdown();
    require(atomic_load(&joins) == before + 1, "repeated_shutdown_joins_reaper_exactly_once");
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    scenario = argv[1]; output_fd = dup(STDOUT_FILENO);
    if (output_fd < 0) return 2;
    dprintf(output_fd, "BEGIN case=%s\n", scenario);
    setup_root(argv[2], argv[3]); initialize_fixture();
    if (!strcmp(scenario,"A") || !strcmp(scenario,"B") || !strcmp(scenario,"E")) bounded_case();
    else if (!strcmp(scenario,"C")) failure_case();
    else if (!strcmp(scenario,"D")) dedup_case();
    else if (!strcmp(scenario,"allow")) ordinary_case("allow",true,true);
    else if (!strcmp(scenario,"deny")) ordinary_case("deny",false,false);
    else if (!strcmp(scenario,"installer")) ordinary_case("installer",false,true);
    else if (!strcmp(scenario,"uidmode")) ordinary_case("uidmode",true,false);
    else if (!strcmp(scenario,"ttl")) ttl_case(false);
    else if (!strcmp(scenario,"failure-ttl")) ttl_case(true);
    else if (!strcmp(scenario,"generation")) generation_case();
    else if (!strcmp(scenario,"gen-replaced")) gen_race_case(true);
    else if (!strcmp(scenario,"gen-unclaimed")) gen_race_case(false);
    else if (!strcmp(scenario,"collision-deny")) collision_case(false,false);
    else if (!strcmp(scenario,"collision-allow")) collision_case(true,false);
    else if (!strcmp(scenario,"collision-aba")) collision_case(false,true);
    else if (!strcmp(scenario,"enoent-recovery")) enoent_case();
    else if (!strcmp(scenario,"shutdown-idle")) shutdown_idle_case();
    else require(false,"unknown_case");
    dprintf(output_fd,"PASS case=%s spawns=%d\n",scenario,atomic_load(&queries));
    return 0;
}
