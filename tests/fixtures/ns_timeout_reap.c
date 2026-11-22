/* 判别驱动：ns 命名空间执行原语的收尸有界性
 *
 * 直编真实 src/injector/ns_utils.c（-DNS_TIMEOUT_NS_UTILS_SRC=），只经
 * -Wl,--wrap=kill / --wrap=_exit 控制两件事：①超时后的 SIGKILL 是否真的
 * 生效（模拟卡在不可中断内核态、SIGKILL 无效的子进程）；②子进程写完结果
 * 后是否立刻退出。被测函数 run_in_mnt_ns_timeout 与收尸逻辑全走真实代码。
 *
 * 必须在 `unshare -Ur -m --propagation private` 下运行：非特权用户直接
 * setns(CLONE_NEWNS) 会 EPERM，走不到被测路径。
 *
 * 判别性（旧实现 = git show <commit>:src/injector/ns_utils.c）：
 *  - 旧超时分支 kill() 后 waitpid(child,NULL,0)：SIGKILL 不生效时调用方
 *    永久阻塞（本驱动用 watchdog 判红）；
 *  - 旧 status 分支 waitpid(child,&status,0)：子进程写完结果却滞留时，调用
 *    方白等满滞留时间（用例 3 的 elapsed 断言判红）。
 * 复现旧实现：NS_TIMEOUT_NS_UTILS_SRC=<旧源码副本> python3 tests/test_ns_timeout_reap.py
 */
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

/* ===== ns_utils.c 的外部依赖（本驱动只触达超时执行原语） ===== */
void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}
int g_log_forward_fd = -1;
int g_epoll_fd = -1;

#include NS_TIMEOUT_NS_UTILS_SRC

/* ===== 受控钩子 ===== */
int __real_kill(pid_t pid, int sig);
void __real__exit(int code);

static pid_t g_killed_pid;  /* 最后一次 kill 的目标（父进程自己调 kill，可直接读） */
/* 子进程 PID 只能由子进程自己知道：写进 fork 前建好的共享映射，父进程才看得到 */
static pid_t* g_shared_child_pid;
static int g_kill_noop;     /* 1 = SIGKILL 不生效（模拟不可中断内核态） */
static int g_child_linger_ms; /* >0 = 子进程写完成结果后仍滞留这么久 */

int __wrap_kill(pid_t pid, int sig) {
    g_killed_pid = pid;
    if (g_kill_noop) return 0;
    return __real_kill(pid, sig);
}

void __wrap__exit(int code) {
    if (g_shared_child_pid) *g_shared_child_pid = getpid();
    if (g_child_linger_ms > 0) {
        struct timespec ts = {.tv_sec = g_child_linger_ms / 1000,
                              .tv_nsec = (long)(g_child_linger_ms % 1000) * 1000000L};
        nanosleep(&ts, NULL);
    }
    __real__exit(code);
}

/* ===== 用例 ===== */
static int g_pass;
static int g_fail;

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void check(const char* label, bool ok) {
    printf("  %s %s\n", ok ? "[PASS]" : "[FAIL]", label);
    if (ok) g_pass++; else g_fail++;
}

/* 有界等一个子进程消失：要么本进程收到它，要么它已被别处收走（ECHILD）。
   绝不 waitpid(...,0)：清理路径同样不许无限阻塞。 */
static bool wait_gone(pid_t pid, long budget_ms) {
    if (pid <= 0) return false;
    long deadline = now_ms() + budget_ms;
    for (;;) {
        pid_t w = waitpid(pid, NULL, WNOHANG);
        if (w == pid) return true;
        if (w == -1 && errno == ECHILD) return true;
        if (now_ms() >= deadline) return false;
        struct timespec s = {.tv_sec = 0, .tv_nsec = 2000000};
        nanosleep(&s, NULL);
    }
}

static int hang_forever(void* args) {
    (void)args;
    for (;;) poll(NULL, 0, 1000);
    return 0;
}

static int return_ok(void* args) {
    (void)args;
    return 0;
}

/* 用例 1（对照）：真 SIGKILL 生效时，超时按预算返回且子进程被回收 */
static void case_normal_timeout(void) {
    g_killed_pid = 0;
    int cerr = 0;
    long t0 = now_ms();
    int ret = run_in_mnt_ns_timeout((int)getpid(), hang_forever, NULL, &cerr, 100);
    long ms = now_ms() - t0;
    pid_t pid = g_killed_pid;
    bool collected = wait_gone(pid, 3000);
    printf("normal_timeout ret=%d cerr=%d elapsed_ms=%ld killed=%d collected=%d\n", ret, cerr, ms,
           (int)pid, (int)collected);
    check("normal_timeout 超时失败返回 -1/ETIMEDOUT", ret == -1 && cerr == ETIMEDOUT);
    check("normal_timeout 在预算附近有界返回", ms >= 90 && ms <= 600);
    check("normal_timeout 子进程已被回收（不留僵尸）", collected);
}

/* 用例 2：SIGKILL 不生效（子进程卡在内核态）时，调用方不得被永久钉住 */
typedef struct {
    int ret;
    int cerr;
    long ms;
} CallRes;

static CallRes g_call;
static atomic_int g_call_done;

static void* call_in_thread(void* args) {
    (void)args;
    int cerr = 0;
    long t0 = now_ms();
    int ret = run_in_mnt_ns_timeout((int)getpid(), hang_forever, NULL, &cerr, 100);
    g_call.ms = now_ms() - t0;
    g_call.ret = ret;
    g_call.cerr = cerr;
    atomic_store(&g_call_done, 1);
    return NULL;
}

static void case_stuck_child(void) {
    g_kill_noop = 1;
    g_killed_pid = 0;
    atomic_store(&g_call_done, 0);
    pthread_t th;
    if (pthread_create(&th, NULL, call_in_thread, NULL) != 0) {
        check("stuck_child 起调用线程", false);
        g_kill_noop = 0;
        return;
    }
    long deadline = now_ms() + 1500;
    while (!atomic_load(&g_call_done) && now_ms() < deadline) {
        struct timespec s = {.tv_sec = 0, .tv_nsec = 2000000};
        nanosleep(&s, NULL);
    }
    bool finished = atomic_load(&g_call_done) != 0;
    printf("stuck_child finished=%d ret=%d cerr=%d elapsed_ms=%ld\n", (int)finished, g_call.ret,
           g_call.cerr, g_call.ms);
    check("stuck_child 调用方没有被收尸钉死", finished);
    if (finished) {
        check("stuck_child 仍按超时失败返回", g_call.ret == -1 && g_call.cerr == ETIMEDOUT);
        check("stuck_child 有界返回（不等待 SIGKILL 生效）", g_call.ms <= 600);
    }
    /* 清理：真 SIGKILL 让旧实现里卡住的 waitpid 解套，再 join 调用线程 */
    pid_t pid = g_killed_pid;
    __real_kill(pid, SIGKILL);
    g_kill_noop = 0;
    pthread_join(th, NULL);
    check("stuck_child 清理后不留僵尸", wait_gone(pid, 3000));
}

/* 用例 3：子进程已把业务结果写进管道、却仍滞留时，调用方不该白等 */
static void case_status_child_lingers(void) {
    g_child_linger_ms = 500;
    if (g_shared_child_pid) *g_shared_child_pid = 0;
    int cerr = 0;
    long t0 = now_ms();
    int ret = run_in_mnt_ns_timeout((int)getpid(), return_ok, NULL, &cerr, 1000);
    long ms = now_ms() - t0;
    g_child_linger_ms = 0;
    pid_t pid = g_shared_child_pid ? *g_shared_child_pid : 0;
    printf("status_lingers ret=%d cerr=%d elapsed_ms=%ld child=%d\n", ret, cerr, ms, (int)pid);
    check("status_lingers 业务返回值仍以管道为准", ret == 0);
    check("status_lingers 不等子进程退出（不白等滞留时间）", ms <= 200);
    check("status_lingers 滞留子进程退出后仍可收尸", wait_gone(pid, 3000));
}

int main(void) {
    printf("ns 执行原语：超时与收尸有界性用例\n");
    g_shared_child_pid = mmap(NULL, sizeof(pid_t), PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_shared_child_pid == MAP_FAILED) {
        printf("  [FAIL] 共享映射建立失败\n");
        return 1;
    }
    *g_shared_child_pid = 0;
    case_normal_timeout();
    case_status_child_lingers();
    case_stuck_child();
    errno = 0;
    bool no_children = waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD;
    check("所有子进程均已回收", no_children);
    munmap(g_shared_child_pid, sizeof(pid_t));
    printf("\n结果: %d 通过, %d 失败\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}