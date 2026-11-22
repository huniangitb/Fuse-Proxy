/* 配置重载的两段式判别：真读盘/慢 pm 在写锁外，锁内只解析发布。
 *
 * 背景：注入器在唯一事件循环线程里重载配置。旧序列 =
 *   config_lock_write(); reload_config_rules_diff(path, …); config_unlock_write();
 * 而这个库函数内部先 config_read_view（真读盘 + scan_active_users 的 pm 探测，
 * 预算 800ms）再构建发布——写锁期间同进程所有 config 读者（pre-hook 规则判定、
 * 发布器、控制面查询）全被挡住，一次慢盘/慢 binder 就放大成整进程无响应。
 *
 * 本驱动用真实 config_parser.c 的两个**生产函数序列**对比：
 *   new = config_read_view(锁外) + [写锁] config_commit_prepared [解锁]
 *   old = [写锁] reload_config_rules_diff [解锁]
 * 读盘与 pm 的慢速由 --wrap 注入（只慢第一次），读者线程全程量 config_lock_read()
 * 的等待时间。这不是内核证明，只判别锁的跨越范围。
 */
#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "config_parser.h"

extern FILE* __real_fopen(const char* path, const char* mode);
extern int __real_common_run_cmd_lines(const char* shell_cmd, int budget_ms, NspCmdLineFn on_line,
                                       void* ctx, bool* timed_out);

static _Atomic int g_slow_read_ms;
static _Atomic int g_slow_pm_ms;

static void sleep_ms(int ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static unsigned long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000ull + (unsigned long long)ts.tv_nsec / 1000ull;
}

static unsigned long long now_ms(void) { return now_us() / 1000ull; }

/* 慢读盘：只慢第一次打开规则文件，之后正常（每轮重置） */
FILE* __wrap_fopen(const char* path, const char* mode) {
    int ms = atomic_load(&g_slow_read_ms);
    if (ms > 0 && path && strstr(path, "rules.conf")) {
        atomic_store(&g_slow_read_ms, 0);
        sleep_ms(ms);
    }
    return __real_fopen(path, mode);
}

/* 慢 pm：模拟 pm list users 挂住（返回空输出，调用方回退磁盘推导） */
int __wrap_common_run_cmd_lines(const char* shell_cmd, int budget_ms, NspCmdLineFn on_line,
                                void* ctx, bool* timed_out) {
    int ms = atomic_load(&g_slow_pm_ms);
    if (ms > 0) {
        atomic_store(&g_slow_pm_ms, 0);
        sleep_ms(ms);
        if (timed_out) *timed_out = false;
        return 0;
    }
    return __real_common_run_cmd_lines(shell_cmd, budget_ms, on_line, ctx, timed_out);
}

static _Atomic unsigned long long g_reader_max_us;
static _Atomic int g_reader_ready;
static _Atomic int g_reader_stop;

static void* reader_main(void* arg) {
    (void)arg;
    atomic_store(&g_reader_ready, 1);
    while (!atomic_load(&g_reader_stop)) {
        unsigned long long t0 = now_us();
        config_lock_read();
        config_unlock_read();
        unsigned long long dt = now_us() - t0;
        if (dt > atomic_load(&g_reader_max_us)) atomic_store(&g_reader_max_us, dt);
        sleep_ms(1);
    }
    return NULL;
}

int main(int argc, char** argv) {
    const char* mode = argc > 1 ? argv[1] : "new";
    int slow_read = argc > 2 ? atoi(argv[2]) : 300;
    int slow_pm = argc > 3 ? atoi(argv[3]) : 300;
    int rounds = argc > 4 ? atoi(argv[4]) : 2;

    char dir[256];
    snprintf(dir, sizeof dir, "%s", CONFIG_DIR);
    char mk[300];
    snprintf(mk, sizeof mk, "mkdir -p %s", dir);
    if (system(mk) != 0) return 2;

    char rules[320];
    snprintf(rules, sizeof rules, "%s/rules.conf", dir);
    FILE* fp = fopen(rules, "w");
    if (!fp) return 2;
    fprintf(fp, "[GLOBAL]\nMONITOR ON\nHIDE /sdcard/seed\n");
    fclose(fp);

    config_init_lock();
    pthread_t th;
    if (pthread_create(&th, NULL, reader_main, NULL) != 0) return 2;
    while (!atomic_load(&g_reader_ready)) sleep_ms(2);
    sleep_ms(30);

    unsigned long long max_read_ms = 0, max_commit_ms = 0;
    ChangedPkg changed[128];
    int last_changed = 0;
    for (int i = 0; i < rounds; i++) {
        /* 每轮改写文件内容，确保提交真的重建（内容不同） */
        fp = fopen(rules, "w");
        if (!fp) return 2;
        fprintf(fp, "[GLOBAL]\nMONITOR ON\nHIDE /sdcard/r%d\n", i);
        fclose(fp);
        atomic_store(&g_slow_read_ms, slow_read);
        atomic_store(&g_slow_pm_ms, slow_pm);
        atomic_store(&g_reader_max_us, 0);

        if (strcmp(mode, "new") == 0) {
            unsigned long long t0 = now_ms();
            NspCfgRec* recs = NULL;
            int count = 0;
            config_read_view(rules, &recs, &count);
            unsigned long long read_ms = now_ms() - t0;
            unsigned long long t1 = now_ms();
            config_lock_write();
            last_changed = config_commit_prepared(recs, count, changed, 128);
            config_unlock_write();
            unsigned long long commit_ms = now_ms() - t1;
            config_free_view(recs, count);
            if (read_ms > max_read_ms) max_read_ms = read_ms;
            if (commit_ms > max_commit_ms) max_commit_ms = commit_ms;
        } else {
            unsigned long long t1 = now_ms();
            config_lock_write();
            last_changed = reload_config_rules_diff(rules, changed, 128);
            config_unlock_write();
            unsigned long long commit_ms = now_ms() - t1;
            if (commit_ms > max_commit_ms) max_commit_ms = commit_ms;
        }
        /* 让读者跑满一个测量窗口 */
        sleep_ms(40);
    }

    atomic_store(&g_reader_stop, 1);
    pthread_join(th, NULL);
    unsigned long long reader_max = atomic_load(&g_reader_max_us);
    printf("mode=%s rounds=%d read_ms=%llu commit_ms=%llu reader_max_us=%llu changed=%d\n", mode,
           rounds, max_read_ms, max_commit_ms, reader_max, last_changed);
    config_destroy_lock();
    return 0;
}
