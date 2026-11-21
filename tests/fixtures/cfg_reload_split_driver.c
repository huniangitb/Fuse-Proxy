/*
 * tests/fixtures/cfg_reload_split_driver.c
 *
 * C11 判别驱动：配置目录的事件必须按 ev->name 分流——uid.map / sys_pkgs.cache 这类
 * **非规则产物**只做轻量刷新，不得触发整份规则重载（重解析 + 重建 Trie + 作废
 * 2048 槽 uid 缓存 + 推送所有模块）；规则文件仍必须触发全量重载。
 *
 * 做法：直编 src/daemon/fw_config.c（-DFW_CONFIG_SRC，同 test_fw_config_view），
 * 并注册自己的 reload 钩子计数——驱动不链接 loader，钩子归驱动所有，故「钩子被
 * 调用次数」就是「全量重载次数」。随后依次改写三类文件，各等一个去抖窗口后打印
 * 累计次数；最后把规则文件重写为**逐字相同**内容，验证「无变化跳过发布」。
 *
 * 判别性：旧实现对任一事件都调 reload_once → 改写 uid.map 后计数 +1（期望 0），
 * 且规则文件重写为相同内容也会 +1（期望 0）。
 *
 * argv[1] = 规则文件路径（其所在目录即被 watch 的配置目录）
 * argv[2] = 配置目录（写 uid.map / sys_pkgs.cache 用；与编译期 CONFIG_DIR 一致）
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "config_parser.h"
#include "fw_config.h"

static _Atomic int g_reloads;
static int reloads_now(void) {
    return atomic_load_explicit(&g_reloads, memory_order_relaxed);
}
static void count_hook(void) {
    atomic_fetch_add_explicit(&g_reloads, 1, memory_order_relaxed);
}

static void write_file(const char* dir, const char* name, const char* content) {
    char p[1024];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    FILE* f = fopen(p, "w");
    if (!f) {
        fprintf(stderr, "写 %s 失败\n", p);
        return;
    }
    fputs(content, f);
    fclose(f);
}

/* 去抖 1s + 事件读取与处理：留足余量 */
static void settle(void) {
    usleep(2500 * 1000);
}

/* ---- locks 模式：慢 sys_pkgs.cache 读取不得冻结冷路径读者 ----
 *
 * 生产事实：daemon 重载线程在 config_lock_write() 内调 sys_pkg_refresh()，而它要
 * fopen/fgets CONFIG_DIR/sys_pkgs.cache——真读盘。把该文件换成 FIFO、写端故意晚
 * 300ms 才交数据，就得到一个真实慢盘；另一线程反复 config_lock_read()/unlock 采样
 * 冷路径读者的通行证。旧实现的冷读者被冻住整个 ~300ms，新实现（refresh 移到
 * unlock 之后）只有微秒级等待。
 */
static _Atomic int g_stop;
static _Atomic int g_sys_reads;
static long long g_cold_max_us;

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static void* provider_main(void* arg) {
    const char* fifo = (const char*)arg;
    static const char lines[] = "com.android.systemui\ncom.android.settings\n";
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        int fd = open(fifo, O_WRONLY | O_NONBLOCK);
        if (fd < 0) {
            usleep(1000);
            continue;
        }
        atomic_fetch_add_explicit(&g_sys_reads, 1, memory_order_relaxed);
        usleep(300 * 1000); /* 慢盘：写端 300ms 后才交数据 */
        ssize_t wr = write(fd, lines, sizeof lines - 1);
        (void)wr;
        close(fd);
        usleep(3000); /* 关后停 3ms：让读方拿到 EOF，别把新写端接上去 */
    }
    return NULL;
}

static void* cold_reader_main(void* arg) {
    (void)arg;
    long long mx = 0;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        long long t0 = now_us();
        config_lock_read();
        config_unlock_read();
        long long dt = now_us() - t0;
        if (dt > mx) mx = dt;
        usleep(200);
    }
    g_cold_max_us = mx;
    return NULL;
}

/* 事件循环是「1s 归并 + 去抖」，慢机或并发负载下可能要好几个周期才处理完一批；
   用条件等待代替固定睡眠，避免把「机器慢」记成写锁之外的结论（本文件早先用固定
   settle 时，8 个 CPU 忙等就能让 locks 段整体读数为 0）。 */
static bool wait_sys_reads(int target, int timeout_ms) {
    for (int i = 0; i < timeout_ms / 10; i++) {
        if (atomic_load_explicit(&g_sys_reads, memory_order_relaxed) >= target) return true;
        usleep(10 * 1000);
    }
    return false;
}

static bool wait_reloads(int target, int timeout_ms) {
    for (int i = 0; i < timeout_ms / 10; i++) {
        if (reloads_now() >= target) return true;
        usleep(10 * 1000);
    }
    return false;
}

static int run_locks(const char* dir) {
    char fifo[1024];
    snprintf(fifo, sizeof fifo, "%s/sys_pkgs.cache", dir);
    unlink(fifo);
    pthread_t prov;
    pthread_t cold;
    if (pthread_create(&prov, NULL, provider_main, fifo) != 0) return 2;
    if (mkfifo(fifo, 0600) != 0) {
        perror("mkfifo");
        atomic_store_explicit(&g_stop, 1, memory_order_relaxed);
        pthread_join(prov, NULL);
        return 2;
    }
    if (pthread_create(&cold, NULL, cold_reader_main, NULL) != 0) return 2;
    /* 用**规则文件**改写驱动全量重载（不依赖 mkfifo 的目录事件是否被并批）：慢盘读取
       必然发生在这个重载里。每次重试写入不同内容——reload_once 对「重解析结果逐字
       相同」会整条跳过（不发布、不调钩子、不刷 sys 表），那样就没有慢读窗口可测。
       重试是必要的：配置线程建立 inotify watch 之前写入的事件会永久丢失（慢机/并发
       负载下线程启动可以晚到几秒），固定重试窗口会把这种启动竞态误判成产品问题。 */
    int reloads_base = reloads_now();
    bool hit = false;
    int attempts = 0;
    long long t_hit = now_us();
    for (; attempts < 10 && !hit; attempts++) {
        char content[256];
        snprintf(content, sizeof content, "[GLOBAL]\nMONITOR ON\nHIDE /sdcard/x%d\n",
                 attempts);
        int before = reloads_now();
        int sys_before = atomic_load_explicit(&g_sys_reads, memory_order_relaxed);
        write_file(dir, "injector.conf", content);
        hit = wait_reloads(before + 1, 6000) && wait_sys_reads(sys_before + 1, 6000);
    }
    int waited_ms = (int)((now_us() - t_hit) / 1000);
    atomic_store_explicit(&g_stop, 1, memory_order_relaxed);
    pthread_join(cold, NULL);
    pthread_join(prov, NULL);
    printf("locks sys_reads=%d cold_max_us=%lld reloads=%d hit=%d attempts=%d waited_ms=%d\n",
           atomic_load_explicit(&g_sys_reads, memory_order_relaxed), g_cold_max_us,
           reloads_now() - reloads_base, hit ? 1 : 0, attempts, waited_ms);
    fflush(stdout);
    unlink(fifo);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <rules.conf> <config_dir>\n", argv[0]);
        return 2;
    }
    const char* rules = argv[1];
    const char* dir = argv[2];
    if (fw_config_init(rules) != 0) {
        fprintf(stderr, "fw_config_init failed\n");
        return 2;
    }
    fw_config_set_reload_hook(count_hook);
    if (argc >= 4 && strcmp(argv[3], "locks") == 0) {
        int rc = run_locks(dir);
        fw_config_shutdown();
        return rc;
    }
    settle(); /* 让 init 期间的异步事件落定；钩子此后才开始计数 */
    int base = reloads_now();

    /* 1) uid.map 变更（injector 每启动一个应用都会写）→ 不得触发全量重载 */
    write_file(dir, "uid.map", "10123 com.demo.app\n");
    settle();
    int after_uidmap = reloads_now();

    /* 2) 规则文件变更 → 必须触发全量重载（正对照，防止"钩子根本没被调用"的伪通过） */
    write_file(dir, "injector.conf", "[GLOBAL]\nMONITOR ON\nHIDE /sdcard/x\n");
    settle();
    int after_rules = reloads_now();

    /* 3) sys_pkgs.cache 变更 → 不得触发全量重载 */
    write_file(dir, "sys_pkgs.cache", "com.android.systemui\n");
    settle();
    int after_syspkg = reloads_now();

    /* 4) 规则文件重写为**逐字相同**内容 → 不得再触发全量重载（C11：重解析后与
       旧视图比对无变化则跳过发布）。旧实现无条件发布，本组必失败。 */
    write_file(dir, "injector.conf", "[GLOBAL]\nMONITOR ON\nHIDE /sdcard/x\n");
    settle();
    int after_same = reloads_now();

    printf("base=%d after_uidmap=%d after_rules=%d after_syspkg=%d after_same=%d\n", base,
           after_uidmap, after_rules, after_syspkg, after_same);
    fflush(stdout);
    fw_config_shutdown();
    return 0;
}
