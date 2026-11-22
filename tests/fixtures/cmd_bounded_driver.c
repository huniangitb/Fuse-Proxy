/* L0 夹具：有界外部命令（common_run_cmd_lines）与两个 pm 调用点的时间上界。
 *
 * 为什么真：直接链接生产的 src/core/common.c、src/config/config_parser.c、
 * src/core/sys_pkg.c，不替身。pm 由 PATH 上的假 `pm` 脚本提供（真机上是 binder
 * 到 system_server 的 `/system/bin/pm`），脚本按 FAKE_PM_MODE 立刻输出或 sleep。
 *
 * 断言口径：
 *   capture-*  —— 按行回调语义（含末行无换行）与「超预算即返回」；
 *   pm-users   —— scan_active_users() 在慢 pm 下必须按预算返回并回退推导；
 *   pm-packages—— sys_pkg_init(true) 在慢 pm 下必须按预算返回（旧实现在这里
 *                 无限 fgets/pclose：注入器事件循环、daemon 热重载线程一起冻住）。
 */
#include "common.h"
#include "config_parser.h"
#include "sys_pkg.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void cache_path(char* out, size_t sz) { snprintf(out, sz, "%s/sys_pkgs.cache", CONFIG_DIR); }

/* 内容校验和（判「失败路径有没有覆盖好 cache」用，不用比 mtime） */
static unsigned long file_sum(const char* path) {
    FILE* fp = fopen(path, "r");
    if (!fp) return 0;
    unsigned long sum = 0;
    int c;
    while ((c = fgetc(fp)) != EOF) sum += (unsigned long)(unsigned char)c;
    fclose(fp);
    return sum;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

typedef struct {
    int lines;
    char joined[256];
} CapCtx;

static void cap_line(const char* line, void* ctx) {
    CapCtx* c = ctx;
    if (c->lines > 0) strncat(c->joined, "|", sizeof c->joined - strlen(c->joined) - 1);
    strncat(c->joined, line, sizeof c->joined - strlen(c->joined) - 1);
    c->lines++;
}

static int run_capture(const char* mode, const char* cmd, int budget_ms) {
    CapCtx c = {.lines = 0, .joined = {0}};
    bool timed = false;
    uint64_t t0 = now_ms();
    int rc = common_run_cmd_lines(cmd, budget_ms, cap_line, &c, &timed);
    printf("mode=%s rc=%d lines=%d timed=%d elapsed_ms=%llu joined=%s\n", mode, rc, c.lines,
           (int)timed, (unsigned long long)(now_ms() - t0), c.joined);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <capture-ok|capture-tail|capture-slow|pm-users|pm-packages>\n",
                argv[0]);
        return 2;
    }
    const char* mode = argv[1];
    if (strcmp(mode, "capture-ok") == 0) return run_capture(mode, "printf 'a\\nb\\nc\\n'", 1000);
    if (strcmp(mode, "capture-tail") == 0) return run_capture(mode, "printf 'x\\ny'", 1000);
    if (strcmp(mode, "capture-slow") == 0) return run_capture(mode, "sleep 8", 200);
    if (strcmp(mode, "pm-users") == 0) {
        uint64_t t0 = now_ms();
        scan_active_users();
        uint64_t elapsed = now_ms() - t0;
        printf("mode=pm-users elapsed_ms=%llu users=%d first=%d\n", (unsigned long long)elapsed,
               g_active_user_count, g_active_user_count > 0 ? g_active_users[0] : -1);
        return 0;
    }
    if (strcmp(mode, "pm-packages") == 0) {
        /* elapsed 覆盖「冷启动建表 + 紧跟的两次查询」：旧实现超时后留下未加载状态，
           这两次查询（生产里在 config 读锁内）各自再付一遍预算——只给 init 计时会
           把这个放大漏掉。refresh_ms / query_ms 再看冷却是否生效。 */
        uint64_t t0 = now_ms();
        sys_pkg_init(true);
        bool systemui = sys_pkg_is_system("com.android.systemui");
        bool settings = sys_pkg_is_system("com.android.settings");
        uint64_t elapsed = now_ms() - t0;
        uint64_t t1 = now_ms();
        sys_pkg_refresh();
        uint64_t refresh_ms = now_ms() - t1;
        uint64_t t2 = now_ms();
        (void)sys_pkg_is_system("com.android.systemui");
        (void)sys_pkg_is_system("com.android.settings");
        uint64_t query_ms = now_ms() - t2;
        printf("mode=pm-packages elapsed_ms=%llu systemui=%d settings=%d refresh_ms=%llu query_ms=%llu\n",
               (unsigned long long)elapsed, (int)systemui, (int)settings,
               (unsigned long long)refresh_ms, (unsigned long long)query_ms);
        sys_pkg_cleanup();
        return 0;
    }
    if (strcmp(mode, "pm-degrade") == 0) {
        /* P2-1：cache 缺失 + pm 超时 → 不得发布空表把它钉住；查询侧不得再 fork pm；
           cache 一出现就自愈（不需要 refresh / 重启）。 */
        char path[PATH_MAX];
        cache_path(path, sizeof path);
        unlink(path);
        uint64_t t0 = now_ms();
        sys_pkg_init(true);
        uint64_t init_ms = now_ms() - t0;
        bool cold_ui = sys_pkg_is_system("com.android.systemui");
        struct stat st;
        int cache_after_init = (stat(path, &st) == 0 && st.st_size > 0) ? 1 : 0;
        uint64_t t1 = now_ms();
        (void)sys_pkg_is_system("com.android.settings");
        (void)sys_pkg_is_system("com.android.systemui");
        uint64_t lazy_ms = now_ms() - t1;
        FILE* fp = fopen(path, "w");
        if (fp) {
            fprintf(fp, "com.android.systemui\ncom.android.settings\n");
            fclose(fp);
        }
        /* 复查间隔 1s（SYS_PKG_CACHE_RETRY_MS）：等它到点，验证「不需要 refresh /
           重启就自愈」。查询侧只查已发布表，cache 的重读在后台装载线程里做，故按
           有界轮询等它落地（不是同步构建）。 */
        struct timespec ts = {.tv_sec = 1, .tv_nsec = 300 * 1000000L};
        nanosleep(&ts, NULL);
        uint64_t t2 = now_ms();
        /* 查询线程本身不得同步读盘/构建：它只该给出既有未知结果（由后台装载补齐）。 */
        bool healed_first = sys_pkg_is_system("com.android.systemui");
        bool healed = healed_first;
        uint64_t healed_ms = now_ms() - t2;
        for (int i = 0; i < 400 && !healed; i++) {
            if (sys_pkg_is_system("com.android.systemui")) {
                healed = true;
                healed_ms = now_ms() - t2;
                break;
            }
            struct timespec step = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
            nanosleep(&step, NULL);
        }
        printf("mode=pm-degrade init_ms=%llu cache_after_init=%d cold_ui=%d lazy_ms=%llu "
               "healed_first=%d healed=%d healed_ms=%llu\n",
               (unsigned long long)init_ms, cache_after_init, (int)cold_ui,
               (unsigned long long)lazy_ms, (int)healed_first, (int)healed,
               (unsigned long long)healed_ms);
        sys_pkg_cleanup();
        return 0;
    }
    if (strcmp(mode, "pm-fail") == 0) {
        /* P2-2：pm 非零退出（不是超时）不得写空 cache 覆盖好 hint。 */
        char path[PATH_MAX];
        cache_path(path, sizeof path);
        unsigned long sum_before = file_sum(path);
        sys_pkg_init(true);
        bool ui = sys_pkg_is_system("com.android.systemui");
        unsigned long sum_after = file_sum(path);
        struct stat st;
        long size = stat(path, &st) == 0 ? (long)st.st_size : -1;
        printf("mode=pm-fail systemui=%d cache_size=%ld sum_before=%lu sum_after=%lu\n",
               (int)ui, size, sum_before, sum_after);
        sys_pkg_cleanup();
        return 0;
    }
    fprintf(stderr, "unknown mode: %s\n", mode);
    return 2;
}