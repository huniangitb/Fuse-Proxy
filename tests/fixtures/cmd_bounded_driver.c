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
#include <time.h>

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
    fprintf(stderr, "unknown mode: %s\n", mode);
    return 2;
}