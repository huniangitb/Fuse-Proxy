/*
 * tests/fixtures/reaped_managed_test.c
 *
 * reaped_managed 的确定性回归：通用收尸（waitpid(-1)）抢先取走受管子进程的僵尸
 * 后，恢复路径仍必须能拿到退出状态（否则崩溃现场不再进日志环，见
 * src/injector/reaped_managed.h）。
 *
 * 真子进程 fork：
 *   A. 子进程退出 → 测试自身 waitpid 收尸（模拟通用收尸）→ put 留档 →
 *      exited 必须为真且状态正确（旧实现此处 waitpid 返回 ECHILD → 假）。
 *   B. 未留档时走 waitpid 兜底：子进程退出未收尸 → exited 为真、状态正确。
 *   C. 消费语义：命中一次后槽位清零，再次调用不再为真。
 *   D. 存活子进程 / 不存在的 pid / pid<=0 → 恒假。
 *
 * 退出码：0 全过，1 有失败。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "reaped_managed.h"

static int g_fail;

static void check(const char* name, bool ok, const char* detail) {
    printf("  %s %s", ok ? "[PASS]" : "[FAIL]", name);
    if (!ok && detail && *detail) printf(" — %s", detail);
    printf("\n");
    if (!ok) g_fail = 1;
}

/* fork 一个立即以 code 退出的子进程并返回 pid（不阻塞） */
static pid_t spawn_exiting(int code) {
    pid_t c = fork();
    if (c == 0) _exit(code);
    return c;
}

/* fork 一个长期存活的子进程（测试结束时由父进程 kill 回收） */
static pid_t spawn_alive(void) {
    pid_t c = fork();
    if (c == 0) {
        for (;;) pause();
    }
    return c;
}

/* 等 pid 变成僵尸（已退出但尚未被收尸）；超时返回 false */
static bool wait_zombie(pid_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    for (int i = 0; i < 300; i++) {
        FILE* f = fopen(path, "r");
        if (!f) return false;
        char buf[512];
        bool zombie = false;
        if (fgets(buf, sizeof buf, f)) {
            char* rp = strrchr(buf, ')');
            if (rp && rp[1] == ' ' && rp[2] == 'Z') zombie = true;
        }
        fclose(f);
        if (zombie) return true;
        usleep(10000);
    }
    return false;
}

int main(void) {
    printf("── reaped_managed 收尸留档/复核 ──\n");

    /* A. 通用收尸先到：留档后仍能取回状态 */
    pid_t c = spawn_exiting(7);
    int st = 0;
    if (waitpid(c, &st, 0) != c) {
        check("A0 测试自身收尸成功（构造前提）", false, "waitpid 失败");
    } else {
        /* 模拟 injector 的通用收尸：僵尸已被取走 */
        reaped_managed_put(c, st);
        int out = -1;
        bool got = reaped_managed_exited(c, &out);
        check("A1 僵尸已被通用收尸后仍判定为已退出", got, got ? "" : "留档未被取回（旧实现 ECHILD）");
        check("A2 取回的状态与原始一致", got && out == st, "状态不一致");
        check("A3 状态可解出退出码 7", got && WIFEXITED(out) && WEXITSTATUS(out) == 7,
              "退出码不符");
        /* C. 消费语义：再查一次不再命中（槽位已清，waitpid 亦 ECHILD） */
        bool again = reaped_managed_exited(c, nullptr);
        check("C1 命中即消费，二次复核不再为真", !again, again ? "槽位未清零" : "");
    }

    /* B. 收尸未到：waitpid 兜底（子进程已退出但仍是僵尸，未收尸） */
    pid_t d = spawn_exiting(9);
    bool is_zombie = wait_zombie(d);
    check("B0 子进程已退出且未被收尸（构造前提）", is_zombie, is_zombie ? "" : "未能观察到僵尸态");
    int out2 = -1;
    bool got2 = reaped_managed_exited(d, &out2);
    check("B1 未留档时经 waitpid 兜底判定已退出", got2, got2 ? "" : "兜底失败");
    check("B2 兜底状态解出退出码 9", got2 && WIFEXITED(out2) && WEXITSTATUS(out2) == 9,
          "退出码不符");

    /* D. 负例 */
    pid_t live = spawn_alive();
    bool live_got = reaped_managed_exited(live, nullptr);
    check("D1 存活子进程判定为未退出", !live_got, live_got ? "误判为已退出" : "");
    bool missing = reaped_managed_exited(999999, nullptr);
    check("D2 不存在的 pid 判定为未退出", !missing, missing ? "误判为已退出" : "");
    bool neg = reaped_managed_exited(-1, nullptr);
    check("D3 pid<=0 恒假", !neg, neg ? "误判为已退出" : "");
    reaped_managed_put(0, 0); /* 幂等：不得越界/污染 */
    check("D4 put(pid=0) 为无害空操作", !reaped_managed_exited(0, nullptr), "");

    kill(live, SIGKILL);
    waitpid(live, nullptr, 0);

    printf("%s\n", g_fail ? "结果: 存在失败" : "结果: 全部通过");
    return g_fail;
}
