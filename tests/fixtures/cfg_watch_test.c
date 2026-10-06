/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
/* cfg_watch 单测驱动：直编实际实现（tests/test_cfg_watch.py 编译运行）。
 *
 * 覆盖（对应 src/daemon/cfg_watch.h 契约）：
 *   1) 只对基目录下的 App-rules* 子目录挂 watch（其余目录不挂）；
 *   2) watch 确实生效——子目录内 tmp+rename 落盘能产生可读事件（这正是
 *      「应用级规则运行中改不动」的缺失环节：没有 watch 就收不到任何事件）；
 *   3) 目录消失后对账会摘表（不留死项）；
 *   4) 基目录不可读时返回 false（调用方据此走定时重扫兜底）。 */
#include "cfg_watch.h"

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_fail;

static void check(const char* name, bool ok, const char* detail) {
    if (ok) {
        printf("PASS %s\n", name);
    } else {
        printf("FAIL %s: %s\n", name, detail);
        g_fail = 1;
    }
}

static void mkdir_p(const char* path) { (void)mkdir(path, 0755); }

static void write_file(const char* path, const char* content) {
    FILE* f = fopen(path, "w");
    if (f) {
        fputs(content, f);
        fclose(f);
    }
}

int main(void) {
    char base[] = "/tmp/cfgwatch_XXXXXX";
    if (!mkdtemp(base)) {
        printf("FAIL mkdtemp: %s\n", strerror(errno));
        return 1;
    }
    char p[1024];
    snprintf(p, sizeof p, "%s/App-rules", base);
    mkdir_p(p);
    snprintf(p, sizeof p, "%s/App-rules-10", base);
    mkdir_p(p);
    snprintf(p, sizeof p, "%s/other", base);
    mkdir_p(p);
    snprintf(p, sizeof p, "%s/App-rules-10/seed.conf", base);
    write_file(p, "HIDE /x\n");

    int ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    check("inotify_init", ifd >= 0, "inotify_init1 失败");
    CfgDirWatch ws[CFG_WATCH_MAX];
    int n = 0;
    bool ok = cfg_watch_sync(ifd, base, ws, &n);
    check("sync_all_watched", ok && n == 2, "应恰好挂上 App-rules 与 App-rules-10 两个目录");
    {
        bool all = (n == 2);
        for (int i = 0; i < n; i++)
            if (ws[i].wd < 0) all = false;
        check("sync_wd_valid", all, "有目录未获得有效 watch 描述符");
        bool saw_other = false, saw_uid = false;
        for (int i = 0; i < n; i++) {
            if (strstr(ws[i].dir, "/App-rules-10") != NULL) saw_uid = true;
            if (strstr(ws[i].dir, "/other") != NULL) saw_other = true;
        }
        check("sync_scope", saw_uid && !saw_other,
              "watch 范围错误（应只含 App-rules* 子目录，普通子目录不得挂）");
    }

    /* 2) watch 生效：tmp+rename 落盘（与 rule_server/nsp_rule_file 同款原子写）
       必须能从 inotify fd 读到事件 */
    char tmpf[1200], dstf[1200];
    snprintf(tmpf, sizeof tmpf, "%s/App-rules-10/foo.conf.tmp", base);
    snprintf(dstf, sizeof dstf, "%s/App-rules-10/foo.conf", base);
    write_file(tmpf, "HIDE /y\n");
    rename(tmpf, dstf);
    struct pollfd pf = {.fd = ifd, .events = POLLIN};
    bool got_ev = false;
    if (poll(&pf, 1, 2000) > 0) {
        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t len = read(ifd, buf, sizeof buf);
        for (ssize_t off = 0; off < len;) {
            struct inotify_event* ev = (struct inotify_event*)(buf + off);
            for (int i = 0; i < n; i++)
                if (ev->wd == ws[i].wd) got_ev = true;
            off += (ssize_t)(sizeof(struct inotify_event) + ev->len);
        }
    }
    check("watch_delivers_event", got_ev, "App-rules 子目录内原子替换未产生可读事件");

    /* 3) 目录消失：对账摘表（先清空目录再删，否则 rmdir ENOTEMPTY） */
    snprintf(p, sizeof p, "%s/App-rules-10/foo.conf", base);
    unlink(p);
    snprintf(p, sizeof p, "%s/App-rules-10/seed.conf", base);
    unlink(p);
    snprintf(p, sizeof p, "%s/App-rules-10", base);
    rmdir(p);
    ok = cfg_watch_sync(ifd, base, ws, &n);
    if (!(ok && n == 1 && strstr(ws[0].dir, "/App-rules") != NULL &&
          strstr(ws[0].dir, "-10") == NULL)) {
        fprintf(stderr, "DEBUG prune: ok=%d n=%d", (int)ok, n);
        for (int i = 0; i < n; i++) fprintf(stderr, " dir[%d]=%s wd=%d", i, ws[i].dir, ws[i].wd);
        fprintf(stderr, "\n");
    }
    check("sync_prunes_removed", ok && n == 1 && strstr(ws[0].dir, "/App-rules") != NULL &&
                                     strstr(ws[0].dir, "-10") == NULL,
          "已删目录未被摘表");

    /* 4) 基目录不可读 → false（调用方兜底） */
    ok = cfg_watch_sync(ifd, "/nonexistent-cfg-dir-xyz", ws, &n);
    check("sync_missing_base_false", !ok, "基目录缺失应返回 false 以触发兜底重扫");

    close(ifd);
    snprintf(p, sizeof p, "%s/App-rules", base);
    rmdir(p);
    snprintf(p, sizeof p, "%s/App-rules", base);
    rmdir(p);
    snprintf(p, sizeof p, "%s/other", base);
    rmdir(p);
    rmdir(base);
    printf(g_fail ? "RESULT FAIL\n" : "RESULT OK\n");
    return g_fail;
}
