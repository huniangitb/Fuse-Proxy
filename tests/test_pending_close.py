#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""延迟 close 环形队列（src/daemon/fd_close_queue.c）单测

直编实际实现 + tests/fixtures/fd_close_queue_test.c 计数关闭钩子，覆盖三条
并发契约（对应 fd_close_queue.h 头注释）：

1. 每个入队 fd **恰好** close 一次——共享队列支持多消费者；getattr/access/
   readdir/open 四个入口都会 flush，旧实现按「多生产者单消费者」写，两个 worker
   会读到同一 ready/consumed 而重复 close（第二次可能命中被复用的 fd 号，误关
   其他线程的资源）。
2. 队列满**不制造被放弃的槽位**——旧实现先占号再判满、占号者直接返回，
   会把 ready 水位永久卡住：「饱和 → flush → 再入队」后新生产者要么自旋等待一个
   永不发布的槽位（FUSE worker 挂死），要么永远走直接 close（队列静默失效）。
3. 多生产者/多消费者并发下不重不漏。
4. **饱和时不得提前关闭本次 fd**（A22）——旧实现「满则直接 close」正好做了队列要
   防的事：内核可能在 reply 发送完成前仍引用该 fd，且 fd 号可被另一 worker 的 open
   立刻复用 → backing 挂到无关文件。判别：填满 CAP 条后再 defer 一个探针 fd，断言
   它此刻**未被关闭**（旧实现立即关闭 → 必失败）。

5. 单个 close 保持未完成时，其他 flush 与复用满队列的生产者仍须完成。
   领取者先复制私有批次，再释放槽；close 在短锁外，不保证该 close 的返回时间。
6. Android backing 使用每 worker 的线程所有权：别的 worker 不得回收未回复 FD；
   同 worker 下一 legacy 请求/正常退出才回收，main 必须显式清尾。实际默认
   worker 上限为在线 CPU 数夹到 4..16；此处不靠扩容判别。

实际队列 + 从 fuse_daemon.c 提取的关闭包装器/完整 backing 回调直接编译。
FUSE/routing 边界使用替身，线程、目录 open/close 真实；不声称真实内核回复已测。
满队列 defer 可以关闭旧批次并重试，耗时无界，但不持共享队列锁等待 close。
FDQ_SRC/FUSE_DAEMON_SRC 可指定完整旧源码作相同驱动的运行期负控。

前置：本机 cc、pthread。失败退出码 1（勿用管道吞掉退出码）；驱动内置超时，
死循环会以退出码非 0 结束而不是挂住测试。
"""

import os
import re
import shlex
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUEUE_SRC = os.environ.get("FDQ_SRC") or os.path.join(ROOT, "src", "daemon", "fd_close_queue.c")
QUEUE_INC = os.path.join(ROOT, "src", "daemon")
INC = os.path.join(ROOT, "include")
DRIVER = os.path.join(ROOT, "tests", "fixtures", "fd_close_queue_test.c")
OWNER_DRIVER = os.path.join(ROOT, "tests", "fixtures", "fd_reply_owner_test.c")
DAEMON_SRC = os.environ.get("FUSE_DAEMON_SRC") or os.path.join(ROOT, "src", "daemon", "fuse_daemon.c")

# 并发用例规模：4 生产者 × 2000 + 3 消费者循环 flush，足以在旧实现下暴露
# 重复 close；超时给足（正常 <2s，饱和后自旋在旧实现下必然超时）
RUN_TIMEOUT = 60


def owner_checks(tmpdir):
    """Extract actual daemon callbacks; do not duplicate their FD ownership logic."""
    with open(DAEMON_SRC, encoding="utf-8") as stream:
        source = stream.read()
    markers = ("/* Android backing fd", "/* 延迟 close 队列（Android backing 路径）")
    start = next((source.find(mark) for mark in markers if mark in source), -1)
    if start < 0:
        raise ValueError("找不到真实daemon关闭包装器")
    wrappers = source[start:source.index("static int recursive_rmdir", start)]
    match = re.search(r"^static int vfs_backing_setup\([^\n]+\) \{", source, re.M)
    if not match:
        raise ValueError("找不到真实vfs_backing_setup")
    end = source.index("\n}", match.start()) + 2
    setup = source[match.start():end]
    header = r"""
#ifndef FD_REPLY_BRIDGE_H
#define FD_REPLY_BRIDGE_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
struct fuse_entry_param { struct stat attr; unsigned backing_action; uint64_t backing_fd; };
int probe_setup(const char*, struct fuse_entry_param*);
void probe_flush(void);
#endif
"""
    preamble = r"""
#define TARGET_ANDROID 1
#include "fd_reply_bridge.h"
#include "fd_close_queue.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define LOG_DBG(...) ((void)0)
#define LOG_DBG_PERF(...) ((void)0)
#define FUSE_ACTION_REPLACE 1
#define BACKING_DECLINE_GLOBAL_DAC 1
#define BACKING_DECLINE_RULE 0
static bool g_bpf_disabled;
static bool g_is_media_fuse = true;
static void backing_decline_log(int reason, const char* path) { (void)reason; (void)path; }
static bool fw_backing_mediation_required_for(const char* path) { (void)path; return false; }
static void common_default_real_path(int user, const char* path, char* out, size_t size) {
    (void)user;
    int n = snprintf(out, size, "%s", path);
    if (n < 0 || (size_t)n >= size) out[0] = '\0';
}
"""
    bridge = os.path.join(tmpdir, "fd_reply_bridge.c")
    with open(os.path.join(tmpdir, "fd_reply_bridge.h"), "w", encoding="utf-8") as stream:
        stream.write(header)
    with open(bridge, "w", encoding="utf-8") as stream:
        stream.write(preamble + wrappers + setup + r"""
int probe_setup(const char* path, struct fuse_entry_param* e) { return vfs_backing_setup(path, e); }
void probe_flush(void) { vfs_flush_pending_closes(); }
""")
    exe = os.path.join(tmpdir, "fd_reply_owner")
    command = [*shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
               "-Wall", "-Wextra", "-Werror", "-I", tmpdir, "-I", QUEUE_INC, "-I", INC,
               OWNER_DRIVER, QUEUE_SRC, bridge, "-pthread", "-o", exe,
               "-Wl,--wrap=pthread_key_create", "-Wl,--wrap=pthread_setspecific",
               "-Wl,--wrap=calloc", "-Wl,--wrap=open", "-Wl,--wrap=pthread_mutex_init"]
    build = subprocess.run(command, capture_output=True, text=True, timeout=60)
    if build.returncode:
        print(build.stdout + build.stderr, file=sys.stderr)
        return False
    ok = True
    for mode in ("before-reply", "slow-owner", "worker-exit", "main-flush",
                 "key-fail", "set-fail", "alloc-fail", "mutex-fail", "second-defer"):
        run = subprocess.run([exe, mode, tmpdir], capture_output=True, text=True, timeout=12)
        print(run.stdout, end="")
        if run.stderr:
            print(run.stderr, file=sys.stderr, end="")
        ok = run.returncode == 0 and ok
    return ok


def main():
    for path in (QUEUE_SRC, DRIVER):
        if not os.path.exists(path):
            print(f"缺少源文件 {path}", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory(prefix="fdq_test_") as tmpdir:
        exe = os.path.join(tmpdir, "fdq_test")
        cmd = [
            *shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Wno-unused-parameter",
            "-I", QUEUE_INC, "-I", INC,
            DRIVER, QUEUE_SRC,
            "-o", exe, "-pthread",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("C 编译/链接失败:", file=sys.stderr)
            print(r.stderr, file=sys.stderr)
            return 1
        if r.stderr.strip():
            print(r.stderr, file=sys.stderr, end="")
        try:
            run = subprocess.run([exe], capture_output=True, text=True, timeout=RUN_TIMEOUT)
        except subprocess.TimeoutExpired:
            print(f"队列测试超时（>{RUN_TIMEOUT}s）：疑似生产者自旋等待永不发布的槽位",
                  file=sys.stderr)
            return 1
        try:
            owner_ok = owner_checks(tmpdir)
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            print(f"回复FD生命周期测试失败: {error}", file=sys.stderr)
            owner_ok = False
    print(run.stdout, end="")
    if run.returncode != 0 or not owner_ok:
        print("延迟 close 队列测试失败", file=sys.stderr)
        return 1
    print("延迟 close 队列测试通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
