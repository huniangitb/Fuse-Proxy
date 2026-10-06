#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""延迟 close 环形队列（src/daemon/fd_close_queue.c）单测

直编实际实现 + tests/fixtures/fd_close_queue_test.c 计数关闭钩子，覆盖三条
并发契约（对应 fd_close_queue.h 头注释）：

1. 每个入队 fd **恰好** close 一次——FUSE worker 默认 2 个且 getattr/access/
   readdir/open 四个入口都会 flush，旧实现按「多生产者单消费者」写，两个 worker
   会读到同一 ready/consumed 而重复 close（第二次可能命中被复用的 fd 号，误关
   其他线程的资源）。
2. 队列满**不阻塞、不制造被放弃的槽位**——旧实现先占号再判满、占号者直接返回，
   会把 ready 水位永久卡住：「饱和 → flush → 再入队」后新生产者要么自旋等待一个
   永不发布的槽位（FUSE worker 挂死），要么永远走直接 close（队列静默失效）。
3. 多生产者/多消费者并发下不重不漏。

该队列本体在 Android 才被 backing 路径使用（defer 调用点在 #ifdef TARGET_ANDROID
内），GNU 侧挂载类用例覆盖不到，故此处不经 Meson 直编实现做单测。

前置：本机 cc、pthread。失败退出码 1（勿用管道吞掉退出码）；驱动内置超时，
死循环会以退出码非 0 结束而不是挂住测试。
"""

import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUEUE_SRC = os.path.join(ROOT, "src", "daemon", "fd_close_queue.c")
QUEUE_INC = os.path.join(ROOT, "src", "daemon")
DRIVER = os.path.join(ROOT, "tests", "fixtures", "fd_close_queue_test.c")

# 并发用例规模：4 生产者 × 2000 + 3 消费者循环 flush，足以在旧实现下暴露
# 重复 close；超时给足（正常 <2s，饱和后自旋在旧实现下必然超时）
RUN_TIMEOUT = 60


def main():
    for path in (QUEUE_SRC, DRIVER):
        if not os.path.exists(path):
            print(f"缺少源文件 {path}", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory(prefix="fdq_test_") as tmpdir:
        exe = os.path.join(tmpdir, "fdq_test")
        cmd = [
            os.environ.get("CC", "cc"), "-std=c23", "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Wno-unused-parameter",
            "-I", QUEUE_INC,
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
    print(run.stdout, end="")
    if run.returncode != 0:
        print("延迟 close 队列测试失败", file=sys.stderr)
        return 1
    print("延迟 close 队列测试通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
