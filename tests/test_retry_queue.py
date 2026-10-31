#!/usr/bin/env python3
"""挂载失败重试记账（src/injector/retry_queue.c）的直编判别回归。

背景（真机回归）：旧实现把"异步派发成功"当成"挂载成功"——retry_pending_mounts
派发后立即摘掉条目，真正的失败由完成回调重新入队（新条目尝试次数归零），退避与
5 次上限因此永远不生效：挂不上的应用以 1Hz 永久重试，每轮写一条 error.log +
WARN + ERROR（真机表现即"错误越来越多"），并持续 fork/读 mountinfo（批量冷启动
时的 IPC 抖动来源）。

做法：tests/fixtures/retry_queue_driver.c 把实际源码整体 #include（-DRETRY_QUEUE_SRC=），
把虚拟时钟交给 nsp_retry_next 逐秒推进，断言退避递增、尝试次数有上限、成功清账、
满队列拒绝。

退出码：全部通过 0，任一失败 1。环境变量 RETRY_QUEUE_SRC 可指向另一份源码副本
（用于验证本用例确能捕获旧语义）。
"""
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests" / "fixtures" / "retry_queue_driver.c"
SRC = os.environ.get("RETRY_QUEUE_SRC") or str(ROOT / "src" / "injector" / "retry_queue.c")


def main():
    if not DRIVER.is_file():
        print(f"缺少 fixture 驱动 {DRIVER}", file=sys.stderr)
        return 1
    if not Path(SRC).is_file():
        print(f"缺少 retry_queue 源码 {SRC}", file=sys.stderr)
        return 1

    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="retry_queue_") as tmp:
        exe = Path(tmp) / "retry_queue_test"
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
            f'-DRETRY_QUEUE_SRC="{SRC}"',
            "-I", str(ROOT / "include"),
            str(DRIVER),
            "-o", str(exe),
        ]
        build = subprocess.run(cmd, capture_output=True, text=True)
        if build.returncode != 0:
            print("编译失败：\n" + build.stderr, file=sys.stderr)
            return 1
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        sys.stdout.write(run.stdout)
        if run.stderr:
            sys.stderr.write(run.stderr)
        return run.returncode


if __name__ == "__main__":
    sys.exit(main())
