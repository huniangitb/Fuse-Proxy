#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""配置目录 watch 对账（src/daemon/cfg_watch.c）单测

背景：inotify 不递归，应用规则写在 `<CONFIG_DIR>/App-rules[-<uid>]/<pkg>.conf`。
旧实现只监听主规则文件所在目录，App-rules 子目录内的编辑收不到事件——运行中改
应用级规则不生效（要等别的事件偶然触发重读）。GLOBAL/类别规则写主文件所以能即时
生效，这个不对称正是漏点。本套件直编 cfg_watch（对账逻辑的唯一实现）验证其契约：

1. 只对 App-rules* 子目录挂 watch（普通子目录不挂）；
2. watch 确实生效：子目录内 tmp+rename 原子落盘能产生可读事件；
3. 目录消失后对账摘表，不留死项；
4. 基目录不可读返回 false（调用方据此定时重扫兜底）。

前置：本机 cc。失败退出码 1（勿用管道吞掉退出码）。
"""

import os
import shlex
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(ROOT, "tests", "fixtures", "cfg_watch_test.c")
SOURCES = [
    os.path.join(ROOT, "src", "daemon", "cfg_watch.c"),
    os.path.join(ROOT, "src", "core", "nsp_util.c"),
]
RUN_TIMEOUT = 60


def main():
    for path in [DRIVER] + SOURCES:
        if not os.path.exists(path):
            print(f"缺少源文件 {path}", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory(prefix="cfgwatch_build_") as tmpdir:
        exe = os.path.join(tmpdir, "cfg_watch_test")
        cmd = [
            *shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Wno-unused-parameter",
            "-I", os.path.join(ROOT, "src", "daemon"), "-I", os.path.join(ROOT, "include"),
            DRIVER, *SOURCES, "-o", exe, "-pthread",
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
            print(f"cfg_watch 测试超时（>{RUN_TIMEOUT}s）", file=sys.stderr)
            return 1
    print(run.stdout, end="")
    if run.returncode != 0:
        print("配置目录 watch 测试失败", file=sys.stderr)
        return 1
    print("配置目录 watch 测试通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
