#!/usr/bin/env python3
"""受管子进程收尸留档的回归（reaped_managed，确定性用例）。

背景（本用例守护的修复，src/injector/reaped_managed.c + injector.c 的
reap_zombies / check_and_recover_fuse）：fuse_daemon 退出后，injector 的恢复
路径要靠 waitpid(pid) 的返回确认"确实退出了"并 dump 崩溃 backtrace；而通用收尸
（reap_zombies 的 waitpid(-1)）会抢先把它收走，之后 waitpid(pid) 返回 ECHILD，
崩溃现场不再进日志环（sys.log / log_ctl 查不到）。修复为收尸时留档退出状态，
恢复路径优先取回（语义等价：无论收尸先后都能拿到状态）。

做法：tests/fixtures/reaped_managed_test.c 直接编入实际源码
src/injector/reaped_managed.c，用真实 fork 子进程构造「已被收尸」「仍是僵尸」
「存活」「不存在」四种收尸状态，无命名空间/FUSE/特权依赖。

覆盖：A 收尸先到仍能取回状态与退出码 / B 未留档走 waitpid 兜底 / C 命中即消费 /
D 存活、不存在、pid<=0 的负例。

退出码：全部通过 0，任一失败 1。环境变量 REAPED_MANAGED_SRC 可指向另一份源码
副本（用于验证本用例确能捕获"不留档"的旧实现）。
"""
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests" / "fixtures" / "reaped_managed_test.c"
SOURCE = os.environ.get("REAPED_MANAGED_SRC") or str(ROOT / "src" / "injector" / "reaped_managed.c")


def main():
    if not DRIVER.is_file() or not Path(SOURCE).is_file():
        print(f"缺少 fixture 驱动或源码（{DRIVER} / {SOURCE}）", file=sys.stderr)
        return 1

    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="reaped_managed_") as tmp:
        exe = Path(tmp) / "reaped_managed_test"
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
            "-I", str(ROOT / "src" / "injector"),
            str(DRIVER), SOURCE,
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
