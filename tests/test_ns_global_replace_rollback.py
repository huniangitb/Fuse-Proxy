#!/usr/bin/env python3
"""全局替换（do_global_replace）失败回滚的失败注入回归（确定性用例）。

背景（本用例守护的修复，src/injector/ns_global_replace.c）：
  替换步骤先卸族根全部挂载再 bind 项目 FUSE；旧实现任一步失败直接 return -1，
  族根停在**裸挂载点**（/mnt/{user,androidwritable,installer}/… 下系统存储视图
  整体消失），而备份树就在手边却不 bind 回去。修复后失败即把本次已动过的族根
  逐一根从备份树还原（与 do_global_restore 共用 restore_root_from_backup）。

做法：tests/fixtures/ns_global_replace_rollback_driver.c 把实际源码
src/injector/ns_global_replace.c 整体 #include（-DNS_GLOBAL_REPLACE_SRC=），
--wrap=fopen 喂合成 mountinfo（fmemopen）、--wrap=mount 让指定 (source,target)
的那次 bind 失败。do_global_replace 全走真实实现，故不依赖命名空间、FUSE、
特权与调度运气。

退出码：全部通过 0，任一失败 1。环境变量 NS_GLOBAL_REPLACE_SRC 可指向另一份
源码副本（用于验证本用例确能捕获「失败不回滚」的旧实现）。
"""
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests" / "fixtures" / "ns_global_replace_rollback_driver.c"
SRC = os.environ.get("NS_GLOBAL_REPLACE_SRC") or str(
    ROOT / "src" / "injector" / "ns_global_replace.c"
)


def main():
    if not DRIVER.is_file():
        print(f"缺少 fixture 驱动 {DRIVER}", file=sys.stderr)
        return 1
    if not Path(SRC).is_file():
        print(f"缺少 ns_global_replace 源码 {SRC}", file=sys.stderr)
        return 1

    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="ns_grepl_rollback_") as tmp:
        exe = Path(tmp) / "ns_global_replace_rollback"
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
            f'-DNS_GLOBAL_REPLACE_SRC="{SRC}"',
            "-I", str(ROOT / "include"),
            "-I", str(ROOT / "src" / "core"),
            "-I", str(ROOT / "src" / "injector"),
            "-ffunction-sections", "-fdata-sections",
            str(DRIVER),
            "-Wl,--gc-sections",
            "-Wl,--wrap=fopen", "-Wl,--wrap=mount", "-Wl,--wrap=umount2",
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
