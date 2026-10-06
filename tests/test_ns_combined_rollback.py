#!/usr/bin/env python3
"""`do_combined_mount` 合并挂载失败回滚的失败注入回归（确定性用例）。

背景（本用例守护的修复，src/injector/ns_utils.c 的 do_combined_mount 回滚分支）：
  合并挂载在真正 bind 项目 FUSE 之前，会先卸载 target/backup 下的子挂载以及
  target 本身。若随后的 `mount(source, target, MS_BIND|MS_REC)` 失败（应用
  命名空间内源不可见/只读等），旧实现直接 `return err` —— 应用被留在"裸"状态
  （连 /storage/emulated 都没有，直到进程重启或重试成功）。修复后以应用 ns 内
  始终存活的**族根**重新 bind 出原生视图（与 cleanup_app_mounts 同源），失败
  才 loud 报错交由重试队列。

做法：tests/fixtures/ns_combined_rollback_driver.c 把实际源码
src/injector/ns_utils.c 整体 #include（-DNS_UTILS_SRC=），只把 mount/umount2
经 -Wl,--wrap 换成可控返回值；do_combined_mount 全走真实实现。因此不依赖
命名空间、FUSE、特权与调度运气。

覆盖：
  A. 源 bind 失败 + 族根可用 → 第二次 mount 以族根为源回滚、日志「已回滚」、
     返回原始 errno。
  B. 源 bind 失败 + 族根不可用 → 不回滚、loud 报错、返回原始 errno。
  C. 对照：源 bind 成功 → 不触发回滚。

退出码：全部通过 0，任一失败 1。环境变量 NS_UTILS_SRC 可指向另一份源码副本
（用于验证本用例确能捕获"移除回滚"的旧实现）。
"""
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests" / "fixtures" / "ns_combined_rollback_driver.c"
NS_UTILS_SRC = os.environ.get("NS_UTILS_SRC") or str(ROOT / "src" / "injector" / "ns_utils.c")


def main():
    if not DRIVER.is_file():
        print(f"缺少 fixture 驱动 {DRIVER}", file=sys.stderr)
        return 1
    if not Path(NS_UTILS_SRC).is_file():
        print(f"缺少 ns_utils 源码 {NS_UTILS_SRC}", file=sys.stderr)
        return 1

    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="ns_combined_rollback_") as tmp:
        exe = Path(tmp) / "ns_combined_rollback"
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
            f'-DNS_UTILS_SRC="{NS_UTILS_SRC}"',
            "-I", str(ROOT / "include"),
            "-I", str(ROOT / "src" / "core"),
            "-I", str(ROOT / "src" / "injector"),
            "-ffunction-sections", "-fdata-sections",
            str(DRIVER),
            "-Wl,--gc-sections",
            "-Wl,--wrap=mount", "-Wl,--wrap=umount2",
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
