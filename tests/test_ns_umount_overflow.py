#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ns_utils mountinfo 扫描栈越界判别测试（历史审计项 A9）

做法：直编 tests/fixtures/ns_umount_overflow_driver.c —— 它把实际源码
src/injector/ns_utils.c 整体 #include（-DNS_UTILS_SRC=），只把 fopen
（/proc/self/mountinfo → 合成内容）与 umount2（记录请求）经 -Wl,--wrap
换成可控实现；do_umount_recursive / do_umount_and_rmdir 全走真实代码。
不依赖命名空间、特权与真实挂载。

判别性：旧实现 `char mounts[N][256]` 却按 PATH_MAX-1 拷贝，末槽遇到 >256
字节挂载点时越界写栈。驱动喂入恰好填满容量的匹配条目、末条超长：
  - 编译带 -fsanitize=address，旧实现必报 stack-buffer-overflow；
  - 且断言「长度 ≥256 的 umount2 请求为 0」「超长条目被 loud 跳过」。
复现旧实现：NS_UTILS_SRC=<旧源码副本> python3 tests/test_ns_umount_overflow.py

退出码约定（与 tests/run.py 一致）：0=通过 1=失败 77=整套跳过(gap)
"""

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests" / "fixtures" / "ns_umount_overflow_driver.c"
NS_UTILS_SRC = os.environ.get("NS_UTILS_SRC") or str(ROOT / "src" / "injector" / "ns_utils.c")

SKIP_RC = 77


def main():
    if not DRIVER.is_file():
        print(f"缺少驱动 {DRIVER}", file=sys.stderr)
        return 1
    if not Path(NS_UTILS_SRC).is_file():
        print(f"缺少 ns_utils 源码 {NS_UTILS_SRC}", file=sys.stderr)
        return SKIP_RC

    cc = shlex.split(os.environ.get("CC", "cc"))
    # ASan 是本用例判别力的关键：旧实现的越界写由 sanitizer 捕获
    tmpdir = tempfile.mkdtemp(prefix="ns_umount_ovf_")
    exe = os.path.join(tmpdir, "driver")
    try:
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
            "-fsanitize=address", "-fno-omit-frame-pointer",
            f'-DNS_UTILS_SRC="{NS_UTILS_SRC}"',
            "-I", str(ROOT / "include"),
            "-I", str(ROOT / "src" / "core"),
            "-I", str(ROOT / "src" / "injector"),
            "-ffunction-sections", "-fdata-sections",
            str(DRIVER),
            "-Wl,--gc-sections",
            "-Wl,--wrap=fopen", "-Wl,--wrap=umount2",
            "-o", exe,
        ]
        build = subprocess.run(cmd, capture_output=True, text=True)
        if build.returncode != 0:
            print("编译失败:", file=sys.stderr)
            print(build.stdout, file=sys.stderr)
            print(build.stderr, file=sys.stderr)
            return 1

        run = subprocess.run([exe], capture_output=True, text=True,
                             env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"})
        out = (run.stdout or "") + (run.stderr or "")
        print(out.rstrip())
        # ASan 报告 / 非 0 退出都算失败
        if "AddressSanitizer" in out or "stack-buffer-overflow" in out:
            print("FAIL: sanitizer 报告栈越界", file=sys.stderr)
            return 1
        if run.returncode != 0:
            print(f"FAIL: 驱动退出码 {run.returncode}", file=sys.stderr)
            return 1
        if "[FAIL]" in out:
            return 1
        print("ns_utils mountinfo 扫描栈越界测试通过 ✔")
        return 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
