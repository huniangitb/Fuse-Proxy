#!/usr/bin/env python3
"""FTP「truncate 清 LIST 缓存」回归（确定性用例）。

背景（本用例守护的修复，src/modules/ftp/ftp_backend_libcurl.c 的
ftp_backend_truncate）：readdir 拉取 LIST 后会把每个子项的 size 预填进 stat
缓存（列举后 getattr 零网络）。因此 truncate 只清 stat 缓存不够——若不清 LIST
缓存，下一次列举会命中旧 LIST、把**截断前**的 size 重新预填回 stat 缓存，
应用于是永远看到旧大小。修复在 truncate 成功路径加 ftp_list_cache_clear。

为什么不用端到端 FUSE 用例：FUSE 侧另有内核 attr 缓存（attr_timeout）等层
会掩盖这条路径，本机复现不出「旧 size 回灌」。故改为模块级驱动，直接编入实际
源码（tests/fixtures/ftp_truncate_list_cache_driver.c，-DFTP_BACKEND_SRC），
只桩化控制面 mux 与 libcurl easy，服务端 LIST/STOR 状态完全可控。

覆盖：A 列举预取 / B 截断后重拉 LIST 且 size=0 / C 邻居条目未被误伤。

退出码：全部通过 0，任一失败 1。环境变量 FTP_BACKEND_SRC 可指向另一份源码
副本（用于验证本用例确能捕获"不清 LIST"的旧实现）。
"""
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests" / "fixtures" / "ftp_truncate_list_cache_driver.c"
BACKEND_SRC = os.environ.get("FTP_BACKEND_SRC") or str(
    ROOT / "src" / "modules" / "ftp" / "ftp_backend_libcurl.c")


def main():
    if not DRIVER.is_file() or not Path(BACKEND_SRC).is_file():
        print(f"缺少 fixture 驱动或后端源码（{DRIVER} / {BACKEND_SRC}）", file=sys.stderr)
        return 1

    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="ftp_truncate_list_") as tmp:
        exe = Path(tmp) / "ftp_truncate_list"
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE", "-DNSP_MODULE_BUILD",
            f'-DFTP_BACKEND_SRC="{BACKEND_SRC}"',
            "-I", str(ROOT / "include"),
            "-I", str(ROOT / "src" / "modules" / "ftp"),
            str(DRIVER),
            # 后端源码经 FTP_BACKEND_SRC 编入驱动；mux 已桩化故不链接 ftp_mux.c；
            # nsp_util.c 提供后端引用的真实通用原语（nsp_snprintf_dyn，纯 libc）
            str(ROOT / "src" / "core" / "nsp_util.c"),
            "-o", str(exe),
            "-pthread", "-lcurl", "-lm",
        ]
        build = subprocess.run(cmd, capture_output=True, text=True)
        if build.returncode != 0:
            print("C 编译/链接失败：", file=sys.stderr)
            print(build.stderr, file=sys.stderr)
            return 1
        run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
        sys.stdout.write(run.stdout)
        if run.stderr.strip():
            sys.stderr.write(run.stderr)
        return run.returncode


if __name__ == "__main__":
    sys.exit(main())
