#!/usr/bin/env python3
"""FTP「上传锁泄漏」判别性回归（确定性用例）。

背景（本用例守护的修复，src/modules/ftp/ftp_backend_libcurl.c 的
ftp_backend_upload）：乱序改写已流式上传的前缀会置 retransmit，close() 触发
FLUSH → ftp_write_sync 走 ftp_backend_upload 全量 STOR 覆盖。旧实现在主路径
（全量 STOR 成功/失败）直接 `return rc` 而未解锁 f_lock → 锁随句柄泄漏，存活
fd 的下一次 write 与最终 release 永久阻塞（应用侧表现：写完 close，再写卡死）。

为什么不用端到端 FUSE 用例：需要 vsftpd + 真实乱序时序，且挂起型缺陷在端到端
下只能靠超时判定（慢、易假阳）。本用例直接编入实际源码
（tests/fixtures/ftp_upload_lock_driver.c，-DFTP_BACKEND_SRC），只桩化控制面
mux 与 libcurl easy，用一个极简「桩 FTP 服务器」承接 STOR/APPE——全量重传与
流式上传都走真实代码路径，而断言是确定性的（trylock + 看门狗）。

覆盖：A1 锁未泄漏 / A2 全量重传内容正确 / B1-B3 FLUSH 后续写与 release 不挂起。

退出码：全部通过 0，任一失败 1。环境变量 FTP_BACKEND_SRC 可指向另一份源码
副本（用于验证本用例确能捕获"主路径漏解锁"的旧实现——旧实现上 A1 必失败）。
"""
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests" / "fixtures" / "ftp_upload_lock_driver.c"
BACKEND_SRC = os.environ.get("FTP_BACKEND_SRC") or str(
    ROOT / "src" / "modules" / "ftp" / "ftp_backend_libcurl.c")


def main():
    if not DRIVER.is_file() or not Path(BACKEND_SRC).is_file():
        print(f"缺少 fixture 驱动或后端源码（{DRIVER} / {BACKEND_SRC}）", file=sys.stderr)
        return 1

    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="ftp_upload_lock_") as tmp:
        exe = Path(tmp) / "ftp_upload_lock"
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE", "-DNSP_MODULE_BUILD",
            f'-DFTP_BACKEND_SRC="{BACKEND_SRC}"',
            "-I", str(ROOT / "include"),
            "-I", str(ROOT / "src" / "modules" / "ftp"),
            str(DRIVER),
            # 后端源码经 FTP_BACKEND_SRC 编入驱动；mux 已桩化故不链接 ftp_mux.c；
            # nsp_util.c 提供后端引用的真实通用原语（nsp_snprintf_dyn 等，纯 libc）
            str(ROOT / "src" / "core" / "nsp_util.c"),
            "-o", str(exe),
            "-pthread", "-lcurl", "-lm",
        ]
        build = subprocess.run(cmd, capture_output=True, text=True)
        if build.returncode != 0:
            print("C 编译/链接失败：", file=sys.stderr)
            print(build.stderr, file=sys.stderr)
            return 1
        # 看门狗 8s + 前置等待 10s，留足余量（正常路径 <1s）
        run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=90)
        sys.stdout.write(run.stdout)
        if run.stderr.strip():
            sys.stderr.write(run.stderr)
        return run.returncode


if __name__ == "__main__":
    sys.exit(main())
