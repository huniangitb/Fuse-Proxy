#!/usr/bin/env python3
"""FTP 生命周期隔离：完整后端 + 真实 mux/libcurl，无网络或挂载。

有限 gate 只注入 callback/new/cleanup 延迟及失败，不替换业务或队列。
严格断言要求不相关 match 在 gate 释放前完成。FTP_BACKEND_SRC 可指向完整旧
源码；旧红须是断言失败，不能是构建失败或 watchdog。每轮所有 gate 正常释放、
所有线程 join，并核对 fd/thread 基线。退出码 0=通过，1=失败。
"""
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests/fixtures/ftp_lifecycle_isolation_test.c"
BACKEND_SRC = Path(os.environ.get("FTP_BACKEND_SRC") or
                   ROOT / "src/modules/ftp/ftp_backend_libcurl.c").resolve()


def main():
    with tempfile.TemporaryDirectory(prefix="ftp_lifecycle_") as tmp:
        exe = Path(tmp) / "probe"
        payload = Path(tmp) / "payload"
        payload.write_bytes(b"local fixture only\n")
        cmd = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE", "-DNSP_MODULE_BUILD",
            f'-DFTP_BACKEND_SRC="{BACKEND_SRC}"',
            "-I", str(ROOT / "include"), "-I", str(ROOT / "src/modules/ftp"),
            str(DRIVER), str(ROOT / "src/modules/ftp/ftp_mux.c"),
            str(ROOT / "src/core/nsp_util.c"), "-pthread", "-lcurl", "-lm",
            "-Wl,--wrap=pthread_mutex_lock,--wrap=pthread_mutex_unlock",
            "-Wl,--wrap=pthread_create,--wrap=pthread_join,--wrap=curl_multi_init",
            "-Wl,--wrap=curl_easy_cleanup,--wrap=calloc,--wrap=realloc", "-o", str(exe),
        ]
        build = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(f"BUILD_EXIT={build.returncode}")
        if build.returncode:
            sys.stderr.write(build.stderr)
            return 1
        fail = False
        for round_id in range(1, 4):
            print(f"ROUND={round_id}")
            try:
                run = subprocess.run([str(exe), str(payload)], capture_output=True,
                                     text=True, timeout=30)
            except subprocess.TimeoutExpired as error:
                print(f"WATCHDOG: {error}", file=sys.stderr)
                return 1
            sys.stdout.write(run.stdout)
            sys.stderr.write(run.stderr)
            print(f"RUN_EXIT={run.returncode}")
            fail |= run.returncode != 0
        return int(fail)


if __name__ == "__main__":
    sys.exit(main())
