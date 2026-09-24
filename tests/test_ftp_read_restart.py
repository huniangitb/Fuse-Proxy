#!/usr/bin/env python3
"""FTP 后端「随机跳变 vs 在途下载」竞态回归（读缓冲状态机确定性用例）。

背景（本用例守护的修复，src/modules/ftp/ftp_backend_libcurl.c）：
  下载线程在**锁外**执行 curl_easy_perform；期间 read 可能因随机 pread 跳变
  把滑动缓冲复位到新偏移（置 dl_restart，清 rbuf_eof）。原实现在 perform
  返回后只按 curl 返回码置 rbuf_eof/dl_error，不校验缓冲是否已被跳变作废，
  于是"旧偏移传输已到文件尾（CURLE_OK）"会把陈旧 EOF 套到新偏移上：read
  命中 "cur == rbuf_off && rbuf_len == 0" 后落入 EOF 分支，静默返回 0 字节。

  现场表现（tests/test_ftp.py 的 1MiB 随机 pread）：固定随机序列可复现
  "偏移 31128 大小 38172 实收 0"；旧版产物（本轮改动前）同样复现，故属既有
  缺陷而非规范化回归。

做法：tests/fixtures/ftp_read_restart_driver.c 直接编入实际源码
（-DFTP_BACKEND_SRC=<路径>），只把下载线程用到的 curl_easy_perform /
curl_easy_setopt 换成 mock，ftp_dl_thread / ftp_backend_read / write_cb 全走
真实实现；时序由 mock 与主线程严格协调（先让旧传输在途，再触发 read 跳变，
最后才让旧传输返回），因此不依赖网络、FUSE 与调度运气。

覆盖：
  A. 在途传输以 CURLE_OK（陈旧 EOF）返回 → 结果丢弃，read 取满请求字节，
     重试下载落在新偏移。
  B. 在途传输以真错误（CURLE_COULDNT_CONNECT）返回 → 陈旧 dl_error 同样
     被丢弃，read 不报伪 -EIO。
  C. 对照：无跳变时真实 EOF 仍被采纳（防修复过度丢弃）。

前置：本机 cc、libcurl 开发包（-lcurl）。退出码 0 = 全过，非 0 = 失败。
可用环境变量 FTP_BACKEND_SRC 指向另一份源码副本，用于验证本用例确能捕获
"移除修复" 的旧实现（旧实现下 A/B 必失败）。
"""
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests" / "fixtures" / "ftp_read_restart_driver.c"
BACKEND_SRC = os.environ.get("FTP_BACKEND_SRC") or str(
    ROOT / "src" / "modules" / "ftp" / "ftp_backend_libcurl.c")


def main():
    if not DRIVER.is_file():
        print(f"缺少 fixture 驱动 {DRIVER}", file=sys.stderr)
        return 1
    if not Path(BACKEND_SRC).is_file():
        print(f"缺少 FTP 后端源码 {BACKEND_SRC}", file=sys.stderr)
        return 1

    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="ftp_read_restart_") as tmp:
        exe = Path(tmp) / "ftp_read_restart"
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE", "-DNSP_MODULE_BUILD",
            f'-DFTP_BACKEND_SRC="{BACKEND_SRC}"',
            "-I", str(ROOT / "include"),
            "-I", str(ROOT / "src" / "modules" / "ftp"),
            str(DRIVER),
            "-o", str(exe),
            "-pthread", "-lcurl", "-lm",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("C 编译/链接失败:", file=sys.stderr)
            print(r.stderr, file=sys.stderr)
            return 1
        if r.stderr.strip():
            print(r.stderr, end="", file=sys.stderr)  # 源码告警原样透出

        run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=90)
        print(run.stdout, end="")
        if run.stderr.strip():
            print(run.stderr, end="", file=sys.stderr)
        if run.returncode != 0:
            print("FTP 读缓冲竞态回归失败", file=sys.stderr)
            return 1
        print("FTP 读缓冲竞态回归通过 ✔")
        return 0


if __name__ == "__main__":
    sys.exit(main())
