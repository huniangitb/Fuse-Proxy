#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A26 杂项判别（ftp_conf `#`/port + nsp_ini_store 落盘持久性）

背景（review-findings-20261007 §A26）：
  ⑤ ftp_conf.c 的 strip_comment 曾用 `strchr(line,'#')` 无条件截断——含 `#` 的
     密码（`pass = p#ssw0rd`）被静默改成首段，服务器 530 拒绝而配置看不出异常；
     `port = 0/-1/65536/abc` 也被 atoi 照收，最终以 `ftp://host:0/` 交给 libcurl。
  ⑨ nsp_ini_store.c 的 nsp_ini_save 曾用固定名 `<path>.tmp`、无文件/目录 fsync，
     两个写者会互相 rename 掉对方未写完的临时文件；掉电时可能「rename 生效、
     内容为空/旧」。

本套件直编 ftp_conf.c（+ nsp_ini_store.c）并断言上述行为。
判别力：把 src/modules/ftp/ftp_conf.c 换回修复前版本（或把 strip_comment 改回
strchr 无条件截断），A 组立即失败（密码变成 "p"）；把 nsp_ini_store.c 换回修复前
版本，C 组的固定名 .tmp 残留断言失败。

前置：本机 cc。失败退出码 1。
"""

import os
import shlex
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(ROOT, "tests", "fixtures", "a26_misc_test.c")
SRC = os.environ.get("A26_FTP_CONF_SRC", os.path.join(ROOT, "src", "modules", "ftp", "ftp_conf.c"))
INI_SRC = os.environ.get("A26_INI_SRC", os.path.join(ROOT, "src", "core", "nsp_ini_store.c"))
UTIL_SRC = os.path.join(ROOT, "src", "core", "nsp_util.c")
RUN_TIMEOUT = 120


def main():
    for path in (DRIVER, SRC, INI_SRC, UTIL_SRC):
        if not os.path.exists(path):
            print(f"缺少源文件 {path}", file=sys.stderr)
            return 1
    include = os.path.join(ROOT, "include")
    with tempfile.TemporaryDirectory(prefix="a26_misc_") as tmpdir:
        exe = os.path.join(tmpdir, "a26_misc_test")
        cmd = [
            *shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
            "-DNSP_MODULE_BUILD",  # ftp_conf.c 经 nsp_module.h 取 LOG_WRN（模块 ABI）
            "-Wall", "-Wextra", "-Wno-unused-parameter",
            "-I", include,
            "-I", os.path.join(ROOT, "src", "modules", "ftp"),
            DRIVER, SRC, INI_SRC, UTIL_SRC, "-o", exe,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("C 编译/链接失败:", file=sys.stderr)
            print(r.stderr, file=sys.stderr)
            return 1
        errlines = [ln for ln in r.stderr.splitlines() if "警告" not in ln and "warning" not in ln
                    and "note" not in ln and "注意" not in ln and "|" not in ln and "^" not in ln]
        if errlines:
            print("\n".join(errlines), file=sys.stderr)
        try:
            run = subprocess.run([exe], capture_output=True, text=True, timeout=RUN_TIMEOUT)
        except subprocess.TimeoutExpired:
            print(f"A26 杂项测试超时（>{RUN_TIMEOUT}s）", file=sys.stderr)
            return 1
    print(run.stdout, end="")
    if run.returncode != 0:
        print("A26 杂项判别测试失败", file=sys.stderr)
        return 1
    print("A26 杂项判别测试通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
