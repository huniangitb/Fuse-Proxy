#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""构建脚本危险路径硬化判别（build-libssh2-android.sh 的输出目录白名单）。

背景：脚本末尾会对输出目录执行 rm -rf，而 rm 只保护 /（--preserve-root），
不保护 $HOME、用户数据目录或项目根。旧实现只拒绝「项目源码树内」的路径：
把 "$HOME" 当输出目录会一路走到 rm -rf "$HOME"（参数传错一次即整目录删除）。

本套件用**假 HOME + PATH 桩**验证（不碰真实 $HOME、不删任何真实路径）：

1. 危险参数（空串、/、$HOME、项目根、无 sftp/fuse-proxy-android 前缀、源码树内）
   必须在**任何 rm / 构建动作之前**被拒：退出码非 0、stderr 含拒绝原因、
   rm 桩与 cmake 桩均未被调用；
2. 合法输出目录仍能走完全流程（正对照，防止「一律拒绝」的假绿）：
   cmake 桩被调用、rm 桩恰好收到该路径、产物落到该目录。

判别性：旧脚本对本套件的「空串 / $HOME」两条不做拒绝，会调用 rm（桩记录到危险
路径），故必失败。复验命令（把旧脚本放进一个独立假根，避免它真的把仓库当输出
目录）：

    mkdir -p /tmp/oldroot/scripts
    git show HEAD:scripts/build-libssh2-android.sh \
        > /tmp/oldroot/scripts/build-libssh2-android.sh
    BUILD_SSH2_SCRIPT=/tmp/oldroot/scripts/build-libssh2-android.sh \
        python3 tests/test_build_scripts.py

前置：bash + coreutils；无网络、无 NDK、无 cmake（均由桩/假树替代）。
退出码：0 通过，1 失败。
"""

import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.environ.get("BUILD_SSH2_SCRIPT") or os.path.join(
    ROOT, "scripts", "build-libssh2-android.sh")
# 脚本用 cd "$(dirname "$0")/.." 推导项目根：判据必须跟着被测脚本走
SCRIPT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(SCRIPT)))

PASS = 0
FAIL = 0
ERRORS = []


def check(desc, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  PASS %s" % desc)
    else:
        FAIL += 1
        print("  FAIL %s: %s" % (desc, detail))
        ERRORS.append((desc, detail))


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _write_exe(path, text):
    _write(path, text)
    os.chmod(path, 0o755)


def make_fixture(tmp):
    """假 HOME + PATH 桩（rm/cmake）+ 假 NDK/源码树：合法路径可走完全流程。"""
    home = os.path.join(tmp, "fake-home")
    os.makedirs(home)
    bindir = os.path.join(tmp, "bin")
    os.makedirs(bindir)
    log = os.path.join(tmp, "stub.log")
    # rm 桩：只记录调用（含参数），绝不删除——危险路径被拒时日志必须为空
    _write_exe(os.path.join(bindir, "rm"),
               '#!/bin/sh\nprintf "rm %s\\n" "$*" >> "$STUB_LOG"\nexit 0\n')
    # cmake 桩：记录并成功（证明拒绝发生在任何构建动作之前）
    _write_exe(os.path.join(bindir, "cmake"),
               '#!/bin/sh\nprintf "cmake %s\\n" "$*" >> "$STUB_LOG"\nexit 0\n')
    ndk = os.path.join(tmp, "ndk")
    os.makedirs(os.path.join(ndk, "toolchains/llvm/prebuilt/linux-x86_64/bin"))
    _write(os.path.join(ndk, "build/cmake/android.toolchain.cmake"), "")
    src = os.path.join(tmp, "src")
    for d in ("mbedtls/build/library", "libssh2/build/src", "libssh2/include"):
        os.makedirs(os.path.join(src, d), exist_ok=True)
    _write(os.path.join(src, "libssh2/include/libssh2.h"), "")
    for rel in ("libssh2/build/src/libssh2.a", "mbedtls/build/library/libmbedtls.a",
                "mbedtls/build/library/libmbedx509.a",
                "mbedtls/build/library/libmbedcrypto.a"):
        _write(os.path.join(src, rel), "")
    return home, bindir, log, ndk, src


def run_script(bindir, log, ndk, src, home, out_arg):
    env = {
        "PATH": bindir + ":/usr/local/bin:/usr/bin:/bin",
        "HOME": home,
        "ANDROID_NDK_HOME": ndk,
        "ANDROID_SFTP_SRC": src,
        "STUB_LOG": log,
        "LANG": "C.UTF-8",
    }
    cmd = ["bash", SCRIPT] if out_arg is None else ["bash", SCRIPT, out_arg]
    return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)


def read_log(log):
    try:
        with open(log, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def main():
    if not os.path.isfile(SCRIPT):
        print("缺少脚本 %s" % SCRIPT, file=sys.stderr)
        return 1
    if not os.path.isfile("/bin/bash"):
        print("缺少 bash，整套跳过", file=sys.stderr)
        return 77

    print("── 被测脚本：%s" % SCRIPT)
    with tempfile.TemporaryDirectory(prefix="build_scripts_") as tmp:
        home, bindir, log, ndk, src = make_fixture(tmp)
        dangerous = [
            ("空输出目录", "", "输出目录不能为空"),
            ("根目录", "/", "不能是根目录"),
            ("HOME 本身", home, "不能是 HOME 本身"),
            ("项目根", SCRIPT_ROOT, "不能是项目根"),
            ("最后一级无前缀", os.path.join(home, "data"), "最后一级须含"),
            ("项目源码树内", os.path.join(SCRIPT_ROOT, "sftp-out"), "项目源码树内"),
        ]
        for name, arg, reason in dangerous:
            if os.path.exists(log):
                os.unlink(log)
            r = run_script(bindir, log, ndk, src, home, arg)
            calls = read_log(log)
            check("%s：退出码非 0" % name, r.returncode != 0,
                  "rc=%d" % r.returncode)
            check("%s：stderr 给出拒绝原因" % name,
                  "拒绝危险的输出目录" in r.stderr and reason in r.stderr,
                  (r.stderr.strip().splitlines() or ["<空>"])[0])
            check("%s：rm 未被调用（拒绝发生在删除之前）" % name,
                  "rm " not in calls, calls.strip()[:200])
            check("%s：cmake 未被调用（拒绝发生在构建之前）" % name,
                  "cmake " not in calls, calls.strip()[:200])

        # 正对照：合法输出目录必须仍能走完全流程
        good = os.path.join(home, ".cache", "fuse-proxy-android", "sftp")
        if os.path.exists(log):
            os.unlink(log)
        r = run_script(bindir, log, ndk, src, home, good)
        calls = read_log(log)
        check("合法输出目录：脚本成功", r.returncode == 0,
              (r.stderr.strip().splitlines() or ["<无 stderr>"])[-1])
        check("合法输出目录：cmake 桩被调用（确实执行了构建流程）",
              "cmake " in calls, calls.strip()[:200])
        check("合法输出目录：rm 桩恰好收到该路径",
              ("rm -rf " + good) in calls, calls.strip()[:300])
        check("合法输出目录：产物落到该目录",
              os.path.isfile(os.path.join(good, "lib", "libssh2.a")) and
              os.path.isfile(os.path.join(good, "include", "libssh2.h")),
              "缺少 include/lib 产物")

    print("\n构建脚本硬化测试 | 通过 %d | 失败 %d" % (PASS, FAIL))
    if ERRORS:
        print("失败详情:")
        for desc, detail in ERRORS[:10]:
            print("  - %s: %s" % (desc, detail))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
