#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ns 命名空间执行原语的超时收尸有界性测试

做法：直编 tests/fixtures/ns_timeout_reap.c —— 它把实际源码
src/injector/ns_utils.c 整体 #include（-DNS_TIMEOUT_NS_UTILS_SRC=），只把
kill（模拟 SIGKILL 在不可中断内核态上不生效）与 _exit（模拟子进程写完结果
后仍滞留）经 -Wl,--wrap 换成可控实现，run_in_mnt_ns_timeout 全走真实代码。

夹具必须在 `unshare -Ur -m --propagation private` 下运行：非特权用户直接
setns(CLONE_NEWNS) 会 EPERM，走不到被测路径。宿主机不支持 unshare 时本套
跳过（77）并以静态检查兜底。

判别性：旧实现（git show <commit>:src/injector/ns_utils.c）两处
waitpid(...,0) 无界等待——1）超时分支 SIGKILL 不生效时调用方永久阻塞
（夹具用 1.5s watchdog 判红，实测旧源 finished=0）；2）status 分支子进程
滞留时白等满滞留时间（实测旧源 elapsed 501ms vs 新 23ms）。
复现旧实现：NS_TIMEOUT_NS_UTILS_SRC=<旧源码副本> python3 tests/test_ns_timeout_reap.py

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
DRIVER = ROOT / "tests" / "fixtures" / "ns_timeout_reap.c"
NS_UTILS_SRC = os.environ.get("NS_TIMEOUT_NS_UTILS_SRC") or str(
    ROOT / "src" / "injector" / "ns_utils.c")
SKIP_RC = 77
# 这两处阻塞等待一旦回到生产源码，注入器事件循环就可能被卡死的子进程钉住
FORBIDDEN = ("waitpid(child, &status, 0)", "waitpid(child, NULL, 0)")


def static_checks():
    """只有直编生产源码时才做结构检查；指向旧源副本时它就是"应当红"的。"""
    try:
        text = Path(NS_UTILS_SRC).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"无法读取 {NS_UTILS_SRC}: {exc}", file=sys.stderr)
        return False
    ok = True
    for bad in FORBIDDEN:
        if bad in text:
            print(f"FAIL: 生产源码仍有无界等待 {bad!r}", file=sys.stderr)
            ok = False
    if "reap_child_bounded" not in text:
        print("FAIL: 生产源码没有有界收尸 reap_child_bounded", file=sys.stderr)
        ok = False
    return ok


def userns_available():
    try:
        probe = subprocess.run(
            ["unshare", "-Ur", "-m", "--propagation", "private", "true"],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


def build(cc, exe, extra):
    cmd = cc + [
        "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
        f'-DNS_TIMEOUT_NS_UTILS_SRC="{NS_UTILS_SRC}"',
        "-I", str(ROOT / "include"),
        "-I", str(ROOT / "src" / "core"),
        "-I", str(ROOT / "src" / "injector"),
        "-ffunction-sections", "-fdata-sections",
        str(DRIVER),
        "-Wl,--gc-sections",
        "-Wl,--wrap=kill", "-Wl,--wrap=_exit",
        "-pthread",
    ] + extra + ["-o", exe]
    return subprocess.run(cmd, capture_output=True, text=True)


def run(exe, env):
    return subprocess.run(
        ["unshare", "-Ur", "-m", "--propagation", "private", exe],
        capture_output=True, text=True, env=env, timeout=180)


def report(tag, res):
    out = (res.stdout or "") + (res.stderr or "")
    print(f"--- {tag} ---")
    print(out.rstrip())
    bad = False
    if "AddressSanitizer" in out:
        print(f"FAIL[{tag}]: sanitizer 报告", file=sys.stderr)
        bad = True
    if "[FAIL]" in out:
        print(f"FAIL[{tag}]: 存在失败断言", file=sys.stderr)
        bad = True
    if res.returncode != 0:
        print(f"FAIL[{tag}]: 驱动退出码 {res.returncode}", file=sys.stderr)
        bad = True
    return bad


def main():
    if not DRIVER.is_file():
        print(f"缺少驱动 {DRIVER}", file=sys.stderr)
        return 1
    if not Path(NS_UTILS_SRC).is_file():
        print(f"缺少 ns_utils 源码 {NS_UTILS_SRC}", file=sys.stderr)
        return SKIP_RC

    override = bool(os.environ.get("NS_TIMEOUT_NS_UTILS_SRC"))
    if not override and not static_checks():
        return 1

    if not userns_available():
        print("跳过：宿主机不允许 unshare -Ur -m（无法 setns，走不到超时收尸路径）",
              file=sys.stderr)
        return SKIP_RC

    cc = shlex.split(os.environ.get("CC", "cc"))
    tmpdir = tempfile.mkdtemp(prefix="ns_timeout_reap_")
    plain = os.path.join(tmpdir, "driver")
    asan = os.path.join(tmpdir, "driver_asan")
    try:
        built = build(cc, plain, [])
        if built.returncode != 0:
            print("编译失败:", file=sys.stderr)
            print(built.stdout, built.stderr, file=sys.stderr)
            return 1
        asan_flags = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        built_asan = build(cc, asan, asan_flags)
        have_asan = built_asan.returncode == 0
        if not have_asan:
            print("(sanitizer 构建不可用，跳过消毒复跑)", file=sys.stderr)

        env = {**os.environ, "ASAN_OPTIONS": "detect_leaks=0",
               "UBSAN_OPTIONS": "print_stacktrace=0"}
        bad = False
        bad |= report("plain", run(plain, env))
        if have_asan:
            bad |= report("asan", run(asan, env))
        if bad:
            return 1
        print("ns 超时收尸有界性测试通过 ✔")
        return 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
