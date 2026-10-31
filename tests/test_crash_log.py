#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""崩溃日志捕获链路测试：fuse_daemon --crash-test 触发崩溃，
验证 crash_handler 的崩溃日志（信号 + backtrace 帧）能够正常输出。

用途：设备上部署新版后，用 injector --crash-test 触发崩溃，
检查 fuse_crash.log / error.log 是否捕获完整 backtrace；
本测试在本机（GNU 构建）用 stderr 重定向模拟 injector 的
dup2 重定向，验证 daemon 侧崩溃输出链路。

用法：
  python3 tests/test_crash_log.py
环境变量：
  FUSE_DAEMON  指定 fuse_daemon 路径（默认 build_gnu/fuse_daemon）
"""

import os
import signal
import subprocess
import sys
import tempfile

DAEMON = os.environ.get("FUSE_DAEMON", os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "build_gnu", "fuse_daemon"))

# 崩溃类型 → (参数, 期望信号, 名称)
CASES = [
    ("--crash-test",      signal.SIGSEGV, "SIGSEGV(默认参数)"),
    ("--crash-test=segv", signal.SIGSEGV, "SIGSEGV(=segv)"),
    ("--crash-test=abrt", signal.SIGABRT, "SIGABRT(=abrt)"),
    ("--crash-test=bus",  signal.SIGBUS,  "SIGBUS(=bus)"),
]


def run_case(name, arg, expected_sig):
    """运行 fuse_daemon --crash-test，stderr 重定向到临时文件（模拟
    injector 的 dup2(fuse_crash.log) 重定向），校验崩溃日志输出。"""
    fd, log_path = tempfile.mkstemp(prefix="fuse_crash_test_", suffix=".log")
    os.close(fd)
    try:
        with open(log_path, "w") as f:
            proc = subprocess.run([DAEMON, arg], stdout=f, stderr=subprocess.STDOUT,
                                  timeout=15)
            rc = proc.returncode
    except FileNotFoundError:
        print(f"  ❌ {name}: fuse_daemon 不存在: {DAEMON}")
        return False
    except subprocess.TimeoutExpired:
        print(f"  ❌ {name}: 超时未崩溃（触发失败？）")
        return False
    finally:
        content = open(log_path).read() if os.path.exists(log_path) else ""

    # 退出码：subprocess 对信号终止返回 -signal（如 -11）；128+signal 为 exit 码惯例
    got_sig = -rc if rc < 0 else (rc & 0x7F)
    ok_sig = (got_sig == expected_sig)
    # 崩溃日志内容校验：必须包含崩溃头 + backtrace 帧
    ok_head = "FUSE DAEMON CRASH" in content
    ok_sig_line = f"Signal: {expected_sig}" in content
    ok_bt = "Backtrace" in content and "#00 pc" in content
    # 帧归属行：把 PC/LR 直接解析成「哪个 .so + 符号偏移」。真机 FORTIFY abort
    # 现场就死在 backtrace() 之前（信号已复位为 DFL，第二次 abort 直接带走进程），
    # 只有这一行能回答"是 libfuse3.so 还是模块 .so"，在拿到 tombstone 之前全靠它。
    owner_lines = [l for l in content.splitlines() if "PC owner:" in l or "LR owner:" in l]
    ok_owner = bool(owner_lines) and any("+0x" in l for l in owner_lines)
    # 偏移必须与映射表的 file offset 口径一致（addr2line 才指得准）：
    # 行内需同时给出 map 区间与 file off
    ok_owner_fmt = ok_owner and all(
        ("map 0x" in l and "file off 0x" in l) for l in owner_lines)
    ok = ok_sig and ok_head and ok_sig_line and ok_bt and ok_owner and ok_owner_fmt

    print(f"  {'✅' if ok else '❌'} {name}: 退出码={rc} "
          f"(期望信号 {expected_sig}, 实际 {'命中' if ok_sig else rc}) | "
          f"崩溃头={'有' if ok_head else '无'} backtrace帧={'有' if ok_bt else '无'} "
          f"帧归属={'有' if ok_owner else '无'}"
          + ("" if ok_owner_fmt else "(格式/偏移缺失)"))
    if not ok:
        print(f"      --- 日志尾部 ---")
        print("\n".join("      | " + l for l in content.splitlines()[-6:]))
    os.unlink(log_path)
    return ok


def main():
    if not os.path.exists(DAEMON):
        print(f"错误: fuse_daemon 不存在: {DAEMON}")
        print("请先构建 GNU 版：meson setup build_gnu -Dtarget_os=gnu && ninja -C build_gnu")
        sys.exit(1)
    print(f"崩溃日志捕获链路测试（daemon: {DAEMON}）")
    print(f"注：以 stderr 重定向模拟 injector 的 fuse_crash.log 重定向；")
    print(f"    设备端可用 injector --crash-test 触发并检查 fuse_crash.log。")
    all_ok = True
    for arg, sig, label in CASES:
        all_ok = run_case(label, arg, sig) and all_ok
    print("═══════════════════════════════════════")
    if all_ok:
        print(f"✅ 崩溃日志捕获链路正常：所有类型均输出完整崩溃日志")
        return 0
    print("❌ 存在失败项，请检查 crash_handler / stderr 重定向链路")
    return 1


if __name__ == "__main__":
    sys.exit(main())
