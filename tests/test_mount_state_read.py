#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""挂载状态读取的「未知 vs 没有挂载」判据（src/injector/mount_manager.c:read_mount_state）

背景：read_mount_state 的返回值有两层含义——false 表示「这次读不出结论」，true 表示
「读到了，标志位里是结论」。调用方拿它决定要不要挂载：把「读不出」当成「没挂载」，
就会在活着的视图上再叠一层；把「没挂载」当成「读不出」，会让本来就健康的应用被反复
清理重挂。两件事必须始终可区分。

修复后的契约（本套件守护）：
  1. 读取按不设上限发起（max_size=0）：任何固定上限都会在条目多的命名空间里把目标
     行截掉，而截掉之后看起来就是「没挂载」；
  2. 读取失败一律返回 false（结论未知），绝不返回「成功且标志位全清」；
  3. 失败前先把整个结构体清零，不给调用方留下半份状态。

分层：A 段驱动直编实际源码（整体 #include mount_manager.c，同 TU 可见 static 的
read_mount_state）+ 桩喂合成 mountinfo（L0，无挂载无特权）；B 段静态契约锁住这三条
性质不被改回去。

判别性：给读取加固定上限会让 C1 失败（目标在第 5000 行之后）；把读取失败改回
「成功但标志位全清」会让 A1 失败。

退出码：0 通过、1 失败。
"""
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests" / "fixtures" / "mount_state_read_driver.c"
MOUNT_MANAGER = ROOT / "src" / "injector" / "mount_manager.c"
INJECT_TARGET = ROOT / "src" / "injector" / "inject_target.c"


def read(path):
    return path.read_text(encoding="utf-8")


def run_driver():
    if not DRIVER.is_file() or not MOUNT_MANAGER.is_file():
        print(f"缺少 fixture 驱动或源码（{DRIVER} / {MOUNT_MANAGER}）", file=sys.stderr)
        return 1
    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="mount_state_read_") as tmp:
        exe = Path(tmp) / "mount_state_read_driver"
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
            "-I", str(ROOT / "include"),
            "-I", str(ROOT / "src" / "core"),
            "-I", str(ROOT / "src" / "injector"),
            str(DRIVER),
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


def check(name, ok, detail=""):
    print(f"case={name:<52} ok={1 if ok else 0} {detail}")
    return 0 if ok else 1


def body_of(text, signature, span=4000):
    at = text.find(signature)
    return text[at:at + span] if at >= 0 else ""


def run_contracts():
    failures = 0
    mm = read(MOUNT_MANAGER)
    state = body_of(mm, "static bool read_mount_state(")

    failures += check("Q1_state_read_is_unbounded",
                      "read_file_dynamic(path, &nread, 0)" in state)
    failures += check("Q2_read_failure_is_unknown",
                      "if (!buf) return false;" in state)
    memset_at = state.find("memset(st, 0, sizeof(*st));")
    failures += check("Q3_state_is_cleared_before_any_failure",
                      0 <= memset_at < state.find("if (!buf) return false;"))
    failures += check("Q4_state_read_has_no_fixed_capacity",
                      "NS_MOUNTINFO_MAX" not in mm)

    # 调用方：读不出结论时不得继续当成「没挂载」往下走
    cached = body_of(mm, "bool is_project_fuse_cached(")
    failures += check("Q5_cached_probe_propagates_unknown",
                      "if (!read_mount_state(pid, target_path, \"\", &mnt)) return false;" in cached)
    mount = body_of(mm, "int perform_app_mount(const char* pkg", 2500)
    failures += check("Q6_mount_path_aborts_on_unknown",
                      "读取挂载状态失败" in mount and "return -1;" in mount)

    strict = len(re.findall(r"if \(!read_mount_state\(", mm))
    # 每次调用前面都必须带 if (!read_mount_state(…)：减去前置声明与定义两处
    all_calls = len(re.findall(r"read_mount_state\(", mm)) - 2
    failures += check("Q7_every_call_site_handles_unknown",
                      strict >= 4 and strict == all_calls,
                      f"calls={all_calls} strict={strict}")
    return failures


def main():
    failures = run_driver()
    failures += run_contracts()
    print(f"===== total_failures={failures} =====")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
