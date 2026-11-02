#!/usr/bin/env python3
"""虚拟条目判定与合成属性（L0 直编）

线上实例：沙盒开启时 readdir 为 /Android/obb/<当前包名> 合成一条目录（真实目录
可以不存在），而 getattr 的虚拟目录兜底只认三层骨架与重定向 virtual_kind，
按名 stat 落回 ENOENT——文件管理器列表里看得见、点不开，画成文件并显示
1970-01-01。排查绕了三轮，原因就是合成路径没有任何断言守着。

本套件两条腿：
  1. 直编 src/daemon/vfs_synth.c：合成目录条目必须 S_ISDIR、nlink>=2、size>0、
     mtime>0；/Android/data|obb/<pkg> 的路径判定必须命中（含带用户层形态），
     其余路径不得误命中。
  2. 静态契约：vfs_synth_stat 必须经 nsp_synth_stat_fill 生成属性（不再自己
     memset），且 getattr / access / opendir 三处虚拟兜底都必须问
     is_virtual_own_pkg_dir——「obb/<pkg> 不存在时 stat 也要成功」靠这条守住。

退出码遵循 tests/run.py 约定：0 通过、1 失败。无环境依赖，不会 gap。
"""
import os
import shlex
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DAEMON = os.path.join(ROOT, "src", "daemon", "fuse_daemon.c")
SOURCE = os.path.join(ROOT, "src", "daemon", "vfs_synth.c")
DRIVER = os.path.join(ROOT, "tests", "fixtures", "vfs_synth_test.c")
RUN_TIMEOUT = 60


def func_body(src, name, span=2500):
    idx = src.find(name + "(")
    if idx < 0:
        return ""
    return src[idx:idx + span]


def static_contract():
    errs = []
    with open(DAEMON, "r", encoding="utf-8") as fh:
        src = fh.read()
    synth = func_body(src, "static void vfs_synth_stat")
    if not synth:
        errs.append("找不到 vfs_synth_stat")
    else:
        if "nsp_synth_stat_fill" not in synth:
            errs.append("vfs_synth_stat 未经 nsp_synth_stat_fill 生成属性")
        if "memset(st" in synth:
            errs.append("vfs_synth_stat 又自己 memset：合成属性必须由 vfs_synth.c 单点给出")
    for fn in ("static int vfs_getattr", "static int vfs_access", "static int vfs_opendir"):
        body = func_body(src, fn, 9000)
        if not body:
            errs.append("找不到 " + fn)
            continue
        if "is_virtual_own_pkg_dir" not in body:
            errs.append(fn + " 的虚拟目录兜底未接入 is_virtual_own_pkg_dir")
    return errs


def main():
    for path in (DRIVER, SOURCE, DAEMON):
        if not os.path.exists(path):
            print("缺少源文件 " + path, file=sys.stderr)
            return 1

    errs = static_contract()
    if errs:
        for e in errs:
            print("[FAIL] " + e, file=sys.stderr)
        return 1
    print("静态契约：合成属性单点生成 / getattr+access+opendir 三处兜底同口径 OK")

    with tempfile.TemporaryDirectory(prefix="vfssynth_build_") as tmpdir:
        exe = os.path.join(tmpdir, "vfs_synth_test")
        cmd = [
            *shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Wno-unused-parameter",
            "-I", os.path.join(ROOT, "include"),
            "-I", os.path.join(ROOT, "src", "daemon"),
            DRIVER, SOURCE, "-o", exe,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("C 编译/链接失败:", file=sys.stderr)
            print(r.stderr, file=sys.stderr)
            return 1
        if r.stderr.strip():
            print(r.stderr, file=sys.stderr, end="")
        try:
            run = subprocess.run([exe], capture_output=True, text=True, timeout=RUN_TIMEOUT)
        except subprocess.TimeoutExpired:
            print(f"驱动超时（>{RUN_TIMEOUT}s）", file=sys.stderr)
            return 1

    print(run.stdout, end="")
    if run.returncode != 0 or "[FAIL]" in run.stdout:
        print("虚拟条目判定/合成属性测试失败", file=sys.stderr)
        return 1
    print("虚拟条目判定/合成属性测试通过 OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
