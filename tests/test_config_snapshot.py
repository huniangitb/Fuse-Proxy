#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""config_parser 解析快照 + config_publisher STATIC 输出的 GNU 快照测试。

背景：config_publisher 的 STATIC 响应此前对 injector.conf 做 strtok_r + sscanf
旁路重解析（自己再算一遍 switches / global 规则 / apps），与 config_parser 的
真实解析语义各写一份，默认值、[pkg:uid]、类别段、ALLOW/REDIRECT 区分都靠两边
手工保持一致。本测试锁定重构后的契约：

  - global/apps 段来自 config_parser 已加载的 AppConfig 快照（单一事实来源，
    即"已解析视图"，不是 injector.conf 的原始文本）；
  - 主文件中裸 [pkg]（省略 :uid）以 user_id=-1 表示"跨用户 fallback"，不是 0；
  - app_rules 段仍回显磁盘原始文件内容（STATIC 语义）；
  - 发布器不得调用 load_config_rules（那会替换 injector 的 live 配置）；
  - 规则数组容量增长：每类 40 条跨 8→16→32→64 多次扩容，计数与末尾规则不丢。

由于 injector 仅在 Android 交叉构建、且 GNU 下 CONFIG_DIR 编译期写死为
/var/fuse-proxy（归 root 不可写），本脚本**临时编译实际源码**（config_parser.c /
config_publisher.c 及其依赖）为独立测试二进制，并把副本头文件中 GNU 配置根常量
指向临时 fixture 目录——不新增 Meson C 测试目标，不写系统目录。常量收敛后该
定义位于 nsp_constants.h 的 NSP_CONFIG_DIR；脚本按候选位置自适应定位，兼容
common.h 仍直接定义 CONFIG_DIR 字面量的旧布局。

前置：本机 cc（gcc/clang）、json-c（pkg-config 或 -ljson-c）、pthread。
退出码：全部通过 0，任一失败 1（勿用管道吞掉退出码；可直接用于增量校验）。
"""

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "config_snapshot")
DRIVER = os.path.join(ROOT, "tests", "fixtures", "config_snapshot_driver.c")

# 与 Meson 构建相同的源码集合（只取本测试实际链接到的部分）
SOURCES = [
    "src/config/config_parser.c",
    "src/config/path_vars.c",
    "src/core/path_trie.c",
    "src/core/nsp_util.c",
    "src/core/nsp_comm.c",
    "src/core/common.c",
    "src/core/sys_pkg.c",
    "src/injector/config_publisher.c",
]

# GNU 配置根字面量（TARGET_GNU 分支），可能定义在以下任一常量头中
CONFIG_DIR_PAT = re.compile(
    r'^#define\s+(?:NSP_CONFIG_DIR|CONFIG_DIR)\s+"/var/fuse-proxy"\s*$', re.M)


def pkg_config(flag):
    try:
        r = subprocess.run(["pkg-config", flag, "json-c"], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.split()
    except FileNotFoundError:
        pass
    return []


def prepare_include(tmpdir, config_dir):
    """复制 include/，并把 GNU 配置根常量指向临时 fixture 根。"""
    src_inc = os.path.join(ROOT, "include")
    dst_inc = os.path.join(tmpdir, "include")
    shutil.copytree(src_inc, dst_inc)
    hits = 0
    for name in sorted(os.listdir(dst_inc)):
        if not name.endswith(".h"):
            continue
        path = os.path.join(dst_inc, name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        patched, n = CONFIG_DIR_PAT.subn(
            lambda m: m.group(0).replace('"/var/fuse-proxy"', f'"{config_dir}"'), text)
        if n:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(patched)
            hits += n
    if hits == 0:
        print("未在副本头文件中定位 GNU 配置根常量（NSP_CONFIG_DIR / CONFIG_DIR）",
              file=sys.stderr)
        return None
    return dst_inc


def compile_binary(tmpdir, inc_dir):
    exe = os.path.join(tmpdir, "cfg_snapshot_test")
    cmd = [
        *shlex.split(os.environ.get("CC", "cc")),
        "-std=c23",
        "-DTARGET_GNU=1",
        "-D_GNU_SOURCE",
        "-Wall",
        "-Wno-unused-parameter",
        "-I", inc_dir,
        "-I", os.path.join(ROOT, "include"),
        DRIVER,
    ] + [os.path.join(ROOT, s) for s in SOURCES] + [
        "-o", exe,
        "-pthread", "-ldl", "-lm",
    ] + pkg_config("--cflags") + pkg_config("--libs")
    if not pkg_config("--libs"):
        cmd.append("-ljson-c")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("C 编译/链接失败:", file=sys.stderr)
        print(r.stderr, file=sys.stderr)
        return None
    if r.stderr.strip():
        # 源码警告原样透出，便于发现重构引入的问题（不视为失败）
        print(r.stderr, file=sys.stderr, end="")
    return exe


def run_case(tmpdir):
    config_dir = os.path.join(tmpdir, "config")
    shutil.copytree(FIXTURE, config_dir)
    inc_dir = prepare_include(tmpdir, config_dir)
    if inc_dir is None:
        return 1
    exe = compile_binary(tmpdir, inc_dir)
    if exe is None:
        return 1
    r = subprocess.run([exe, os.path.join(config_dir, "injector.conf")],
                       capture_output=True, text=True)
    print(r.stdout, end="")
    if r.stderr:
        print(r.stderr, end="", file=sys.stderr)
    if r.returncode != 0:
        print("config 快照测试失败", file=sys.stderr)
        return 1
    print("config 快照测试通过 ✔")
    return 0


def main():
    if not os.path.isfile(DRIVER):
        print(f"缺少 fixture 驱动 {DRIVER}", file=sys.stderr)
        return 1
    if not os.path.isdir(FIXTURE):
        print(f"缺少 fixture 配置目录 {FIXTURE}", file=sys.stderr)
        return 1
    # TemporaryDirectory：无论成功/失败/异常都在 finally 清理，不泄漏临时目录
    with tempfile.TemporaryDirectory(prefix="cfg_snapshot_") as tmpdir:
        return run_case(tmpdir)


if __name__ == "__main__":
    sys.exit(main())
