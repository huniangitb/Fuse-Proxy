#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""监控开关三层合并（框架权威）与 uid→包名解析的 GNU 单元测试。

背景：`MONITOR` 是**配置开关**而非路径决策。它的值此前只由规则模块给出
（`br_effective_monitor` 的应用 > 类别 > 全局合并），框架仅在模块缺席时用
`[GLOBAL]` 兜底——于是模块未加载/被 ban 时，`[USER_APPS:0] MONITOR ON`
（或 `OFF` 否决）静默失效：文件读写一切正常，只有监控日志开关被改写。

修复后三层合并归框架（`fw_config_monitor_for` + `fw_pkg_resolve`），因此必须
锁定"不依赖模块也算得对"。**FUSE 端到端测试覆盖不到这一层**：请求者是本机 uid
（<10000）恒走 system 分支，`[USER_APPS:*]` 永远不参与匹配。故本脚本临时编译
实际源码（fw_config.c / fw_pkg.c / config_parser.c 及其依赖），把 GNU 配置根
常量指向临时 fixture 目录（uid.map 与规则文件都在其中），用**合成 uid**
（10123 = user 0 应用、200123 = user 2 应用）逐个断言合并结果。

锁定内容：
  1. uid→包名：uid.map 优先；未收录时走 /proc（Tgid + cmdline）回退；两者都拿不到 → "unknown"。
  2. 三层优先级：应用显式 > 类别显式（USER_APPS[:uid] / SYSTEM_APPS）> 全局，
     两个方向都要生效——全局 ON 时的类别否决、全局 OFF 时的类别开启。
  3. 用户隔离：`[USER_APPS:0]` 不作用于 user 2；`[USER_APPS:2]` 独立生效。
  4. fail-safe：包名不可解析（unknown/过短/zygote）时只认 `[GLOBAL]`。

前置：本机 cc、pthread。退出码：全部通过 0，任一失败 1。
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "monitor_layers")
DRIVER = os.path.join(ROOT, "tests", "fixtures", "monitor_layers_driver.c")

# 与 Meson 构建相同的源码集合（只取本测试实际链接到的部分）
SOURCES = [
    "src/daemon/fw_config.c",
    "src/daemon/fw_pkg.c",
    # fw_config 重载时会通知内建规则引擎作废缓存 → 链接 fw_rules.c（及 sys_pkg 等依赖）
    "src/daemon/fw_rules.c",
    "src/config/config_parser.c",
    "src/config/path_vars.c",
    "src/core/path_trie.c",
    "src/core/nsp_util.c",
    "src/core/nsp_comm.c",
    "src/core/common.c",
    "src/core/sys_pkg.c",
    "src/core/uid_map.c",
    "src/core/fast_pid.c",
]

CONFIG_DIR_PAT = re.compile(
    r'^#define\s+(?:NSP_CONFIG_DIR|CONFIG_DIR)\s+"/var/fuse-proxy"\s*$', re.M)

# (配置, uid 参数, 期望包名或 None=不校验, 期望 monitor)
# uid 参数带 "@self" 表示以驱动自身 pid 作 tid，覆盖 uid.map 未收录时的 /proc 回退
CASES = [
    # 全局 ON：类别/应用显式 OFF 必须否决
    ("cat_off.conf", "10123", "com.demo.app", False),   # [USER_APPS:0] MONITOR OFF
    ("cat_off.conf", "10500", "com.plain.app", False),  # [com.plain.app] MONITOR OFF
    ("cat_off.conf", "200123", "com.user2.app", True),  # [com.user2.app] MONITOR ON
    ("cat_off.conf", "5000", "system", False),          # [SYSTEM_APPS] MONITOR OFF
    ("cat_off.conf", "15000", "unknown", True),         # 包名不可解析 → 仅 GLOBAL
    # 全局 OFF：类别显式 ON 是唯一开来源（模块缺席时的核心验收）
    ("cat_on.conf", "10123", "com.demo.app", True),     # [USER_APPS:0] MONITOR ON
    ("cat_on.conf", "5000", "system", True),            # [SYSTEM_APPS] MONITOR ON
    ("cat_on.conf", "200123", "com.user2.app", False),  # [USER_APPS:2] OFF：用户隔离
    ("cat_on.conf", "15000", "unknown", False),         # 包名不可解析 → 仅 GLOBAL
    # uid.map 未收录 + /proc 回退拿到可解析包名（argv[0]）→ 类别层照常参与
    ("cat_off.conf", "25000@self", None, False),        # 全局 ON，[USER_APPS:0] OFF 否决
    ("cat_on.conf", "25000@self", None, True),          # 全局 OFF，[USER_APPS:0] ON 开启
]


def prepare_include(tmpdir, config_dir):
    """复制 include/，并把 GNU 配置根常量指向临时 fixture 根（uid.map 所在处）。"""
    dst_inc = os.path.join(tmpdir, "include")
    shutil.copytree(os.path.join(ROOT, "include"), dst_inc)
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
    exe = os.path.join(tmpdir, "monitor_layers_test")
    cmd = [
        os.environ.get("CC", "cc"), "-std=c23", "-DTARGET_GNU=1", "-D_GNU_SOURCE",
        "-Wall", "-Wno-unused-parameter",
        "-I", inc_dir, "-I", os.path.join(ROOT, "include"),
        # fw_config.h / fw_pkg.h 随实现放在 src/daemon（框架侧私有头）
        "-I", os.path.join(ROOT, "src", "daemon"),
        DRIVER,
    ] + [os.path.join(ROOT, s) for s in SOURCES] + [
        "-o", exe, "-pthread", "-ldl", "-lm",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("C 编译/链接失败:", file=sys.stderr)
        print(r.stderr, file=sys.stderr)
        return None
    if r.stderr.strip():
        print(r.stderr, file=sys.stderr, end="")
    return exe


def parse(out):
    """'uid=10123 pkg=com.demo.app monitor=1' → {uid: (pkg, monitor_bool)}"""
    got = {}
    for line in out.splitlines():
        m = re.match(r"uid=(\d+) pkg=(\S+) monitor=([01])$", line.strip())
        if m:
            got[int(m.group(1))] = (m.group(2), m.group(3) == "1")
    return got


def run_case(exe, tmpdir, conf, uid_args):
    r = subprocess.run([exe, os.path.join(tmpdir, "config", conf)] + list(uid_args),
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"驱动退出码 {r.returncode}: {r.stderr}", file=sys.stderr)
        return None
    return parse(r.stdout)


def main():
    if not os.path.isfile(DRIVER) or not os.path.isdir(FIXTURE):
        print("缺少 fixture（驱动或配置目录）", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="monitor_layers_") as tmpdir:
        config_dir = os.path.join(tmpdir, "config")
        shutil.copytree(FIXTURE, config_dir)
        inc_dir = prepare_include(tmpdir, config_dir)
        if inc_dir is None:
            return 1
        exe = compile_binary(tmpdir, inc_dir)
        if exe is None:
            return 1

        results = {}
        for conf in sorted({c[0] for c in CASES}):
            # 每个配置一次进程内批量查询：一次 init 即可覆盖全部 uid（驱动按参数逐个算）
            results[conf] = run_case(exe, tmpdir, conf,
                                     [c[1] for c in CASES if c[0] == conf])
        if any(v is None for v in results.values()):
            return 1

        passed = failed = 0
        for conf, uid_arg, want_pkg, want_mon in CASES:
            got = results[conf].get(int(uid_arg.split("@")[0]))
            name = f"{conf} uid={uid_arg}"
            if got is None:
                print(f"FAIL {name}: 无输出行")
                failed += 1
                continue
            pkg, mon = got
            if mon != want_mon or (want_pkg is not None and pkg != want_pkg):
                print(f"FAIL {name}: 期望 pkg={want_pkg or '(任意)'} monitor={int(want_mon)}，"
                      f"实得 pkg={pkg} monitor={int(mon)}")
                failed += 1
            else:
                print(f"PASS {name}: pkg={pkg} monitor={int(mon)}")
                passed += 1

    print(f"监控三层合并测试 | 通过 {passed} | 失败 {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
