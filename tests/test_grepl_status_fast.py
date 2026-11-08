#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""稳态对账的状态快查（ns_global_status 的 dev 快判分支）

背景：周期对账每 5s 调一次 ns_global_status()，旧实现每次都整份读 + 逐行解析
/proc/<pid>/mountinfo。这份挂载表在条目上千的机型上一次 68ms 级（mount_manager.c
的实测注释），而稳态下结论九成以上是「已替换」——判据只是「每个族根是否挂在当前
FUSE 源的超块上」（bind 与源共享 superblock，dev 就是指纹）。

现在的结构：先用族根的 dev 快判 REPLACED（三族 × 数字用户目录各 stat 一次），
判不出来才回落整份扫描。本套件守的是这条快查的**覆盖面**与**回落**：

  1. 快查命中时一次 mountinfo 都不打开（否则等于没省，还多花几次 stat）；
  2. 任一族根对不上 / stat 出错 / 目录打不开 / 一条族根都没有 → 必须回落扫描，
     结论由挂载表决定（MIXED、NORMAL、UNKNOWN 都只能从那里得出）；
  3. 枚举覆盖三族下**全部**数字用户目录：漏一个用户就等于让那一族永久跳过对账
     （新用户接管、被 vold 重挂回系统视图都靠这条链自愈）；
  4. 源 stat 不出来时不得判 REPLACED（源是普通目录时 bind 会把空目录装进族根）；
  5. 源与族根都必须仍是 **FUSE**：普通目录之间 dev 相同是常态（同一个文件系统下的
     兄弟目录），而共享挂载组上的挂载会传播——vold 重挂族根时源可能被同一个空 tmpfs
     一起盖住，那时两边 dev 相等却都不是项目视图。

分层：A 段直编实际源码（ns_mountinfo.c + ns_global_replace.c），--wrap=fopen 判
mountinfo 是否被打开、--wrap=stat 合成 dev、--wrap=statfs 合成 fstype、
--wrap=opendir/readdir 合成族目录（L0，无挂载无特权）；B 段静态契约锁住「快查不得
自己读挂载表」「回落分支不得被删」「快查必须排在扫描之前」「fstype 判据不得丢」。

判别性：A1/A2/F1 在旧实现（无快查）上必失败——旧实现一定打开 mountinfo，合成表
留空时只会给 UNKNOWN。

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
DRIVER = ROOT / "tests" / "fixtures" / "grepl_status_fast_driver.c"
SRC = Path(os.environ.get("NS_GLOBAL_REPLACE_SRC")
           or (ROOT / "src" / "injector" / "ns_global_replace.c"))
SCANNER = ROOT / "src" / "injector" / "ns_mountinfo.c"


def read(path):
    return path.read_text(encoding="utf-8")


def run_driver():
    if not DRIVER.is_file() or not SRC.is_file():
        print(f"缺少 fixture 驱动或源码（{DRIVER} / {SRC}）", file=sys.stderr)
        return 1
    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="grepl_status_fast_") as tmp:
        exe = Path(tmp) / "grepl_status_fast_driver"
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
            f'-DNS_GLOBAL_REPLACE_SRC="{SRC}"',
            "-I", str(ROOT / "include"),
            "-I", str(ROOT / "src" / "core"),
            "-I", str(ROOT / "src" / "injector"),
            str(DRIVER),
            "-Wl,--wrap=fopen",
            "-Wl,--wrap=stat",
            "-Wl,--wrap=statfs",
            "-Wl,--wrap=opendir",
            "-Wl,--wrap=readdir",
            "-Wl,--wrap=closedir",
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


def run_contracts():
    failures = 0
    impl = read(SRC)

    quick = impl.find("static bool ns_family_root_quick_replaced(")
    status = impl.find("int ns_global_status(")
    failures += check("S1_quick_path_exists", quick >= 0)
    if quick < 0 or status < 0:
        return failures + 1
    quick_body = impl[quick:status]
    status_body = impl[status:status + 3600]

    # 快查自己不得读挂载表，否则「省一次读」变成「多读一次」
    failures += check("S2_quick_path_reads_no_mountinfo",
                      "ns_scan_mountinfo_stats(" not in quick_body and
                      "ns_read_mountinfo_pid(" not in quick_body and
                      "fopen(" not in quick_body)

    # 回落必须保留：整份扫描仍是唯一能判 NORMAL/MIXED/UNKNOWN 的地方
    failures += check("S3_fallback_scan_kept",
                      "ns_scan_mountinfo_stats(" in status_body and
                      status_body.count("NSP_GLOBAL_STATUS_UNKNOWN") >= 2)

    # 顺序：先快查、后扫描
    q = status_body.find("ns_family_root_quick_replaced(mnt_ns_pid, fuse_src)")
    s = status_body.find("ns_scan_mountinfo_stats(")
    failures += check("S4_quick_path_runs_before_scan", q >= 0 and s > q, f"quick={q} scan={s}")

    # 覆盖面：三族都枚举，且只认纯数字用户目录
    failures += check("S5_enumerates_three_families",
                      '"installer", "androidwritable", "user"' in quick_body)
    failures += check("S6_only_numeric_user_dirs",
                      "ns_is_digit_char(" in quick_body)

    # 任何不确定都返回 false（回落），不得默认 REPLACED
    failures += check("S7_uncertain_returns_false", quick_body.count("return false;") >= 3,
                      f"found={quick_body.count('return false;')}")
    failures += check("S8_no_roots_is_not_replaced",
                      re.search(r"return seen > 0;", quick_body) is not None)
    # fstype 判据：dev 相等不算证据，两条路径都必须仍是 FUSE（源 + 每条族根）
    failures += check("S9_fstype_gate_on_both",
                      quick_body.count("ns_path_is_fuse_mount(") >= 2,
                      f"fuse_checks={quick_body.count('ns_path_is_fuse_mount(')}")
    return failures


def main():
    failures = run_driver()
    failures += run_contracts()
    print(f"===== total_failures={failures} =====")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
