#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mountinfo 读取的容量语义（ns_read_mountinfo_pid / ns_global_status / ns_backup_point_state）

背景：读取实现原先由调用方预分配 NS_MOUNTINFO_MAX(4096) 条，触顶只打一行 WRN 就
把「读到的那部分」当结果返回——调用方无从区分「表里只有 n 条」与「被截断了」。
真实设备的命名空间条目数只跟挂了多少东西有关，4096 之上再出现族根时，替换/回滚/
状态判定会把这些条目当成不存在。

修复后的契约（本套件守护的就是这几条）：
  1. 条目数按需增长，没有固定上限；
  2. 只要这份列表可能不完整（打开失败 / 内存不足 / 丢弃过超长行），就返回 -1 =
     「未知」，不交回半份条目；
  3. 调用方必须把「未知」与「0 条」分开：状态判定返回 UNKNOWN 而不是 NORMAL，
     备份点判定返回 NS_BACKUP_UNKNOWN 而不是「可以新建」。

分层：A 段直编实际源码（ns_mountinfo.c + ns_global_replace.c）+ --wrap=fopen 喂
合成 mountinfo（L0，无挂载无特权）；B 段静态契约锁住调用点不得退回去用固定上限，
以及 mount_manager.c 的挂载状态读取仍然是无上限读取且失败按未知处理。

判别性：旧实现在 A1/A2/B1 失败（读回 4096 条、状态 UNKNOWN）；把「读失败」当
「没有挂载」会让 C1/C2/C3 失败。

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
DRIVER = ROOT / "tests" / "fixtures" / "mountinfo_dynamic_driver.c"
SRC = Path(os.environ.get("NS_GLOBAL_REPLACE_SRC")
           or (ROOT / "src" / "injector" / "ns_global_replace.c"))
SCANNER = ROOT / "src" / "injector" / "ns_mountinfo.c"
HDR = ROOT / "src" / "injector" / "ns_global_replace.h"
MOUNT_MANAGER = ROOT / "src" / "injector" / "mount_manager.c"


def read(path):
    return path.read_text(encoding="utf-8")


def run_driver():
    if not DRIVER.is_file() or not SRC.is_file():
        print(f"缺少 fixture 驱动或源码（{DRIVER} / {SRC}）", file=sys.stderr)
        return 1
    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="mountinfo_dynamic_") as tmp:
        exe = Path(tmp) / "mountinfo_dynamic_driver"
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
            f'-DNS_GLOBAL_REPLACE_SRC="{SRC}"',
            "-I", str(ROOT / "include"),
            "-I", str(ROOT / "src" / "core"),
            "-I", str(ROOT / "src" / "injector"),
            str(DRIVER),
            "-Wl,--wrap=fopen",
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
    scanner = read(SCANNER)
    hdr = read(HDR)
    mm = read(MOUNT_MANAGER)

    failures += check("P1_header_declares_dynamic_reader",
                      "int ns_read_mountinfo_pid(int pid, NsMountEntry** out);" in hdr)
    failures += check("P2_scanner_exposes_per_call_stats",
                      "int ns_scan_mountinfo_stats(" in scanner and
                      "int ns_scan_mountinfo_stats(" in hdr)

    # 读取路径不得再出现「按固定上限分配一次」的写法
    fixed = len(re.findall(r"NsMountEntry\* all = malloc\(NS_MOUNTINFO_MAX", impl))
    failures += check("P3_read_path_has_no_fixed_capacity_malloc", fixed == 0,
                      f"found={fixed}")
    failures += check("P4_reader_grows_with_realloc",
                      "realloc(c->out" in impl and "c->cap * 2" in impl)

    # 不完整 → 未知：两条出口（内存不足 / 丢弃过超长行）都必须整份作废
    failures += check("P5_incomplete_read_is_unknown", "c.nomem || st.truncated" in impl)
    failures += check("P6_no_partial_result_on_unknown", impl.count("free(c.out);\n        return -1;") >= 2)

    # 调用点全部换成新签名（旧三参调用会编译不过，这里再静态核一遍）
    old_calls = len(re.findall(r"ns_read_mountinfo_pid\([^;]*NS_MOUNTINFO_MAX", impl))
    failures += check("P7_no_legacy_fixed_capacity_calls", old_calls == 0, f"found={old_calls}")

    # 状态判定：读不到不得返回 NORMAL
    status = impl.find("int ns_global_status(")
    status_body = impl[status:status + 2000]
    failures += check("P8_status_returns_unknown_on_read_failure",
                      "if (n < 0)" in status_body and
                      status_body.count("NSP_GLOBAL_STATUS_UNKNOWN") >= 2)

    # 备份点：读不到不得返回「未挂载可新建」
    backup = impl.find("int ns_backup_point_state(")
    backup_body = impl[backup:backup + 900]
    failures += check("P9_backup_state_has_unknown_value",
                      "NS_BACKUP_UNKNOWN" in backup_body)

    # 不完整读取必须整份作废：先 free 再按未知返回，且不得把部分条目交出去；
    # 也禁止「跳过这一行继续」的写法（顺序/条数都对得上，看起来完全正常）
    trunc = impl.find("if (c.nomem || st.truncated)")
    failures += check("P13_truncated_invalidates_whole_result",
                      trunc >= 0 and
                      impl.find("free(c.out);", trunc) > trunc and
                      impl.find("return -1;", trunc) > trunc and
                      impl.find("*out = c.out;") > impl.find("return -1;", trunc))
    failures += check("P14_no_skip_and_continue_on_truncation",
                      "if (st.truncated) continue" not in impl and
                      "if (st.truncated) break" not in impl)

    # mount_manager：挂载状态读取无上限（max_size=0），且失败一律不当「未挂载」
    failures += check("P10_mount_state_read_is_unbounded",
                      "read_file_dynamic(path, &nread, 0)" in mm)
    callers = re.findall(r"read_mount_state\(([^;]*)\);", mm)
    checked = len(re.findall(r"if \(!read_mount_state\(", mm))
    failures += check("P11_every_call_site_checks_read_result",
                      checked == len(callers) and checked >= 4,
                      f"callers={len(callers)} checked={checked}")
    failures += check("P12_mount_state_has_no_fixed_line_buffer",
                      "char line[4096]" not in mm)
    return failures


def main():
    failures = run_driver()
    failures += run_contracts()
    print(f"===== total_failures={failures} =====")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
