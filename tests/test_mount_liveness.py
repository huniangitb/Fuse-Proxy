#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""已挂载视图的连接活性判据（ns_mount_health）与启动扫描接线的回归

背景：daemon 退出后 mountinfo 里的 FUSE 条目仍在（内核只把 superblock 标成断开），
所以「目标挂着项目 FUSE」说明不了「视图还能用」。injector 重启不会重建已注入应用
命名空间里的旧挂载——那些进程此后每次访问存储都拿到 ENOTCONN，只能靠杀应用进程或
重启设备恢复（真机现场：「杀模块进程没用、只能重启」）。修复由两处组成：
  1. `src/injector/ns_mount_health.c` 给出连接活性判据（statfs 探测）；
  2. injector 启动时扫一遍（repair_stale_app_mounts_at_startup），注入前也先查一次。

分层：
  A 段（直编 + --wrap=statfs，L0）：判据矩阵与「没有项目挂载时一次探测都不做」；
  B 段（静态契约，L0）：调用点必须同时要求 target_fuse_unverified 与判据、启动扫描
     只在 FUSE 就绪后跑一次且 v2/v3 直接返回、探测原语不得换成会被属性缓存骗过的 stat。

判别性：旧实现没有这套判据（「条目在」= 直接跳过挂载），A 段无从成立；删掉
has_project_fuse 早退 → A2 失败；把 start 扫描从就绪分支挪走 → B 段失败。

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
DRIVER = ROOT / "tests" / "fixtures" / "mount_liveness_driver.c"
SOURCE = os.environ.get("NS_MOUNT_HEALTH_SRC") or str(
    ROOT / "src" / "injector" / "ns_mount_health.c")

MOUNT_MANAGER = ROOT / "src" / "injector" / "mount_manager.c"
INJECTOR = ROOT / "src" / "injector" / "injector.c"
NS_UTILS_H = ROOT / "include" / "ns_utils.h"
MOUNT_MANAGER_H = ROOT / "include" / "mount_manager.h"


def read(path):
    return path.read_text(encoding="utf-8")


def run_driver():
    if not DRIVER.is_file() or not Path(SOURCE).is_file():
        print(f"缺少 fixture 驱动或源码（{DRIVER} / {SOURCE}）", file=sys.stderr)
        return 1
    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="mount_liveness_") as tmp:
        exe = Path(tmp) / "mount_liveness_driver"
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
            "-I", str(ROOT / "include"),
            str(DRIVER), SOURCE,
            "-Wl,--wrap=statfs",
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
    print(f"case={name:<46} ok={1 if ok else 0} {detail}")
    return 0 if ok else 1


def run_contracts():
    failures = 0
    health = read(Path(SOURCE))
    mm = read(MOUNT_MANAGER)
    inj = read(INJECTOR)
    hdr = read(NS_UTILS_H)
    mm_hdr = read(MOUNT_MANAGER_H)

    # 探测原语只允许 statfs：stat/getattr 会被 FUSE 的 inode 属性缓存挡住，
    # 连接断开后仍可能命中旧值而误判为健康
    failures += check("P1_probe_uses_statfs", "statfs(" in health)
    failures += check("P2_probe_avoids_cached_attr_calls",
                      not re.search(r"\b(statx|fstat|fstatat|stat)\s*\(", health))

    failures += check("P3_header_declares_probe",
                      "int ns_mount_conn_state(" in hdr)
    failures += check("P4_header_declares_repair_predicate",
                      "bool ns_mount_needs_repair(" in hdr)
    failures += check("P5_header_declares_startup_scan",
                      "int repair_stale_app_mounts_at_startup(void)" in mm_hdr)

    # 调用点：两条挂载路径都必须以「条目在 + 未验证」为前提才探测
    sites = len(re.findall(r"ns_mount_needs_repair\(", mm))
    failures += check("P6_two_mount_paths_plus_scan_call_repair", sites == 3, f"sites={sites}")
    failures += check("P7_repair_requires_unverified_state",
                      mm.count("mnt.target_fuse_unverified &&") == 2)
    guard = mm.find("ns_mount_needs_repair(")
    skip = mm.find("已经存在程序自身的 FUSE 挂载")
    failures += check("P8_repair_precedes_skip_branch", 0 <= guard < skip)

    # 启动扫描：v2/v3 不适用（emulated 由全局替换提供）
    scan = mm.find("int repair_stale_app_mounts_at_startup(void)")
    failures += check("P9_startup_scan_skips_global_replace",
                      scan >= 0 and "inject_is_global_replace()" in mm[scan:scan + 400])

    # 接线：FUSE 就绪分支里跑一次；启动时置位
    failures += check("P10_ready_handler_runs_startup_scan",
                      inj.find("repair_stale_app_mounts_at_startup()") >
                      inj.rfind("g_fuse_ready = 1;"))
    failures += check("P11_scan_armed_at_startup",
                      inj.count("g_pending_startup_scan = 1;") == 1)
    failures += check("P12_scan_consumed_once",
                      inj.count("if (g_pending_startup_scan)") == 1)

    # 崩溃恢复重挂的耗时与条数：现场只能看到「开始/完成」两行时无法区分
    # 「重挂很快、卡在别处」和「重挂本身慢」，所以完成行必须带条数与毫秒
    remount = inj.find("static void remount_all_tracked() {")
    body = inj[remount:remount + 1200] if remount >= 0 else ""
    failures += check("P13_recovery_timer_is_monotonic",
                      body.count("clock_gettime(CLOCK_MONOTONIC") == 2)
    failures += check("P14_recovery_finish_logs_count_and_ms",
                      "FUSE 崩溃恢复重挂完成: 重挂 %d 个（用时 %ldms）" in body)
    ok_site = inj.find('perform_app_mount(pkg, pid, uid, mnt_src, "FUSE崩溃恢复重挂") == 0')
    failures += check("P15_recovery_counts_only_success",
                      0 <= ok_site and "g_remount_done++;" in inj[ok_site:ok_site + 200])
    return failures


def main():
    failures = run_driver()
    failures += run_contracts()
    print(f"===== total_failures={failures} =====")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
