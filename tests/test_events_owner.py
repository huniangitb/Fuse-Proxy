#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""事件通道归属：固定给全局实例，且失败可查（fw_events + fuse_daemon + log_ctl）

背景：nsp_fs_events / nsp_fs_query 是抽象命名空间的 UDS，内核对名字唯一——谁先 bind
谁收订阅。全局实例与媒体实例都调 fw_events_start()，归属由启动竞态决定：输的那条
实例的应用事件一条也发不出去，外部表现只是「事件功能随机全哑」，且只有一条 WARN
滚在日志里，事后无法查。

修复后的契约（本套件守护的就是这几条）：
  1. 媒体实例不参与事件通道，归属固定给全局实例；
  2. 任何一步失败（含 bind）都写 log/events_socket.status，log_ctl 能读到；
  3. 归属可从 /proc 实测（谁绑着这个名字），log_ctl events 给出持有者与处置提示。

分层：A 段直编 src/core/nsp_events_status.c（纯状态机 + 采集边界，L0）；B 段静态契约
锁住 daemon 的归属固定、状态文件落盘、名字常量单一来源与 log_ctl 的接线。

判别性：把媒体实例的早退删掉会让 B1 失败；失败不写状态文件会让 B2/B3 失败；名字
退回两处字面量会让 B4 失败；实例判定退回「命令行里出现 fuse_daemon」，驱动 C3/C6/C9
会失败（用户敲 pidof fuse_daemon 的当下会多算一个全局实例），B15 也会失败。

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
DRIVER = ROOT / "tests" / "fixtures" / "events_status_driver.c"
SRC = ROOT / "src" / "core" / "nsp_events_status.c"
FW_EVENTS = ROOT / "src" / "daemon" / "fw_events.c"
DAEMON = ROOT / "src" / "daemon" / "fuse_daemon.c"
LOG_CTL = ROOT / "src" / "log" / "log_ctl.c"
CONSTANTS = ROOT / "include" / "nsp_constants.h"
MESON = ROOT / "meson.build"


def read(path):
    return path.read_text(encoding="utf-8")


def run_driver():
    if not DRIVER.is_file() or not SRC.is_file():
        print(f"缺少 fixture 驱动或源码（{DRIVER} / {SRC}）", file=sys.stderr)
        return 1
    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="events_status_") as tmp:
        exe = Path(tmp) / "events_status_driver"
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
            "-I", str(ROOT / "include"),
            str(DRIVER), str(SRC),
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
    daemon = read(DAEMON)
    fw = read(FW_EVENTS)
    lc = read(LOG_CTL)
    const = read(CONSTANTS)
    meson = read(MESON)
    impl = read(SRC)

    # B1：媒体实例不建立事件通道，归属固定
    guard = daemon.find("if (g_is_media_fuse)")
    start = daemon.find("fw_events_start()")
    failures += check("B1_media_instance_skips_event_channel",
                      0 <= guard < start and "媒体实例不建立事件通道" in daemon,
                      f"guard={guard} start={start}")
    failures += check("B2_global_instance_still_starts_channel",
                      "fw_events_start() != 0" in daemon)

    # B3：失败与成功都落状态文件，失败带阶段名与 errno
    failures += check("B3_failure_recorded_to_status_file",
                      "events_socket.status" in fw and "fw_events_record_result(false" in fw)
    failures += check("B4_success_clears_stale_failure",
                      "fw_events_record_result(true, NULL, 0)" in fw)
    stages = len(re.findall(r'stage = "', fw))
    failures += check("B5_failure_stages_are_named", stages >= 8, f"stages={stages}")
    failures += check("B6_record_carries_errno",
                      "errno=%d" in fw and "saved_errno" in fw)

    # B7：socket 名字单一来源（两处字面量不一致会让 log_ctl 查空）
    bind_uses_macro = (fw.count("nsp_uds_abstract_addr(&addr, FW_EVENTS_SOCK_NAME)") == 1 and
                       fw.count("nsp_uds_abstract_addr(&addr, FW_QUERY_SOCK_NAME)") == 1)
    failures += check("B7_socket_name_comes_from_constants",
                      bind_uses_macro and
                      "#define FW_EVENTS_SOCK_NAME NSP_EVENTS_SOCK_NAME" in fw and
                      "#define FW_QUERY_SOCK_NAME NSP_EVENTS_QUERY_SOCK_NAME" in fw and
                      'nsp_uds_abstract_addr(&addr, "' not in fw)
    failures += check("B8_constants_define_both_names",
                      '#define NSP_EVENTS_SOCK_NAME "nsp_fs_events"' in const and
                      '#define NSP_EVENTS_QUERY_SOCK_NAME "nsp_fs_query"' in const)

    # B9：log_ctl 能查（子命令 + status 块 + 处置提示）
    failures += check("B9_log_ctl_has_events_subcommand",
                      'strcmp(pos_args[0], "events")' in lc and "handle_events(" in lc)
    failures += check("B10_log_ctl_reports_owner_and_state",
                      "nsp_events_state(" in lc and "nsp_events_hint(" in lc and
                      "nsp_events_status_collect(" in lc)
    status = lc.find("static void handle_status(")
    status_body = lc[status:status + 4000] if status >= 0 else ""
    failures += check("B11_status_block_includes_events",
                      "nsp_events_status_collect(" in status_body)

    # B12：归属判定不写死本机路径，全部经 NSP_LOG_DIR / 入参
    failures += check("B12_no_hardcoded_log_dir",
                      "/var/fuse-proxy" not in impl and "/data/Namespace-Proxy" not in impl)

    # B14：实例判定只认 argv[0]（命令行里提到 fuse_daemon 的 shell 不算实例）
    hdr = read(ROOT / "include" / "nsp_events_status.h")
    collect = impl.find("static int collect_daemons(")
    collect_body = impl[collect:collect + 1200] if collect >= 0 else ""
    failures += check("B14_classifier_is_pure_and_declared",
                      "NspEventsOwner nsp_events_classify_cmdline(const char* cmd);" in hdr and
                      "NspEventsOwner nsp_events_classify_cmdline(const char* cmd) {" in impl)
    failures += check("B15_collect_uses_classifier",
                      "nsp_events_classify_cmdline(cmd)" in collect_body and
                      'strstr(cmd, "fuse_daemon")' not in impl)
    failures += check("B16_classifier_requires_argv0_basename",
                      "while (*end && *end != ' ')" in impl and
                      "if (*p == '/') base = p + 1;" in impl and
                      "len != sizeof(kName) - 1" in impl)

    # B13：新源文件进公共对象，injector / daemon / log_ctl 才都能用
    failures += check("B13_sources_in_common_objects",
                      "src/core/nsp_events_status.c" in meson and
                      "src/core/crash_tail.c" in meson)

    return failures


def main():
    rc = run_driver()
    failures = run_contracts()
    if failures:
        print(f"\n静态契约失败 {failures} 条")
        return 1
    return 0 if rc == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
