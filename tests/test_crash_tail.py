#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""崩溃诊断只取「本次 daemon 启动之后」的 fuse_crash.log（crash_tail + injector）

背景：fuse_crash.log 是 append 打开的长期文件，每次 fuse_daemon 启动都接着往里写。
诊断原先摊尾部固定 16KB，把上一轮启动残留的 linker 报错当成「本次崩溃主因」，现场
据此误判死因。

修复后的契约（本套件守护的就是这几条）：
  1. 窗口锚在「本次启动时的文件大小」上，只读这个偏移之后的内容；
  2. 起点不可信（stat 失败 / 文件被截断）时退回尾部，但要丢掉可能残掉的首行；
  3. 本次启动后没有新增时不摊旧内容，只报「无新增输出」；
  4. 启动时的大小必须在 fork 之前取，子进程只 dup2 不重新打开文件。

分层：A 段直编 src/core/crash_tail.c（纯函数，L0 无挂载无特权）；B 段静态契约锁住
injector.c 的取点时机与调用点，防止退回「尾部固定字节」。

判别性：旧实现（尾部固定 cap）会让驱动 A2、A11 失败；把「无新增」当可读会让 A3
失败；在子进程里重新 open 会让 C3/C4 失败。

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
DRIVER = ROOT / "tests" / "fixtures" / "crash_tail_driver.c"
SRC = ROOT / "src" / "core" / "crash_tail.c"
HDR = ROOT / "include" / "crash_tail.h"
INJECTOR = ROOT / "src" / "injector" / "injector.c"
INJECTOR_HDR = ROOT / "include" / "injector.h"


def read(path):
    return path.read_text(encoding="utf-8")


def run_driver():
    if not DRIVER.is_file() or not SRC.is_file():
        print(f"缺少 fixture 驱动或源码（{DRIVER} / {SRC}）", file=sys.stderr)
        return 1
    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="crash_tail_") as tmp:
        exe = Path(tmp) / "crash_tail_driver"
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
    inj = read(INJECTOR)
    hdr = read(INJECTOR_HDR)
    impl = read(SRC)

    failures += check("C1_header_declares_window", "bool crash_tail_window(" in read(HDR))
    failures += check("C2_injector_uses_window_helper",
                      "crash_tail_window(" in inj and '#include "crash_tail.h"' in inj)

    # 启动时的大小必须记在父进程、fork 之前：子进程只能 dup2 已打开的 fd
    opens = [m.start() for m in re.finditer(r'open\(LOG_DIR "/fuse_crash\.log"', inj)]
    forks = [m.start() for m in re.finditer(r"= fork\(\);", inj)]
    failures += check("C3_crash_log_opened_once_per_spawn", len(opens) == 2, f"found={len(opens)}")
    before = all(any(f > o and f - o < 3000 for f in forks) for o in opens)
    failures += check("C4_open_happens_before_fork", before and len(forks) >= 2,
                      f"opens={len(opens)} forks={len(forks)}")

    starts = inj.count("crash_log_start = crash_st.st_size")
    failures += check("C5_start_offset_recorded_from_fstat", starts == 2, f"found={starts}")
    failures += check("C6_start_offset_defaults_unknown",
                      inj.count("crash_log_start = -1;") == 2,
                      f"found={inj.count('crash_log_start = -1;')}")
    failures += check("C7_struct_carries_offset",
                      re.search(r"off_t\s+crash_log_start;", hdr) is not None)

    # 调用点全部带上起点，不得再有零参调用
    zero = len(re.findall(r"dump_crash_log_tail\(\)", inj))
    with_arg = len(re.findall(r"dump_crash_log_tail\(g_global_fuse\.crash_log_start\)", inj))
    failures += check("C8_dump_calls_pass_start_offset", zero == 0 and with_arg >= 4,
                      f"zero={zero} with_arg={with_arg}")

    body = inj[inj.find("static void dump_crash_log_tail(off_t run_start)"):]
    body = body[:body.find("\n}\n") + 3]
    failures += check("C9_dump_reports_empty_window",
                      "本次守护进程启动后 fuse_crash.log 无新增输出" in body)
    failures += check("C10_dump_header_marks_window", "仅本次启动后" in body)
    failures += check("C11_dump_drops_partial_first_line", "drop_first_line" in body)

    # 纯函数本身：不可信起点必须标记丢首行
    failures += check("C12_untrusted_start_flags_partial_line",
                      "out->drop_first_line = (from > 0);" in impl)

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
