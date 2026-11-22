#!/usr/bin/env python3
"""L0: 配置发布窗口里的读者必须阻塞等待，不得自旋烧 CPU。

场景（生产等价）：一个读者仍占着旧代际读槽，写者已把 g_cfg_gen 置奇、正等它
排空；此时 8 个 FUSE worker 调 config_read_begin。旧实现是 sched_yield 自旋——
它们把 CPU 从写者正在等的那个慢读者手里抢走，慢读者更慢、窗口更长（自旋放大）。
新实现是 futex 等待 + 发布放行唤醒，判据仍只有 g_cfg_gen。

断言：
  1) 每个读者的线程 CPU < 20ms（实测新 ≤1ms，旧约 66ms）；
  2) 采样窗口的进程 CPU < 120ms（新约 3-5ms，旧约 207ms）；
  3) 读者确实被挡住（max_reader_wait_ms >= 100，慢读者持槽 150ms）；
  4) 放行后 50ms 内返回（唤醒不漏，语义不变）。

CFG_WAIT_SRC 指向旧 config_parser.c（`git show HEAD:src/config/config_parser.c`
的副本）做判别；CFG_WAIT_OUTPUT_DIR 保留编译产物与运行日志。
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "tests/fixtures/config_read_wait_driver.c"
SOURCES = ["src/config/config_parser.c", "src/config/path_vars.c", "src/core/path_trie.c",
           "src/core/nsp_util.c", "src/core/nsp_comm.c", "src/core/common.c",
           "src/core/sys_pkg.c"]
LIMIT_READER_CPU_MS = 20   # 读者在窗口里的线程 CPU 上限
LIMIT_WINDOW_CPU_MS = 120  # 60ms 采样窗口的进程 CPU 上限（自旋时 8 线程×窗口）
MIN_WAIT_MS = 100          # 慢读者持槽 150ms，读者必须真的等到快结束
MAX_LAG_MS = 50            # 放行后返回延迟：futex 唤醒不得丢
MIN_DRAIN_WALL_MS = 50     # 排空真的等到了慢读者（否则写者 CPU 断言无意义）
LIMIT_DRAIN_CPU_MS = 20    # 写者排空期间烧的 CPU（新 ~0-3ms，旧自旋 ≈ 窗口长度）


def main():
    out = os.environ.get("CFG_WAIT_OUTPUT_DIR")
    work = Path(out) if out else Path(tempfile.mkdtemp(prefix="cfg-wait-"))
    work.mkdir(parents=True, exist_ok=True)
    exe = work / "config_read_wait"
    sources = [str(ROOT / s) for s in SOURCES]
    override = os.environ.get("CFG_WAIT_SRC")
    if override:
        sources[0] = str(Path(override).resolve())
    build = subprocess.run(["cc", "-std=gnu2x", "-O2", "-pthread", "-I", str(ROOT / "include"),
                            "-o", str(exe), str(DRIVER)] + sources,
                           capture_output=True, text=True)
    (work / "build.log").write_text(build.stdout + build.stderr, encoding="utf-8")
    if build.returncode != 0:
        print("❌ 编译失败（日志 %s/build.log）：" % work)
        print((build.stdout + build.stderr)[-2000:])
        return 1
    try:
        run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print("❌ 运行超时 120s（读者可能永远等不到放行）")
        return 1
    (work / "run.log").write_text(run.stdout + run.stderr, encoding="utf-8")
    if run.returncode != 0:
        print("❌ 运行失败 rc=%d：%s" % (run.returncode, (run.stdout + run.stderr)[-500:]))
        return 1
    m = re.search(r"readers=(\d+) window_cpu_ms=(-?\d+) max_reader_cpu_ms=(-?\d+) "
                  r"max_reader_wait_ms=(-?\d+) max_return_lag_ms=(-?\d+) "
                  r"drain_wall_ms=(-?\d+) drain_cpu_ms=(-?\d+)", run.stdout)
    if not m:
        print("❌ 输出无法解析：%r" % run.stdout[-500:])
        return 1
    readers, window_cpu, reader_cpu, wait_ms, lag, drain_wall, drain_cpu = (int(x) for x in m.groups())
    print("readers=%d window_cpu_ms=%d max_reader_cpu_ms=%d max_reader_wait_ms=%d "
          "max_return_lag_ms=%d drain_wall_ms=%d drain_cpu_ms=%d"
          % (readers, window_cpu, reader_cpu, wait_ms, lag, drain_wall, drain_cpu))
    fails = 0
    if readers <= 0:
        print("❌ 读者线程数异常：%d" % readers)
        fails += 1
    if wait_ms < MIN_WAIT_MS:
        print("❌ 读者没有被写者窗口挡住（max_reader_wait_ms=%d < %d）：场景没成立，断言无意义"
              % (wait_ms, MIN_WAIT_MS))
        fails += 1
    if reader_cpu >= LIMIT_READER_CPU_MS:
        print("❌ 读者在写者窗口里自旋烧 CPU：%dms（期望 < %dms；旧实现约 60-70ms）"
              % (reader_cpu, LIMIT_READER_CPU_MS))
        fails += 1
    if window_cpu >= LIMIT_WINDOW_CPU_MS:
        print("❌ 采样窗口进程 CPU %dms（期望 < %dms；自旋实现约 200ms）"
              % (window_cpu, LIMIT_WINDOW_CPU_MS))
        fails += 1
    if lag > MAX_LAG_MS:
        print("❌ 放行后返回延迟 %dms（期望 <= %dms）：唤醒丢了或判据没跟上"
              % (lag, MAX_LAG_MS))
        fails += 1
    if drain_wall < MIN_DRAIN_WALL_MS:
        print("❌ 写者排空只等了 %dms（期望 >= %dms）：场景没成立，CPU 断言无意义"
              % (drain_wall, MIN_DRAIN_WALL_MS))
        fails += 1
    if drain_cpu >= LIMIT_DRAIN_CPU_MS:
        print("❌ 写者排空烧了 %dms CPU（期望 < %dms；旧实现自旋 ≈ 整个窗口）"
              % (drain_cpu, LIMIT_DRAIN_CPU_MS))
        fails += 1
    if fails:
        print("配置读槽等待测试失败：%d 项（证据 %s）" % (fails, work))
        return 1
    print("配置读槽等待测试通过 ✔（证据 %s）" % work)
    return 0


if __name__ == "__main__":
    sys.exit(main())
