#!/usr/bin/env python3
"""
追踪表并发遍历回归测试（A25）
=============================
`inject_target.c` 的 `g_tracked_hash` 是**跨线程共享**的链表哈希表：
`add_tracked` / `mark_injected` / `unmark_injected` / `remove_tracked` /
`prune_stale_tracked` 都持 `g_tracked_mutex`，而下面五条**遍历**路径却全程不持锁：

  - `force_recover_tracked_mounts()`   （退出前逐应用还原 + 整表释放）
  - `audit_tracked_apps()`             （配置审查）
  - `audit_and_remount_specific_apps()`（局部规则变动审查）
  - `handle_list_injected()`           （list-injected 查询）
  - `get_injected_snapshot()`          （快照查询）

裸遍历 + 并发摘链的失效模式：游标 `pp`/`e` 此刻指向节点 X 的 `next` 字段，
另一线程把**更早访问过的节点**摘掉并 free，游标仍指向那个已释放节点内部的
`next` 槽 → `pp = &(*pp)->next` 读到悬垂地址 → 下一次迭代 `(*pp)->pid`
即 heap-use-after-free。同一根因还使这些路径无法直接补锁：它们会调
`cleanup_app_mounts` / `perform_app_mount`，那两个函数内部**再取**
`g_tracked_mutex`，持锁遍历必自锁。故修法是「锁内快照 pid → 锁外处理」。

判别手段（直编 + ASan，无需 root/挂载）：
  直编 `src/injector/inject_target.c`（其余依赖以桩替代），两个钩子精确制造
  「访问到链首时摘掉已访问过的节点」这一时序：
    - `proc_get_cmdline` 桩覆盖 audit_* 两条路径；
    - `--wrap=kill` 包装覆盖 force_recover（该路径不查 cmdline）。
  旧实现必报 heap-use-after-free；新实现无报告且摘除照常生效。

前置：本机 `cc`（需支持 -fsanitize=address 与 -Wl,--wrap）。
失败退出码 1（勿用管道吞掉退出码）。
"""
import os
import shlex
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.environ.get("INJECT_TARGET_SRC") or os.path.join(
    ROOT, "src", "injector", "inject_target.c")
DRIVER = os.path.join(ROOT, "tests", "fixtures", "inject_target_tracked_race_driver.c")
INCLUDES = [os.path.join(ROOT, "include"), os.path.join(ROOT, "src", "core")]

RUN_TIMEOUT = 120


def main():
    for path in (SRC, DRIVER):
        if not os.path.exists(path):
            print(f"缺少源文件 {path}", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory(prefix="inj_track_race_") as tmpdir:
        exe = os.path.join(tmpdir, "tracked_race")
        cmd = [
            *shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Wno-unused-parameter",
            "-fsanitize=address", "-fno-omit-frame-pointer",
        ]
        for inc in INCLUDES:
            cmd += ["-I", inc]
        cmd += [
            DRIVER, SRC,
            "-Wl,--wrap=kill",
            "-o", exe,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("C 编译/链接失败:", file=sys.stderr)
            print(r.stderr, file=sys.stderr)
            return 1
        if r.stderr.strip():
            print(r.stderr, file=sys.stderr, end="")
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        try:
            run = subprocess.run([exe], capture_output=True, text=True,
                                 timeout=RUN_TIMEOUT, env=env)
        except subprocess.TimeoutExpired:
            print(f"驱动超时（>{RUN_TIMEOUT}s）：疑似遍历挂死", file=sys.stderr)
            return 1
        print(run.stdout, end="")
        if run.stderr.strip():
            print(run.stderr, file=sys.stderr, end="")
        # ASan 报告（UAF 等）与驱动自身判定都必须为零
        if run.returncode != 0 or "RESULT OK" not in run.stdout:
            print("追踪表并发遍历测试失败", file=sys.stderr)
            return 1
    print("追踪表并发遍历测试通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
