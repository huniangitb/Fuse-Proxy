#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nsp_rule_file 跨进程编辑回归（读-改-写串行化 + 唯一临时名 + 落盘持久化）

背景：rule_server 与 log_ctl 都走 nsp_rule_file 编辑规则文件，编辑动作本身是
「读全文件 → 改内存 → tmp+rename 覆盖写」。缺跨进程串行化时，两个编辑者读到同一份
内容再各自写回，后写者的 rename 会吃掉前者的修改（丢更新）；临时名固定为
`<path>.tmp` 时，并发写者还会互相 rename 掉对方尚未写完的临时文件。

本套件直编 src/core/nsp_rule_file.c，起 4 个子进程各 upsert 150 条互不相同的规则，
断言最终恰好 600 条且无重复；去掉目录 flock 后实测只剩约 200 条（确定性失败）。
写入路径另做：文件内容 fsync + rename + 目录 fsync（掉电后 rename 不会指向旧内容）。

另含三组判别：
  A10 —— 文件 chmod 000 后 upsert 必须返回 EIO 且原文件逐字不动（旧实现把读失败的
         NULL 当空文件，写回「段头+1 条」把原规则全丢）；以 root 运行时跳过（gap）。
  A6/C6 —— **全部**公共编辑入口必须共用同一把目录 flock：另起进程持锁不放，断言
         手工「读改写」形态立即返回，而 upsert_line / upsert_in_section /
         remove_nth / remove_nth_scoped / toggle_nth_scoped 逐个阻塞到放行。
  C6  —— 公共 API 面不得再暴露无锁写入口：探针引用 nsp_rule_file_write 编译——
         旧实现暴露该符号、可自行拼出不持锁的读改写（探针编译成功 → 本组失败）；
         新实现已将其下沉为内部 static（未声明 → 探针编译失败 → 通过）。

前置：本机 cc。失败退出码 1（勿用管道吞掉退出码）。
"""

import os
import shlex
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(ROOT, "tests", "fixtures", "rule_file_lock_test.c")
SOURCES = [
    os.path.join(ROOT, "src", "core", "nsp_rule_file.c"),
    os.path.join(ROOT, "src", "core", "nsp_util.c"),
]
RUN_TIMEOUT = 120


def probe_no_public_write(tmpdir, include_dir):
    """C6 判别：公共 API 面不得再暴露无锁写入口。

    旧实现暴露 nsp_rule_file_write，调用方可自行拼「读全文→改一行→write」而绕过
    目录 flock（fixture 的 old_shape_toggle 正是这一形态）→ 探针能编译 → 本组失败；
    新实现将其下沉为内部 static → 头文件里无声明，探针编译失败 → 通过。
    返回 (已撤下?, 编译器 stderr)。"""
    src = os.path.join(tmpdir, "probe_public_write.c")
    with open(src, "w", encoding="utf-8") as f:
        f.write('#include "nsp_rule_file.h"\n'
                'int main(void) { void* p = (void*)nsp_rule_file_write; return p == 0; }\n')
    obj = os.path.join(tmpdir, "probe_public_write.o")
    cmd = [
        *shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
        "-Werror=implicit-function-declaration",
        "-I", include_dir, "-c", src, "-o", obj,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode != 0, r.stderr


def main():
    for path in [DRIVER] + SOURCES:
        if not os.path.exists(path):
            print(f"缺少源文件 {path}", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory(prefix="rulelock_build_") as tmpdir:
        exe = os.path.join(tmpdir, "rule_file_lock_test")
        cmd = [
            *shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Wno-unused-parameter",
            "-I", os.path.join(ROOT, "include"),
            DRIVER, *SOURCES, "-o", exe,
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
            print(f"规则文件并发编辑测试超时（>{RUN_TIMEOUT}s）", file=sys.stderr)
            return 1
        no_public_write, probe_err = probe_no_public_write(tmpdir, os.path.join(ROOT, "include"))
    print(run.stdout, end="")
    if no_public_write:
        print("PASS C6 公共 API 面已撤下无锁写入口（nsp_rule_file_write 不可见）")
    else:
        print("FAIL C6 公共 API 面仍暴露 nsp_rule_file_write——调用方可拼出不持锁的读改写",
              file=sys.stderr)
        print(probe_err, file=sys.stderr, end="")
        return 1
    if run.returncode == 78:
        print("跳过项（gap，不计通过）: A10 读失败不覆盖（以 root 运行）", file=sys.stderr)
        return 78
    if run.returncode != 0:
        print("规则文件并发编辑测试失败", file=sys.stderr)
        return 1
    print("规则文件并发编辑测试通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
