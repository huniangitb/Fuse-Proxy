#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FUSE worker 线程数：按核数取默认，但可配置覆盖
=====================================================
libfuse 多线程 loop 自身默认 10 个 worker，项目长期固定 2 个。2 个在「单个应用
冷启动」这种成百上千次并发 getattr/open/read 的窗口里容易排队；而按核数一把梭
在 4 核低端机上是让线程互抢 CPU。默认取 min(max(2, ncpu/2), 8)：4 核→2、
6 核→3、8 核→4、16 核→8。

判别方式：把 `nsp_default_fuse_threads()` 从 include/fuse_threads.h 原样抽出编译，
用核数表判定（把下限写成 1 或上限写成 16，对应格立刻失败）。静态契约钉住：
daemon 未显式指定时才取默认、显式值仍保留 0=单线程 / -1=libfuse 默认、注入器
按 [GLOBAL] FUSE_THREADS 下发、配置解析器接受该键、文档有该键。

退出码：0 通过、1 失败、77 缺编译器（整套跳过）。
"""
import os
import shlex
import shutil
import subprocess
import sys
import tempfile

SKIP_RC = 77
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HEADER = os.path.join(ROOT, "include", "fuse_threads.h")
DAEMON = os.path.join(ROOT, "src", "daemon", "fuse_daemon.c")
INJECTOR = os.path.join(ROOT, "src", "injector", "injector.c")
CONFIG = os.path.join(ROOT, "src", "config", "config_parser.c")
CONFIG_H = os.path.join(ROOT, "include", "config_parser.h")
DOC = os.path.join(ROOT, "docs", "config.md")

CASES = [(0, 2), (1, 2), (2, 2), (3, 2), (4, 2), (6, 3), (8, 4), (12, 6), (16, 8), (32, 8)]

MAIN = r'''
#include <stdbool.h>
#include <stdio.h>

static int g_fail;

int main(void) {
    struct { int ncpu; int want; } cases[] = {
__CASES__
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int got = nsp_default_fuse_threads(cases[i].ncpu);
        printf("case=ncpu=%-3d got=%-2d want=%-2d\n", cases[i].ncpu, got, cases[i].want);
        if (got != cases[i].want) g_fail++;
    }
    if (g_fail) { printf("total_failures=%d\n", g_fail); return 1; }
    printf("all cases passed\n");
    return 0;
}
'''


def read(path):
    with open(path, encoding="utf-8") as fp:
        return fp.read()


def extract_function(text, start_marker, end_marker="\n}\n"):
    start = text.find(start_marker)
    if start < 0:
        return None
    end = text.find(end_marker, start)
    if end < 0:
        return None
    return text[start:end + 3]


def check(name, ok, detail=""):
    print(f"case={name:<46} ok={1 if ok else 0} {detail}")
    return 0 if ok else 1


def run_driver():
    cc = shlex.split(os.environ.get("CC") or shutil.which("cc") or "")
    if not cc:
        print("缺少 C 编译器，跳过", file=sys.stderr)
        return SKIP_RC
    if not os.path.isfile(HEADER):
        print(f"缺少 {HEADER}", file=sys.stderr)
        return 1
    fn = extract_function(read(HEADER), "static inline int nsp_default_fuse_threads(int ncpu) {")
    if not fn:
        print("fuse_threads.h 里找不到 nsp_default_fuse_threads()", file=sys.stderr)
        return 1
    cases = "\n".join(f"        {{ {n}, {w} }}," for n, w in CASES)
    source = "#include <stddef.h>\n" + fn + "\n" + MAIN.replace("__CASES__", cases)
    with tempfile.TemporaryDirectory(prefix="fuse_threads_") as tmp:
        src = os.path.join(tmp, "fuse_threads_driver.c")
        exe = os.path.join(tmp, "fuse_threads_driver")
        with open(src, "w", encoding="utf-8") as fp:
            fp.write(source)
        build = subprocess.run(cc + ["-std=c23", "-O1", "-o", exe, src],
                               capture_output=True, text=True)
        if build.returncode != 0:
            print("编译失败：\n" + build.stderr, file=sys.stderr)
            return 1
        run = subprocess.run([exe], capture_output=True, text=True)
        sys.stdout.write(run.stdout)
        if run.stderr:
            sys.stderr.write(run.stderr)
        return run.returncode


def run_contracts():
    failures = 0
    daemon = read(DAEMON)
    injector = read(INJECTOR)
    config = read(CONFIG)
    config_h = read(CONFIG_H)
    doc = read(DOC)

    failures += check("T1_daemon_uses_helper_when_not_explicit",
                      '#include "fuse_threads.h"' in daemon and
                      "if (!g_fuse_threads_explicit)" in daemon and
                      "nsp_default_fuse_threads((int)sysconf(_SC_NPROCESSORS_ONLN))" in daemon)
    failures += check("T2_explicit_flag_set_on_arg",
                      "g_fuse_threads_explicit = true;" in daemon)
    failures += check("T3_daemon_logs_resolved_count",
                      "按核数自动" in daemon and "线程（显式）" in daemon)
    failures += check("T4_injector_passes_config_value",
                      'snprintf(threads_arg, sizeof threads_arg, "--fuse-threads=%d",' in injector and
                      "g_global_cfg.fuse_threads != 0" in injector)
    failures += check("T5_config_parser_accepts_key",
                      'strcmp(tok, "FUSE_THREADS") == 0' in config and
                      "parse_fuse_threads_rule(cur, p_ptr, line_num, file_path)" in config and
                      "cur->fuse_threads = (int)n;" in config)
    failures += check("T6_config_field_declared",
                      "int fuse_threads;" in config_h and
                      "FUSE_THREADS <n>" in config_h)
    failures += check("T7_docs_describe_key",
                      "FUSE_THREADS" in doc and "ncpu" in doc)
    failures += check("T8_single_thread_and_libfuse_defaults_kept",
                      "g_fuse_threads == 0" in daemon and "g_fuse_threads == -1" in daemon)
    return failures


def main():
    rc = run_driver()
    if rc == SKIP_RC:
        return SKIP_RC
    failures = run_contracts()
    if failures:
        print(f"\n静态契约失败 {failures} 条")
        return 1
    return 0 if rc == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
