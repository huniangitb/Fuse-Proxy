#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""配置重载的 inotify 过滤：只认 .conf 结尾，并且窗口足够宽
================================================================
CONFIG_DIR 里除了规则文件还有别的工具维护的文件（例如包名→应用名对照表
`list.config`）。旧实现的过滤条件 `strstr(ev->name, ".conf")` 把 `.config`
也算进来：那张表每写一次就触发一次整份重载（全量重解析 + 全量对账 + 72KB
JSON 广播），现场日志表现为「配置重载 #1 来源=inotify 合并事件=390」。

判别方式：把 injector.c 里的 `reload_name_matches()` 原样抽出来编译，用文件名
表判定；`list.config` / `x.conf.bak` / `injector.conf.tmp.123` 只要有一个被判成
配置文件，B4 就失败。静态契约另外钉住过滤点用的是这个函数而不是子串匹配，以及
去抖窗口是 500ms / 最长推迟 2000ms。

退出码：0 通过、1 失败、77 缺编译器（整套跳过）。
"""
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

SKIP_RC = 77
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INJECTOR = os.path.join(ROOT, "src", "injector", "injector.c")

CASES = [
    ("injector.conf", True),
    ("App-rules-bin.mt.plus.canary.conf", True),
    ("a.conf", True),
    (".conf", False),
    ("list.config", False),
    ("something.config", False),
    ("injector.conf.bak", False),
    ("injector.conf.tmp.123", False),
    ("uid.map", False),
    ("", False),
]

MAIN = r'''
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int g_fail;

static void check(const char* name, bool got, bool want) {
    printf("case=%-34s got=%d want=%d\n", name, got ? 1 : 0, want ? 1 : 0);
    if (got != want) g_fail++;
}

int main(void) {
    struct { const char* name; bool want; } cases[] = {
__CASES__
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        check(cases[i].name, reload_name_matches(cases[i].name), cases[i].want);
    if (g_fail) { printf("total_failures=%d\n", g_fail); return 1; }
    printf("all cases passed\n");
    return 0;
}
'''


def read(path):
    with open(path, encoding="utf-8") as fp:
        return fp.read()


def extract_function(text, signature):
    start = text.find(signature)
    if start < 0:
        return None
    end = text.find("\n}\n", start)
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
    text = read(INJECTOR)
    fn = extract_function(text, "static bool reload_name_matches(const char* name) {")
    if not fn:
        print("injector.c 里找不到 reload_name_matches()", file=sys.stderr)
        return 1
    cases = "\n".join(f'        {{ "{n}", {str(w).lower()} }},{"" if n else ""}'
                      for n, w in CASES)
    source = "#include <stdbool.h>\n#include <stddef.h>\n#include <string.h>\n\n" + fn + "\n" + MAIN.replace("__CASES__", cases)
    with tempfile.TemporaryDirectory(prefix="reload_filter_") as tmp:
        src = os.path.join(tmp, "reload_filter_driver.c")
        exe = os.path.join(tmp, "reload_filter_driver")
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
    text = read(INJECTOR)
    failures += check("R1_handler_uses_suffix_matcher",
                      "reload_name_matches(ev->name)" in text)
    failures += check("R2_no_substring_conf_match",
                      'strstr(ev->name, ".conf")' not in text)
    failures += check("R3_debounce_window_is_500ms",
                      "#define NSP_RELOAD_DEBOUNCE_MS   500" in text)
    failures += check("R4_max_defer_is_bounded",
                      "#define NSP_RELOAD_MAX_DEFER_MS  2000" in text)
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
