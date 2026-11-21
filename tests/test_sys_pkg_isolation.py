#!/usr/bin/env python3
"""L0: 实际 sys_pkg TU 的慢缓存读/写隔离与迟到构建回归；不启动 pm/挂载。"""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ["src/config/config_parser.c", "src/config/path_vars.c",
           "src/core/path_trie.c", "src/core/nsp_util.c", "src/core/nsp_comm.c",
           "src/core/common.c"]


def function_body(text, name):
    start = text.find(name + "(")
    if start < 0:
        return None
    brace = text.find("{", start)
    if brace < 0:
        return None
    end = text.find("\n}\n", brace)
    return text[brace:end if end > 0 else len(text)]


def static_checks(source):
    """查询路径必须在任何锁/读槽内保持「只查已发布表」，冷缓存交给后台装载。"""
    body = function_body(source.read_text(), "bool sys_pkg_is_system")
    if body is None:
        print("❌ 找不到 sys_pkg_is_system 定义")
        return False
    ok = True
    if "sys_pkg_request_load()" not in body:
        print("❌ 查询路径没有把冷缓存装载交给后台线程（缺 sys_pkg_request_load()）")
        ok = False
    for forbidden in ("sys_pkg_build_and_publish(", "sys_pkg_load_file("):
        if forbidden in body:
            print(f"❌ 查询路径仍在同步构建/读盘（出现 {forbidden}）")
            ok = False
    return ok


def main():
    # 临时头文件沿用 config_snapshot suite 的 GNU 常量覆写方式。
    with tempfile.TemporaryDirectory(prefix="sys_pkg_isolation_") as tmp:
        tmp = Path(tmp)
        config = tmp / "config"
        config.mkdir()
        inc = tmp / "include"
        shutil.copytree(ROOT / "include", inc)
        pattern = re.compile(r'^#define\s+(?:NSP_CONFIG_DIR|CONFIG_DIR)\s+"/var/fuse-proxy"\s*$', re.M)
        hits = 0
        for header in inc.glob("*.h"):
            text, n = pattern.subn(lambda m: m.group().replace('"/var/fuse-proxy"', f'"{config}"'),
                                  header.read_text())
            if n:
                header.write_text(text)
                hits += n
        if not hits:
            raise RuntimeError("未找到 GNU CONFIG_DIR 常量")
        source = Path(os.environ.get("SYS_PKG_SRC", ROOT / "src/core/sys_pkg.c")).resolve()
        # 静态判别与运行判别都保留：旧源应当同时红在这两层。
        static_ok = static_checks(source)
        command = [*shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-DTARGET_GNU=1",
                   "-D_GNU_SOURCE", "-O1", "-g", "-Wall", "-Wextra", "-Wno-unused-parameter",
                   "-ffunction-sections", "-fdata-sections", "-I", str(inc), "-I", str(ROOT / "include"),
                   str(ROOT / "tests/fixtures/sys_pkg_isolation.c"), str(source),
                   *(str(ROOT / s) for s in SOURCES), "-o", str(tmp / "test"),
                   "-pthread", "-ldl", "-lm", "-Wl,--gc-sections",
                   "-Wl,--wrap=fopen,--wrap=fgets,--wrap=fclose,--wrap=popen,--wrap=pclose,"
                    "--wrap=common_run_cmd_lines"]
        command += shlex.split(os.environ.get("SYS_PKG_TEST_CFLAGS", ""))
        for argv, timeout in [(command, 60), ([str(tmp / "test")], 25)]:
            result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
            print(result.stdout, end="")
            print(result.stderr, end="", file=sys.stderr)
            if result.returncode:
                return 1
    if not static_ok:
        return 1
    print("sys_pkg 隔离测试通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
