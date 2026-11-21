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
    print("sys_pkg 隔离测试通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
