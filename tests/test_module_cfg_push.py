#!/usr/bin/env python3
"""配置下发归属判别测试：模块配置由框架读、按 owner 过滤下发（视图版本 2）。

约定（nsp_module.h / docs/modules.md §6.1.1）：模块**不读文件、不跑 inotify**，
包括它自己的配置 `<modules_dir>/<模块名>/<模块名>.conf`。框架读入后以
`NSP_CFG_REC_MODULE_FILE` / `NSP_CFG_REC_MODULE_LINE` 记录下发，并**按 owner
过滤**——只发给同名模块（模块间配置隔离与规则隔离同等要求）。

判别性（旧实现上必失败）：旧实现 `config_read_view` 只读主文件 + App-rules，
视图里没有任何 MODULE_* 记录，故「标记存在」「逐行下发」「owner 隔离」三条全失败。
判别性验证：`FW_CONFIG_SRC=<旧实现> python3 tests/test_module_cfg_push.py`
（旧实现 = 去掉 `config_read_view` 里的 `view_scan_module_confs` 调用）。

本套件直编 `src/daemon/fw_config.c` + `src/config/config_parser.c` 及其依赖
（不经 Meson），驱动见 `tests/fixtures/module_cfg_push_driver.c`。

前置：本机 cc、pthread。退出码：通过 0，失败 1，缺编译器/源码 77（整套跳过）。
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(ROOT, "tests", "fixtures", "module_cfg_push_driver.c")

# 与 Meson 构建同源（只取本测试实际链接到的部分，见 test_fw_config_view.py）
SOURCES = [
    "src/daemon/fw_pkg.c",
    "src/daemon/cfg_watch.c",
    "src/daemon/fw_rules.c",
    "src/config/config_parser.c",
    "src/config/path_vars.c",
    "src/core/path_trie.c",
    "src/core/nsp_util.c",
    "src/core/nsp_comm.c",
    "src/core/common.c",
    "src/core/sys_pkg.c",
    "src/core/uid_map.c",
    "src/core/fast_pid.c",
]
# 可经环境变量覆盖（判别旧实现用）
FW_CONFIG_SRC = os.environ.get("FW_CONFIG_SRC") or os.path.join(ROOT, "src", "daemon", "fw_config.c")
# 旧实现 = config_read_view 不扫描模块配置（去掉 view_scan_module_confs 调用）
CONFIG_PARSER_SRC = os.environ.get("CONFIG_PARSER_SRC") or os.path.join(
    ROOT, "src", "config", "config_parser.c")

CONFIG_DIR_PAT = re.compile(
    r'^#define\s+(?:NSP_CONFIG_DIR|CONFIG_DIR)\s+"/var/fuse-proxy"\s*$', re.M)


def prepare_include(tmpdir, config_dir):
    """复制 include/，把 GNU 配置根常量指向临时 fixture 根（与 fw_config_view 同法）。"""
    dst_inc = os.path.join(tmpdir, "include")
    shutil.copytree(os.path.join(ROOT, "include"), dst_inc)
    hits = 0
    for name in sorted(os.listdir(dst_inc)):
        if not name.endswith(".h"):
            continue
        path = os.path.join(dst_inc, name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        patched, n = CONFIG_DIR_PAT.subn(
            lambda m: m.group(0).replace('"/var/fuse-proxy"', f'"{config_dir}"'), text)
        if n:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(patched)
            hits += n
    return dst_inc if hits else None


def compile_binary(tmpdir, inc_dir):
    exe = os.path.join(tmpdir, "module_cfg_push_test")
    cmd = [
        *os.environ.get("CC", "cc").split(), "-std=c23", "-DTARGET_GNU=1", "-D_GNU_SOURCE",
        "-Wall", "-Wno-unused-parameter",
        "-I", inc_dir, "-I", os.path.join(ROOT, "include"),
        "-I", os.path.join(ROOT, "src", "daemon"),
        DRIVER, FW_CONFIG_SRC,
    ] + [CONFIG_PARSER_SRC if s == "src/config/config_parser.c" else os.path.join(ROOT, s)
         for s in SOURCES] + [
        "-o", exe, "-pthread", "-ldl", "-lm",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("C 编译/链接失败:", file=sys.stderr)
        print(r.stderr, file=sys.stderr)
        return None
    return exe


def main():
    if not os.path.isfile(DRIVER):
        print("缺少驱动 fixture", file=sys.stderr)
        return 1
    if not os.path.isfile(FW_CONFIG_SRC):
        print(f"缺少源码 {FW_CONFIG_SRC}", file=sys.stderr)
        return 77
    if not os.path.isfile(CONFIG_PARSER_SRC):
        print(f"缺少源码 {CONFIG_PARSER_SRC}", file=sys.stderr)
        return 77
    if not shutil.which(os.environ.get("CC", "cc").split()[0]):
        print("无 C 编译器，整套跳过", file=sys.stderr)
        return 77

    with tempfile.TemporaryDirectory(prefix="module_cfg_push_") as tmpdir:
        config_dir = os.path.join(tmpdir, "config")
        modules = os.path.join(config_dir, "modules")
        # modA/modB 各有配置；modC 只有目录（无配置文件）→ 标记仍须下发
        for mod in ("modA", "modB", "modC"):
            os.makedirs(os.path.join(modules, mod), exist_ok=True)
        with open(os.path.join(modules, "modA", "modA.conf"), "w", encoding="utf-8") as fh:
            fh.write("# 注释行\nhost = a.example.com\npass = p#ssw0rd\nHIDE /nsp_from_module_conf\n")
        with open(os.path.join(modules, "modB", "modB.conf"), "w", encoding="utf-8") as fh:
            fh.write("host = b.example.com\n")

        inc_dir = prepare_include(tmpdir, config_dir)
        if inc_dir is None:
            print("未在 include 头中定位 GNU 配置根常量", file=sys.stderr)
            return 1

        rules = os.path.join(config_dir, "injector.conf")
        with open(rules, "w", encoding="utf-8") as fh:
            fh.write("[GLOBAL]\nMONITOR ON\nHIDE /nsp_main_rule\n")

        exe = compile_binary(tmpdir, inc_dir)
        if exe is None:
            return 1

        print("── 模块配置下发（框架读 → 按 owner 过滤 → 模块消费）──")
        r = subprocess.run([exe, rules, modules], capture_output=True, text=True,
                           env=dict(os.environ))
        print(r.stdout, end="")
        if r.stderr:
            print(r.stderr, end="", file=sys.stderr)
        if r.returncode != 0:
            print("配置下发归属测试失败")
            return 1
        print("配置下发归属测试通过 ✔")
        return 0


if __name__ == "__main__":
    sys.exit(main())
