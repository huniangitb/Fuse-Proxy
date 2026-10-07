#!/usr/bin/env python3
"""A14 判别测试：配置下发视图在并发热重载下必须保持有效（快照不可变 + 引用计数）。

问题（旧实现）：`fw_config_view_for` 在解锁后交出 `&s->cfg`（借用订阅表内嵌结构），
而 `reload_once`（配置监听线程）在同一临界区原地 `free(s->filtered)` 并改写
`s->cfg.recs/count`；同时模块加载线程（loader 的 push_config_to_slot）在锁外读
`cfg->recs/count` 交给模块 `config_update`。两线程并发即读已释放数组（UAF），
模块还会看到被并发改写的 generation/recs（视图不再一致）。

修法：下发视图改为**不可变 + 引用计数 + 自持字符串**的快照，
`fw_config_view_acquire/release` 取用即持引用；重载只换订阅表指针，旧快照延迟到
最后一个持有者释放才 free。

本测试直编 `src/daemon/fw_config.c` 及其依赖（不经 Meson），驱动复刻模块真实访问
模式（先缓存 recs 指针与 generation，再触发真实重载，最后访问缓存指针）：

  * 新实现：视图不可变，recs 指针/代际/内容在 release 前恒定 → PASS。
  * 旧实现：视图被原地改写 → generation/recs 变化 → FAIL（且 ASan 下缓存指针即
    已释放数组，报 heap-use-after-free）。

判别性验证：`FW_CONFIG_SRC=<旧语义源码> python3 tests/test_fw_config_view.py`
（旧语义 = 把 rebuild_filter 改为原地改写同一视图对象、立即 free 旧数组，
见提交说明；不带该环境变量即测仓库当前实现）。

前置：本机 cc、pthread。退出码：通过 0，失败 1，缺编译器/源码 77（整套跳过）。
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(ROOT, "tests", "fixtures", "fw_config_view_uaf_driver.c")

# 与 Meson 构建同源（只取本测试实际链接到的部分，见 test_monitor_layers.py）
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

CONFIG_DIR_PAT = re.compile(
    r'^#define\s+(?:NSP_CONFIG_DIR|CONFIG_DIR)\s+"/var/fuse-proxy"\s*$', re.M)


def prepare_include(tmpdir, config_dir):
    """复制 include/，把 GNU 配置根常量指向临时 fixture 根（与 monitor_layers 同法）。"""
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


def compile_binary(tmpdir, inc_dir, asan):
    exe = os.path.join(tmpdir, "fw_config_view_test")
    cmd = [
        *os.environ.get("CC", "cc").split(), "-std=c23", "-DTARGET_GNU=1", "-D_GNU_SOURCE",
        "-Wall", "-Wno-unused-parameter",
    ]
    if asan:
        cmd += ["-fsanitize=address", "-fno-omit-frame-pointer", "-g", "-O1"]
    cmd += [
        "-I", inc_dir, "-I", os.path.join(ROOT, "include"),
        "-I", os.path.join(ROOT, "src", "daemon"),
        DRIVER, FW_CONFIG_SRC,
    ] + [os.path.join(ROOT, s) for s in SOURCES] + [
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
    if not shutil.which(os.environ.get("CC", "cc").split()[0]):
        print("无 C 编译器，整套跳过", file=sys.stderr)
        return 77

    asan = os.environ.get("ASAN") == "1"
    with tempfile.TemporaryDirectory(prefix="fw_cfg_view_") as tmpdir:
        config_dir = os.path.join(tmpdir, "config")
        os.makedirs(config_dir, exist_ok=True)
        inc_dir = prepare_include(tmpdir, config_dir)
        if inc_dir is None:
            print("未在 include 头中定位 GNU 配置根常量", file=sys.stderr)
            return 1

        rules = os.path.join(config_dir, "injector.conf")
        with open(rules, "w") as fh:
            fh.write("[GLOBAL]\nMONITOR ON\nHIDE /nsp_init_rule\n")

        exe = compile_binary(tmpdir, inc_dir, asan)
        if exe is None:
            return 1

        env = dict(os.environ)
        if asan:
            # 旧实现 arm 会泄漏旧字符串；只关心 UAF，关掉泄漏检测
            env["ASAN_OPTIONS"] = "detect_leaks=0:" + env.get("ASAN_OPTIONS", "")
        r = subprocess.run([exe, rules], capture_output=True, text=True, env=env, timeout=120)
        print(r.stdout, end="")
        if r.stderr.strip():
            print(r.stderr, end="", file=sys.stderr)

        if "RESULT OK" not in r.stdout:
            print("下发视图并发重载测试失败（视图被改写/释放）", file=sys.stderr)
            return 1
        print("下发视图并发重载测试通过 ✔")
        return 0


if __name__ == "__main__":
    sys.exit(main())
