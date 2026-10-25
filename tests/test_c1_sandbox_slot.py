#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C1 判别：沙盒落点的目录创建不得发生在配置读槽内
===================================================
`fw_rules_resolve` 全程持 `config_read_begin()/config_read_end()` 的无锁快照读槽：
持槽期间发布线程会等读者归零才推进（`config_drain_readers`）。旧实现把沙盒落点的
`access()+mkdir_recursive_p()` 直接写在 `br_check_redir_rule` 里——它正是在持槽期间
被调用的，慢存储上会放大全局停顿；该副作用还与 `fw_rules_probe`「不触发目录创建」
的语义相悖，并给 resolve 热路径引入 TOCTOU。

判别方式（确定性，不靠时序概率）：驱动经 `-Wl,--wrap=config_read_begin/end` 维护
「当前是否在槽内」，`-Wl,--wrap=mkdir_recursive_p` 记录每次目录创建及槽状态。触发
一次沙盒重定向的 resolve 后：
  - 旧实现：mkdir 发生在槽内（mkdir_in_slot ≥ 1）→ 本组失败；
  - 新实现：槽内只记录待建目录、出槽后补建（mkdir_in_slot == 0 且 mkdir_total ≥ 1）。

复现旧实现：C1_FW_RULES_SRC=<旧 fw_rules.c 副本> python3 tests/test_c1_sandbox_slot.py

前置：本机 cc、json-c；缺失则以 SKIP_RC 退出（环境不具备 = gap，不计通过）。
退出码约定（与 tests/run.py 一致）：0=通过 1=失败 77=环境不具备跳过(gap)
"""
import os
import re
import shlex
import shutil
import subprocess
import sys
import time

SKIP_RC = 77

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DRIVER = os.path.join(ROOT, "tests", "fixtures", "c1_sandbox_slot_driver.c")
FW_RULES_SRC = os.environ.get("C1_FW_RULES_SRC") or os.path.join(
    ROOT, "src", "daemon", "fw_rules.c")
SOURCES = [
    "src/daemon/fw_config.c",
    "src/daemon/cfg_watch.c",
    "src/daemon/fw_pkg.c",
    "src/config/config_parser.c",
    "src/config/path_vars.c",
    "src/core/path_trie.c",
    "src/core/nsp_util.c",
    "src/core/nsp_comm.c",
    "src/core/common.c",
    "src/core/sys_pkg.c",
    "src/core/uid_map.c",
    "src/core/fast_pid.c",
    "src/injector/config_publisher.c",
]
CONFIG_DIR_PAT = re.compile(
    r'^#define\s+(?:NSP_CONFIG_DIR|CONFIG_DIR)\s+"/var/fuse-proxy"\s*$', re.M)
# 存储根也必须私有化：沙盒落点是 <NSP_STORAGE_BASE>/<uid>/Android/data/<pkg>/sandbox，
# 只补 CONFIG_DIR 的话落点仍指向**共享绝对路径** /var/fuse-proxy/storage/...——
# ① 本套件会往共享配置树里写目录；② 在 --jobs 下与同样用 sandbox.conf 夹具的套件
# （test_monitor_layers 等）并发时，对方先建好该落点 → access() 命中 → 本套件
# 一次 mkdir_recursive_p 都不调 → mkdir_total=0 假失败（隔离跑实测复现）。
STORAGE_BASE_PAT = re.compile(
    r'^#define\s+NSP_STORAGE_BASE\s+"/var/fuse-proxy/storage"\s*$', re.M)

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "monitor_layers")


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


def pkg_config(flag):
    try:
        r = subprocess.run(["pkg-config", flag, "json-c"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.split()
    except FileNotFoundError:
        pass
    return []


def parse(out):
    """驱动每行可含多个 key=value（如 `valid=1 is_redirect=1`），全量提取。"""
    return {m.group(1): m.group(2) for m in re.finditer(r"(\w+)=(\S*)", out)}


def main():
    cc = shlex.split(os.environ.get("CC", "cc"))
    if shutil.which(cc[0]) is None:
        log("跳过：缺少 C 编译器")
        return SKIP_RC
    if not pkg_config("--libs"):
        log("跳过：缺少 json-c")
        return SKIP_RC
    if not os.path.isfile(FW_RULES_SRC):
        log(f"跳过：缺少 fw_rules 源码 {FW_RULES_SRC}")
        return SKIP_RC

    tmpdir = "/tmp/fuse_c1_slot"
    shutil.rmtree(tmpdir, ignore_errors=True)
    os.makedirs(tmpdir)
    cfgdir = os.path.join(tmpdir, "cfg")
    os.makedirs(cfgdir)

    src_inc = os.path.join(ROOT, "include")
    dst_inc = os.path.join(tmpdir, "include")
    shutil.copytree(src_inc, dst_inc)
    hits = 0
    for name in sorted(os.listdir(dst_inc)):
        if not name.endswith(".h"):
            continue
        path = os.path.join(dst_inc, name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        patched, n = CONFIG_DIR_PAT.subn(
            lambda m: m.group(0).replace('"/var/fuse-proxy"', f'"{cfgdir}"'), text)
        patched, n2 = STORAGE_BASE_PAT.subn(
            lambda m: m.group(0).replace('"/var/fuse-proxy/storage"',
                                         f'"{tmpdir}/storage"'), patched)
        n += n2
        if n:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(patched)
            hits += n
    if hits == 0:
        log("跳过：未定位 GNU 配置根/存储根常量")
        return SKIP_RC

    exe = os.path.join(tmpdir, "c1_test")
    cmd = cc + ["-std=c23", "-DTARGET_GNU=1",
                "-D_GNU_SOURCE", "-Wall", "-Wno-unused-parameter",
                "-I", dst_inc, "-I", os.path.join(ROOT, "include"),
                "-I", os.path.join(ROOT, "src", "daemon"), DRIVER, FW_RULES_SRC] + \
        [os.path.join(ROOT, s) for s in SOURCES] + \
        ["-Wl,--wrap=config_read_begin", "-Wl,--wrap=config_read_end",
         "-Wl,--wrap=mkdir_recursive_p",
         # 存储根守卫后沙盒补建走 common_mkdir_within_storage（与 mkdir_recursive_p
         # 同 TU，直调 wrap 不到）——两个出口都要观察，见驱动注释
         "-Wl,--wrap=common_mkdir_within_storage",
         "-o", exe, "-pthread", "-ldl", "-lm"] + \
        pkg_config("--cflags") + pkg_config("--libs")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        log(f"❌ 测试二进制编译: {r.stderr.strip()[-500:]}")
        return 1

    # 复用 monitor_layers 的 fixture：sandbox.conf 给 [com.demo.app] SANDBOX ON，
    # uid.map 给 10123 → com.demo.app（uid→包名解析命中是进沙盒分支的前提）
    shutil.copy(os.path.join(FIXTURE, "sandbox.conf"),
                os.path.join(cfgdir, "injector.conf"))
    shutil.copy(os.path.join(FIXTURE, "uid.map"), os.path.join(cfgdir, "uid.map"))

    run = subprocess.run([exe, os.path.join(cfgdir, "injector.conf")],
                         capture_output=True, text=True)
    vals = parse(run.stdout)
    print(f"driver rc={run.returncode}")
    print(run.stdout.rstrip())
    if run.stderr.strip():
        print(run.stderr.rstrip(), file=sys.stderr)

    fails = []
    if vals.get("valid") != "1" or vals.get("is_redirect") != "1":
        fails.append(f"未命中沙盒重定向（valid={vals.get('valid')} "
                     f"is_redirect={vals.get('is_redirect')}）")
    try:
        total = int(vals.get("mkdir_total", "-1"))
        in_slot = int(vals.get("mkdir_in_slot", "-1"))
    except ValueError:
        total, in_slot = -1, -1
    if total < 1:
        fails.append(f"沙盒落点未被补建（mkdir_total={total}）")
    if in_slot != 0:
        fails.append(f"目录创建发生在配置读槽内（mkdir_in_slot={in_slot}，期望 0）")

    shutil.rmtree(tmpdir, ignore_errors=True)
    if fails:
        for f in fails:
            log(f"  ❌ {f}")
        log(f"结果: {len(fails)} 项失败")
        return 1
    log(f"  ✅ 沙盒重定向命中；mkdir_total={total} mkdir_in_slot={in_slot}"
        f"（补建在槽外）")
    log("结果: 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
