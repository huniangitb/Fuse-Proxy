#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C11 判别：配置目录事件按 ev->name 分流（uid.map / sys_pkgs.cache 不触发规则重载）
====================================================================================
`uid_map_upsert` 每启动一个应用就在 CONFIG_DIR 里 tmp+rename 写 uid.map，产生多条
inotify 事件；旧实现对这些事件与规则文件一视同仁，都走 `reload_once()`——整份重解析
+ 重建 Trie + 作废 2048 槽 uid 缓存 + 推送所有模块。应用启动高峰期（大量应用同时
拉起）会让 FUSE 热路径的派生缓存持续冷启。

判别方式（确定性）：驱动直编 `src/daemon/fw_config.c` 并注册自己的 reload 钩子计数
（= 全量重载次数），然后依次改写三类文件、各等一个去抖窗口：
  - 旧实现：改写 uid.map 后计数 +1（期望 0）→ 本组失败；
  - 新实现：uid.map / sys_pkgs.cache 只做轻量刷新（fw_pkg_reload / sys_pkg_refresh
    + 代际递增），只有规则文件才触发全量重载。
另含 C11 第二半「重解析后与旧视图比对无变化则跳过发布」：把规则文件重写为**逐字
相同**内容后计数不得再涨（旧实现无条件发布 → 本组失败）。

复现旧实现：FW_CONFIG_SRC=<旧 fw_config.c 副本> python3 tests/test_cfg_reload_split.py

前置：本机 cc、pthread。退出码：0=通过 1=失败 77=缺编译器（整套跳过）。
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
DRIVER = os.path.join(ROOT, "tests", "fixtures", "cfg_reload_split_driver.c")
FW_CONFIG_SRC = os.environ.get("FW_CONFIG_SRC") or os.path.join(
    ROOT, "src", "daemon", "fw_config.c")

# 与 Meson 构建同源（同 test_fw_config_view.py）
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

CONFIG_DIR_PAT = re.compile(
    r'^#define\s+(?:NSP_CONFIG_DIR|CONFIG_DIR)\s+"/var/fuse-proxy"\s*$', re.M)


def prepare_include(tmpdir, config_dir):
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


def main():
    if not os.path.isfile(DRIVER):
        print(f"缺少驱动 {DRIVER}", file=sys.stderr)
        return 1
    if not os.path.isfile(FW_CONFIG_SRC):
        print(f"缺少 fw_config 源码 {FW_CONFIG_SRC}", file=sys.stderr)
        return SKIP_RC
    cc = shlex.split(os.environ.get("CC", "cc"))
    if shutil.which(cc[0]) is None:
        print("跳过：缺少 C 编译器")
        return SKIP_RC

    with tempfile.TemporaryDirectory(prefix="cfg_reload_split_") as tmpdir:
        cfgdir = os.path.join(tmpdir, "cfg")
        os.makedirs(cfgdir)
        rules = os.path.join(cfgdir, "injector.conf")
        with open(rules, "w") as fh:
            fh.write("[GLOBAL]\nMONITOR OFF\n")

        inc_dir = prepare_include(tmpdir, cfgdir)
        if inc_dir is None:
            print("跳过：未定位 GNU 配置根常量")
            return SKIP_RC

        exe = os.path.join(tmpdir, "cfg_reload_split")
        cmd = cc + [
            "-std=c23", "-DTARGET_GNU=1", "-D_GNU_SOURCE",
            "-Wall", "-Wno-unused-parameter",
            "-I", inc_dir, "-I", os.path.join(ROOT, "include"),
            "-I", os.path.join(ROOT, "src", "daemon"),
            DRIVER, FW_CONFIG_SRC,
        ] + [os.path.join(ROOT, s) for s in SOURCES] + [
            "-o", exe, "-pthread", "-ldl", "-lm",
        ]
        build = subprocess.run(cmd, capture_output=True, text=True)
        if build.returncode != 0:
            print("C 编译/链接失败:", file=sys.stderr)
            print(build.stderr, file=sys.stderr)
            return 1

        run = subprocess.run([exe, rules, cfgdir], capture_output=True, text=True, timeout=90)
        print(run.stdout.rstrip())
        if run.stderr.strip():
            print(run.stderr.rstrip(), file=sys.stderr)
        if run.returncode != 0:
            print(f"FAIL 驱动退出码 {run.returncode}", file=sys.stderr)
            return 1

        vals = {m.group(1): int(m.group(2))
                for m in re.finditer(r"(\w+)=(\d+)", run.stdout)}
        fails = []
        if vals.get("after_uidmap") != vals.get("base"):
            fails.append(f"uid.map 变更触发了全量规则重载（{vals.get('base')} → "
                         f"{vals.get('after_uidmap')}，期望不变）")
        if vals.get("after_rules", 0) != vals.get("after_uidmap", 0) + 1:
            fails.append(f"规则文件变更未触发全量重载（{vals.get('after_uidmap')} → "
                         f"{vals.get('after_rules')}，期望 +1）")
        if vals.get("after_syspkg") != vals.get("after_rules"):
            fails.append(f"sys_pkgs.cache 变更触发了全量规则重载（{vals.get('after_rules')} → "
                         f"{vals.get('after_syspkg')}，期望不变）")
        if vals.get("after_same") != vals.get("after_rules"):
            fails.append(f"规则文件重写为相同内容仍触发了全量重载（{vals.get('after_rules')} → "
                         f"{vals.get('after_same')}，期望不变）")
        if fails:
            for f in fails:
                print(f"  ❌ {f}", file=sys.stderr)
            return 1
        print("  ✅ uid.map / sys_pkgs.cache 不触发规则重载；规则文件仍触发（正对照）")
        print("  ✅ 规则文件重写为相同内容不再发布（无变化跳过）")

        # 第二段：慢 sys_pkgs.cache 读取不得罩在配置写锁里冻住冷路径读者。
        # 把该文件换成 FIFO、写端晚 300ms 交数据 = 真实慢盘；另一线程反复
        # config_lock_read()/unlock 采样。旧实现（refresh 在写锁内）冷读者被冻
        # ~300ms，新实现（refresh 在 unlock 之后）只有微秒级等待。
        run2 = subprocess.run([exe, rules, cfgdir, "locks"], capture_output=True,
                              text=True, timeout=180)
        print(run2.stdout.rstrip())
        if run2.stderr.strip():
            print(run2.stderr.rstrip(), file=sys.stderr)
        if run2.returncode != 0:
            print(f"FAIL locks 驱动退出码 {run2.returncode}", file=sys.stderr)
            return 1
        lv = {m.group(1): int(m.group(2))
              for m in re.finditer(r"(\w+)=(\d+)", run2.stdout)}
        fails2 = []
        # hit=「规则变更触发了全量重载」且「这次重载真的读了慢盘」：两个条件缺一即
        # 说明测量没落在写锁窗口上（调度慢/事件被并批），不能拿它下结论。
        if lv.get("hit", 0) != 1:
            fails2.append(f"重载窗口没建立（hit={lv.get('hit')}、reloads={lv.get('reloads')}、"
                          f"sys_reads={lv.get('sys_reads')}、waited_ms={lv.get('waited_ms')}）")
        if lv.get("sys_reads", 0) < 1:
            fails2.append(f"慢盘没有被真正读取（sys_reads={lv.get('sys_reads')}，期望 ≥1）")
        if lv.get("reloads", 0) < 1:
            fails2.append(f"规则变更未触发全量重载（reloads={lv.get('reloads')}，期望 ≥1）")
        if lv.get("cold_max_us", 1 << 30) >= 50000:
            fails2.append(f"慢 sys_pkgs.cache 读取把冷路径读者冻住了 "
                          f"{lv.get('cold_max_us')}µs（期望 <50000µs：真读盘不得罩在写锁内；"
                          "旧实现固定 300000µs 量级）")
        if fails2:
            for f in fails2:
                print(f"  ❌ {f}", file=sys.stderr)
            return 1
        print("  ✅ 慢 sys_pkgs.cache 读取不再冻结冷路径读者（写锁不含真读盘）")
        print("配置重载分流测试通过 ✔")
        return 0


if __name__ == "__main__":
    sys.exit(main())
