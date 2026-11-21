#!/usr/bin/env python3
"""L0: `pm` 查询必须有时间上界，慢/挂起的 binder 调用不得冻住调用者。

背景（生产等价）：`scan_active_users()`（配置视图内）与 `sys_pkg_init/refresh`
（注入器事件循环、fuse_daemon 热重载线程）历史上都是 popen + fgets + pclose：
`pm` 走 binder 到 system_server，挂起时没有时间上界，一次挂起就把整个进程/整个
FUSE 会话拖成无响应。新实现用 common_run_cmd_lines 的预算（pm list users 800ms、
pm list packages 3s）：到点 SIGKILL 子进程并返回已读内容，调用方按「这次没结果」
回退（用户表回退磁盘推导；系统包表保留已发布表、绝不写空 cache）。

判别：CMD_BOUNDED_OLD_TREE 指向一个目录，里面放 `git show <旧提交>:<路径>` 得到的
common.c / config_parser.c / sys_pkg.c 时，同一夹具会跑旧实现——慢 pm 下耗时
≈8s（真挂住），本文件把它当「旧红」证据打印，不做失败处理。
"""
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "tests/fixtures/cmd_bounded_driver.c"
SOURCES = ["src/config/config_parser.c", "src/config/path_vars.c", "src/core/path_trie.c",
           "src/core/nsp_util.c", "src/core/nsp_comm.c", "src/core/common.c",
           "src/core/sys_pkg.c"]
# 预算上限（含进程启动/收尾抖动）：800ms 的 pm list users 给到 2s，3s 的
# pm list packages 给到 4.5s；旧实现是 sleep 8s，判据分离度足够。
LIMIT_USERS_MS = 2000
LIMIT_PACKAGES_MS = 4500
LIMIT_CAPTURE_MS = 1500
LIMIT_REFRESH_MS = 800   # 冷却期内 refresh 只读磁盘 cache，不再 fork pm
LIMIT_QUERY_MS = 200     # 冷却期内 is_system 直接命中已发布表
# 旧源码树没有 common_run_cmd_lines：给旧树配一个「popen + fgets 无预算」的替身，
# 让旧实现在同一夹具里仍然真的挂住（这才是要复现的红，而不是链接失败）。
OLD_SHIM = """
#define _GNU_SOURCE
#include "common.h"
#include <stdio.h>
int common_run_cmd_lines(const char* shell_cmd, int budget_ms, NspCmdLineFn on_line, void* ctx,
                         bool* timed_out) {
    (void)budget_ms;
    if (timed_out) *timed_out = false;
    FILE* fp = popen(shell_cmd, "r");
    if (!fp) return -1;
    char line[512];
    while (fgets(line, sizeof line, fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\\n' || line[len - 1] == '\\r')) line[--len] = '\\0';
        if (on_line) on_line(line, ctx);
    }
    pclose(fp);
    return 0;
}
"""
SLOW_PM_SLEEP_S = 8

FAKE_PM = """#!/bin/sh
# 假 pm：真机上是 binder 到 system_server 的命令，这里用 sleep 模拟挂起
case "$FAKE_PM_MODE" in
  slow) sleep %d ;;
esac
case "$1 $2" in
  "list users")
    printf '\\tUserInfo{0:Owner:13} running\\n'
    printf '\\tUserInfo{10:Work:13} running\\n'
    ;;
  "list packages")
    printf 'package:com.android.systemui\\n'
    printf 'package:com.android.settings\\n'
    ;;
esac
exit 0
""" % SLOW_PM_SLEEP_S


def build(work, sources, tag):
    exe = work / ("cmd_bounded_" + tag)
    build = subprocess.run(["cc", "-std=gnu2x", "-O2", "-pthread", "-I", str(ROOT / "include"),
                            "-o", str(exe), str(DRIVER)] + sources,
                           capture_output=True, text=True)
    (work / ("build-%s.log" % tag)).write_text(build.stdout + build.stderr, encoding="utf-8")
    if build.returncode != 0:
        print("❌ 编译失败（%s，见 %s/build-%s.log）：" % (tag, work, tag))
        print((build.stdout + build.stderr)[-2000:])
        return None
    return exe


def run(exe, mode, pm_mode, bin_dir):
    env = {
        "PATH": str(bin_dir) + ":/usr/local/bin:/usr/bin:/bin",
        "FAKE_PM_MODE": pm_mode,
    }
    proc = subprocess.run([str(exe), mode], capture_output=True, text=True, timeout=180, env=env)
    return proc.returncode, proc.stdout + proc.stderr


def parse(out, fields):
    found = {}
    for name in fields:
        m = re.search(r"\b%s=(-?\d+)" % name, out)
        if m:
            found[name] = int(m.group(1))
    return found


def main():
    out_dir = os.environ.get("CMD_BOUNDED_OUTPUT_DIR")
    work = Path(out_dir) if out_dir else Path(tempfile.mkdtemp(prefix="cmd-bounded-"))
    work.mkdir(parents=True, exist_ok=True)
    bin_dir = work / "bin"
    bin_dir.mkdir(exist_ok=True)
    pm = bin_dir / "pm"
    pm.write_text(FAKE_PM, encoding="utf-8")
    pm.chmod(pm.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    sources = [str(ROOT / s) for s in SOURCES]
    exe = build(work, sources, "new")
    if exe is None:
        return 1
    fails = 0
    log = []

    # 1) 行回调语义：printf 三行 -> 三行；末行无换行也要回调（同 fgets）
    rc, out = run(exe, "capture-ok", "fast", bin_dir)
    log.append(out.strip())
    got = parse(out, ["lines", "timed", "elapsed_ms"])
    if rc != 0 or got.get("lines") != 3 or "a|b|c" not in out or got.get("timed") != 0:
        print("❌ 行回调语义不符：rc=%d out=%r" % (rc, out[-300:]))
        fails += 1
    rc, out = run(exe, "capture-tail", "fast", bin_dir)
    log.append(out.strip())
    got = parse(out, ["lines"])
    if rc != 0 or got.get("lines") != 2 or "x|y" not in out:
        print("❌ 末行无换行未回调：rc=%d out=%r" % (rc, out[-300:]))
        fails += 1

    # 2) 超预算必须返回（不是等子进程）
    rc, out = run(exe, "capture-slow", "fast", bin_dir)
    log.append(out.strip())
    got = parse(out, ["timed", "elapsed_ms"])
    if rc != 0 or got.get("timed") != 1 or got.get("elapsed_ms", 10 ** 9) > LIMIT_CAPTURE_MS:
        print("❌ 超预算未返回：rc=%d out=%r" % (rc, out[-300:]))
        fails += 1

    # 3) 快 pm：解析语义不变
    rc, out = run(exe, "pm-users", "fast", bin_dir)
    log.append(out.strip())
    got = parse(out, ["users", "elapsed_ms"])
    if rc != 0 or got.get("users", 0) < 2 or "first=0" not in out:
        print("❌ 快 pm 下用户表解析异常：rc=%d out=%r" % (rc, out[-300:]))
        fails += 1
    rc, out = run(exe, "pm-packages", "fast", bin_dir)
    log.append(out.strip())
    got = parse(out, ["systemui", "settings", "elapsed_ms"])
    if rc != 0 or got.get("systemui") != 1 or got.get("settings") != 1:
        print("❌ 快 pm 下系统包表解析异常：rc=%d out=%r" % (rc, out[-300:]))
        fails += 1

    # 4) 慢 pm：两个调用点都必须按预算返回
    rc, out = run(exe, "pm-users", "slow", bin_dir)
    log.append(out.strip())
    got = parse(out, ["users", "elapsed_ms"])
    if rc != 0 or got.get("elapsed_ms", 10 ** 9) > LIMIT_USERS_MS:
        print("❌ 慢 pm 下 scan_active_users 未按预算返回：rc=%d out=%r" % (rc, out[-300:]))
        fails += 1
    if got.get("users", 0) < 1:
        print("❌ 慢 pm 回退后用户表为空（至少要有 user 0）：out=%r" % out[-300:])
        fails += 1
    rc, out = run(exe, "pm-packages", "slow", bin_dir)
    log.append(out.strip())
    got = parse(out, ["elapsed_ms", "refresh_ms", "query_ms"])
    if rc != 0 or got.get("elapsed_ms", 10 ** 9) > LIMIT_PACKAGES_MS:
        print("❌ 慢 pm 下 sys_pkg 冷启动+查询超出预算：rc=%d out=%r" % (rc, out[-300:]))
        fails += 1
    # 超时后必须进入冷却：紧接着的 refresh 与查询不得再各付一遍 3s 预算
    if got.get("refresh_ms", 10 ** 9) > LIMIT_REFRESH_MS:
        print("❌ 超时后 refresh 又付了一遍 pm 预算：refresh_ms=%s（期望 <= %d）"
              % (got.get("refresh_ms"), LIMIT_REFRESH_MS))
        fails += 1
    if got.get("query_ms", 10 ** 9) > LIMIT_QUERY_MS:
        print("❌ 超时后查询又付了一遍 pm 预算（生产里在 config 读锁内）：query_ms=%s"
              % got.get("query_ms"))
        fails += 1

    # 5) 旧实现判别（可选）：同一夹具跑旧源码
    old_tree = os.environ.get("CMD_BOUNDED_OLD_TREE")
    if old_tree:
        old_sources = list(sources)
        for name, rel in (("common.c", "src/core/common.c"),
                          ("config_parser.c", "src/config/config_parser.c"),
                          ("sys_pkg.c", "src/core/sys_pkg.c")):
            idx = old_sources.index(str(ROOT / rel))
            old_sources[idx] = str(Path(old_tree) / name)
        shim = work / "old_capture_shim.c"
        shim.write_text(OLD_SHIM, encoding="utf-8")
        old_exe = build(work, old_sources + [str(shim)], "old")
        if old_exe is None:
            print("⚠️  旧源码编译失败，跳过旧红对照")
        else:
            for mode, limit in (("pm-users", LIMIT_USERS_MS), ("pm-packages", LIMIT_PACKAGES_MS)):
                rc, out = run(old_exe, mode, "slow", bin_dir)
                log.append("OLD " + out.strip())
                got = parse(out, ["elapsed_ms"])
                elapsed = got.get("elapsed_ms", -1)
                if elapsed <= limit:
                    print("⚠️  旧实现在慢 pm 下也很快（%s elapsed=%sms）——旧红未成立"
                          % (mode, elapsed))
                else:
                    print("旧实现慢 pm 红：%s elapsed=%sms（预算上限 %sms）"
                          % (mode, elapsed, limit))

    (work / "run.log").write_text("\n".join(log) + "\n", encoding="utf-8")
    if fails:
        print("有界 pm 测试失败：%d 项（证据 %s）" % (fails, work))
        return 1
    print("有界 pm 测试通过 ✔（证据 %s）" % work)
    return 0


if __name__ == "__main__":
    sys.exit(main())