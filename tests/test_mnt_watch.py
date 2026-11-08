#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""稳态对账的唤醒源：挂载表变化事件（而非 5s 周期扫描）

背景：v2/v3 的族根由 vold 掌握——用户启动/切换、卷重挂、FUSE 崩溃恢复都会新建或
重建 /mnt/<族>/<uid>/emulated。过去靠「稳态每 5s 复查一次」发现这些变化：最小延迟
被周期锁死，而 5s 里绝大多数复查的结论都是「没变」。这不是靠调周期能同时满足的
两头（调快烧 CPU、调慢拉长接管延迟）。

现在稳态挂在**事件源**上：/proc/<pid>/mountinfo 的 poll 实现在该命名空间每次
mount/umount 后回报一次 EPOLLERR（内核对比 ns->event 与打开时的快照）。族根一变，
挂载表必然变，于是「变化 → 复查」只隔一次 epoll 唤醒；没有变化就一次复查都不做。

本套件守三件事：
  A. 事件源本身的行为（沙箱内真实 mount/umount 实测）：空闲不自旋、变化必到、
     每次变化只报一次、读文件既不自造也不吞掉事件、坏 pid 返回 -1；
  B. injector 的接入方式（静态契约）：注册掩码必须是 0（带 EPOLLIN 就成忙轮询）、
     稳态分支等事件、事件源不可用时仍要退回周期复查、替换动作之间要有间隔闸；
  C. 宿主零污染：沙箱内挂载不得回流。

判别性：A 段在「靠周期扫描」的旧实现上无对应模块（驱动编不过）；B 段在旧实现上
必失败——旧实现没有事件源、没有 GREPL_STEADY_EVENT、也没有替换间隔闸。

退出码：0 通过、1 失败、7 跳过（缺 unshare / userns）。
"""
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests" / "fixtures" / "mnt_watch_driver.c"
WATCH_C = ROOT / "src" / "injector" / "ns_mnt_watch.c"
WATCH_H = ROOT / "src" / "injector" / "ns_mnt_watch.h"
INJECTOR = ROOT / "src" / "injector" / "injector.c"

SKIP_RC = 7
PASS = 0
FAIL = 0
ERRORS = []


def log(msg):
    print(msg, flush=True)


def ok(desc):
    global PASS
    PASS += 1
    log(f"  ✅ {desc}")


def fail(desc, detail=""):
    global FAIL
    FAIL += 1
    ERRORS.append((desc, detail))
    log(f"  ❌ {desc}" + (f" — {detail}" if detail else ""))


def parse_kv(text):
    """按空白切词再切 KEY=VALUE：驱动可能一行里打多个观测值。"""
    out = {}
    for token in text.split():
        if "=" not in token:
            continue
        k, _, v = token.partition("=")
        out[k.strip()] = v.strip()
    return out


def num(kv, key):
    try:
        return int(kv.get(key, "nan"))
    except ValueError:
        return -10**9


# ── A 段：事件源实测（沙箱内） ───────────────────────────────────────────────

def run_mode(exe, mode, scratch):
    r = subprocess.run([exe, mode, scratch], capture_output=True, text=True, timeout=60)
    kv = parse_kv(r.stdout)
    if r.returncode != 0 and "error" not in r.stdout:
        log(f"    驱动输出: {r.stdout.strip()} / {r.stderr.strip()}")
    return kv


def check_events(exe, tmp_root):
    log("A 段：挂载表变化事件源（真实 mount/umount）")

    kv = run_mode(exe, "idle", os.path.join(tmp_root, "idle"))
    if num(kv, "idle_events") == 0:
        ok("空闲 300ms 无唤醒（不自旋、不误报）")
    else:
        fail("空闲时被唤醒", f"idle_events={kv.get('idle_events')}（掩码带了 EPOLLIN 就会忙轮询）")

    kv = run_mode(exe, "mount", os.path.join(tmp_root, "mount"))
    ms = num(kv, "mount_ms")
    if num(kv, "mount_rc") == 0 and num(kv, "mount_events") == 1:
        ok(f"挂载后收到 1 次事件（{ms}ms）")
    else:
        fail("挂载未触发事件",
             f"mount_rc={kv.get('mount_rc')} events={kv.get('mount_events')}")
    if -1 < ms <= 250:
        ok(f"挂载 → 事件延迟 {ms}ms ≤ 250ms")
    else:
        fail("挂载 → 事件延迟超限", f"{ms}ms")
    if num(kv, "again_events") == 0:
        ok("同一次变化不会重复上报（换掉事件源后不刷屏）")
    else:
        fail("同一次变化重复上报", f"again_events={kv.get('again_events')}")

    kv = run_mode(exe, "umount", os.path.join(tmp_root, "umount"))
    ms = num(kv, "umount_ms")
    if num(kv, "umount_rc") == 0 and num(kv, "umount_events") == 1 and -1 < ms <= 250:
        ok(f"卸载后收到 1 次事件（{ms}ms）——vold 重挂族根走的就是这条")
    else:
        fail("卸载未触发事件",
             f"rc={kv.get('umount_rc')} events={kv.get('umount_events')} ms={ms}")

    kv = run_mode(exe, "seq", os.path.join(tmp_root, "seq"))
    d1, d2 = num(kv, "mount_ms"), num(kv, "umount_ms")
    if (num(kv, "mount_events") == 1 and num(kv, "umount_events") == 1
            and -1 < d1 <= 250 and -1 < d2 <= 250):
        ok(f"连续两次变化各唤醒一次（{d1}ms / {d2}ms），事件源可重复使用")
    else:
        fail("连续变化漏报",
             f"mount={kv.get('mount_events')}@{d1}ms umount={kv.get('umount_events')}@{d2}ms")

    kv = run_mode(exe, "read", os.path.join(tmp_root, "read"))
    if num(kv, "read_lines") > 0:
        ok(f"mountinfo 可整份读（{kv.get('read_lines')} 行）")
    else:
        fail("mountinfo 读不到", f"read_lines={kv.get('read_lines')} rc={kv.get('read_rc')}")
    if num(kv, "events_after_read") == 0:
        ok("读文件本身不产生事件（不会把「自己读表」当成变化）")
    else:
        fail("读文件产生了事件", f"events_after_read={kv.get('events_after_read')}")
    if num(kv, "mount_events") == 1:
        ok("读过文件之后仍能收到变化事件（读不吞事件）")
    else:
        fail("读文件吞掉了事件", f"mount_events={kv.get('mount_events')}")

    kv = run_mode(exe, "badpid", os.path.join(tmp_root, "badpid"))
    if num(kv, "badpid_fd") == -1:
        ok("不存在的 pid 返回 -1（调用方据此退回周期复查）")
    else:
        fail("坏 pid 未报错", f"badpid_fd={kv.get('badpid_fd')}")


# ── B 段：injector 的接入方式（静态契约） ────────────────────────────────────

def func_body(src, name):
    """取 C 源里某个函数的函数体（花括号配平），取不到返回空串。"""
    m = re.search(r"^static\s+[\w\s\*]+" + re.escape(name) + r"\s*\([^;]*?\)\s*\{", src,
                  re.M)
    if not m:
        return ""
    i = m.end() - 1
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
    return ""


def check_contracts():
    log("B 段：injector 接入契约（静态判别）")
    src = INJECTOR.read_text(encoding="utf-8")
    watch_h = WATCH_H.read_text(encoding="utf-8")

    body = func_body(src, "grepl_watch_arm")
    if not body:
        fail("找不到 grepl_watch_arm()", "事件源注册函数被删掉了")
    else:
        if "ns_mnt_watch_open(" in body:
            ok("事件源由 ns_mnt_watch_open() 打开")
        else:
            fail("grepl_watch_arm 未调用 ns_mnt_watch_open()")
        if re.search(r"\.events\s*=\s*0\b", body) and "EPOLL_CTL_ADD" in body:
            ok("epoll 注册掩码为 0（mounts_poll 恒置 EPOLLIN，带上就成忙轮询）")
        else:
            fail("注册掩码不是 0",
                 "带 EPOLLIN 会电平触发的忙轮询；EPOLLERR 不受掩码约束，只留它才对")
        if "g_grepl_watch_fd = fd" in body:
            ok("句柄登记到 g_grepl_watch_fd（主循环据此分发）")
        else:
            fail("事件源句柄未登记")

    body = func_body(src, "maybe_reconcile_global_replace")
    if not body:
        fail("找不到 maybe_reconcile_global_replace()")
    else:
        if re.search(r"GREPL_STEADY_EVENT", body):
            ok("稳态分支改为等事件（GREPL_STEADY_EVENT）")
        else:
            fail("稳态仍按固定周期复查", "GREPL_STEADY_EVENT 未出现在对账函数里")
        if re.search(r"g_grepl_watch_fd\s*>=\s*0\)\s*\?\s*GREPL_STEADY_EVENT", body):
            ok("事件源可用才等事件，不可用时回落周期复查（不把功能押在事件源上）")
        else:
            fail("事件源不可用时没有兜底",
                 "必须回落到 GREPL_STEADY_SEC 周期，否则打不开 mountinfo 就再也不复查")
        if re.search(r"if\s*\(g_grepl_next_sec\s*<\s*0\)\s*return;", body):
            ok("稳态（等事件）时不再按 tick 复查")
        else:
            fail("稳态仍在按 tick 复查", "g_grepl_next_sec < 0 的提前返回被删掉了")
        if "g_grepl_replace_gap" in body and "g_grepl_last_replace_ms" in body:
            ok("两次动挂载之间有最小间隔闸（替换自身会触发事件源）")
        else:
            fail("缺少替换间隔闸",
                 "替换改变挂载表 → 事件源立即回报 → 再替换，会退化成毫秒级循环")
        # 间隔加倍必须以「窗口内反复动挂载」为条件：无条件加倍会把一次健康替换后的
        # 间隔越推越大，紧随其后的族根要等更久——这正好抹掉事件驱动的收益。
        if re.search(r"g_grepl_churn_n\s*>=\s*GREPL_CHURN_SLOTS", body) and \
                "GREPL_CHURN_WINDOW_MS" in src:
            ok("间隔只在「窗口内反复动挂载」时加倍（健康单次替换不推大间隔）")
        else:
            fail("间隔加倍没有窗口条件",
                 "无条件加倍会让健康替换把间隔推到 30s，紧跟的族根反而等更久")
        if "g_grepl_churn_n = 0" in body:
            ok("收敛（REPLACED）时清零观察窗口，间隔闸随之复位")
        else:
            fail("收敛时没有复位观察窗口", "间隔闸会带着上一轮的账继续走")
        # ret>0（尚未就绪）这一支必须在记 last_replace 之前返回：否则开机阶段攒下的
        # 退避会把「族根刚刚出现」那一刻挡在门外。
        m = re.search(r"if\s*\(ret\s*>\s*0\)\s*\{(.*?)\n    \}", body, re.S)
        if m and "last_replace" not in m.group(1):
            ok("尚未就绪（ret>0）不记替换时刻——族根一出现就能立刻接管")
        elif m:
            fail("ret>0 也记了替换时刻", "会推迟「族根刚出现」的接管")
        else:
            fail("ret>0 分支不存在", "「尚未就绪」与「失败」必须分开处理")

    body = func_body(src, "on_mnt_watch_event")
    if not body:
        fail("找不到 on_mnt_watch_event()")
    else:
        if re.search(r"GREPL_RETRY_MIN_SEC", body) and "g_grepl_next_sec = 0" in body:
            ok("事件到来：稳态立即复查、退避中压到最小档（开机挂载事件密集，不逐条复查）")
        else:
            fail("事件回调没处理退避/稳态两种计时状态")

    loop = func_body(src, "injector_event_loop")
    if "g_grepl_watch_fd" in loop and "on_mnt_watch_event()" in loop:
        ok("事件源已接入主循环分发")
    else:
        fail("事件源未接入主循环", "分发链里没有 g_grepl_watch_fd 分支")
    if loop.find("g_grepl_watch_fd") < loop.find("on_client_fd(fd)"):
        ok("分发分支排在 on_client_fd() 之前（否则新 fd 被当成客户端 fd）")
    else:
        fail("分发分支位置错误")

    if "EPOLLERR" in watch_h and "events" in watch_h:
        ok("模块头写明「注册掩码必须为 0」的用法约束")
    else:
        fail("模块头没写清注册约束", "后来的人很容易顺手加上 EPOLLIN")

    if re.search(r"#define\s+GREPL_STEADY_SEC\s+5", src) and re.search(
            r"#define\s+GREPL_STEADY_EVENT\s+\(-1\)", src):
        ok("GREPL_STEADY_SEC 退居兜底，稳态用 GREPL_STEADY_EVENT 哨兵")
    else:
        fail("稳态哨兵/兜底常量缺失")

    # 事件源不可用是**持续状态**：注册函数每个 tick 都被调用，回落判定每个周期都
    # 会走到。两处都必须自己防重，否则现场日志按秒刷同一条，真出问题时反而淹没。
    arm = func_body(src, "grepl_watch_arm")
    if re.search(r"if\s*\(!g_grepl_watch_warned\)", arm):
        ok("事件源不可用的告警只报一次（注册每个 tick 都调用，否则按秒刷屏）")
    else:
        fail("事件源告警没有防重", "grepl_watch_arm 每 tick 调用一次，LOG_WRN 会按秒重复")
    if "g_grepl_watch_warned = false" in arm and "g_grepl_fallback_logged = false" in arm:
        ok("事件源恢复后复位标志，下次再坏重新报一条")
    else:
        fail("事件源恢复后没有复位", "一次失败会把后续所有回落都静音")

    body = func_body(src, "maybe_reconcile_global_replace")
    m = re.search(r"if\s*\(g_grepl_watch_fd\s*<\s*0\s*&&\s*!g_grepl_fallback_logged\)\s*\{(.*?)\n        \}",
                  body, re.S)
    if not m:
        fail("回落周期复查时没有日志",
             "现场看不出「族根变化为什么得等一个周期」，排查只能靠猜")
    else:
        blk = m.group(1)
        if re.search(r"(^|\n)\s*LOG\(", blk):
            ok("回落打的是 INFO 级日志（LOG），不是 DEBUG")
        else:
            fail("回落日志级别不对", "回落是现场排查线索，DEBUG 级在量产日志里看不到")
        if "GREPL_STEADY_SEC" in blk:
            ok("回落日志带上兜底周期秒数")
        else:
            fail("回落日志没写周期", "只说「回落到周期」等于没说多久一轮")
        if blk.count("= true;") == 1 and "_logged" in blk:
            ok("回落日志带一次性守卫（稳态判定每周期都会走到这一行）")
        else:
            fail("回落日志没有一次性守卫", "不防重就是按周期刷屏")


# ── 沙箱执行体 ──────────────────────────────────────────────────────────────

def inner_main(exe):
    try:
        tmp_root = tempfile.mkdtemp(prefix="mnt_watch_")
        check_events(exe, tmp_root)
        shutil.rmtree(tmp_root, ignore_errors=True)
        check_contracts()
    finally:
        pass
    print(f"\n结果: {PASS} 通过, {FAIL} 失败")
    if ERRORS:
        for d, det in ERRORS:
            print(f"  ❌ {d}: {det}")
        return 1
    return 0


def build_driver(tmpdir):
    cc = shlex.split(os.environ.get("CC", "cc"))
    exe = Path(tmpdir) / "mnt_watch_driver"
    cmd = cc + [
        "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
        "-I", str(ROOT / "src" / "injector"),
        str(DRIVER), str(WATCH_C),
        "-o", str(exe),
    ]
    build = subprocess.run(cmd, capture_output=True, text=True)
    if build.returncode != 0:
        log("编译失败：\n" + build.stderr)
        return None
    return exe


def mountinfo_snapshot():
    try:
        with open("/proc/self/mountinfo") as fh:
            return sorted(fh.read().splitlines())
    except OSError:
        return []


def userns_available():
    if shutil.which("unshare") is None:
        return False
    r = subprocess.run(["unshare", "--user", "--map-root-user", "--mount", "true"],
                       capture_output=True, timeout=15)
    return r.returncode == 0


def main():
    if not DRIVER.is_file() or not WATCH_C.is_file():
        log(f"缺少 fixture 驱动或源码（{DRIVER} / {WATCH_C}）")
        return 1
    if not userns_available():
        log("跳过：user/mount ns 不可用（需要 unshare 与 userns 权限）")
        return SKIP_RC
    with tempfile.TemporaryDirectory(prefix="mnt_watch_build_") as tmpdir:
        exe = build_driver(tmpdir)
        if exe is None:
            return 1
        host_before = mountinfo_snapshot()
        cmd = ["unshare", "--user", "--map-root-user", "--mount",
               sys.executable, os.path.abspath(__file__), "--inner", str(exe)]
        try:
            r = subprocess.run(cmd, timeout=180)
            rc = r.returncode
        except subprocess.TimeoutExpired:
            log("失败：沙箱内测试超时(180s)")
            rc = 1
        host_after = mountinfo_snapshot()
        if host_before != host_after:
            diff = [ln for ln in host_after if ln not in host_before][:6]
            log(f"  ❌ 宿主 mountinfo 被污染: {'; '.join(diff)}")
            rc = 1
        else:
            log("  ✅ 宿主 mountinfo 零变化")
    return rc


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--inner":
        sys.exit(inner_main(sys.argv[2]))
    sys.exit(main())
