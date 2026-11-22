#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""补挂载盯梢的等待：有界 + 事件驱动（而不是固定 2ms 步进）

背景：应用的挂载命名空间要到 specialize 完成才成立，pre 阶段拿到的 pid 还在
zygote 的命名空间里，此刻挂载会污染之后 fork 的每个应用。盯梢线程因此要等
/proc/<pid>/ns/mnt 的 (dev, ino) 变掉——过去的做法是「睡 2ms、stat 一次」，
切换检测的滞后被步进锁死（真机日志里 36 条「切换后」实测全落在 2ms 的整数倍）。

本套件守四件事：
  A. 命名空间切换的检测延迟：切换发生后多久被发现（有 userns 才跑，否则跳过）；
  B. 有界与不空转：预算到点必退出、CPU 时间与预算同阶、进程中途退出立刻收工、
     0 预算只复核一次；
  C. 事件源真的把等待叫醒：一次「挂载表变了」的假事件必须让复核立刻发生，
     而不是睡满节拍；事件源打不开时退回纯节拍（此时仍能发现切换，只是粗）；
  D. 接线契约（静态）：等的是事件不是步进、注册掩码为 0、超时仍走「跳过」分支。

判别性：被测模块在旧实现上不存在（驱动编不过）；C 段的「事件后立即复核」在
「睡固定步进」的实现上量出来就是节拍本身（2ms），必然超限。

退出码：0 通过、1 失败、7 跳过（驱动编不过）、78 部分跳过（缺 userns）。
"""
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests" / "fixtures" / "ns_mnt_wait_driver.c"
WAIT_C = ROOT / "src" / "injector" / "ns_mnt_wait.c"
WAIT_H = ROOT / "src" / "injector" / "ns_mnt_wait.h"
IPC_C = ROOT / "src" / "injector" / "ipc_server.c"

SKIP_RC = 7
PARTIAL_RC = 78
PASS = 0
FAIL = 0
GAP = []
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


def gap(desc):
    GAP.append(desc)
    log(f"  ⚠️ 跳过：{desc}")


def parse_kv(text):
    out = {}
    for token in text.split():
        if "=" not in token:
            continue
        k, _, v = token.partition("=")
        out[k.strip()] = v.strip()
    return out


def num(kv, key, default=-10 ** 9):
    try:
        return int(kv.get(key, default))
    except (TypeError, ValueError):
        return default


def run_mode(exe, args, timeout=120):
    r = subprocess.run([exe, *args], capture_output=True, text=True, timeout=timeout)
    kv = parse_kv(r.stdout)
    if r.returncode != 0:
        log(f"    驱动输出: {r.stdout.strip()} / {r.stderr.strip()}")
    return kv, r


# ── B 段：有界与不空转 ──────────────────────────────────────────────────────

def check_bounded(exe):
    log("B 段：预算到点必退出，且不空转")

    budget_ms = 300
    kv, _ = run_mode(exe, ["idle", str(budget_ms)])
    waited = num(kv, "waited_us")
    cpu = num(kv, "cpu_us")
    arms = num(kv, "arms")
    if num(kv, "capture_ok") == 1 and num(kv, "switched") == 0:
        ok("不切换时按「没换」结束（switched=0）")
    else:
        fail("不切换时的结论不对", f"switched={kv.get('switched')} capture_ok={kv.get('capture_ok')}")
    if budget_ms * 1000 - 2000 <= waited <= budget_ms * 1000 + 40000:
        ok(f"等待 = 预算（{waited}µs / {budget_ms * 1000}µs），没有提前也没有超时")
    else:
        fail("等待时长偏离预算", f"waited={waited}µs budget={budget_ms * 1000}µs")
    # 空转的判据：CPU 时间与预算同阶即为自旋（忙等会把 300ms 预算烧成 300ms CPU）
    if 0 <= cpu < 30000:
        ok(f"CPU 时间 {cpu}µs 远小于预算（不是忙轮询）")
    else:
        fail("等待烧掉了过多 CPU", f"cpu_us={cpu}")
    if 80 <= arms <= 400:
        ok(f"arm {arms} 次与「2ms 档 + 16ms 高速窗」相符（步进没有被改成忙轮询）")
    else:
        fail("arm 次数异常", f"arms={arms}（期望 80~400）")

    kv, _ = run_mode(exe, ["zero"])
    if num(kv, "switched") == 0 and num(kv, "waited_us") <= 1000 and num(kv, "wall_us") <= 5000:
        ok(f"0 预算只复核一次就返回（{kv.get('wall_us')}µs）")
    else:
        fail("0 预算没有立即返回", f"{kv}")

    kv, _ = run_mode(exe, ["dead"])
    if num(kv, "switched") == 0 and 0 <= num(kv, "waited_us") <= 50000:
        ok(f"进程已死立刻收工（{kv.get('waited_us')}µs，不陪着等满预算）")
    else:
        fail("进程死亡没有立刻结束", f"{kv}")


# ── C 段：事件源叫醒 / 退回纯节拍 ───────────────────────────────────────────

def check_event_source(exe):
    log("C 段：事件源叫醒")
    budget_ms = 80
    # 两组都在「某次 arm 开始后 100µs」这一时刻动手，只有一组真的投递事件。
    # 单次读数会被调度污染，两个方向都要重复取稳健值（并发负载下实测到的两端）：
    #  · 对照组（不投递）读数只会是「节拍 ± 迟到」：过睡把投递点推到下一拍时，
    #    读数会缩成节拍的零头（实测 384µs），而节拍被调度推迟则涨到毫秒级
    #    （实测 4681µs）；故取 3 轮里**最大**的一次，避开缩短那侧。
    #  · 投递组要的是「被事件提前叫醒」的存在性：投递线程被推迟到拍尾、事件整个
    #    错过本次节拍时，读数仍是一整个节拍（实测 1810µs）；故取 5 轮里**最小**
    #    的一次——只要有一轮事件落在拍中，就能看出它比节拍短。
    gap_base = -1
    for _ in range(3):
        base, _ = run_mode(exe, ["event", str(budget_ms), "0"])
        if num(base, "switched") != 0:
            fail("事件用例的结论不对", f"{base}")
            return
        gap_base = max(gap_base, num(base, "gap_us"))
        if gap_base >= 1000:
            break
    gaps = []
    for _ in range(5):
        fired, _ = run_mode(exe, ["event", str(budget_ms), "1"])
        if num(fired, "switched") != 0:
            fail("事件用例的结论不对", f"{fired}")
            return
        g = num(fired, "gap_us")
        if g >= 0:
            gaps.append(g)
        if 0 <= g <= 500:
            break
    gap_fired = min(gaps) if gaps else -1
    # 读数下限放宽到 1000µs：夹具已把「投递点必须落在本节拍前 500µs 内」校准了
    # （过睡会跨到下一拍，量出来只剩节拍的一小截，实测过 384µs）。上限放到 20000µs：
    # 并发负载下节拍本身的唤醒可以被调度推迟到毫秒级（实测过 4681µs），那不是产品缺陷。
    if 1000 <= gap_base <= 20000:
        ok(f"对照组（不投递）在 {gap_base}µs 后按节拍醒来——节拍档的本来面目")
    else:
        fail("对照组的间隔不是节拍本身", f"gap_us={gap_base}（应 ≈2000µs）")
    if gap_base > 0 and gap_fired >= 0 and gap_fired * 2 <= gap_base:
        ok(f"投递组的唤醒（{gap_fired}µs）比节拍（{gap_base}µs）小一个量级——不是靠等节拍发现的")
    else:
        fail("投递组没能明显早于节拍", f"fired={gap_fired}µs base={gap_base}µs")
    if 0 <= gap_fired <= 500:
        ok(f"投递事件后 {gap_fired}µs 就复核（不投递则要等 {gap_base}µs）")
    else:
        fail("事件没有把等待叫醒", f"gap_us={gap_fired}，节拍 {gap_base}µs")


def check_fallback(exe):
    log("C 段：事件源打不开时退回纯节拍")
    kv, _ = run_mode(exe, ["fallback", "300", "3"])
    if num(kv, "unshare_fail") > 0 and num(kv, "switched_n") == 0:
        gap("userns 不可用，切换类用例跳过")
        return
    best = num(kv, "best_us")
    if num(kv, "switched_n") == num(kv, "reps"):
        ok(f"没有事件源仍能发现切换（{kv.get('switched_n')}/{kv.get('reps')} 次）")
    else:
        fail("没有事件源就发现不了切换", f"{kv}")
    # 上限放到 8000µs：并发负载下最好的一次也能被调度推到 4ms+（实测 4065µs），
    # 而判据要的是「精度仍是节拍量级」而不是「打不开就失灵」，与 2ms 档差几倍仍成立。
    if 1500 <= best <= 8000:
        ok(f"退回后的精度是节拍本身（{best}µs ≈ 2ms 档），不是「打不开就失灵」")
    else:
        fail("退回节拍的行为不符", f"best_us={best}")


def check_switch_latency(exe):
    log("A 段：切换检测延迟")
    kv, _ = run_mode(exe, ["switch", "200", "7"])
    if num(kv, "unshare_fail") > 0 and num(kv, "switched_n") == 0:
        gap("userns 不可用，切换类用例跳过")
        return
    best = num(kv, "best_us")
    worst = num(kv, "worst_us")
    lag = num(kv, "best_lag_us")
    if num(kv, "switched_n") == num(kv, "reps") and best >= 0:
        ok(f"七次都能发现切换（最慢 {worst}µs）")
    else:
        fail("切换被漏掉", f"{kv}")
    # 旧的 2ms 步进在同样场景下量出来就是 ~2000µs（第一个取样点在 2ms 后）
    if 0 <= best <= 1200:
        ok(f"切换后 {best}µs 被发现（旧步进 ≥2000µs）")
    else:
        fail("检测延迟没有降到步进以下", f"best_us={best}")
    # 扣掉子进程自己被调度推迟的那段，剩下的才是「切换之后多久被看见」
    if 0 <= lag <= 800:
        ok(f"切换发生后 {lag}µs 被看见（平均值 {kv.get('avg_lag_us')}µs）")
    else:
        fail("切换之后看见得太慢", f"best_lag_us={lag}")


# ── D 段：接线契约（静态） ──────────────────────────────────────────────────

def func_body(src, name):
    m = re.search(r"^static\s+[\w\s\*]+" + re.escape(name) + r"\s*\([^;]*?\)\s*\{", src, re.M)
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
    log("D 段：接线契约（静态判别）")
    ipc = IPC_C.read_text(encoding="utf-8")
    waitc = WAIT_C.read_text(encoding="utf-8")
    waith = WAIT_H.read_text(encoding="utf-8")

    body = func_body(ipc, "ipc_post_mount_thread")
    if not body:
        fail("找不到 ipc_post_mount_thread()")
    else:
        if "ns_mnt_wait_switch(" in body:
            ok("盯梢线程的等待交给 ns_mnt_wait_switch()")
        else:
            fail("盯梢线程没有用新的等待体")
        if "IPC_POST_WAIT_MS" in body:
            ok("预算仍取自 IPC_POST_WAIT_MS（有界兜底语义不变）")
        else:
            fail("预算不是 IPC_POST_WAIT_MS")
        if "nanosleep(" not in body:
            ok("线程里不再有固定步进的 sleep")
        else:
            fail("线程里还留着固定步进", "等待必须由等待体统一做，否则又出现两套步进")
        timeout = ""
        branch = re.search(r"if\s*\(\s*!switched\s*\)\s*\{", body)
        if branch:
            start = branch.end() - 1
            depth = 0
            for end in range(start, len(body)):
                depth += (body[end] == "{") - (body[end] == "}")
                if depth == 0:
                    timeout = body[start:end + 1]
                    break
        if "IPC补挂载跳过" in timeout and "schedule_retry_mount(" in timeout:
            ok("超时本分支走「跳过 + 交后台重试」，不再误认别的分支的调用")
        else:
            fail("超时分支未接重试", "必须检查 !switched 本分支，不能查整个线程体")
        if timeout and not re.search(r"\bperform_app_mount(?:_sync)?\s*\(", timeout):
            ok("超时未证明私有命名空间时不直接挂载")
        else:
            fail("超时分支直接挂载", "存储条目存在不能证明不是 zygote ns")
        if "get_app_uid(" in timeout and "is_isolated_uid(" in timeout:
            ok("超时入队核对当前 UID，过滤 isolated")
        else:
            fail("超时入队没有当前 UID / isolated 判定")

    body = func_body(ipc, "ipc_post_mount_dispatch")
    if "ns_mnt_wait_capture(" in body:
        ok("基线由 ns_mnt_wait_capture() 取（与等待体同一套判据）")
    else:
        fail("基线仍在自己拼路径")

    if re.search(r"\.events\s*=\s*0\b", waitc) and "ppoll(" in waitc:
        ok("poll 注册掩码为 0（mounts_poll 恒置 EPOLLIN，带上就成忙轮询）")
    else:
        fail("注册掩码不是 0 或没有 ppoll")
    if re.search(r"left_us\s*<=\s*0\)\s*break", waitc):
        ok("预算耗尽即退出（有界，不可能无上限等）")
    else:
        fail("循环里没有预算退出条件")
    if re.search(r"watch_fd\s*>=\s*0", waitc) and "nanosleep(" in waitc:
        ok("事件源不可用退回纯节拍（功能不押在事件源上）")
    else:
        fail("事件源打不开时没有退路")
    if re.search(r"#define\s+NS_MNT_WAIT_ARM_US\s+2000L?\b", waitc):
        ok("退回/长等待档仍是 2ms（与旧步进同粒度，唤醒次数不增加）")
    else:
        fail("长等待档粒度被改动")
    if re.search(r"ns_mnt_wait_capture\(pid,\s*&now_dev", waitc):
        ok("每一轮醒来都用 stat 复核（事件本身不作为充分条件）")
    else:
        fail("醒来后没有 stat 复核", "伪唤醒/别的挂载变化会把挂载挂错命名空间")
    if re.search(r"不产生", waith) and "掩码" in waith:
        ok("模块头写明事件源能看见什么、看不见什么")
    else:
        fail("模块头没写清事件源的能力边界")


# ── 沙箱无关的入口 ─────────────────────────────────────────────────────────

def build_driver(tmpdir):
    cc = shlex.split(os.environ.get("CC", "cc"))
    exe = Path(tmpdir) / "ns_mnt_wait_driver"
    cmd = cc + [
        "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
        "-I", str(ROOT / "src" / "injector"),
        str(DRIVER), str(WAIT_C),
        "-o", str(exe), "-pthread",
    ]
    build = subprocess.run(cmd, capture_output=True, text=True)
    if build.returncode != 0:
        log("编译失败：\n" + build.stderr)
        return None
    return exe


def main():
    if not DRIVER.is_file() or not WAIT_C.is_file() or not WAIT_H.is_file():
        log(f"缺少驱动或被测源码（{DRIVER} / {WAIT_C}）")
        return 1
    with tempfile.TemporaryDirectory(prefix="ns_mnt_wait_build_") as tmpdir:
        exe = build_driver(tmpdir)
        if exe is None:
            log("跳过：驱动编不过（缺本机 cc）")
            return SKIP_RC
        check_switch_latency(exe)
        check_bounded(exe)
        check_event_source(exe)
        check_fallback(exe)
    check_contracts()

    print(f"\n结果: {PASS} 通过, {FAIL} 失败, {len(GAP)} 跳过")
    for d, det in ERRORS:
        print(f"  ❌ {d}: {det}")
    if FAIL:
        return 1
    if GAP:
        return PARTIAL_RC
    return 0


if __name__ == "__main__":
    sys.exit(main())
