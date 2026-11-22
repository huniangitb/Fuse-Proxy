#!/usr/bin/env python3
"""L0: 配置重载后的运行中应用对账必须挪出注入器唯一事件循环线程。

`handle_pending_reload` 原先内联 audit_tracked_apps / audit_and_remount_specific_apps /
audit_running_apps：逐个 tracked 应用做「配置判定 + 实测视图 + 挂载/卸载/还原」，
单次挂载预算就有数百毫秒，几十个在跑的应用叠起来能把事件循环按在那里数十秒——
期间所有应用的 pre-hook 判定、IPC ACK、挂载派发全停。配置目录被反复写（工具/用户）
时还会一轮接一轮。

判别（真实 TU，无替身）：夹具直编 `src/injector/audit_worker.c`，只把审计本体换成
「慢动作 + 记账」的替身（它们是挂载/卸载的边界，夹具不碰真实挂载）。
  * `defer`：30 次突发请求在调用线程上每次 < 5ms、总耗时 < 400ms，慢审计只跑 1~3 轮、
    恒跑在别的线程、并发峰值恒 1、空闲后 /proc/self/task 回到 1；
  * `inline`：旧形态对照——同样 30 次慢审计直接跑在调用线程上，量化被冻住的时长；
  * 粒度语义：v1 → audit_running_apps；v2 + reset → audit_tracked_apps；
    v2 + 具体变更 → audit_and_remount_specific_apps，两轮请求去重合并后原样送达；
  * `shutdown`：退出等手上那一轮跑完，之后的请求不再执行。
静态检查：`handle_pending_reload` 里不得再有那三个审计调用，必须改成
`nsp_audit_request(`；`injector_shutdown` 必须先 `nsp_audit_shutdown()`。

复现旧红灯：AUDIT_WORKER_INJECTOR_SRC=<旧 injector.c> python3 tests/test_audit_defer.py --expect-old-red
（旧源里 handle_pending_reload 内联了三个审计，静态检查必须红。）
"""
import os
import re
import shlex
import subprocess
import sys
import tempfile

SKIP_RC = 77
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DRIVER = os.path.join(ROOT, 'tests', 'fixtures', 'audit_defer_driver.c')
MODULE = os.path.join(ROOT, 'src', 'injector', 'audit_worker.c')
# 审计轮整轮持挂载锁（src/injector/mount_ops.c）：真 TU 必须一起链，不能桩掉。
MOUNT_OPS = os.path.join(ROOT, 'src', 'injector', 'mount_ops.c')
INJECTOR = os.path.join(ROOT, 'src', 'injector', 'injector.c')
SPAWN_DRIVER = os.path.join(ROOT, 'tests', 'fixtures', 'audit_spawn_fail_driver.c')
AUDITS = ('audit_tracked_apps', 'audit_and_remount_specific_apps', 'audit_running_apps')
CALL_US_MAX = 5000          # 单次 nsp_audit_request 上限 5ms
BURST_TOTAL_US = 400000     # 30 次突发（含夹具自身 60ms 睡眠）总上限 400ms
MAX_ROUNDS = 3              # 合并后只该有 1~2 轮
INLINE_MIN_US = 3000000     # 旧形态对照：调用线程被冻 >=3s 才算判别成立
EXPECTED_SEEN = ['com.one.app:0', 'com.two.app:10', 'com.three.app:0', 'com.four.app:10']


def func_body(text, name):
    """按函数名取大括号体（够用的花括号计数）。"""
    m = re.search(r"\n[^\n]*\b%s\s*\([^;]*?\)\s*\{" % re.escape(name), text)
    if not m:
        return None
    start = text.index("{", m.start())
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def check_call_sites(fails, injector_path):
    """注入器接线检查；旧源应当在这里红。"""
    if not os.path.isfile(injector_path):
        fails.append(f"injector 源不存在: {injector_path}")
        return
    text = open(injector_path, encoding="utf-8").read()
    if '#include "audit_worker.h"' not in text:
        fails.append("injector.c 未包含 audit_worker.h")
    # 重载已拆两段：对账派发在提交段 reload_apply_view；旧源只有一次性
    # handle_pending_reload，这里自然红。
    start_body = func_body(text, "handle_pending_reload_begin")
    finish_body = func_body(text, "handle_pending_reload_finish")
    body = func_body(text, "reload_apply_view")
    if start_body is None or finish_body is None or body is None:
        fails.append("找不到两段式重载的入口/提交段")
    else:
        if "nsp_audit_request(" not in body:
            fails.append("重载提交段未派发 nsp_audit_request()")
        for name in AUDITS:
            for where, blob in (("begin", start_body), ("finish", finish_body),
                                ("apply", body)):
                if re.search(r"\b%s\s*\(" % name, blob):
                    fails.append(f"重载{where}段仍内联 {name}()（慢对账还在事件循环上）")
        commit = body.find("config_commit_prepared(")
        request = body.find("nsp_audit_request(")
        if commit >= 0 and request >= 0 and not commit < request:
            fails.append("对账派发必须排在配置提交之后（先发布视图再对账）")
        cell = body[request:body.find(";", request) + 1] if request >= 0 else ""
        if "out_changed" not in cell:
            fails.append("派发没有带上 out_changed（具体变更被吞成空集合）")
        if "changed_count == -1" not in cell or "changed_count > 0" not in cell:
            fails.append("changed_count → (变更集合, reset) 映射写错："
                         "整体变化(-1) 必须当 reset，条目只在 >0 时携带")
    shutdown = func_body(text, "injector_shutdown")
    if shutdown is None:
        fails.append("找不到 injector_shutdown()")
    elif "nsp_audit_shutdown()" not in shutdown:
        fails.append("injector_shutdown 未调用 nsp_audit_shutdown()（后台对账线程不受控）")


def build(work, tag, sanitize):
    exe = os.path.join(work, f"audit_defer_{tag}")
    cmd = [
        "cc", "-std=gnu2x", "-DTARGET_GNU=1", "-D_GNU_SOURCE", "-O1",
        "-Wall", "-Wextra", "-Werror", "-I", os.path.join(ROOT, "include"),
    ]
    if sanitize:
        cmd += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    cmd += [DRIVER, MODULE, MOUNT_OPS, "-o", exe, "-pthread"]
    print("$", shlex.join(cmd), flush=True)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.stdout + result.stderr:
        print(result.stdout + result.stderr, end="", flush=True)
    if result.returncode != 0:
        raise SystemExit(f"编译失败: {tag}")
    return exe


def build_spawn(work):
    """起线程失败路径的夹具：--wrap=pthread_create 精确注入 EAGAIN。"""
    exe = os.path.join(work, "audit_spawn_fail")
    cmd = [
        "cc", "-std=gnu2x", "-DTARGET_GNU=1", "-D_GNU_SOURCE", "-O1",
        "-Wall", "-Wextra", "-Werror", "-I", os.path.join(ROOT, "include"),
        SPAWN_DRIVER, MODULE, MOUNT_OPS, "-Wl,--wrap=pthread_create", "-o", exe, "-pthread",
    ]
    print("$", shlex.join(cmd), flush=True)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.stdout + result.stderr:
        print(result.stdout + result.stderr, end="", flush=True)
    if result.returncode != 0:
        raise SystemExit("编译失败: audit_spawn_fail")
    return exe


def run_mode(exe, mode, timeout=90):
    print(f"$ {shlex.join([exe, mode])}", flush=True)
    result = subprocess.run([exe, mode], capture_output=True, text=True, timeout=timeout)
    out = result.stdout + result.stderr
    print(out, end="", flush=True)
    print(f"exit={result.returncode}", flush=True)
    if result.returncode != 0:
        return None
    values = {}
    for line in out.splitlines():
        if line.startswith("mode="):
            for item in line.split(" "):
                if "=" in item:
                    key, _, val = item.partition("=")
                    values[key] = val
        if line.startswith("seen_items="):
            values["seen_items"] = line.partition("=")[2]
    return values


def check_defer(fails, v):
    if v is None:
        fails.append("defer 模式运行失败")
        return
    call_us_max = int(v.get("call_us_max", -1))
    total_us = int(v.get("total_us", -1))
    runs = int(v.get("runs", -1))
    offmain = int(v.get("offmain", -1))
    peak = int(v.get("peak", -1))
    threads = int(v.get("threads", -1))
    if call_us_max < 0 or call_us_max > CALL_US_MAX:
        fails.append(f"单次请求在调用线程上花了 {call_us_max}us（上限 {CALL_US_MAX}）")
    if total_us < 0 or total_us > BURST_TOTAL_US:
        fails.append(f"30 次突发在调用线程上共花 {total_us}us（上限 {BURST_TOTAL_US}）")
    if runs < 1 or runs > MAX_ROUNDS:
        fails.append(f"慢审计跑了 {runs} 轮（应合并到 1~{MAX_ROUNDS} 轮）")
    if offmain != runs:
        fails.append(f"有 {runs - offmain} 轮审计跑在调用线程上（必须全部在 worker 上）")
    if peak != 1:
        fails.append(f"审计并发峰值 {peak}（必须恒为 1）")
    if threads != 1:
        fails.append(f"空闲后仍有 {threads} 个线程（worker 未自退）")


def main():
    global MODULE
    expect_old_red = "--expect-old-red" in sys.argv
    fixture_module = os.environ.get("AUDIT_WORKER_SRC", MODULE)
    injector = os.environ.get("AUDIT_WORKER_INJECTOR_SRC", INJECTOR)
    print(f"module={fixture_module}", flush=True)
    print(f"injector={injector}", flush=True)
    MODULE = fixture_module
    fails = []
    check_call_sites(fails, injector)
    with tempfile.TemporaryDirectory(prefix="audit_defer_") as work:
        plain = build(work, "plain", False)
        values = {m: run_mode(plain, m) for m in
                  ("defer", "inline", "mode_v1", "mode_reset_v2", "mode_specific_v2",
                   "mode_both_reset_first", "mode_both_specific_first", "shutdown")}
        asan = build(work, "asan", True)
        asan_defer = run_mode(asan, "defer")
        asan_shutdown = run_mode(asan, "shutdown")
        spawn = build_spawn(work)
        spawn_retry = run_mode(spawn, "retry")
        spawn_race = run_mode(spawn, "shutdown_race")

    if not expect_old_red:
        check_defer(fails, values["defer"])
        check_defer(fails, asan_defer)
        inline = values["inline"]
        if inline is None or int(inline.get("total_us", 0)) < INLINE_MIN_US:
            fails.append("inline 对照组没有复现「调用线程被慢审计冻住」（判别不成立）")
        v1 = values["mode_v1"]
        if v1 is None or (v1.get("running"), v1.get("tracked"), v1.get("specific")) != ("1", "0", "0"):
            fails.append("v1 模式下没有走全量对账 audit_running_apps()")
        reset = values["mode_reset_v2"]
        if reset is None or (reset.get("tracked"), reset.get("specific"), reset.get("running")) != ("1", "0", "0"):
            fails.append("v2 + 整体变化 没有走 audit_tracked_apps()")
        spec = values["mode_specific_v2"]
        if spec is None:
            fails.append("mode_specific_v2 运行失败")
        else:
            # 只断言语义（具体变更、不回落整体对账、送达集合与去重），不断言轮数：
            # 第二份请求可能落在同一待跑轮、也可能被 worker 抓走后另起一轮，两种都合法。
            if int(spec.get("specific", 0)) < 1 or spec.get("tracked") != "0" \
                    or spec.get("running") != "0":
                fails.append("v2 + 具体变更 没有走 audit_and_remount_specific_apps()")
            seen = [x for x in spec.get("seen_items", "").split(",") if x]
            if sorted(seen) != sorted(EXPECTED_SEEN):
                fails.append(f"变更集合送达不符（去重/合并/user_id 漂移）: {spec.get('seen_items')}")
            if int(spec.get("max_items", 99)) > len(EXPECTED_SEEN):
                fails.append(f"单轮审计集合大小 {spec.get('max_items')}，应 <= {len(EXPECTED_SEEN)}")
        # 同一轮里既整体变化又有具体条目：两路都必须跑（旧实现互斥，条目整轮丢）
        for mode in ("mode_both_reset_first", "mode_both_specific_first"):
            both = values[mode]
            if both is None:
                fails.append(f"{mode} 运行失败")
                continue
            if int(both.get("tracked", 0)) < 1:
                fails.append(f"{mode}: 整体变化没有走全量对账（tracked=0）")
            if int(both.get("specific", 0)) < 1:
                fails.append(f"{mode}: 具体条目整轮丢失（specific=0，两路互斥回归）")
            if both.get("running") != "0":
                fails.append(f"{mode}: v2 下不该走 audit_running_apps")
            seen = [x for x in both.get("seen_items", "").split(",") if x]
            for want in ("com.b1.app:0", "com.b2.app:10", "com.b3.app:0"):
                if want not in seen:
                    fails.append(f"{mode}: 具体条目未送达 {want}（实到 {seen}）")
        shut = values["shutdown"]
        if shut is None:
            fails.append("shutdown 运行失败")
        else:
            if int(shut.get("shutdown_us", 0)) < 100000:
                fails.append(f"shutdown 只等了 {shut.get('shutdown_us')}us，没等手上那一轮跑完")
            if shut.get("runs_after") != shut.get("runs_before"):
                fails.append("shutdown 之后的请求仍被执行了")
            if shut.get("threads") != "1" or shut.get("active") != "0":
                fails.append("shutdown 后仍有 worker 线程/活跃对账")
        if asan_shutdown is None:
            fails.append("ASan/UBSan 版 shutdown 运行失败")
        if spawn_retry is None:
            fails.append("起线程失败后：下一请求没能补跑保留的那一轮（retry 失败）")
        else:
            if spawn_retry.get("ok") != "1" or int(spawn_retry.get("call_us", 1 << 30)) > 50000:
                fails.append(f"起线程失败时调用线程被拖住或没补跑: {spawn_retry}")
            # 失败那一轮是「整体变化」，恢复后的请求带 3 条不同条目：两者都必须送达
            if int(spawn_retry.get("tracked_runs", 0)) < 1:
                fails.append("创建失败时排队的那一轮被丢了（tracked_runs=0）")
            if int(spawn_retry.get("specific_runs", 0)) < 1:
                fails.append("合并进保留轮的具体变更没送达（两路互斥）")
            if spawn_retry.get("seen") != "3":
                fails.append(f"具体变更条数 {spawn_retry.get('seen')}，应为 3")
        if spawn_race is None:
            fails.append("创建慢失败时 nsp_audit_shutdown 未返回（会永久挂住退出）")
        elif spawn_race.get("ok") != "1":
            fails.append(f"shutdown_race 未通过: {spawn_race}")

    if expect_old_red:
        raced = spawn_race is None  # 旧实现：create 慢失败时 shutdown 永久挂住 -> 看门狗杀死
        if fails and raced:
            for item in fails:
                print(f"[FAIL] {item}", flush=True)
            print("旧实现按预期红（静态接线 + 起线程失败挂住）", flush=True)
            return 0
        for item in fails:
            print(f"[FAIL] {item}", flush=True)
        print(f"旧实现判据不成立：静态红={bool(fails)} 起线程失败挂住={raced}", flush=True)
        return 1

    if fails:
        for item in fails:
            print(f"[FAIL] {item}", flush=True)
        print(f"❌ {len(fails)} 项失败", flush=True)
        return 1
    print("✅ 全部通过：对账已移出事件循环，粒度与生命周期语义保持", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
