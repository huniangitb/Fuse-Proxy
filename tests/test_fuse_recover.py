#!/usr/bin/env python3
"""L0: FUSE 崩溃恢复的重启序列必须挪出注入器唯一事件循环线程。

`check_and_recover_fuse()` 跑在注入器唯一的 epoll 循环里（每个 1s tick）。旧代码一旦
发现全局 daemon 死掉，就内联整段重启序列：等旧实例退出的 10ms×50 轮询、SIGKILL 后
50ms、`ns_force_umount_stale` 之后最多 20×20ms 的卸载复核、fork+exec 新实例，以及
`cleanup_all_target_apps()` 对全进程表逐个核挂载——秒级慢活。这段时间里 pre-hook 判定、
挂载派发与 IPC ACK 全部停住；zygisk pre-hook 的 IPC 超时只有 100ms，超时即 fail-open。

判别（真实 TU）：夹具直编 `src/injector/fuse_recover.c`，用慢回调（150ms）代替真实重启
  offload  —— request 必须 µs 级返回，回调跑在 worker 上、经 eventfd 交回完成；
  inline   —— 同二进制对照组：直接调回调会把调用线程冻住整段（判别力自检）；
  coalesce —— 慢回调进行中再发 40 次请求，只许多跑 1 轮（请求合并）；
  shutdown —— 退出等手上那轮跑完（有界），之后请求被拒绝、线程数回 1；
  early    —— 没有完成过一轮时 take 返回 false。
静态检查同时核对注入器接线（慢活必须在恢复回调里、循环只发请求、就绪 fd 分支、
shutdown join）。复现旧红灯：
  FUSE_RECOVER_INJECTOR_SRC=<旧 injector.c> python3 tests/test_fuse_recover.py --expect-old-red
"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SKIP_RC = 77
ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "tests/fixtures/fuse_recover_driver.c"
INJECTOR = ROOT / "src/injector/injector.c"
MODULE = "src/injector/fuse_recover.c"
WORK_MS = 150
LIMIT_REQUEST_US = 5000       # request 只入队：上限 5ms（实测 61µs 含首次建线程）
READY_MIN_MS = WORK_MS - 40   # 完成通知必须等真跑完（否则说明阶段没等回调）
READY_MAX_MS = 3000
INLINE_MIN_MS = WORK_MS - 40  # inline 对照组：调用线程必须被真冻住
MAX_ROUNDS = 2                # 40 次突发只许多跑 1 轮
BURST_LIMIT_US = 20000
SHUTDOWN_MIN_MS = WORK_MS // 2
SHUTDOWN_MAX_MS = 3000


def func_body(text, name):
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
    """注入器接线检查；返回是否全部通过（旧源应当在这里红）。"""
    if not os.path.isfile(injector_path):
        print("❌ 找不到注入器源码: %s" % injector_path)
        fails.append("injector-missing")
        return False
    with open(injector_path, encoding="utf-8") as fh:
        text = fh.read()
    names = ("check_and_recover_fuse", "injector_fuse_recover_cb",
             "injector_event_loop", "injector_setup_epoll", "injector_shutdown")
    bodies = {name: func_body(text, name) for name in names}
    ok = True
    for name, body in bodies.items():
        if body is None:
            print("❌ 注入器里没有 %s()——恢复阶段化没有落地" % name)
            fails.append("missing-" + name)
            ok = False
    if not ok:
        return False
    tick = bodies["check_and_recover_fuse"]
    recover = bodies["injector_fuse_recover_cb"]
    loop = bodies["injector_event_loop"]
    setup = bodies["injector_setup_epoll"]
    shutdown = bodies["injector_shutdown"]

    def need(cond, tag, message):
        nonlocal ok
        if not cond:
            print("❌ " + message)
            fails.append(tag)
            ok = False

    slow_calls = ("force_recover_tracked_mounts(", "inject_global_fuse(",
                  "cleanup_all_target_apps(")
    need("nsp_fuse_recover_request()" in tick, "tick-request",
         "check_and_recover_fuse 没有把重启序列交给恢复 worker（缺 nsp_fuse_recover_request）")
    for call in slow_calls:
        need(call not in tick, "tick-inline-" + call,
             "check_and_recover_fuse 仍在事件循环上内联 %s" % call)
        need(call in recover, "recover-missing-" + call,
             "恢复回调里没有 %s（慢活没有真正搬进 worker）" % call)
    need("g_pending_remount = 1" not in recover, "recover-writes-remount",
         "恢复回调直接写了 g_pending_remount——那是循环线程的记账")
    need("g_pending_remount = 1" in tick, "tick-remount-flag",
         "check_and_recover_fuse 没有在发请求时置重挂标记：新实例就绪事件可能早于"
         "worker 回报，重挂会一直被推迟到下一次 FUSE 就绪")
    need("fd == g_fuse_recover_fd" in loop, "loop-branch",
         "事件循环里没有恢复 worker 的就绪 fd 分支")
    need("nsp_fuse_recover_take()" in loop, "loop-take",
         "就绪分支没有取走完成结果（重挂记账会丢）")
    need("nsp_fuse_recover_start(" in setup, "setup-start",
         "injector_setup_epoll 没有启动恢复 worker")
    need("nsp_fuse_recover_shutdown()" in shutdown, "shutdown-join",
         "injector_shutdown 没有 join 恢复 worker（退出会遇到在跑的重启序列）")
    return ok


def build(work, tag, sanitize=False):
    exe = work / ("fr_" + tag)
    cc = os.environ.get("CC", "cc")
    cmd = [cc, "-std=c23", "-DTARGET_GNU=1", "-D_GNU_SOURCE", "-O1", "-g",
           "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "include")]
    if sanitize:
        cmd += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    cmd += [str(ROOT / MODULE), str(DRIVER), "-o", str(exe), "-lpthread"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr)
        return None
    return exe


def run_mode(exe, mode, work_ms=WORK_MS, timeout=60):
    try:
        r = subprocess.run([str(exe), mode, str(work_ms)], capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr)
        return None
    vals = dict(re.findall(r"(\w+)=(-?\d+)", r.stdout))
    return vals


def main():
    expect_old_red = "--expect-old-red" in sys.argv
    fails = []
    injector_path = os.environ.get("FUSE_RECOVER_INJECTOR_SRC", str(INJECTOR))
    wiring_ok = check_call_sites(fails, injector_path)
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        exe = build(work, "plain")
        asan = build(work, "asan", sanitize=True) if exe else None
        if exe is None:
            print("❌ 夹具编译失败")
            fails.append("build")
            return 1
        vals = {}
        if not expect_old_red:
            for mode in ("offload", "inline", "coalesce", "shutdown", "early"):
                vals[mode] = run_mode(exe, mode)
                if vals[mode] is None:
                    fails.append("run-" + mode)
                    print("❌ %s 模式运行失败" % mode)
        else:
            vals["offload"] = run_mode(exe, "offload")
        if not expect_old_red and asan is not None:
            for mode in ("offload", "shutdown", "coalesce"):
                if run_mode(asan, mode, timeout=120) is None:
                    print("❌ ASan 版 %s 模式运行失败" % mode)
                    fails.append("asan-" + mode)

    if expect_old_red:
        # 红灯要落在「慢活还在 tick 里」这个事实上，而不只是「函数不存在」：
        # 旧源的 check_and_recover_fuse 必须真的内联那三个慢调用。
        old_inline = []
        try:
            with open(injector_path, encoding="utf-8") as fh:
                old_tick = func_body(fh.read(), "check_and_recover_fuse") or ""
            for call in ("force_recover_tracked_mounts(", "inject_global_fuse(",
                         "cleanup_all_target_apps("):
                if call in old_tick:
                    old_inline.append(call.rstrip("("))
        except OSError:
            old_tick = ""
        if not wiring_ok and old_inline:
            for item in fails:
                print("[FAIL] %s" % item)
            print("旧实现按预期红：check_and_recover_fuse 仍内联 %s" % ", ".join(old_inline))
            return 0
        print("旧实现判据不成立：静态红=%s tick 内联慢调用=%s" % (not wiring_ok, old_inline))
        return 1

    off = vals.get("offload") or {}
    if off.get("start_failed"):
        fails.append("start")
    if int(off.get("request_us", 1 << 30)) > LIMIT_REQUEST_US:
        fails.append("request-slow")
        print("❌ request 阻塞了 %sus（应只入队）" % off.get("request_us"))
    if int(off.get("got", 0)) != 1:
        fails.append("no-ready")
        print("❌ 恢复跑完没有写就绪 eventfd")
    if int(off.get("took", 0)) != 1:
        fails.append("no-take")
        print("❌ take() 没有取到完成结果")
    ready_ms = int(off.get("ready_ms", -1))
    if not (READY_MIN_MS <= ready_ms <= READY_MAX_MS):
        fails.append("ready-window")
        print("❌ 完成通知在 %sms 就到（应等回调跑完 %sms）" % (ready_ms, WORK_MS))
    if int(off.get("cb_off_main", 0)) != 1:
        fails.append("cb-on-caller")
        print("❌ 回调不在 worker 线程上（等于没挪走）")
    if int(off.get("runs", 0)) != 1:
        fails.append("runs")
        print("❌ 单次请求跑了 %s 轮" % off.get("runs"))
    if int(off.get("threads", -1)) != 1:
        fails.append("threads")
        print("❌ worker 跑完线程数没有回到 1（%s）" % off.get("threads"))

    inline = vals.get("inline") or {}
    if int(inline.get("inline_ms", -1)) < INLINE_MIN_MS:
        fails.append("inline-control")
        print("❌ inline 对照组没有被冻住（%sms），判别力不成立" % inline.get("inline_ms"))
    if inline.get("cb_off_main") != "0":
        fails.append("inline-main")

    co = vals.get("coalesce") or {}
    if int(co.get("burst_us", 1 << 30)) > BURST_LIMIT_US:
        fails.append("burst-slow")
        print("❌ 40 次突发请求花了 %sus" % co.get("burst_us"))
    rounds = int(co.get("rounds", -1))
    if not (1 <= rounds <= MAX_ROUNDS):
        fails.append("coalesce")
        print("❌ 突发请求跑了 %s 轮（应合并到 <=%s）" % (rounds, MAX_ROUNDS))
    if int(co.get("threads", -1)) != 1:
        fails.append("coalesce-threads")

    sh = vals.get("shutdown") or {}
    sd_ms = int(sh.get("shutdown_ms", -1))
    if not (SHUTDOWN_MIN_MS <= sd_ms <= SHUTDOWN_MAX_MS):
        fails.append("shutdown-wait")
        print("❌ shutdown 只等了 %sms（应等手上那轮跑完）" % sd_ms)
    if sh.get("runs_after") != sh.get("runs_before"):
        fails.append("shutdown-runs")
        print("❌ shutdown 之后还有回调在跑")
    if sh.get("after_req") != "0":
        fails.append("shutdown-accept")
        print("❌ shutdown 之后 request 仍被接受")
    if int(sh.get("threads", -1)) != 1:
        fails.append("shutdown-threads")

    ea = vals.get("early") or {}
    if ea.get("early_take") != "0":
        fails.append("early-take")
        print("❌ 没有跑过一轮时 take() 返回了真")

    if fails:
        print("❌ %d 项失败: %s" % (len(fails), ", ".join(fails)))
        return 1
    print("✅ 全部通过：重启序列已移出事件循环，请求合并/完成回执/关停等待均成立")
    return 0


if __name__ == "__main__":
    sys.exit(main())
