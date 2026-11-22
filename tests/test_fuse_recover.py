#!/usr/bin/env python3
"""L0: FUSE 状态机上的秒级慢活必须挪出注入器唯一事件循环线程。

注入器只有一条 epoll 循环线程，它同时承载 zygisk pre-hook 判定、挂载派发与 IPC ACK
（pre-hook 的 IPC 超时只有 100ms，超时即 fail-open）。三段慢活都曾内联在这条线程上：
  - 崩溃恢复：等旧 daemon 退出的 10ms×50 轮询、SIGKILL 宽限、卸载复核、fork/exec、
    全进程清理；
  - 启动扫描：injector 重启后逐进程修存量断连挂载；
  - 重挂：FUSE 就绪后对全进程表逐个核规则并挂载（百级应用即秒级）。
现在三段都交给一条维护 worker 串行执行（`src/injector/fuse_recover.c` 的任务位），
循环线程只按状态组合任务位发请求。

判别（真实 TU）：夹具直编真实 `src/injector/fuse_recover.c`，用慢回调（150ms）代替慢活
  offload  —— 单任务请求必须 µs 级返回，回调跑在 worker 上、任务位原样到达、完成经
              eventfd 交回；
  inline   —— 同二进制对照组：直接调回调会把调用线程冻住整段（判别力自检）；
  coalesce —— 慢回调进行中再发 40 次请求，只许多跑 1 轮（请求合并）；
  shutdown —— 退出等手上那轮跑完（有界），之后请求被拒绝、线程数回 1；
  early    —— 没有完成过一轮时 take 返回 0；
  jobs     —— 一次请求带三段任务位，回调必须一次看到全部位；
  queue2   —— `--wrap=pthread_create` 把建 worker 推迟到两次请求之后，两次请求的位都
              必须跑到（按位 OR；用赋值会丢先到的那个任务，一次恢复就此消失）。
静态检查同时核对注入器接线（tick 只发请求、就绪处理只组合任务位且就绪判定留在循环侧、
失败分支不再内联杀等待、维护回调里三段顺序固定、shutdown join）。

复现旧红灯：
  FUSE_RECOVER_INJECTOR_SRC=<旧 injector.c> python3 tests/test_fuse_recover.py --expect-old-red
复现位合并变异：
  FUSE_RECOVER_SRC=<把 pending |= jobs 改成 pending = jobs 的副本> python3 tests/test_fuse_recover.py
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
MODULE = os.environ.get("FUSE_RECOVER_SRC", "src/injector/fuse_recover.c")
WORK_MS = 150
LIMIT_REQUEST_US = 5000       # request 只入队：上限 5ms（实测 61µs 含首次建线程）
READY_MIN_MS = WORK_MS - 40   # 完成通知必须等真跑完（否则说明阶段没等回调）
READY_MAX_MS = 3000
INLINE_MIN_MS = WORK_MS - 40  # inline 对照组：调用线程必须被真冻住
MAX_ROUNDS = 2                # 40 次突发只许多跑 1 轮
BURST_LIMIT_US = 20000
SHUTDOWN_MIN_MS = WORK_MS // 2
SHUTDOWN_MAX_MS = 3000
JOB_ALL = 7                   # RECOVER | STARTUP_SCAN | REMOUNT


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


def squash(body):
    return re.sub(r"\s+", " ", body)


def check_call_sites(fails, injector_path):
    """注入器接线检查；返回是否全部通过（旧源应当在这里红）。"""
    if not os.path.isfile(injector_path):
        print("❌ 找不到注入器源码: %s" % injector_path)
        fails.append("injector-missing")
        return False
    with open(injector_path, encoding="utf-8") as fh:
        text = fh.read()
    names = ("check_and_recover_fuse", "injector_fuse_maintenance_cb", "request_fuse_jobs",
             "handle_fuse_ready_event", "remount_all_tracked", "injector_event_loop",
             "injector_setup_epoll", "injector_shutdown")
    bodies = {name: func_body(text, name) for name in names}
    ok = True
    for name, body in bodies.items():
        if body is None:
            print("❌ 注入器里没有 %s()——慢活阶段化没有落地" % name)
            fails.append("missing-" + name)
            ok = False
    if not ok:
        return False
    tick = bodies["check_and_recover_fuse"]
    cb = bodies["injector_fuse_maintenance_cb"]
    req = squash(bodies["request_fuse_jobs"])
    ready = bodies["handle_fuse_ready_event"]
    remount = squash(bodies["remount_all_tracked"])
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
    ready_slow_calls = ("repair_stale_app_mounts_at_startup(", "remount_all_tracked(")
    need("NSP_FUSE_JOB_RECOVER" in tick, "tick-request",
         "check_and_recover_fuse 没有把重启序列交给维护 worker（缺 NSP_FUSE_JOB_RECOVER）")
    for call in slow_calls:
        need(call not in tick, "tick-inline-" + call,
             "check_and_recover_fuse 仍在事件循环上内联 %s" % call)
        need(call in cb, "cb-missing-" + call,
             "维护回调里没有 %s（慢活没有真正搬进 worker）" % call)
    # 就绪处理：两段慢活都必须只表现为任务位，且就绪判定留在循环侧。
    for call in ready_slow_calls:
        need(call not in ready, "ready-inline-" + call,
             "handle_fuse_ready_event 仍在事件循环上内联 %s" % call)
    need("NSP_FUSE_JOB_STARTUP_SCAN" in ready, "ready-scan-bit",
         "就绪处理没有把启动扫描交给 worker")
    need("NSP_FUSE_JOB_REMOUNT" in ready, "ready-remount-bit",
         "就绪处理没有把重挂交给 worker")
    need(ready.find("g_pending_remount = 0") >= 0 and
         ready.find("g_pending_remount = 0") < ready.find("NSP_FUSE_JOB_REMOUNT"),
         "ready-remount-consume",
         "重挂标记没有在循环线程上、发请求之前消费掉")
    need("get_active_mnt_src()" in ready, "ready-readiness",
         "重挂的就绪判定不在循环线程上：worker 判「未就绪」与就绪事件分发之间有个窗口，"
         "标记放回去就再没人消费")
    need("request_fuse_jobs(jobs)" in squash(ready), "ready-request",
         "就绪处理没有把组合出来的任务位发给维护 worker")
    # 失败分支：不再在循环上等旧实例退出（10ms×50 + SIGKILL 升级由 worker 做）。
    need("for (int w = 0" not in ready, "ready-killwait",
         "handle_fuse_ready_event 仍在事件循环上轮询等旧实例退出")
    need(re.search(r"kill\([^)]*SIGKILL", ready) is None, "ready-sigkill",
         "handle_fuse_ready_event 仍自己做 SIGKILL 升级（应交给维护 worker）")
    need("NSP_FUSE_JOB_RECOVER" in ready, "ready-recover-bit",
         "就绪失败分支没有请求重启（等 tick 的 1s 探测会白等一轮）")
    need("g_passive_mode" in ready, "ready-passive",
         "就绪处理丢了被动模式判定（存量应用修复必须跳过）")
    # 维护回调：顺序固定（恢复 → 启动扫描 → 重挂），重挂失败要把标记放回去。
    need(cb.find("force_recover_tracked_mounts(") >= 0 and
         cb.find("force_recover_tracked_mounts(") < cb.find("inject_global_fuse("),
         "cb-recover-order", "维护回调把清理排在 fork 之后：新实例一就绪就会与重挂并发")
    need("cleanup_all_target_apps(" in cb and
         cb.find("cleanup_all_target_apps(") < cb.find("inject_global_fuse("),
         "cb-cleanup-order",
         "维护回调把 cleanup_all_target_apps() 排在 inject_global_fuse() 之后：清理与"
         "重挂会并发（同一应用刚挂上又被拆）")
    need(cb.find("remount_all_tracked(") > cb.find("repair_stale_app_mounts_at_startup("),
         "cb-remount-last", "维护回调没有把重挂排在启动扫描之后")
    need("if (!remount_all_tracked()) g_pending_remount = 1;" in squash(cb),
         "cb-remount-defer",
         "重挂判定与执行之间视图没了时没有把标记放回去（应用会一直停在断链挂载上）")
    need(squash(cb).count("g_pending_remount") == 1, "cb-remount-writes",
         "维护回调多处改 g_pending_remount——那是循环线程的记账")
    need(re.search(r"return false;", remount) and re.search(r"return true;", remount),
         "remount-return", "remount_all_tracked 没有用返回值区分「已跑完 / 视图未就绪」")
    # 请求入口：非阻塞请求 + 起线程失败内联兜底。
    need("nsp_fuse_recover_request(jobs)" in req, "request-call",
         "request_fuse_jobs 没有把任务位交给 worker")
    need("injector_fuse_maintenance_cb(jobs, nullptr)" in req, "request-fallback",
         "worker 起不来时没有内联兜底（宁可慢一次也不能丢任务）")
    need("fd == g_fuse_recover_fd" in loop, "loop-branch",
         "事件循环里没有维护 worker 的就绪 fd 分支")
    need("nsp_fuse_recover_take()" in loop, "loop-take",
         "就绪分支没有取走完成位（worker 的完成状态会一直挂着）")
    need(text.count("g_ready_mu") >= 4, "ready-mu",
         "就绪管道所有权没有加锁（注册在 worker、分发在事件循环）")
    need("fuse_ready_take(" in loop, "ready-take",
         "事件循环没有用 fuse_ready_take() 摘取 ctx（跨线程会 double free/关错 fd）")
    need("nsp_fuse_recover_start(" in setup, "setup-start",
         "injector_setup_epoll 没有启动维护 worker")
    need("nsp_fuse_recover_shutdown()" in shutdown, "shutdown-join",
         "injector_shutdown 没有 join 维护 worker（退出会遇到在跑的慢活）")
    return ok


def build(work, tag, sanitize=False):
    exe = work / ("fr_" + tag)
    cc = os.environ.get("CC", "cc")
    cmd = [cc, "-std=c23", "-DTARGET_GNU=1", "-D_GNU_SOURCE", "-O1", "-g",
           "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "include")]
    if sanitize:
        cmd += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    cmd += [str(ROOT / MODULE), str(DRIVER), "-o", str(exe), "-lpthread",
            "-Wl,--wrap=pthread_create"]
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
    modes = ("offload", "inline", "coalesce", "shutdown", "early", "jobs", "queue2")
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
            for mode in modes:
                vals[mode] = run_mode(exe, mode)
                if vals[mode] is None:
                    fails.append("run-" + mode)
                    print("❌ %s 模式运行失败" % mode)
        else:
            vals["offload"] = run_mode(exe, "offload")
        if not expect_old_red and asan is not None:
            for mode in ("offload", "shutdown", "coalesce", "jobs", "queue2"):
                if run_mode(asan, mode, timeout=120) is None:
                    print("❌ ASan 版 %s 模式运行失败" % mode)
                    fails.append("asan-" + mode)

    if expect_old_red:
        # 红灯要落在「慢活还在循环线程上」这个事实上，而不只是「函数不存在」。
        old_inline = []
        try:
            with open(injector_path, encoding="utf-8") as fh:
                old_text = fh.read()
            old_tick = func_body(old_text, "check_and_recover_fuse") or ""
            old_ready = func_body(old_text, "handle_fuse_ready_event") or ""
            for call in ("force_recover_tracked_mounts(", "inject_global_fuse(",
                         "cleanup_all_target_apps("):
                if call in old_tick:
                    old_inline.append("tick:" + call.rstrip("("))
            for call in ("repair_stale_app_mounts_at_startup(", "remount_all_tracked("):
                if call in old_ready:
                    old_inline.append("ready:" + call.rstrip("("))
        except OSError:
            old_inline = []
        if not wiring_ok and old_inline:
            for item in fails:
                print("[FAIL] %s" % item)
            print("旧实现按预期红：循环线程仍内联 %s" % ", ".join(old_inline))
            return 0
        print("旧实现判据不成立：静态红=%s 循环内联慢调用=%s" % (not wiring_ok, old_inline))
        return 1

    off = vals.get("offload") or {}
    if off.get("start_failed"):
        fails.append("start")
    if int(off.get("request_us", 1 << 30)) > LIMIT_REQUEST_US:
        fails.append("request-slow")
        print("❌ request 阻塞了 %sus（应只入队）" % off.get("request_us"))
    if int(off.get("got", 0)) != 1:
        fails.append("no-ready")
        print("❌ 慢活跑完没有写就绪 eventfd")
    if int(off.get("took", 0)) != 1:
        fails.append("no-take")
        print("❌ take() 没有取到完成结果")
    if int(off.get("took_bits", 0)) != 1 or int(off.get("rrec", 0)) != 1:
        fails.append("take-bits")
        print("❌ take() 没有把这一轮的任务位交回来（took_bits=%s）" % off.get("took_bits"))
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
        print("❌ 没有跑过一轮时 take() 返回了非零")

    jobs = vals.get("jobs") or {}
    if jobs.get("queued") != "1":
        fails.append("jobs-queued")
        print("❌ 一次带三段任务位的请求没有被接受")
    if int(jobs.get("request_us", 1 << 30)) > LIMIT_REQUEST_US:
        fails.append("jobs-request-slow")
        print("❌ 三段任务位的请求阻塞了 %sus（应只入队）" % jobs.get("request_us"))
    if int(jobs.get("took_bits", 0)) != JOB_ALL or int(jobs.get("bits_seen", 0)) != JOB_ALL:
        fails.append("jobs-bits")
        print("❌ 任务位没有原样到达回调（bits_seen=%s took_bits=%s）"
              % (jobs.get("bits_seen"), jobs.get("took_bits")))
    for bit in ("has_recover", "has_scan", "has_remount"):
        if jobs.get(bit) != "1":
            fails.append("jobs-" + bit)
            print("❌ 回调没看到任务位 %s" % bit)
    if int(jobs.get("runs", 0)) != 1:
        fails.append("jobs-runs")
        print("❌ 三段任务位跑了 %s 轮（应一轮串行跑完）" % jobs.get("runs"))
    if int(jobs.get("cb_off_main", 0)) != 1:
        fails.append("jobs-on-caller")
    if int(jobs.get("threads", -1)) != 1:
        fails.append("jobs-threads")

    q2 = vals.get("queue2") or {}
    if q2.get("q1") != "1" or q2.get("q2") != "1":
        fails.append("queue2-accept")
        print("❌ 推迟建线程期间的两次请求没有被接受")
    if q2.get("has_recover") != "1" or q2.get("has_remount") != "1":
        fails.append("queue2-merge")
        print("❌ 两次请求的任务位没有按位合并（has_recover=%s has_remount=%s）——"
              "用赋值会丢先到的任务" % (q2.get("has_recover"), q2.get("has_remount")))
    if int(q2.get("rounds", -1)) != 1:
        fails.append("queue2-rounds")
        print("❌ 同一轮内的两次请求跑了 %s 轮" % q2.get("rounds"))
    if int(q2.get("threads", -1)) != 1:
        fails.append("queue2-threads")

    if fails:
        for item in fails:
            print("[FAIL] %s" % item)
        print("❌ %d 项失败" % len(fails))
        return 1
    print("✅ 全部通过：三段慢活都在维护 worker 上，任务位按位合并、顺序固定")
    return 0


if __name__ == "__main__":
    sys.exit(main())
