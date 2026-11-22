#!/usr/bin/env python3
"""L0: 挂载表的写者必须串行，而事件循环侧只能用 trylock。

注入器的挂载视图有三个写者：维护 worker（恢复/重挂/媒体实例）、审计 worker（运行中
应用对账）、事件循环（重试派发）。它们都做「读 mountinfo → fork → mount/umount →
改追踪表」，并发跑会「一边刚挂上、另一边又清掉」，同一进程被两边各改一遍。

判别分两半：
  - 真实 TU：夹具直编 `src/injector/mount_ops.c`，验证锁语义本身——别的线程持有时
    trylock 立刻失败、释放后立刻成功；begin 阻塞到真正拿到锁（覆盖持有者剩余时间）；
    4 线程各 200 轮临界区里并发计数最大 1；无人持有时 trylock 上限 1ms。
  - 接线静态检查（`src/injector/injector.c`、`src/injector/audit_worker.c`）：整轮维护
    回调与审计轮都在锁内；重试派发只在循环上用 trylock 且抢不到就 20ms 后再跑；
    媒体实例的三条事件循环路径只发任务位、不再内联 kill 等待与 fork；恢复卡住时按
    backoff 重发（上限 5 次），就绪回来立刻清零。

这把锁不保证单个挂载调用有界——它只保证「一次只有一个写者」，慢写者仍会拖住其它写者
（它们不在事件循环上，代价是挂载延迟而不是全线程无响应）。

复现旧红灯：
  MOUNT_OPS_INJECTOR_SRC=<旧 injector.c> python3 tests/test_mount_ops.py --expect-old-red
"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SKIP_RC = 77
ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "tests/fixtures/mount_ops_driver.c"
MOUNT_OPS = os.environ.get("MOUNT_OPS_SRC", "src/injector/mount_ops.c")
INJECTOR = os.environ.get("MOUNT_OPS_INJECTOR_SRC", "src/injector/injector.c")
AUDIT = os.environ.get("MOUNT_OPS_AUDIT_SRC", "src/injector/audit_worker.c")
HEADER = os.environ.get("MOUNT_OPS_HEADER", "include/mount_ops.h")
HOLD_US = 150000
WAIT_MIN_US = HOLD_US - 30000   # begin 必须等掉持有者的剩余持有时间
TRY_MAX_US = 1000


def resolve(path):
    p = Path(path)
    return p if p.is_absolute() else ROOT / p


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
    return re.sub(r"\s+", " ", body or "")


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def build(workdir):
    exe = Path(workdir) / "mount_ops_driver"
    cmd = [os.environ.get("CC", "cc"), "-std=c23", "-O1", "-Wall", "-Wextra", "-Werror",
           "-I" + str(ROOT / "include"), str(resolve(MOUNT_OPS)), str(DRIVER),
           "-o", str(exe), "-pthread"]
    flags = os.environ.get("MOUNT_OPS_TEST_CFLAGS")
    if flags:
        cmd[1:1] = flags.split()
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stdout)
        print(res.stderr)
        return None
    return exe


def run_mode(exe, mode, timeout=120):
    res = subprocess.run([str(exe), mode], capture_output=True, text=True, timeout=timeout)
    vals = {}
    for key, val in re.findall(r"(\w+)=(-?\d+)", res.stdout):
        vals[key] = val
    return res.returncode, vals, res.stdout + res.stderr


def check_runtime(fails, exe):
    rc, vals, out = run_mode(exe, "try")
    if rc != 0 or vals.get("start_failed"):
        fails.append("try-mode")
        print("\u274c try 模式跑不起来: %s" % out.strip()[:300])
        return
    if vals.get("try_busy") != "0":
        fails.append("try-busy")
        print("\u274c 别的线程持有时 trylock 成功了（锁没生效）")
    if vals.get("try_free") != "1":
        fails.append("try-free")
        print("\u274c 持有者释放后 trylock 仍失败（锁泄漏）")
    if int(vals.get("try_busy_us", 1 << 30)) > TRY_MAX_US:
        fails.append("try-blocked")
        print("\u274c 持锁时的 trylock 卡了 %sus（必须立刻返回）" % vals.get("try_busy_us"))

    rc, vals, out = run_mode(exe, "block")
    if rc != 0:
        fails.append("block-mode")
        print("\u274c block 模式失败: %s" % out.strip()[:300])
    else:
        waited = int(vals.get("block_wait_us", 0))
        if waited < WAIT_MIN_US:
            fails.append("block-short")
            print("\u274c begin 只等了 %sus（持有者还要按 %sus：说明没真拿到锁）"
                  % (waited, HOLD_US))

    rc, vals, out = run_mode(exe, "serialize")
    if rc != 0:
        fails.append("serialize-mode")
        print("\u274c serialize 模式失败: %s" % out.strip()[:300])
    else:
        if vals.get("concurrency_max") != "1":
            fails.append("serialize")
            print("\u274c 临界区内并发数是 %s（应恒为 1：写者没被串行化）"
                  % vals.get("concurrency_max"))
        if vals.get("ops") != "800":
            fails.append("serialize-ops")
            print("\u274c 只完成 %s 轮（应 4×200=800）" % vals.get("ops"))

    rc, vals, out = run_mode(exe, "tryfree")
    if rc != 0:
        fails.append("tryfree-mode")
        print("\u274c tryfree 模式失败: %s" % out.strip()[:300])
    else:
        if vals.get("tryfree_taken") != "1000":
            fails.append("tryfree-taken")
            print("\u274c 无人持有时 trylock 失败 %s 次" %
                  (1000 - int(vals.get("tryfree_taken", 0))))
        if int(vals.get("tryfree_worst_us", 1 << 30)) > TRY_MAX_US:
            fails.append("tryfree-slow")
            print("\u274c 无人持有时 trylock 最长 %sus" % vals.get("tryfree_worst_us"))


def check_wiring(fails):
    inj_path = resolve(INJECTOR)
    aud_path = resolve(AUDIT)
    hdr_path = resolve(HEADER)
    ok = True
    for path in (inj_path, aud_path, hdr_path):
        if not path.is_file():
            print("\u274c 找不到源码: %s" % path)
            fails.append("missing-" + path.name)
            ok = False
    if not ok:
        return False
    text = inj_path.read_text(encoding="utf-8")
    code = strip_comments(text)
    audit = strip_comments(aud_path.read_text(encoding="utf-8"))
    header = hdr_path.read_text(encoding="utf-8")

    names = ("injector_fuse_maintenance_cb", "retry_pending_mounts", "on_timer_event",
             "maybe_retry_recover", "media_fuse_stop", "media_fuse_maintain",
             "inject_media_fuse", "check_and_recover_fuse", "reload_apply_view",
             "handle_fuse_ready_event", "injector_start_fuses",
             "fuse_jobs_run_locked", "request_fuse_jobs", "flush_deferred_fuse_jobs")
    bodies = {name: func_body(text, name) for name in names}
    # 缺函数本身已经是红，但不在这里提前返回：继续用空体重跑后面的接线断言，
    # 这样旧实现的「内联慢活」与「没有锁」会一起被点名，诊断不被第一条挡住。
    for name, body in bodies.items():
        if body is None:
            print("\u274c 注入器里没有 %s()" % name)
            fails.append("missing-" + name)
            bodies[name] = ""
            ok = False

    def need(cond, tag, message):
        nonlocal ok
        if not cond:
            print("\u274c " + message)
            fails.append(tag)
            ok = False

    # 0) 头文件与模块本体
    for fn in ("mount_ops_begin", "mount_ops_end", "mount_ops_try_begin"):
        need(re.search(r"\b" + fn + r"\s*\(\s*void\s*\)", header) is not None,
             "header-" + fn, "include/mount_ops.h 没有声明 %s(void)" % fn)
    mo_text = resolve(MOUNT_OPS).read_text(encoding="utf-8") if resolve(MOUNT_OPS).is_file() else ""
    need("static pthread_mutex_t" in mo_text, "module-mutex",
         "mount_ops.c 里没有唯一那把静态互斥量")
    meson = (ROOT / "meson.build").read_text(encoding="utf-8")
    need("src/injector/mount_ops.c" in meson, "meson-mount-ops",
         "meson.build 的 injector_sources 没有登记 src/injector/mount_ops.c")

    # 1) 维护回调整轮持锁，任务体在 fuse_jobs_run_locked 里（同一条 worker、同一把锁）
    cb_code = strip_comments(bodies["injector_fuse_maintenance_cb"])
    run_code_ = strip_comments(bodies["fuse_jobs_run_locked"])
    begin_at = cb_code.find("mount_ops_begin();")
    run_at = cb_code.find("fuse_jobs_run_locked(")
    end_at = cb_code.find("mount_ops_end();")
    need(begin_at >= 0 and run_at > begin_at, "cb-lock-scope",
         "维护回调没有在跑任务体之前拿挂载锁：恢复/重挂会与审计并发改视图")
    need(end_at > run_at, "cb-lock-end",
         "维护回调的 mount_ops_end() 不在任务体之后（锁提前放了）")
    media_at = run_code_.find("if (jobs & NSP_FUSE_JOB_MEDIA)")
    remount_at = run_code_.find("if (jobs & NSP_FUSE_JOB_REMOUNT)")
    need(media_at > remount_at >= 0 and "media_fuse_maintain()" in run_code_, "cb-media",
         "任务体没有在重挂之后跑媒体实例维护（任务位 NSP_FUSE_JOB_MEDIA 空转）")
    need("mount_ops_" not in run_code_, "run-locked-selflock",
         "任务体自己又拿/放了挂载锁：锁由调用方持有，自取会死锁或提前放锁")

    # 1b) worker 不可用时的回退执行：事件循环上只 trylock，抢不到就延后重试
    fb = strip_comments(bodies["flush_deferred_fuse_jobs"])
    need("mount_ops_try_begin()" in fb, "fallback-trylock",
         "回退执行没有用 trylock：worker 不可用时会在循环上等一轮审计")
    need("mount_ops_begin()" not in fb, "fallback-blocking",
         "回退执行在事件循环上用了阻塞 begin")
    fb_at = fb.find("g_fuse_jobs_defer_ms =")
    fb_arm = fb.find("arm_due_timer();", fb_at if fb_at >= 0 else 0)
    need(fb_at >= 0 and fb_arm > fb_at, "fallback-defer",
         "回退执行抢不到锁时没有延后并重臂定时器（这次恢复/重挂就丢了）")
    req = strip_comments(bodies["request_fuse_jobs"])
    need("nsp_fuse_recover_request(" in req and "flush_deferred_fuse_jobs()" in req,
         "fallback-route",
         "request_fuse_jobs 没有先派 worker、再走有界回退")
    need("injector_fuse_maintenance_cb(" not in req, "fallback-inline",
         "request_fuse_jobs 仍直接内联跑任务体（会在循环上等挂载锁）")

    # 2) 审计轮整轮持锁
    a_begin = audit.find("mount_ops_begin();")
    a_run = audit.find("audit_run_job(&job);")
    a_end = audit.find("mount_ops_end();")
    need(a_begin >= 0 and a_run > a_begin and a_end > a_run, "audit-lock",
         "审计 worker 没有把整轮对账包在挂载锁里（与维护/重试并发改挂载表）")

    # 3) 事件循环侧只 trylock
    retry = strip_comments(bodies["retry_pending_mounts"])
    need("mount_ops_try_begin()" in retry, "retry-trylock",
         "重试派发没有用 trylock：在事件循环上等一轮审计就停掉所有 IPC")
    need("mount_ops_begin()" not in retry, "retry-blocking",
         "重试派发在事件循环上用了阻塞 begin")
    defer_at = retry.find("g_retry_defer_ms =")
    arm_at = retry.find("arm_due_timer();", defer_at if defer_at >= 0 else 0)
    need(defer_at >= 0, "retry-defer",
         "抢不到锁时没有把本轮重试推到 20ms 后再跑（这一轮的重试就丢了）")
    need(arm_at > defer_at, "retry-rearm",
         "抢不到锁后没有重新臂定时器：延迟重试永远等不到")
    need(retry.find("mount_ops_end();") > retry.find("perform_app_mount("), "retry-unlock",
         "重试派发没有在派发循环之后放锁")

    # 4) 媒体实例：三条事件循环路径只发任务位
    tick = strip_comments(bodies["check_and_recover_fuse"])
    reload = strip_comments(bodies["reload_apply_view"])
    calls = len(re.findall(r"inject_media_fuse\(\);", code))
    need(calls == 2, "media-callsites",
         "inject_media_fuse() 的调用点有 %d 处（只应剩两处：维护 worker 与启动期）" % calls)
    for path_name, body in (("tick", tick), ("reload", reload)):
        need("inject_media_fuse(" not in body, path_name + "-inline-start",
             "%s 仍在事件循环上内联拉起媒体实例（fork/setns）" % path_name)
        need("ns_force_umount_stale(" not in body, path_name + "-inline-umount",
             "%s 仍在事件循环上内联卸载媒体挂载点" % path_name)
        need("request_fuse_jobs(NSP_FUSE_JOB_MEDIA)" in body, path_name + "-media-bit",
             "%s 没有把媒体实例维护交给维护 worker" % path_name)
    need(tick.count("request_fuse_jobs(NSP_FUSE_JOB_MEDIA)") == 3, "tick-media-branches",
         "tick 的媒体三条分支（崩溃重拉/惰性启动/热重载终结）没有都改成发任务位")
    stop = strip_comments(bodies["media_fuse_stop"])
    need("fork(" not in stop, "stop-no-fork",
         "media_fuse_stop 仍在 fork（停与拉该分开：先停再按当下配置决定拉）")
    maintain = strip_comments(bodies["media_fuse_maintain"])
    need("media_fuse_stop();" in maintain and "inject_media_fuse();" in maintain,
         "maintain-order", "媒体维护没有「先停旧实例、再按当下配置决定拉起」")

    # 5) 恢复卡住时的有界重试
    timer = strip_comments(bodies["on_timer_event"])
    need(timer.find("maybe_retry_recover();") > timer.find("check_and_recover_fuse();") >= 0,
         "timer-retry", "定时器没有在崩溃检查之后跑恢复重试")
    retry_body = strip_comments(bodies["maybe_retry_recover"])
    need("NSP_FUSE_JOB_RECOVER" in retry_body, "retry-recover-bit",
         "恢复重试没有重发恢复任务位（等于不重试）")
    need("FUSE_RECOVER_RETRY_MAX" in retry_body, "retry-bounded",
         "恢复重试没有上限：卡死的实例会按 tick 无限重发")
    need("g_fuse_ready" in retry_body, "retry-clear",
         "恢复重试没有在就绪后停手")
    need("recover_arm_deadline();" in tick, "tick-arm",
         "崩溃分支请求恢复前没有臂上重试期限")
    ready = strip_comments(bodies["handle_fuse_ready_event"])
    need("recover_clear_deadline();" in ready, "ready-clear",
         "就绪处理没有清掉恢复重试链（就绪了还会继续重发恢复）")
    need(ready.find("recover_clear_deadline();") > ready.find("g_fuse_ready = 1"), "ready-clear-order",
         "恢复重试链在置就绪之前就清了：清完再就绪，这次恢复卡住就没人重试")
    return ok


def main():
    expect_old = "--expect-old-red" in sys.argv
    fails = []
    wiring_ok = check_wiring(fails)
    if expect_old:
        if not wiring_ok:
            for item in fails:
                print("[FAIL] %s" % item)
            print("旧实现按预期红：%d 项接线检查不成立" % len(fails))
            return 0
        print("旧实现判据不成立：接线检查全通过")
        return 1

    with tempfile.TemporaryDirectory() as work:
        exe = build(work)
        if exe is None:
            print("\u274c 夹具编译失败")
            return 1
        check_runtime(fails, exe)

    if fails:
        print("SUMMARY fail=%d: %s" % (len(fails), ", ".join(fails)))
        return 1
    print("SUMMARY pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
