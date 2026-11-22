#!/usr/bin/env python3
"""L0: 重载路径的慢 pm 重读必须挪出注入器唯一事件循环线程。

`handle_pending_reload` 跑在注入器唯一的 epoll 循环里，旧代码内联
`if (config_has_category_rules()) sys_pkg_refresh();`——该函数会 fork
`pm list packages -s`（预算 3s）。这段时间里 pre-hook 判定、挂载派发、IPC 全停，
一次慢 binder 就放大成整进程无响应；工具/用户连写配置还会一轮接一轮。

判别（真实 TU）：夹具直编 `src/injector/async_refresh.c`，回调是 120ms 的慢查询替身。
50 次突发请求在调用线程上的总耗时必须 < 100ms（旧形态 inline 对照组约 6s），
回调轮数被合并到 1~3 轮、并发峰值恒 1、settle 后 /proc/self/task 回到 1 个线程；
`late` 证明 settle 之后的请求不会被丢；`shutdown` 证明退出会等手上那一轮跑完且
之后的请求不再执行。另做静态检查：`handle_pending_reload` 里不得有 `sys_pkg_refresh()`，
必须改成 `nsp_async_refresh_request()`；启动期 `reload_injector_config()` 保持同步
（那时事件循环还没起来，异步化只会让冷启动首查看到空表）。

复现旧红灯：ASYNC_REFRESH_INJECTOR_SRC=<旧 injector.c> python3 tests/test_async_refresh.py --expect-old-red
（旧源里 handle_pending_reload 内联了 sys_pkg_refresh，静态检查必须红。）
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
DRIVER = os.path.join(ROOT, "tests", "fixtures", "async_refresh_driver.c")
MODULE = os.path.join(ROOT, "src", "injector", "async_refresh.c")
INJECTOR = os.path.join(ROOT, "src", "injector", "injector.c")
CB_MS = 120                 # 慢查询替身时长
BURST = 50                  # 突发请求数
LIMIT_CALL_US = 5000        # 单次 request 上限 5ms
LIMIT_TOTAL_US = 100000     # 50 次突发总耗时上限 100ms
MAX_ROUNDS = 3              # 回调轮数上限（合并后只该有 1~2 轮）
INLINE_MIN_MS = 1000        # 旧形态对照：调用线程被冻 >=1s 才算判别成立


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


def check_call_sites(fails, log, injector_path):
    """注入器接线检查；返回是否全部通过（旧源应当在这里红）。"""
    if not os.path.isfile(injector_path):
        print("❌ 缺少注入器源码 %s" % injector_path)
        fails.append("missing-injector")
        return False
    text = open(injector_path, encoding="utf-8").read()
    ok = True
    # 重载已拆两段（读取在工作线程、提交在循环上）：刷新派发在提交段
    # reload_apply_view；旧源只有一次性 handle_pending_reload，这里自然红。
    start_body = func_body(text, "handle_pending_reload_begin")
    finish_body = func_body(text, "handle_pending_reload_finish")
    reload_body = func_body(text, "reload_apply_view")
    if start_body is None or finish_body is None or reload_body is None:
        print("❌ 找不到两段式重载的入口/提交段（静态检查失效）")
        fails.append("no-reload-body")
        return False
    for name, body in (("handle_pending_reload_begin", start_body),
                       ("handle_pending_reload_finish", finish_body),
                       ("reload_apply_view", reload_body)):
        if "sys_pkg_refresh()" in body:
            print("❌ %s 仍内联 sys_pkg_refresh()：慢 pm 会冻住事件循环" % name)
            fails.append("inline-refresh")
            ok = False
    if "nsp_async_refresh_request()" not in reload_body:
        print("❌ 重载提交段没有把刷新改成 nsp_async_refresh_request()")
        fails.append("no-request")
        ok = False
    startup_body = func_body(text, "reload_injector_config")
    if startup_body is None or "sys_pkg_refresh()" not in startup_body:
        print("❌ 启动期 reload_injector_config 不再同步刷新 sys 表（冷启动首查会看到空表）")
        fails.append("startup-async")
        ok = False
    shutdown_body = func_body(text, "injector_shutdown")
    if shutdown_body is None or "nsp_async_refresh_shutdown()" not in shutdown_body:
        print("❌ injector_shutdown 没有等待后台刷新收尾（nsp_async_refresh_shutdown）")
        fails.append("no-shutdown")
        ok = False
    early_body = func_body(text, "injector_early_init")
    if early_body is None or "nsp_async_refresh_init(injector_sys_pkg_refresh_cb" not in early_body:
        print("❌ injector_early_init 没有装配异步刷新回调")
        fails.append("no-init")
        ok = False
    cb_body = func_body(text, "injector_sys_pkg_refresh_cb")
    if cb_body is None or "sys_pkg_refresh()" not in cb_body:
        print("❌ 回调 injector_sys_pkg_refresh_cb 没有真正刷新 sys 表")
        fails.append("callback-body")
        ok = False
    log.append("静态：reload_pending=%d 字节，startup=%d，shutdown=%d，early_init=%d"
               % (len(reload_body), len(startup_body or ""), len(shutdown_body or ""),
                  len(early_body or "")))
    return ok


def parse(out):
    return dict((k, v) for k, v in re.findall(r"(\w+)=(-?\d+)", out))


def run_mode(exe, args, fails, log, timeout=120):
    proc = subprocess.run([exe] + args, capture_output=True, text=True, timeout=timeout,
                          env={"PATH": "/usr/local/bin:/usr/bin:/bin"})
    out = proc.stdout + proc.stderr
    log.append("%s rc=%d %s" % (" ".join(args), proc.returncode, out.strip()))
    if proc.returncode != 0:
        print("❌ %s 运行失败 rc=%d out=%r" % (" ".join(args), proc.returncode, out[-400:]))
        fails.append("rc-" + args[0])
        return None
    return parse(out)


def main():
    argv = sys.argv[1:]
    expect_old_red = "--expect-old-red" in argv
    cc = shlex.split(os.environ.get("CC", "cc"))
    if shutil.which(cc[0]) is None:
        print("跳过：缺少 C 编译器")
        return SKIP_RC
    module = os.environ.get("ASYNC_REFRESH_SRC", MODULE)
    injector = os.environ.get("ASYNC_REFRESH_INJECTOR_SRC", INJECTOR)
    out_dir = os.environ.get("ASYNC_REFRESH_OUTPUT_DIR")
    tmp = out_dir or tempfile.mkdtemp(prefix="async_refresh_")
    os.makedirs(tmp, exist_ok=True)
    fails, log = [], []

    static_ok = check_call_sites(fails, log, injector)

    exe = os.path.join(tmp, "async_refresh")
    build = cc + ["-std=gnu2x", "-O2", "-pthread", "-I", os.path.join(ROOT, "include"),
                  "-o", exe, DRIVER, module]
    proc = subprocess.run(build, capture_output=True, text=True)
    with open(os.path.join(tmp, "build.log"), "w", encoding="utf-8") as fh:
        fh.write(proc.stdout + proc.stderr)
    if proc.returncode != 0:
        print("❌ 编译失败（见 %s/build.log）" % tmp)
        print((proc.stdout + proc.stderr)[-2000:])
        return 1

    if expect_old_red:
        # 旧源的判别是静态的（内联调用点），再用 inline 对照组量化它冻住调用线程多久
        got = run_mode(exe, ["inline", str(BURST), str(CB_MS)], fails, log)
        if got is not None and int(got.get("inline_total_ms", 0)) < INLINE_MIN_MS:
            print("⚠️  inline 对照仅 %sms——判别力不足，按失败处理" % got.get("inline_total_ms"))
            fails.append("inline-control")
        if static_ok:
            print("⚠️  旧源未红：静态检查仍然通过——判别力不足，按失败处理")
            return 1
        print("旧源判别红成立（内联刷新冻住调用线程 %sms）" % (got or {}).get("inline_total_ms"))
        return 0

    got = run_mode(exe, ["burst", str(BURST), str(CB_MS)], fails, log)
    if got is not None:
        if int(got.get("requests", 0)) != BURST:
            print("❌ 突发请求数不对：%s" % got.get("requests"))
            fails.append("burst-count")
        if int(got.get("call_max_us", 10 ** 9)) > LIMIT_CALL_US:
            print("❌ 单次 request 阻塞调用线程：call_max_us=%s（上限 %d）"
                  % (got.get("call_max_us"), LIMIT_CALL_US))
            fails.append("burst-call")
        if int(got.get("call_total_us", 10 ** 9)) > LIMIT_TOTAL_US:
            print("❌ %d 次突发请求总耗时 %sµs（上限 %d，旧形态约 6s）"
                  % (BURST, got.get("call_total_us"), LIMIT_TOTAL_US))
            fails.append("burst-total")
        if not 1 <= int(got.get("invocations", 0)) <= MAX_ROUNDS:
            print("❌ 回调轮数 %s 不在 1~%d（请求合并失效或落后）"
                  % (got.get("invocations"), MAX_ROUNDS))
            fails.append("burst-rounds")
        if int(got.get("peak", 0)) != 1:
            print("❌ 回调并发峰值 %s（应恒为 1：至多一个 worker）" % got.get("peak"))
            fails.append("burst-peak")
        if int(got.get("threads_after", -1)) != 1:
            print("❌ settle 后线程数 %s（应回到 1：worker 空闲自己退出）"
                  % got.get("threads_after"))
            fails.append("burst-threads")
        if int(got.get("active_after", 1)) != 0:
            print("❌ settle 后仍有 worker 在跑")
            fails.append("burst-active")
        if int(got.get("settle_ms", 10 ** 9)) > 3000:
            print("❌ worker 收敛太慢：settle_ms=%s" % got.get("settle_ms"))
            fails.append("burst-settle")

    got = run_mode(exe, ["late", "0", str(50)], fails, log)
    if got is not None and int(got.get("delta", 0)) != 1:
        print("❌ settle 之后的请求没有执行：delta=%s（应恰好 1 次）" % got.get("delta"))
        fails.append("late-delta")

    got = run_mode(exe, ["shutdown", "0", str(CB_MS)], fails, log)
    if got is not None:
        shutdown_ms = int(got.get("shutdown_ms", 10 ** 9))
        if not 40 <= shutdown_ms <= 400:
            print("❌ shutdown 没有等手上那一轮跑完（也绝不无限等）：shutdown_ms=%s"
                  % shutdown_ms)
            fails.append("shutdown-wait")
        if int(got.get("calls_after_shutdown", 0)) != 1:
            print("❌ shutdown 前在跑的那轮回调没有完成：calls=%s"
                  % got.get("calls_after_shutdown"))
            fails.append("shutdown-calls")
        if int(got.get("late_requests", -1)) != 0:
            print("❌ shutdown 之后的请求仍执行了 %s 次" % got.get("late_requests"))
            fails.append("shutdown-late")

    got = run_mode(exe, ["inline", str(BURST), str(CB_MS)], fails, log)
    if got is not None:
        inline_ms = int(got.get("inline_total_ms", 0))
        if inline_ms < INLINE_MIN_MS:
            print("⚠️  inline 对照仅 %dms（判据 >=%d）——判别力不足，按失败处理"
                  % (inline_ms, INLINE_MIN_MS))
            fails.append("inline-control")
        else:
            log.append("inline 对照：调用线程被冻 %dms（异步后 <1ms/次）" % inline_ms)

    with open(os.path.join(tmp, "run.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(log) + "\n")
    if fails:
        print("异步刷新判别失败：%s（证据 %s）" % (",".join(fails), tmp))
        return 1
    print("异步刷新判别通过 ✔（证据 %s）" % tmp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
