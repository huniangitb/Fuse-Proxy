#!/usr/bin/env python3
"""L0: 配置重载的「读盘 + pm 用户探测」必须挪出注入器唯一事件循环线程。

`handle_pending_reload` 跑在注入器唯一的 epoll 循环里。旧代码内联
`config_read_view()`——它会先 `scan_active_users()` 跑 `pm list users`（预算 800ms），
再逐个 fopen 主配置 / App-rules / 模块 conf。慢盘或慢 binder 一次就把 pre-hook 判定、
挂载派发与 IPC ACK 一起冻住；zygisk pre-hook 的 IPC 超时只有 100ms，超时即 fail-open，
应用这次启动看到的是系统存储视图。

判别（真实 TU）：夹具直编 `src/injector/reload_stage.c` + 真实 `config_parser.c`，主配置
文件的 fopen 经 `--wrap=fopen` 人为变慢 250ms：
  offload  —— request 必须 µs 级返回，视图由 worker 读回来后取走（read_on_worker=1）；
  inline   —— 同二进制对照组：直接 config_read_view 会把调用线程冻住整段（判别力自检）；
  coalesce —— 慢读进行中再发 50 次请求，只许多读 1 轮（请求合并）；
  shutdown —— 退出等手上那轮读完（有界）、结果丢弃、线程数回 1；
  empty    —— 空视图（count==0）也算取到，否则重载会被静默丢弃；
  early    —— 没有备好视图时 take 返回 false。
静态检查同时核对注入器接线（读盘/就绪 fd/两段式/shutdown），
复现旧红灯：RELOAD_STAGE_INJECTOR_SRC=<旧 injector.c> python3 tests/test_reload_stage.py --expect-old-red
"""
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SKIP_RC = 77
ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "tests/fixtures/reload_stage_driver.c"
INJECTOR = ROOT / "src/injector/injector.c"
SOURCES = ["src/config/config_parser.c", "src/config/path_vars.c", "src/core/path_trie.c",
           "src/core/nsp_util.c", "src/core/nsp_comm.c", "src/core/common.c",
           "src/core/sys_pkg.c", "src/core/uid_map.c", "src/core/fast_pid.c",
           "src/injector/reload_stage.c"]
WORK_MS = 250
CONF = "[GLOBAL]\nMONITOR ON\nHIDE /sdcard/secret\n"
LIMIT_REQUEST_US = 5000      # request 只入队：上限 5ms（实测 0~2µs）
READY_MIN_MS = WORK_MS - 30  # 视图必须等真读完成（否则说明读的是别的东西）
READY_MAX_MS = 3000
INLINE_MIN_MS = WORK_MS - 30 # inline 对照组：调用线程必须被真冻住
MAX_COALESCE_READS = 3       # 50 次突发只许多读 1 轮
SHUTDOWN_MIN_MS = WORK_MS // 2
SHUTDOWN_MAX_MS = 3000


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
        print("❌ 找不到注入器源码: %s" % injector_path)
        fails.append("injector-missing")
        return False
    with open(injector_path, encoding="utf-8") as fh:
        text = fh.read()
    bodies = {name: func_body(text, name) for name in
              ("handle_pending_reload_begin", "handle_pending_reload_finish",
               "reload_apply_view", "injector_event_loop", "injector_setup_epoll",
               "injector_shutdown")}
    ok = True
    for name, body in bodies.items():
        if body is None:
            print("❌ 注入器里没有 %s()——两段式重载没有落地" % name)
            fails.append("missing-" + name)
            ok = False
    if not ok:
        return False
    begin = bodies["handle_pending_reload_begin"]
    finish = bodies["handle_pending_reload_finish"]
    apply_view = bodies["reload_apply_view"]
    loop = bodies["injector_event_loop"]
    setup = bodies["injector_setup_epoll"]
    shutdown = bodies["injector_shutdown"]

    def need(cond, tag, message):
        nonlocal ok
        if not cond:
            print("❌ " + message)
            fails.append(tag)
            ok = False

    need("nsp_reload_stage_request()" in begin, "begin-request",
         "重载第一段没有把读取派给 worker（nsp_reload_stage_request）")
    need("nsp_reload_stage_take(" in finish, "finish-take",
         "重载第二段没有取走 worker 备好的视图（nsp_reload_stage_take）")
    need("config_read_view(" not in finish, "finish-inline-read",
         "重载第二段仍在读盘：读必须留在 worker 上")
    need("config_read_view(" not in apply_view, "apply-inline-read",
         "提交视图的函数里出现了 config_read_view：读盘又回到事件循环")
    need("config_commit_prepared(" in apply_view, "apply-commit",
         "提交视图没有走 config_commit_prepared")
    need("nsp_reload_stage_start(" in setup, "setup-start",
         "启动期没有起配置读取 worker（nsp_reload_stage_start）")
    need("nsp_reload_stage_shutdown()" in shutdown, "shutdown-join",
         "退出没有停配置读取 worker（nsp_reload_stage_shutdown）")
    need("fd == g_reload_ready_fd" in loop, "loop-branch",
         "事件循环没有处理读取就绪 eventfd")
    need("handle_pending_reload_finish()" in loop, "loop-finish",
         "事件循环没有在就绪时提交视图")
    need("handle_pending_reload_begin()" in loop, "loop-begin",
         "事件循环没有每轮检查配置重载到期")
    need("handle_pending_reload();" not in text, "legacy-call",
         "源码里还留着旧的一次性 handle_pending_reload() 调用")
    if ok:
        log.append("注入器接线检查通过：两段式重载 + 读取就绪分支 + shutdown join")
    return ok


def prepare(directory):
    sandbox = directory / "stage"
    shutil.rmtree(sandbox, ignore_errors=True)
    cfg = sandbox / "cfg"
    cfg.mkdir(parents=True)
    headers = sandbox / "include"
    shutil.copytree(ROOT / "include", headers)
    pattern = re.compile(r'^#define\s+(?:NSP_CONFIG_DIR|CONFIG_DIR)\s+"/var/fuse-proxy"\s*$', re.M)
    hits = 0
    for path in sorted(headers.glob("*.h")):
        text = path.read_text(encoding="utf-8")
        new, count = pattern.subn(lambda m: m.group(0).replace('"/var/fuse-proxy"', '"%s"' % cfg), text)
        if count:
            path.write_text(new, encoding="utf-8")
            hits += count
    if not hits:
        return None, None, "未定位 GNU 配置根常量"
    conf = cfg / "injector.conf"
    conf.write_text(CONF, encoding="utf-8")
    return cfg, headers, None


def build(directory, headers):
    cc = shlex.split(os.environ.get("CC", "cc"))
    if not cc or not shutil.which(cc[0]):
        return None, "C 编译器不可用"
    pkgconfig = subprocess.run(["pkg-config", "--cflags", "--libs", "json-c"],
                               capture_output=True, text=True)
    if pkgconfig.returncode != 0:
        return None, "缺少 json-c"
    binary = directory / "stage" / "reload_stage_driver"
    command = cc + [
        "-std=c23", "-DTARGET_GNU=1", "-D_GNU_SOURCE", "-Wall", "-Wno-unused-parameter",
        "-I" + str(headers), "-I" + str(ROOT / "include"), "-I" + str(ROOT / "src/daemon"),
        str(DRIVER),
    ] + [str(ROOT / rel) for rel in SOURCES] + [
        # 主配置文件的 fopen 换成本地拦截版：读得慢，才能看出谁在等它
        "-Wl,--wrap=fopen",
    ] + shlex.split(pkgconfig.stdout) + ["-lpthread", "-o", str(binary)]
    proc = subprocess.run(command, capture_output=True, text=True)
    with open(directory / "build.log", "w", encoding="utf-8") as fh:
        fh.write(" ".join(command) + "\n" + proc.stdout + proc.stderr)
    if proc.returncode != 0:
        return None, "编译/链接失败（见 build.log）"
    return binary, None


def run_mode(exe, args):
    proc = subprocess.run([str(exe)] + [str(a) for a in args], capture_output=True,
                          text=True, timeout=120)
    if proc.returncode != 0:
        return None, proc
    return dict(re.findall(r"(\w+)=(-?\d+)", proc.stdout)), proc


def main():
    expect_old = "--expect-old-red" in sys.argv[1:]
    injector_path = os.environ.get("RELOAD_STAGE_INJECTOR_SRC", str(INJECTOR))
    tmpdir = os.environ.get("RELOAD_STAGE_OUTPUT_DIR")
    tmp = tempfile.mkdtemp(prefix="reload_stage_")
    keep = bool(tmpdir)
    if keep:
        os.makedirs(tmpdir, exist_ok=True)
        tmp = tmpdir
    try:
        fails, log = [], []
        static_ok = check_call_sites(fails, log, injector_path)
        cfg, headers, err = prepare(Path(tmp))
        if err:
            print("⚠️  " + err)
            return SKIP_RC
        exe, err = build(Path(tmp), headers)
        if err:
            print("⚠️  " + err)
            return SKIP_RC
        conf = cfg / "injector.conf"
        missing = cfg / "missing.conf"

        if expect_old:
            got, _proc = run_mode(exe, ["offload", conf, WORK_MS])
            if got is not None and int(got.get("request_us", 0)) > LIMIT_REQUEST_US:
                print("⚠️  旧源未红：offload 请求本身不该慢")
                return 1
            if static_ok:
                print("⚠️  旧源未红：静态检查仍然通过——判别力不足，按失败处理")
                return 1
            print("旧源判别红成立（静态接线检查失败 %d 项）" % len(fails))
            return 0

        got, proc = run_mode(exe, ["offload", conf, WORK_MS])
        if got is None:
            print("❌ offload 运行失败: %s" % (proc.stderr or proc.stdout).strip()[:300])
            fails.append("offload-run")
        else:
            log.append("offload: " + proc.stdout.strip())
            if int(got.get("request_us", 10 ** 9)) > LIMIT_REQUEST_US:
                print("❌ request 阻塞调用线程：request_us=%s（上限 %d）"
                      % (got.get("request_us"), LIMIT_REQUEST_US))
                fails.append("offload-request")
            if int(got.get("ready_ms", -1)) < READY_MIN_MS or int(got.get("ready_ms", 10 ** 9)) > READY_MAX_MS:
                print("❌ 视图就绪耗时 %sms 不在 %d~%d（读必须真的发生在 worker 上）"
                      % (got.get("ready_ms"), READY_MIN_MS, READY_MAX_MS))
                fails.append("offload-ready")
            if int(got.get("took", 0)) != 1 or int(got.get("count", 0)) < 1:
                print("❌ 没有取到视图：took=%s count=%s" % (got.get("took"), got.get("count")))
                fails.append("offload-take")
            if int(got.get("read_on_worker", 0)) != 1:
                print("❌ 读盘仍发生在调用线程上（read_on_worker=%s）" % got.get("read_on_worker"))
                fails.append("offload-worker")
            if int(got.get("threads_after", -1)) != 1:
                print("❌ shutdown 后线程数 %s（应回到 1）" % got.get("threads_after"))
                fails.append("offload-threads")

        got, proc = run_mode(exe, ["inline", conf, WORK_MS])
        if got is None:
            print("❌ inline 对照组运行失败: %s" % (proc.stderr or proc.stdout).strip()[:300])
            fails.append("inline-run")
        else:
            if int(got.get("inline_ms", 0)) < INLINE_MIN_MS or int(got.get("read_on_main", 0)) != 1:
                print("⚠️  inline 对照仅 %sms/read_on_main=%s——慢读注入没生效，判别力不足"
                      % (got.get("inline_ms"), got.get("read_on_main")))
                fails.append("inline-control")
            else:
                log.append("inline 对照：调用线程被冻 %sms（offload 下 0~2µs 返回）"
                           % got.get("inline_ms"))

        got, proc = run_mode(exe, ["coalesce", conf, WORK_MS])
        if got is None:
            print("❌ coalesce 运行失败: %s" % (proc.stderr or proc.stdout).strip()[:300])
            fails.append("coalesce-run")
        else:
            log.append("coalesce: " + proc.stdout.strip())
            reads = int(got.get("reads", 10 ** 9))
            if not 1 <= reads <= MAX_COALESCE_READS:
                print("❌ 慢读期间的 50 次请求触发了 %d 轮读盘（上限 %d，合并失效）"
                      % (reads, MAX_COALESCE_READS))
                fails.append("coalesce-reads")
            if int(got.get("burst_us", 10 ** 9)) > LIMIT_REQUEST_US:
                print("❌ 突发请求阻塞调用线程：burst_us=%s" % got.get("burst_us"))
                fails.append("coalesce-burst")
            if int(got.get("rounds", 0)) < 1:
                print("❌ 合并期间一个视图都没取到")
                fails.append("coalesce-rounds")
            if int(got.get("threads_after", -1)) != 1:
                print("❌ coalesce 后线程数 %s（应回到 1）" % got.get("threads_after"))
                fails.append("coalesce-threads")

        got, proc = run_mode(exe, ["shutdown", conf, WORK_MS])
        if got is None:
            print("❌ shutdown 运行失败: %s" % (proc.stderr or proc.stdout).strip()[:300])
            fails.append("shutdown-run")
        else:
            log.append("shutdown: " + proc.stdout.strip())
            ms = int(got.get("shutdown_ms", 10 ** 9))
            if not SHUTDOWN_MIN_MS <= ms <= SHUTDOWN_MAX_MS:
                print("❌ shutdown 等待 %sms 不在 %d~%d（应等手上那轮读完且有界）"
                      % (ms, SHUTDOWN_MIN_MS, SHUTDOWN_MAX_MS))
                fails.append("shutdown-wait")
            if int(got.get("leftover", 1)) != 0:
                print("❌ shutdown 之后仍留下未取走的视图")
                fails.append("shutdown-leftover")
            if int(got.get("threads_after", -1)) != 1:
                print("❌ shutdown 后线程数 %s（应回到 1）" % got.get("threads_after"))
                fails.append("shutdown-threads")

        got, proc = run_mode(exe, ["empty", missing, 0])
        if got is None:
            print("❌ empty 运行失败: %s" % (proc.stderr or proc.stdout).strip()[:300])
            fails.append("empty-run")
        else:
            log.append("empty: " + proc.stdout.strip())
            if int(got.get("took", 0)) != 1 or int(got.get("count", -1)) != 0:
                print("❌ 空视图没有被算作一次结果：took=%s count=%s（重载会被静默丢弃）"
                      % (got.get("took"), got.get("count")))
                fails.append("empty-take")

        got, proc = run_mode(exe, ["early", conf, 0])
        if got is None:
            print("❌ early 运行失败: %s" % (proc.stderr or proc.stdout).strip()[:300])
            fails.append("early-run")
        elif int(got.get("early_take", 1)) != 0:
            print("❌ 没有备好视图时 take 返回了 true")
            fails.append("early-take")

        with open(os.path.join(tmp, "run.log"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(log) + "\n")
        if fails:
            print("配置读取阶段化判别失败：%s（证据 %s）" % (",".join(fails), tmp))
            return 1
        print("配置读取阶段化判别通过 ✔（证据 %s）" % tmp)
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
