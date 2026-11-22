#!/usr/bin/env python3
"""L0: 配置重载的慢读盘/慢 pm 不得跨配置写锁（否则整进程读者一起冻住）。

注入器在唯一事件循环线程里重载配置，旧序列是
`config_lock_write(); reload_config_rules_diff(...); config_unlock_write();`，
而该库函数内部先 `config_read_view`（真读盘 + `scan_active_users` 的 pm 探测，预算
800ms）再构建发布：写锁期间同进程所有 config 读者（pre-hook 规则判定、发布器、
控制面查询）全被挡住，一次慢盘/慢 binder 放大成整进程无响应。

判别（真实 TU）：驱动直编 `src/config/config_parser.c`，用 `--wrap=fopen` 注入 300ms
慢读盘、`--wrap=common_run_cmd_lines` 注入 300ms 慢 pm，读者线程全程量
`config_lock_read()` 的等待。两段式序列（读盘锁外 + 提交锁内）读者等待 <50ms；
旧序列（全在写锁内）读者被挡 >300ms。另做静态检查：注入器两个调用点不得在
`config_lock_write()`…`config_unlock_write()` 之间读视图。

复现旧序列红灯：python3 tests/test_cfg_reload_lock.py --show-old（旧序列一律会红，
本套件把它当判别证据打印，不据此判失败）。
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
DRIVER = os.path.join(ROOT, "tests", "fixtures", "cfg_reload_lock_driver.c")
INJECTOR = os.path.join(ROOT, "src", "injector", "injector.c")
SOURCES = [
    "src/config/config_parser.c",
    "src/config/path_vars.c",
    "src/core/path_trie.c",
    "src/core/nsp_util.c",
    "src/core/nsp_comm.c",
    "src/core/common.c",
    "src/core/sys_pkg.c",
]
LIMIT_READER_US = 50000   # 新序列：读者等待上限 50ms
MIN_READ_MS = 400         # 证明慢读盘/慢 pm 真的发生了（300+300）
OLD_MIN_BLOCK_US = 300000 # 旧序列：读者被挡 ≥300ms 才算判别成立
CONFIG_DIR_PAT = re.compile(
    r'^#define\s+(?:NSP_CONFIG_DIR|CONFIG_DIR)\s+"/var/fuse-proxy"\s*$', re.M)


def prepare_include(tmpdir, config_dir):
    dst = os.path.join(tmpdir, "include")
    shutil.copytree(os.path.join(ROOT, "include"), dst)
    hits = 0
    for name in sorted(os.listdir(dst)):
        if not name.endswith(".h"):
            continue
        path = os.path.join(dst, name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        patched, n = CONFIG_DIR_PAT.subn(
            lambda m: m.group(0).replace('"/var/fuse-proxy"', '"%s"' % config_dir), text)
        if n:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(patched)
            hits += n
    return dst if hits else None


def func_body(text, name):
    """按函数名取大括号体（够用的花括号计数，注释里无裸花括号的目标函数）。"""
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


def check_call_sites(fails, log):
    if not os.path.isfile(INJECTOR):
        print("❌ 缺少注入器源码 %s" % INJECTOR)
        fails.append("missing-injector")
        return
    text = open(INJECTOR, encoding="utf-8").read()
    for fn in ("reload_injector_config", "reload_apply_view"):
        body = func_body(text, fn)
        if body is None:
            print("❌ 找不到 %s 函数体（静态检查失效）" % fn)
            fails.append(fn)
            continue
        log.append("%s: 找到函数体 %d 字节" % (fn, len(body)))
        for lock in ("config_lock_write();",):
            if lock not in body:
                print("❌ %s 里没有 %s" % (fn, lock))
                fails.append(fn + "-no-lock")
                continue
        lw = body.find("config_lock_write();")
        uw = body.find("config_unlock_write();", lw)
        if lw < 0 or uw < 0:
            print("❌ %s 的写锁区间不完整" % fn)
            fails.append(fn + "-no-span")
            continue
        span = body[lw:uw]
        for banned in ("config_read_view", "reload_config_rules_diff", "load_config_rules"):
            if banned in span:
                print("❌ %s 在写锁内仍有 %s（慢读盘会跨写锁）" % (fn, banned))
                fails.append(fn + "-" + banned)
        if fn == "reload_apply_view":
            # 重载已两段式：提交段根本不该出现读视图（读盘在 reload_stage worker 上）
            if "config_read_view" in body:
                print("❌ reload_apply_view 里出现了 config_read_view（读盘又回到事件循环）")
                fails.append(fn + "-inline-read")
        elif "config_read_view" not in body[:lw]:
            print("❌ %s 没有在取写锁前准备视图（config_read_view）" % fn)
            fails.append(fn + "-no-prepare")
        log.append("%s: 写锁区间 %d 字节，锁内无读视图调用" % (fn, len(span)))
    # 两段式入口：第一段只发请求、全程不取写锁（读盘不在循环上，也就没有锁内读盘）
    start_body = func_body(text, "handle_pending_reload_begin")
    if start_body is None:
        print("❌ 找不到 handle_pending_reload_begin 函数体（静态检查失效）")
        fails.append("no-reload-begin")
    else:
        if "config_lock_write();" in start_body:
            print("❌ 重载第一段取了配置写锁（慢读盘会跨写锁）")
            fails.append("begin-write-lock")
        if "nsp_reload_stage_request()" not in start_body:
            print("❌ 重载第一段没有把读取派给 worker")
            fails.append("begin-no-request")
    finish_body = func_body(text, "handle_pending_reload_finish")
    if finish_body is None or "nsp_reload_stage_take(" not in finish_body:
        print("❌ 重载第二段没有取走 worker 备好的视图")
        fails.append("finish-no-take")


def main():
    show_old = "--show-old" in sys.argv[1:]
    cc = shlex.split(os.environ.get("CC", "cc"))
    if shutil.which(cc[0]) is None:
        print("跳过：缺少 C 编译器")
        return SKIP_RC
    out_dir = os.environ.get("CFG_RELOAD_LOCK_OUTPUT_DIR")
    tmp = out_dir or tempfile.mkdtemp(prefix="cfg_reload_lock_")
    os.makedirs(tmp, exist_ok=True)
    cfgdir = os.path.join(tmp, "cfg")
    os.makedirs(cfgdir, exist_ok=True)
    inc = prepare_include(tmp, cfgdir)
    if inc is None:
        print("❌ 没找到 CONFIG_DIR 宏，无法隔离配置目录")
        return 1
    exe = os.path.join(tmp, "cfg_reload_lock")
    build = cc + ["-std=gnu2x", "-O2", "-pthread", "-I", inc, "-I", os.path.join(ROOT, "include"),
                  "-o", exe, DRIVER] + [os.path.join(ROOT, s) for s in SOURCES] + [
                  "-Wl,--wrap=fopen", "-Wl,--wrap=common_run_cmd_lines"]
    proc = subprocess.run(build, capture_output=True, text=True)
    with open(os.path.join(tmp, "build.log"), "w", encoding="utf-8") as fh:
        fh.write(proc.stdout + proc.stderr)
    if proc.returncode != 0:
        print("❌ 编译失败（见 %s/build.log）" % tmp)
        print((proc.stdout + proc.stderr)[-2000:])
        return 1

    fails = []
    log = []
    for mode in ("new", "old"):
        proc = subprocess.run([exe, mode, "300", "300", "2"], capture_output=True, text=True,
                              timeout=120, env={"PATH": "/usr/local/bin:/usr/bin:/bin"})
        out = proc.stdout + proc.stderr
        log.append("%s: %s" % (mode, out.strip()))
        got = dict((k, int(v)) for k, v in re.findall(r"(\w+)=(-?\d+)", out))
        if proc.returncode != 0:
            print("❌ %s 模式运行失败 rc=%d out=%r" % (mode, proc.returncode, out[-300:]))
            fails.append(mode + "-rc")
            continue
        if mode == "new":
            if got.get("read_ms", 0) < MIN_READ_MS:
                print("❌ 慢读盘/慢 pm 没有真的发生：read_ms=%s（期望 >=%d）"
                      % (got.get("read_ms"), MIN_READ_MS))
                fails.append("new-read")
            if got.get("reader_max_us", 10 ** 9) > LIMIT_READER_US:
                print("❌ 两段式序列仍挡住配置读者：reader_max_us=%s（上限 %d）"
                      % (got.get("reader_max_us"), LIMIT_READER_US))
                fails.append("new-reader")
        else:
            blocked = got.get("reader_max_us", 0)
            msg = "旧序列读者被挡 %dµs（判据 >=%d）" % (blocked, OLD_MIN_BLOCK_US)
            if blocked >= OLD_MIN_BLOCK_US:
                print("旧序列判别红：" + msg)
            else:
                print("⚠️  旧序列未红：" + msg + "——判别力不足，按失败处理")
                fails.append("old-not-red")
    check_call_sites(fails, log)
    with open(os.path.join(tmp, "run.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(log) + "\n")
    if fails:
        print("配置重载锁判别失败：%s（证据 %s）" % (",".join(fails), tmp))
        return 1
    print("配置重载锁判别通过 ✔（证据 %s）" % tmp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
