#!/usr/bin/env python3
"""
-o negative_timeout 熔断回归测试
================================
libfuse 的负缓存分支在 LOOKUP 未命中且 negative_timeout != 0 时，以
`e.ino=0` 成功回包（subprojects/libfuse/lib/fuse.c fuse_lib_lookup）；
现代内核（proto>=4）把 nodeid=0 原样入缓存，后续 FORGET(0) 触发
`get_node(0)` abort → SIGABRT（线上崩溃实例）。

框架侧约定：fuse_daemon 启动时单点剥离 `-o negative_timeout[=N]` 子项
（其余 -o 子项保留），恒以 libfuse 默认 0.0 运行。本用例断言该不变式：

  A. 分词形式（injector 下发 FUSE_EXTRA_ARGS 的实际形态：`-o`,
     `negative_timeout=5,...`）：挂载成功 + 未命中后建文件立即可见
     （负缓存生效时 5s 内仍报 ENOENT）。
  B. 粘连形式（`-onegative_timeout=5`）：挂载成功 + 基本 IO 正常
     （剥离不得破坏其余参数解析）。

前置：GNU 产物 build_gnu/fuse_daemon、fusermount3、/dev/fuse；
缺失则跳过（rc=0，沿用仓库约定）。
"""
import os
import shutil
import subprocess
import sys
import time
import uuid

BASE = "/tmp/fuse_neg_test"
MNT = BASE + "/mnt"
STORAGE = BASE + "/storage"
CONF = BASE + "/injector.conf"
MODDIR = BASE + "/modules"
DAEMON = os.environ.get("FUSE_DAEMON") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "build_gnu", "fuse_daemon"))
TEST_ID = str(uuid.uuid4())[:8]
PASS = 0
FAIL = 0
ERRORS = []


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


def ok(desc):
    global PASS
    PASS += 1
    log(f"  ✅ {desc}")


def fail(desc, detail=""):
    global FAIL
    FAIL += 1
    log(f"  ❌ {desc}: {detail}")
    ERRORS.append((desc, detail))


CONFIG_TEXT = """
[GLOBAL]
MONITOR OFF
"""


def setup_env():
    shutil.rmtree(BASE, ignore_errors=True)
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    os.makedirs(STORAGE + "/0", exist_ok=True)
    os.makedirs(MNT, exist_ok=True)
    os.makedirs(MODDIR, exist_ok=True)
    with open(CONF, "w") as fh:
        fh.write(CONFIG_TEXT.strip())


def start_daemon(extra_args, log_path):
    proc = subprocess.Popen(
        [DAEMON, "--root=" + STORAGE, "--rules=" + CONF,
         "--modules-dir=" + MODDIR, "-f", MNT] + extra_args + ["info"],
        stdout=open(log_path, "w"),
        stderr=subprocess.STDOUT)
    for _ in range(15):
        time.sleep(0.3)
        try:
            os.listdir(MNT + "/0")
            return proc
        except OSError:
            pass
        if proc.poll() is not None:
            return None
    return proc


def stop_daemon(proc):
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            proc.kill()
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)


def scenario_separate_form():
    """A. 分词形式 `-o negative_timeout=5,...`：负缓存必须关闭。"""
    log("场景A: 分词形式 -o negative_timeout=5,attr_timeout=7")
    setup_env()
    probe = f"neg_probe_{TEST_ID}"
    with open(f"{STORAGE}/0/seed_{TEST_ID}.txt", "w") as fh:
        fh.write("seed")
    proc = start_daemon(["-o", "negative_timeout=5,attr_timeout=7"],
                        BASE + "/daemon_a.log")
    if proc is None or proc.poll() is not None:
        fail("daemon 挂载成功（分词形式未破坏参数解析）", "daemon 提前退出")
        stop_daemon(proc)
        return
    ok("daemon 挂载成功（分词形式未破坏参数解析）")
    try:
        try:
            os.stat(f"{MNT}/0/{probe}")
            fail("未命中先报 ENOENT", "不存在的文件 stat 竟成功")
            return
        except FileNotFoundError:
            ok("不存在的文件先报 ENOENT")
        # 绕过 FUSE 直接建文件：负缓存生效时 5s 内仍报 ENOENT
        with open(f"{STORAGE}/0/{probe}", "w") as fh:
            fh.write("content_" + TEST_ID)
        try:
            with open(f"{MNT}/0/{probe}") as fh:
                data = fh.read()
        except FileNotFoundError:
            fail("建文件后立即可见（负缓存已关闭）", "仍报 ENOENT：negative_timeout 生效中")
            return
        if data == "content_" + TEST_ID:
            ok("建文件后立即可见（负缓存已关闭）")
        else:
            fail("建文件后立即可见（负缓存已关闭）", f"内容不符: {data!r}")
    finally:
        stop_daemon(proc)


def scenario_attached_form():
    """B. 粘连形式 `-onegative_timeout=5`：剥离且挂载/IO 正常。"""
    log("场景B: 粘连形式 -onegative_timeout=5")
    setup_env()
    with open(f"{STORAGE}/0/seed_{TEST_ID}.txt", "w") as fh:
        fh.write("seed_" + TEST_ID)
    proc = start_daemon(["-onegative_timeout=5"], BASE + "/daemon_b.log")
    if proc is None or proc.poll() is not None:
        fail("daemon 挂载成功（粘连形式未破坏参数解析）", "daemon 提前退出")
        stop_daemon(proc)
        return
    ok("daemon 挂载成功（粘连形式未破坏参数解析）")
    try:
        try:
            with open(f"{MNT}/0/seed_{TEST_ID}.txt") as fh:
                data = fh.read()
        except OSError as e:
            fail("基本 IO 正常", f"读种子文件失败: {e}")
            return
        if data == "seed_" + TEST_ID:
            ok("基本 IO 正常")
        else:
            fail("基本 IO 正常", f"内容不符: {data!r}")
    finally:
        stop_daemon(proc)


def main():
    if not os.path.exists(DAEMON):
        log(f"跳过：找不到 fuse_daemon 产物 {DAEMON}")
        return 0
    if not os.path.exists("/dev/fuse"):
        log("跳过：缺少 /dev/fuse（内核未启用 FUSE）")
        return 0
    if shutil.which("fusermount3") is None:
        log("跳过：缺少 fusermount3")
        return 0
    scenario_separate_form()
    scenario_attached_form()
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    shutil.rmtree(BASE, ignore_errors=True)
    print(f"\n结果: {PASS} 通过, {FAIL} 失败")
    if ERRORS:
        for d, det in ERRORS:
            print(f"  ❌ {d}: {det}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
