#!/usr/bin/env python3
"""L0: uid.map 的整表落盘必须离开 IPC ACK 路径。

uid.map 是启动期缓存，权威视图是 injector 的内存表。旧实现在 update_uid_map_locked
里内联「读全表 + 写 uid.map.tmp + fsync + rename」，而它被 IPC ACK 前的路径与每个挂载
线程调用、并持着 uid 表互斥：宿主实测首次映射 58.9ms（p90 108.3、max 133.4），并发
命中被拖到 2583ms——一个慢 fsync 就能冻住事件循环上的其它 ACK。

判别分两半：
  - 真实 TU（夹具直编 src/injector/uid_cache_writer.c + src/core/uid_map.c，只把
    uid.map 路径指向私有目录、把 fsync 注入 200ms 慢盘）：
      ack      : request 返回 < 5ms（实测 µs），而 flush 等到慢盘写完（>=150ms）；
      coalesce : 落盘期间持续 50 次请求合并成 <=4 次 fsync，文件仍是完整 50 条；
      shutdown : 请求后直接 shutdown，已请求的一轮必须写完（文件有条目、线程回 1）；
      inline-old: 同一条慢 fsync 下直接调 uid_map_upsert —— 旧实现每次新映射的代价。
  - 接线静态检查（src/injector/inject_target.c / injector.c）：update_uid_map_locked
    只请求落盘、不再调 uid_map_upsert；early_init 装配落盘线程；关机先 flush 再 shutdown。

复现旧红灯：UID_WRITER_TARGET_SRC=<旧 inject_target.c> UID_WRITER_INJECTOR_SRC=<旧
injector.c> python3 tests/test_uid_cache_writer.py --expect-old-red
"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "tests/fixtures/uid_cache_writer_test.c"
WRITER = os.environ.get("UID_WRITER_SRC", "src/injector/uid_cache_writer.c")
TARGET = os.environ.get("UID_WRITER_TARGET_SRC", "src/injector/inject_target.c")
INJECTOR = os.environ.get("UID_WRITER_INJECTOR_SRC", "src/injector/injector.c")
MODES = ("ack", "coalesce", "shutdown", "inline-old")


def func_body(text, name):
    start = text.find(name + "(")
    if start < 0:
        return ""
    brace = text.find("{", start)
    if brace < 0:
        return ""
    depth = 0
    for idx in range(brace, len(text)):
        if text[idx] == "{":
            depth += 1
        elif text[idx] == "}":
            depth -= 1
            if depth == 0:
                return text[start:idx + 1]
    return ""


def wiring_checks():
    fails = []
    target = (ROOT / TARGET).read_text(encoding="utf-8", errors="replace")
    injector = (ROOT / INJECTOR).read_text(encoding="utf-8", errors="replace")
    body = func_body(target, "static void update_uid_map_locked")
    if not body:
        fails.append("update_uid_map_locked 未找到")
    else:
        if "uid_cache_write_request(" not in body:
            fails.append("update_uid_map_locked 没有请求后台落盘")
        if "uid_map_upsert(" in body:
            fails.append("update_uid_map_locked 仍在 ACK 路径上同步 upsert（慢 fsync 会冻住 ACK）")
    init = func_body(target, "void init_uid_map_persist")
    if "uid_cache_write_init(" not in init:
        fails.append("init_uid_map_persist 没有装配落盘线程")
    if "init_uid_map_persist();" not in injector:
        fails.append("early_init 没有调用 init_uid_map_persist")
    if "uid_cache_write_flush();" not in injector or "uid_cache_write_shutdown();" not in injector:
        fails.append("injector_shutdown 没有 flush + shutdown 落盘线程")
    return fails


def run(work):
    exe = work / "uid_cache_writer_test"
    command = ["cc", "-std=gnu2x", "-O1", "-Wall", "-Wextra", "-Werror", "-pthread",
               "-I", str(ROOT / "include"), "-o", str(exe), str(DRIVER),
               str(ROOT / WRITER), str(ROOT / "src/core/uid_map.c"),
               "-Wl,--wrap=fsync", "-Wl,--wrap=fopen", "-Wl,--wrap=rename",
               "-Wl,--wrap=unlink"]
    build = subprocess.run(command, capture_output=True, text=True)
    (work / "build.log").write_text(build.stdout + build.stderr, encoding="utf-8")
    if build.returncode != 0:
        print("❌ 编译失败（日志 %s/build.log）：" % work)
        print((build.stdout + build.stderr)[-2000:])
        return 1
    failed = 0
    for mode in MODES:
        sub = work / mode
        sub.mkdir(exist_ok=True)
        try:
            result = subprocess.run([str(exe), mode, str(sub)], capture_output=True,
                                    text=True, timeout=60)
            text = result.stdout + result.stderr + "exit=%d\n" % result.returncode
        except subprocess.TimeoutExpired:
            text = "❌ 超时 60s（落盘线程卡死或 flush 等不到完成）\n"
            result = None
        (work / (mode + ".log")).write_text(text, encoding="utf-8")
        print("%s: %s" % (mode, text.strip()))
        if result is None or result.returncode != 0:
            failed += 1
            continue
        if mode == "ack":
            m = re.search(r"request_us=(\d+) flush_ms=(\d+) fsync_calls=(\d+) file_has_entry=(\d)", text)
            if not m:
                print("❌ ack 输出无法解析")
                failed += 1
                continue
            request_us, flush_ms, _calls, has = (int(x) for x in m.groups())
            if request_us >= 5000:
                print("❌ 请求路径花了 %dus（应 < 5000us）：慢盘动作没有离开 ACK 路径" % request_us)
                failed += 1
            if flush_ms < 150:
                print("❌ flush 只等了 %dms（应 >= 150ms）：慢盘没有真的发生在落盘线程上" % flush_ms)
                failed += 1
            if has != 1:
                print("❌ 落盘线程没有写出条目")
                failed += 1
        if mode == "coalesce":
            m = re.search(r"fsync_calls=(\d+) entries_in_file=(\d+)", text)
            if not m:
                print("❌ coalesce 输出无法解析")
                failed += 1
                continue
            calls, entries = (int(x) for x in m.groups())
            if calls > 4:
                print("❌ 50 次请求产生了 %d 次 fsync：没有合并" % calls)
                failed += 1
            if entries != 50:
                print("❌ 文件只有 %d 条（应 50 条）：合并丢了条目" % entries)
                failed += 1
        if mode == "shutdown":
            if "file_has_entry=1" not in text:
                print("❌ shutdown 丢掉了已请求的写入")
                failed += 1
            m = re.search(r"tasks=(\d+)", text)
            if not m or int(m.group(1)) != 1:
                print("❌ shutdown 后仍有落盘线程残留（tasks!=1）")
                failed += 1
        if mode == "inline-old":
            m = re.search(r"inline_ms=(\d+)", text)
            if not m or int(m.group(1)) < 150:
                print("❌ 旧路径慢盘代价没有体现出来（inline_ms 应 >= 150）")
                failed += 1
    fails = wiring_checks()
    expect_old = "--expect-old-red" in sys.argv[1:]
    if expect_old:
        if not fails:
            print("❌ 旧源码上接线检查没有变红：判别力失效")
            return 1
        print("✅ 旧源码按预期变红：" + "；".join(fails))
        return 0 if failed == 0 else 1
    for item in fails:
        print("❌ 接线：" + item)
    failed += len(fails)
    if failed:
        print("uid.map 落盘隔离测试失败：%d 项（证据 %s）" % (failed, work))
        return 1
    print("uid.map 落盘隔离测试通过 ✔（证据 %s）" % work)
    return 0


def main():
    out = os.environ.get("UID_WRITER_OUTPUT_DIR")
    if out:
        work = Path(out)
        work.mkdir(parents=True, exist_ok=True)
        return run(work)
    with tempfile.TemporaryDirectory(prefix="uid-writer-") as private:
        return run(Path(private))


if __name__ == "__main__":
    sys.exit(main())