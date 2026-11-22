#!/usr/bin/env python3
"""L0: fast_pid 缓存的跨线程安全（恢复 worker 扫描 + 事件循环清缓存）。

夹具直编真实 src/core/fast_pid.c：一个线程扮 FUSE 恢复 worker 反复 fast_pid_each，
另一个扮事件循环每轮 fast_pid_cache_clear + fast_pid_each。旧实现没有锁、且共用一块
1MB 目录项缓冲，ASan/UBSan 构建下必然命中 use-after-free（修剪循环读到已释放的
pid 数组），plain 构建则不崩——最难现场取证的那类。

FAST_PID_SRC 指向旧源做判别；FAST_PID_OUTPUT_DIR 保留编译/运行证据。
--expect-old-red：要求旧源红（动态 ASan 命中），用于判别性自证。
"""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ITERS = "300"
SANITIZE = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g"]


def func_body(text, name):
    start = text.find(name + "(")
    if start < 0:
        return None
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return None


def static_checks(fails, source_path):
    """缓存访问必须加锁、目录项缓冲不得跨线程共用。"""
    with open(source_path, encoding="utf-8") as fh:
        text = fh.read()
    ok = True

    def need(cond, tag, message):
        nonlocal ok
        if not cond:
            print("❌ " + message)
            fails.append(tag)
            ok = False

    need("g_dirent_buf" not in text, "static-shared-buf",
         "fast_pid 仍用全文件共享的目录项缓冲：两个线程遍历 /proc 会互相覆盖")
    need(text.count("pthread_mutex_lock(&g_fp_mu)") >= 4, "static-lock",
         "缓存访问没有全部进锁（clear/add/prune/init 至少四处）")
    each = func_body(text, "void fast_pid_each")
    prune = func_body(text, "static void cache_prune_dead")
    need(each is not None and "cache_prune_dead()" in each, "static-prune",
         "fast_pid_each 末尾的修剪没有走持锁的 cache_prune_dead()")
    need(prune is not None and "pthread_mutex_lock(&g_fp_mu)" in prune, "static-prune-lock",
         "修剪循环没有持锁：与 fast_pid_cache_clear 的释放会撞成 use-after-free")
    return ok


def build(work, source):
    cc = shlex.split(os.environ.get("CC", "cc"))
    if not cc or not shutil.which(cc[0]):
        return None
    binary = work / "fast_pid_threads"
    command = cc + ["-std=c23", "-DTARGET_GNU=1", "-D_GNU_SOURCE", "-O1",
                    "-Wall", "-Wextra", "-Werror", "-I" + str(ROOT / "include")]
    command += SANITIZE
    command += [str(source), str(ROOT / "tests/fixtures/fast_pid_threads_driver.c"),
                "-pthread", "-o", str(binary)]
    compiled = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=300)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        print("FAIL: compile", compiled.returncode)
        return None
    return binary


def run(binary, work):
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1"
    try:
        result = subprocess.run([str(binary), ITERS], cwd=ROOT, capture_output=True,
                                text=True, timeout=300, env=env)
    except subprocess.TimeoutExpired as exc:
        text = "FAIL: 驱动超过 300s（%s）\n" % exc
        (work / "run.log").write_text(text)
        return 1, text
    text = result.stdout + result.stderr + "exit=%d\n" % result.returncode
    (work / "run.log").write_text(text)
    return result.returncode, text


def main():
    old_red = "--expect-old-red" in sys.argv
    source = Path(os.environ.get("FAST_PID_SRC", ROOT / "src/core/fast_pid.c")).resolve()
    retained = os.environ.get("FAST_PID_OUTPUT_DIR")
    directory = Path(retained).resolve() if retained else Path(tempfile.mkdtemp(prefix="nsp-fpth-"))
    directory.mkdir(parents=True, exist_ok=True)
    fails = []
    if old_red:
        if not static_checks(fails, source):
            print("旧实现静态判据按预期红：缓存访问无锁/共用目录项缓冲")
        binary = build(directory, source)
        if binary is None:
            print("FAIL: 旧源编译失败（判别基线不可用）")
            return 1
        code, text = run(binary, directory)
        print(text, end="")
        if code != 0 and ("AddressSanitizer" in text or "use-after-free" in text):
            print("旧实现按预期红：ASan/UBSan 命中跨线程 use-after-free")
            return 0
        print("❌ 旧实现没有红（判别力失效）")
        return 1
    if not static_checks(fails, source):
        return 1
    binary = build(directory, source)
    if binary is None:
        return 1
    code, text = run(binary, directory)
    print(text, end="")
    for marker in ("AddressSanitizer", "use-after-free", "runtime error"):
        if marker in text:
            print("❌ 运行期出现 " + marker)
            fails.append("sanitizer")
    if code != 0:
        print("❌ 驱动退出码 %d（缓存跨线程访问破坏状态）" % code)
        fails.append("exit")
    counts = dict(re.findall(r"(calls_[ab])=(\d+)", text))
    for key in ("calls_a", "calls_b"):
        if not counts.get(key, u"0").isdigit() or int(counts.get(key, u"0")) <= 0:
            print("❌ " + key + " 没有增长（扫描没有真正跑到进程表）")
            fails.append(key)
    for marker, tag in (("clear_after_join=ok", "after-join"), ("cleanup=ok", "cleanup")):
        if marker not in text:
            print("❌ 缺少 " + marker)
            fails.append(tag)
    if fails:
        print("❌ fast_pid 跨线程判别未通过（%s）" % ",".join(fails))
        return 1
    print("✅ 全部通过：fast_pid 缓存在多线程扫描/清缓存下无 use-after-free")
    return 0


if __name__ == "__main__":
    sys.exit(main())
