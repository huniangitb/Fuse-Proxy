#!/usr/bin/env python3
"""新建条目的权限值：mode 以调用方为准，父目录只提供属主与 setgid。

VFS 在进 FUSE 回调之前已按请求者 umask 归一过 mode（本模块不置
FUSE_CAP_DONT_MASK），daemon 不得再用父目录 mode 覆盖它——否则 umask 与
应用显式指定的 0600/0700 一起失效，父目录一旦被写成 2700 还会自我繁殖。

判别性用例（旧实现下前四条的 1/2/4 失败）：
  1. umask 022 建目录 → 0755
  2. umask 077 建目录 → 0700
  3. 父目录无 setgid 时，新建子目录不带 S_ISGID
  4. 父目录是 2700 时，新建子目录不是 2700
附加（同一根因的另一面）：
  5. umask 077 建文件 → 0600
  6. umask 022 建文件 → 0644

前置：build_gnu/ 产物、/dev/fuse、fusermount3。
"""
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BASE = Path("/tmp/fuse_entry_perms")
MNT = BASE / "mnt"
STORAGE = BASE / "storage"
MODDIR = BASE / "modules"
CONF = BASE / "injector.conf"
DLOG = BASE / "daemon.log"
DAEMON = os.environ.get("FUSE_DAEMON") or str(ROOT / "build_gnu" / "fuse_daemon")

PASS = 0
FAIL = 0
ERRS = []


def ok(d):
    global PASS
    PASS += 1
    print(f"  ✅ {d}")


def fail(d, detail=""):
    global FAIL
    FAIL += 1
    print(f"  ❌ {d}: {detail}")
    ERRS.append((d, detail))


def mode_of(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def expect_mode(desc, want, path):
    try:
        got = mode_of(path)
    except OSError as e:
        fail(desc, f"lstat 失败: {e}")
        return
    if got == want:
        ok(f"{desc} → {oct(got)}")
    else:
        fail(desc, f"期望 {oct(want)}，实际 {oct(got)}")


def with_umask(um, fn):
    old = os.umask(um)
    try:
        return fn()
    finally:
        os.umask(old)


def setup():
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)
    shutil.rmtree(BASE, ignore_errors=True)
    # 三种父目录：默认目录（属组可写）、无 setgid 的普通目录、被写成 2700 的目录
    (STORAGE / "0" / "Download").mkdir(parents=True)
    (STORAGE / "0" / "Plain").mkdir(parents=True)
    (STORAGE / "0" / "Poison").mkdir(parents=True)
    os.chmod(STORAGE / "0" / "Download", 0o770)
    os.chmod(STORAGE / "0" / "Plain", 0o755)
    os.chmod(STORAGE / "0" / "Poison", 0o2700)
    MNT.mkdir(parents=True)
    MODDIR.mkdir(parents=True, exist_ok=True)
    CONF.write_text("[GLOBAL]\nMONITOR OFF\nSANDBOX OFF\n")


def start():
    p = subprocess.Popen([DAEMON, f"--root={STORAGE}", f"--rules={CONF}",
                          f"--modules-dir={MODDIR}", "-f", str(MNT)],
                         stdout=open(DLOG, "w"), stderr=subprocess.STDOUT)
    for _ in range(45):
        time.sleep(0.3)
        try:
            if list(MNT.iterdir()):
                return p
        except OSError:
            pass
        if p.poll() is not None:
            return None
    return p


def stop(p):
    if p:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
    time.sleep(0.3)
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)


def main():
    setup()
    p = start()
    if not p:
        fail("daemon 启动失败", f"见 {DLOG}")
        return 1
    try:
        u0 = MNT / "0"
        dl = u0 / "Download"
        plain = u0 / "Plain"
        poison = u0 / "Poison"

        print("\n── A. 目录：mode 由调用方 umask 决定 ──")
        with_umask(0o022, lambda: os.mkdir(dl / "d022"))
        expect_mode("umask 022 mkdir", 0o755, dl / "d022")

        with_umask(0o077, lambda: os.mkdir(dl / "d077"))
        expect_mode("umask 077 mkdir", 0o700, dl / "d077")

        print("\n── B. setgid 只在父目录带它时继承 ──")
        with_umask(0o022, lambda: os.mkdir(plain / "child"))
        expect_mode("父目录无 setgid（0755）时子目录", 0o755, plain / "child")

        print("\n── C. 毒化不复现：2700 父目录不再把 2700 复制给子目录 ──")
        with_umask(0o022, lambda: os.mkdir(poison / "probe"))
        try:
            got = mode_of(poison / "probe")
            if got == 0o2700:
                fail("2700 父目录下新建子目录", "仍是 2700（继承逻辑在复制父目录 mode）")
            else:
                ok(f"2700 父目录下新建子目录 → {oct(got)}（不是 2700）")
        except OSError as e:
            fail("2700 父目录下新建子目录", f"lstat 失败: {e}")

        print("\n── D. 文件：umask 同样生效 ──")
        with_umask(0o077, lambda: open(dl / "f077", "w").close())
        expect_mode("umask 077 create", 0o600, dl / "f077")

        with_umask(0o022, lambda: open(dl / "f022", "w").close())
        expect_mode("umask 022 create", 0o644, dl / "f022")

        print("\n── E. 结构条目：应用改不动顶层目录的 mode ──")
        before = mode_of(STORAGE / "0" / "Download")
        try:
            os.chmod(dl, 0o700)
        except OSError as e:
            fail("chmod 顶层目录", f"应静默成功（AOSP 口径），实际抛 {e}")
        else:
            after = mode_of(STORAGE / "0" / "Download")
            if after == before:
                ok(f"chmod 顶层目录被丢弃（{oct(before)} 保持不变）")
            else:
                fail("chmod 顶层目录", f"权限被改：{oct(before)} → {oct(after)}")
    finally:
        stop(p)

    print(f"\n结果：{PASS} 通过 / {FAIL} 失败")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
