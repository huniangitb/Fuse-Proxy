#!/usr/bin/env python3
"""新建条目的权限值：mode 以调用方为准，共享存储按固定形状补位，私有树只给文件补组位。

VFS 在进 FUSE 回调之前已按请求者 umask 归一过 mode（本模块不置
FUSE_CAP_DONT_MASK），daemon 不得再用父目录 mode 覆盖它——否则 umask 与
应用显式指定的 0600/0700 一起失效，父目录一旦被写成 2700 还会自我繁殖。

另一头是共享存储：条目最终要能被树里的其他应用打开（MediaProvider 按调用方
凭证做 DAC，0600 的条目除写入者谁也打不开），故落点在 <存储根>/<用户层> 且
不在 Android/{data,obb,media} 三棵私有树里时，mode 再按固定形状补位：文件
0660、目录 0770，只加位不减位。

私有树（根层 Android/{data,obb,media}）补得更窄：普通文件补组位（0600→0660），
目录保持调用方 mode。能穿过包目录（2770 归 ext_data_rw）的本来就只有全盘访问
能力应用与系统组件，应用在下载目录里被 umask 削到 0600 的条目，这批身份读不到；
目录不补，树的隔离靠目录位，连目录一起放宽才会造出第二个共享存储。

判别性用例（父目录 mode 覆盖实现下 1/2/5 失败；私有树不补位的实现下 6/7 失败；
私有树连目录一起补位的实现下 11 失败）：
  1. umask 022 建目录 → 0755 | 0770 = 0775
  2. umask 077 建目录 → 0700 | 0770 = 0770
  3. 父目录无 setgid 时，新建子目录不带 S_ISGID
  4. 父目录是 2700 时，新建子目录不是 2700
  5. umask 077 / 022 建文件 → 0660 / 0664
  6. 私有树里 umask 077 建文件 → 0660（0600 | 0060）
  7. 私有树里 umask 022 建文件 → 0664（0644 | 0060）
  8. 私有树的 obb / media 两棵同样补组位
  9. 私有树的普通文件属主/属组跟随父目录
 10. 私有树里 setgid 仍按父目录继承，2700 父目录不把 2700 送给子目录
 11. 私有树里建目录 → 0700（目录不补位）
 12. 深层同名目录（/sdcard/x/Android/data）仍按共享存储补位：目录 0770
附加：
 13. 结构条目的 chmod 被丢弃（AOSP 口径）

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
PRIV_PKG = "com.example.app"
PRIV_SG = "com.example.sg"

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


def expect_owner(desc, path, parent):
    try:
        st = os.lstat(path)
        pst = os.lstat(parent)
    except OSError as e:
        fail(desc, f"lstat 失败: {e}")
        return
    if (st.st_uid, st.st_gid) == (pst.st_uid, pst.st_gid):
        ok(f"{desc} → {st.st_uid}:{st.st_gid}")
    else:
        fail(desc, f"期望 {pst.st_uid}:{pst.st_gid}，实际 {st.st_uid}:{st.st_gid}")


def with_umask(um, fn):
    old = os.umask(um)
    try:
        return fn()
    finally:
        os.umask(old)


def create(path, mode=0o666):
    """按给定 mode 建空文件：os.open 的 mode 会被 umask 削，与内核进 FUSE 前一致。"""
    os.close(os.open(path, os.O_CREAT | os.O_WRONLY, mode))


def setup():
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)
    shutil.rmtree(BASE, ignore_errors=True)
    # 父目录：共享存储默认目录（属组可写）、无 setgid 的普通目录、被写成 2700 的目录、
    # 私有树三棵（data 含一个 setgid 包目录）、以及深层同名 Android/data
    for rel in ("Download", "Plain", "Poison",
                f"Android/data/{PRIV_PKG}", f"Android/data/{PRIV_SG}",
                f"Android/obb/{PRIV_PKG}", f"Android/media/{PRIV_PKG}",
                f"Deep/Android/data/{PRIV_PKG}"):
        (STORAGE / "0" / rel).mkdir(parents=True)
    os.chmod(STORAGE / "0" / "Download", 0o770)
    os.chmod(STORAGE / "0" / "Plain", 0o755)
    os.chmod(STORAGE / "0" / "Poison", 0o2700)
    for rel in (f"Android/data/{PRIV_PKG}", f"Android/obb/{PRIV_PKG}",
                f"Android/media/{PRIV_PKG}", f"Deep/Android/data/{PRIV_PKG}"):
        os.chmod(STORAGE / "0" / rel, 0o770)
    os.chmod(STORAGE / "0" / "Android/data" / PRIV_SG, 0o2770)
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
        priv = u0 / "Android" / "data" / PRIV_PKG
        priv_sg = u0 / "Android" / "data" / PRIV_SG
        deep = u0 / "Deep" / "Android" / "data" / PRIV_PKG

        print("\n── A. 共享存储的目录：umask 决定其它位，组位由树补齐 ──")
        with_umask(0o022, lambda: os.mkdir(dl / "d022"))
        expect_mode("umask 022 mkdir（0755 | 0770）", 0o775, dl / "d022")

        with_umask(0o077, lambda: os.mkdir(dl / "d077"))
        expect_mode("umask 077 mkdir（0700 | 0770）", 0o770, dl / "d077")

        print("\n── B. setgid 只在父目录带它时继承 ──")
        with_umask(0o022, lambda: os.mkdir(plain / "child"))
        expect_mode("父目录无 setgid（0755）时子目录", 0o775, plain / "child")

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

        print("\n── D. 共享存储的文件：umask 生效，组位照补 ──")
        with_umask(0o077, lambda: create(dl / "f077"))
        expect_mode("umask 077 create（0600 | 0660）", 0o660, dl / "f077")

        with_umask(0o022, lambda: create(dl / "f022"))
        expect_mode("umask 022 create（0644 | 0660）", 0o664, dl / "f022")

        print("\n── E. 私有树的文件：只补组位，属主/属组跟随父目录 ──")
        with_umask(0o077, lambda: create(priv / "f077"))
        expect_mode("私有树 umask 077 create（0600 | 0060）", 0o660, priv / "f077")
        expect_owner("私有树 create 的属主/属组", priv / "f077", priv)

        with_umask(0o022, lambda: create(priv / "f022"))
        expect_mode("私有树 umask 022 create（0644 | 0060）", 0o664, priv / "f022")

        with_umask(0o000, lambda: create(priv / "f400", 0o400))
        expect_mode("私有树显式 0400（只补组位，属主位不动）", 0o460, priv / "f400")

        with_umask(0o022, lambda: create(u0 / "Android" / "obb" / PRIV_PKG / "f"))
        expect_mode("私有树 obb 的 create", 0o664, u0 / "Android" / "obb" / PRIV_PKG / "f")

        with_umask(0o077, lambda: create(u0 / "Android" / "media" / PRIV_PKG / "f"))
        expect_mode("私有树 media 的 create", 0o660, u0 / "Android" / "media" / PRIV_PKG / "f")

        print("\n── F. 私有树的目录：不补位，setgid 仍按父目录继承 ──")
        with_umask(0o077, lambda: os.mkdir(priv / "d077"))
        expect_mode("私有树 umask 077 mkdir（不补目录位）", 0o700, priv / "d077")

        with_umask(0o077, lambda: os.mkdir(priv_sg / "child"))
        expect_mode("私有树 setgid 父目录（2770）下子目录", 0o2700, priv_sg / "child")

        with_umask(0o022, lambda: create(priv_sg / "f"))
        expect_mode("私有树 setgid 父目录下文件（不带 S_ISGID）", 0o664, priv_sg / "f")

        print("\n── G. 两条路径不串：深层同名 Android/data 仍按共享存储 ──")
        with_umask(0o077, lambda: os.mkdir(deep / "child"))
        expect_mode("深层同名目录下 mkdir（0700 | 0770）", 0o770, deep / "child")

        print("\n── H. 结构条目：应用改不动顶层目录的 mode ──")
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
