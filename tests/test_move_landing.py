#!/usr/bin/env python3
"""跨树搬移的落位属性：rename 落进共享存储后，属主/属组跟随目标父目录、mode 补位。

rename(2) 只换名字不换属性，被搬进 /sdcard 的条目会带着来源树的属主与 mode 落地。
共享存储里属主是「某个应用」的条目，MediaProvider 按调用方凭证走 DAC：0600 就意味
着除写入者自己，别的应用全部 open EACCES（文件管理器打不开「另存到
/sdcard/Download」的文件就是这个形状）。

判据按落点归类，不按「属主是否与父目录相同」：应用私有树与共享存储可能同属一个
uid（私有树里的文件本就归应用），属主一致却正是来源树 mode 被削到 0600 的现场。

判别性用例（旧实现下 A 组与 B5 失败）：
  A1. 0600 文件搬进共享目录 → 0660 且属组跟随父目录
  A2. 0644 文件搬进共享目录 → 0664（只加位不减位，o+r 保留）
  A3. 0700 目录搬进带 setgid 的共享目录 → 02770
  A4. 0700 目录搬进不带 setgid 的共享目录 → 0770（不带 S_ISGID）
  B5. 属主/属组与目标父目录一致的搬移 → 仍按树补齐 0660（旧实现按属主早退得 0600）
  C6. 搬进应用私有树（/Android/data/<包>）→ 属性原样不动
  D7. 符号链接搬进共享目录 → 仍是链接，链接自身 mode 不动、不改到目标文件

前置：build_gnu/ 产物、/dev/fuse、fusermount3。跨用户（uid）搬移需要 root，本套件
用「同 uid、不同属组」构造跨树，普通用户即可跑。
"""
import grp
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BASE = Path("/tmp/fuse_move_landing")
MNT = BASE / "mnt"
STORAGE = BASE / "storage"
MODDIR = BASE / "modules"
CONF = BASE / "injector.conf"
DLOG = BASE / "daemon.log"
DAEMON = os.environ.get("FUSE_DAEMON") or str(ROOT / "build_gnu" / "fuse_daemon")

PASS = 0
FAIL = 0
SKIP = 0
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


def skip(d, why):
    global SKIP
    SKIP += 1
    print(f"  ⏭️ {d}：{why}")


def alt_gid():
    """一个当前用户**不是**主属组的补充组：跨树搬移靠它构造（同 uid、不同 gid）。"""
    for g in os.getgroups():
        if g != os.getgid():
            return g
    return None


def attrs(path):
    st = os.lstat(path)
    return st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)


def expect_attrs(desc, want_mode, want_gid, path, want_uid=None):
    try:
        uid, gid, mode = attrs(path)
    except OSError as e:
        fail(desc, f"lstat 失败: {e}")
        return
    bad = []
    if mode != want_mode:
        bad.append(f"mode 期望 {oct(want_mode)} 实际 {oct(mode)}")
    if want_gid is not None and gid != want_gid:
        bad.append(f"属组期望 {want_gid} 实际 {gid}")
    if want_uid is not None and uid != want_uid:
        bad.append(f"属主期望 {want_uid} 实际 {uid}")
    if bad:
        fail(desc, "；".join(bad))
    else:
        ok(f"{desc} → {oct(mode)} {uid}:{gid}")


def setup():
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)
    shutil.rmtree(BASE, ignore_errors=True)
    share_gid = alt_gid()
    # 共享存储的落点都取**根层之下**的目录：根一级条目的 mode 由 daemon 启动时的
    # 顶层修复统一改为 0770（test_entry_perms.py 的 E 组守的就是这条），拿它当落点
    # 会把 setgid 一起抹掉，量到的是修复后的形态而不是搬移的收尾
    (STORAGE / "0" / "Download" / "QQ").mkdir(parents=True)
    (STORAGE / "0" / "Shared" / "NoSG").mkdir(parents=True)
    (STORAGE / "0" / "Shared" / "Own").mkdir(parents=True)
    # 来源树（代表应用私有树里的暂存目录）
    (STORAGE / "0" / "Staging").mkdir(parents=True)
    # 应用私有树的落点
    (STORAGE / "0" / "Android" / "data" / "com.example.app").mkdir(parents=True)
    if share_gid is not None:
        # 带 setgid、属组是别的组
        os.chown(STORAGE / "0" / "Download" / "QQ", os.getuid(), share_gid)
        os.chmod(STORAGE / "0" / "Download" / "QQ", 0o2775)
        # 不带 setgid、属组是别的组
        os.chown(STORAGE / "0" / "Shared" / "NoSG", os.getuid(), share_gid)
        os.chmod(STORAGE / "0" / "Shared" / "NoSG", 0o775)
    os.chmod(STORAGE / "0" / "Shared" / "Own", 0o775)
    os.chmod(STORAGE / "0" / "Staging", 0o775)
    os.chmod(STORAGE / "0" / "Android" / "data" / "com.example.app", 0o770)
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
    share_gid = alt_gid()
    if share_gid is None:
        print("环境不具备：当前用户没有第二属组，无法构造跨树搬移（返回 77）")
        return 77
    setup()
    p = start()
    if not p:
        fail("daemon 启动失败", f"见 {DLOG}")
        return 1
    dl_name = grp.getgrgid(share_gid).gr_name
    try:
        u0 = MNT / "0"
        dl = u0 / "Download" / "QQ"
        nosg = u0 / "Shared" / "NoSG"
        own = u0 / "Shared" / "Own"
        staging = u0 / "Staging"
        priv = u0 / "Android" / "data" / "com.example.app"
        dl_backing = STORAGE / "0" / "Download" / "QQ"
        own_backing = STORAGE / "0" / "Shared" / "Own"
        nosg_backing = STORAGE / "0" / "Shared" / "NoSG"

        print(f"\n── A. 跨树搬移进共享存储（目标属组 {share_gid}={dl_name}）──")
        src_file = staging / "qq.apk"
        open(src_file, "w").close()
        os.chmod(src_file, 0o600)
        expect_attrs("来源文件（应用私有树形态）", 0o600, os.getgid(), src_file)
        os.rename(str(src_file), str(dl / "saved.apk.1"))
        expect_attrs("A1 0600 文件搬进共享目录", 0o660, share_gid, dl_backing / "saved.apk.1")
        expect_attrs("A1′ 同一文件经挂载视图看", 0o660, share_gid, dl / "saved.apk.1")

        src2 = staging / "readable.bin"
        open(src2, "w").close()
        os.chmod(src2, 0o644)
        os.rename(str(src2), str(dl / "readable.bin"))
        expect_attrs("A2 0644 搬进共享目录（只加位不减位）", 0o664, share_gid,
                     dl_backing / "readable.bin")

        src_dir = staging / "dir700"
        os.mkdir(src_dir)
        os.chmod(src_dir, 0o700)
        os.rename(str(src_dir), str(dl / "dir700"))
        expect_attrs("A3 0700 目录搬进带 setgid 的共享目录", 0o2770, share_gid,
                     dl_backing / "dir700")

        src_dir2 = staging / "dir700b"
        os.mkdir(src_dir2)
        os.chmod(src_dir2, 0o700)
        os.rename(str(src_dir2), str(nosg / "dir700b"))
        expect_attrs("A4 0700 目录搬进不带 setgid 的目录", 0o770, share_gid,
                     nosg_backing / "dir700b")

        print("\n── B. 属主与父目录一致的搬移：仍按树补齐 ──")
        mine = own / "keep600"
        open(mine, "w").close()
        os.chmod(mine, 0o600)
        os.rename(str(mine), str(own / "keep600.renamed"))
        expect_attrs("B5 同属主改名后补到 0660", 0o660, os.getgid(),
                     own_backing / "keep600.renamed")

        print("\n── C. 私有树落点不动 ──")
        pv = staging / "private.bin"
        open(pv, "w").close()
        os.chmod(pv, 0o600)
        try:
            os.rename(str(pv), str(priv / "private.bin"))
        except OSError as e:
            skip("C6 搬进应用私有树", f"ACL 层不允许本用户写该包目录（{e}）")
        else:
            expect_attrs("C6 搬进应用私有树", 0o600, os.getgid(),
                         STORAGE / "0" / "Android" / "data" / "com.example.app" / "private.bin")

        print("\n── D. 符号链接：只搬链接本身 ──")
        target = staging / "target.bin"
        open(target, "w").close()
        os.chmod(target, 0o600)
        link = staging / "link-to-target"
        os.symlink(str(target), str(link))
        os.rename(str(link), str(dl / "link-to-target"))
        moved_link = dl_backing / "link-to-target"
        if not os.path.islink(moved_link):
            fail("D7 搬移后仍是符号链接", "落位条目不是符号链接")
        else:
            ok("D7 搬移后仍是符号链接")
            expect_attrs("D7′ 链接自身属性不动", 0o777, os.getgid(), moved_link)
            expect_attrs("D7″ 目标文件属性不动（chmod 未穿透）", 0o600, os.getgid(),
                         STORAGE / "0" / "Staging" / "target.bin")
    finally:
        stop(p)

    print(f"\n结果：{PASS} 通过 / {FAIL} 失败 / {SKIP} 跳过")
    if FAIL:
        return 1
    return 78 if SKIP else 0


if __name__ == "__main__":
    sys.exit(main())
