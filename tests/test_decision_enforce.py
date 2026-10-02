#!/usr/bin/env python3
"""决策强制单点回归：规则只声明"路径该怎么表现"，errno 映射由框架统一施加
（`fw_route` 的 appear_missing → ENOENT、read_only → EROFS），逐回调验证 errno。

规则来源是**配置**（V4 起规则引擎内建，见 `src/daemon/fw_rules.c`）：
  HIDE /ovr/gone → appear_missing：**所有**回调统一 ENOENT（V2 时代写类是 EACCES）
  RO   /ovr/ro   → read_only：变更操作统一 EROFS；读路径与 access(F_OK) 放行

原属本套件的 attr_override（模块声明 mode/uid/gid 覆盖 + 类型位保持）已随 V4 删除：
规则语法从未支持它、引擎恒不置位，属无生产者的能力（见 docs/modules.md §3）。

前置：build_gnu/ 产物、/dev/fuse、fusermount3。
"""
import ctypes
import errno
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MNT = Path("/tmp/fuse_overrides_test/mnt")
STORAGE = Path("/tmp/fuse_overrides_test/storage")
MODDIR = Path("/tmp/fuse_overrides_test/modules")
CONF = Path("/tmp/Namespace-Proxy/injector.conf")
DLOG = Path("/tmp/fo.log")
DAEMON = os.environ.get("FUSE_DAEMON") or str(ROOT / "build_gnu" / "fuse_daemon")
OVR_UID, OVR_GID = 4242, 4343

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


def expect_errno(desc, want, fn):
    """调用 fn()，断言抛出的 OSError.errno == want"""
    try:
        fn()
    except OSError as e:
        if e.errno == want:
            ok(desc)
        else:
            fail(desc, f"期望 errno={want}({errno.errorcode.get(want)}) 实际 {e.errno}"
                       f"({errno.errorcode.get(e.errno)})")
    except Exception as e:  # noqa: BLE001
        fail(desc, f"非 OSError: {e!r}")
    else:
        fail(desc, f"期望 errno={want}({errno.errorcode.get(want)})，实际调用成功")


def expect_ok(desc, fn):
    try:
        fn()
        ok(desc)
    except OSError as e:
        fail(desc, f"期望成功，实际 errno={e.errno}({errno.errorcode.get(e.errno)})")


def access_errno(path, mode):
    """os.access 只返回 bool，无法区分 ENOENT/EROFS/EACCES——直接调 libc"""
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    rc = libc.access(str(path).encode(), mode)
    return 0 if rc == 0 else ctypes.get_errno()


def setup():
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)
    shutil.rmtree("/tmp/fuse_overrides_test", ignore_errors=True)
    # 真实底层：gone 目录**真实存在**（否则 appear_missing 断言会平凡通过）
    (STORAGE / "0" / "ovr" / "gone").mkdir(parents=True)
    (STORAGE / "0" / "ovr" / "ro").mkdir(parents=True)
    (STORAGE / "0" / "normal").mkdir(parents=True)
    (STORAGE / "0" / "ovr" / "gone" / "f.txt").write_text("hidden")
    (STORAGE / "0" / "ovr" / "ro" / "f.txt").write_text("readonly")
    (STORAGE / "0" / "normal" / "n.txt").write_text("normal")
    MNT.mkdir(parents=True)
    MODDIR.mkdir(parents=True, exist_ok=True)
    CONF.parent.mkdir(parents=True, exist_ok=True)
    # 规则由框架内建引擎解释：HIDE → appear_missing、RO → read_only
    CONF.write_text("[GLOBAL]\nMONITOR OFF\nSANDBOX OFF\n"
                    "HIDE /ovr/gone\nRO /ovr/ro\n")


def start():
    env = dict(os.environ)
    p = subprocess.Popen([DAEMON, f"--root={STORAGE}", f"--rules={CONF}",
                          f"--modules-dir={MODDIR}", "-f", str(MNT)],
                         stdout=open(DLOG, "w"), stderr=subprocess.STDOUT, env=env)
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
    global FAIL
    setup()
    p = start()
    if not p:
        fail("daemon 启动失败")
        return 1
    try:
        gone = MNT / "0" / "ovr" / "gone"
        ro = MNT / "0" / "ovr" / "ro"
        normal = MNT / "0" / "normal"

        # 前置：底层真实存在（证明后面的 ENOENT 来自规则声明而非文件缺失）
        if (STORAGE / "0" / "ovr" / "gone" / "f.txt").exists():
            ok("前置：/ovr/gone/f.txt 在底层真实存在")
        else:
            fail("前置", "底层文件缺失，appear_missing 断言将平凡通过")
        # 规则生效判据：HIDE 命中后 /ovr/gone 立即不可见（等价旧"模块已加载"前置）
        for _ in range(20):
            try:
                os.stat(gone / "f.txt")
            except OSError:
                break
            time.sleep(0.3)

        print("\n── A. appear_missing：所有回调统一 ENOENT（含写类）──")
        expect_errno("stat → ENOENT", errno.ENOENT, lambda: os.stat(gone / "f.txt"))
        expect_errno("listdir → ENOENT", errno.ENOENT, lambda: os.listdir(gone))
        expect_errno("open(O_RDONLY) → ENOENT", errno.ENOENT,
                     lambda: os.open(gone / "f.txt", os.O_RDONLY))
        # 以下 6 项是 V3 的行为变更点：V2 时写类回调映射为 EACCES
        expect_errno("mkdir → ENOENT（旧行为 EACCES）", errno.ENOENT,
                     lambda: os.mkdir(gone / "newdir"))
        expect_errno("create(O_CREAT) → ENOENT（旧行为 EACCES）", errno.ENOENT,
                     lambda: os.open(gone / "new.txt", os.O_CREAT | os.O_WRONLY, 0o644))
        expect_errno("unlink → ENOENT（旧行为 EACCES）", errno.ENOENT,
                     lambda: os.unlink(gone / "f.txt"))
        expect_errno("rmdir → ENOENT（旧行为 EACCES）", errno.ENOENT, lambda: os.rmdir(gone))
        expect_errno("chmod → ENOENT（旧行为 EACCES）", errno.ENOENT,
                     lambda: os.chmod(gone / "f.txt", 0o600))
        expect_errno("truncate → ENOENT（旧行为 EACCES）", errno.ENOENT,
                     lambda: os.truncate(gone / "f.txt", 0))
        expect_errno("rename 源 → ENOENT（旧行为 EACCES）", errno.ENOENT,
                     lambda: os.rename(gone / "f.txt", normal / "moved.txt"))
        expect_errno("access(F_OK) → ENOENT", errno.ENOENT,
                     lambda: _raise(access_errno(gone / "f.txt", os.F_OK)))

        print("\n── B. read_only：变更 EROFS，读路径放行 ──")
        expect_ok("stat 放行", lambda: os.stat(ro / "f.txt"))
        expect_ok("listdir 放行", lambda: os.listdir(ro))
        expect_ok("open(O_RDONLY) 放行", lambda: os.close(os.open(ro / "f.txt", os.O_RDONLY)))
        expect_ok("access(F_OK) 放行", lambda: _raise(access_errno(ro / "f.txt", os.F_OK)))
        expect_ok("access(R_OK) 放行", lambda: _raise(access_errno(ro / "f.txt", os.R_OK)))
        expect_errno("access(W_OK) → EROFS", errno.EROFS,
                     lambda: _raise(access_errno(ro / "f.txt", os.W_OK)))
        expect_errno("open(O_WRONLY) → EROFS", errno.EROFS,
                     lambda: os.open(ro / "f.txt", os.O_WRONLY))
        expect_errno("open(O_RDWR) → EROFS", errno.EROFS,
                     lambda: os.open(ro / "f.txt", os.O_RDWR))
        expect_errno("open(O_RDONLY|O_TRUNC) → EROFS", errno.EROFS,
                     lambda: os.open(ro / "f.txt", os.O_RDONLY | os.O_TRUNC))
        expect_errno("open(O_APPEND) → EROFS", errno.EROFS,
                     lambda: os.open(ro / "f.txt", os.O_WRONLY | os.O_APPEND))
        expect_errno("mkdir → EROFS", errno.EROFS, lambda: os.mkdir(ro / "d"))
        expect_errno("unlink → EROFS", errno.EROFS, lambda: os.unlink(ro / "f.txt"))
        expect_errno("rmdir → EROFS", errno.EROFS, lambda: os.rmdir(ro))
        expect_errno("chmod → EROFS", errno.EROFS, lambda: os.chmod(ro / "f.txt", 0o600))
        expect_errno("chown → EROFS", errno.EROFS,
                     lambda: os.chown(ro / "f.txt", OVR_UID, OVR_GID))
        expect_errno("truncate → EROFS", errno.EROFS, lambda: os.truncate(ro / "f.txt", 0))
        expect_errno("utime → EROFS", errno.EROFS, lambda: os.utime(ro / "f.txt"))
        expect_errno("setxattr → EROFS", errno.EROFS,
                     lambda: os.setxattr(ro / "f.txt", "user.t", b"v"))
        expect_errno("removexattr → EROFS", errno.EROFS,
                     lambda: os.removexattr(ro / "f.txt", "user.t"))
        expect_errno("symlink → EROFS", errno.EROFS,
                     lambda: os.symlink("x", ro / "link"))
        expect_errno("rename → EROFS", errno.EROFS,
                     lambda: os.rename(ro / "f.txt", normal / "moved.txt"))

        print("\n── C. 未被规则命中的路径：框架默认策略不变（真实属主/权限）──")
        nst = os.stat(normal / "n.txt")
        real = os.lstat(STORAGE / "0" / "normal" / "n.txt")
        if nst.st_uid == real.st_uid and nst.st_gid == real.st_gid:
            ok("直通路径属主取自底层真实属性（伪造属主=访问者的模式已删除）")
        else:
            fail("直通属主", f"实际 {nst.st_uid}/{nst.st_gid}，底层 {real.st_uid}/{real.st_gid}")
        if nst.st_mode & 0o7777 == 0o644:
            ok("直通路径权限仍为 0644")
        else:
            fail("直通权限", f"实际 {oct(nst.st_mode & 0o7777)}")
        expect_ok("直通路径可写（未误判 read_only）",
                  lambda: os.close(os.open(normal / "n.txt", os.O_WRONLY)))

        print("\n── D. 读路径不受 read_only 影响（readdir 子项可见）──")
        if "f.txt" in os.listdir(ro):
            ok("read_only 目录仍可列目录")
        else:
            fail("read_only 目录列表", f"{os.listdir(ro)}")

        if p.poll() is None:
            ok("daemon 存活")
        else:
            fail("daemon 崩溃", f"rc={p.poll()}")
    finally:
        stop(p)
        if FAIL and DLOG.exists():
            print("\n--- daemon 日志尾部 ---")
            print("\n".join(DLOG.read_text(errors="replace").splitlines()[-20:]))

    print("\n═══════════════════════════════════════")
    print(f"决策强制单点回归 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS + FAIL}")
    if ERRS:
        for d, detail in ERRS:
            print(f"   ✗ {d}: {detail}")
    print("注：read_only 的 root 豁免需以 uid 0 访问，本测试以普通用户运行，"
          "该分支未覆盖（与 test_global_replace.py 同样受权限限制）。")
    print("注2：本套件只用 [GLOBAL] 段——包作用域（[包名]/[包名:userid]）的合并语义"
          "端到端测不到（本机 uid<10000 恒走 system 分支），由 "
          "test_monitor_layers.py 用合成 uid 直接验证框架合并函数。")
    return 1 if FAIL else 0


def _raise(err):
    """把 access() 的 errno 结果转成异常，便于复用 expect_ok/expect_errno"""
    if err != 0:
        raise OSError(err, os.strerror(err))
    return None


if __name__ == "__main__":
    sys.exit(main())
