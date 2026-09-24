#!/usr/bin/env python3
"""V3 声明式决策回归：模块只声明，框架单点强制（appear_missing / read_only /
属性覆盖），逐回调验证 errno 与属性结果。

被测量（tests/override_rules.c，第三方模块视角仅依赖 nsp_module.h）：
  /0/ovr/gone/**  → appear_missing：**所有**回调统一 ENOENT（V2 时代写类是 EACCES）
  /0/ovr/ro/**    → read_only：变更操作统一 EROFS；读路径与 access(F_OK) 放行
  /0/ovr/attrs/** → attr_override：mode 0700 + uid/gid 被采用，而文件类型位
                    仍取自真实属性（模块故意声明 S_IFDIR，必须仍是普通文件）

前置：build_gnu/ 产物、/dev/fuse、fusermount3、gcc。
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
MODULE = "override_rules"
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


def build_module():
    if not Path(DAEMON).exists():
        print(f"!! 缺少 {DAEMON}，请先 ninja -C build_gnu")
        sys.exit(2)
    out = ROOT / "build_gnu" / f"{MODULE}.so"
    r = subprocess.run(["gcc", "-shared", "-fPIC", "-O1", "-DNSP_MODULE_BUILD",
                        f"-I{ROOT}/include", "-o", str(out), str(HERE / f"{MODULE}.c")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"!! 测试模块编译失败:\n{r.stderr}")
        sys.exit(2)


def setup():
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)
    shutil.rmtree("/tmp/fuse_overrides_test", ignore_errors=True)
    # 真实底层：gone 目录**真实存在**（否则 appear_missing 断言会平凡通过）
    (STORAGE / "0" / "ovr" / "gone").mkdir(parents=True)
    (STORAGE / "0" / "ovr" / "ro").mkdir(parents=True)
    (STORAGE / "0" / "ovr" / "attrs").mkdir(parents=True)
    (STORAGE / "0" / "normal").mkdir(parents=True)
    (STORAGE / "0" / "ovr" / "gone" / "f.txt").write_text("hidden")
    (STORAGE / "0" / "ovr" / "ro" / "f.txt").write_text("readonly")
    (STORAGE / "0" / "ovr" / "attrs" / "f.txt").write_text("attrs")
    (STORAGE / "0" / "normal" / "n.txt").write_text("normal")
    os.chmod(STORAGE / "0" / "ovr" / "attrs" / "f.txt", 0o644)
    MNT.mkdir(parents=True)
    d = MODDIR / MODULE
    d.mkdir(parents=True)
    shutil.copy(ROOT / "build_gnu" / f"{MODULE}.so", d / f"{MODULE}.so")
    CONF.parent.mkdir(parents=True, exist_ok=True)
    CONF.write_text("[GLOBAL]\nMONITOR OFF\nSANDBOX OFF\n")
    time.sleep(0.6)  # 模块加载稳定性窗口


def start():
    env = dict(os.environ, NSP_OVR_STORAGE=str(STORAGE))
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
    build_module()  # 先产出 build_gnu/*.so，setup 再放置到模块目录
    setup()
    p = start()
    if not p:
        fail("daemon 启动失败")
        return 1
    try:
        gone = MNT / "0" / "ovr" / "gone"
        ro = MNT / "0" / "ovr" / "ro"
        attrs = MNT / "0" / "ovr" / "attrs"
        normal = MNT / "0" / "normal"

        # 前置：底层真实存在（证明后面的 ENOENT 来自模块声明而非文件缺失）
        if (STORAGE / "0" / "ovr" / "gone" / "f.txt").exists():
            ok("前置：/ovr/gone/f.txt 在底层真实存在")
        else:
            fail("前置", "底层文件缺失，appear_missing 断言将平凡通过")
        # 模块生效判据：attrs 的属主被改成 4242
        for _ in range(20):
            try:
                if os.stat(attrs / "f.txt").st_uid == OVR_UID:
                    break
            except OSError:
                pass
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

        print("\n── C. 属性覆盖：权限位/属主可改，类型位取自真实属性 ──")
        st = os.stat(attrs / "f.txt")
        if st.st_mode & 0o7777 == 0o700:
            ok("mode 覆盖为 0700（真实底层为 0644）")
        else:
            fail("mode 覆盖", f"实际 {oct(st.st_mode & 0o7777)}")
        if os.path.isfile(attrs / "f.txt") and not os.path.isdir(attrs / "f.txt"):
            ok("类型位仍为普通文件（模块声明了 S_IFDIR 也不生效）")
        else:
            fail("类型位", f"st_mode={oct(st.st_mode)}")
        if st.st_uid == OVR_UID and st.st_gid == OVR_GID:
            ok(f"uid/gid 覆盖为 {OVR_UID}/{OVR_GID}")
        else:
            fail("uid/gid 覆盖", f"实际 {st.st_uid}/{st.st_gid}")
        expect_ok("覆盖后仍可读", lambda: os.close(os.open(attrs / "f.txt", os.O_RDONLY)))

        print("\n── D. 未声明覆盖的路径：框架默认策略不变 ──")
        nst = os.stat(normal / "n.txt")
        if nst.st_uid == os.getuid() and nst.st_gid == os.getgid():
            ok("直通路径属主仍为访问者（框架默认伪造策略未被破坏）")
        else:
            fail("直通属主", f"实际 {nst.st_uid}/{nst.st_gid}，期望 {os.getuid()}/{os.getgid()}")
        if nst.st_mode & 0o7777 == 0o644:
            ok("直通路径权限仍为 0644")
        else:
            fail("直通权限", f"实际 {oct(nst.st_mode & 0o7777)}")
        expect_ok("直通路径可写（未误判 read_only）",
                  lambda: os.close(os.open(normal / "n.txt", os.O_WRONLY)))

        print("\n── E. 读路径不受 read_only 影响（readdir 子项可见）──")
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
    print(f"V3 声明式决策回归 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS + FAIL}")
    if ERRS:
        for d, detail in ERRS:
            print(f"   ✗ {d}: {detail}")
    print("注：read_only 的 root 豁免需以 uid 0 访问，本测试以普通用户运行，"
          "该分支未覆盖（与 test_global_replace.py 同样受权限限制）。")
    return 1 if FAIL else 0


def _raise(err):
    """把 access() 的 errno 结果转成异常，便于复用 expect_ok/expect_errno"""
    if err != 0:
        raise OSError(err, os.strerror(err))
    return None


if __name__ == "__main__":
    sys.exit(main())
