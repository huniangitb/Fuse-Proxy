#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打开中的顶层文件删除（open-unlink）必须成功——真 daemon + 真挂载

判别点（为什么这条套件存在）：
  libfuse 的 high-level 层在「删除仍打开的文件」时不会直接发 UNLINK，而是先把
  文件改名成 .fuse_hidden<16hex>，等最后一个句柄 RELEASE 后再删。本地 backing
  支持 POSIX 的「先删名、后关句柄」，所以 vfs_rename 识别该隐藏名后直接 unlink
  源文件（不产生隐藏名，与 Android 自带 FUSE 的可见行为一致）。

  历史缺陷：那次隐藏名 rename 在**识别之前**就按 RENAME_SRC 走 fw_route 的
  ACL，而「存储根一级条目不可改名」的结构规则会把它当成用户改名拒绝 EPERM——
  于是「删除 /sdcard 下仍打开的文件」会返回 EPERM（并发下 RELEASE 尚在处理时
  尤其明显；验收门 G4/G9 里表现为 test_acl_nonintrusive 偶发
  「普通写读删：删除成功: 实际='E1'」）。

  本套件把这些语义钉在真实挂载视图上：
    - 顶层（以及子目录）里「打开中删除」必须成功、名字消失、已打开句柄仍可读、
      且不留下 .fuse_hidden 残留；
    - 普通 rename 仍成功；顶层目录改名仍 EPERM（含 rename 到隐藏名的旁路）；
    - RO 路径的删除仍 EROFS；他包 Android/data 的删除仍 ENOENT（DELETE 路由
      不得绕过跨应用隔离）。
  判别性：FUSE_DAEMON=<未修复二进制>（.cache/global-slowcall-20261121/
  fuse_daemon-pre-fix）运行时「顶层打开中删除」必须红（实际 E1）。

隔离：rootless user namespace（unshare -Urm --map-auto）内挂私有 tmpfs /tmp、
起 daemon、做挂载；宿主 /tmp、/var/fuse-proxy 与 mountinfo 零污染。客户端以
uid 10123、argv[0]=com.demo.app 运行（fw_pkg_resolve_exact 读 /proc/<pid>/cmdline）。

前置：build_gnu/fuse_daemon、/dev/fuse、fusermount3、unshare、/etc/subuid；
缺一即整套跳过（77，非「通过」）。
"""
import errno
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BASE = Path("/tmp/nsp_open_unlink")
MNT = BASE / "mnt"
STORAGE = BASE / "storage"
MODDIR = BASE / "modules"
CONF = BASE / "open-unlink.conf"
DLOG = BASE / "daemon.log"
DAEMON = os.environ.get("FUSE_DAEMON") or str(ROOT / "build_gnu" / "fuse_daemon")
INNER_ENV = "NSP_OPEN_UNLINK_INNER"

PASS = 0
FAIL = 0
SKIP = 0

APP_UID = 10123
APP_PKG = "com.demo.app"
OTHER_PKG = "com.other.app"
HIDDEN_NAME = ".fuse_hidden0000000000000001"


def ok(d):
    global PASS
    PASS += 1
    print(f"  ✅ {d}")


def fail(d, detail=""):
    global FAIL
    FAIL += 1
    print(f"  ❌ {d}: {detail}")


def skip(d):
    global SKIP
    SKIP += 1
    print(f"  ⏭ {d}")


def ename(num):
    return errno.errorcode.get(num, str(num))


def as_errno(v):
    if isinstance(v, str) and v.startswith("E") and v[1:].isdigit():
        return int(v[1:])
    return None


# ── 客户端侧（普通调用者身份）────────────────────────────────────────
CLIENT_PRELUDE = """\
import os, json
M = os.environ["MNT"]
R = {}
def st(k, f):
    try:
        v = f()
        R[k] = "OK" if v is None else v
    except OSError as e:
        R[k] = "E%d" % (e.errno or 0)
"""


def client(body, timeout=25):
    code = CLIENT_PRELUDE + textwrap.dedent(body) + "\nprint(json.dumps(R))\n"
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "MNT": str(MNT),
    }
    try:
        p = subprocess.run([APP_PKG, "-c", code], executable=sys.executable, env=env,
                           user=APP_UID, group=APP_UID, extra_groups=[],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        fail("客户端超时", f"功能预期=在 {timeout}s 内完成，实际=挂死")
        return {}
    if p.returncode != 0:
        tail = (p.stderr or "").strip().splitlines()[-3:]
        fail("客户端异常退出", f"rc={p.returncode} {tail}")
        return {}
    lines = (p.stdout or "").strip().splitlines()
    if not lines:
        fail("客户端无输出", f"stderr={(p.stderr or '')[-300:]}")
        return {}
    try:
        return json.loads(lines[-1])
    except ValueError:
        fail("客户端输出不可解析", lines[-1][:300])
        return {}


def expect_ok(label, res, key):
    v = res.get(key)
    if v == "OK":
        ok(label)
        return True
    fail(label, f"功能预期=成功（OK），实际={v!r}")
    return False


def expect_value(label, res, key, want):
    v = res.get(key)
    if v == want:
        ok(label)
    else:
        fail(label, f"功能预期={want!r}，实际={v!r}")


def expect_errno(label, res, key, allowed):
    v = res.get(key)
    got = as_errno(v)
    want = "/".join(sorted(ename(n) for n in allowed))
    if got in allowed:
        ok(f"{label}（{ename(got)}）")
    else:
        fail(label, f"功能预期=errno ∈ {{{want}}}，实际={v!r}")


# ── 环境与夹具 ──────────────────────────────────────────────────────
def preflight():
    if not (os.path.isfile(DAEMON) and os.access(DAEMON, os.X_OK)):
        return f"缺少 daemon 产物：{DAEMON}"
    if not os.path.exists("/dev/fuse"):
        return "缺少 /dev/fuse"
    for tool in ("fusermount3", "unshare"):
        if shutil.which(tool) is None:
            return f"缺少 {tool}"
    if not os.path.exists("/etc/subuid"):
        return "缺少 /etc/subuid（--map-auto 需要 subordinate uid）"
    try:
        help_txt = subprocess.run(["unshare", "--help"], capture_output=True,
                                  text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        help_txt = ""
    if "--map-auto" not in help_txt:
        return "unshare 不支持 --map-auto（util-linux 过旧）"
    return None


def setup_fixture():
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)
    shutil.rmtree(BASE, ignore_errors=True)
    for d in ("0/DCIM", "0/ro", "0/Android/data/" + OTHER_PKG):
        (STORAGE / d).mkdir(parents=True)
    (STORAGE / "0/ro/keep.txt").write_text("readonly")
    (STORAGE / "0/Android/data" / OTHER_PKG / "private.txt").write_text("other")
    MNT.mkdir(parents=True)
    MODDIR.mkdir(parents=True)
    CONF.write_text(
        "[GLOBAL]\n"
        "MONITOR OFF\n"
        "SANDBOX OFF\n"
        "RO /ro\n",
        encoding="utf-8")


def start_daemon():
    log = open(DLOG, "w")
    p = subprocess.Popen(
        [DAEMON, f"--root={STORAGE}", f"--rules={CONF}", f"--modules-dir={MODDIR}",
         "-f", "-o", "allow_other", str(MNT)],
        stdout=log, stderr=subprocess.STDOUT)
    for _ in range(60):
        if p.poll() is not None:
            return None
        time.sleep(0.1)
        try:
            os.listdir(MNT / "0")
            return p
        except OSError:
            pass
    return p


def stop_daemon(p):
    if p:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(5)
    time.sleep(0.1)
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)


def no_hidden_left(label, directory, view_names):
    """隐藏名是普通条目（读得到），所以残留能直接看出来。"""
    stray = [n for n in (view_names or [])
             if isinstance(n, str) and n.startswith(".fuse_hidden")]
    if stray:
        fail(label, f"功能预期=无 .fuse_hidden 残留，实际={stray}")
    else:
        ok(label)
    disk = sorted(p.name for p in Path(directory).iterdir()
                  if p.name.startswith(".fuse_hidden"))
    if disk:
        fail("backing 不产生 .fuse_hidden 文件", f"功能预期=无，实际={disk}")
    else:
        ok("backing 不产生 .fuse_hidden 文件")


# ── 用例 ────────────────────────────────────────────────────────────
def case_open_unlink_toplevel():
    """顶层条目「打开中删除」：AOSP 只限制改名，删除必须成功（历史缺陷点）。"""
    res = client("""\
f = open(M + "/0/open_top.txt", "w+")
f.write("open-unlink")
f.flush()
os.fsync(f.fileno())
st("unlink", lambda: os.unlink(M + "/0/open_top.txt"))
st("after", lambda: os.stat(M + "/0/open_top.txt"))
f.seek(0)
st("read_back", lambda: f.read())
st("list", lambda: sorted(os.listdir(M + "/0")))
""")
    expect_ok("顶层打开中删除：unlink 成功", res, "unlink")
    expect_errno("顶层打开中删除：名字已消失", res, "after", {errno.ENOENT})
    expect_value("顶层打开中删除：已打开句柄仍可读", res, "read_back", "open-unlink")
    no_hidden_left("顶层打开中删除：目录里无隐藏名残留", STORAGE / "0", res.get("list"))
    if (STORAGE / "0/open_top.txt").exists():
        fail("顶层打开中删除：backing 文件已删", "功能预期=不存在，实际=仍在")
    else:
        ok("顶层打开中删除：backing 文件已删")


def case_open_unlink_nested():
    """子目录里的「打开中删除」一直是通的，这里只防回归。"""
    res = client("""\
f = open(M + "/0/DCIM/nested.txt", "w+")
f.write("nested")
f.flush()
st("unlink", lambda: os.unlink(M + "/0/DCIM/nested.txt"))
st("after", lambda: os.stat(M + "/0/DCIM/nested.txt"))
f.seek(0)
st("read_back", lambda: f.read())
""")
    expect_ok("子目录打开中删除：unlink 成功", res, "unlink")
    expect_errno("子目录打开中删除：名字已消失", res, "after", {errno.ENOENT})
    expect_value("子目录打开中删除：已打开句柄仍可读", res, "read_back", "nested")


def case_plain_rename():
    """普通 rename（两端都关着）不受本次改动影响。"""
    res = client("""\
fd = os.open(M + "/0/DCIM/r1.txt", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
os.write(fd, b"ren")
os.close(fd)
st("rename", lambda: os.rename(M + "/0/DCIM/r1.txt", M + "/0/DCIM/r2.txt"))
st("old", lambda: os.stat(M + "/0/DCIM/r1.txt"))
st("new", lambda: open(M + "/0/DCIM/r2.txt").read())
""")
    expect_ok("普通 rename：改名成功", res, "rename")
    expect_errno("普通 rename：源名已消失", res, "old", {errno.ENOENT})
    expect_value("普通 rename：目标内容正确", res, "new", "ren")


def case_toplevel_dir_rename_denied():
    """结构规则不变：顶层目录不可改名（含 rename 到隐藏名的旁路）。"""
    body = """\
st("mkdir", lambda: os.mkdir(M + "/0/Download"))
st("rename", lambda: os.rename(M + "/0/Download", M + "/0/Download2"))
st("rename_hidden", lambda: os.rename(M + "/0/Download", M + "/0/HIDDEN"))
st("still", lambda: os.stat(M + "/0/Download") and None)
""".replace("HIDDEN", HIDDEN_NAME)
    res = client(body)
    expect_ok("顶层目录改名：建目录成功", res, "mkdir")
    expect_errno("顶层目录改名：仍拒绝", res, "rename", {errno.EPERM})
    expect_errno("顶层目录改名到隐藏名：仍拒绝", res, "rename_hidden", {errno.EPERM})
    expect_ok("顶层目录改名：目录仍在", res, "still")


def case_ro_open_unlink():
    """RO 规则的删除仍 EROFS（打开中删除不得绕过只读）。"""
    res = client("""\
f = open(M + "/0/ro/keep.txt")
st("unlink", lambda: os.unlink(M + "/0/ro/keep.txt"))
st("still", lambda: os.stat(M + "/0/ro/keep.txt") and None)
""")
    expect_errno("RO 打开中删除：EROFS", res, "unlink", {errno.EROFS})
    expect_ok("RO 打开中删除：文件仍在", res, "still")


def case_other_pkg_denied():
    """跨应用隔离不变：DELETE 路由不得放行他包 Android/data。"""
    body = """\
st("open", lambda: open(M + "/0/Android/data/OTHER/private.txt"))
st("unlink", lambda: os.unlink(M + "/0/Android/data/OTHER/private.txt"))
""".replace("OTHER", OTHER_PKG)
    res = client(body)
    expect_errno("他包 Android/data：打开仍不可见", res, "open", {errno.ENOENT})
    expect_errno("他包 Android/data：删除仍被隔离", res, "unlink", {errno.ENOENT})


# ── 主流程 ──────────────────────────────────────────────────────────
def run_tests():
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=1777", "tmpfs", "/tmp"], check=True)
    setup_fixture()
    daemon = start_daemon()
    if daemon is None or daemon.poll() is not None:
        print("daemon 启动失败，日志尾部：")
        try:
            print("\n".join(DLOG.read_text(errors="replace").splitlines()[-20:]))
        except OSError:
            pass
        return 1
    try:
        case_open_unlink_toplevel()
        case_open_unlink_nested()
        case_plain_rename()
        case_toplevel_dir_rename_denied()
        case_ro_open_unlink()
        case_other_pkg_denied()
    finally:
        stop_daemon(daemon)
    print(f"\nopen_unlink_toplevel：{PASS} 通过, {FAIL} 失败, {SKIP} 跳过")
    return 0 if FAIL == 0 else 1


def run_in_userns():
    reason = preflight()
    if reason:
        print(f"SKIP: {reason}")
        return 77
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        INNER_ENV: "1",
        "FUSE_DAEMON": DAEMON,
    }
    cmd = ["unshare", "--user", "--map-root-user", "--map-auto",
           "--mount", "--pid", "--fork", "--mount-proc",
           sys.executable, str(Path(__file__).resolve())]
    try:
        p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired as e:
        sys.stdout.write(e.stdout or "")
        print("FAIL: 套件超时（>90s），功能预期=30s 内完成")
        return 1
    sys.stdout.write(p.stdout or "")
    if p.stderr:
        sys.stderr.write(p.stderr)
    err = p.stderr or ""
    if p.returncode != 0 and ("Operation not permitted" in err or
                              "unshare failed: Invalid argument" in err):
        print("SKIP: 当前环境不允许 unshare user namespace")
        return 77
    return p.returncode


def main():
    if os.environ.get(INNER_ENV) != "1":
        return run_in_userns()
    return run_tests()


if __name__ == "__main__":
    sys.exit(main())
