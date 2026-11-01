#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ACL 不干扰：真实 fuse_daemon + 真实挂载下的功能验收（验收门 G9 的执行体）

判别点（为什么这条套件存在）：
  fw_acl.c 是 AOSP 用户态策略层，价值在于补齐 Android 语义；前提是
  **不得改变功能预期**——该拦的（他包 Android/data、骨架目录、顶层增删）
  拦掉，不该拦的（普通读写删、REDIRECT 落点、RO 的读、ALLOW 直通、
  沙盒镜像、AOSP 默认顶层目录）必须照常工作。

  所以这里不 import fw_acl、不断言内部判定，全部断言都写在「挂载视图上的
  真实文件操作」上：以普通应用 uid 经真 FUSE 发起 create/write/read/
  unlink/mkdir/rename/stat/readdir，只看功能结果与 errno。任何一条失败
  都打印「功能预期 vs 实际 errno」，便于现场判断是 ACL 误拦还是规则配错。

  判别性：把 fw_acl_check 改成恒回 -EACCES（只改副本，不动工作树）后
  本套件大量失败；恢复后全过。

隔离：rootless user namespace（unshare -Urm --map-auto）内挂私有 tmpfs /tmp、
起 daemon、做挂载，宿主 /tmp、/var/fuse-proxy 与 mountinfo 零污染。
uid 10123/10223 经 --map-auto 映射；调用方 argv[0] 即包名（fw_pkg_resolve_exact
读 /proc/<pid>/cmdline），无需 uid.map / packages.list 夹具，整套 hermetic。

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
BASE = Path("/tmp/nsp_acl_nonintrusive")
MNT = BASE / "mnt"
STORAGE = BASE / "storage"
MODDIR = BASE / "modules"
CONF = BASE / "acl.conf"
DLOG = BASE / "daemon.log"
DAEMON = os.environ.get("FUSE_DAEMON") or str(ROOT / "build_gnu" / "fuse_daemon")
INNER_ENV = "NSP_ACL_NONINTRUSIVE_INNER"

PASS = 0
FAIL = 0
SKIP = 0

APP_UID = 10123          # 普通应用
APP_PKG = "com.demo.app"
SANDBOX_UID = 10223      # 沙盒应用
SANDBOX_PKG = "com.sandbox.app"
OTHER_PKG = "com.other.app"


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
    """客户端把 OSError 折成 "E<num>"；返回 int 或 None。"""
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


def client(uid, pkg, body, timeout=25):
    code = CLIENT_PRELUDE + textwrap.dedent(body) + "\nprint(json.dumps(R))\n"
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "MNT": str(MNT),
    }
    try:
        p = subprocess.run([pkg, "-c", code], executable=sys.executable, env=env,
                           user=uid, group=uid, extra_groups=[],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        fail(f"客户端 {pkg}(uid={uid}) 超时", f"功能预期=在 {timeout}s 内完成，实际=挂死")
        return {}
    if p.returncode != 0:
        tail = (p.stderr or "").strip().splitlines()[-3:]
        fail(f"客户端 {pkg}(uid={uid}) 异常退出", f"rc={p.returncode} {tail}")
        return {}
    line = (p.stdout or "").strip().splitlines()
    if not line:
        fail(f"客户端 {pkg}(uid={uid}) 无输出", f"stderr={(p.stderr or '')[-300:]}")
        return {}
    try:
        return json.loads(line[-1])
    except ValueError:
        fail(f"客户端 {pkg}(uid={uid}) 输出不可解析", line[-1][:300])
        return {}


def expect_ok(label, res, key):
    v = res.get(key)
    if v == "OK" or (v is not None and v != "OK" and not isinstance(v, str)):
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


# ── 环境与夹具 ────────────────────────────────────────────────────────
def preflight():
    if not (os.path.isfile(DAEMON) and os.access(DAEMON, os.X_OK)):
        return f"缺少 daemon 产物：{DAEMON}"
    if not os.path.exists("/dev/fuse"):
        return "缺少 /dev/fuse"
    if shutil.which("fusermount3") is None:
        return "缺少 fusermount3"
    if shutil.which("unshare") is None:
        return "缺少 unshare"
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
    for d in ("0/DCIM", "0/Pictures", "0/ro", "0/secret", "0/allowed", "0/movies",
              "0/Android/data/" + OTHER_PKG, "0/Android/data/" + SANDBOX_PKG):
        (STORAGE / d).mkdir(parents=True)
    (STORAGE / "0/ro/readonly.txt").write_text("readonly")
    (STORAGE / "0/secret/inside.txt").write_text("hidden")
    (STORAGE / "0/Android/data" / OTHER_PKG / "private.txt").write_text("other")
    MNT.mkdir(parents=True)
    MODDIR.mkdir(parents=True)
    CONF.write_text(
        "[GLOBAL]\n"
        "MONITOR OFF\n"
        "SANDBOX OFF\n"
        "REDIRECT /dcim /movies\n"
        "HIDE /secret\n"
        "RO /ro\n"
        "ALLOW /allowed\n"
        "\n"
        f"[{SANDBOX_PKG}]\n"
        "SANDBOX ON\n"
        "ALLOW /Music/\n",
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
            os.listdir(MNT / "0")     # 挂载前 MNT 是空目录，/0 必然 ENOENT
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


# ── 逐条功能预期 ──────────────────────────────────────────────────────
def case_plain_io():
    res = client(APP_UID, APP_PKG, """\
st("create", lambda: open(M + "/0/plain.txt", "w").write("hello-acl"))
st("read", lambda: open(M + "/0/plain.txt").read())
st("unlink", lambda: os.unlink(M + "/0/plain.txt"))
st("after", lambda: os.stat(M + "/0/plain.txt"))
""")
    expect_ok("普通写读删：创建+写入成功", res, "create")
    expect_value("普通写读删：读回内容", res, "read", "hello-acl")
    expect_ok("普通写读删：删除成功", res, "unlink")
    expect_errno("普通写读删：删除后不可见", res, "after", {errno.ENOENT})


def case_redirect():
    res = client(APP_UID, APP_PKG, """\
st("write", lambda: open(M + "/0/dcim/a.txt", "w").write("redirected"))
st("read", lambda: open(M + "/0/dcim/a.txt").read())
""")
    expect_ok("REDIRECT：虚拟前缀下写入成功", res, "write")
    expect_value("REDIRECT：虚拟路径可读回", res, "read", "redirected")
    real = STORAGE / "0" / "movies" / "a.txt"
    if real.is_file() and real.read_text() == "redirected":
        ok("REDIRECT：内容落在真实目标目录 movies/a.txt")
    else:
        fail("REDIRECT：内容落在真实目标目录 movies/a.txt",
             f"功能预期={real} 存在且内容为 redirected，实际="
             f"{'缺失' if not real.exists() else real.read_text()!r}")
    if not (STORAGE / "0" / "dcim").exists():
        ok("REDIRECT：虚拟前缀未被实体化（storage/0/dcim 不存在）")
    else:
        fail("REDIRECT：虚拟前缀未被实体化", "功能预期=不存在，实际=被创建为真实目录")


def case_hide():
    res = client(APP_UID, APP_PKG, """\
st("stat", lambda: os.stat(M + "/0/secret"))
st("stat_file", lambda: os.stat(M + "/0/secret/inside.txt"))
st("list", lambda: sorted(os.listdir(M + "/0")))
st("list_hidden", lambda: os.listdir(M + "/0/secret"))
""")
    expect_errno("HIDE：被隐藏目录 stat", res, "stat", {errno.ENOENT})
    expect_errno("HIDE：被隐藏目录内文件 stat", res, "stat_file", {errno.ENOENT})
    entries = res.get("list")
    if isinstance(entries, list) and "secret" not in entries:
        ok("HIDE：父目录列举不含被隐藏条目")
    else:
        fail("HIDE：父目录列举不含被隐藏条目",
             f"功能预期=不含 'secret'，实际={entries!r}")
    expect_errno("HIDE：被隐藏目录 readdir", res, "list_hidden", {errno.ENOENT})


def case_ro():
    res = client(APP_UID, APP_PKG, """\
st("read", lambda: open(M + "/0/ro/readonly.txt").read())
st("open_w", lambda: os.close(os.open(M + "/0/ro/readonly.txt", os.O_WRONLY)))
st("unlink", lambda: os.unlink(M + "/0/ro/readonly.txt"))
st("rename", lambda: os.rename(M + "/0/ro/readonly.txt", M + "/0/ro/moved.txt"))
""")
    expect_value("RO：读仍然成功", res, "read", "readonly")
    expect_errno("RO：open(O_WRONLY)", res, "open_w", {errno.EROFS})
    expect_errno("RO：unlink", res, "unlink", {errno.EROFS})
    expect_errno("RO：rename（源在只读路径）", res, "rename", {errno.EROFS})
    if (STORAGE / "0" / "ro" / "readonly.txt").is_file():
        ok("RO：真实文件未被删除/改名")
    else:
        fail("RO：真实文件未被删除/改名", "功能预期=readonly.txt 仍在，实际=已被破坏")


def case_allow():
    res = client(APP_UID, APP_PKG, """\
st("write", lambda: open(M + "/0/allowed/a.txt", "w").write("allowed"))
st("read", lambda: open(M + "/0/allowed/a.txt").read())
""")
    expect_ok("ALLOW：被放行路径写入成功", res, "write")
    expect_value("ALLOW：被放行路径读回", res, "read", "allowed")
    real = STORAGE / "0" / "allowed" / "a.txt"
    if real.is_file() and real.read_text() == "allowed":
        ok("ALLOW：内容落在自身存储 allowed/a.txt（未被隔离/重定向）")
    else:
        fail("ALLOW：内容落在自身存储", f"功能预期={real} 存在且内容为 allowed，"
                                         f"实际={'缺失' if not real.exists() else real.read_text()!r}")


def case_aosp_semantics():
    res = client(APP_UID, APP_PKG, """\
st("list_root", lambda: sorted(os.listdir(M + "/0")))
st("mkdir_top", lambda: os.mkdir(M + "/0/NewTop"))
st("mkdir_dcim", lambda: os.mkdir(M + "/0/DCIM/sub"))
st("rmdir_top", lambda: os.rmdir(M + "/0/DCIM"))
""")
    entries = res.get("list_root")
    if isinstance(entries, list) and "DCIM" in entries and "Android" in entries:
        ok("AOSP：用户根 /0 可列举（含 DCIM/Android）")
    else:
        fail("AOSP：用户根 /0 可列举", f"功能预期=列出 DCIM/Android，实际={entries!r}")
    expect_errno("AOSP：顶层新建非默认目录被拒", res, "mkdir_top",
                 {errno.EPERM, errno.EACCES})
    expect_ok("AOSP：默认目录 DCIM 内可建子目录", res, "mkdir_dcim")
    expect_errno("AOSP：删顶层目录被拒", res, "rmdir_top",
                 {errno.EPERM, errno.EACCES})
    if (STORAGE / "0" / "DCIM" / "sub").is_dir():
        ok("AOSP：DCIM/sub 真实落盘")
    else:
        fail("AOSP：DCIM/sub 真实落盘", "功能预期=目录存在，实际=缺失")


def case_sandbox():
    res = client(SANDBOX_UID, SANDBOX_PKG, """\
st("other_stat", lambda: os.stat(M + "/0/Android/data/" + "com.other.app" + "/private.txt"))
st("other_list", lambda: os.listdir(M + "/0/Android/data/" + "com.other.app"))
st("own_mkdir", lambda: os.makedirs(M + "/0/Android/data/com.sandbox.app/x", exist_ok=True))
st("own_write", lambda: open(M + "/0/Android/data/com.sandbox.app/x/f.txt", "w").write("own"))
st("own_read", lambda: open(M + "/0/Android/data/com.sandbox.app/x/f.txt").read())
st("shared_mkdir", lambda: os.makedirs(M + "/0/Download", exist_ok=True))
st("shared_write", lambda: open(M + "/0/Download/d.txt", "w").write("shared"))
st("music_mkdir", lambda: os.makedirs(M + "/0/Music", exist_ok=True))
st("music_write", lambda: open(M + "/0/Music/m.txt", "w").write("music"))
""")
    for key, label in (("other_stat", "沙盒：访问他包 data 文件 stat"),
                       ("other_list", "沙盒：访问他包 data 目录 readdir")):
        v = res.get(key)
        got = as_errno(v)
        if got in (errno.ENOENT, errno.EACCES, errno.EPERM):
            ok(f"{label}（{ename(got)}）")
        else:
            fail(label, f"功能预期=ENOENT 或权限错误，实际={v!r}"
                        "（第三种行为：既不是隔离也不可见）")
    expect_ok("沙盒：自己包 Android/data/<自身>/x 可创建", res, "own_mkdir")
    expect_ok("沙盒：自己包名下可写", res, "own_write")
    expect_value("沙盒：自己包名下可读回", res, "own_read", "own")
    own_real = STORAGE / "0" / "Android/data" / SANDBOX_PKG / "x" / "f.txt"
    if own_real.is_file() and own_real.read_text() == "own":
        ok("沙盒：自身 data 写入落在真实自身目录")
    else:
        fail("沙盒：自身 data 写入落在真实自身目录",
             f"功能预期={own_real} 存在，实际={'缺失' if not own_real.exists() else '内容不符'}")
    expect_ok("沙盒：共享目录 /Download 可创建（进沙盒镜像）", res, "shared_mkdir")
    expect_ok("沙盒：共享目录内可写", res, "shared_write")
    sandbox_real = (STORAGE / "0" / "Android/data" / SANDBOX_PKG / "sandbox"
                    / "Download" / "d.txt")
    if sandbox_real.is_file() and sandbox_real.read_text() == "shared":
        ok("沙盒：共享目录写入落在 <pkg>/sandbox/Download（沙盒镜像生效）")
    else:
        fail("沙盒：共享目录写入落在沙盒镜像",
             f"功能预期={sandbox_real} 存在且内容为 shared，实际=缺失或被写到别处")
    expect_ok("ALLOW：应用段放行目录可创建（不被沙盒重定向）", res, "music_mkdir")
    expect_ok("ALLOW：应用段放行目录可写", res, "music_write")
    music_real = STORAGE / "0" / "Music" / "m.txt"
    if music_real.is_file() and music_real.read_text() == "music":
        ok("ALLOW：放行目录写入落在自身存储（ALLOW 豁免沙盒）")
    else:
        fail("ALLOW：放行目录写入落在自身存储",
             f"功能预期={music_real} 存在且内容为 music，实际=缺失或被沙盒吞掉")


def case_privileged():
    # daemon 没有 packages.list 夹具入口（fw_pkg_set_packagelist_path 仅进程内钩子，
    # fw_acl_set_test_uid 只服务 tests/fixtures/fw_acl_driver.c），无法在真实 daemon
    # 上伪造 platform seinfo 的 uid。判定层面的 covered 在 test_acl.py / test_rules.py
    # §28（直编 + 夹具），这里显式跳过并注明，避免假装覆盖。
    skip("特权应用豁免：daemon 无 packages.list 夹具入口，跳过（判定层见 test_acl.py / test_rules.py §28）")


# ── 主流程 ────────────────────────────────────────────────────────────
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
        case_plain_io()
        case_redirect()
        case_hide()
        case_ro()
        case_allow()
        case_aosp_semantics()
        case_sandbox()
        case_privileged()
    finally:
        stop_daemon(daemon)
    print(f"\nacl_nonintrusive：{PASS} 通过, {FAIL} 失败, {SKIP} 跳过")
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
