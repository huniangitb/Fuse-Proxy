#!/usr/bin/env python3
"""存储根一级条目守卫（历史缺陷：/data/media 顶层反复出现纯数字垃圾目录）
=====================================================================

线上形态：/storage/emulated（底层 /data/media）顶层反复出现 10 位纯数字目录
（如 1814208618），只能在 /data/media 下删除；顶层也会冒出非数字垃圾文件。

链路（本套件的判别对象）：
  应用请求 /<数字>/… → fw_parse_path 把第一个全数字段当 user_id（历史实现无
  存在性校验）→ real_path=<STORAGE_BASE>/<数字>/… → 创建路径的父目录补建
  （mkdir_recursive_p）以 root 把 <STORAGE_BASE>/<数字> 造出来；此后它被当成
  真实用户目录反复使用。**根级 REDIRECT 规则**（真机典型配置）下规则引擎会把
  /<数字> 合成为“已存在目录”（NSP_VK_ANCESTOR），应用据此下探，CREATE/MKDIR/
  RENAME/SYMLINK 的父目录补建随即落盘——这是“反复出现”的主链路，本套件第 2
  段用该配置复现。

新语义（本套件逐项钉住）：
  1) 不存在的用户根：**读写一律** -ENOENT（读侧也拦，内核不再合成该名字，
     下探不会发生）；
  2) 存储根一级条目：变更（创建/删除/改名/元数据/带写 flags 的 open）→ -EPERM，
     读（列出/stat/只读 open 既有条目）照旧；
  3) 父目录补建唯一出口 common_mkdir_within_storage **永不创建**一级组件；
  4) 数字串溢出 int 的用户层（/4294967296/x）按非法处理（atoi 别名不得落到 /0/x）。

判别性：旧实现在第 1 段 create/symlink/rename、第 2 段 mkdir/create/makedirs、
第 3 段 rmdir、第 4 段 open(O_TRUNC) 上必失败（条目被创建/被删/被截断）。
FUSE_DAEMON=<旧二进制> 可复验。
"""
import errno
import os
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager

BASE = "/tmp/nsp_storage_root_guard"
MNT = BASE + "/mnt"
STORAGE = BASE + "/storage"
CONF = BASE + "/injector.conf"
DAEMON = os.environ.get("FUSE_DAEMON") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "build_gnu", "fuse_daemon"))

PASS = 0
FAIL = 0
ERRORS = []
SKIP = 77
JUNK = "1814208618"

CFG_PLAIN = "[GLOBAL]\nMONITOR OFF\n"
# 真机典型配置：根级 REDIRECT（让 /<任意名> 被合成为“存在目录”）+ 沙盒
CFG_ROOT_REDIRECT = "[GLOBAL]\nMONITOR OFF\nSANDBOX ON\nREDIRECT /网盘/ /Download/\n"


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def ok(desc):
    global PASS
    PASS += 1
    log(f"  \u2705 {desc}")


def bad(desc, detail=""):
    global FAIL
    FAIL += 1
    log(f"  \u274c {desc}: {detail}")
    ERRORS.append((desc, detail))


def skip_all(msg):
    log(f"\u26a0\ufe0f 跳过：{msg}")
    sys.exit(SKIP)


def setup():
    shutil.rmtree(BASE, ignore_errors=True)
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    for d in ["0/Download", "0/dev", "999", "10"]:
        os.makedirs(f"{STORAGE}/{d}", exist_ok=True)
    with open(f"{STORAGE}/0/Download/hello.txt", "w") as fh:
        fh.write("hello")
    with open(f"{STORAGE}/0/dev/move_me.txt", "w") as fh:
        fh.write("move")
    os.makedirs(f"{STORAGE}/legacy_junk_dir")
    with open(f"{STORAGE}/legacy_top_file", "w") as fh:
        fh.write("legacy-original")
    os.makedirs(MNT, exist_ok=True)
    write_conf(CFG_PLAIN)


def write_conf(text):
    with open(CONF, "w") as fh:
        fh.write(text)


@contextmanager
def daemon(root=None):
    proc = subprocess.Popen(
        [DAEMON, "--root=" + (root or STORAGE), "--rules=" + CONF, "-f", MNT, "info"],
        stdout=open(BASE + "/daemon.log", "w"), stderr=subprocess.STDOUT)
    ready = False
    for _ in range(30):
        time.sleep(0.2)
        try:
            if os.listdir(MNT):
                ready = True
                break
        except OSError:
            pass
        if proc.poll() is not None:
            break
    try:
        yield proc if ready else None
    finally:
        proc.terminate()
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            proc.kill()
        subprocess.run(["fusermount3", "-u", MNT], capture_output=True)


def errno_of(fn):
    try:
        r = fn()
        if hasattr(r, "close"):
            r.close()
        return 0
    except OSError as e:
        return e.errno or -1


def expect_errno(desc, fn, want):
    got = errno_of(fn)
    if got == want:
        ok(desc)
    else:
        bad(desc, f"errno={got}（{errno.errorcode.get(got, got)}），期望 {want}"
                  f"（{errno.errorcode.get(want, want)}）")


def expect_ok(desc, fn):
    try:
        r = fn()
        if hasattr(r, "close"):
            r.close()
        ok(desc)
    except OSError as e:
        bad(desc, f"意外失败 errno={e.errno}（{errno.errorcode.get(e.errno, '')}）")


def expect_absent(desc, path):
    if os.path.lexists(path):
        bad(desc, f"{path} 被创建（存储根被写脏）")
    else:
        ok(desc)


def read_text(path):
    with open(path) as fh:
        return fh.read()


def top_level():
    return sorted(os.listdir(STORAGE))


# ─────────────────────────────────────────────────────────────
# 第 1 段：无规则配置 —— 不存在的数字用户根 / 非数字顶层 / 顶层变更 / 溢出
# ─────────────────────────────────────────────────────────────
def phase_plain(base_top):
    log("\n━━━ 1. 不存在的数字用户根（无规则） ━━━")
    expect_errno(f"mkdir /{JUNK} → ENOENT", lambda: os.mkdir(f"{MNT}/{JUNK}"), errno.ENOENT)
    expect_absent(f"底层未生成 {JUNK}/", f"{STORAGE}/{JUNK}")
    expect_errno(f"create /{JUNK}/a.txt → ENOENT",
                 lambda: open(f"{MNT}/{JUNK}/a.txt", "w"), errno.ENOENT)
    expect_absent(f"底层未生成 {JUNK}/（create）", f"{STORAGE}/{JUNK}")
    expect_errno(f"makedirs /{JUNK}/a/b → ENOENT",
                 lambda: os.makedirs(f"{MNT}/{JUNK}/a/b"), errno.ENOENT)
    expect_absent(f"底层未生成 {JUNK}/（多级）", f"{STORAGE}/{JUNK}")
    expect_errno(f"symlink → /{JUNK} → ENOENT",
                 lambda: os.symlink("x", f"{MNT}/{JUNK}"), errno.ENOENT)
    expect_absent(f"底层未生成 {JUNK}（symlink）", f"{STORAGE}/{JUNK}")
    expect_errno(f"create 同名顶层文件 /{JUNK} → ENOENT",
                 lambda: open(f"{MNT}/{JUNK}", "w"), errno.ENOENT)
    expect_absent(f"底层未生成同名文件 {JUNK}", f"{STORAGE}/{JUNK}")
    expect_errno(f"rename 到 /{JUNK}/move.txt → ENOENT",
                 lambda: os.rename(f"{MNT}/0/dev/move_me.txt", f"{MNT}/{JUNK}/move.txt"),
                 errno.ENOENT)
    expect_absent(f"底层未生成 {JUNK}/（rename）", f"{STORAGE}/{JUNK}")
    expect_ok("rename 源文件仍在（失败不产生副作用）",
              lambda: os.stat(f"{MNT}/0/dev/move_me.txt"))

    log("\n━━━ 2. 数字层溢出别名（atoi UB → 不得落到 /0） ━━━")
    expect_errno("mkdir /4294967296 → ENOENT",
                 lambda: os.mkdir(f"{MNT}/4294967296"), errno.ENOENT)
    expect_absent("底层未生成 0/x（别名）", f"{STORAGE}/0/x")
    expect_errno("create /4294967296/x → ENOENT",
                 lambda: open(f"{MNT}/4294967296/x", "w"), errno.ENOENT)
    expect_absent("底层未生成 4294967296", f"{STORAGE}/4294967296")

    log("\n━━━ 3. 存储根非数字新条目（无规则） ━━━")
    expect_errno("mkdir /_junk_dir → EPERM",
                 lambda: os.mkdir(f"{MNT}/_junk_dir"), errno.EPERM)
    expect_absent("底层未生成 _junk_dir", f"{STORAGE}/_junk_dir")
    expect_errno("create /_junk_file → EPERM",
                 lambda: open(f"{MNT}/_junk_file", "w"), errno.EPERM)
    expect_absent("底层未生成 _junk_file", f"{STORAGE}/_junk_file")
    expect_errno("symlink /_junk_link → EPERM",
                 lambda: os.symlink("target", f"{MNT}/_junk_link"), errno.EPERM)
    expect_absent("底层未生成 _junk_link", f"{STORAGE}/_junk_link")

    log("\n━━━ 4. 既有顶层条目：变更被拒 / 读放行 ━━━")
    expect_errno("rmdir /legacy_junk_dir → EPERM",
                 lambda: os.rmdir(f"{MNT}/legacy_junk_dir"), errno.EPERM)
    expect_ok("历史垃圾条目仍在（拒绝删除）", lambda: os.stat(f"{STORAGE}/legacy_junk_dir"))
    expect_errno("rmdir /999（用户根）→ EPERM",
                 lambda: os.rmdir(f"{MNT}/999"), errno.EPERM)
    expect_ok("用户根 999 仍在", lambda: os.stat(f"{STORAGE}/999"))
    expect_errno("rename 顶层条目 → EPERM",
                 lambda: os.rename(f"{MNT}/legacy_junk_dir", f"{MNT}/legacy_junk_dir2"),
                 errno.EPERM)
    expect_ok("顶层条目未被改名", lambda: os.stat(f"{STORAGE}/legacy_junk_dir"))
    # 带写 flags 的 open 属变更语义：对既有顶层文件必须拒绝（否则 1 级条目被截断）
    expect_errno("open(legacy_top_file, 'w') → EPERM（写 flags 的 open）",
                 lambda: open(f"{MNT}/legacy_top_file", "w"), errno.EPERM)
    expect_ok("顶层文件内容未被截断",
              lambda: _check_eq(read_text(f"{STORAGE}/legacy_top_file"), "legacy-original"))
    expect_ok("open(legacy_top_file, 'r') 只读放行",
              lambda: _check_eq(read_text(f"{MNT}/legacy_top_file"), "legacy-original"))
    expect_errno("chmod 顶层条目 → EPERM",
                 lambda: os.chmod(f"{MNT}/legacy_junk_dir", 0o700), errno.EPERM)

    log("\n━━━ 5. 读语义不变（不隐藏数据） ━━━")
    expect_ok("存储根仍可列举", lambda: os.listdir(MNT))
    if "legacy_junk_dir" in os.listdir(MNT):
        ok("既有顶层条目在列举中可见（不隐藏数据）")
    else:
        bad("既有顶层条目在列举中可见（不隐藏数据）", "ls 结果缺 legacy_junk_dir")
    expect_ok("存储根 getattr 正常", lambda: os.stat(MNT))

    log("\n━━━ 6. 既有用户根正对照（含多用户/多级补建） ━━━")
    expect_ok("mkdir /0/newdir", lambda: os.mkdir(f"{MNT}/0/newdir"))
    expect_ok("底层目录已建", lambda: os.stat(f"{STORAGE}/0/newdir"))
    expect_ok("makedirs /0/deep/a/b（逐级 mkdir 补建）",
              lambda: os.makedirs(f"{MNT}/0/deep/a/b"))
    expect_ok("底层多级目录已建", lambda: os.stat(f"{STORAGE}/0/deep/a/b"))
    expect_ok("create /0/deep/a/b/c.txt（父目录已存在）",
              lambda: open(f"{MNT}/0/deep/a/b/c.txt", "w"))
    expect_ok("rename /0/dev/move_me.txt → /0/Download/moved.txt",
              lambda: os.rename(f"{MNT}/0/dev/move_me.txt", f"{MNT}/0/Download/moved.txt"))
    expect_ok("rmdir /0/newdir", lambda: os.rmdir(f"{MNT}/0/newdir"))
    expect_ok("mkdir /999/newdir（多用户）", lambda: os.mkdir(f"{MNT}/999/newdir"))
    expect_ok("mkdir /10/newdir（多用户）", lambda: os.mkdir(f"{MNT}/10/newdir"))

    expect_ok("存储根顶层零新增（1 段收尾）",
              lambda: _check_eq(top_level(), base_top))


def _check_eq(got, want):
    if got != want:
        raise OSError(errno.EIO, f"got={got!r} want={want!r}")


# ─────────────────────────────────────────────────────────────
# 第 2 段：根级 REDIRECT（真机典型配置）——“反复出现”的主链路
# ─────────────────────────────────────────────────────────────
def phase_root_redirect(base_top):
    log("\n━━━ 7. 根级 REDIRECT + SANDBOX：数字名不得被合成/落盘 ━━━")
    write_conf(CFG_ROOT_REDIRECT)
    with daemon() as proc:
        if proc is None:
            bad("根级 REDIRECT 配置下 daemon 就绪", "见 daemon.log")
            return
        # 读侧 fail-closed：/<数字> 不再是“已存在目录”，mkdir 应得 ENOENT（旧实现 EEXIST）
        expect_errno(f"mkdir /{JUNK} → ENOENT", lambda: os.mkdir(f"{MNT}/{JUNK}"), errno.ENOENT)
        expect_absent(f"底层未生成 {JUNK}/", f"{STORAGE}/{JUNK}")
        expect_errno("create /1814208619/a.txt → ENOENT",
                     lambda: open(f"{MNT}/1814208619/a.txt", "w"), errno.ENOENT)
        expect_absent("底层未生成 1814208619/", f"{STORAGE}/1814208619")
        expect_errno("makedirs /1814208620/a/b → ENOENT",
                     lambda: os.makedirs(f"{MNT}/1814208620/a/b"), errno.ENOENT)
        expect_absent("底层未生成 1814208620/", f"{STORAGE}/1814208620")
        expect_errno("symlink /1814208622 → ENOENT",
                     lambda: os.symlink("x", f"{MNT}/1814208622"), errno.ENOENT)
        expect_absent("底层未生成 1814208622", f"{STORAGE}/1814208622")
        # 正对照：合法用户根下照常
        expect_ok("mkdir /0/rt_newdir（合法用户根）", lambda: os.mkdir(f"{MNT}/0/rt_newdir"))
        expect_ok("存储根顶层零新增（2 段收尾）",
                  lambda: _check_eq(sorted(set(top_level()) - {"1814208619", "1814208620",
                                                               "1814208622"}), base_top))


# ─────────────────────────────────────────────────────────────
# 第 3 段：--root 带尾斜杠（base 归一）
# ─────────────────────────────────────────────────────────────
def phase_trailing_slash_root(base_top):
    log("\n━━━ 8. --root=<dir>/ 尾斜杠：守卫不得失效 ━━━")
    write_conf(CFG_PLAIN)
    with daemon(root=STORAGE + "/") as proc:
        if proc is None:
            bad("尾斜杠 root 下 daemon 就绪", "见 daemon.log")
            return
        expect_errno("rmdir /999 → EPERM（尾斜杠 root）",
                     lambda: os.rmdir(f"{MNT}/999"), errno.EPERM)
        expect_ok("用户根 999 仍在", lambda: os.stat(f"{STORAGE}/999"))
        expect_errno("mkdir /_junk_dir → EPERM（尾斜杠 root）",
                     lambda: os.mkdir(f"{MNT}/_junk_dir"), errno.EPERM)
        expect_absent("底层未生成 _junk_dir（尾斜杠 root）", f"{STORAGE}/_junk_dir")
        expect_errno(f"mkdir /{JUNK} → ENOENT（尾斜杠 root）",
                     lambda: os.mkdir(f"{MNT}/{JUNK}"), errno.ENOENT)
        expect_ok("存储根顶层零新增（3 段收尾）",
                  lambda: _check_eq(top_level(), base_top))


# ─────────────────────────────────────────────────────────────
# 第 4 段：既有数字垃圾目录（历史遗留）——读放行、不隐藏、不新增
# ─────────────────────────────────────────────────────────────
def phase_legacy_junk(base_top):
    log("\n━━━ 9. 既有数字垃圾目录：读放行、变更仍被拒 ━━━")
    os.makedirs(f"{STORAGE}/{JUNK}")
    with open(f"{STORAGE}/{JUNK}/keep.txt", "w") as fh:
        fh.write("keep")
    want = sorted(base_top + [JUNK])
    with daemon() as proc:
        if proc is None:
            bad("就绪（遗留垃圾段）", "见 daemon.log")
            return
        if JUNK in os.listdir(MNT):
            ok("既有数字目录在列举中可见（不隐藏数据）")
        else:
            bad("既有数字目录在列举中可见（不隐藏数据）", "ls 缺条目")
        expect_ok("读既有数字目录内的文件",
                  lambda: _check_eq(read_text(f"{MNT}/{JUNK}/keep.txt"), "keep"))
        expect_errno("rmdir 既有数字目录 → EPERM",
                     lambda: os.rmdir(f"{MNT}/{JUNK}"), errno.EPERM)
        expect_ok("存储根顶层不变（4 段收尾）", lambda: _check_eq(top_level(), want))


def main():
    log("═══ 存储根一级条目守卫 ═══")
    if not os.path.isfile(DAEMON):
        skip_all(f"产物不存在：{DAEMON}")
    if not os.path.exists("/dev/fuse"):
        skip_all("本机无 /dev/fuse")
    setup()
    base_top = top_level()
    log(f"基线顶层：{base_top}")
    with daemon() as proc:
        if proc is None:
            skip_all("daemon 未能就绪（看 " + BASE + "/daemon.log）")
        try:
            phase_plain(base_top)
        finally:
            pass
    phase_root_redirect(base_top)
    phase_trailing_slash_root(base_top)
    phase_legacy_junk(base_top)

    if FAIL == 0:
        shutil.rmtree(BASE, ignore_errors=True)
    else:
        log(f"（失败现场保留：{BASE}）")
    log(f"\n结果：{PASS} 通过 / {FAIL} 失败")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
