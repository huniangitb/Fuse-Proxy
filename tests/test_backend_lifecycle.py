#!/usr/bin/env python3
"""后端模块引用生命周期回归 — backend_refs 配对释放 / 热卸载“真卸载”。

背景（本用例守护的修复）：
  框架 vfs_* 在 rr.is_ftp 命中后端模块（module_backend_lookup /
  module_backend_lookup_slot 返回 0）后，若模块未实现对应 backend_* 回调，
  或 readdir 的 calloc 失败，原实现直接跳过分支/返回而未调
  module_backend_put，槽位在途引用（g_backend_slot_refs）不归零。
  module_unload_one 等待引用归零超时（~2s）后**回滚卸载**（恢复 active/
  handle/链），模块 .so 永久留在进程地址空间，热拔失效。
  同类问题：rename 的 from/to 各 lookup 一次，同一模块时引用计数为 2，
  原实现按指针去重只 put 一次（成功分支与 -EXDEV 分支均泄漏 1）。

断言策略（避免“只看规则是否生效”的伪证据）：
  - 卸载判定用内核证据：轮询 /proc/<pid>/maps，断言模块 .so 映射消失。
    引用泄漏会让卸载回滚、映射保留 → 测试失败。这是本用例的核心判别。
  - 反向排除：断言规则模块仍在 maps、daemon 存活、挂载仍可列目录，
    证明“后端不再被分派”不是“规则整体失效”造成的。
  - 分派证据：后端 backend_match / backend_rename 落 marker 文件，
    断言其后端确被调用（否则可能是规则没置 is_ftp，测试会平凡通过）。

覆盖：
  A. 后端仅实现 backend_match（+ backend_rename），其余回调 NULL：
     getattr/open/create/readdir/unlink/rmdir/truncate 全部本地 fallback
     （产物落真实 storage），同模块 rename 两次 lookup 配对释放。
  B. 后端仅实现 backend_match（rename 也 NULL）：rename 返回 -EXDEV，
     覆盖 EXDEV 分支的两次 lookup 配对释放。

测试模块由本脚本临时写源码 + cc 现场编译（第三方模块视角，仅依赖
include/nsp_module.h）。所有 fixture 位于 mkdtemp 临时目录；每个用例
finally 精确终止自身 daemon pid 并卸载自身挂载点，脚本末尾清理临时目录。

前置：build_gnu/fuse_daemon、/dev/fuse、fusermount3、cc。
运行：python3 tests/test_backend_lifecycle.py
"""
import errno
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DAEMON = os.environ.get("FUSE_DAEMON") or str(ROOT / "build_gnu" / "fuse_daemon")
CC = os.environ.get("CC", "cc")

# —— 临时 fixture 路径：由 main() 用 mkdtemp 建立（import 无副作用）——
TMP = MNT = STORAGE = MODDIR = BUILT = SRCDIR = CONF = MARKER = DLOG = None

RULES_MOD = "lifecycle_rules"
BACKEND_MOD = "lifecycle_backend"           # 含 backend_rename（成功分支）
BACKEND_NORENAME_MOD = "lifecycle_backend_norename"  # rename NULL（EXDEV 分支）

# 用例等待上限（秒）：模块热插拔扫描周期 5s + 卸载 drain 等待 2s + 余量
LOAD_TIMEOUT = 25.0
UNLOAD_TIMEOUT = 35.0

PASS = 0
FAIL = 0
ERRS = []


def ok(d):
    global PASS
    PASS += 1
    print(f"  ✅ {d}")


def fail(d, dt=""):
    global FAIL
    FAIL += 1
    print(f"  ❌ {d}: {dt}")
    ERRS.append((d, dt))


# ================= 测试模块源码（临时写盘后 cc 编译） =================

RULES_SRC = r'''
/* 测试规则模块：为 /blife* 置 is_ftp 并把 real_path 指向测试 storage，
   使框架进入后端分派分支（backend_*）。无 /<uid>/ 用户层的路径不解析，
   交框架直通回退（与 basic_rules 的 path_has_uid_layer 约定一致）。 */
#include "nsp_module.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NSP_TEST_STORAGE
#error "编译需 -DNSP_TEST_STORAGE=\"/path\""
#endif

static int lr_resolve(const NspQueryCtx* q, NspResolveResult* out) {
    if (!q || !q->path || !out) return -22; /* -EINVAL */
    const char* p = q->path;
    int user_id = -1;
    const char* sub = p;
    if (p[0] == '/' && p[1] >= '0' && p[1] <= '9') {
        const char* d = p + 1;
        while (*d >= '0' && *d <= '9') d++;
        if (*d == '\0' || *d == '/') {
            user_id = atoi(p + 1);
            const char* slash = strchr(p + 1, '/');
            sub = slash ? slash : "/";
        }
    }
    if (user_id < 0) return 0; /* 无用户层：valid 保持 false，框架直通 */
    out->valid = true;
    out->user_id = user_id;
    snprintf(out->sub_path, sizeof out->sub_path, "%s", sub);
    snprintf(out->real_path, sizeof out->real_path, "%s/%d%s", NSP_TEST_STORAGE, user_id, sub);
    out->is_ftp = (strncmp(sub, "/blife", 6) == 0);
    return 0;
}

static const NspModuleOps lr_ops = {.resolve = lr_resolve};

const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .type = NSP_MODULE_TYPE_RULES,
    .caps = NSP_CAP_REDIRECT,
    .name = "__NAME__",
    .version = "1",
    .init = NULL,
    .exit = NULL,
    .ops = &lr_ops,
};
'''

BACKEND_SRC = r'''
/* 测试后端模块：仅 backend_match（可选 backend_rename），其余回调留 NULL，
   强制框架在“命中但无回调”时走本地回退——正是引用泄漏的触发路径。
   marker 记录 match/rename 确被调用，供测试断言后端确被分派。 */
#include "nsp_module.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifndef NSP_TEST_STORAGE
#error "编译需 -DNSP_TEST_STORAGE=\"/path\""
#endif
#ifndef NSP_TEST_MARKER
#error "编译需 -DNSP_TEST_MARKER=\"/path\""
#endif

static void mark_once(int* flag, const char* what) {
    if (*flag) return;
    *flag = 1;
    FILE* f = fopen(NSP_TEST_MARKER, "a");
    if (f) {
        fprintf(f, "%s\n", what);
        fclose(f);
    }
}

static int lb_match(const char* path) {
    static int marked = 0;
    if (path && strncmp(path, "/blife", 6) == 0) {
        mark_once(&marked, "match");
        return 1;
    }
    return 0;
}
__RENAME_FN__
static const NspModuleOps lb_ops = {
    .backend_match = lb_match,
__RENAME_FIELD__
};

const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .type = NSP_MODULE_TYPE_BACKEND,
    .caps = NSP_CAP_BACKEND_IO,
    .name = "__NAME__",
    .version = "1",
    .init = NULL,
    .exit = NULL,
    .ops = &lb_ops,
};
'''

RENAME_FN = r'''
/* 同模块 rename：框架 from/to 各 lookup 一次（引用计数 2），此回调负责真实
   移动测试 storage 内文件，使“后端确被调用”可被行为化断言。 */
static int lb_rename(const char* from, const char* to) {
    static int marked = 0;
    mark_once(&marked, "rename");
    char a[PATH_MAX], b[PATH_MAX];
    if (snprintf(a, sizeof a, "%s/0%s", NSP_TEST_STORAGE, from) >= (int)sizeof a) return -36;
    if (snprintf(b, sizeof b, "%s/0%s", NSP_TEST_STORAGE, to) >= (int)sizeof b) return -36;
    if (rename(a, b) != 0) return -errno;
    return 0;
}
'''
RENAME_FIELD = "    .backend_rename = lb_rename,"


def build_modules():
    """临时写 C 源码并现场编译三个测试模块到 BUILT/。"""
    for d in (MODDIR, BUILT, SRCDIR):
        d.mkdir(parents=True, exist_ok=True)
    defs = [f'-DNSP_TEST_STORAGE="{STORAGE}"', f'-DNSP_TEST_MARKER="{MARKER}"']

    specs = [
        (RULES_MOD, RULES_SRC.replace("__NAME__", RULES_MOD)),
        (BACKEND_MOD,
         BACKEND_SRC.replace("__NAME__", BACKEND_MOD)
                    .replace("__RENAME_FN__", RENAME_FN)
                    .replace("__RENAME_FIELD__", RENAME_FIELD)),
        (BACKEND_NORENAME_MOD,
         BACKEND_SRC.replace("__NAME__", BACKEND_NORENAME_MOD)
                    .replace("__RENAME_FN__", "")
                    .replace("__RENAME_FIELD__", "")),
    ]
    for name, src in specs:
        cfile = SRCDIR / f"{name}.c"
        cfile.write_text(src)
        so = BUILT / f"{name}.so"
        r = subprocess.run(
            [CC, "-std=c23", "-shared", "-fPIC", "-O1", "-DNSP_MODULE_BUILD",
             f"-I{ROOT / 'include'}", *defs, str(cfile), "-o", str(so)],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(f"!! 测试模块 {name} 编译失败:\n{r.stderr}")
            sys.exit(2)


def stage(name):
    d = MODDIR / name
    d.mkdir(parents=True, exist_ok=True)
    shutil.copy(BUILT / f"{name}.so", d / f"{name}.so")


def unstage(name):
    shutil.rmtree(MODDIR / name, ignore_errors=True)


def reset_storage():
    """每个用例独立 storage：/0/blife/seed.txt 为真实本地文件。"""
    shutil.rmtree(STORAGE, ignore_errors=True)
    (STORAGE / "0" / "blife").mkdir(parents=True)
    (STORAGE / "0" / "blife" / "seed.txt").write_text("seed")


def clear_marker():
    try:
        MARKER.unlink()
    except OSError:
        pass


def marker_text():
    try:
        return MARKER.read_text()
    except OSError:
        return ""


# ================= daemon 生命周期 / 内核证据 =================

def start():
    """启动 daemon（前台，pid 即 daemon）并等挂载就绪（/0 可见）。"""
    p = subprocess.Popen(
        [DAEMON, f"--root={STORAGE}", f"--rules={CONF}", f"--modules-dir={MODDIR}",
         "-f", str(MNT), "warn"],
        stdout=open(DLOG, "w"), stderr=subprocess.STDOUT)
    for _ in range(60):
        time.sleep(0.3)
        try:
            if (MNT / "0").is_dir():
                return p
        except OSError:
            pass
        if p.poll() is not None:
            return None
    return p


def stop(p):
    """精确清理自身 daemon pid 与自身挂载点（不动其他挂载）。"""
    if p:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.wait(3)
            except subprocess.TimeoutExpired:
                pass
    time.sleep(0.2)
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)


def maps_has(pid, needle):
    try:
        return needle in Path(f"/proc/{pid}/maps").read_text()
    except OSError:
        return False


def wait_maps(pid, needle, want, timeout):
    """轮询 /proc/<pid>/maps 等待模块 .so 出现/消失（卸载真伪的核心证据）。"""
    end = time.time() + timeout
    while time.time() < end:
        if maps_has(pid, needle) == want:
            return True
        if not Path(f"/proc/{pid}").exists():
            return False
        time.sleep(0.3)
    return maps_has(pid, needle) == want


def run_case(label, backend_name, body):
    """用例骨架：独立 storage/marker，装载规则+后端，启动后执行 body(p)，
    finally 精确停 daemon + 卸载 + 撤模块。"""
    print(f"\n── {label} ──")
    reset_storage()
    clear_marker()
    unstage(RULES_MOD)
    unstage(backend_name)
    stage(RULES_MOD)
    stage(backend_name)
    p = start()
    if not p:
        fail("启动失败", f"见 {DLOG}")
        unstage(RULES_MOD)
        unstage(backend_name)
        return
    try:
        if not wait_maps(p.pid, f"{RULES_MOD}.so", True, LOAD_TIMEOUT):
            fail("规则模块未加载", f"{RULES_MOD}.so 未出现在 maps")
            return
        if not wait_maps(p.pid, f"{backend_name}.so", True, LOAD_TIMEOUT):
            fail("后端模块未加载", f"{backend_name}.so 未出现在 maps")
            return
        ok("规则+后端模块均已加载（maps 可见）")
        body(p, backend_name)
    finally:
        stop(p)
        unstage(RULES_MOD)
        unstage(backend_name)


def assert_unloaded(p, backend_name, label):
    """核心断言：移除后 .so 必须从 maps 消失；并排除“规则整体失效”伪因。"""
    if wait_maps(p.pid, f"{backend_name}.so", False, UNLOAD_TIMEOUT):
        ok(f"{label}：后端 .so 已从 /proc/{p.pid}/maps 消失（真卸载，引用已归零）")
    else:
        fail(f"{label}：后端 .so 仍在 maps",
             "卸载被回滚——backend_refs/槽位在途引用未归零（引用泄漏）")
    # 反向排除：不是“规则不生效”或 daemon 已死
    if maps_has(p.pid, f"{RULES_MOD}.so"):
        ok(f"{label}：规则模块仍在 maps（排除“规则整体失效”伪因）")
    else:
        fail(f"{label}：规则模块也消失了", "无法排除规则整体失效")
    if p.poll() is None:
        ok(f"{label}：daemon 存活")
    else:
        fail(f"{label}：daemon 已退出", f"rc={p.poll()}")
    try:
        mounted = (MNT / "0").is_dir()
    except OSError:
        mounted = False
    if mounted:
        ok(f"{label}：挂载仍可服务")
    else:
        fail(f"{label}：挂载不可用", "后端卸载后 /0 不可见")


# ================= 用例 =================

def case_local_fallback_and_rename_success(p, backend_name):
    """A. 命中后端但 getattr/open/create/readdir/unlink/rmdir/truncate 回调
       缺失 → 本地 fallback；同模块 rename 两次 lookup 配对（成功分支）。"""
    blife = MNT / "0" / "blife"
    real_blife = STORAGE / "0" / "blife"

    # getattr：backend_getattr NULL → 本地 lstat
    try:
        st = os.stat(blife)
        ok("getattr 缺失回调：本地 fallback（/blife 为目录）") if stat.S_ISDIR(st.st_mode) \
            else fail("getattr fallback", f"st_mode={oct(st.st_mode)}")
    except OSError as e:
        fail("getattr fallback", str(e))

    # readdir：backend_readdir NULL → 本地 opendir
    try:
        names = os.listdir(blife)
        ok("readdir 缺失回调：本地 fallback（seed.txt 可见）") if "seed.txt" in names \
            else fail("readdir fallback", f"names={names!r}")
    except OSError as e:
        fail("readdir fallback", str(e))

    # open：backend_open NULL → 本地 open
    try:
        got = (blife / "seed.txt").read_text()
        ok("open 缺失回调：本地 fallback（内容正确）") if got == "seed" \
            else fail("open fallback", f"got={got!r}")
    except OSError as e:
        fail("open fallback", str(e))

    # create：backend_create NULL → 本地创建，产物落真实 storage
    try:
        (blife / "new.txt").write_text("abc")
        ok("create 缺失回调：本地创建落 storage") if (real_blife / "new.txt").read_text() == "abc" \
            else fail("create fallback", "storage 未见 new.txt 内容")
    except OSError as e:
        fail("create fallback", str(e))

    # mkdir：backend_mkdir NULL → 本地 mkdir
    try:
        os.mkdir(blife / "newdir")
        ok("mkdir 缺失回调：本地创建落 storage") if (real_blife / "newdir").is_dir() \
            else fail("mkdir fallback", "storage 未见 newdir")
    except OSError as e:
        fail("mkdir fallback", str(e))

    # truncate：backend_truncate NULL → 本地 truncate
    try:
        os.truncate(blife / "new.txt", 0)
        ok("truncate 缺失回调：本地截断落 storage") if (real_blife / "new.txt").stat().st_size == 0 \
            else fail("truncate fallback", "storage 中 new.txt 未截断")
    except OSError as e:
        fail("truncate fallback", str(e))

    # rename：同模块 from/to 两次 lookup，backend_rename 真实移动（成功分支配对）
    try:
        os.rename(blife / "new.txt", blife / "renamed.txt")
        moved = (real_blife / "renamed.txt").exists() and not (real_blife / "new.txt").exists()
        ok("rename：同模块两次 lookup，backend_rename 生效并配对释放") if moved \
            else fail("rename 后端", "storage 未见 renamed.txt / 旧名仍在")
    except OSError as e:
        fail("rename 后端", str(e))

    # unlink：backend_unlink NULL → 本地 unlink
    try:
        os.unlink(blife / "renamed.txt")
        ok("unlink 缺失回调：本地删除落 storage") if not (real_blife / "renamed.txt").exists() \
            else fail("unlink fallback", "storage 中 renamed.txt 仍在")
    except OSError as e:
        fail("unlink fallback", str(e))

    # rmdir：backend_rmdir NULL → 本地 rmdir
    try:
        os.rmdir(blife / "newdir")
        ok("rmdir 缺失回调：本地删除落 storage") if not (real_blife / "newdir").exists() \
            else fail("rmdir fallback", "storage 中 newdir 仍在")
    except OSError as e:
        fail("rmdir fallback", str(e))

    # 后端确被分派（marker），否则可能 is_ftp 未生效、测试平凡通过
    mtext = marker_text()
    if "match" in mtext:
        ok("backend_match 确被调用（marker 证据，排除规则未生效）")
    else:
        fail("backend_match 未调用", f"marker={mtext!r}（规则可能未置 is_ftp）")
    if "rename" in mtext:
        ok("backend_rename 确被调用（marker 证据）")
    else:
        fail("backend_rename 未调用", f"marker={mtext!r}")

    # 移除后端模块目录（MODDIR 下事件即时触发扫描）→ 必须真卸载
    shutil.rmtree(MODDIR / backend_name, ignore_errors=True)
    assert_unloaded(p, backend_name, "A")


def case_rename_missing_exdev(p, backend_name):
    """B. 后端 rename 也 NULL：同模块 rename → -EXDEV（EXDEV 分支两次 lookup
       配对释放）；再触发 getattr/open 本地回退。"""
    blife = MNT / "0" / "blife"

    try:
        os.stat(blife)
        (blife / "seed.txt").read_text()
        ok("getattr/open 本地 fallback 已触发（每次一次后端引用）")
    except OSError as e:
        fail("getattr/open fallback", str(e))

    rename_errno = None
    try:
        os.rename(blife / "seed.txt", blife / "seed2.txt")
    except OSError as e:
        rename_errno = e.errno
    if rename_errno == errno.EXDEV:
        ok("rename（rename 回调缺失）：返回 EXDEV，走跨后端分支配对释放")
    else:
        fail("rename EXDEV", f"errno={rename_errno}（期望 {errno.EXDEV}）")
    if (STORAGE / "0" / "blife" / "seed.txt").exists() and \
            not (STORAGE / "0" / "blife" / "seed2.txt").exists():
        ok("rename 未移动文件（EXDEV 语义）")
    else:
        fail("rename EXDEV 语义", "文件被意外移动")

    if "match" in marker_text():
        ok("backend_match 确被调用（marker 证据）")
    else:
        fail("backend_match 未调用", f"marker={marker_text()!r}")

    shutil.rmtree(MODDIR / backend_name, ignore_errors=True)
    assert_unloaded(p, backend_name, "B")


def main():
    global TMP, MNT, STORAGE, MODDIR, BUILT, SRCDIR, CONF, MARKER, DLOG
    if not Path(DAEMON).exists():
        print(f"!! 缺少 {DAEMON}，请先构建 GNU 产物（scripts/build.sh）")
        return 2
    if not shutil.which("fusermount3"):
        print("!! 缺少 fusermount3（测试前置）")
        return 2
    if not Path("/dev/fuse").exists():
        print("!! 缺少 /dev/fuse（测试前置）")
        return 2

    TMP = Path(tempfile.mkdtemp(prefix="fuse_backend_lifecycle_"))
    MNT = TMP / "mnt"
    STORAGE = TMP / "storage"
    MODDIR = TMP / "modules"
    BUILT = TMP / "built"
    SRCDIR = TMP / "src"
    CONF = TMP / "injector.conf"
    MARKER = TMP / "backend_marker"
    DLOG = TMP / "daemon.log"

    print(f"临时目录: {TMP}")
    MNT.mkdir(parents=True, exist_ok=True)
    CONF.write_text("[GLOBAL]\nMONITOR OFF\nSANDBOX OFF\n")
    try:
        build_modules()
    except SystemExit as e:
        shutil.rmtree(TMP, ignore_errors=True)
        return e.code or 2

    try:
        run_case("A. 回调缺失本地 fallback + 同模块 rename 成功分支配对",
                 BACKEND_MOD, case_local_fallback_and_rename_success)
        run_case("B. rename 回调缺失 → EXDEV 分支配对",
                 BACKEND_NORENAME_MOD, case_rename_missing_exdev)
    finally:
        # 精确清理自身挂载点与临时目录（daemon 已由各用例 finally 终止）
        subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)
        shutil.rmtree(TMP, ignore_errors=True)

    print("\n═══════════════════════════════════════")
    print(f"[{time.strftime('%H:%M:%S')}] 测试完成 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS + FAIL}")
    for d, dt in ERRS:
        print(f"   ✗ {d}: {dt}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
