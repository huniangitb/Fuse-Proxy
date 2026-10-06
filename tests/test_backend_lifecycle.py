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
  - 卸载判定用内核证据：轮询 /proc/<pid>/maps，断言该模块的映射项消失。
    V4 起模块从**内存副本**（memfd）加载，maps 里呈现为 "memfd:nsp_module_<名>"，
    不再出现磁盘 .so 路径——按该名断言即可（同时证明是内存副本加载）。
    引用泄漏会让卸载回滚、映射保留 → 测试失败。这是本用例的核心判别。
  - 反向排除：daemon 存活、挂载仍可列目录（V4 规则内建，无规则模块可作对照），
    证明“后端不再被分派”不是“规则整体失效”造成的。
  - 分派证据：后端 backend_match / backend_rename 落 marker 文件，
    断言其后端确被调用（否则可能是规则没置 is_ftp，测试会平凡通过）。

覆盖：
  A. 后端仅实现 backend_match（+ backend_rename），其余回调 NULL：
     getattr/open/create/readdir/unlink/rmdir/truncate 全部本地 fallback
     （产物落真实 storage），同模块 rename 两次 lookup 配对释放。
  B. 后端仅实现 backend_match（rename 也 NULL）：rename 返回 -EXDEV，
     覆盖 EXDEV 分支的两次 lookup 配对释放。
  C. 热重载放弃新实例（旧实例在途引用未归零）：新实例 init 已成功、已起自有
     线程，框架必须在 dlclose 前经围栏调 exit 停线程。判别证据是 v2 独有的
     exit 标记——旧实现直接 dlclose 会让残留线程执行已解除映射的代码，daemon
     当场 SIGSEGV（本用例在旧实现下实测 rc=-11）。

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
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DAEMON = os.environ.get("FUSE_DAEMON") or str(ROOT / "build_gnu" / "fuse_daemon")
CC = os.environ.get("CC", "cc")

# —— 临时 fixture 路径：由 main() 用 mkdtemp 建立（import 无副作用）——
TMP = MNT = STORAGE = MODDIR = BUILT = SRCDIR = CONF = MARKER = DLOG = HOLD = RELEASE = None

BACKEND_MOD = "lifecycle_backend"           # 含 backend_rename（成功分支）
BACKEND_NORENAME_MOD = "lifecycle_backend_norename"  # rename NULL（EXDEV 分支）
SWAP_MOD = "lifecycle_swap"                 # 热重载回滚用例（同名两版本）
SWAP_V2_SO = SWAP_MOD + "_v2.so"            # v2 构建产物（v1 走通用 <name>.so）
SWAP_EXIT_TAG = "swap-exit-v2"              # 仅 v2 的 exit 会落此标记
SWAP_HOLD_CAP_MS = 30000                    # 阻塞 rename 的兜底上限（防用例异常时永不返回）

# 用例等待上限（秒）：事件触发扫描（1s 归并窗口 + 0.5s 稳定性校验）+ 卸载 drain 等待 2s + 余量
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

# 热重载回滚用例模块：rename 在 hold 文件存在时阻塞，用于在 module_unload_one
# 的 drain 窗口（~2s）内持续持有后端引用，稳定命中「旧实例在途引用未归零 →
# 热重载放弃新实例」分支。v2 额外提供 init（起自有线程）/exit（停线程 + 落唯一
# 标记），用于断言「被放弃的新实例仍经围栏调了 exit」——旧实现直接 dlclose，
# 残留线程执行已解除映射的代码即带崩整个 daemon。
SWAP_SRC = r'''
#include "nsp_module.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef NSP_TEST_STORAGE
#error "编译需 -DNSP_TEST_STORAGE=\"/path\""
#endif
#ifndef NSP_TEST_MARKER
#error "编译需 -DNSP_TEST_MARKER=\"/path\""
#endif
#ifndef NSP_TEST_HOLD
#error "编译需 -DNSP_TEST_HOLD=\"/path\""
#endif
#ifndef NSP_TEST_RELEASE
#error "编译需 -DNSP_TEST_RELEASE=\"/path\""
#endif

static void swap_mark(const char* what) {
    FILE* f = fopen(NSP_TEST_MARKER, "a");
    if (f) {
        fprintf(f, "%s\n", what);
        fclose(f);
    }
}

static int swap_match(const char* path) {
    return path && strncmp(path, "/blife", 6) == 0;
}

static int swap_rename(const char* from, const char* to) {
    if (access(NSP_TEST_HOLD, F_OK) == 0) {
        swap_mark("hold-begin");
        /* 阻塞到测试写 RELEASE 为止（上限 NSP_SWAP_CAP_MS 兜底）：**固定时长**会被
           机器负载吃掉——扫描/prepare 一慢，卸载侧反而等到了引用归零、走成"正常
           热重载"，用例断言随之失真。开放阻塞让"卸载必然超时"与时序无关。 */
        for (int i = 0; i < __HOLD_MS__ / 10; i++) {
            if (access(NSP_TEST_RELEASE, F_OK) == 0) break;
            struct timespec ts = {0, 10 * 1000 * 1000L};
            nanosleep(&ts, NULL);
        }
    }
    char a[PATH_MAX], b[PATH_MAX];
    if (snprintf(a, sizeof a, "%s/0%s", NSP_TEST_STORAGE, from) >= (int)sizeof a) return -36;
    if (snprintf(b, sizeof b, "%s/0%s", NSP_TEST_STORAGE, to) >= (int)sizeof b) return -36;
    if (rename(a, b) != 0) return -errno;
    return 0;
}

__SWAP_INIT_EXIT__

static const NspModuleOps swap_ops = {
    .backend_match = swap_match,
    .backend_rename = swap_rename,
};

const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .name = "__NAME__",
    .version = "__VERSION__",
    .init = __INIT__,
    .exit = __EXIT__,
    .ops = &swap_ops,
};
'''

# v2 独有：自有线程 + exit 落标记（v1 的 init/exit 为 NULL）
SWAP_V2_INIT_EXIT = r'''
static pthread_t swap_tid;
static volatile int swap_stop;

static void* swap_thread(void* arg) {
    (void)arg;
    while (!swap_stop) {
        struct timespec ts = {0, 10 * 1000 * 1000L};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static int swap_init(const NspFrameworkApi* api) {
    (void)api;
    swap_stop = 0;
    if (pthread_create(&swap_tid, NULL, swap_thread, NULL) != 0) return -1;
    return 0;
}

static void swap_exit(void) {
    swap_stop = 1;
    pthread_join(swap_tid, NULL);
    /* 唯一标记：证明「init 已成功的新实例」被拒绝时确实调用了 exit */
    swap_mark(NSP_SWAP_EXIT_TAG);
}
'''


def swap_source(version):
    init_exit = SWAP_V2_INIT_EXIT if version == "2" else ""
    return (SWAP_SRC.replace("__SWAP_INIT_EXIT__", init_exit)
                   .replace("__HOLD_MS__", str(SWAP_HOLD_CAP_MS))
                   .replace("__VERSION__", version)
                   .replace("__INIT__", "swap_init" if version == "2" else "NULL")
                   .replace("__EXIT__", "swap_exit" if version == "2" else "NULL")
                   .replace("__NAME__", SWAP_MOD))


def build_modules():
    """临时写 C 源码并现场编译测试模块到 BUILT/（含同名两版本的热重载用例）。"""
    for d in (MODDIR, BUILT, SRCDIR):
        d.mkdir(parents=True, exist_ok=True)
    defs = [f'-DNSP_TEST_STORAGE="{STORAGE}"', f'-DNSP_TEST_MARKER="{MARKER}"',
            f'-DNSP_TEST_HOLD="{HOLD}"', f'-DNSP_TEST_RELEASE="{RELEASE}"']

    def compile_so(so_name, src, extra=()):
        cfile = SRCDIR / f"{so_name}.c"
        cfile.write_text(src)
        so = BUILT / f"{so_name}.so"
        r = subprocess.run(
            [CC, "-std=c23", "-shared", "-fPIC", "-O1", "-DNSP_MODULE_BUILD", "-pthread",
             f"-I{ROOT / 'include'}", *defs, *extra, str(cfile), "-o", str(so)],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(f"!! 测试模块 {so_name} 编译失败:\n{r.stderr}")
            sys.exit(2)

    specs = [
        (BACKEND_MOD,
         BACKEND_SRC.replace("__NAME__", BACKEND_MOD)
                    .replace("__RENAME_FN__", RENAME_FN)
                    .replace("__RENAME_FIELD__", RENAME_FIELD)),
        (BACKEND_NORENAME_MOD,
         BACKEND_SRC.replace("__NAME__", BACKEND_NORENAME_MOD)
                    .replace("__RENAME_FN__", "")
                    .replace("__RENAME_FIELD__", "")),
        # 热重载回滚用例 v1：与 v2 同模块名、同 match/rename，但无 init/exit
        (SWAP_MOD, swap_source("1")),
    ]
    for name, src in specs:
        compile_so(name, src)
    # v2：同一模块名的第二版本（init 起线程 / exit 停线程并落唯一标记），
    # 编译到独立 .so，测试中途原子替换到模块目录触发热重载
    compile_so(SWAP_MOD + "_v2", swap_source("2"), [f'-DNSP_SWAP_EXIT_TAG="{SWAP_EXIT_TAG}"'])


def stage_file(name, so_name):
    """把 BUILT/<so_name> 原子替换到 MODDIR/<name>/<name>.so（触发热重载/首装）。"""
    d = MODDIR / name
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / f"{name}.so.tmp"
    shutil.copy(BUILT / so_name, tmp)
    os.replace(tmp, d / f"{name}.so")


def stage(name):
    stage_file(name, f"{name}.so")


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


def wait_marker(text, timeout):
    """轮询 marker 文件等待出现指定行（模块侧证据）。"""
    end = time.time() + timeout
    while time.time() < end:
        if text in marker_text():
            return True
        time.sleep(0.2)
    return text in marker_text()


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
    unstage(backend_name)
    stage(backend_name)
    p = start()
    if not p:
        fail("启动失败", f"见 {DLOG}")
        unstage(backend_name)
        return
    try:
        if not wait_maps(p.pid, f"memfd:nsp_module_{backend_name}", True, LOAD_TIMEOUT):
            fail("后端模块未加载", f"memfd:nsp_module_{backend_name} 未出现在 maps")
            return
        ok("后端模块已加载（maps 可见）")
        body(p, backend_name)
    finally:
        stop(p)
        unstage(backend_name)


def assert_unloaded(p, backend_name, label):
    """核心断言：移除后 .so 必须从 maps 消失；并排除“规则整体失效”伪因。"""
    if wait_maps(p.pid, f"memfd:nsp_module_{backend_name}", False, UNLOAD_TIMEOUT):
        ok(f"{label}：模块映射已从 /proc/{p.pid}/maps 消失（真卸载，引用已归零）")
    else:
        fail(f"{label}：模块映射仍在 maps",
             "卸载被回滚——backend_refs/槽位在途引用未归零（引用泄漏）")
    # 反向排除：daemon 未死、挂载仍可服务（V4 规则已内建，不再有规则模块可作对照）
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


def case_hot_reload_rollback_calls_exit(p, name):
    """C. 旧实例在途引用未归零 → 热重载放弃新实例。新实例 init 已成功（起了自有
       线程），必须经围栏 exit 停线程后再 dlclose；直接 dlclose 会让残留线程执行
       已解除映射的代码，把整个 daemon 带崩。
       判别证据：v2 独有的 exit 标记必须出现（旧实现直接 dlclose，标记必然缺失）。"""
    blife = MNT / "0" / "blife"
    HOLD.write_text("hold")
    errs = []

    def do_rename():
        try:
            os.rename(blife / "seed.txt", blife / "seed2.txt")
        except OSError as e:
            errs.append(e)

    th = threading.Thread(target=do_rename, daemon=True)
    th.start()
    if not wait_marker("hold-begin", LOAD_TIMEOUT):
        fail("旧实例 rename 未进入阻塞", f"marker={marker_text()!r}")
        HOLD.unlink(missing_ok=True)
        RELEASE.write_text("go")  # 兜底放行，别把 daemon 卡住
        return
    ok("旧实例在途 rename 阻塞（drain 窗口内持续持引用，开放阻塞直到放行）")

    # .so 原子替换 → 热重载：prepare(v2) 成功（init 已起线程），unload(v1) 因
    # 在途引用超时失败 → 放弃新实例——此分支必须调 v2 的 exit。
    # 期间旧实例一直持引用（用例控制放行时机），故与扫描/prepare 快慢无关。
    stage_file(name, SWAP_V2_SO)
    marked = wait_marker(SWAP_EXIT_TAG, UNLOAD_TIMEOUT)
    RELEASE.write_text("go")  # 放行旧实例的 rename，后续流程照常
    if marked:
        ok("热重载放弃分支执行了新实例 exit（线程已停后再 dlclose）")
    else:
        fail("新实例 exit 未执行",
             f"marker={marker_text()!r}（旧实现 dlclose 不带 exit，残留线程会带崩 daemon）")

    th.join(timeout=40)
    HOLD.unlink(missing_ok=True)
    if p.poll() is None:
        ok("daemon 存活（无语义残留线程踩空）")
    else:
        fail("daemon 已退出", f"rc={p.poll()}")
    try:
        mounted = (MNT / "0").is_dir()
    except OSError:
        mounted = False
    if mounted:
        ok("挂载仍可服务")
    else:
        fail("挂载不可用", "/0 不可见")


def main():
    global TMP, MNT, STORAGE, MODDIR, BUILT, SRCDIR, CONF, MARKER, DLOG, HOLD, RELEASE
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
    HOLD = TMP / "hold_flag"
    RELEASE = TMP / "release_flag"
    DLOG = TMP / "daemon.log"

    print(f"临时目录: {TMP}")
    MNT.mkdir(parents=True, exist_ok=True)
    # FTP 规则使内建引擎为该前缀置 is_ftp，框架才会进入后端分派分支
    CONF.write_text("[GLOBAL]\nMONITOR OFF\nSANDBOX OFF\nFTP /blife seg1\n")
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
        run_case("C. 热重载放弃新实例：新实例 exit 必须执行（自有线程已停）",
                 SWAP_MOD, case_hot_reload_rollback_calls_exit)
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
