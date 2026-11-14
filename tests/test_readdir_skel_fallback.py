#!/usr/bin/env python3
"""
readdir 骨架回退回归测试
========================
线上实例：lower 层拒绝（daemon 侧 `lstat` 报 EACCES，root 同样命中，
故非 DAC 问题）时，`vfs_readdir_scan_local` 对物理存在的骨架名
（Android/data/obb/自身包名）发出 NULL stat 条目（d_type=UNKNOWN），
而 `has_*` 标记照置导致后继合成兜底被跳过——文件管理器遂显示为文件
且无法点击，按名 stat（getattr 虚拟分支）却又是正常目录。

修复约定：lstat 失败的骨架名不上架、不置标记，由 fill 阶段合成标准
目录条目（S_IFDIR|0755 + 同源 ino）；lstat 失败但 getdents 已给出类型的
非骨架名按该类型合成条目（不再上架 NULL stat 条目——NULL 即 d_type=UNKNOWN，
客户端会把它画成「未知/文件」）；类型未知时才保留 NULL 条目，按需 lookup
由 getattr 裁决。

复现手段：LD_PRELOAD 垫片让 daemon 进程内指定后缀路径的 `lstat`
恒报 EACCES（目录本身真实存在），无需 root。d_type 经原始
getdents64 解析（Python 的 scandir/is_dir 在 UNKNOWN 时会 stat 兜底，
不能作为类型探针）：
  - 骨架名 data：d_type == DT_DIR（修复前为 UNKNOWN，即复现）；
  - 非骨架对照名 otherdir：按其 getdents 类型合成 DIR（曾为 UNKNOWN）；
  - 同一被拒目录里的普通文件 seed.txt：合成为 DT_REG——与 otherdir 一起
    构成「条目类型取自 getdents 而非 lstat」的证据，证明垫片确实生效、
    测试非空转。

沙盒对 /Android 只有一种口径：三个容器本身与该应用自己的私有目录让位真实目录，
其余整树进镜像。镜像里没有真实的容器目录，`/Android` 读侧必须补出 data/obb/media
三条，且三条按名 stat 都是目录（不是文件、时间戳不是 1970）；未列举过的 media
子路径仍 ENOENT——「readdir 列过才允许按名 stat」的口径不能因为补齐骨架而放宽。
第二、第三两个场景跑同一组断言：前者不带任何开关（单一口径的默认形态），后者带
一行遗留的 `SANDBOX_ANDROID_TREE OFF`（该行已弃用，须照常解析、不报错、不改变
任何落点，daemon 日志里有且仅有一条告警）。

前置：GNU 产物 build_gnu/fuse_daemon、fusermount3、/dev/fuse、cc；
缺失则以 SKIP_RC 退出（环境不具备 = gap，不计通过）。
"""
import ctypes
import os
import shutil
import stat as statmod
import struct
import subprocess
import sys
import time
import uuid

# 退出码约定（与 tests/run.py 一致）：0=通过 1=失败 77=环境不具备跳过(gap)
SKIP_RC = 77

BASE = "/tmp/fuse_skel_test"
MNT = BASE + "/mnt"
STORAGE = BASE + "/storage"
CONF = BASE + "/injector.conf"
MODDIR = BASE + "/modules"
SHIM_C = BASE + "/deny_lstat.c"
SHIM_SO = BASE + "/deny_lstat.so"
DAEMON = os.environ.get("FUSE_DAEMON") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "build_gnu", "fuse_daemon"))
TEST_ID = str(uuid.uuid4())[:8]
PASS = 0
FAIL = 0
ERRORS = []


def asan_runtime_path():
    """daemon 若动态链接了 ASan 运行时，返回其路径（否则空串）。

    本套件用 LD_PRELOAD 垫片拦 lstat；ASan 要求自己的运行时**在 LD_PRELOAD 里排
    第一**，垫片必须排在它之后——否则 ASan 链接的 daemon 直接以「ASan runtime
    does not come first in initial library list」拒启（内存验收跑本套件时必踩）。
    与 test_modules.py 的 asan_runtime_path 同源。"""
    try:
        out = subprocess.run(["ldd", DAEMON], capture_output=True, text=True).stdout
    except OSError:
        return ""
    for ln in out.splitlines():
        if "libasan" not in ln:
            continue
        parts = ln.split("=>")
        if len(parts) == 2:
            p = parts[1].strip().split(" ")[0]
            if p.startswith("/"):
                return p
    return ""

DT_UNKNOWN = 0
DT_DIR = 4
DT_REG = 8

SHIM_SRC = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
static int (*real_lstat)(const char*, struct stat*) = NULL;
static void resolve(void) {
    if (!real_lstat) real_lstat = dlsym(RTLD_NEXT, "lstat");
}
static int has_suffix(const char* path, const char* suf) {
    size_t pl = strlen(path), sl = strlen(suf);
    return pl >= sl && strcmp(path + pl - sl, suf) == 0;
}
static int deny_hit(const char* path) {
    const char* deny = getenv("NSP_TEST_LSTAT_DENY");
    if (!deny || !*deny || !path) return 0;
    char* list = strdup(deny);
    for (char* tok = strtok(list, ","); tok; tok = strtok(NULL, ",")) {
        if (*tok && has_suffix(path, tok)) {
            free(list);
            return 1;
        }
    }
    free(list);
    return 0;
}
/* daemon 以 -D_FILE_OFFSET_BITS=64 编译，lstat 即 lstat64（见 readelf）：
   两符号都拦截；其余一律透传。 */
int lstat(const char* path, struct stat* buf) {
    resolve();
    if (deny_hit(path)) {
        errno = EACCES;
        return -1;
    }
    return real_lstat(path, buf);
}
int lstat64(const char* path, struct stat64* buf) {
    resolve();
    if (deny_hit(path)) {
        errno = EACCES;
        return -1;
    }
    return ((int (*)(const char*, struct stat64*))real_lstat)(path, buf);
}
"""

_LIBC = ctypes.CDLL("libc.so.6", use_errno=True)


def raw_dtypes(path):
    """原始 getdents64 解析：{name: d_type}，不触发任何 stat。"""
    out = {}
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        buf = ctypes.create_string_buffer(65536)
        while True:
            n = _LIBC.getdents64(fd, buf, 65536)
            if n <= 0:
                break
            raw = buf.raw[:n]
            off = 0
            while off < n:
                ino, doff, reclen = struct.unpack_from("QQH", raw, off)
                # d_type 在固定偏移 +18（linux_dirent64 头 19 字节末）；
                # off+reclen-1 是记录尾填充，不可用
                dtype = raw[off + 18]
                name = raw[off + 19:off + reclen - 1].split(b"\0", 1)[0].decode(
                    "utf-8", "replace")
                if name not in (".", ".."):
                    out[name] = dtype
                off += reclen
    finally:
        os.close(fd)
    return out


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


def ok(desc):
    global PASS
    PASS += 1
    log(f"  ✅ {desc}")


def fail(desc, detail=""):
    global FAIL
    FAIL += 1
    log(f"  ❌ {desc}: {detail}")
    ERRORS.append((desc, detail))


CONFIG_PLAIN = """
[GLOBAL]
MONITOR OFF
"""

# 存量配置的形态：/Android 口径已不设开关，这一行只剩兼容解析
CONFIG_RETIRED_LINE = CONFIG_PLAIN + "SANDBOX_ANDROID_TREE OFF\n"


def write_conf(text):
    with open(CONF, "w") as fh:
        fh.write(text.strip())


def setup_env():
    shutil.rmtree(BASE, ignore_errors=True)
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    os.makedirs(STORAGE + "/0/Android/data", exist_ok=True)
    os.makedirs(STORAGE + "/0/Android/otherdir", exist_ok=True)
    with open(STORAGE + "/0/Android/data/seed.txt", "w") as fh:
        fh.write("seed_" + TEST_ID)
    os.makedirs(MNT, exist_ok=True)
    os.makedirs(MODDIR, exist_ok=True)
    write_conf(CONFIG_PLAIN)
    with open(SHIM_C, "w") as fh:
        fh.write(SHIM_SRC)
    r = subprocess.run(["cc", "-shared", "-fPIC", "-o", SHIM_SO, SHIM_C, "-ldl"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"垫片编译失败: {r.stderr.strip()}")
    # 垫片自检：daemon 以 -D_FILE_OFFSET_BITS=64 编译（lstat 即 lstat64），
    # 自检程序同条件编译，确保拦截链路真实可用，否则测试无意义
    check_c = BASE + "/check_lstat.c"
    check_bin = BASE + "/check_lstat"
    with open(check_c, "w") as fh:
        fh.write('#include <sys/stat.h>\n'
                 'int main(int a, char** v) { struct stat s;'
                 ' return lstat(v[1], &s) == 0 ? 0 : 1; }\n')
    r = subprocess.run(["cc", "-D_FILE_OFFSET_BITS=64", "-o", check_bin, check_c],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"自检程序编译失败: {r.stderr.strip()}")
    env = dict(os.environ)
    env["LD_PRELOAD"] = SHIM_SO
    env["NSP_TEST_LSTAT_DENY"] = "/Android/data"
    r = subprocess.run([check_bin, STORAGE + "/0/Android/data"],
                       capture_output=True, env=env)
    if r.returncode == 0:
        raise RuntimeError("垫片自检失败：lstat 未被拦截")


def start_daemon():
    env = dict(os.environ)
    # ASan 链接的 daemon 要求其运行时在 LD_PRELOAD 首位（垫片排后），否则拒启
    env["LD_PRELOAD"] = ":".join(p for p in (asan_runtime_path(), SHIM_SO) if p)
    # 真实存在但 daemon 侧 lstat 恒 EACCES：骨架名 + 非骨架对照名
    env["NSP_TEST_LSTAT_DENY"] = "/Android/data,/Android/otherdir"
    proc = subprocess.Popen(
        [DAEMON, "--root=" + STORAGE, "--rules=" + CONF,
         "--modules-dir=" + MODDIR, "-f", MNT, "info"],
        stdout=open(BASE + "/daemon.log", "w"),
        stderr=subprocess.STDOUT, env=env)
    for _ in range(15):
        time.sleep(0.3)
        try:
            if "Android" in os.listdir(MNT + "/0"):
                return proc
        except OSError:
            pass
        if proc.poll() is not None:
            return None
    return proc


def stop_daemon(proc):
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            proc.kill()
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)


def scenario_skel_fallback():
    """lstat 被拒时骨架名的回退合成（单一口径下的读侧基线）。

    夹具的 /Android 是真实目录（data、otherdir 都在），media 不存在：
    三条容器里前两条来自真实文件系统，缺的那条由框架补齐。"""
    log("场景 1: lstat EACCES 下骨架名回退合成（LD_PRELOAD 模拟 lower 层拒绝）")
    rc = 0
    proc = start_daemon()
    try:
        if proc is None or proc.poll() is not None:
            fail("daemon 挂载成功", "daemon 提前退出")
            return 1
        ok("daemon 挂载成功")
        dtypes = raw_dtypes(MNT + "/0/Android")
        # 1. 骨架名：d_type 必须为 DIR（修复前为 UNKNOWN，即线上“显示为文件”）
        if dtypes.get("data") == DT_DIR:
            ok("骨架 data 条目 d_type == DT_DIR")
        else:
            fail("骨架 data 条目 d_type == DT_DIR",
                 f"实测={dtypes.get('data')}（UNKNOWN 即复现），全表={dtypes}")
            rc = 1
        # 2. 按名 stat 一致为可进入目录（线上“子目录可进入”侧）
        try:
            st = os.stat(MNT + "/0/Android/data")
            if statmod.S_ISDIR(st.st_mode) and st.st_mode & statmod.S_IXUSR:
                ok("按名 stat 为可进入目录")
            else:
                fail("按名 stat 为可进入目录", f"mode={oct(st.st_mode)}")
                rc = 1
        except OSError as e:
            fail("按名 stat 为可进入目录", repr(e))
            rc = 1
        # 3. 非骨架对照名：lstat 被拒但 getdents 给了类型，按该类型合成
        if dtypes.get("otherdir") == DT_DIR:
            ok("非骨架对照名按 d_type 合成 DIR（不再上架 UNKNOWN 条目）")
        else:
            fail("非骨架对照名按 d_type 合成 DIR", f"实测={dtypes.get('otherdir')}")
            rc = 1
        # 4. 同一被拒目录里的普通文件：类型必须取自 d_type（REG），
        #    证明垫片拦住了 lstat 且 readdir 不靠 lstat 定类型
        data_dtypes = raw_dtypes(MNT + "/0/Android/data")
        if data_dtypes.get("seed.txt") == DT_REG:
            ok("被拒目录内的普通文件按 d_type 上报 DT_REG（类型不依赖 lstat）")
        else:
            fail("被拒目录内的普通文件上报 DT_REG",
                 f"实测={data_dtypes.get('seed.txt')}，全表={data_dtypes}")
            rc = 1
        # 5. 三个容器条目齐备：夹具里没有 media 目录，也要由框架补出来
        #    （容器条目取自镜像，镜像里没有真实目录，缺的那条就整条不见）
        if dtypes.get("media") == DT_DIR:
            ok("骨架 media 条目 d_type == DT_DIR")
        else:
            fail("骨架 media 条目 d_type == DT_DIR", f"实测={dtypes.get('media')}，全表={dtypes}")
            rc = 1
        try:
            st = os.stat(MNT + "/0/Android/media")
            if statmod.S_ISDIR(st.st_mode):
                ok("按名 stat media 为目录")
            else:
                fail("按名 stat media 为目录", f"mode={oct(st.st_mode)}")
                rc = 1
        except OSError as e:
            fail("按名 stat media 为目录", repr(e))
            rc = 1
        # 6. 未列举过的 media 子路径仍按真实结果 ENOENT：补齐骨架不等于放行任意子路径
        try:
            os.stat(MNT + "/0/Android/media/com.example")
            fail("未列举的 media 子路径仍 ENOENT", "按名 stat 成功（凭空变出目录）")
            rc = 1
        except OSError:
            ok("未列举的 media 子路径仍 ENOENT")
    finally:
        stop_daemon(proc)
    return rc


def scenario_containers(conf, label):
    """单一口径｜/Android 读侧三个容器条目齐全，且各自 stat 正常。

    容器条目取自镜像，镜像里没有真实的 data/obb/media，三条都要由 readdir
    合成；合成条目按名 stat 必须是目录（不是文件、时间戳不落到 1970），而
    镜像里没列举过的子路径仍要 ENOENT（不能因为父路径像容器就放行）。"""
    log(f"场景: {label}")
    rc = 0
    write_conf(conf)
    proc = start_daemon()
    try:
        if proc is None or proc.poll() is not None:
            fail(f"daemon 挂载成功（{label}）", "daemon 提前退出")
            return 1
        ok(f"daemon 挂载成功（{label}）")
        dtypes = raw_dtypes(MNT + "/0/Android")
        for name in ("data", "obb", "media"):
            if dtypes.get(name) == DT_DIR:
                ok(f"镜像口径 {name} 条目 d_type == DT_DIR")
            else:
                fail(f"镜像口径 {name} 条目 d_type == DT_DIR",
                     f"实测={dtypes.get(name)}，全表={dtypes}")
                rc = 1
        for name in ("data", "obb", "media"):
            try:
                st = os.stat(MNT + "/0/Android/" + name)
            except OSError as e:
                fail(f"镜像口径 {name} 按名 stat 为目录", repr(e))
                rc = 1
                continue
            if not statmod.S_ISDIR(st.st_mode):
                fail(f"镜像口径 {name} 按名 stat 为目录", f"mode={oct(st.st_mode)}")
                rc = 1
            elif st.st_mtime <= 0:
                fail(f"镜像口径 {name} 按名 stat 为目录",
                     f"mtime={st.st_mtime}（1970 即无兜底）")
                rc = 1
            else:
                ok(f"镜像口径 {name} 按名 stat 为目录（mtime 正常）")
        try:
            os.stat(MNT + "/0/Android/media/com.example")
            fail("镜像里未列举的 media 子路径仍 ENOENT", "按名 stat 成功（凭空变出目录）")
            rc = 1
        except OSError:
            ok("镜像里未列举的 media 子路径仍 ENOENT")
    finally:
        stop_daemon(proc)
    return rc


def scenario_retired_line():
    """存量配置里遗留的 SANDBOX_ANDROID_TREE 行只做兼容解析。

    该开关已弃用：值不再切换任何口径，行也不能让解析失败。故本场景与不带开关
    的那一轮断言必须一致，唯一的额外证据是 daemon 日志里那条告警——它证明行
    被读到过（不是被当成未知规则丢掉），也证明了值没有生效。"""
    rc = 0
    write_conf(CONFIG_RETIRED_LINE)
    proc = start_daemon()
    try:
        if proc is None or proc.poll() is not None:
            fail("daemon 挂载成功（遗留开关行）", "daemon 提前退出（解析报错？）")
            return 1
        ok("daemon 挂载成功（遗留开关行）")
        dtypes = raw_dtypes(MNT + "/0/Android")
        for name in ("data", "obb", "media"):
            if dtypes.get(name) == DT_DIR:
                ok(f"遗留开关行 {name} 条目 d_type == DT_DIR")
            else:
                fail(f"遗留开关行 {name} 条目 d_type == DT_DIR",
                     f"实测={dtypes.get(name)}，全表={dtypes}")
                rc = 1
        try:
            os.stat(MNT + "/0/Android/media/com.example")
            fail("遗留开关行｜未列举的 media 子路径仍 ENOENT", "按名 stat 成功")
            rc = 1
        except OSError:
            ok("遗留开关行｜未列举的 media 子路径仍 ENOENT")
        # 该行「被读到且只告警一次」这一半在 test_vfs_synth 的源码契约里查：
        # 配置期日志进环形缓冲（log_monitor / sys.log），不出现在进程 stderr，
        # 在这里断 stderr 只会永远空手。落点不变这一半由上面的断言给出。
    finally:
        stop_daemon(proc)
    return rc


def main():
    rc = 0
    if not os.path.exists(DAEMON):
        log(f"跳过：找不到 fuse_daemon 产物 {DAEMON}")
        return SKIP_RC
    if not os.path.exists("/dev/fuse"):
        log("跳过：缺少 /dev/fuse（内核未启用 FUSE）")
        return SKIP_RC
    if shutil.which("fusermount3") is None or shutil.which("cc") is None:
        log("跳过：缺少 fusermount3/cc")
        return SKIP_RC
    try:
        setup_env()
    except RuntimeError as e:
        log(f"跳过：{e}")
        return SKIP_RC

    try:
        rc |= scenario_skel_fallback()
        rc |= scenario_containers(CONFIG_PLAIN, "单一口径｜/Android 三容器齐备")
        rc |= scenario_retired_line()
    finally:
        subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
        shutil.rmtree(BASE, ignore_errors=True)
    print(f"\n结果: {PASS} 通过, {FAIL} 失败")
    if ERRORS:
        for d, det in ERRORS:
            print(f"  ❌ {d}: {det}")
        return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
