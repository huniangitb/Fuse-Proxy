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
目录条目（S_IFDIR|0755 + 同源 ino）；非骨架名维持原语义（NULL 条目，
按需 lookup 由 getattr 裁决）。

复现手段：LD_PRELOAD 垫片让 daemon 进程内指定后缀路径的 `lstat`
恒报 EACCES（目录本身真实存在），无需 root。d_type 经原始
getdents64 解析（Python 的 scandir/is_dir 在 UNKNOWN 时会 stat 兜底，
不能作为类型探针）：
  - 骨架名 data：d_type == DT_DIR（修复前为 UNKNOWN，即复现）；
  - 非骨架对照名：仍按旧语义上架（d_type UNKNOWN），证明垫片生效、
    测试非空转（若垫片未拦截，对照名将是正常 DIR，测试失败）。

前置：GNU 产物 build_gnu/fuse_daemon、fusermount3、/dev/fuse、cc；
缺失则跳过（rc=0，沿用仓库约定）。
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

DT_UNKNOWN = 0
DT_DIR = 4

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


CONFIG_TEXT = """
[GLOBAL]
MONITOR OFF
"""


def setup_env():
    shutil.rmtree(BASE, ignore_errors=True)
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    os.makedirs(STORAGE + "/0/Android/data", exist_ok=True)
    os.makedirs(STORAGE + "/0/Android/otherdir", exist_ok=True)
    with open(STORAGE + "/0/Android/data/seed.txt", "w") as fh:
        fh.write("seed_" + TEST_ID)
    os.makedirs(MNT, exist_ok=True)
    os.makedirs(MODDIR, exist_ok=True)
    with open(CONF, "w") as fh:
        fh.write(CONFIG_TEXT.strip())
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
    env["LD_PRELOAD"] = SHIM_SO
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


def main():
    rc = 0
    if not os.path.exists(DAEMON):
        log(f"跳过：找不到 fuse_daemon 产物 {DAEMON}")
        return 0
    if not os.path.exists("/dev/fuse"):
        log("跳过：缺少 /dev/fuse（内核未启用 FUSE）")
        return 0
    if shutil.which("fusermount3") is None or shutil.which("cc") is None:
        log("跳过：缺少 fusermount3/cc")
        return 0
    try:
        setup_env()
    except RuntimeError as e:
        log(f"跳过：{e}")
        return 0

    log("场景: lstat EACCES 下骨架名回退合成（LD_PRELOAD 模拟 lower 层拒绝）")
    proc = start_daemon()
    try:
        if proc is None or proc.poll() is not None:
            fail("daemon 挂载成功", "daemon 提前退出")
            rc = 1
        else:
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
            # 3. 非骨架对照名：维持旧语义（UNKNOWN 上架），证明垫片生效
            if dtypes.get("otherdir") == DT_UNKNOWN:
                ok("非骨架对照名维持旧语义（UNKNOWN 上架，垫片生效）")
            else:
                fail("非骨架对照名维持旧语义", f"实测={dtypes.get('otherdir')}")
                rc = 1
    finally:
        stop_daemon(proc)
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
