#!/usr/bin/env python3
"""libfuse 分支新增的 dentry 级失效 API 回归（fuse_invalidate_path_entry）。

该接口不在上游 libfuse 中，只存在于 subprojects/libfuse（master-Android
分支）——因此本测试只在「用项目内子模块构建 libfuse」时运行
（-Dlibfuse_source=subproject），系统库/预构建模式下自动跳过。

前置：fusermount3、/dev/fuse（与其他挂载类测试一致）。
产物路径可用 LIBFUSE_LIB / LIBFUSE_INC 覆盖。
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tests" / "libfuse_inval_probe.c"
SYMBOL = "fuse_invalidate_path_entry"


def find_lib():
    """定位打过补丁的 libfuse3（含 dentry 失效符号），共享库/静态库均可。"""
    env = os.environ.get("LIBFUSE_LIB")
    if env:
        cands = [Path(env)]
    else:
        cands = sorted(ROOT.glob("build*/subprojects/libfuse/lib/libfuse3.so*"))
        cands += sorted(ROOT.glob("build*/subprojects/libfuse/lib/libfuse3.a"))
    for lib in cands:
        if not lib.exists() or lib.is_symlink():
            continue
        # 静态库用 nm（无 -D）；共享库用 nm -D 看导出表
        flags = ["-D", "--defined-only"] if ".so" in lib.name else ["--defined-only"]
        try:
            out = subprocess.run(["nm"] + flags + [str(lib)], capture_output=True, text=True,
                                 check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            continue
        if SYMBOL in out:
            return lib
    return None


def find_incs(lib):
    """子模块头目录 + 构建目录（含生成的 libfuse_config.h）。"""
    env = os.environ.get("LIBFUSE_INC")
    if env:
        return [Path(env)]
    # lib = <build>/subprojects/libfuse/lib/libfuse3.*
    build_sub = lib.parents[1]
    dirs = [ROOT / "subprojects" / "libfuse" / "include"]
    if (build_sub / "libfuse_config.h").exists():
        dirs.append(build_sub)
    return dirs


def unmount(mnt):
    """尽力卸载：先常规，再惰性（-z）。探针自身也会卸载，但子进程异常退出
    时挂载点会残留，测试必须自己兜底，否则 rmtree 会撞 ENOTCONN。"""
    if not mnt.exists():
        return
    if not os.path.ismount(mnt):
        return
    for args in (["-u"], ["-u", "-z"]):
        subprocess.run(["fusermount3"] + args + [str(mnt)], capture_output=True)
        if not os.path.ismount(mnt):
            return


def main():
    if not PROBE.exists():
        print(f"缺少探针源码 {PROBE}")
        return 1
    if not (shutil.which("fusermount3") and Path("/dev/fuse").exists()):
        print("跳过：需要 fusermount3 与 /dev/fuse")
        return 0

    lib = find_lib()
    if lib is None:
        print("跳过：未找到含 fuse_invalidate_path_entry 的 libfuse3 子模块构建产物")
        print("      （GNU 下用 scripts/build.sh build_sp_patch -Dlibfuse_source=subproject 生成）")
        return 0

    incs = find_incs(lib)
    if not (ROOT / "subprojects" / "libfuse" / "include" / "fuse.h").exists() and not os.environ.get(
            "LIBFUSE_INC"):
        print(f"跳过：缺少 libfuse 头目录（{incs}）")
        return 0

    # 挂载点独立于构建产物目录：即便卸载失败也不会污染临时目录清理
    mnt = Path(tempfile.mkdtemp(prefix="libfuse_inval_mnt_"))
    try:
        with tempfile.TemporaryDirectory(prefix="libfuse_inval_bin_") as bindir:
            binary = Path(bindir) / "probe"
            cc = [os.environ.get("CC", "cc"), "-O1", "-D_GNU_SOURCE", "-std=gnu11", "-Wall",
                  "-pthread"]
            for d in incs:
                cc.append("-I" + str(d))
            cmd = cc + [str(PROBE), "-o", str(binary), "-L" + str(lib.parent), "-lfuse3",
                        "-Wl,-rpath," + str(lib.parent)]
            subprocess.run(cmd, check=True)

            try:
                proc = subprocess.run([str(binary), str(mnt)], capture_output=True, text=True,
                                      timeout=120)
            except subprocess.TimeoutExpired:
                unmount(mnt)
                print("失败：探针超时（120s）")
                return 1
            sys.stdout.write(proc.stdout)
            if proc.stderr:
                sys.stderr.write(proc.stderr)
            if proc.returncode != 0:
                print(f"失败：探针退出码 {proc.returncode}")
                return 1
    finally:
        unmount(mnt)
        shutil.rmtree(mnt, ignore_errors=True)

    print("libfuse dentry 级失效 API 检查通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
