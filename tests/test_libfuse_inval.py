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


def _elf_machine(path):
    """读 ELF e_machine（静态库取首个成员）。直接解析头部字节——readelf
    的输出是本地化的（如中文 "机器:"），按英文关键字解析会静默失效。"""
    try:
        data = Path(path).read_bytes()[:1 << 20]
    except OSError:
        return None
    off = data.find(b"\x7fELF")
    if off < 0 or len(data) < off + 20:
        return None
    little = data[off + 5] == 1  # EI_DATA
    return int.from_bytes(data[off + 18:off + 20], "little" if little else "big")


def _host_machine(cc):
    """本机 cc 产出物的 e_machine，作为兼容性基准。"""
    with tempfile.TemporaryDirectory(prefix="libfuse_inval_cc_") as d:
        src = Path(d) / "t.c"
        src.write_text("int main(void) { return 0; }\n")
        obj = Path(d) / "t.o"
        if subprocess.run([cc, "-c", str(src), "-o", str(obj)],
                          capture_output=True).returncode != 0:
            return None
        return _elf_machine(obj)


def find_lib(cc):
    """定位打过补丁、且与本机架构一致的 libfuse3（含 dentry 失效符号）。

    必须校验架构：构建目录里同时存在 Android 交叉编译的 libfuse3（同样
    含该符号），而 `build*` 的字典序会把 build_android 排在最前——只按
    符号存在挑选会选中 aarch64 库。也不能靠"能否 -lfuse3 链接成功"判断，
    因为搜索路径会回退到系统库而使交叉库蒙混过关。"""
    env = os.environ.get("LIBFUSE_LIB")
    if env:
        cands = [Path(env)]  # 显式指定：仍走同样的符号/架构校验，不合格则跳过
    else:
        cands = sorted(ROOT.glob("build*/subprojects/libfuse/lib/libfuse3.so*"))
    host = _host_machine(cc)
    for lib in cands:
        if not lib.exists() or lib.is_symlink():
            continue
        try:
            out = subprocess.run(["nm", "-D", "--defined-only", str(lib)],
                                 capture_output=True, text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            continue
        if SYMBOL not in out:
            continue
        if host and _elf_machine(lib) != host:
            continue
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


def _mounted(mnt):
    """是否仍挂在挂载表里。用 /proc/mounts 而不是 os.path.ismount——连接已死的
    FUSE 挂载点 stat 会返回 ENOTCONN，ismount 判为 False 却仍占着挂载表，
    于是残留不断累积并影响后续运行。"""
    try:
        return str(mnt) in Path("/proc/mounts").read_text()
    except OSError:
        return False


def unmount(mnt):
    """尽力卸载：先常规，再惰性（-z）。探针自身也会卸载，但子进程异常退出
    （超时被 kill）时挂载点会残留，测试必须自己兜底，否则 rmtree 会撞
    ENOTCONN 且残留挂载会拖累后续运行。"""
    for args in (["-u"], ["-u", "-z"]):
        if not _mounted(mnt):
            return
        subprocess.run(["fusermount3"] + args + [str(mnt)], capture_output=True)


def main():
    if not PROBE.exists():
        print(f"缺少探针源码 {PROBE}")
        return 1
    if not (shutil.which("fusermount3") and Path("/dev/fuse").exists()):
        print("跳过：需要 fusermount3 与 /dev/fuse")
        return 0

    cc = [os.environ.get("CC", "cc")]
    lib = find_lib(cc[0])
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
            cc = cc + ["-O1", "-D_GNU_SOURCE", "-std=gnu11", "-Wall", "-pthread"]
            for d in incs:
                cc.append("-I" + str(d))
            cmd = cc + [str(PROBE), str(lib), "-o", str(binary),
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
