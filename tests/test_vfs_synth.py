#!/usr/bin/env python3
"""虚拟条目判定与合成属性（L0 直编）

线上实例：沙盒开启时 readdir 为 /Android/obb/<当前包名> 合成一条目录（真实目录
可以不存在），而 getattr 的虚拟目录兜底只认三层骨架与重定向 virtual_kind，
按名 stat 落回 ENOENT——文件管理器列表里看得见、点不开，画成文件并显示
1970-01-01。排查绕了三轮，原因就是合成路径没有任何断言守着。

本套件两条腿：
  1. 直编 src/daemon/vfs_synth.c：合成目录条目必须 S_ISDIR、nlink>=2、size>0、
     mtime>0；/Android/data|obb/<pkg> 的路径判定必须命中（含带用户层形态），
     其余路径不得误命中。
  2. 静态契约：vfs_synth_stat 必须经 nsp_synth_stat_fill 生成属性（不再自己
     memset），且 getattr / access / opendir 三处虚拟兜底都必须问
     is_virtual_own_pkg_dir——「obb/<pkg> 不存在时 stat 也要成功」靠这条守住。
     另外 getattr 兜底与 vfs_synth_stat 都必须经 nsp_stat_nearest_ancestor 上溯：
     重定向落点不存在时整条虚拟目录链都缺，只继承一层会让时间戳留 0。

退出码遵循 tests/run.py 约定：0 通过、1 失败。无环境依赖，不会 gap。
"""
import os
import shlex
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DAEMON = os.path.join(ROOT, "src", "daemon", "fuse_daemon.c")
SOURCE = os.path.join(ROOT, "src", "daemon", "vfs_synth.c")
DRIVER = os.path.join(ROOT, "tests", "fixtures", "vfs_synth_test.c")
ACL = os.path.join(ROOT, "src", "daemon", "fw_acl.c")
RUN_TIMEOUT = 60


def func_body(src, name, span=2500):
    idx = src.find(name + "(")
    if idx < 0:
        return ""
    return src[idx:idx + span]


def static_contract():
    errs = []
    with open(DAEMON, "r", encoding="utf-8") as fh:
        src = fh.read()
    synth = func_body(src, "static void vfs_synth_stat")
    if not synth:
        errs.append("找不到 vfs_synth_stat")
    else:
        if "nsp_synth_stat_fill" not in synth:
            errs.append("vfs_synth_stat 未经 nsp_synth_stat_fill 生成属性")
        if "memset(st" in synth:
            errs.append("vfs_synth_stat 又自己 memset：合成属性必须由 vfs_synth.c 单点给出")
        if "nsp_stat_nearest_ancestor" not in synth:
            errs.append("vfs_synth_stat 未经 nsp_stat_nearest_ancestor 上溯父目录")
    getattr = func_body(src, "static int vfs_getattr", 9000)
    if getattr and "nsp_stat_nearest_ancestor" not in getattr:
        errs.append("getattr 虚拟目录兜底未经 nsp_stat_nearest_ancestor 上溯父目录"
                    "（多级合成链的时间戳会留 0）")
    for fn in ("static int vfs_getattr", "static int vfs_access", "static int vfs_opendir"):
        body = func_body(src, fn, 9000)
        if not body:
            errs.append("找不到 " + fn)
            continue
        if "is_virtual_own_pkg_dir" not in body:
            errs.append(fn + " 的虚拟目录兜底未接入 is_virtual_own_pkg_dir")
        if "nsp_listed_own_pkg" not in body:
            errs.append(fn + " 的 own_pkg 兜底未要求列举登记"
                        "（路径形状像就放行＝凭空变出目录）")
    init = func_body(src, "static void vfs_readdir_ctx_init", 1800)
    if not init:
        errs.append("找不到 vfs_readdir_ctx_init")
    elif "sub_path_is_storage_android_dir" not in init:
        errs.append("vfs_readdir_ctx_init 的 is_android_dir 未用存储根判定"
                    "（尾段匹配会让嵌套 Android 目录也补 data/obb）")
    if "sub_path_is_android_dir(" in src:
        errs.append("fuse_daemon 仍引用尾段匹配的 sub_path_is_android_dir")
    children = func_body(src, "static bool vfs_readdir_fill_android_children", 900)
    if not children or "d->is_android_dir" not in children:
        errs.append("vfs_readdir_fill_android_children 未由 d->is_android_dir 守门")
    vis = func_body(src, "static NspVisibility vfs_entry_visibility", 9000)
    for need in ('"/Android/data"', '"/Android/obb"'):
        if vis and need not in vis:
            errs.append("vfs_entry_visibility 缺少根层精确判定 " + need)
    errs.extend(container_listing_contract(src))
    return errs


def container_listing_contract(src):
    """容器目录（/Android/data|obb）列举只能出自身包名。

    两道门都钉住：①列举前逐条过 vfs_entry_visibility（发射点不得早于判定点）；
    ②合成阶段只补自身包名，绝不枚举真实目录。任一条被绕开，沙盒开启的应用
    就能在容器里看到别的包名目录（隔离问题，不是显示问题）。"""
    errs = []
    scan = func_body(src, "static bool vfs_readdir_scan_local", 9000)
    if not scan:
        return ["找不到 vfs_readdir_scan_local"]
    vis_at = scan.find("vfs_entry_visibility(")
    if vis_at < 0:
        errs.append("vfs_readdir_scan_local 未调用 vfs_entry_visibility（容器列举会漏出他包条目）")
    else:
        for emit in ("vfs_emit(", "vfs_readdir_emit_dedup("):
            pos = scan.find(emit)
            while pos >= 0:
                if pos < vis_at:
                    errs.append("vfs_readdir_scan_local 在可见性判定之前就发射条目：" + emit)
                    break
                pos = scan.find(emit, pos + 1)
    for fn in ("static bool vfs_readdir_fill_own_pkg", "static int vfs_readdir"):
        body = func_body(src, fn, 12000)
        if body and "nsp_listed_mark_own_pkg" not in body:
            errs.append(fn + " 发出 own_pkg 条目后未登记（getattr 兜底会拒掉刚列出的目录）")
    own = func_body(src, "static bool vfs_readdir_fill_own_pkg", 900)
    if not own:
        errs.append("找不到 vfs_readdir_fill_own_pkg")
    else:
        if "d->current_pkg" not in own:
            errs.append("fill_own_pkg 未按 d->current_pkg 合成自身包名目录")
        if "hide_others" not in own or "sub_path_is_android_container" not in own:
            errs.append("fill_own_pkg 的合成条件缺少 hide_others/container 守门")
        if "readdir(" in own:
            errs.append("fill_own_pkg 枚举了真实目录（应只合成自身包名）")
    return errs


def acl_contract():
    """ACL 骨架门：容器目录本身对应用不可列举（AOSP 语义）。

    这条门是容器列举的最后一道保险——它与可见性过滤互不替代。门被放开而过滤
    没跟上，就是「应用能列出 obb 下所有包名」的现成路径。"""
    if not os.path.exists(ACL):
        return ["缺少源文件 " + ACL]
    with open(ACL, "r", encoding="utf-8") as fh:
        src = fh.read()
    idx = src.find("case NSP_PATH_SKELETON:")
    if idx < 0:
        return ["fw_acl.c 找不到 NSP_PATH_SKELETON 分支"]
    body = src[idx:idx + 800]
    errs = []
    for need in ("NSP_ACL_OP_OPENDIR", "NSP_ACL_OP_READDIR", "NSP_ACL_DENY_EACCES"):
        if need not in body:
            errs.append("ACL 骨架目录分支缺少 " + need + "（容器可被列举＝他包目录名外泄）")
    return errs


def main():
    for path in (DRIVER, SOURCE, DAEMON):
        if not os.path.exists(path):
            print("缺少源文件 " + path, file=sys.stderr)
            return 1

    errs = static_contract() + acl_contract()
    if errs:
        for e in errs:
            print("[FAIL] " + e, file=sys.stderr)
        return 1
    print("静态契约：合成属性单点生成 / getattr+access+opendir 三处兜底同口径 OK")

    with tempfile.TemporaryDirectory(prefix="vfssynth_build_") as tmpdir:
        exe = os.path.join(tmpdir, "vfs_synth_test")
        cmd = [
            *shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Wno-unused-parameter",
            "-I", os.path.join(ROOT, "include"),
            "-I", os.path.join(ROOT, "src", "daemon"),
            DRIVER, SOURCE, "-o", exe,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("C 编译/链接失败:", file=sys.stderr)
            print(r.stderr, file=sys.stderr)
            return 1
        if r.stderr.strip():
            print(r.stderr, file=sys.stderr, end="")
        try:
            run = subprocess.run([exe], capture_output=True, text=True, timeout=RUN_TIMEOUT)
        except subprocess.TimeoutExpired:
            print(f"驱动超时（>{RUN_TIMEOUT}s）", file=sys.stderr)
            return 1

    print(run.stdout, end="")
    if run.returncode != 0 or "[FAIL]" in run.stdout:
        print("虚拟条目判定/合成属性测试失败", file=sys.stderr)
        return 1
    print("虚拟条目判定/合成属性测试通过 OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
