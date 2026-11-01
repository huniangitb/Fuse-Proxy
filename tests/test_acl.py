#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""访问控制判定表（src/daemon/fw_acl.c）判别性单测

背景（AOSP 事实，见 docs/architecture.md「访问控制」）：
  Android 的 /storage/emulated 由 MediaProvider 自己当 FUSE 服务端，挂载参数
  **故意不加 default_permissions**（vold 原注释：不想让内核在路由到 daemon 前做
  低层权限检查），属主/权限由 daemon 合成；唯一门是 FuseDaemon 的
  is_app_accessible_path() + MediaProvider 的 13 个 JNI 判定。本项目此前完全没有
  这一层——daemon 以 root 执行所有 syscall，任意应用能删改挂载内任意文件。

本套件直编真实源码 src/daemon/fw_acl.c（只桩掉 uid→包名 / 特权签名 / 跨应用
隔离开关三个事实源），断言判定表的**行为**而不只是「接口存在」：

  1. 路径分类对齐 AOSP PATTERN_OWNED_PATH：卷根 / 骨架目录 / 他包私有目录 /
     Android/media（明确不算私有）/ 顶层条目；
  2. 他包 /Android/data|obb → ENOENT（看不见），自己包（含 ":push" 进程后缀）放行，
     platform 签名豁免，[GLOBAL] ALLOW_CROSS_APP_DATA ON 放行，包名解析失败放行；
  3. 骨架目录不可列举（EACCES）、不可增删改名（EPERM）；Android/media 可读写但不可改名；
  4. 顶层条目只能建默认目录、不可删、不可改名；
  5. access(2) 的 X_OK 对普通文件 EACCES（MS_NOEXEC），对目录放行；
  6. 拒绝码三码不混用（ENOENT/EACCES/EPERM）。

判别性：旧实现没有 fw_acl.c（整个模块为新增）；且本驱动含 A 组 AOSP 语义断言，
任何一条在旧行为下都不成立（旧 daemon 对上述路径全部放行）。

前置：本机 cc。失败退出码 1（勿用管道吞掉退出码）。
"""

import os
import shlex
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(ROOT, "tests", "fixtures", "fw_acl_driver.c")
SOURCE = os.path.join(ROOT, "src", "daemon", "fw_acl.c")
DAEMON = os.path.join(ROOT, "src", "daemon", "fuse_daemon.c")
RUN_TIMEOUT = 60


def static_contract():
    """决策单点：ACL 只能由 fw_route 调一次，其它回调不得自己写访问判定。"""
    errs = []
    with open(DAEMON, encoding="utf-8") as f:
        src = f.read()
    calls = src.count("fw_acl_check(")
    if calls != 1:
        errs.append(f"fuse_daemon.c 里 fw_acl_check( 出现 {calls} 次，期望 1 次（唯一执行点）")
    # 回调里不得出现直接的属主/他包字符串判定（判定只许在 fw_acl.c 一份）
    for bad in ('strcmp(owner', 'strncmp(owner'):
        if bad in src:
            errs.append(f"fuse_daemon.c 出现 {bad} —— 访问判定必须只在 fw_acl.c")
    # 每个 VFS_SETUP_CORE* 都必须带 ACL 操作种类（宏展开保证），抽查关键回调
    for fn, op in (("vfs_create", "NSP_ACL_OP_CREATE"), ("vfs_mkdir", "NSP_ACL_OP_MKDIR"),
                   ("vfs_unlink", "NSP_ACL_OP_DELETE"), ("vfs_rmdir", "NSP_ACL_OP_RMDIR"),
                   ("vfs_rename", "NSP_ACL_OP_RENAME_SRC"), ("vfs_mknod", "NSP_ACL_OP_MKNOD"),
                   ("vfs_chmod", "NSP_ACL_OP_SETATTR"), ("vfs_opendir", "NSP_ACL_OP_OPENDIR")):
        idx = src.find("static int " + fn + "(")
        if idx < 0:
            errs.append(f"找不到回调 {fn}")
            continue
        if op not in src[idx:idx + 900]:
            errs.append(f"{fn} 未接入 {op}（回调必须把操作种类交给 fw_route）")
    return errs


def main():
    for path in (DRIVER, SOURCE):
        if not os.path.exists(path):
            print(f"缺少源文件 {path}", file=sys.stderr)
            return 1

    errs = static_contract()
    if errs:
        for e in errs:
            print("❌ " + e, file=sys.stderr)
        return 1
    print("静态契约：ACL 唯一执行点 / 回调操作种类注入 ✔")

    with tempfile.TemporaryDirectory(prefix="fwacl_build_") as tmpdir:
        exe = os.path.join(tmpdir, "fw_acl_driver")
        cmd = [
            *shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Wno-unused-parameter", "-Wno-unused-function",
            "-I", os.path.join(ROOT, "include"),
            "-I", os.path.join(ROOT, "src", "core"),
            "-I", os.path.join(ROOT, "src", "config"),
            "-I", os.path.join(ROOT, "src", "daemon"),
            DRIVER, "-o", exe,
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
            print(f"fw_acl 驱动超时（>{RUN_TIMEOUT}s）", file=sys.stderr)
            return 1

    print(run.stdout, end="")
    if run.returncode != 0 or "❌" in run.stdout:
        print("访问控制判定表测试失败", file=sys.stderr)
        return 1
    print("访问控制判定表测试通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
