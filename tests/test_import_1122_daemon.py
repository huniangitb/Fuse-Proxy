#!/usr/bin/env python3
"""1122 daemon 导入回归：原样函数直编 + 私有临时 IO，无 FUSE/挂载/设备。

FW_RULES_SRC / FUSE_DAEMON_SRC 可指向旧源码；不是在附件树执行脚本。
路由、ACL xattr 与日志是受控边界；补父 guard 和属性收尾链接真实 common.c。
不证明内核 lookup/bind、SELinux 或完整 fw_route 权限引擎（需后续授权 L1/L4）。
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def extract(text, signature, optional=False):
    start = text.find(signature)
    if start < 0:
        if optional:
            return ""
        raise ValueError(f"找不到实际函数: {signature}")
    end = text.find("\n}\n", start)
    if end < 0:
        raise ValueError(f"找不到函数结束: {signature}")
    return text[start:end + 3]


def run(command, timeout):
    result = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result.returncode


def main():
    cc = shlex.split(os.environ.get("CC") or "cc")
    if not cc or not shutil.which(cc[0]):
        print("缺少 C 编译器：SKIP", file=sys.stderr)
        return 77
    rules = Path(os.environ.get("FW_RULES_SRC") or ROOT / "src/daemon/fw_rules.c").read_text()
    daemon = Path(os.environ.get("FUSE_DAEMON_SRC") or ROOT / "src/daemon/fuse_daemon.c").read_text()
    source = "\n".join([
        extract(rules, "static bool br_path_android_passthrough("),
        extract(rules, "static void br_ensure_sandbox_dir("),
        extract(daemon, "static void chmod_acl_drop_note(", optional=True),
        "#define mknod import_mknod\n#define lgetxattr import_lgetxattr",
        extract(daemon, "static int vfs_mknod("),
        extract(daemon, "static int vfs_chmod("),
        "#undef mknod\n#undef lgetxattr",
    ])
    fixture = (ROOT / "tests/fixtures/import_1122_daemon_driver.c").read_text()
    if fixture.count("/* ACTUAL_FUNCTIONS */") != 1:
        raise ValueError("函数插入点必须唯一")
    with tempfile.TemporaryDirectory(prefix="nsp_import_1122_") as tmp:
        tmp = Path(tmp)
        driver, common, exe = tmp / "driver.c", tmp / "common.o", tmp / "driver"
        driver.write_text(fixture.replace("/* ACTUAL_FUNCTIONS */", source))
        flags = ["-std=c23", "-O1", "-Wall", "-Wextra", "-Werror", "-ffunction-sections",
                 "-fdata-sections", "-I" + str(ROOT / "include")]
        # common 的日志实现改名，保留其真实 FS/guard/attrs；driver 只计 callback 日志。
        # common.c 的 O1 告警含既有 log_batch_end format-truncation；只对该 TU 豁免。
        rc = run(cc + flags + ["-Wno-format-truncation", "-Dlog_internal=import_common_log_internal", "-c",
                 str(ROOT / "src/core/common.c"), "-o", str(common)], 30)
        if rc:
            return rc
        rc = run(cc + flags + [str(driver), str(common), "-pthread", "-Wl,--gc-sections",
                 "-Wl,--wrap=common_mkdir_within_storage", "-Wl,--wrap=access",
                 "-Wl,--wrap=open", "-Wl,--wrap=openat", "-Wl,--wrap=mkdirat",
                 "-Wl,--wrap=fchown", "-Wl,--wrap=fchmod", "-o", str(exe)], 30)
        if rc:
            return rc
        return run([str(exe), str(tmp)], 15)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"1122 daemon 回归失败: {error}", file=sys.stderr)
        sys.exit(1)
