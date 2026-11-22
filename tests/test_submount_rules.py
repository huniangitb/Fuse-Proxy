#!/usr/bin/env python3
"""L0 submount veto: compile actual mount_manager.c and run both callers.

No mounts/FUSE I/O: only external facts and side effects are stubbed. The user
layer parser is linked from common.c, not copied. MOUNT_MANAGER_SRC selects a
frozen old source for discrimination; the adapter only handles its old signature.
Dynamic rules and generic sandbox-child routing are deliberately out of scope.
"""
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests/fixtures/submount_rules_driver.c"
SOURCE = Path(os.environ.get("MOUNT_MANAGER_SRC", ROOT / "src/injector/mount_manager.c")).resolve()


def main():
    source = SOURCE.read_text(encoding="utf-8")
    signature = re.search(r"static bool submount_conflicts_with_rules_locked\s*\(([^)]*)\)", source)
    if signature is None:
        print("missing production submount conflict helper", file=sys.stderr)
        return 1
    legacy = "const char* pkg" in signature.group(1)
    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="submount_rules_") as tmp:
        exe = Path(tmp) / "submount_rules_driver"
        command = cc + shlex.split(os.environ.get("CFLAGS", "")) + [
            "-std=c23", "-O1", "-Wall", "-Wextra", "-D_GNU_SOURCE",
            "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections", "-pthread",
            "-I", str(ROOT / "include"), "-I", str(ROOT / "src/core"),
            "-I", str(ROOT / "src/injector"),
            f'-DMOUNT_MANAGER_SRC="{SOURCE}"', f"-DSUBMOUNT_LEGACY_HELPER={int(legacy)}",
            str(DRIVER), str(ROOT / "src/core/common.c"), str(ROOT / "src/core/nsp_util.c"),
            "-o", str(exe),
        ]
        try:
            build = subprocess.run(command, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            print("compile timed out after 120s", file=sys.stderr)
            return 1
        if build.returncode:
            sys.stderr.write("compile failed:\n" + build.stdout + build.stderr)
            return 1
        if build.stderr:
            sys.stderr.write(build.stderr)
        try:
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            print("driver timed out after 15s", file=sys.stderr)
            return 1
        sys.stdout.write(run.stdout)
        sys.stderr.write(run.stderr)
        return run.returncode


if __name__ == "__main__":
    sys.exit(main())
