#!/usr/bin/env python3
"""L0: real fw_pkg/uid_map ownership; uid.map reload vs in-flight resolve.

PKG_MAP_SRC can point to an old fw_pkg.c for discrimination.
PKG_MAP_OUTPUT_DIR retains compile/probe evidence (otherwise private TemporaryDirectory).
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MODES = ("serial", "reload-race", "shutdown-race", "load-io", "stress")


def run(directory):
    cc = shlex.split(os.environ.get("CC", "cc"))
    if not cc or not shutil.which(cc[0]):
        print("SKIP: C compiler unavailable")
        return 77
    source = Path(os.environ.get("PKG_MAP_SRC", ROOT / "src/daemon/fw_pkg.c")).resolve()
    binary = directory / "pkg-map-lifetime"
    command = cc + ["-std=c23", "-DTARGET_GNU=1", "-Wall", "-Wextra", "-Werror",
                    "-ffunction-sections", "-fdata-sections",
                    "-I" + str(ROOT / "include"), "-I" + str(ROOT / "src/daemon"),
                    str(source),
                    str(ROOT / "src/core/uid_map.c"), str(ROOT / "src/core/fast_pid.c"),
                    str(ROOT / "tests/fixtures/pkg_map_lifetime.c"), "-pthread",
                    "-Wl,--gc-sections", "-Wl,--wrap=fopen", "-Wl,--wrap=uid_map_lookup",
                    "-Wl,--wrap=free", "-o", str(binary)]
    compiled = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
    (directory / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        print("FAIL: compile", compiled.returncode)
        return 1
    failed = 0
    for mode in MODES:
        target = directory / (mode + ".map")
        try:
            result = subprocess.run([str(binary), mode, str(target)], cwd=ROOT,
                                    capture_output=True, text=True, timeout=20)
            text = result.stdout + result.stderr + f"exit={result.returncode}\n"
            failed += result.returncode != 0
        except subprocess.TimeoutExpired as exc:
            # subprocess.run kills AND waits its direct child; fixture only joins its own threads.
            text = f"FAIL: driver exceeded 20s ({exc})\n"
            failed += 1
        (directory / (mode + ".log")).write_text(text)
        print(text, end="")
    print(f"pkg_map_lifetime: {len(MODES) - failed}/{len(MODES)} PASS ({source})")
    return 1 if failed else 0


def main():
    retained = os.environ.get("PKG_MAP_OUTPUT_DIR")
    if retained:
        directory = Path(retained).resolve()
        directory.mkdir(parents=True, exist_ok=True)
        return run(directory)
    with tempfile.TemporaryDirectory(prefix="nsp-pkg-map-") as private:
        return run(Path(private))


if __name__ == "__main__":
    sys.exit(main())
