#!/usr/bin/env python3
"""L0: real fw_pkg.c bounded I/O gates; no mount/device/child/network.

PKG_CACHE_SRC can point to an old fw_pkg.c for discrimination.
PKG_CACHE_OUTPUT_DIR retains compile/probe evidence (otherwise private TemporaryDirectory).
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(directory):
    cc = shlex.split(os.environ.get("CC", "cc"))
    if not cc or not shutil.which(cc[0]):
        print("SKIP: C compiler unavailable")
        return 77
    source = Path(os.environ.get("PKG_CACHE_SRC", ROOT / "src/daemon/fw_pkg.c")).resolve()
    binary = directory / "pkg-cache-isolation"
    command = cc + ["-std=c23", "-DTARGET_GNU=1", "-Wall", "-Wextra", "-Werror",
                    "-ffunction-sections", "-fdata-sections", "-I" + str(ROOT / "include"),
                    "-I" + str(ROOT / "src/daemon"), str(source),
                    str(ROOT / "tests/fixtures/pkg_cache_isolation.c"), "-pthread",
                    "-Wl,--gc-sections", "-Wl,--wrap=fopen", "-Wl,--wrap=fgets", "-Wl,--wrap=fclose",
                    "-o", str(binary)]
    compiled = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    (directory / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        print("FAIL: compile", compiled.returncode)
        return 1
    failed = 0
    count = 0
    for api in ("priv", "pkg"):
        for mode in ("basic", "cold", "hot", "refresh", "refresh-unclaimed", "double-refresh", "same", "collision", "aba"):
            for edge in (("open",) if mode == "basic" else ("open", "read", "close")):
                name = "-".join((api, mode, edge))
                try:
                    result = subprocess.run([str(binary), api, mode, edge, str(directory / (name + ".list"))],
                                            cwd=ROOT, capture_output=True, text=True, timeout=5)
                    text = result.stdout + result.stderr + f"exit={result.returncode}\n"
                    failed += result.returncode != 0
                except subprocess.TimeoutExpired as exc:
                    # subprocess.run kills AND waits its direct child; fixture creates no children.
                    text = f"FAIL: driver exceeded 5s ({exc})\n"
                    failed += 1
                (directory / (name + ".log")).write_text(text)
                print(text, end="")
                count += 1
    print(f"pkg_cache_isolation: {count - failed}/{count} PASS ({source})")
    return 1 if failed else 0


def main():
    retained = os.environ.get("PKG_CACHE_OUTPUT_DIR")
    if retained:
        directory = Path(retained).resolve()
        directory.mkdir(parents=True, exist_ok=True)
        return run(directory)
    with tempfile.TemporaryDirectory(prefix="nsp-pkg-cache-") as private:
        return run(Path(private))


if __name__ == "__main__":
    sys.exit(main())
