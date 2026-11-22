#!/usr/bin/env python3
"""1122 injector: actual production functions, mocked proc/ns data, no mounts.

INJECTOR_SRC / IPC_SERVER_SRC / NS_UTILS_SRC accept historical source copies.
The retry fixture links the actual retry_queue.c; async callback keeps the real
fork/pipe/waitpid matrix (including late exit). Compile/run have hard deadlines.
"""
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests/fixtures"


def masked(text):
    tokens = r"""/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"""
    return re.sub(tokens, lambda m: " " * len(m.group()), text, flags=re.S)


def function(text, name, optional=False):
    clean = masked(text)
    match = re.search(r"^[^\n;{}]*\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", clean, re.M)
    if not match:
        if optional:
            return ""
        raise ValueError(f"production function missing: {name}")
    start = clean.index("{", match.start())
    depth = 0
    for end in range(start, len(clean)):
        depth += (clean[end] == "{") - (clean[end] == "}")
        if depth == 0:
            return text[match.start():end + 1]
    raise ValueError(f"unterminated production function: {name}")


def startup_block(text):
    clean = masked(text)
    pos = clean.index("if (g_pending_startup_scan)")
    start = clean.index("{", pos)
    depth = 0
    for end in range(start, len(clean)):
        depth += (clean[end] == "{") - (clean[end] == "}")
        if depth == 0:
            return text[pos:end + 1]
    raise ValueError("unterminated startup block")


def run(command, timeout):
    print("$", shlex.join(map(str, command)), flush=True)
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    print(result.stdout + result.stderr, end="", flush=True)
    print(f"exit={result.returncode}", flush=True)
    return result.returncode


def main():
    injector = Path(os.environ.get("INJECTOR_SRC", ROOT / "src/injector/injector.c"))
    ipc = Path(os.environ.get("IPC_SERVER_SRC", ROOT / "src/injector/ipc_server.c"))
    ns = Path(os.environ.get("NS_UTILS_SRC", ROOT / "src/injector/ns_utils.c"))
    print(f"sources: injector={injector} ipc={ipc} ns={ns}", flush=True)
    failures = 0
    with tempfile.TemporaryDirectory(prefix="import_1122_injector_") as tmp:
        tmp = Path(tmp)
        inj_text, ipc_text = injector.read_text(), ipc.read_text()
        # The exact IPC argument declaration accompanies the exact thread body.
        arg = re.search(r"typedef struct \{[^{}]*\} IpcPostArg;", ipc_text, re.S)
        if not arg:
            raise ValueError("IpcPostArg declaration missing")
        target_text = (ROOT / "src/injector/inject_target.c").read_text()
        # Snapshot layout is extracted too: never duplicate a production struct in the fixture.
        identity = re.search(r"typedef struct \{[^{}]*\} RetryMountIdentity;", inj_text, re.S)
        funcs = ([identity.group()] if identity else []) + [function(target_text, "is_isolated_uid")]
        funcs += [function(inj_text, n, optional=True) for n in
                  ("retry_proc_identity", "retry_mount_ns_ready")]
        funcs += [function(inj_text, "retry_pending_mounts"), arg.group(),
                  function(ipc_text, "ipc_elapsed_ms"), function(ipc_text, "ipc_post_mount_thread")]
        (tmp / "production.inc").write_text("\n\n".join(funcs))
        (tmp / "startup.inc").write_text(startup_block(inj_text))
        cc = shlex.split(os.environ.get("CC", "cc"))
        flags = ["-std=c23", "-O1", "-g", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
                 "-I", str(ROOT / "include"),
                 "-I", str(ROOT / "src/injector"), "-I", str(tmp), "-pthread",
                 "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"]
        exe = tmp / "import_injector"
        rc = run(cc + flags + [str(FIXTURES / "import_1122_injector.c"),
                               str(ROOT / "src/injector/retry_queue.c"), "-o", str(exe)], 30)
        failures += bool(rc)
        if rc == 0:
            failures += bool(run([str(exe)], 10))
        exe = tmp / "async_reaped"
        rc = run(cc + flags + [str(FIXTURES / "async_reaped.c"), str(ns), "-o", str(exe)], 30)
        failures += bool(rc)
        if rc == 0:
            failures += bool(run([str(exe)], 20))
    print(f"1122 injector groups failed={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
