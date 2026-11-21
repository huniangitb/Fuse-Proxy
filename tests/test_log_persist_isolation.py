#!/usr/bin/env python3
"""L0: real log_monitor callbacks, full pipe, format/rotation and failure checks.

LOG_MONITOR_SRC selects an old source copy for discriminating-red checks.
CC, LOG_PERSIST_TEST_SANITIZERS (default address,undefined; empty disables),
LOG_PERSIST_TEST_CFLAGS/LDFLAGS, ASAN_OPTIONS and UBSAN_OPTIONS are overridable.
No service socket, mount, device, network or global log path is used.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "BASH_ENV")}
    env["PATH"] = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin"
    default_cc = shutil.which("clang", path=env["PATH"]) or "cc"
    cc = shlex.split(env.get("CC", default_cc))
    if not cc or not shutil.which(cc[0], path=env["PATH"]):
        print("SKIP: C compiler unavailable")
        return 77
    source = Path(env.get("LOG_MONITOR_SRC", ROOT / "src/log/log_monitor.c")).resolve()
    sanitizers = env.get("LOG_PERSIST_TEST_SANITIZERS", "address,undefined")
    env.setdefault("ASAN_OPTIONS", "detect_leaks=1:abort_on_error=1")
    env.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
    with tempfile.TemporaryDirectory(prefix="nsp-log-persist-") as tmp:
        private = Path(tmp)
        binary = private / "probe"
        compile_cmd = [*cc, "-std=gnu2x", "-O1", "-g", "-ffunction-sections",
                       "-fdata-sections", "-fno-omit-frame-pointer",
                       f'-DLOG_MONITOR_SOURCE="{source}"', "-I", str(ROOT / "include"),
                       str(ROOT / "tests/fixtures/log_persist_isolation.c"),
                       str(ROOT / "src/core/nsp_util.c"), "-pthread", "-Wl,--gc-sections",
                       "-Wl,--wrap=open", "-Wl,--wrap=write", "-Wl,--wrap=unlink",
                       "-Wl,--wrap=rename", "-Wl,--wrap=close", "-Wl,--wrap=pthread_create"]
        if sanitizers:
            compile_cmd += [f"-fsanitize={sanitizers}"]
        compile_cmd += shlex.split(env.get("LOG_PERSIST_TEST_CFLAGS", ""))
        compile_cmd += shlex.split(env.get("LOG_PERSIST_TEST_LDFLAGS", ""))
        compile_cmd += ["-o", str(binary)]
        try:
            compiled = subprocess.run(compile_cmd, cwd=ROOT, env=env, timeout=30,
                                      text=True, capture_output=True)
            print(compiled.stdout, end="")
            print(compiled.stderr, end="")
            if compiled.returncode:
                return 1
            for case in ("isolation", "partial", "zero", "start-fail", "clear", "lazy", "format", "rotation"):
                case_dir = private / case
                case_dir.mkdir()
                result = subprocess.run([str(binary), str(case_dir), case], cwd=ROOT,
                                        env=env, timeout=8, text=True, capture_output=True)
                print(result.stdout, end="")
                print(result.stderr, end="")
                print(f"fixture {case} exit={result.returncode}")
                if result.returncode:
                    return 1
        except subprocess.TimeoutExpired as exc:
            print(f"FAIL finite compile/probe timeout: {exc.cmd}")
            return 1
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
