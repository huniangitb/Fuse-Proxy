#!/usr/bin/env python3
"""直编真实 fw_pkg，验证 appops 有界查询、锁外执行和缓存。

FW_PKG_SRC 可指定旧源码复验：A/B/D 必须明确报父 deadline/等待阶段，
C 必须报八次失败查询未冷却。fixture 只在私有 user/mount/pid namespace
的 tmpfs+pivot_root 下创建。read/waitpid/mutex 均未 mock。
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = next(parent for parent in HERE.parents if (parent / "src/daemon/fw_pkg.c").is_file())
FIXTURES = HERE if (HERE / "fw_pkg_appops_driver.c").is_file() else HERE / "fixtures"
CASES = ("A", "B", "C", "D", "E", "allow", "deny", "installer", "uidmode", "ttl", "failure-ttl", "generation",
         "gen-replaced", "gen-unclaimed", "collision-deny", "collision-allow",
         "collision-aba", "enoent-recovery", "shutdown-idle")


def snapshot():
    return Path("/proc/self/mountinfo").read_bytes()


def children_and_threads(pid):
    found = set()
    try:
        tasks = list(Path(f"/proc/{pid}/task").iterdir())
    except FileNotFoundError:
        return found
    for task in tasks:
        if int(task.name) != pid:
            found.add(int(task.name))
        try:
            child_ids = (task / "children").read_text().split()
        except FileNotFoundError:
            continue
        for value in child_ids:
            child = int(value)
            if child not in found:
                found.add(child)
                found.update(children_and_threads(child))
    return found


def stop_namespace(process, driver):
    observed = children_and_threads(process.pid)
    inits = []
    for pid in observed:
        try:
            if os.readlink(f"/proc/{pid}/exe") == str(driver) and int(Path(f"/proc/{pid}/status").read_text().split("Tgid:")[1].split()[0]) == pid:
                inits.append(pid)
        except FileNotFoundError:
            continue
    for pid in inits:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if not inits:
        os.killpg(process.pid, signal.SIGKILL)
    try:
        out, err = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        out, err = process.communicate(timeout=2)
    survivors = [pid for pid in sorted(observed) if Path(f"/proc/{pid}").exists()]
    return out, err, inits, survivors


def run_case(stage, driver, cmd, case, environment):
    location = stage / case
    location.mkdir()
    root = location / "root"
    root.mkdir()
    before = snapshot()
    (location / "host-before.mountinfo").write_bytes(before)
    argv = ["unshare", "--user", "--map-root-user", "--mount", "--pid", "--fork", "--kill-child=KILL",
            str(driver), case, str(root), str(cmd)]
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env=environment, start_new_session=True)
    timed_out = False
    inits, survivors = [], []
    began = time.monotonic()
    try:
        try:
            out, err = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            timed_out = True
            out, err, inits, survivors = stop_namespace(process, driver)
    finally:
        if process.poll() is None:
            stop_namespace(process, driver)
    after = snapshot()
    (location / "host-after.mountinfo").write_bytes(after)
    (location / "stdout.log").write_text(out)
    (location / "stderr.log").write_text(err)
    equal = before == after
    root_empty = not any(root.iterdir())
    if timed_out:
        phase = next((line for line in reversed(out.splitlines()) if line.startswith("PHASE")), "PHASE fixture/setup")
        failure = f"parent_deadline_2000ms {phase}"
    elif process.returncode:
        failure = next((line for line in out.splitlines() if line.startswith("FAIL ")), err.strip() or f"driver_exit={process.returncode}")
    elif f"PASS case={case}" not in out:
        failure = "missing_driver_pass"
    else:
        failure = ""
    ok = not failure and equal and root_empty and not survivors
    result = {"case": case, "pass": ok, "exit": process.returncode, "timeout": timed_out,
              "failure": failure, "elapsed_ms": (time.monotonic()-began)*1000,
              "host_mountinfo_equal": equal, "host_root_empty": root_empty,
              "namespace_init_killed": inits, "survivors": survivors, "argv": argv}
    (location / "result.json").write_text(json.dumps(result, indent=2)+"\n")
    print(f"{'PASS' if ok else 'FAIL'} {case}: {failure or 'bounded/cache contract'}; "
          f"mountinfo_equal={equal} survivors={survivors}", flush=True)
    return result


def main():
    output_root = ROOT / ".cache/test-appops-bounded"
    output_root.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="run-", dir=output_root))
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("BASH_ENV", None)
    before = snapshot()
    (stage / "host-before.mountinfo").write_bytes(before)
    source = Path(os.environ.get("FW_PKG_SRC", ROOT / "src/daemon/fw_pkg.c")).resolve()
    driver, cmd = stage / "appops-driver", stage / "cmd-fixture"
    compiler = shlex.split(os.environ.get("CC", "cc"))
    commands = [compiler + ["-std=c23", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
                str(FIXTURES / "appops_cmd_fixture.c"), "-o", str(cmd)],
                compiler + ["-std=c23", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-DTARGET_GNU=1",
                "-ffunction-sections", "-fdata-sections", "-I", str(ROOT / "include"),
                "-I", str(ROOT / "src/daemon"), str(FIXTURES / "fw_pkg_appops_driver.c"), str(source),
                "-pthread", "-Wl,--gc-sections", "-Wl,--wrap=clock_gettime", "-Wl,--wrap=posix_spawn",
                "-Wl,--wrap=uid_map_load", "-Wl,--wrap=pthread_join", "-o", str(driver)]]
    compiled = []
    for argv in commands:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, env=environment, timeout=60)
        compiled.append({"argv": argv, "exit": result.returncode, "output": result.stdout})
        (stage / "compile.json").write_text(json.dumps(compiled, indent=2)+"\n")
        if result.returncode:
            print(f"FAIL compile: {result.stdout}\nArtifacts: {stage}")
            return 1
    probe = subprocess.run(["unshare", "--user", "--map-root-user", "--mount", "--pid", "--fork", "true"],
                           capture_output=True, text=True, env=environment, timeout=2)
    if probe.returncode:
        print(f"SKIP user/mount/pid namespace unavailable: {probe.stderr.strip()}")
        return 77
    results = [run_case(stage, driver, cmd, case, environment) for case in CASES]
    after = snapshot()
    (stage / "host-after.mountinfo").write_bytes(after)
    equal = before == after
    summary = {"fw_pkg_source": str(source), "fw_pkg_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
               "results": results, "host_mountinfo_equal": equal,
               "passed": sum(result["pass"] for result in results), "total": len(results)}
    (stage / "summary.json").write_text(json.dumps(summary, indent=2)+"\n")
    print(f"Result: {summary['passed']}/{len(results)}, host_mountinfo_equal={equal}\nArtifacts: {stage}")
    return 0 if equal and all(result["pass"] for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
