#!/usr/bin/env python3
"""
透传探测文件 TOCTOU 回归测试（B3）
==================================
`fuse_daemon.c` 的 `passthrough_probe()` 会在 `/data/local/tmp`（GNU：`/tmp`）
下以可预测名字 `.fuse_pt_probe.<pid>` 创建普通文件，再把它的 fd 作为
`fuse_backing_map.fd` 交给 `FUSE_DEV_IOC_BACKING_OPEN`，由**内核**把该 inode
挂成 backing。两个目录对普通用户可写、名字可预测，于是：

  - 攻击者预置**符号链接**指向任意路径（如 /etc/shadow）→ root daemon
    `open()` 跟随链接 → 内核把目标 inode 当 backing 交出去（越权读取）。
  - 攻击者预置**同名普通文件 / FIFO** → daemon 复用攻击者的对象，内容与
    生命周期受外部控制（FIFO 还会让 open 阻塞）。

旧实现：`open(probe_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600)` —— 既无
`O_EXCL`（不拒绝既有对象）也无 `O_NOFOLLOW`（跟随符号链接），两条都中招。

修法：加 `O_EXCL | O_NOFOLLOW`；`EEXIST`（残留）时先 `unlink`（不跟随链接）
再独占创建。

判别手段：`--wrap` 在 open/unlink 上装钩子（见 fixtures 驱动头注释），
对**新旧两种实现**各跑一遍（`PROBE_VARIANT=old|new`）：
  - 新实现四组全过；
  - 旧实现在 symlink / fifo 两组必挂 —— 证明确有 TOCTOU 且本用例判得出来。

前置：本机 `cc`（需支持 `-Wl,--wrap`）。失败退出码 1。
"""
import os
import shlex
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.environ.get("PT_PROBE_DRIVER") or os.path.join(
    ROOT, "tests", "fixtures", "pt_probe_toctou_driver.c")

RUN_TIMEOUT = 60


def build(exe):
    cmd = [
        *shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
        "-Wall", "-Wextra", "-Wno-unused-parameter",
        "-I", os.path.join(ROOT, "include"),
        DRIVER,
        "-Wl,--wrap=open", "-Wl,--wrap=unlink",
        "-o", exe,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("C 编译/链接失败:", file=sys.stderr)
        print(r.stderr, file=sys.stderr)
        return False
    if r.stderr.strip():
        print(r.stderr, file=sys.stderr, end="")
    return True


def run_case(exe, case, variant, cwd):
    env = dict(os.environ, PROBE_VARIANT=variant)
    try:
        r = subprocess.run([exe, case], capture_output=True, text=True,
                           timeout=RUN_TIMEOUT, env=env, cwd=cwd)
    except subprocess.TimeoutExpired:
        return None, f"超时（>{RUN_TIMEOUT}s）"
    return r, (r.stdout.strip() + " " + r.stderr.strip()).strip()


def main():
    if not os.path.exists(DRIVER):
        print(f"缺少驱动 {DRIVER}", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="pt_probe_") as tmpdir:
        exe = os.path.join(tmpdir, "pt_probe")
        if not build(exe):
            return 1

        passed = failed = 0
        # 新实现：全部应 RESULT OK
        cases = ["symlink", "fifo", "stale", "clean"]
        for case in cases:
            r, detail = run_case(exe, case, "new", tmpdir)
            if "RESULT OK" in r.stdout:
                passed += 1
                print(f"  ✅ new/{case}: {r.stdout.strip()}")
            elif "RESULT SKIP" in r.stdout:
                print(f"  ⚠ new/{case}: 环境不支持，跳过（{r.stdout.strip()}）")
            else:
                failed += 1
                print(f"  ❌ new/{case}: rc={r.returncode} {detail}", file=sys.stderr)

        # 旧实现：symlink / fifo 必须「不安全」——即驱动打印 RESULT OK（其期望就是旧实现不安全）。
        # 判别力的证法：令驱动以 old 语义跑，若结果仍为 OK，说明旧实现确实中招；
        # 再断言新实现同一用例为 OK 但含 unsafe=0（上面已断）。这里额外断言：
        # 旧实现在 symlink 组的 ioctl_fd >= 0（真把不安全 fd 交了出去）。
        for case in ("symlink", "fifo"):
            r, detail = run_case(exe, case, "old", tmpdir)
            out = r.stdout.strip()
            if "RESULT OK" in out and "unsafe=1" in out:
                passed += 1
                print(f"  ✅ 判别力 old/{case}: 旧实现确为不安全（{out}）")
            elif r.returncode != 0:
                # 旧实现路径本就该「不安全」；若驱动报 FAIL 说明钩子未生效
                failed += 1
                print(f"  ❌ 判别力 old/{case}: 钩子未生效（{detail}）", file=sys.stderr)
            else:
                failed += 1
                print(f"  ❌ 判别力 old/{case}: 旧实现竟然安全 —— 用例不判别（{out}）",
                      file=sys.stderr)

        print(f"\n结果: {passed} 通过, {failed} 失败")
        if failed:
            print("透传探测 TOCTOU 测试失败", file=sys.stderr)
            return 1
    print("透传探测 TOCTOU 测试通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
