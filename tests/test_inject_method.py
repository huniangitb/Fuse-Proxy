#!/usr/bin/env python3
"""
注入方法 v1/v2/v3 判定测试
===========================================
injector 本体仅 Android 交叉构建，GNU 下经测试驱动 build_gnu/global_replace_ctl
验证注入方法语义（不经 FUSE、不需 root）：

  method  <v1|v2|v3>                       打印派生标志 global_replace / restore_nontarget
  is-target <v1|v2|v3> <conf> <pkg> <uid> <pid> <ipc0|1>
            装载配置后跑 inject_target.c 的 is_target_app_locked，输出 target=0/1

覆盖：
  v1/v2 按 GLOBAL_INJECT / SKIP_SYSTEM_APPS 判定（v2 额外承担非目标应用还原）；
  v3 忽略这两个全局参数——含系统应用在内一律为目标（默认全局挂载）；
  v3 下应用段/类别段头显式 OFF、隔离进程与 zygote 排除仍然生效；
  非法方法值直接拒绝（rc=2），不静默回退 v1。
"""
import os, sys, time, subprocess, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CTL = os.environ.get("GLOBAL_REPLACE_CTL") or os.path.join(ROOT, "build_gnu", "global_replace_ctl")

PASS = 0
FAIL = 0
ERRORS = []


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def ok(desc):
    global PASS
    PASS += 1
    log(f"  ✅ {desc}")


def fail(desc, detail=""):
    global FAIL
    FAIL += 1
    log(f"  ❌ {desc}: {detail}")
    ERRORS.append((desc, detail))


def ctl(*args):
    return subprocess.run([CTL, *args], capture_output=True, text=True)


def write_conf(dirpath, name, body):
    path = os.path.join(dirpath, name)
    with open(path, "w") as f:
        f.write(body)
    return path


def expect(desc, got, want):
    if got == want:
        ok(f"{desc} == {want}")
    else:
        fail(desc, f"期望 {want}，实际 {got}")


def is_target(conf, method, pkg, uid, pid=4321, ipc=1):
    """返回 (rc, target 值)；target 非 0/1 时原样返回。"""
    r = ctl("is-target", method, conf, pkg, str(uid), str(pid), str(ipc))
    if r.returncode != 0:
        return r.returncode, None
    out = r.stdout.strip()
    for tok in out.split():
        if tok.startswith("target="):
            return 0, int(tok.split("=", 1)[1])
    return 0, None


def main():
    if not os.path.isfile(CTL):
        log(f"SKIP: 找不到测试驱动 {CTL}（先执行 scripts/build.sh）")
        return 0

    tmp = tempfile.mkdtemp(prefix="inject_method_test_")
    # A：GLOBAL_INJECT ON / SKIP_SYSTEM_APPS ON + 应用段显式 OFF
    conf_on = write_conf(tmp, "on.conf",
                         "[GLOBAL]\nGLOBAL_INJECT ON\nSKIP_SYSTEM_APPS ON\n\n"
                         "[com.off.app] OFF\n")
    # B：GLOBAL_INJECT OFF
    conf_gi_off = write_conf(tmp, "gi_off.conf",
                             "[GLOBAL]\nGLOBAL_INJECT OFF\nSKIP_SYSTEM_APPS ON\n")
    # C：GLOBAL_INJECT ON / SKIP_SYSTEM_APPS OFF
    conf_noskip = write_conf(tmp, "noskip.conf",
                             "[GLOBAL]\nGLOBAL_INJECT ON\nSKIP_SYSTEM_APPS OFF\n")
    # D：类别段 [SYSTEM_APPS] OFF
    conf_cat_off = write_conf(tmp, "cat_off.conf",
                              "[GLOBAL]\nGLOBAL_INJECT ON\nSKIP_SYSTEM_APPS ON\n\n"
                              "[SYSTEM_APPS] OFF\n")

    SYS_UID, NORM_UID, OFF_UID, ISOLATED_UID = 9999, 10123, 10124, 99000

    log("场景1: method 派生标志")
    for method, gr, rn in (("v1", 0, 0), ("v2", 1, 1), ("v3", 1, 0)):
        r = ctl("method", method)
        if r.returncode != 0:
            fail(f"method {method}", f"rc={r.returncode} {r.stderr.strip()}")
            continue
        tokens = dict(t.split("=", 1) for t in r.stdout.split() if "=" in t)
        expect(f"method {method} global_replace", int(tokens.get("global_replace", -1)), gr)
        expect(f"method {method} restore_nontarget", int(tokens.get("restore_nontarget", -1)), rn)
    r = ctl("method", "v4")
    expect("非法方法值 rc", r.returncode, 2)

    log("场景2: GLOBAL_INJECT ON / SKIP_SYSTEM_APPS ON")
    for method in ("v1", "v2"):
        expect(f"{method} 系统应用(uid {SYS_UID})",
               is_target(conf_on, method, "com.sys.app", SYS_UID)[1], 0)
        expect(f"{method} 普通应用",
               is_target(conf_on, method, "com.norm.app", NORM_UID)[1], 1)
        expect(f"{method} 应用段 OFF",
               is_target(conf_on, method, "com.off.app", OFF_UID)[1], 0)
    # v3：忽略 SKIP_SYSTEM_APPS（系统应用入列），但段头 OFF 仍生效
    expect("v3 系统应用（忽略 SKIP_SYSTEM_APPS）",
           is_target(conf_on, "v3", "com.sys.app", SYS_UID)[1], 1)
    expect("v3 普通应用", is_target(conf_on, "v3", "com.norm.app", NORM_UID)[1], 1)
    expect("v3 应用段 OFF 仍生效", is_target(conf_on, "v3", "com.off.app", OFF_UID)[1], 0)

    log("场景3: GLOBAL_INJECT OFF")
    for method in ("v1", "v2"):
        expect(f"{method} 系统应用", is_target(conf_gi_off, method, "com.sys.app", SYS_UID)[1], 0)
        expect(f"{method} 普通应用", is_target(conf_gi_off, method, "com.norm.app", NORM_UID)[1], 0)
    # v3：忽略 GLOBAL_INJECT
    expect("v3 系统应用（忽略 GLOBAL_INJECT）",
           is_target(conf_gi_off, "v3", "com.sys.app", SYS_UID)[1], 1)
    expect("v3 普通应用（忽略 GLOBAL_INJECT）",
           is_target(conf_gi_off, "v3", "com.norm.app", NORM_UID)[1], 1)

    log("场景4: GLOBAL_INJECT ON / SKIP_SYSTEM_APPS OFF")
    expect("v1 系统应用（未跳过）", is_target(conf_noskip, "v1", "com.sys.app", SYS_UID)[1], 1)
    expect("v2 系统应用（未跳过）", is_target(conf_noskip, "v2", "com.sys.app", SYS_UID)[1], 1)

    log("场景5: 类别段 [SYSTEM_APPS] OFF（v3 也生效）")
    expect("v1 系统应用", is_target(conf_cat_off, "v1", "com.sys.app", SYS_UID)[1], 0)
    expect("v3 系统应用（类别段 OFF 仍生效）",
           is_target(conf_cat_off, "v3", "com.sys.app", SYS_UID)[1], 0)
    expect("v3 普通应用（不属该类别）",
           is_target(conf_cat_off, "v3", "com.norm.app", NORM_UID)[1], 1)

    log("场景6: v3 的隔离进程 / zygote 排除照旧")
    expect("v3 隔离进程 uid",
           is_target(conf_gi_off, "v3", "com.isolated.app", ISOLATED_UID)[1], 0)
    expect("v3 zygote 进程", is_target(conf_gi_off, "v3", "zygote64", NORM_UID)[1], 0)

    log("场景7: 扫描路径（ipc=0，非 zygote 子进程）")
    expect("v1 扫描路径", is_target(conf_on, "v1", "com.norm.app", NORM_UID, ipc=0)[1], 0)
    expect("v3 扫描路径", is_target(conf_on, "v3", "com.norm.app", NORM_UID, ipc=0)[1], 0)

    log(f"\n结果: {PASS} 通过, {FAIL} 失败")
    for d, e in ERRORS:
        log(f"  ❌ {d}: {e}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
