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

直编组（只需 cc，不依赖 build_gnu 产物；缺 cc/userns 时计为 gap）：
  tests/fixtures/ipc_binding.c  → 编入**实际** src/injector/ipc_server.c，
      校验 IPC 请求的身份绑定（R8）：自报 pid 不是对端进程、包名与
      /proc/<pid>/cmdline 不符、伪造目标/非目标包名、非 root 对端发 REPORT
      一律拒绝且 uid.map 原样、零派发；合法身份正对照通过。
      IPC_SERVER_SRC=<旧副本> 可复验判别性（旧实现四条全 ACK → 必失败）。
  tests/fixtures/async_reaped.c → 编入**实际** src/injector/ns_utils.c，
      用真实 fork/pipe/waitpid 覆盖异步挂载完成事件的「结果判定 vs 收尸」矩阵
      （R9）：failure/EOF + 主循环先收尸（ECHILD）两组必须 retries=1、
      removed=1，success+ECHILD 不得误重试。NS_UTILS_SRC=<旧副本> 可复验
      判别性（旧实现两组 0/0 → 必失败）。
"""
import os, re, shlex, shutil, sys, time, subprocess, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CTL = os.environ.get("GLOBAL_REPLACE_CTL") or os.path.join(ROOT, "build_gnu", "global_replace_ctl")

# 退出码约定（与 tests/run.py 一致）：0=通过 1=失败 77=环境不具备跳过(gap)
SKIP_RC = 77

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



# ─────────────────────────── 直编组（R8 / R9） ───────────────────────────

FIXTURES = os.path.join(ROOT, "tests", "fixtures")
# 两个平台根常量在副本头里定向替换（与 test_config_snapshot / test_cfg_reload_split
# 同一套路）：NSP_CONFIG_DIR → 临时 conf（uid.map 断言不碰系统配置根）；
# NSP_ANDROID_EMULATED_ROOT → 临时 emulated 目录（目标分支的
# access(/storage/emulated) 门在普通主机上不存在，私有化后判别确定）。
CONFIG_DIR_PAT = re.compile(r'^#define\s+NSP_CONFIG_DIR\s+"/var/fuse-proxy"\s*$', re.M)
EMU_ROOT_PAT = re.compile(r'^#define\s+NSP_ANDROID_EMULATED_ROOT\s+"/storage/emulated"\s*$', re.M)


def prepare_private_include(tmpdir):
    """复制 include/ 并私有化平台根常量。返回 (include 目录, conf, emulated, 替换数)。"""
    inc = os.path.join(tmpdir, "include")
    shutil.copytree(os.path.join(ROOT, "include"), inc)
    conf = os.path.join(tmpdir, "conf")
    emu = os.path.join(tmpdir, "emulated")
    os.makedirs(conf, exist_ok=True)
    os.makedirs(emu, exist_ok=True)
    path = os.path.join(inc, "nsp_constants.h")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    text, n1 = CONFIG_DIR_PAT.subn(lambda _m: '#define NSP_CONFIG_DIR "%s"' % conf, text, count=1)
    text, n2 = EMU_ROOT_PAT.subn(lambda _m: '#define NSP_ANDROID_EMULATED_ROOT "%s"' % emu,
                                 text, count=1)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return inc, conf, emu, n1 + n2


def build_fixture(tmpdir, out_name, fixture, sources):
    """cc 直编 fixture + 实际源码。返回 (exe, CompletedProcess)。"""
    cc = shlex.split(os.environ.get("CC", "cc"))
    exe = os.path.join(tmpdir, out_name)
    cmd = cc + [
        "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
        "-I", os.path.join(tmpdir, "include"),
        "-I", os.path.join(ROOT, "src", "injector"),
        os.path.join(FIXTURES, fixture),
    ] + list(sources) + ["-o", exe, "-pthread"]
    return exe, subprocess.run(cmd, capture_output=True, text=True)


def record_fixture_output(title, proc):
    """把夹具自身的 PASS/FAIL 行计入套件计数；无断言输出或非零退出也计失败。"""
    global PASS, FAIL
    text = (proc.stdout or "") + (proc.stderr or "")
    rows = 0
    fails = 0
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("PASS "):
            rows += 1
            PASS += 1
            log(f"  ✅ {title}: {s[5:]}")
        elif s.startswith("FAIL "):
            rows += 1
            fails += 1
            FAIL += 1
            ERRORS.append((f"{title}: {s[5:]}", "夹具输出见上"))
            log(f"  ❌ {title}: {s[5:]}")
    if rows == 0:
        FAIL += 1
        ERRORS.append((title, f"夹具无断言输出 rc={proc.returncode}"))
        log(f"  ❌ {title}: 夹具无断言输出（rc={proc.returncode}）")
        log(text[:1200])
    elif proc.returncode != 0 and fails == 0:
        FAIL += 1
        ERRORS.append((title, f"rc={proc.returncode} 但无 FAIL 行"))
        log(f"  ❌ {title}: rc={proc.returncode} 但无 FAIL 行")


def userns_uid_mapping_ok():
    """unshare 用户/pid ns + uid 映射到 10123（R8 夹具需要真实 uid >= 10000）。"""
    unshare = shutil.which("unshare")
    if not unshare:
        return False, "缺少 unshare(1)"
    try:
        r = subprocess.run([unshare, "--user", "--map-user=10123", "--map-group=10123",
                            "--pid", "--fork", "--mount-proc", "true"],
                           capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"unshare 探测失败: {e}"
    if r.returncode != 0:
        return False, f"userns/uid 映射不可用（rc={r.returncode}）"
    return True, ""


def direct_compile_group():
    """直编组：R8（IPC 身份绑定）+ R9（异步挂载结果判定）。返回 (已跑组数, 跳过原因)。"""
    skips = []
    ran = 0
    if not (os.path.isfile(os.path.join(FIXTURES, "ipc_binding.c")) and
            os.path.isfile(os.path.join(FIXTURES, "async_reaped.c"))):
        skips.append("缺少 tests/fixtures/{ipc_binding,async_reaped}.c")
        return ran, skips
    try:
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + ["--version"],
                       capture_output=True, timeout=20, check=True)
    except (OSError, subprocess.SubprocessError):
        skips.append("缺少本机 cc，直编组跳过")
        return ran, skips

    tmp = tempfile.mkdtemp(prefix="inject_direct_")
    _inc, _conf, _emu, patched = prepare_private_include(tmp)
    if patched != 2:
        fail("直编组：私有化平台根常量", f"仅替换 {patched}/2 处（头文件结构变化？）")
        return ran, skips

    # ── R8：IPC 请求身份绑定 ──
    ipc_src = os.environ.get("IPC_SERVER_SRC") or os.path.join(
        ROOT, "src", "injector", "ipc_server.c")
    log(f"直编组 R8：被测 ipc_server 源 = {ipc_src}")
    exe, build = build_fixture(tmp, "ipc_binding", "ipc_binding.c", [
        ipc_src,
        # 补挂载盯梢的等待体与其事件源（ipc_server 直接调用）
        os.path.join(ROOT, "src", "injector", "ns_mnt_wait.c"),
        os.path.join(ROOT, "src", "injector", "ns_mnt_watch.c"),
        # timeout 取消分支清真实重试账，不用空桩掩盖新增依赖。
        os.path.join(ROOT, "src", "injector", "retry_queue.c"),
        os.path.join(ROOT, "src", "injector", "inject_target.c"),
        # uid 表写回已异步化：真实落盘线程 TU，不用空桩掩盖新增依赖。
        os.path.join(ROOT, "src", "injector", "uid_cache_writer.c"),
        os.path.join(ROOT, "src", "core", "uid_map.c"),
        os.path.join(ROOT, "src", "core", "fast_pid.c"),
        os.path.join(ROOT, "src", "core", "nsp_util.c"),
    ])
    if build.returncode != 0:
        fail("R8 直编夹具编译", (build.stderr or build.stdout).strip()[:800])
    else:
        ok, why = userns_uid_mapping_ok()
        if not ok:
            skips.append(f"R8 直编组跳过：{why}")
        else:
            try:
                proc = subprocess.run(
                    ["unshare", "--user", "--map-user=10123", "--map-group=10123",
                     "--pid", "--fork", "--mount-proc", exe],
                    capture_output=True, text=True, timeout=180)
                ran += 1
                record_fixture_output("R8 IPC 身份绑定", proc)
            except subprocess.TimeoutExpired:
                fail("R8 IPC 身份绑定", "夹具 180s 超时")

    # ── R9：异步挂载完成事件（结果判定与收尸解耦） ──
    ns_src = os.environ.get("NS_UTILS_SRC") or os.path.join(
        ROOT, "src", "injector", "ns_utils.c")
    log(f"直编组 R9：被测 ns_utils 源 = {ns_src}")
    exe, build = build_fixture(tmp, "async_reaped", "async_reaped.c", [ns_src])
    if build.returncode != 0:
        fail("R9 直编夹具编译", (build.stderr or build.stdout).strip()[:800])
    else:
        try:
            proc = subprocess.run([exe], capture_output=True, text=True, timeout=120)
            ran += 1
            record_fixture_output("R9 异步挂载收尾", proc)
        except subprocess.TimeoutExpired:
            fail("R9 异步挂载收尾", "夹具 120s 超时")

    if FAIL == 0:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        log(f"直编组失败，保留临时目录以便复现：{tmp}")
    return ran, skips


def main():
    ran_direct, direct_skips = direct_compile_group()
    ctl_missing = not os.path.isfile(CTL)
    if ctl_missing:
        log(f"SKIP: 找不到测试驱动 {CTL}（先执行 scripts/build.sh）")
        log("")
        log(f"结果: {PASS} 通过, {FAIL} 失败")
        for d, e in ERRORS:
            log(f"  ❌ {d}: {e}")
        for s in direct_skips:
            log(f"  gap: {s}")
        if FAIL:
            return 1
        return SKIP_RC if ran_direct == 0 else 78

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

    # 4×2 矩阵：系统/用户应用 × 有/无应用段，在两档 GLOBAL_INJECT 下各跑一遍。
    # SKIP_SYSTEM_APPS 只在 GLOBAL_INJECT 成立时收窄作用域：GLOBAL_INJECT OFF 时它
    # 不单独生效（显式段本来就独立裁决，两种取值下都必须照常注入）。
    conf_gi_on_skip_on = write_conf(
        tmp, "m_on_on.conf",
        "[GLOBAL]\nGLOBAL_INJECT ON\nSKIP_SYSTEM_APPS ON\n\n"
        "[com.sys.named] ON\n[com.user.named] ON\n[com.user.off] OFF\n")
    conf_gi_on_skip_off = write_conf(
        tmp, "m_on_off.conf",
        "[GLOBAL]\nGLOBAL_INJECT ON\nSKIP_SYSTEM_APPS OFF\n\n"
        "[com.sys.named] ON\n[com.user.named] ON\n[com.user.off] OFF\n")
    conf_gi_off_skip_on = write_conf(
        tmp, "m_off_on.conf",
        "[GLOBAL]\nGLOBAL_INJECT OFF\nSKIP_SYSTEM_APPS ON\n\n"
        "[com.sys.named] ON\n[com.user.named] ON\n[com.user.off] OFF\n")
    conf_gi_off_skip_off = write_conf(
        tmp, "m_off_off.conf",
        "[GLOBAL]\nGLOBAL_INJECT OFF\nSKIP_SYSTEM_APPS OFF\n\n"
        "[com.sys.named] ON\n[com.user.named] ON\n[com.user.off] OFF\n")

    matrix = (
        # (配置, 名称, GLOBAL_INJECT, SKIP_SYSTEM_APPS,
        #  系统应用无段, 系统应用有段, 用户应用无段, 用户应用有段)
        (conf_gi_on_skip_on, "GLOBAL_INJECT ON  SKIP_SYSTEM_APPS ON ", 1, 1, 0, 1, 1, 1),
        (conf_gi_on_skip_off, "GLOBAL_INJECT ON  SKIP_SYSTEM_APPS OFF", 1, 0, 1, 1, 1, 1),
        (conf_gi_off_skip_on, "GLOBAL_INJECT OFF SKIP_SYSTEM_APPS ON ", 0, 1, 0, 1, 0, 1),
        (conf_gi_off_skip_off, "GLOBAL_INJECT OFF SKIP_SYSTEM_APPS OFF", 0, 0, 0, 1, 0, 1),
    )
    for conf, label, _gi, _skip, sys_plain, sys_named, user_plain, user_named in matrix:
        log(f"场景8: 4×2 矩阵 — {label}")
        for method in ("v1", "v2"):
            expect(f"{method} {label} 系统应用·无段", is_target(conf, method, "com.sys.app", SYS_UID)[1], sys_plain)
            expect(f"{method} {label} 系统应用·有段", is_target(conf, method, "com.sys.named", SYS_UID)[1], sys_named)
            expect(f"{method} {label} 用户应用·无段", is_target(conf, method, "com.user.app", NORM_UID)[1], user_plain)
            expect(f"{method} {label} 用户应用·有段", is_target(conf, method, "com.user.named", NORM_UID)[1], user_named)
            expect(f"{method} {label} 用户应用·段 OFF", is_target(conf, method, "com.user.off", OFF_UID)[1], 0)
        # v3：全局挂载，两键都不参与
        expect(f"v3 {label} 系统应用·无段", is_target(conf, "v3", "com.sys.app", SYS_UID)[1], 1)
        expect(f"v3 {label} 用户应用·段 OFF", is_target(conf, "v3", "com.user.off", OFF_UID)[1], 0)

    log(f"\n结果: {PASS} 通过, {FAIL} 失败")
    for d, e in ERRORS:
        log(f"  ❌ {d}: {e}")
    for s in direct_skips:
        log(f"  gap: {s}")
    if FAIL:
        return 1
    # 直编组被跳过（缺 cc/userns）→ 部分跳过，不计通过
    return 78 if direct_skips else 0


if __name__ == "__main__":
    sys.exit(main())
