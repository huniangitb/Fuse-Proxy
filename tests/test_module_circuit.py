#!/usr/bin/env python3
"""模块故障防护测试 — 熔断器 / 崩溃围栏 / ban 持久化（Phase 1a-1c）。

V4 起规则引擎已内建（`src/daemon/fw_rules.c`），模块只剩「后端存储提供者」形态，
故故障注入一律改由 `backend_*` 承载；「模块还活着」的观测点也从"规则是否生效"
换成"后端是否仍在服务该路径"。

观测口径：配置 `FTP /<关键字> seg1` 后，该虚拟路径由后端模块接管——
`isdir(mnt/0/<健康关键字>)` 为真即模块在册，模块被置毒/卸载后落回本地直通
（本地无此目录）→ 假。

覆盖：
  1. 熔断：后端对 /0/berrN 返回**非 errno 契约**码（窗口内 5 次）→ 立即置毒卸载，
     其健康路径随之失效（行为化证据）
  2. 崩溃围栏：backend_match 触发 SIGSEGV → 围栏 longjmp 恢复，daemon 存活，
     单次即置毒；ban 记录 kind=crash
  3. 回调缺失（BADFN）：模块未实现 backend_open/read 时框架静默跳过，
     不得误毒化（模块仍在册、无 ban 记录）
  4. .banned 重写完整性：stale 条目移除不破坏其他模块的 ban 记录
  5. ban 持久化：重启 daemon 后同 mtime 坏 .so 不重载（防崩溃-重载震荡）
  6. backend_readdir 崩溃围栏 → 恢复 + 置毒
  7. backend_readdir 谎报条数（>max）→ 整批丢弃 + 计错误，ls 无垃圾条目
  8. 同进程连续两次崩溃（两个模块各一次）daemon 均存活（in_handler 复位）
  9. backend_match 崩溃围栏 + 业务 errno 不计熔断（连续多次 -ENOENT 不得置毒）
  10. ban 自愈 + 槽位复用：坏模块熔断后换同名修复版 .so（mtime 变化）→ 重载恢复

测试模块（gcc 现场编译，第三方视角仅依赖 nsp_module.h，见 docs/modules.md）：
  backend_crash.so — backend_match: bcrash→SIGSEGV / bmatch→认领 / biznoent→业务 -ENOENT
  backend_bad.so   — berr→非 errno 契约违规 / bovf→谎报条数 / breaddir_crash→SIGSEGV
                     / bhealth→健康基线；-DFIXED 编译出同名修复版供用例 10

前置：build_gnu/ 产物；/dev/fuse；gcc；fusermount3；/var/fuse-proxy/log 可写。
"""
import subprocess, os, sys, time, shutil
from pathlib import Path

HERE  = Path(__file__).resolve().parent
ROOT  = HERE.parent
MNT   = Path("/tmp/fuse_circuit_test/mnt")
STORAGE= Path("/tmp/fuse_circuit_test/storage")
MODDIR= Path("/tmp/fuse_circuit_test/modules")
CONF  = Path("/tmp/Namespace-Proxy/injector.conf")
DLOG  = Path("/tmp/fc.log")
DAEMON= os.environ.get("FUSE_DAEMON") or str(ROOT / "build_gnu" / "fuse_daemon")
# 熔断参数：3 秒窗口 5 次阈值（env 透传给 daemon 进程）
GUARD_ENV = {"NSP_GUARD_WINDOW_SEC": "3", "NSP_GUARD_ERR_MAX": "5"}
ERRLOG  = Path("/var/fuse-proxy/log/module_errors.log")
BANFILE = MODDIR / ".banned"

PASS = 0; FAIL = 0; ERRS = []
def ok(d):  global PASS; PASS += 1; print(f"  ✅ {d}")
def fail(d, dt=""): global FAIL; FAIL += 1; print(f"  ❌ {d}: {dt}"); ERRS.append((d, dt))

def build_modules():
    """按模块 ABI 编译故障测试模块（第三方模块视角：仅 nsp_module.h）。
    只编译到 build_gnu/，不预置进模块目录——各用例 stage_module 按需放置。"""
    if not Path(DAEMON).exists():
        print(f"!! 缺少 {DAEMON}，请先 ninja -C build_gnu"); sys.exit(2)
    for name, extra, cflags in (("backend_crash", "-O1 -g", []),
                                ("backend_bad", "-O1 -g", []),
                                # 同名修复版：模块名仍是 backend_bad，只有 mtime 不同
                                ("backend_bad_fixed", "-O1 -DFIXED", [])):
        out = ROOT / "build_gnu" / f"{name}.so"
        r = subprocess.run(["gcc", "-shared", "-fPIC", *extra.split(), "-DNSP_MODULE_BUILD",
                            *cflags, f"-I{ROOT}/include", "-o", str(out), str(HERE / f"{name.split('_fixed')[0]}.c")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"!! 测试模块 {name} 编译失败:\n{r.stderr}"); sys.exit(2)

def stage_module(name, as_name=None):
    """放置单个模块进模块目录（用例隔离：每次只加载本用例要测的模块）。
    as_name 用于"同名修复版"（backend_bad_fixed.so 以 backend_bad.so 名义放置）。"""
    as_name = as_name or name
    d = MODDIR / as_name
    d.mkdir(parents=True, exist_ok=True)
    # 原子替换（tmp + rename）：就地覆盖已 dlopen 的 .so 会让其映射页失效，
    # 半写文件被重新缺页后 ops 函数指针变成链接期残值 → 野指针跳转崩溃
    tmp = d / f"{as_name}.so.tmp"
    shutil.copy(ROOT / "build_gnu" / f"{name}.so", tmp)
    os.replace(tmp, d / f"{as_name}.so")
    time.sleep(0.6)   # 模块加载稳定性校验窗口 0.5s，等文件写入完成

def unstage_module(name):
    """用例结束移除模块目录（保留 .banned ban 记录供后续用例使用）"""
    shutil.rmtree(MODDIR / name, ignore_errors=True)

def setup():
    shutil.rmtree("/tmp/fuse_circuit_test", ignore_errors=True)
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)
    (STORAGE / "0" / "normal").mkdir(parents=True)
    (STORAGE / "0" / "normal" / "n.txt").write_text("normal")
    MNT.mkdir(parents=True)
    CONF.parent.mkdir(parents=True, exist_ok=True)
    if ERRLOG.exists(): ERRLOG.unlink()
    CONF.write_text("[GLOBAL]\nMONITOR OFF\nSANDBOX OFF\n")

def wconf(*kws):
    """写入配置：每个关键字一条 FTP 规则——引擎据此置 is_ftp，框架才会走后端查找"""
    lines = ["[GLOBAL]", "MONITOR OFF", "SANDBOX OFF"]
    lines += [f"FTP /{kw} seg1" for kw in kws]
    CONF.write_text("\n".join(lines) + "\n")

def start():
    """启动 daemon 并等待挂载就绪（任意内容可见即返回）"""
    env = dict(os.environ, **GUARD_ENV)
    p = subprocess.Popen([DAEMON, f"--root={STORAGE}", f"--rules={CONF}",
                          f"--modules-dir={MODDIR}", "-f", str(MNT)],
                         stdout=open(DLOG, "w"), stderr=subprocess.STDOUT, env=env)
    for _ in range(45):
        time.sleep(0.3)
        try:
            if list(MNT.iterdir()): return p
        except OSError: pass
        if p.poll() is not None: return None
    return p

def node(kw):
    return MNT / "0" / kw

def alive(kw, timeout=10.0):
    """后端是否仍在服务该关键字路径（模块在册证据）；超时返回最后一次结果"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            if os.path.isdir(node(kw)): return True
        except OSError: pass
        time.sleep(0.3)
    try:
        return os.path.isdir(node(kw))
    except OSError:
        return False

def gone(kw, timeout=12.0):
    """等待该路径不再由后端服务（置毒/卸载后落回本地直通）"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            if not os.path.isdir(node(kw)): return True
        except OSError:
            return True
        time.sleep(0.3)
    try:
        return not os.path.isdir(node(kw))
    except OSError:
        return True

def stop(p):
    if p:
        p.terminate()
        try: p.wait(5)
        except subprocess.TimeoutExpired: p.kill()
    time.sleep(0.3)
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)

def errlog_text():
    try: return ERRLOG.read_text()
    except OSError: return ""

def banned_text():
    try: return BANFILE.read_text()
    except OSError: return ""

def storm(kw, n=9):
    """错误风暴：路径必须落在 FTP 规则的**组件作用域内**（/berr 覆盖 /berr/x 但不覆盖
    /berr0），故在 kw 下逐次换叶子名——内核对失败 lookup 缓存负 dentry，同名只触达一次"""
    for i in range(n):
        try: (node(kw) / f"x{i}").stat()
        except OSError: pass
        time.sleep(0.12)

def main():
    global PASS, FAIL
    setup()
    build_modules()

    # ── 1. 熔断：后端持续契约违规（非 errno 返回码）→ 窗口内 5 次后置毒 ──
    print("\n── 1. 熔断：契约违规风暴 → 自动卸载 + 后端失效 ──")
    wconf("berr", "bhealth")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败"); return
    try:
        ok("普通路径直通") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "n.txt 不可见")
        ok("模块加载：/0/bhealth 由后端服务") if alive("bhealth") else fail("后端前置", "backend_bad 加载后 /0/bhealth 不是目录")
        storm("berr")
        ok("daemon 存活（熔断不杀进程）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("熔断后后端不再服务（置毒卸载）") if gone("bhealth") else fail("bhealth 应失效", "熔断后仍由后端服务")
        ok("普通路径不受影响") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "熔断后 n.txt 不可见")
        if "backend_bad" in banned_text() and "circuit" in banned_text():
            ok("ban 落盘（circuit_break）")
        else:
            fail("ban 落盘", f".banned 内容: {banned_text()!r}")
        if "circuit_break" in errlog_text():
            ok("module_errors.log 记录熔断事件")
        else:
            fail("module_errors.log", f"内容: {errlog_text()[:200]!r}")
    finally:
        stop(p)
        unstage_module("backend_bad")

    # ── 2. 崩溃围栏：backend_match 触发 SIGSEGV → longjmp 恢复，单次即置毒 ──
    print("\n── 2. 崩溃围栏：backend_match SIGSEGV → 恢复 + 置毒 ──")
    wconf("bcrash", "bmatch")
    stage_module("backend_crash")
    p = start()
    if not p: fail("启动失败（backend_crash）"); return
    try:
        ok("模块加载：/0/bmatch 由后端服务") if alive("bmatch") else fail("后端前置", "backend_crash 加载后 /0/bmatch 不是目录")
        try: (MNT/"0/bcrash/x").stat()
        except OSError: pass
        time.sleep(1.2)
        ok("daemon 存活（崩溃被围栏恢复）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("崩溃后后端失效（置毒）") if gone("bmatch") else fail("bmatch 应失效", "崩溃后仍由后端服务")
        ok("普通路径不受崩溃影响") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "崩溃后 n.txt 不可见")
        if "backend_crash" in banned_text():
            ok("崩溃置毒 ban 落盘")
        else:
            fail("崩溃 ban 落盘", f".banned: {banned_text()!r}")
        if "backend_crash" in errlog_text() and "kind=crash" in errlog_text():
            ok("module_errors.log 记录崩溃事件")
        else:
            fail("module_errors.log(崩溃)", f"内容: {errlog_text()[:200]!r}")
    finally:
        stop(p)
        unstage_module("backend_crash")

    # ── 3. BADFN 不触发毒化：模块未实现某后端回调时静默跳过 ──
    print("\n── 3. BADFN 不触发毒化：未实现的后端回调不得误 ban ──")
    # backend_crash 在本用例上一轮（用例 2）已因崩溃被 ban，同 mtime 会加载不上；
    # 本用例要验的是"回调缺失不毒化"，故先清掉 ban 记录（ban 机制本身由 4/5 覆盖）
    if BANFILE.exists(): BANFILE.unlink()
    wconf("bmatch")
    stage_module("backend_crash")   # 只实现 match/getattr/readdir，无 open/read/write
    p = start()
    if not p: fail("启动失败（BADFN）"); return
    try:
        ok("模块加载：/0/bmatch 由后端服务") if alive("bmatch") else fail("后端前置", "bmatch 不是目录")
        ok("普通路径直通") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "n.txt 不可见")
        # 触发未实现回调：open/read 走 backend_open/backend_read（均为 NULL）
        for _ in range(6):
            try:
                with open(node("bmatch") / "x.txt", "rb") as fh: fh.read()
            except OSError:
                pass
            time.sleep(0.2)
        ok("daemon 存活（BADFN 不杀进程）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("BADFN 后模块仍在册（未被误毒化）") if alive("bmatch") else fail("模块被误毒化", "bmatch 不再由后端服务")
        ok("普通路径不受影响") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "BADFN 后 n.txt 不可见")
        if "backend_crash" not in banned_text():
            ok("BADFN 未写入 ban 记录")
        else:
            fail("BADFN 误写 ban", f".banned 内容: {banned_text()!r}")
    finally:
        stop(p)
        unstage_module("backend_crash")

    # ── 4. .banned 文件重写完整性：stale 条目移除不破坏其他条目 ──
    print("\n── 4. .banned 重写完整性：stale 条目移除后其他条目保留 ──")
    BANFILE.parent.mkdir(parents=True, exist_ok=True)
    BANFILE.write_text("other_mod|abc123fakehash|test_reason|1700000000\n")
    wconf("berr", "bhealth")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（ban 重写测试）"); return
    try:
        ok("模块加载：/0/bhealth 由后端服务") if alive("bhealth") else fail("后端前置", "bhealth 不是目录")
        storm("berr")
        ok("熔断触发") if gone("bhealth") else fail("bhealth 应失效", "熔断后仍由后端服务")
    finally:
        stop(p)
        unstage_module("backend_bad")

    ban_content = banned_text()
    if "backend_bad" in ban_content and "circuit" in ban_content:
        ok("backend_bad ban 记录已写入")
    else:
        fail("backend_bad ban 记录", f".banned: {ban_content!r}")
    if ("other_mod" in ban_content and "abc123fakehash" in ban_content
            and "test_reason" in ban_content and "1700000000" in ban_content):
        ok("other_mod ban 记录完整保留（未被查找的名字不受重写影响）")
    else:
        fail("other_mod ban 记录被破坏", f".banned: {ban_content!r}")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 5. ban 持久化：重启 daemon 后同 mtime .so 不重载 ──
    print("\n── 5. ban 持久化：重启不重载同 mtime 坏模块 ──")
    wconf("berr", "bhealth")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（ban 持久化测试）"); return
    try:
        ok("模块加载：/0/bhealth 由后端服务") if alive("bhealth") else fail("后端前置", "bhealth 不是目录")
        storm("berr")
        ok("首次熔断并落盘 ban") if "backend_bad" in banned_text() else fail("ban 未落盘", banned_text()[:120])
    finally:
        stop(p)
    # 同 mtime .so 仍在目录：重启后必须被 ban 拦截，不重载
    p = start()
    if not p: fail("重启失败"); return
    try:
        time.sleep(1.5)
        ok("重启后同 mtime 坏模块未重载") if not alive("bhealth", timeout=3) else fail("ban 失效", "重启后坏模块又被加载")
        ok("重启后普通路径正常") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "重启后 n.txt 不可见")
    finally:
        stop(p)
        unstage_module("backend_bad")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 6. backend_readdir 崩溃围栏 ──
    print("\n── 6. backend_readdir 崩溃围栏：SIGSEGV → 恢复 + 置毒 ──")
    wconf("breaddir_crash", "bhealth")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（readdir 崩溃）"); return
    try:
        ok("模块加载：/0/bhealth 由后端服务") if alive("bhealth") else fail("后端前置", "bhealth 不是目录")
        try: list(node("breaddir_crash").iterdir())
        except OSError: pass
        time.sleep(1.2)
        ok("daemon 存活（readdir 崩溃被围栏恢复）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("readdir 崩溃后模块失效（置毒）") if gone("bhealth") else fail("bhealth 应失效", "readdir 崩溃后仍由后端服务")
        if "backend_readdir" in errlog_text():
            ok("module_errors.log 记录 op=backend_readdir")
        else:
            fail("errlog 缺 op", f"内容: {errlog_text()[:200]!r}")
    finally:
        stop(p)
        unstage_module("backend_bad")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 7. backend_readdir 谎报条数（>max）：整批丢弃，不得越界读 ──
    print("\n── 7. backend_readdir 超限：谎报条数 → 丢弃 + 计错误 ──")
    wconf("bovf", "bhealth")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（readdir 超限）"); return
    try:
        ok("模块加载：/0/bhealth 由后端服务") if alive("bhealth") else fail("后端前置", "bhealth 不是目录")
        entries = []
        # 谎报条数 = 契约违规：每次 readdir 记一次错误，窗口内 5 次即熔断
        for _ in range(7):
            try: entries = [e.name for e in os.scandir(node("bovf"))]
            except OSError: pass
            time.sleep(0.3)
        ok("daemon 存活（超限不越界读）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("不填充越界条目（无 ovf 垃圾）") if not any("ovf" in e for e in entries) else fail(
            "越界条目", f"entries={entries[:6]}")
        ok("超限被记为契约违规（累计够阈值即熔断）") if gone("bhealth") else fail(
            "超限未记账", f"bhealth 仍由后端服务；errlog: {errlog_text()[:200]!r}")
    finally:
        stop(p)
        unstage_module("backend_bad")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 8. 同进程连续两次崩溃均恢复（in_handler 复位） ──
    print("\n── 8. 连续两次崩溃：daemon 全程存活 ──")
    wconf("bcrash", "breaddir_crash", "bhealth")
    stage_module("backend_crash")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（连续崩溃）"); return
    try:
        try: (MNT/"0/bcrash/x").stat()
        except OSError: pass
        time.sleep(1.2)
        ok("第一次崩溃后 daemon 存活") if p.poll() is None else fail("首次崩溃即死", f"rc={p.poll()}")
        try: list(node("breaddir_crash").iterdir())
        except OSError: pass
        time.sleep(1.2)
        ok("第二次崩溃后 daemon 仍存活") if p.poll() is None else fail("二次崩溃带崩", f"rc={p.poll()}")
        ok("普通路径仍可用") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "两次崩溃后 n.txt 不可见")
    finally:
        stop(p)
        unstage_module("backend_crash")
        unstage_module("backend_bad")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 9. 业务 errno 不计熔断（FTP 路径频繁 ENOENT 不得置毒） ──
    print("\n── 9. 业务 errno 豁免：连续 -ENOENT 不得触发熔断 ──")
    wconf("biznoent")
    stage_module("backend_crash")
    p = start()
    if not p: fail("启动失败（业务 errno）"); return
    try:
        for i in range(6):
            try: (MNT/"0" / f"biznoent{i}").stat()
            except OSError: pass
            time.sleep(0.15)
        time.sleep(1.0)
        ok("daemon 存活") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        if "backend_crash" not in banned_text():
            ok("业务 errno 未触发熔断（无 ban 记录）")
        else:
            fail("业务 errno 误熔断", f".banned: {banned_text()!r}")
        ok("普通路径正常") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "n.txt 不可见")
    finally:
        stop(p)
        unstage_module("backend_crash")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 10. ban 自愈 + 槽位复用：换同名修复版 .so（mtime 变化）→ 重载恢复 ──
    print("\n── 10. ban 自愈：同 mtime 被 ban → 换修复版 .so → 重载恢复 ──")
    wconf("berr", "bhealth")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（ban 自愈）"); return
    try:
        ok("坏版本加载并生效") if alive("bhealth") else fail("后端前置", "bhealth 不是目录")
        storm("berr")
        ok("坏版本被熔断") if gone("bhealth") else fail("bhealth 应失效", "坏版本仍生效")
        if "backend_bad" in banned_text():
            ok("坏版本已 ban")
        else:
            fail("坏版本未 ban", banned_text()[:120])
    finally:
        stop(p)

    # 同目录换入同名修复版（.so 内容不同 → mtime 变化 → 允许重载）
    # 注意 .banned 需保留：正是"mtime 不同才放行"的验证点
    unstage_module("backend_bad")
    stage_module("backend_bad_fixed", as_name="backend_bad")
    p = start()
    if not p: fail("重启失败（修复版）"); return
    try:
        ok("换修复版后重载恢复（mtime 变化绕过 ban）") if alive("bhealth") else fail(
            "修复版未恢复", "bhealth 仍不可用（ban 未按 mtime 放行）")
        ok("普通路径正常") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "n.txt 不可见")
    finally:
        stop(p)
        unstage_module("backend_bad")
    if BANFILE.exists(): BANFILE.unlink()

    print(f"\n═══════════════════════════════════════")
    print(f"[{time.strftime('%H:%M:%S')}] 测试完成 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS+FAIL}")
    if ERRS:
        for d, dt in ERRS: print(f"  失败: {d}: {dt}")
        sys.exit(1)

if __name__ == "__main__":
    main()
