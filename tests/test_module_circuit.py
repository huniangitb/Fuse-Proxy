#!/usr/bin/env python3
"""模块故障防护测试 — 熔断器 / 崩溃围栏 / ban 持久化（Phase 1a-1c）。

覆盖：
  1. 熔断：模块对 /0/errtest/ 持续报错（窗口内 5 次）→ 立即置毒卸载，
     规则自动失效（/0/virt/ 由可见变不可见 = 行为化证据）
  2. 熔断落盘：.banned 记录（circuit_break）+ module_errors.log 高危事件
  3. 崩溃围栏：模块 /0/crashtest/ 触发 SIGSEGV → 围栏 longjmp 恢复，
     daemon 存活，单次即置毒，/0/virt/ 规则同样自动失效
  4. ban 持久化：重启 daemon 后同哈希 .so 不重载（防崩溃-重载震荡）

测试模块（gcc 现场编译，第三方视角仅依赖 nsp_module.h，见 docs/module-dev.md）：
  bad_rules.so    — /0/virt/→重定向；/0/errtest/→resolve 返回 -EIO
  crash_rules.so  — /0/virt/→重定向；/0/crashtest/→resolve 触发 SIGSEGV

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
GUARD_ENV = {"NSP_GUARD_WINDOW_SEC": "3", "NSP_GUARD_ERR_MAX": "5",
             "CIRCUIT_TEST_STORAGE": str(STORAGE)}
ERRLOG  = Path("/var/fuse-proxy/log/module_errors.log")
BANFILE = MODDIR / ".banned"

PASS = 0; FAIL = 0; ERRS = []
def ok(d):  global PASS; PASS += 1; print(f"  ✅ {d}")
def fail(d, dt=""): global FAIL; FAIL += 1; print(f"  ❌ {d}: {dt}"); ERRS.append((d, dt))

def build_modules():
    """按模块 ABI 编译故障测试模块（第三方模块视角：仅 nsp_module.h）。
    只编译到 build_gnu/，不预置进模块目录——各用例 stage_module 按需放置
    （模块都带 /0/virt/ 重定向，共存会导致一个被熔断后另一个继续
    解析 virt，破坏"规则失效"断言）。"""
    if not Path(DAEMON).exists():
        print(f"!! 缺少 {DAEMON}，请先 ninja -C build_gnu"); sys.exit(2)
    for name, extra in {"bad_rules": "-O1", "crash_rules": "-O1 -g",
                        "badfn_rules": "-O1"}.items():
        out = ROOT / "build_gnu" / f"{name}.so"
        r = subprocess.run(["gcc", "-shared", "-fPIC", *extra.split(), "-DNSP_MODULE_BUILD",
                            f"-I{ROOT}/include", "-o", str(out), str(HERE / f"{name}.c")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"!! 测试模块 {name} 编译失败:\n{r.stderr}"); sys.exit(2)

def stage_module(name):
    """放置单个模块进模块目录（用例隔离：每次只加载本用例要测的模块）"""
    d = MODDIR / name
    d.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "build_gnu" / f"{name}.so", d / f"{name}.so")
    time.sleep(0.6)   # 模块加载稳定性校验窗口 0.5s，等文件写入完成

def unstage_module(name):
    """用例结束移除模块目录（保留 .banned ban 记录供后续用例使用）"""
    shutil.rmtree(MODDIR / name, ignore_errors=True)

def setup():
    shutil.rmtree("/tmp/fuse_circuit_test", ignore_errors=True)
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)
    (STORAGE / "0" / "real_dir").mkdir(parents=True)
    (STORAGE / "0" / "normal").mkdir(parents=True)
    (STORAGE / "0" / "real_dir" / "hi.txt").write_text("redirected")
    (STORAGE / "0" / "normal" / "n.txt").write_text("normal")
    MNT.mkdir(parents=True)
    CONF.parent.mkdir(parents=True, exist_ok=True)
    if ERRLOG.exists(): ERRLOG.unlink()
    CONF.write_text("[GLOBAL]\nMONITOR OFF\nSANDBOX OFF\n")

def start():
    """启动 daemon 并等待挂载就绪（任意内容可见即返回）；
    模块是否生效由各用例自行等待（等模块加载完成需 0.5s 稳定性窗口）"""
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

def wait_virt(timeout=10.0):
    """等待模块加载完成（/0/virt/ 可见）；超时返回 False"""
    end = time.time() + timeout
    while time.time() < end:
        if virt_visible(): return True
        time.sleep(0.3)
    return virt_visible()

def stop(p):
    if p:
        p.terminate()
        try: p.wait(5)
        except subprocess.TimeoutExpired: p.kill()
    time.sleep(0.3)
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)

def virt_visible():
    return (MNT / "0" / "virt" / "hi.txt").exists()

def errlog_text():
    try: return ERRLOG.read_text()
    except OSError: return ""

def banned_text():
    try: return BANFILE.read_text()
    except OSError: return ""

def main():
    global PASS, FAIL
    setup()
    build_modules()

    # ── 1. 熔断：bad_rules 对 /0/errtest/ 持续报错 → 窗口内 5 次后置毒 ──
    print("\n── 1. 熔断：错误风暴 → 自动卸载 + 规则失效 ──")
    stage_module("bad_rules")
    p = start()
    if not p: fail("启动失败"); return
    try:
        ok("普通路径直通") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "n.txt 不可见")
        ok("模块加载：/0/virt/ 重定向可见") if wait_virt() else fail("virt 前置", "模块加载时 /0/virt/hi.txt 不可见")
        # 触发错误风暴：每次 stat 不同组件名 /0/errtestN 计一次熔断错误。
        # 必须用不同名：内核对失败 lookup 缓存负向 dentry，同名路径只触达
        # 模块一次（实测 16 次同名 stat 仅 1 次 resolve），够不到阈值。
        for i in range(9):
            try: (MNT/"0" / f"errtest{i}").stat()
            except OSError: pass
            time.sleep(0.12)
        ok("daemon 存活（熔断不杀进程）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        # 内核正向 dentry 缓存（entry_timeout=1.0）：熔断前 stat 过的 /0/virt/hi.txt
        # 最长再缓存 1s——等缓存过期再断言规则失效
        time.sleep(1.3)
        ok("熔断后 /0/virt/ 规则失效（直通不可见）") if not virt_visible() else fail("virt 应失效", "熔断后 /0/virt/hi.txt 仍可见")
        ok("普通路径不受影响") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "熔断后 n.txt 不可见")
        if "bad_rules" in banned_text() and "circuit" in banned_text():
            ok("ban 落盘（circuit_break）")
        else:
            fail("ban 落盘", f".banned 内容: {banned_text()!r}")
        if "circuit_break" in errlog_text():
            ok("module_errors.log 记录熔断事件")
        else:
            fail("module_errors.log", f"内容: {errlog_text()[:200]!r}")
    finally:
        stop(p)
        unstage_module("bad_rules")

    # ── 2. 崩溃围栏：crash_rules 触发 SIGSEGV → longjmp 恢复，单次即置毒 ──
    print("\n── 2. 崩溃围栏：SIGSEGV → 恢复 + 置毒 ──")
    stage_module("crash_rules")
    p = start()
    if not p: fail("启动失败（crash_rules）"); return
    try:
        ok("模块加载：/0/virt/ 重定向可见") if wait_virt() else fail("virt 前置", "crash_rules 加载时 /0/virt/hi.txt 不可见")
        try: (MNT/"0/crashtest/x").stat()
        except OSError: pass
        time.sleep(1.2)
        ok("daemon 存活（崩溃被围栏恢复）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("崩溃后 /0/virt/ 规则失效（置毒）") if not virt_visible() else fail("virt 应失效", "崩溃后 /0/virt/hi.txt 仍可见")
        ok("普通路径不受崩溃影响") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "崩溃后 n.txt 不可见")
        if "crash_rules" in banned_text():
            ok("崩溃置毒 ban 落盘")
        else:
            fail("崩溃 ban 落盘", f".banned: {banned_text()!r}")
        if "crash_rules" in errlog_text() and "kind=crash" in errlog_text():
            ok("module_errors.log 记录崩溃事件")
        else:
            fail("module_errors.log(崩溃)", f"内容: {errlog_text()[:200]!r}")
    finally:
        stop(p)
        unstage_module("crash_rules")

    # ── 3. BADFN 不触发毒化：模块未实现 readdir_extra/get_pkg 时静默跳过 ──
    print("\n── 3. BADFN 不触发毒化：未实现 readdir_extra/get_pkg 的模块不应被误 ban ──")
    stage_module("badfn_rules")
    p = start()
    if not p: fail("启动失败（badfn_rules）"); return
    try:
        ok("模块加载：/0/virt/ 重定向可见") if wait_virt() else fail("virt 前置", "badfn_rules 加载时 /0/virt/hi.txt 不可见")
        ok("普通路径直通") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "n.txt 不可见")
        # 触发 readdir：ls /0/ 会调用 readdir_extra（badfn_rules 未实现 → BADFN）
        # 不应触发毒化——模块应保持加载
        try: list((MNT / "0").iterdir())
        except OSError: pass
        time.sleep(1.0)
        # 再多次触发确保不会累积到熔断
        for _ in range(5):
            try: list((MNT / "0").iterdir())
            except OSError: pass
            time.sleep(0.2)
        ok("daemon 存活（BADFN 不杀进程）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        # 关键断言：/0/virt/ 仍然可见（模块未被毒化）
        ok("BADFN 后 /0/virt/ 规则仍然有效（未被误毒化）") if virt_visible() else fail("virt 不应失效", "BADFN 后 /0/virt/hi.txt 不可见（模块被误毒化）")
        ok("普通路径不受影响") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "BADFN 后 n.txt 不可见")
        # .banned 不应有 badfn_rules 记录
        if "badfn_rules" not in banned_text():
            ok("BADFN 未写入 ban 记录")
        else:
            fail("BADFN 误写 ban", f".banned 内容: {banned_text()!r}")
    finally:
        stop(p)
        unstage_module("badfn_rules")

    # ── 4. .banned 文件重写完整性：stale 哈希重写不破坏其他条目 ──
    print("\n── 4. .banned 重写完整性：stale 条目移除后其他条目保留 ──")
    # 先手动写入一个"假"的 ban 记录（模拟另一个已 ban 模块）
    BANFILE.parent.mkdir(parents=True, exist_ok=True)
    BANFILE.write_text("other_mod|abc123fakehash|test_reason|1700000000\n")
    # 放入 bad_rules 并触发熔断——产生 stale 条目（哈希与实际 .so 不同）
    stage_module("bad_rules")
    p = start()
    if not p: fail("启动失败（ban 重写测试）"); return
    try:
        ok("模块加载：/0/virt/ 重定向可见") if wait_virt() else fail("virt 前置", "bad_rules 加载时不可见")
        for i in range(9):
            try: (MNT/"0" / f"errtest{i}").stat()
            except OSError: pass
            time.sleep(0.12)
        time.sleep(1.3)
        ok("熔断触发") if not virt_visible() else fail("virt 应失效", "熔断后仍可见")
    finally:
        stop(p)
        unstage_module("bad_rules")

    # 验证 .banned 文件：bad_rules 应有记录，other_mod 的记录应完整保留
    ban_content = banned_text()
    if "bad_rules" in ban_content and "circuit" in ban_content:
        ok("bad_rules ban 记录已写入")
    else:
        fail("bad_rules ban 记录", f".banned: {ban_content!r}")
    if "other_mod" in ban_content and "abc123fakehash" in ban_content and "test_reason" in ban_content and "1700000000" in ban_content:
        ok("other_mod ban 记录完整保留（hash+reason+timestamp）")
    else:
        fail("other_mod ban 记录被破坏", f".banned: {ban_content!r}")
    # 清理 .banned 供后续用例
    if BANFILE.exists(): BANFILE.unlink()

    # ── 5. ban 持久化：重启 daemon 后同哈希 .so 不重载 ──
    print("\n── 5. ban 持久化：重启不重载同哈希坏模块 ──")
    # 自包含：先触发 bad_rules 熔断产生 ban 记录，再重启验证同哈希 .so 不被重载。
    # 只加载 bad_rules（crash_rules 也注册 /0/virt/，共存会干扰断言）。
    stage_module("bad_rules")
    p = start()
    if not p: fail("启动失败（ban 持久化测试）"); return
    try:
        ok("模块加载：/0/virt/ 重定向可见") if wait_virt() else fail("virt 前置", "bad_rules 加载时不可见")
        # 触发 bad_rules 熔断
        for i in range(9):
            try: (MNT/"0" / f"errtest{i}").stat()
            except OSError: pass
            time.sleep(0.12)
        time.sleep(1.5)
        ok("熔断触发，bad_rules 已 ban") if not virt_visible() else fail("virt 应失效", "熔断后仍可见")
        # 记录当前 .banned 内容
        ban_before = banned_text()
        if "bad_rules" in ban_before and "circuit" in ban_before:
            ok("bad_rules ban 记录已写入 .banned")
        else:
            fail("bad_rules ban 记录", f".banned: {ban_before!r}")
    finally:
        stop(p)

    # 重启 daemon（模块目录未变，.banned 已保留）
    p = start()
    if not p: fail("重启失败"); return
    try:
        time.sleep(2.5)   # 等启动扫描（含 0.5s 稳定性窗口）完成
        ok("重启后 daemon 正常服务") if (MNT/"0/normal/n.txt").exists() else fail("重启后服务", "n.txt 不可见")
        ok("重启后坏模块未重载（/0/virt/ 不可见）") if not virt_visible() else fail("ban 失效", "重启后 /0/virt/hi.txt 可见（坏模块被错误重载）")
    finally:
        stop(p)

    print(f"\n═══════════════════════════════════════")
    print(f"[{time.strftime('%H:%M:%S')}] 测试完成 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS+FAIL}")
    for d, dt in ERRS: print(f"   ✗ {d}: {dt}")
    sys.exit(1 if FAIL else 0)

if __name__ == "__main__":
    main()
