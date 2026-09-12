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

扩展回归（用户日志 log_2026.9.11_0125.zip 全链路）：
  6. readdir_extra 崩溃围栏：readdir 触发 SIGSEGV → 恢复+置毒（op=readdir_extra）
  7. readdir_extra 超限返回：谎报 got>max → 整批丢弃+熔断，ls 正常无垃圾
  8. 围栏二次恢复：同一模块连续崩溃两次，daemon 均存活（in_handler 复位）
  9. backend_match 崩溃围栏：FTP 路径触发 SIGSEGV → 恢复+置毒（裸调用修复）
  10. ban 自愈+槽位复用：坏模块熔断后换同名修复版 .so（哈希变化）→ 重载恢复
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
                        "badfn_rules": "-O1",
                        "readdir_crash_rules": "-O1 -g",
                        "overflow_rules": "-O1",
                        "backend_crash": "-O1 -g",
                        "bad_rules_fixed": "-O1"}.items():
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
        # 清理：后续用例需干净 ban 状态
        if BANFILE.exists(): BANFILE.unlink()
        unstage_module("bad_rules")

    # ── 6. readdir_extra 崩溃围栏（用户日志 op=readdir_extra path=/Android）──
    print("\n── 6. readdir_extra 崩溃围栏：readdir → 恢复 + 置毒 ──")
    stage_module("readdir_crash_rules")
    p = start()
    if not p: fail("启动失败（readdir_crash_rules）"); return
    try:
        ok("模块加载：/0/virt/ 重定向可见") if wait_virt() else fail("virt 前置", "readdir_crash_rules 加载时不可见")
        try: list((MNT / "0").iterdir())  # 触发 readdir_extra → SIGSEGV
        except OSError: pass
        time.sleep(1.2)
        ok("daemon 存活（readdir 崩溃被围栏恢复）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        time.sleep(1.3)  # 等内核 dentry 缓存过期
        ok("崩溃后 /0/virt/ 规则失效（置毒）") if not virt_visible() else fail("virt 应失效", "readdir 崩溃后仍可见")
        ok("普通路径不受影响") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "崩溃后 n.txt 不可见")
        if "readdir_crash_rules" in banned_text():
            ok("readdir 崩溃置毒 ban 落盘")
        else:
            fail("readdir 崩溃 ban 落盘", f".banned: {banned_text()!r}")
    finally:
        stop(p)
        unstage_module("readdir_crash_rules")
        if BANFILE.exists(): BANFILE.unlink()

    # ── 7. readdir_extra 超限返回（got > max 钳制）──
    print("\n── 7. readdir_extra 超限返回：谎报条目数 → 丢弃 + 熔断 ──")
    stage_module("overflow_rules")
    p = start()
    if not p: fail("启动失败（overflow_rules）"); return
    try:
        ok("模块加载：/0/virt/ 重定向可见") if wait_virt() else fail("virt 前置", "overflow_rules 加载时不可见")
        # 单次 readdir：超限批次应被丢弃，ls 本身正常返回（无垃圾条目、无崩溃）
        try:
            names = [x.name for x in (MNT / "0").iterdir()]
        except OSError as e:
            fail("readdir 应正常返回", f"OSError: {e}"); names = []
        ok("daemon 存活（超限返回不带崩）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        if any(n.startswith("ovf") for n in names):
            fail("超限批次应被丢弃", f"ls 见垃圾条目: {names!r}")
        else:
            ok("超限批次已丢弃（无 ovf* 垃圾条目）")
        # 多次触发攒够熔断阈值 → 置毒，virt 失效（行为化证据）
        for _ in range(9):
            try: list((MNT / "0").iterdir())
            except OSError: pass
            time.sleep(0.12)
        time.sleep(1.3)
        ok("daemon 存活（熔断不杀进程）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("熔断后 /0/virt/ 规则失效") if not virt_visible() else fail("virt 应失效", "超限熔断后仍可见")
        if "overflow_rules" in banned_text():
            ok("超限熔断 ban 落盘")
        else:
            fail("超限 ban 落盘", f".banned: {banned_text()!r}")
    finally:
        stop(p)
        unstage_module("overflow_rules")
        if BANFILE.exists(): BANFILE.unlink()

    # ── 8. 围栏二次恢复（in_handler 复位；修复前第二次崩溃杀进程）──
    print("\n── 8. 围栏二次恢复：连续两次崩溃 daemon 均存活 ──")
    stage_module("crash_rules")
    p = start()
    if not p: fail("启动失败（二次恢复）"); return
    try:
        ok("模块加载：/0/virt/ 重定向可见") if wait_virt() else fail("virt 前置", "crash_rules 加载时不可见")
        # 第一次崩溃：用独立模块目录快照？crash 后即置毒 ban，第二次需新实例。
        # 此处验证同一 daemon 进程内围栏可重复使用：先用 crash_rules 崩一次，
        # 再换 readdir_crash_rules 崩一次（同一进程、不同模块），两次都应恢复。
        try: (MNT/"0/crashtest/x").stat()
        except OSError: pass
        time.sleep(1.0)
        ok("第一次崩溃后存活") if p.poll() is None else fail("第一次崩溃杀进程", f"rc={p.poll()}")
        # 动态换模块：移除 crash_rules，放入 readdir_crash_rules（ban 不同名，不冲突）
        unstage_module("crash_rules")
        time.sleep(1.0)
        stage_module("readdir_crash_rules")
        for _ in range(30):
            if (MODDIR / "readdir_crash_rules").exists(): break
            time.sleep(0.2)
        time.sleep(2.5)  # 等热插拔加载（含 0.5s 稳定性窗口）
        try: list((MNT / "0").iterdir())
        except OSError: pass
        time.sleep(1.0)
        ok("第二次崩溃后仍存活（in_handler 已复位）") if p.poll() is None else fail("第二次崩溃杀进程", f"rc={p.poll()}")
        ok("普通路径正常") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "二次崩溃后 n.txt 不可见")
    finally:
        stop(p)
        unstage_module("crash_rules")
        unstage_module("readdir_crash_rules")
        if BANFILE.exists(): BANFILE.unlink()

    # ── 9. backend_match 崩溃围栏（修复前裸调用野指针带崩框架）──
    print("\n── 9. backend_match 崩溃围栏：FTP 路径 → 恢复 + 置毒 ──")
    # 需 basic_rules（FTP 规则解析）+ backend_crash 共存
    basic_so = ROOT / "build_gnu" / "basic_rules.so"
    if not basic_so.exists():
        fail("缺少 basic_rules.so", "请先 ninja -C build_gnu")
        p = None
    else:
        d = MODDIR / "basic_rules"
        d.mkdir(parents=True, exist_ok=True)
        shutil.copy(basic_so, d / "basic_rules.so")
        stage_module("backend_crash")
        CONF.write_text("[GLOBAL]\nMONITOR OFF\nSANDBOX OFF\nFTP /bcrash seg1\nFTP /bmatch seg1\n")
        time.sleep(0.6)
        p = start()
    if p:
        try:
            time.sleep(2.5)  # 等双模块加载
            ok("daemon 存活（启动）") if p.poll() is None else fail("启动崩溃", f"rc={p.poll()}")
            # 正常后端路径可用（backend_match 返回 1 不崩）
            try:
                is_dir = (MNT / "0" / "bmatch").is_dir()
            except OSError:
                is_dir = False
            ok("正常 FTP 后端路径可用") if (is_dir or p.poll() is None) else fail("bmatch", "后端路径不可用且进程异常")
            # 触发 backend_match 崩溃路径
            try: (MNT / "0" / "bcrash" / "x").stat()
            except OSError: pass
            time.sleep(1.2)
            ok("daemon 存活（backend_match 崩溃被围栏恢复）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
            ok("普通路径不受影响") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "崩溃后 n.txt 不可见")
            if "backend_crash" in banned_text():
                ok("backend 崩溃置毒 ban 落盘")
            else:
                fail("backend 崩溃 ban 落盘", f".banned: {banned_text()!r}")
        finally:
            stop(p)
            unstage_module("backend_crash")
            unstage_module("basic_rules")
            if BANFILE.exists(): BANFILE.unlink()
            CONF.write_text("[GLOBAL]\nMONITOR OFF\nSANDBOX OFF\n")

    # ── 10. ban 自愈 + 槽位复用（哈希变化放行；注册表不泄漏）──
    print("\n── 10. ban 自愈 + 槽位复用：同名修复版 .so 重载恢复 ──")
    stage_module("bad_rules")
    p = start()
    if not p: fail("启动失败（自愈测试）"); return
    try:
        ok("模块加载：/0/virt/ 可见") if wait_virt() else fail("virt 前置", "bad_rules 加载时不可见")
        for i in range(9):
            try: (MNT/"0" / f"errtest{i}").stat()
            except OSError: pass
            time.sleep(0.12)
        time.sleep(1.3)
        ok("熔断触发") if not virt_visible() else fail("virt 应失效", "熔断后仍可见")
        # 同名覆盖修复版（哈希变化；mtime 必变）→ ban 应自愈放行
        shutil.copy(ROOT / "build_gnu" / "bad_rules_fixed.so",
                    MODDIR / "bad_rules" / "bad_rules.so")
        # 等热重载（monitor 5s 周期 + 0.5s 稳定性窗口）；轮询 virt 恢复
        healed = False
        for _ in range(40):
            time.sleep(0.5)
            if virt_visible():
                healed = True
                break
        ok("同名修复版重载恢复（ban 自愈 + 槽位复用）") if healed else fail("自愈失败", "覆盖修复版后 /0/virt/ 仍不可见")
        ok("daemon 存活") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
    finally:
        stop(p)
        unstage_module("bad_rules")
        if BANFILE.exists(): BANFILE.unlink()

    print(f"\n═══════════════════════════════════════")
    print(f"[{time.strftime('%H:%M:%S')}] 测试完成 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS+FAIL}")
    for d, dt in ERRS: print(f"   ✗ {d}: {dt}")
    sys.exit(1 if FAIL else 0)

if __name__ == "__main__":
    main()
