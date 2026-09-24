#!/usr/bin/env python3
"""热插拔模块测试 — basic_rules.so 的动态加载/卸载/容错/直通。

覆盖：
  1. 规则模块已加载：REDIRECT 生效
  2. 运行中移除模块 .so：规则失效（直通回退）
  3. 运行中放回模块 .so：规则恢复（热插拔加载）
  4. 损坏 .so：加载失败但 daemon 存活、其他路径正常
  5. 无模块：纯直通
"""
import subprocess, os, sys, time, shutil
from pathlib import Path

MNT    = "/tmp/fuse_mod_test/mnt"
STORAGE= "/tmp/fuse_mod_test/storage"
MODDIR = "/tmp/fuse_mod_test/modules"
CONF   = "/tmp/Namespace-Proxy/injector.conf"
DAEMON = os.environ.get("FUSE_DAEMON") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "build_gnu", "fuse_daemon"))
BASIC_RULES = os.environ.get("BASIC_RULES_SO") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "build_gnu", "basic_rules.so"))

PASS = 0; FAIL = 0; ERRS = []
def ok(d): global PASS; PASS += 1; print(f"  ✅ {d}")
def fail(d, dt=""): global FAIL; FAIL += 1; print(f"  ❌ {d}: {dt}"); ERRS.append((d, dt))

def setup():
    shutil.rmtree("/tmp/fuse_mod_test", ignore_errors=True)
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    os.makedirs(f"{STORAGE}/0/real_dir", exist_ok=True)   # REDIRECT 相对目标 → storage/0/real_dir
    os.makedirs(f"{STORAGE}/0/normal", exist_ok=True)
    (Path(STORAGE)/"0/real_dir/hi.txt").write_text("redirected")
    (Path(STORAGE)/"0/normal/n.txt").write_text("normal")
    os.makedirs(MNT, exist_ok=True)
    os.makedirs("/tmp/Namespace-Proxy", exist_ok=True)
    put_module("basic_rules")   # 预置规则模块：case1 启动即加载

def wconf(t): open(CONF, "w").write(t.strip())
def put_module(name="basic_rules"):
    os.makedirs(f"{MODDIR}/{name}", exist_ok=True)
    shutil.copy(BASIC_RULES, f"{MODDIR}/{name}/{name}.so")
def rm_module(name="basic_rules"):
    p = Path(f"{MODDIR}/{name}/{name}.so")
    if p.exists(): p.unlink()

def start():
    p = subprocess.Popen([DAEMON, "--root="+STORAGE, "--rules="+CONF,
                          "--modules-dir="+MODDIR, "-f", MNT, "info"],
                         stdout=open("/tmp/fm.log", "w"), stderr=subprocess.STDOUT)
    for _ in range(30):
        time.sleep(0.3)
        try:
            if os.listdir(MNT): return p
        except: pass
        if p.poll() is not None: return None
    return p
def stop(p):
    if p: p.terminate()
    try: p.wait(3)
    except: p.kill()
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)

def wait_check(mnt, rel, want_exists, timeout=8.0):
    """轮询等待热插拔生效（loader inotify 归并 1s + 扫描）"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        exists = (mnt / rel).exists()
        if exists == want_exists: return True
        time.sleep(0.4)
    return (mnt / rel).exists() == want_exists

def run_case(label, body):
    print(f"\n── {label} ──")
    wconf("""
[GLOBAL]
REDIRECT /云盘 real_dir
""")
    p = start()
    if not p: return fail("启动失败")
    try:
        body(p, Path(MNT))
    finally:
        stop(p)

def main():
    global PASS, FAIL
    setup()

    def case1(p, m):
        """模块已加载：REDIRECT /云盘 → storage/0/real_dir"""
        ok("启动含模块") if (m/"0/云盘/hi.txt").exists() else fail("REDIRECT 生效", "模块加载时 /0/云盘/hi.txt 不可见")
        got = (m/"0/云盘/hi.txt").read_text().strip() if (m/"0/云盘/hi.txt").exists() else ""
        ok("内容重定向") if got == "redirected" else fail("内容", f"got='{got}'")
        ok("普通路径直通") if (m/"0/normal/n.txt").exists() else fail("普通路径", "/0/normal/n.txt 不可见")
    run_case("1. 模块加载生效（REDIRECT）", case1)

    def case2(p, m):
        """运行中移除模块 → 规则失效（直通）"""
        if not (m/"0/云盘/hi.txt").exists():
            return fail("前置", "模块未生效，无法测热插拔")
        got = (m/"0/云盘/hi.txt").read_text()
        ok("热拔前已打开并读取文件") if got == "redirected" else fail("热拔前读取", got)
        rm_module()
        ok("热拔：规则失效") if wait_check(m, "0/云盘/hi.txt", False) else fail("热拔", "/0/云盘/hi.txt 仍可见（直通应不可见）")
        ok("热拔：缺失路径不合成目录") if not (m/"0/never-existed").exists() else fail("热拔-虚假目录")
        ok("热拔：普通路径不受影响") if (m/"0/normal/n.txt").exists() else fail("热拔-普通", "直通后普通文件不可见")
    run_case("2. 运行中移除模块（热拔）", case2)

    def case3(p, m):
        """运行中放回模块 → 规则恢复（热插加载）"""
        put_module()
        ok("热插：规则恢复") if wait_check(m, "0/云盘/hi.txt", True) else fail("热插", "放回模块后 /0/云盘/hi.txt 未恢复")
    run_case("3. 运行中放回模块（热插）", case3)

    def case4(p, m):
        """损坏 .so：加载失败但 daemon 存活、普通路径正常"""
        put_module("broken")
        with open(f"{MODDIR}/broken/broken.so", "w") as fh: fh.write("not a real elf")
        time.sleep(3)
        ok("daemon 存活") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("普通路径正常") if (m/"0/normal/n.txt").exists() else fail("普通路径", "坏模块后普通文件不可见")
        rm_module("broken")
    run_case("4. 损坏 .so 容错", case4)

    def case5(p, m):
        """无模块：纯直通（规则不生效）"""
        rm_module()
        ok("直通：云盘不可见") if wait_check(m, "0/云盘/hi.txt", False, timeout=12) else fail("直通", "无模块时 REDIRECT 不应生效")
        ok("直通：普通路径可见") if (m/"0/normal/n.txt").exists() else fail("直通-普通", "直通文件不可见")
    run_case("5. 无模块纯直通", case5)

    print(f"\n═══════════════════════════════════════")
    print(f"[{time.strftime('%H:%M:%S')}] 测试完成 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS+FAIL}")
    if ERRS:
        for d, dt in ERRS: print(f"  失败: {d}: {dt}")
        sys.exit(1)

if __name__ == "__main__":
    main()
