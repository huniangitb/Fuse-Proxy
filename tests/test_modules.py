#!/usr/bin/env python3
"""热插拔模块测试 — 后端模块的动态加载/卸载/容错，以及"规则与模块解耦"。

V4 起模块只有后端形态、规则引擎内建，故本套件覆盖：
  1. 规则不依赖模块：模块目录为空时 REDIRECT 照样生效
  2. 后端模块随 .so 放入而接管路径（热插）
  3. 运行中移除 .so：后端不再服务该路径，落回本地直通（热拔）
  4. 损坏 .so：加载失败但 daemon 存活、其它路径正常
  5. 热拔后规则仍在（引擎不受模块存亡影响）
"""
import subprocess, os, sys, time, shutil
from pathlib import Path

HERE   = Path(__file__).resolve().parent
ROOT   = HERE.parent
MNT    = "/tmp/fuse_mod_test/mnt"
STORAGE= "/tmp/fuse_mod_test/storage"
MODDIR = "/tmp/fuse_mod_test/modules"
CONF   = "/tmp/Namespace-Proxy/injector.conf"
DAEMON = os.environ.get("FUSE_DAEMON") or os.path.abspath(
    os.path.join(HERE, "..", "build_gnu", "fuse_daemon"))
MODULE = "backend_bad"

PASS = 0; FAIL = 0; ERRS = []
def ok(d): global PASS; PASS += 1; print(f"  ✅ {d}")
def fail(d, dt=""): global FAIL; FAIL += 1; print(f"  ❌ {d}: {dt}"); ERRS.append((d, dt))

def build_module():
    """现场编译后端测试模块（第三方模块视角：仅 nsp_module.h）"""
    if not os.path.exists(DAEMON):
        print(f"!! 缺少 {DAEMON}，请先 ninja -C build_gnu"); sys.exit(2)
    out = ROOT / "build_gnu" / f"{MODULE}.so"
    r = subprocess.run(["gcc", "-shared", "-fPIC", "-O1", "-DNSP_MODULE_BUILD",
                        f"-I{ROOT}/include", "-o", str(out), str(HERE / f"{MODULE}.c")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"!! 测试模块编译失败:\n{r.stderr}"); sys.exit(2)

def setup():
    shutil.rmtree("/tmp/fuse_mod_test", ignore_errors=True)
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    os.makedirs(f"{STORAGE}/0/real_dir", exist_ok=True)   # REDIRECT 相对目标 → storage/0/real_dir
    os.makedirs(f"{STORAGE}/0/normal", exist_ok=True)
    (Path(STORAGE)/"0/real_dir/hi.txt").write_text("redirected")
    (Path(STORAGE)/"0/normal/n.txt").write_text("normal")
    os.makedirs(MNT, exist_ok=True)
    os.makedirs("/tmp/Namespace-Proxy", exist_ok=True)
    os.makedirs(MODDIR, exist_ok=True)   # 空模块目录：case1 验证"无模块也有规则"

def wconf(t): open(CONF, "w").write(t.strip())
def put_module(name=MODULE):
    """原子替换模块 .so：先写 .tmp 再 rename。
    **就地覆盖已被 dlopen 的 .so 会让其已映射页失效**（truncate 使映射页被丢弃，
    再访问时从半写文件中重新缺页 → ops 函数指针变成链接期残值 → 野指针跳转崩
    溃）。rename 换 inode，旧映射不受影响，加载器再按新文件热重载。"""
    os.makedirs(f"{MODDIR}/{name}", exist_ok=True)
    tmp = f"{MODDIR}/{name}/{name}.so.tmp"
    shutil.copy(ROOT / "build_gnu" / f"{name}.so", tmp)
    os.replace(tmp, f"{MODDIR}/{name}/{name}.so")
def rm_module(name=MODULE):
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
        except OSError: pass
        if p.poll() is not None: return None
    return p
def stop(p):
    if p: p.terminate()
    try: p.wait(3)
    except Exception: p.kill()
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)

def wait_check(path, want, timeout=10.0):
    """轮询等待热插拔生效（loader inotify 归并 1s + 扫描）"""
    p = Path(path)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            exists = p.exists()
        except OSError:
            exists = False
        if exists == want: return True
        time.sleep(0.4)
    try:
        return p.exists() == want
    except OSError:
        return not want

def backend_serves(timeout=10.0):
    """后端是否在服务 /0/bhealth（isdir 为真 = 模块在册）"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            if os.path.isdir(f"{MNT}/0/bhealth"): return True
        except OSError: pass
        time.sleep(0.3)
    try:
        return os.path.isdir(f"{MNT}/0/bhealth")
    except OSError:
        return False

def run_case(label, body):
    print(f"\n── {label} ──")
    wconf("""
[GLOBAL]
REDIRECT /云盘 real_dir
FTP /bhealth seg1
""")
    p = start()
    if not p: return fail("启动失败")
    try:
        body(p, Path(MNT))
    finally:
        stop(p)
        try:
            shutil.copy("/tmp/fm.log", f"/tmp/fm_{label.split('.')[0]}.log")
        except OSError:
            pass

def main():
    global PASS, FAIL
    build_module()
    setup()

    def case1(p, m):
        """引擎内建：模块目录为空，REDIRECT 照样生效"""
        ok("无模块时 REDIRECT 生效") if (m/"0/云盘/hi.txt").exists() else fail(
            "REDIRECT 未生效", "空模块目录下 /0/云盘/hi.txt 不可见（规则不应依赖模块）")
        got = (m/"0/云盘/hi.txt").read_text().strip() if (m/"0/云盘/hi.txt").exists() else ""
        ok("内容重定向") if got == "redirected" else fail("内容", f"got='{got}'")
        ok("普通路径直通") if (m/"0/normal/n.txt").exists() else fail("普通路径", "/0/normal/n.txt 不可见")
        ok("无后端模块时不服务 FTP 路径") if not backend_serves(timeout=2) else fail(
            "FTP 路径不应可用", "/0/bhealth 在没有后端模块时也是目录")
    run_case("1. 规则不依赖模块（空模块目录）", case1)

    def case2(p, m):
        """热插后端模块：放入 .so → 该路径由后端接管"""
        put_module()
        ok("热插：后端接管路径") if backend_serves() else fail("热插", "放入 .so 后 /0/bhealth 仍不是目录")
        ok("热插后规则照常") if (m/"0/云盘/hi.txt").exists() else fail("规则", "热插后 /0/云盘 不可见")
    run_case("2. 热插后端模块", case2)

    def case3(p, m):
        """热拔：移除 .so → 后端不再服务，落回本地直通"""
        put_module()
        if not backend_serves():
            return fail("前置", "后端未接管，无法测热拔")
        rm_module()
        ok("热拔：后端不再服务") if wait_check(f"{MNT}/0/bhealth", False) else fail(
            "热拔", "/0/bhealth 仍由后端服务（应落回本地直通）")
        ok("热拔：普通路径不受影响") if (m/"0/normal/n.txt").exists() else fail("热拔-普通", "直通后普通文件不可见")
        ok("热拔后规则仍在（引擎独立于模块）") if (m/"0/云盘/hi.txt").exists() else fail(
            "热拔后规则", "/0/云盘/hi.txt 不可见——规则不应随模块消失")
    run_case("3. 运行中移除模块（热拔）", case3)

    def case4(p, m):
        """损坏 .so：加载失败但 daemon 存活、普通路径正常"""
        os.makedirs(f"{MODDIR}/broken", exist_ok=True)
        with open(f"{MODDIR}/broken/broken.so", "w") as fh: fh.write("not a real elf")
        time.sleep(3)
        ok("daemon 存活") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("普通路径正常") if (m/"0/normal/n.txt").exists() else fail("普通路径", "坏模块后普通文件不可见")
        rm_module("broken")
    run_case("4. 损坏 .so 容错", case4)

    print(f"\n═══════════════════════════════════════")
    print(f"[{time.strftime('%H:%M:%S')}] 测试完成 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS+FAIL}")
    if ERRS:
        for d, dt in ERRS: print(f"  失败: {d}: {dt}")
        sys.exit(1)

if __name__ == "__main__":
    main()
