#!/usr/bin/env python3
"""FTP 模块端到端测试 — ftp_module(FTP-FUSE) + basic_rules 变量 + REDIRECT。

链路：
  ftp.conf([云盘]) → ftp_module 挂载 storage/0/云盘（FTP-FUSE）
  injector.conf: FTP_云盘=云盘; REDIRECT /云盘 $FTP_云盘
  fuse_daemon：/0/云盘/xxx → storage/0/云盘/xxx → FTP 服务器（vsftpd 匿名）

覆盖：列目录 / 读现有文件 / 创建写入 / 读回 / mkdir / rename / unlink / rmdir，
并直接核对 vsftpd 匿名根（/home/bdy/ftp）验证 FTP 服务器实际变化。
"""
import subprocess, os, sys, time, shutil
from pathlib import Path

MNT      = "/tmp/fuse_ftp_test/mnt"
STORAGE  = "/tmp/fuse_ftp_test/storage"
FTP_BASE = "/tmp/fuse_ftp_test/storage/0"     # ftp_module --mount-base
FTP_ROOT = "/home/bdy/ftp"                     # vsftpd anon_root（chroot 根，须对 ftp 用户不可写）
FTP_UPLOAD = f"{FTP_ROOT}/upload"              # 匿名可写区（777），ftp.conf remote_dir=/upload
MODDIR   = "/tmp/fuse_ftp_test/modules"
CONF_FTP = "/tmp/Namespace-Proxy/ftp.conf"   # 与规则配置同目录（ftp_module init 经 get_rules_path 推导）
CONF     = "/tmp/Namespace-Proxy/injector.conf"
SERVER   = "云盘"
REPO     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DAEMON   = os.environ.get("FUSE_DAEMON") or f"{REPO}/build_gnu/fuse_daemon"
FTP_MOD_SO = os.environ.get("FTP_MODULE_SO") or f"{REPO}/build_gnu/ftp_module.so"
BASIC_RULES = os.environ.get("BASIC_RULES_SO") or f"{REPO}/build_gnu/basic_rules.so"

PASS = 0; FAIL = 0; ERRS = []
def ok(d): global PASS; PASS += 1; print(f"  ✅ {d}")
def fail(d, dt=""): global FAIL; FAIL += 1; print(f"  ❌ {d}: {dt}"); ERRS.append((d, dt))

def setup():
    shutil.rmtree("/tmp/fuse_ftp_test", ignore_errors=True)
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    os.makedirs(f"{STORAGE}/0", exist_ok=True)
    os.makedirs(MNT, exist_ok=True)
    os.makedirs("/tmp/Namespace-Proxy", exist_ok=True)
    os.makedirs(f"{MODDIR}/basic_rules", exist_ok=True)
    os.makedirs(f"{MODDIR}/ftp_module", exist_ok=True)
    if os.path.exists(BASIC_RULES):
        shutil.copy(BASIC_RULES, f"{MODDIR}/basic_rules/basic_rules.so")
    else:
        print("  ⚠ basic_rules.so 未找到")
    if os.path.exists(FTP_MOD_SO):
        shutil.copy(FTP_MOD_SO, f"{MODDIR}/ftp_module/ftp_module.so")
    else:
        print("  ⚠ ftp_module.so 未找到")
    # vsftpd 匿名 chroot 到 anon_root：根目录须对 ftp 用户不可写（否则
    # "refusing to run with writable root inside chroot()" 拒绝服务）；
    # 可写区用其下的 upload 子目录（777），ftp.conf 的 remote_dir=/upload
    if os.path.isdir(FTP_ROOT):
        os.chmod(FTP_ROOT, 0o755)
    os.makedirs(FTP_UPLOAD, exist_ok=True)
    os.chmod(FTP_UPLOAD, 0o777)
    with open(CONF_FTP, "w") as fh:
        fh.write(f"""
[{SERVER}]
host = 127.0.0.1
port = 21
user = anonymous
password =
remote_dir = /upload
""".strip())

def wait_ftp_ready(timeout=10.0):
    """等待 fuse_daemon 加载 ftp_module.so：/0/云盘 经框架后端分派可访问
       （后端方式无独立挂载点，须经 FUSE 虚拟路径探测）"""
    probe = Path(MNT) / "0" / SERVER
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if probe.is_dir(): return True
        except Exception:
            pass
        time.sleep(0.3)
    return False

def start_fuse():
    # FTP 规则：`FTP <虚拟前缀> <段名>` 写在 [GLOBAL]（全局生效）。
    # /0/云盘 剥离 /0/ 后命中规则 → 框架分派给 ftp_module（段名=SERVER）
    with open(CONF, "w") as fh:
        fh.write(f"[GLOBAL]\nFTP /{SERVER} {SERVER}\n")
    p = subprocess.Popen([DAEMON, "--root="+STORAGE, "--rules="+CONF,
                          "--modules-dir="+MODDIR, "-f", MNT, "info"],
                         stdout=open("/tmp/fuse_ftp_test/fuse.log", "w"),
                         stderr=subprocess.STDOUT)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            if os.listdir(MNT): return p
        except: pass
        if p.poll() is not None: return None
        time.sleep(0.3)
    return p

def stop_fuse(p):
    if p:
        p.terminate()
        try: p.wait(3)
        except: p.kill()
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)

def wait_ftp_content(rel, want, timeout=6.0):
    """轮询等待 FTP 上传区文件内容（FUSE release 的 STOR 上传异步完成）"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            p = Path(FTP_UPLOAD) / rel
            if p.exists() and p.read_text(errors="replace").strip() == want:
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False

def main():
    global PASS, FAIL
    print("前置：vsftpd 匿名服务（127.0.0.1:21）须已运行，匿名根 " + FTP_ROOT)
    setup()

    p = start_fuse()
    if not p:
        print("  ❌ fuse_daemon 启动失败"); sys.exit(1)
    print("  ✅ fuse_daemon 已挂载")

    # ftp_module.so 由 fuse_daemon 进程 dlopen 加载，注册后端前缀
    # （/tmp/fuse_ftp_test/storage/0/云盘）；路径经框架命中后端分派，
    # 不再存在独立 FUSE 挂载点
    if not wait_ftp_ready():
        stop_fuse(p)
        print(f"  ❌ FTP 后端未就绪: /0/{SERVER}（检查 ftp.conf / ftp_module.so / fuse.log）")
        sys.exit(1)
    print(f"  ✅ FTP 后端已注册（fuse_daemon 进程内）")

    # 预置一个已知文件到 FTP 根（供读取比对）
    orig = "compute_bench_origin.txt"
    (Path(FTP_UPLOAD)/orig).write_text("ftp-original-content")
    known_file = "compute_bench.cpp"

    m = Path(MNT)
    try:
        # 1. 列目录：/0/云盘/ 显示 FTP 根内容
        try:
            items = sorted(os.listdir(m/"0"/SERVER))
            print(f"  [列表] /0/云盘/ → {items[:6]}{'...' if len(items)>6 else ''}")
            ok("列目录（FTP 根内容可见）") if known_file in items or orig in items else fail("列目录", f"缺 {known_file}")
        except Exception as e: fail("列目录", str(e))

        # 2. 读现有 FTP 文件
        try:
            got = (m/"0"/SERVER/orig).read_text().strip()
            ok("读取现有 FTP 文件") if got == "ftp-original-content" else fail("读文件", f"got='{got}'")
        except Exception as e: fail("读文件", str(e))

        # 3. 创建 + 写入 → FTP 根出现
        newf = "nsp_test_write.txt"
        try:
            (m/"0"/SERVER/newf).write_text("hello from fuse-ftp")
            ok("写入新文件（FTP 出现）") if (Path(FTP_UPLOAD)/newf).exists() else fail("写文件", "FTP 根未见")
            ok("内容正确") if wait_ftp_content(newf, "hello from fuse-ftp") else fail("写内容", "FTP 内容未同步")
        except Exception as e: fail("写文件", str(e))

        # 4. 读回（经 fuse）
        try:
            got = (m/"0"/SERVER/newf).read_text().strip()
            ok("读回写入内容") if got == "hello from fuse-ftp" else fail("读回", f"got='{got}'")
        except Exception as e: fail("读回", str(e))

        # 5. mkdir → FTP 出现目录
        d1 = "nsp_test_dir"
        try:
            (m/"0"/SERVER/d1).mkdir()
            ok("mkdir（FTP 出现目录）") if (Path(FTP_UPLOAD)/d1).is_dir() else fail("mkdir", "FTP 未见目录")
        except Exception as e: fail("mkdir", str(e))

        # 6. rename（经 fuse）→ FTP 验证
        try:
            (m/"0"/SERVER/newf).rename(m/"0"/SERVER/"nsp_renamed.txt")
            ok("rename（FTP 验证）") if (Path(FTP_UPLOAD)/"nsp_renamed.txt").exists() and not (Path(FTP_UPLOAD)/newf).exists() else fail("rename", "FTP 侧不一致")
        except Exception as e: fail("rename", str(e))

        # 7. unlink → FTP 消失
        try:
            (m/"0"/SERVER/"nsp_renamed.txt").unlink()
            ok("unlink（FTP 删除）") if not (Path(FTP_UPLOAD)/"nsp_renamed.txt").exists() else fail("unlink", "FTP 侧仍存在")
        except Exception as e: fail("unlink", str(e))

        # 8. rmdir → FTP 消失
        try:
            (m/"0"/SERVER/d1).rmdir()
            ok("rmdir（FTP 删除目录）") if not (Path(FTP_UPLOAD)/d1).exists() else fail("rmdir", "FTP 目录仍存在")
        except Exception as e: fail("rmdir", str(e))

        # 9. 非 FTP 路径不受影响（普通存储直通）
        try:
            (Path(STORAGE)/"0/normal.txt").write_text("local")
            got = (m/"0/normal.txt").read_text().strip()
            ok("普通路径直通") if got == "local" else fail("普通路径", f"got='{got}'")
        except Exception as e: fail("普通路径", str(e))

    finally:
        stop_fuse(p)   # fuse_daemon 退出 → 模块 exit 清理后端
        # 清理测试残留
        for f in [orig]:
            fp = Path(FTP_UPLOAD)/f
            if fp.exists(): fp.unlink()

    print(f"\n═══════════════════════════════════════")
    print(f"[{time.strftime('%H:%M:%S')}] 测试完成 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS+FAIL}")
    if ERRS:
        for d, dt in ERRS: print(f"  失败: {d}: {dt}")
        sys.exit(1)

if __name__ == "__main__":
    main()
