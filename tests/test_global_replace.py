#!/usr/bin/env python3
"""
注入方法 v2（全局替换）测试
===========================================
在**私有挂载命名空间**中模拟安卓 emulated 挂载视图，驱动
build_gnu/global_replace_ctl 验证新方法的完整生命周期：
  replace（备份一个族 + 三族全部替换为项目 FUSE 源）
  status（normal/replaced/mixed 状态判定，基于 major:minor 设备号）
  app-restore（非目标应用命名空间内卸载项目 FUSE 并还原系统视图）
  restore（从备份恢复三族视图）

模拟视图（对照真实设备 mount 输出）：
  三族 × 多用户：/mnt/{installer,androidwritable,user}/{0,999}/emulated
  f2fs 直通子挂载：.../emulated/<uid>/Android/{data,obb}
  嵌套跨用户 fuse 视图：.../emulated/<其他用户>
  排除项：/mnt/pass_through/0/emulated（直通视图，不得被替换）
  项目 FUSE 源：/mnt/nsp_global

运行要求：免 root——经 `unshare --user --map-root-user --mount`
进 rootless 沙箱（映射根用户后即具挂载权限），先 `mount --make-rprivate /`
切断传播，全程不污染宿主；userns 不可用时跳过。
"""
import os, sys, time, subprocess, shutil, ctypes

CLONE_NEWNS = 0x00020000
LIB_C = ctypes.CDLL("libc.so.6", use_errno=True)

CTL = os.environ.get("GLOBAL_REPLACE_CTL") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "build_gnu", "global_replace_ctl"))
FUSE_SRC = "/mnt/nsp_global"
BACKUP_ROOT = "/tmp/fuse_global_replace_test/backup"
FAMILIES = ["installer", "androidwritable", "user"]
USERS = [0, 999]

PASS = 0
FAIL = 0
ERRORS = []


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


def ok(desc):
    global PASS
    PASS += 1
    log(f"  ✅ {desc}")


def fail(desc, detail=""):
    global FAIL
    FAIL += 1
    log(f"  ❌ {desc}: {detail}")
    ERRORS.append((desc, detail))


def sh(*args, check=True):
    r = subprocess.run(args, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} 失败: {r.stderr.strip()}")
    return r


def mount_tmpfs(path):
    os.makedirs(path, exist_ok=True)
    sh("mount", "-t", "tmpfs", "tmpfs", path)


def read_mountinfo(pid=None):
    path = f"/proc/{pid}/mountinfo" if pid else "/proc/self/mountinfo"
    entries = []
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 6:
                continue
            # 字段: id parent major:minor root mountpoint ...
            dev = parts[2]
            mp = parts[4]
            fstype = src = ""
            if " - " in line:
                tail = line.split(" - ", 1)[1].split()
                if len(tail) >= 2:
                    fstype, src = tail[0], tail[1]
            entries.append({"dev": dev, "mount_point": mp, "fstype": fstype, "src": src})
    return entries


def mount_dev(pid, mp):
    for e in read_mountinfo(pid):
        if e["mount_point"] == mp:
            return e["dev"]
    return None


def child_mount_dev(pid, mp):
    """读子进程命名空间内挂载设备号；子进程已退出时返回 None，不抛异常。"""
    try:
        return mount_dev(pid, mp)
    except (FileNotFoundError, ProcessLookupError, OSError):
        return None


def is_mounted(pid, mp):
    return any(e["mount_point"] == mp for e in read_mountinfo(pid))


def ctl_status(pid):
    r = sh(CTL, "status", str(pid), FUSE_SRC, check=False)
    out = r.stdout.strip()
    if "status=" not in out:
        return "unknown"
    return out.split("status=", 1)[1].split("(", 1)[0]


def setup_view():
    """在私有命名空间中构造模拟安卓视图。"""
    # 先切断挂载传播：测试挂载绝不回流宿主（沙箱退出后内核自动回收）
    sh("mount", "--make-rprivate", "/")
    os.makedirs(BACKUP_ROOT, exist_ok=True)
    mount_tmpfs(FUSE_SRC)  # 项目 FUSE 源（模拟 fuse_daemon 挂载）
    for fam in FAMILIES:
        for uid in USERS:
            mount_tmpfs(f"/mnt/{fam}/{uid}/emulated")  # 模拟系统 /dev/fuse
    # f2fs 直通子挂载：user 族 × data/obb
    for uid in USERS:
        for sub in ("Android/data", "Android/obb"):
            p = f"/mnt/user/{uid}/emulated/{uid}/{sub}"
            mount_tmpfs(p)
    # 嵌套跨用户 fuse 视图：/mnt/user/0/emulated/999 与 /mnt/user/999/emulated/0
    mount_tmpfs("/mnt/user/0/emulated/999")
    mount_tmpfs("/mnt/user/999/emulated/0")
    # 排除项：pass_through 直通视图（f2fs，不得被替换）
    mount_tmpfs("/mnt/pass_through/0/emulated")


def teardown():
    """清理：卸载测试挂载（按最深优先）。命名空间销毁时也会自动清理。"""
    mps = [e["mount_point"] for e in read_mountinfo()
           if e["mount_point"].startswith(("/mnt/", "/storage/emulated"))]
    for mp in sorted(mps, key=lambda s: s.count("/"), reverse=True):
        subprocess.run(["umount", "-l", mp], capture_output=True)


def run_tests():
    pid = os.getpid()

    # 1. 初始状态：全部为系统视图
    log("场景1: 初始状态判定 (normal)")
    st = ctl_status(pid)
    if st == "normal":
        ok("初始 status == normal")
    else:
        fail("初始 status", f"期望 normal 实际 {st}")
    # 排除项在初始/替换后都应保持直通
    pass_dev_before = mount_dev(pid, "/mnt/pass_through/0/emulated")

    # 2. replace：备份一个族 + 三族全部替换
    log("场景2: 全局替换 (replace)")
    r = sh(CTL, "replace", str(pid), FUSE_SRC, BACKUP_ROOT, check=False)
    if r.returncode == 0:
        ok("replace 命令返回 0")
    else:
        fail("replace 命令", f"rc={r.returncode} {r.stdout.strip()}")
        return

    src_dev = mount_dev(pid, FUSE_SRC)
    # 三族 × 每用户族根全部替换为项目 FUSE（dev 相同）
    all_replaced = True
    for fam in FAMILIES:
        for uid in USERS:
            d = mount_dev(pid, f"/mnt/{fam}/{uid}/emulated")
            if d != src_dev:
                all_replaced = False
                fail(f"族根替换: /mnt/{fam}/{uid}/emulated", f"dev={d} != src_dev={src_dev}")
    if all_replaced:
        ok("三族 × 每用户族根均已替换为项目 FUSE (dev 一致)")
    # 子挂载（f2fs 直通 data/obb）已随替换卸载，不再残留
    sub_gone = all(
        not is_mounted(pid, f"/mnt/user/{uid}/emulated/{uid}/{sub}")
        for uid in USERS for sub in ("Android/data", "Android/obb"))
    if sub_gone:
        ok("f2fs 直通子挂载 (Android/data, obb) 已全部卸载（不遗漏）")
    else:
        fail("子挂载卸载", "data/obb 仍有残留")
    # 嵌套跨用户视图已卸载
    if not is_mounted(pid, "/mnt/user/0/emulated/999"):
        ok("嵌套跨用户视图 (/mnt/user/0/emulated/999) 已卸载")
    else:
        fail("嵌套视图卸载", "999 视图仍挂载")
    # 排除项未被替换
    pass_dev_after = mount_dev(pid, "/mnt/pass_through/0/emulated")
    if pass_dev_after == pass_dev_before:
        ok("排除项 /mnt/pass_through 保持直通未被替换")
    else:
        fail("排除项", f"pass_through dev 变化 {pass_dev_before} -> {pass_dev_after}")
    # 备份点已创建（备份族 = user，每用户一份）
    if is_mounted(pid, f"{BACKUP_ROOT}/user_0/emulated"):
        ok("备份点已创建: backup/user_0/emulated")
    else:
        fail("备份点创建", "backup/user_0/emulated 未挂载")

    # 3. status 判定
    log("场景3: 替换后状态判定 (replaced)")
    st = ctl_status(pid)
    if st == "replaced":
        ok("替换后 status == replaced")
    else:
        fail("替换后 status", f"期望 replaced 实际 {st}")

    # 4. app-restore：非目标应用命名空间还原
    log("场景4: 非目标应用还原 (app-restore)")
    child = os.fork()
    if child == 0:
        # 子进程模拟"非目标应用"：独立私有命名空间，/storage/emulated 顶层为项目 FUSE
        try:
            LIB_C.unshare(CLONE_NEWNS)
            os.makedirs("/storage/emulated", exist_ok=True)
            subprocess.run(["mount", "--bind", FUSE_SRC, "/storage/emulated"],
                           check=True, capture_output=True)
            time.sleep(30)
        except Exception as e:
            # setup 失败必须非零退出并报错，否则父进程无法区分"未就绪"与"成功"
            log(f"子进程(应用) setup 失败: {e}")
            os._exit(1)
        os._exit(0)
    time.sleep(0.5)
    # 子进程 setup 失败会提前退出（exit 1）：先 WNOHANG 回收检查，
    # 避免后续读 /proc/<pid>/mountinfo 时抛未处理异常拖垮整个测试
    child_reaped = False
    try:
        wpid, _ = os.waitpid(child, os.WNOHANG)
        child_reaped = (wpid == child)
    except OSError:
        child_reaped = True
    if child_reaped:
        fail("应用子进程 setup", "子进程提前退出（unshare/mount 失败），场景4无法验证")
    else:
        # 子进程命名空间内 /storage/emulated 应已为项目 FUSE 视图
        child_src_dev = child_mount_dev(child, "/storage/emulated")
        if child_src_dev == src_dev:
            ok(f"子进程(应用)命名空间内 /storage/emulated 为项目 FUSE 视图 (dev={child_src_dev})")
        else:
            fail("应用视图准备", f"child /storage/emulated dev={child_src_dev} != {src_dev}")
        r = sh(CTL, "app-restore", str(child), FUSE_SRC, BACKUP_ROOT, "0", check=False)
        if r.returncode == 0:
            ok("app-restore 命令返回 0")
        else:
            fail("app-restore 命令", f"rc={r.returncode} {r.stdout.strip()}")
        time.sleep(0.3)
        child_after = child_mount_dev(child, "/storage/emulated")
        if child_after != src_dev:
            ok(f"非目标应用 /storage/emulated 已还原为系统视图 (dev={child_after})")
        else:
            fail("应用还原", f"child /storage/emulated 仍是项目 FUSE dev={child_after}")
    # 清理子进程（可能已退出，需防 OSError）
    if not child_reaped:
        try:
            os.kill(child, 9)
        except OSError:
            pass
        os.waitpid(child, 0)

    # 4.5 配置审查与强制回收（audit/force-recover，全局替换模式）
    log("场景4.5: 配置审查与强制回收 (audit/force-recover, 全局替换模式)")
    child2 = os.fork()
    if child2 == 0:
        # 子进程模拟"非目标应用"：独立私有命名空间，/storage/emulated 为项目 FUSE 视图。
        # tmpfs 不支持 fsname 选项；用 bind 源路径含 fuse_daemon 的方式，使 mountinfo
        # source 字段含 fuse_daemon（ns_is_mounted 按 source/fstype 字符串识别）
        try:
            LIB_C.unshare(CLONE_NEWNS)
            os.makedirs("/mnt/fuse_daemon_view", exist_ok=True)
            subprocess.run(["mount", "-t", "tmpfs", "tmpfs", "/mnt/fuse_daemon_view"],
                           check=True, capture_output=True)
            os.makedirs("/storage/emulated", exist_ok=True)
            subprocess.run(["mount", "--bind", "/mnt/fuse_daemon_view", "/storage/emulated"],
                           check=True, capture_output=True)
            time.sleep(30)
        except Exception as e:
            log(f"子进程(审查) setup 失败: {e}")
            os._exit(1)
        os._exit(0)
    time.sleep(0.5)
    child2_reaped = False
    try:
        wpid, _ = os.waitpid(child2, os.WNOHANG)
        child2_reaped = (wpid == child2)
    except OSError:
        child2_reaped = True
    if child2_reaped:
        fail("审查子进程 setup", "子进程提前退出，场景4.5无法验证")
    else:
        if child_mount_dev(child2, "/storage/emulated") is not None:
            ok("审查子进程 /storage/emulated 已就绪 (fuse_daemon 视图)")
        else:
            fail("审查子进程准备", "/storage/emulated 未挂载")
        # 单进程组合：set-src + add-tracked + audit + force-recover 一次调用完成，
        # 状态（追踪表/fuse_src）在进程内共享，避免跨进程状态丢失导致空洞通过
        r = sh(CTL, "audit-run", str(child2), FUSE_SRC, "10000", "com.audit.test", "v2",
               check=False)
        if r.returncode == 0:
            ok("audit-run(全局替换) 命令返回 0")
        else:
            fail("audit-run(v2)", f"rc={r.returncode} {r.stdout.strip()}")
        out = r.stdout.strip()
        import re as _re
        m = _re.search(r"audit_mounted=(\d+) force_mounted=(\d+)", out)
        if m:
            audit_mounted, force_mounted = int(m.group(1)), int(m.group(2))
            if audit_mounted == 1:
                ok("全局替换模式: audit 保留项目视图（未执行旧式卸载）")
            else:
                fail("audit(on) 保留视图", f"audit_mounted={audit_mounted}")
            if force_mounted == 1:
                ok("全局替换模式: force-recover 跳过逐应用卸载（挂载保持）")
            else:
                fail("force-recover(v2) 跳过卸载", f"force_mounted={force_mounted}")
        else:
            fail("audit-run 输出解析", f"无法解析: {out}")
    if not child2_reaped:
        try:
            os.kill(child2, 9)
        except OSError:
            pass
        os.waitpid(child2, 0)

    # 5. restore：从备份恢复三族
    log("场景5: 全局恢复 (restore)")
    r = sh(CTL, "restore", str(pid), BACKUP_ROOT, check=False)
    if r.returncode == 0:
        ok("restore 命令返回 0")
    else:
        fail("restore 命令", f"rc={r.returncode} {r.stdout.strip()}")
        return
    # 族根不再是项目 FUSE（dev 与 FUSE 源不同）
    restored = all(
        mount_dev(pid, f"/mnt/{fam}/{uid}/emulated") != src_dev
        for fam in FAMILIES for uid in USERS)
    if restored:
        ok("三族族根已恢复为系统视图 (dev != FUSE 源)")
    else:
        fail("族根恢复", "仍有族根是项目 FUSE")
    # 子挂载还原（备份含 data/obb，恢复时逐节点 bind 回来）
    sub_back = all(
        is_mounted(pid, f"/mnt/user/{uid}/emulated/{uid}/{sub}")
        for uid in USERS for sub in ("Android/data", "Android/obb"))
    if sub_back:
        ok("f2fs 直通子挂载已随恢复还原")
    else:
        fail("子挂载还原", "data/obb 未还原")
    # 备份点已卸载
    if not is_mounted(pid, f"{BACKUP_ROOT}/user_0/emulated"):
        ok("备份点已卸载")
    else:
        fail("备份点卸载", "backup/user_0/emulated 仍挂载")

    # 6. 恢复后状态
    log("场景6: 恢复后状态判定 (normal)")
    st = ctl_status(pid)
    if st == "normal":
        ok("恢复后 status == normal")
    else:
        fail("恢复后 status", f"期望 normal 实际 {st}")


def mountinfo_snapshot():
    try:
        with open("/proc/self/mountinfo") as fh:
            return sorted(fh.read().splitlines())
    except OSError:
        return []


def inner_main():
    """rootless 沙箱内执行体：隔离挂载 + 全场景不断言遗漏。"""
    try:
        setup_view()
        run_tests()
    finally:
        teardown()
    print(f"\n结果: {PASS} 通过, {FAIL} 失败")
    if ERRORS:
        for d, det in ERRORS:
            print(f"  ❌ {d}: {det}")
        return 1
    return 0


def userns_available():
    if shutil.which("unshare") is None:
        return False
    r = subprocess.run(["unshare", "--user", "--map-root-user", "--mount", "true"],
                       capture_output=True, timeout=15)
    return r.returncode == 0


def main():
    if not os.path.exists(CTL):
        log(f"跳过：找不到测试驱动 {CTL}（请先构建 build_gnu）")
        return 0
    if not userns_available():
        log("跳过：user/mount ns 不可用（需要 unshare 与 userns 权限）")
        return 0
    host_before = mountinfo_snapshot()
    # rootless 沙箱：映射根用户后具挂载权限；测试挂载 confined 于私有命名空间，
    # 进程退出即随命名空间销毁，宿主零残留（另有前后 mountinfo 比对兜底）
    cmd = ["unshare", "--user", "--map-root-user", "--mount",
           sys.executable, os.path.abspath(__file__), "--inner"]
    try:
        r = subprocess.run(cmd, timeout=180)
        rc = r.returncode
    except subprocess.TimeoutExpired:
        log("失败：沙箱内测试超时(180s)")
        rc = 1
    host_after = mountinfo_snapshot()
    if host_before != host_after:
        diff = [l for l in host_after if l not in host_before][:6]
        log(f"  ❌ 宿主 mountinfo 被污染: {'; '.join(diff)}")
        rc = 1
    else:
        log("  ✅ 宿主 mountinfo 零变化")
    # /tmp 下测试目录仅为占位（挂载已随命名空间销毁），尽力清理
    shutil.rmtree(os.path.dirname(BACKUP_ROOT), ignore_errors=True)
    if rc != 0:
        sys.exit(rc)
    return rc


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        sys.exit(inner_main())
    sys.exit(main())
