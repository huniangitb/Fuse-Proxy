#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_inject_mount_env.py — rootless 容器沙箱中的真实挂载拓扑测试
======================================================================

目的
----
让 GNU 构建的 ``injector``（默认 ``build_gnu/injector``）在一个 **rootless
容器沙箱**（unshare user+mount+pid+net namespace）里真实执行
``--inject-method=v1/v2/v3`` 的完整挂载生命周期：FUSE 就绪 →（v2/v3）
emulated 三族全局替换 → REQ 注入/非目标还原 → SIGTERM 退出清理，全程对挂载
结果做确定性断言。沙箱 pivot_root 后宿主旧根彻底脱离，与宿主完全隔离、零污染。

拓扑依据（AOSP 源码实证，沙箱照抄真机时序）
--------------------------------------------
* ``system/core/rootdir/init.rc`` on post-fs::

      mount none /mnt/user/0 /storage bind rec
      mount none none /storage slave rec

  即 ``/storage`` = ``/mnt/user/0`` 的递归 bind + 递归 make-slave；此后
  ``/mnt``（tmpfs，MS_SHARED）上的族根挂载沿传播到达 ``/storage/emulated``
  （根偏移 slave-bind 的子挂载传播）。
* ``frameworks/base/core/jni/com_android_internal_os_Zygote.cpp``
  （MountEmulatedStorage / UnmountStorageOnInit）：应用命名空间 =
  ``unshare(CLONE_NEWNS)`` + ``MS_REC|MS_SLAVE /`` + 懒卸 ``/storage`` 树 +
  ``rbind /mnt/user/0 → /storage``。
* ``system/vold/model/EmulatedVolume.cpp``：fuse 挂
  ``/mnt/<installer|androidwritable|user>/<uid>/emulated``（族根），
  ``Android/data`` 为族根下的子挂载。

沙箱结构
--------
tmpfs 根（pivot_root 后旧根从 ``/oldroot`` 懒卸并校验彻底脱离）+ rbind
``/usr /bin /sbin /lib /lib64 /etc /sys /dev``（单向 slave，只读降级，
``/dev`` 保留可写）+ 仓库只读绑定（二进制在原路径可执行）+ ``chan`` 读写
绑定（report.json 与日志直达宿主）+ 新 pid ns 的 proc + tmpfs ``/tmp``；
随后 ``MS_REC|MS_SHARED /`` 再建拓扑。宿主侧负责 unshare 拉起、超时
TERM→KILL 升级、宿主 mountinfo 前后比对、按 cmdline 标记甄别残留进程。

覆盖点（每个注入方法独立沙箱、串行）
--------------------------------------
1. 拓扑基线：``/storage/emulated`` = 系统视图、``0/Android/data`` 子挂载就位；
2. FUSE 就绪：``/mnt/nsp_global`` 挂载；v2/v3 三族族根全部替换为项目 FUSE、
   ``/storage/emulated`` 经传播跟随、备份点建立、原生子挂载随替换卸载；
3. 应用可见性：替换前启动的 app1 与替换后启动的 app2（各自跑 zygote 序列）
   在其命名空间内均跟随为项目 FUSE（v2/v3）；v1 全程不动 init 族根；
4. REQ：目标应用标记注入（``LIST_INJECTED``）；v2 非目标在自身 ns 还原系统
   视图、v3 不还原；v1 目标逐应用挂载且保留原生子挂载、非目标不动；
5. 文件级 IO：系统标记/项目标记互斥可见（init ns 经 ``/storage/emulated``）；
6. SIGTERM 退出清理：族根/应用视图回到系统视图、``/mnt/nsp_global`` 卸载、
   备份点卸载、目标应用逐应用挂载回收、injector 与 fuse_daemon 全部退出。

运行
----
    python3 tests/test_inject_mount_env.py

环境变量：
    ``INJECTOR``        injector 路径（默认 ``build_gnu/injector``；必须位于
                        仓库内——沙箱按原路径绑定，且其旁须有 ``fuse_daemon``，
                        injector 经 ``get_self_dir()`` 定位它）

前置：GNU 产物、``/dev/fuse``、可用的 unshare(1)；userns 不可用时自动跳过。
失败诊断：``<workdir>/inner.log``（沙箱控制台）与 ``<workdir>/chan/log/``
（``sys.log`` / ``io.log`` / ``fuse_crash.log``，经 chan 绑定直达宿主）。
"""

import ctypes
import errno as errno_mod
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time

# ─────────────────────────── 路径与常量 ───────────────────────────

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INJECTOR = os.environ.get("INJECTOR") or os.path.join(REPO, "build_gnu", "injector")
LOG_MONITOR = os.path.join(os.path.dirname(INJECTOR), "log_monitor")
ROOTBASE = "/tmp/fuse_proxy_test/mnt_env"
METHODS = ("v1", "v2", "v3")

TARGET_PKG = "com.test.target"
NONTARGET_PKG = "com.test.nontarget"

CONFIG_PATH = "/var/fuse-proxy/injector.conf"
GLOBAL_MNT = "/mnt/nsp_global"
MEDIA_MNT = "/mnt/nsp_media"
STORAGE_EMU = "/storage/emulated"
FAMILY_ROOTS = (
    "/mnt/user/0/emulated",
    "/mnt/installer/0/emulated",
    "/mnt/androidwritable/0/emulated",
)
FAM_SUB = "/mnt/user/0/emulated/0/Android/data"  # 族根下的原生子挂载
STG_SUB = STORAGE_EMU + "/0/Android/data"        # /storage 视角的子挂载
SYS_MARK = STORAGE_EMU + "/0/sys_marker"         # 系统视图标记
PROJ_MARK = STORAGE_EMU + "/0/proj_marker"       # 项目视图标记（经 FUSE）
PROJ_MARK_PHYS = "/var/fuse-proxy/storage/0/proj_marker"
BACKUP_TOP = "/var/fuse-proxy/backup/global_emulated/user_0/emulated"

# 残留进程甄别标记（沙箱进程一旦漏杀，必然带其一；宿主自身不带）
HOST_MARKERS = ("--inject-method=", "--ready-fd=", "--workdir",
                TARGET_PKG, NONTARGET_PKG)

# 配置：GLOBAL_INJECT OFF → v1 不拉媒体 FUSE；目标段带实质规则（否则 v1
# perform_app_mount 走「无规则保留原生视图」跳过且不 mark_injected）
CONFIG_TEXT = """[GLOBAL]
GLOBAL_INJECT OFF
SKIP_SYSTEM_APPS OFF

[com.test.target] ON
HIDE /HIDE_ME/

[com.test.nontarget] OFF
"""

# ─────────────────────────── mount 原语 ───────────────────────────

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MS_SLAVE = 1 << 19
MS_SHARED = 1 << 20
MNT_DETACH = 2
CLONE_NEWNS = 0x00020000

_SYS_PIVOT_ROOT = {"x86_64": 155, "amd64": 155, "aarch64": 41, "arm64": 41,
                   "armv7l": 217, "i686": 217, "i386": 217}

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.c_char_p]


def _b(s):
    return s if isinstance(s, (bytes, type(None))) else s.encode()


def mount(source, target, fstype=None, flags=0, data=None):
    """mount(2) 包装：字符串参数自动编码；失败抛 OSError。"""
    r = libc.mount(_b(source), _b(target), _b(fstype), ctypes.c_ulong(flags), _b(data))
    if r != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"mount({source}, {target}, flags={flags}): {os.strerror(e)}")


def umount2(path, flags=0):
    """umount2 包装：失败抛 OSError。"""
    r = libc.umount2(_b(path), ctypes.c_ulong(flags))
    if r != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"umount2({path}): {os.strerror(e)}")


# ─────────────────────────── mountinfo 解析 ───────────────────────────

def read_mountinfo(pid=None):
    """返回挂载条目列表（顺序 = mount id 递增 = 底层在前、顶层在后）。"""
    path = f"/proc/{pid}/mountinfo" if pid else "/proc/self/mountinfo"
    entries = []
    try:
        with open(path) as fh:
            for line in fh:
                left, sep, right = line.partition(" - ")
                lp = left.split()
                rp = right.split()
                if not sep or len(lp) < 6 or len(rp) < 1:
                    continue
                entries.append({
                    "dev": lp[2], "root": lp[3], "mp": lp[4],
                    "fstype": rp[0], "src": rp[1] if len(rp) > 1 else "",
                })
    except OSError:
        return []
    return entries


def top_entry(mp, pid=None):
    """最顶层（最后一条）覆盖 mp 的挂载条目；未挂载返回 None。
       与 do_restore_app_fuse 的「最后一条=实际生效视图」约定一致。"""
    ent = None
    for e in read_mountinfo(pid):
        if e["mp"] == mp:
            ent = e
    return ent


def dev_at(mp, pid=None):
    e = top_entry(mp, pid)
    return e["dev"] if e else None


def entry_desc(e):
    if not e:
        return "(未挂载)"
    return f"dev={e['dev']} {e['fstype']} src={e['src']}"


def read_text(path):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return None


def find_procs(marker):
    """沙箱 pid ns 内含 marker 的进程 pid 列表。"""
    out = []
    try:
        names = os.listdir("/proc")
    except OSError:
        return out
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as fh:
                cmd = fh.read()
        except OSError:
            continue
        if marker.encode() in cmd:
            out.append(int(name))
    return out


# ─────────────────────────── 宿主侧 ───────────────────────────

PASS = 0
FAIL = 0


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


def mountinfo_snapshot():
    try:
        with open("/proc/self/mountinfo") as fh:
            return sorted(fh.read().splitlines())
    except OSError:
        return []


def preflight():
    """返回 (skips, errors)：skips → 环境不支持，退出 0；errors → 产物缺失，也退出 0（沿用仓库跳过约定）。"""
    skips, errors = [], []
    if not os.path.exists("/dev/fuse"):
        skips.append("缺少 /dev/fuse（内核未启用 FUSE）")
    if shutil.which("unshare") is None:
        skips.append("缺少 unshare(1)")
    else:
        r = subprocess.run(["unshare", "--user", "--map-root-user", "--mount",
                            "--pid", "--fork", "--net", "true"],
                           capture_output=True, timeout=15)
        if r.returncode != 0:
            skips.append(f"unshare user/mount/pid ns 不可用（rc={r.returncode}）")
    if not os.path.exists(INJECTOR):
        errors.append(f"缺少 injector 产物 {INJECTOR}（请先构建 build_gnu）")
    if not os.path.exists(os.path.join(os.path.dirname(INJECTOR), "fuse_daemon")):
        errors.append(f"缺少 {os.path.dirname(INJECTOR)}/fuse_daemon（injector 经 get_self_dir() 定位）")
    repo = os.path.realpath(REPO)
    if os.path.exists(INJECTOR) and not os.path.realpath(INJECTOR).startswith(repo):
        errors.append(f"INJECTOR={INJECTOR} 须位于仓库内（沙箱按原路径绑定仓库）")
    return skips, errors


def host_marker_pids():
    """宿主上疑似沙箱残留的进程 [(pid, cmdline 首段)]。"""
    out = []
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) == os.getpid():
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as fh:
                cmd = fh.read()
        except OSError:
            continue
        text = cmd.replace(b"\0", b" ").decode(errors="replace")
        if any(m in text for m in HOST_MARKERS):
            out.append((int(name), text.split(" ")[0]))
    return out


def sweep_kill(pids):
    for pid, _ in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def tail_file(path, lines=30):
    try:
        with open(path, errors="replace") as fh:
            return "".join(fh.readlines()[-lines:])
    except OSError:
        return "(无日志)"


def run_method(method):
    """在独立 rootless 沙箱中跑一个注入方法的全流程。返回 (rc, report, workdir, timed_out)。"""
    workdir = os.path.join(ROOTBASE, method)
    shutil.rmtree(workdir, ignore_errors=True)
    chan = os.path.join(workdir, "chan")
    os.makedirs(chan, exist_ok=True)
    os.makedirs(os.path.join(chan, "log"), exist_ok=True)
    inner_log = os.path.join(workdir, "inner.log")

    cmd = ["unshare", "--user", "--map-root-user", "--mount", "--pid", "--fork",
           "--net", "--kill-child=SIGKILL",
           sys.executable, os.path.abspath(__file__), "--inner",
           "--method", method, "--workdir", workdir]
    log(f"▶ 方法 {method}: 启动沙箱 {os.path.basename(workdir)} …")
    timed_out = False
    with open(inner_log, "w") as lf:
        proc = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT,
                                start_new_session=True)
        deadline = time.monotonic() + 120
        while proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.2)
        if proc.poll() is None:
            timed_out = True
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(proc.pid, sig)
                except OSError:
                    pass
                for _ in range(50):
                    if proc.poll() is not None:
                        break
                    time.sleep(0.1)
                if proc.poll() is not None:
                    break
        rc = proc.wait()

    report = None
    rpath = os.path.join(chan, "report.json")
    if os.path.exists(rpath):
        try:
            with open(rpath) as fh:
                report = json.load(fh)
        except (OSError, ValueError) as e:
            log(f"  report.json 解析失败: {e}")

    # 残留进程甄别：先判定（作为断言），再兜底清理
    leftovers = host_marker_pids()
    host_before = MOUNTINFO_SNAPSHOT
    host_after = mountinfo_snapshot()

    if rc == 0 and not timed_out and report and report.get("done") and not report.get("fatal"):
        ok(f"{method}: 沙箱内全部断言通过（{len(report['checks'])} 项）")
    else:
        why = []
        if timed_out:
            why.append("沙箱超时(120s)")
        if report is None:
            why.append("报告缺失")
        else:
            if report.get("fatal"):
                why.append(f"fatal={report['fatal']}")
            if not report.get("done"):
                why.append(f"未完成(阶段 {report.get('phase')})")
        if rc != 0 and not timed_out:
            why.append(f"沙箱退出码 {rc}")
        fail(f"{method}: 沙箱流程", "; ".join(why) or "未知")
        if report:
            for c in report.get("checks", []):
                if not c["ok"]:
                    log(f"      ✗ {c['name']}: {c['detail']}")
        log(f"  ── inner.log 尾部（{inner_log}）──")
        log(tail_file(inner_log))

    if leftovers:
        fail(f"{method}: 宿主残留沙箱进程", ", ".join(f"{p}:{n}" for p, n in leftovers))
        sweep_kill(leftovers)
    else:
        ok(f"{method}: 无沙箱残留进程")

    if host_before == host_after:
        ok(f"{method}: 宿主 mountinfo 零变化")
    else:
        diff = [l for l in host_after if l not in host_before][:6]
        fail(f"{method}: 宿主 mountinfo 被污染", "; ".join(diff))

    return rc, report, workdir, timed_out


def main():
    skips, errors = preflight()
    if skips:
        for s in skips:
            log(f"跳过：{s}")
        return 0
    if errors:
        for e in errors:
            log(f"跳过：{e}")
        return 0

    global MOUNTINFO_SNAPSHOT
    MOUNTINFO_SNAPSHOT = mountinfo_snapshot()
    os.makedirs(ROOTBASE, exist_ok=True)
    log(f"沙箱挂载环境测试：injector={INJECTOR}；宿主 mountinfo 基线 {len(MOUNTINFO_SNAPSHOT)} 行")

    for method in METHODS:
        rc, report, workdir, timed_out = run_method(method)

    leftovers = host_marker_pids()
    if leftovers:
        fail("全部方法结束后仍有残留进程", str(leftovers))
        sweep_kill(leftovers)
    if MOUNTINFO_SNAPSHOT == mountinfo_snapshot():
        ok("宿主 mountinfo 全程零变化")
    else:
        fail("宿主 mountinfo 全程零变化", "前后不一致")

    print(f"\n结果: {PASS} 通过, {FAIL} 失败")
    if FAIL:
        print("失败诊断：各方法 workdir 下的 inner.log 与 chan/log/{sys,io,fuse_crash}.log")
        return 1
    return 0


# ─────────────────────────── 沙箱内（--inner） ───────────────────────────

STOP = False


def _on_term(signum, frame):
    global STOP
    STOP = True


class Report:
    """渐进式落盘的断言报告（每个检查写盘，中途被杀也可取证）。"""

    def __init__(self, host_path, method):
        self.host_path = host_path
        self.method = method
        self.phase_name = "init"
        self.checks = []
        self.fatal = None
        self.done = False

    def path(self):
        # pivot 后宿主路径不存在，落到 /chan（同一目录的沙箱内视图）
        if os.path.exists(os.path.dirname(self.host_path)):
            return self.host_path
        return "/chan/report.json"

    def set_phase(self, name):
        self.phase_name = name
        self.flush()

    def check(self, name, okv, detail=""):
        self.checks.append({"name": name, "ok": bool(okv), "detail": str(detail)[:600]})
        log(f"  {'✅' if okv else '❌'} {name}" + (f" — {detail}" if detail and not okv else ""))
        self.flush()

    def set_fatal(self, msg):
        self.fatal = str(msg)[:600]
        self.flush()

    def finish(self, done=True):
        self.done = done
        self.flush()

    def flush(self):
        data = {"method": self.method, "phase": self.phase_name, "fatal": self.fatal,
                "checks": self.checks, "done": self.done,
                "ts": time.time()}
        p = self.path()
        try:
            tmp = p + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, p)
        except OSError:
            pass


REP = None


def wait_check(desc, fn, timeout=8.0, interval=0.1):
    """轮询 fn() → (ok, detail)，超时/中断记为失败。"""
    deadline = time.monotonic() + timeout
    last = ""
    while True:
        if STOP:
            REP.check(desc, False, "被中断 (SIGTERM)")
            return False
        try:
            okv, last = fn()
        except Exception as e:  # noqa: BLE001 — 环境异常也要落报告
            okv, last = False, f"异常 {e!r}"
        if okv:
            REP.check(desc, True, last)
            return True
        if time.monotonic() >= deadline:
            REP.check(desc, False, f"超时 {timeout}s；最后状态：{last}")
            return False
        time.sleep(interval)


def check_now(desc, fn):
    try:
        okv, last = fn()
    except Exception as e:  # noqa: BLE001
        okv, last = False, f"异常 {e!r}"
    REP.check(desc, okv, last)
    return okv


def dev_is(mp, want, pid=None):
    def f():
        e = top_entry(mp, pid)
        got = e["dev"] if e else None
        return got == want, f"{mp} dev={got} 期望 {want}（{entry_desc(e)}）"
    return f


def mounted(mp, pid=None):
    def f():
        e = top_entry(mp, pid)
        return e is not None, f"{mp} {entry_desc(e)}"
    return f


def unmounted(mp, pid=None):
    def f():
        e = top_entry(mp, pid)
        return e is None, f"{mp} {'仍未卸载: ' + entry_desc(e) if e else '已卸载'}"
    return f


def file_has(path, text):
    def f():
        data = read_text(path)
        return data == text, f"{path} = {data!r} 期望 {text!r}"
    return f


def file_missing(path):
    def f():
        if os.path.exists(path):
            return False, f"{path} 意外存在"
        return True, f"{path} 不存在(预期)"
    return f


# ── 沙箱构建 ──────────────────────────────────────────────────────────

def rbind_tree(src, dst, readonly=True):
    """宿主树 rbind 进沙箱：单向 slave（沙箱挂载绝不回流宿主）+ 只读降级。"""
    os.makedirs(dst, exist_ok=True)
    mount(src, dst, None, MS_BIND | MS_REC)
    mount(None, dst, None, MS_SLAVE | MS_REC)
    if readonly:
        try:
            mount(None, dst, None, MS_REMOUNT | MS_BIND | MS_RDONLY)
        except OSError:
            pass  # 个别内核拒绝 bind 重挂只读：降级为可读写，仍靠 slave 隔离


def setup_sandbox(workdir):
    """tmpfs 根 + 系统树 + 仓库/chan 绑定 + pivot_root。"""
    REP.set_phase("setup")
    mount(None, "/", None, MS_REC | MS_PRIVATE)

    newroot = os.path.join(workdir, "newroot")
    shutil.rmtree(newroot, ignore_errors=True)
    os.makedirs(newroot)
    mount("nsp_sandbox_root", newroot, "tmpfs", 0, "mode=0755")

    # 系统树：宿主上的符号链接（Arch: /bin -> usr/bin 等）在沙箱内保真重建
    for src in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/sys", "/dev"):
        real = os.path.realpath(src)
        tgt = newroot + src
        if real != src:
            if not os.path.lexists(tgt):
                os.makedirs(os.path.dirname(tgt), exist_ok=True)
                os.symlink(os.path.relpath(real, os.path.dirname(src)), tgt)
            continue
        if not os.path.isdir(src):
            continue
        rbind_tree(src, tgt, readonly=(src != "/dev"))

    for d in ("/proc", "/tmp", "/var", "/data", "/mnt", "/storage", "/run", "/home",
              "/oldroot"):
        os.makedirs(newroot + d, exist_ok=True)

    # 仓库只读绑定：injector/fuse_daemon/模块在原路径可达可执行
    os.makedirs(newroot + REPO, exist_ok=True)
    rbind_tree(REPO, newroot + REPO, readonly=True)

    # chan 读写绑定：report 与日志直达宿主
    os.makedirs(newroot + "/chan", exist_ok=True)
    mount(os.path.dirname(REP.host_path), newroot + "/chan", None, MS_BIND)
    mount(None, newroot + "/chan", None, MS_SLAVE)

    # pivot_root：旧根挂到 /oldroot 并彻底脱离（失败即中止，保证零污染）
    os.chdir(newroot)
    sysno = _SYS_PIVOT_ROOT.get(platform.machine().lower())
    if sysno is None:
        raise RuntimeError(f"未知架构 {platform.machine()}，缺 SYS_pivot_root")
    if libc.syscall(sysno, b".", b"oldroot") != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"pivot_root: {os.strerror(e)}")
    os.chdir("/")
    # 新 proc 必须在旧根卸载【之前】挂：宿主 proc（随旧根）一旦彻底消失，内核即
    # 拒绝在 userns 内新建 proc 实例（EPERM，mount_too_revealing 路径）；此顺序下
    # 新 proc 归属本 pid ns（/proc/1 = 沙箱 pid1），P2 探针已验证卸载旧根后仍有效
    mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV)
    umount2("/oldroot", MNT_DETACH)  # 必须成功：宿主旧根不得在沙箱内残留
    try:
        os.rmdir("/oldroot")
    except OSError:
        pass

    mount("tmpfs", "/tmp", "tmpfs", 0, "mode=1777")
    mount(None, "/", None, MS_REC | MS_SHARED)
    REP.check("沙箱 pivot_root 完成（旧根 /oldroot 彻底脱离，根 MS_SHARED）",
              os.path.exists("/proc/self/mountinfo") and not os.path.exists("/oldroot"),
              "proc 可读且 /oldroot 已消失")


def build_topology():
    """照抄 init.rc + Zygote 序列的安卓挂载拓扑。"""
    REP.set_phase("topology")
    mount("nsp_mnt", "/mnt", "tmpfs", 0, "mode=0755")
    mount(None, "/mnt", None, MS_SHARED)
    for d in ("/mnt/user/0/emulated", "/mnt/installer/0/emulated",
              "/mnt/androidwritable/0/emulated", "/storage", "/data/media/0",
              "/var/fuse-proxy/log", "/chan/log"):
        os.makedirs(d, exist_ok=True)

    # init.rc on post-fs：先 bind+slave，后挂族根（fuse 晚于 rbind，全靠传播）
    mount("/mnt/user/0", "/storage", None, MS_BIND | MS_REC)
    mount(None, "/storage", None, MS_SLAVE | MS_REC)
    check_now("init.rc 序列：/storage = rbind(/mnt/user/0) + 递归 make-slave", lambda: (
        top_entry("/storage") is not None and top_entry("/storage/emulated") is None,
        entry_desc(top_entry("/storage"))))

    # 族根系统视图（真机为 vold 的三份同内容 fuse；沙箱用 tmpfs 仿真）+ 子挂载
    mount("nsp_sysview", "/mnt/user/0/emulated", "tmpfs", 0, "mode=0755")
    os.makedirs("/mnt/user/0/emulated/0/Android/data", exist_ok=True)
    with open("/mnt/user/0/emulated/0/sys_marker", "w") as fh:
        fh.write("system-view")
    mount("nsp_sysdata", FAM_SUB, "tmpfs", 0, "mode=0755")
    with open(FAM_SUB + "/data_marker", "w") as fh:
        fh.write("native-data")
    # 另外两族：同内容视图（真机三族独立实例，内容一致）
    mount("/mnt/user/0/emulated", "/mnt/installer/0/emulated", None, MS_BIND | MS_REC)
    mount("/mnt/user/0/emulated", "/mnt/androidwritable/0/emulated", None, MS_BIND | MS_REC)

    # 配置与标记
    with open(CONFIG_PATH, "w") as fh:
        fh.write(CONFIG_TEXT)
    os.makedirs("/var/fuse-proxy/storage/0", exist_ok=True)
    with open(PROJ_MARK_PHYS, "w") as fh:
        fh.write("project-view")
    # 日志落 chan/log（宿主可直接取证）
    if os.path.isdir("/chan/log"):
        mount("/chan/log", "/var/fuse-proxy/log", None, MS_BIND)
    # 规则引擎已内建（fw_rules）：无需装载模块，本测试也不断言规则求值
    # 基线断言 + 记录关键 dev
    sys_dev = dev_at("/mnt/user/0/emulated")
    REP.check("族根 /mnt/user/0/emulated = 系统视图 (nsp_sysview)",
              sys_dev is not None and dev_at(STORAGE_EMU) == sys_dev,
              f"族根 {entry_desc(top_entry('/mnt/user/0/emulated'))}；"
              f"/storage/emulated {entry_desc(top_entry(STORAGE_EMU))}（应经传播同源）")
    REP.check("子挂载 /storage/emulated/0/Android/data 就位 (nsp_sysdata)",
              dev_at(STG_SUB) is not None and dev_at(STG_SUB) == dev_at(FAM_SUB),
              f"storage {entry_desc(top_entry(STG_SUB))}；族根 {entry_desc(top_entry(FAM_SUB))}")
    check_now("系统标记 sys_marker 经 /storage/emulated 可读", file_has(SYS_MARK, "system-view"))
    check_now("项目标记 proj_marker 基线不可见", file_missing(PROJ_MARK))
    REP.check("fuse 就绪门 /data/media/0 已建立", os.path.isdir("/data/media/0"), "")
    REP.check("injector.conf 已写入 (GLOBAL_INJECT OFF + 目标/非目标段)",
              "[com.test.target] ON" in (read_text(CONFIG_PATH) or ""), "")
    return sys_dev


def spawn_app(pkg):
    """zygote 序列拉起假应用：unshare + MS_REC|MS_SLAVE / + UnmountTree(/storage)
       + rbind /mnt/user/0 → /storage，随后 exec 睡眠进程（argv[0]=pkg）。"""
    pid = os.fork()
    if pid == 0:
        try:
            if libc.unshare(CLONE_NEWNS) != 0:
                os._exit(41)
            mount(None, "/", None, MS_REC | MS_SLAVE)
            entries = read_mountinfo()
            under = [e for e in entries
                     if e["mp"] == "/storage" or e["mp"].startswith("/storage/")]
            for e in sorted(under, key=lambda x: x["mp"].count("/"), reverse=True):
                for _ in range(5):
                    try:
                        umount2(e["mp"], MNT_DETACH)
                        break
                    except OSError:
                        time.sleep(0.02)
            if top_entry("/storage") is not None:
                os._exit(43)  # UnmountTree 失败：视图不干净，宁可暴露
            mount("/mnt/user/0", "/storage", None, MS_BIND | MS_REC)
            os.execv(sys.executable,
                     [pkg, "-c", "import time\nwhile True: time.sleep(3600)"])
        except BaseException:  # noqa: BLE001
            os._exit(42)
    # 等 exec 完成（cmdline 首段变为 pkg），并捕获子进程早退
    deadline = time.monotonic() + 5
    want = pkg.encode()
    while time.monotonic() < deadline:
        try:
            wpid, _ = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                raise RuntimeError(f"假应用 {pkg} 启动失败（子进程已退出）")
        except ChildProcessError:
            pass
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmd = fh.read()
        except OSError:
            time.sleep(0.05)
            continue
        if cmd.split(b"\0", 1)[0] == want:
            return pid
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    raise RuntimeError(f"假应用 {pkg} 未在 5s 内完成 exec")


def start_log_monitor():
    if not os.path.exists(LOG_MONITOR):
        REP.check("log_monitor 启动（日志取证）", True, "产物缺失，跳过（不影响断言）")
        return None
    try:
        lf = open("/chan/log/log_monitor.out", "w")
        p = subprocess.Popen([LOG_MONITOR, "-p"], stdout=lf, stderr=subprocess.STDOUT)
        lf.close()
        return p
    except OSError as e:
        REP.check("log_monitor 启动（日志取证）", True, f"启动失败 {e}（不影响断言）")
        return None


def start_injector(method):
    r = subprocess.run([INJECTOR, f"--inject-method={method}", "--passive"],
                       capture_output=True, timeout=15)
    if r.returncode != 0:
        raise RuntimeError(f"injector 启动失败 rc={r.returncode} "
                           f"stderr={r.stderr.decode(errors='replace')[:300]}")
    # nsp_daemonize 后父进程立即退出；按 argv 标记定位 daemon（沙箱内 pid<1000，
    # 周期扫描 scan_zygote_children 因 pid<1000 全部跳过 → 确定性只靠 REQ）
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        pids = find_procs("--inject-method=")
        if pids:
            return pids[0]
        time.sleep(0.1)
    raise RuntimeError("未能定位 injector daemon（--inject-method= 标记）")


def ipc_session(cmd, timeout=3.0):
    """单连接单命令（服务端读一次即处理）：abstract UDS。"""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(b"\0nsp_ipc_socket")
        s.sendall((cmd + "\n").encode())
        data = b""
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        return data.decode(errors="replace")
    finally:
        s.close()


def ipc_retry(cmd, budget=5.0):
    deadline = time.monotonic() + budget
    last = None
    while time.monotonic() < deadline:
        if STOP:
            return None
        try:
            return ipc_session(cmd)
        except OSError as e:
            last = e
            time.sleep(0.1)
    raise RuntimeError(f"IPC 连接失败: {cmd}（{last}）")


def list_injected():
    out = ipc_retry("LIST_INJECTED", budget=5.0) or ""
    return out


def listed_pids(text):
    pids = set()
    for line in text.splitlines():
        parts = line.strip().split("|")
        if len(parts) >= 3 and parts[0] == "APP":
            try:
                pids.add(int(parts[2]))
            except ValueError:
                pass
    return pids


def wait_listed(pid, pkg, timeout=6.0):
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        if STOP:
            REP.check(f"LIST_INJECTED 含目标应用 {pkg}", False, "被中断")
            return False
        try:
            pids = listed_pids(list_injected())
        except RuntimeError as e:
            last = str(e)
            time.sleep(0.2)
            continue
        if pid in pids:
            REP.check(f"LIST_INJECTED 含目标应用 {pkg}", True, f"pid={pid}")
            return True
        last = f"当前列表 {sorted(pids)}"
        time.sleep(0.2)
    REP.check(f"LIST_INJECTED 含目标应用 {pkg}", False, f"超时 {timeout}s；{last}")
    return False


def wait_pid_exit(pid, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if STOP:
            return False
        try:
            wpid, _ = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                return True
        except ChildProcessError:
            pass
        except OSError:
            pass
        if not os.path.exists(f"/proc/{pid}"):
            return True
        time.sleep(0.1)
    return False


def kill_and_reap(pid, sig=signal.SIGKILL):
    try:
        os.kill(pid, sig)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except (ChildProcessError, OSError):
        pass


# ── 沙箱主流程 ────────────────────────────────────────────────────────

def inner_main(argv):
    global REP, STOP
    method = None
    workdir = None
    i = 0
    while i < len(argv):
        if argv[i] == "--method" and i + 1 < len(argv):
            method = argv[i + 1]
            i += 2
        elif argv[i] == "--workdir" and i + 1 < len(argv):
            workdir = argv[i + 1]
            i += 2
        else:
            i += 1
    if method not in METHODS or not workdir:
        print(f"inner: 参数错误 method={method} workdir={workdir}", flush=True)
        return 2

    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    REP = Report(os.path.join(workdir, "chan", "report.json"), method)
    log(f"── inner: 方法 {method} 沙箱开始 (pid={os.getpid()}) ──")

    app_pids = []
    daemon_pid = None
    log_mon = None
    try:
        os.chdir("/")
        setup_sandbox(workdir)
        sys_dev = build_topology()
        sys_data_dev = dev_at(FAM_SUB)

        # app1 在 injector 启动【前】启动：覆盖「替换前启动的应用被活传播替换」
        REP.set_phase("apps")
        app1 = spawn_app(TARGET_PKG)
        app_pids.append(app1)
        REP.check(f"假应用 app1({TARGET_PKG}) 替换前启动，视图 = 系统视图",
                  dev_at(STORAGE_EMU, app1) == sys_dev,
                  f"app1 {entry_desc(top_entry(STORAGE_EMU, app1))}")

        log_mon = start_log_monitor()

        REP.set_phase("injector")
        daemon_pid = start_injector(method)
        REP.check(f"injector daemon 已启动 (--inject-method={method})",
                  os.path.exists(f"/proc/{daemon_pid}"), f"pid={daemon_pid}")

        # ── FUSE 就绪 / 全局替换 ──
        REP.set_phase("ready")

        def ready_fn():
            g = top_entry(GLOBAL_MNT)
            if g is None:
                return False, f"{GLOBAL_MNT} 未挂载"
            if method == "v1":
                return True, f"项目 FUSE {entry_desc(g)}"
            for r in FAMILY_ROOTS:
                e = top_entry(r)
                if e is None or e["dev"] != g["dev"]:
                    return False, f"族根 {r} {entry_desc(e)}，期望 dev={g['dev']}"
            b = top_entry(BACKUP_TOP)
            if b is None:
                return False, f"备份点 {BACKUP_TOP} 未建立"
            return True, f"三族族根 dev={g['dev']}；备份 {entry_desc(b)}"

        if not wait_check("FUSE 就绪" + ("（v1 不替换）" if method == "v1" else
                                         "且 v2/v3 三族族根替换 + 备份建立"),
                          ready_fn, timeout=20):
            raise RuntimeError("FUSE 就绪超时（详见 chan/log/fuse_crash.log 与 sys.log）")
        g_dev = dev_at(GLOBAL_MNT)

        if method == "v1":
            check_now("v1 不触碰 init 族根（仍为系统视图）",
                      dev_is("/mnt/user/0/emulated", sys_dev))
            check_now("v1 不触碰 init /storage/emulated（仍为系统视图）",
                      dev_is(STORAGE_EMU, sys_dev))
        else:
            check_now("init /storage/emulated 经传播跟随为项目 FUSE",
                      dev_is(STORAGE_EMU, g_dev))
            check_now("族根原生子挂载已随替换卸载", unmounted(FAM_SUB))
            check_now("/storage 原生子挂载已随替换卸载", unmounted(STG_SUB))
            check_now("替换前启动的 app1 视图被活传播替换为项目 FUSE",
                      dev_is(STORAGE_EMU, g_dev, app1))
        check_now(f"不启动媒体专属 FUSE（{MEDIA_MNT} 未挂载）", unmounted(MEDIA_MNT))

        # app2 在就绪/替换【后】启动：覆盖「替换后启动的应用直接见项目 FUSE」
        app2 = spawn_app(NONTARGET_PKG)
        app_pids.append(app2)
        if method == "v1":
            REP.check(f"app2({NONTARGET_PKG}) 视图 = 系统视图（v1 无全局替换）",
                      dev_at(STORAGE_EMU, app2) == sys_dev,
                      entry_desc(top_entry(STORAGE_EMU, app2)))
        else:
            REP.check(f"app2({NONTARGET_PKG}) 替换后启动，直接见项目 FUSE",
                      dev_at(STORAGE_EMU, app2) == g_dev,
                      entry_desc(top_entry(STORAGE_EMU, app2)))

        # ── REQ 注入 / 非目标还原 ──
        REP.set_phase("req")
        # 目标 REQ 与 LIST 轮询合一：规避「挂载出现早于 g_fuse_ready 置位」的窄竞态
        rep_t = ipc_retry(f"REQ {TARGET_PKG} {app1} 0")
        REP.check(f"REQ target({TARGET_PKG}) 返回 OK", rep_t is not None and "OK" in rep_t,
                  repr(rep_t))
        rep_n = ipc_retry(f"REQ {NONTARGET_PKG} {app2} 0")
        REP.check(f"REQ nontarget({NONTARGET_PKG}) 返回 OK",
                  rep_n is not None and "OK" in rep_n, repr(rep_n))

        listed_ok = wait_listed(app1, TARGET_PKG, timeout=8)
        # 目标确认后补一次 REQ，确保 v1 窄竞态下挂载线程重跑（幂等）
        if listed_ok and method == "v1" and dev_at(STORAGE_EMU, app1) != g_dev:
            ipc_retry(f"REQ {TARGET_PKG} {app1} 0")
        try:
            not_listed = app2 not in listed_pids(list_injected())
        except RuntimeError as e:
            not_listed = False
            REP.check(f"LIST_INJECTED 不含非目标应用 {NONTARGET_PKG}", False, str(e))
        if not_listed:
            REP.check(f"LIST_INJECTED 不含非目标应用 {NONTARGET_PKG}", True, f"pid={app2}")

        # 方法相关的视图断言
        if method == "v1":
            wait_check("app1 已逐应用挂载为项目 FUSE", dev_is(STORAGE_EMU, g_dev, app1))
            wait_check("app1 原生子挂载 0/Android/data 保留 (nsp_sysdata)",
                       dev_is(STG_SUB, sys_data_dev, app1))
            check_now("app2（非目标）未被触碰", dev_is(STORAGE_EMU, sys_dev, app2))
        elif method == "v2":
            wait_check("app2（非目标）已在自身 ns 还原为系统视图",
                       dev_is(STORAGE_EMU, sys_dev, app2))
            wait_check("app2 子挂载随还原", dev_is(STG_SUB, sys_data_dev, app2))
            check_now("app1（目标）保持项目 FUSE", dev_is(STORAGE_EMU, g_dev, app1))
            check_now("init 视图保持项目 FUSE", dev_is(STORAGE_EMU, g_dev))
        else:  # v3
            wait_check("app2（非目标）不还原（v3 默认全局挂载）",
                       dev_is(STORAGE_EMU, g_dev, app2))
            check_now("app1（目标）保持项目 FUSE", dev_is(STORAGE_EMU, g_dev, app1))
            check_now("init 视图保持项目 FUSE", dev_is(STORAGE_EMU, g_dev))

        # 文件级 IO（init ns 视角）
        if method == "v1":
            wait_check("IO: 系统标记经 /storage/emulated 可读", file_has(SYS_MARK, "system-view"))
            check_now("IO: 项目标记不可见（v1 未替换 init 视图）", file_missing(PROJ_MARK))
        else:
            wait_check("IO: 项目标记经项目 FUSE 可读", file_has(PROJ_MARK, "project-view"))
            check_now("IO: 系统标记不可见（已被项目视图替换）", file_missing(SYS_MARK))

        # ── SIGTERM 退出清理 ──
        REP.set_phase("termination")
        os.kill(daemon_pid, signal.SIGTERM)
        exited = wait_pid_exit(daemon_pid, timeout=25)
        REP.check("injector 收到 SIGTERM 后优雅退出", exited,
                  "" if exited else f"pid {daemon_pid} 25s 未退出")

        # fuse_daemon 随退出终结（--ready-fd= 是 injector 启动 daemon 的稳定标记）
        def fuse_gone():
            pids = find_procs("--ready-fd=")
            return not pids, f"仍存活: {pids}" if pids else "已终结"
        wait_check("fuse_daemon 已随 injector 退出终结", fuse_gone, timeout=8)

        REP.set_phase("cleanup")
        wait_check("/mnt/nsp_global 已卸载", unmounted(GLOBAL_MNT), timeout=8)

        if method == "v1":
            wait_check("清理: 族根仍为系统视图（v1 从未替换）",
                       dev_is("/mnt/user/0/emulated", sys_dev))
            wait_check("清理: init /storage/emulated 系统视图", dev_is(STORAGE_EMU, sys_dev))
            wait_check("清理: app1 逐应用挂载已回收为系统视图",
                       dev_is(STORAGE_EMU, sys_dev, app1))
            wait_check("清理: app1 原生子挂载已回收", dev_is(STG_SUB, sys_data_dev, app1))
            wait_check("清理: app2 全程未受影响", dev_is(STORAGE_EMU, sys_dev, app2))
        else:
            wait_check("清理: 三族族根从备份还原为系统视图", lambda: (
                all(dev_at(r) == sys_dev for r in FAMILY_ROOTS),
                "; ".join(f"{r}={dev_at(r)}" for r in FAMILY_ROOTS)))
            wait_check("清理: init /storage/emulated 还原为系统视图",
                       dev_is(STORAGE_EMU, sys_dev))
            wait_check("清理: /storage/emulated/0/Android/data 子挂载还原",
                       dev_is(STG_SUB, sys_data_dev))
            wait_check("清理: app1 视图经传播还原为系统视图",
                       dev_is(STORAGE_EMU, sys_dev, app1))
            wait_check("清理: app2 视图还原为系统视图",
                       dev_is(STORAGE_EMU, sys_dev, app2))
            wait_check("清理: 备份点已卸载（无残留）", unmounted(BACKUP_TOP))
        wait_check("清理: 系统标记恢复可见", file_has(SYS_MARK, "system-view"))
        wait_check("清理: 项目标记消失", file_missing(PROJ_MARK))
        wait_check("清理: 媒体 FUSE 从未出现", unmounted(MEDIA_MNT))

        # ── 拆除沙箱内进程 ──
        REP.set_phase("teardown")
        for p in app_pids:
            kill_and_reap(p)
        REP.check("假应用已终止", True, "")
        if log_mon is not None and log_mon.poll() is None:
            log_mon.terminate()
            try:
                log_mon.wait(timeout=3)
            except subprocess.TimeoutExpired:
                log_mon.kill()
                log_mon.wait(timeout=3)
        REP.check("log_monitor 已停止", True, "")

        REP.finish(done=True)
        rc = 0 if all(c["ok"] for c in REP.checks) else 1
        log(f"── inner: 方法 {method} 结束，{sum(1 for c in REP.checks if c['ok'])}/"
            f"{len(REP.checks)} 通过 ──")
        return rc

    except Exception as e:  # noqa: BLE001
        REP.set_fatal(f"{type(e).__name__}: {e}")
        log(f"── inner: 致命错误 {type(e).__name__}: {e} ──")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        # 最佳努力清理：即使遗漏，pid ns 的 init（本进程）退出时内核会 SIGKILL
        # 全部成员，挂载随 mnt ns 销毁，宿主零残留
        if daemon_pid and os.path.exists(f"/proc/{daemon_pid}") and not STOP:
            try:
                os.kill(daemon_pid, signal.SIGTERM)
                wait_pid_exit(daemon_pid, timeout=5)
            except OSError:
                pass
        for p in app_pids:
            kill_and_reap(p)
        if log_mon is not None and log_mon.poll() is None:
            try:
                log_mon.kill()
                log_mon.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                pass
        if REP is not None and not REP.done:
            REP.finish(done=False)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        sys.exit(inner_main(sys.argv[2:]))
    sys.exit(main())
