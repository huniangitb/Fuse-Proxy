#!/usr/bin/env python3
"""FTP 控制面并发 / 连接复用回归 — ftp_mux（epoll + curl_multi）行为守护。

背景（本用例守护的实现，src/modules/ftp/ftp_mux.c）：
  控制面（getattr/readdir/DELE/MKD/RMD/RNFR/STOR 空文件）此前共用一个 easy
  句柄 + op_lock 串行化：并发 stat 全部排队（总耗时 = 操作数 × 单次往返），
  且任何失败都 curl_easy_cleanup 重建句柄——连 550「不存在」也丢掉健康的
  控制连接，下一次操作白付一次 TCP + USER/PASS 登录。
  改为 epoll + curl_multi 后：任务并行在飞（同一服务器并发控制连接上限 4），
  连接在 multi 的连接缓存里长期复用，业务失败不再重建连接。

做法（不依赖调度运气：用一个「每块延迟 D ms」的 TCP 中继把控制通道的
单次往返放大到 2D，于是并发与串行的耗时差异远超噪声）：
  A. 并发正确性：8 线程 × 混合控制/数据操作（readdir / stat / open+read /
     缺失路径 ENOENT），结果必须全部正确——mux 任务交接、连接复用不得串味。
  B. 连接复用与并发（核心断言）：
     - 8 次并发 stat 期间中继新接受的**同时存在**控制连接数 ≥ 2
       （旧实现恒为 1：op_lock 串行化 + 单句柄）；且 ≤ 4
       （CURLMOPT_MAX_HOST_CONNECTIONS 上限生效，不会把服务器打爆）。
     - 自校准延迟收敛：预热连接后，12 次 stat 串行耗时 T_seq 与并发耗时
       T_par 须满足 T_par < 0.6 × T_seq（4 路并发理论 ~0.25）。
  C. 热重载竞态：在途慢操作（D 调大以保证在飞）期间重写 ftp.conf，触发
     ftp_backend_clear → mux shutdown 归位在途任务。断言 daemon 存活、
     所有在途调用都能返回（不悬挂）、重载后操作恢复正常——守护
     ftp_mux_shutdown 的「abort 在途 + 等引用归零再销毁」路径。

前置同 test_ftp.py：vsftpd 匿名服务（127.0.0.1:21）+ 可写 /upload。
用法：python3 tests/test_ftp_parallel.py
"""
import errno
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# 复用 test_ftp.py 的挂载框架与常量（其 main 在 __main__ 保护下，import 不执行）
from test_ftp import (setup, stop_fuse, FTP_UPLOAD, MNT, MODDIR, STORAGE,
                      CONF, CONF_FTP, SERVER, DAEMON)

RELAY_PORT = 2121          # 中继监听口（ftp.conf 指向它，数据连接由
                           # CURLOPT_FTP_SKIP_PASV_IP 直连 vsftpd）
FTP_PORT = 21
DELAY_A_MS = 10            # 阶段 A：只需可用的往返放大，不必大
DELAY_B_MS = 30            # 阶段 B：单次 LIST ≈ 2~3 往返 ≈ 120~180ms
DELAY_C_MS = 300           # 阶段 C：拉大在飞窗口，保证重载时确有在途任务
PREFIX = f"nsp_par_{os.getpid()}_"

PASS = 0
FAIL = 0
ERRS = []


def ok(d):
    global PASS
    PASS += 1
    print(f"  ✅ {d}")


def fail(d, dt=""):
    global FAIL
    FAIL += 1
    print(f"  ❌ {d}: {dt}")
    ERRS.append((d, dt))


# ================= 延迟中继 =================

class DelayRelay:
    """127.0.0.1:listen_port → 127.0.0.1:target_port 的 TCP 中继，每转发一块
    延迟 delay_ms（双向各自延迟，故一次请求/响应往返 ≈ 2×delay_ms）。

    只代理控制通道：模块设了 CURLOPT_FTP_SKIP_PASV_IP，数据连接直连 vsftpd，
    故数据面（读/写）不经中继、不受延迟影响。

    统计「同时存在的连接数」：模块的连接复用（multi 连接缓存）会让并发任务
    共享少量长连接，这正是本用例要断言的行为（旧实现恒为 1 条）。"""

    def __init__(self, listen_port, target_port, delay_ms):
        self.listen_port = listen_port
        self.target_port = target_port
        self.delay_ms = delay_ms
        self.accepted = 0
        self.cur = 0
        self.max_cur = 0
        self._lock = threading.Lock()
        self._stop = False
        self._srv = None
        self._thread = None
        self._active = set()   # 在途连接集合（pause 断连场景须一并掐断）

    def start(self):
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.listen_port))
        self._srv.listen(64)
        self._srv.settimeout(0.2)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop = True
        if self._thread:
            self._thread.join(2)
        if self._srv:
            try:
                self._srv.close()
            except OSError:
                pass

    def pause(self):
        """断连场景：停止监听并掐断所有在途连接——新连接 ECONNREFUSED，
        连接缓存里已建立的长连接也必须一并失效（否则复用连接仍可成功）"""
        with self._lock:
            srv, self._srv = self._srv, None
            act = list(self._active)
        if srv:
            try:
                srv.close()
            except OSError:
                pass
        for s in act:
            try:
                s.close()
            except OSError:
                pass

    def resume(self):
        """恢复监听（pause 的逆操作）"""
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.listen_port))
        srv.listen(64)
        srv.settimeout(0.2)
        with self._lock:
            self._srv = srv

    def reset(self):
        with self._lock:
            self.accepted = 0
            self.max_cur = 0

    def stats(self):
        with self._lock:
            return self.accepted, self.max_cur

    def _accept_loop(self):
        while not self._stop:
            srv = self._srv
            if srv is None:  # pause() 中：无监听（断连场景）
                time.sleep(0.05)
                continue
            try:
                cli, _ = srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                up = socket.create_connection(("127.0.0.1", self.target_port), timeout=5)
            except OSError:
                cli.close()
                continue
            with self._lock:
                self.accepted += 1
                self.cur += 1
                self.max_cur = max(self.max_cur, self.cur)
            threading.Thread(target=self._serve, args=(cli, up), daemon=True).start()

    def _serve(self, cli, up):
        with self._lock:
            self._active.add(cli)
            self._active.add(up)
        t = threading.Thread(target=self._pump, args=(cli, up), daemon=True)
        t.start()
        self._pump(up, cli)
        t.join(2)
        for s in (cli, up):
            try:
                s.close()
            except OSError:
                pass
        with self._lock:
            self._active.discard(cli)
            self._active.discard(up)
            self.cur -= 1

    def _pump(self, src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                time.sleep(self.delay_ms / 1000.0)
                dst.sendall(data)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


# ================= 挂载（--fuse-threads=-1：给足 FUSE worker，
#   否则并发度被人为压到默认的 2，测不出 mux 的连接复用上限） =================

def write_conf(port, remote_dir="/upload"):
    with open(CONF_FTP, "w") as fh:
        fh.write(f"""
[{SERVER}]
host = 127.0.0.1
port = {port}
user = anonymous
password =
remote_dir = {remote_dir}
""".strip())


def wait_in_listing(name, timeout=20.0):
    """轮询 FTP 根列举直到出现指定名字（热重载后新配置生效的判据）"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            if name in os.listdir(Path(MNT) / "0" / SERVER):
                return True
        except OSError:
            pass
        time.sleep(0.3)
    return False


def start_fuse(threads=-1):
    with open(CONF, "w") as fh:
        fh.write(f"[GLOBAL]\nFTP /{SERVER} {SERVER}\n")
    log = open("/tmp/fuse_ftp_test/par_fuse.log", "w")
    p = subprocess.Popen([DAEMON, "--root=" + STORAGE, "--rules=" + CONF,
                          "--modules-dir=" + MODDIR, f"--fuse-threads={threads}",
                          "-f", MNT, "info"], stdout=log, stderr=subprocess.STDOUT)
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            if os.listdir(MNT):
                return p
        except OSError:
            pass
        if p.poll() is not None:
            return None
        time.sleep(0.3)
    return p


def wait_ready(timeout=20.0):
    probe = Path(MNT) / "0" / SERVER
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if probe.is_dir():
                return True
        except OSError:
            pass
        time.sleep(0.3)
    return False


def vpath(name):
    return Path(MNT) / "0" / SERVER / name


def make_files(names, size=100):
    for n in names:
        p = Path(FTP_UPLOAD) / n
        p.write_bytes(b"x" * size)
        os.chmod(p, 0o666)


def rm_files(names):
    for n in names:
        try:
            (Path(FTP_UPLOAD) / n).unlink()
        except OSError:
            pass


def run_threads(fn, args_list):
    """并发跑 fn(*args)，返回结果列表（顺序对应 args_list）。"""
    out = [None] * len(args_list)
    ths = [threading.Thread(target=lambda i=i, a=a: out.__setitem__(i, fn(*a)))
           for i, a in enumerate(args_list)]
    for t in ths:
        t.start()
    for t in ths:
        t.join(120)
    return out


def stat_ok(name, size=100):
    """返回 None=正确；否则返回错误描述。"""
    try:
        st = os.stat(vpath(name))
    except OSError as e:
        return f"{name} stat 失败 {e!r}"
    if st.st_size != size:
        return f"{name} 大小 {st.st_size} != {size}"
    return None


def listdir_n(base):
    """一次目录列举；返回 None=成功。
    注意：同目录重复列举命中模块侧 LIST 缓存（V5 单条目，零网络）——
    延迟测量须列不同目录（见阶段 B），此处只保证正确性。"""
    try:
        if not os.listdir(base):
            return "readdir 返回空目录"
    except OSError as e:
        return f"readdir 失败 {e!r}"
    return None


def make_dirs(names):
    for n in names:
        d = Path(FTP_UPLOAD) / n
        d.mkdir(exist_ok=True)
        (d / "f").write_bytes(b"x")
        os.chmod(d / "f", 0o666)


def rm_dirs(names):
    for n in names:
        shutil.rmtree(Path(FTP_UPLOAD) / n, ignore_errors=True)


# ================= 阶段 A：并发正确性 =================

CONTENT = b"parallel-content-0123456789"


def phase_a():
    print("── A. 并发正确性（8 线程 × 混合控制/数据操作）──")
    names = [f"{PREFIX}a{i}" for i in range(6)]
    for n in names:
        (Path(FTP_UPLOAD) / n).write_bytes(CONTENT)
    missing = f"{PREFIX}absent"

    def worker(idx):
        errs = []
        try:
            base = Path(MNT) / "0" / SERVER
            for it in range(4):
                items = os.listdir(base)
                if names[0] not in items:
                    errs.append(f"readdir 缺 {names[0]}（{len(items)} 项）")
                    break
                n = names[(idx + it) % len(names)]
                st = os.stat(base / n)
                if st.st_size != len(CONTENT):
                    errs.append(f"stat {n} 大小 {st.st_size}")
                with open(base / n, "rb") as fh:
                    data = fh.read()
                if data != CONTENT:
                    errs.append(f"读 {n} 内容不符（{len(data)} 字节）")
                try:
                    os.stat(base / missing)
                    errs.append("缺失路径未报 ENOENT")
                except FileNotFoundError:
                    pass
        except Exception as e:  # noqa: BLE001 - 现场诊断需要原始异常
            errs.append(f"线程 {idx} 异常 {e!r}")
        return errs

    results = run_threads(worker, [(i,) for i in range(8)])
    flat = [e for r in results for e in r]
    if flat:
        fail("8 线程并发混合操作结果正确", "; ".join(flat[:4]))
    else:
        ok("8 线程并发混合操作结果正确（readdir/stat/read/ENOENT 均正常）")
    rm_files(names)


# ================= 阶段 B：连接复用与并发 =================
#
# 测量对象是 **readdir**（LIST）而非 stat：stat 对未解析路径要先做一次
# lookup（内核 VFS 对同一父目录的并发 lookup 会排队），那样测到的瓶颈是
# 内核路径解析而不是本模块的控制面并发；readdir 无此confound——每个不同
# 目录的首次 os.listdir 都实打实落到 backend_readdir 发一次 LIST（同目录
# 重复列举命中模块侧 V5 LIST 缓存，零网络，故基线/并发须列不同目录）。

def phase_b(relay, restart_fuse):
    print("── B. 连接复用与延迟收敛（延迟中继放大控制往返）──")
    warm = [f"{PREFIX}w{i}" for i in range(8)]
    make_files(warm)
    relay.delay_ms = DELAY_B_MS

    # 重启 daemon：清掉阶段 A 建立的连接缓存，使下面的并发预热确实是
    # 「本阶段新开的连接」（连接数是本阶段要断言的量）
    p = restart_fuse()
    if not p:
        fail("阶段 B 挂载", "fuse_daemon 启动失败")
        rm_files(warm)
        return
    base = Path(MNT) / "0" / SERVER
    relay.reset()

    # 12 个不同目录：每个基线/并发 listdir 都是缓存未命中的真实 LIST
    #（同目录重复列举命中 V5 LIST 缓存，测不出网络延迟）。
    dirs = [f"{PREFIX}bd{i}" for i in range(12)]
    make_dirs(dirs)
    vdirs = [base / d for d in dirs]

    # 预热：并发 readdir 触发多连接建立（首轮并发会开新连接并留在 multi 的
    # 连接缓存里，后续轮次直接复用——连接数只能在首次并发时观察到）
    for _ in range(3):
        bad = [b for b in run_threads(listdir_n, [(base,)] * 8) if b]
        if bad:
            fail("预热并发 readdir", "; ".join(bad[:2]))
            rm_files(warm)
            rm_dirs(dirs)
            return

    # 串行基线（12 个不同目录 × 真实 LIST）
    t0 = time.monotonic()
    for vd in vdirs:
        err = listdir_n(vd)
        if err:
            fail("串行基线 readdir", err)
            break
    t_seq = time.monotonic() - t0
    # 并发（12 线程 × 12 个不同目录，12 路真实 LIST 并发在飞）
    t0 = time.monotonic()
    bad = [b for b in run_threads(listdir_n, [(vd,) for vd in vdirs]) if b]
    t_par = time.monotonic() - t0
    new_conns, max_conns = relay.stats()

    # 旧实现（单共享句柄 + op_lock）全程恒为 1 条——这是"控制面不再串行"的直接证据
    if max_conns >= 2:
        ok(f"控制面并发连接 ≥ 2（峰值并存 {max_conns} 条；不再被单一共享句柄串行化）")
    else:
        fail("控制面并发连接 ≥ 2", f"峰值仅 {max_conns} 条（疑似仍在串行）")
    if max_conns <= 4:
        ok(f"并发控制连接 ≤ 4（CURLMOPT_MAX_HOST_CONNECTIONS 生效，全程新接受 {new_conns} 条）")
    else:
        fail("并发控制连接 ≤ 4", f"峰值 {max_conns} 条，未受上限约束")

    if bad:
        fail("并发 readdir", "; ".join(bad[:2]))
    elif t_seq < 0.3:
        fail("延迟基线异常", f"12 次串行 readdir 仅 {t_seq:.3f}s，中继延迟未生效")
    else:
        ratio = t_par / t_seq
        print(f"  [耗时] 串行 {t_seq:.3f}s / 并发 {t_par:.3f}s = {ratio:.2f}×")
        if ratio < 0.6:
            ok(f"并发耗时 < 串行 0.6×（实为 {ratio:.2f}×，4 路理论 ~0.25）")
        else:
            fail("并发耗时 < 串行 0.6×", f"{ratio:.2f}×（串行 {t_seq:.3f}s，并发 {t_par:.3f}s）")
    rm_files(warm)
    rm_dirs(dirs)


# ================= 阶段 C：热重载竞态 =================

def phase_c(relay, restart_fuse):
    print("── C. 在途操作撞上 ftp.conf 热重载 ──")
    names = [f"{PREFIX}h{i}" for i in range(12)]
    make_files(names)
    relay.delay_ms = DELAY_C_MS

    p = restart_fuse()
    if not p:
        fail("阶段 C 挂载", "fuse_daemon 启动失败")
        rm_files(names)
        return
    if not wait_ready(30):
        fail("阶段 C 后端就绪", "/0/云盘 不可访问")
        rm_files(names)
        return

    # 起 12 个慢 stat（每次操作被中继放大到秒级，保证重载时确在飞）。
    # 数量 ≥ 静默阈值 8：热重载归位（CURLE_ABORTED_BY_CALLBACK）若被误计入
    # fail_count（尤其累加在 add 清零之后的竞态窗口），后端进静默 → 恢复检查
    # 在 2s 探测窗口内会报 ENOENT——配合 reset_curl 的归位豁免守护
    done = [False] * len(names)
    errs = [None] * len(names)

    def slow_stat(i, n):
        try:
            st = os.stat(vpath(n))
            if st.st_size != 100:
                errs[i] = f"大小 {st.st_size}"
        except OSError as e:
            errs[i] = f"{type(e).__name__}"  # 热重载期间失败是允许的
        done[i] = True

    ths = [threading.Thread(target=slow_stat, args=(i, n)) for i, n in enumerate(names)]
    for t in ths:
        t.start()
    time.sleep(0.5)  # 确保已进入后端（在途）

    # 重写 ftp.conf（内容不变）触发 inotify → ftp_backend_clear + add
    write_conf(RELAY_PORT)

    for t in ths:
        t.join(30)
    hung = sum(1 for d in done if not d)
    if hung:
        fail("在途调用全部返回（热重载不悬挂）", f"{hung}/{len(names)} 个线程未返回")
    else:
        ok("在途调用全部返回（mux shutdown 归位在途任务，无悬挂）")
    if p.poll() is None:
        ok("热重载后 fuse_daemon 存活")
    else:
        fail("热重载后 fuse_daemon 存活", f"退出码 {p.returncode}")

    # 恢复：重载后新操作应成功。用**重载后新建**的未缓存路径——缓存命中会在
    # silent_fast_fail 之前返回，只有全新路径才能真正检验「未进静默」
    relay.delay_ms = 20
    names2 = [f"{PREFIX}r{i}" for i in range(4)]
    make_files(names2)
    rec = []
    for n in names2:
        rec.append(stat_ok(n))
    rec = [r for r in rec if r]
    if rec:
        fail("热重载后操作恢复", "; ".join(rec[:2]))
    else:
        ok("热重载后操作恢复正常")

    # C2. 配置**内容**变更（远程目录换一个）：重载后必须由新配置服务，旧目录的
    #     内容不得继续可见（后端对象按代际重建；旧对象只被在途/已打开操作继续
    #     持有，不再改写它）。末尾改回 /upload 并等生效——后续阶段依赖它。
    up2 = Path(FTP_UPLOAD).parent / "upload2"  # 与 FTP_UPLOAD 同底盘：anon chroot 根下
    up2.mkdir(parents=True, exist_ok=True)
    os.chmod(up2, 0o777)
    m2 = f"{PREFIX}gen2.txt"
    (up2 / m2).write_text("gen2")
    write_conf(RELAY_PORT, "/upload2")
    if wait_in_listing(m2):
        ok("远程目录变更生效（列举来自新配置）")
    else:
        fail("远程目录变更生效", f"未在列举中见到 {m2}")
    if names2 and not any(vpath(n).exists() for n in names2):
        ok("旧目录内容不再可见（未跨代串用）")
    else:
        fail("旧目录内容不再可见", "改配置后仍能看见旧目录的文件")
    write_conf(RELAY_PORT)
    if wait_in_listing(names2[0]):
        ok("配置还原生效（/upload）")
    else:
        fail("配置还原生效", "改回 /upload 后未见到既有文件")
    rm_files(names)
    rm_files(names2)


def phase_d(relay):
    print("── D. 断连 → 熔断静默 → 恢复自愈（防误杀） ──")
    # FTP 侧建 10 个真实文件；FUSE 侧从未 stat 过 → 无内核/负缓存干扰
    names = [f"{PREFIX}d{i}" for i in range(10)]
    make_files(names)

    # 断连：关监听 + 掐断在途连接 → 新操作 connect 立即失败（服务器从未应答
    # = res_is_unavailable 里唯一计入熔断的类别），连接缓存里的长连接也失效
    relay.pause()
    relay.delay_ms = 20

    results = [None] * len(names)

    def probe(i, n):
        try:
            os.stat(vpath(n))
            results[i] = "ok"
        except OSError as e:
            results[i] = e.errno
        except Exception as e:
            results[i] = type(e).__name__

    ths = [threading.Thread(target=probe, args=(i, n))
           for i, n in enumerate(names)]
    for t in ths:
        t.start()
    for t in ths:
        t.join(30)

    hung = sum(1 for r in results if r is None)
    if hung:
        fail("断连期间操作全部返回（不挂起）", f"{hung}/{len(names)} 个未返回")
    else:
        ok("断连期间操作全部返回（熔断快速失败，不挂起）")
    # 后端故障必须报 EIO：报 ENOENT 会让应用把完好文件当消失（误杀）
    bad = [r for r in results if r != errno.EIO]
    if bad:
        fail("断连期间统一 EIO（不谎报路径缺失）", f"results={results}")
    else:
        ok("断连期间统一 EIO（不把后端故障谎报成路径缺失 ENOENT）")

    # 恢复：不重启 daemon、不重写配置——探活窗口放行 → 成功清零退出静默。
    # 成功前应观测到 ≥2 次静默快速失败 EIO（否则说明熔断根本没触发）
    relay.resume()
    t0 = time.time()
    eio_before_ok = 0
    recovered = None
    while time.time() - t0 < 8:
        try:
            os.stat(vpath(names[0]))
            recovered = time.time() - t0
            break
        except OSError as e:
            if e.errno == errno.EIO:
                eio_before_ok += 1
        time.sleep(0.2)
    if recovered is None:
        fail("断连恢复后自愈", "8s 内未能 stat 成功")
    else:
        ok(f"断连恢复后 {recovered:.1f}s 自愈（探活放行+成功清零，无需重启/重载）")
    if eio_before_ok >= 2:
        ok("静默快速失败可观察（熔断确已触发）")
    else:
        fail("熔断未触发或快速失败失效", f"恢复成功前仅 {eio_before_ok} 次 EIO")
    rm_files(names)


def main():
    global FAIL
    print("前置：vsftpd 匿名服务（127.0.0.1:21）须已运行（同 test_ftp.py）")

    relay = DelayRelay(RELAY_PORT, FTP_PORT, DELAY_A_MS)
    try:
        relay.start()
    except OSError as e:
        print(f"  ❌ 中继端口 {RELAY_PORT} 不可用: {e}", file=sys.stderr)
        return 1
    print(f"  ✅ 延迟中继已起：127.0.0.1:{RELAY_PORT} → 127.0.0.1:{FTP_PORT}")

    setup()
    write_conf(RELAY_PORT)  # 覆盖 test_ftp.setup() 的直连端口

    def restart_fuse():
        # 重挂：清掉连接缓存 + stat 缓存（模块状态随 daemon 重建），
        # 使阶段 B 的「新接受连接数」确实是本阶段行为
        if cur[0]:
            stop_fuse(cur[0])
        cur[0] = start_fuse()
        if cur[0] and not wait_ready(30):
            return None
        return cur[0]

    cur = [None]
    cur[0] = start_fuse()
    if not cur[0]:
        relay.stop()
        print("  ❌ fuse_daemon 启动失败", file=sys.stderr)
        return 1
    print("  ✅ fuse_daemon 已挂载")
    if not wait_ready(30):
        stop_fuse(cur[0])
        relay.stop()
        print(f"  ❌ FTP 后端未就绪: /0/{SERVER}（检查 ftp.conf / ftp_module.so / par_fuse.log）",
              file=sys.stderr)
        return 1
    print("  ✅ FTP 后端已注册")

    try:
        phase_a()
        phase_b(relay, restart_fuse)
        phase_c(relay, restart_fuse)
        phase_d(relay)
    finally:
        stop_fuse(cur[0])
        relay.stop()
        leftovers = [n for n in os.listdir(FTP_UPLOAD) if n.startswith(PREFIX)]
        rm_files(leftovers)

    print("═══════════════════════════════════════")
    print(f"测试完成 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS + FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
