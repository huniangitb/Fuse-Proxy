#!/usr/bin/env python3
"""
日志链路回归测试（log_internal → nsp_comm → log_monitor → log_ctl 查询）
=====================================================================

锁定三类行为，均来自「框架运行期间监控日志凭空消失、只有历史遗留记录」的现场：

1. **框架闸门不得静默关闭监控**（`fw_route` 单点给出 `monitor_on`，且由框架自算）
   - 规则文件里没有任何规则记录（引擎直通分支）时，`[GLOBAL] MONITOR ON`
     仍须记录 IO：修复前该情形文件读写一切正常、监控日志却是 0；
   - 路径无 `<uid>/` 用户层（挂载点根）时同样须记录（修复前为 0）；
   - `MONITOR OFF` 必须**仍然**不记录——兜底不能退化成无条件开；
   - 类别段（`[SYSTEM_APPS]`）在引擎直通时同样生效：全局 OFF + 类别 ON 要记录、
     全局 ON + 类别 OFF 要不记录（三层合并在框架侧完成，不依赖模块）。
     `[USER_APPS:<uid>]` 分支需要 uid>=10000 的请求者，端到端测不到——那一层由
     `test_monitor_layers.py` 用合成 uid 直接验证框架合并函数。
2. **磁盘历史可查**：`io.log.1` + `io.log` 全量进入启动快照，
   `log-count` / `search-io` 不再被 2048 条固定上限截断。
3. **端到端可达**：fuse_daemon 产生的 IO 日志能经 sock 查询到，
   而不只是躺在落盘文件里（子用例 1 同时覆盖本条）。

前置：GNU 产物 `build_gnu/{fuse_daemon,log_monitor,log_ctl}`、
      `fusermount3`、`/dev/fuse`。非默认产物路径用环境变量覆盖：
      `FUSE_DAEMON`、`LOG_MONITOR`、`LOG_CTL`。

副作用：抽象套接字 `nsp_log_socket` 全局唯一，本测试会**重启 log_monitor**
        （记录并还原被停掉的实例），并备份/还原 `<LOG_DIR>/io.log{,.1}`。
"""
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD = os.environ.get("BUILD_DIR") or os.path.join(ROOT, "build_gnu")

DAEMON = os.environ.get("FUSE_DAEMON") or os.path.join(BUILD, "fuse_daemon")
LOG_MON = os.environ.get("LOG_MONITOR") or os.path.join(BUILD, "log_monitor")
LOG_CTL = os.environ.get("LOG_CTL") or os.path.join(BUILD, "log_ctl")

LOG_DIR = os.environ.get("NSP_LOG_DIR") or "/var/fuse-proxy/log"
IO_LOG = os.path.join(LOG_DIR, "io.log")
IO_ROT = IO_LOG + ".1"
LOG_SOCKET_NAME = "nsp_log_socket"  # 抽象地址，权威在 include/common.h

BASE = "/tmp/fuse_proxy_test"
MNT = BASE + "/mnt"
STORAGE = BASE + "/storage"
MODDIR = BASE + "/modules"
CONF = "/tmp/Namespace-Proxy/injector.conf"

TEST_ID = str(uuid.uuid4())[:8]
PASS = 0
FAIL = 0
ERRORS = []


def log(msg, *a):
    print(("[%s] " % time.strftime("%H:%M:%S")) + (msg % a if a else msg))


def ok(desc):
    global PASS
    PASS += 1
    log("  ✅ %s", desc)


def fail(desc, detail=""):
    global FAIL
    FAIL += 1
    log("  ❌ %s: %s", desc, detail)
    ERRORS.append((desc, detail))


def check(desc, cond, detail=""):
    ok(desc) if cond else fail(desc, detail)


# ───────────────────────────────────────────────────────────
# log_monitor 生命周期（套接字全局唯一，必须独占）
# ───────────────────────────────────────────────────────────
_FOREIGN = None  # (cmdline, cwd) 或 None——被本测试停掉的既有实例
_LOGMON = None   # 本测试自己拉起的实例


def _logmon_pids():
    try:
        out = subprocess.run(["pgrep", "-x", "log_monitor"], capture_output=True, text=True).stdout
        return [int(p) for p in out.split() if p.strip()]
    except Exception:
        return []


def _read_foreign():
    """记录当前 log_monitor 的启动方式，收尾时原样还原（不打断开发机上的实例）。"""
    global _FOREIGN
    pids = _logmon_pids()
    if not pids:
        return
    pid = pids[0]
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            cmd = [c.decode() for c in f.read().split(b"\0") if c]
        cwd = os.readlink("/proc/%d/cwd" % pid)
        _FOREIGN = (cmd, cwd)
        log("检测到既有 log_monitor(pid=%d)，测试期间暂停，收尾时还原", pid)
    except Exception as e:
        log("⚠ 无法记录既有 log_monitor 启动方式（%s），将直接停掉", e)
        _FOREIGN = None


def _kill_logmon():
    subprocess.run(["pkill", "-9", "-x", "log_monitor"], capture_output=True)
    for _ in range(30):
        if not _logmon_pids():
            return True
        time.sleep(0.1)
    return False


def start_logmon():
    global _LOGMON
    _kill_logmon()
    out = open("/tmp/log_pipeline_monitor.out", "w")
    _LOGMON = subprocess.Popen([LOG_MON], stdout=out, stderr=subprocess.STDOUT)
    out.close()
    # 等 accept 就绪：直接探连（连上即关，不影响服务）
    import socket
    for _ in range(50):
        if _LOGMON.poll() is not None:
            return False
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect(("\0" + LOG_SOCKET_NAME).encode())
            s.close()
            return True
        except Exception:
            time.sleep(0.1)
    return False


def stop_logmon():
    global _LOGMON
    if _LOGMON and _LOGMON.poll() is None:
        _LOGMON.send_signal(signal.SIGTERM)
        try:
            _LOGMON.wait(3)
        except Exception:
            _LOGMON.kill()
    _LOGMON = None
    _kill_logmon()


# ───────────────────────────────────────────────────────────
# log_ctl 封装
# ───────────────────────────────────────────────────────────
def ctl(*args, timeout=20):
    try:
        r = subprocess.run([LOG_CTL, *args], capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return ""
    return (r.stdout or "") + (r.stderr or "")


def io_count():
    """`log-count` 的 I/O 总条数（磁盘快照 + 内存环）。"""
    out = ctl("log-count")
    m = re.search(r"I/O 日志:\s*(\d+)\s*条", out)
    return int(m.group(1)) if m else -1


def search_io(key, limit=50, offset=0):
    return ctl("search-io", key, str(limit), str(offset))


def clear_io():
    return ctl("clear-io")


def stream_io_dump(key, timeout=6.0):
    """直连 log_monitor 发 `STREAM_IO`，取历史转储（`dump_buf_to_client` 路径）。

    不走 `log_ctl stream-io`：那是持续流（要 Ctrl+C 才停），且 stdout 走 stdio
    缓冲，管道下拿不到已打印内容。找到 key 即断开——最旧一条在转储首部，
    不会被慢读者触发的 EAGAIN 丢掉。"""
    import socket
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(b"\0" + LOG_SOCKET_NAME.encode())
    s.sendall(b"STREAM_IO:0\n")
    buf = b""
    want = key.encode()
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            if want in buf:
                break
    except OSError:
        pass
    finally:
        s.close()
    return buf.decode("utf-8", "replace")


# ───────────────────────────────────────────────────────────
# fuse_daemon 生命周期
# ───────────────────────────────────────────────────────────
def fresh_env(conf_text):
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(STORAGE + "/0/Download", exist_ok=True)
    os.makedirs(MNT, exist_ok=True)
    # 规则引擎内建（fw_rules），模块目录留空——规则不依赖模块
    os.makedirs(MODDIR, exist_ok=True)
    os.makedirs(os.path.dirname(CONF), exist_ok=True)
    with open(CONF, "w") as f:
        f.write(conf_text)
    for i in range(5):
        with open("%s/0/Download/f%d_%s.txt" % (STORAGE, i, TEST_ID), "w") as f:
            f.write("payload-%d-%s" % (i, TEST_ID))


def start_fuse():
    proc = subprocess.Popen(
        [DAEMON, "--root=" + STORAGE, "--rules=" + CONF,
         "--modules-dir=" + MODDIR, "-f", MNT, "info"],
        stdout=open("/tmp/fuse_log_pipeline.log", "w"),
        stderr=subprocess.STDOUT)
    for _ in range(40):
        time.sleep(0.3)
        try:
            if os.path.isdir(MNT + "/0"):
                return proc
        except OSError:
            pass
        if proc.poll() is not None:
            return None
    return proc


def stop_fuse(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(3)
        except Exception:
            proc.kill()
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)


# ───────────────────────────────────────────────────────────
# 用例 1：框架闸门矩阵
# ───────────────────────────────────────────────────────────
def ops_uid():
    """带 <uid>/ 用户层的常规路径操作。返回是否成功。"""
    try:
        entries = os.listdir(MNT + "/0/Download")
        hit = [e for e in entries if e.endswith("_%s.txt" % TEST_ID)]
        for e in hit:
            with open(os.path.join(MNT, "0/Download", e)) as f:
                f.read()
        return len(hit) >= 5
    except Exception:
        return False


def ops_root():
    """仅访问挂载点根（`path_has_uid_layer` 为 false 的路径）。"""
    try:
        os.listdir(MNT)
        return True
    except Exception:
        return False


def run_gate_case(name, conf_text, ops, expect_log, search_key=None, expect_ops=True):
    """起一套独立环境 → clear-io → 执行操作 → 断言 IO 日志条数与文件操作结果。"""
    fresh_env(conf_text)
    proc = start_fuse()
    if not proc:
        fail("%s: fuse_daemon 未能挂载" % name)
        return
    try:
        time.sleep(0.6)          # 让挂载期产生的日志先落定
        clear_io()
        time.sleep(0.2)
        ops_ok = ops()
        time.sleep(1.2)          # 等 comm 环 + 500ms 刷盘 tick
        n = io_count()
        check("%s: 文件操作%s" % (name, "正常" if expect_ops else ""),
              ops_ok == expect_ops, "ops_ok=%s" % ops_ok)
        if expect_log:
            check("%s: 产生 IO 监控日志" % name, n > 0, "count=%d" % n)
            key = search_key if search_key is not None else TEST_ID
            body = search_io(key)
            check("%s: 可经 sock 查询到" % name, key in body,
                  body[:200].replace("\n", " "))
        else:
            check("%s: 无 IO 监控日志（开关关闭）" % name, n == 0, "count=%d" % n)
    finally:
        stop_fuse(proc)


MON_ON = "[GLOBAL]\nMONITOR ON\n"
MON_OFF = "[GLOBAL]\nMONITOR OFF\n"
# 类别段（[USER_APPS:<uid>] / [SYSTEM_APPS]）：本测试的请求者是本机 uid（<10000），
# 恒走 system 分支——USER_APPS 正常不参与匹配，类别层只由 SYSTEM_APPS 命中。
CAT_SYS_OFF = "[GLOBAL]\nMONITOR ON\n[SYSTEM_APPS] ON\nMONITOR OFF\n"
CAT_SYS_ON = "[GLOBAL]\nMONITOR OFF\n[SYSTEM_APPS] ON\nMONITOR ON\n"
CAT_UA_OFF = "[GLOBAL]\nMONITOR ON\n[USER_APPS:0] ON\nMONITOR OFF\n"


def test_gate_matrix():
    log("\n━━━ 用例组1: 框架闸门矩阵（monitor_on 不得随决策失效一起丢） ━━━")
    run_gate_case("1.1 基准(uid 路径)", MON_ON, ops_uid, expect_log=True)
    # 规则文件只有 [GLOBAL]（无任何规则记录）：引擎走"无规则"直通分支，开关仍须生效
    run_gate_case("1.2 无规则记录（引擎直通）", MON_ON, ops_uid, expect_log=True)
    # 挂载点根没有测试 ID 可作检索键，用操作名本身做键（clear-io 后它是唯一来源）
    run_gate_case("1.3 路径无 uid 层", MON_ON, ops_root, expect_log=True,
                  search_key="READDIR")
    run_gate_case("1.4 MONITOR OFF", MON_OFF, ops_uid, expect_log=False)
    # 类别层：MONITOR 的三层合并归框架，模块缺席时也必须算得对
    if os.getuid() >= 10000:
        log("⚠ 本进程 uid=%d 属用户应用，类别段用例（1.5/1.6）语义不同，跳过",
            os.getuid())
    else:
        run_gate_case("1.5 类别段不越界(USER_APPS vs system)", CAT_UA_OFF, ops_uid,
                      expect_log=True)
        run_gate_case("1.6 类别段可开启(全局 OFF + SYSTEM_APPS ON)", CAT_SYS_ON, ops_uid,
                      expect_log=True)
    run_gate_case("1.7 类别段否决(全局 ON + SYSTEM_APPS OFF)", CAT_SYS_OFF, ops_uid,
                  expect_log=False)


# ───────────────────────────────────────────────────────────
# 用例 2：磁盘历史可查
# ───────────────────────────────────────────────────────────
def test_disk_history():
    log("\n━━━ 用例组2: 磁盘历史可查（启动快照不再被 2048 条截断） ━━━")
    n_old, n_new = 3000, 3000
    stop_logmon()

    def write_hist(path, start, count):
        with open(path, "w") as f:
            for i in range(count):
                # 行格式 ts|level|msg，与 persist_stage 落盘一致
                f.write("%s|1|[hist][OPEN] /Download/hist-%06d_%s.txt\n" %
                        (time.strftime("%Y-%m-%d %H:%M:%S"), start + i, TEST_ID))

    try:
        write_hist(IO_ROT, 1, n_old)                 # 旧 → 新
        write_hist(IO_LOG, 1 + n_old, n_new)
    except OSError as e:
        log("⚠ 无法写入 %s（%s），跳过本组", LOG_DIR, e)
        return
    total = n_old + n_new

    if not start_logmon():
        fail("log_monitor 启动失败", "见 /tmp/log_pipeline_monitor.out")
        return
    try:
        n = io_count()
        check("2.1 log-count 覆盖全部历史 (%d)" % total, n >= total, "count=%d" % n)
        # 最旧一条：截断式实现只保留最新 2048 条，永远查不到它
        n1 = search_io("hist-%06d_%s" % (1, TEST_ID))
        check("2.2 最旧一条可检索", "hist-" in n1, n1[:200].replace("\n", " "))
        # 最新一条：确认新旧两段都在
        n2 = search_io("hist-%06d_%s" % (total, TEST_ID))
        check("2.3 最新一条可检索", "hist-" in n2, n2[:200].replace("\n", " "))
        # 中段记录：截断式实现只留最新 2048 条（hist-003953..006000），翻不到它
        n3 = search_io("hist-%06d_%s" % (1500, TEST_ID), limit=10, offset=0)
        check("2.4 中段记录可检索", "hist-" in n3, n3[:200].replace("\n", " "))
        # 历史转储走 dump_buf_to_client，与 search_log_paged 是两条独立代码路径
        dump = stream_io_dump("hist-%06d_%s" % (1, TEST_ID))
        check("2.5 历史转储含最旧一条", "hist-000001_" in dump,
              dump[:200].replace("\n", " "))
    finally:
        stop_logmon()


# ───────────────────────────────────────────────────────────
# 主流程
# ───────────────────────────────────────────────────────────
def main():
    global PASS, FAIL
    log("═══ 日志链路回归测试 ═══")
    log("测试ID: %s", TEST_ID)
    for label, path in (("fuse_daemon", DAEMON), ("log_monitor", LOG_MON),
                        ("log_ctl", LOG_CTL)):
        if not os.path.exists(path):
            log("❌ 缺少 %s: %s", label, path)
            log("   先执行 ninja -C build_gnu（或用环境变量指定产物路径）")
            return 1
    if not os.path.exists("/dev/fuse"):
        log("❌ /dev/fuse 不可用，跳过全部")
        return 1

    # 备份磁盘历史：本测试会改写 io.log/.1，收尾原样还原
    backup = {}
    for p in (IO_LOG, IO_ROT):
        if os.path.exists(p):
            try:
                shutil.copy2(p, p + ".test_bak")
                backup[p] = p + ".test_bak"
            except OSError as e:
                log("⚠ 无法备份 %s（%s）", p, e)

    _read_foreign()
    old_fuse = subprocess.run(["pgrep", "-x", "fuse_daemon"], capture_output=True, text=True).stdout
    if old_fuse.strip():
        log("⚠ 检测到既有 fuse_daemon(%s)，测试期间暂停", old_fuse.split())
        subprocess.run(["pkill", "-9", "-x", "fuse_daemon"], capture_output=True)
        time.sleep(0.5)

    try:
        if not start_logmon():
            fail("log_monitor 启动失败", "见 /tmp/log_pipeline_monitor.out")
        else:
            test_gate_matrix()
            test_disk_history()
    finally:
        stop_fuse(None)
        stop_logmon()
        for p, bak in backup.items():
            try:
                shutil.move(bak, p)
            except OSError:
                pass
        if _FOREIGN:
            cmd, cwd = _FOREIGN
            try:
                subprocess.Popen(cmd, cwd=cwd,
                                 stdout=open("/tmp/log_pipeline_monitor.out", "a"),
                                 stderr=subprocess.STDOUT)
                log("已还原既有 log_monitor: %s", " ".join(cmd))
            except Exception as e:
                log("⚠ 还原既有 log_monitor 失败: %s", e)

    total = PASS + FAIL
    log("\n═══════════════════════════════════════")
    log("日志链路测试 | ✅ %d 通过 | ❌ %d 失败 | 共 %d", PASS, FAIL, total)
    if ERRORS:
        log("失败详情:")
        for desc, detail in ERRORS[:10]:
            log("  ❌ %s  %s", desc, detail)
    log("═══════════════════════════════════════")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
