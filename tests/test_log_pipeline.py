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
3. **等级字段可读且不丢语义**：落盘行/查询行/历史转储统一渲染为
   `时间|LEVEL|msg`（LEVEL = DEBUG/INFO/WARN/ERROR 名称，可直接 grep）；
   旧文件的纯数字等级仍能解析，**非法等级字段判为无效行跳过**
   （不得退化成 `atoi`，否则 `INFO` 会被静默当成 0=DEBUG）。
4. **端到端可达**：fuse_daemon 产生的 IO 日志能经 sock 查询到，
   而不只是躺在落盘文件里（子用例 1 同时覆盖本条）。
5. **退出路径线程收尾**：SIGTERM 退出时必须在 free `AsyncCtx` 之前 join
   async 线程（先 shutdown 唤醒阻塞 read）；旧实现先 free 后线程醒来写
   `notify_fd` → ASan heap-use-after-free。用例 5 直编 log_monitor 源码 + ASan
   判别，`LOG_MONITOR_SRC=<旧副本>` 必失败。
6. **per-事件 DEBUG 不得刷屏**：fuse_daemon 的「打开中删除」直删分支（真机
   20:05:18 一秒 633 行 `open-unlink 本地直删`）必须限速成「首条打全路径 +
   每 1024 条一条（只报目录 + 累计计数）」。用例 6 把观测口
   `log_open_unlink_direct` 从 `src/daemon/fuse_daemon.c` 抽出来直编、用桩
   `LOG_DBG` 数行数：2200 次调用只许 3 行。`FUSE_DAEMON_SRC=<旧副本>` 必失败。

前置：GNU 产物 `build_gnu/{fuse_daemon,log_monitor,log_ctl}`、
      `fusermount3`、`/dev/fuse`。非默认产物路径用环境变量覆盖：
      `FUSE_DAEMON`、`LOG_MONITOR`、`LOG_CTL`。

副作用：抽象套接字 `nsp_log_socket` 全局唯一，本测试会**重启 log_monitor**
        （记录并还原被停掉的实例），并备份/还原 `<LOG_DIR>/io.log{,.1}` 与
        `sys.log{,.1}`。
"""
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD = os.environ.get("BUILD_DIR") or os.path.join(ROOT, "build_gnu")

DAEMON = os.environ.get("FUSE_DAEMON") or os.path.join(BUILD, "fuse_daemon")
LOG_MON = os.environ.get("LOG_MONITOR") or os.path.join(BUILD, "log_monitor")
LOG_CTL = os.environ.get("LOG_CTL") or os.path.join(BUILD, "log_ctl")
RULE_SERVER = os.environ.get("RULE_SERVER") or os.path.join(BUILD, "rule_server")

LOG_DIR = os.environ.get("NSP_LOG_DIR") or "/var/fuse-proxy/log"
IO_LOG = os.path.join(LOG_DIR, "io.log")
IO_ROT = IO_LOG + ".1"
SYS_LOG = os.path.join(LOG_DIR, "sys.log")
SYS_ROT = SYS_LOG + ".1"
LOG_SOCKET_NAME = "nsp_log_socket"  # 抽象地址，权威在 include/common.h

# 退出码约定（与 tests/run.py 一致）：0=通过 1=失败 77=整套跳过(gap)
# 78=部分子组跳过(gap)——本套件有「产物缺失/uid 语义不同/日志目录不可写」等
# 子组级跳过，整套仍有有效断言，故与整套跳过区分，但同样不计通过。
SKIP_RC = 77
GAP_RC = 78
GAPS = []  # 子组级跳过原因（收尾汇总，run.py 据此判 gap）

# 落盘/查询/流式三处统一的行格式：时间|LEVEL|msg（LEVEL 为名称，见 nsp_log.h）
LEVEL_LINE_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\|(DEBUG|INFO|WARN|ERROR)\|")

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


def stream_sys_api_dump(key, timeout=6.0):
    """直连 log_monitor 发 `STREAM_SYS_API:0:1`（带时间戳 + 等级名），取历史转储。

    覆盖 `dump_buf_to_client` → `dump_one_entry` 的 with_level 渲染路径（与
    `search-sys`、落盘是三条独立代码路径）。该命令是持续流（没有 DONE 行），
    故读到 key 即断开。"""
    import socket
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(b"\0" + LOG_SOCKET_NAME.encode())
    s.sendall(b"STREAM_SYS_API:0:1\n")
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
        GAPS.append(f"类别段用例 1.5/1.6（本进程 uid={os.getuid()} 非系统 uid）")
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
        GAPS.append(f"磁盘历史组（无法写入 {LOG_DIR}：{e}）")
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
# 用例 3：等级字段可读（名称）与旧数字行兼容
# ───────────────────────────────────────────────────────────
def test_level_format():
    log("\n━━━ 用例组3: 等级字段渲染为名称（旧数字行仍可解析） ━━━")
    stop_logmon()
    # 合成历史：新格式名称 + 旧格式数字（2=WARN）+ 两种非法等级字段
    synth = [
        "ERROR|[hist] lvl-err-%s" % TEST_ID,
        "2|[hist] lvl-warn-%s" % TEST_ID,
        "INFO|[hist] lvl-info-%s" % TEST_ID,
        "9|[hist] lvl-bad-%s" % TEST_ID,        # 越界数字 → 无效行
        "garbage|[hist] lvl-junk-%s" % TEST_ID,  # 非等级 → 无效行
    ]
    try:
        with open(SYS_LOG, "w") as f:
            for body in synth:
                f.write("%s|%s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), body))
    except OSError as e:
        log("⚠ 无法写入 %s（%s），跳过本组", SYS_LOG, e)
        GAPS.append(f"等级渲染组（无法写入 {SYS_LOG}：{e}）")
        return

    if not start_logmon():
        fail("log_monitor 启动失败", "见 /tmp/log_pipeline_monitor.out")
        return
    proc = None
    try:
        err = ctl("search-sys", "lvl-err-" + TEST_ID)
        check("3.1 查询行渲染为名称等级", "|ERROR|" in err, err[:200].replace("\n", " "))
        # 旧文件（纯数字等级）必须仍然解析得出正确级别，而不是跳过或当 0
        warn = ctl("search-sys", "lvl-warn-" + TEST_ID)
        check("3.2 旧数字等级行仍可解析为 WARN", "|WARN|" in warn,
              warn[:200].replace("\n", " "))
        lv2 = ctl("search-sys", "--level", "2", "lvl-")
        check("3.3 --level 过滤按语义生效（2=WARN 及以上）",
              "lvl-warn-" in lv2 and "lvl-err-" in lv2 and "lvl-info-" not in lv2,
              lv2[:200].replace("\n", " "))
        # 非法等级（越界数字/非等级文本）不得被当成合法级别放行
        bad = ctl("search-sys", "lvl-bad-" + TEST_ID) + ctl("search-sys", "lvl-junk-" + TEST_ID)
        check("3.4 非法等级字段的行被跳过（不得静默当 DEBUG）",
              "lvl-bad-" not in bad and "lvl-junk-" not in bad,
              bad[:200].replace("\n", " "))
        # 历史转储（dump_one_entry 的 with_level 路径）同样带名称等级
        dump = stream_sys_api_dump("lvl-err-" + TEST_ID)
        check("3.5 历史转储行带名称等级", "|ERROR|" in dump, dump[:200].replace("\n", " "))
        # 运行期真实落盘行：起一次 daemon 让 log_monitor 写新行
        fresh_env(MON_ON)
        proc = start_fuse()
        if not proc:
            fail("3.6 fuse_daemon 未能挂载")
        else:
            ops_uid()
            time.sleep(1.5)  # 等 comm 环 + 500ms 刷盘 tick
    finally:
        stop_fuse(proc)
        stop_logmon()  # SIGTERM → 退出刷盘

    try:
        with open(SYS_LOG) as f:
            lines = [x for x in f.read().splitlines() if x]
    except OSError as e:
        fail("3.6 读取 sys.log 失败", str(e))
        return
    live = lines[len(synth):]
    bad_lines = [x for x in live if not LEVEL_LINE_RE.match(x)]
    check("3.6 运行期落盘行带名称等级（新增 %d 行）" % len(live),
          len(live) > 0 and not bad_lines, (bad_lines[:2] or ["无新增行"])[0])


# ───────────────────────────────────────────────────────────
# 用例 4：rule_server 拒绝日志注入防护（A17）
# ───────────────────────────────────────────────────────────
def _rs_send(sock_name, cmd_obj, timeout=5.0):
    """连抽象套接字发一条 JSON 命令，返回响应 dict（与 test_rule_server 同法）。"""
    import json as _json
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(("\0" + sock_name).encode())
    s.sendall((_json.dumps(cmd_obj, ensure_ascii=False) + "\n").encode("utf-8"))
    s.shutdown(socket.SHUT_WR)
    buf = b""
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if b"\n" in buf:
            break
    s.close()
    return _json.loads(buf.decode("utf-8"))


def test_rule_server_log_injection():
    """A17：rule_server 拒绝应答落日志前必须清洗客户端可控文本。

    log_monitor 按 '\\n' 拆行、按行首 "<数字>:" 取等级，故未清洗时一次
    `{"cmd":"GET","pkg":"x\\n3:伪造\\n"}`（JSON 转义解码后是真换行）即可向
    sys.log 注入伪造的 ERROR 行。断言：sys.log 无伪造等级行，且原文本以转义
    （`\\n`）形式保留在单条 WARN 行内。
    """
    log("── 用例 4：rule_server 拒绝日志注入防护（A17） ──")
    if not os.path.exists(RULE_SERVER):
        GAPS.append("rule_server 产物缺失，A17 注入用例跳过")
        log("  ⏭ 缺少 rule_server 产物，跳过 A17")
        return
    # 用例 3 收尾停了 log_monitor 以便刷盘读取；本用例需重新拉起（生产者要能建链）
    if not start_logmon():
        GAPS.append("log_monitor 未就绪，A17 注入用例跳过")
        log("  ⏭ log_monitor 未就绪，跳过 A17")
        return
    marker = "A17FORGE" + TEST_ID
    tmpdir = tempfile.mkdtemp(prefix="log_pipe_rs_")
    conf_dir = os.path.join(tmpdir, "conf")
    os.makedirs(conf_dir, exist_ok=True)
    with open(os.path.join(conf_dir, "injector.conf"), "w", encoding="utf-8") as f:
        f.write("[GLOBAL]\nMONITOR ON\n")
    sock_name = "nsp_logpipe_rs_%d" % os.getpid()
    proc = subprocess.Popen(
        [RULE_SERVER, "--foreground", "--config-dir", conf_dir, "--socket", sock_name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ready = False
        deadline = time.time() + 5
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            try:
                if _rs_send(sock_name, {"cmd": "PING"}, timeout=0.5).get("status") == "ok":
                    ready = True
                    break
            except Exception:
                time.sleep(0.1)
        if not ready:
            fail("A17 rule_server 未就绪", "见构建产物与抽象套接字")
            return
        # pkg 里带真换行 + 伪造等级前缀；valid_pkg 拒绝 → reply_error 落日志
        _rs_send(sock_name, {"cmd": "GET", "pkg": "x\n3:%s\n" % marker})
        time.sleep(1.5)  # 等 comm 环 + 500ms 刷盘 tick
    finally:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(3)
        except Exception:
            proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)
        stop_logmon()  # SIGTERM → 退出刷盘，确保 sys.log 可读

    try:
        with open(SYS_LOG) as f:
            lines = f.read().splitlines()
    except OSError as e:
        fail("A17 读取 sys.log 失败", str(e))
        return
    forged = [x for x in lines if "|ERROR|" in x and marker in x]
    check("4.1 客户端换行不得注入伪造等级行（无 |ERROR| 伪造行）", not forged,
          (forged[:2] or ["无"])[0])
    # 正向确认载荷确实到达日志（否则 4.1 会因「没日志」而假绿）
    seen = [x for x in lines if marker in x]
    check("4.2 拒绝日志仍留痕且为单行（换行转义为 \\n）",
          bool(seen) and all(("\\n" in x) for x in seen),
          (seen[:1] or ["未找到含 marker 的日志行"])[0])


def test_query_channel():
    """用例组4：查询通道判定必须取自**固定前缀**（A24）

    旧实现在**整行**（含搜索关键字）上 `strstr("IO")`/`strstr("LOGCAT")` 判通道，
    并用 9/13/10 三档偏移切 rest：`log_ctl search-sys IO` 拼出的
    `QUERY_SYS:-1:IO:100:0` 因关键字含 "IO" 被判成 io 通道，且 rest 从 `line+9`
    切到前缀中间 → key 变成 "-1"、limit 被 atoi("IO:100:0") 成 0
    → 静默查了**另一个环**且一条都不返回（前端看到"没有日志"）。
    关键字含 "LOGCAT" 时同理落到 logcat 环。

    判别：sys 历史里合成只存在于 sys 环的关键字行，`search-sys <含 IO 的关键字>`
    必须命中；旧实现命中不到。对照 `search-io` 用同一关键字仍正常（证明问题出在
    通道判定而不是关键字本身）。
    """
    log("\n━━━ 用例组4: 查询通道判定取自固定前缀（A24） ━━━")
    stop_logmon()
    mark_sys = "A24SYSIO-" + TEST_ID
    mark_sys_lc = "A24SYSLOGCAT-" + TEST_ID
    mark_io = "A24IOIO-" + TEST_ID
    try:
        with open(SYS_LOG, "w") as f:
            for body in ("INFO|[hist] %s" % mark_sys, "INFO|[hist] %s" % mark_sys_lc):
                f.write("%s|%s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), body))
        with open(IO_LOG, "w") as f:
            f.write("%s|%s|%s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), "INFO",
                                    "[hist] " + mark_io))
    except OSError as e:
        GAPS.append(f"查询通道组（无法写入日志历史：{e}）")
        log("  ⏭ 无法写入日志历史（%s），跳过本组", e)
        return

    if not start_logmon():
        fail("log_monitor 启动失败（查询通道组）", "见 /tmp/log_pipeline_monitor.out")
        return
    try:
        got = ctl("search-sys", "IO")
        check("4.1 search-sys 关键字含 IO → 仍查 sys 环", mark_sys in got,
              got[:200].replace("\n", " "))
        got_lc = ctl("search-sys", "LOGCAT")
        check("4.2 search-sys 关键字含 LOGCAT → 仍查 sys 环", mark_sys_lc in got_lc,
              got_lc[:200].replace("\n", " "))
        got_io = ctl("search-io", "IO")
        check("4.3 对照：search-io 用同一关键字仍正常命中", mark_io in got_io,
              got_io[:200].replace("\n", " "))
    finally:
        stop_logmon()


# ───────────────────────────────────────────────────────────
# 用例 5：退出路径必须先停/join async 线程再 free（ASan 判别）
# ───────────────────────────────────────────────────────────
# 探针直编被测源码（默认仓库当前实现，可经 LOG_MONITOR_SRC 指向旧副本）：
#   - 在独立线程里跑真实的 log_monitor main（#define main 改名后 include 源码）；
#   - 连上抽象 socket 发一条 LOG_SYS，让 process_line 建 AsyncCtx 并起 async 线程；
#   - --wrap=read 把 async 线程拦在 read 里（同时 --wrap=accept 记录被接管的 fd，
#     --wrap=shutdown 让新实现的「shutdown 唤醒」能放行）；
#   - 只对 monitor 线程发 SIGTERM → 走真实退出清理；join 该线程后再放行 read。
# 旧实现：清理里 free(ctx) 后线程才醒来写 ctx->notify_fd → ASan heap-use-after-free
# （log_monitor.c:993）。新实现：shutdown→join→drain→close→free，无报告。
EXIT_JOIN_PROBE = r'''
#define _GNU_SOURCE
#define main review_unused_monitor_main
#include "@LOG_MONITOR_SRC@"
#undef main

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static int g_target_fd = -1; /* process_line 接管的 async 连接 fd */
static int g_entered;        /* async 线程已停在 read */
static int g_release;        /* 探针放行 read（旧实现路径用） */
static int g_woken;          /* 被测实现调了 shutdown（新实现路径用） */
static __thread int t_monitor_thread;

ssize_t __real_read(int, void*, size_t);
ssize_t __wrap_read(int fd, void* buf, size_t n) {
    int block = 0;
    pthread_mutex_lock(&g_mu);
    if (fd == g_target_fd && g_target_fd >= 0 && !t_monitor_thread) {
        block = 1;
        g_entered = 1;
        pthread_cond_broadcast(&g_cv);
        while (!g_release && !g_woken) pthread_cond_wait(&g_cv, &g_mu);
    }
    pthread_mutex_unlock(&g_mu);
    return block ? 0 : __real_read(fd, buf, n);
}
int __real_shutdown(int, int);
int __wrap_shutdown(int fd, int how) {
    pthread_mutex_lock(&g_mu);
    if (fd == g_target_fd && g_target_fd >= 0) {
        g_woken = 1;
        pthread_cond_broadcast(&g_cv);
    }
    pthread_mutex_unlock(&g_mu);
    return __real_shutdown(fd, how);
}
int __real_accept(int, struct sockaddr*, socklen_t*);
int __wrap_accept(int fd, struct sockaddr* a, socklen_t* l) {
    int c = __real_accept(fd, a, l);
    if (c >= 0) {
        pthread_mutex_lock(&g_mu);
        if (fd == g_server_sock) g_target_fd = c;
        pthread_mutex_unlock(&g_mu);
    }
    return c;
}

static void* monitor_entry(void* arg) {
    (void)arg;
    t_monitor_thread = 1;
    char* argv[] = {(char*)"log_monitor_exit_probe", NULL};
    review_unused_monitor_main(1, argv);
    return NULL;
}

int main(void) {
    pthread_t mon;
    if (pthread_create(&mon, NULL, monitor_entry, NULL) != 0) return 2;
    struct sockaddr_un sa;
    socklen_t sl = nsp_uds_abstract_addr(&sa, LOG_SOCKET_NAME);
    int s = -1;
    for (int i = 0; i < 200; i++) {
        s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s >= 0 && connect(s, (struct sockaddr*)&sa, sl) == 0) break;
        if (s >= 0) close(s);
        s = -1;
        usleep(50000);
    }
    if (s < 0) {
        fprintf(stderr, "PROBE: connect failed\n");
        return 2;
    }
    const char* line = "LOG_SYS:1:probe-exit-join\n";
    if (write(s, line, strlen(line)) != (ssize_t)strlen(line)) return 2;
    /* 等 async 线程停在 read，再只对 monitor 线程发 SIGTERM（epoll_wait 必被中断） */
    pthread_mutex_lock(&g_mu);
    while (!g_entered) pthread_cond_wait(&g_cv, &g_mu);
    pthread_mutex_unlock(&g_mu);
    pthread_kill(mon, SIGTERM);
    pthread_join(mon, NULL); /* 退出清理已跑完：旧实现此处已 free(ctx) */
    pthread_mutex_lock(&g_mu);
    g_release = 1;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
    usleep(200000);
    close(s);
    fprintf(stderr, "PROBE: done\n");
    return 0;
}
'''

# ASan 阳性对照：确认本机 ASan 能编译、且 log_path 落盘机制真的生效
ASAN_POSITIVE = r'''
#include <stdlib.h>
int main(void) {
    volatile int* p = (volatile int*)malloc(sizeof(int));
    if (!p) return 2;
    free((void*)p);
    return *p;
}
'''

# log_monitor 的链接依赖（与 Meson 的 common_sources + nsp_util/nsp_comm 同源）
LOG_MONITOR_DEPS = [
    "src/core/common.c",
    "src/core/build_info.c",
    "src/core/path_trie.c",
    "src/config/config_parser.c",
    "src/config/path_vars.c",
    "src/core/fast_search.c",
    "src/core/uid_map.c",
    "src/core/sys_pkg.c",
    "src/core/nsp_util.c",
    "src/core/nsp_comm.c",
]

LOG_MONITOR_SRC = os.environ.get("LOG_MONITOR_SRC") or os.path.join(
    ROOT, "src", "log", "log_monitor.c")

ASAN_OPTS = ("detect_leaks=0:print_stacktrace=1:"
             "allocator_release_to_os_interval_ms=-1")


def _cc():
    return os.environ.get("CC", "cc").split()


def _compile_asan(tmpdir, name, sources, extra=()):
    exe = os.path.join(tmpdir, name)
    cmd = [*_cc(), "-std=c23", "-w", "-g", "-O0", "-fno-omit-frame-pointer",
           "-fsanitize=address", "-DTARGET_GNU=1", "-D_GNU_SOURCE",
           "-DNSP_GIT_HASH=\"probe\"", "-DNSP_BUILD_MODE=\"probe\"",
           "-DNSP_PROJECT_VERSION=\"0\"",
           "-I", os.path.join(ROOT, "include"), *sources, *extra,
           "-o", exe, "-pthread", "-ldl", "-lm"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        return None
    return exe


def _run_asan(exe, log_prefix, timeout=60):
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "log_path=%s:%s" % (log_prefix, ASAN_OPTS)
    env.pop("LSAN_OPTIONS", None)
    return subprocess.run([exe], capture_output=True, text=True, env=env,
                          timeout=timeout)


def _asan_reports(tmpdir, prefix):
    out = []
    for name in os.listdir(tmpdir):
        if name.startswith(os.path.basename(prefix) + "."):
            path = os.path.join(tmpdir, name)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    out.append(fh.read())
            except OSError:
                pass
    return out


def test_exit_join():
    """用例组5：SIGTERM 退出路径必须先 join async 线程再 free（ASan 判别）。

    旧实现退出清理：disconnected=true → drain → close(fd/notify_fd) → free(ctx)，
    线程仍阻塞在 read；主线程随后 free，线程醒来在已释放对象上写 notify_fd
    （报告实测 ASan heap-use-after-free log_monitor.c:993）。新实现先 shutdown
    唤醒、再 join，free 前有「线程已退出」的同步证据。

    判别性：LOG_MONITOR_SRC=<git show HEAD:src/log/log_monitor.c> 跑本用例必失败
    （ASan 报告 + 非 0 退出）。跳过边界：本机 cc 不支持 -fsanitize=address 时
    记 gap（不假装通过）。
    """
    log("\n━━━ 用例组5: 退出路径 join async 线程（ASan 判别） ━━━")
    if not os.path.isfile(LOG_MONITOR_SRC):
        GAPS.append("log_monitor 源码缺失，退出 join 用例跳过")
        log("  ⏭ 缺少 %s，跳过", LOG_MONITOR_SRC)
        return
    with tempfile.TemporaryDirectory(prefix="log_exit_join_") as tmpdir:
        pos_src = os.path.join(tmpdir, "asan_positive.c")
        with open(pos_src, "w", encoding="utf-8") as fh:
            fh.write(ASAN_POSITIVE)
        pos = _compile_asan(tmpdir, "asan_positive", [pos_src])
        if pos is None:
            GAPS.append("本机 cc 不支持 -fsanitize=address，退出 join 用例跳过")
            log("  ⏭ 本机 cc 不支持 ASan，跳过（该用例的判别力依赖 ASan）")
            return
        pos_log = os.path.join(tmpdir, "asanpos")
        _run_asan(pos, pos_log, timeout=30)
        reports = _asan_reports(tmpdir, pos_log)
        if not any("heap-use-after-free" in r for r in reports):
            fail("5.0 ASan 阳性对照未落盘（落盘机制/环境异常）",
                 "reports=%d" % len(reports))
            return
        ok("5.0 ASan 阳性对照生效（越界探针产生 heap-use-after-free 报告）")

        src = os.path.join(tmpdir, "exit_join_probe.c")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(EXIT_JOIN_PROBE.replace("@LOG_MONITOR_SRC@", LOG_MONITOR_SRC))
        probe = _compile_asan(
            tmpdir, "exit_join_probe",
            [src] + [os.path.join(ROOT, p) for p in LOG_MONITOR_DEPS],
            extra=["-Wl,--wrap=read", "-Wl,--wrap=shutdown", "-Wl,--wrap=accept"])
        if probe is None:
            fail("5.1 退出路径探针编译失败", "见上方编译器输出")
            return
        # 抽象 socket 全局唯一：先停掉本套件拉起的实例，探针自己起一份
        stop_logmon()
        probe_log = os.path.join(tmpdir, "asanexit")
        try:
            r = _run_asan(probe, probe_log, timeout=90)
        except subprocess.TimeoutExpired:
            fail("5.2 退出路径探针超时", "线程未被 shutdown/join 唤醒（可能死锁）")
            return
        reports = _asan_reports(tmpdir, probe_log)
        uaf = [x for x in reports if "heap-use-after-free" in x]
        check("5.2 退出路径无 ASan 报告（free 前已 join 线程）",
              r.returncode == 0 and not uaf,
              (uaf[0].splitlines()[1] if uaf else
               "rc=%d stderr=%s" % (r.returncode,
                                    (r.stderr or "").strip().splitlines()[-1:])))
        check("5.3 探针正常跑完（SIGTERM 退出路径可达）",
              "PROBE: done" in r.stderr, (r.stderr or "").strip()[:200])
    # 探针进程已退出，抽象 socket 释放；后续用例需要时自行 start_logmon()

# ───────────────────────────────────────────────────────────
# 用例组6：per-事件 DEBUG 限速（open-unlink 本地直删）
# ───────────────────────────────────────────────────────────
DAEMON_SRC = os.environ.get("FUSE_DAEMON_SRC") or os.path.join(
    ROOT, "src", "daemon", "fuse_daemon.c")

# 限速函数的观测口：真机 20:05:18 一秒 633 行（com.taobao.idlefish 批量删
# lockfile），把 sys.log 里有用的行全冲掉。这里把它从 fuse_daemon.c 里抽出来
# 直编，用桩 LOG_DBG 数行数——不需要 /dev/fuse、不需要把 injector 开到 DEBUG，
# 也不受沙箱时间线影响。
OPEN_UNLINK_PROBE = r"""
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static int g_lines;

/* 桩：只数行数 + 原样打印，等价于 LOG_DBG 在 DEBUG 级别下的落盘行为 */
#define LOG_DBG(fmt, ...) do { g_lines++; printf(fmt "\n", ##__VA_ARGS__); } while (0)

@FUNC@

#ifndef CALLS
#define CALLS 2200
#endif

int main(void) {
    char p[4096];
    for (int i = 0; i < CALLS; i++) {
        snprintf(p, sizeof(p),
                 "/storage/emulated/0/Android/data/com.demo/files/lock%d.bin", i);
        log_open_unlink_direct(p);
    }
    printf("LINES=%d\n", g_lines);
    return 0;
}
"""

# 阳性对照：未限速的实现（= 旧行为）。探针必须对它报出 CALLS 行——证明这套
# 直编机制对「回归到每事件一条」是敏感的，而不是恒绿的。
OPEN_UNLINK_NAIVE = r"""
#include <stdio.h>

static int g_lines;
#define LOG_DBG(fmt, ...) do { g_lines++; printf(fmt "\n", ##__VA_ARGS__); } while (0)

static void log_open_unlink_direct(const char* path) {
    LOG_DBG("open-unlink 本地直删（不产生隐藏名）: %s", path);
}

int main(void) {
    char p[4096];
    for (int i = 0; i < 2200; i++) {
        snprintf(p, sizeof(p),
                 "/storage/emulated/0/Android/data/com.demo/files/lock%d.bin", i);
        log_open_unlink_direct(p);
    }
    printf("LINES=%d\n", g_lines);
    return 0;
}
"""


def _extract_c_function(text, name):
    """按花括号配平从 C 源里抽一个函数定义（签名可跨行）。抽不到返回 None。"""
    m = re.search(r"^[ \t]*(?:static\s+)?[A-Za-z_][\w \t\*]*\b" + re.escape(name) +
                  r"\s*\(", text, re.M)
    if not m:
        return None
    i = text.find("{", m.end())
    if i < 0:
        return None
    depth = 0
    while i < len(text):
        c = text[i]
        if c == '"' or c == "'":
            quote = c
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    break
                i += 1
        elif c == "/" and text.startswith("/*", i):
            i = text.find("*/", i)
            if i < 0:
                return None
            i += 2
            continue
        elif c == "/" and text.startswith("//", i):
            nl = text.find("\n", i)
            if nl < 0:
                return None
            i = nl + 1
            continue
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[m.start():i + 1]
        i += 1
    return None


def _build_and_run_open_unlink(tmpdir, tag, body, calls=2200):
    src = os.path.join(tmpdir, tag + ".c")
    with open(src, "w", encoding="utf-8") as fh:
        fh.write(body)
    exe = os.path.join(tmpdir, tag)
    # -D_GNU_SOURCE：被测函数用 PATH_MAX（真实构建里由 meson 定义）
    r = subprocess.run([*_cc(), "-std=c23", "-w", "-O0", "-D_GNU_SOURCE",
                        f"-DCALLS={calls}", src, "-o", exe],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stderr
    run = subprocess.run([exe], capture_output=True, text=True, timeout=60)
    if run.returncode != 0:
        return None, run.stderr
    return run.stdout, ""


def test_open_unlink_throttle():
    """用例组6：open-unlink 本地直删的 DEBUG 必须限速（旧实现每事件一条）。

    真机现场：com.taobao.idlefish 批量删 lockfile，20:05:18 一秒 633 行
    ``open-unlink 本地直删（不产生隐藏名）: <path>``。修复后首条打全路径、
    此后每 1024 条一条（只报目录 + 累计计数）。

    判别性：``FUSE_DAEMON_SRC=<git show HEAD:src/daemon/fuse_daemon.c>`` 跑本
    用例必失败——旧实现里没有 log_open_unlink_direct 这个观测口，抽取直接失败；
    即便有人把函数补上却不限速，探针会数到 2200 行（阈值 ≤4）。阳性对照
    （未限速实现）在同一套直编机制下必须报 2200 行，证明探针不是恒绿的。
    """
    log("\n━━━ 用例组6: open-unlink DEBUG 限速（L0 直编契约） ━━━")
    if not os.path.isfile(DAEMON_SRC):
        GAPS.append("fuse_daemon 源码缺失，open-unlink 限速用例跳过")
        log("  ⏭ 缺少 %s，跳过", DAEMON_SRC)
        return
    with open(DAEMON_SRC, encoding="utf-8", errors="replace") as fh:
        daemon_src = fh.read()
    func = _extract_c_function(daemon_src, "log_open_unlink_direct")
    if func is None:
        fail("6.0 fuse_daemon.c 里有 open-unlink 直删的唯一观测出口",
             "旧实现没有 log_open_unlink_direct：每 unlink 一条 LOG_DBG")
        return
    ok("6.0 fuse_daemon.c 里有 open-unlink 直删的唯一观测出口")
    with tempfile.TemporaryDirectory(prefix="log_open_unlink_") as tmpdir:
        naive, err = _build_and_run_open_unlink(tmpdir, "naive", OPEN_UNLINK_NAIVE)
        if naive is None:
            fail("6.1 阳性对照探针编译/运行失败", (err or "").strip()[:300])
            return
        m = re.search(r"LINES=(\d+)", naive)
        naive_lines = int(m.group(1)) if m else -1
        check("6.1 阳性对照（未限速实现）报出每事件一条——探针对回归敏感",
              naive_lines == 2200, f"LINES={naive_lines}（期望 2200）")

        body = OPEN_UNLINK_PROBE.replace("@FUNC@", func)
        out, err = _build_and_run_open_unlink(tmpdir, "throttle", body)
        if out is None:
            fail("6.2 限速探针编译/运行失败", (err or "").strip()[:300])
            return
        m = re.search(r"LINES=(\d+)", out)
        lines = int(m.group(1)) if m else -1
        want = 1 + 2200 // 1024
        check("6.2 2200 次「打开中删除」只产生首条 + 每 1024 条一条",
              lines == want, f"LINES={lines}（期望 {want}；旧实现 2200）")
        printed = [l for l in out.splitlines() if "open-unlink" in l]
        check("6.3 首条打全路径（现场能看出是哪个文件）",
              bool(printed) and "files/lock0.bin" in printed[0],
              printed[0] if printed else "无输出")
        check("6.4 折叠行只报目录 + 累计计数（不重复打文件名）",
              len(printed) >= 2 and "累计 1024 次" in printed[1]
              and printed[1].rstrip().endswith("files/")
              and "lock1024.bin" not in printed[1],
              printed[1] if len(printed) >= 2 else "无折叠行")


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
            return SKIP_RC
    if not os.path.exists("/dev/fuse"):
        log("❌ /dev/fuse 不可用，跳过全部")
        return SKIP_RC

    # 备份磁盘历史：本测试会改写 io.log/.1 与 sys.log/.1，收尾原样还原
    backup = {}
    for p in (IO_LOG, IO_ROT, SYS_LOG, SYS_ROT):
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
        # 用例组6 纯直编，不依赖 log_monitor（放在最前：监控起不来也要跑）
        test_open_unlink_throttle()
        if not start_logmon():
            fail("log_monitor 启动失败", "见 /tmp/log_pipeline_monitor.out")
        else:
            test_gate_matrix()
            test_disk_history()
            test_level_format()
            test_query_channel()
            test_rule_server_log_injection()
            test_exit_join()
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
    if GAPS:
        log("跳过项（gap，不计通过）:")
        for g in GAPS:
            log("  ⏭ %s", g)
    log("═══════════════════════════════════════")
    if FAIL:
        return 1
    return GAP_RC if GAPS else 0


if __name__ == "__main__":
    sys.exit(main())
