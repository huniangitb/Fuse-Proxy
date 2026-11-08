#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FUSE 事件通道端到端（GNU 真实 daemon + 真实 FUSE 挂载）

单元套件用桩隔离了三条依赖（路径合成 / 规则决策 / 访问控制），这里补上
"真实 fuse_daemon 进程"这一维：只有真的写穿 FUSE，才能证明埋点挂在
**正确的回调成功点**上，而不是挂在桩里。

判别点：
  1. 订阅后经挂载写文件 → 收到一条 write_done，且 vpath 相对用户根、
     spath 是存储视图绝对路径、rpath 是真实落盘路径（三域自洽）；
  2. 建目录/改名 → op=mkdir / op=rename，rename 额外带 src_vpath/src_spath；
  3. 被 RO 拒绝的写 → write_denied + errno=EROFS + spath，且**不带** rpath
     （文件根本没落盘：扫描侧不得据此去扫一个不存在的路径）；
  4. nsp_fs_query：绝对 spath 反解 → REDIRECT 给出落点 spath、RO 给出
     denied=1/reason=ro、正常路径 exists=1、非视图路径 ok=0；
  5. 开关默认 OFF：同一份配置去掉 FUSE_EVENTS 后两条 socket 都不存在
     （connect 得到 ECONNREFUSED）——"默认关就是真关"。

前置：build_gnu/ 产物、/dev/fuse、fusermount3；三者缺一即整层跳过（77）。
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BASE = Path("/tmp/fuse_events_test")
MNT = BASE / "mnt"
STORAGE = BASE / "storage"
MODDIR = BASE / "modules"
CONF = BASE / "injector.conf"  # 本套件 BASE 内，勿与其他套件共用
DLOG = Path("/tmp/fw_events_fuse.log")
DAEMON = os.environ.get("FUSE_DAEMON") or str(ROOT / "build_gnu" / "fuse_daemon")
EV_ADDR = b"\0nsp_fs_events"
Q_ADDR = b"\0nsp_fs_query"

PASS = 0
FAIL = 0


def ok(d):
    global PASS
    PASS += 1
    print(f"  ✅ {d}")


def fail(d, detail=""):
    global FAIL
    FAIL += 1
    print(f"  ❌ {d}: {detail}")


def setup(events_on=True):
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)
    shutil.rmtree(BASE, ignore_errors=True)
    (STORAGE / "0" / "Pictures").mkdir(parents=True)
    (STORAGE / "0" / "ro").mkdir(parents=True)
    (STORAGE / "0" / "movies").mkdir(parents=True)
    (STORAGE / "0" / "ro" / "r.txt").write_text("readonly")
    MNT.mkdir(parents=True)
    MODDIR.mkdir(parents=True, exist_ok=True)
    CONF.parent.mkdir(parents=True, exist_ok=True)
    lines = ["[GLOBAL]", "MONITOR OFF", "SANDBOX OFF"]
    if events_on:
        # 通道白名单：让本进程有权连两条 socket（默认只有 root/system/media_rw）
        lines += ["FUSE_EVENTS ON", f"FUSE_EVENTS_UIDS {os.getuid()}"]
    # REDIRECT 的 target 相对 <存储根>/<user>（与 $DATA_BASE 同口径），
    # 写成 /movies 即落到 STORAGE/0/movies —— 这样 rpath 能映射回视图
    lines += ["REDIRECT /dcim /movies", "RO /ro"]
    CONF.write_text("\n".join(lines) + "\n")


def start():
    p = subprocess.Popen([DAEMON, f"--root={STORAGE}", f"--rules={CONF}",
                          f"--modules-dir={MODDIR}", "-f", str(MNT)],
                         stdout=open(DLOG, "a"), stderr=subprocess.STDOUT)
    for _ in range(45):
        time.sleep(0.2)
        try:
            os.listdir(MNT)
            return p
        except OSError:
            pass
        if p.poll() is not None:
            return None
    return p


def stop(p):
    if p:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
    time.sleep(0.2)
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)


def probe(addr, typ):
    s = socket.socket(socket.AF_UNIX, typ)
    try:
        s.connect(addr)
        return True
    except OSError:
        return False
    finally:
        s.close()


def wait_ready(addr, typ, timeout=10.0):
    """daemon 在挂载可见之后才 bind 事件 socket（daemonize 之后起线程/建 socket，
    早于此刻的 connect 会得到 ECONNREFUSED），客户端按契约退避重连。"""
    end = time.time() + timeout
    while time.time() < end:
        if probe(addr, typ):
            return True
        time.sleep(0.05)
    return False


def subscribe():
    """抽象命名空间 DGRAM 订阅者（契约里客户端侧的唯一形态）。"""
    if not wait_ready(EV_ADDR, socket.SOCK_DGRAM):
        raise RuntimeError("nsp_fs_events 未就绪（开关没打开？）")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(f"\0nsp_fs_events.py.{os.getpid()}")
    s.settimeout(5.0)
    req = {"cmd": "SUBSCRIBE", "reply": f"nsp_fs_events.py.{os.getpid()}",
           "filter": {"types": ["write_done", "write_denied"]}}
    s.sendto(json.dumps(req).encode(), EV_ADDR)
    time.sleep(0.3)  # 让 daemon 事件线程处理订阅帧
    return s


def read_events(sock, want_types, timeout=5.0):
    """收到第一条 type 属于 want_types 的帧就返回它（跳过其它类型）。"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            data = sock.recv(2048)
        except socket.timeout:
            break
        except OSError:
            break
        for line in data.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                fail("事件帧必须是单行 NDJSON", line[:120])
                continue
            if ev.get("type") in want_types:
                return ev
    return None


def query(req):
    wait_ready(Q_ADDR, socket.SOCK_SEQPACKET)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    s.settimeout(5.0)
    try:
        s.connect(Q_ADDR)
    except OSError as e:
        s.close()
        return {"_error": str(e)}
    req.setdefault("cmd", "QUERY")
    req.setdefault("v", 1)
    s.send(json.dumps(req).encode())
    try:
        data = s.recv(4096)
    except OSError as e:
        s.close()
        return {"_error": str(e)}
    s.close()
    try:
        return json.loads(data.decode().strip())
    except json.JSONDecodeError:
        return {"_raw": data.decode(errors="replace")}


def main():
    if not os.path.exists(DAEMON):
        print(f"缺少 {DAEMON}", file=sys.stderr)
        return 77
    if not os.path.exists("/dev/fuse"):
        print("缺少 /dev/fuse", file=sys.stderr)
        return 77
    if shutil.which("fusermount3") is None:
        print("缺少 fusermount3", file=sys.stderr)
        return 77

    setup(events_on=True)
    p = start()
    if not p:
        print(DLOG.read_text()[-2000:], file=sys.stderr)
        fail("daemon 启动失败")
        return 1
    sock = None
    try:
        print("\n── A. 订阅 + 写穿 FUSE → write_done 三路径域自洽 ──")
        sock = subscribe()
        target = MNT / "0" / "Pictures" / "a.jpg"
        with open(target, "wb") as f:
            f.write(b"hello-event")
        ev = read_events(sock, {"write_done"})
        if ev is None:
            fail("写文件后应收到 write_done", "5s 内没有事件（埋点没挂到 vfs_write/vfs_create？）")
        else:
            ok(f"收到 write_done: op={ev.get('op')}")
            checks = [
                ("v", ev.get("v") == 1),
                ("seq>0", isinstance(ev.get("seq"), int) and ev["seq"] > 0),
                ("ts>0", isinstance(ev.get("ts"), int) and ev["ts"] > 0),
                ("vol", ev.get("vol") == "external_primary"),
                ("uid", ev.get("uid") == os.getuid()),
                ("op∪", ev.get("op") in ("create", "close_write", "write")),
                ("vpath 相对用户根", ev.get("vpath") == "/Pictures/a.jpg"),
                ("spath 存储视图", ev.get("spath") == "/storage/emulated/0/Pictures/a.jpg"),
                ("rpath 真实落盘", str(ev.get("rpath", "")).startswith(str(STORAGE / "0"))),
            ]
            for name, good in checks:
                if good:
                    ok(f"字段 {name}")
                else:
                    fail(f"字段 {name}", json.dumps(ev, ensure_ascii=False))

        print("\n── B. mkdir / rename 的 op 与 src 字段 ──")
        os.mkdir(MNT / "0" / "Pictures" / "d1")
        ev = read_events(sock, {"write_done"})
        if ev and ev.get("op") == "mkdir" and ev.get("vpath") == "/Pictures/d1":
            ok("mkdir → write_done{op=mkdir, vpath=/Pictures/d1}")
        else:
            fail("mkdir 事件", json.dumps(ev, ensure_ascii=False) if ev else "无事件")

        os.rename(MNT / "0" / "Pictures" / "a.jpg", MNT / "0" / "Pictures" / "b.jpg")
        ev = read_events(sock, {"write_done"})
        if ev and ev.get("op") == "rename" and ev.get("vpath") == "/Pictures/b.jpg":
            ok("rename → write_done{op=rename, vpath=目标}")
            if ev.get("src_vpath") == "/Pictures/a.jpg" and \
                    ev.get("src_spath") == "/storage/emulated/0/Pictures/a.jpg":
                ok("rename 带 src_vpath/src_spath")
            else:
                fail("rename 的 src 字段", json.dumps(ev, ensure_ascii=False))
        else:
            fail("rename 事件", json.dumps(ev, ensure_ascii=False) if ev else "无事件")

        print("\n── C. RO 拒绝 → write_denied（带 errno/spath，不带 rpath）──")
        try:
            os.close(os.open(MNT / "0" / "ro" / "blocked.jpg", os.O_CREAT | os.O_WRONLY, 0o644))
            fail("RO 路径的创建应被拒", "居然成功了")
        except OSError:
            ok("RO 路径创建被拒（EROFS）")
        ev = read_events(sock, {"write_denied"})
        if ev is None:
            fail("被拒的写应产生 write_denied", "5s 内没有事件")
        else:
            if ev.get("type") == "write_denied" and ev.get("errno") == "EROFS":
                ok("write_denied{errno=EROFS}")
            else:
                fail("write_denied 的 errno", json.dumps(ev, ensure_ascii=False))
            if ev.get("spath") == "/storage/emulated/0/ro/blocked.jpg":
                ok("write_denied 带 spath（本应落到的存储视图路径）")
            else:
                fail("write_denied 的 spath", json.dumps(ev, ensure_ascii=False))
            if "rpath" not in ev:
                ok("write_denied 不带 rpath（文件未落盘）")
            else:
                fail("write_denied 不得带 rpath", json.dumps(ev, ensure_ascii=False))

        print("\n── D. nsp_fs_query 五类响应 ──")
        uid = os.getuid()
        r = query({"spath": "/storage/emulated/0/Pictures/b.jpg", "uid": uid, "seq": 7})
        if r.get("ok") == 1 and r.get("exists") == 1 and r.get("denied") == 0 \
                and r.get("reason") == "none":
            ok("正常路径 → ok=1/exists=1/denied=0/reason=none")
        else:
            fail("正常路径查询", json.dumps(r, ensure_ascii=False))
        if r.get("seq") == 7:
            ok("响应回显 seq")
        else:
            fail("响应 seq", json.dumps(r, ensure_ascii=False))

        r = query({"spath": "/storage/emulated/0/ro/r.txt", "uid": uid, "seq": 8})
        if r.get("ok") == 1 and r.get("denied") == 1 and r.get("reason") == "ro":
            ok("RO 路径 → denied=1/reason=ro")
        else:
            fail("RO 路径查询", json.dumps(r, ensure_ascii=False))

        r = query({"spath": "/storage/emulated/0/Pictures/missing.jpg", "uid": uid, "seq": 9})
        if r.get("ok") == 1 and r.get("exists") == 0 and r.get("denied") == 0:
            ok("不存在路径 → ok=1/exists=0/denied=0")
        else:
            fail("不存在路径查询", json.dumps(r, ensure_ascii=False))

        r = query({"spath": "/data/media/0/Pictures/b.jpg", "uid": uid, "seq": 10})
        if r.get("ok") == 0 and "denied" not in r:
            ok("非存储视图路径 → ok=0（不得伪装成 denied）")
        else:
            fail("非视图路径应 ok=0", json.dumps(r, ensure_ascii=False))

        r = query({"spath": "/storage/emulated/0/dcim/moved.jpg", "uid": uid, "seq": 11})
        if r.get("reason") == "redirect" and r.get("ok") == 1:
            ok(f"REDIRECT 命中 → reason=redirect, spath={r.get('spath')}")
            if str(r.get("rpath", "")).endswith("/movies/moved.jpg"):
                ok("REDIRECT 的 rpath 指向落点")
            else:
                fail("REDIRECT 的 rpath", json.dumps(r, ensure_ascii=False))
            if r.get("spath") == "/storage/emulated/0/movies/moved.jpg":
                ok("REDIRECT 的 spath 映射回落点视图")
            else:
                fail("REDIRECT 的 spath", json.dumps(r, ensure_ascii=False))
        else:
            fail("REDIRECT 查询", json.dumps(r, ensure_ascii=False))
    finally:
        if sock:
            sock.close()
        stop(p)

    print("\n── E. 开关默认 OFF：两条 socket 都不存在 ──")
    setup(events_on=False)
    p = start()
    if not p:
        fail("daemon 启动失败（OFF 配置）")
        return 1
    try:
        time.sleep(1.5)  # 给"关着就该没有"一个充分窗口
        offline = {"ev": False, "q": False}
        for name, addr in (("ev", EV_ADDR), ("q", Q_ADDR)):
            s = socket.socket(socket.AF_UNIX,
                              socket.SOCK_DGRAM if name == "ev" else socket.SOCK_SEQPACKET)
            try:
                s.connect(addr)
            except OSError:
                offline[name] = True
            finally:
                s.close()
        if offline["ev"] and offline["q"]:
            ok("FUSE_EVENTS OFF（默认）：nsp_fs_events / nsp_fs_query 均不可连接")
        else:
            fail("OFF 时不得创建事件 socket", json.dumps(offline))
        # OFF 时挂载照旧可用（零行为影响）
        with open(MNT / "0" / "Pictures" / "off.txt", "wb") as f:
            f.write(b"x")
        ok("OFF 时挂载读写照常")
    finally:
        stop(p)

    print(f"\nfw_events 端到端：{PASS} 通过, {FAIL} 失败")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
