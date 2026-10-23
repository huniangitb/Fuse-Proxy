#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rule_server 规则控制守护进程测试

覆盖：
- PING / LIST / GET 查询（全局 + 应用规则、开关、注入状态）
- ADD 动态新增（GLOBAL 段规则、应用规则、REDIRECT src|dst、INJECT_ENABLE 开关）
- ENABLE / DISABLE 停用启用（# 注释切换）
- REMOVE 按 (类型, 索引) 删除
- SET 设置开关 ON/OFF
- STATUS / QUIT

前置：GNU 构建产物 build_gnu/rule_server（可用 RULE_SERVER 环境变量覆盖路径）。
测试使用 --config-dir 指向临时目录，抽象套接字名带 PID 后缀避免与真实服务冲突。
失败时退出码为 1（勿用管道吞掉退出码）。
"""

import json
import os
import random
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULE_SERVER = os.environ.get("RULE_SERVER", os.path.join(ROOT, "build_gnu", "rule_server"))

# 退出码约定（与 tests/run.py 一致）：0=通过 1=失败 77=整套跳过(gap)
# 78=部分子组跳过(gap)——SERVICE 段需 bin 目录下有 log_monitor，缺则跳过该段，
# 其余断言仍有效，故与整套跳过区分，但同样不计通过。
SKIP_RC = 77
GAP_RC = 78
GAPS = []


def abstract_sockaddr(name):
    """构造 Linux 抽象命名空间 AF_UNIX 地址：sun_path[0]='\\0' + 名称。
    Python 标准做法：'\0' + name 字符串即对应抽象地址。"""
    return "\0" + name


def send_cmd(server, sock_name, cmd_obj, timeout=5.0):
    """连接抽象套接字，发送单条 JSON 命令，返回 JSON 响应"""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(abstract_sockaddr(sock_name))
    payload = (json.dumps(cmd_obj, ensure_ascii=False) + "\n").encode("utf-8")
    s.sendall(payload)
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
    return json.loads(buf.decode("utf-8"))


def send_cmd_soft(server, sock_name, cmd_obj, timeout=5.0):
    """send_cmd 的容错版：服务崩溃/连接被拒时返回 {"status": "transport-error"}。

    判别性用例（如 R5 的 fields 非 object）在旧实现上会让 rule_server SIGSEGV，
    直接 send_cmd 会抛异常中断整套测试；软发送把「进程已死」变成一个可断言的
    失败项，后续正对照仍能继续跑。
    """
    try:
        return send_cmd(server, sock_name, cmd_obj, timeout)
    except (OSError, socket.timeout, ValueError) as e:
        return {"status": "transport-error", "error": str(e)}


def wait_server_ready(proc, sock_name, timeout=5.0):
    """轮询 PING 直到服务就绪"""
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"rule_server 提前退出: rc={proc.returncode}")
        try:
            resp = send_cmd(proc, sock_name, {"cmd": "PING"}, timeout=0.5)
            if resp.get("status") == "ok":
                return resp
            last_err = resp
        except (OSError, socket.timeout, json.JSONDecodeError) as e:
            last_err = e
        time.sleep(0.1)
    raise RuntimeError(f"rule_server 未就绪: {last_err}")


def main():
    if not os.path.exists(RULE_SERVER):
        print(f"错误: 未找到 rule_server 产物: {RULE_SERVER}", file=sys.stderr)
        print("请先执行: meson setup build_gnu -Dtarget_os=gnu && ninja -C build_gnu rule_server", file=sys.stderr)
        return SKIP_RC

    tmpdir = tempfile.mkdtemp(prefix="rule_srv_test_")
    conf_dir = os.path.join(tmpdir, "conf")
    os.makedirs(conf_dir, exist_ok=True)
    sock_name = f"nsp_rule_test_{os.getpid()}"

    # 预置主配置文件：GLOBAL 段带一条 HIDE 规则，一个应用段
    with open(os.path.join(conf_dir, "injector.conf"), "w", encoding="utf-8") as f:
        f.write("[GLOBAL]\n")
        f.write("MONITOR ON\n")
        f.write("HIDE /sdcard/secret\n")
        f.write("\n[com.example.app:0] ON\n")

    # 预置一个"已加载模块"的规则类型注册文件（模拟 ftp_module 的 FTP 类型），
    # 验证 rule_server 动态合并模块声明的规则类型
    # （含多语言 desc 与 argc 参数约束属性）
    mod_dir = os.path.join(conf_dir, "modules", "ftp_module")
    os.makedirs(mod_dir, exist_ok=True)
    with open(os.path.join(mod_dir, "ftp_module.rules"), "w", encoding="utf-8") as f:
        f.write('[FTP]\nformat = pair\nargc = 2\ndesc = FTP 存储映射：<虚拟前缀>|<段名>\ndesc.en = FTP storage mapping: <virtual prefix>|<section>\n')

    # ---- 模块配置 schema 判别点 ----
    # 上面这份 .rules **没有 [conf] 段**：此时控制面须回退编译期默认表
    # （5 个字段，只有 FTP 的 host/port/user/password/remote_dir），
    # 于是 key_file 这类 SFTP 字段会被拒——正是"新增键要改 C"的旧形态。
    # 下面先记录默认表形态，再改写 .rules 加入 [conf] 段，同一个键必须转为接受。

    # 预置第二用户（uid=10）空间：App-rules-10/ 目录 + 一个已停用应用
    user10_dir = os.path.join(conf_dir, "App-rules-10")
    os.makedirs(user10_dir, exist_ok=True)
    with open(os.path.join(user10_dir, "com.user10.app.conf"), "w", encoding="utf-8") as f:
        f.write("RO /sdcard/u10_ro\n")
    with open(os.path.join(user10_dir, "com.user10.disabled.conf.disabled"), "w", encoding="utf-8") as f:
        f.write("HIDE /sdcard/u10_hidden\n")

    proc = subprocess.Popen(
        [RULE_SERVER, "--foreground", "--config-dir", conf_dir, "--socket", sock_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        # B2：高危命令（STOP/QUIT/EXPORT_LOGS）默认仅 root 可执行；本用例以当前
        # 用户身份跑，故把自己的 uid 列入受信任白名单（负例见 check 里的 B2 段）
        env={**os.environ, "NSP_TRUSTED_UIDS": str(os.getuid())},
    )
    try:
        wait_server_ready(proc, sock_name)
        check(proc, sock_name, conf_dir)
        if GAPS:
            print(f"跳过项（gap，不计通过）: {GAPS}", file=sys.stderr)
            return GAP_RC
        print("rule_server 测试通过 ✔")
        return 0
    finally:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)


def check(proc, sock_name, conf_dir):
    failed = []

    def expect(name, cond, detail=""):
        if cond:
            print(f"  ok  {name}")
        else:
            print(f"FAIL {name} {detail}", file=sys.stderr)
            failed.append(name)

    # ---- PING ----
    r = send_cmd(proc, sock_name, {"cmd": "PING"})
    expect("PING", r.get("status") == "ok" and r["data"]["pong"] is True, r)

    # ---- UPTIME：运行时长查询 ----
    r = send_cmd(proc, sock_name, {"cmd": "UPTIME"})
    ok_ut = (r.get("status") == "ok"
             and isinstance(r["data"].get("uptime_seconds"), int)
             and r["data"]["uptime_seconds"] >= 0
             and isinstance(r["data"].get("uptime"), str)
             and r["data"]["uptime"]
             and isinstance(r["data"].get("started_at"), int)
             and r["data"]["started_at"] > 0
             and abs(r["data"]["uptime_seconds"] - (time.time() - r["data"]["started_at"])) < 60)
    expect("UPTIME", ok_ut, r)
    # UPTIME 数值随时间单调递增（间隔 1.1s 后再查应更大）
    time.sleep(1.1)
    r2 = send_cmd(proc, sock_name, {"cmd": "UPTIME"})
    expect("UPTIME 单调递增", r2.get("status") == "ok"
           and r2["data"]["uptime_seconds"] > r["data"]["uptime_seconds"], r2)

    # ---- LIST：GLOBAL 段 ----
    r = send_cmd(proc, sock_name, {"cmd": "LIST"})
    expect("LIST status", r.get("status") == "ok", r)
    g = r["data"]["global"]
    expect("LIST global switches.MONITOR", g["switches"].get("MONITOR") is True, g)
    expect("LIST global has HIDE", len(g["rules"]) == 1 and g["rules"][0]["type"] == "HIDE", g["rules"])

    # ---- GET GLOBAL ----
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "GLOBAL"})
    expect("GET global", r.get("status") == "ok" and r["data"]["global"]["switches"]["MONITOR"] is True, r)

    # ---- ADD GLOBAL 规则 ----
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "REDIRECT", "value": "/sdcard/a|/sdcard/b"})
    expect("ADD global REDIRECT", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "RO", "value": "/sdcard/ro"})
    expect("ADD global RO", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "LIST"})
    types = [x["type"] for x in r["data"]["global"]["rules"]]
    expect("LIST contains REDIRECT/RO", "REDIRECT" in types and "RO" in types, types)

    # ---- 应答 command 必须与实际请求一致（契约）----
    # 判别点：SET 此前直接转发给 handle_add，而 handle_add 把 "ADD" 写死在应答里，
    #         于是 SET 的应答自称 ADD（客户端只校验 status 才没暴露）。
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "HIDE",
                                   "value": "/sdcard/cmd_probe_a"})
    expect("ADD 应答 command=ADD", r.get("status") == "ok" and r.get("command") == "ADD", r)
    r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "GLOBAL", "type": "HIDE",
                                   "value": "/sdcard/cmd_probe_b"})
    expect("SET 应答 command=SET（旧实现回 ADD）",
           r.get("status") == "ok" and r.get("command") == "SET", r)
    r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "GLOBAL"})
    expect("SET 失败应答 command 同样为 SET",
           r.get("status") == "error" and r.get("command") == "SET", r)
    # 清掉两条探针规则（此刻 GLOBAL 的 HIDE 只有这两条 + 预置的 /sdcard/secret）
    for _ in range(2):
        send_cmd(proc, sock_name, {"cmd": "REMOVE", "pkg": "GLOBAL", "type": "HIDE", "index": 0})
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "GLOBAL"})
    hides = [x["value"] for x in r["data"]["global"]["rules"] if x["type"] == "HIDE"]
    expect("探针规则已清理（只剩预置的 /sdcard/secret）", hides == ["/sdcard/secret"], hides)

    # ---- ADD 应用规则 ----
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "com.example.app", "type": "HIDE", "value": "/sdcard/app_secret"})
    expect("ADD app HIDE", r.get("status") == "ok", r)
    app_file = os.path.join(conf_dir, "App-rules", "com.example.app.conf")
    expect("app conf written", os.path.exists(app_file) and "HIDE /sdcard/app_secret" in open(app_file, encoding="utf-8").read())

    # ---- GET APP ----
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "com.example.app"})
    expect("GET app inject_enable true（.conf 存在）",
           r.get("status") == "ok" and r["data"]["app"]["inject_enable"] is True, r)

    # ---- 停用应用：INJECT_ENABLE OFF → .conf 重命名为 .conf.disabled，不接触 injector.conf ----
    r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "com.example.app", "type": "INJECT_ENABLE", "value": "OFF"})
    expect("SET app INJECT_ENABLE OFF", r.get("status") == "ok", r)
    dis_file = os.path.join(conf_dir, "App-rules", "com.example.app.conf.disabled")
    expect(".conf.disabled 文件已生成", os.path.exists(dis_file), dis_file)
    expect(".conf 原文件已移除", not os.path.exists(app_file), app_file)
    conf_text = open(os.path.join(conf_dir, "injector.conf"), encoding="utf-8").read()
    expect("injector.conf 未被改写（无 OFF 段头）", "[com.example.app:0] OFF" not in conf_text, conf_text)
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "com.example.app"})
    expect("app inject_enable OFF", r["data"]["app"]["inject_enable"] is False, r)
    # LIST 中停用的应用仍应可见（disabled_file 标记）
    r = send_cmd(proc, sock_name, {"cmd": "LIST"})
    app_entry = next((a for a in r["data"]["apps"] if a["pkg"] == "com.example.app"), None)
    expect("LIST 含停用应用（disabled_file）",
           app_entry is not None and app_entry["inject_enable"] is False
           and app_entry.get("disabled_file") is True, app_entry)

    # ---- 重新启用：INJECT_ENABLE ON → 去掉 .disabled 后缀 ----
    r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "com.example.app", "type": "INJECT_ENABLE", "value": "ON"})
    expect("SET app INJECT_ENABLE ON", r.get("status") == "ok", r)
    expect(".conf 恢复", os.path.exists(app_file) and not os.path.exists(dis_file), app_file)
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "com.example.app"})
    expect("app inject_enable ON", r["data"]["app"]["inject_enable"] is True, r)

    # ---- 停用后继续操作：必须路由到 .conf.disabled，不新建残缺 .conf、不丢规则 ----
    # 先补充一条规则与开关，再停用
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "com.example.app", "type": "RO", "value": "/sdcard/ro"})
    r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "com.example.app", "type": "MONITOR", "value": "ON"})
    r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "com.example.app", "type": "INJECT_ENABLE", "value": "OFF"})
    # 停用状态下继续 SET 开关 / ADD 规则（修复前：新建残缺 .conf → 丢规则 + 注入异常开启）
    r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "com.example.app", "type": "MONITOR", "value": "OFF"})
    expect("停用后 SET MONITOR 成功", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "com.example.app", "type": "HIDE", "value": "/sdcard/post_disable"})
    expect("停用后 ADD 成功", r.get("status") == "ok", r)
    # .conf 不应被重建（否则注入状态异常开启）
    expect("停用后不新建残缺 .conf", not os.path.exists(app_file), app_file)
    # 全部内容写入 .conf.disabled（开关唯一、规则不丢、新规则追加）
    dis_content = open(dis_file, encoding="utf-8").read()
    mon_cnt = len([l for l in dis_content.splitlines() if l.strip().startswith("MONITOR ")])
    expect("停用后 MONITOR 唯一且为 OFF", mon_cnt == 1 and "MONITOR OFF" in dis_content, dis_content)
    expect("停用后原有规则不丢失", "HIDE /sdcard/app_secret" in dis_content and "RO /sdcard/ro" in dis_content, dis_content)
    expect("停用后新规则已追加", "HIDE /sdcard/post_disable" in dis_content, dis_content)
    # GET 状态仍为停用、规则完整；LIST 仅 1 个条目（不重复）
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "com.example.app"})
    app_st = r["data"]["app"]
    expect("停用后 GET inject_enable=False", app_st["inject_enable"] is False, app_st)
    expect("停用后 GET disabled_file=True", app_st.get("disabled_file") is True, app_st)
    got_types = sorted(x["type"] for x in app_st["rules"])
    expect("停用后 GET 规则完整", got_types == ["HIDE", "HIDE", "RO"], got_types)
    r = send_cmd(proc, sock_name, {"cmd": "LIST"})
    app_entries = [a for a in r["data"]["apps"] if a["pkg"] == "com.example.app"]
    expect("停用后 LIST 仅 1 个条目（去重）", len(app_entries) == 1, app_entries)
    # 恢复启用：全部规则保留（不丢）
    r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "com.example.app", "type": "INJECT_ENABLE", "value": "ON"})
    expect("停用后恢复启用成功", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "com.example.app"})
    got_types = sorted(x["type"] for x in r["data"]["app"]["rules"])
    expect("恢复启用后规则完整（不丢）", got_types == ["HIDE", "HIDE", "RO"], got_types)
    expect("恢复启用后 inject_enable=True", r["data"]["app"]["inject_enable"] is True, r)

    # ---- DISABLE / ENABLE ----
    r = send_cmd(proc, sock_name, {"cmd": "DISABLE", "pkg": "GLOBAL", "type": "HIDE", "index": 0})
    expect("DISABLE global HIDE", r.get("status") == "ok" and r["data"]["enabled"] is False, r)
    r = send_cmd(proc, sock_name, {"cmd": "LIST"})
    hides = [x for x in r["data"]["global"]["rules"] if x["type"] == "HIDE"]
    expect("HIDE disabled in LIST", len(hides) == 1 and hides[0]["enabled"] is False, hides)
    conf_text = open(os.path.join(conf_dir, "injector.conf"), encoding="utf-8").read()
    expect("HIDE line commented", "#HIDE /sdcard/secret" in conf_text, conf_text)

    r = send_cmd(proc, sock_name, {"cmd": "ENABLE", "pkg": "GLOBAL", "type": "HIDE", "index": 0})
    expect("ENABLE global HIDE", r.get("status") == "ok" and r["data"]["enabled"] is True, r)
    r = send_cmd(proc, sock_name, {"cmd": "LIST"})
    hides = [x for x in r["data"]["global"]["rules"] if x["type"] == "HIDE"]
    expect("HIDE enabled again", len(hides) == 1 and hides[0]["enabled"] is True, hides)

    # ---- REMOVE ----
    r = send_cmd(proc, sock_name, {"cmd": "REMOVE", "pkg": "GLOBAL", "type": "RO", "index": 0})
    expect("REMOVE global RO", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "LIST"})
    types = [x["type"] for x in r["data"]["global"]["rules"]]
    expect("RO removed", "RO" not in types, types)

    # ---- SET GLOBAL 开关 ----
    r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "GLOBAL", "type": "SANDBOX", "value": "ON"})
    expect("SET global SANDBOX ON", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "GLOBAL"})
    expect("SANDBOX ON reflected", r["data"]["global"]["switches"].get("SANDBOX") is True, r)

    # ---- ADD 类别段规则（[USER_APPS:<uid>]/[SYSTEM_APPS] 写主文件精确段头）----
    # 置于 REMOVE/TOGGLE 之后：类别规则进入主文件会影响文件全局索引断言
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "USER_APPS", "uid": 10, "type": "HIDE", "value": "/sdcard/cat_secret"})
    expect("ADD USER_APPS HIDE", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "SYSTEM_APPS", "type": "REDIRECT", "value": "/sdcard/sys_a|/sdcard/sys_b"})
    expect("ADD SYSTEM_APPS REDIRECT", r.get("status") == "ok", r)
    conf_text = open(os.path.join(conf_dir, "injector.conf"), encoding="utf-8").read()
    expect("主文件含 [USER_APPS:10] 段头", "[USER_APPS:10]" in conf_text, conf_text)
    expect("主文件含 [SYSTEM_APPS] 段头", "[SYSTEM_APPS]" in conf_text, conf_text)
    expect("类别规则落段", "HIDE /sdcard/cat_secret" in conf_text, conf_text)
    # 全局专属类型拒绝写入类别段；INJECT_ENABLE 不适用于类别段
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "USER_APPS", "uid": 10, "type": "GLOBAL_INJECT", "value": "ON"})
    expect("类别段拒绝 GLOBAL_INJECT", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "SYSTEM_APPS", "type": "INJECT_ENABLE", "value": "OFF"})
    expect("类别段拒绝 INJECT_ENABLE", r.get("status") == "error", r)
    # SET 开关写入类别段（开关替换路径）
    r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "USER_APPS", "uid": 10, "type": "MONITOR", "value": "ON"})
    expect("SET USER_APPS MONITOR ON", r.get("status") == "ok", r)
    # GET 类别段视图（段内切片）
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "USER_APPS", "uid": 10})
    cat = r["data"]["category"]
    expect("GET USER_APPS section", r.get("status") == "ok" and cat["section"] == "[USER_APPS:10]", cat)
    expect("GET USER_APPS 含 HIDE", any(x["type"] == "HIDE" and "cat_secret" in x["value"] for x in cat["rules"]), cat["rules"])
    expect("GET USER_APPS 开关", cat["switches"].get("MONITOR") is True, cat["switches"])
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "SYSTEM_APPS"})
    expect("GET SYSTEM_APPS section", r.get("status") == "ok" and r["data"]["category"]["section"] == "[SYSTEM_APPS]", r)

    # ---- A5：类别段索引口径必须与 GET 一致（混合段往返）----
    # GET 类别段回的是**段内**索引；REMOVE/TOGGLE 若按整文件全局序号计数，
    # 会删/改到 [GLOBAL] 里的同类型规则（旧实现：`[GLOBAL]` 已有 HIDE 时，
    # GET USER_APPS 报 index=0，REMOVE index=0 删掉的却是 [GLOBAL] 那条）。
    # 先补一条 [GLOBAL] HIDE，让全局与类别段各有一条同类型规则（歧义最大化）。
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "HIDE", "value": "/sdcard/global_second"})
    expect("A5 预置 GLOBAL 第二条 HIDE", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "GLOBAL"})
    g_hides = [x["value"] for x in r["data"]["global"]["rules"] if x["type"] == "HIDE"]
    expect("A5 GET GLOBAL 只含 [GLOBAL] 段规则（不混类别段）",
           sorted(g_hides) == ["/sdcard/global_second", "/sdcard/secret"], g_hides)

    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "USER_APPS", "uid": 10})
    cat_hides = [(x["index"], x["value"]) for x in r["data"]["category"]["rules"] if x["type"] == "HIDE"]
    expect("A5 类别段 HIDE 段内索引从 0 起", cat_hides == [(0, "/sdcard/cat_secret")], cat_hides)

    r = send_cmd(proc, sock_name, {"cmd": "REMOVE", "pkg": "USER_APPS", "uid": 10, "type": "HIDE", "index": 0})
    expect("A5 REMOVE 类别段 index=0 成功", r.get("status") == "ok", r)
    expect("A5 REMOVE 删的是类别段那条（不是 GLOBAL）",
           "cat_secret" in r["data"].get("removed", ""), r.get("data"))
    conf_text = open(os.path.join(conf_dir, "injector.conf"), encoding="utf-8").read()
    expect("A5 GLOBAL 两条 HIDE 原样保留",
           "HIDE /sdcard/secret" in conf_text and "HIDE /sdcard/global_second" in conf_text, conf_text)
    expect("A5 类别段 HIDE 已删除", "cat_secret" not in conf_text, conf_text)
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "GLOBAL"})
    expect("A5 REMOVE 后 GET GLOBAL 仍有 2 条 HIDE",
           len([x for x in r["data"]["global"]["rules"] if x["type"] == "HIDE"]) == 2,
           r["data"]["global"]["rules"])

    # TOGGLE 同口径：类别段补一条 HIDE，DISABLE index=0 只注释类别段那条
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "USER_APPS", "uid": 10, "type": "HIDE", "value": "/sdcard/cat_toggle"})
    expect("A5 类别段补一条 HIDE", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "DISABLE", "pkg": "USER_APPS", "uid": 10, "type": "HIDE", "index": 0})
    expect("A5 DISABLE 类别段 index=0", r.get("status") == "ok" and r["data"]["enabled"] is False, r)
    conf_text = open(os.path.join(conf_dir, "injector.conf"), encoding="utf-8").read()
    expect("A5 DISABLE 只注释类别段那条", "#HIDE /sdcard/cat_toggle" in conf_text, conf_text)
    expect("A5 DISABLE 未误注释 GLOBAL 的 HIDE",
           "#HIDE /sdcard/secret" not in conf_text
           and "#HIDE /sdcard/global_second" not in conf_text, conf_text)
    r = send_cmd(proc, sock_name, {"cmd": "ENABLE", "pkg": "USER_APPS", "uid": 10, "type": "HIDE", "index": 0})
    expect("A5 ENABLE 类别段 index=0", r.get("status") == "ok" and r["data"]["enabled"] is True, r)
    # 清理类别段探针，恢复初始形态（后续 GLOBAL 索引断言不受类别段干扰）
    r = send_cmd(proc, sock_name, {"cmd": "REMOVE", "pkg": "USER_APPS", "uid": 10, "type": "HIDE", "index": 0})
    expect("A5 清理类别段 HIDE 探针", r.get("status") == "ok", r)

    # ---- 动态规则类型（模块 .rules 注册）----
    # 1. PING 返回的类型表应含模块声明的 FTP（非内置、来源 ftp_module、pair 双参）
    r = send_cmd(proc, sock_name, {"cmd": "PING"})
    types = r["data"]["rule_types"]
    ftp_type = next((t for t in types if t["type"] == "FTP"), None)
    expect("PING 类型表含模块 FTP", ftp_type is not None and ftp_type["builtin"] is False
           and ftp_type["module"] == "ftp_module" and ftp_type["format"] == "pair", types)
    expect("PING 类型表含内置 HIDE", any(t["type"] == "HIDE" and t["builtin"] is True for t in types), types)

    # 0. 内建类型的元数据随二进制内嵌（原 basic_rules.rules 的内容）：规则引擎
    #    内建后模块目录里不再有该文件，若改回在 C 里裸注册类型名，desc 会全空
    #    （前端按 desc 渲染类型说明），argc/global-only 只能靠格式默认值兜着。
    hide_t = next((t for t in types if t["type"] == "HIDE"), None)
    expect("内建 HIDE desc 中文", hide_t is not None and hide_t.get("desc") == "隐藏路径", hide_t)
    expect("内建 HIDE desc_map 含英文",
           hide_t is not None and hide_t.get("desc_map", {}).get("en") == "Hide path", hide_t)
    expect("内建 MONITOR switch 1:1",
           any(t["type"] == "MONITOR" and t["format"] == "switch" and t["argc_min"] == 1
               and t["argc_max"] == 1 for t in types), types)
    expect("内建 global_only 仅 GLOBAL_INJECT/SKIP_SYSTEM_APPS/SANDBOX_DIR",
           {t["type"] for t in types if t["global_only"]} ==
           {"GLOBAL_INJECT", "SKIP_SYSTEM_APPS", "SANDBOX_DIR"},
           types)
    expect("内建类型 9 个且全部标 builtin",
           {t["type"] for t in types if t["builtin"]} ==
           {"HIDE", "RO", "REDIRECT", "ALLOW", "MONITOR", "SANDBOX",
            "GLOBAL_INJECT", "SKIP_SYSTEM_APPS", "SANDBOX_DIR"}, types)

    # 1.1 多语言描述：默认（不传 lang）回传中文 desc；lang=en 回传英文 desc；
    #     同时含 desc_map 全语言映射与 argc 参数约束
    expect("FTP desc 默认中文",
           ftp_type is not None and ftp_type.get("desc") == "FTP 存储映射：<虚拟前缀>|<段名>",
           ftp_type)
    expect("FTP argc 约束", ftp_type is not None
           and ftp_type.get("argc_min") == 2 and ftp_type.get("argc_max") == 2, ftp_type)
    expect("FTP desc_map 全语言", ftp_type is not None
           and ftp_type.get("desc_map", {}).get("en") == "FTP storage mapping: <virtual prefix>|<section>",
           ftp_type)
    r_en = send_cmd(proc, sock_name, {"cmd": "PING", "lang": "en"})
    ftp_en = next((t for t in r_en["data"]["rule_types"] if t["type"] == "FTP"), None)
    expect("FTP desc lang=en",
           ftp_en is not None and ftp_en.get("desc") == "FTP storage mapping: <virtual prefix>|<section>",
           ftp_en)
    hide_en = next((t for t in r_en["data"]["rule_types"] if t["type"] == "HIDE"), None)
    expect("内建 HIDE desc lang=en",
           hide_en is not None and hide_en.get("desc") == "Hide path", hide_en)
    # 1.2 未知语言回退中文
    r_xx = send_cmd(proc, sock_name, {"cmd": "PING", "lang": "ja"})
    ftp_xx = next((t for t in r_xx["data"]["rule_types"] if t["type"] == "FTP"), None)
    expect("FTP desc 未知语言回退中文",
           ftp_xx is not None and ftp_xx.get("desc") == "FTP 存储映射：<虚拟前缀>|<段名>", ftp_xx)

    # 1.3 属性顺序任意：desc.en= 出现在 desc= 之前，默认描述仍应标记为中文
    mod_rules = os.path.join(conf_dir, "modules", "ftp_module", "ftp_module.rules")
    with open(mod_rules, "w", encoding="utf-8") as f:
        f.write('[FTP]\nformat = pair\nargc = 2\ndesc.en = EN FIRST\ndesc = 中文在后\n')
    r_ord = send_cmd(proc, sock_name, {"cmd": "PING", "lang": "zh"})
    ftp_ord = next((t for t in r_ord["data"]["rule_types"] if t["type"] == "FTP"), None)
    dmap = ftp_ord.get("desc_map", {}) if ftp_ord else {}
    expect("FTP desc 顺序任意(zh 在 en 后仍为中文)",
           ftp_ord is not None and ftp_ord.get("desc") == "中文在后"
           and dmap.get("zh") == "中文在后" and dmap.get("en") == "EN FIRST", ftp_ord)
    # 恢复原预置声明（供后续用例使用）
    with open(mod_rules, "w", encoding="utf-8") as f:
        f.write('[FTP]\nformat = pair\nargc = 2\ndesc = FTP 存储映射：<虚拟前缀>|<段名>\ndesc.en = FTP storage mapping: <virtual prefix>|<section>\n')

    # 1.4 畸形 argc 声明：argc=abc 应被跳过（不注册 0:0 错误约束），类型仍可用
    with open(mod_rules, "w", encoding="utf-8") as f:
        f.write('[FTP]\nformat = pair\nargc = abc\ndesc = 坏声明\n')
    r_bad = send_cmd(proc, sock_name, {"cmd": "PING"})
    ftp_bad = next((t for t in r_bad["data"]["rule_types"] if t["type"] == "FTP"), None)
    expect("FTP 畸形 argc 声明被跳过(取默认 pair=2)",
           ftp_bad is not None and ftp_bad.get("argc_min") == 2
           and ftp_bad.get("argc_max") == 2, ftp_bad)
    r_bad_add = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "FTP", "value": "/a|/b"})
    expect("FTP 畸形 argc 后 ADD 仍可用", r_bad_add.get("status") == "ok", r_bad_add)
    if r_bad_add.get("status") == "ok":
        send_cmd(proc, sock_name, {"cmd": "REMOVE", "pkg": "GLOBAL", "type": "FTP", "index": 0})
    # 恢复原预置声明
    with open(mod_rules, "w", encoding="utf-8") as f:
        f.write('[FTP]\nformat = pair\nargc = 2\ndesc = FTP 存储映射：<虚拟前缀>|<段名>\ndesc.en = FTP storage mapping: <virtual prefix>|<section>\n')

    # 2. ADD 模块类型规则（FTP <虚拟前缀>|<段名>）应成功
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "FTP", "value": "/云盘|云盘"})
    expect("ADD 动态类型 FTP", r.get("status") == "ok", r)
    conf_text = open(os.path.join(conf_dir, "injector.conf"), encoding="utf-8").read()
    expect("FTP 行已写入", "FTP /云盘 云盘" in conf_text, conf_text)

    # 3. LIST 的 rules 应含 FTP 且带 module 来源
    r = send_cmd(proc, sock_name, {"cmd": "LIST"})
    ftp_rules = [x for x in r["data"]["global"]["rules"] if x["type"] == "FTP"]
    expect("LIST 含 FTP 规则", len(ftp_rules) == 1 and ftp_rules[0]["module"] == "ftp_module", ftp_rules)

    # 4. REMOVE 动态类型
    r = send_cmd(proc, sock_name, {"cmd": "REMOVE", "pkg": "GLOBAL", "type": "FTP", "index": 0})
    expect("REMOVE 动态类型 FTP", r.get("status") == "ok", r)

    # 5. pair 恰好 2 参数：3 token / 1 token 应被拒绝（FTP 固定 <虚拟前缀>|<段名>）
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "FTP", "value": "/a|b|c"})
    expect("FTP 3 token 被拒（pair 恰好 2 参数）", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "FTP", "value": "单token"})
    expect("FTP 1 token 被拒", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "FTP", "value": "/a|"})
    expect("FTP 空 token 被拒", r.get("status") == "error", r)
    # REDIRECT（同为 pair）也应恰好 2 参数
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "REDIRECT", "value": "/a|/b|/c"})
    expect("REDIRECT 3 token 被拒（pair）", r.get("status") == "error", r)

    # 5. 卸载模块（删除 .rules）→ 类型回收，ADD 应拒绝
    os.remove(os.path.join(conf_dir, "modules", "ftp_module", "ftp_module.rules"))
    r = send_cmd(proc, sock_name, {"cmd": "PING"})
    expect("卸载后类型表无 FTP", all(t["type"] != "FTP" for t in r["data"]["rule_types"]),
           r["data"]["rule_types"])
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "FTP", "value": "/云盘|云盘"})
    expect("卸载后 ADD FTP 被拒", r.get("status") == "error", r)

    # 6. 恢复模块 → 类型重新可用（热更新）
    with open(os.path.join(conf_dir, "modules", "ftp_module", "ftp_module.rules"), "w", encoding="utf-8") as f:
        f.write("[FTP]\nformat = pair\n")
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "FTP", "value": "/云盘|云盘"})
    expect("恢复后 ADD FTP 成功", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "REMOVE", "pkg": "GLOBAL", "type": "FTP", "index": 0})
    expect("清理动态 FTP 规则", r.get("status") == "ok", r)

    # ---- 非法输入 ----
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "../evil", "type": "HIDE", "value": "/x"})
    expect("ADD 拒绝路径穿越包名", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "BADTYPE", "value": "x"})
    expect("ADD 拒绝未知类型", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "UNKNOWN_CMD"})
    expect("未知命令报错", r.get("status") == "error", r)

    # ---- R5：MODULE_CONF_ADD/SET 的 fields 必须校验 JSON 类型 ----
    # 判别点：旧实现对 fields 只判存在就 json_object_object_foreach（对非 object
    #   强转解引用），string/array/number 会让 rule_server 直接 SIGSEGV。下面每条
    #   都用软发送（崩溃时得到 transport-error 而非抛异常），并紧跟 PING 正对照。
    for bad_fields in ("not-an-object", [1, 2], 123):
        kind = type(bad_fields).__name__
        r = send_cmd_soft(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                            "name": "R5盘", "fields": bad_fields})
        expect(f"R5 ADD fields={kind} 明确拒绝",
               r.get("status") == "error" and bool(r.get("error")), r)
        expect("R5 ADD 拒绝后服务存活（PING）",
               proc.poll() is None
               and send_cmd_soft(proc, sock_name, {"cmd": "PING"}).get("status") == "ok",
               proc.poll())
        r = send_cmd_soft(proc, sock_name, {"cmd": "MODULE_CONF_SET", "module": "ftp_module",
                                            "name": "云盘", "fields": bad_fields})
        expect(f"R5 SET fields={kind} 明确拒绝",
               r.get("status") == "error" and bool(r.get("error")), r)
        expect("R5 SET 拒绝后服务存活（PING）",
               proc.poll() is None
               and send_cmd_soft(proc, sock_name, {"cmd": "PING"}).get("status") == "ok",
               proc.poll())
    # fields 为 null = 未提供：ADD 回落到散字段拾取（给 host 即成功）
    r = send_cmd_soft(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                        "name": "R5盘", "fields": None, "host": "r5.example"})
    expect("R5 fields=null 按未提供处理（散字段 host 生效）",
           r.get("status") == "ok" and r["data"]["changed"] is True, r)
    # 既无 fields 也无散字段：明确报错（不是静默建空段）
    r = send_cmd_soft(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                        "name": "R5空", "fields": None})
    expect("R5 fields=null 且无散字段时明确拒绝",
           r.get("status") == "error" and bool(r.get("error")), r)
    # SET 同理：null 回落到单字段形态
    r = send_cmd_soft(proc, sock_name, {"cmd": "MODULE_CONF_SET", "module": "ftp_module",
                                        "name": "R5盘", "fields": None})
    expect("R5 SET fields=null 缺 key 时明确拒绝", r.get("status") == "error", r)
    r = send_cmd_soft(proc, sock_name, {"cmd": "MODULE_CONF_SET", "module": "ftp_module",
                                        "name": "R5盘", "fields": None,
                                        "key": "host", "value": "r5b.example"})
    expect("R5 SET fields=null 回落到单字段形态",
           r.get("status") == "ok" and r["data"]["changed"] is True, r)
    # 清理：条目删掉（文件留空不影响后续 FTP_LIST 空表断言）
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_REMOVE", "module": "ftp_module",
                                   "name": "R5盘"})
    expect("R5 清理条目", r.get("status") == "ok", r)
    expect("R5 全程后服务存活",
           proc.poll() is None
           and send_cmd(proc, sock_name, {"cmd": "PING"}).get("status") == "ok", proc.poll())

    # ---- R6：REMOVE 的包名校验不得被开关类型短路 ----
    # 判别点：旧实现对开关类型（MONITOR 等）跳过 valid_pkg，pkg="../../outside"
    #   经 App-rules/<pkg>.conf 越出配置根，把外部 .conf 的 MONITOR 行删掉。
    outside_dir = os.path.dirname(conf_dir)
    outside = os.path.join(outside_dir, "outside.conf")
    outside_body = "MONITOR ON\nHIDE /outside/keep\n"
    with open(outside, "w", encoding="utf-8") as f:
        f.write(outside_body)
    for bad_pkg in ("../../outside", "..", "a/b", "..%2f"):
        for t in ("MONITOR", "HIDE"):
            r = send_cmd(proc, sock_name, {"cmd": "REMOVE", "pkg": bad_pkg,
                                           "type": t, "index": 0})
            expect(f"R6 REMOVE 拒绝非法包名 {bad_pkg!r} type={t}",
                   r.get("status") == "error", r)
            expect(f"R6 外部文件逐字节不变 {bad_pkg!r} type={t}",
                   open(outside, encoding="utf-8").read() == outside_body, "外部文件被改动")
    # 正对照：合法 App-rules/<pkg> 与停用态 .conf.disabled 的 REMOVE 仍工作
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "com.r6.app", "type": "HIDE",
                                   "value": "/sdcard/r6_keep"})
    expect("R6 正对照 ADD", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "com.r6.app",
                                   "type": "INJECT_ENABLE", "value": "OFF"})
    expect("R6 正对照停用（路由到 .conf.disabled）", r.get("status") == "ok", r)
    r6_dis = os.path.join(conf_dir, "App-rules", "com.r6.app.conf.disabled")
    expect("R6 .conf.disabled 已生成", os.path.exists(r6_dis), r6_dis)
    r = send_cmd(proc, sock_name, {"cmd": "REMOVE", "pkg": "com.r6.app",
                                   "type": "HIDE", "index": 0})
    expect("R6 合法应用（停用态）REMOVE 成功",
           r.get("status") == "ok" and "r6_keep" in r["data"].get("removed", ""), r)
    expect("R6 停用态 REMOVE 写回 .conf.disabled 且不新建 .conf",
           "r6_keep" not in open(r6_dis, encoding="utf-8").read()
           and not os.path.exists(os.path.join(conf_dir, "App-rules", "com.r6.app.conf")),
           "路径/内容不符")
    # 纵深防御：App-rules 被替换成指向配置根外的符号链接时，realpath 边界校验必须
    # 拒绝（判别点：旧实现顺着链接把根外 .conf 的规则删掉）。
    sym_root = os.path.join(outside_dir, "sym_conf")
    sym_outside = os.path.join(outside_dir, "sym_outside")
    os.makedirs(sym_root, exist_ok=True)
    os.makedirs(sym_outside, exist_ok=True)
    sym_victim = os.path.join(sym_outside, "com.sym.app.conf")
    sym_body = "HIDE /victim/keep\n"
    with open(sym_victim, "w", encoding="utf-8") as f:
        f.write(sym_body)
    os.symlink(sym_outside, os.path.join(sym_root, "App-rules"))
    sym_sock = f"nsp_rule_sym_{os.getpid()}"
    sym_proc = subprocess.Popen(
        [RULE_SERVER, "--foreground", "--config-dir", sym_root, "--socket", sym_sock],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ, "NSP_TRUSTED_UIDS": str(os.getuid())})
    try:
        wait_server_ready(sym_proc, sym_sock)
        r = send_cmd_soft(sym_proc, sym_sock, {"cmd": "REMOVE", "pkg": "com.sym.app",
                                               "type": "HIDE", "index": 0})
        expect("R6 App-rules 符号链接越出配置根被拒绝",
               r.get("status") == "error", r)
        expect("R6 符号链接外目标逐字节不变",
               open(sym_victim, encoding="utf-8").read() == sym_body, "根外文件被改动")
    finally:
        try:
            sym_proc.send_signal(signal.SIGTERM)
            sym_proc.wait(timeout=3)
        except Exception:
            sym_proc.kill()

    # ---- 全局专属类型：仅 GLOBAL 可用，应用作用域必须拒绝 ----
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "com.example.app", "type": "GLOBAL_INJECT", "value": "ON"})
    expect("应用作用域拒绝 GLOBAL_INJECT", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "com.example.app", "type": "SKIP_SYSTEM_APPS", "value": "ON"})
    expect("应用作用域拒绝 SKIP_SYSTEM_APPS", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "com.example.app", "type": "FUSE_DIRECT", "value": "ON"})
    expect("应用作用域拒绝 FUSE_DIRECT", r.get("status") == "error", r)
    # GLOBAL 作用域应允许
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "GLOBAL", "type": "GLOBAL_INJECT", "value": "ON"})
    expect("GLOBAL 作用域允许 GLOBAL_INJECT", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "GLOBAL"})
    expect("GLOBAL_INJECT ON reflected", r["data"]["global"]["switches"].get("GLOBAL_INJECT") is True, r)
    # 应用配置文件未被写入全局专属类型
    app_conf_text = open(os.path.join(conf_dir, "App-rules", "com.example.app.conf"), encoding="utf-8").read()
    expect("应用配置文件无 GLOBAL_INJECT/SKIP_SYSTEM_APPS",
           "GLOBAL_INJECT" not in app_conf_text and "SKIP_SYSTEM_APPS" not in app_conf_text, app_conf_text)

    # ---- 多用户支持 ----
    # 1. USERS：列出全部已配置用户（App-rules=uid 0、App-rules-10=uid 10）
    r = send_cmd(proc, sock_name, {"cmd": "USERS"})
    users = r["data"]["users"]
    uids = sorted(u["uid"] for u in users)
    expect("USERS 含 uid 0 与 10", uids == [0, 10], users)
    u10 = next((u for u in users if u["uid"] == 10), None)
    expect("USERS uid10 app_count=2（含 .disabled）", u10 is not None and u10["app_count"] == 2, u10)

    # 2. GET uid 过滤：仅返回该用户的应用（不含 uid 0 的 com.example.app）
    r = send_cmd(proc, sock_name, {"cmd": "GET", "uid": 10})
    apps10 = r["data"].get("apps", [])
    pkgs10 = sorted(a["pkg"] for a in apps10)
    expect("GET uid=10 只含 uid10 应用", pkgs10 == ["com.user10.app", "com.user10.disabled"], pkgs10)
    expect("GET uid=10 含全局快照", "global" in r["data"], r["data"].keys())
    # 全部应用列表应同时含 uid 0 与 uid 10 的应用
    r = send_cmd(proc, sock_name, {"cmd": "LIST"})
    all_pkgs = [(a["pkg"], a["uid"]) for a in r["data"]["apps"]]
    expect("LIST 含双用户应用", ("com.example.app", 0) in all_pkgs and ("com.user10.app", 10) in all_pkgs,
           all_pkgs)

    # 3. uid10 空间操作：ADD/REMOVE/停用启用隔离于 uid 0
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "com.user10.app", "uid": 10, "type": "HIDE", "value": "/sdcard/u10_new"})
    expect("uid10 ADD HIDE", r.get("status") == "ok", r)
    u10_file = os.path.join(conf_dir, "App-rules-10", "com.user10.app.conf")
    expect("uid10 文件已写入", "HIDE /sdcard/u10_new" in open(u10_file, encoding="utf-8").read())
    # uid 0 的同名规则不受影响（com.example.app 无 HIDE /sdcard/u10_new）
    app0_text = open(os.path.join(conf_dir, "App-rules", "com.example.app.conf"), encoding="utf-8").read()
    expect("uid0 应用未受影响", "u10_new" not in app0_text, app0_text)
    # uid10 停用/启用：.disabled 在 App-rules-10/ 下，不接触 uid 0
    r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "com.user10.app", "uid": 10, "type": "INJECT_ENABLE", "value": "OFF"})
    expect("uid10 INJECT_ENABLE OFF", r.get("status") == "ok", r)
    expect("uid10 .disabled 生成", os.path.exists(u10_file + ".disabled") and not os.path.exists(u10_file))
    expect("uid0 .conf 未被波及", os.path.exists(app_file))
    r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "com.user10.app", "uid": 10, "type": "INJECT_ENABLE", "value": "ON"})
    expect("uid10 INJECT_ENABLE ON", r.get("status") == "ok", r)
    expect("uid10 .conf 恢复", os.path.exists(u10_file) and not os.path.exists(u10_file + ".disabled"))
    r = send_cmd(proc, sock_name, {"cmd": "REMOVE", "pkg": "com.user10.app", "uid": 10, "type": "HIDE", "index": 0})
    expect("uid10 REMOVE HIDE", r.get("status") == "ok", r)

    # 4. 非法 uid 拒绝
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "com.example.app", "uid": 99999999, "type": "HIDE", "value": "/x"})
    expect("ADD 拒绝超范围 uid", r.get("status") == "error", r)

    # ---- 截断边界 ----
    # 1. 大响应不截断：写入大量规则使 LIST 响应远超 MAX_REQ_LEN(8192)，
    #    客户端应收到完整 JSON（服务端 send 无上限）
    for i in range(200):
        r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": "com.big.app", "type": "HIDE", "value": f"/sdcard/big/{i:03d}"})
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": "com.big.app"})
    big_rules = r["data"]["app"]["rules"]
    raw_len = len(json.dumps(r))
    expect("大响应 JSON 完整可解析（规则数=200）", r.get("status") == "ok" and len(big_rules) == 200,
           f"rules={len(big_rules)} bytes={raw_len}")
    expect("大响应超过 8KB 仍完整", raw_len > 8192, f"bytes={raw_len}")
    # 清理大规则文件，避免影响后续用例
    os.remove(os.path.join(conf_dir, "App-rules", "com.big.app.conf"))

    # 2. 超长请求被拒：超过 MAX_REQ_LEN 的请求应返回 error 而非截断误解析
    big_pkg = "com." + "x" * 9000
    r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": big_pkg, "type": "HIDE", "value": "/x"})
    expect("超长请求被拒（不截断误解析）", r.get("status") == "error", r.get("error", ""))

    # ---- 开关去重回归：反复 SET 后文件中每个开关应只有一行（后写覆盖） ----
    for v in ["OFF", "ON", "OFF", "ON", "ON"]:
        r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "GLOBAL", "type": "MONITOR", "value": v})
    for v in ["ON", "OFF", "ON"]:
        r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "GLOBAL", "type": "SANDBOX", "value": v})
    for v in ["ON", "OFF", "ON", "OFF"]:
        r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "com.example.app", "type": "MONITOR", "value": v})
    for v in ["OFF", "ON", "OFF"]:
        r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": "com.example.app", "type": "SANDBOX", "value": v})
    gconf_text = open(os.path.join(conf_dir, "injector.conf"), encoding="utf-8").read()
    aconf_text = open(os.path.join(conf_dir, "App-rules", "com.example.app.conf"), encoding="utf-8").read()
    # injector.conf 含类别段（[USER_APPS:10] MONITOR）时开关天然多行：仅统计 [GLOBAL] 段内
    glines = gconf_text.splitlines()
    gstart = next((i for i, l in enumerate(glines) if l.strip() == "[GLOBAL]"), 0)
    gend = next((i for i in range(gstart + 1, len(glines)) if glines[i].strip().startswith("[")), len(glines))
    gscope = "\n".join(glines[gstart:gend])
    for fname, text, sw in [("injector.conf[GLOBAL]", gscope, ["MONITOR", "SANDBOX"]),
                            ("App-rules/com.example.app.conf", aconf_text, ["MONITOR", "SANDBOX"])]:
        for s in sw:
            cnt = len([l for l in text.splitlines() if l.strip().startswith(s + " ")])
            expect(f"开关去重 {fname} {s} 仅一行", cnt == 1, f"{s}={cnt}")

    # ---- 高压力随机化：随机操作配置文件，最终文件必须完整可解析 ----
    random.seed(20260807)
    stress_pkg = "com.stress.app"
    stress_types = ["HIDE", "RO", "ALLOW"]
    for _ in range(300):
        op = random.choice(["ADD", "SET", "REMOVE", "ENABLE", "DISABLE"])
        scope = random.choice(["GLOBAL", stress_pkg])
        if op == "ADD":
            t = random.choice(stress_types + ["MONITOR", "SANDBOX"])
            if t in ("MONITOR", "SANDBOX"):
                val = random.choice(["ON", "OFF"])
            else:
                val = f"/sdcard/stress/{random.randint(0, 50)}"
            r = send_cmd(proc, sock_name, {"cmd": "ADD", "pkg": scope, "type": t, "value": val})
        elif op == "SET":
            t = random.choice(["MONITOR", "SANDBOX"])
            r = send_cmd(proc, sock_name, {"cmd": "SET", "pkg": scope, "type": t, "value": random.choice(["ON", "OFF"])})
        elif op == "REMOVE":
            t = random.choice(stress_types)
            r = send_cmd(proc, sock_name, {"cmd": "REMOVE", "pkg": scope, "type": t, "index": random.randint(0, 5)})
        else:
            t = random.choice(stress_types)
            r = send_cmd(proc, sock_name, {"cmd": op, "pkg": scope, "type": t, "index": random.randint(0, 5)})
        # 所有操作必须返回结构化响应（不崩溃、不截断）
        if not isinstance(r, dict) or "status" not in r:
            expect("随机操作返回结构化响应", False, f"op={op} r={r}")
            break
    # 压力后文件完整性：GET 可解析、开关唯一、HIDE 规则数正确
    r = send_cmd(proc, sock_name, {"cmd": "GET", "pkg": stress_pkg})
    expect("压力后 GET 可解析", r.get("status") == "ok", r)
    stress_conf = open(os.path.join(conf_dir, "App-rules", "com.stress.app.conf"), encoding="utf-8").read()
    for s in ["MONITOR", "SANDBOX"]:
        cnt = len([l for l in stress_conf.splitlines() if l.strip().startswith(s + " ")])
        expect(f"压力后 {s} 唯一", cnt <= 1, f"{s}={cnt}")
    hide_cnt = len([l for l in stress_conf.splitlines() if l.strip().startswith("HIDE ")])
    expect("压力后 HIDE 规则数 ≤ 51（去重）", hide_cnt <= 51, f"HIDE={hide_cnt}")
    expect("压力后 HIDE 文件未丢失内容", hide_cnt > 0, f"HIDE={hide_cnt}")

    # ---- FTP 服务器账号管理（模块配置文件，基于公共 nsp_ini_store） ----
    # 落点 = 框架读取的同一路径 <config-dir>/modules/ftp_module/ftp_module.conf
    # （模块不读文件、不跑 inotify——见 docs/modules.md §6.1.1）
    ftp_path = os.path.join(conf_dir, "modules", "ftp_module", "ftp_module.conf")
    # 初始无配置文件：空表
    r = send_cmd(proc, sock_name, {"cmd": "FTP_LIST"})
    expect("FTP_LIST 空表", r.get("status") == "ok" and r["data"]["servers"] == []
           and r["data"]["file"].endswith("ftp_module.conf"), r)
    # 新建中文段名服务器
    r = send_cmd(proc, sock_name, {"cmd": "FTP_ADD", "name": "云盘", "host": "192.168.1.100",
                                   "port": 21, "user": "myuser", "password": "mypass",
                                   "remote_dir": "/"})
    expect("FTP_ADD 云盘", r.get("status") == "ok" and r["data"]["changed"] is True
           and r["data"]["duplicate"] is False, r)
    # 幂等：同值再加 → duplicate
    r = send_cmd(proc, sock_name, {"cmd": "FTP_ADD", "name": "云盘", "host": "192.168.1.100",
                                   "port": 21, "user": "myuser", "password": "mypass",
                                   "remote_dir": "/"})
    expect("FTP_ADD 幂等 duplicate", r.get("status") == "ok" and r["data"]["duplicate"] is True
           and r["data"]["changed"] is False, r)
    # GET 脱敏：无 password 键、有 has_password
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "云盘"})
    expect("FTP_GET 脱敏", r.get("status") == "ok" and "password" not in r["data"]
           and "pass" not in r["data"] and r["data"]["has_password"] is True
           and r["data"]["host"] == "192.168.1.100" and r["data"]["port"] == 21
           and r["data"]["user"] == "myuser" and r["data"]["remote_dir"] == "/", r)
    # 缺省值回填：只给 host 的匿名服务器
    r = send_cmd(proc, sock_name, {"cmd": "FTP_ADD", "name": "公共盘", "host": "ftp.example.com"})
    expect("FTP_ADD 缺省字段", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "公共盘"})
    expect("FTP_GET 缺省回填", r.get("status") == "ok" and r["data"]["port"] == 21
           and r["data"]["user"] == "anonymous" and r["data"]["remote_dir"] == "/"
           and r["data"]["has_password"] is False, r)
    # LIST 两条
    r = send_cmd(proc, sock_name, {"cmd": "FTP_LIST"})
    expect("FTP_LIST 两条", r.get("status") == "ok" and len(r["data"]["servers"]) == 2, r)
    # SET 改 host + port
    r = send_cmd(proc, sock_name, {"cmd": "FTP_SET", "name": "云盘", "key": "host", "value": "10.0.0.1"})
    expect("FTP_SET host", r.get("status") == "ok" and r["data"]["changed"] is True, r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_SET", "name": "云盘", "key": "host", "value": "10.0.0.1"})
    expect("FTP_SET 同值免写", r.get("status") == "ok" and r["data"]["changed"] is False, r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_SET", "name": "云盘", "key": "port", "value": "2121"})
    expect("FTP_SET port", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "云盘"})
    expect("FTP_SET 生效", r["data"]["host"] == "10.0.0.1" and r["data"]["port"] == 2121, r["data"])
    # 轮换密码：FTP_ADD 同名新密码必须落盘（非 duplicate）
    r = send_cmd(proc, sock_name, {"cmd": "FTP_ADD", "name": "云盘", "host": "10.0.0.1",
                                   "port": 2121, "user": "myuser", "password": "newpass",
                                   "remote_dir": "/"})
    expect("FTP_ADD 换密码落盘", r.get("status") == "ok" and r["data"]["changed"] is True
           and r["data"]["duplicate"] is False, r)
    ftp_text = open(ftp_path, encoding="utf-8").read()
    expect("FTP_ADD 新密码已写入", "password = newpass" in ftp_text
           and "password = mypass" not in ftp_text, ftp_text)
    # 含 # 的值拒绝（读侧以 # 为注释起点，放行会被截断）
    r = send_cmd(proc, sock_name, {"cmd": "FTP_ADD", "name": "井号盘", "host": "h", "password": "a#b"})
    expect("FTP_ADD 密码含#拒绝", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_SET", "name": "云盘", "key": "host", "value": "h#x"})
    expect("FTP_SET host含#拒绝", r.get("status") == "error", r)
    # 落盘权限 0600（明文密码）
    import stat as _stat
    mode = _stat.S_IMODE(os.stat(ftp_path).st_mode)
    expect("ftp.conf 权限 0600", mode == 0o600, oct(mode))
    # pass 别名归一 password
    r = send_cmd(proc, sock_name, {"cmd": "FTP_SET", "name": "公共盘", "key": "pass", "value": "anonpass"})
    expect("FTP_SET pass 别名", r.get("status") == "ok" and r["data"]["key"] == "password", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "公共盘"})
    expect("FTP_SET pass 生效且脱敏", r["data"]["has_password"] is True
           and "password" not in r["data"] and "pass" not in r["data"], r["data"])
    # 空值删键回缺省
    r = send_cmd(proc, sock_name, {"cmd": "FTP_SET", "name": "公共盘", "key": "password", "value": ""})
    expect("FTP_SET 空值删键", r.get("status") == "ok" and r["data"]["changed"] is True, r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "公共盘"})
    expect("FTP_SET 删键后无密码", r["data"]["has_password"] is False, r["data"])
    # 非法输入拒绝
    r = send_cmd(proc, sock_name, {"cmd": "FTP_ADD", "name": "GLOBAL", "host": "x"})
    expect("FTP_ADD 拒绝 GLOBAL 段名", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_ADD", "name": "坏[名", "host": "x"})
    expect("FTP_ADD 拒绝非法段名", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_ADD", "name": "新盘"})
    expect("FTP_ADD 新建缺 host 拒绝", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_ADD", "name": "新盘", "host": "x", "port": 99999})
    expect("FTP_ADD 非法端口拒绝", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_SET", "name": "云盘", "key": "bogus", "value": "x"})
    expect("FTP_SET 未知字段拒绝", r.get("status") == "error", r)

    # ---- 模块配置 schema：声明驱动 vs 硬编码白名单（判别性） ----
    # 现状：本测试布的 .rules 无 [conf] 段 → 走编译期默认表，
    #   SFTP 的 known_hosts 虽被模块解析侧支持，却因不在白名单而被拒（漂移形态）。
    r = send_cmd(proc, sock_name,
                 {"cmd": "FTP_SET", "name": "云盘", "key": "known_hosts", "value": "/kh"})
    expect("无 [conf] 段时 known_hosts 被拒（默认表）", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_SCHEMA"})
    expect("MODULE_SCHEMA 默认表仅 5 字段",
           r.get("status") == "ok" and len(r["data"]["fields"]) == 5, r)
    # 改写 .rules 加入 [conf] 段声明（含 SFTP 字段 + 枚举 + 敏感），
    # rule_server 每次命令前扫描，故下一次命令即生效，无需重启。
    rules_path = os.path.join(conf_dir, "modules", "ftp_module", "ftp_module.rules")
    with open(rules_path, "w", encoding="utf-8") as f:
        f.write(
            '[FTP]\nformat = pair\nargc = 2\ndesc = FTP 存储映射\n'
            '[conf]\n'
            'conf.host.type = string\nconf.host.maxlen = 255\n'
            'conf.host.required = true\nconf.host.desc = 服务器地址\n'
            'conf.port.type = int\nconf.port.range = 1:65535\nconf.port.default = 21\n'
            'conf.port.default.proto.sftp = 22\n'
            'conf.user.type = string\nconf.user.max = 63\nconf.user.default = anonymous\n'
            'conf.password.type = string\nconf.password.max = 127\n'
            'conf.password.sensitive = true\n'
            'conf.remote_dir.type = string\nconf.remote_dir.max = 511\n'
            'conf.remote_dir.default = /\n'
            'conf.proto.type = string\nconf.proto.enum = ftp|sftp\nconf.proto.default = ftp\n'
            'conf.known_hosts.type = path\nconf.known_hosts.maxlen = 511\n'
            'conf.known_hosts.desc = known_hosts 路径\n'
            'conf.known_hosts.desc.en = known_hosts path\n'
            'conf.host_key_check.type = bool\nconf.host_key_check.default = true\n')
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_SCHEMA"})
    expect("MODULE_SCHEMA 声明后扩到 8 字段（默认 5 + SFTP 3）", r.get("status") == "ok"
           and len(r["data"]["fields"]) == 8, r)
    keys = [f["key"] for f in r["data"]["fields"]] if r.get("status") == "ok" else []
    expect("schema 含 SFTP 的 known_hosts/proto",
           "known_hosts" in keys and "proto" in keys, keys)
    # 形状：前端据此自动渲染（类型/上限/敏感/缺省/可选值/顺序/标签）
    kh = next((f for f in r["data"]["fields"] if f["key"] == "known_hosts"), None)
    expect("schema 带 type/maxlen/desc/required", kh and kh["type"] == "path"
           and kh["maxlen"] == 511 and kh["desc"] == "known_hosts 路径"
           and kh["required"] is False, kh)
    pr = next((f for f in r["data"]["fields"] if f["key"] == "proto"), None)
    expect("schema 带 enum", pr and pr.get("enum") == ["ftp", "sftp"], pr)
    pw = next((f for f in r["data"]["fields"] if f["key"] == "password"), None)
    expect("schema 敏感字段标 sensitive", pw and pw["sensitive"] is True, pw)
    # 同一个键现在被接受 —— 判别点：不改 C、不重启，仅靠模块声明
    r = send_cmd(proc, sock_name,
                 {"cmd": "FTP_SET", "name": "云盘", "key": "known_hosts", "value": "/kh"})
    expect("声明后 known_hosts 被接受", r.get("status") == "ok", r)

    # ---- 随包分发的 .rules：SSH 密钥认证字段不进 schema（前端只给密码） ----
    # 判别点：把仓库里真实发布的那份声明装进模块目录。key_file / key_pass 必须
    #   既不出现在 MODULE_CONF_SCHEMA（前端不渲染私钥/口令输入框），也写不进去
    #   （控制面 fail-closed）——旧声明里有这两项，下面四条断言会全数失败。
    shipped = os.path.join(ROOT, "src", "modules", "ftp", "ftp_module.rules")
    with open(shipped, encoding="utf-8") as f:
        shipped_text = f.read()
    with open(rules_path, "w", encoding="utf-8") as f:
        f.write(shipped_text)
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SCHEMA", "module": "ftp_module"})
    real_keys = [f["key"] for f in r["data"]["fields"]] if r.get("status") == "ok" else []
    expect("随包 .rules：schema 无 key_file/key_pass（前端不渲染私钥输入）",
           r.get("status") == "ok" and "key_file" not in real_keys
           and "key_pass" not in real_keys, real_keys)
    expect("随包 .rules：8 字段且顺序稳定（密码认证）",
           real_keys == ["host", "port", "user", "password", "remote_dir", "proto",
                         "known_hosts", "host_key_check"], real_keys)
    r = send_cmd(proc, sock_name,
                 {"cmd": "FTP_SET", "name": "云盘", "key": "key_file", "value": "/k/id"})
    expect("随包 .rules：SET key_file 被拒（未知字段，fail-closed）",
           r.get("status") == "error" and "key_file" in (r.get("error") or ""), r)
    before = open(ftp_path, encoding="utf-8").read()
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                   "name": "密钥盘",
                                   "fields": {"host": "h", "key_file": "/k/id"}})
    expect("随包 .rules：ADD 带 key_file 整条拒绝", r.get("status") == "error", r)
    expect("随包 .rules：拒绝后文件逐字未变（不部分写入）",
           open(ftp_path, encoding="utf-8").read() == before
           and "密钥盘" not in before, "文件被改动")
    # ---- 契约形状（前端零兜底渲染的前提）----
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SCHEMA", "module": "ftp_module"})
    fs = {f["key"]: f for f in r["data"]["fields"]}
    # string/path 给 maxlen（长度语义），int 给 min/max 值域，二者不混用
    expect("string 字段给 maxlen、不给 min/max",
           "maxlen" in fs["host"] and "min" not in fs["host"] and "max" not in fs["host"], fs.get("host"))
    expect("int 字段给值域 min/max、不给 maxlen",
           fs["port"].get("min") == 1 and fs["port"].get("max") == 65535
           and "maxlen" not in fs["port"], fs.get("port"))
    expect("bool 字段不给 maxlen 且 default 为 JSON 布尔",
           "maxlen" not in fs["host_key_check"]
           and fs["host_key_check"]["default"] is True, fs.get("host_key_check"))
    expect("required 标记存在", fs["host"]["required"] is True, fs.get("host"))
    # 值域越界须按 schema 拒（不是固定 1~65535 兜底）
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SET", "name": "云盘",
                                   "key": "port", "value": "99999"})
    expect("int 值域越界被拒（按 schema 值域）", r.get("status") == "error", r)

    # 枚举越界仍拒（schema 校验生效，不是放行一切）
    r = send_cmd(proc, sock_name,
                 {"cmd": "FTP_SET", "name": "云盘", "key": "proto", "value": "scp"})
    expect("schema 枚举外值被拒", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name,
                 {"cmd": "FTP_SET", "name": "云盘", "key": "proto", "value": "sftp"})
    expect("schema 枚举内值接受", r.get("status") == "ok", r)

    # ---- E3：空值删键必须先于类型校验（int 字段否则永远删不掉） ----
    # 此时 云盘 的 proto=sftp、port 是显式 2121
    r = send_cmd(proc, sock_name, {"cmd": "FTP_SET", "name": "云盘", "key": "port", "value": ""})
    expect("E3 SET 空值删 int 字段（port）", r.get("status") == "ok"
           and r["data"]["changed"] is True, r)
    ftp_text = open(ftp_path, encoding="utf-8").read()
    expect("E3 port 键已从文件删除", "port = " not in ftp_text, ftp_text)
    # 纯空白与空串同义：旧实现会把键写成空值，模块读侧对空值整段作废
    r = send_cmd(proc, sock_name, {"cmd": "FTP_SET", "name": "云盘", "key": "user", "value": "   "})
    expect("E3 SET 纯空白 = 删键", r.get("status") == "ok" and r["data"]["changed"] is True, r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "云盘"})
    expect("E3 删键后回缺省（user=anonymous）",
           r.get("status") == "ok" and r["data"]["user"] == "anonymous", r)

    # ---- E4：port 缺省须认 proto（与模块侧推导同口径） ----
    # 判别点：旧实现把 port 缺省硬编码成 21，sftp 段回读得 21，前端整体回写即把
    #         sftp 段写成 port=21（模块连 21 端口，SFTP 配置被写坏）。
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "云盘"})
    expect("E4 删键后 port 回条件缺省 22（proto=sftp）",
           r.get("status") == "ok" and r["data"]["port"] == 22, r.get("data"))
    expect("E4 derived 标出 port 未显式配置（前端可只回写显式键）",
           "port" in r["data"].get("derived", []), r["data"].get("derived"))
    # 新建 sftp 段（不给 port）→ 22；默认 proto=ftp 的段 → 21
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                   "name": "sftp盘", "fields": {"host": "10.1.1.1",
                                                                "proto": "sftp"}})
    expect("E4 ADD sftp 段", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "sftp盘"})
    expect("E4 sftp 段未配 port → 22（旧实现报 21）",
           r.get("status") == "ok" and r["data"]["port"] == 22
           and "port" in r["data"].get("derived", []), r.get("data"))
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                   "name": "ftp盘", "fields": {"host": "10.1.1.2"}})
    expect("E4 ADD ftp 段", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "ftp盘"})
    expect("E4 未配 proto → 缺省 ftp，port 21",
           r["data"]["port"] == 21 and r["data"]["proto"] == "ftp", r.get("data"))
    # 显式 port 优先于条件缺省
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                   "name": "sftp2222", "fields": {"host": "h",
                                                                  "proto": "sftp",
                                                                  "port": "2222"}})
    expect("E4 ADD 显式 port", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "sftp2222"})
    expect("E4 显式 port 优先于条件缺省",
           r["data"]["port"] == 2222 and "port" not in r["data"].get("derived", []), r.get("data"))
    # 手写段（依赖字段写在后面）同样按文件内容推导，与书写顺序无关
    with open(ftp_path, "a", encoding="utf-8") as f:
        f.write("\n[手写盘]\nhost = h\nuser = u\nproto = sftp\n")
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "手写盘"})
    expect("E4 手写 sftp 段（proto 在末尾）port → 22",
           r.get("status") == "ok" and r["data"]["port"] == 22, r.get("data"))
    # schema 把条件缺省一并交给前端（placeholder 与 GET 同口径）
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SCHEMA", "module": "ftp_module"})
    fs2 = {f["key"]: f for f in r["data"]["fields"]}
    expect("E4 default_if 暴露条件缺省",
           fs2["port"].get("default_if") == {"key": "proto", "value": "sftp", "default": 22},
           fs2.get("port"))
    expect("default 按类型给 JSON 型别（int → 数字）",
           isinstance(fs2["port"]["default"], int) and fs2["port"]["default"] == 21
           and fs2["host"]["default"] == "", fs2.get("port"))

    # ---- R13：bool 字段词法校验 + 归一（on/off），GET 与模块解析同口径 ----
    # 判别点：旧实现 bool 落到通用字符串分支，garbage/2 照收，GET 渲染成 true，
    #   而模块侧 ftp_conf 会整段作废（前端显示已开启、后端却不存在）。
    def ftp_text_now():
        return open(ftp_path, encoding="utf-8").read()

    r13_before = ftp_text_now()
    for bad in ("garbage", "2", "yes"):
        r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SET", "module": "ftp_module",
                                       "name": "云盘", "key": "host_key_check",
                                       "value": bad})
        expect(f"R13 bool 拒绝非法值 {bad!r}",
               r.get("status") == "error" and "host_key_check" in (r.get("error") or ""), r)
        expect(f"R13 拒绝 {bad!r} 后文件逐字未变", ftp_text_now() == r13_before)
    for val, want, want_bool in (("TRUE", "on", True), ("On", "on", True), ("1", "on", True),
                                 ("FALSE", "off", False), ("off", "off", False),
                                 ("0", "off", False)):
        r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SET", "module": "ftp_module",
                                       "name": "云盘", "key": "host_key_check", "value": val})
        expect(f"R13 bool 接受 {val!r}", r.get("status") == "ok", r)
        seg = ftp_text_now().split("[云盘]")[1].split("\n[")[0]
        expect(f"R13 bool {val!r} 归一落盘为 {want}", f"host_key_check = {want}" in seg, seg)
        r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "云盘"})
        expect(f"R13 GET {val!r} → {want_bool}",
               r.get("status") == "ok" and r["data"]["host_key_check"] is want_bool,
               r.get("data"))
        expect(f"R13 显式配置后 {val!r} 不在 derived",
               "host_key_check" not in r["data"].get("derived", []),
               r["data"].get("derived"))
    # ADD 路径同一口径（fields 形态）：非法整体拒绝、合法归一落盘
    r13_before = ftp_text_now()
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                   "name": "R13盘",
                                   "fields": {"host": "h", "host_key_check": "garbage"}})
    expect("R13 ADD bool 非法值整体拒绝", r.get("status") == "error", r)
    expect("R13 ADD 拒绝后文件逐字未变", ftp_text_now() == r13_before)
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                   "name": "R13盘",
                                   "fields": {"host": "h", "host_key_check": "true"}})
    expect("R13 ADD bool 合法值归一落盘",
           r.get("status") == "ok"
           and "host_key_check = on" in ftp_text_now().split("[R13盘]")[1].split("\n[")[0], r)
    # 空值沿用既有「SET=删键回缺省 / ADD=不写」语义（E3/E5），不是词法错误
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SET", "module": "ftp_module",
                                   "name": "云盘", "key": "host_key_check", "value": ""})
    expect("R13 bool 空值 = 删键回缺省（既有语义）",
           r.get("status") == "ok" and r["data"]["changed"] is True, r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "云盘"})
    expect("R13 删键后回 schema 缺省（host_key_check=true 且标 derived）",
           r["data"]["host_key_check"] is True
           and "host_key_check" in r["data"].get("derived", []), r.get("data"))
    send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_REMOVE", "module": "ftp_module",
                               "name": "R13盘"})

    # ---- E5：ADD 空值 = 不写该键（不落 `key = ` 空行，模块读侧对空值整段作废） ----
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                   "name": "空值盘", "host": "10.2.2.2", "user": "",
                                   "remote_dir": "   ", "password": ""})
    expect("E5 ADD 带空值字段仍成功", r.get("status") == "ok", r)
    ftp_text = open(ftp_path, encoding="utf-8").read()
    seg = ftp_text.split("[空值盘]")[1].split("\n[")[0] if "[空值盘]" in ftp_text else ""
    expect("E5 空值字段未落盘（无 user/remote_dir/password 空行）",
           "host = 10.2.2.2" in seg and "user" not in seg
           and "remote_dir" not in seg and "password" not in seg, seg)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "空值盘"})
    expect("E5 空值字段走缺省",
           r["data"]["user"] == "anonymous" and r["data"]["remote_dir"] == "/"
           and r["data"]["has_password"] is False, r.get("data"))
    # 空值不等于"未声明字段"：未知键即使给空值也必须拒（fail-closed 先解析键名）
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                   "name": "空值盘", "fields": {"bogus": ""}})
    expect("未知键给空值仍被拒（空值不豁免键名校验）", r.get("status") == "error", r)

    # ---- 散字段形态按 schema 拾取（旧实现硬编码 5 个字段名，proto/known_hosts 静默丢弃）----
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                   "name": "散字段盘", "host": "h2", "proto": "sftp",
                                   "known_hosts": "/kh/known_hosts"})
    expect("散字段形态可写 schema 新增字段", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "散字段盘"})
    expect("散字段写入的 proto/known_hosts 生效（旧实现丢弃）",
           r["data"]["proto"] == "sftp"
           and r["data"]["known_hosts"] == "/kh/known_hosts", r.get("data"))

    # ---- required 由控制面强制（schema 的 required 不只是前端提示）----
    # 判别点：旧实现放行 → 落一个无 host 的段，模块侧整段作废（"配了却不生效"）
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                   "name": "缺host盘", "fields": {"port": "21"}})
    expect("新建条目缺 required 字段被拒", r.get("status") == "error", r)
    expect("被拒条目未落盘", "[缺host盘]" not in open(ftp_path, encoding="utf-8").read())

    # ---- 一次请求内既写字段又删键（MODULE_CONF_SET 的 fields 形态）----
    # 判别点：旧实现只认单字段 key/value，一次请求只能写或只能删；表单整体保存
    #         必须拆成 N 个请求，中途状态还能被并发读到。
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                   "name": "多字段盘", "fields": {"host": "10.3.3.3",
                                                                  "proto": "sftp",
                                                                  "user": "u",
                                                                  "port": "2222",
                                                                  "remote_dir": "/d"}})
    expect("多字段盘 ADD", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SET", "module": "ftp_module",
                                   "name": "多字段盘",
                                   "fields": {"host": "10.3.3.4", "port": "", "user": "",
                                              "known_hosts": "/kh/known_hosts"}})
    expect("SET fields 一次写+删（keys/deleted 如实回报）",
           r.get("status") == "ok"
           and sorted(r["data"]["keys"]) == ["host", "known_hosts"]
           and sorted(r["data"]["deleted"]) == ["port", "user"] and r["data"]["changed"] is True,
           r)
    conf_text = open(ftp_path, encoding="utf-8").read()
    seg = conf_text.split("[多字段盘]")[1].split("\n[")[0] if "[多字段盘]" in conf_text else ""
    expect("SET fields 落盘：host 更新、known_hosts 新增、port/user 删除",
           "host = 10.3.3.4" in seg and "known_hosts = /kh/known_hosts" in seg
           and "port" not in seg and "user" not in seg, seg)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "多字段盘"})
    expect("SET fields 后生效值（port 回条件缺省 22）",
           r["data"]["host"] == "10.3.3.4" and r["data"]["port"] == 22
           and r["data"]["known_hosts"] == "/kh/known_hosts"
           and "port" in r["data"].get("derived", []), r.get("data"))
    # 全有或全无：一个键非法即整条请求拒绝，文件逐字不动（不部分写入）
    before = open(ftp_path, encoding="utf-8").read()
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SET", "module": "ftp_module",
                                   "name": "多字段盘", "fields": {"host": "10.9.9.9",
                                                                  "bogus": "x"}})
    expect("SET fields 含未知键整体拒绝", r.get("status") == "error", r)
    expect("被拒请求不改动文件", open(ftp_path, encoding="utf-8").read() == before)
    # 空 fields 对象：无字段可设，明确拒绝（不静默回 ok）
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SET", "module": "ftp_module",
                                   "name": "多字段盘", "fields": {}})
    expect("SET fields 为空拒绝", r.get("status") == "error", r)
    # 单字段形态的应答形状保持不变（另回 key），并补出 keys/deleted
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SET", "module": "ftp_module",
                                   "name": "多字段盘", "key": "user", "value": "u2"})
    expect("单字段形态仍回 key，并给出 keys/deleted",
           r["data"]["key"] == "user" and r["data"].get("keys") == ["user"]
           and r["data"].get("deleted") == [], r)
    # ---- MODULE_CONF_* 通用入口（按 module 寻址任意模块） ----
    # 造第二个"模块"：无 [conf] 声明 → 无字段可写（安全默认：未声明不放行任何键）
    other_dir = os.path.join(conf_dir, "modules", "other_mod")
    os.makedirs(other_dir, exist_ok=True)
    with open(os.path.join(other_dir, "other_mod.rules"), "w", encoding="utf-8") as f:
        f.write('[conf]\nconf.token.type = string\nconf.token.max = 64\n'
                'conf.token.desc = 令牌\n'
                'conf.limit.type = int\nconf.limit.range = 1:9\n'
                'conf.limit.desc = 限额\n')
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SCHEMA", "module": "other_mod"})
    expect("MODULE_CONF_SCHEMA 跨模块",
           r.get("status") == "ok" and [f["key"] for f in r["data"]["fields"]] == ["token", "limit"],
           r)
    # int 字段一律写规范十进制——旧实现只对 port 一个字段名特判，"007" 会原样落盘
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "other_mod",
                                   "name": "B", "fields": {"token": "t", "limit": "007"}})
    expect("other_mod ADD（含 int 字段）", r.get("status") == "ok", r)
    other_conf = open(os.path.join(other_dir, "other_mod.conf"), encoding="utf-8").read()
    expect("int 字段写规范十进制（007 → 7，不再按字段名特判）",
           "limit = 7" in other_conf, other_conf)
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "other_mod",
                                   "name": "C", "fields": {"token": "t", "limit": "99"}})
    expect("非 port 的 int 字段同样按 schema 值域拒越界", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "other_mod",
                                  "name": "A", "host": "x"})
    expect("MODULE_CONF_ADD 按 schema 过滤字段（host 非该模块字段）",
           r.get("status") == "error", r)

    # ---- R7：schema 字段名必须精确比较（前缀不得串字段/吞敏感标记） ----
    # 判别点：旧实现 strncasecmp(cs->cf_key, rest, klen) 只比新字段名长度，
    #   token_secret 之后声明 token 会被当成同一字段：token 消失、token_secret
    #   的 sensitive 被后者覆盖为 false → GET 明文回读。
    r7_dir = os.path.join(conf_dir, "modules", "schema_mod")
    os.makedirs(r7_dir, exist_ok=True)
    with open(os.path.join(r7_dir, "schema_mod.rules"), "w", encoding="utf-8") as f:
        f.write('[conf]\n'
                'conf.token_secret.type = string\nconf.token_secret.sensitive = true\n'
                'conf.token.type = string\nconf.token.sensitive = false\n'
                'conf.ab.type = string\nconf.ab.sensitive = true\n'
                'conf.a.type = string\nconf.a.sensitive = false\n')
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SCHEMA", "module": "schema_mod"})
    r7_fields = {f["key"]: f for f in r["data"]["fields"]} if r.get("status") == "ok" else {}
    expect("R7 交叠字段名全部独立存在",
           sorted(r7_fields) == ["a", "ab", "token", "token_secret"], sorted(r7_fields))
    expect("R7 token_secret 保持 sensitive",
           r7_fields.get("token_secret", {}).get("sensitive") is True,
           r7_fields.get("token_secret"))
    expect("R7 token 非 sensitive",
           r7_fields.get("token", {}).get("sensitive") is False, r7_fields.get("token"))
    expect("R7 ab 保持 sensitive",
           r7_fields.get("ab", {}).get("sensitive") is True, r7_fields.get("ab"))
    expect("R7 a 非 sensitive",
           r7_fields.get("a", {}).get("sensitive") is False, r7_fields.get("a"))
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "schema_mod",
                                   "name": "S",
                                   "fields": {"token_secret": "PRIVATE_TOKEN",
                                              "token": "PUBLIC_TOKEN",
                                              "ab": "PRIVATE_AB", "a": "PUBLIC_A"}})
    expect("R7 交叠字段可同时写入", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_GET", "module": "schema_mod",
                                   "name": "S"})
    r7_get = r.get("data") or {}
    expect("R7 敏感字段键本身不出现（只回 has_）",
           r.get("status") == "ok" and "token_secret" not in r7_get and "ab" not in r7_get
           and r7_get.get("has_token_secret") is True and r7_get.get("has_ab") is True, r7_get)
    expect("R7 非敏感字段正常回读",
           r7_get.get("token") == "PUBLIC_TOKEN" and r7_get.get("a") == "PUBLIC_A", r7_get)
    expect("R7 GET 响应不含敏感明文",
           "PRIVATE_TOKEN" not in json.dumps(r) and "PRIVATE_AB" not in json.dumps(r),
           json.dumps(r, ensure_ascii=False))
    send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_REMOVE", "module": "schema_mod",
                               "name": "S"})

    # ---- R7b: module dir mtime precision must not hide a newly added module ----
    # 判别点：快速路径只比目录 mtime 时，mkdir+写文件若落在同一时钟 tick 内，
    # mtime 比较结果与上次相同 -> 不重扫 -> 新模块 schema 偶发缺失（热插拔失效）。
    # 用例把 modules 目录 mtime 显式拨回创建前的值，稳定复现该窗口：
    # 旧实现（只看 mtime）-> schema 缺失；新实现（同时比条目数）-> 正常发现。
    mods_dir = os.path.join(conf_dir, "modules")
    mt_before = os.stat(mods_dir).st_mtime_ns
    r7b_dir = os.path.join(mods_dir, "late_mod")
    os.makedirs(r7b_dir, exist_ok=True)
    with open(os.path.join(r7b_dir, "late_mod.rules"), "w", encoding="utf-8") as f:
        f.write("[conf]\nconf.k.type = string\n")
    os.utime(mods_dir, ns=(mt_before, mt_before))  # 模拟 mtime 未变
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_SCHEMA", "module": "late_mod"})
    r7b_keys = sorted(f["key"] for f in r["data"]["fields"]) if r.get("status") == "ok" else []
    expect("R7b 目录 mtime 未变时新增模块 schema 仍被发现", r7b_keys == ["k"], (r, r7b_keys))
    # ftp_module 走通用命令：等价于 FTP_ADD（别名行为一致）
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                   "name": "通用盘", "host": "10.9.9.9", "port": 21})
    expect("MODULE_CONF_ADD module=ftp_module 等价 FTP_ADD", r.get("status") == "ok", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "通用盘"})
    expect("FTP_* 别名读到通用入口写入的段",
           r.get("status") == "ok" and r["data"]["host"] == "10.9.9.9", r)
    # 目录穿越必须被拒（module 直接参与路径拼接）
    for bad in ("../../etc", "a/b", ".."):
        r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_LIST", "module": bad})
        expect(f"module={bad} 拒绝（防目录穿越）", r.get("status") == "error", r)
    # 未声明 schema 的模块：任何键都不放行（fail-closed）
    nos_dir = os.path.join(conf_dir, "modules", "nos_mod")
    os.makedirs(nos_dir, exist_ok=True)
    with open(os.path.join(nos_dir, "nos_mod.rules"), "w", encoding="utf-8") as f:
        f.write('[conf]\n')
    r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "nos_mod",
                                  "name": "A", "host": "x"})
    expect("无字段声明的模块拒绝写入", r.get("status") == "error", r)
    # 清理本块在 ftp_module 里建的段，避免影响后续既有用例的条目计数
    for _n in ("通用盘", "sftp盘", "ftp盘", "sftp2222", "手写盘", "空值盘", "散字段盘", "多字段盘"):
        send_cmd(proc, sock_name, {"cmd": "FTP_REMOVE", "name": _n})

    # 反向确认：撤掉 [conf] 段（回到旧形态）后，known_hosts 必须**重新被拒**——
    # 证明上面的"接受"确实来自声明，而不是别的路径（如默认表被放宽）。
    with open(rules_path, "w", encoding="utf-8") as f:
        f.write('[FTP]\nformat = pair\nargc = 2\ndesc = FTP 存储映射\n')
    r = send_cmd(proc, sock_name,
                 {"cmd": "FTP_SET", "name": "云盘", "key": "known_hosts", "value": "/kh2"})
    expect("撤掉 [conf] 后 known_hosts 重新被拒", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_SET", "name": "不存在", "key": "host", "value": "x"})
    expect("FTP_SET 不存在拒绝", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_GET", "name": "不存在"})
    expect("FTP_GET 不存在拒绝", r.get("status") == "error", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_REMOVE", "name": "不存在"})
    expect("FTP_REMOVE 不存在拒绝", r.get("status") == "error", r)
    # 文件级验证：注释保留、可被 ftp_conf 语义解析
    ftp_text = open(ftp_path, encoding="utf-8").read()
    expect("ftp.conf 含两段", "[云盘]" in ftp_text and "[公共盘]" in ftp_text, ftp_text)
    expect("ftp.conf 密码落盘（轮换后）", "password = newpass" in ftp_text, ftp_text)
    # REMOVE
    r = send_cmd(proc, sock_name, {"cmd": "FTP_REMOVE", "name": "公共盘"})
    expect("FTP_REMOVE", r.get("status") == "ok" and r["data"]["name"] == "公共盘", r)
    r = send_cmd(proc, sock_name, {"cmd": "FTP_LIST"})
    expect("FTP_REMOVE 后剩一条", len(r["data"]["servers"]) == 1
           and r["data"]["servers"][0]["name"] == "云盘", r)

    # ---- R12：模块配置读失败不得当空存储（否则下一次 ADD 覆盖整份文件） ----
    # 判别点：旧实现 nsp_ini_open 把 EACCES 也当「空存储」，MODULE_CONF_ADD 随即用
    #   只含本次条目的内容原子覆盖整份 ftp_module.conf。root 下 chmod 000 仍可读，
    #   该组跳过计 gap（见 AGENTS A10）；非 root 由本组端到端覆盖，--wrap=fopen 的
    #   确定性判别在 test_a26_misc.py 的直编组。
    if os.geteuid() != 0:
        r12_before = open(ftp_path, "rb").read()
        os.chmod(ftp_path, 0)
        try:
            r = send_cmd_soft(proc, sock_name,
                              {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                               "name": "读失败盘", "host": "h"})
            expect("R12 读失败时 ADD 返回错误",
                   r.get("status") == "error" and "读取" in (r.get("error") or ""), r)
            r = send_cmd_soft(proc, sock_name, {"cmd": "FTP_LIST"})
            expect("R12 读失败时 LIST 拒绝（不回空表）", r.get("status") == "error", r)
        finally:
            os.chmod(ftp_path, 0o600)
        expect("R12 读失败时文件逐字节不变", open(ftp_path, "rb").read() == r12_before)
        # 正对照：恢复可读后同一请求成功
        r = send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_ADD", "module": "ftp_module",
                                       "name": "恢复盘", "host": "h"})
        expect("R12 恢复可读后 ADD 正常", r.get("status") == "ok", r)
        send_cmd(proc, sock_name, {"cmd": "MODULE_CONF_REMOVE", "module": "ftp_module",
                                   "name": "恢复盘"})
    else:
        print("  (跳过 R12 读失败用例：以 root 运行，chmod 000 仍可读)")
        GAPS.append("R12 读失败（root 运行无法用 chmod 制造 EACCES）")

    # ---- EXPORT_LOGS：一键导出日志（落点/私有性/打包内容/prune 收敛） ----
    import tarfile as _tarfile
    log_dir = os.path.join(conf_dir, "log")
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, "io.log"), "w", encoding="utf-8") as f:
        f.write("1:export_probe io line\n")
    exp_dir = os.path.join(conf_dir, "export")

    r = send_cmd(proc, sock_name, {"cmd": "EXPORT_LOGS"})
    ok = r.get("status") == "ok"
    expect("EXPORT_LOGS 成功", ok, r)
    pkg = r["data"]["file"] if ok else ""
    # 落点必须在 <CONFIG_DIR>/export（root 私有），不得落在共享存储 STORAGE_BASE
    expect("EXPORT_LOGS 落点在 <CONFIG_DIR>/export",
           bool(pkg) and pkg.startswith(exp_dir + os.sep)
           and os.path.basename(pkg).startswith("log_export_")
           and pkg.endswith(".tar.gz"), pkg)
    expect("EXPORT_LOGS 产物存在且非空", bool(pkg) and os.path.isfile(pkg)
           and os.path.getsize(pkg) > 0, pkg)
    expect("EXPORT_LOGS 导出目录 0700（root 私有）",
           os.path.isdir(exp_dir) and (os.stat(exp_dir).st_mode & 0o777) == 0o700,
           oct(os.stat(exp_dir).st_mode & 0o777) if os.path.isdir(exp_dir) else "missing")
    names = []
    try:
        with _tarfile.open(pkg, "r:gz") as tf:
            names = tf.getnames()
    except Exception as e:  # noqa: BLE001
        names = [f"<open failed: {e}>"]
    expect("EXPORT_LOGS 包内含 log/io.log",
           any(n.endswith("io.log") for n in names), names)

    # 连续两次导出：只保留最新一份（旧实现同秒互相覆盖 / 留两份）
    r2 = send_cmd(proc, sock_name, {"cmd": "EXPORT_LOGS"})
    expect("EXPORT_LOGS 第二次成功", r2.get("status") == "ok", r2)
    pkgs = sorted(n for n in os.listdir(exp_dir)
                  if n.startswith("log_export_") and n.endswith(".tar.gz"))
    expect("EXPORT_LOGS 只保留最新一份", len(pkgs) == 1, pkgs)
    expect("EXPORT_LOGS 保留的是最新那份",
           len(pkgs) == 1 and pkgs[0] == os.path.basename(r2["data"]["file"]), pkgs)

    # 预置历史堆积（模拟多次导出遗留的旧包）→ 一次调用即收敛到 1 份
    stale_names = []
    for i in range(3):
        sn = f"log_export_1000000000_1_{i}.tar.gz"
        stale_names.append(sn)
        sp = os.path.join(exp_dir, sn)
        with open(sp, "w", encoding="utf-8") as f:
            f.write("stale")
        os.utime(sp, (1000 + i, 1000 + i))  # 旧 mtime，确保被当作最旧
    r3 = send_cmd(proc, sock_name, {"cmd": "EXPORT_LOGS"})
    expect("EXPORT_LOGS 第三次成功", r3.get("status") == "ok", r3)
    left = sorted(n for n in os.listdir(exp_dir)
                  if n.startswith("log_export_") and n.endswith(".tar.gz"))
    expect("EXPORT_LOGS 一次调用清空历史堆积（收敛到 1 份）", len(left) == 1, left)
    expect("EXPORT_LOGS 历史旧包全部删除",
           not any(n in left for n in stale_names), left)

    # 日志目录缺失 → 明确失败（不生成空包）
    shutil.rmtree(log_dir, ignore_errors=True)
    r4 = send_cmd(proc, sock_name, {"cmd": "EXPORT_LOGS"})
    expect("EXPORT_LOGS 日志目录缺失时拒绝",
           r4.get("status") == "error", r4)
    os.makedirs(log_dir, exist_ok=True)

    # ---- STATUS ----
    r = send_cmd(proc, sock_name, {"cmd": "STATUS"})
    expect("STATUS", r.get("status") == "ok" and r["data"]["config_dir"] == conf_dir, r)

    # ---- SERVICE：状态查询 + 启停控制 ----
    r = send_cmd(proc, sock_name, {"cmd": "SERVICE"})
    expect("SERVICE status ok", r.get("status") == "ok", r)
    sd = r["data"]
    expect("SERVICE 含 rule_server(pid+alive)",
           sd["rule_server"]["alive"] is True and sd["rule_server"]["pid"] > 0, sd)
    for proc_name in ["injector", "fuse_daemon", "log_monitor"]:
        expect(f"SERVICE 含 {proc_name} 状态字段",
               isinstance(sd.get(proc_name), dict) and "pid" in sd[proc_name]
               and "alive" in sd[proc_name], sd.get(proc_name))
    expect("SERVICE 含 ready 汇总", "ready" in sd, sd)
    # 未知 action 拒绝
    r = send_cmd(proc, sock_name, {"cmd": "SERVICE", "action": "bad"})
    expect("SERVICE 未知 action 拒绝", r.get("status") == "error", r)

    # 启停控制：start → log_monitor 存活（若同目录存在二进制）；stop → 退出；restart → 重新拉起
    import glob as _glob
    bin_dir = os.path.dirname(os.path.abspath(RULE_SERVER))
    has_log_monitor = os.path.exists(os.path.join(bin_dir, "log_monitor"))
    if has_log_monitor:
        # 先确保干净：杀掉可能残留的测试 log_monitor（仅匹配本测试进程树）
        try:
            subprocess.run(["pkill", "-9", "-x", "log_monitor"], capture_output=True)
        except Exception:
            pass
        time.sleep(0.2)
        r = send_cmd(proc, sock_name, {"cmd": "SERVICE", "action": "status"})
        expect("SERVICE 初始 log_monitor 未运行",
               r["data"]["log_monitor"]["alive"] is False, r["data"]["log_monitor"])
        r = send_cmd(proc, sock_name, {"cmd": "SERVICE", "action": "start"})
        expect("SERVICE start ok", r.get("status") == "ok" and r["data"]["started"] >= 1, r)
        time.sleep(0.5)
        r = send_cmd(proc, sock_name, {"cmd": "SERVICE", "action": "status"})
        expect("SERVICE start 后 log_monitor 存活且 pid>0",
               r["data"]["log_monitor"]["alive"] is True and r["data"]["log_monitor"]["pid"] > 0,
               r["data"]["log_monitor"])
        r = send_cmd(proc, sock_name, {"cmd": "SERVICE", "action": "stop"})
        expect("SERVICE stop ok", r.get("status") == "ok" and r["data"]["stopped"] >= 1, r)
        time.sleep(0.3)
        r = send_cmd(proc, sock_name, {"cmd": "SERVICE", "action": "status"})
        expect("SERVICE stop 后 log_monitor 退出",
               r["data"]["log_monitor"]["alive"] is False, r["data"]["log_monitor"])
        r = send_cmd(proc, sock_name, {"cmd": "SERVICE", "action": "restart"})
        expect("SERVICE restart ok", r.get("status") == "ok", r)
        time.sleep(0.6)
        r = send_cmd(proc, sock_name, {"cmd": "SERVICE", "action": "status"})
        expect("SERVICE restart 后 log_monitor 存活(跳过僵尸)",
               r["data"]["log_monitor"]["alive"] is True and r["data"]["log_monitor"]["pid"] > 0,
               r["data"]["log_monitor"])
        # 清理测试拉起的 log_monitor，避免污染环境
        try:
            subprocess.run(["pkill", "-9", "-x", "log_monitor"], capture_output=True)
        except Exception:
            pass
    else:
        print("  (跳过 SERVICE 启停控制：bin 目录无 log_monitor)")
        GAPS.append("SERVICE 启停控制（bin 目录无 log_monitor）")

    # ---- B2：对端鉴权（高危命令白名单） ----
    # 另起一个**未配置 NSP_TRUSTED_UIDS** 的实例：本测试进程（非 root）对它的
    # STOP / EXPORT_LOGS 必须被拒且进程存活，PING 等非高危命令仍放行。
    # 判别点：旧实现 accept 后直接 dispatch，这两条会真的生效（STOP 会停服）。
    if os.getuid() != 0:
        auth_sock = f"nsp_rule_auth_{os.getpid()}"
        env_no_trust = {k: v for k, v in os.environ.items() if k != "NSP_TRUSTED_UIDS"}
        aproc = subprocess.Popen(
            [RULE_SERVER, "--foreground", "--config-dir", conf_dir, "--socket", auth_sock],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env_no_trust)
        try:
            wait_server_ready(aproc, auth_sock)
            ra = send_cmd(aproc, auth_sock, {"cmd": "STOP"})
            expect("B2 非受信任 uid 的 STOP 被拒", ra.get("status") == "error", ra)
            ra = send_cmd(aproc, auth_sock, {"cmd": "EXPORT_LOGS"})
            expect("B2 非受信任 uid 的 EXPORT_LOGS 被拒", ra.get("status") == "error", ra)
            # SERVICE 的 start/stop/restart 与 STOP 同等能力（停/起 injector、
            # fuse_daemon、log_monitor），必须同样受限。判别点：旧实现只看顶层
            # cmd，`SERVICE stop` 会真的停服并回 status=ok。
            for action in ("start", "stop", "restart"):
                ra = send_cmd(aproc, auth_sock, {"cmd": "SERVICE", "action": action})
                expect(f"B2 非受信任 uid 的 SERVICE {action} 被拒",
                       ra.get("status") == "error", ra)
            # status 是只读查询：必须保持开放，否则管理器 App 看不到服务状态
            ra = send_cmd(aproc, auth_sock, {"cmd": "SERVICE", "action": "status"})
            expect("B2 SERVICE status 仍放行（只读查询）", ra.get("status") == "ok", ra)
            ra = send_cmd(aproc, auth_sock, {"cmd": "PING"})
            expect("B2 非高危命令仍放行（PING）", ra.get("status") == "ok", ra)
            expect("B2 拒绝后服务存活（命令未生效）", aproc.poll() is None, aproc.poll())
        finally:
            try:
                aproc.send_signal(signal.SIGTERM)
                aproc.wait(timeout=3)
            except Exception:
                aproc.kill()
    else:
        print("  (跳过 B2 负例：以 root 运行，对端 uid=0 属受信任)")

    # ---- QUIT：服务应退出 ----
    r = send_cmd(proc, sock_name, {"cmd": "QUIT"})
    expect("QUIT", r.get("status") == "ok", r)
    try:
        proc.wait(timeout=3)
        expect("QUIT 后进程退出", True)
    except subprocess.TimeoutExpired:
        expect("QUIT 后进程退出", False, "进程未退出")

    if failed:
        print(f"共 {len(failed)} 项失败: {failed}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
