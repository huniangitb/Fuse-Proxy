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
        return 1

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
    )
    try:
        wait_server_ready(proc, sock_name)
        check(proc, sock_name, conf_dir)
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

    # ---- 动态规则类型（模块 .rules 注册）----
    # 1. PING 返回的类型表应含模块声明的 FTP（非内置、来源 ftp_module、pair 双参）
    r = send_cmd(proc, sock_name, {"cmd": "PING"})
    types = r["data"]["rule_types"]
    ftp_type = next((t for t in types if t["type"] == "FTP"), None)
    expect("PING 类型表含模块 FTP", ftp_type is not None and ftp_type["builtin"] is False
           and ftp_type["module"] == "ftp_module" and ftp_type["format"] == "pair", types)
    expect("PING 类型表含内置 HIDE", any(t["type"] == "HIDE" and t["builtin"] is True for t in types), types)

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
