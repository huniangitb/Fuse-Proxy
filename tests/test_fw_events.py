#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FUSE 事件通道生产侧（src/daemon/fw_events.c）判别性单测

背景（契约：Media-Provider-Manager 的 FUSE-EVENTS.md v5 冻结版）：
  扫描侧（MediaProvider/MPM）要知道「哪个路径刚变过」，否则只能整树重扫。
  生产侧是 fuse_daemon 的两条抽象命名空间 UDS：
    nsp_fs_events（SOCK_DGRAM，订阅 + NDJSON 推送）
    nsp_fs_query（SOCK_SEQPACKET，一次性查询）
  本套件直编真实源码 src/daemon/fw_events.c，只桩掉它不负责的三层
  （common_* 路径合成、fw_rules_resolve 规则决策、fw_acl_check 访问控制、
  fw_pkg_resolve 身份），断言**行为**：

    1. 事件字段构造：v/seq/ts/type/vol/uid/pkg/op/vpath/spath/rpath 齐全且自洽，
       vpath 相对用户根、spath 是存储视图绝对路径、rename 带 src_vpath/src_spath、
       write_denied 带 errno 与 spath 且**不带** rpath（写没落盘）；
    2. 200ms 内同 vpath 合并为最后一条（不同 vpath 各自成条）；
    3. 环形队列 4096 满丢最旧并累计 dropped，心跳如实上报增量；
    4. 无订阅者 / 开关关闭时埋点早退（不入队、不分配）；
    5. QUERY 六类响应互不混淆（ok=0 与 denied=1、busy=1 与 ok=0）；
    6. 绝对 spath 反解 user 10（user 一路带到 rpath 与 spath 合成）；
    7. exists 的 TTL≤200ms 与「write_done 使缓存失效」；
    8. 订阅 filter 生效、通道白名单默认含 root/system/media_rw；
    9. 白名单自动含 MediaProvider 进程 uid——按包名从 packages.list **真实**解析
       （夹具里写行即命中、删行即不在、同 uid 去重），以及 ENOSPC/EDQUOT 的写
       拒绝要发布（EIO 仍是噪声，不发）。

判别性：fw_events.c 是新增模块（旧树上整个文件不存在）；此外每条断言都对着
契约的具体条款——把窗口改成 0ms、把 dropped 改成累计值、把 ok=0 复用成
denied=1、把 TTL 去掉，都会让本套件失败。白名单自动项与 ENOSPC 两条在
修复前 HEAD（旧实现）上必失败：旧实现既不解析 packages.list 的 pkg→uid，
write_denied 的 errno 集合也没有 ENOSPC/EDQUOT。

前置：本机 cc。失败退出码 1（勿用管道吞掉退出码）。
"""

import os
import re
import shlex
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(ROOT, "tests", "fixtures", "fw_events_driver.c")
SOURCE = os.path.join(ROOT, "src", "daemon", "fw_events.c")
HEADER = os.path.join(ROOT, "src", "daemon", "fw_events.h")
DAEMON = os.path.join(ROOT, "src", "daemon", "fuse_daemon.c")
UTIL = os.path.join(ROOT, "src", "core", "nsp_util.c")
MESON = os.path.join(ROOT, "meson.build")
RUN_TIMEOUT = 120


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def static_contract():
    """契约类静态断言：判决单点、零分配热路径、开关默认 OFF、埋点不阻塞。"""
    errs = []
    ev = _read(SOURCE)
    daemon = _read(DAEMON)
    meson = _read(MESON)

    # ① 判定复用单点：不得另写规则/ACL 判定
    if ev.count("fw_acl_check(") != 1:
        errs.append(f"fw_events.c 里 fw_acl_check( 出现 {ev.count('fw_acl_check(')} 次，期望 1 次")
    # 两处合法调用点：事件 rpath 现算 + QUERY 判定（都只是"问引擎"，不自己判）
    if ev.count("fw_rules_resolve(") > 2:
        errs.append(f"fw_events.c 里 fw_rules_resolve( 出现 {ev.count('fw_rules_resolve(')} 次，"
                    "期望 ≤2 次（事件 rpath + QUERY 判定；再多就是绕开单点）")
    for bad in ('"/Android/data"', '"/Android/obb"', '"hidden"', "appear_missing ="):
        if bad in ev:
            errs.append(f"fw_events.c 出现 {bad} —— 规则判定必须留在 fw_rules，事件层只读结论")

    # ② 热路径不得分配、不得阻塞
    if "malloc(" in ev or ev.count("calloc(") != 1:
        errs.append("fw_events.c 只允许启动期一次 calloc（事件环）；热路径不得分配")
    if ev.count("lstat(") != 1:
        errs.append(f"fw_events.c 里 lstat( 出现 {ev.count('lstat(')} 次，期望 1 次"
                    "（exists 缓存 + TTL 是唯一的文件系统探测）")
    if "MSG_DONTWAIT" not in ev:
        errs.append("对外发送必须带 MSG_DONTWAIT（订阅者塞满队列时不得反压 IO 路径）")

    # ③ 默认 OFF 的零开销：开关判断必须在线程/socket 创建之前
    start = ev.find("int fw_events_start(void) {")
    body = ev[start:] if start >= 0 else ""
    off = body.find("if (!g_global_cfg.fuse_events)")
    first_thread = body.find("pthread_create(")
    if start < 0 or off < 0:
        errs.append("fw_events.c 找不到 [GLOBAL] FUSE_EVENTS 的开关判断")
    elif first_thread >= 0 and off > first_thread:
        errs.append("开关判断必须在 fw_events_start 内创建线程之前（默认 OFF 时零线程零 socket）")

    # ④ 通道身份校验方式：DGRAM 走 SCM_CREDENTIALS，SEQPACKET 走 SO_PEERCRED
    if "SO_PASSCRED" not in ev or "SCM_CREDENTIALS" not in ev:
        errs.append("订阅侧必须用 SO_PASSCRED/SCM_CREDENTIALS 取通道身份（DGRAM 的 SO_PEERCRED 不可靠）")
    if "nsp_peer_cred(" not in ev:
        errs.append("QUERY 侧必须用 nsp_peer_cred（SO_PEERCRED）校验通道身份")

    # ⑤ daemon 侧接线：埋点只在开关打开时调用，启动在 daemonize 之后
    if daemon.count("fw_events_note_write_done(") < 4:
        errs.append("fuse_daemon.c 的事件埋点少于 4 处（create/mkdir/write/release/rename）")
    if daemon.count("fw_events_active()") < 4:
        errs.append("每个埋点都必须先过 fw_events_active()（关闭时零开销）")
    if "fw_events_note_write_denied(" not in daemon:
        errs.append("fuse_daemon.c 缺 write_denied 埋点（fw_route 拒绝路径）")
    d_daemonize = daemon.find("fuse_daemonize(fopts.foreground)")
    d_start = daemon.find("fw_events_start()")
    if d_start < 0 or d_start < d_daemonize:
        errs.append("fw_events_start() 必须在 fuse_daemonize 之后（fork 不保留线程）")
    d_stop = daemon.rfind("fw_events_stop()")
    d_shutdown = daemon.rfind("module_system_shutdown();")
    if d_stop < 0 or (0 <= d_shutdown < d_stop):
        errs.append("fw_events_stop() 必须在 module_system_shutdown() 之前")
    if daemon.count("fw_acl_check(") != 1:
        errs.append("fuse_daemon.c 里 fw_acl_check( 必须仍只有 1 处（唯一执行点）")

    # ⑥ 编入与开关落位
    if "src/daemon/fw_events.c" not in meson:
        errs.append("meson.build 未把 src/daemon/fw_events.c 编入 fuse_daemon_sources")
    cfg_h = _read(os.path.join(ROOT, "include", "config_parser.h"))
    cfg_c = _read(os.path.join(ROOT, "src", "config", "config_parser.c"))
    if "bool fuse_events;" not in cfg_h or "fuse_events_uids[8]" not in cfg_h:
        errs.append("AppConfig 缺 fuse_events / fuse_events_uids 字段")
    if '"FUSE_EVENTS"' not in cfg_c or '"FUSE_EVENTS_UIDS"' not in cfg_c:
        errs.append("config_parser.c 未分派 FUSE_EVENTS / FUSE_EVENTS_UIDS")

    # ⑦ 白名单里的 MediaProvider uid 必须**解析**得来（包名不可由请求方声明，
    #    uid 也不许写死：同一 ROM 版本不同设备/多用户下 uid 会变）
    pkg_c = _read(os.path.join(ROOT, "src", "daemon", "fw_pkg.c"))
    if "fw_pkg_uid_for_package(" not in ev:
        errs.append("fw_events.c 未调用 fw_pkg_uid_for_package（MediaProvider 的 uid "
                    "必须按包名从 packages.list 解析，不能写死在默认表里）")
    # 默认三项之外不许再出现写死的 uid（MediaProvider 的 uid 随 ROM/多用户变）
    hard = set(re.findall(r"fw_allow_add\((\d+)\)", ev)) - {"0", "1000", "1023"}
    if hard:
        errs.append(f"fw_events.c 白名单里出现硬编码 uid {sorted(hard)} —— 其余 uid 只能由 "
                    "fw_pkg_uid_for_package 从 packages.list 解析得到")
    if "bool fw_pkg_uid_for_package(" not in pkg_c:
        errs.append("fw_pkg.c 缺 fw_pkg_uid_for_package 实现（pkg→uid 唯一出处）")

    # ⑧ 事件线程不得空转：合并槽只能被 maintain 清，且无订阅者时超时必须非 0
    #    （现场形态：最后一个订阅者失联后遗留槽的 deadline 永远是过去时，
    #    超时恒 0 → poll(…,0) 立即返回 → 事件线程单核 100%，请求全堵）
    if "static void fw_events_maintain(void)" not in ev:
        errs.append("fw_events.c 缺 fw_events_maintain（合并槽清理/环排空必须收敛到单一入口）")
    if ev.count("fw_coalesce_flush_due();") != 1:
        errs.append(f"fw_coalesce_flush_due() 被调用 {ev.count('fw_coalesce_flush_due();')} 次，"
                    "期望 1 次（只在 fw_events_maintain 内，无条件执行）")
    maintain = ev.split("static void fw_events_maintain(void) {", 1)
    if len(maintain) == 2:
        body = maintain[1].split("\n}\n", 1)[0]
        if "fw_coalesce_flush_due();" not in body:
            errs.append("合并槽清理不在 fw_events_maintain 内——放回 g_sub_count>0 分支会让"
                        "无订阅者时遗留槽永不清、事件线程空转")
    if not re.search(r"if \(g_sub_count == 0\)\s*\n?\s*return FW_EVENTS_POLL_MAX_MS;", ev):
        errs.append("fw_coalesce_timeout() 缺 g_sub_count == 0 守卫（无订阅者时按槽到期返回 0 会空转）")
    if "static int fw_poll_timeout_ms(void)" not in ev:
        errs.append("fw_events.c 缺 fw_poll_timeout_ms（合并槽到期与心跳取小、封顶 POLL_MAX_MS）")
    if "poll(pfd, 2, fw_poll_timeout_ms())" not in ev:
        errs.append("事件线程的 poll 超时必须走 fw_poll_timeout_ms()")
    if "fw_events_maintain();" not in ev:
        errs.append("事件线程每轮必须调用 fw_events_maintain()")
    return errs


def main():
    for path in (DRIVER, SOURCE, HEADER, UTIL):
        if not os.path.exists(path):
            print(f"缺少源文件 {path}", file=sys.stderr)
            return 1

    errs = static_contract()
    if errs:
        for e in errs:
            print("❌ " + e, file=sys.stderr)
        return 1
    print("静态契约：判决单点 / 零分配热路径 / 开关在前 / 埋点接线 ✔")

    with tempfile.TemporaryDirectory(prefix="fwev_build_") as tmpdir:
        exe = os.path.join(tmpdir, "fw_events_driver")
        cmd = [
            *shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Wno-unused-parameter", "-Wno-unused-function",
            "-I", os.path.join(ROOT, "include"),
            "-I", os.path.join(ROOT, "src", "core"),
            "-I", os.path.join(ROOT, "src", "config"),
            "-I", os.path.join(ROOT, "src", "daemon"),
            DRIVER, UTIL, "-o", exe,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("C 编译/链接失败:", file=sys.stderr)
            print(r.stderr, file=sys.stderr)
            return 1
        if r.stderr.strip():
            print(r.stderr, file=sys.stderr, end="")
        try:
            run = subprocess.run([exe], capture_output=True, text=True, timeout=RUN_TIMEOUT)
        except subprocess.TimeoutExpired:
            print(f"fw_events 驱动超时（>{RUN_TIMEOUT}s）", file=sys.stderr)
            return 1

    out = run.stdout + run.stderr
    print(out, end="")
    if run.returncode != 0 or "❌" in out:
        print("FUSE 事件通道测试失败", file=sys.stderr)
        return 1
    print("FUSE 事件通道测试通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
