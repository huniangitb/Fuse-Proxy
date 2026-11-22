#!/usr/bin/env python3
"""L0: 配置读槽 × 慢能力查询（槽内外部命令放大为整池停顿）。

真实 fw_rules.c / fw_pkg.c / config_parser.c 直编成驱动（同 test_rules.py 跨应用
隔离段配方），能力查询用生产测试钩子替换成可计时睡眠。断言：
  1) publish 协议（begin→drain→end）在慢查询进行中不被拖住（<20ms）；
  2) 迟到读者不被冻住（<20ms）；
  3) 裁决语义不变，且预取只为 /Android/data|obb 且无豁免的 uid 付查询。

CFGSLOT_SRC_DIR 可指向老实现（需含 fw_rules.c 与 fw_pkg.c）做判别。
CFGSLOT_OUTPUT_DIR 保留编译/运行证据（否则私有临时目录）。
"""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "tests/fixtures/cfg_slot_isolation.c"
SOURCES = ["src/daemon/fw_rules.c", "src/daemon/fw_pkg.c", "src/config/config_parser.c",
           "src/config/path_vars.c", "src/core/path_trie.c", "src/core/nsp_util.c",
           "src/core/nsp_comm.c", "src/core/common.c", "src/core/sys_pkg.c",
           "src/core/uid_map.c", "src/core/fast_pid.c", "src/injector/config_publisher.c"]
OVERRIDABLE = {"src/daemon/fw_rules.c", "src/daemon/fw_pkg.c"}
LIMIT_US = 20000  # 20ms：一次外部命令查询量级是 40ms+，槽外后发布者不该等它
BASE = "[GLOBAL]\nMONITOR OFF\n"
WHITELIST = BASE + "ALLOW_CROSS_APP_PKGS com.demo.app\n"
GATE_OFF = BASE + "ALLOW_CROSS_APP_BY_CAPABILITY OFF\n"
ISOLATE_OFF = BASE + "ALLOW_CROSS_APP_DATA ON\n"
UID_MAP = "10123 com.demo.app\n10150 com.doc.ui\n"
PACKAGE_LIST = ("com.demo.app 10123 0 /data/user/0/com.demo.app default:targetSdkVersion=34\n"
                # 与 com.demo.app 共用 uid（sharedUserId 兄弟包）：判定必须按 uid 当同一
                # 应用放行，而这只有真查过清单才知道——冷缓存不能冒充「无此包」。
                "com.sibling.app 10123 0 /data/user/0/com.sibling.app default:targetSdkVersion=34\n"
                "com.doc.ui 10150 0 /data/user/0/com.doc.ui platform:privapp:targetSdkVersion=34\n")
OTHER = "/0/Android/data/com.other.app/files/x"
OTHER_OBB = "/0/Android/obb/com.other.app/pack.bin"
OWN = "/0/Android/data/com.demo.app/files/x"
PLAIN = "/0/DCIM/camera/a.txt"


def prepare(directory):
    sandbox = directory / "iso"
    shutil.rmtree(sandbox, ignore_errors=True)
    cfg = sandbox / "cfg"
    cfg.mkdir(parents=True)
    headers = sandbox / "include"
    shutil.copytree(ROOT / "include", headers)
    pattern = re.compile(r'^#define\s+(?:NSP_CONFIG_DIR|CONFIG_DIR)\s+"/var/fuse-proxy"\s*$', re.M)
    hits = 0
    for path in sorted(headers.glob("*.h")):
        text = path.read_text(encoding="utf-8")
        new, count = pattern.subn(lambda m: m.group(0).replace('"/var/fuse-proxy"', '"%s"' % cfg), text)
        if count:
            path.write_text(new, encoding="utf-8")
            hits += count
    if not hits:
        return None, None, None, "未定位 GNU 配置根常量"
    (cfg / "uid.map").write_text(UID_MAP, encoding="utf-8")
    plist = sandbox / "packages.list"
    plist.write_text(PACKAGE_LIST, encoding="utf-8")
    return cfg, headers, plist, None


def build(directory, cfg, headers):
    cc = shlex.split(os.environ.get("CC", "cc"))
    if not cc or not shutil.which(cc[0]):
        return None, "C 编译器不可用"
    older = os.environ.get("CFGSLOT_SRC_DIR")
    files = []
    for rel in SOURCES:
        if older and rel in OVERRIDABLE:
            files.append(str(Path(older).resolve() / Path(rel).name))
        else:
            files.append(str(ROOT / rel))
    pkgconfig = subprocess.run(["pkg-config", "--cflags", "--libs", "json-c"],
                               capture_output=True, text=True)
    if pkgconfig.returncode != 0:
        return None, "缺少 json-c"
    binary = directory / "cfg_slot_isolation"
    # --wrap=fopen：观测「打开 packages.list 时本线程是否持配置读槽」（见 check_publish_pkgs）
    command = cc + [
        "-std=c23", "-DTARGET_GNU=1", "-D_GNU_SOURCE", "-Wall", "-Wno-unused-parameter",
        "-I" + str(headers), "-I" + str(ROOT / "include"), "-I" + str(ROOT / "src/daemon"),
        str(DRIVER),
    ] + files + [
        "-o", str(binary), "-pthread", "-ldl", "-lm", "-Wl,--wrap=fopen", "-Wl,--wrap=fgets",
    ] + pkgconfig.stdout.split()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
    (directory / "compile.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        return None, "编译失败：" + (result.stdout + result.stderr).strip()[-400:]
    return binary, None


def run_driver(binary, args, env_extra, timeout=30):
    env = dict(os.environ)
    env.update(env_extra)
    try:
        result = subprocess.run([str(binary)] + args, cwd=ROOT, capture_output=True,
                                text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None, f"驱动超时 {timeout}s：{' '.join(args)}"
    if result.returncode != 0:
        return None, f"驱动退出 {result.returncode}：{(result.stdout + result.stderr).strip()[-300:]}"
    return result.stdout.strip(), None


def parse_kv(line):
    fields = {}
    for part in line.split():
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = int(value)
    return fields


def check_publish(binary, conf_path, plist, slow_ms, path=None):
    args = ["publish", str(conf_path), str(slow_ms)] + ([path] if path else [])
    out, error = run_driver(binary, args, {"NSP_PACKAGELIST": str(plist)})
    if error:
        return [("publish 运行", False, error)]
    fields = parse_kv(out)
    checks = [
        ("publish 期间 drain 未被慢查询拖住",
         fields["drain_us"] < LIMIT_US,
         f"drain_us={fields['drain_us']} 阈值<{LIMIT_US} (慢查询 {slow_ms}ms)"),
        ("迟到读者未被冻住",
         fields["late_reader_us"] < LIMIT_US,
         f"late_reader_us={fields['late_reader_us']} 阈值<{LIMIT_US}"),
        ("整段发布耗时不含量级放大",
         fields["publish_us"] < LIMIT_US,
         f"publish_us={fields['publish_us']} 阈值<{LIMIT_US}"),
        ("慢查询仍发生一次（能力事实真被查了）", fields["queries"] == 1,
         f"queries={fields['queries']}"),
        ("他包 data 仍被隔离", fields["blocked"] == 1 and fields["probed"] == 1,
         f"blocked={fields['blocked']} probed={fields['probed']}"),
    ]
    return checks


# 发布起始偏移要覆盖到「请求已在读槽里做文件 IO」的那一段：旧实现在 800–1300ms
# 被拖住（drain 455ms），更早的偏移它还没进槽、更晚已出槽，都看不出来。
PKG_DELAYS = (0, 200, 400, 600, 800, 900, 1000, 1100, 1200, 1300)


def check_publish_pkgs(binary, conf_path, plist, fifo, slow_ms):
    """packages.list 的**真**慢读：override 是 FIFO，读方 open 阻塞到写方睡完
    slow_ms 才拿到清单。身份解析（/proc + packages.list）与隔离要的属主 uid、
    特权档都来自这份文件——它们留在读槽里就等于把发布者按慢读时长钉住。
    发布器起始时刻按 PKG_DELAYS 扫描：请求先在槽外预取、再进读槽，只有撞上
    「正持读槽做文件 IO」那一段，旧实现才会把 drain 拖到慢读量级。判别信号
    两路：--wrap=fopen 统计「打开时本线程持配置读槽」的次数（旧 >0），且每个
    偏移下 drain 与迟到读者都要留在 LIMIT_US 内（旧在命中窗口时超限）。"""
    checks = []
    for delay in PKG_DELAYS:
        out, error = run_driver(
            binary, ["publish-pkgs", str(conf_path), str(slow_ms)],
            {"NSP_PACKAGELIST": str(plist), "NSP_PKGLIST_FIFO": str(fifo),
             "NSP_PUBLISH_DELAY_MS": str(delay)},
            timeout=90)
        label = f"packages.list 慢读[{delay}ms 偏移]"
        if error:
            checks.append((label, False, error))
            continue
        fields = parse_kv(out)
        checks += [
            (label + " 不拖住发布 drain",
             fields["drain_us"] < LIMIT_US,
             f"drain_us={fields['drain_us']} 阈值<{LIMIT_US} (慢读 {slow_ms}ms)"),
            (label + " 不冻住迟到读者",
             fields["late_reader_us"] < LIMIT_US,
             f"late_reader_us={fields['late_reader_us']} 阈值<{LIMIT_US}"),
            (label + " 槽内一次都没打开 packages.list",
             fields["pkgl_in_slot"] == 0,
             f"pkgl_in_slot={fields['pkgl_in_slot']}（持读槽时打开清单 = 把慢读"
             f"留在槽内；pkgl_slow_in_slot={fields['pkgl_slow_in_slot']}）"),
        ]
        if delay == 0:
            checks += [
                ("packages.list 真被读过（事实查询没被删掉）",
                 fields["pkgl_opens"] >= 1,
                 f"pkgl_opens={fields['pkgl_opens']}"),
                ("慢读确实发生",
                 fields["resolve_us"] >= slow_ms * 800,
                 f"resolve_us={fields['resolve_us']} 期望>={slow_ms * 800}"),
                ("他包 data 仍被隔离",
                 fields["blocked"] == 1 and fields["probed"] == 1,
                 f"blocked={fields['blocked']} probed={fields['probed']}"),
            ]
    return checks


# probe 冷路径同样要覆盖「发布撞上读槽内文件 IO」那一段：probe-pkgs 先 probe，
# 此时 uid→包名缓存全冷，身份解析只能由 probe 自己做。
PKG_PROBE_DELAYS = (0, 300, 500, 600, 700, 800)


def check_probe_pkgs(binary, conf_path, plist, fifo, slow_ms):
    """fw_rules_probe 的冷路径（readdir 条目级）：旧实现在读槽里解析身份，
    packages.list 慢读就把发布者连同后续读者一起钉住；新实现槽前解析。"""
    checks = []
    for delay in PKG_PROBE_DELAYS:
        out, error = run_driver(
            binary, ["probe-pkgs", str(conf_path), str(slow_ms)],
            {"NSP_PACKAGELIST": str(plist), "NSP_PKGLIST_FIFO": str(fifo),
             "NSP_PUBLISH_DELAY_MS": str(delay)},
            timeout=90)
        label = f"probe 冷路径[{delay}ms 偏移]"
        if error:
            checks.append((label, False, error))
            continue
        fields = parse_kv(out)
        checks += [
            (label + " 不拖住发布 drain",
             fields["drain_us"] < LIMIT_US,
             f"drain_us={fields['drain_us']} 阈值<{LIMIT_US} (慢读 {slow_ms}ms)"),
            (label + " 不冻住迟到读者",
             fields["late_reader_us"] < LIMIT_US,
             f"late_reader_us={fields['late_reader_us']} 阈值<{LIMIT_US}"),
            (label + " 槽内一次都没打开 packages.list",
             fields["pkgl_in_slot"] == 0,
             f"pkgl_in_slot={fields['pkgl_in_slot']}（持读槽时打开清单 = 把慢读"
             f"留在槽内；pkgl_slow_in_slot={fields['pkgl_slow_in_slot']}）"),
        ]
        if delay == PKG_PROBE_DELAYS[0]:
            checks += [
                ("probe 真读了 packages.list（身份查询没被删掉）",
                 fields["pkgl_opens"] >= 1,
                 f"pkgl_opens={fields['pkgl_opens']}"),
                ("probe 冷路径慢读确实发生",
                 fields["probe_us"] >= slow_ms * 800,
                 f"probe_us={fields['probe_us']} 期望>={slow_ms * 800}"),
                ("probe 仍判他包 data 隔离", fields["probed"] == 1,
                 f"probed={fields['probed']}"),
            ]
    return checks

# 清单永远读空：身份解析拿不到结论，事实永远是「不知道」。这是负结论缓存的
# 判别窗口——不缓存负结论的实现会在槽内反复重读这份慢清单。
PKG_EMPTY_DELAYS = (0, 600, 1200)


def check_publish_empty(binary, conf_path, plist, fifo, slow_ms):
    """packages.list 慢读且**永远读空**：真实现里 known 恒为假。没有负结论缓存
    就会在配置读槽内反复重读这份慢清单，把发布者按慢读时长钉住；有了负结论
    TTL + 槽内零 IO 规则，重读次数被收敛在槽外。断言四件事：drain/迟到读者快、
    槽内一次都没打开清单、慢读确实发生在槽外、重读次数有界（不是放弃事实），
    并且裁决与既有实现一致（读不到清单也不漏判隔离）。"""
    checks = []
    for delay in PKG_EMPTY_DELAYS:
        out, error = run_driver(
            binary, ["publish-pkgs", str(conf_path), str(slow_ms)],
            {"NSP_PACKAGELIST": str(plist), "NSP_PKGLIST_FIFO": str(fifo),
             "NSP_PKGL_EMPTY": "1", "NSP_PUBLISH_DELAY_MS": str(delay)},
            timeout=90)
        label = f"清单恒空[{delay}ms 偏移]"
        if error:
            checks.append((label, False, error))
            continue
        fields = parse_kv(out)
        checks += [
            (label + " 不拖住发布 drain",
             fields["drain_us"] < LIMIT_US,
             f"drain_us={fields['drain_us']} 阈值<{LIMIT_US} (慢读 {slow_ms}ms)"),
            (label + " 不冻住迟到读者",
             fields["late_reader_us"] < LIMIT_US,
             f"late_reader_us={fields['late_reader_us']} 阈值<{LIMIT_US}"),
            (label + " 槽内一次都没打开 packages.list",
             fields["pkgl_in_slot"] == 0,
             f"pkgl_in_slot={fields['pkgl_in_slot']}（负结论没被复用 → 槽内重读）"),
            (label + " 慢读确实发生在槽外",
             fields["resolve_us"] >= slow_ms * 800,
             f"resolve_us={fields['resolve_us']} 期望>={slow_ms * 800}"),
            (label + " 槽外重读次数有界",
             fields["pkgl_opens"] <= 12,
             f"pkgl_opens={fields['pkgl_opens']} 阈值<=12（不收敛会一直重读）"),
            (label + " 读不到清单也不漏判隔离",
             fields["blocked"] == 1 and fields["probed"] == 1,
             f"blocked={fields['blocked']} probed={fields['probed']}"),
        ]
    return checks


# 代际抖动：uid.map 变化在生产里就调 fw_pkg_reload()，它把整代 fw_pkg 事实缓存
# 一并作废（即便 packages.list 没变）。预热因此反复失效，旧实现预热 8 次后退回
# 「槽内阻塞查询」——把慢读挂回配置读槽。断言槽内打开清单的次数为 0。
CHURN_ITERS = 6


def check_churn(binary, conf_path, plist, fifo, label="代际抖动", uid=None,
               delay_ms=3, extra_line=None, expect_blocked=True):
    """真慢清单 + 每 1ms 一次 fw_pkg_reload() 的代际抖动 + 两个请求线程。旧实现
    在升级路径上把 packages.list 的阻塞读放回读槽（实测 40 次判定里 158 次槽内
    打开、单次 resolve 217ms）；新实现槽外取全事实，槽内零 IO，裁决不变。

    `uid` 换调用方身份：隔离判定**先**问「是不是他包路径」（要目标属主那条事实）
    **再**问特权档，所以特权调用方也会走升级路径——槽外取全时若只在非特权分支收
    集属主事实，槽内仍会未命中并退回阻塞读，这条断言就是那个缺口的判别器。
    `extra_line` 往清单补一行（例如给调用方一个平台签名档）。"""
    env = {"NSP_PACKAGELIST": str(plist), "NSP_PKGLIST_FIFO": str(fifo),
           "NSP_CHURN_PKGL_DELAY_MS": str(delay_ms)}
    if uid is not None:
        env["NSP_CHURN_UID"] = str(uid)
    if extra_line:
        env["NSP_PKGLIST_EXTRA"] = extra_line
    out, error = run_driver(
        binary, ["churn", str(conf_path), str(CHURN_ITERS), OTHER, OTHER_OBB],
        env, timeout=300)  # sanitizer 下 2 线程 × 6 轮 + 20ms 慢读会被放大，给足时限
    if error:
        return [(label, False, error)]
    f = parse_kv(out)
    expected = 2 * CHURN_ITERS * 2
    checks = [
        (label + " 所有判定都跑完（没有活锁）", f["resolves"] == expected,
         f"resolves={f['resolves']} 期望={expected}"),
        (label + " 事实真被查过（没把查询删掉了事）", f["pkgl_opens"] >= 1,
         f"pkgl_opens={f['pkgl_opens']}"),
        (label + " 槽内一次都没打开 packages.list",
         f["pkgl_in_slot"] == 0,
         f"pkgl_in_slot={f['pkgl_in_slot']}（预热反复失效后旧实现把阻塞读放回读槽；"
         f"pkgl_opens={f['pkgl_opens']} pkgl_slow_in_slot={f['pkgl_slow_in_slot']}）"),
        # 槽内只可能因为 allow_io 兜底才开文件；这里连同「慢读」一起钉住，
        # 免得将来兜底被触发时只靠 pkgl_in_slot 一个信号（快读也可能 0 次）。
        (label + " 槽内没有慢读", f["pkgl_slow_in_slot"] == 0,
         f"pkgl_slow_in_slot={f['pkgl_slow_in_slot']}"),
    ]
    if expect_blocked is None:
        # 每 1ms 一次 reload 时 `fw_pkg_is_privileged` 的代际守卫会把「读盘期间代际
        # 变了」答成未知（旧实现同样如此），特权档因此时真时假——裁决属于既有语义，
        # 本变体只钉「槽内零 IO」。
        pass
    elif expect_blocked:
        checks.append((label + " 他包 data/obb 仍被隔离", f["blocked"] == f["resolves"],
                       f"blocked={f['blocked']} resolves={f['resolves']}"))
    else:
        checks.append((label + " 特权调用方仍全部放行（裁决不变）", f["blocked"] == 0,
                       f"blocked={f['blocked']} resolves={f['resolves']}"))
    checks.append((label + " 单次判定耗时没有失控", f["max_resolve_us"] < 2000000,
                   f"max_resolve_us={f['max_resolve_us']} 阈值<2000000"))
    return checks


def check_uidcache(binary, conf_path, plist):
    """新只读入口 `fw_pkg_uid_cached` 的契约：冷缓存返回 false（事实还没备好），
    已查过的正/负结论返回 true。把它写成「冷缓存 = 无此包」会让**同 uid 兄弟包**
    被判成他应用（隔离/ENOENT），而 HEAD 是放行——这类漂移只有真查过清单才看得见。"""
    out, error = run_driver(binary, ["uidcache", str(conf_path)],
                            {"NSP_PACKAGELIST": str(plist)})
    if error:
        return [("uid.map 包名缓存契约", False, error)]
    f = parse_kv(out)
    return [
        ("冷缓存不是「无此包」（必须返回 false 让调用方出槽预热）",
         f["cold_false"] == 1, f"cold_false={f['cold_false']}"),
        ("查过的正结论可在槽内命中（含 uid）",
         f["warm_true"] == 1 and f["warm_src"] == 1,
         f"warm_true={f['warm_true']} warm_src={f['warm_src']}"),
        ("未收录包名的冷缓存同样返回 false",
         f["absent_cold"] == 1 and f["absent_src"] == 0,
         f"absent_cold={f['absent_cold']} absent_src={f['absent_src']}"),
        ("查过的负结论可在槽内命中",
         f["absent_neg"] == 1, f"absent_neg={f['absent_neg']}"),
        ("空包名/空指针不命中", f["bad_args"] == 1, f"bad_args={f['bad_args']}"),
    ]


def check_matrix(binary, directory, cfg, plist, name, conf, uid, paths, expect):
    conf_path = cfg / "injector.conf"
    conf_path.write_text(conf, encoding="utf-8")
    out, error = run_driver(binary, ["matrix", str(conf_path)] + paths,
                            {"NSP_PACKAGELIST": str(plist), "NSP_ISO_UID": str(uid)})
    label = f"matrix[{name}]"
    if error:
        return [(label, False, error)]
    (directory / (re.sub(r"[^a-z0-9]+", "-", name.lower()) + ".log")).write_text(out + "\n")
    rows = {}
    for line in out.splitlines():
        parts = line.split()
        rows[parts[0]] = parse_kv(line)
    checks = []
    for path, want in expect.items():
        row = rows.get(path)
        if row is None:
            checks.append((f"{label} {path}", False, "驱动未输出该路径"))
            continue
        actual = {key: row[key] for key in want}
        checks.append((f"{label} {path}", actual == want, f"期望 {want} 实测 {actual}"))
    return checks


def run(directory):
    cfg, headers, plist, error = prepare(directory)
    if error:
        print("SKIP: " + error)
        return 77
    binary, error = build(directory, cfg, headers)
    if error:
        print("FAIL: " + error)
        return 1
    checks = []
    base_conf = cfg / "base.conf"
    base_conf.write_text(BASE, encoding="utf-8")
    checks += check_publish(binary, base_conf, plist, 300)
    # P2-A：判定用的是 br_strip_and_sanitize 清理后的 sub_path，而 path_sanitize 会删
    # 字节——原始写法里 0x01 删掉后才凑出 /Android/data/ 前缀。若预取直接扫原始路径，
    # 这条请求的慢查询会留在槽内（旧实现实测 drain 260ms）。
    checks += check_publish(binary, base_conf, plist, 300, "/0/Android/\x01data/com.other.app/files/x")
    # packages.list 真慢读：FIFO + --wrap=fopen 观测「持读槽时打开」。身份解析与
    # 隔离要的属主 uid/特权档都读这份文件；旧实现把读放在槽内 → 发布者被钉住。
    fifo = directory / "packages.list.fifo"
    if fifo.exists():
        fifo.unlink()
    os.mkfifo(fifo)
    checks += check_publish_pkgs(binary, base_conf, plist, fifo, 250)
    checks += check_probe_pkgs(binary, base_conf, plist, fifo, 250)
    # 负结论窗口：清单恒空时，事实永远是「不知道」。这是第六批验收漏出的残余
    # 路径（预取读到空 → known 假不缓存 → 槽内重读慢清单）。
    checks += check_publish_empty(binary, base_conf, plist, fifo, 250)
    # 代际抖动 × 预热失效：旧实现的升级路径把慢读放回读槽（第十三批修的第一个
    # 「在槽内做 IO」出口）。断言槽内零打开，且裁决不变。
    checks += check_churn(binary, base_conf, plist, fifo)
    # 特权调用方：判定先问属主事实、再问特权档，属主事实漏了就同样退回槽内阻塞读
    checks += check_churn(binary, base_conf, plist, fifo, label="代际抖动（特权调用方）",
                          uid=10150, delay_ms=20,
                          extra_line="com.priv.app 10150 0 /data/user/0/com.priv.app "
                                     "platform:privapp:targetSdkVersion=34\n",
                          expect_blocked=None)
    checks += check_uidcache(binary, base_conf, plist)
    # 语义矩阵（一次进程走多路径；只断言裁决，不看累计查询次数）
    checks += check_matrix(binary, directory, cfg, plist, "默认隔离", BASE, 10123,
                           [OTHER, OTHER_OBB, OWN, PLAIN], {
                               OTHER: {"resolve": 1, "probe": 1},
                               OTHER_OBB: {"resolve": 1, "probe": 1},
                               OWN: {"resolve": 0, "probe": 0},
                               PLAIN: {"resolve": 0, "probe": 0},
                           })
    # 查询次数：每条路径单独一个进程（q0 恒 0；q1 首次 resolve 后，q2 probe 后，q3 二次 resolve 后）
    once = {"q0": 0, "q1": 1, "q2": 1, "q3": 1}
    never = {"q0": 0, "q1": 0, "q2": 0, "q3": 0}
    checks += check_matrix(binary, directory, cfg, plist, "他包data查一次", BASE, 10123,
                           [OTHER], {OTHER: dict(once, resolve=1, probe=1)})
    checks += check_matrix(binary, directory, cfg, plist, "他包obb复用同一次", BASE, 10123,
                           [OTHER_OBB], {OTHER_OBB: dict(once, resolve=1, probe=1)})
    checks += check_matrix(binary, directory, cfg, plist, "自身data不查询", BASE, 10123,
                           [OWN], {OWN: dict(never, resolve=0, probe=0)})
    checks += check_matrix(binary, directory, cfg, plist, "自身obb不查询", BASE, 10123,
                           ["/0/Android/obb/com.demo.app/pack.bin"],
                           {"/0/Android/obb/com.demo.app/pack.bin": dict(never, resolve=0, probe=0)})

    # 同 uid 兄弟包（sharedUserId）：判定按 uid 当同一应用放行。这条同时是
    # 「冷缓存不能冒充无此包」的端到端判别——HEAD 放行，伪造负结论会判隔离。
    sibling = "/0/Android/data/com.sibling.app/files/x"
    checks += check_matrix(binary, directory, cfg, plist, "同uid兄弟包按同一应用", BASE, 10123,
                           [sibling], {sibling: {"resolve": 0, "probe": 0}})
    checks += check_matrix(binary, directory, cfg, plist, "普通路径不查询", BASE, 10123,
                           [PLAIN], {PLAIN: dict(never, resolve=0, probe=0)})
    checks += check_matrix(binary, directory, cfg, plist, "特权豁免不查询", BASE, 10150,
                           [OTHER], {OTHER: dict(never, resolve=0, probe=0)})
    # 白名单只能按调用方包名判（解析 uid→包名要 IO），预取拿不到；故白名单应用会多付
    # 一次缓存查询（30s 内一次），用一次查询换掉「慢查询落槽」的全池放大。裁决不变。
    checks += check_matrix(binary, directory, cfg, plist, "白名单裁决不变", WHITELIST, 10123,
                           [OTHER], {OTHER: dict(once, resolve=0, probe=0)})
    # P2-B：两个总闸关掉时判定根本不问能力（关能力总闸仍按默认边界隔离；关隔离直接放行），
    # 预取若还照常 fork 就是纯浪费——断言查询次数为 0。
    checks += check_matrix(binary, directory, cfg, plist, "能力总闸关闭不预取", GATE_OFF, 10123,
                           [OTHER], {OTHER: dict(never, resolve=1, probe=1)})
    checks += check_matrix(binary, directory, cfg, plist, "隔离总闸关闭不预取", ISOLATE_OFF, 10123,
                           [OTHER], {OTHER: dict(never, resolve=0, probe=0)})
    # 只有真正的前缀形状才算他包（判定用 strncmp 认前缀）：路径中段出现 Android/data
    # 不是跨应用形状，预取也不该在这里付查询。
    MID = "/0/DCIM/Android/data/com.other.app/x"
    checks += check_matrix(binary, directory, cfg, plist, "中段非前缀不预取", BASE, 10123,
                           [MID], {MID: dict(never, resolve=0, probe=0)})
    # .nomedia 是标记名而不是包名：判定直接当"不是他包"放行，预取同样不付查询。
    NOMEDIA = "/0/Android/data/.nomedia/x"
    checks += check_matrix(binary, directory, cfg, plist, "nomedia标记不预取", BASE, 10123,
                           [NOMEDIA], {NOMEDIA: dict(never, resolve=0, probe=0)})
    failed = 0
    lines = []
    for name, good, detail in checks:
        lines.append(("PASS " if good else "FAIL ") + name + ("  —  " + detail if not good else ""))
        failed += not good
    report = "\n".join(lines)
    (directory / "checks.log").write_text(report + "\n")
    print(report)
    print(f"cfg_slot_isolation: {len(checks) - failed}/{len(checks)} PASS")
    return 1 if failed else 0


def main():
    retained = os.environ.get("CFGSLOT_OUTPUT_DIR")
    if retained:
        directory = Path(retained).resolve()
        directory.mkdir(parents=True, exist_ok=True)
        return run(directory)
    with tempfile.TemporaryDirectory(prefix="nsp-cfg-slot-") as private:
        return run(Path(private))


if __name__ == "__main__":
    sys.exit(main())
