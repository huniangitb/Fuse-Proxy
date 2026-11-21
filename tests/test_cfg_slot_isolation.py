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
    command = cc + ["-std=c23", "-DTARGET_GNU=1", "-D_GNU_SOURCE", "-Wall",
                    "-Wno-unused-parameter", "-I" + str(headers), "-I" + str(ROOT / "include"),
                    "-I" + str(ROOT / "src/daemon"), str(DRIVER)] + files + [
                    "-o", str(binary), "-pthread", "-ldl", "-lm"] + pkgconfig.stdout.split()
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
