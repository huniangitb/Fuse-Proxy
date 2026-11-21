#!/usr/bin/env python3
"""L0: 跨应用白名单数组的槽外借用 × 配置发布释放。

真实 fw_acl.c / fw_rules.c / fw_pkg.c / config_parser.c 直编成驱动（同 test_rules.py
跨应用隔离段配方）。断言：
  1) 两处生产调用者（ACL 身份组装、readdir 跨应用判据）都不在已释放的旧条目上比较；
  2) 发布被持槽读者挡住（说明白名单读确实在槽内）；
  4) 已持读槽的线程再调快照入口不会与发布者的排空互等（nested 窗口 <1s 返回）；
  5) 重载后判"未放行"，再重载加回后判"放行"——读的是当前配置而不是缓存副本。

ACL_WHITELIST_SRC_DIR 可指向老实现（需含 fw_acl.c、fw_rules.c、fw_pkg.c）做判别，
ACL_WHITELIST_VARIANT=old 另外用编译期宏把第二个窗口切回槽外旧入口。
ACL_WHITELIST_OUTPUT_DIR 保留编译/运行证据（否则私有临时目录）。
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
DRIVER = ROOT / "tests/fixtures/acl_whitelist_lifetime.c"
SOURCES = ["src/daemon/fw_acl.c", "src/daemon/fw_rules.c", "src/daemon/fw_pkg.c",
           "src/config/config_parser.c", "src/config/path_vars.c", "src/core/path_trie.c",
           "src/core/nsp_util.c", "src/core/nsp_comm.c", "src/core/common.c",
           "src/core/sys_pkg.c", "src/core/uid_map.c", "src/core/fast_pid.c",
           "src/injector/config_publisher.c"]
OVERRIDABLE = {"src/daemon/fw_acl.c", "src/daemon/fw_rules.c", "src/daemon/fw_pkg.c"}
BASE = "[GLOBAL]\nMONITOR OFF\n"
UID_MAP = "10123 com.demo.app\n"
PACKAGE_LIST = "com.demo.app 10123 0 /data/user/0/com.demo.app default:targetSdkVersion=34\n"


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
    conf = cfg / "base.conf"
    conf.write_text(BASE, encoding="utf-8")
    return cfg, headers, plist, None


def build(directory, headers):
    cc = shlex.split(os.environ.get("CC", "cc"))
    legacy = os.environ.get("ACL_WHITELIST_VARIANT") == "old"
    if not cc or not shutil.which(cc[0]):
        return None, "C 编译器不可用"
    older = os.environ.get("ACL_WHITELIST_SRC_DIR")
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
    binary = directory / "acl_whitelist_lifetime"
    command = cc + ["-std=c23", "-DTARGET_GNU=1", "-D_GNU_SOURCE", "-Wall",
                    "-Wno-unused-parameter", "-I" + str(headers), "-I" + str(ROOT / "include"),
                    "-I" + str(ROOT / "src/daemon"), str(DRIVER)] + files + [
                    "-DACL_WL_LEGACY_CALL=%d" % (1 if legacy else 0),
                    "-DACL_WL_HAS_SNAPSHOT=%d" % (0 if os.environ.get("ACL_WHITELIST_HAS_SNAPSHOT") == "0" else 1),
                    "-Wl,--wrap=strlen", "-Wl,--wrap=strncmp",
                    "-o", str(binary), "-pthread", "-ldl", "-lm"] + pkgconfig.stdout.split()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
    (directory / "compile.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        return None, "编译失败：" + (result.stdout + result.stderr).strip()[-600:]
    return binary, None


def parse_kv(line):
    fields = {}
    for part in line.split():
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = int(value)
    return fields


def run_nested_mode(directory, binary, conf, env):
    """嵌套窗口：本线程已持读槽时调快照入口 + 并发发布，必须立即返回且发布随后完成。"""
    try:
        result = subprocess.run([str(binary), "nested", str(conf)], cwd=ROOT,
                                capture_output=True, text=True, timeout=30, env=env)
    except subprocess.TimeoutExpired:
        return None, "嵌套窗口超时 30s（持槽时空转/死锁）"
    output = (result.stdout + result.stderr).strip()
    (directory / "nested.log").write_text(output + "\n")
    if result.returncode != 0:
        return None, "嵌套窗口退出 %d：%s" % (result.returncode, output[-300:])
    return parse_kv(output), None


def run(directory):
    cfg, headers, plist, error = prepare(directory)
    if error:
        print("SKIP: " + error)
        return 77
    binary, error = build(directory, headers)
    if error:
        print("FAIL: " + error)
        return 1
    env = dict(os.environ)
    env["NSP_PACKAGELIST"] = str(plist)
    conf = cfg / "base.conf"
    try:
        result = subprocess.run([str(binary), "lifetime", str(conf)], cwd=ROOT,
                                capture_output=True, text=True, timeout=30, env=env)
    except subprocess.TimeoutExpired:
        print("FAIL: 驱动超时 30s")
        return 1
    output = (result.stdout + result.stderr).strip()
    (directory / "run.log").write_text(output + "\n")
    if result.returncode != 0:
        print("FAIL: 驱动退出 %d：%s" % (result.returncode, output[-400:]))
        return 1
    fields = {}
    for line in output.splitlines():
        fields.update(parse_kv(line))
    checks = [
        ("发布前白名单命中判放行", fields.get("before_allowed") == 1,
         "before_allowed=%s" % fields.get("before_allowed")),
        ("ACL 身份读在槽内（发布被挡住）", fields.get("acl_blocked") == 1,
         "acl_blocked=%s（0 = 发布越过读者）" % fields.get("acl_blocked")),
        ("ACL 身份不在已释放条目上比较", fields.get("acl_freed") == 0,
         "在已释放旧条目上比较 %s 次" % fields.get("acl_freed")),
        ("再加回后判放行（读当前配置）", fields.get("again_allowed") == 1,
         "again_allowed=%s" % fields.get("again_allowed")),
        ("readdir 跨应用读在槽内（发布被挡住）", fields.get("access_blocked") == 1,
         "access_blocked=%s（0 = 发布越过读者）" % fields.get("access_blocked")),
        ("readdir 跨应用不在已释放条目上比较", fields.get("access_freed") == 0,
         "在已释放旧条目上比较 %s 次" % fields.get("access_freed")),
    ]
    if not os.environ.get("ACL_WHITELIST_SRC_DIR"):
        daemon = (ROOT / "src/daemon/fuse_daemon.c").read_text(encoding="utf-8")
        bare = re.search(r"fw_rules_cross_app_access\((?!\))", daemon)
        # 槽外调用者必须用 _snapshot：裸调会让发布者在重载时释放掉正在比较的白名单数组。
        checks.append(("fuse_daemon 只用槽内快照入口", bare is None and
                       "fw_rules_cross_app_access_snapshot(" in daemon,
                       "fuse_daemon.c 仍裸调 fw_rules_cross_app_access" if bare else "缺少快照入口"))
    if os.environ.get("ACL_WHITELIST_HAS_SNAPSHOT") != "0":
        nested_fields, nested_error = run_nested_mode(directory, binary, conf, env)
        if nested_error:
            checks.append(("已持读槽时快照入口不自旋", False, nested_error))
            checks.append(("嵌套读裁决为当前配置", False, "嵌套窗口未产出"))
            checks.append(("嵌套读后发布完成", False, "嵌套窗口未产出"))
        else:
            nested_us = nested_fields.get("nested_us", -1)
            checks.append(("已持读槽时快照入口不自旋", 0 <= nested_us < 1000000,
                           "nested_us=%s（>1s 说明内层取槽在与排空互等）" % nested_us))
            checks.append(("嵌套读裁决为当前配置", nested_fields.get("nested_verdict") == 1,
                           "nested_verdict=%s" % nested_fields.get("nested_verdict")))
            checks.append(("嵌套读后发布完成", nested_fields.get("nested_swapped") == 1,
                           "nested_swapped=%s" % nested_fields.get("nested_swapped")))
    failed = 0
    lines = []
    for name, good, detail in checks:
        lines.append(("PASS " if good else "FAIL ") + name + ("  —  " + detail if not good else ""))
        failed += not good
    report = "\n".join(lines)
    (directory / "checks.log").write_text(report + "\n")
    print(report)
    print("acl_whitelist_lifetime: %d/%d PASS" % (len(checks) - failed, len(checks)))
    return 1 if failed else 0


def main():
    retained = os.environ.get("ACL_WHITELIST_OUTPUT_DIR")
    if retained:
        directory = Path(retained).resolve()
        directory.mkdir(parents=True, exist_ok=True)
        return run(directory)
    with tempfile.TemporaryDirectory(prefix="nsp-acl-wl-") as private:
        return run(Path(private))


if __name__ == "__main__":
    sys.exit(main())