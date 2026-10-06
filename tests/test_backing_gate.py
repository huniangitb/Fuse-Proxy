#!/usr/bin/env python3
"""
backing 直通仲裁门回归测试
============================
`vfs_backing_setup` 挂接 backing 后该子树 I/O 不再经过 daemon，且系统 BPF
策略程序按调用方独立裁决（daemon 零感知）——线上实例：空规则下 root 按名
stat 他包 data 目录被判 ENOENT（直接访问 backing 则正常），且 SANDBOX 过滤
/REDIRECT/HIDE/RO 对该子树整体失效。故挂接前须确认无规则需仲裁。

两层门：
- 全局门 `fw_data_mediation_required()`（8 组）：任一规则触及 data 即要求仲裁。
- 按路径门 `fw_backing_mediation_required_for(query)`（8 组）：仅自身/其下/
  直接父命中才要求仲裁，远祖先（/、/0、/Android）不强制，SANDBOX ON 除外
  （整树仲裁）。REDIRECT 只看 virtual_prefix（ALLOW 跳过）。

本用例临时编译实际源码（fw_rules.c 等，不经 Meson）并断言 16 组配置。
前置：本机 cc、json-c；缺失则以 SKIP_RC 退出（环境不具备 = gap，不计通过）。
"""
import os
import re
import shlex
import shutil
import subprocess
import sys
import time

# 退出码约定（与 tests/run.py 一致）：0=通过 1=失败 77=环境不具备跳过(gap)
SKIP_RC = 77

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DRIVER = os.path.join(ROOT, "tests", "fixtures", "backing_gate_driver.c")
SOURCES = [
    "src/daemon/fw_rules.c",
    "src/daemon/fw_pkg.c",
    "src/config/config_parser.c",
    "src/config/path_vars.c",
    "src/core/path_trie.c",
    "src/core/nsp_util.c",
    "src/core/nsp_comm.c",
    "src/core/common.c",
    "src/core/sys_pkg.c",
    "src/core/uid_map.c",
    "src/core/fast_pid.c",
    "src/injector/config_publisher.c",
]
CONFIG_DIR_PAT = re.compile(
    r'^#define\s+(?:NSP_CONFIG_DIR|CONFIG_DIR)\s+"/var/fuse-proxy"\s*$', re.M)
PASS = 0
FAIL = 0
ERRORS = []

CASES = [
    ("空规则", "[GLOBAL]\nGLOBAL_INJECT ON\n", 0),
    ("SANDBOX ON", "[GLOBAL]\nGLOBAL_INJECT ON\nSANDBOX ON\n", 1),
    ("变量展开触及data", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "DATA_BASE=/sdcard/Android/data/$package\n"
     "REDIRECT /files $DATA_BASE/files\n", 1),
    ("字面data路径", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "REDIRECT /Android/data/.x /tmp/y\n", 1),
    ("HIDE触及data", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "HIDE /Android/data/com.foo/*\n", 1),
    ("无关规则", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "REDIRECT /sdcard/X /tmp/Y\n", 0),
    ("纯ALLOW", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "ALLOW /Android/data/com.foo\n", 0),
    ("注释提及", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "#HIDE /Android/data/com.foo/*\n", 0),
]

REDIR_FOO = ("[GLOBAL]\nGLOBAL_INJECT ON\n"
             "REDIRECT /Android/data/com.foo /tmp/y\n")
# (描述, 配置, 查询路径, 期望)：查询可带 /<uid>/ 层，门内归一
PCASES = [
    ("重定向自身", REDIR_FOO, "/0/Android/data/com.foo", 1),
    ("重定向其下", REDIR_FOO, "/0/Android/data/com.foo/bar", 1),
    ("重定向直接父", REDIR_FOO, "/0/Android/data", 1),
    ("重定向兄弟不受影响", REDIR_FOO, "/0/Android/data/com.bar", 0),
    ("远祖先不强制", REDIR_FOO, "/", 0),
    ("SANDBOX整树", "[GLOBAL]\nGLOBAL_INJECT ON\nSANDBOX ON\n",
     "/0/Download", 1),
    ("纯ALLOW直通", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "ALLOW /Android/data/com.foo\n", "/0/Android/data/com.foo", 0),
    ("变量展开命中", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "MYD=/Android/data/com.foo\n"
     "HIDE $MYD/*\n", "/0/Android/data/com.foo/a", 1),
]


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


def ok(desc):
    global PASS
    PASS += 1
    log(f"  ✅ {desc}")


def fail(desc, detail=""):
    global FAIL
    FAIL += 1
    log(f"  ❌ {desc}: {detail}")
    ERRORS.append((desc, detail))


def pkg_config(flag):
    try:
        r = subprocess.run(["pkg-config", flag, "json-c"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.split()
    except FileNotFoundError:
        pass
    return []


def main():
    # CC 须按 shlex 拆词取可执行名：CC 常带参数（如内存验收时
    # CC="cc -fsanitize=address,undefined"），直接 which 整个串会误判「缺少编译器」
    cc = shlex.split(os.environ.get("CC", "cc"))
    if shutil.which(cc[0]) is None:
        log("跳过：缺少 C 编译器")
        return SKIP_RC
    if not pkg_config("--libs"):
        log("跳过：缺少 json-c")
        return SKIP_RC
    tmpdir = "/tmp/fuse_gate_test"
    shutil.rmtree(tmpdir, ignore_errors=True)
    os.makedirs(tmpdir)
    cfgdir = os.path.join(tmpdir, "cfg")
    os.makedirs(cfgdir)
    # include 副本：GNU 配置根指向临时目录（沿用 test_config_snapshot 做法）
    src_inc = os.path.join(ROOT, "include")
    dst_inc = os.path.join(tmpdir, "include")
    shutil.copytree(src_inc, dst_inc)
    hits = 0
    for name in sorted(os.listdir(dst_inc)):
        if not name.endswith(".h"):
            continue
        path = os.path.join(dst_inc, name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        patched, n = CONFIG_DIR_PAT.subn(
            lambda m: m.group(0).replace('"/var/fuse-proxy"', f'"{cfgdir}"'), text)
        if n:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(patched)
            hits += n
    if hits == 0:
        log("跳过：未定位 GNU 配置根常量")
        return SKIP_RC
    exe = os.path.join(tmpdir, "gate_test")
    cmd = cc + ["-std=c23", "-DTARGET_GNU=1",
           "-D_GNU_SOURCE", "-Wall", "-Wno-unused-parameter",
           "-I", dst_inc, "-I", os.path.join(ROOT, "include"),
           "-I", os.path.join(ROOT, "src", "daemon"), DRIVER] + \
          [os.path.join(ROOT, s) for s in SOURCES] + \
          ["-o", exe, "-pthread", "-ldl", "-lm"] + \
          pkg_config("--cflags") + pkg_config("--libs")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        fail("测试二进制编译", r.stderr.strip()[-500:])
        return 1
    for desc, conf, want in CASES:
        with open(os.path.join(cfgdir, "injector.conf"), "w") as fh:
            fh.write(conf)
        r = subprocess.run([exe, os.path.join(cfgdir, "injector.conf")],
                           capture_output=True, text=True)
        got = r.stdout.strip()
        if r.returncode == 0 and got == str(want):
            ok(f"{desc} → {want}")
        else:
            fail(f"{desc} → {want}", f"实测={got!r} rc={r.returncode} {r.stderr.strip()[-200:]}")
    for desc, conf, query, want in PCASES:
        with open(os.path.join(cfgdir, "injector.conf"), "w") as fh:
            fh.write(conf)
        r = subprocess.run([exe, os.path.join(cfgdir, "injector.conf"), query],
                           capture_output=True, text=True)
        got = r.stdout.strip()
        if r.returncode == 0 and got == str(want):
            ok(f"{desc} {query} → {want}")
        else:
            fail(f"{desc} {query} → {want}", f"实测={got!r} rc={r.returncode} {r.stderr.strip()[-200:]}")
    shutil.rmtree(tmpdir, ignore_errors=True)
    print(f"\n结果: {PASS} 通过, {FAIL} 失败")
    if ERRORS:
        for d, det in ERRORS:
            print(f"  ❌ {d}: {det}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
