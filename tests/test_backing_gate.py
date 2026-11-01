#!/usr/bin/env python3
"""
backing 直通仲裁门回归测试
============================
`vfs_backing_setup` 挂接 backing 后该子树 I/O 不再经过 daemon，且系统 BPF
策略程序按调用方独立裁决（daemon 零感知）——线上实例：空规则下 root 按名
stat 他包 data 目录被判 ENOENT（直接访问 backing 则正常），且 SANDBOX 过滤
/REDIRECT/HIDE/RO 对该子树整体失效。故挂接前须确认无规则需仲裁。

两层门：
- 全局门 `fw_data_mediation_required()`（9 组）：任一规则触及 data 即要求仲裁。
- 按路径门 `fw_backing_mediation_required_for(query)`：仅自身/其下/直接父
  命中才要求仲裁，远祖先（/、/0、/Android）不强制，SANDBOX ON 除外（整树
  仲裁）。REDIRECT 只看 virtual_prefix。

**ALLOW 也算仲裁维度（DAC）**：ALLOW 只声明"这一层放行"，不代表可以绕过
daemon——backing 直通之后的下层 I/O 由内核按**调用方凭证**做 DAC，
`/data/media` 归 MediaProvider（10277:1023、子目录 2700），应用一律 EACCES。
旧实现把 ALLOW 当直通跳过，线上表现「只写 ALLOW /Download 时注入后反而写不
进去」。另有静态契约锁住 `vfs_backing_setup`：全局实例（非 --media-fuse）
一个 dentry 也不挂 backing——dentry 由所有应用共用，无法按调用方分别裁决。

**MONITOR 维度（B1）**：`MONITOR ON` 的段其调用者 IO 要进 io.log，而 backing 直通后
内核绕过 daemon、`vfs_log_io` 静默归零——故任一段 MONITOR ON 即要求整树仲裁
（监控优先，牺牲该子树的部分加速）。旧实现的门只扫 sandbox/hide/ro/redir/ftp，
仅 `MONITOR ON`（无改路径规则）时子树仍被挂 backing，监控静默失效。

本用例临时编译实际源码（fw_rules.c 等，不经 Meson）并断言 12 组全局门配置 +
22 组按路径门配置，另加 2 条源码静态契约（全局实例不得挂 backing）。
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

# 跨应用隔离（默认生效）让 data/obb 子树恒要求仲裁——本文件原有的「无关规则
# 不仲裁」用例改在 ALLOW_CROSS_APP_DATA ON（= 关掉隔离）下验证规则维度，
# 另加一组「隔离开启」用例验证新维度（见文首说明与 test_rules.py §27）。
CASES = [
    ("空规则", "[GLOBAL]\nGLOBAL_INJECT ON\nALLOW_CROSS_APP_DATA ON\n", 0),
    ("SANDBOX ON", "[GLOBAL]\nGLOBAL_INJECT ON\nSANDBOX ON\n", 1),
    ("变量展开触及data", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "DATA_BASE=/sdcard/Android/data/$package\n"
     "REDIRECT /files $DATA_BASE/files\n", 1),
    ("字面data路径", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "REDIRECT /Android/data/.x /tmp/y\n", 1),
    ("HIDE触及data", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "HIDE /Android/data/com.foo/*\n", 1),
    ("无关规则", "[GLOBAL]\nGLOBAL_INJECT ON\nALLOW_CROSS_APP_DATA ON\n"
     "REDIRECT /sdcard/X /tmp/Y\n", 0),
    # ALLOW 不再算直通：它只声明"这一层放行"，路径仍须由 daemon 代理（下层 DAC
    # 按调用方凭证，应用对 /data/media 一律 EACCES）——旧实现该项期望 0。
    ("纯ALLOW", "[GLOBAL]\nGLOBAL_INJECT ON\nALLOW_CROSS_APP_DATA ON\n"
     "ALLOW /Android/data/com.foo\n", 1),
    ("注释提及", "[GLOBAL]\nGLOBAL_INJECT ON\nALLOW_CROSS_APP_DATA ON\n"
     "#HIDE /Android/data/com.foo/*\n", 0),
    # B1：MONITOR ON 要求仲裁（监控需 daemon 记录 IO；旧实现遗漏此维度 → 期望 0）
    ("MONITOR ON", "[GLOBAL]\nGLOBAL_INJECT ON\nMONITOR ON\n", 1),
    # 跨应用隔离开启（默认）：与规则无关，data/obb 子树恒要求仲裁
    ("隔离开启-空规则", "[GLOBAL]\nGLOBAL_INJECT ON\n", 1),
    ("隔离开启-无关规则", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "REDIRECT /sdcard/X /tmp/Y\n", 1),
    ("隔离开启-纯ALLOW", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "ALLOW /Android/data/com.foo\n", 1),
]

REDIR_FOO = ("[GLOBAL]\nGLOBAL_INJECT ON\n"
             "REDIRECT /Android/data/com.foo /tmp/y\n")
# 关掉跨应用隔离（= 旧行为）后再看"规则是否要求仲裁"：远祖先/兄弟目录不强制
REDIR_FOO_OPEN = REDIR_FOO + "ALLOW_CROSS_APP_DATA ON\n"
# (描述, 配置, 查询路径, 期望)：查询可带 /<uid>/ 层，门内归一
PCASES = [
    ("重定向自身", REDIR_FOO, "/0/Android/data/com.foo", 1),
    ("重定向其下", REDIR_FOO, "/0/Android/data/com.foo/bar", 1),
    ("重定向直接父", REDIR_FOO, "/0/Android/data", 1),
    ("重定向兄弟不受影响", REDIR_FOO_OPEN, "/0/Android/data/com.bar", 0),
    ("远祖先不强制", REDIR_FOO_OPEN, "/", 0),
    ("SANDBOX整树", "[GLOBAL]\nGLOBAL_INJECT ON\nSANDBOX ON\n",
     "/0/Download", 1),
    # ALLOW 也要求仲裁（同上）：命中 ALLOW 的路径必须由 daemon 代理
    ("纯ALLOW也仲裁", "[GLOBAL]\nGLOBAL_INJECT ON\nALLOW_CROSS_APP_DATA ON\n"
     "ALLOW /Android/data/com.foo\n", "/0/Android/data/com.foo", 1),
    ("ALLOW 其下也仲裁", "[GLOBAL]\nGLOBAL_INJECT ON\nALLOW_CROSS_APP_DATA ON\n"
     "ALLOW /Android/data/com.foo\n", "/0/Android/data/com.foo/bar", 1),
    ("非data ALLOW 也仲裁", "[GLOBAL]\nGLOBAL_INJECT ON\nALLOW_CROSS_APP_DATA ON\n"
     "ALLOW /Download\n", "/0/Download", 1),
    ("非data 无规则仍可直通", "[GLOBAL]\nGLOBAL_INJECT ON\nALLOW_CROSS_APP_DATA ON\n"
     "ALLOW /Download\n", "/0/Documents", 0),
    ("变量展开命中", "[GLOBAL]\nGLOBAL_INJECT ON\n"
     "MYD=/Android/data/com.foo\n"
     "HIDE $MYD/*\n", "/0/Android/data/com.foo/a", 1),
    # B1：MONITOR ON 对任意查询路径（含远祖先）均要求仲裁（整树，监控优先）
    ("MONITOR 整树仲裁", "[GLOBAL]\nGLOBAL_INJECT ON\nMONITOR ON\n",
     "/0/Download", 1),
    ("MONITOR 整树仲裁（远祖先）", "[GLOBAL]\nGLOBAL_INJECT ON\nMONITOR ON\n", "/", 1),
    # 跨应用隔离（默认生效）：data/obb 子树（含直接父 /Android、/Android/data
    # 本身）必须 daemon 仲裁——backing 直通用 daemon 凭证，per-caller 隔离无从
    # 裁决；media/obj 不在隔离范围，仍可直通；ALLOW_CROSS_APP_DATA ON 后放开。
    ("隔离开启-他包data", "[GLOBAL]\nGLOBAL_INJECT ON\n",
     "/0/Android/data/com.other.app/files/x", 1),
    ("隔离开启-他包obb", "[GLOBAL]\nGLOBAL_INJECT ON\n",
     "/0/Android/obb/com.other.app", 1),
    ("隔离开启-自身data也仲裁", "[GLOBAL]\nGLOBAL_INJECT ON\n",
     "/0/Android/data/com.foo/x", 1),
    ("隔离开启-data骨架", "[GLOBAL]\nGLOBAL_INJECT ON\n", "/0/Android/data", 1),
    ("隔离开启-直接父", "[GLOBAL]\nGLOBAL_INJECT ON\n", "/0/Android", 1),
    ("隔离不扩media", "[GLOBAL]\nGLOBAL_INJECT ON\n", "/0/Android/media/com.other.app", 0),
    ("隔离不扩obj", "[GLOBAL]\nGLOBAL_INJECT ON\n", "/0/Android/obj/com.other.app", 0),
    ("隔离开启-远祖先仍加速", "[GLOBAL]\nGLOBAL_INJECT ON\n", "/", 0),
    ("隔离关闭后他包data可直通", "[GLOBAL]\nGLOBAL_INJECT ON\nALLOW_CROSS_APP_DATA ON\n",
     "/0/Android/data/com.other.app/files/x", 0),
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


def _brace_block(text, start):
    """从 start 处的 '{' 起做花括号配对，返回块内文本（含首尾括号），失败返回 None。"""
    i = text.find("{", start)
    if i < 0:
        return None
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    return None


def static_contract():
    """静态契约：全局实例不得挂 backing（DAC）。

    `vfs_backing_setup` 里 `if (!g_is_media_fuse)` 分支必须直接 decline 并
    返回 -ENOENT，`e->backing_fd =` 只能出现在它之后（= 只有 media 实例能走到
    挂接）。不编译 daemon（重量级，且 bpf_setup 依赖内核支持），只锁源码形状。
    """
    path = os.path.join(ROOT, "src", "daemon", "fuse_daemon.c")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    fn = text.find("static int vfs_backing_setup(")
    if fn < 0:
        fail("静态契约：vfs_backing_setup 存在", "函数未找到")
        return
    body = _brace_block(text, fn)
    if body is None:
        fail("静态契约：vfs_backing_setup 可解析", "花括号不配对")
        return
    gi = body.find("if (!g_is_media_fuse)")
    blk = _brace_block(body, gi) if gi >= 0 else None
    if blk is None:
        fail("静态契约：全局实例分支存在", "未找到 if (!g_is_media_fuse) 块")
        return
    ok1 = "BACKING_DECLINE_GLOBAL_DAC" in blk and "return -ENOENT" in blk
    if ok1:
        ok("静态契约：全局实例分支直接 decline 挂接")
    else:
        fail("静态契约：全局实例分支直接 decline 挂接", f"块内容={blk.strip()[:200]!r}")
    fd = body.find("->backing_fd = ")
    ok2 = fd > gi
    if ok2:
        ok("静态契约：只有 media 实例能走到 backing 挂接")
    else:
        fail("静态契约：只有 media 实例能走到 backing 挂接",
             f"backing_fd 赋值早于全局实例分支（idx={fd} vs {gi}）")


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
    static_contract()
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
