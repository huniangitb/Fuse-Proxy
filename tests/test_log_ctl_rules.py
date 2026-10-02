#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""log_ctl 规则编辑（set-rule / remove-rule）行为测试。

背景：log_ctl 的 set-rule/remove-rule 此前零测试覆盖——原因是它的配置根目录
写死编译期 CONFIG_DIR（GNU 下 /var/fuse-proxy，归 root 不可写），无法在普通
用户下测试。现已支持 --config-dir 覆盖（与 rule_server 同名选项一致），本测试
据此在临时目录中驱动。

本测试锁定的是**行为契约**，用于保护后续重构（把 log_ctl 与 rule_server 重复
的行级文件工具收敛为共享实现 nsp_rule_file）：

  稳定契约（重构不得改变）
    - GLOBAL 开关（MONITOR/SANDBOX/GLOBAL_INJECT）就地替换，不新增行
    - GLOBAL 普通规则插入段头之后，且同规则去重
    - REDIRECT "a|b" → "REDIRECT a b"；单值 v → "REDIRECT v v"
    - 应用段规则落 App-rules/<pkg>.conf；--uid 落 App-rules-<uid>/
    - USER_APPS 落主文件 [USER_APPS:<uid>]；SYSTEM_APPS 落 [SYSTEM_APPS]
    - 类别段头带 ON/OFF 后缀、尾空白或末行无换行时，写入仍命中该段：
      不追加重复段、不改写原段头、不与末行粘连
    - 未知类型报错且不改动文件

  已统一的分叉（log_ctl 现与 rule_server 同语义）
    - remove-rule 的 index **计入**以 # 停用的行，与 rule_server 的
      find_rule_line/classify_line 及 LIST 输出一致。此前 log_ctl 跳过
      停用行，同一命令在两个二进制下索引结果不同——已随共享实现统一。

前置：GNU 构建产物 build_gnu/log_ctl（可用 LOG_CTL 环境变量覆盖）。
失败时退出码为 1（勿用管道吞掉退出码）。
"""

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_CTL = os.environ.get("LOG_CTL") or os.path.join(ROOT, "build_gnu", "log_ctl")

PASS = 0
FAIL = 0
ERRS = []


def ok(desc):
    global PASS
    PASS += 1
    print(f"  ✅ {desc}")


def fail(desc, detail=""):
    global FAIL
    FAIL += 1
    ERRS.append((desc, detail))
    print(f"  ❌ {desc}: {detail}")


def check(desc, got, want):
    if got == want:
        ok(desc)
    else:
        fail(desc, f"got={got!r} want={want!r}")


class Cfg:
    """一次用例的临时配置根目录。"""

    def __init__(self, initial="[GLOBAL]\n"):
        self.dir = tempfile.mkdtemp(prefix="lc_rules_")
        self.main = os.path.join(self.dir, "injector.conf")
        with open(self.main, "w", encoding="utf-8") as fh:
            fh.write(initial)

    def run(self, *args):
        r = subprocess.run([LOG_CTL, *args, "--config-dir", self.dir],
                           capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def main_text(self):
        with open(self.main, encoding="utf-8") as fh:
            return fh.read()

    def app_text(self, pkg, uid=None):
        sub = "App-rules" if uid is None else f"App-rules-{uid}"
        p = os.path.join(self.dir, sub, f"{pkg}.conf")
        if not os.path.exists(p):
            return None
        with open(p, encoding="utf-8") as fh:
            return fh.read()

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def lines_of(text):
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def test_global_switch_replace():
    print("── GLOBAL 开关就地替换（不新增行） ──")
    c = Cfg("[GLOBAL]\nMONITOR ON\nHIDE /keep\n")
    c.run("set-rule", "GLOBAL", "MONITOR", "OFF")
    ls = lines_of(c.main_text())
    check("MONITOR 就地改为 OFF", "MONITOR OFF" in ls, True)
    check("不残留 MONITOR ON", "MONITOR ON" in ls, False)
    check("开关未新增行", len([x for x in ls if x.startswith("MONITOR")]), 1)
    check("其它规则不受影响", "HIDE /keep" in ls, True)
    # 再次设置同一开关不产生重复行
    c.run("set-rule", "GLOBAL", "MONITOR", "OFF")
    check("重复设置同一开关仍只一行",
          len([x for x in lines_of(c.main_text()) if x.startswith("MONITOR")]), 1)
    c.close()


def test_global_rule_insert_and_dedupe():
    print("── GLOBAL 普通规则插入 + 去重 ──")
    c = Cfg("[GLOBAL]\nMONITOR ON\n")
    c.run("set-rule", "GLOBAL", "HIDE", "/secret")
    ls = lines_of(c.main_text())
    check("HIDE 写入", "HIDE /secret" in ls, True)
    check("插入在段头之后", ls.index("HIDE /secret"), 1)
    # 同规则重复写入应去重
    c.run("set-rule", "GLOBAL", "HIDE", "/secret")
    check("同规则去重", lines_of(c.main_text()).count("HIDE /secret"), 1)
    # 不同规则各占一行
    c.run("set-rule", "GLOBAL", "RO", "/ro")
    check("不同规则并存", lines_of(c.main_text()).count("RO /ro"), 1)
    c.close()


def test_redirect_forms():
    print("── REDIRECT 单值/双值形式 ──")
    c = Cfg("[GLOBAL]\n")
    c.run("set-rule", "GLOBAL", "REDIRECT", "/only")
    check("单值 v → REDIRECT v v", "REDIRECT /only /only" in lines_of(c.main_text()), True)
    c.run("set-rule", "GLOBAL", "REDIRECT", "/x|/y")
    check("双值 a|b → REDIRECT a b", "REDIRECT /x /y" in lines_of(c.main_text()), True)
    c.close()


def test_app_scope():
    print("── 应用段落 App-rules ──")
    c = Cfg("[GLOBAL]\n")
    c.run("set-rule", "com.test.app", "HIDE", "/apphide")
    check("落 App-rules/<pkg>.conf", "HIDE /apphide" in (c.app_text("com.test.app") or ""), True)
    check("不污染主文件", "apphide" in c.main_text(), False)
    c.run("set-rule", "com.test.app", "HIDE", "/u5hide", "--uid", "5")
    check("--uid 5 落 App-rules-5/",
          "HIDE /u5hide" in (c.app_text("com.test.app", uid=5) or ""), True)
    c.close()


def test_category_scope():
    print("── 类别段落主文件精确段头 ──")
    c = Cfg("[GLOBAL]\n")
    c.run("set-rule", "USER_APPS", "HIDE", "/uahide")
    check("USER_APPS 默认落 [USER_APPS:0]",
          "[USER_APPS:0]" in lines_of(c.main_text()), True)
    check("USER_APPS 规则写入", "HIDE /uahide" in lines_of(c.main_text()), True)
    c.run("set-rule", "USER_APPS", "HIDE", "/ua7", "--uid", "7")
    check("USER_APPS --uid 7 落 [USER_APPS:7]",
          "[USER_APPS:7]" in lines_of(c.main_text()), True)
    c.run("set-rule", "SYSTEM_APPS", "RO", "/sysro")
    check("SYSTEM_APPS 落 [SYSTEM_APPS]",
          "[SYSTEM_APPS]" in lines_of(c.main_text()), True)
    c.close()


def test_category_header_variants():
    """类别段头的容错形态：写入不得另起重复段、不得破坏原段头、不得粘连末行。

    回归背景：共享实现曾把"带 \\n 的段头文本"传给精确匹配器，导致
    [USER_APPS:0] OFF / [USER_APPS:0]␠␠ / 末行无换行 三种形态全部匹配失败，
    于是追加一个**默认 ON** 的同名重复段——显式 OFF 的类别会被静默重新使能。
    """
    print("── 类别段头容错形态（OFF 后缀 / 尾空白 / 末行无换行） ──")
    for label, initial in [
        ("OFF 后缀", "[GLOBAL]\n[USER_APPS:0] OFF\n"),
        ("尾空白", "[GLOBAL]\n[USER_APPS:0]  \n"),
        ("末行无换行", "[GLOBAL]\n[USER_APPS:0]"),
    ]:
        c = Cfg(initial)
        rc, out = c.run("set-rule", "USER_APPS", "HIDE", "/hdrprobe")
        check(f"[{label}] 写入成功", rc, 0)
        ls = lines_of(c.main_text())
        check(f"[{label}] 未另起重复段",
              len([x for x in ls if x.startswith("[USER_APPS:0]")]), 1)
        check(f"[{label}] 规则落入该段", "HIDE /hdrprobe" in ls, True)
        check(f"[{label}] 规则在段头之后",
              ls.index("HIDE /hdrprobe") > ls.index(
                  next(x for x in ls if x.startswith("[USER_APPS:0]"))), True)
        if label == "OFF 后缀":
            check("OFF 后缀未被改写为默认 ON", "OFF" in ls[ls.index("[USER_APPS:0] OFF")], True)
        if label == "末行无换行":
            # 段头行与规则行必须是两行，而非粘连成 "[USER_APPS:0]HIDE /hdrprobe"
            check("未与末行粘连", "[USER_APPS:0]HIDE /hdrprobe" in ls, False)
        c.close()


def test_unknown_type():
    print("── 未知类型：报错且不改动文件 ──")
    c = Cfg("[GLOBAL]\nHIDE /keep\n")
    before = c.main_text()
    _, out = c.run("set-rule", "GLOBAL", "BOGUS", "/x")
    check("提示未知规则类型", "未知规则类型" in out, True)
    check("文件未被改动", c.main_text(), before)
    c.close()


def test_remove_index_semantics():
    print("── remove-rule 索引语义（计入停用行，与 LIST 一致） ──")
    # 索引计入以 # 停用的行
    c = Cfg("[GLOBAL]\nHIDE /a\n# HIDE /b\nHIDE /c\nRO /r\n")
    c.run("remove-rule", "GLOBAL", "HIDE", "1")
    ls = lines_of(c.main_text())
    check("index 1 命中停用行 # HIDE /b（计入停用行）", "# HIDE /b" in ls, False)
    check("HIDE /c 保留", "HIDE /c" in ls, True)
    check("HIDE /a 保留", "HIDE /a" in ls, True)
    c.close()
    # 索引从 0 开始，且按类型筛选
    c = Cfg("[GLOBAL]\nHIDE /a\nRO /r0\nHIDE /c\n")
    c.run("remove-rule", "GLOBAL", "HIDE", "0")
    ls = lines_of(c.main_text())
    check("index 0 删首条 HIDE", "HIDE /a" in ls, False)
    check("按类型筛选：RO 不受影响", "RO /r0" in ls, True)
    check("其它 HIDE 保留", "HIDE /c" in ls, True)
    c.close()
    # 同机制覆盖 REDIRECT（pair 类型同样按类型筛选计索引）
    c = Cfg("[GLOBAL]\nREDIRECT /a /b\nREDIRECT /c /d\n")
    c.run("remove-rule", "GLOBAL", "REDIRECT", "1")
    ls = lines_of(c.main_text())
    check("删除第 2 条 REDIRECT", "REDIRECT /c /d" in ls, False)
    check("第 1 条 REDIRECT 保留", "REDIRECT /a /b" in ls, True)
    c.close()
    # 越界索引：报错且不改动
    c = Cfg("[GLOBAL]\nHIDE /only\n")
    before = c.main_text()
    _, out = c.run("remove-rule", "GLOBAL", "HIDE", "9")
    check("越界索引提示未找到", "未找到" in out, True)
    check("越界索引不改动文件", c.main_text(), before)
    c.close()


def main():
    if not os.path.exists(LOG_CTL):
        print(f"缺少 {LOG_CTL}，请先 ninja -C build_gnu", file=sys.stderr)
        return 1
    print(f"log_ctl: {LOG_CTL}\n")
    test_global_switch_replace()
    test_global_rule_insert_and_dedupe()
    test_redirect_forms()
    test_app_scope()
    test_category_scope()
    test_category_header_variants()
    test_unknown_type()
    test_remove_index_semantics()
    print()
    print("═" * 39)
    print(f"log_ctl 规则编辑测试 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS + FAIL}")
    if ERRS:
        for d, dt in ERRS:
            print(f"   ✗ {d}: {dt}")
    print("═" * 39)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
