#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HIDE 命中返回码（HIDE_ERRNO）的回归

背景：HIDE 规则命中时恒返回 ENOENT。对「访问失败就重试」的应用（自建缓存目录、
先 probe 再写）来说，ENOENT 等于「还没生成」，于是一次启动能把同一条路径打上
几百遍，FUSE 请求量被放大成重试风暴。EACCES 语义是「存在但不许访问」，这类
应用通常一次就放弃。

分层：
  A 段（直编 include/nsp_hide_errno.h，L0）：0 → ENOENT（缺省不变）、显式值原样；
  B 段（静态契约，L0）：只认用户规则命中、内部隐藏不受影响、配置键只在
     [GLOBAL] 生效且非法值退回缺省；拒绝码经决策结构送达框架唯一执行点
     （fw_route），跨应用隔离不得跟着换码。

判别性：把缺省从 ENOENT 改成 EACCES → A1 失败；把 HIDE_ERRNO 应用到骨架/内部
隐藏 → B3 失败；去掉 [GLOBAL] 守卫 → B5 失败。

退出码：0 通过、1 失败。
"""
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADER = ROOT / "include" / "nsp_hide_errno.h"
RULES = ROOT / "src" / "daemon" / "fw_rules.c"
PARSER = ROOT / "src" / "config" / "config_parser.c"
PARSER_H = ROOT / "include" / "config_parser.h"
DOCS = ROOT / "docs" / "config.md"

fails = 0


def check(name, ok, detail=""):
    global fails
    if not ok:
        fails += 1
    print(f"case={name:<46} ok={1 if ok else 0} {detail}")


def read(path):
    return Path(path).read_text(encoding="utf-8")


def run_helper():
    if not HEADER.is_file():
        check("A0_header_exists", False)
        return
    with tempfile.TemporaryDirectory(prefix="hide_errno_") as tmp:
        src = Path(tmp) / "probe.c"
        src.write_text(
            "#include <stdio.h>\n"
            "#include <errno.h>\n"
            '#include "nsp_hide_errno.h"\n'
            "int main(void) {\n"
            "    printf(\"%d %d %d\\n\", nsp_hide_errno_of(0), nsp_hide_errno_of(EACCES),\n"
            "           nsp_hide_errno_of(EPERM));\n"
            "    return 0;\n"
            "}\n",
            encoding="utf-8",
        )
        exe = Path(tmp) / "probe"
        cc = shlex.split(os.environ.get("CC", "cc"))
        cmd = cc + ["-std=c23", "-I", str(ROOT / "include"), str(src), "-o", str(exe)]
        build = subprocess.run(cmd, capture_output=True, text=True)
        if build.returncode != 0:
            check("A0_header_compiles", False, build.stderr.strip()[:200])
            return
        out = subprocess.run([str(exe)], capture_output=True, text=True).stdout.split()
        got = [int(x) for x in out] if out else []
        check("A1_default_is_enoent", got[:1] == [errno_value("ENOENT")], f"got={got}")
        check("A2_eacces_passthrough", got[1:2] == [errno_value("EACCES")], f"got={got}")
        check("A3_eperm_passthrough", got[2:3] == [errno_value("EPERM")], f"got={got}")


def errno_value(name):
    probe = subprocess.run(
        ["cc", "-dM", "-E", "-"], input=f"#include <errno.h>\n", capture_output=True, text=True)
    m = re.search(rf"#define {name} (\d+)", probe.stdout)
    return int(m.group(1)) if m else -1


def run_contracts():
    rules = read(RULES)
    parser = read(PARSER)
    parser_h = read(PARSER_H)
    docs = read(DOCS)

    hidden = rules.find("br_is_path_hidden_internal(cfg, cat, sub_path_out")
    body = rules[hidden:hidden + 300] if hidden >= 0 else ""
    check("B1_hidden_uses_configured_errno",
          "return -nsp_hide_errno_of(g_global_cfg.hide_errno);" in body, "")
    check("B2_sanitize_failure_stays_enoent",
          not body.split("br_strip_and_sanitize")[0:1] or
          "return -ENOENT;" in rules[max(0, hidden - 500):hidden], "")
    check("B3_only_user_rules_use_configured_errno",
          rules.count("nsp_hide_errno_of(") == 2 and
          "nsp_hide_errno_of" in read(HEADER), "")
    check("B4_config_field_present", re.search(r"int hide_errno;", parser_h) is not None, "")
    check("B5_parser_restricted_to_global",
          "HIDE_ERRNO 仅 [GLOBAL] 段有效" in parser, "")
    check("B6_parser_accepts_three_values",
          all(v in parser for v in ("ENOENT", "EACCES", "EPERM")), "")
    check("B7_parser_dispatch_registered",
          'strcmp(tok, "HIDE_ERRNO") == 0' in parser, "")
    check("B8_docs_document_key", "HIDE_ERRNO" in docs, "")
    rules_h = read(ROOT / "src" / "daemon" / "fw_rules.h")
    daemon = read(ROOT / "src" / "daemon" / "fuse_daemon.c")
    check("B9_decision_carries_deny_errno",
          re.search(r"int deny_errno;", rules_h) is not None, "")
    check("B10_resolve_sets_errno_only_for_hide",
          "out->deny_errno = hidden ? nsp_hide_errno_of(g_global_cfg.hide_errno) : 0;"
          in rules, "")
    check("B11_route_applies_errno",
          "return rr->deny_errno ? -rr->deny_errno : -ENOENT;" in daemon, "")
    check("B12_deny_errno_initialized_zero",
          "out->deny_errno = 0;" in rules, "")


if __name__ == "__main__":
    run_helper()
    run_contracts()
    print(f"===== total_failures={fails} =====")
    sys.exit(1 if fails else 0)
