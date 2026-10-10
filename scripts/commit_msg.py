#!/usr/bin/env python3
"""提交信息工具：规范校验（lint）+ CHANGELOG 生成（changelog）。

CONTRIBUTING.md §5 是规则的权威出处，本文件是它**唯一**的可执行形式——
校验与 CHANGELOG 共用同一个 conventional 解析，不另写第二份。

    python3 scripts/commit_msg.py lint <提交信息文件>     # .githooks/commit-msg 调用
    python3 scripts/commit_msg.py changelog [--range <ref>..HEAD] [--output CHANGELOG.md]

长度一律按**显示宽度**计（CJK 占 2 列）。按字符数计的实现（如 commitlint 的
header-max-length）在中文下是假合规：40 个汉字报「40 字符」却占 80 列，终端
必然折行——本仓库实测 25% 的正文行超宽就是这么来的。
"""
import argparse
import os
import re
import subprocess
import sys
import unicodedata
from datetime import date

TYPES = ("feat", "fix", "docs", "refactor", "perf", "test", "build", "chore")
SCOPES = ("fw", "fuse", "module", "ftp", "injector", "zygisk", "log", "rule",
          "config", "core", "build", "scripts", "test", "docs")

# 正文可省的 type：纯文档与杂项没有「以实现什么」可写
BODY_EXEMPT = ("docs", "chore")
HEADER_TARGET = 50
HEADER_MAX = 72
LINE_MAX = 72

# 仓库外的本机材料：读者解析不了，等于噪声
LOCAL_REFS = (".workbuddy-ai", "review-findings-", "review-todo-", ".zcode", "会话记忆")
# git 自己生成的提交信息不校验
SKIP_PREFIXES = ("Merge ", 'Revert "', "fixup!", "squash!")

HEADER_RE = re.compile(r"^(?P<type>[a-z]+)(?:\((?P<scope>[^()]*)\))?(?P<bang>!)?: (?P<desc>.+)$")
FOOTER_RE = re.compile(
    r"^(?P<token>BREAKING[ -]CHANGE|Co-Authored-By|Signed-off-by|Refs|Closes|Fixes):\s*(?P<value>.*)$")
BREAKING_RE = re.compile(r"^BREAKING[ -]CHANGE: \S", re.M)
LABELS = ("以实现：", "凭什么对：")

SECTIONS = (("feat", "新功能"), ("fix", "缺陷修复"), ("perf", "性能"),
            ("refactor", "重构"), ("build", "构建与打包"), ("test", "测试"),
            ("docs", "文档"), ("chore", "杂项"))


def width(s):
    """显示宽度：CJK 全角占 2 列（终端与 git log 的实际排版口径）。"""
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def strip_comments(text):
    """去掉 git 的注释行（core.commentChar 默认 #）。"""
    return "\n".join(l for l in text.splitlines() if not l.startswith("#"))


def check(text):
    """返回 (errors, warnings)。空列表 = 通过。"""
    errs, warns = [], []
    lines = strip_comments(text).splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return ["提交信息为空"], warns

    header = lines[0].rstrip()
    if header.startswith(SKIP_PREFIXES):
        return [], []
    rest = lines[1:]
    if rest and rest[0].strip():
        errs.append("标题与正文之间必须空一行")
    body = "\n".join(rest).strip("\n")

    m = HEADER_RE.match(header)
    if not m:
        errs.append("标题不符合 <type>(<scope>): <做了什么更改> —— " + repr(header))
        return errs, warns
    t, scope, bang, desc = m.group("type"), m.group("scope"), m.group("bang"), m.group("desc")

    hw = width(header)
    if hw > HEADER_MAX:
        errs.append("标题 %d 显示列 > 上限 %d（中文按 2 列计，约 %d 个汉字）：%s"
                    % (hw, HEADER_MAX, HEADER_MAX // 2, header))
    elif hw > HEADER_TARGET:
        warns.append("标题 %d 显示列 > 目标 %d（未超上限，仅提示）" % (hw, HEADER_TARGET))

    if t not in TYPES:
        errs.append("type %s 不在词表：%s" % (t, " ".join(TYPES)))
    if scope is not None:
        if "," in scope:
            errs.append("scope 只能有一个：%s" % scope)
        elif re.match(r"^[ABC][0-9]+$", scope):
            errs.append("scope %s 是内部计划/评审编号（仓库外不可解；追溯写进正文），"
                        "应换成模块 scope" % scope)
        elif scope not in SCOPES:
            errs.append("scope %s 不在词表：%s" % (scope, " ".join(SCOPES)))
    if desc.endswith(("。", ".")):
        errs.append("标题句末不加句号")
    if " + " in desc or "；" in desc:
        errs.append("标题出现「+」或「；」：一个提交塞了多件事，按 §5.3 拆开")
    code = re.search(r"(?<![A-Za-z0-9])([ABC][0-9]+)(?![0-9])", desc)
    if code:
        errs.append("标题不得含内部计划/评审编号 %s（仓库外不可解；追溯写进正文）" % code.group(1))

    breaking = bool(BREAKING_RE.search(body))
    if bool(bang) != breaking:
        errs.append("「!」与 BREAKING CHANGE: 必须成对出现"
                    + ("（标题有 ! 但正文缺 footer）" if bang else "（正文有 footer 但标题缺 !）"))

    for idx, ln in enumerate(rest):          # 行号按提交信息原文计（标题为第 1 行）
        lineno = idx + 2
        if not ln.strip() or "http://" in ln or "https://" in ln:
            continue
        lw = width(ln)
        if lw > LINE_MAX:
            errs.append("正文第 %d 行 %d 显示列 > %d：%s" % (lineno, lw, LINE_MAX, ln[:40] + "…"))
    for idx, ln in enumerate(rest):
        s = ln.strip()
        if s in LABELS:
            nxt = rest[idx + 1] if idx + 1 < len(rest) else ""
            if not nxt.strip():
                errs.append("空标签「%s」：写了标签就要写内容，不写就删掉整行" % s)

    for ref in LOCAL_REFS:
        if ref in text:
            errs.append("引用仓库外的本机材料「%s」（读者解析不了）" % ref)

    if t not in BODY_EXEMPT:
        if not body:
            errs.append("%s 提交必须写正文（§5.2）：以实现什么 / 凭什么对" % t)
        elif "以实现：" not in body:
            errs.append("正文缺「以实现：」段——先答「让什么能力成立 / 让什么错误消失」")

    # trailer 必须在最后一个段落（与正文之间空一行）
    if body:
        paras = [p for p in body.split("\n\n") if p.strip()]
        for p in paras[:-1]:
            for ln in p.splitlines():
                fm = FOOTER_RE.match(ln)
                if fm:
                    errs.append("trailer「%s:」必须位于正文末尾，且与正文空一行" % fm.group("token"))
    return errs, warns


# ── changelog ────────────────────────────────────────────────────────────────
def parse_commit(header, body=""):
    m = HEADER_RE.match(header)
    if not m:
        return None
    return {"type": m.group("type"), "scope": m.group("scope"), "desc": m.group("desc"),
            "breaking": bool(m.group("bang")) or bool(BREAKING_RE.search(body))}


def read_history(rng):
    out = subprocess.run(["git", "log", "--pretty=format:%H%x00%s%x00%b%x01", rng],
                         capture_output=True, text=True).stdout
    commits = []
    for rec in out.split("\x01"):
        rec = rec.strip("\n")
        if not rec:
            continue
        parts = rec.split("\x00")
        if len(parts) < 2:
            continue
        c = parse_commit(parts[1], parts[2] if len(parts) > 2 else "")
        if not c:
            continue
        c["hash"] = parts[0][:7]
        commits.append(c)
    return commits


def render(commits, title):
    out = ["# Changelog", "", "## " + title, ""]
    for t, name in SECTIONS:
        group = [c for c in commits if c["type"] == t]
        if not group:
            continue
        out += ["### " + name, ""]
        for c in group:
            sc = ("**" + c["scope"] + "**: ") if c["scope"] else ""
            out.append("- %s%s (%s)" % (sc, c["desc"], c["hash"]))
        out.append("")
    brk = [c for c in commits if c["breaking"]]
    if brk:
        out += ["### 破坏性变更", ""]
        for c in brk:
            out.append("- %s (%s)" % (c["desc"], c["hash"]))
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def write_changelog(path, section):
    """已存在则在首个标题行后插入，否则新建。"""
    if os.path.exists(path):
        old = open(path, encoding="utf-8").read()
        lines = old.splitlines()
        if lines and lines[0].startswith("# "):
            new = "\n".join([lines[0], ""] + section.splitlines()[1:] + lines[1:])
        else:
            new = section + old
    else:
        new = section
    with open(path, "w", encoding="utf-8") as f:
        f.write(new.rstrip() + "\n")


def cmd_lint(args):
    if args.file == "-":
        text = sys.stdin.read()
    else:
        with open(args.file, encoding="utf-8") as f:
            text = f.read()
    errs, warns = check(text)
    for w in warns:
        print("提示：" + w, file=sys.stderr)
    if errs:
        print("✗ 提交信息不符合规范（CONTRIBUTING.md §5）", file=sys.stderr)
        for e in errs:
            print("  · " + e, file=sys.stderr)
        print("修正后重试：git commit --edit --file=" + args.file, file=sys.stderr)
        return 1
    return 0


def cmd_changelog(args):
    rng = args.range
    if not rng:
        tag = subprocess.run(["git", "describe", "--tags", "--abbrev=0"],
                             capture_output=True, text=True).stdout.strip()
        rng = tag + "..HEAD" if tag else "HEAD"
    commits = read_history(rng)
    title = args.version or date.today().isoformat()
    section = render(commits, title)
    if args.output:
        write_changelog(args.output, section)
        print("已更新 %s：%d 条提交（范围 %s）" % (args.output, len(commits), rng))
    else:
        sys.stdout.write(section)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="提交信息校验与 CHANGELOG 生成")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("lint", help="校验提交信息（不合规 exit 1）")
    p1.add_argument("file", help="提交信息文件；- 表示 stdin")
    p1.set_defaults(func=cmd_lint)
    p2 = sub.add_parser("changelog", help="按 conventional 类型生成 CHANGELOG")
    p2.add_argument("--range", default="", help="git 范围，默认最近 tag..HEAD")
    p2.add_argument("--version", default="", help="小节标题，默认当天日期")
    p2.add_argument("--output", default="", help="写入文件（已存在则在首个标题后插入）")
    p2.set_defaults(func=cmd_changelog)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
