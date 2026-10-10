#!/usr/bin/env python3
"""提交信息工具：规范校验（lint）、正文折行（wrap）、CHANGELOG 生成（changelog）。

CONTRIBUTING.md §5 是规则的权威出处，本文件是它**唯一**的可执行形式——
校验、折行与 CHANGELOG 共用同一个 conventional 解析，不另写第二份。

    python3 scripts/commit_msg.py lint <提交信息文件>        # .githooks/commit-msg 调用
    python3 scripts/commit_msg.py lint --fix <文件>          # 先自动折行再校验
    python3 scripts/commit_msg.py wrap <文件> [--check]      # 只折行正文
    python3 scripts/commit_msg.py changelog [--range R] [--output CHANGELOG.md]

长度一律按**显示宽度**计（CJK 占 2 列）。按字符数计的实现（如 commitlint 的
header-max-length）在中文下是假合规：40 个汉字报「40 字符」却占 80 列，终端
必然折行——本仓库实测 25% 的正文行超宽就是这么来的。

scope 省略或不在词表时，按本次改动的文件路径给出建议（只提示，不判定）。
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

# 路径 → scope（首个命中者胜，故具体项在前）。仅用于给出建议，不参与判定。
SCOPE_PATHS = (
    ("prefix", "src/daemon/fw_", "fw"),
    ("prefix", "src/daemon/fuse_daemon.c", "fuse"),
    ("prefix", "src/daemon/fd_close_queue", "fuse"),
    ("prefix", "src/daemon/cfg_watch", "config"),
    ("prefix", "src/daemon/", "fuse"),
    ("prefix", "src/module/", "module"),
    ("prefix", "src/modules/ftp/", "ftp"),
    ("prefix", "src/modules/", "module"),
    ("prefix", "src/injector/", "injector"),
    ("prefix", "src/zygisk/", "zygisk"),
    ("prefix", "src/log/", "log"),
    ("prefix", "src/rule/", "rule"),
    ("prefix", "src/config/", "config"),
    ("prefix", "src/core/nsp_rule_file", "rule"),
    ("prefix", "src/core/", "core"),
    ("prefix", "include/nsp_module.h", "module"),
    ("prefix", "include/nsp_rule_file.h", "rule"),
    ("prefix", "include/", "core"),
    ("prefix", "tests/", "test"),
    ("prefix", "scripts/", "scripts"),
    ("prefix", ".githooks/", "scripts"),
    ("prefix", "meson.build", "build"),
    ("prefix", "meson_options.txt", "build"),
    ("prefix", "subprojects/", "build"),
    ("prefix", "docs/", "docs"),
    ("suffix", ".md", "docs"),
)

HEADER_RE = re.compile(r"^(?P<type>[a-z]+)(?:\((?P<scope>[^()]*)\))?(?P<bang>!)?: (?P<desc>.+)$")
FOOTER_RE = re.compile(
    r"^(?P<token>BREAKING[ -]CHANGE|Co-Authored-By|Signed-off-by|Refs|Closes|Fixes):\s*(?P<value>.*)$")
BREAKING_RE = re.compile(r"^BREAKING[ -]CHANGE: \S", re.M)
LIST_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<marker>[-*+]|\d+[.)])(?P<space>\s+)")
CODE_RE = re.compile(r"^(    |\t)")
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


# ── scope 建议 ───────────────────────────────────────────────────────────────
def scope_of_path(path):
    for kind, val, sc in SCOPE_PATHS:
        if (path.startswith(val) if kind == "prefix" else path.endswith(val)):
            return sc
    return None


def suggest_scope(paths):
    """按改动文件给 scope 建议，返回 (scope, 命中数, 可映射总数, 样例路径) 或 None。"""
    hits, total, sample = {}, 0, {}
    for p in paths:
        sc = scope_of_path(p)
        if not sc:
            continue
        total += 1
        hits[sc] = hits.get(sc, 0) + 1
        sample.setdefault(sc, p)
    if not hits:
        return None
    best = max(hits, key=lambda k: hits[k])
    return best, hits[best], total, sample[best]


def _git_lines(*args):
    r = subprocess.run(["git", *args], capture_output=True, text=True)
    if r.returncode != 0:
        return []
    return [l.strip() for l in r.stdout.splitlines() if l.strip()]


def changed_paths():
    """本次提交涉及的文件：优先暂存区（commit-msg 时刻的真实范围）。"""
    staged = _git_lines("diff", "--cached", "--name-only")
    if staged:
        return staged
    return _git_lines("diff", "--name-only", "HEAD") + \
        _git_lines("ls-files", "--others", "--exclude-standard")


# ── 折行 ─────────────────────────────────────────────────────────────────────
def _char_chunks(word, limit):
    """无空格的长 token（中文段落）按显示宽度切；URL 不切（宁可超宽也不拆链接）。"""
    if "://" in word:
        return [word]
    out, acc = [], ""
    for ch in word:
        if acc and width(acc + ch) > limit:
            out.append(acc)
            acc = ch
        else:
            acc += ch
    if acc:
        out.append(acc)
    return out


def wrap_para(text, limit, first_prefix="", cont_prefix=""):
    lines, cur, prefix = [], "", first_prefix
    for word in text.split(" "):
        if not word:
            continue
        room = limit - max(width(first_prefix), width(cont_prefix))
        pieces = [word] if width(word) <= room else _char_chunks(word, room)
        for pi, piece in enumerate(pieces):
            sep = " " if (pi == 0 and cur) else ""
            if not cur:
                cur = piece
            elif width(prefix + cur + sep + piece) <= limit:
                cur += sep + piece
            else:
                lines.append(prefix + cur)
                prefix = cont_prefix
                cur = piece
    if cur:
        lines.append(prefix + cur)
    return lines


def wrap_block(blk, limit):
    if not blk.strip():
        return blk
    lines = blk.split("\n")
    if any(CODE_RE.match(l) for l in lines):
        return blk                                  # 缩进代码块：折行会破坏结构
    fm = FOOTER_RE.match(lines[0])
    if fm:
        text = (fm.group("value") + " " + " ".join(l.strip() for l in lines[1:])).strip()
        return "\n".join(wrap_para(text, limit, fm.group("token") + ": ", "  "))
    out, prose = [], []

    def flush_prose():
        if prose:
            out.extend(wrap_para(" ".join(l.strip() for l in prose), limit))
            del prose[:]

    i = 0
    while i < len(lines):
        m = LIST_RE.match(lines[i])
        if not m:
            prose.append(lines[i])
            i += 1
            continue
        flush_prose()
        item = [lines[i]]
        i += 1
        while i < len(lines) and not LIST_RE.match(lines[i]):
            item.append(lines[i])                   # 续行并入当前条目
            i += 1
        marker = m.group("marker") + m.group("space")
        text = (item[0][m.end():] + " " + " ".join(x.strip() for x in item[1:])).strip()
        out.extend(wrap_para(text, limit, m.group("indent") + marker,
                             m.group("indent") + " " * width(marker)))
    flush_prose()
    return "\n".join(out)


def wrap_message(text, limit=LINE_MAX):
    """只折正文；标题原样保留——标题超宽是「该重写」而不是「该折行」。"""
    trailing = "\n" if text.endswith("\n") else ""
    core = text[:-1] if trailing else text
    lines = core.split("\n")
    if len(lines) < 2:
        return text
    header, rest = lines[0], lines[1:]
    while rest and not rest[0].strip():
        rest.pop(0)                       # 标题与正文之间固定一个空行
    if not rest:
        return header + "\n" + trailing
    body = "\n".join(rest)
    wrapped = "\n\n".join(wrap_block(b, limit) for b in body.split("\n\n"))
    return header + "\n\n" + wrapped + trailing


# ── 校验 ─────────────────────────────────────────────────────────────────────
def check(text, paths=None):
    """返回 (errors, warnings)。空列表 = 通过。paths 非 None 时给出 scope 建议。"""
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

    suggestion = suggest_scope(paths) if paths is not None else None

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

    hint = ""
    if suggestion:
        sc, hits, total, sample = suggestion
        hint = "（本次改动 %d/%d 个文件在 %s，建议 scope: %s）" % (hits, total, sample, sc)
    if t not in TYPES:
        errs.append("type %s 不在词表：%s" % (t, " ".join(TYPES)))
    if scope is not None:
        if "," in scope:
            errs.append("scope 只能有一个：%s" % scope)
        elif re.match(r"^[ABC][0-9]+$", scope):
            errs.append("scope %s 是内部计划/评审编号（仓库外不可解；追溯写进正文），"
                        "应换成模块 scope%s" % (scope, hint))
        elif scope not in SCOPES:
            errs.append("scope %s 不在词表：%s%s" % (scope, " ".join(SCOPES), hint))
    elif suggestion:
        sc, hits, total, sample = suggestion
        warns.append("scope 省略；本次改动 %d/%d 个文件在 %s，建议 scope: %s"
                     % (hits, total, sample, sc))
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
        if CODE_RE.match(ln):                   # 缩进代码块：无法折行，按预格式化处理
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
                fm2 = FOOTER_RE.match(ln)
                if fm2:
                    errs.append("trailer「%s:」必须位于正文末尾，且与正文空一行" % fm2.group("token"))
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


# ── 子命令 ───────────────────────────────────────────────────────────────────
def read_text(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as f:
        return f.read()


def write_text(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def cmd_lint(args):
    text = read_text(args.file)
    if args.fix:
        fixed = wrap_message(text)
        if fixed != text:
            if args.file == "-":
                sys.stdout.write(fixed)
            else:
                write_text(args.file, fixed)
            print("已自动折行正文（上限 %d 显示列）" % LINE_MAX, file=sys.stderr)
            text = fixed
    paths = args.paths.split(",") if args.paths else changed_paths()
    errs, warns = check(text, paths=paths)
    for w in warns:
        print("提示：" + w, file=sys.stderr)
    if errs:
        print("✗ 提交信息不符合规范（CONTRIBUTING.md §5）", file=sys.stderr)
        for e in errs:
            print("  · " + e, file=sys.stderr)
        print("修正后重试：git commit --edit --file=" + args.file, file=sys.stderr)
        if any("显示列 >" in e for e in errs) and args.file != "-":
            print("或自动折行：python3 scripts/commit_msg.py lint --fix " + args.file,
                  file=sys.stderr)
        return 1
    return 0


def cmd_wrap(args):
    text = read_text(args.file)
    fixed = wrap_message(text, args.limit)
    if fixed == text:
        print("无需改动：正文已在 %d 显示列以内" % args.limit)
        return 0
    if args.check:
        print("需要折行：" + args.file, file=sys.stderr)
        return 1
    write_text(args.file, fixed)
    print("已折行 %s（上限 %d 显示列）" % (args.file, args.limit))
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
    ap = argparse.ArgumentParser(description="提交信息校验 / 折行 / CHANGELOG 生成")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("lint", help="校验提交信息（不合规 exit 1）")
    p1.add_argument("file", help="提交信息文件；- 表示 stdin")
    p1.add_argument("--fix", action="store_true", help="先按显示宽度自动折行正文，再校验")
    p1.add_argument("--paths", default="", help="逗号分隔的改动文件（scope 建议用；默认取 git 暂存区）")
    p1.set_defaults(func=cmd_lint)
    p2 = sub.add_parser("wrap", help="只把正文折到显示宽度以内")
    p2.add_argument("file")
    p2.add_argument("--limit", type=int, default=LINE_MAX)
    p2.add_argument("--check", action="store_true", help="只检查是否需要折行（需要时 exit 1），不写回")
    p2.set_defaults(func=cmd_wrap)
    p3 = sub.add_parser("changelog", help="按 conventional 类型生成 CHANGELOG")
    p3.add_argument("--range", default="", help="git 范围，默认最近 tag..HEAD")
    p3.add_argument("--version", default="", help="小节标题，默认当天日期")
    p3.add_argument("--output", default="", help="写入文件（已存在则在首个标题后插入）")
    p3.set_defaults(func=cmd_changelog)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
