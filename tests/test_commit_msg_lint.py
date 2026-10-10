#!/usr/bin/env python3
"""提交信息规范工具（scripts/commit_msg.py）的契约与判别性用例。

为什么需要这一套：规则写在 CONTRIBUTING.md §5，可执行形式是
scripts/commit_msg.py lint，由 .githooks/commit-msg 在每次提交时调用。
两边漂移（改了规则没改校验器，或反过来）会让规范悄悄失效——本套件钉住
各条规则的行为、正文折行（wrap / lint --fix）与 scope 建议，以及三件工件的形态。

判别性（本仓库最重要的一条）：**长度按显示宽度计，不按字符数计**。
  * 60 个 ASCII 字符的标题 = 60 列   -> 放行
  * 30 个汉字            = 60 列   -> 放行
  * 40 个汉字            = 40 字符但 80 列 -> 必须拒绝
按字符数计的实现（commitlint 的 header-max-length 默认口径）会放行第三种，
本仓库实测 25% 的正文行超宽正是这么来的。

退出码遵循 tests/run.py 约定：0 通过、1 失败。本套件无环境依赖，不会 gap。
"""
import importlib.util
import os
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOL = os.path.join(ROOT, "scripts", "commit_msg.py")
HOOK = os.path.join(ROOT, ".githooks", "commit-msg")
SETUP = os.path.join(ROOT, "scripts", "setup-hooks.sh")
TEMPLATE = os.path.join(ROOT, ".gitmessage")

GOOD = ("fix(fuse): 修复列举可见性漂移\n\n"
        "probe 与 getattr 现在走同一套前缀剥离。\n")

# (用例名, 提交信息, 期望退出码, 期望出现在输出里的子串或 None)
CASES = [
    ("合规 fix + 正文", GOOD, 0, None),
    ("合规 docs 免正文", "docs: 修正过期文档\n", 0, None),
    ("合规 chore 免正文", "chore: 忽略本机产物\n", 0, None),
    # ── 判别性：显示宽度 vs 字符数 ──
    ("标题 40 汉字 = 80 列 必须拒绝", "fix(fuse): " + "中" * 40 + "\n\n补充说明。\n", 1, "显示列"),
    ("标题 30 汉字 = 60 列 放行", "fix(fuse): " + "中" * 30 + "\n\n补充说明。\n", 0, None),
    ("标题 60 ASCII = 60 列 放行", "fix(fuse): " + "a" * 60 + "\n\n补充说明。\n", 0, None),
    # ── 标题 ──
    ("type 不在词表", "nope: 改点东西\n\n补充说明。\n", 1, "不在词表"),
    ("scope 不在词表", "fix(whatever): 改点东西\n\n补充说明。\n", 1, "不在词表"),
    ("scope 写了两个", "fix(fuse,ftp): 改点东西\n\n补充说明。\n", 1, "只能有一个"),
    ("标题含内部编号", "fix(B1): backing 仲裁门补 MONITOR 维度\n\n补充说明。\n", 1, "编号"),
    ("标题句末句号", "fix(fuse): 改点东西。\n\n补充说明。\n", 1, "句号"),
    ("标题含 + 挤了两件事", "fix(fuse): 甲 + 乙\n\n补充说明。\n", 1, "拆开"),
    ("标题与正文之间没空行", "fix(fuse): 改点东西\n补充说明。\n", 1, "空一行"),
    # ── 正文 ──
    ("非 docs/chore 正文可省", "fix(fuse): 改点东西\n", 0, None),
    ("正文无固定标签 放行", "fix(fuse): 改点东西\n\n凭什么对：x\n", 0, None),
    ("正文行超宽", "fix(fuse): 改点东西\n\n说明：" + "中" * 40 + "\n", 1, "正文第 3 行"),
    ("正文含 URL 的行豁免", "fix(fuse): 改点东西\n\n见 https://example.com/" + "a" * 120 + "\n", 0, None),
    ("正文缩进代码块豁免行宽", "fix(fuse): 改点东西\n\n补充说明。\n\n    " + "z" * 80 + "\n", 0, None),
    ("正文后接列表 放行", "fix(fuse): 改点东西\n\n要点：\n- 要点一\n", 0, None),
    # ── 破坏性变更 ──
    ("! 缺 BREAKING CHANGE", "refactor(fw)!: 规则引擎内建\n\n补充说明。\n", 1, "成对"),
    ("BREAKING CHANGE 缺 !", "refactor(fw): 规则引擎内建\n\n补充说明。\n\nBREAKING CHANGE: ABI 3→4\n", 1, "成对"),
    ("! 与 footer 成对 放行",
     "refactor(fw)!: 规则引擎内建\n\n补充说明。\n\nBREAKING CHANGE: ABI 3→4，旧模块须重编译。\n", 0, None),
    ("trailer 不在正文末尾",
     "fix(fuse): 改点东西\n\n补充说明。\n\nBREAKING CHANGE: 有\n\nCo-Authored-By: a@b.c\n", 1, "trailer"),
    # ── 跳过与引用 ──
    ("Merge 跳过", "Merge branch master\n", 0, None),
    ("Revert 跳过", 'Revert "fix: 改点东西"\n\nThis reverts commit 0123456789abcdef.\n', 0, None),
    ("fixup! 跳过", "fixup! fix(fuse): 改点东西\n", 0, None),
    ("引用未入库的本地材料", "fix(fuse): 改点东西\n\n见 review-findings-20261007.md。\n", 1, "本机材料"),
]


def lint(text):
    fd, path = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        p = subprocess.run([sys.executable, TOOL, "lint", path],
                           capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr
    finally:
        os.unlink(path)


def write_tmp(text):
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def run_tool(*args):
    return subprocess.run([sys.executable, TOOL, *args], capture_output=True, text=True)


def load_module():
    spec = importlib.util.spec_from_file_location("nsp_commit_msg", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check_artifacts(fails):
    for path, need_x in ((TOOL, True), (HOOK, True), (SETUP, True), (TEMPLATE, False)):
        if not os.path.exists(path):
            fails.append("缺少工件：" + os.path.relpath(path, ROOT))
            continue
        if need_x and not os.access(path, os.X_OK):
            fails.append("工件不可执行：" + os.path.relpath(path, ROOT))
    # 模板：首行必须是骨架，其余非空行必须全是 # 注释
    # （漏了 # 的提示行会被 git 当正文提交进去）
    if os.path.exists(TEMPLATE):
        with open(TEMPLATE, encoding="utf-8") as f:
            lines = f.read().splitlines()
        if not lines or not lines[0].startswith("<type>"):
            fails.append(".gitmessage 首行不是 <type>(<scope>)!: 骨架")
        for i, ln in enumerate(lines[1:], start=2):
            if ln.strip() and not ln.startswith("#"):
                fails.append(".gitmessage 第 %d 行不是 # 注释，会被提交进正文：%s" % (i, ln[:30]))


def check_changelog(fails):
    mod = load_module()
    c = mod.parse_commit("feat(fw): 规则引擎内建")
    if not c or c["type"] != "feat" or c["scope"] != "fw":
        fails.append("parse_commit 未正确解析 conventional 标题")
    if mod.parse_commit("Merge branch master") is not None:
        fails.append("parse_commit 应拒绝非 conventional 标题")
    if mod.parse_commit("refactor(fw)!: 收窄", "")["breaking"] is not True:
        fails.append("parse_commit 未识别 ! 破坏性标记")
    out = mod.render([{"type": "fix", "scope": "fuse", "desc": "甲", "hash": "0123456", "breaking": True}], "v1")
    for want in ("# Changelog", "### 缺陷修复", "### 破坏性变更", "**fuse**: 甲 (0123456)"):
        if want not in out:
            fails.append("render 输出缺少：" + want)
    p = subprocess.run([sys.executable, TOOL, "changelog", "--range", "HEAD..HEAD"],
                       capture_output=True, text=True, cwd=ROOT)
    if p.returncode != 0 or "# Changelog" not in p.stdout:
        fails.append("changelog 子命令端到端失败：rc=%d %s" % (p.returncode, p.stderr[:120]))


def check_wrap(fails):
    """折行：按显示宽度、保结构、幂等，折完必须能过 lint。"""
    mod = load_module()
    cases = {
        "中文长段落": "fix(fuse): 甲\n\n" + "中" * 90 + "\n",
        "要点+列表混排": "fix(fuse): 甲\n\n要点：\n- " + "乙" * 50 + "\n- 短的\n",
        "footer 折行": "fix(fuse)!: 甲\n\n补充说明。\n\nBREAKING CHANGE: " + "丙" * 60 + "\n",
    }
    for name, src in cases.items():
        path = write_tmp(src)
        try:
            if run_tool("wrap", path).returncode != 0:
                fails.append("wrap %s：退出码非 0" % name)
            out = open(path, encoding="utf-8").read()
            widest = max(mod.width(l) for l in out.splitlines())
            if widest > 72:
                fails.append("wrap %s：折行后仍有 %d 列" % (name, widest))
            if run_tool("wrap", "--check", path).returncode != 0:
                fails.append("wrap %s：不幂等（二次检查仍要改）" % name)
            if run_tool("lint", path).returncode != 0:
                fails.append("wrap %s：折行后仍不合规" % name)
            if not out.startswith(src.split("\n")[0] + "\n\n"):
                fails.append("wrap %s：标题或标题后的空行被改动" % name)
        finally:
            os.unlink(path)

    # 结构保持：列表项不被并进上一段；URL 不被拆；缩进代码块原样
    path = write_tmp("fix(fuse): 甲\n\n要点：\n- " + "乙" * 50 + "\n- 短的\n")
    try:
        run_tool("wrap", path)
        out = open(path, encoding="utf-8").read()
        if "- 短的" not in out or "要点：\n- " not in out:
            fails.append("wrap：列表项结构被破坏（被并成一段）")
    finally:
        os.unlink(path)
    url = "https://example.com/" + "a" * 100
    path = write_tmp("fix(fuse): 甲\n\n见 " + url + "\n")
    try:
        run_tool("wrap", path)
        if url not in open(path, encoding="utf-8").read():
            fails.append("wrap：URL 被拆断")
    finally:
        os.unlink(path)
    code = "    " + "z" * 80
    path = write_tmp("fix(fuse): 甲\n\n补充说明。\n\n" + code + "\n")
    try:
        run_tool("wrap", path)
        if code not in open(path, encoding="utf-8").read():
            fails.append("wrap：缩进代码块被折行破坏")
    finally:
        os.unlink(path)

    # lint --fix 一步修到合规
    path = write_tmp("fix(fuse): 甲\n\n" + "中" * 90 + "\n")
    try:
        p = run_tool("lint", "--fix", path)
        if p.returncode != 0:
            fails.append("lint --fix：未把超宽正文修到合规｜" + (p.stdout + p.stderr)[:120])
    finally:
        os.unlink(path)


def check_scope_suggest(fails):
    """scope 建议：按改动路径给出候选，且只提示不判定。"""
    mod = load_module()
    for paths, want in ((["src/modules/ftp/ftp_mux.c", "tests/test_ftp.py"], "ftp"),
                        (["src/injector/ns_utils.c", "src/injector/injector.c"], "injector"),
                        (["scripts/commit_msg.py"], "scripts"),
                        (["meson.build"], "build")):
        got = mod.suggest_scope(paths)
        if not got or got[0] != want:
            fails.append("suggest_scope(%s) 期望 %s，实际 %s" % (paths, want, got))
    if mod.suggest_scope(["no/such/path.xyz"]) is not None:
        fails.append("suggest_scope 对无法映射的路径应返回 None")

    path = write_tmp("fix(nope): 改点东西\n\n补充说明。\n")
    try:
        p = run_tool("lint", "--paths", "src/modules/ftp/ftp_mux.c", path)
        if p.returncode != 1 or "建议 scope: ftp" not in p.stdout + p.stderr:
            fails.append("lint：scope 不在词表时未给出建议")
    finally:
        os.unlink(path)
    path = write_tmp("fix: 改点东西\n\n补充说明。\n")
    try:
        p = run_tool("lint", "--paths", "src/injector/ns_utils.c", path)
        if p.returncode != 0:
            fails.append("lint：scope 省略不应判失败")
        if "建议 scope: injector" not in p.stderr:
            fails.append("lint：scope 省略时未给出建议")
    finally:
        os.unlink(path)


def main():
    print("=" * 64)
    print("提交信息规范工具（lint + wrap + changelog）")
    print("=" * 64)
    fails = []
    check_artifacts(fails)
    check_changelog(fails)
    check_wrap(fails)
    check_scope_suggest(fails)

    for name, text, want_rc, want_sub in CASES:
        rc, out = lint(text)
        if rc != want_rc:
            fails.append("%s：期望 exit=%d，实际 %d｜%s" % (name, want_rc, rc, out.strip().replace("\n", " ")[:140]))
            continue
        if want_sub and want_sub not in out:
            fails.append("%s：输出未包含 %r｜%s" % (name, want_sub, out.strip().replace("\n", " ")[:140]))

    total = len(CASES)
    if fails:
        print("✗ %d/%d 用例失败：" % (len(fails), total))
        for f in fails:
            print("  · " + f)
        return 1
    print("✅ 全部通过：%d 个提交信息用例 + 工件形态 + 折行契约 + scope 建议 + changelog 契约" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
