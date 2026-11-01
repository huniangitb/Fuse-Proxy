#!/usr/bin/env python3
"""文档 / 测试台账一致性（恒跑的 L0 契约套件）
==============================================

本仓库的文档是**契约**（AGENTS.md「文档即契约」），但此前没有任何机制校验它。
实测结果：一次全量审计在 4 份文档里查出约 30 处与代码矛盾的陈述，其中
`docs/architecture.md` 把 `NSP_MODULE_ABI_VERSION` 写成 4（实际 5）——模块作者
照文档编出来的 .so 会被加载器当场拒绝。同时 38 个套件里有 13 个没被任何验收层
点名，`test_ftp_stress.py` 则长期游离在 `--all` 之外，看不出是有意按需还是漏登记。

这个套件把「能机器判定的文档陈述」变成断言。它不审文风，只查**可证伪**的点：

  1. 套件台账闭合：tests/test_*.py ⊆ SUITE_MAP ∪ ON_DEMAND，且 SUITE_MAP 里的
     套件文件真实存在（拼错名字此前只在真跑时才报 rc=127）。
  2. 分层完整：SUITE_MAP 里每个套件恰好属于一个 LAYERS 层——漏登记意味着
     `--layer` 的分层验收跑不到它，而那正是对外宣称的验收流程。
  3. Tier 自洽：PARALLEL_SAFE / TIER_EXCLUSIVE 不得指向未知套件，且两者互斥
     （同时出现在并行白名单与独占 Tier 里是矛盾配置）。
  4. 版本号：文档里写出的 NSP_MODULE_ABI_VERSION / NSP_FRAMEWORK_API_VERSION
     必须等于 include/nsp_module.h 的实际值。
  5. 路径引用：文档里形如 src/… include/… scripts/… tests/… 的路径必须存在
     （外部骨架脚本与示例占位符走 EXTERNAL_PATHS 豁免，豁免项需写明理由）。
  6. 退出码契约：docs/testing.md 写出的 77/78/127 与 run.py 的常量一致。
  7. 已删标识符不得以「现行机制」的口吻出现在文档里（canary / NSP_CAP_* /
     module_dispatch_resolve 等 V3/V4 删除物）——这是审计里占比最大的一类错误。
  8. 受检文档齐全：DOCS 列出的每份文档都必须存在。
  9. 源码树覆盖：每个 src/**/*.c 与 include/*.h 都必须被某条 SUITE_MAP 路径谓词
     命中（或登记进 SOURCE_COVER_EXEMPT 并写明理由）。否则改它只会跑恒跑基线，
     对应套件不会被选中——那是一片没有任何断言的绿色。

退出码遵循 tests/run.py 约定：0 通过、1 失败。本套件无环境依赖，不会 gap。
"""
import os
import re
import sys
import importlib.util

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TESTS = os.path.join(ROOT, "tests")

# 受检文档：对外契约（docs/ + README）与 agent 工作手册（AGENTS.md）
DOCS = [
    "README.md",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "docs/README.md",
    "docs/architecture.md",
    "docs/modules.md",
    "docs/config.md",
    "docs/testing.md",
]

# 路径引用豁免：不在本仓库但文档必须提到的东西。每条都要有理由，
# 否则「加豁免」会变成绕过检查的后门。
EXTERNAL_PATHS = {
    "service.sh": "Magisk 模块骨架脚本，在外部骨架仓库（scripts/pack-module.sh 同步进去）",
    "customize.sh": "同上，Magisk 安装脚本",
    "module.prop": "同上，Magisk 模块元数据",
    "FUSE-EVENTS.md": "跨项目接口契约，在 Media-Provider-Manager 仓库（docs/architecture.md §4.7 引用其 v5 冻结版）",
    "my_module.c": "docs/modules.md §6 第三方模块示例占位名",
    "my_module.so": "同上",
    "execinfo.h": "glibc 系统头（backtrace，libfuse 链接依赖）",
    "sitecustomize.py": "宿主 CLI 注入的垫片（WorkBuddy/CodeBuddy），不在本仓库",
    "io.log": "运行期日志文件（LOG_DIR 下，构建产物之外）",
    "sys.log": "同上",
    "daemon.log": "同上",
    "module_errors.log": "同上",
    "uid.map": "运行期生成的 uid→包名映射（CONFIG_DIR 下）",
    "sys_pkgs.cache": "运行期生成的系统包缓存（CONFIG_DIR 下）",
    "injector.conf": "运行期配置（CONFIG_DIR 下；conf/ 里是示例）",
    "ftp.conf": "同上，FTP 模块运行期配置",
    "persistent_io.log": "debug 构建下 persist_io_log 写的独立文件，非仓库文件",
    "shell-runtime-bash-env.sh": "宿主 CLI（WorkBuddy/CodeBuddy）注入的 BASH_ENV，不在本仓库",
    "fuse.c": "libfuse 子模块内的 lib/fuse.c（subprojects/libfuse，按上游路径提及）",
    "fuse_versionscript": "同上，libfuse 导出版本脚本",
    "br_rules.c": "V4 前模块侧的规则引擎文件，已原样搬入 src/daemon/fw_rules.c，按历史提及",
    "test_libfuse_inval.py": "已移除的探针套件（本机随机挂起），文档按历史提及",
    "basic_rules.rules": "V4 前规则模块的规则文件，按历史提及",
    "compile_commands.json": "Meson 生成在构建目录内，非仓库文件",
}

# 已随 V3/V4 删除的标识符：文档不得以现行机制的口吻描述它们。
# 允许在「历史/演进」语境中出现，故只在**同一行**没有历史标记词时才判失败。
# 注：`br_get_app_cfg` 不在此列——它仍在，只是已搬进框架（src/daemon/fw_rules.c
# 的 static 函数）；真正没了的是模块侧那份副本与 br_rules.c 这个文件名。
REMOVED_IDENTS = [
    "module_dispatch_resolve",
    "nsp_resolve_result_init",
    "NspResolveGuard",
    "NspResolveResult",
    "nsp_decision_init",
    "NspDecisionGuard",
    "NSP_CAP_BACKEND_IO",
    "NSP_CAP_RULES",
    "NSP_MODULE_TYPE_",
    "vfs_apply_attr_override",
    "br_rules.c",
    "basic_rules.so",
    "RETIRED_MODULES",
    "attr_override",
    "NSP_OV_",
]
# 行内出现这些词即视为「在讲历史」，不判失败。
HISTORY_MARKERS = (
    "已删", "删除", "移除", "不再", "此前", "旧版", "历史", "曾", "V1→V2", "V2→V3",
    "V3→V4", "V4→V5", "改为", "取代", "原", "退役", "弃用", "过去", "之前",
)

# 成段的历史记录（如 docs/modules.md 的 V3 ABI 旧语义）用显式区域标记圈起来：
#
#     <!-- history:begin 为什么保留这段历史 -->
#     …（整段不受「已删标识符」检查）…
#     <!-- history:end -->
#
# 用显式标记而不是「按标题猜」，是因为同一节里往往历史与现行混排——
# docs/modules.md §3.3 就是上半段讲 V3 的 resolve、下半段讲现行后端方法。
# 标记本身也是给读者的提示：这段别照着写新代码。
HISTORY_BEGIN = "<!-- history:begin"
HISTORY_END = "<!-- history:end"


def history_mask(lines):
    """返回与 lines 等长的 bool 列表：True = 该行在显式历史区域内。"""
    mask = [False] * len(lines)
    depth = 0
    for i, line in enumerate(lines):
        if HISTORY_BEGIN in line:
            depth += 1
            mask[i] = True
            continue
        if HISTORY_END in line:
            depth = max(0, depth - 1)
            mask[i] = True
            continue
        mask[i] = depth > 0
    return mask


failures = []
checked = 0


def fail(msg):
    failures.append(msg)


def read(rel):
    p = os.path.join(ROOT, rel)
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8", errors="ignore") as f:
        return f.read()


def load_runner():
    spec = importlib.util.spec_from_file_location("nsp_run", os.path.join(TESTS, "run.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ── 1. 套件台账闭合 ────────────────────────────────────────────────────────
def check_suite_ledger(run):
    global checked
    # tests/ 下的每个 .py 都是套件，唯独两个例外：run.py 是统一入口本身；
    # `_*.py` 预留为共享助手模块（见结构评审：抽 tests/_harness.py 收口样板）。
    # 此前只 glob `test_*.py`，`stress_fuse.py` 因此完全逃过台账检查。
    disk = {f for f in os.listdir(TESTS)
            if f.endswith(".py") and f != "run.py" and not f.startswith("_")}
    mapped = set(run.all_suites())
    on_demand = set(run.ON_DEMAND)

    for s in sorted(disk - mapped - on_demand):
        fail(f"[台账] tests/{s} 既不在 SUITE_MAP 也不在 ON_DEMAND："
             f"`--all` 永远跑不到它。按改动映射登记进 SUITE_MAP，"
             f"或（压力/基准类）登记进 ON_DEMAND 并注明理由")
    for s in sorted(mapped):
        if s not in disk:
            fail(f"[台账] SUITE_MAP 登记了 tests/{s}，但文件不存在"
                 f"（真跑时 rc=127 计为失败）")
    for s in sorted(on_demand):
        if s not in disk:
            fail(f"[台账] ON_DEMAND 登记了 tests/{s}，但文件不存在")
    overlap = mapped & on_demand
    if overlap:
        fail(f"[台账] 同时登记在 SUITE_MAP 与 ON_DEMAND：{sorted(overlap)}"
             f"（按需套件不该被 --all 选中）")
    checked += 1
    return mapped


# ── 2. 分层完整 ───────────────────────────────────────────────────────────
def check_layers(run, mapped):
    global checked
    seen = {}
    for layer, (desc, suites) in run.LAYERS.items():
        if not desc.strip():
            fail(f"[分层] {layer} 缺少说明文字")
        for s in suites:
            if s in seen:
                fail(f"[分层] tests/{s} 同时属于 {seen[s]} 与 {layer}："
                     f"一个套件只能属一层")
            seen[s] = layer
            if s not in mapped and s not in run.ON_DEMAND:
                fail(f"[分层] {layer} 点名了 tests/{s}，但它不在 SUITE_MAP"
                     f"（分层跑得到、改动映射跑不到，口径不一致）")
    for s in sorted(mapped - set(seen)):
        fail(f"[分层] tests/{s} 未归入任何验收层："
             f"`run.py --layer` 的分层验收跑不到它。登记进 LAYERS 的 L0/L1/L2")
    checked += 1


# ── 3. Tier 自洽 ──────────────────────────────────────────────────────────
def check_tiers(run, mapped):
    global checked
    for s in sorted(run.PARALLEL_SAFE):
        if s not in mapped:
            fail(f"[Tier] PARALLEL_SAFE 含未知套件 tests/{s}")
    for s in sorted(run.TIER_EXCLUSIVE):
        if s not in mapped:
            fail(f"[Tier] TIER_EXCLUSIVE 含未知套件 tests/{s}")
    both = run.PARALLEL_SAFE & run.TIER_EXCLUSIVE
    if both:
        fail(f"[Tier] 既在并行白名单又在独占 Tier：{sorted(both)}")
    checked += 1


# ── 4. ABI / API 版本号 ───────────────────────────────────────────────────
def check_versions():
    global checked
    hdr = read("include/nsp_module.h")
    if hdr is None:
        fail("[版本] 找不到 include/nsp_module.h")
        return
    real = {}
    for macro in ("NSP_MODULE_ABI_VERSION", "NSP_FRAMEWORK_API_VERSION"):
        m = re.search(rf"#define\s+{macro}\s+(\d+)u?", hdr)
        if not m:
            fail(f"[版本] include/nsp_module.h 里找不到 #define {macro}")
            continue
        real[macro] = int(m.group(1))

    # 文档里形如 `NSP_MODULE_ABI_VERSION=5` / `NSP_MODULE_ABI_VERSION 为 5` /
    # 「当前 `NSP_MODULE_ABI_VERSION=5`」都要抓到
    for rel in DOCS:
        text = read(rel)
        if text is None:
            continue
        for ln, line in enumerate(text.splitlines(), 1):
            for macro, want in real.items():
                for m in re.finditer(rf"{macro}\s*(?:=|==|为|是)\s*`?(\d+)", line):
                    got = int(m.group(1))
                    if got != want:
                        fail(f"[版本] {rel}:{ln} 写 {macro}={got}，"
                             f"实际 include/nsp_module.h 是 {want}"
                             f"（照错版本编的模块会被加载器拒绝）")
    checked += 1


# ── 5. 文档路径引用 ───────────────────────────────────────────────────────
# 路径 token 提取：带目录前缀的相对路径，或裸文件名 + 已知扩展名。
# 末尾的 (?![A-Za-z0-9_]) 是必需的——没有它，`github.com` 会被切成 `github.c`、
# `ftp.conf` 切成 `ftp.c`、`sys_pkgs.cache` 切成 `sys_pkgs.c`，全是假阳性。
PATH_RE = re.compile(
    r"(?:(?:src|include|scripts|tests|tools|conf|compat|subprojects|docs)/"
    r"[A-Za-z0-9_./\-]*"
    r"|[A-Za-z0-9_\-]+\.(?:c|cpp|h|hpp|py|sh|ini|rules|build|prop|json|md|conf|cache|map|log))"
    r"(?![A-Za-z0-9_])"
)


def check_doc_paths():
    global checked
    for rel in DOCS:
        text = read(rel)
        if text is None:
            continue
        for ln, line in enumerate(text.splitlines(), 1):
            for m in PATH_RE.finditer(line):
                tok = m.group(0)
                # 紧跟通配符的是**前缀占位**（`tests/test_*.py`、`src/zygisk/*.so`）：
                # 正则的字符类在 `*` 处停下，token 会是半截的 `tests/test_`，
                # 当成真路径去查必然不存在。看原文下一个字符来判别。
                nxt = line[m.end():m.end() + 1]
                if nxt in ("*", "?", "{", "<"):
                    continue
                tok = tok.rstrip("./")
                if not tok or tok in EXTERNAL_PATHS:
                    continue
                base = os.path.basename(tok)
                if base in EXTERNAL_PATHS:
                    continue
                # 目录通配/占位（`src/modules/<名>/`）不查
                if any(c in tok for c in "<>*?"):
                    continue
                if os.path.exists(os.path.join(ROOT, tok)):
                    continue
                # 裸文件名（不带目录）：全仓库找同名文件即算命中——文档常以
                # `fw_rules.c` 这样的短名指代源文件
                if "/" not in tok:
                    hit = False
                    for dirpath, dirnames, filenames in os.walk(ROOT):
                        dirnames[:] = [d for d in dirnames
                                       if not d.startswith((".", "build", "subprojects"))]
                        if base in filenames:
                            hit = True
                            break
                    if hit:
                        continue
                fail(f"[路径] {rel}:{ln} 引用了不存在的路径 `{tok}`"
                     f"（若为外部/占位，登记进 EXTERNAL_PATHS 并写明理由）")
    checked += 1


# ── 6. 退出码契约 ─────────────────────────────────────────────────────────
def check_exit_codes(run):
    global checked
    text = read("docs/testing.md")
    if text is None:
        fail("[退出码] 缺 docs/testing.md（测试与验收手册）")
        return
    # 只认退出码表里**自成一格**的单元格（`| `127` | …`），不认散文顺带提及，
    # 也不认恰好含该数字的别的表格。两次放宽都被实测绕过：
    #   ① 只查「数字出现在文件任意处」→ 删掉整行表格仍通过（§2 散文里还有 127）；
    #   ② 放宽到「出现在任意表格行」→ 仍通过（前置条件表里有 127.0.0.1:21）。
    cell_re = {code: re.compile(rf"^\|\s*`?{code}`?\s*\|")
               for code in (run.SKIP_RC, run.GAP_RC, run.MISSING_RC)}
    rows = [ln.lstrip() for ln in text.splitlines() if ln.lstrip().startswith("|")]
    for name, want in (("SKIP_RC", run.SKIP_RC), ("GAP_RC", run.GAP_RC),
                       ("MISSING_RC", run.MISSING_RC)):
        if not any(cell_re[want].match(r) for r in rows):
            fail(f"[退出码] docs/testing.md 的退出码表里没有首列为 {want} 的行"
                 f"（{name}；退出码约定是防假绿的核心，手册必须成表写明）")
    checked += 1


# ── 7. 已删标识符不得以现行机制口吻出现 ──────────────────────────────────
def check_removed_idents():
    global checked
    for rel in DOCS:
        text = read(rel)
        if text is None:
            continue
        lines = text.splitlines()
        mask = history_mask(lines)
        unclosed = text.count(HISTORY_BEGIN) - text.count(HISTORY_END)
        if unclosed:
            fail(f"[已删] {rel} 的 history:begin/end 不配对（差 {unclosed} 个）："
                 f"未闭合的历史区域会把后文整段豁免掉")
        for ln, line in enumerate(lines, 1):
            if mask[ln - 1]:
                continue
            if any(mk in line for mk in HISTORY_MARKERS):
                continue
            for ident in REMOVED_IDENTS:
                if ident in line:
                    fail(f"[已删] {rel}:{ln} 以现行机制口吻提到已删除的 "
                         f"`{ident}`：{line.strip()[:70]}"
                         f"…（讲历史请在同行写明「已删/不再/此前」等，"
                         f"或用 history:begin/end 圈起整段）")
    checked += 1


# ── 8. 受检文档齐全 ───────────────────────────────────────────────────────
def check_docs_exist():
    global checked
    for rel in DOCS:
        if read(rel) is None:
            fail(f"[文档] 受检文档缺失：{rel}")
    checked += 1


# ── 9. 源码树覆盖：改任何源文件都必须能选中一个有目标的套件 ────────────────
# run.py 按「路径谓词 or 符号谓词」选套件；两者都不命中的文件改了就只跑恒跑
# 基线——那是一片没有任何断言的绿色。实测（2026-10-11）13 个 src/**/*.c 与
# 24 个 include/*.h 处于这种状态，其中 include/nsp_module.h（模块 ABI 唯一入口）
# 改动不跑 test_module_abi.py、src/core/path_trie.c（规则匹配核心）改动不跑
# test_rules.py。本组把「源码 → 套件」的台账也闭合掉。
#
# 豁免表：必须写明理由，且理由只能是「由恒跑基线套件覆盖」这类**可核对的**事实，
# 不接受「暂时没写」——那正是本检查要拦的东西。
SOURCE_COVER_EXEMPT = {
    "src/daemon/fuse_thread_naming.c":
        "仅截持 pthread_create 改线程名（无行为断言可写）；恒跑基线 "
        "test_functional.py 每次起 daemon 都在验证该截持不破坏建线程",
}


def check_source_coverage(run):
    global checked
    pats = [p for _suites, pp, _syms, _desc in run.SUITE_MAP for p in pp]
    # 覆盖对象：全部 src/**/*.c（行为所在）与 include/*.h（跨文件契约所在）。
    # 不含 src/**/*.h：那些是子系统私有头，与其 .c 同生共死；逐条登记只会
    # 随拆分 TU 增长成噪声，而真正要堵的是「改了核心源码却只跑基线」。
    targets = []
    for dirpath, _dirs, files in os.walk(os.path.join(ROOT, "src")):
        for f in files:
            if f.endswith(".c"):
                targets.append(os.path.relpath(os.path.join(dirpath, f), ROOT))
    targets += ["include/" + f for f in os.listdir(os.path.join(ROOT, "include"))
                if f.endswith(".h")]

    for rel in sorted(targets):
        if rel in SOURCE_COVER_EXEMPT:
            continue
        if any(p in rel for p in pats):
            continue
        fail(f"[覆盖] {rel} 不在任何 SUITE_MAP 路径谓词里：改动它只会跑恒跑基线，"
             f"对应套件不会被选中。加进合适的条目，或登记进 SOURCE_COVER_EXEMPT"
             f" 并写明理由")
    for rel, why in SOURCE_COVER_EXEMPT.items():
        if not os.path.exists(os.path.join(ROOT, rel)):
            fail(f"[覆盖] SOURCE_COVER_EXEMPT 里的 {rel} 已不存在（豁免过期，请删）")
        elif not why.strip():
            fail(f"[覆盖] SOURCE_COVER_EXEMPT 的 {rel} 缺理由")
    checked += 1


def main():
    print("═" * 64)
    print("文档 / 测试台账一致性（L0 契约，无环境依赖）")
    print("═" * 64)
    run = load_runner()

    check_docs_exist()
    mapped = check_suite_ledger(run)
    check_layers(run, mapped)
    check_tiers(run, mapped)
    check_versions()
    check_doc_paths()
    check_exit_codes(run)
    check_removed_idents()
    check_source_coverage(run)

    print(f"\n已跑检查组：{checked}")
    print(f"套件台账：SUITE_MAP {len(mapped)} 个 + ON_DEMAND {len(run.ON_DEMAND)} 个")
    for layer in sorted(run.LAYERS):
        desc, suites = run.LAYERS[layer]
        print(f"  {layer} {desc}：{len(suites)} 套件")

    if failures:
        print(f"\n❌ 失败 {len(failures)} 项：")
        for i, msg in enumerate(failures, 1):
            print(f"  {i:>2}. {msg}")
        print("═" * 64)
        return 1
    print("\n✅ 全部通过：文档陈述与代码/台账一致")
    print("═" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
