#!/usr/bin/env python3
"""
统一测试入口：按改动文件自动选套件（tests/*.py 各脚本保持独立可跑）
====================================================================

    python3 tests/run.py                 # 默认：按本次改动匹配映射表后依次执行
    python3 tests/run.py --list          # 只打印将要执行的套件，不真正跑
    python3 tests/run.py --all           # 忽略映射，跑全部套件
    python3 tests/run.py --base <ref>    # 与指定提交对比（默认 HEAD，即未提交改动）
    python3 tests/run.py test_rules.py …  # 显式指定套件（同时跳过自动匹配）
    python3 tests/run.py --jobs 4        # Tier 0 白名单套件并行，其余仍串行

改动来源：`git diff --name-only <base>` + 未跟踪文件（新文件按整体内容匹配符号）。
映射规则：每个条目给出 **文件路径子串**（任一命中即选中）与 **符号**（该符号出现在
任一改动文件内容中即选中，二者为「或」）。改动为文档/脚本等未命中项时，
仍会跑「通用回归」基线——它对所有改动恒定生效。

对应 AGENTS.md「测试流程」映射表；两边需同步维护。
"""
import argparse
import concurrent.futures
import os
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TESTS = os.path.join(ROOT, "tests")

# (套件名, 路径子串, 符号, 说明)
SUITE_MAP = [
    # ── 基线：条目不给任何路径/符号谓词即恒定命中（IO/SQLite/并发 + 崩溃日志取证） ──
    (("test_functional.py", "test_crash_log.py"), (), (),
     "通用回归基线"),

    # ── AGENTS.md 映射表 ──
    (("test_rules.py", "test_config_snapshot.py", "test_monitor_layers.py",
      "test_decision_enforce.py"),
     ("src/daemon/fw_rules.c", "src/config/config_parser.c", "src/daemon/fuse_daemon.c"),
     ("fw_rules_resolve", "config_build_from_view", "parse_config_line"),
     "内建规则引擎(fw_rules) / fuse_daemon.c / config_parser.c"),

    (("test_ftp.py", "test_ftp_read_restart.py"),
     ("src/modules/ftp/",),
     ("module_backend_lookup", "module_backend_put", "backend_rename", "backend_read"),
     "src/modules/ftp/ 或框架后端分派"),

    (("test_ftp_parallel.py",),
     ("src/modules/ftp/ftp_mux.c",),
     ("backend_rc_is_business",),
     "ftp_mux.c 或 backend_rc_is_business"),

    (("test_path_vars.py",), ("src/config/path_vars.c",), (), "src/config/path_vars.c"),

    (("test_inject_method.py", "test_global_replace.py"),
     ("src/injector/inject_target.c",),
     ("inject-method",),
     "injector 目标判定 / 注入方法"),

    (("test_inject_mount_env.py",),
     ("src/injector/ns_utils.c", "src/injector/ns_global_replace.c"),
     ("cleanup_app_mounts",),
     "injector 挂载/清理序列"),

    (("test_modules.py", "test_module_circuit.py", "test_module_abi.py",
      "test_backend_lifecycle.py"),
     ("src/module/",), ("memfd_create", "module_backend_", "module_fault_poison"),
     "src/module/（加载器/内存副本加载/围栏/熔断/ABI）"),

    (("test_decision_enforce.py",), (),
     ("fw_route", "appear_missing", "vfs_check_read_only"), "决策强制单点（errno 矩阵）"),

    (("test_log_ctl_rules.py", "test_rule_server.py"),
     ("src/rule/", "src/log/log_ctl.c"),
     ("nsp_rule_file",),
     "log_ctl / rule_server 规则编辑"),

    (("test_log_pipeline.py",),
     ("src/log/", "src/core/nsp_comm.c", "include/nsp_comm.h", "include/nsp_log.h",
      "src/core/common.c", "src/core/nsp_util.c"),
     ("vfs_log_io", "monitor_on", "persist_stage", "drain_async", "log_internal",
      "fw_config_monitor_for", "nsp_log_level_name", "nsp_log_level_parse"),
     "日志链路（生产 → 通讯 → log_monitor → 查询）"),

    (("test_monitor_layers.py",),
     ("src/daemon/fw_config.c", "src/daemon/fw_config.h", "src/daemon/fw_pkg.c",
      "src/daemon/fw_pkg.h"),
     ("fw_config_monitor_for", "fw_pkg_resolve"),
     "监控开关三层合并 / uid→包名（框架权威）"),
]


def git(*args):
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    return r.stdout


def changed_paths(base):
    """本次改动的文件（相对仓库根）：已跟踪文件用 diff，新文件走未跟踪列表。"""
    tracked = set()
    for line in git("diff", "--name-only", base).splitlines():
        line = line.strip()
        if line:
            tracked.add(line)
    untracked = set()
    for line in git("ls-files", "--others", "--exclude-standard").splitlines():
        line = line.strip()
        if line:
            untracked.add(line)
    return sorted(tracked | untracked), sorted(untracked)


def is_source(path):
    """符号匹配只看构建输入（src/ include/ subprojects/）——测试脚本本身也含
    这些符号字面量（映射表），扫它会自我命中导致套件全选。"""
    return path.startswith(("src/", "include/", "subprojects/"))


def changed_lines_text(base, paths, untracked):
    """符号匹配的语料：**本次真正改动的行**（diff 的 +/- 行）+ 新文件的全文。

    只看改动行是为了让「符号型条目」精确——改了 fuse_daemon.c 不等于改了
    `backend_*` 分派分支；需要全量时用 --all 或显式指定套件。"""
    out = []
    for p in paths:
        if not is_source(p):
            continue
        if p in untracked:
            out.append(read_text(p))
            continue
        d = git("diff", "--unified=0", base, "--", p)
        for line in d.splitlines():
            if line.startswith(("+++", "---", "@@", "diff ", "index ", "new file")):
                continue
            if line[:1] in "+-":
                out.append(line[1:])
    return "\n".join(out)


def read_text(path):
    p = os.path.join(ROOT, path)
    if not os.path.isfile(p):
        return ""
    try:
        with open(p, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def select_suites(syms_text, paths):
    """按映射表选套件，按表内顺序去重返回。

    条目**既无路径子串也无符号**（如「通用回归基线」）视为恒定命中；
    否则路径子串命中**或**符号出现在改动行中即选中。"""
    picked = []
    matched_rows = []
    for suites, path_pats, syms, desc in SUITE_MAP:
        hit = not path_pats and not syms
        if not hit and path_pats:
            hit = any(pat in p for p in paths for pat in path_pats)
        if not hit and syms:
            hit = any(s in syms_text for s in syms)
        if hit:
            matched_rows.append(desc)
            for s in suites:
                if s not in picked:
                    picked.append(s)
    return picked, matched_rows


def all_suites():
    out = []
    for suites, *_ in SUITE_MAP:
        for s in suites:
            if s not in out:
                out.append(s)
    return sorted(out)


# Tier 0 并行白名单：逐个核对过无共享状态的套件（判据：无 FUSE 挂载，或
# 挂载点/CONF 全由 mkdtemp 派生自管；无固定端口；无全局 pkill；不碰系统
# log_monitor 与真实日志文件）。命中 --jobs 时仅这些进线程池并行，其余
# 按选中顺序串行。新套件默认串行，要加入须先核对判据。
PARALLEL_SAFE = frozenset({
    "test_config_snapshot.py",    # cc 编译夹具直跑，临时 config_dir
    "test_module_abi.py",         # cc 编译 ABI 夹具，无 daemon
    "test_path_vars.py",          # cc 编译直跑
    "test_monitor_layers.py",     # cc 编译实际源码 + 合成 uid，无挂载
    "test_log_ctl_rules.py",      # 全走 mkdtemp
    "test_inject_method.py",      # conf 全走 mkdtemp + global_replace_ctl 驱动
    "test_crash_log.py",          # --crash-test 挂载前退出，日志只写临时文件
    "test_backend_lifecycle.py",  # MNT/CONF 全由 mkdtemp 派生，自管 daemon
})
# 注意：test_rule_server.py 虽用临时 conf_dir，但 SERVICE 用例会 pkill -9 全局
# log_monitor 并拉起系统实例，与 test_log_pipeline.py 互斥，故不进白名单。


def run_suite(name, capture=False):
    """跑单个套件，返回 (rc, dt, output)。

    capture=False（串行默认）：子进程输出直接透传终端，行为与旧版一致。
    capture=True（并行用）：输出截获后由调用方在任务完成时统一打印，
    避免多套件刷屏交错；退出码原样回传（不用管道吞退出码）。
    """
    path = os.path.join(TESTS, name)
    if not os.path.exists(path):
        print(f"⚠ 缺少 {name}，跳过")
        return None, 0.0, ""
    t0 = time.time()
    if capture:
        r = subprocess.run([sys.executable, path], cwd=ROOT,
                           capture_output=True, text=True)
        dt = time.time() - t0
        return r.returncode, dt, r.stdout + r.stderr
    print(f"\n{'━' * 60}\n▶ {name}\n{'━' * 60}", flush=True)
    # 不用管道承接子进程输出：退出码须原样回传（AGENTS 失败处理要求）
    rc = subprocess.run([sys.executable, path], cwd=ROOT).returncode
    dt = time.time() - t0
    return rc, dt, ""


def run_parallel(safe, jobs):
    """Tier 0 套件并行：输出截获、按完成顺序打印，返回 {套件名: (rc, dt)}。"""
    done = {}
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(jobs, len(safe))) as pool:
        futs = {pool.submit(run_suite, s, True): s for s in safe}
        for fut in concurrent.futures.as_completed(futs):
            s = futs[fut]
            rc, dt, out = fut.result()
            if rc is None:
                continue
            print(f"\n{'━' * 60}\n▶ {s}（并行，{dt:.1f}s）\n{'━' * 60}",
                  flush=True)
            print(out, end="", flush=True)
            if rc != 0:
                print(f"\n❌ {s} 失败（退出码 {rc}，{dt:.1f}s）")
            done[s] = (rc, dt)
    return done


def main():
    ap = argparse.ArgumentParser(description="按改动文件自动选套件的统一测试入口")
    ap.add_argument("suites", nargs="*", help="显式指定要跑的 tests/*.py（跳过自动匹配）")
    ap.add_argument("--all", action="store_true", help="忽略映射，跑全部套件")
    ap.add_argument("--list", action="store_true", help="只列出将要执行的套件")
    ap.add_argument("--base", default="HEAD",
                    help="与该提交对比以确定改动（默认 HEAD = 暂存+未暂存+未跟踪）")
    ap.add_argument("--jobs", "-j", type=int, default=1,
                    help="Tier 0 套件（PARALLEL_SAFE 白名单）并行worker数，默认1即全串行")
    args = ap.parse_args()

    if args.suites:
        suites = [s if s.endswith(".py") else s + ".py" for s in args.suites]
        rows = ["显式指定"]
    elif args.all:
        suites, rows = all_suites(), ["--all 全量"]
    else:
        paths, untracked = changed_paths(args.base)
        if not paths:
            print(f"自 {args.base} 起无改动，仅跑通用回归基线")
        else:
            print(f"改动文件（对比 {args.base}，{len(paths)} 个）：")
            for p in paths:
                print(f"  {p}")
        syms_text = changed_lines_text(args.base, paths, untracked)
        suites, rows = select_suites(syms_text, paths)

    print("\n选中套件：")
    safe = [s for s in suites if s in PARALLEL_SAFE]
    excl = [s for s in suites if s not in PARALLEL_SAFE]
    for s in suites:
        tag = "并行" if s in PARALLEL_SAFE else "串行"
        print(f"  [{tag}] {s}")
    print("命中条目：" + ("、".join(rows) if rows else "无"))
    if args.list:
        return 0

    results = []
    if args.jobs > 1 and safe:
        # 先并行 Tier 0，再串行其余：挂载类/独占类之间仍保持原有顺序语义，
        # 且独占类（log_monitor/vsftpd/userns）不受并行任务干扰
        para = run_parallel(safe, args.jobs)
        by_name = dict(para)
        for s in suites:
            if s in by_name:
                rc, dt = by_name[s]
                results.append((s, rc, dt))
        suites = excl
    for s in suites:
        rc, dt, _ = run_suite(s)
        if rc is None:
            continue
        results.append((s, rc, dt))
        if rc != 0:
            print(f"\n❌ {s} 失败（退出码 {rc}，{dt:.1f}s）")

    print(f"\n{'═' * 60}")
    failed = [r for r in results if r[1] != 0]
    print(f"测试汇总 | ✅ {len(results) - len(failed)} 通过 | ❌ {len(failed)} 失败 | 共 {len(results)}")
    for s, rc, dt in results:
        mark = "✅" if rc == 0 else "❌"
        print(f"  {mark} {s:<34} {dt:6.1f}s  rc={rc}")
    if failed:
        print("存在失败套件——按 AGENTS.md 要求全绿方可提交")
    print("═" * 60)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
