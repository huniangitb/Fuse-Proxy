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
    python3 tests/run.py --strict        # 验收模式：跳过项（gap）计为失败

改动来源：`git diff --name-only <base>` + 未跟踪文件（新文件按整体内容匹配符号）。
映射规则：每个条目给出 **文件路径子串**（任一命中即选中）与 **符号**（该符号出现在
任一改动文件内容中即选中，二者为「或」）。改动为文档/脚本等未命中项时，
仍会跑「通用回归」基线——它对所有改动恒定生效。

对应 AGENTS.md「测试流程」映射表；两边需同步维护。

退出码约定（防「假绿」）：
  0   = 全部通过
  1   = 存在失败，或 --strict 下存在跳过/部分跳过
  77  = 单套件「环境不具备，整套跳过」（gap，不计通过）
  78  = 单套件「部分子组跳过」（跑了一部分，仍有子组 gap；不计通过）
  127 = 套件文件不存在（计为失败——此前按「跳过」处理，拼错名字也 rc=0）

宿主环境坑：WorkBuddy/CodeBuddy CLI 会注入 PYTHONPATH（sitecustomize 把
unlink/rmtree 重定向到回收站）与 BASH_ENV（safe-bin 垫 PATH），会让删文件的
套件假失败。跑测试请剥掉：
  env -u PYTHONPATH -u BASH_ENV PATH="/usr/local/bin:/usr/bin:/bin" python3 tests/run.py --all
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
      "test_decision_enforce.py", "test_negative_timeout.py",
      "test_readdir_skel_fallback.py", "test_backing_gate.py"),
     ("src/daemon/fw_rules.c", "src/daemon/fw_rules.h", "src/config/config_parser.c",
      "src/daemon/fuse_daemon.c"),
     ("fw_rules_resolve", "config_build_from_view", "parse_config_line",
      "fw_data_mediation_required", "fw_backing_mediation_required_for"),
     "内建规则引擎(fw_rules) / fuse_daemon.c / config_parser.c"),

    (("test_ftp.py", "test_ftp_read_restart.py", "test_ftp_truncate_list.py",
      "test_ftp_upload_lock.py"),
     ("src/modules/ftp/",),
     ("module_backend_lookup", "module_backend_put", "backend_rename", "backend_read",
      "ftp_backend_truncate", "ftp_list_cache_clear", "ftp_backend_upload",
      # fsync 与 FLUSH 共用后端收尾（vfs_fsync 不再是空操作）→ 改这些行必须跑 ftp
      "vfs_backend_finish_data", "vfs_fsync", "backend_flush"),
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

    (("test_inject_mount_env.py", "test_ns_combined_rollback.py"),
     ("src/injector/ns_utils.c", "src/injector/ns_global_replace.c"),
     ("cleanup_app_mounts", "do_combined_mount"),
     "injector 挂载/清理序列"),

    (("test_reaped_managed.py",),
     ("src/injector/reaped_managed.c", "src/injector/reaped_managed.h",
      "src/injector/injector.c"),
     ("reaped_managed_put", "reaped_managed_exited", "reap_zombies"),
     "受管子进程收尸留档（崩溃现场入日志环）"),

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
      "src/core/common.c", "src/core/nsp_util.c", "include/nsp_util.h"),
     ("vfs_log_io", "monitor_on", "persist_stage", "drain_async", "log_internal",
      "fw_config_monitor_for", "nsp_log_level_name", "nsp_log_level_parse",
      "nsp_getline_capped", "nsp_snprintf_dyn", "nsp_format_dynamic"),
     "日志链路（生产 → 通讯 → log_monitor → 查询）"),

    # fw_config.c 含规则文件/App-rules 的 inotify 监听线程——热重载触发路径本身，
    # 故改动它同时跑 test_rules.py（重载语义端到端）
    (("test_monitor_layers.py", "test_cfg_watch.py", "test_rules.py"),
     ("src/daemon/fw_config.c", "src/daemon/fw_config.h", "src/daemon/fw_pkg.c",
      "src/daemon/fw_pkg.h"),
     ("fw_config_monitor_for", "fw_pkg_resolve"),
     "监控开关三层合并 / uid→包名（框架权威）"),

    (("test_pending_close.py",),
     ("src/daemon/fd_close_queue.c", "src/daemon/fd_close_queue.h"),
     ("fdq_defer", "fdq_flush"),
     "延迟 close 环形队列（Android backing fd 回收）"),

    (("test_cfg_watch.py",),
     ("src/daemon/cfg_watch.c", "src/daemon/cfg_watch.h"),
     ("cfg_watch_sync",),
     "配置目录 watch 对账（App-rules 子目录热更新）"),

    (("test_rule_file_lock.py", "test_log_ctl_rules.py", "test_rule_server.py"),
     ("src/core/nsp_rule_file.c", "src/core/nsp_rule_file.h"),
     ("nsp_rule_file_write", "nsp_rule_file_app_active_path"),
     "规则文件编辑（nsp_rule_file：并发/持久性/停用态路径）"),
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


# ── 共享状态冲突矩阵（逐个审计 tests/test_*.py 得出，2026-10）──
# 资源 R1 固定 CONF=/tmp/Namespace-Proxy/injector.conf：
#   test_functional / test_rules / test_ftp / test_ftp_parallel /
#   test_modules / test_module_circuit / test_decision_enforce /
#   test_log_pipeline（各写各的规则内容，串行才安全）
# 资源 R2 /tmp/fuse_proxy_test 基目录复用：
#   test_functional(mnt/modules/storage) 与 test_log_pipeline(BASE 同名) 直接重合；
#   test_inject_mount_env(ROOTBASE=…/mnt_env) 同前缀（但跑在 unshare 沙箱内）
# 资源 R3 全局 pkill：test_functional / test_rules(pkill -f fuse_daemon 会杀掉
#   别人刚起的 daemon)；test_log_pipeline / test_rule_server(SERVICE 段)
#   pkill -9 -x log_monitor（会杀掉别人的 monitor）
# 资源 R4 vsftpd 127.0.0.1:21 + 服务端目录 /home/bdy/ftp/upload（服务端文件互见）：
#   test_ftp / test_ftp_parallel / test_ftp_stress 三者互斥
# 资源 R5 固定中继端口 127.0.0.1:2121：test_ftp_parallel 独占绑定
# 资源 R6 全局 log_monitor（抽象套接字 nsp_log_socket 单例 + 系统 LOG_DIR）：
#   test_log_pipeline（重启系统实例 + 备份还原 /var/fuse-proxy/log 下 io/sys.log）
#   与 test_rule_server（SERVICE 启停拉起系统 log_monitor）互斥，
#   且二者与 test_inject_mount_env（沙箱内自起 log_monitor -p）互斥
# 资源 R7 系统配置 /var/fuse-proxy/injector.conf：test_inject_mount_env 直接改写
# 结论：挂载类恒串行；R6 两套件另划独占 Tier（最后跑，收尾把系统 monitor 还原）。
#
# Tier 0 并行白名单：逐个核对过无共享状态的套件（判据：CONF/挂载点全由 mkdtemp
# 派生自管或根本不挂载；无固定端口；无全局 pkill；不碰系统 log_monitor 与
# 真实日志文件）。命中 --jobs 时仅这些进线程池并行，其余按 Tier 串行。
# 新套件默认串行，要加入须先核对判据。
PARALLEL_SAFE = frozenset({
    "test_config_snapshot.py",    # cc 编译夹具直跑，TemporaryDirectory
    "test_module_abi.py",         # cc 编译 ABI 夹具，无 daemon（TemporaryDirectory）
    "test_path_vars.py",          # cc 编译直跑（mkdtemp）
    "test_monitor_layers.py",     # cc 编译实际源码 + 合成 uid，无挂载（TemporaryDirectory）
    "test_log_ctl_rules.py",      # 全走 mkdtemp（--config-dir 指向临时目录）
    "test_inject_method.py",      # conf 全走 mkdtemp + global_replace_ctl 驱动，无 daemon
    "test_crash_log.py",          # --crash-test 挂载前退出，日志只写 mkstemp 临时文件
    "test_backend_lifecycle.py",  # MNT/CONF 全由 mkdtemp 派生，自管 daemon（精确杀自身 pid）
    "test_ftp_read_restart.py",   # cc+mock 直跑（TemporaryDirectory），无 FUSE/网络/端口/pkill
    "test_pending_close.py",      # cc 直编队列实现 + 驱动，TemporaryDirectory，无挂载
    "test_cfg_watch.py",          # cc 直编 watch 对账 + 驱动，/tmp mkdtemp，无挂载
    "test_rule_file_lock.py",     # cc 直编 nsp_rule_file + 子进程并发写，/tmp 工作目录
    "test_ns_combined_rollback.py",  # cc 直编 ns_utils.c + --wrap 桩 mount，无挂载/特权
    "test_reaped_managed.py",     # cc 直编收尸留档 + 真实 fork 子进程，无共享状态
    "test_ftp_truncate_list.py",  # cc 直编 FTP 后端 + 桩 mux/curl，无网络/端口/FUSE
    "test_ftp_upload_lock.py",    # cc 直编 FTP 后端 + 桩 mux/curl，无网络/端口/FUSE
})
# Tier 2 独占：碰全局 log_monitor（R6）的套件，串行且排在最后执行，保证收尾时
# 系统 monitor 已还原，不干扰其他套件。
TIER_EXCLUSIVE = frozenset({
    "test_log_pipeline.py",
    "test_rule_server.py",
})
# 注意：test_rule_server.py 主体已隔离（临时 conf_dir + PID 后缀 socket），但
# SERVICE 用例会 pkill -9 全局 log_monitor 并拉起系统实例，故仍归 Tier 2。


# Tier 0 默认 worker 数：cc 编译型小套件为主，4 足够吃满；上限 8 防 fork 炸弹。
# Tier 1/2（挂载/独占类）恒串行，不受 --jobs 影响。
DEFAULT_JOBS = min(4, os.cpu_count() or 1)
MAX_JOBS = 8

# 单套件退出码约定（见模块 docstring）：77 = 环境不具备整套跳过（gap），
# 78 = 部分子组跳过（gap），127 = 套件文件不存在（计为失败，不得静默当跳过）。
SKIP_RC = 77
GAP_RC = 78
MISSING_RC = 127


def classify(rc):
    """把套件退出码归入 PASS / SKIP / GAP / FAIL 四态。"""
    if rc == 0:
        return "PASS"
    if rc == SKIP_RC:
        return "SKIP"
    if rc == GAP_RC:
        return "GAP"
    return "FAIL"


def is_gap(rc):
    """SKIP/GAP 均为「不计通过」的缺口。"""
    return classify(rc) in ("SKIP", "GAP")


def gap_note(rc):
    kind = classify(rc)
    if kind == "SKIP":
        return "  ← 环境不具备，整套跳过=gap，不计通过"
    if kind == "GAP":
        return "  ← 部分子组跳过=gap，不计通过"
    if rc == MISSING_RC:
        return "  ← 套件文件不存在"
    return ""


def tier_of(name):
    """套件分 Tier：0=并行白名单，2=独占（全局 log_monitor），其余 1=挂载类串行。"""
    if name in PARALLEL_SAFE:
        return 0
    if name in TIER_EXCLUSIVE:
        return 2
    return 1


def run_suite(name, capture=False):
    """跑单个套件，返回 (rc, dt, output)。

    capture=False（串行默认）：子进程输出直接透传终端，行为与旧版一致。
    capture=True（并行用）：输出截获后由调用方在任务完成时统一打印，
    避免多套件刷屏交错；退出码原样回传（不用管道吞退出码）。
    套件文件不存在返回 MISSING_RC（计为失败）——此前返回 None 被当作
    「跳过」，拼错套件名也会 rc=0（假绿）。
    """
    path = os.path.join(TESTS, name)
    if not os.path.exists(path):
        print(f"❌ 套件不存在：{name}（计为失败；拼写错误不会被静默跳过）")
        return MISSING_RC, 0.0, ""
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
            print(f"\n{'━' * 60}\n▶ {s}（并行，{dt:.1f}s）\n{'━' * 60}",
                  flush=True)
            print(out, end="", flush=True)
            if classify(rc) == "FAIL":
                print(f"\n❌ {s} 失败（退出码 {rc}，{dt:.1f}s）")
            elif is_gap(rc):
                print(f"\n⏭ {s} 跳过（退出码 {rc}，gap 不计通过）")
            done[s] = (rc, dt)
    return done


def main():
    ap = argparse.ArgumentParser(description="按改动文件自动选套件的统一测试入口")
    ap.add_argument("suites", nargs="*", help="显式指定要跑的 tests/*.py（跳过自动匹配）")
    ap.add_argument("--all", action="store_true", help="忽略映射，跑全部套件")
    ap.add_argument("--list", action="store_true", help="只列出将要执行的套件")
    ap.add_argument("--base", default="HEAD",
                    help="与该提交对比以确定改动（默认 HEAD = 暂存+未暂存+未跟踪）")
    ap.add_argument("--jobs", "-j", type=int, default=DEFAULT_JOBS,
                    help=f"Tier 0 套件（PARALLEL_SAFE 白名单）并行worker数，"
                         f"默认{DEFAULT_JOBS}（上限{MAX_JOBS}）；"
                         "Tier 1/2（挂载/独占类）恒串行")
    ap.add_argument("--strict", action="store_true",
                    help="验收模式：跳过项（环境不具备，gap）计为失败，rc=1")
    args = ap.parse_args()
    if args.jobs > MAX_JOBS:
        print(f"⚠ --jobs {args.jobs} 超过上限 {MAX_JOBS}，钳制为 {MAX_JOBS}")
        args.jobs = MAX_JOBS
    if args.jobs < 1:
        args.jobs = 1

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
    t0 = [s for s in suites if tier_of(s) == 0]
    t1 = [s for s in suites if tier_of(s) == 1]
    t2 = [s for s in suites if tier_of(s) == 2]
    for s in suites:
        tag = {0: "Tier0并行", 1: "Tier1串行", 2: "Tier2独占"}[tier_of(s)]
        print(f"  [{tag}] {s}")
    print("命中条目：" + ("、".join(rows) if rows else "无"))
    if args.list:
        return 0

    results = []
    # Tier 0 恒执行（此前 `if args.jobs > 1 and t0` 使 --jobs 1 时整组 Tier0
    # 被漏跑，且 t1+t2 为空时汇总仍「共 0、通过」、rc=0）。--jobs 1 走串行分支
    # 以保留输出透传；>1 时进线程池并行。
    if t0 and args.jobs > 1:
        # 先并行 Tier 0，再串行 Tier 1，最后独占 Tier 2：挂载类/独占类之间
        # 仍保持选中顺序语义，且独占类（log_monitor/vsftpd/userns）不受
        # 并行任务干扰，收尾时系统 log_monitor 已还原
        para = run_parallel(t0, args.jobs)
        for s in t0:
            rc, dt = para[s]
            results.append((s, rc, dt))
    else:
        for s in t0:
            rc, dt, _ = run_suite(s)
            results.append((s, rc, dt))
            if classify(rc) == "FAIL":
                print(f"\n❌ {s} 失败（退出码 {rc}，{dt:.1f}s）")
            elif is_gap(rc):
                print(f"\n⏭ {s} 跳过（退出码 {rc}，gap 不计通过）")
    for s in t1 + t2:
        rc, dt, _ = run_suite(s)
        results.append((s, rc, dt))
        if classify(rc) == "FAIL":
            print(f"\n❌ {s} 失败（退出码 {rc}，{dt:.1f}s）")
        elif is_gap(rc):
            print(f"\n⏭ {s} 跳过（退出码 {rc}，gap 不计通过）")

    print(f"\n{'═' * 60}")
    passed = [r for r in results if classify(r[1]) == "PASS"]
    gaps = [r for r in results if is_gap(r[1])]
    failed = [r for r in results if classify(r[1]) == "FAIL"]
    print(f"测试汇总 | ✅ {len(passed)} 通过 | ❌ {len(failed)} 失败 | "
          f"⏭ {len(gaps)} 跳过(gap) | 共 {len(results)}")
    for s, rc, dt in results:
        mark = {"PASS": "✅", "SKIP": "⏭", "GAP": "⏭", "FAIL": "❌"}[classify(rc)]
        print(f"  {mark} {s:<34} {dt:6.1f}s  rc={rc}{gap_note(rc)}")
    if gaps:
        print("⚠ 跳过项（gap，不计通过）：" + "、".join(s for s, _, _ in gaps))
    if failed:
        print("存在失败套件——按 AGENTS.md 要求全绿方可提交")
    if gaps and args.strict:
        print("--strict（验收模式）：跳过项计为失败")
    print("═" * 60)
    return 1 if (failed or (args.strict and gaps)) else 0


if __name__ == "__main__":
    sys.exit(main())
