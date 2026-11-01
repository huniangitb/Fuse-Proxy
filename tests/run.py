#!/usr/bin/env python3
"""
统一测试入口：按改动文件自动选套件（tests/*.py 各脚本保持独立可跑）
====================================================================

    python3 tests/run.py                 # 默认：按本次改动匹配映射表后依次执行
    python3 tests/run.py --list          # 只打印将要执行的套件，不真正跑
    python3 tests/run.py --all           # 忽略映射，跑全部常规套件（不含按需套件）
    python3 tests/run.py --layer L0      # 只跑某个验收层（可重复：--layer L0 --layer L1）
    python3 tests/run.py --base <ref>    # 与指定提交对比（默认 HEAD，即未提交改动）
    python3 tests/run.py test_rules.py …  # 显式指定套件（同时跳过自动匹配）
    python3 tests/run.py --jobs 4        # Tier 0 白名单套件并行，其余仍串行
    python3 tests/run.py --strict        # 验收模式：跳过项（gap）计为失败

改动来源：`git diff --name-only <base>` + 未跟踪文件（新文件按整体内容匹配符号）。
映射规则：每个条目给出 **文件路径子串**（任一命中即选中）与 **符号**（该符号出现在
任一改动文件内容中即选中，二者为「或」）。改动为文档/脚本等未命中项时，
仍会跑「通用回归」基线——它对所有改动恒定生效。

两组正交的分类，各有唯一出处，别混用：
  * **Tier**（`PARALLEL_SAFE` / `TIER_EXCLUSIVE`）= 能否并行，按共享状态冲突划分；
  * **Layer**（`LAYERS`）= 验收分层，按「贴近 Android 的程度」划分，供 `--layer` 用。
`LAYERS` 是 L0/L1/L2 归属的唯一出处（此前只在 AGENTS.md 里是散文，跑不了也对不上
账：实测 38 个套件里有 13 个没被任何层点名）。新套件必须同时登记进 `SUITE_MAP`
与 `LAYERS`，否则 `tests/test_docs_sync.py` 失败。

对应 docs/testing.md 的映射表与分层清单；一致性由 `tests/test_docs_sync.py`
机器校验（拼错/漏登记当场失败），不再依赖人工两边同步。

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
    # ── 基线：条目不给任何路径/符号谓词即恒定命中（IO/SQLite/并发 + 崩溃日志取证 ──
    #    + 文档/映射表/分层一致性，后者恒跑是有意的：文档漂移正是靠它当场失败才拦住的）
    (("test_functional.py", "test_crash_log.py", "test_docs_sync.py"), (), (),
     "通用回归基线"),

    # ── AGENTS.md 映射表 ──
    # ── 访问控制判定表（fw_acl.c）：AOSP 语义的唯一执行点 ──
    # 直编 fw_acl.c + 纯逻辑驱动（桩掉 uid→包名/特权/隔离开关三个事实源），
    # 另有静态契约断言：fw_acl_check 在 fuse_daemon.c 只能出现一次、关键回调
    # 必须把 ACL 操作种类交给 fw_route。
    (("test_acl.py",),
     ("src/daemon/fw_acl.c", "src/daemon/fw_acl.h"),
     ("fw_acl_decide", "fw_acl_classify", "fw_acl_check", "fw_acl_identity",
      "fw_rules_cross_app_isolated"),
     "访问控制判定表(fw_acl) / 跨应用隔离开关"),

    (("test_rules.py", "test_config_snapshot.py", "test_monitor_layers.py",
      "test_decision_enforce.py", "test_negative_timeout.py",
      "test_readdir_skel_fallback.py", "test_backing_gate.py",
      # C1：沙盒落点的目录创建不得发生在 config_read_begin 持槽期间
      # （br_check_redir_rule 的 access+mkdir 已移出读槽）
      "test_c1_sandbox_slot.py",
      # 后端 read/write 回传长度钳制（vfs_read/vfs_write）住 fuse_daemon.c，
      # 判别用例在 test_module_circuit.py §7b/7c（谎报 got/wrote 的后端模块）
      "test_module_circuit.py",
      # 存储根一级条目守卫（fw_route 单点 + 父目录补建出口）：历史缺陷
      # 「/data/media 顶层被应用 materialize 出纯数字垃圾目录」
      "test_storage_root_guard.py"),
     ("src/daemon/fw_rules.c", "src/daemon/fw_rules.h", "src/config/config_parser.c",
      "include/config_parser.h", "src/daemon/fuse_daemon.c",
      # Trie 是规则匹配的加速结构（architecture.md §7：改 Trie 或线性通道须保持
      # 二者优先级一致）；fast_search 提供规则扫描用的 fast_strstr；config_publisher
      # 是 App-rules 的发布侧，test_config_snapshot.py 直编它
      "src/core/path_trie.c", "include/path_trie.h",
      "src/core/fast_search.c", "include/fast_search.h",
      "src/injector/config_publisher.c", "include/config_publisher.h"),
     ("fw_rules_resolve", "config_build_from_view", "parse_config_line",
      "fw_data_mediation_required", "fw_backing_mediation_required_for"),
     "内建规则引擎(fw_rules) / fuse_daemon.c / config_parser.c"),

    (("test_ftp.py", "test_ftp_read_restart.py", "test_ftp_truncate_list.py",
      "test_ftp_upload_lock.py", "test_sftp.py"),
     ("src/modules/ftp/",),
     ("module_backend_lookup", "module_backend_put", "backend_rename", "backend_read",
      "ftp_backend_truncate", "ftp_list_cache_clear", "ftp_backend_upload",
      # fsync 与 FLUSH 共用后端收尾（vfs_fsync 不再是空操作）→ 改这些行必须跑 ftp
      "vfs_backend_finish_data", "vfs_fsync", "backend_flush",
      # SFTP（proto=sftp）协议分派：改动这些必须跑 test_sftp.py
      "res_is_unavailable", "res_is_not_found", "res_file_probe_ok", "ftp_quote_errno",
      "ftp_quote_arg", "ftp_url_unescape", "curl_supports_sftp", "ftp_easy_new"),
     "src/modules/ftp/ 或框架后端分派"),

    (("test_ftp_parallel.py",),
     ("src/modules/ftp/ftp_mux.c",),
     ("backend_rc_is_business",),
     "ftp_mux.c 或 backend_rc_is_business"),

    (("test_path_vars.py",),
     ("src/config/path_vars.c", "include/path_vars.h"), (), "src/config/path_vars.c"),

    (("test_inject_method.py", "test_global_replace.py", "test_inject_tracked_race.py"),
     ("src/injector/inject_target.c", "include/inject_target.h",
      # global_replace_ctl 是 test_global_replace.py 的被测驱动（仅 GNU 构建）
      "src/injector/global_replace_ctl.c"),
     ("inject-method",),
     "injector 目标判定 / 注入方法 / 追踪表并发遍历"),

    (("test_inject_mount_env.py", "test_ns_combined_rollback.py", "test_ns_umount_overflow.py",
      "test_ns_global_replace_rollback.py"),
     ("src/injector/ns_utils.c", "include/ns_utils.h", "src/injector/ns_global_replace.c",
      "src/injector/injector.c", "include/injector.h",
      # mountinfo 扫描原语（C7 收口）与卸载序列同源；mount_manager 是注入挂载的
      # 执行体；ipc_server 随 injector 进程生命周期起停（zygisk 通知入口）
      "src/injector/ns_mountinfo.c", "src/injector/mount_manager.c",
      "include/mount_manager.h", "src/injector/ipc_server.c", "include/ipc_server.h"),
     ("cleanup_app_mounts", "do_combined_mount"),
     "injector 挂载/清理序列"),

    (("test_reaped_managed.py",),
     ("src/injector/reaped_managed.c", "src/injector/reaped_managed.h",
      "src/injector/injector.c"),
     ("reaped_managed_put", "reaped_managed_exited", "reap_zombies"),
     "受管子进程收尸留档（崩溃现场入日志环）"),

    (("test_modules.py", "test_module_circuit.py", "test_module_abi.py",
      "test_backend_lifecycle.py", "test_fw_config_view.py"),
     ("src/module/", "include/module_loader.h", "include/module_guard.h",
      "include/fault_fence.h",
      # 模块 ABI 的唯一入口：改它必须跑布局契约套件。此前它不在任何路径谓词里
      # ——改 ABI 头只跑基线 3 套，test_module_abi.py 根本不会执行
      "include/nsp_module.h"),
     ("memfd_create", "module_backend_", "module_fault_poison"),
     "src/module/（加载器/内存副本加载/围栏/熔断/ABI）"),

    (("test_decision_enforce.py",), (),
     ("fw_route", "appear_missing", "vfs_check_read_only"), "决策强制单点（errno 矩阵）"),

    (("test_log_ctl_rules.py", "test_rule_server.py", "test_log_pipeline.py"),
     ("src/rule/", "src/log/log_ctl.c"),
     ("nsp_rule_file",),
     "log_ctl / rule_server 规则编辑"),

    # 存储根一级条目守卫：不变量与两个出海口都在 common.c（路径合成 / 父目录
    # 补建），改它必须跑判别用例（旧实现把客户端请求 /<大数字>/… materialize 成
    # <STORAGE_BASE>/<大数字>，线上形态即 /data/media 顶层反复出现纯数字目录）
    (("test_storage_root_guard.py",),
     ("src/core/common.c", "include/common.h"), (),
     "存储根一级条目守卫（common.c 路径合成 + 父目录补建出口）"),

    (("test_log_pipeline.py",),
     ("src/log/", "src/core/nsp_comm.c", "include/nsp_comm.h", "include/nsp_log.h",
      "src/core/common.c", "include/common.h", "src/core/nsp_util.c", "include/nsp_util.h",
      # 启动水印（nsp_log_build_info）与崩溃留档都写进日志环，故归日志链路
      "src/core/build_info.c", "include/build_info.h",
      "src/core/crash_dump.c", "include/crash_dump.h"),
     # log_open_unlink_direct 是 fuse_daemon 侧「打开中删除」per-事件 DEBUG 的
     # 唯一出口（真机一秒 633 行）；它的限速回归是 test_log_pipeline 的 L0 直编
     # 契约（用例 6，桩掉 LOG_DBG 数行数），所以符号登记在这里而不是挂载环境套件
     ("vfs_log_io", "monitor_on", "persist_stage", "drain_async", "log_internal",
      "fw_config_monitor_for", "nsp_log_level_name", "nsp_log_level_parse",
      "nsp_getline_capped", "nsp_snprintf_dyn", "nsp_format_dynamic",
      "log_open_unlink_direct"),
     "日志链路（生产 → 通讯 → log_monitor → 查询）"),

    # fw_config.c 含规则文件/App-rules 的 inotify 监听线程——热重载触发路径本身，
    # 故改动它同时跑 test_rules.py（重载语义端到端）
    (("test_monitor_layers.py", "test_cfg_watch.py", "test_rules.py",
      "test_fw_config_view.py",
      # C11：配置目录事件按 ev->name 分流（uid.map / sys_pkgs.cache 不触发规则重载）
      "test_cfg_reload_split.py"),
     ("src/daemon/fw_config.c", "src/daemon/fw_config.h", "src/daemon/fw_pkg.c",
      "src/daemon/fw_pkg.h",
      # uid→包名的三级输入：uid.map（uid_map）、系统包缓存（sys_pkg）、
      # pid→包名快取（fast_pid）——test_monitor_layers.py 直编它们
      "src/core/uid_map.c", "include/uid_map.h",
      "src/core/sys_pkg.c", "include/sys_pkg.h",
      "src/core/fast_pid.c", "include/fast_pid.h"),
     ("fw_config_monitor_for", "fw_pkg_resolve"),
     "监控开关三层合并 / uid→包名（框架权威）"),

    (("test_pending_close.py",),
     ("src/daemon/fd_close_queue.c", "src/daemon/fd_close_queue.h"),
     ("fdq_defer", "fdq_flush"),
     "延迟 close 环形队列（Android backing fd 回收）"),

    (("test_cfg_watch.py",),
     ("src/daemon/cfg_watch.c", "src/daemon/cfg_watch.h"),
     ("cfg_watch_sync", "cfg_watch_sync_subdirs"),
     "配置目录 watch 对账（App-rules / 模块目录子目录热更新）"),

    # 配置下发归属（视图版本 2）：框架读 <modules_dir>/<名>/<名>.conf 后按 owner
    # 过滤下发给同名模块——模块不读文件、不跑 inotify（含它自己的配置）。
    # 判别性：去掉 config_read_view 的 view_scan_module_confs 即旧实现，本套件必失败
    (("test_module_cfg_push.py",),
     ("include/nsp_cfg_view.h",),
     ("NSP_CFG_REC_MODULE_FILE", "NSP_CFG_REC_MODULE_LINE", "config_set_modules_dir",
      "config_modules_dir", "view_scan_module_confs"),
     "模块配置下发（框架读 → 按 owner 过滤 → 模块消费）"),

    (("test_rule_file_lock.py", "test_log_ctl_rules.py", "test_rule_server.py"),
     ("src/core/nsp_rule_file.c", "src/core/nsp_rule_file.h", "include/nsp_rule_file.h"),
     ("nsp_rule_file_edit", "nsp_rule_file_app_active_path"),
     "规则文件编辑（nsp_rule_file：并发/持久性/停用态路径）"),

    (("test_a26_misc.py",),
     ("src/core/nsp_ini_store.c", "include/nsp_ini_store.h", "src/modules/ftp/ftp_conf.c"),
     ("nsp_ini_save", "ftp_conf_load", "strip_comment"),
     "A26 杂项（ftp_conf `#`/port 校验 + nsp_ini_store 落盘持久性）"),

    (("test_pt_probe_toctou.py",),
     ("src/daemon/fuse_daemon.c",),
     ("passthrough_probe", "g_pt_probe_pending", "O_NOFOLLOW"),
     "透传探测文件 TOCTOU（B3：O_EXCL|O_NOFOLLOW + pending 原子 test-and-set）"),

    # 跨进程/跨模块常量的唯一出处（include/nsp_constants.h）与模块配置视图
    # （include/nsp_cfg_view.h）都是「一改影响所有进程与模块 ABI」的文件，
    # 没有单一归属套件，故给覆盖面最广的一组；命中即多跑几套，漏跑才是灾难
    (("test_functional.py", "test_rules.py", "test_module_abi.py",
      "test_log_pipeline.py", "test_config_snapshot.py"),
     ("include/nsp_constants.h", "include/nsp_cfg_view.h"),
     (),
     "跨进程常量 / 模块配置视图（影响所有进程与模块 ABI）"),

    # CONTRIBUTING.md §5 的可执行形式：.githooks/commit-msg 每次提交调用它，
    # 模板 .gitmessage 与装配脚本同属这套（改任一都跑本套件）
    (("test_commit_msg_lint.py",),
     ("scripts/commit_msg.py", ".githooks/", ".gitmessage", "scripts/setup-hooks.sh"),
     ("HEADER_MAX", "BREAKING CHANGE", "LOCAL_REFS"),
     "提交信息规范工具（lint + CHANGELOG）"),

    # 构建脚本的输出目录白名单：脚本末尾对 $OUT 执行 rm -rf，误传 / 或 $HOME
    # 会整目录删除。用例用假 HOME + PATH 桩（rm/cmake）验证拒绝发生在删除之前。
    (("test_build_scripts.py",),
     ("scripts/build-libssh2-android.sh",),
     (),
     "构建脚本危险路径白名单（rm -rf 前的 $OUT 校验）"),

    # 挂载失败重试记账：旧实现「派发成功即出队、失败回调重新入队（次数归零）」
    # 让退避与上限永远不生效——挂不上的应用 1Hz 永久重试、错误日志刷屏。
    # 新实现把尝试次数随条目保存，并按**毫秒**分三档退避（快档 20ms×10 → 中档
    # 100ms×5 → 指数 1/2/4/8s，上限 NSP_RETRY_MAX_ATTEMPTS）：设备上
    # /storage/emulated 要 ~140ms 才被 vold 装配进应用 ns，秒粒度首个 1s 退避等于白等。
    (("test_retry_queue.py",),
     ("src/injector/retry_queue.c", "include/retry_queue.h"),
     ("nsp_retry_schedule", "nsp_retry_next", "nsp_retry_done", "nsp_retry_backoff_ms",
      "nsp_retry_next_due_ms", "nsp_retry_now_ms"),
     "挂载失败重试记账（重试收敛 / 毫秒三档退避 / 放弃 / 清账 / 到期时刻）"),
]


# ── 验收分层（LAYERS）：L0/L1/L2 归属的唯一出处 ─────────────────────────────
# 与 Tier（并行安全性）正交：Tier 管「能不能一起跑」，Layer 管「贴近 Android 到
# 什么程度」，即验收时的递进顺序。docs/testing.md 的分层清单由此生成式对账，
# 一致性与完整性由 tests/test_docs_sync.py 强制：
#   * SUITE_MAP 里的每个套件必须恰好属于一层（漏登记 → 分层验收跑不到它）；
#   * 每层里的套件必须真实存在且在 SUITE_MAP 里。
#
# L0 静态/契约：不挂载、不联网、不起 daemon。多为「直编实际源码 + --wrap 桩/ASan」
#    的判别性用例，宿主零副作用，可并行。
# L1 GNU 真实 FUSE：起真 daemon、真挂载（/dev/fuse + fusermount3），部分需 vsftpd
#    或系统 log_monitor，故串行。
# L2 Android 拓扑仿真：rootless unshare 沙箱内仿真安卓挂载拓扑，验收时须核对宿主
#    mountinfo 前后零变化。
# L3/L4 不在本文件内：L3 需 emulator/AVD 或真机（SELinux/Bionic/vold/FUSE-BPF/
#    Zygisk 双 ABI/多用户），L4 经 scripts/adb-sh.sh 做设备最终验收。见 docs/testing.md。
LAYERS = {
    "L0": (
        "静态/契约（无挂载无网络，可并行）",
        (
            "test_docs_sync.py",
            "test_acl.py",
            "test_config_snapshot.py",
            "test_monitor_layers.py",
            "test_path_vars.py",
            "test_pending_close.py",
            "test_cfg_watch.py",
            "test_cfg_reload_split.py",
            "test_module_cfg_push.py",
            "test_fw_config_view.py",
            "test_rule_file_lock.py",
            "test_module_abi.py",
            "test_backing_gate.py",
            "test_c1_sandbox_slot.py",
            "test_a26_misc.py",
            "test_pt_probe_toctou.py",
            "test_reaped_managed.py",
            "test_crash_log.py",
            "test_ftp_read_restart.py",
            "test_ftp_truncate_list.py",
            "test_ftp_upload_lock.py",
            "test_ns_combined_rollback.py",
            "test_retry_queue.py",
            "test_ns_umount_overflow.py",
            "test_ns_global_replace_rollback.py",
            "test_inject_method.py",
            "test_inject_tracked_race.py",
            "test_log_ctl_rules.py",
            "test_commit_msg_lint.py",
            "test_build_scripts.py",
        ),
    ),
    "L1": (
        "GNU 真实后端/FUSE（串行；FUSE 类需 /dev/fuse + fusermount3，"
        "test_sftp 需本机 sshd 于 127.0.0.1:2222）",
        (
            "test_functional.py",
            "test_rules.py",
            "test_decision_enforce.py",
            "test_negative_timeout.py",
            "test_storage_root_guard.py",
            "test_readdir_skel_fallback.py",
            "test_modules.py",
            "test_module_circuit.py",
            "test_backend_lifecycle.py",
            "test_ftp.py",
            "test_ftp_parallel.py",
            "test_sftp.py",
            "test_log_pipeline.py",
            "test_rule_server.py",
        ),
    ),
    "L2": (
        "Android 拓扑仿真（rootless unshare 沙箱，须核对宿主 mountinfo 零变化）",
        (
            "test_inject_mount_env.py",
            "test_global_replace.py",
        ),
    ),
}

# 按需套件：压力/基准类，耗时长且断言的是指标而非正确性，故**有意**不进 SUITE_MAP，
# `--all` 也不跑（否则每次验收都要等它们）。显式写名字才跑：
#   python3 tests/run.py test_ftp_stress.py
# 登记在此是为了让 tests/test_docs_sync.py 能区分「有意按需」与「新套件漏登记」——
# 不在 SUITE_MAP 又不在这里的 tests/*.py（run.py 自身除外）一律判为漏登记
# （此前 test_ftp_stress.py 长期游离在 --all 之外，没人看得出是故意还是忘了；
#  `stress_fuse.py` 则因为台账只 glob `test_*.py` 而完全逃过检查）。
ON_DEMAND = frozenset({
    "test_ftp_stress.py",     # FTP 吞吐/长稳压力，需 vsftpd，分钟级
    "stress_fuse.py",         # FUSE 综合压测，分钟级，断言指标而非正确性
})


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


def layer_of(name):
    """套件所属验收层；未登记返回 None（test_docs_sync.py 会判失败）。"""
    for layer, (_desc, suites) in LAYERS.items():
        if name in suites:
            return layer
    return None


def layer_suites(layers):
    """按层取套件，依 L0→L1→L2 递进顺序返回（层内保持 LAYERS 里的书写顺序）。"""
    out = []
    for layer in sorted(layers):
        for s in LAYERS[layer][1]:
            if s not in out:
                out.append(s)
    return out


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
    "test_docs_sync.py",          # 纯静态读文件（文档/台账一致性），无子进程/无挂载
    "test_acl.py",                # cc 直编 fw_acl.c + 纯逻辑驱动，TemporaryDirectory，无挂载
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
    "test_retry_queue.py",           # cc 直编 retry_queue.c + 虚拟时钟，无挂载/无子进程
    "test_ns_umount_overflow.py",    # cc 直编 ns_utils.c + ASan + --wrap 桩 fopen/umount2，无挂载
    "test_ns_global_replace_rollback.py",  # cc 直编 ns_global_replace.c + --wrap 桩 mount/fopen，无挂载
    "test_reaped_managed.py",     # cc 直编收尸留档 + 真实 fork 子进程，无共享状态
    "test_ftp_truncate_list.py",  # cc 直编 FTP 后端 + 桩 mux/curl，无网络/端口/FUSE
    "test_ftp_upload_lock.py",    # cc 直编 FTP 后端 + 桩 mux/curl，无网络/端口/FUSE
    "test_fw_config_view.py",     # cc 直编 fw_config.c + 依赖，TemporaryDirectory，无挂载
    "test_module_cfg_push.py",    # cc 直编 config_parser.c/fw_config.c + 依赖，TemporaryDirectory
    "test_inject_tracked_race.py",  # cc 直编 inject_target.c + ASan + --wrap 桩 kill，无挂载/特权
    "test_a26_misc.py",           # cc 直编 ftp_conf.c/nsp_ini_store.c，/tmp mkdtemp，无挂载/网络
    "test_pt_probe_toctou.py",    # cc 直编驱动 + --wrap 桩 open/unlink，cwd 临时目录，无挂载/特权
    "test_build_scripts.py",      # 假 HOME + PATH 桩跑脚本，TemporaryDirectory，不碰真实路径
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
    ap.add_argument("--all", action="store_true", help="忽略映射，跑全部常规套件（不含 ON_DEMAND 按需套件）")
    ap.add_argument("--layer", action="append", choices=sorted(LAYERS), default=None,
                    metavar="L0|L1|L2",
                    help="只跑指定验收层（可重复，如 --layer L0 --layer L1）；"
                         "层定义见 LAYERS 与 docs/testing.md")
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
    elif args.layer:
        suites = layer_suites(args.layer)
        rows = [f"{lv}（{LAYERS[lv][0]}）" for lv in sorted(args.layer)]
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
        print(f"  [{tag}][{layer_of(s) or '未分层'}] {s}")
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
