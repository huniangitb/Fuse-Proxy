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
    python3 tests/run.py --jobs 4        # 资源感知并行：无冲突的套件同时跑
    python3 tests/run.py --strict        # 验收模式：跳过项（gap）计为失败

改动来源：`git diff --name-only <base>` + 未跟踪文件（新文件按整体内容匹配符号）。
映射规则：每个条目给出 **文件路径子串**（任一命中即选中）与 **符号**（该符号出现在
任一改动文件内容中即选中，二者为「或」）。改动为文档/脚本等未命中项时，
仍会跑「通用回归」基线——它对所有改动恒定生效。

两组正交的分类，各有唯一出处，别混用：
  * **Tier**（`PARALLEL_SAFE` / `QUIET_ON_HOST` / `TIER_EXCLUSIVE` / `SUITE_RESOURCES`）
    = 并行与互斥，按共享状态冲突划分（见文件后半「并行调度」段）；
  * **Layer**（`LAYERS`）= 验收分层，按「贴近 Android 的程度」划分，供 `--layer` 用。

并行调度不是「白名单并行、其余全串行」：挂载类套件彼此几乎没有共享（规则文件、
挂载点、日志全在各自 BASE 下），真正需要互斥的只有 `SUITE_RESOURCES` 里点名的
那几处；而要求「宿主挂载表零变化」的套件（`QUIET_ON_HOST`）必须独占到没有任何
别的套件在宿主命名空间里挂/卸。调度器按这两条自动合流：能同时跑的绝不排队。
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
import threading
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
    # ── 虚拟条目（vfs_synth.c）：路径段判定 + 合成条目属性 ──
    # 沙盒合成的 /Android/obb/<pkg> 曾因 getattr 兜底不认这条路径而落回 ENOENT，
    # 文件管理器列表里看得见、点不开（画成文件 + 1970-01-01）。
    # 单元套件直编 vfs_synth.c 守住合成属性（目录/nlink>=2/size>0/mtime>0），
    # 静态契约锁住 getattr/access/opendir 三处兜底都问 is_virtual_own_pkg_dir。
    (("test_vfs_synth.py",),
     ("src/daemon/vfs_synth.c", "src/daemon/vfs_synth.h", "src/daemon/fuse_daemon.c"),
     ("nsp_synth_stat_fill", "is_virtual_own_pkg_dir", "is_android_skel_dir"),
     "虚拟条目(vfs_synth) / 合成条目属性 + 自身包名目录判定"),

    # ── FUSE 事件通道（fw_events.c）：订阅推送 + 查询面，默认 OFF ──
    # 单元套件直编 fw_events.c（桩掉路径合成/规则决策/访问控制三个事实源），
    # 静态契约锁死：判定只问 fw_rules_resolve/fw_acl_check、热路径零分配、
    # 开关判断先于线程创建；端到端套件在真实 daemon 上验证埋点挂在**回调成功点**。
    (("test_fw_events.py", "test_fw_events_fuse.py"),
     ("src/daemon/fw_events.c", "src/daemon/fw_events.h"),
     ("fw_events_note_write_done", "fw_events_note_write_denied", "fw_events_start",
      "fw_events_stop", "fw_query_handle", "fw_coalesce_push", "fw_ring_push",
      "fw_maybe_ping", "fw_exists_lookup", "fw_build_allow_list"),
     "FUSE 事件通道(fw_events) / 订阅推送 + QUERY"),

    (("test_acl.py",),
     ("src/daemon/fw_acl.c", "src/daemon/fw_acl.h"),
     ("fw_acl_decide", "fw_acl_classify", "fw_acl_check", "fw_acl_identity",
      "fw_rules_cross_app_isolated"),
     "访问控制判定表(fw_acl) / 跨应用隔离开关"),
    (("test_appops_bounded.py",),
     ("src/daemon/fw_pkg.c", "src/daemon/fw_pkg.h", "src/daemon/fw_acl.c",
      "tests/fixtures/fw_pkg_appops_driver.c", "tests/fixtures/appops_cmd_fixture.c"),
     ("ext_lookup", "ext_cached", "appops_query_storage_ops", "appops_child_finish",
      "appops_children_shutdown", "acl_fill_capabilities"),
     "AppOps 有界查询 / 锁外缓存填充与失败冷却"),
    # ── ACL 不干扰（验收门 G9）：真 daemon + 真挂载上以普通调用者身份做真实文件
    # 操作，断言「功能预期」而不是 ACL 内部判定——ACL 层不得改变功能语义。
    (("test_acl_nonintrusive.py",),
     ("src/daemon/fw_acl.c", "src/daemon/fw_acl.h", "src/daemon/fuse_daemon.c"),
     ("fw_acl_check", "fw_acl_decide", "fw_route", "vfs_check_read_only"),
     "ACL 不干扰(G9) / 真实挂载视图功能预期"),
    # 打开中删除（libfuse 隐藏名 rename）的 ACL 语义：隐藏名等价于 unlink，
    # 源端必须按 DELETE 路由，否则顶层条目的「不可改名」结构规则误拒 EPERM。
    (("test_open_unlink_toplevel.py",),
     ("src/daemon/fuse_daemon.c", "tests/test_open_unlink_toplevel.py"),
     ("rename_is_open_unlink", "is_fuse_hidden_name", "vfs_rename"),
     "打开中删除的隐藏名改名按删除路由 / 真实挂载视图"),

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
     # 后端落点物化（fw_ingest.c）：把后端字节回读成本地文件，供扫描侧入库
     ("src/modules/ftp/", "src/daemon/fw_ingest.c"),
     ("module_backend_lookup", "module_backend_put", "backend_rename", "backend_read",
      "fw_ingest_materialize",
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

    (("test_inject_method.py",),
     ("src/injector/ns_utils.c", "src/injector/ipc_server.c",
      "tests/fixtures/async_reaped.c", "tests/fixtures/ipc_binding.c"),
     ("handle_async_mount_event",),
     "IPC 请求身份与异步完成回调收尾"),

    (("test_submount_rules.py",),
     ("src/injector/mount_manager.c", "include/mount_manager.h", "src/core/common.c",
      "src/config/config_parser.c", "include/config_parser.h",
      "tests/fixtures/submount_rules_driver.c"),
     ("submount_conflicts_with_rules_locked", "path_prefix_overlap", "common_parse_user_layer"),
     "原生子挂载显式规则冲突 / 用户层与类别判定"),

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

    # ── 稳态对账的唤醒源：挂载表变化事件（ns_mnt_watch.c + injector 接线）──
    # 事件源是 /proc/<pid>/mountinfo 的 poll 实现：该命名空间每次 mount/umount 后
    # 以 EPOLLERR 回报一次。驱动在 rootless 沙箱里真实挂/卸，量「空闲不自旋、变化必到、
    # 每次变化只报一次、读文件不吞事件」；静态契约锁住 injector 侧三条接线——注册掩码
    # 必须为 0（mounts_poll 恒置 EPOLLIN，带上就是忙轮询）、稳态等事件而事件源不可用时
    # 回落 GREPL_STEADY_SEC、两次动挂载之间必须有间隔闸（替换自身会触发事件源）。
    (("test_mnt_watch.py",),
     ("src/injector/ns_mnt_watch.c", "src/injector/ns_mnt_watch.h",
      "src/injector/injector.c"),
     ("ns_mnt_watch_open", "GREPL_STEADY_EVENT", "on_mnt_watch_event",
      "g_grepl_replace_gap"),
     "稳态对账由挂载表变化事件驱动"),

    # ── 补挂载盯梢的等待：有界 + 事件驱动（ns_mnt_wait.c + 盯梢线程接线）──
    # pre 阶段拿到的 pid 还在 zygote 的挂载 ns 里，真正的挂载要等应用自己的 ns 成立。
    # 过去是「睡 2ms、stat 一次」，检测滞后被步进锁死。驱动直编等待体（自备事件源
    # stub，可注入「打不开」与「挂载表变了」两种情形）：量切换检测延迟、预算到点必退、
    # CPU 不随预算增长、进程已死立刻收工、事件能把等待叫醒、没有事件源时退回节拍；
    # 静态契约锁住「等的是事件+纳秒节拍而不是固定步进」「注册掩码为 0」「超时仍走
    # 跳过 + 后台重试」「每轮醒来都用 stat 复核」。
    (("test_ns_mnt_wait.py",),
     ("src/injector/ns_mnt_wait.c", "src/injector/ns_mnt_wait.h",
      "src/injector/ipc_server.c"),
     ("ns_mnt_wait_switch", "ns_mnt_wait_capture", "NS_MNT_WAIT_ARM_US"),
     "补挂载盯梢的等待有界且由挂载表事件驱动"),

    # ── zygisk 模块 post-specialize 的等待预算（src/zygisk/post_wait.h + 下发链）──
    # pre 的 DEFER 应答带毫秒预算（proto 4 起），模块据此决定 post 等多久：0 = 不等待、
    # 一次 mountinfo 都不读；>0 = 按墙钟预算等挂载表变化事件再复探。解析逻辑单独成头
    # 文件，宿主 cc 直编跑真函数（矩阵含裸 DEFER/0/负数/乱码/超上限）；静态契约锁住
    # 「带数字的应答只发给认识它的模块」「模块用应答预算而不是编译期常量」「等的是
    # 事件不是步进」「两处上限同值」。
    (("test_zygisk_post_wait.py",),
     ("src/zygisk/post_wait.h", "src/zygisk/zygisk_module.cpp",
      "src/injector/ipc_server.c", "src/config/config_parser.c",
      "include/config_parser.h", "include/ipc_server.h"),
     ("nsp_post_wait_budget", "NSP_ZYGISK_PROTO", "IPC_PROTO_POST_WAIT",
      "ZYGISK_POST_WAIT_MS"),
     "zygisk post 等待预算由 injector 下发"),

    # ── 已挂载视图的连接活性（ns_mount_health.c）+ 启动扫描修复 ──
    # 直编探测原语 + --wrap=statfs：判据矩阵，以及「没有项目挂载时一次探测都不做」
    # （健康进程零行为变化）。静态契约锁住三处接线：两条挂载路径都必须先要求
    # target_fuse_unverified 才探测、启动扫描只在 FUSE 就绪分支跑一次且 v2/v3 直接返回、
    # 探测不得换成会被 FUSE 属性缓存骗过的 stat/statx。
    (("test_mount_liveness.py",),
     ("src/injector/ns_mount_health.c", "src/injector/mount_manager.c",
      "include/mount_manager.h", "include/ns_utils.h", "src/injector/injector.c"),
     ("ns_mount_conn_state", "ns_mount_needs_repair",
      "repair_stale_app_mounts_at_startup", "target_fuse_unverified"),
     "已挂载视图连接活性 / 启动扫描修复死连接挂载"),

    # ── mountinfo 读取容量语义（ns_mountinfo.c + ns_global_replace.c + mount_manager.c）──
    # 读取原先由调用方预分配 NS_MOUNTINFO_MAX(4096) 条，触顶只打一行 WRN 就把读到的
    # 那部分当结果返回——调用方分不清「表里只有 n 条」与「被截断了」；族根落在 4096
    # 之后时，替换/回滚/状态判定会把它当成不存在。现在按需增长，任何可能不完整的读取
    # （打开失败 / 内存不足 / 丢弃过超长行）都返回 -1「未知」，状态判定给 UNKNOWN、
    # 备份点给 NS_BACKUP_UNKNOWN；mount_manager 的挂载状态读取本身无上限，读不出结论
    # 一律返回 false 而不是「成功且没有挂载」。
    # ── 稳态对账快查（ns_global_status 的 dev 快判分支）──
    # 周期对账每 5s 一次，旧实现每次都整份读 + 逐行解析 mountinfo。稳态结论九成以上
    # 是「已替换」，判据只是「每个族根挂在当前 FUSE 源的超块上」。现在先按族根 dev
    # 快判（三族 × 数字用户各 stat 一次），判不出来才回落扫描；缺一个用户就是让那
    # 一族永久跳过对账，所以两段都要有判别用例。
    (("test_mountinfo_dynamic.py", "test_mount_state_read.py", "test_grepl_status_fast.py"),
     ("src/injector/ns_mountinfo.c", "src/injector/ns_global_replace.c",
      "src/injector/ns_global_replace.h", "src/injector/mount_manager.c",
      "src/injector/ns_utils.c", "include/ns_utils.h"),
     ("ns_read_mountinfo_pid", "ns_scan_mountinfo_stats", "read_mount_state",
      "NS_BACKUP_UNKNOWN", "ns_family_root_quick_replaced"),
     "mountinfo 读取容量语义 / 未知态不降级为未挂载"),

    # ── 事件通道归属（fw_events.c + fuse_daemon.c + nsp_events_status.c + log_ctl.c）──
    # nsp_fs_events / nsp_fs_query 是抽象 UDS，名字唯一：全局实例与媒体实例都曾尝试
    # bind，归属由启动竞态决定，输的那条实例的应用事件一条也发不出去，外部只表现为
    # 「事件功能随机全哑」。现在媒体实例不参与事件通道，归属固定给全局实例；任何一步
    # 失败都写 log/events_socket.status，log_ctl events 能查到持有者与处置提示。
    (("test_events_owner.py",),
     ("src/daemon/fw_events.c", "src/core/nsp_events_status.c",
      "include/nsp_events_status.h", "src/log/log_ctl.c",
      "include/nsp_constants.h", "src/daemon/fuse_daemon.c"),
     ("fw_events_start", "fw_events_record_result", "nsp_events_status_collect",
      "nsp_events_state"),
     "事件通道归属固定给全局实例 / 失败可从 log_ctl 查"),

    # ── 崩溃诊断窗口（crash_tail.c + injector.c）──
    # fuse_crash.log 是 append 打开的长期文件，历次启动的 stderr 都在里面；诊断原先
    # 摊尾部固定 16KB，会把上一轮启动的 linker 报错读成「本次崩溃原因」。窗口现在锚在
    # 本次 daemon 启动时的文件大小上，起点不可信时才退回尾部并丢弃可能的半行。
    (("test_crash_tail.py",),
     ("src/core/crash_tail.c", "include/crash_tail.h",
      "src/injector/injector.c", "include/injector.h"),
     ("crash_tail_window", "dump_crash_log_tail", "crash_log_start"),
     "崩溃诊断只取本次 daemon 启动之后的输出"),

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
      "src/core/fast_pid.c", "include/fast_pid.h",
      # 分流判别驱动（C11 + 写锁内真读盘 locks 段）改它也要重跑
      "tests/test_cfg_reload_split.py", "tests/fixtures/cfg_reload_split_driver.c"),
     ("fw_config_monitor_for", "fw_pkg_resolve"),
     "监控开关三层合并 / uid→包名（框架权威）"),

    (("test_pending_close.py",),
     ("src/daemon/fd_close_queue.c", "src/daemon/fd_close_queue.h",
      "src/daemon/fuse_daemon.c", "tests/test_pending_close.py",
      "tests/fixtures/fd_close_queue_test.c", "tests/fixtures/fd_reply_owner_test.c"),
     ("fdq_defer", "fdq_flush", "fdq_thread_defer", "fdq_thread_flush",
      "vfs_backing_setup", "vfs_init"),
     "慢 close 隔离、worker 回复 FD 所有权与退出回收"),

    (("test_pkg_cache_isolation.py",),
     ("src/daemon/fw_pkg.c", "tests/test_pkg_cache_isolation.py",
      "tests/fixtures/pkg_cache_isolation.c"),
     ("fw_pkg_is_privileged", "fw_pkg_uid_for_package", "fw_pkg_reload"),
     "包身份缓存锁外读取与代际发布隔离"),

    # uid.map 数组的借用/释放所有权：重载换表与请求线程并发时，旧实现先 free
     # 后 snprintf（ASan 实录 resolve_uncached heap-use-after-free）。
    (("test_pkg_map_lifetime.py",),
     ("src/daemon/fw_pkg.c", "src/core/uid_map.c", "include/uid_map.h",
      "tests/test_pkg_map_lifetime.py", "tests/fixtures/pkg_map_lifetime.c"),
     ("uid_map_copy", "uid_map_build"),
     "uid.map 换表与请求借表所有权（锁内拷贝）"),

    # 配置读槽 × 槽内慢能力查询：readdir/getattr 决策在 config_read_begin/end 槽里
     # fork 查 appops，发布者排空旧读者时被它拖住，随后每个 worker 都在
     # config_read_begin 上自旋（旧实现实测单次 300ms 查询 → 发布与迟到读者
     # 各等 270ms）。预取移到取槽之前。
     (("test_cfg_slot_isolation.py",),
      ("src/daemon/fw_rules.c", "src/daemon/fw_pkg.c", "src/config/config_parser.c",
       "src/daemon/fw_pkg.h", "tests/test_cfg_slot_isolation.py",
       "tests/fixtures/cfg_slot_isolation.c"),
      ("fw_pkg_prefetch_isolation_facts", "br_prefetch_xapp_facts", "fw_pkg_uid_map_name",
       "priv_cached_lookup", "fw_pkg_priv_cached", "fw_pkg_uid_cached", "br_isolation_slot",
       "BR_FACT_WARM_TRIES", "FW_PKG_PRIV_MISS_TTL_MS"),
      "配置读槽内的慢能力查询与慢身份事实（槽外预取 + 负结论缓存）"),

    # 跨应用白名单数组是配置指针：发布者在排空旧读者后释放它，槽外读者若在
    # 比较途中被发布穿插就会读已释放条目（ASan：fw_acl_identity → strlen(freed)）。
    # 槽外调用者改走槽内快照入口。
    (("test_acl_whitelist_lifetime.py",),
     ("src/daemon/fw_acl.c", "src/daemon/fw_rules.c", "src/daemon/fuse_daemon.c",
      "tests/test_acl_whitelist_lifetime.py", "tests/fixtures/acl_whitelist_lifetime.c"),
     ("fw_rules_cross_app_pkg_allowed_snapshot", "fw_rules_cross_app_access_snapshot"),
     "跨应用白名单数组的槽外借用（槽内快照）"),

    (("test_sys_pkg_isolation.py",),
     ("src/core/sys_pkg.c", "tests/test_sys_pkg_isolation.py",
      "tests/fixtures/sys_pkg_isolation.c"),
     ("sys_pkg_init", "sys_pkg_refresh", "sys_pkg_cleanup", "sys_pkg_is_system"),
     "系统包缓存慢构建、刷新与读者隔离"),

    (("test_ftp_lifecycle_isolation.py",),
     ("src/modules/ftp/ftp_backend_libcurl.c", "src/modules/ftp/ftp_mux.c",
      "tests/test_ftp_lifecycle_isolation.py",
      "tests/fixtures/ftp_lifecycle_isolation_test.c"),
     ("backend_add_server", "backend_clear_servers", "backend_find", "backend_mux_ref"),
     "FTP 生命周期慢构造及关闭不占服务元数据锁"),

    (("test_log_persist_isolation.py",),
     ("src/log/log_monitor.c", "tests/test_log_persist_isolation.py",
      "tests/fixtures/log_persist_isolation.c"),
     ("persist_stage", "persist_clear", "persist_worker_start", "persist_worker_stop"),
     "日志慢落盘与主事件循环隔离"),

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

    # 配置重载的 inotify 过滤：CONFIG_DIR 里还有别的工具维护的文件（包名对照表
    # list.config），旧实现的子串匹配把它当成配置文件，每写一次就整份重载。
    (("test_inject_reload_filter.py",),
     ("src/injector/injector.c",),
     ("reload_name_matches", "NSP_RELOAD_DEBOUNCE_MS", "NSP_RELOAD_MAX_DEFER_MS"),
     "配置重载只认 .conf 结尾（list.config 不再触发整份重载）"),

    # 1122 安全合并：源码包真实新增行为，旧源码路径可复验，不运行附件脚本。
    (("test_import_1122_daemon.py",),
     ("tests/test_import_1122_daemon.py", "tests/fixtures/import_1122_daemon_driver.c",
      "src/daemon/fw_rules.c", "src/daemon/fuse_daemon.c", "src/core/common.c", "include/common.h"),
     ("common_storage_child_path", "common_mkdir_storage_child", "common_apply_fd_attrs",
      "new_entry_mode", "br_ensure_sandbox_dir",
      "vfs_mknod", "chmod_acl_drop_note"),
     "沙盒 Android 补建、mknod 补父、ACL chmod 日志限频与路径边界"),
    (("test_import_1122_injector.py",),
     ("tests/test_import_1122_injector.py", "tests/fixtures/import_1122_injector.c",
      "src/injector/ipc_server.c", "src/injector/injector.c", "src/injector/ns_utils.c"),
     ("ipc_post_mount_thread", "retry_pending_mounts"),
     "超时盯梢入队、当前 UID/目标/命名空间重验及 passive 启动分支"),

    # FUSE worker 默认按核数取 min(max(4, ncpu), 16)，配置覆盖仍保留。
    (("test_fuse_threads.py",),
     ("include/fuse_threads.h", "src/daemon/fuse_daemon.c", "src/injector/injector.c",
      "src/config/config_parser.c", "include/config_parser.h", "docs/config.md"),
     ("nsp_default_fuse_threads", "g_fuse_threads_explicit", "fuse_threads"),
     "FUSE worker 线程数的默认取值与配置覆盖"),

    # HIDE 命中返回码：ENOENT 会被「失败就重试」的应用当成「还没生成」，
    # 一次启动把同一条路径打几百遍；HIDE_ERRNO 允许换成 EACCES/EPERM。
    (("test_hide_errno.py",),
     ("include/nsp_hide_errno.h", "src/daemon/fw_rules.c", "src/config/config_parser.c",
      "include/config_parser.h", "docs/config.md"),
     ("nsp_hide_errno_of", "hide_errno", "HIDE_ERRNO"),
     "HIDE 命中返回码可配（默认 ENOENT）"),

    # COPY_FILE_RANGE 一律交回内核：libfuse 高层 wrapper 在判断操作是否存在之前
    # 先取线程上下文，收尾窗口里上下文缺失就解空指针（现场 SIGSEGV 落在 libc 的
    # pthread_getspecific）；关掉低层派发后内核收到 ENOSYS 即永久改走 read/write。
    (("test_fuse_copy_range.py",),
     ("subprojects/libfuse/include/fuse.h", "subprojects/libfuse/lib/fuse.c",
      "subprojects/libfuse/lib/fuse_lowlevel.c", "src/daemon/fuse_daemon.c",
      "docs/architecture.md"),
     ("fuse_disable_copy_file_range", "copy_file_range_common", "COPY_FILE_RANGE"),
     "COPY_FILE_RANGE 一律交回内核（不进入 libfuse 高层回退路径）"),

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

    # 新建条目的权限值：mode 以调用方为准，父目录只提供属主与 setgid。
    # 判别点在「谁说了算」——旧实现用父目录整份 mode 覆盖调用方 mode，于是
    # umask 与应用显式的 0600/0700 一起失效，父目录被写成 2700 后还会自我繁殖
    # （2700 下再 mkdir 还是 2700）。真挂载上按不同 umask 建目录/建文件取值，
    # 并验证顶层目录的 chmod 被丢弃。
    (("test_entry_perms.py",),
     ("src/core/common.c", "include/common.h", "src/daemon/fuse_daemon.c",
      "src/daemon/fw_acl.c", "src/daemon/fw_acl.h"),
     ("nsp_new_entry_attrs", "fw_acl_is_structure_entry", "fw_acl_repair_storage_toplevel"),
     "新建条目权限值(mode 以调用方为准) / 顶层目录 chmod 丢弃"),

    # 跨树搬移的落位属性：rename 不产生新条目，来源树的属主与 mode 会跟着落地，
    # 共享存储里「属主是某个应用、mode 0600」的条目除写入者外谁也打不开（另存到
    # /sdcard/Download 的文件在文件管理器里 EACCES 就是这个形状）。判别点在「落位
    # 时按目标父目录重挂」：旧实现 A 组全失败；同属主改名与私有树落点必须原样不动。
    (("test_move_landing.py",),
     ("src/core/common.c", "include/common.h", "src/daemon/fuse_daemon.c"),
     ("nsp_rehome_moved_entry", "nsp_new_entry_attrs"),
     "跨树搬移的落位属性(rename 后按目标父目录重挂属主/mode)"),
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
#    或系统 log_monitor。彼此可并发，共享外部状态的那几对由 SUITE_RESOURCES 互斥；
#    与断言「宿主 mountinfo 零变化」的套件互斥（QUIET_ON_HOST）。
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
            "test_vfs_synth.py",
            "test_fw_events.py",
            "test_config_snapshot.py",
            "test_monitor_layers.py",
            "test_path_vars.py",
            "test_pending_close.py",
            "test_pkg_cache_isolation.py",
            "test_pkg_map_lifetime.py",
            "test_cfg_slot_isolation.py",
            "test_acl_whitelist_lifetime.py",
            "test_sys_pkg_isolation.py",
            "test_ftp_lifecycle_isolation.py",
            "test_log_persist_isolation.py",
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
            "test_mount_liveness.py",
            "test_mountinfo_dynamic.py",
            "test_mount_state_read.py",
            "test_submount_rules.py",
            "test_zygisk_post_wait.py",
            "test_ns_mnt_wait.py",
            "test_grepl_status_fast.py",
            "test_events_owner.py",
            "test_crash_tail.py",
            "test_log_ctl_rules.py",
            "test_commit_msg_lint.py",
            "test_build_scripts.py",
            "test_inject_reload_filter.py",
            "test_fuse_threads.py",
            "test_import_1122_daemon.py",
            "test_import_1122_injector.py",
            "test_hide_errno.py",
            "test_fuse_copy_range.py",
        ),
    ),
    "L1": (
        "GNU 真实后端/FUSE（按资源并发；FUSE 类需 /dev/fuse + fusermount3，"
        "test_sftp 需本机 sshd 于 127.0.0.1:2222）",
        (
            "test_functional.py",
            "test_rules.py",
            "test_decision_enforce.py",
            "test_fw_events_fuse.py",
            "test_acl_nonintrusive.py",
            "test_open_unlink_toplevel.py",
            "test_negative_timeout.py",
            "test_storage_root_guard.py",
            "test_readdir_skel_fallback.py",
            "test_entry_perms.py",
            "test_move_landing.py",
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
            "test_appops_bounded.py",
            "test_inject_mount_env.py",
            "test_global_replace.py",
            "test_mnt_watch.py",
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


# ── 共享状态冲突矩阵（逐个审计 tests/test_*.py 得出）──
# 每个套件的规则文件、挂载点、日志、模块目录都在自己的 BASE 下（规则文件曾被 8 个
# 套件共用 /tmp/Namespace-Proxy/injector.conf，现已各自搬进 BASE），所以真正共享的
# 只剩下面几处：
# 资源 S1 vsftpd 127.0.0.1:21 + 服务端目录（服务端文件互见）：test_ftp 与
#   test_ftp_parallel（二者还共用 BASE /tmp/fuse_ftp_test 和中继端口 2121）；
#   test_ftp_stress 同属这一组，但它是按需套件，不进 --all。
# 资源 S2 系统级 log_monitor（抽象套接字 nsp_log_socket 单例 + 系统 LOG_DIR）：
#   test_log_pipeline（重启系统实例 + 备份还原 /var/fuse-proxy/log 下 io/sys.log）、
#   test_rule_server（SERVICE 段 pkill -9 -x log_monitor 并拉起系统实例）、
#   test_inject_mount_env（沙箱内自起 log_monitor -p）。
# 资源 S3 BASE /tmp/fuse_proxy_test：test_functional 与 test_log_pipeline 同名。
# 宿主挂载表：L1 的 FUSE 挂载就落在宿主命名空间里，故断言「宿主 mountinfo 全程零
#   变化」的套件（QUIET_ON_HOST）必须独占到没有别的套件正在挂/卸；它们彼此之间也
#   互斥——对方的一次挂载对它就是一次变化。
# 曾经的全局副作用已就地收窄：test_functional / test_rules 的收尾清理改成只杀
#   自己起的 daemon（按 --rules=<本套件 CONF> 精确匹配，原来的 pkill -f fuse_daemon
#   会杀掉并发套件的 daemon）；全局 pkill -x log_monitor 只剩 Tier2 两套件。
# 结论：除 S1/S2/S3 与宿主挂载表外，套件之间没有共享状态，可以并发。
#
# Tier 0 = 宿主零副作用的套件：判据是「不进宿主命名空间挂载、不 bind 固定端口、
# 不做全局 pkill、不碰系统 log_monitor 与真实日志文件」（规则文件/工作目录自管即可，
# mkdtemp 或自有 BASE 都算）。这类套件彼此之间、以及与其他挂载类都能同时跑。
# 「自管 daemon、只杀自己那个 pid」不构成豁免：daemon 一挂载就落进宿主命名空间，
# 那一次挂载对断言 mountinfo 零变化的套件就是实打实的污染（判据里「不进宿主命名
# 空间挂载」就是这一条）。所以起 daemon 的套件一律按挂载类对待，哪怕它自己收尾
# 收得干净。
# 不在本名单里的套件按「会动宿主挂载」对待，与 QUIET_ON_HOST 互斥（见「并行调度」段）。
# 新套件默认按挂载类对待，要进白名单须先核对判据。
PARALLEL_SAFE = frozenset({
    "test_docs_sync.py",          # 纯静态读文件（文档/台账一致性），无子进程/无挂载
    "test_acl.py",                # cc 直编 fw_acl.c + 纯逻辑驱动，TemporaryDirectory，无挂载
    "test_fw_events.py",          # cc 直编 fw_events.c + 驱动，TemporaryDirectory；
                                  # 只 bind 自己 pid 命名的抽象地址，不碰全局 nsp_fs_*
    "test_config_snapshot.py",    # cc 编译夹具直跑，TemporaryDirectory
    "test_module_abi.py",         # cc 编译 ABI 夹具，无 daemon（TemporaryDirectory）
    "test_path_vars.py",          # cc 编译直跑（mkdtemp）
    "test_monitor_layers.py",     # cc 编译实际源码 + 合成 uid，无挂载（TemporaryDirectory）
    "test_log_ctl_rules.py",      # 全走 mkdtemp（--config-dir 指向临时目录）
    "test_inject_method.py",      # conf 全走 mkdtemp + global_replace_ctl 驱动，无 daemon
    "test_mount_liveness.py",     # cc 直编 ns_mount_health.c + --wrap=statfs，无挂载/无 daemon
    "test_mountinfo_dynamic.py",  # cc 直编 ns_mountinfo.c/ns_global_replace.c + --wrap=fopen，
                                  # 合成 mountinfo，无挂载/无 daemon
    "test_mount_state_read.py",   # cc 直编 mount_manager.c + 桩，合成 mountinfo，无挂载/无 daemon
    "test_submount_rules.py",     # 直编 mount_manager/common + 合成 mountinfo，无挂载/无 daemon
    "test_zygisk_post_wait.py",   # cc 直编 post_wait.h + 静态读源码，无挂载/无 daemon
    "test_grepl_status_fast.py",  # cc 直编 ns_mountinfo.c/ns_global_replace.c + --wrap 桩
                                  # stat/opendir/readdir/fopen，合成族目录，无挂载/无 daemon
    "test_events_owner.py",       # cc 直编 nsp_events_status.c + 只读 /proc 快照，不起 daemon
    "test_crash_tail.py",         # cc 直编 crash_tail.c 纯函数，无文件/无 daemon
    "test_crash_log.py",          # --crash-test 挂载前退出，日志只写 mkstemp 临时文件
    "test_ftp_read_restart.py",   # cc+mock 直跑（TemporaryDirectory），无 FUSE/网络/端口/pkill
    "test_pending_close.py",      # 真实队列/FD/线程与 daemon wrapper，临时目录，无挂载
    "test_pkg_cache_isolation.py", # 真实 fw_pkg + 定向文件 gate，临时目录，无挂载
    "test_pkg_map_lifetime.py",   # 真实 fw_pkg/uid_map + 私有 uid.map，临时目录，无挂载
    "test_cfg_slot_isolation.py",  # 真实 fw_rules/fw_pkg/parser + 测试钩子，临时目录，无挂载
    "test_acl_whitelist_lifetime.py", # 真实 fw_acl/fw_rules + 真实发布协议，临时目录，无挂载
    "test_sys_pkg_isolation.py",   # 真实 sys_pkg/parser + 文件 gate，临时目录，无挂载
    "test_ftp_lifecycle_isolation.py", # 真实 backend/mux/curl file://，无网络或挂载
    "test_log_persist_isolation.py", # 原 log_monitor TU/满pipe，无服务或全局日志
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
    "test_inject_reload_filter.py",  # 抽出 injector.c 的纯函数直编，无挂载/无 daemon
    "test_fuse_threads.py",          # 抽出 fuse_threads.h 的内联函数直编，无挂载/无 daemon
    "test_import_1122_daemon.py",    # 实际函数 + common，temp FIFO/目录，无挂载/无 daemon
    "test_import_1122_injector.py",  # 实际函数 + retry_queue，合成 proc/ns，无挂载/无 daemon
    "test_hide_errno.py",            # 直编 nsp_hide_errno.h 的内联函数，无挂载/无 daemon
    "test_fuse_copy_range.py",       # 只读源码文本做静态契约，无挂载/无 daemon
})
# Tier 2 独占：碰全局 log_monitor（R6）的套件，串行且排在最后执行，保证收尾时
# 系统 monitor 已还原，不干扰其他套件。
TIER_EXCLUSIVE = frozenset({
    "test_log_pipeline.py",
    "test_rule_server.py",
})
# 注意：test_rule_server.py 主体已隔离（临时 conf_dir + PID 后缀 socket），但
# SERVICE 用例会 pkill -9 全局 log_monitor 并拉起系统实例，故仍归 Tier 2。

# 断言「宿主 mountinfo 全程零变化」的套件：运行期间不允许任何别的套件在宿主命名
# 空间里挂/卸（L1 的 FUSE 挂载就落在宿主 ns），它们彼此之间也一样。调度器先让它们
# 独占跑完，再放挂载类进来——否则写锁永远等不到「零读者」那个瞬间。
QUIET_ON_HOST = frozenset({
    "test_appops_bounded.py",
    "test_inject_mount_env.py",
    "test_global_replace.py",
    "test_mnt_watch.py",
})

# 互斥资源：同名资源的套件不并发，不同资源之间可以。只登记「真的共享外部状态」的
# 那几处（见文件上方冲突矩阵），别把「同一类的」当资源——那等于退回全串行。
SUITE_RESOURCES = {
    "test_ftp.py": {"vsftpd-21", "ftp-base"},
    "test_ftp_parallel.py": {"vsftpd-21", "ftp-base"},  # 中继口 2121 只有它用
    "test_functional.py": {"base-fuse-proxy-test"},
    "test_log_pipeline.py": {"base-fuse-proxy-test", "system-log-monitor"},
    "test_rule_server.py": {"system-log-monitor"},
    "test_inject_mount_env.py": {"system-log-monitor"},
}


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
    """套件分 Tier：0=宿主零副作用，1=会动宿主挂载（彼此可并发），2=独占收尾
    （系统 log_monitor）。互斥由 SUITE_RESOURCES / QUIET_ON_HOST 另行给出。"""
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


def claim_of(name):
    """套件要独占的资源集合与宿主挂载姿态：("quiet"|"mount"|"free")。

    quiet = 要求宿主挂载表全程零变化（独占，写锁）；mount = 会进宿主命名空间挂载
    （可互相并发，读锁）；free = 宿主零副作用（Tier 0 白名单，不参与挂载锁）。
    """
    if name in QUIET_ON_HOST:
        mode = "quiet"
    elif name in PARALLEL_SAFE:
        mode = "free"
    else:
        mode = "mount"
    return SUITE_RESOURCES.get(name, frozenset()), mode


def can_start(mode, st, quiet_left):
    """调度门：现在能不能再放一个套件进来。

    quiet 是「断言宿主挂载表全程零变化」的姿态，必须全场没有别人在跑——别的套件
    一次挂载对它就是一次变化，所以连另一个 quiet 也不能并存（它们各自比对自己
    那份 mountinfo 快照）。mount / free 反过来要等安静套件跑完且队列清空，否则
    安静套件永远等不到「零读者」那一刻（写者优先，防饥饿）。
    """
    if mode == "quiet":
        return st["running"] == 0
    return not st["writer"] and quiet_left == 0


def report_parallel(name, rc, dt, out):
    """并行套件的输出：整块打印，避免多套件在终端里交错。"""
    print(f"\n{'━' * 60}\n▶ {name}（并行，{dt:.1f}s）\n{'━' * 60}", flush=True)
    print(out, end="", flush=True)
    if classify(rc) == "FAIL":
        print(f"\n❌ {name} 失败（退出码 {rc}，{dt:.1f}s）")
    elif is_gap(rc):
        print(f"\n⏭ {name} 跳过（退出码 {rc}，gap 不计通过）")


def run_pool(suites, jobs):
    """按资源门调度：能立刻开跑的套件才占 worker，返回 {套件名: (rc, dt, out)}。

    与「白名单并行、其余串行」的区别：worker 不再空等。资源冲突只让**那一个**
    套件排队（挂载类彼此不冲突，照样并发）。安静姿态（要求宿主挂载表零变化）是
    排他的：它开跑时全场必须已经空了，跑的过程中也不再放任何套件进来——一次外来
    挂载就能把它的前后快照比对搞红，且这种红是间歇的、很难复现。
    """
    done = {}
    cv = threading.Condition()
    st = {"running": 0, "readers": 0, "writer": False, "busy": set()}
    pending = list(suites)
    quiet_left = sum(1 for s in pending if claim_of(s)[1] == "quiet")

    def startable(name):
        res, mode = claim_of(name)
        if st["busy"] & res:
            return False
        return can_start(mode, st, quiet_left)

    def worker(name, res, mode):
        rc, dt, out = run_suite(name, True)
        with cv:
            st["busy"] = st["busy"] - res
            if mode == "quiet":
                st["writer"] = False
            elif mode == "mount":
                st["readers"] -= 1
            st["running"] -= 1
            done[name] = (rc, dt, out)
            report_parallel(name, rc, dt, out)
            cv.notify_all()

    with cv:
        while pending or st["running"]:
            launched = False
            for name in list(pending):
                if st["running"] >= jobs:
                    break
                if not startable(name):
                    continue
                res, mode = claim_of(name)
                pending.remove(name)
                st["busy"] = st["busy"] | res
                if mode == "quiet":
                    st["writer"] = True
                    quiet_left -= 1
                elif mode == "mount":
                    st["readers"] += 1
                st["running"] += 1
                threading.Thread(target=worker, args=(name, res, mode),
                                 daemon=True).start()
                launched = True
            if not launched:
                cv.wait()
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
                    help=f"并发 worker 数，默认{DEFAULT_JOBS}（上限{MAX_JOBS}）；"
                         "共享资源的套件按 SUITE_RESOURCES 互斥，其余照常并发")
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
    mounted = [s for s in suites if tier_of(s) == 1]
    free = [s for s in suites if tier_of(s) == 0]
    exclusive = [s for s in suites if tier_of(s) == 2]
    for s in suites:
        tag = {0: "无挂载", 1: "挂载类", 2: "独占收尾"}[tier_of(s)]
        if s in QUIET_ON_HOST:
            tag = "挂载类·宿主静默"
        print(f"  [{tag}][{layer_of(s) or '未分层'}] {s}")
    print("命中条目：" + ("、".join(rows) if rows else "无"))
    if args.list:
        return 0

    # 调度顺序即优先级：要求宿主挂载表零变化的套件要独占跑，排后面会一直等挂载类
    # 落地，所以放最前；无挂载的小套件随后塞满剩余 worker；最后放开挂载类并发。
    # Tier 0 恒执行（此前 `if args.jobs > 1 and t0` 让 --jobs 1 时整组 Tier0 被
    # 漏跑，t1+t2 为空时汇总仍是「共 0、通过」、rc=0）。
    order = ([s for s in mounted if s in QUIET_ON_HOST] +
             free +
             [s for s in mounted if s not in QUIET_ON_HOST])
    got = {}
    if args.jobs > 1 and order:
        for s, (rc, dt, _) in run_pool(order, args.jobs).items():
            got[s] = (rc, dt)
    else:
        for s in order:
            rc, dt, _ = run_suite(s)
            got[s] = (rc, dt)
            if classify(rc) == "FAIL":
                print(f"\n❌ {s} 失败（退出码 {rc}，{dt:.1f}s）")
            elif is_gap(rc):
                print(f"\n⏭ {s} 跳过（退出码 {rc}，gap 不计通过）")
    # Tier 2 仍最后串行：这些套件碰系统 log_monitor，收尾时把系统实例还原回原状，
    # 不与任何并发任务交叉（含它们自己的 pkill -9 -x log_monitor）。
    for s in exclusive:
        rc, dt, _ = run_suite(s)
        got[s] = (rc, dt)
        if classify(rc) == "FAIL":
            print(f"\n❌ {s} 失败（退出码 {rc}，{dt:.1f}s）")
        elif is_gap(rc):
            print(f"\n⏭ {s} 跳过（退出码 {rc}，gap 不计通过）")
    results = [(s, got[s][0], got[s][1]) for s in suites if s in got]

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
