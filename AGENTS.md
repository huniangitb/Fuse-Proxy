# AGENTS.md

Android 13+ 用户态 FUSE 存储代理（root 模块二进制核心），C23 编写，Meson + Ninja 构建。

## 构建

- **陷阱**：`target_os` **默认是 `android`**。不带 `-Dtarget_os=gnu` 在普通 Linux 上必然失败（依赖 NDK clang）。
- GNU 本机：`scripts/build.sh`（默认 `build_gnu/`）。第三方依赖系统库优先、缺失回退子模块，clone 后一键成功。
- Android 交叉：`scripts/android-build.sh`，或 `meson setup build --cross-file android-aarch64.ini && ninja -C build`。cross 文件须含 `cmake = 'cmake'`（cmake 子项目交叉必需）与 `host_machine.system = 'android'`（libfuse 的 librt 豁免开关）。`-Dandroid_{libfuse,json_c,curl}=prebuilt` 可切回预构建（需 `-Dfuse3_root=` / `-Dcurl_dir=`）。
- 产物：`fuse_daemon`（含内建规则引擎 `fw_rules`）、`log_monitor`、`log_ctl`、`rule_server`、`ftp_module.so`（全平台）；`injector` 与 Zygisk 通知模块 `src/zygisk/{arm64-v8a,armeabi-v7a}.so` 仅 Android；`global_replace_ctl` 仅 GNU（测试驱动，不 install）。仅 `fuse_daemon` 带 `-DFUSE_USE_VERSION=317` 与 `-Wl,--export-dynamic` 导出公共符号供模块解析；模块与 `rule_server` 均不链接 libfuse3。
- Zygisk 模块经 `custom_target` 直接调 NDK `clang++` 编双 ABI（`src/zygisk/meson.build`），**不给 `project()` 加 cpp 语言**——否则 GNU 构建也会要求 C++ 编译器。它与主项目零链接关系，注入 zygote 子进程，故禁 STL（`-nostdlib++`）、禁 RTTI/异常；改动后必须确认 `readelf -d` 无 `libc++_shared.so`。
- 调试：`-Denable_debug=true`（可叠加 `-Dwith_asan=true` / `-Dwith_ubsan=true`，sanitizer 仅 debug 下生效）；默认 `-O3 -flto -Wl,-s`。
- 打包：`scripts/pack-module.sh`（同步 `build_android/` 产物到模块骨架，产出 zip 与符号包）。
- **libfuse 子模块是自维护 fork**（`huniangitb/libfuse` 分支 `master-Android`，与 `~/libfuse` 同源），已含 Android 适配与**分支追加接口** `fuse_invalidate_path_entry()`（entry 级缓存失效，导出版本节点 `FUSE_3.19`，见 `lib/fuse.c` + `lib/fuse_versionscript`）。该接口**只在 `libfuse_source=subproject/custom` 与 Android 默认（子模块）构建下存在**；系统 pkg-config 库与 `prebuilt` 没有，故框架侧用**弱引用**（`fuse_daemon.c` 的 `vfs_inval_path`）：缺失时自动退化为仅 inode 级 `fuse_invalidate_path`，不破坏「系统库优先、clone 后一键成功」。改动子模块源码后须确认 `ninja -C build_sp_patch`（`-Dlibfuse_source=subproject`）通过（该接口无自动化用例：曾经的 `test_libfuse_inval.py` 探针在本机会随机挂起，已移除）。

## 开发流程

1. 先读对应文档：架构 `docs/architecture.md`、模块 `docs/modules.md`、配置语法 `docs/config.md`。
2. 按归属写代码：纯 libc 无全局依赖的公共工具进 `src/core/nsp_util.c`（禁止各文件私刻副本）；依赖项目全局（`g_real_root`、日志）的进 `src/core/common.c`；跨进程/跨模块常量进 `include/nsp_constants.h`、日志级别与宏进 `include/nsp_log.h`（两者均为唯一出处）；新跨文件函数必须带域前缀（见 `docs/architecture.md` §7）。
3. 同步测试：改了行为就地补用例，跑下方映射表全绿。
4. 提交：仓库文档与提交信息均中文，Conventional Commits 前缀（`fix:`/`feat:`/`docs:`/`refactor:`/`perf:`）。

### 红线（破坏即回滚）

- 同一模块 ABI 版本内不改 fuse_daemon 导出表公共符号签名——已编译模块靠 `b_lundef=false` + `--export-dynamic` 解析它们。授权升 ABI 时（如本次 V1→V2）允许破坏签名/删字段，但必须递增 `NSP_MODULE_ABI_VERSION` 让加载器拒绝旧版本（见 `docs/modules.md` §3/§6.5），不得静默改变既有版本的语义。
- 不破坏"REDIRECT 虚拟前缀不含 user_id，FUSE 层剥离 `/0/` 后再匹配"约定。
- 路径合成走 `common_*` 唯一出口（禁止裸拼，`MAX_PATH_LEN` 放不下返回 -1 而非截断）。
- 决策强制只在 `fw_route` / `vfs_apply_attr_override` 单点——新增回调不得自行手写 hidden/ro 判定（V3 已收敛，散落判定会重新漂移）。
- YAGNI——不留无调用者的预留实现。

## 测试流程（纯 Python，无 C 测试目标）

**一条命令**：`python3 tests/run.py` —— 自动按「本次改动的文件 + 改动行里的符号」匹配下表，依次执行选中的套件并汇总退出码。`--list` 只看会跑哪些、`--all` 忽略映射跑全量、`--base <ref>` 换对比基线（默认 `HEAD`，即暂存+未暂存+未跟踪）、尾部直接给脚本名则跳过自动匹配、`--strict` 为验收模式（跳过项计为失败）。`--jobs N` 并行加速：仅 `PARALLEL_SAFE` 白名单内的无共享状态套件进线程池（挂载类恒串行，`test_rule_server.py` 因全局 `pkill log_monitor` 副作用被排除），其余仍串行；`--jobs 1` 亦会跑 Tier0（不再整组漏跑）。下表的可执行形式是 `tests/run.py` 的 `SUITE_MAP`，**两边须同步维护**；各脚本仍可单独直接跑。

**套件退出码约定（防假绿）**：`0`=通过、`1`=失败、`77`=环境不具备**整套**跳过（gap）、`78`=**部分子组**跳过（gap，如 `test_log_pipeline` 的类别段组、`test_rule_server` 的 SERVICE 段）、`127`=套件文件不存在（**计为失败**——拼错名字不得静默通过）。`run.py` 汇总区分 PASS/FAIL/跳过(gap)，**跳过不计通过**；验收须用 `--strict` 让 gap 变成失败。

前置：GNU 产物 `build_gnu/`、`fusermount3`、`/dev/fuse`、Python `sqlite3`。非默认产物路径用环境变量覆盖：`FUSE_DAEMON`、`FTP_MODULE_SO`、`GLOBAL_REPLACE_CTL`、`LOG_CTL`、`LOG_MONITOR`。

按改动跑映射（全绿方可提交）：

| 改动 | 测试 |
|---|---|
| 内建规则引擎（`src/daemon/fw_rules.c`）/ `fuse_daemon.c` / `config_parser.c` | `test_rules.py`（44，含本地大目录断点续扫）、`test_config_snapshot.py`、`test_monitor_layers.py`（MONITOR 三层合并）、`test_decision_enforce.py`（决策强制单点 errno 矩阵）、`test_negative_timeout.py`（-o negative_timeout 熔断：未命中后建文件立即可见）、`test_readdir_skel_fallback.py`（lstat 拒绝时骨架名回退合成目录条目）、`test_backing_gate.py`（backing 仲裁门 16 项：全局 8 + 按路径 8） |
| `src/modules/ftp/` 或框架后端分派 | `test_ftp.py`（24，需 vsftpd；含 V5 分页 700 文件大目录列全；3c **fsync 落远端判别用例**——write+fsync 后、close 之前核对远端已有内容，旧实现 `vfs_fsync` 对后端句柄返回 0 时必失败；3d **写模式回灌判别用例**——远端预置非空文件（探针须 0666，否则匿名用户无权覆盖会把权限问题伪装成缺陷）→ `open(O_RDWR)` 先 `pread` 应读到远端内容 → 尾部 `pwrite` → close 后远端**前段仍在**；旧实现只 mkstemp 空 tmp、全量 STOR 覆盖，前段变 NUL 空洞必失败；3e **后端列举可见性判别用例**——FTP 列举里 HIDE 条目必须不出现且直接访问 ENOENT（旧实现后端 readdir 零 probe 过滤，名字泄露）；6b 后端 rename 带 flags 必须 EINVAL（旧实现忽略 flags 直接改名）；**收尾按 `nsp_` 前缀自清 `/home/bdy/ftp/upload` 残留**——该目录同时是用户投递目录）、`test_backend_lifecycle.py`（后端引用配对/真卸载，无需 vsftpd）、`test_ftp_read_restart.py`（读缓冲随机跳变竞态，无需 vsftpd）、`test_ftp_parallel.py`（14，控制面并发/连接复用/延迟收敛/热重载竞态/断连熔断自愈，需 vsftpd；自起延迟中继，占用 127.0.0.1:2121；阶段 B 列 12 个不同目录以绕开 V5 LIST 缓存；工件用 `nsp_par_` 前缀并在 finally 对 `upload/` 与 chroot 根下 `upload2/` **两处**按宽前缀自清——按 pid 限定只能清自己那份，历史/异常退出的会永久堆积）、`test_ftp_truncate_list.py`（truncate 清 LIST 缓存：直编后端 + 桩 mux/curl 注入服务端状态，无网络——旧实现不清 LIST 时列举命中旧缓存把截断前 size 回灌 stat。**另含 A15 判别**：合成 LIST 正文含 `.hidden`/`.git`，断言点条目照常上架——旧实现 `name[0] != '.'` 把所有点开头名字一起丢掉；端到端不可观测，因本机 vsftpd 默认 `force_dot_files=NO` 的 LIST 根本不回点条目）、`test_ftp_upload_lock.py`（**上传锁泄漏判别用例**：直编后端 + 桩 mux/curl，乱序改写→FLUSH 全量重传→trylock 断言锁未泄漏 + 看门狗断言续写/release 不挂起；旧实现上必失败） |
| `src/modules/ftp/ftp_mux.c`（epoll + curl_multi 控制面复用器）或 `backend_rc_is_business`（业务 errno 豁免） | `test_ftp_parallel.py`（连接复用与延迟收敛）、`test_module_circuit.py` §9（业务 errno 不得触发熔断/ban） |
| `src/config/path_vars.c` | `test_path_vars.py` |
| injector 目标判定 / 注入方法（`inject_target.c`、`--inject-method=v1\|v2\|v3`） | `test_inject_method.py`（31，v1/v2/v3 判定矩阵：v3 忽略 `GLOBAL_INJECT`/`SKIP_SYSTEM_APPS` 而段头 `OFF` 仍生效、派生标志、非法值拒绝）、`test_global_replace.py`（rootless unshare 沙箱内 v2 替换/还原/审查生命周期，userns 不可用自动跳过） |
| injector 挂载/清理序列（`ns_utils.c` 跨 ns bind 与 preserve 路径、`ns_global_replace.c` 替换/备份/还原、`cleanup_app_mounts`、`injector.c` 拉起 FUSE 的 execv 参数装配） | `test_inject_mount_env.py`（38/42/41，rootless unshare 沙箱仿真安卓拓扑内 v1/v2/v3 全生命周期：注入→REQ→SIGTERM 清理→退出后宿主 mountinfo 前后比对零污染，缺产物/userns 不可用自动跳过。**配置含 24 token 的 `FUSE_EXTRA_ARGS`（全为 `-f`，对 libfuse 合法且重复无副作用）——A11 判别**：旧实现 token 守卫 `ai < 31` 未给尾部固定的 `-f`/`-o`/挂载选项/NULL 4 项预留，末条 token 写到 `args[31]` 之后；ASan 构建下必报 `stack-buffer-overflow … inject_global_fuse`，FUSE 起不来）、`test_ns_combined_rollback.py`（合并挂载失败回滚：直编 `ns_utils.c` + `--wrap=mount/umount2` 注入 mount 失败，断言以族根回滚而非留应用于裸状态）、`test_ns_umount_overflow.py`（**mountinfo 扫描栈越界判别**：直编 `ns_utils.c` + ASan + `--wrap=fopen/umount2`，合成 mountinfo 填满容量且末条挂载点 >256 字节——旧实现 `strncpy(mounts[i], mp, PATH_MAX-1)` 写爆 `char[256]` 槽、ASan 必报 stack-buffer-overflow；新实现跳过超长条目并 loud 告警，其余条目仍全量卸载） |
| 受管子进程收尸留档（`reaped_managed.c`、`injector.c` 的 `reap_zombies`/崩溃恢复） | `test_reaped_managed.py`（直编收尸留档 + 真实 fork：通用收尸先到仍能取回退出状态——旧实现 waitpid 得 ECHILD 致崩溃现场不入日志环；含未收尸兜底/消费语义/负例） |
| `src/module/`（加载器/内存副本加载/围栏/熔断/ABI） | `test_modules.py`（残留旧 ABI 模块：加载前拒绝/按 mtime 落 ban/不泄漏 memfd fd/不挡真更新 + 旧哈希格式 ban 自愈）、`test_module_circuit.py`（故障隔离：后端载体；**§11 A12 quiescence 门控判别**：`backend_hold` 建模 FTP 形态——自带配置线程 + 由句柄拥有的数据面线程（exit 不 join），标记文件使 `nsp_module_active_handles()>0`；熔断置毒后断言 daemon 存活 + `memfd:nsp_module_backend_hold` **仍在 maps**（门控跳过 dlclose）；旧实现实测 daemon rc=-11 且映射消失）、`test_module_abi.py`（V5 布局契约/旧版本 V1/V2/V3/V4 拒载/最小后端模块/20 模块注册表增长）、`test_backend_lifecycle.py`（后端引用配对/真卸载 + **热重载放弃新实例时必须先经围栏 exit 停其自有线程再 dlclose**：旧实现直接 dlclose，用例实测 daemon rc=-11） |
| 决策强制单点（`fw_route` 的 appear_missing→ENOENT、read_only→EROFS） | `test_decision_enforce.py`（38，逐回调 errno 矩阵，规则来自配置 HIDE/RO） |
| `src/daemon/fd_close_queue.c`（Android backing fd 延迟关闭环形队列） | `test_pending_close.py`（12：多生产者/多消费者下每个 fd 恰好关一次；队满不阻塞且不制造被放弃槽位——饱和→flush→再入队仍能延迟；双消费者独占领取由钩子阻塞撑开窗口断言。旧「先占号再判满 + 无独占领取」实现在饱和与双消费者两条上必现失败：前者挂死/队列永久失效，后者重复关闭） |
| `log_ctl` / `rule_server` 规则编辑（`nsp_rule_file`） | `test_log_ctl_rules.py`（58，含**停用态**：编辑仍落 `.conf.disabled`、不新建 `.conf`；**含 A5 段内索引判别**：`[GLOBAL]` 与 `[USER_APPS:0]` 各一条同类型规则时 `remove-rule USER_APPS <type> 0` 必须删类别段那条——旧实现按整文件序号计数必删到 GLOBAL）、`test_rule_server.py`（含 **EXPORT_LOGS**：落点必须在 `<CONFIG_DIR>/export`（root 私有 0700，**不得**落共享存储——旧实现落 `/data/media/0`，任意应用可预置软链令 root 的 tar/chmod 覆盖任意文件）、包内含 log、连续两次导出只留最新一份、历史堆积一次调用收敛、日志目录缺失明确拒绝；**含 A5 混合段往返**：GET 类别段报段内索引、REMOVE/ENABLE/DISABLE 同口径，且 `GET GLOBAL` 只回 `[GLOBAL]` 段不混类别段）、`test_rule_file_lock.py`（4 进程并发 upsert 各 150 条 → 恰好 600 条无重复：目录 flock 串行化读改写 + 临时名带 pid；去掉锁实测只剩约 200 条。**另含 A10 判别**：规则文件 chmod 000 后 upsert 必须返回 EIO 且原文件逐字不动——旧实现把「读失败」的 NULL 当空文件，写回「段头+1 条」把 3 条原规则全丢；以 root 运行该组跳过计 gap。**另含 A6 判别**：另起进程持有规则目录 flock 不放，断言「调用侧读改写」形态立即返回（不串行化的窗口）、`nsp_rule_file_toggle_nth_scoped` 阻塞到放行——toggle 若又退化成不持锁的读改写即失败） |
| 日志链路（`src/log/`、`nsp_comm.*`、`nsp_log.h` / `nsp_util.c` 的 `nsp_log_level_*`、`common.c` 的 `vfs_log_io` / `monitor_on` / `persist_stage` / `drain_async`） | `test_log_pipeline.py`（30，框架闸门矩阵：无规则记录 / 路径无 `<uid>/` 层 / `MONITOR OFF` / 类别段 `[SYSTEM_APPS]` 否决与开启五态 + 磁盘历史全量可查（`count`/`search`/历史转储三条路径）+ 等级字段渲染为名称且旧数字行仍可解析、非法等级行跳过 + sock 查询端到端；**会重启 log_monitor 并备份还原 `io.log{,.1}` 与 `sys.log{,.1}`**） |
| `src/daemon/fw_config.c`（含规则文件/App-rules 的 inotify 监听线程——热重载触发路径本身） | `test_monitor_layers.py`、`test_cfg_watch.py`、`test_rules.py`（重载语义端到端） |
| `src/daemon/cfg_watch.c`（App-rules* 子目录 watch 对账） | `test_cfg_watch.py`（7：只对 `App-rules[-<uid>]` 挂 watch、普通子目录不挂；子目录内 tmp+rename 能产生可读事件（旧实现完全不监听这些目录→应用级规则改了不生效）；目录消失摘表、基目录不可读返回 false 走兜底重扫） |
| 框架侧规则解析：uid→包名（`fw_pkg.c`）、MONITOR 三层合并（`fw_config_monitor_for`）、沙盒/ALLOW 解析（`fw_rules.c`） | `test_monitor_layers.py`（20：uid→包名与 MONITOR 合并 11 项；**沙盒解析契约 9 项**——`SANDBOX ON` 时 Download/Pictures/Documents 等共享目录一并重定向进本应用沙盒、自己的 data/obb 与 `/Android` 下非 data/obb 不重定向、`ALLOW` 落回真实路径。本机 uid<10000 恒走 system 分支测不到这些，故自编译实际源码 + 合成 uid，不经 Meson）、`test_cfg_watch.py`（`fw_config.c` 改动同时跑配置目录 watch 套件） |
| 通用回归 | `test_functional.py`（73，IO/SQLite/并发/rmdir 标准语义/**rename flags**/**跨设备 rename**）、`test_crash_log.py` |
| 压力（按需） | `stress_fuse.py`、`test_ftp_stress.py` |

特殊前置：`test_ftp.py` 需本机 vsftpd 匿名服务（127.0.0.1:21，匿名根只读 + `upload/` 可写）；`test_config_snapshot.py`、`test_module_abi.py` 不经 Meson，直接用本机 `cc` 临时编译实际源码（前者另需 json-c），故不依赖 `build_gnu/`；

失败处理：退出码 1 为失败（勿用管道吞退出码）；**跳过（77/78）不算通过**——验收用 `python3 tests/run.py --all --strict` 让 gap 计为失败，并逐条核对跳过原因；残留挂载点（`/tmp/fuse_proxy_test/mnt`、`/tmp/fuse_rules_test/mnt`、`/tmp/fuse_neg_test/mnt`）用 `fusermount3 -u` 清理后重跑；测试规则文件在 `/tmp/Namespace-Proxy/injector.conf`。

**测试自清约定**（写**真实** FTP 树 `upload/`、`upload2/` 的套件适用，那是用户的投递目录，会无界累积）：清扫必须按**宽前缀 / 模式**（`nsp_`、`nsp_par_`、`conc_*.bin`…），**不得**用含 `os.getpid()` 的名字限定——否则只能清自己那份，异常退出（或修好前的历史运行）留下的 `nsp_par_<旧 pid>_*` 永久堆积。写盘位置与清扫位置要**成对**（如 `upload2/` 有写就得有扫）。判定是否残留**用 `find -name`，不要用 `ls | grep '^前缀'`**：本机 `ls` 是 eza、输出带图标前缀，锚定 grep 恒假阴性。判别性验证时探针要选套件**不碰**的名字，否则会伪装成套件缺陷（例：往真实树预置 `pat_1m.bin` 会让匿名 ftp 用户无权覆盖，用例报 EIO）。

内存验收：`meson setup build_asan2 -Dtarget_os=gnu -Denable_debug=true -Db_sanitize=address,undefined`（等价 `-Dwith_asan=true -Dwith_ubsan=true`）。**sanitizer 标志必须同时进编译与链接**——只进 `link_flags` 会「链接了运行时但零插桩」，核对方式：`compile_commands.json` 里每条命令都含 `-fsanitize`（`-Dwith_asan/with_ubsan` 仅在 `enable_debug=true` 下生效，release 下给出 warning 并忽略）。

内存验收实际范围与结果（2026-10-06 实测，**共 26 套全绿、0 条 sanitizer 报告**）：
- **L0 13 套全跑**：`CC="cc -fsanitize=address,undefined -fno-omit-frame-pointer" ASAN_OPTIONS=detect_leaks=0`，13/13。`detect_leaks=0` 是必需的——后端对象是**有意 immortal**（`ftp_backend_add` 注释：条目永不 free），LeakSanitizer 会把它们全报成泄漏。
- **L1 7 套**：把 `FUSE_DAEMON`/`FTP_MODULE_SO`/`LOG_CTL`/`LOG_MONITOR` 指向 `build_asan2/`，functional / rules / decision_enforce / negative_timeout / modules / backend_lifecycle / ftp 全绿。
- **L1/L2 余下 6 套**：inject_method / global_replace / inject_mount_env / log_ctl_rules / log_pipeline / rule_server 全绿（`INJECTOR`/`GLOBAL_REPLACE_CTL` 同样指向 `build_asan2/`）。
- **不纳入内存验收的套件**（预期信号或指标不可比）：`test_module_circuit`（故意 SIGSEGV）、`test_readdir_skel_fallback`（LD_PRELOAD 垫片）、`test_crash_log`（`--crash-test`）、`test_ftp_parallel`（断言控制面延迟收敛，ASan 的 2~5 倍减速会让指标失去可比性）。
- **§C 曾约两成概率失败（已修，非产品缺陷）**：`test_backend_lifecycle` §C 断言「热重载放弃新实例时 exit 必被执行」。热重载是**事件驱动**的，单次 stage 后 daemon 有时没走到 prepare，exit 标记自然不出现——与 exit 无关。修法两层：① 判别改用**模块侧 init/exit 标记对**（`swap-init-v2`/`swap-exit-v2`），不再 grep daemon 日志——日志走 UDS 交给 log_monitor，测试进程拿不到，实测 `daemon.log` 恒为空，靠它判别会把真缺陷误报成环境问题；② 走到 prepare 即收敛，否则最多重放 3 次 stage（重放不会掩盖缺陷：任一次 init 出现即可判定）。同时把 `SWAP_HOLD_CAP_MS` 从 30s 抬到 120s——必须大于全部等待窗口，否则 hold 中途到期会让引用归零走 commit 分支，届时 init 跑了而 exit 不该跑，会被误判成"exit 未执行"的真缺陷。改造后连跑 17 次全过。
- **跑 L1 的坑**：`test_functional`/`test_rules` 会 `pkill -f fuse_daemon`，而 `FUSE_DAEMON=…/fuse_daemon` 会出现在外层 shell 命令行里 → 自杀（无输出、SIGTERM）。把 env 与套件列表写进**落盘脚本**再 `sh 脚本` 执行即可。

**环境坑（WorkBuddy/CodeBuddy CLI 宿主）**：这类宿主的 shell 会注入 `PYTHONPATH=<…>/cli/vendor/shim`（其 `sitecustomize.py` 把 `os.unlink`/`shutil.rmtree` 重定向到回收站）与 `BASH_ENV=<…>/shell-runtime-bash-env.sh`（把 `safe-bin` 垫到 `PATH` 最前）。这会让 `test_module_circuit`（删 `/var/fuse-proxy/log/module_errors.log`）、`test_inject_mount_env`（沙箱内批量删除）等**假失败**（`PermissionError: /.Trash-1000`）。跑测试须剥掉这两项：

```
env -u PYTHONPATH -u BASH_ENV PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin" python3 tests/run.py --all
```

### 分层验收流程（尽量贴近 Android）

- **L0 静态/契约**（无挂载无网络，可并行）：`config_snapshot`、`monitor_layers`、`path_vars`、`pending_close`、`cfg_watch`、`rule_file_lock`、`ns_combined_rollback`、`reaped_managed`、`ftp_read_restart`、`ftp_truncate_list`、`ftp_upload_lock`、`module_abi`、`backing_gate`。
- **L1 GNU 真实 FUSE**（串行）：`functional`、`rules`、`decision_enforce`、`negative_timeout`、`readdir_skel_fallback`、`modules`、`module_circuit`、`backend_lifecycle`、`ftp*`。
- **L2 Android 拓扑仿真**：`inject_mount_env`（v1/v2/v3 全生命周期 + 宿主 mountinfo 前后比对）、`global_replace`——各自在 rootless unshare 沙箱内，宿主零污染。
- **L3 真实 Android 内核/权限**（需 emulator/AVD 或真机；本机无，未做）：SELinux/Bionic/vold/FUSE-BPF/Zygisk 双 ABI/多用户。
- **L4 设备最终验收**：仅授权后经 `scripts/adb-sh.sh`（强制降权 `su shell`、`SAFE_ROOT` 合成 fixture）。

**验收标准**（全绿方可提交）：

1. GNU 与 Android 交叉构建零**新增**告警、产物齐全（含 `src/zygisk/*.so` 的 `readelf -d` 无 `libc++_shared.so`）。
2. `python3 tests/run.py --all --strict` 退出码 0：跳过项（77/78）为 0，或逐条记录原因并确认非产品缺陷。
3. **判别性**：新增回归用例必须在旧实现上失败（本仓库套路：`FTP_BACKEND_SRC=<git show HEAD:旧副本>` 复验，或直编旧源码副本）。
4. 隔离证据：L2 套件宿主 `mountinfo` 前后零变化；挂载未消失前禁删 fixture。
5. L2 通过 ≠ Android 运行时已验证——SELinux/Bionic/vold/Zygisk/多用户须 L3–L4 覆盖。

### 隔离跑全量（宿主零污染）

`scripts/test-isolated.sh [套件名…]`（不传套件名即 `--all`）。在
`unshare --user --map-root-user --map-auto --mount --pid --fork --mount-proc --net`
里跑，并把 **/tmp、/var、/home/bdy/ftp 全部私有化**，沙箱内自起一份 vsftpd。
退出前对宿主三项不变量做前后比对：**mountinfo / `/var/fuse-proxy` / FTP 树**；
任一变化即报错并保留现场（`$STAGE/diff.txt`）。退出码：0 全绿且零污染、1 有污染、
2 测试失败、3 两者皆有。

实测：**30 套全绿且宿主零变化**，跑完自动清理（含属主归还）。四个坑都已写进脚本注释，
改动前务必先读：
- 客户端必须 uid 1000 **且带 ambient CAP_SYS_ADMIN**：RO 用例要求非 root
  （`vfs_check_read_only` 对 `uid==0` 有框架级豁免），但降权后 setuid 的 `fusermount3`
  在本 userns 内提不了权（EPERM），故须显式给 cap；它不影响 RO 判定（那条只看 uid）。
- 私有 `/var` 后 vsftpd 会因缺 `secure_chroot_dir` 而「端口在听、连上即挂」
  （守护化后错误只进 syslog，stderr 恒空，极易误判成网络问题）→ 显式指定到 stage 下。
- FTP 树**不能整树复制**（`/home/bdy/ftp` 有 4.7G）→ 用最小合成树
  （根 0755 不可写、`upload/` 与 `upload2/` 0777），测试自建全部数据。
- 内层 uid 1000 经 `--map-auto` 落到 subuid，与 ns-root 属主错配 → FTP 树与
  `build_gnu/` 需 `chown` 给客户端，收尾再 `chown -R 0:0` 归还，否则仓库里会留下
  宿主无法覆盖的 subuid 属主 .so。

## 已按标准语义修复（原「待裁决」，2026-10-06 裁定）

以下两处此前只取证未改，现按标准语义修复，各配判别性用例（旧实现上均必失败）。

1. **`vfs_rmdir` 非空目录返回 ENOTEMPTY**（`src/daemon/fuse_daemon.c`，旧实现由 `51abd2c`
   引入）。旧实现对本地真实路径的 ENOTEMPTY 直接 `recursive_rmdir(p)` 并返回 0——即
   **对非空目录调 `rmdir` 会静默删掉整个子树**（实测一次普通 `os.rmdir()` 让
   `dir/a/sub/c` 全部消失），不符 POSIX，也与同函数的虚拟路径分支（返回 ENOTEMPTY）不一致。
   现本地分支直接返回 `-ENOTEMPTY`。`recursive_rmdir` 仍保留给 `rename` 的 EXDEV 回退
   （跨设备移动 = 拷贝后删源树，那里递归删除才是正确语义）。
   用例：`test_functional.py` 模块4「rmdir 标准语义」——非空→ENOTEMPTY、失败后子树完整
   保留、清空后 rmdir 成功（正对照）。

2. **`vfs_fsync` 对后端句柄真正落盘**（同上文件）。旧实现对后端句柄直接返回 0，数据留在
   模块缓冲里——依赖 `fsync()` 持久化的调用方（SQLite `synchronous=FULL`、编辑器保存）
   会拿到「成功」而远端无数据。现改为调用模块 `backend_flush`（与 FLUSH 同一条收尾路径，
   已抽成 `vfs_backend_finish_data` 供两者共用），成功则失效路径缓存；不销毁句柄，可重复
   调用（FUSE 的 FLUSH 会因 dup/fork 对同一句柄多次触发）。
   用例：`test_ftp.py` 3c——write+fsync 后、**close 之前**核对远端已有内容。

## 设备操作（生产级隔离，血的教训）

真机视为生产：一切设备命令经 `scripts/adb-sh.sh` 执行（会话强制 PATH 垫片 + source `adb-safe.sh` + `set -u` + 变更/生产路径文本预检），禁止裸 `adb shell` 做变更。隔离主体是 Linux 原生机制（内核强制，非约定）：测试 I/O 一律 `su shell` 降级执行——实测 uid=gid=groups=2000（1078 等危险组已脱）、CapEff=0，`assert_downgraded()` 每次先验，root 只建/卸挂载（/dev/fuse 0600，只能 root 开）且 `need_root()` 留痕；backing 只用 `SAFE_ROOT` 合成 fixture（生产 backing 永不进测试挂载，需真实下层行为时 cp -a 快照到沙盒）。纵深为 shell 层：设备侧脚本 source harness 即自动影子危险命令（rm/umount/mv/cp/dd/tee/chcon/chmod/chown/restorecon/setenforce/kill），绕过须 `command`/绝对路径（评审可见）；umount 循环卸直到消失、失败即 die 且错误禁止重定向吞掉；`set -u` 常开。SELinux 现状：测试树自动落 `shell_data_file`，root 段尚无专用受限域（ksu 域基本不受限，需 policy 新域——列为二期，不在这次范围内）。

## 架构要点

- **多进程 + UDS**：`injector`（主控：epoll + inotify + zygote fork 检测）启动 `fuse_daemon`（约 27 个 FUSE 回调 + 模块调度）；`rule_server` 以 JSON 行协议动态改规则；`log_monitor` 收日志、`log_ctl` 查询。injector 维护全局 + 媒体模块两棵 FUSE 树，共用同一二进制与配置。
- **模块化（V4 起只有一种模块）**：规则决策（REDIRECT/SANDBOX/HIDE/ALLOW/RO + FTP 前缀归属）与 uid→包名、MONITOR 开关都是**框架能力**（`src/daemon/fw_rules.c` / `fw_pkg.c` / `fw_config.c`）——放进模块会让「模块缺席 ⇒ 规则与监控一起失效」。模块只剩**后端存储提供者**（如 `ftp_module.so`）：**不实现 FUSE**，只提供 `backend_*` 方法。FTP 映射由 `FTP <虚拟前缀> <段名>` 规则决定，作用域随所在段（`[GLOBAL]` 全局 / `[包名]` 仅该应用）。模块目录 `<CONFIG_DIR>/modules/<名>/<名>.so`，inotify 热插拔；**模块从内存副本加载**（memfd，maps 里呈现为 `memfd:nsp_module_<名>`），故磁盘上那份文件无论原子替换还是就地覆盖都伤不到运行中的模块。
- **模块 ABI**：第三方模块只以 `include/nsp_module.h` 为唯一入口（该头代含 `nsp_log.h` / `nsp_constants.h` / `nsp_cfg_view.h`，分发 SDK 须一并给出），编译须带 `-DNSP_MODULE_BUILD`；日志等公共符号经导出表解析——改签名会破坏已编译模块。当前 `NSP_MODULE_ABI_VERSION=5`、`NSP_FRAMEWORK_API_VERSION=4`。**V3 是决策结果的不兼容重构**：声明式 `NspPathDecision` 取代 `NspResolveResult`（`hidden`→`appear_missing`、`ro`→`read_only`、两个虚拟目录 bool→`virtual_kind`、删 `user_id`/`sub_path`（框架自算）、新增 `attr_override`+`mode`/`uid`/`gid`）；`appear_missing` 在所有回调统一 ENOENT（V2 写类是 EACCES，属有意行为修正）。**V4 删掉已归框架的三个成员**——`NspPathDecision` 的 `pkg`/`monitor_on` 与 `NspModuleOps.get_pkg`：包名（`fw_pkg.c`）与 MONITOR 三层合并（`fw_config_monitor_for`）都是配置语义，模块缺席时也必须成立，故框架自算；`monitor_on` 同时**移出决策结构**（`fw_route` 经出参单独给出——它本就不是路径决策）。**V5 给 `backend_readdir` 加 `offset` 分页**（大目录不再 512 截断）+ 超长名跳过语义 + 注册表动态化（初容 16/硬上限 1024）。**V1/V2/V3/V4 模块须重编译**，加载器在 `dlopen` 之后、`init`/`ops` 之前按版本拒载；`NspFrameworkApi` 不变（仍 4）。模块不链接 `nsp_comm`；`nsp_ini_store` 已退出模块 ABI，是 rule_server 的私有静态库（log_ctl 不用）。
- **决策强制归属**：引擎只声明「路径该怎么表现」（`NspPathDecision`，见 `src/daemon/fw_rules.h`），errno 映射与权限策略在框架单点——`fw_route()` 统一 `appear_missing`→ENOENT 与 `read_only`→EROFS（含 root 豁免）。框架一律原样上报真实属主/权限（「伪造属主=访问者」的默认模式与 `--preserve-perms` 开关均已删除；V3 的 `attr_override` 因无规则语法生产者已随 V4 删除）。**新增回调时必须走 `VFS_SETUP_CORE(path, VFS_OP_READ|VFS_OP_MUTATE)`**，不要在各回调里手写 hidden/ro 判定——那正是 V3 收敛掉的漂移来源。
- **后端 errno 契约**：`backend_*` 以 errno 风格返回码回传业务失败（`-ENOENT`/`-EPERM`/`-ENOTEMPTY`/`-EIO`……），框架**不把它计入模块熔断窗口**（`backend_rc_is_business()`，`-1..-4095` 即业务码）；否则应用探测若干缺失路径就会把健康模块置毒卸载 + ban（`test_module_circuit.py` §9 守护）。规则模块反之：`resolve`/`probe` 用决策字段回传业务结果，返回非 0 仍判契约违规。新增 `backend_*` 分派分支时，`module_guard_error` 必须带上这一豁免。
- **配置读取归属**：配置的**读取**（文件 I/O + inotify + 词法/段头识别）完全在框架侧（`src/daemon/fw_config.c` + `config_read_view`），模块**不读文件、不跑 inotify**；框架按模块经 `subscribe_rules` 申请的规则类型过滤后以 `NspModuleConfig` 下发，模块据此建索引（`config_build_from_view`）。**建索引仍在模块**（规则对象/trie 是模块的索引表示，框架不建 AppConfig）。改动 `config_parser.c` 的读取/词法部分须同时跑 `test_rules.py` 与 `test_config_snapshot.py`。
- **规则**：INI 格式，`[GLOBAL]` / `[包名]` / `[包名:userid]` / `[USER_APPS:uid]` / `[SYSTEM_APPS]` 段；关键字 `REDIRECT`/`ALLOW`/`HIDE`/`RO`/`SANDBOX`/`MONITOR`。裸 `[包名]` 记为 user_id=-1 跨用户 fallback。`CONFIG_DIR` Android 为 `/data/Namespace-Proxy`、GNU 为 `/var/fuse-proxy`（常量权威在 `include/nsp_constants.h`，`common.h` 以别名暴露）。
