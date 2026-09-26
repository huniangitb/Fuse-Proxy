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

**一条命令**：`python3 tests/run.py` —— 自动按「本次改动的文件 + 改动行里的符号」匹配下表，依次执行选中的套件并汇总退出码。`--list` 只看会跑哪些、`--all` 忽略映射跑全量、`--base <ref>` 换对比基线（默认 `HEAD`，即暂存+未暂存+未跟踪）、尾部直接给脚本名则跳过自动匹配。下表的可执行形式是 `tests/run.py` 的 `SUITE_MAP`，**两边须同步维护**；各脚本仍可单独直接跑。

前置：GNU 产物 `build_gnu/`、`fusermount3`、`/dev/fuse`、Python `sqlite3`。非默认产物路径用环境变量覆盖：`FUSE_DAEMON`、`FTP_MODULE_SO`、`BASIC_RULES_SO`、`GLOBAL_REPLACE_CTL`、`LOG_CTL`、`LOG_MONITOR`。

按改动跑映射（全绿方可提交）：

| 改动 | 测试 |
|---|---|
| 内建规则引擎（`src/daemon/fw_rules.c`）/ `fuse_daemon.c` / `config_parser.c` | `test_rules.py`（44）、`test_config_snapshot.py`、`test_monitor_layers.py`（MONITOR 三层合并）、`test_decision_enforce.py`（决策强制单点 errno 矩阵） |
| `src/modules/ftp/` 或框架后端分派 | `test_ftp.py`（14，需 vsftpd）、`test_backend_lifecycle.py`（后端引用配对/真卸载，无需 vsftpd）、`test_ftp_read_restart.py`（读缓冲随机跳变竞态，无需 vsftpd）、`test_ftp_parallel.py`（11，控制面并发/连接复用/延迟收敛/热重载竞态/断连熔断自愈，需 vsftpd；自起延迟中继，占用 127.0.0.1:2121） |
| `src/modules/ftp/ftp_mux.c`（epoll + curl_multi 控制面复用器）或 `backend_rc_is_business`（业务 errno 豁免） | `test_ftp_parallel.py`（连接复用与延迟收敛）、`test_module_circuit.py` §9（业务 errno 不得触发熔断/ban） |
| `src/config/path_vars.c` | `test_path_vars.py` |
| injector 目标判定 / 注入方法（`inject_target.c`、`--inject-method=v1\|v2\|v3`） | `test_inject_method.py`（31，v1/v2/v3 判定矩阵：v3 忽略 `GLOBAL_INJECT`/`SKIP_SYSTEM_APPS` 而段头 `OFF` 仍生效、派生标志、非法值拒绝）、`test_global_replace.py`（需 root，v2 替换/还原/审查生命周期，无权限自动跳过） |
| injector 挂载/清理序列（`ns_utils.c` 跨 ns bind 与 preserve 路径、`ns_global_replace.c` 替换/备份/还原、`cleanup_app_mounts`） | `test_inject_mount_env.py`（38/42/41，rootless unshare 沙箱仿真安卓拓扑内 v1/v2/v3 全生命周期：注入→REQ→SIGTERM 清理→退出后宿主 mountinfo 前后比对零污染，缺产物/userns 不可用自动跳过） |
| `src/module/`（加载器/内存副本加载/围栏/熔断/ABI） | `test_modules.py`（11，热插拔 + 规则不依赖模块）、`test_module_circuit.py`（46，故障隔离：后端载体）、`test_module_abi.py`（V4 布局契约/旧版本 V1/V2/V3 拒载/最小后端模块）、`test_backend_lifecycle.py`（23，后端引用配对/真卸载） |
| 决策强制单点（`fw_route` 的 appear_missing→ENOENT、read_only→EROFS） | `test_decision_enforce.py`（38，逐回调 errno 矩阵，规则来自配置 HIDE/RO） |
| `log_ctl` / `rule_server` 规则编辑（`nsp_rule_file`） | `test_log_ctl_rules.py`（30）、`test_rule_server.py` |
| 日志链路（`src/log/`、`nsp_comm.*`、`common.c` 的 `vfs_log_io` / `monitor_on` / `persist_stage` / `drain_async`） | `test_log_pipeline.py`（24，框架闸门矩阵：无规则记录 / 路径无 `<uid>/` 层 / `MONITOR OFF` / 类别段 `[SYSTEM_APPS]` 否决与开启五态 + 磁盘历史全量可查（`count`/`search`/历史转储三条路径）+ sock 查询端到端；**会重启 log_monitor 并备份还原 `io.log{,.1}`**） |
| 框架侧 uid→包名（`fw_pkg.c`）与 MONITOR 三层合并（`fw_config.c` 的 `fw_config_monitor_for`） | `test_monitor_layers.py`（11，应用 > 类别 > 全局两个方向、`[USER_APPS:0]`/`[USER_APPS:2]` 用户隔离、uid.map 未收录时 /proc 回退、包名不可解析 fail-safe；本机 uid<10000 走不到 USER_APPS 分支，故自编译实际源码 + 合成 uid，不经 Meson） |
| 通用回归 | `test_functional.py`（34，IO/SQLite/并发）、`test_crash_log.py` |
| 压力（按需） | `stress_fuse.py`、`test_ftp_stress.py` |

特殊前置：`test_ftp.py` 需本机 vsftpd 匿名服务（127.0.0.1:21，匿名根只读 + `upload/` 可写）；`test_global_replace.py` 需 root（无权限自动跳过）；`test_config_snapshot.py`、`test_module_abi.py` 不经 Meson，直接用本机 `cc` 临时编译实际源码（前者另需 json-c），故不依赖 `build_gnu/`；

失败处理：退出码 1 为失败（勿用管道吞退出码）；残留挂载点（`/tmp/fuse_proxy_test/mnt`、`/tmp/fuse_rules_test/mnt`）用 `fusermount3 -u` 清理后重跑；测试规则文件在 `/tmp/Namespace-Proxy/injector.conf`。

## 架构要点

- **多进程 + UDS**：`injector`（主控：epoll + inotify + zygote fork 检测）启动 `fuse_daemon`（约 27 个 FUSE 回调 + 模块调度）；`rule_server` 以 JSON 行协议动态改规则；`log_monitor` 收日志、`log_ctl` 查询。injector 维护全局 + 媒体模块两棵 FUSE 树，共用同一二进制与配置。
- **模块化（V4 起只有一种模块）**：规则决策（REDIRECT/SANDBOX/HIDE/ALLOW/RO + FTP 前缀归属）与 uid→包名、MONITOR 开关都是**框架能力**（`src/daemon/fw_rules.c` / `fw_pkg.c` / `fw_config.c`）——放进模块会让「模块缺席 ⇒ 规则与监控一起失效」。模块只剩**后端存储提供者**（如 `ftp_module.so`）：**不实现 FUSE**，只提供 `backend_*` 方法。FTP 映射由 `FTP <虚拟前缀> <段名>` 规则决定，作用域随所在段（`[GLOBAL]` 全局 / `[包名]` 仅该应用）。模块目录 `<CONFIG_DIR>/modules/<名>/<名>.so`，inotify 热插拔；**模块从内存副本加载**（memfd，maps 里呈现为 `memfd:nsp_module_<名>`），故磁盘上那份文件无论原子替换还是就地覆盖都伤不到运行中的模块。
- **模块 ABI**：第三方模块只以 `include/nsp_module.h` 为唯一入口（该头代含 `nsp_log.h` / `nsp_constants.h` / `nsp_cfg_view.h`，分发 SDK 须一并给出），编译须带 `-DNSP_MODULE_BUILD`；日志等公共符号经导出表解析——改签名会破坏已编译模块。当前 `NSP_MODULE_ABI_VERSION=4`、`NSP_FRAMEWORK_API_VERSION=4`。**V3 是决策结果的不兼容重构**：声明式 `NspPathDecision` 取代 `NspResolveResult`（`hidden`→`appear_missing`、`ro`→`read_only`、两个虚拟目录 bool→`virtual_kind`、删 `user_id`/`sub_path`（框架自算）、新增 `attr_override`+`mode`/`uid`/`gid`）；`appear_missing` 在所有回调统一 ENOENT（V2 写类是 EACCES，属有意行为修正）。**V4 删掉已归框架的三个成员**——`NspPathDecision` 的 `pkg`/`monitor_on` 与 `NspModuleOps.get_pkg`：包名（`fw_pkg.c`）与 MONITOR 三层合并（`fw_config_monitor_for`）都是配置语义，模块缺席时也必须成立，故框架自算；`monitor_on` 同时**移出决策结构**（`fw_route` 经出参单独给出——它本就不是路径决策）。**V1/V2/V3 模块须重编译**（多半只需删掉对这两个字段的赋值），加载器在 `dlopen` 之后、`init`/`ops` 之前按版本拒载；`NspFrameworkApi` 不变（仍 4）。模块不链接 `nsp_comm`；`nsp_ini_store` 已退出模块 ABI，是 rule_server 的私有静态库（log_ctl 不用）。
- **决策强制归属**：引擎只声明「路径该怎么表现」（`NspPathDecision`，见 `src/daemon/fw_rules.h`），errno 映射与权限策略在框架单点——`fw_route()` 统一 `appear_missing`→ENOENT 与 `read_only`→EROFS（含 root 豁免）。框架一律原样上报真实属主/权限（「伪造属主=访问者」的默认模式与 `--preserve-perms` 开关均已删除；V3 的 `attr_override` 因无规则语法生产者已随 V4 删除）。**新增回调时必须走 `VFS_SETUP_CORE(path, VFS_OP_READ|VFS_OP_MUTATE)`**，不要在各回调里手写 hidden/ro 判定——那正是 V3 收敛掉的漂移来源。
- **后端 errno 契约**：`backend_*` 以 errno 风格返回码回传业务失败（`-ENOENT`/`-EPERM`/`-ENOTEMPTY`/`-EIO`……），框架**不把它计入模块熔断窗口**（`backend_rc_is_business()`，`-1..-4095` 即业务码）；否则应用探测若干缺失路径就会把健康模块置毒卸载 + ban（`test_module_circuit.py` §9 守护）。规则模块反之：`resolve`/`probe` 用决策字段回传业务结果，返回非 0 仍判契约违规。新增 `backend_*` 分派分支时，`module_guard_error` 必须带上这一豁免。
- **配置读取归属**：配置的**读取**（文件 I/O + inotify + 词法/段头识别）完全在框架侧（`src/daemon/fw_config.c` + `config_read_view`），模块**不读文件、不跑 inotify**；框架按模块经 `subscribe_rules` 申请的规则类型过滤后以 `NspModuleConfig` 下发，模块据此建索引（`config_build_from_view`）。**建索引仍在模块**（规则对象/trie 是模块的索引表示，框架不建 AppConfig）。改动 `config_parser.c` 的读取/词法部分须同时跑 `test_rules.py` 与 `test_config_snapshot.py`。
- **规则**：INI 格式，`[GLOBAL]` / `[包名]` / `[包名:userid]` / `[USER_APPS:uid]` / `[SYSTEM_APPS]` 段；关键字 `REDIRECT`/`ALLOW`/`HIDE`/`RO`/`SANDBOX`/`MONITOR`。裸 `[包名]` 记为 user_id=-1 跨用户 fallback。`CONFIG_DIR` Android 为 `/data/Namespace-Proxy`、GNU 为 `/var/fuse-proxy`（常量权威在 `include/nsp_constants.h`，`common.h` 以别名暴露）。
