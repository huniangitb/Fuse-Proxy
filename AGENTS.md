# AGENTS.md

Android 13+ 用户态 FUSE 存储代理（root 模块二进制核心），C23 编写，Meson + Ninja 构建。

## 构建

- **陷阱**：`target_os` **默认是 `android`**。不带 `-Dtarget_os=gnu` 在普通 Linux 上必然失败（依赖 NDK clang）。
- GNU 本机：`scripts/build.sh`（默认 `build_gnu/`）。第三方依赖系统库优先、缺失回退子模块，clone 后一键成功。
- Android 交叉：`scripts/android-build.sh`，或 `meson setup build --cross-file android-aarch64.ini && ninja -C build`。cross 文件须含 `cmake = 'cmake'`（cmake 子项目交叉必需）与 `host_machine.system = 'android'`（libfuse 的 librt 豁免开关）。`-Dandroid_{libfuse,json_c,curl}=prebuilt` 可切回预构建（需 `-Dfuse3_root=` / `-Dcurl_dir=`）。
- 产物：`fuse_daemon`、`log_monitor`、`log_ctl`、`rule_server`、`basic_rules.so`、`ftp_module.so`（全平台）；`injector` 与 Zygisk 通知模块 `src/zygisk/{arm64-v8a,armeabi-v7a}.so` 仅 Android；`global_replace_ctl` 仅 GNU（测试驱动，不 install）。仅 `fuse_daemon` 带 `-DFUSE_USE_VERSION=317` 与 `-Wl,--export-dynamic` 导出公共符号供模块解析；模块与 `rule_server` 均不链接 libfuse3。
- Zygisk 模块经 `custom_target` 直接调 NDK `clang++` 编双 ABI（`src/zygisk/meson.build`），**不给 `project()` 加 cpp 语言**——否则 GNU 构建也会要求 C++ 编译器。它与主项目零链接关系，注入 zygote 子进程，故禁 STL（`-nostdlib++`）、禁 RTTI/异常；改动后必须确认 `readelf -d` 无 `libc++_shared.so`。
- 调试：`-Denable_debug=true`（可叠加 `-Dwith_asan=true` / `-Dwith_ubsan=true`，sanitizer 仅 debug 下生效）；默认 `-O3 -flto -Wl,-s`。
- 打包：`scripts/pack-module.sh`（同步 `build_android/` 产物到模块骨架，产出 zip 与符号包）。
- **libfuse 子模块是自维护 fork**（`huniangitb/libfuse` 分支 `master-Android`，与 `~/libfuse` 同源），已含 Android 适配与**分支追加接口** `fuse_invalidate_path_entry()`（entry 级缓存失效，导出版本节点 `FUSE_3.19`，见 `lib/fuse.c` + `lib/fuse_versionscript`）。该接口**只在 `libfuse_source=subproject/custom` 与 Android 默认（子模块）构建下存在**；系统 pkg-config 库与 `prebuilt` 没有，故框架侧用**弱引用**（`fuse_daemon.c` 的 `vfs_inval_path`）：缺失时自动退化为仅 inode 级 `fuse_invalidate_path`，不破坏「系统库优先、clone 后一键成功」。改动子模块源码后须确认 `ninja -C build_sp_patch`（`-Dlibfuse_source=subproject`）通过，并跑 `tests/test_libfuse_inval.py`。

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

前置：GNU 产物 `build_gnu/`、`fusermount3`、`/dev/fuse`、Python `sqlite3`。非默认产物路径用环境变量覆盖：`FUSE_DAEMON`、`FTP_MODULE_SO`、`BASIC_RULES_SO`、`GLOBAL_REPLACE_CTL`、`LOG_CTL`。

按改动跑映射（全绿方可提交）：

| 改动 | 测试 |
|---|---|
| `basic_rules` / `fuse_daemon.c` / `config_parser.c` | `test_rules.py`（44，ALLOW/REDIRECT/HIDE/RO/通配符/最长前缀/沙盒/热重载）、`test_config_snapshot.py`（解析快照 + STATIC 输出） |
| `src/modules/ftp/` 或框架后端分派 | `test_ftp.py`（13，需 vsftpd）、`test_backend_lifecycle.py`（后端引用配对/真卸载，无需 vsftpd）、`test_ftp_read_restart.py`（读缓冲随机跳变竞态，无需 vsftpd） |
| `backend_rc_is_business`（后端业务 errno 豁免）/ `fuse_daemon.c` 后端分派 | `test_module_circuit.py` §9（业务 errno 不得触发熔断/ban） |
| `src/config/path_vars.c` | `test_path_vars.py` |
| `src/module/`（加载器/围栏/熔断/ABI） | `test_modules.py`（12，热插拔）、`test_module_circuit.py`（55，故障隔离）、`test_module_abi.py`（V3 契约/默认值/输出校验/V1+V2 拒载） |
| 决策结构 / 框架单点强制（`NspPathDecision`、`fw_route` 的 appear_missing·read_only、`vfs_apply_attr_override`） | `test_module_overrides.py`（42，逐回调 errno 矩阵：appear_missing 统一 ENOENT、read_only 统一 EROFS、属性覆盖与类型位保持） |
| `log_ctl` / `rule_server` 规则编辑（`nsp_rule_file`） | `test_log_ctl_rules.py`（30）、`test_rule_server.py` |
| `subprojects/libfuse`（fork 追加接口）或框架缓存失效 | `test_libfuse_inval.py`（需 `-Dlibfuse_source=subproject` 的产物，缺失自动跳过） |
| 通用回归 | `test_functional.py`（34，IO/SQLite/并发）、`test_crash_log.py` |
| 压力（按需） | `stress_fuse.py`、`test_ftp_stress.py` |

特殊前置：`test_ftp.py` 需本机 vsftpd 匿名服务（127.0.0.1:21，匿名根只读 + `upload/` 可写）；`test_global_replace.py` 需 root（无权限自动跳过）；`test_config_snapshot.py`、`test_module_abi.py` 不经 Meson，直接用本机 `cc` 临时编译实际源码（前者另需 json-c），故不依赖 `build_gnu/`；`test_libfuse_inval.py` 同样自编译探针（`tests/libfuse_inval_probe.c`），只在找到含 `fuse_invalidate_path_entry` 的 libfuse 子模块产物时运行，否则跳过。

失败处理：退出码 1 为失败（勿用管道吞退出码）；残留挂载点（`/tmp/fuse_proxy_test/mnt`、`/tmp/fuse_rules_test/mnt`）用 `fusermount3 -u` 清理后重跑；测试规则文件在 `/tmp/Namespace-Proxy/injector.conf`。

## 架构要点

- **多进程 + UDS**：`injector`（主控：epoll + inotify + zygote fork 检测）启动 `fuse_daemon`（约 27 个 FUSE 回调 + 模块调度）；`rule_server` 以 JSON 行协议动态改规则；`log_monitor` 收日志、`log_ctl` 查询。injector 维护全局 + 媒体模块两棵 FUSE 树，共用同一二进制与配置。
- **模块化**：fuse_daemon 是零规则功能的框架——规则能力由 dlopen 的 `basic_rules.so` 提供，存储后端（FTP）由 `ftp_module.so` 提供。模块**不实现 FUSE**，只提供 `backend_*` 方法；FTP 映射由 `FTP <虚拟前缀> <段名>` 规则决定，作用域随所在段（`[GLOBAL]` 全局 / `[包名]` 仅该应用）。模块目录 `<CONFIG_DIR>/modules/<名>/<名>.so`，inotify 热插拔。
- **模块 ABI**：第三方模块只以 `include/nsp_module.h` 为唯一入口（该头代含 `nsp_log.h` / `nsp_constants.h` / `nsp_cfg_view.h`，分发 SDK 须一并给出），编译须带 `-DNSP_MODULE_BUILD`；日志等公共符号经导出表解析——改签名会破坏已编译模块。当前 `NSP_MODULE_ABI_VERSION=3`、`NSP_FRAMEWORK_API_VERSION=4`。**V3 是决策结果的不兼容重构**：声明式 `NspPathDecision` 取代 `NspResolveResult`（`hidden`→`appear_missing`、`ro`→`read_only`、两个虚拟目录 bool→`virtual_kind`、删 `user_id`/`sub_path`（框架自算）、新增 `attr_override`+`mode`/`uid`/`gid`），**V1/V2 模块须重编译**；`appear_missing` 在所有回调统一 ENOENT（V2 写类是 EACCES，属有意行为修正）。V4 是 `NspFrameworkApi` 尾部兼容新增（`subscribe_rules` / `set_config_listener`），不单独要求重编译。加载器在 `dlopen` 之后、`init`/`ops` 之前校验 ABI。模块不链接 `nsp_comm`；`nsp_ini_store` 已退出模块 ABI，是 rule_server 的私有静态库（log_ctl 不用）。
- **决策强制归属**：模块只声明「路径该怎么表现」，errno 映射与权限策略在框架单点——`fw_route()` 统一 `appear_missing`→ENOENT 与 `read_only`→EROFS（含 root 豁免），`vfs_apply_attr_override()` 在框架既有权限策略之后落实 `attr_override`（故模块显式声明优先于伪造模式/skel 等默认）。**新增回调时必须走 `VFS_SETUP_CORE(path, VFS_OP_READ|VFS_OP_MUTATE)`**，不要在各回调里手写 hidden/ro 判定——那正是 V3 收敛掉的漂移来源。
- **后端 errno 契约**：`backend_*` 以 errno 风格返回码回传业务失败（`-ENOENT`/`-EPERM`/`-ENOTEMPTY`/`-EIO`……），框架**不把它计入模块熔断窗口**（`backend_rc_is_business()`，`-1..-4095` 即业务码）；否则应用探测若干缺失路径就会把健康模块置毒卸载 + ban（`test_module_circuit.py` §9 守护）。规则模块反之：`resolve`/`probe` 用决策字段回传业务结果，返回非 0 仍判契约违规。新增 `backend_*` 分派分支时，`module_guard_error` 必须带上这一豁免。
- **配置读取归属**：配置的**读取**（文件 I/O + inotify + 词法/段头识别）完全在框架侧（`src/daemon/fw_config.c` + `config_read_view`），模块**不读文件、不跑 inotify**；框架按模块经 `subscribe_rules` 申请的规则类型过滤后以 `NspModuleConfig` 下发，模块据此建索引（`config_build_from_view`）。**建索引仍在模块**（规则对象/trie 是模块的索引表示，框架不建 AppConfig）。改动 `config_parser.c` 的读取/词法部分须同时跑 `test_rules.py` 与 `test_config_snapshot.py`。
- **规则**：INI 格式，`[GLOBAL]` / `[包名]` / `[包名:userid]` / `[USER_APPS:uid]` / `[SYSTEM_APPS]` 段；关键字 `REDIRECT`/`ALLOW`/`HIDE`/`RO`/`SANDBOX`/`MONITOR`。裸 `[包名]` 记为 user_id=-1 跨用户 fallback。`CONFIG_DIR` Android 为 `/data/Namespace-Proxy`、GNU 为 `/var/fuse-proxy`（常量权威在 `include/nsp_constants.h`，`common.h` 以别名暴露）。
