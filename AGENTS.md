# AGENTS.md

Android 13+ 用户态 FUSE 存储代理（KernelSU/Magisk 模块二进制核心），C23 编写，Meson + Ninja 构建。仓库文档与提交信息均使用中文（提交为 fix:/feat:/docs:/refactor:/perf: 等 Conventional Commits 前缀）。

## 构建

- 本机 GNU 构建（主线 libfuse3，pkg-config 查找）：`meson setup build_gnu -Dtarget_os=gnu && ninja -C build_gnu`。GNU 构建还需系统 **libcurl >= 8.21.0**（ftp_module 依赖；meson 会编译期校验版本，过旧直接报错）。
- 陷阱：`meson_options.txt` 中 `target_os` **默认是 `android`**。不带 `-Dtarget_os=gnu` 配置会走 Android 分支（依赖 NDK clang 与 `fuse3_root` 静态库），在普通 Linux 上必然失败。
- Android 交叉构建：`meson setup build --cross-file android-aarch64.ini -Dfuse3_root=<静态库根> -Dcurl_dir=<预构建 libcurl 根>`——缺 `-Dcurl_dir` 直接 error（ftp_module 静态链接 libcurl）。
- 产物：`fuse_daemon`、`log_monitor`、`log_ctl`、`rule_server`、`basic_rules.so`、`ftp_module.so`（全部平台）；`injector` 仅 Android；`global_replace_ctl` 仅 GNU（测试驱动，不 install）。仅 `fuse_daemon` 带 `-DFUSE_USE_VERSION=317` 且 `-Wl,--export-dynamic` 导出公共符号供 dlopen 模块解析；模块与 `rule_server` 均不链接 libfuse3。
- 调试：`-Denable_debug=true`（可叠加 `-Dwith_asan=true` / `-Dwith_ubsan=true`，sanitizer 仅在 debug 下生效）；默认 `-O3 -flto -Wl,-s`。

## 测试（纯 Python，无 C 测试目标）

- 核心套件：`python3 tests/test_functional.py`（基础 IO/SQLite/并发）、`tests/test_rules.py`（ALLOW/REDIRECT/HIDE/RO/通配符/最长前缀优先/沙盒/热重载）、`tests/test_modules.py`（热插拔）、`tests/test_rule_server.py`（内置+模块动态规则热更新、多语言 desc/argc 约束）、`tests/test_path_vars.py`（路径合成）、`tests/test_crash_log.py`（崩溃链路，不挂载 FUSE）。有失败时退出码为 1（注意勿用管道吞掉退出码）。
- 特殊前置：`tests/test_ftp.py` 需本机 vsftpd 匿名服务（127.0.0.1:21，匿名根只读 + `upload/` 可写）；`tests/test_global_replace.py` 需 root（私有 mount namespace 内跑，无权限自动跳过）。压力类：`stress_fuse.py`、`test_ftp_stress.py`。
- 前置：GNU 构建产物 `build_gnu/`、`fusermount3`、`/dev/fuse`、Python `sqlite3`。产物路径可用环境变量覆盖：`FUSE_DAEMON`、`FTP_MODULE_SO`、`BASIC_RULES_SO`、`GLOBAL_REPLACE_CTL`（默认均在 `build_gnu/`）。
- 测试挂载 `/tmp/fuse_proxy_test/mnt` 与 `/tmp/fuse_rules_test/mnt`，规则写入 `/tmp/Namespace-Proxy/injector.conf`；失败残留的挂载点需 `fusermount3 -u` 清理后才能重跑。

## 架构与约定

- 多进程经 Unix Domain Socket 协作：`injector`（主控：epoll + inotify + zygote fork 检测）启动 `fuse_daemon`（`--mode=redirect --root=... --rules=<conf>`，约 27 个 FUSE 回调 + 模块调度）；`rule_server` 以 JSON 行协议动态增删/启停规则；`log_monitor` 收集日志、`log_ctl` 查询。injector 维护全局 + 媒体模块两棵 FUSE 树，共用同一二进制与配置。
- **模块化**：fuse_daemon 是零规则功能的框架——规则能力（REDIRECT/SANDBOX/HIDE/ALLOW/RO）由 dlopen 的 `basic_rules.so` 提供（原 `vfs_core.c` 迁移）；存储后端（如 FTP）由 `ftp_module.so` 提供：模块**不实现 FUSE**，只提供 `backend_*` 操作方法；FTP 映射由 injector.conf 的 `FTP <虚拟前缀> <段名>` 规则决定（如 `FTP /云盘 云盘`，写在 `[GLOBAL]`=全局生效、`[应用包名]`=仅该应用生效，与 REDIRECT 作用域一致），框架 vfs 回调经规则模块 resolve 命中 FTP 规则（`rr.is_ftp`）后调用模块方法完成读写。模块目录 `<CONFIG_DIR>/modules/<名>/<名>.so`，inotify 热插拔。详见 `docs/modules.md`。
- 模块 ABI 契约：第三方模块源码**只依赖 `include/nsp_module.h`**，编译须带 `-DNSP_MODULE_BUILD`；日志等公共符号经 fuse_daemon 导出表解析（`b_lundef=false` + `--export-dynamic`）——修改公共符号签名会破坏已编译模块。详见 `docs/module-dev.md`。
- 规则为 INI 格式：`[GLOBAL]` 段含 `MONITOR ON/OFF`（inotify 热重载开关）、`SANDBOX ON/OFF`；规则关键字 `REDIRECT <虚拟> <真实>`、`ALLOW`、`HIDE`、`RO`；应用段用 `[包名]` 或 `[包名:userid]`。`CONFIG_DIR` Android 为 `/data/Namespace-Proxy`、GNU 为 `/var/fuse-proxy`（见 `include/common.h`），但测试显式传 `--rules=/tmp/Namespace-Proxy/injector.conf`。
- 关键陷阱：配置中 REDIRECT 的虚拟前缀**不含 user_id**（如 `/云盘/`），测试经 `/0/云盘/...` 访问——FUSE 层剥离 `/0/` 后再匹配规则。修改路径匹配语义时勿破坏该约定。
- 改动后必跑：`basic_rules` / `fuse_daemon.c` / `config_parser.c` → `tests/test_rules.py`；`src/modules/ftp/` 或框架后端分派 → `tests/test_ftp.py`；`src/config/path_vars.c` 路径合成逻辑 → `tests/test_path_vars.py`。

## 文档索引

- 设计总览：`docs/architecture.md`；模块架构/开发：`docs/modules.md`、`docs/module-dev.md`；配置规范（含 App-rules 分文件）：`docs/ai-config-guide.md`；配置广播：`docs/config-broadcast.md`；路径变量：`docs/path-variables.md`；规则控制服务：`docs/rule-server-api.md`；log_ctl JSON API：`docs/log_ctl-api.md`；测试说明：`tests/README.md`。
