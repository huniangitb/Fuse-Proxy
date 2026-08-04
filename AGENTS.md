# AGENTS.md

Android 13+ 用户态 FUSE 存储代理（KernelSU/Magisk 模块二进制核心），C23 编写，Meson + Ninja 构建。仓库文档与提交信息均使用中文。

## 构建

- 本机 GNU 构建（主线 libfuse3，pkg-config 查找）：`meson setup build_gnu -Dtarget_os=gnu && ninja -C build_gnu`
- 陷阱：`meson_options.txt` 中 `target_os` **默认是 `android`**。不带 `-Dtarget_os=gnu` 配置会走 Android 分支（依赖 NDK clang 与 `fuse3_root` 静态库），在普通 Linux 上必然失败。
- Android 交叉构建：`meson setup build --cross-file android-aarch64.ini -Dfuse3_root=<静态库根>`。
- 产物：`fuse_daemon`（全部平台，框架）、`injector`（仅 Android）、`log_monitor`、`log_ctl`、`basic_rules.so`（规则模块）、`ftp_module.so`（FTP 后端模块）。仅 `fuse_daemon` 带 `-DFUSE_USE_VERSION=317` 宏；模块均不链接 libfuse3。
- 调试：`-Denable_debug=true`（可叠加 `-Dwith_asan=true` / `-Dwith_ubsan=true`）；默认 `-O3 -flto -Wl,-s`。

## 测试（纯 Python，无 C 测试目标）

- `python3 tests/test_functional.py`；`python3 tests/test_rules.py`；`python3 tests/test_modules.py`（热插拔）；`python3 tests/test_ftp.py`（FTP 后端，需 vsftpd 匿名服务）；有失败时退出码为 1（注意勿用管道吞掉退出码）。
- 前置：`fusermount3`、`/dev/fuse`、Python `sqlite3`；daemon 路径用 `FUSE_DAEMON` 环境变量覆盖（默认 `build_gnu/fuse_daemon`）。
- 测试挂载 `/tmp/fuse_proxy_test/mnt` 与 `/tmp/fuse_rules_test/mnt`，规则写入 `/tmp/Namespace-Proxy/injector.conf`；失败残留的挂载点需 `fusermount3 -u` 清理后才能重跑。

## 架构与约定

- 4 个独立进程经 Unix Domain Socket 协作：`injector`（主控：epoll + inotify + zygote fork 检测）启动 `fuse_daemon`（`--mode=redirect --root=... --rules=<conf>`，约 27 个 FUSE 回调 + 模块调度）；`log_monitor` 收集日志、`log_ctl` 查询。injector 维护全局 + 媒体模块两棵 FUSE 树，共用同一二进制与配置。
- **模块化**：fuse_daemon 是零规则功能的框架——规则能力（REDIRECT/SANDBOX/HIDE/ALLOW/RO）由 dlopen 的 `basic_rules.so` 提供（原 `vfs_core.c` 迁移）；存储后端（如 FTP）由 `ftp_module.so` 提供：模块**不实现 FUSE**，只提供 `backend_*` 操作方法；FTP 映射由 injector.conf 的 `FTP <虚拟前缀> <段名>` 规则决定（如 `FTP /云盘 云盘`，写在 `[GLOBAL]`=全局生效、`[应用包名]`=仅该应用生效，与 REDIRECT 作用域一致），框架 vfs 回调经规则模块 resolve 命中 FTP 规则（`rr.is_ftp`）后调用模块方法完成读写。模块目录 `/data/Namespace-Proxy/modules/<名>/<名>.so`，inotify 热插拔。详见 `docs/modules.md`。
- 规则为 INI 格式：`[GLOBAL]` 段含 `MONITOR ON/OFF`（inotify 热重载开关）、`SANDBOX ON/OFF`；规则关键字 `REDIRECT <虚拟> <真实>`、`ALLOW`、`HIDE`、`RO`；应用段用 `[包名]` 或 `[包名:userid]`。
- 关键陷阱：配置中 REDIRECT 的虚拟前缀**不含 user_id**（如 `/云盘/`），测试经 `/0/云盘/...` 访问——FUSE 层剥离 `/0/` 后再匹配规则。修改路径匹配语义时勿破坏该约定。
- 修改 `basic_rules` / `fuse_daemon.c` / `config_parser.c` 后必须跑 `tests/test_rules.py`（覆盖 ALLOW/REDIRECT/HIDE/RO/通配符/最长前缀优先/沙盒/热重载）；修改 `modules/ftp/` 或框架后端分派后必须跑 `tests/test_ftp.py`。

## 文档索引

- 设计总览：`docs/architecture.md`；模块架构：`docs/modules.md`；配置广播：`docs/config-broadcast.md`；路径变量：`docs/path-variables.md`；测试说明：`tests/README.md`。
