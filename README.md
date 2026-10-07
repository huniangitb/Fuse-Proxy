# Fuse-Proxy

**Android 13+ (API 33~35)** 用户态 FUSE 文件系统代理 + 挂载命名空间隔离工具，作为 root 模块的二进制核心组件运行。

通过 FUSE 用户态文件系统与 Linux 挂载命名空间，实现**应用粒度**的存储访问重定向、隐藏与隔离：

- **存储重定向**：按应用规则将文件操作透明重定向到指定目录
- **路径隐藏**：基于 fnmatch 规则对特定应用隐藏文件/目录
- **沙箱隔离**：为应用创建独立的存储沙箱
- **只读保护**：指定目录对特定应用只读
- **命名空间注入**：检测 zygote 子进程自动注入挂载命名空间

## 构建

```bash
git clone --recurse-submodules https://github.com/huniangitb/Fuse-Proxy && cd Fuse-Proxy
```

| 平台 | 命令 | 说明 |
|---|---|---|
| GNU（本机测试） | `scripts/build.sh` | 构建到 `build_gnu/`；等价 `meson setup build_gnu -Dtarget_os=gnu && ninja -C build_gnu` |
| Android（NDK 交叉） | `scripts/android-build.sh` | NDK 自动搜索（`ANDROID_NDK_HOME` 优先），API 默认 35（`ANDROID_API` 覆盖） |
| 打包 | `scripts/pack-module.sh` | 同步 Android 产物到模块骨架并打包 zip（`-h` 查看选项） |

前置：`meson`、`ninja`、`cmake`、`pkg-config`、`gcc`；Android 另需 NDK。

第三方依赖由 Meson 自动处理，无需手动指定：

| 依赖 | GNU | Android |
|---|---|---|
| libfuse3 | 系统库优先，缺失回退编译 `subprojects/libfuse` | 默认编译子模块 |
| json-c | 系统库优先，缺失回退编译 `subprojects/json-c` | 默认编译子模块 |
| libcurl（ftp_module，≥8.21.0） | 系统库优先，缺失回退编译 `subprojects/curl`（仅 FTP+HTTP、无 SSL 最小集） | 默认编译子模块 |

子模块均为上游 pin 版，`git submodule update --init --recursive` 即可补齐。强制指定来源见 `meson_options.txt`（如 `-Dlibfuse_source=system`、`-Dandroid_curl=prebuilt`）。

## 产物

构建目录根下（`meson install` 后按下表落位）：

| 产物 | 安装位置 | 说明 |
|---|---|---|
| `fuse_daemon` | `bin/` | FUSE 文件系统守护进程（框架：FUSE 回调 + 内建规则引擎 `fw_rules` + 模块调度） |
| `injector` | `bin/`（仅 Android 安装） | 挂载命名空间注入守护进程。GNU 下也编一份但不 install，供 `tests/test_inject_mount_env.py` 用 |
| `rule_server` | `bin/` | 规则控制服务（JSON 行协议动态改规则） |
| `log_monitor` / `log_ctl` | `bin/` | 日志收集服务 / 查询流式输出 CLI |
| `ftp_module.so` | `bin/modules/ftp_module/` | FTP 存储后端模块（热插拔；当前唯一模块，见下） |
| `src/zygisk/{arm64-v8a,armeabi-v7a}.so` | `zygisk/` | Zygisk 应用创建通知模块（仅 Android，双 ABI） |
| `global_replace_ctl` | 不 install | 全局替换挂载测试驱动（仅 GNU，供 `tests/test_global_replace.py`） |

**规则能力在框架内，不在模块里**：自模块 ABI V4 起，规则决策（REDIRECT/SANDBOX/HIDE/ALLOW/RO）、uid→包名、MONITOR 开关全部由框架自持（`src/daemon/fw_rules.c`、`fw_pkg.c`、`fw_config.c`）——否则「模块缺席」会让规则与监控一起失效。模块只剩**后端存储提供者**一种形态（不实现 FUSE，只提供 `backend_*` 方法）。详见 [docs/modules.md](docs/modules.md)。

## 测试

```bash
python3 tests/run.py                  # 按本次改动自动选套件（推荐）
python3 tests/run.py --layer L0       # 只跑 L0 静态/契约层（无挂载无网络）
python3 tests/run.py --all --strict    # 全量验收：跳过项计为失败
scripts/acceptance.sh                 # 完整验收门（构建 + 全量测试 + 文档一致性 + 报告）
```

前置：GNU 产物 `build_gnu/`、`fusermount3`、`/dev/fuse`、Python `sqlite3`；`tests/test_ftp.py` 另需本机 vsftpd 匿名服务。

分层说明、套件映射表、退出码约定与环境坑见 [docs/testing.md](docs/testing.md)。

## 结构

```
include/      # 公共头文件（含 nsp_module.h，第三方模块唯一依赖）
src/
  daemon/     # fuse_daemon（框架：FUSE 回调 + 内建规则引擎 fw_rules + 模块调度）
  injector/   # injector（主控：挂载/命名空间/IPC/配置广播）
  module/     # 模块框架（加载器 + 故障围栏 + 熔断）
  modules/    # ftp（FTP 存储后端，当前唯一模块）
  zygisk/     # Zygisk 应用创建通知模块（仅 Android，双 ABI）
  rule/       # rule_server
  config/     # 规则解析 + 路径变量
  core/       # 公共工具（日志/通讯线程/trie/uid 映射/crash）
  log/        # log_monitor、log_ctl
subprojects/  # 第三方源码子模块（随主项目编译）
compat/       # 头文件布局转接（<fuse3/...> → 子模块平铺头）
conf/         # 示例配置
scripts/      # 构建 / 打包 / 隔离测试 / 设备操作脚本
tests/        # Python 测试套件（统一入口 run.py）
tools/        # 开发辅助工具
docs/         # 设计文档
```

## 文档

| 文档 | 内容 |
|---|---|
| [docs/README.md](docs/README.md) | **文档索引**：先读哪份、各份管什么契约 |
| [docs/architecture.md](docs/architecture.md) | 进程架构、规则引擎、并发、维护规范 |
| [docs/modules.md](docs/modules.md) | 模块架构、ABI 契约、第三方模块开发 |
| [docs/config.md](docs/config.md) | 配置语法、路径变量、禁忌清单 |
| [docs/testing.md](docs/testing.md) | 测试分层、套件映射、验收门与证据要求 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 开发流程、红线、提交与验收规范 |
| [AGENTS.md](AGENTS.md) | 构建陷阱、判别性用例细节、AI 协作约定 |

## 许可证

本项目以 **GPL-3.0-or-later** 发布，见 `LICENSE`。

**模块 ABI 链接例外**：仅通过 `include/nsp_module.h` 的公开 ABI 与本项目结合的独立模块（运行时 dlopen 加载的 `.so`），可按任意条款发布，不因此受 GPL 约束——框架保持 copyleft，模块生态保持自由。完整条款见 `LICENSE.module-exception`。

构建产物静态链接了 libfuse（LGPL-2.1）、json-c（MIT）、libcurl（curl 许可证）。各组件许可证与 LGPL 重新链接权利的说明见 `THIRD-PARTY-NOTICES.md`。
