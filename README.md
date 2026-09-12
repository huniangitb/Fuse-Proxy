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

在构建目录根下（`meson install` 后进 `bin/`）：

| 产物 | 说明 |
|---|---|
| `fuse_daemon` | FUSE 文件系统守护进程（框架，规则能力来自 dlopen 模块） |
| `injector` | 挂载命名空间注入守护进程（仅 Android） |
| `rule_server` | 规则控制服务（JSON 行协议动态改规则） |
| `log_monitor` / `log_ctl` | 日志收集服务 / 查询流式输出 CLI |
| `basic_rules.so` / `ftp_module.so` | 热插拔模块（规则引擎 / FTP 存储后端） |

## 测试

```bash
python3 tests/test_functional.py  # 基础 IO/SQLite/并发（默认用 build_gnu/ 产物）
python3 tests/test_rules.py       # 规则边界（REDIRECT/HIDE/RO/通配符/热重载）
```

需 `fusermount3`、`/dev/fuse`；`tests/test_ftp.py` 需本机 vsftpd 匿名服务，`tests/test_global_replace.py` 需 root。完整映射表见 `AGENTS.md`。

## 结构

```
include/      # 公共头文件（含 nsp_module.h，第三方模块唯一依赖）
src/
  daemon/     # fuse_daemon（框架：FUSE 回调骨架 + 模块调度 + 存储原语）
  injector/   # injector（主控：挂载/命名空间/IPC/配置广播）
  module/     # 模块框架（加载器 + 故障围栏 + 熔断）
  modules/    # basic_rules（规则引擎）、ftp（FTP 后端）
  rule/       # rule_server
  config/     # 规则解析 + 路径变量
  core/       # 公共工具（日志/通讯线程/trie/uid 映射/crash）
  log/        # log_monitor、log_ctl
subprojects/  # 第三方源码子模块（随主项目编译）
compat/       # 头文件布局转接（<fuse3/...> → 子模块平铺头）
conf/         # 示例配置
tests/        # Python 功能测试
docs/         # 设计文档
```

## 文档

| 文档 | 内容 |
|---|---|
| `docs/architecture.md` | 进程架构、规则引擎、并发、维护规范 |
| `docs/modules.md` | 模块架构、ABI 契约、第三方模块开发 |
| `docs/config.md` | 配置语法、路径变量、禁忌清单 |
| `AGENTS.md` | 构建陷阱、开发红线、测试映射表 |
