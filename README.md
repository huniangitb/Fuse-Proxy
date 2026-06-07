# Fuse-Proxy

**兼容: Android 13+ (API 33~35)**

Android 用户态 FUSE 文件系统代理 + 挂载命名空间隔离工具，作为 KernelSU / Magisk 模块的二进制核心组件运行。

## 概述

通过 FUSE 用户态文件系统和 Linux 挂载命名空间（mount namespace）技术，实现应用粒度的存储访问重定向、隐藏与隔离。

- **存储重定向**：按应用规则将文件操作透明重定向到指定目录
- **路径隐藏**：基于 fnmatch 规则对特定应用隐藏文件/目录
- **沙箱隔离**：为应用创建独立的存储沙箱
- **只读保护**：指定目录对特定应用只读
- **命名空间注入**：通过 zygote 子进程检测自动注入挂载命名空间

## 模块结构

```
Fuse-Proxy/
├── include/                # 公共头文件
├── src/
│   ├── core/               # 核心工具 (common, crash_dump, fast_pid, fast_search)
│   ├── daemon/             # FUSE 守护进程 (fuse_daemon, vfs_core)
│   ├── injector/           # 注入器 (injector, inject_target, mount_manager, ns_utils, ipc_server)
│   ├── config/             # 规则解析 (config_parser)
│   └── log/                # 日志服务 (log_ctl, log_monitor)
├── scripts/                # 辅助脚本
└── meson.build             # Meson 构建配置
```

## 构建

依赖：Meson、Ninja、Android NDK (clang)、libfuse3

```bash
meson setup build --cross-file /path/to/android-cross.ini
ninja -C build
```

产物在 `build/bin/`：
- `fuse_daemon` — FUSE 文件系统守护进程
- `injector` — 挂载命名空间注入守护进程
- `log_monitor` — 日志收集服务
- `log_ctl` — 日志查询/流式输出 CLI