# 第三方组件声明

Fuse-Proxy 本体以 GPL-3.0-or-later 发布（见 `LICENSE`），并对模块 ABI
授予链接例外（见 `LICENSE.module-exception`）。

构建产物中静态链接了以下第三方组件，它们各自的许可证条款独立于本项目、
并继续适用于各自的代码：

## libfuse

- 用途：FUSE 用户态文件系统库，仅 `fuse_daemon` 链接
- 来源：`subprojects/libfuse`（fork 自 https://github.com/libfuse/libfuse）
- 许可证：**LGPL-2.1**（`include/` 与 `lib/` 目录，即本项目使用的部分）；
  该项目其余文件为 GPL-2.0，本项目未使用
- 完整文本：`subprojects/libfuse/LICENSE` 与 `subprojects/libfuse/LGPL2.txt`

**LGPL-2.1 第 6 条相关说明**：本项目在 Android 平台静态链接 libfuse。
使用者有权改用自行修改的 libfuse 版本重新链接出可用的 `fuse_daemon`。
为此本项目以完整源码形式发布，libfuse 以 git 子模块引入并指向其上游仓库：
替换 `subprojects/libfuse` 的内容后重新执行构建即可，无需本项目作者协助。

## json-c

- 用途：配置广播与日志的 JSON 序列化
- 来源：`subprojects/json-c`（https://github.com/json-c/json-c）
- 许可证：**MIT**
- 完整文本：`subprojects/json-c/COPYING`

## libcurl

- 用途：FTP 存储后端（`ftp_module.so`），最小构建集（仅 FTP+HTTP、无 SSL）
- 来源：`subprojects/curl`（https://github.com/curl/curl）
- 许可证：**curl 许可证**（MIT/X 衍生）
- 完整文本：`subprojects/curl/COPYING`

## 获取源码

完整源码（含上述子模块的引用版本）：

```
git clone --recurse-submodules https://github.com/huniangitb/Fuse-Proxy
```

若你通过预编译的模块压缩包获得本软件，而无法访问上述地址，可依 GPLv3
第 6 节向作者索取对应版本的完整源码。
