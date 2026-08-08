# Fuse-Proxy 总体设计文档

> 面向维护者的架构说明。目标读者：需要理解模块边界、进程协作与数据流，以便安全地修改和扩展本项目的开发者。

## 1. 项目定位

Fuse-Proxy 是运行在 **Android 13+（API 33~35）** 上的用户态存储代理，作为 KernelSU / Magisk 模块的二进制核心组件运行。它通过两项内核机制实现**应用粒度**的存储访问控制：

- **FUSE 用户态文件系统**：拦截应用对外部存储（`/sdcard`、`/storage/emulated/N`）的文件操作，按规则透明改写。底层真实物理存储固定为 `/data/media/<user_id>`（`STORAGE_BASE` 常量），所有重定向最终都归一到此。
- **Linux 挂载命名空间（mount namespace）隔离**：通过检测 zygote 子进程，将定制的 FUSE 挂载注入到目标应用的 mount namespace，使规则只对目标应用生效，不影响系统其余部分。

### 核心能力

| 能力 | 说明 |
|------|------|
| 存储重定向（REDIRECT / ALLOW） | 将虚拟路径的文件操作透明重定向到指定真实目录；`ALLOW` 等价于"重定向回自身真实存储"（parse 阶段生成 `?` 前缀内部标记） |
| 路径隐藏（HIDE） | 对特定应用隐藏文件/目录（返回 ENOENT）；含跨应用隔离——应用访问 `/Android/data/<其他包名>/` 自动隐藏 |
| 只读保护（RO） | 指定路径对应用只读（写操作返回 EROFS） |
| 沙箱隔离（SANDBOX） | 为应用创建独立存储沙箱（`/Android/data/<pkg>/sandbox`），隔离 `/Android/data`、`/Android/obb` |
| 命名空间注入 | 检测 zygote fork，自动为目标应用注入 FUSE 挂载；支持 `FUSE_DIRECT` 直挂模式跳过 bind mount 备份还原 |
| 专属媒体 FUSE | 为 `com.android.providers.media.module` 单独起一个 FUSE 实例（惰性启动/退出） |
| 配置广播 | 通过 UDS 实时对外发布当前配置（供管理器 App 消费） |

## 2. 进程架构

项目编译产出 4 个独立可执行文件，各自是一个进程，通过 Unix Domain Socket 协作：

```
                         ┌─────────────────────────────────────────┐
                         │            injector (主控进程)            │
                         │  epoll 事件循环 + inotify 配置监听        │
                         │  ┌─────────────┬──────────────────────┐  │
       zygote fork 检测 ────▶│  │ inject_target│ mount_manager        │  │
                         │  │ (目标判定)   │ (挂载/命名空间注入)  │  │
                         │  ├─────────────┼──────────────────────┤  │
                         │  │ ipc_server  │ config_publisher     │  │
                         │  │ (IPC 服务)  │ (配置广播 UDS)       │  │
                         │  └─────────────┴──────────────────────┘  │
                         └───────┬───────────────────────┬─────────┘
                                 │ 启动 / 信号             │ UDS 广播
                                 ▼                         ▼
                    ┌────────────────────┐      ┌────────────────────┐
                    │  fuse_daemon        │      │  管理器 App /       │
                    │  FUSE 操作回调       │      │  log_ctl (CLI)     │
                    │  ┌───────────────┐  │      └────────────────────┘
                    │  │ vfs_core      │  │
                    │  │ (规则匹配引擎)│  │
                    │  └───────┬───────┘  │
                    └──────────┼──────────┘
                               │ 读 config_parser 解析的规则
                               ▼
                    ┌────────────────────┐
                    │  config_parser      │
                    │  规则解析 + Trie    │
                    └────────────────────┘

                    ┌────────────────────┐      ┌────────────────────┐
                    │  log_monitor        │◀─────│  各进程 log_internal │
                    │  日志收集服务        │ UDS  │  (common.c)         │
                    └────────────────────┘      └────────────────────┘
```

> 注：injector 实际同时维护**两棵** FUSE 树——全局 FUSE（`inject_global_fuse`）和媒体模块专属 FUSE（`inject_media_fuse`，仅当 `com.android.providers.media.module` 在注入目标时起）。二者共用同一 `fuse_daemon` 二进制、同一 `--rules` 配置，但挂载点不同。

### 2.1 injector — 主控进程

职责：系统级守护，负责发现目标应用并为其注入 FUSE 挂载。

- **事件循环**：`epoll` 统一管理 inotify（配置文件变更）、IPC socket、异步挂载完成管道、FUSE ready 管道、定时器（周期扫描）。
- **目标判定**（`inject_target.c`）：判断一个进程是否为注入目标——依据包名匹配配置、系统应用过滤、隔离进程过滤等。
- **挂载注入**（`mount_manager.c` + `ns_utils.c`）：进入目标进程的 mount namespace，挂载 FUSE 并做 bind mount 恢复。支持 `FUSE_DIRECT` 直挂模式——跳过备份/还原，直接追加挂载，首启动应用可走快速路径免读 mountinfo。
- **IPC 服务**（`ipc_server.c`）：接收外部（如管理器 App）的查询/控制命令。
- **配置广播**（`config_publisher.c`）：以 JSON 通过 UDS 实时发布配置，支持 GET / STATIC / SUBSCRIBE。详见 `config-broadcast.md`。

### 2.2 fuse_daemon — FUSE 文件系统守护

职责：实现 FUSE 操作回调，对被注入应用的每次文件操作应用规则。

- **FUSE 回调层**（`fuse_daemon.c`）：实现约 27 个 `fuse_operations` 回调（getattr/readdir/open/read/write/rename/xattr…）。由 injector 以 `--mode=redirect --root=/data/media --rules=<injector.conf>` 启动。框架**零规则功能**：规则决策经模块分派（`module_dispatch_resolve`）交给 dlopen 的规则模块（basic_rules.so）完成；无规则模块时直通回退。
- **后端分派**（`NSP_CAP_BACKEND_IO`）：FUSE 回调解析出 sub_path 后，若规则模块 resolve 命中 FTP 规则（`rr.is_ftp`，`FTP <虚拟前缀> <段名>`，作用域按规则所在段：GLOBAL=全局、应用段=仅该应用），则经 `module_backend_lookup` 定位后端模块（如 ftp_module.so）并改调其 `backend_*` 方法完成文件操作——**模块不实现 FUSE，只提供目标功能的方法，最终执行仍由框架回调驱动**；无后端模块或未命中 FTP 规则时本地文件系统直通（`module_backend_active()` 快速路径零开销）。
- **规则匹配引擎**：已整体迁移为热插拔规则模块 `basic_rules.so`（`src/modules/basic_rules/`，dlopen 进 fuse_daemon 进程，函数指针调用），模块化后框架不含任何规则语义。
- **uid→包名解析**（规则模块内 `br_get_pkg`）：uid<10000 直接判为 `system`；否则先查 `uid.map`、再读 `/proc/<tid>/status` 的 `Tgid`+`cmdline`；解析出 `<pre-`/`zygote`/长度<3 的进程视为不可解析，缓存为 nullptr。
- **每个 metadata 操作的热路径**：`vfs_get_app_cfg`（uid→配置，2048 槽 mutex 缓存，命中 O(1)）→ `vfs_sanitize_and_check_hidden`（路径消毒 + 隐藏判定）→ `vfs_to_real_path`（重定向/沙箱解析）——以上均由 basic_rules 模块内实现，框架经一次 `resolve` 调用取回全部决策（含最终真实路径），保住"一次查询多路复用"的性能语义。

### 2.3 log_monitor / log_ctl — 日志子系统

- **log_monitor**：常驻日志收集服务，通过 AF_UNIX 流式 socket（抽象地址 `nsp_log_socket`，`SOCK_STREAM`）接收各进程 `log_internal` 发来的日志，落盘/转发；同时提供 `search`/`stream`/`clear`/`count` 等查询服务。
- **log_ctl**：CLI 客户端，用于查询日志、流式输出、规则编辑（`set-rule`/`remove-rule`/`validate-rules`）、以及拉取配置广播（`get-config` / `stream-config`）。详见 `log_ctl-api.md`。

#### 挂载周期日志合并（LOG_BATCH 协议）

应用还原等"一条日志对应整个挂载周期"的场景，周期内中间日志（bind/f2fs
等）由 `log_batch_begin/end` 在 `log_internal` 层累积，`log_batch_end`
合并为**单条**多行日志写入环形缓冲（带不可见 `LOG_MERGED_MARK` 前缀）：

- sender 检测到 `LOG_MERGED_MARK` 即按 `LOG_BATCH\n<内容>\nLOG_BATCH_END`
  分帧发送；普通日志（LOG_IO/LOGCAT/SYS）逐条逻辑不变
- log_monitor 的 `async_log_thread` 收集 LOG_BATCH 帧，`LOG_BATCH_END`
  整块合并为**一条**入库（前端最终只显示一条，多个发送请求并入一个日志）
- 合并日志为**单行输出**：`[injector] <条目1>\t<条目2>...`，条目间以
  制表符连接（不用换行，避免前端按行拆分导致 UTF-8 截断乱码）
- 合并日志级别固定为 `LOG_DEBUG`（`--level >=1` 查询时不显示）
- 粘包/竞态处理：主循环首行 LOG_SYS 转 async 前把剩余字节移交
  `AsyncCtx.pending`（在 `pthread_create` 之前填充）；背靠背 LOG_BATCH
  帧写入多槽队列 `batch_q`（BATCH_Q_CAP=4），由 `drain_async` 逐槽
  push 入 g_sys_buf，互不覆盖

## 3. 模块与源码布局

```
Fuse-Proxy/
├── include/                # 公共头文件（对外接口声明）
├── src/
│   ├── core/               # 跨进程共享的基础设施
│   │   ├── common.c        # 日志、路径消毒、IPC 收发、时区、cgroup 逃逸、STORAGE_BASE 常量
│   │   ├── crash_dump.c    # 崩溃转储
│   │   ├── fast_pid.c      # PID/进程信息快速读取
│   │   ├── fast_search.c   # NEON 优化的子串检索（mountinfo 匹配）
│   │   ├── path_trie.c     # 路径 Trie（零业务依赖，可独立单元测试）
│   │   └── uid_map.c       # uid→包名 映射表（磁盘持久化 + 内存缓存）
│   ├── config/             # 规则配置
│   │   ├── config_parser.c # 规则文件解析、AppConfig 管理、Trie 构建、变量静态性分析
│   │   └── path_vars.c     # 路径变量（$package 等）展开、真实目标分类
│   ├── daemon/             # FUSE 守护进程
│   │   └── fuse_daemon.c   # FUSE 操作回调 + main（框架零规则功能，含后端分派）
│   ├── module/             # 热插拔模块加载器
│   │   └── loader.c        # dlopen 加载/卸载、能力登记、resolve/probe/后端分派、inotify 热插拔监控
│   ├── modules/            # 热插拔模块（.so，dlopen 进 fuse_daemon）
│   │   ├── basic_rules/    # 基础规则引擎（原 vfs_core 迁移）：REDIRECT/SANDBOX/HIDE/ALLOW/RO
│   │   └── ftp/            # FTP 存储后端（纯方法模块，无 FUSE 实现）：ftp_backend/ftp_client/ftp_conf/ftp_module
│   ├── injector/           # 注入器
│   │   ├── injector.c      # main + epoll 事件循环（含 inject_global_fuse/inject_media_fuse）
│   │   ├── inject_target.c # 注入目标判定 + uid 映射维护
│   │   ├── mount_manager.c # FUSE 挂载管理（含 FUSE_DIRECT 直挂快速路径）
│   │   ├── ns_utils.c      # mount namespace 操作（含 do_force_umount_stale 预清理）
│   │   ├── ipc_server.c    # IPC 服务端（含 FUSE_DIRECT 快速路径首启动免读 mountinfo）
│   │   └── config_publisher.c # 配置广播 UDS 服务
│   └── log/                # 日志子系统
│       ├── log_monitor.c   # 日志收集服务（AF_UNIX SOCK_STREAM，抽象地址 nsp_log_socket）
│       └── log_ctl.c       # 日志/配置查询 + 规则编辑 CLI
└── meson.build             # Meson 构建配置
```

## 4. 构建产物与源文件映射

由 `meson.build` 定义。四个可执行文件共享一组 `common_sources`：

```
common_sources = core/common.c, config/config_parser.c, config/path_vars.c,
                 core/fast_search.c, core/uid_map.c
```

| 可执行文件 | 专属源文件 | 说明 |
|-----------|-----------|------|
| `fuse_daemon` | daemon/fuse_daemon.c, module/loader.c, core/crash_dump.c, core/fast_pid.c | FUSE 守护（框架，零规则功能） |
| `injector` | injector/*.c（injector, inject_target, mount_manager, ipc_server, config_publisher, ns_utils）, core/fast_pid.c | 注入器 |
| `log_monitor` | log/log_monitor.c | 日志收集 |
| `log_ctl` | log/log_ctl.c | 日志/配置 CLI |

| 共享库（模块，dlopen） | 源文件 | 说明 |
|-----------------------|--------|------|
| `basic_rules.so` | modules/basic_rules/*.c | 规则模块（原 vfs_core 迁移），安装到 `bin/modules/basic_rules/` |
| `ftp_module.so` | modules/ftp/*.c, core/common.c | FTP 存储后端（纯方法模块，**不依赖 libfuse3**），安装到 `bin/modules/ftp_module/` |

外部依赖：`libfuse3`（仅 fuse_daemon 直接用；规则/后端模块均不链接）、`json-c`（配置广播/日志 JSON 序列化）、`iconv`（字符编码）、`pthread`。

编译：交叉编译到 `aarch64-linux-android35`，C23 标准，`warning_level=3`。Release 用 `-O3 -flto`。

## 5. 规则系统设计（核心）

规则系统是 fuse_daemon 的心脏，位于 `config_parser.c`（解析与存储）+ `vfs_core.c`（匹配与应用）。

### 5.1 规则类型

| 规则 | 语法 | 语义 |
|------|------|------|
| ALLOW | `ALLOW <虚拟路径>` | 放行：虚拟路径映射到当前用户真实存储（`?` 前缀内部标记） |
| REDIRECT | `REDIRECT <虚拟路径> <真实目标>` | 将虚拟路径重定向到指定真实目标 |
| HIDE | `HIDE <路径>` | 对应用隐藏该路径（返回 ENOENT） |
| RO | `RO <路径>` | 该路径对应用只读（写返回 EROFS） |
| SANDBOX | `SANDBOX ON/OFF` | 沙箱开关（隔离 /Android/data、/Android/obb 到独立目录） |

作用域：`[GLOBAL]` 段为全局规则（所有应用共享）；`[包名:用户ID]` 段为应用专属。应用规则也可放在 `App-rules/包名.conf` 独立文件。多用户场景使用 `App-rules-<uid>/<包名>.conf`。

> 注：`SANDBOX` / `MONITOR` / `FUSE_DIRECT` 等开关既可写在 `[GLOBAL]` 段作全局默认，也可写在应用段覆盖全局；应用段显式写一次即标记 `*_explicit`，此后以应用段值为准——不存在"继承全局后再覆盖"的中间态。

### 5.2 双通道存储：Trie + 线性数组

规则按是否含**通配符/变量**分两条通道存储，这是性能与灵活性的权衡：

- **纯静态规则**（无 `*?[]` 通配、无 `$` 变量）→ 写入 **Trie（前缀树）**。按路径 `/` 分段逐层匹配，单次查询 O(路径段数)，且一次 `trie_lookup` 同时返回 hidden/ro/redirect 三类命中。这是绝大多数规则的快路径。
- **含通配/变量的规则** → 存入线性数组（`hide_rules[]` / `ro_rules[]` / `redir_rules[]`），逐条 `fnmatch` + 前缀匹配。数量通常很少。

> 注：Trie 是一棵**多叉前缀树**（每个节点按路径段分支），不是二叉树。它是内聚、零配置依赖的数据结构，独立于 AppConfig。

### 5.3 路径变量

`REDIRECT` / `HIDE` / `RO` / `ALLOW` 的路径支持变量（`path_vars.c`）：

- `$package`：当前命中应用的包名（运行时按 uid 解析）。
- 自定义变量：`NAME=VALUE` 定义，可相互引用（带循环检测）。
- **静态/动态优化**：加载时分析每个变量——不含 `$package` 的静态变量预计算并缓存展开值；含动态因素的每次请求展开。详见 `path-variables.md`。

### 5.4 单次操作的匹配流程（fuse_daemon 热路径）

```
FUSE 回调（如 getattr）
  └─ VFS_SETUP_CORE 宏：
       ① vfs_get_app_cfg(uid) ────────── uid→AppConfig（2048 槽缓存，命中 O(1)）
       ② vfs_sanitize_and_check_hidden ─ 路径消毒 + Trie 一次性解析（填 TrieMatch）+ 隐藏判定
       ③ vfs_to_real_path ────────────── 复用 TrieMatch 的 redirect 结果 → 真实路径
  └─ 写操作额外：vfs_is_path_ro ───────── 复用 TrieMatch 的 ro 结果
```

`TrieMatch` 缓存使单次操作对两棵 Trie（app + global）的遍历从 6 次降到 2 次。

### 5.5 真实目标分类与 sandbox

`vfs_to_real_path` 解析真实路径时按以下优先级：

1. **Trie 静态 redirect 命中**（复用 `TrieMatch`）：若目标以 `?` 开头，转换为 `STORAGE_BASE/<user_id><后缀>`。
2. **线性 redir_rules**：app 优先、global 兜底；目标经 `build_real_base_from_target` 分类——`?` 前缀或相对路径→当前用户存储；`/storage/emulated/X/...`→归一为当前用户存储；`/data`、`/mnt`、`/storage`→绝对路径原样；其他以 `/` 开头→当前用户存储。
3. **sandbox 重定向**：`SANDBOX ON` 时，除应用自身 `/Android/data/<pkg>`、`/Android/obb/<pkg>` 外的 `/Android/data`、`/Android/obb` 访问重定向到 `/Android/data/<pkg>/sandbox`。应用段显式 `SANDBOX OFF` 可覆盖全局 `ON`（靠 `sandbox_explicit` 标记）。
4. **fallback**：无任何命中则默认 `STORAGE_BASE/<user_id><sub_path>`。

> `?` 前缀是项目内部标记，由 parse 阶段对 ALLOW 和相对路径 REDIRECT 自动生成，表示"相对当前用户存储"，运行时由 `vfs_to_real_path`/`build_real_base_from_target` 还原为 `STORAGE_BASE/<user_id>`。配置文件中一般无需手写。

### 5.6 跨应用隔离

- `vfs_is_other_app_pkg`：应用访问 `/Android/data/<其他包>/`、`/Android/obb/<其他包>/` 自动判为其他应用，由 `is_path_hidden_internal` 返回隐藏（ENOENT）。
- `CONFIG_DIR`（`/data/Namespace-Proxy`）路径下的所有访问无条件隐藏，防止应用窥探配置本身。

## 6. 进程间协作与数据流

### 6.1 注入流程

1. injector 启动时先 `inject_global_fuse`：在 `/mnt/nsp_global` 挂载全局 FUSE 实例（fuse_daemon 以 `--root=/data/media --rules=<injector.conf>` 启动）。若 `com.android.providers.media.module` 在注入目标之列，再惰性 `inject_media_fuse` 起一个专用 FUSE 实例。
2. injector 通过检测 zygote 子进程（`fast_pid` + `/proc` 扫描，周期由 timerfd 驱动）发现新启动的应用。
3. `inject_target` 判定该进程是否为配置的目标应用（含 `SKIP_SYSTEM_APPS` 默认过滤 uid<10000、隔离进程过滤）。
4. 命中则 `mount_manager` + `ns_utils` 进入其 mount namespace，挂载 fuse_daemon 提供的 FUSE 文件系统。`FUSE_DIRECT` 开启时走快速路径：跳过 bind mount 备份/还原，直接追加挂载；首启动应用可免读 mountinfo。
5. 此后该应用对 `/sdcard` 等的访问经 FUSE → vfs_core 规则匹配。

### 6.2 配置热重载

- injector 用 inotify 监听 `injector.conf` 与 `App-rules/*.conf` 变更。
- fuse_daemon 独立用 inotify 监听规则目录（`vfs_core.c` 的 `config_monitor_thread`），变更后 `reload_config` 重建 AppConfig 与 Trie、清空 uid 缓存、重读 `uid.map`。
- 变更后 injector 通过 `config_publisher` 向订阅者广播新配置；若 `global_inject` 切换则广播"全量变更"（`changed_count=-1`）触发全应用重挂载，否则仅通知受影响包。

### 6.3 IPC 与广播（UDS）

| Socket | 类型 | 用途 |
|--------|------|------|
| `nsp_ipc_socket` | IPC 命令（抽象） | injector 控制/查询（如 `list-injected`） |
| `nsp_config_broadcast` | DGRAM 抽象 | 配置广播（GET/STATIC/SUBSCRIBE），详见 config-broadcast.md |
| `nsp_log_socket` | AF_UNIX SOCK_STREAM 抽象 | 各进程 `log_internal` → log_monitor；log_ctl 也经此 `search`/`stream`/`clear`/`count` |

## 7. 关键全局状态与并发

| 全局 | 归属 | 保护 | 说明 |
|------|------|------|------|
| `g_global_cfg` / `g_app_cfgs` | config_parser | `g_rules_lock`（rwlock） | 规则配置，读多写少，reload 时持写锁 |
| `g_uid_maps` / `g_uid_map_count` | vfs_core | 同上 rwlock | uid→包名 映射（`uid.map` 加载，二分查询） |
| `g_uid_cache[2048]` | vfs_core | per-slot mutex | uid→AppConfig 缓存，slot = `uid % 2048` |
| `g_global_fuse` / `g_media_fuse` | injector | 各自字段 | 全局/媒体 FUSE 实例状态（pid/mnt_path/disabled/crash_count） |

并发要点：FUSE 回调多线程并发执行，读规则前必须 `config_lock_read()`，且**所有返回路径必须解锁**（`VFS_RETURN` 宏统一处理，切勿裸 `return`）。uid 缓存槽用 `uid % UID_CACHE_SIZE` 取模，未命中时回退到 `/proc/<tid>/status`+`cmdline` 解析。

## 8. 维护规范

- **公共工具归属**：跨进程复用的工具函数放 `src/core/common.c`（声明在 `common.h`）。路径/字符串处理、mkdir、SELinux 上下文继承等应集中一处，避免各文件各写一份。
- **数据结构独立**：内聚、零业务依赖的数据结构（如 Trie）应自成模块（`.c`+`.h`），可独立单元测试。`path_trie.c` 不引用 AppConfig 或任何配置全局。
- **规则匹配语义等价**：修改 Trie 或线性通道时，务必保持二者对同一规则的优先级一致——app trie 优先于 global trie；redirect 取 app 命中优先、global 仅兜底；hidden/ro 取 app+global **并集**（任一命中即生效）。
- **Trie matched 语义**：`trie_lookup` 的返回值表示"命中至少一条真实规则（hidden/ro/redirect，含祖先继承）"，而非"路径途经了无规则的中间节点"——否则 `/Android/data/<未配置包>` 会误判。修改时务必保留此语义。
- **sandbox 路径长度校验**：`current_pkg` 来自 uid 缓存可极长，sandbox target 拼接后可能超过 `MAX_PATH_LEN`，命中时**放弃沙盒重定向**（不截断后 mkdir 错误位置）。修改 sandbox 路径生成时勿破坏该校验。
- **YAGNI**：不保留无调用者的"预留"实现。新增能力以实际需求驱动。
- **单元测试**：`tests/` 下有 `test_trie` / `test_path_vars` / `test_path_sanitize`。修改对应模块须同步更新测试，`ninja -C build test` 全绿方可提交。

## 9. 相关文档

- `docs/ai-config-guide.md` — 配置规范（段头、开关、规则、变量、禁忌）
- `docs/path-variables.md` — 路径变量语法与真实目标分类
- `docs/config-broadcast.md` — 配置广播服务的 Android 接入
- `docs/log_ctl-api.md` — 日志/配置/规则编辑 CLI API

