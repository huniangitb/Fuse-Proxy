# 热插拔模块架构（FUSE 框架 + 模块）

> 面向维护者与模块开发者的技术文档。说明 Fuse-Proxy 的模块化设计：
> fuse_daemon 仅作为框架（回调骨架 + 模块调度 + 存储原语），规则能力
> （REDIRECT / SANDBOX / HIDE / ALLOW 豁免 / RO）由热插拔模块提供；
> 存储后端（如 FTP）同样是模块——只提供目标功能的方法，FUSE 由框架
> 统一实现，路径命中后端前缀时框架调用模块方法完成读写。

## 1. 设计目标

- **框架零功能**：fuse_daemon 不内置任何规则语义，只负责 FUSE 回调骨架、
  路径清洗（剥离 `/0/` user_id 前缀）、模块调度与本地存储原语。
- **能力自述**：模块加载后通过能力位图告诉框架"我支持哪些规则类型"，
  框架只调用模块声明过的接口（被动触发，模块仅提供接口方法）。
- **热插拔**：模块放入模块目录即加载，删除即卸载，覆盖 `.so` 即重载，
  运行中不中断已挂载的 FUSE。
- **扩展性**：ABI 版本化 + 能力位图（32 位）预留，新能力通过新增位 +
  接口字段演进，不破坏旧模块；FTP 等存储后端模块（BACKEND 类型）落地：
  模块只提供目标功能方法（backend_*），不实现 FUSE（框架已实现）；
  FTP 映射由规则模块的 `FTP <虚拟前缀> <段名>` 规则决定（作用域按规则
  所在段：GLOBAL=全局、应用段=仅该应用），框架命中后调用这些方法。

## 2. 模块目录约定

```
<MODULES_DIR>/<模块名>/<模块名>.so      # 规则模块（dlopen 进 fuse_daemon）
<MODULES_DIR>/<模块名>/<模块名>.rules   # 可选：规则类型注册（rule_server 读取）
<MODULES_DIR>/<模块名>/...               # 模块可选资源（配置等）
```

- **Android**：`/data/Namespace-Proxy/modules`
- **GNU**：`/var/fuse-proxy/modules`（测试可用 `--modules-dir=` 覆盖）
- 模块名仅含 `[a-z0-9_-]`，目录名 = 模块名 = `.so` 文件名（`<name>.so`）

### 2.1 规则类型注册（`.rules`，前端动态能力）

模块可在自己的目录放置 `<模块名>.rules` 文本文件，向 **rule_server** 声明
自己支持的规则类型，实现「前端可操作的规则随加载模块动态追加」。

**conf 段格式（推荐，易于编写）**——`[类型名]` 段 + `key=value` 属性行：

```ini
[FTP]
format = pair
argc = 2
desc = FTP 存储映射：<虚拟前缀>|<段名>
desc.en = FTP storage mapping: <virtual prefix>|<section>
```

| 键 | 说明 | 示例 |
|----|------|------|
| `format` | 值格式：`path`（单值路径）/ `pair`（src\|dst 双值）/ `switch`（ON/OFF 开关）/ `tokens`（多 token，默认 2 个以上任意数量） | `format = pair` |
| `argc=N` | 恰好 N 个参数（覆盖 format 默认约束：path=1、pair=2、tokens=2+） | `argc = 3` |
| `argc=N:M` | N~M 个参数（M 用 `*` 或不写表示不限上界） | `argc = 2:4`、`argc = 2:*` |
| `global-only` | `true`/`false`：仅全局作用域可用（应用作用域 ADD 报错） | `global-only = true` |
| `desc` | 中文描述（默认语言） | `desc = 隐藏路径` |
| `desc.xx` | 指定语言的描述（xx=语言代码，如 `en`/`ja`） | `desc.en = Hide path` |

**旧行格式（兼容）**：`<TYPE> <FORMAT> [属性...]`，如
`FTP pair argc=2 desc="..." desc.en="..."`。解析器为状态机，两种格式
可在同一 `.rules` 文件中混合使用；段内无 `=` 的行或段外行按旧行格式处理，
文件尾自动刷新未结束的段。

rule_server 按声明解析属性并体现在 `rule_types` 中：`argc_min/argc_max`
用于 ADD 时参数数量校验；`global_only` 限制作用域；多语言 `desc` 按
PING/LIST 请求的 `lang` 参数回传（默认中文，未知语言回退 zh），并附
`desc_map` 全语言映射供前端渲染语言切换。畸形声明（如 `argc=abc`）
被跳过，不注册错误约束。

- rule_server 按需扫描 `modules/*/<模块名>.rules`，动态合并进规则类型表：
  带目录/文件 mtime 缓存，模块目录与 .rules 未变化时直接复用类型表（零扫描）；
  放入/删除/修改 `.rules`（mtime 变化）即热更新，无需重启（内置 HIDE/RO/REDIRECT/ALLOW/
  MONITOR/SANDBOX/GLOBAL_INJECT 始终存在，与 basic_rules 对应）。
- 未注册的类型前端无法 ADD/REMOVE/ENABLE/DISABLE；LIST/PING 返回的
  `rule_types` 数组即当前全部可用类型（含 `builtin`/`module`/`format`/
  `global_only`/`argc_min`/`argc_max`/`desc`/`desc_map` 字段）。
- 无 `.rules` 文件的模块不影响加载（rule_server 仅跳过其类型注册）。

## 3. 模块 ABI（`include/nsp_module.h`）

### 3.1 模块类型

| 类型 | 说明 |
|------|------|
| `NSP_MODULE_TYPE_RULES` | 规则模块：参与路径决策（REDIRECT/SANDBOX/HIDE/ALLOW/RO） |
| `NSP_MODULE_TYPE_BACKEND` | 存储后端模块：提供新存储后端（如 FTP）的操作方法，不实现 FUSE |

### 3.2 能力位图（模块自述能力）

| 位 | 能力 | 说明 |
|----|------|------|
| 0 | `NSP_CAP_REDIRECT` | 支持 REDIRECT 重定向 |
| 1 | `NSP_CAP_SANDBOX` | 支持 SANDBOX 沙箱 |
| 2 | `NSP_CAP_HIDE` | 支持 HIDE 隐藏 |
| 3 | `NSP_CAP_ALLOW` | 支持 ALLOW 豁免 |
| 4 | `NSP_CAP_RO` | 支持 RO 只读 |
| 5 | `NSP_CAP_READDIR_EXTRA` | 支持 readdir 虚拟目录补充 |
| 6 | `NSP_CAP_VIRTUAL_DIR` | 支持虚拟目录合成 |
| 10 | `NSP_CAP_MOUNT_POINT` | （后端）提供虚拟前缀路径（`/<段名>`） |
| 11 | `NSP_CAP_VAR` | （后端）向框架注册变量（如 `FTP_云盘=/mnt/nsp_ftp/云盘`） |
| 12 | `NSP_CAP_BACKEND_IO` | （后端）后端 I/O：路径命中时由框架调用模块方法完成文件操作 |

### 3.3 框架服务表（框架 → 模块）

模块 `init` 时收到 `NspFrameworkApi`，仅经它使用框架设施（版本化，字段尾部追加）：

| 接口 | 说明 |
|------|------|
| `log(level, fmt, ...)` | 日志 |
| `get_real_root()` | 真实存储根（`--root=`） |
| `get_rules_path()` | 规则配置路径（`--rules=`） |
| `get_flags()` | 启动标志（`NSP_FLAG_DISABLE_SANDBOX` 等） |

### 3.4 决策接口（模块 → 框架）

- `resolve(const NspQueryCtx*, NspResolveResult*)`：路径决策。输入 FUSE 原始
  路径 + uid/pid/gid，输出完整决策（hidden / ro / allow / redir / sandbox /
  最终真实路径 / 虚拟目录标志 / monitor 状态）。**一次调用返回全部结果**，
  保住 TrieMatch"一次查询多路复用"的性能语义。
- `readdir_extra(...)`：readdir 虚拟目录补充，返回条目数组（框架负责去重 +
  filler），不依赖 fuse 类型，便于解耦。
- `reload()`：配置热重载通知。
- `get_pkg(uid, pid, out)`：uid → 包名解析（框架日志用）。

#### 后端 I/O 接口（`NSP_CAP_BACKEND_IO`，仅 BACKEND 模块）

模块**不实现 FUSE**，只提供方法；框架 vfs 回调（getattr/readdir/open/create/
read/write/release/unlink/mkdir/rmdir/rename/truncate 等）在解析出 real_path
后经 `module_backend_lookup` 命中模块 `backend_match(path)==1` 时改调对应
方法（作用域由规则模块 resolve 的 `rr.is_ftp` 控制——FTP 规则所在段决定
哪些应用命中），最终执行仍由框架的 FUSE 回调驱动。路径参数为框架解析后的
真实路径（如 `/mnt/nsp_ftp/云盘/xxx`），模块自行剥离前缀映射到目标存储。

| 接口 | 说明 |
|------|------|
| `backend_match(path)` | 1=模块管理该路径（前缀匹配） 0=否 |
| `backend_getattr(path, st)` | 元数据（SIZE/LIST/CWD 判定等） |
| `backend_readdir(path, entries, max)` | 返回 `NspDirEntry` 条目数组（框架 filler） |
| `backend_open(path, flags, &h)` / `backend_create(path, mode, &h)` | 打开/创建，`h` 为模块句柄（框架透传） |
| `backend_read(h, buf, size, off, &got)` / `backend_write(h, buf, size, off, &wrote)` | 读写 |
| `backend_flush(h)` | FUSE FLUSH 数据收尾（写路径上传完成），**保留句柄**——FLUSH 可因 dup/fork 多次调用，销毁须等 RELEASE |
| `backend_release(h)` | 关闭（句柄销毁唯一入口；写路径未上传则补传） |
| `backend_unlink/mkdir/rmdir/rename/truncate(...)` | 删除/建目录/重命名/截断 |

**句柄编码（fh，框架↔模块透传）**：模块 `backend_open/create` 返回的句柄
`h`（模块分配的小整数）由框架编码进 FUSE `fi->fh` 高位，供 read/write/
release/fsync/flush 无锁快速分派（免每 IO 解析路径、线性扫描模块）：

- `bit40`：后端句柄标志（`NSP_FH_BACKEND_FLAG`，与本地 fd 区分）
- `bit41-47`：模块槽位（`MAX_MODULES=16`，7 位足够）
- `bit0-39`：后端句柄 ID（模块分配，经 `NSP_FH_HANDLE_MASK` 还原）

`module_backend_acquire_slot(slot)` 原子槽位快照取模块 ops 指针，用完
`module_backend_release_slot` 归还——热路径无锁竞争。**模块侧须保证**
句柄 ID 在 bit0-39 范围内（Android tagged-pointer 对 top byte 会 SIGABRT，
故高位一律保留给框架标志/槽位）。

无后端模块时框架走本地文件系统直通，`module_backend_active()` 快速路径
保证零额外开销（不产生函数指针调用）。

### 3.5 生命周期与导出

模块必须导出静态符号 `nsp_module_info`（`NspModuleInfo` 结构）：

```c
const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,          /* 魔数校验 */
    .abi_version = NSP_MODULE_ABI_VERSION, /* 必须匹配，否则拒绝加载 */
    .type = NSP_MODULE_TYPE_RULES,
    .caps = NSP_CAP_REDIRECT | NSP_CAP_SANDBOX | NSP_CAP_HIDE |
            NSP_CAP_ALLOW | NSP_CAP_RO | NSP_CAP_READDIR_EXTRA | NSP_CAP_VIRTUAL_DIR,
    .name = "basic_rules",
    .version = "1.0.0",
    .init = br_module_init,
    .exit = br_module_exit,
    .ops = &g_br_ops,
};
```

> **独立编译要求**：模块编译须定义 `-DNSP_MODULE_BUILD`（激活 `nsp_module.h`
> 中的模块公共运行时 ABI 段：LOG 宏 / CONFIG_DIR / 框架导出符号声明）；
> 源码只依赖 `nsp_module.h` + 标准库，不 include 框架内部头、不编译框架
> 源码（日志/路径符号经主程序 export-dynamic 导出表解析）。完整开发指南
> 见 `docs/module-dev.md`。

## 4. 加载流程

1. fuse_daemon 启动后调用 `module_system_init(rules_path, modules_dir, flags)`：
   mkdir 模块目录 → 全量扫描（`module_scan_diff`）→ 启动 inotify 监控线程。
2. 对每个 `<name>/<name>.so`：`dlopen(RTLD_NOW | RTLD_LOCAL)` → `dlsym`
   (`nsp_module_info`) → 校验魔数 / ABI 版本 / 名字一致 → 调 `init(api)` →
   登记注册表（能力位 → 模块链）。
3. 分派器（`module_dispatch_resolve`）：FUSE 回调经 `VFS_SETUP_CORE` 宏调用，
   遍历注册了规则能力的模块聚合决策；**无规则模块时快速路径零函数指针调用**
   （`g_active_rules_count == 0` 直接回退直通）。

## 5. 热插拔机制

- fuse_daemon 内 inotify 线程监听模块目录：新目录/`.so` → 加载注册；
  删除 → exit + dlclose + 注销；`.so` 覆盖（mtime 变化）→ 卸载后重载。
- **inotify watch 不递归模块子目录**，`.so` 增删事件（子目录内）收不到，
  因此 monitor 线程 poll 超时（每 5s）做周期兜底全量扫描。
- 模块变更后经 IPC socket 上报 `MODULE_CHANGED <name>` 给 injector
  （启动初始扫描不上报，`g_boot_scan_done` 区分），injector 收到后
  全量重挂追踪应用（`audit_tracked_apps`）——规则能力变化影响所有应用。
- IPC 查询：`LIST_MODULES` 返回当前模块目录中的模块列表。

## 6. basic_rules 模块（基础规则引擎）

`src/modules/basic_rules/`：从原 vfs_core 决策逻辑适配，匹配语义逐行等价。

| 文件 | 说明 |
|------|------|
| `basic_rules.c` | 模块入口：导出 `nsp_module_info`，实现 resolve/readdir_extra/reload/get_pkg |
| `br_rules.c` | 决策引擎：uid 缓存 / uid.map / Trie + 线性通道 / sandbox / 虚拟目录 / inotify 规则热重载 |
| `br_rules.h` | 模块内部接口（自定义 TrieMatch 类型，不依赖 fuse3 头） |

关键语义（与 AGENTS.md"规则匹配语义等价"一致）：

- **hidden / ro**：app + global **并集**（任一命中即生效）
- **redirect / sandbox**：app 优先，global 兜底；sandbox 仅在无 redir 命中时生效
- **ALLOW**：parse 阶段转 `?` 前缀内部标记，运行时解析为"相对当前用户存储"
- **一次 resolve 多路复用**：TrieMatch 一次查询同时取 hidden/ro/redir
- 模块内 `br_resolve` 读规则前持 `config_lock_read()`，防止规则热重载线程并发写

## 7. 编写自定义规则模块

1. 新建 `src/modules/<name>/`，实现 `nsp_module_info` 与 `ops`（resolve 必选）。
2. 在 `meson.build` 添加 `shared_library('<name>', ...)`（`name_prefix: ''`
   生成 `<name>.so`，`b_lundef` 项目级已关，允许引用主程序导出符号）。
3. 放入 `<MODULES_DIR>/<name>/<name>.so` 即热加载；`LIST_MODULES` 可查询。
4. 规则类型为枚举位图；如需自定义规则类型，扩展 `nsp_module.h` 能力位
   （32 位预留）并同步 ABI 文档。

> 后端模块（FTP 等，`src/modules/ftp/`）：type = BACKEND，caps =
> `MOUNT_POINT`|`VAR`|`BACKEND_IO`，ops 实现 `backend_*` + `get_vars`。
> 模块**不实现 FUSE、不挂载任何文件系统**——只提供 `backend_*` 操作方法。
> FTP 映射由 injector.conf 的 `FTP <虚拟前缀> <段名>` 规则决定（如
> `FTP /云盘 云盘`）：规则所在段决定作用域（`[GLOBAL]`=全局，`[应用包名]`=
> 仅该应用，与 REDIRECT 一致）。框架 vfs 回调经规则模块 resolve 命中
> FTP 规则（`rr.is_ftp`）后调用模块方法（FTP 列目录/读/写/删/建/重命名等，
> 写路径为本地临时文件缓存 + release 时 STOR 全量上传）。变量
> `FTP_<段名>=/<段名>` 经 `get_vars` 注册（兼容旧规则引用）。

## 8. 构建与测试

```bash
# GNU（本机测试）
meson setup build_gnu -Dtarget_os=gnu && ninja -C build_gnu
# Android 交叉（basic_rules.so 不依赖 libfuse3，交叉编译已验证）
meson setup build --cross-file android-aarch64.ini -Dfuse3_root=<静态库根>

# 测试（测试脚本自动预置 basic_rules.so / ftp_module.so 到临时模块目录并传 --modules-dir）
python3 tests/test_rules.py       # 规则边界 36 用例
python3 tests/test_functional.py  # 功能 + SQLite + 并发 34 用例
python3 tests/test_modules.py     # 热插拔 11 用例
python3 tests/test_ftp.py         # FTP 后端端到端 13 用例（vsftpd 匿名服务 + $FTP_云盘 变量 + REDIRECT）

# 模块独立编译（第三方模块：只依赖 include/nsp_module.h，须定义 NSP_MODULE_BUILD）
cc -shared -fPIC -std=c23 -DNSP_MODULE_BUILD -Iinclude my_module.c -o my_module.so
```

产物：`fuse_daemon`（框架，含后端分派）、`basic_rules.so`（规则模块，
安装到 `bin/modules/basic_rules/`）、`ftp_module.so`（FTP 后端模块，无
FUSE 依赖，安装到 `bin/modules/ftp_module/`）、`injector`/`log_monitor`/
`log_ctl` 不变。

## 8.1 模块错误日志与熔断（框架层防护）

框架对全部模块调用（`resolve`/`probe`/`readdir_extra`/`get_pkg`/
`backend_*`/`init`/`exit`）做了三层防护，**模块错误不会带崩 fuse_daemon**
（同进程隔离，覆盖栈上野指针/return 地址踩踏/除零/非法指令/abort；
堆损坏的延迟爆发是残留边界——见下）。

### 三层防护

1. **调用围栏（`src/module/fault_fence.c`）**：每 FUSE worker 线程一套
   `sigsetjmp` 围栏 + 全局 `sigaltstack`（256KB）。模块调用窗口内崩溃
   （SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT）→ 信号处理器归因到肇事线程
   正在调用的模块槽位 → `siglongjmp` 恢复框架执行——**daemon 存活，
   该次请求按 `-EIO` 失败**；归因失败（如堆损坏延迟到框架代码爆发）
   走原 `crash_dump` 链路（dump + 死亡 + injector 重启兜底）。
2. **输出校验（`src/module/module_guard.c`）**：`NspResolveResult`
   前后 canary 哨兵（防整块越界写）+ 全部字符串字段 NUL 终止检查 +
   `user_id` 值域检查 + readdir 条目名校验。
3. **熔断器**：每模块滑动窗口（默认 **10 秒内 5 次错误**，env 可覆盖
   `NSP_GUARD_WINDOW_SEC` / `NSP_GUARD_ERR_MAX`）→ 触发即
   `module_fault_poison`：**槽位快照置空 = 该模块全部规则立即失效**
   （后续请求走框架直通回退）+ `.so` 卸载 + **ban 落盘**。
   崩溃（围栏恢复）单次即置毒（模块内存状态不可信，无需计数）。

### ban 机制（防崩溃-重载震荡）

- ban 记录：`<MODULES_DIR>/.banned`，每行 `模块名|SHA256|原因|时间戳`；
- 热插拔扫描线程见 .so 哈希与 ban 记录一致 → **跳过加载**；
- 哈希变化（发布新 .so 版本）→ 记录失效，允许重新加载（**版本更新自愈**）；
- daemon 重启后 ban 依然有效（文件持久化），直到换版本或手动删除文件。

### MOD_ERR 日志（`log_ctl` 可查）

所有模块错误统一结构化前缀，`log_ctl search-sys --level 2 MOD_ERR <模块名>`
按模块过滤（单条错误 WARN 级，**熔断/崩溃/置毒为 ERR 级**）：

```
[MOD_ERR] module=<模块名> op=<resolve|probe|readdir_extra|get_pkg|backend_*> \
          rc=<模块返回码> path=<路径> detail=<原因>
```

detail 取值示例：`sub_path 未终止` / `输出 canary 破坏(越界写)` /
`user_id 值域非法` / `模块返回异常` / `熔断触发(...)` /
`模块崩溃(SIGSEGV/...)被调用围栏恢复,立即卸载:规则全部失效`。

**日志限流**：窗口内前 5 条明细全打，之后每 100 条打 1 条汇总
（`已抑制 N 条同类错误`）——坏模块错误风暴不会淹没日志环。

**高危事件落盘**：熔断触发/崩溃恢复两类低频高危事件无条件追加到
`<LOG_DIR>/module_errors.log`（log_monitor/UDS 链路中断时仍可事后查）。

**崩溃转储归因行**：`error.log`/stderr 的 backtrace 前附带
`Crash attribution: module=<名> slot=<N> op=<op> (in module call window)`。

### 健康快照

`module_health_snapshot()`（`NspModuleHealth`）输出每模块：
`err_count`（当前窗口）/`err_total`（本周期累计）/`banned`/
`ban_reason`/`last_err_time`——前端模块列表可展示健康度与 ban 原因。

### 模块开发者须知（契约）

- ops 回调返回值：`0` 成功 / **负值 errno** 失败（返回正数非 0 会被计为错误）；
- 输出字符串字段**必须 NUL 终止**，越界写会破坏 canary 触发置毒；
- 回调内**不得阻塞**（无锁/短耗时）：围栏调用窗口内框架线程不可恢复地
  持锁会破坏 longjmp 安全性（框架侧已保证分派路径不持锁）；
- 崩溃不会连累框架，但模块进程级资源（句柄/连接）需自行保证幂等——
  置毒时框架**不调用** `exit()`（崩溃模块代码不可信）。

## 9. 相关文档

- 总体设计：`docs/architecture.md`（进程协作、命名空间注入）
- 配置规范：`docs/ai-config-guide.md`（injector.conf 语法）
- 路径变量：`docs/path-variables.md`（`$package` / 用户变量展开）
- 配置广播：`docs/config-broadcast.md`（UDS 广播 JSON）
- 模块开发：`docs/module-dev.md`（ABI 兼容模块开发指南）
- 测试说明：`tests/README.md`
