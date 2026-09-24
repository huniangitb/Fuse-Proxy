# 热插拔模块架构与开发

`fuse_daemon` 只是框架——FUSE 回调骨架 + 路径清洗 + 模块调度 + 本地存储原语，**不内置任何规则语义**。规则能力（REDIRECT/SANDBOX/HIDE/ALLOW/RO）与存储后端（如 FTP）均由 dlopen 的热插拔模块提供。第三方模块**只以 `include/nsp_module.h` 为唯一入口**（该头代含 `nsp_log.h` / `nsp_constants.h` / `nsp_cfg_view.h`，见 §6.1），可在独立仓库独立编译。

## 1. 设计要点

- **框架零功能**：无规则模块时框架直通回退（`g_active_rules_count == 0` 快速路径，零函数指针调用）。
- **能力自述**：模块经 32 位能力位图声明支持哪些规则类型，框架只调用声明过的接口。
- **热插拔**：`.so` 放入模块目录即加载，删除即卸载，覆盖即重载，不中断已挂载的 FUSE。
- **后端不实现 FUSE**：BACKEND 模块只提供 `backend_*` 操作方法，FUSE 由框架统一实现。

## 2. 模块目录约定

```
<MODULES_DIR>/<模块名>/<模块名>.so      # 模块本体（dlopen 进 fuse_daemon）
<MODULES_DIR>/<模块名>/<模块名>.rules   # 可选：规则类型注册（rule_server 读取）
```

- Android：`/data/Namespace-Proxy/modules`；GNU：`/var/fuse-proxy/modules`（`--modules-dir=` 可覆盖）。
- 模块名仅含 `[a-z0-9_-]`，**目录名 = 模块名 = `.so` 文件名 = `NspModuleInfo.name`**，不一致拒绝加载。

### 2.1 规则类型注册（`.rules`）

模块可放置 `<模块名>.rules` 向 **rule_server** 声明自己支持的规则类型，实现「前端可操作的规则随模块动态追加」。conf 段格式（推荐）：

```ini
[FTP]
format = pair
argc = 2
desc = FTP 存储映射：<虚拟前缀>|<段名>
desc.en = FTP storage mapping: <virtual prefix>|<section>
```

| 键 | 说明 |
|----|------|
| `format` | `path`（单值）/ `pair`（src\|dst）/ `switch`（ON/OFF）/ `tokens`（多 token） |
| `argc=N` / `argc=N:M` | 参数数量约束（`M` 用 `*` 表示不限上界），覆盖 format 默认值 |
| `global-only` | `true` 时仅全局作用域可用 |
| `desc` / `desc.xx` | 中文描述 / 指定语言描述（`xx` 为语言代码） |

- 旧行格式 `<TYPE> <FORMAT> [属性...]` 仍兼容，两种格式可在同一文件混用；畸形声明（如 `argc=abc`）被跳过。
- rule_server 带目录/文件 mtime 缓存，未变化时零扫描复用类型表；`.rules` 增删改即热更新，无需重启。
- `argc_min/argc_max` 用于 ADD 参数校验，`global_only` 限制作用域，`desc` 按请求 `lang` 回传（默认中文，未知语言回退 zh）并附 `desc_map` 全语言映射。
- 内置类型（HIDE/RO/REDIRECT/ALLOW/MONITOR/SANDBOX/GLOBAL_INJECT/SKIP_SYSTEM_APPS）始终存在；未注册的类型前端无法 ADD/REMOVE/ENABLE/DISABLE。无 `.rules` 的模块正常加载，仅跳过类型注册。
- **`log_ctl` 与 `rule_server` 的类型集合刻意不同**：`rule_server` 是权威控制面，读取 `.rules` 合并模块动态类型；`log_ctl` 的 `set-rule`/`remove-rule` 只认内置类型（HIDE/RO/REDIRECT/ALLOW/MONITOR/SANDBOX/GLOBAL_INJECT，不含 SKIP_SYSTEM_APPS），不扫描模块目录。两者对同一内置类型的编辑语义一致（行级实现共享，见 §6.1）。

## 3. 模块 ABI（`include/nsp_module.h`）

当前 `NSP_MODULE_ABI_VERSION = 3`、`NSP_FRAMEWORK_API_VERSION = 4`。

**V3 是决策结果的不兼容重构**：`NspResolveResult` 被声明式的 `NspPathDecision` 取代，模块只声明「这个路径该怎么表现」，errno 映射与权限策略全部收归框架单点（`fw_route` 强制 appear_missing/read_only，`vfs_apply_attr_override` 落实属性覆盖，只读判定统一走 `vfs_check_read_only`）。字段变化：

| 删除 | 新增/替换 | 理由 |
|---|---|---|
| `hidden` | `appear_missing` | 语义不变，但强制统一为 ENOENT（见下） |
| `ro` | `read_only` | 语义不变，强制统一为 EROFS |
| `is_virtual_ancestor` + `is_redirect_target` | `virtual_kind`（`NSP_VK_NONE/ANCESTOR/TARGET`） | 两个并列 bool 合并为单枚举，合并策略明确（ANCESTOR 优先） |
| `is_redir` | `is_redirect` | 仅改名 |
| `user_id` / `sub_path` | —（框架自算） | 框架的 `fw_parse_path` 与模块侧剥离逻辑逐行等价，无需跨 ABI 传递；结果结构由 8336 降到约 4.2KB |
| — | `attr_override` + `mode`/`uid`/`gid` | 模块可覆盖权限位与属主（见 §3.3） |

`pkg` 保留在结果内：它随 `resolve` 一次返回；若移到框架侧需每请求额外一次 `get_pkg` 模块调用（围栏+校验开销），得不偿失。

**V3 的行为变更（有意）**：`appear_missing` 在**所有**回调统一返回 `ENOENT`。V2 时代读类回调是 `ENOENT`、写类回调是 `EACCES`，同一声明产生两种结果；统一后与「存在变不存在」的语义一致。若前端曾依赖写类路径的 `EACCES`，需按 `ENOENT` 调整。

**V4 是 `NspFrameworkApi` 的尾部兼容新增**（`subscribe_rules` / `set_config_listener`），故 V4 本身不要求重编译。`NspFrameworkApi` 只保留框架真正消费的字段（`api_version` / `get_rules_path` / `get_flags`）；日志由 `nsp_log.h` 的 `log_internal(LogLevel)` 统一提供。V2 删除了中间字段（`log` / `get_real_root`、`NspResolveResult` 的 `allow`/`has_redir`/`redir_target`/`has_sandbox`/`sandbox_target`/`is_other_app_pkg`/`ftp_backend`、`ops` 的 `get_vars`/`reload` 等）——**V1 与 V2 模块都必须按 V3 头重编译**，否则加载被拒（见下方加载校验顺序、§6.5）。

加载校验顺序（`module_prepare`）：`dlopen` → `dlsym(nsp_module_info)` → 魔数/ABI 版本 → 名字一致 → 自哈希 → `init`。**ABI 校验发生在 `dlopen` 之后**：`RTLD_NOW` 会立即解析模块的全部符号，V1 模块引用已删除的导出符号时可能在 ABI 检查之前就解析失败；模块的构造器也已在 `dlopen` 期间运行。因此"拒绝旧 ABI"是加载失败，不是加载前拦截。

### 3.1 类型与能力位

| 类型 | 说明 |
|------|------|
| `NSP_MODULE_TYPE_RULES` | 规则模块：参与路径决策 |
| `NSP_MODULE_TYPE_BACKEND` | 存储后端模块：提供后端操作方法，**不实现 FUSE** |

| 位 | 能力 | 归属 |
|----|------|------|
| 0-4 | `NSP_CAP_REDIRECT` / `SANDBOX` / `HIDE` / `ALLOW` / `RO` | 规则 |
| 5 | `NSP_CAP_READDIR_EXTRA`（readdir 虚拟目录补充） | 规则 |
| 12 | `NSP_CAP_BACKEND_IO` 路径命中时由框架调用模块方法完成文件操作 | 后端 |

位图按整组判断：0-4 位任一置位即视为规则模块（参与 `resolve`/`probe` 分派）。V2 删除了 `VIRTUAL_DIR`（位 6）、`MOUNT_POINT`（位 10）、`VAR`（位 11）——虚拟目录性质由 `NspPathDecision` 的 `virtual_kind` 表达，无需单独能力位；后端虚拟前缀不再由模块注册变量，改由 `FTP <虚拟前缀> <段名>` 规则 + `is_ftp` 表达。

### 3.2 框架服务表 `NspFrameworkApi`（框架 → 模块）

`init` 时注入，模块**仅经它取用框架参数**（版本化，兼容新增字段追加尾部）：

```c
typedef struct NspFrameworkApi {
    uint32_t api_version;                       /* NSP_FRAMEWORK_API_VERSION */
    const char* (*get_rules_path)(void);        /* 规则配置路径（--rules） */
    uint32_t (*get_flags)(void);                /* NSP_FLAG_DISABLE_SANDBOX 等 */
    /* ---- API V4 追加（尾部新增，旧模块按 api_version 决定是否使用）---- */
    void (*subscribe_rules)(const char* const* types, int count);   /* 声明申请的规则类型 */
    void (*set_config_listener)(void (*cb)(const NspModuleConfig*)); /* 配置下发回调 */
} NspFrameworkApi;
```

- `api_version` 是模块 `init` 的第一道自检（`basic_rules` 在 `api->api_version < NSP_FRAMEWORK_API_VERSION` 时拒绝初始化）。
- 日志**不再经服务表**：`nsp_module.h` 代含 `nsp_log.h`，模块直接调用 `log_internal(LogLevel, ...)` / `LOG`/`LOG_WRN`/`LOG_ERR`/`LOG_DBG` 宏，与框架同一套 `LogLevel`（0=DEBUG 1=INFO 2=WARN 3=ERROR）。真实存储根不再经服务表暴露——路径合成用导出表里的 `common_default_real_path` / `common_sandbox_path`（见 §6.1）。

### 3.3 接口表 `NspModuleOps`（模块 → 框架）

所有字段可选，未实现置 NULL。返回 `0` 成功 / **负值 errno** 失败。

规则模块：

```c
int (*resolve)(const NspQueryCtx* q, NspPathDecision* out);  /* 路径决策，一次调用返回全部声明式决策 */
int (*probe)(const NspQueryCtx* q, NspProbeResult* out);      /* readdir 逐条目轻量过滤 */
int (*readdir_extra)(const NspQueryCtx*, const char* sub_path, int user_id,
                     const char* pkg, bool is_root, NspDirEntry* out, int max);
int (*get_pkg)(uid_t uid, pid_t tid, char* out, size_t size); /* uid→包名（框架日志用） */
```

`resolve` 输入 FUSE 原始路径 + uid/pid/gid，输出**声明式决策**：`valid` / `appear_missing` / `read_only` / `attr_override`+`mode`/`uid`/`gid` / `virtual_kind` / `pkg` / `real_path` / `is_redirect` / `is_ftp` / `monitor_on`——**一次调用返回全部决策**，保住「一次查询多路复用」的性能语义。ALLOW 与 SANDBOX 不单独回传：模块已把它们落实进 `real_path`。`probe` 只判 `valid`/`appear_missing`/`virtual_kind`/`is_other_app_pkg`，不构建真实路径、不触发 sandbox 目录创建。

**强制由框架单点完成**（`src/daemon/fuse_daemon.c` 的 `fw_route`），模块不参与 errno 决策：

| 声明 | 框架行为 |
|---|---|
| `appear_missing` | 所有回调统一 `ENOENT`（含写类；V2 写类为 `EACCES`） |
| `read_only` | 变更操作统一 `EROFS`；root 豁免由框架持有。`open`/`access` 是否算"写"由 `flags`/`mask` 判定（`O_RDONLY` 打开只读路径必须放行） |
| `attr_override` | 位图（`NSP_OV_MODE`/`NSP_OV_UID`/`NSP_OV_GID`），默认 0 = 不改——故 `memset(out, 0, sizeof *out)` 这类零初始化是安全的。在框架既有权限策略**之后**应用，模块的显式声明优先于框架默认（伪造模式属主=访问者、skel 目录 0755 等）。`mode` 只取 `07777`，`S_IFMT` 类型位一律忽略 |

> **属性覆盖为何用位图而非"特殊值哨兵"**：若用 `mode == UNSET`/`uid == -1` 表示"不改"，模块惯用的 `memset` 零初始化会静默变成"权限清 0 + 属主 root"。位图让"零初始化 = 什么都不改"成立。

> **初始化不变量**：`resolve` 输出必须**逐字段**重置（框架经 `nsp_decision_init` 统一初始化，`NspDecisionGuard` 与之共用同一实现），不能只置 `valid=false`。FUSE 回调在模块未命中时仍会读 `read_only`/`is_ftp`/`virtual_kind` 等标志；历史上"未命中只置 valid + 固定栈填充恰好稳定"曾把不存在的路径合成为目录，逐字段初始化是回归防线。

后端模块（`NSP_CAP_BACKEND_IO`）：

```c
int (*backend_match)(const char* path);        /* 1=管理该路径（前缀匹配） 0=否 */
int (*backend_getattr)(const char* path, struct stat* st);
int (*backend_readdir)(const char* path, NspDirEntry* entries, int max);
int (*backend_open)(const char* path, int flags, uint64_t* h);
int (*backend_create)(const char* path, mode_t mode, uint64_t* h);
int (*backend_read)(uint64_t h, char* buf, size_t size, off_t off, size_t* got);
int (*backend_write)(uint64_t h, const char* buf, size_t size, off_t off, size_t* wrote);
int (*backend_flush)(uint64_t h);              /* 收尾数据但保留句柄 */
int (*backend_release)(uint64_t h);            /* 句柄销毁唯一入口 */
int (*backend_unlink/mkdir/rmdir/rename/truncate)(...);
```

`backend_flush` 与 `backend_release` 的分工是易错点：FLUSH 可因 dup/fork **多次调用**，只能收尾数据（如上传完成），销毁必须等 RELEASE。

### 3.4 后端分派与句柄编码

框架 vfs 回调解析出 real_path 后，若规则模块 resolve 命中 FTP 规则（`rr.is_ftp`）且 `backend_match(path)==1`，则改调模块方法；否则本地文件系统直通（`module_backend_active()` 保证零开销）。路径参数为框架解析后的真实路径（如 `/mnt/nsp_ftp/云盘/xxx`），模块自行剥离前缀。

模块返回的句柄 `h` 被框架编码进 FUSE `fi->fh`，供 read/write/release 无锁快速分派：

| 位段 | 含义 |
|------|------|
| `bit40` | 后端句柄标志 `NSP_FH_BACKEND_FLAG`（与本地 fd 区分） |
| `bit41-47` | 模块槽位（`MAX_MODULES=16`） |
| `bit0-39` | 后端句柄 ID（`NSP_FH_HANDLE_MASK` 还原） |

**模块侧须保证句柄 ID 落在 bit0-39 内**——Android tagged-pointer 对 top byte 会 SIGABRT，高位一律保留给框架。

## 4. 加载与热插拔

1. `module_system_init(rules_path, modules_dir, flags)`：mkdir 模块目录 → 全量扫描 → 启动 inotify 监控线程。
2. 每个 `<name>/<name>.so`：0.5s 文件稳定性校验（防加载半写入的 .so）→ `dlopen(RTLD_NOW|RTLD_LOCAL)` → `dlsym(nsp_module_info)` → 校验魔数/ABI 版本/名字一致/自哈希 → `init(api)`（经围栏）→ 按能力位登记注册表。顺序见 §3：ABI 校验在 `dlopen` 之后、`init`/`ops` 之前。
3. inotify 监听模块目录：新增加载、删除卸载、`.so` 覆盖（mtime 变化）重载。**watch 不递归子目录**，故 monitor 线程每 5s poll 超时做兜底全量扫描。
4. 模块变更**不再经 IPC 上报 injector**：`fuse_daemon` 的规则/后端分派走槽位原子快照，热插拔即时生效，无需 injector 重挂。`LIST_MODULES` 仍可查询当前模块列表（由 injector 扫描模块目录应答，与 fuse_daemon 的加载约定一致）。

## 5. 故障隔离（框架层防护）

框架对全部模块调用（`resolve`/`probe`/`readdir_extra`/`get_pkg`/`backend_*`/`init`/`exit`）做三层防护，**模块错误不会带崩 fuse_daemon**：

1. **调用围栏**（`src/module/fault_fence.c`）：每 worker 线程一套 TLS `sigsetjmp` 围栏；`sigaltstack` 是 **per-thread** 的——`fault_fence_init` 设置的全局 altstack 只覆盖主线程，每个首次调用围栏的线程还会为自己设置独立 TLS altstack（worker 不继承主线程的 altstack）。调用窗口内崩溃（SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT）→ 归因到肇事模块槽位 → `siglongjmp` 恢复，daemon 存活、该请求按 `-EIO` 失败。归因失败（如堆损坏延迟到框架代码爆发）走原 `crash_dump` 链路。
2. **输出校验**（`src/module/module_guard.c`）：`NspPathDecision` 前后 canary 哨兵 + 字符串字段 NUL 终止检查 + `virtual_kind` 值域与 `attr_override` 未知位检查 + readdir 条目名校验。
3. **熔断器**：每模块滑动窗口（默认 10 秒 5 次错误，env `NSP_GUARD_WINDOW_SEC` / `NSP_GUARD_ERR_MAX` 可覆盖）触发即 `module_fault_poison`——槽位置空（该模块规则立即全部失效，走直通回退）+ 卸载 + ban 落盘。崩溃单次即置毒。

**ban 机制**：记录写 `<MODULES_DIR>/.banned`（每行 `模块名|SHA256|原因|时间戳`）。扫描线程见哈希与 ban 记录一致即跳过加载；哈希变化（发布新版本）记录失效，**版本更新自愈**；daemon 重启后 ban 仍有效。

**排障入口**：`log_ctl search-sys --level 2 MOD_ERR <模块名>` 按模块过滤结构化错误行（`module=/op=/rc=/path=/detail=`）。窗口内前 5 条明细全打、之后每 100 条打 1 条汇总，坏模块不会淹没日志环；熔断与崩溃恢复两类高危事件无条件追加到 `<LOG_DIR>/module_errors.log`；崩溃转储附 `Crash attribution: module=<名> slot=<N> op=<op>` 归因行。`module_health_snapshot()` 输出每模块 `err_count`/`err_total`/`banned`/`ban_reason`/`last_err_time` 供前端展示。

## 6. 开发第三方模块

### 6.1 依赖与前置

- **唯一接口头**：`include/nsp_module.h`，源码只依赖本头 + 标准库。该头**代含** `nsp_log.h`（`LogLevel` 与 `log_internal`）、`nsp_constants.h`（`NSP_CONFIG_DIR`/`NSP_STORAGE_BASE`/`NSP_LOG_DIR` 等共享常量）与 `nsp_cfg_view.h`（配置下发视图 `NspCfgRec`/`NspModuleConfig`）；分发 SDK 时必须把这三个代含头一并给出，否则模块无法编译。
- **许可证**：框架以 GPL-3.0-or-later 发布，但**对模块 ABI 授予链接例外**——仅通过本头文件公开 ABI 结合的独立模块，可按任意条款发布（含闭源），不因此受 GPL 约束。前提是不编入框架源码、不依赖本头以外的内部头、不引用未声明的内部符号。**代含的 `nsp_log.h` / `nsp_constants.h` / `nsp_cfg_view.h` 同属公开 ABI 头**，链接例外同样覆盖。完整条款见 `LICENSE.module-exception`。
- **编译宏**：必须定义 `-DNSP_MODULE_BUILD`，激活头内「模块公共运行时 ABI」段（`LogLevel`/日志宏、平台常量、框架导出符号声明）。框架自身 TU 不定义该宏，声明与宏以 `common.h` 为准。
- **运行时符号**：日志/路径等框架符号经 fuse_daemon 的 `-Wl,--export-dynamic` 导出表在 dlopen 时解析，模块无需链接框架，**不得把 `src/core/common.c` 等框架源编入自身**。模块也**不链接 `nsp_comm`**——统一通讯线程是框架各进程的内部设施，不属于模块 ABI。
- **公开 ABI 只有 `nsp_module.h` 及其代含头**，不包含任何 `src/` 下的项目工具。`nsp_util`（`nsp_mkdir_p`、`nsp_set_thread_name`、App-rules 路径合成等）**不是 SDK 公共 ABI**：树内以 GPL 发布的模块可以链接它，但**第三方模块若要保留链接例外，就不能因此 include `nsp_util.h` 或编入任何项目源码**——例外只覆盖 `nsp_module.h` 声明的接口（含代含的 `nsp_log.h`/`nsp_constants.h`/`nsp_cfg_view.h`），越界即落入 GPL（见 `LICENSE.module-exception` 的「独立模块」定义）。通用 INI 段式存储（`nsp_ini_open/...`）与规则文件行级读写（`nsp_rule_file.h`）同样**不在模块 ABI 内**：`nsp_ini_store` 是 rule_server 的私有静态库（log_ctl 不使用），`nsp_rule_file` 是 rule_server/log_ctl 的控制面共享实现，两者都不经 `nsp_module.h` 暴露。

### 6.1.1 配置读取归属（V4）

**读取完全由框架完成**：框架读 `injector.conf` 与 `App-rules*`，完成行级词法
（去注释/首尾空白）与段头识别（`[段]` / `ON|OFF` / `:uid`），产出扁平记录视图
（`NspCfgRec`：段头、规则行、App-rules 文件归属）。**模块不读文件、不跑 inotify。**

模块侧流程：

1. `init` 内调 `api->subscribe_rules(types, n)` 声明申请的规则类型（如
   `{"HIDE","REDIRECT","VAR"}`）。框架**只下发这些类型的记录**，其他模块声明的
   类型不会出现在本模块视图里——这是模块间规则隔离；订阅为空表示申请全部（不推荐）。
2. `init` 内调 `api->set_config_listener(cb)` 注册回调；框架在 `init` 返回后
   **立即回调一次**，之后每次热重载再回调（带新 `generation`）。
3. 回调内用视图重建自己的索引。视图**只读且仅在回调期间有效**（字符串归框架所有），
   不得留存指针；框架在推送完成后才释放旧视图。

`NspModuleConfig.generation` 在每次重载递增，模块可据此跳过无变化的重建。
段头与 App-rules 归属记录**恒下发**（规则要靠它们解释作用域），过滤只作用于规则行。

> 注意：`uid.map`（uid→包名）与 `sys_pkgs.cache`（系统应用表）目前仍由模块自行读取
> （它们不是规则配置而是数据表），后续版本可能一并收归框架下发。

### 6.2 最小骨架

```c
#include "nsp_module.h"   /* NSP_MODULE_BUILD 已定义 */

static int my_init(const NspFrameworkApi* api) {
    g_api = api;                    /* 保存框架参数表（get_rules_path / get_flags） */
    return 0;                       /* 非 0 拒绝加载 */
}
static void my_exit(void) { /* 清理（可为 NULL） */ }

const NspModuleInfo nsp_module_info = {
    .magic       = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,    /* 必须匹配，否则拒绝加载 */
    .type        = NSP_MODULE_TYPE_RULES,     /* 或 BACKEND */
    .caps        = NSP_CAP_REDIRECT,          /* 能力位图，须与 ops 一致 */
    .name        = "my_module",               /* 须与 .so 文件名/目录名一致 */
    .version     = "1.0.0",
    .init        = my_init,
    .exit        = my_exit,
    .ops         = &g_my_ops,
};
```

### 6.3 编译与安装

```sh
# GNU（本机测试）
cc -shared -fPIC -std=c23 -DNSP_MODULE_BUILD -I<项目>/include my_module.c -o my_module.so

# Android（NDK 交叉）
aarch64-linux-android35-clang -shared -fPIC -std=c23 \
   -DNSP_MODULE_BUILD -I<项目>/include my_module.c -o my_module.so
```

放入 `<MODULES_DIR>/my_module/my_module.so` 即热加载。项目内模块走 meson：`shared_library('<name>', ..., name_prefix: '', c_args: ['-DNSP_MODULE_BUILD'])`（`b_lundef` 项目级已关，允许引用主程序导出符号）；树内模块可另加 `nsp_util_dep`（共享工具，非公开 ABI，见 §6.1），第三方模块不要这样做。

### 6.4 契约（违反即被熔断）

- 返回值：`0` 成功 / 负值 errno 失败（**返回正数非 0 会被计为错误**）。
- 输出字符串字段**必须 NUL 终止**，越界写会破坏 canary 触发置毒。
- 回调内**不得阻塞**：围栏窗口内不可恢复地持锁会破坏 longjmp 安全性（框架侧已保证分派路径不持锁）。
- 置毒时框架**仍会调用 `exit()`**（经围栏，崩溃会被 longjmp 收敛）——模块可能持有自己的 pthread，`exit` 是停掉它们的唯一途径，不调就 `dlclose` 会让残留线程踩空带崩 daemon。仅当 `exit` 自身崩溃（无法确认线程已停）才保留 `.so` 映射不 `dlclose`。因此模块 `exit` 必须幂等、且负责 join 自己创建的线程。

### 6.5 ABI 演进

| 场景 | 机制 |
|------|------|
| 不兼容变更（改表结构/删字段） | `NSP_MODULE_ABI_VERSION` 递增 → 旧模块被校验拒绝，须重编译 |
| 兼容新增框架能力 | `NspFrameworkApi` 尾部追加字段 + `NSP_FRAMEWORK_API_VERSION` 递增 |
| 新能力 / 新模块类型 | `caps` 位图扩展（32 位预留），框架按位判断 |
| 模块自身版本 | `NspModuleInfo.version` 字符串（不影响加载兼容性） |

ABI 从 1 到 2 的变更属于第一类：`NspFrameworkApi` 删除了中间的 `log`/`get_real_root` 字段，`NspModuleOps` 也删除了字段——**不是**仅尾部兼容扩展，故必须递增 ABI 版本并要求 V1 模块重编译（`NspResolveResult` 由 V1 的 16596 字节降到 V2 的 8336 字节）；V3 把 `NspResolveResult` 换成声明式的 `NspPathDecision`（结构降到约 4.2KB）并要求 V1/V2 重编译。校验拒绝发生在 `dlopen` 之后（见 §3），旧模块的构造器与 `RTLD_NOW` 符号解析会先于 ABI 检查执行。

## 7. 参考实现

| 模块 | 源码 | 说明 |
|------|------|------|
| `basic_rules.so` | `src/modules/basic_rules/` | 规则引擎（原 `vfs_core` 迁移，匹配语义逐行等价）：`basic_rules.c` 模块入口（订阅规则类型 + 注册配置监听器）、`br_rules.c` 决策引擎（uid 缓存 / uid.map / Trie + 线性通道 / sandbox / 虚拟目录）；配置热重载由**框架**驱动（见 §6.1.1） |
| `ftp_module.so` | `src/modules/ftp/` | FTP 后端（libcurl，**不依赖 libfuse3**）：含 `backend_flush` 两阶段收尾与弱网重试示例；写路径为本地临时文件缓存 + release 时 STOR 全量上传 |

FTP 映射由 `injector.conf` 的 `FTP <虚拟前缀> <段名>` 规则决定（如 `FTP /云盘 云盘`），作用域按规则所在段——`[GLOBAL]` 全局、`[应用包名]` 仅该应用，与 REDIRECT 一致。命中后 `resolve` 回传 `is_ftp`，框架据此把该路径分派给 FTP 后端模块（不再有 `FTP_<段名>` 变量注册机制）。

basic_rules 的关键语义（修改时必须保持）：appear_missing/read_only 取 app + global **并集**；redirect/sandbox 取 app 优先、global 兜底，sandbox 仅在无 redir 命中时生效；`br_resolve`/`br_probe` 走 `config_read_begin`/`config_read_end` 无锁快照（不再持 `config_lock_read()` rwlock，见 `architecture.md` §6）。

## 8. 相关文档

- 进程架构与规则引擎：`architecture.md`
- 配置语法：`config.md`
- 构建与测试：`README.md`、`AGENTS.md`
