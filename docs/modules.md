# 热插拔模块架构与开发

`fuse_daemon` 只是框架——FUSE 回调骨架 + 路径清洗 + 模块调度 + 本地存储原语，**不内置任何规则语义**。规则能力（REDIRECT/SANDBOX/HIDE/ALLOW/RO）与存储后端（如 FTP）均由 dlopen 的热插拔模块提供。第三方模块**仅依赖 `include/nsp_module.h`**，可在独立仓库独立编译。

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
- 内置类型（HIDE/RO/REDIRECT/ALLOW/MONITOR/SANDBOX/GLOBAL_INJECT）始终存在；未注册的类型前端无法 ADD/REMOVE/ENABLE/DISABLE。无 `.rules` 的模块正常加载，仅跳过类型注册。

## 3. 模块 ABI（`include/nsp_module.h`）

当前 `NSP_MODULE_ABI_VERSION = 1`、`NSP_FRAMEWORK_API_VERSION = 2`。

### 3.1 类型与能力位

| 类型 | 说明 |
|------|------|
| `NSP_MODULE_TYPE_RULES` | 规则模块：参与路径决策 |
| `NSP_MODULE_TYPE_BACKEND` | 存储后端模块：提供后端操作方法，**不实现 FUSE** |

| 位 | 能力 | 归属 |
|----|------|------|
| 0-4 | `NSP_CAP_REDIRECT` / `SANDBOX` / `HIDE` / `ALLOW` / `RO` | 规则 |
| 5-6 | `NSP_CAP_READDIR_EXTRA`（readdir 虚拟目录补充）/ `VIRTUAL_DIR`（虚拟目录合成） | 规则 |
| 10 | `NSP_CAP_MOUNT_POINT` 提供虚拟前缀路径 | 后端 |
| 11 | `NSP_CAP_VAR` 向框架注册变量（如 `FTP_云盘=/mnt/nsp_ftp/云盘`） | 后端 |
| 12 | `NSP_CAP_BACKEND_IO` 路径命中时由框架调用模块方法完成文件操作 | 后端 |

### 3.2 框架服务表 `NspFrameworkApi`（框架 → 模块）

`init` 时注入，模块**仅经它使用框架设施**（版本化，新增字段追加尾部）：

```c
typedef struct NspFrameworkApi {
    uint32_t api_version;                       /* NSP_FRAMEWORK_API_VERSION */
    void (*log)(int level, const char* fmt, ...);  /* 0=DEBUG 1=INFO 2=WARN 3=ERROR */
    const char* (*get_real_root)(void);         /* 真实存储根（--root） */
    const char* (*get_rules_path)(void);        /* 规则配置路径（--rules） */
    uint32_t (*get_flags)(void);                /* NSP_FLAG_DISABLE_SANDBOX 等 */
} NspFrameworkApi;
```

### 3.3 接口表 `NspModuleOps`（模块 → 框架）

所有字段可选，未实现置 NULL。返回 `0` 成功 / **负值 errno** 失败。

规则模块：

```c
int (*resolve)(const NspQueryCtx* q, NspResolveResult* out);  /* 路径决策，一次调用返回全部结果 */
int (*probe)(const NspQueryCtx* q, NspProbeResult* out);      /* readdir 逐条目轻量过滤 */
int (*readdir_extra)(const NspQueryCtx*, const char* sub_path, int user_id,
                     const char* pkg, bool is_root, NspDirEntry* out, int max);
int (*reload)(void);                                          /* 配置热重载通知 */
int (*get_pkg)(uid_t uid, pid_t tid, char* out, size_t size); /* uid→包名（框架日志用） */
```

`resolve` 输入 FUSE 原始路径 + uid/pid/gid，输出完整决策（hidden / ro / allow / redir / sandbox / 最终真实路径 / 虚拟目录标志 / monitor 状态）——**一次调用返回全部结果**，保住「一次查询多路复用」的性能语义。`probe` 只判 hidden/重定向目标/虚拟目录标志，不构建真实路径、不触发 sandbox 目录创建。

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
int (*get_vars)(const char*** names, const char*** values, int* count);
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
2. 每个 `<name>/<name>.so`：`dlopen(RTLD_NOW|RTLD_LOCAL)` → `dlsym(nsp_module_info)` → 校验魔数/ABI 版本/名字一致 → `init(api)` → 按能力位登记注册表。
3. inotify 监听模块目录：新增加载、删除卸载、`.so` 覆盖（mtime 变化）重载。**watch 不递归子目录**，故 monitor 线程每 5s poll 超时做兜底全量扫描。
4. 模块变更经 IPC 上报 `MODULE_CHANGED <name>` 给 injector（启动初始扫描不上报），injector 全量重挂追踪应用。`LIST_MODULES` 可查询当前模块列表。

## 5. 故障隔离（框架层防护）

框架对全部模块调用（`resolve`/`probe`/`readdir_extra`/`get_pkg`/`backend_*`/`init`/`exit`）做三层防护，**模块错误不会带崩 fuse_daemon**：

1. **调用围栏**（`src/module/fault_fence.c`）：每 worker 线程一套 `sigsetjmp` 围栏 + 全局 `sigaltstack`。调用窗口内崩溃（SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT）→ 归因到肇事模块槽位 → `siglongjmp` 恢复，daemon 存活、该请求按 `-EIO` 失败。归因失败（如堆损坏延迟到框架代码爆发）走原 `crash_dump` 链路。
2. **输出校验**（`src/module/module_guard.c`）：`NspResolveResult` 前后 canary 哨兵 + 字符串字段 NUL 终止检查 + `user_id` 值域检查 + readdir 条目名校验。
3. **熔断器**：每模块滑动窗口（默认 10 秒 5 次错误，env `NSP_GUARD_WINDOW_SEC` / `NSP_GUARD_ERR_MAX` 可覆盖）触发即 `module_fault_poison`——槽位置空（该模块规则立即全部失效，走直通回退）+ 卸载 + ban 落盘。崩溃单次即置毒。

**ban 机制**：记录写 `<MODULES_DIR>/.banned`（每行 `模块名|SHA256|原因|时间戳`）。扫描线程见哈希与 ban 记录一致即跳过加载；哈希变化（发布新版本）记录失效，**版本更新自愈**；daemon 重启后 ban 仍有效。

**排障入口**：`log_ctl search-sys --level 2 MOD_ERR <模块名>` 按模块过滤结构化错误行（`module=/op=/rc=/path=/detail=`）。窗口内前 5 条明细全打、之后每 100 条打 1 条汇总，坏模块不会淹没日志环；熔断与崩溃恢复两类高危事件无条件追加到 `<LOG_DIR>/module_errors.log`；崩溃转储附 `Crash attribution: module=<名> slot=<N> op=<op>` 归因行。`module_health_snapshot()` 输出每模块 `err_count`/`err_total`/`banned`/`ban_reason`/`last_err_time` 供前端展示。

## 6. 开发第三方模块

### 6.1 依赖与前置

- **唯一接口头**：`include/nsp_module.h`，源码只依赖本头 + 标准库。
- **许可证**：框架以 GPL-3.0-or-later 发布，但**对模块 ABI 授予链接例外**——仅通过本头文件公开 ABI 结合的独立模块，可按任意条款发布（含闭源），不因此受 GPL 约束。前提是不编入框架源码、不依赖本头以外的内部头、不引用未声明的内部符号。完整条款见 `LICENSE.module-exception`。
- **编译宏**：必须定义 `-DNSP_MODULE_BUILD`，激活头内「模块公共运行时 ABI」段（日志宏 `LOG/LOG_WRN/LOG_ERR/LOG_DBG`、`CONFIG_DIR`/`STORAGE_BASE`、框架导出符号声明）。
- **运行时符号**：日志/路径等框架符号经 fuse_daemon 的 `-Wl,--export-dynamic` 导出表在 dlopen 时解析，模块无需链接框架，**不得把 `src/core/common.c` 等框架源编入自身**。
- **可借用的公共抽象**：通用 INI 段式存储（`nsp_ini_open/close/get/set/del_key/del_section/save`，经 `nsp_module.h` 代含 `nsp_ini_store.h`）——模块自有配置文件（如 `ftp.conf`）可直接调用，注释保留 + 原子落盘，语义见该头注释。

### 6.2 最小骨架

```c
#include "nsp_module.h"   /* NSP_MODULE_BUILD 已定义 */

static int my_init(const NspFrameworkApi* api) {
    g_api = api;                    /* 保存框架服务表（唯一访问通道） */
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

放入 `<MODULES_DIR>/my_module/my_module.so` 即热加载。项目内模块走 meson：`shared_library('<name>', ..., name_prefix: '', c_args: ['-DNSP_MODULE_BUILD'])`（`b_lundef` 项目级已关，允许引用主程序导出符号）。

### 6.4 契约（违反即被熔断）

- 返回值：`0` 成功 / 负值 errno 失败（**返回正数非 0 会被计为错误**）。
- 输出字符串字段**必须 NUL 终止**，越界写会破坏 canary 触发置毒。
- 回调内**不得阻塞**：围栏窗口内不可恢复地持锁会破坏 longjmp 安全性（框架侧已保证分派路径不持锁）。
- 置毒时框架**不调用** `exit()`（崩溃模块代码不可信），模块进程级资源需自行保证幂等。

### 6.5 ABI 演进

| 场景 | 机制 |
|------|------|
| 不兼容变更（改表结构/删字段） | `NSP_MODULE_ABI_VERSION` 递增 → 旧模块被校验拒绝 |
| 兼容新增框架能力 | `NspFrameworkApi` 尾部追加字段 + `NSP_FRAMEWORK_API_VERSION` 递增 |
| 新能力 / 新模块类型 | `caps` 位图扩展（32 位预留），框架按位判断 |
| 模块自身版本 | `NspModuleInfo.version` 字符串（不影响加载兼容性） |

## 7. 参考实现

| 模块 | 源码 | 说明 |
|------|------|------|
| `basic_rules.so` | `src/modules/basic_rules/` | 规则引擎（原 `vfs_core` 迁移，匹配语义逐行等价）：`basic_rules.c` 模块入口、`br_rules.c` 决策引擎（uid 缓存 / uid.map / Trie + 线性通道 / sandbox / 虚拟目录 / inotify 规则热重载） |
| `ftp_module.so` | `src/modules/ftp/` | FTP 后端（libcurl，**不依赖 libfuse3**）：含 `backend_flush` 两阶段收尾与弱网重试示例；写路径为本地临时文件缓存 + release 时 STOR 全量上传 |

FTP 映射由 `injector.conf` 的 `FTP <虚拟前缀> <段名>` 规则决定（如 `FTP /云盘 云盘`），作用域按规则所在段——`[GLOBAL]` 全局、`[应用包名]` 仅该应用，与 REDIRECT 一致。变量 `FTP_<段名>` 经 `get_vars` 注册。

basic_rules 的关键语义（修改时必须保持）：hidden/ro 取 app + global **并集**；redirect/sandbox 取 app 优先、global 兜底，sandbox 仅在无 redir 命中时生效；`br_resolve` 读规则前持 `config_lock_read()`。

## 8. 相关文档

- 进程架构与规则引擎：`architecture.md`
- 配置语法：`config.md`
- 构建与测试：`README.md`、`AGENTS.md`
