# ABI 兼容模块开发文档

Fuse-Proxy 的模块系统允许**第三方独立开发**功能模块（规则引擎 / 存储后端），
模块间**仅 ABI 兼容**——模块源码只依赖 `include/nsp_module.h`（+ 标准库），
不 include 任何框架内部头、不编译框架源码，可在独立仓库独立编译，经
`fuse_daemon` dlopen 热插拔。

## 1. 依赖与前置

- **唯一接口头**：`include/nsp_module.h`（ABI 契约，约 290 行）
- **源码依赖**：仅本头 + 标准库（string.h/pthread.h/errno.h 等由本头代含）
- **编译宏**：模块编译须定义 `-DNSP_MODULE_BUILD`——激活本头中的
  "模块公共运行时 ABI"段（日志宏 `LOG/LOG_WRN/LOG_ERR/LOG_DBG`、
  `CONFIG_DIR/STORAGE_BASE`、框架导出符号声明）
- **运行时符号**：日志/路径等框架符号经主程序（fuse_daemon）
  `-Wl,--export-dynamic` 导出表在 dlopen 时解析，模块无需链接框架
- **不编译框架源码**：模块不得把 `src/core/common.c` 等框架源编入自身
- **可借用的公共抽象**：通用 INI 段式存储（`nsp_ini_open/close/get/set/
  del_key/del_section/save`，声明经 `nsp_module.h` 代含 `nsp_ini_store.h`，
  实现逐源编入 `fuse_daemon` 常驻导出表）——模块自有配置文件（如类
  `ftp.conf` 的服务器账号）可直接调用，注释保留 + 原子落盘，与
  `rule_server` 的 `FTP_*` 命令同实现；语义见 `include/nsp_ini_store.h`
  头注释（含 ON/OFF 后缀段头、重复段等边界说明）

## 2. 最小模块骨架

模块必须导出静态符号 `nsp_module_info`（`NspModuleInfo` 结构），
加载器校验 **magic / abi_version / name** 一致后才调用 `init`：

```c
#include "nsp_module.h"   /* NSP_MODULE_BUILD 已定义 */

static int my_init(const NspFrameworkApi* api) {
    g_api = api;                    /* 保存框架服务表（唯一访问通道） */
    return 0;                       /* 非 0 拒绝加载 */
}
static void my_exit(void) { /* 清理（可为 NULL） */ }

const NspModuleInfo nsp_module_info = {
    .magic       = NSP_MODULE_MAGIC,          /* 必须 */
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

## 3. 模块类型与能力位

| 类型 | 用途 |
|------|------|
| `NSP_MODULE_TYPE_RULES` | 规则模块：参与路径决策（REDIRECT/SANDBOX/HIDE/ALLOW/RO） |
| `NSP_MODULE_TYPE_BACKEND` | 存储后端模块：提供新后端操作方法，**不实现 FUSE** |

能力位（`caps`，32 位预留）：`NSP_CAP_REDIRECT/SANDBOX/HIDE/ALLOW/RO/
READDIR_EXTRA/VIRTUAL_DIR`（规则）、`NSP_CAP_MOUNT_POINT/VAR/BACKEND_IO`（后端）。

## 4. 接口表 `NspModuleOps`

规则模块实现：

```c
int (*resolve)(const NspQueryCtx* q, NspResolveResult* out);   /* 路径决策 */
int (*probe)(const NspQueryCtx* q, NspProbeResult* out);       /* readdir 轻量过滤 */
int (*readdir_extra)(const NspQueryCtx*, const char*, int, const char*, bool,
                     NspDirEntry*, int);                        /* 虚拟目录补充 */
```

后端模块（`NSP_CAP_BACKEND_IO`）实现完整文件操作，`path` 为框架剥离
user_id 后的虚拟路径，模块自行映射到目标存储：

```c
int (*backend_match)(const char* path);          /* 1=管理该路径 0=否 */
int (*backend_getattr)(const char* path, struct stat* st);
int (*backend_readdir)(const char* path, NspDirEntry* entries, int max);
int (*backend_open)(const char* path, int flags, uint64_t* h);  /* h 模块自管 */
int (*backend_read)(uint64_t h, char* buf, size_t size, off_t off, size_t* got);
int (*backend_write)(uint64_t h, const char* buf, size_t size, off_t off, size_t* wrote);
int (*backend_flush)(uint64_t h);    /* FUSE FLUSH：收尾数据但保留句柄
                                        （FLUSH 可因 dup/fork 多次调用，
                                        销毁须等 RELEASE） */
int (*backend_release)(uint64_t h);  /* 唯一销毁点 */
int (*backend_create)(const char* path, mode_t mode, uint64_t* h);
int (*backend_unlink)(const char* path);
int (*backend_mkdir)(const char* path, mode_t mode);
int (*backend_rmdir)(const char* path);
int (*backend_rename)(const char* from, const char* to);
int (*backend_truncate)(const char* path, off_t size);
```

## 5. 框架服务表 `NspFrameworkApi`

`init` 时由框架注入，模块**仅经它使用框架设施**（版本化，新增字段追加尾部，
旧模块按 `api_version` 决定是否访问）：

```c
typedef struct NspFrameworkApi {
    uint32_t api_version;                      /* NSP_FRAMEWORK_API_VERSION */
    void (*log)(int level, const char* fmt, ...);       /* 0=DEBUG 1=INFO 2=WARN 3=ERROR */
    const char* (*get_real_root)(void);        /* 真实存储根（--root） */
    const char* (*get_rules_path)(void);       /* 规则配置路径（--rules） */
    uint32_t (*get_flags)(void);
} NspFrameworkApi;
```

## 6. 编译

```sh
# GNU（本机测试）
cc -shared -fPIC -std=c23 -DNSP_MODULE_BUILD \
   -I<项目>/include my_module.c -o my_module.so

# Android（NDK 交叉）
aarch64-linux-android35-clang -shared -fPIC -std=c23 \
   -DNSP_MODULE_BUILD -I<项目>/include my_module.c -o my_module.so
```

Meson 集成（参考框架 `meson.build`）：模块 target 加 `c_args: ['-DNSP_MODULE_BUILD']`。

## 7. 安装与热插拔

- 目录：`/data/Namespace-Proxy/modules/<模块名>/<模块名>.so`
- 放入即热加载（inotify 监控，无需重启）；删除即卸载
- `name` 字段必须与 `<模块名>` 一致，否则拒绝加载

## 8. ABI 演进规则

| 场景 | 机制 |
|------|------|
| 不兼容变更（改表结构/删字段） | `NSP_MODULE_ABI_VERSION` 递增 → 旧模块被加载校验拒绝 |
| 兼容新增框架能力 | `NspFrameworkApi` 尾部追加字段 + `NSP_FRAMEWORK_API_VERSION` 递增 |
| 新能力/新模块类型 | `caps` 位图扩展（32 位预留），框架按位判断 |
| 模块自身版本 | `NspModuleInfo.version` 字符串（不影响加载兼容性） |

## 9. 参考实现

- 规则模块：`src/modules/basic_rules/`（`resolve/probe/readdir_extra` 全实现）
- 后端模块：`src/modules/ftp/`（`NSP_CAP_BACKEND_IO`，libcurl 后端，含
  `backend_flush` 两阶段收尾与弱网重试示例）
