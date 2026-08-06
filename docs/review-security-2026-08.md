# 安全审查报告（2026-08-06）

审查范围：`src/daemon/fuse_daemon.c`、`src/injector/ipc_server.c`、`src/module/loader.c`、
`src/modules/basic_rules/br_rules.c`、`src/core/common.c`、`src/core/uid_map.c`、
`src/config/path_vars.c`、`src/core/path_trie.c`。
威胁模型：daemon 与 injector 均以 **root** 运行，处理来自**不可信应用**的路径、包名与 IPC 输入。

---

## 🔴 严重

### 1. IPC 抽象 socket 无任何鉴权 —— 任意本地进程可触发 root 级操作

- **位置**: `src/injector/ipc_server.c:153-183`（socket 创建）、`189-287`（命令处理）
- **问题**: 使用**抽象命名空间** Unix socket（`sun_path[0]='\0'`），**没有 `SO_PEERCRED` 校验、没有 token/鉴权**。任何 uid 的进程都能 connect 并发 `REPORT <pkg> <pid> <uid>` / `REQ ...`。
- **触发条件**: `ipc_server_init` 后任意本地进程可连。pid 只校验了范围（`1..1048576`，L210），**未校验 pid 是否属于调用者**；uid 只校验非负。
- **利用场景**:
  - 伪造任意 pid → `ipc_mount_thread` → `ns_global_mount_async(arg->pid, ...)` 以 root 向**受害者进程的命名空间**做 bind mount（L122）——把全局 FUSE 挂到任意进程的存储路径，或引发挂载风暴 DoS；
  - 伪造 uid/pkg → `update_uid_map(uid, clean_pkg)`（L236）污染 `CONFIG_DIR/uid.map`，直接影响规则解析（见 #6）；
  - `LIST_INJECTED` / `LIST_MODULES` 匿名枚举已注入应用与已装模块（信息泄露）。
- **修复（最小改动）**: 接受连接后立即 `getsockopt(SO_PEERCRED)`，**拒绝 uid!=0（或 injector 自身 uid）的客户端**；再叠加 SELinux 策略约束抽象 socket。

### 2. `vfs_symlink` 任意 target + `vfs_open` 跟随符号链接 —— root 任意文件读写

- **位置**: `src/daemon/fuse_daemon.c:936-958`（`vfs_symlink`）、`560-613`（`vfs_open`，`open(p, ...)` L590）
- **问题**: `symlink(target, p)` 的 **target 完全由应用控制且无校验**（L943）；而 `vfs_open`/`vfs_create`/`vfs_mkdir` 等用普通 `open()`/`mkdir()` **跟随符号链接**。daemon 以 root 运行。
- **触发条件**: 真实存储 `g_real_root` 位于支持符号链接的文件系统（ext4 等）上时，应用在自己目录内 `symlink("/data/data/<其他应用>/...", link)` 再打开该虚拟路径。
- **利用场景**: 应用创建指向 `/data/data/<victim>/databases/...`、`/data/Namespace-Proxy/...` 的链接 → daemon 以 root 跟随 → **读取/覆写任意 root 可读文件**，横向越权到其它应用私有数据。另有 TOCTOU：路径解析与 `open` 之间可并发把目录换成符号链接（交换竞态）。
- **修复**: `open`/`create`/`mkdir` 等最终组件用 `O_NOFOLLOW`（目录跟随需 `openat2(RESOLVE_BENEATH)` 或 realpath 前缀校验）；`vfs_symlink` 校验 target 绝对路径必须位于允许根内。

---

## 🟠 高

### 3. 模块热插拔 dlopen 无运行时所有权校验 —— 目录可写即 root 代码执行

- **位置**: `src/module/loader.c:121-182`（`module_load_one`）
- **问题**: inotify 热加载 `/data/Namespace-Proxy/modules/<名>/<名>.so`，`dlopen` 后直接调用 `init(&g_api)`（L151-157）。**加载时未校验 .so 属主/权限/目录权限**，也没有对加载路径做 openat 式防替换。
- **触发条件**: 模块目录被非 root 可写（安装时权限配置错误、或目录被应用先行创建）。
- **利用场景**: 往模块目录投放恶意 .so → daemon 自动 dlopen 并以 root 执行任意代码（init 即入口）。框架还以 `--export-dynamic` 导出符号（见 docs/module-dev.md），模块可达框架全部能力。
- **修复**: 加载前 `stat` 校验：属主 uid==0、非 group/world 可写、目录 0755 root 属主；配合 SELinux 限制模块目录。

---

## 🟡 中

### 4. 路径清理不处理 `..` —— 纵深防御缺失

- **位置**: `src/core/common.c:259-310`（`path_contains_invalid_chars`/`path_sanitize`）
- **问题**: 仅过滤控制字符与部分 Unicode，**`..`/`.` 段原样通过**。FUSE 内核路径通常已规范化（缓解），但 `fw_default_real_path`（`fuse_daemon.c:125-137`）直接拼接 `g_real_root + "/" + user_id + sub_path`，`br_check_redir_rule` 的 sandbox 目标也是 `STORAGE_BASE "/%d/Android/data/%s/sandbox"`（`br_rules.c:464-471`）——任一路径段含 `..` 即逃出预期根。
- **触发条件**: 与 #6 的 pkg 污染组合，或未来新增的路径来源绕过内核规范化。
- **修复**: `path_sanitize` 增加 `..`/`.` 段剥离或拒绝（同时保持与内核语义一致）。

### 5. `LIST_INJECTED` / `LIST_MODULES` 匿名可读

- **位置**: `src/injector/ipc_server.c:264-273`
- **问题**: 无鉴权连接即可枚举已注入应用清单与已装模块清单，辅助攻击者侦察（结合 #1 一并修复）。

### 6. `uid.map` 包名注入 → sandbox 路径穿越链

- **位置**: `ipc_server.c:236`（`update_uid_map(uid, clean_pkg)`）→ `uid_map.c:49-142`（`uid_map_upsert`）→ `br_rules.c:202`（`uid_map_lookup` 取 pkg）→ `br_rules.c:469`（sandbox 路径拼接）
- **问题**: `clean_pkg` 只做了 `:` 截断（L234-235），**未做字符白名单**——`REPORT` 可携带含 `/`、`..` 的包名写入 uid.map；`br_get_app_cfg` 读到该 pkg 后拼进 sandbox 目标路径与 hide 规则比对 → **目录穿越**（root 创建/重定向任意路径）。同时可把受害者 uid 映射到攻击者包名 → 规则解析混淆（跨应用）。
- **触发条件**: 任意本地进程连 IPC（#1 无鉴权）即可发动。
- **修复**: 写入 uid.map 前与加载时校验 pkg 仅含 `[A-Za-z0-9_.]`（Android 包名合法字符）；`br_get_app_cfg` 对读取的 pkg 同样校验。

---

## ⚪ 低 / 已核查

| 项 | 位置 | 结论 |
|----|------|------|
| 格式串安全 | `fuse_daemon.c:92`、`vfs_log_io` | 格式串固定、路径作为 `%s` 实参——无格式化注入 ✅ |
| `path_char_is_invalid` 越界 | `common.c:259-283` | p[1..3] 读取均有 `'\0'` 短路保护，不越界 ✅ |
| `uid_map_upsert` 原子写 | `uid_map.c:109-139` | tmp+fsync+rename，无并发脏读 ✅ |
| 配置热重载 | `br_rules.c:75-83` | 持写锁原子重载 + `clear_uid_cache`，读侧有锁保护 ✅ |
| `strncpy`/`snprintf` 边界 | 全仓库 | 主要拷贝均显式限长并补 `\0` ✅ |
| 配置注入 | `config_parser.c` | 配置文件为 root 管控；风险取决于安装权限（同 #3 一并约束） |

---

## 总体结论与最优先修复 3 项

**结论**: 项目在内存安全与并发设计上相当扎实（锁序一致、原子写、边界防护），**主要风险集中在"root 守护进程的可信输入边界"**：IPC 无鉴权（#1）、符号链接跟随（#2）、模块目录无权限校验（#3）。三者任一被利用都可达 **root 权限的代码执行或任意文件访问**，建议优先修复。

1. **IPC 增加 `SO_PEERCRED` uid==0 校验**（连带封死 #1/#5/#6 的投递面，改动约 10 行）
2. **`vfs_open`/`vfs_create` 等最终打开路径加 `O_NOFOLLOW` + 真实路径前缀校验**（root 任意读写面）
3. **模块加载前 stat 校验属主/权限 + SELinux 约束模块目录**
