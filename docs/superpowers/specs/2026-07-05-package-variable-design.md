# 路径变量支持（`$package` + 用户自定义变量 + 静态/动态优化） — 设计文档

- 日期：2026-07-05
- 分支：test
- 状态：待实现

## 1. 背景与目标

Fuse-Proxy 已能根据命中 uid 解析出当前请求所属应用包名（`current_pkg`，已去 `:process` 后缀），但目前该值只用于 sandbox 硬编码路径（`vfs_core.c:321`）。本设计在配置路径中引入**两层变量系统 + 静态/动态分类优化**：

- **系统变量 `$package`**：运行时按命中 uid 动态决定包名。
- **用户变量**：配置时用 `NAME=VALUE` 定义，值可引用其他变量（含 `$package`），运行时递归展开。
- **静态/动态分类**：parse 阶段自动判定每个用户变量是否依赖运行时上下文；静态变量预计算展开值缓存，运行时 `memcpy`，动态变量才递归展开。

典型用例：

```
# 用户变量（全局段）
STATIC_BASE=/sdcard/myapp                 # 静态：纯字面量
DATA_BASE=/sdcard/Android/data/$package   # 动态：含 $package
NESTED=$STATIC_BASE/cache                 # 静态：传递闭包仍无 $package

REDIRECT /files   $DATA_BASE/files        # 动态规则
HIDE     $STATIC_BASE/private             # 引用静态变量，变量替换 O(1)
```

当前代码**没有任何路径变量替换机制**，本设计为全新功能。

## 2. 需求（已与用户确认）

| 决策点 | 结论 |
|---|---|
| 系统变量 | `$package`（按命中 uid 动态） |
| 用户变量定义语法 | `NAME=VALUE`（环境变量风格，紧凑无空格围绕 `=`） |
| 用户变量作用域 | 全局（`[GLOBAL]` 段）+ 应用级（`[com.xxx:0]` 段），app 同名覆盖 global |
| 值引用能力 | 可引用其他变量（含系统变量），运行时递归展开 |
| 变量名规则 | `[A-Za-z_][A-Za-z0-9_]*`，大小写敏感 |
| 系统保留名 | `package`（及未来 `uid`/`user_id`）禁止用户覆盖，违反时告警并忽略 |
| 路径引用语法 | `$name` 与 `${name}` 都认 |
| 未知变量 | 保留字面 `$name`（向后兼容） |
| 未命中真实包名 | 含 `$package` 的规则**失效（跳过）**，走默认 fallback |
| 性能：规则级短路 | `expand_path_vars` 内部 `memchr('$')` 短路，无 `$` 零开销 |
| 性能：变量级优化 | parse 阶段判定变量静态/动态；静态变量预计算缓存，运行时 `memcpy`，动态变量才递归展开 |

## 3. 核心抽象

### 3.1 静态/动态判定

> 一个用户变量是**静态** ⟺ 它的展开结果不依赖运行时上下文 ⟺ 值的变量引用传递闭包**不含** `$package`。

- 纯字面量（`STATIC_BASE=/sdcard/myapp`）→ 静态
- 引用其他静态变量（`NESTED=$STATIC_BASE/cache`）→ 静态
- 含 `$package` 或引用动态变量（`DATA_BASE=.../$package`）→ 动态
- 循环引用（`A=$B`,`B=$A`）→ 动态（运行时展开 + 循环检测兜底）

parse 阶段对所有用户变量做不动点迭代标记（O(V·E)，变量数少，可忽略）。

### 3.2 数据结构

```c
// AppConfig 新增字段（用户变量持久存储，解析阶段填充，热加载整体替换）
char** var_names;
char** var_values;      // 原始值（含 $ 占位），动态变量运行时展开用
char** var_resolved;    // 静态变量的预计算展开值；动态变量为 NULL
bool*  var_is_static;   // 静态/动态标记
int    var_count;
int    var_capacity;
```

### 3.3 函数

```c
// 含变量占位符判定（与 is_wildcard_string 并列，config_parser.c:201）
bool has_path_var(const char* s);              // strchr(s, '$') != NULL

// current_pkg 是否可解析为真实包名（复用 vfs_core.c:294/579/177 的 system/unknown 判定）
static bool pkg_resolvable(const char* pkg);

// 判断一行是否为赋值语句 NAME=VALUE
bool parse_var_assignment(const char* line, char* name, size_t nname,
                          char* value, size_t nval);

// 静态/动态分析：对 cfg->var_* 做不动点标记，并为静态变量预计算 var_resolved
// 分析某 app 时合并视图：(app var_*) + (g_global_cfg.var_*) + 系统变量
void analyze_var_staticness(AppConfig* cfg);

// 展开 $name / ${name}：
//   - memchr('$') 短路：无 '$' 直接 memcpy 返回
//   - 查找变量：
//       package        → current_pkg（系统）
//       用户变量静态   → memcpy var_resolved（O(1)，不再递归）
//       用户变量动态   → 取 var_values，对其递归 expand（含循环检测）
//       未找到         → 保留字面 $name
//   - 循环检测：递归路径上维护已展开变量名集合 + 深度上限 32
//   - 溢出截断并保证 null 终止；返回写入长度
size_t expand_path_vars(const char* in, char* out, size_t outsz,
                        const AppConfig* cfg, const char* current_pkg);

// 判定 path 是否为系统绝对根目录路径（支持根目录本身与带子路径形式）：
//   /data | /data/... | /mnt | /mnt/... | /storage | /storage/...（非 emulated）
// 用于把系统根目录（如 /mnt、/data，含无尾部斜杠的根目录形式）与 user 存储相对路径
//   （如 /sdcard/... 通常为 symlink、Android/... 相对）区分开。parse 与运行时复用。
bool is_system_abs_path(const char* path);

// 由 real_target 构造 real_base（合并现有 :457-468 分类 + :271-276 ?前缀构造）：
//   - 含 '$' → 先 expand_path_vars 展开成完整路径字符串（!pkg_resolvable 返回 false 使规则失效）
//   - 对（展开后的）target 分类（按此顺序判定，用 is_system_abs_path 支持根目录形式）：
//       /storage/emulated/X/... → STORAGE_BASE "/" user_id "/..."（归一为当前 user 存储）
//       is_system_abs_path 为真 → 绝对路径原样（/mnt、/data、/storage 及其子路径，含根目录本身）
//       其他以 '/' 开头（如 /sdcard/...，通常为 user 存储 symlink）或无前导 '/' → 相对当前 user 存储（STORAGE_BASE/user_id/...）
//   - 不含 '$' 的 target 走同一分类（与含 '$' 行为一致）
// 返回 false 表示规则应失效（含 $ 但包名不可解析）；true 表示 real_base 已写入
bool build_real_base_from_target(const char* target, int user_id,
                                 char* real_base, size_t sz,
                                 const AppConfig* cfg, const char* current_pkg);
```

**expand 签名**：`(in, out, outsz, cfg, current_pkg)`。用户变量在 `cfg` 里、系统变量来自 `current_pkg`，由 expand 内部统一查找。

**放置位置：** `has_path_var` / `parse_var_assignment` / `analyze_var_staticness` 放 `config_parser.c`（与 `is_wildcard_string` 同处，声明进共享头）；`pkg_resolvable` / `expand_path_vars` 放 `vfs_core.c`（声明进共享头供两侧用）。

### 3.4 变量查找顺序（展开一个 `$name`）

1. 系统保留变量：`package` → `current_pkg`。
2. 应用用户变量：`cfg->var_names`（静态用 `var_resolved`，动态用 `var_values` 递归）。
3. 全局用户变量：`g_global_cfg.var_names`（同上）。
4. 未找到 → 保留字面 `$name`。

系统保留名禁止用户覆盖，故系统变量与用户变量无冲突；app 用户变量覆盖 global 用户变量。

## 4. 数据流

```
解析时（load_config_rules）：
  parse_config_line
    ├─ parse_var_assignment 命中 → 保留名校验 → 存 cur->var_names/var_values
    └─ 否则 → 原 REDIRECT/HIDE/RO/... 分发
  某段解析完成后调 analyze_var_staticness(cur)：
    ├─ 不动点迭代标记 var_is_static
    └─ 静态变量递归展开（仅含字面量 + 其他静态变量）→ var_resolved

运行时（fuse 请求）：
  VFS_SETUP_CORE 解析出 current_pkg
    └─ 规则匹配点（4 处）每条规则三分支：
         ├─ 不含 '$'                → 原样使用（快路径）
         ├─ 含 '$' 且 !pkg_resolvable → 规则失效（continue）
         └─ 含 '$' 且 pkg_resolvable  → expand_path_vars：
              静态变量 memcpy var_resolved；动态变量递归展开
```

关键：`current_pkg` 永不为空（`vfs_get_app_cfg` 保证至少 `"system"`/`"unknown"`/真实包名）。

## 5. 改动点清单

### 5.1 解析阶段（`src/config/config_parser.c` + `include/config_parser.h`）

1. **`AppConfig` 新增** `var_names`/`var_values`/`var_resolved`/`var_is_static`/`var_count`/`var_capacity`。
2. **`parse_config_line` 开头**插入赋值分支：`parse_var_assignment` 命中且变量名非系统保留名时存入 `cur->var_*`；保留名 `LOG_WRN` 并忽略。
3. **`analyze_var_staticness`**：在某段（`[GLOBAL]` 或某 `[com.xxx]`）所有赋值解析完后调用，对该 cfg 的变量做静态分析与预计算。app 段分析时合并 global 变量视图。
4. **`free_config_rules`** 释放 `var_names`/`var_values`/`var_resolved`/`var_is_static`。
5. **`trie_insert` 判定收紧**：hide(:388) / ro(:409) / redirect(:437,477) 从 `!is_wildcard_string(x)` 改为 `!is_wildcard_string(x) && !has_path_var(x)`。含 `$` 规则只走线性匹配。
6. **`REDIRECT` real_target 含 `$` 的延迟归一**：`v2` 含 `$` 时，parse 阶段**原样存入 `real_target`**（不做 :457-468 的归一，因为变量未展开无法判定路径类型）；路径类型判定延迟到运行时展开后，由 `build_real_base_from_target`（见 3.3）按现有 REDIRECT target 的同一套规则分类。这样含 `$` 的 target 展开后，**绝对路径、相对路径、emulated 前缀三类都能正确处理**——兼顾绝对与相对，且与不含 `$` 的规则行为一致。（`virtual_prefix` 不支持 `$`，无需处理。）
7. **系统绝对根目录判定统一**：现有 :463 的绝对路径分支用 `strncmp(v2,"/data/",6)` 等（**带尾部斜杠**），导致 `/data`、`/mnt`、`/storage` 这类**根目录本身**（无尾部斜杠）漏判走 else 被当相对路径。改为统一用 `is_system_abs_path()`（见 3.3），支持根目录本身（`/data`、`/mnt`、`/storage`）与带子路径形式（`/data/...`、`/mnt/...`），parse（无 `$`）与 `build_real_base_from_target`（含 `$`）共用，行为一致。

### 5.2 运行时（`src/daemon/vfs_core.c`，4 处调用点）

| # | 位置 | 规则字段 | 展开时机 |
|---|------|---------|------|
| 1 | `check_redir_rule` :270 | `real_target` | 用 `build_real_base_from_target` 替代原 real_base 构造（含 `$` 先展开再按统一规则分类），返回 false 则本条 redir 失效；成功后算 `tlen`/拼 `temp` |
| 2 | `vfs_fill_virtual_dirs` 宏 :612 | `real_target` | 用 `build_real_base_from_target` 构造 `dummy`，返回 false 则不合成该虚拟目录；否则 `access(F_OK)`。需给 `vfs_fill_virtual_dirs` 增加 `current_pkg` 参数（从 readdir handler 宏传入） |
| 3 | `is_path_hidden_internal` :219-236 | `hide_rules[i]` | 规则串直接展开后 fnmatch + 前缀 |
| 4 | `vfs_to_real_path` RO 段 :388-403 | `ro_rules[i]` | 规则串直接展开后 fnmatch + 前缀 |

**#3/#4 模式（hide/ro，规则串即匹配串）：**

```c
const char* rule = <hide_rules[i] 或 ro_rules[i]>;
char expanded[PATH_MAX];
const char* match_str;
if (has_path_var(rule)) {
    if (!pkg_resolvable(current_pkg)) continue;          // 规则失效
    expand_path_vars(rule, expanded, sizeof(expanded), cfg, current_pkg);
    match_str = expanded;
} else {
    match_str = rule;                                    // 快路径
}
// 用 match_str 做 fnmatch / 前缀匹配
```

**#1/#2 模式（redir real_target，统一用 `build_real_base_from_target`）：**

```c
const char* target = c->redir_rules[i].real_target;
char base[PATH_MAX];
if (!build_real_base_from_target(target, user_id, base, sizeof(base), cfg, current_pkg)) {
    continue;   // 含 $ 但包名不可解析 → 规则失效（#2 不合成该虚拟目录）
}
// 用 base 计算 tlen、拼 temp（#1）或 access(F_OK)（#2）
```

`build_real_base_from_target` 封装了「含 `$` 则展开、按现有 REDIRECT 规则分类、构造 real_base/dummy」全过程，使 #1/#2 与不含 `$` 的规则复用同一套路径分类逻辑——绝对路径、相对路径、emulated 前缀三类都正确处理。

> 性能说明：`expand_path_vars` 内部对静态变量走 `memcpy var_resolved`，对动态变量才递归。引用纯静态变量的规则（如 `$STATIC_BASE/files`）虽走 expand，但变量替换是 O(1)；只有引用动态变量的规则（如 `$DATA_BASE/files`）才付出递归展开代价。

### 5.3 不改动的点

- `vfs_is_redirect_target` :463 — 仅比较 `virtual_prefix`，本次不支持虚拟前缀侧 `$package`。
- sandbox 硬编码路径 :321 — 已用 `current_pkg`，与变量机制无关。
- `config_publisher.c` / `log_ctl.c` 的 JSON 序列化与调试打印 — 展示配置原始字面量（含 `$name` 与 `NAME=VALUE`）是正确行为。（可选：附带序列化 `var_*` 与 `var_is_static` 以便调试，非必须。）

## 6. 错误处理

| 场景 | 行为 |
|------|------|
| 循环引用（`A=$B`，`B=$A`） | 静态分析归为动态；运行时深度上限 32 + 已展开变量名集合，超限/重复保留剩余字面 `$name`，不无限递归 |
| 用户覆盖系统保留名（`package=xxx`） | 解析时 `LOG_WRN` 并忽略该赋值 |
| 未知变量（`$foo` 未定义） | 保留字面 `$foo`，expand 正常返回（不失效） |
| 未命中真实包名（system/unknown） | `pkg_resolvable` 短路 → 含 `$` 规则失效 → 默认 fallback |
| 静态变量预计算溢出 | `var_resolved` 缓冲截断 + null 终止；运行时 expand 输出缓冲同样截断 |
| 配置热加载（inotify） | `var_*` 随 `AppConfig` 整体释放重建，静态分析在重载时重跑，无需特殊处理 |

## 7. 测试策略

### 7.1 单元测试

- `parse_var_assignment`：合法 `NAME=VALUE`、带空格 VALUE、非法变量名（数字开头）、系统保留名 `package=...` 被拒。
- `analyze_var_staticness`：纯字面量→静态、含 `$package`→动态、嵌套静态变量→静态、嵌套动态变量→动态、循环引用→动态。
- `expand_path_vars`：无 `$`、`$package`/`${package}`、静态变量走缓存（结果与递归展开一致）、动态变量递归、循环引用防死循环、未知变量保留字面、多次出现、system/unknown 上层短路、缓冲区边界。
- `is_system_abs_path` / `build_real_base_from_target`：`/data`、`/data/...`、`/mnt`、`/mnt/...`、`/storage`（非 emulated）→ 绝对；`/storage/emulated/X/...` → 归一为当前 user 存储；`/sdcard/...`、`Android/...` → 相对；含 `$` 展开后分类与不含 `$` 一致；包名不可解析时返回 false。
- 作用域：app 用户变量覆盖 global 用户变量。

### 7.2 运行时验证（项目惯例）

1. **静态变量**：`[GLOBAL]` `STATIC_BASE=/sdcard/myapp`，`REDIRECT /x $STATIC_BASE/files` → 所有应用都落到 `/sdcard/myapp/files`。
2. **动态变量 + 递归**：`[GLOBAL]` `DATA_BASE=/sdcard/Android/data/$package`，`REDIRECT /files $DATA_BASE/files` → 应用 A/B 各落各包目录。
3. **HIDE 按包生效**：`HIDE $DATA_BASE/private`，本应用不可见、他应用可见。
4. **app 覆盖 global**：`[GLOBAL]` `VAR=/global`，`[com.x:0]` `VAR=/appx` → com.x 用 `/appx`、其他用 `/global`。
5. **未命中失效**：system 进程访问含 `$package` 规则 → 规则失效走默认。
6. **`${name}` 语法**：与 `$name` 行为一致。
7. **系统根目录**：`MNT=/mnt/sdcard/$package`，`REDIRECT /ext $MNT` → 展开为 `/mnt/sdcard/com.x`，绝对路径；`VAR=/data`，`REDIRECT /d $VAR` → 绝对 `/data`（根目录本身，无尾部斜杠也正确）；`VAR=/mnt` 同理。验证系统根目录不被误当相对路径。

### 7.3 观测手段

`vfs_log_io` 的 `[MAP]` 调试日志（`vfs_core.c:506`，`g_min_log_level == LOG_DEBUG`）打印 `sub_path -> real_path`，可直接核对展开结果。

## 8. 不在范围内（YAGNI）

- 虚拟前缀（`virtual_prefix`）侧的 `$package` 支持。
- SANDBOX 自定义目录配置项（`SANDBOX_TARGET`）。
- `$uid` / `$user_id` 等其他系统变量的实际注册（仅预留保留名与查找框架）。
- `$pkg` 别名（仅 `$package`）。
- **规则级静态预计算**（把"只引用静态变量"的整条规则在 parse 时预计算并跳过运行时 expand）——收益最大但需把 `hide_rules`/`ro_rules` 从 `char**` 改结构体数组，侵入 config_publisher/log_ctl/mount_manager 多处；当前变量级优化已覆盖主要收益，规则级留待后续按需。

## 9. 涉及文件

- `include/config_parser.h` — `AppConfig` 加 `var_*` 字段；`path_var_t` / `has_path_var` / `parse_var_assignment` / `analyze_var_staticness` / `is_system_abs_path` 声明。
- `src/config/config_parser.c` — `has_path_var` / `parse_var_assignment` / `analyze_var_staticness` / `is_system_abs_path` 实现；赋值分支、`var_*` 生命周期、trie 判定收紧、REDIRECT 含 `$` 延迟归一、:463 绝对路径判定改用 `is_system_abs_path` 支持根目录。
- `src/daemon/vfs_core.c` — `pkg_resolvable` / `expand_path_vars`（静态/动态分支）/ `build_real_base_from_target`（延迟归一），4 处调用点改造，`vfs_fill_virtual_dirs` 签名加 `current_pkg`。
- 配置文档（若有）— 补充 `NAME=VALUE` 与 `$name`/`${name}` 语法说明。
