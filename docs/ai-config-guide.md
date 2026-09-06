# Fuse-Proxy 配置规范
---

## 1. 文件位置

| 用途 | 路径 |
|------|------|
| 主规则文件 | `/data/Namespace-Proxy/injector.conf` |
| 应用规则（user 0） | `/data/Namespace-Proxy/App-rules/<pkg>.conf` |
| 应用规则（多用户） | `/data/Namespace-Proxy/App-rules-<uid>/<pkg>.conf` |

- 一个 `<pkg>.conf` 对应一个应用。
- 缺失目录会自动创建，无需手动建。
- 主文件先加载，再扫描各 `App-rules*/` 目录。

---

## 2. 段头写法

| 写法 | 含义 |
|------|------|
| `[GLOBAL]` | 全局段，规则对所有应用生效 |
| `[<pkg>]` | 应用段，如 `[com.tencent.mm]` |
| `[<pkg>:<uid>]` | 指定多用户的应用段，如 `[com.tencent.mm:10]`、`[com.tencent.mm:999]` |
| `[USER_APPS:<uid>]` | 类别段：该用户全部**用户应用**，如 `[USER_APPS:0]`；省略 `:uid`（裸 `[USER_APPS]`）时对所有用户生效 |
| `[SYSTEM_APPS]` | 类别段：全部**系统应用**（忽略 uid，对所有用户系统应用生效；带 `:uid` 会被归一并告警） |

- 类别判定复用 `SKIP_SYSTEM_APPS` 逻辑：`pm list packages -s` 缓存（injector 查询并落盘
  `sys_pkgs.cache` 供 FUSE 侧只读），失败回退 `uid < 10000`；无表时等价于回退。
- 优先级：**应用专属 > 类别 > GLOBAL**（REDIRECT/FTP 取首命中，HIDE/RO 取并集，
  MONITOR/SANDBOX 显式覆盖按同序，ALLOW 豁免同序；应用段 `SANDBOX OFF` 显式否决类别+全局，
  类别段 `SANDBOX OFF` 显式否决全局）。
- 包名不可解析时（`system`/`unknown`/过短/`zygote` 等）类别段不生效，仅 GLOBAL 适用。
- 注入判定：类别段有实质规则（REDIRECT/HIDE/RO/SANDBOX）即视为点名注入（跳过
  `SKIP_SYSTEM_APPS` 过滤）；段头 `OFF` 则显式否决该类别注入（含通配/全局）。
- 类别段只写主文件（`App-rules/` 分文件暂不支持，写了也会被归一读取——建议只写主文件）。
- `GLOBAL_INJECT` / `SKIP_SYSTEM_APPS` / `FUSE_EXTRA_ARGS` 仍仅 `[GLOBAL]` 段有效，
  写在其他段会被忽略并告警。

- 段头后可加 `ON` / `OFF` 控制该段是否注入使能：
  ```
  [com.tencent.mm] ON
  [com.termux] OFF
  ```
- 缺省 `ON` / `OFF` 时段头默认 **ON**（即 `[com.tencent.mm]` 等价于 `[com.tencent.mm] ON`）。解析器只识别紧跟 `]` 后（忽略空格）的 `ON` / `OFF` 前缀，其他字符视为默认 ON。
- 省略 `:uid` 时作用于 user 0。
- **`:uid` 可取任意活跃用户 ID**（如 `999`），规则仅对该用户生效；多开/分身场景常用此形式区分同一包的不同实例。活跃用户列表由 `scan_active_users` 通过 `pm list users` 获取（失败时回退到 `/data/media` 扫描，再兜底 user 0）。

---

## 3. 开关项

所有开关取 `ON` 或 `1` 为开，其他值（含省略）为关。

| 开关 | 作用范围 | 说明 |
|------|----------|------|
| `MONITOR` | 应用段 | 监控该应用的文件访问；应用段显式写一次即覆盖全局（`monitor_explicit`） |
| `SANDBOX` | 应用段 | 为该应用启用独立沙箱；应用段显式写一次即覆盖全局（`sandbox_explicit`） |
| `GLOBAL_INJECT` | 全局段 | 全局注入开关 |
| `SKIP_SYSTEM_APPS` | 全局段 | 是否跳过系统应用，默认 **ON**（`load_config_rules` 初始化为 true）。判定走 `pm list packages -s` 缓存（`load_system_pkg_cache`，命中即系统应用）；`pm` 不可用时回退到 `uid < 10000` |
| `FUSE_EXTRA_ARGS` | 全局段 | 透传给 `fuse_daemon` 的额外命令行参数（读取行尾原样内容，不做分词；上限 512 字节） |

写法示例：

```
[GLOBAL]
GLOBAL_INJECT ON
SKIP_SYSTEM_APPS ON
FUSE_EXTRA_ARGS --strip-o-direct

[com.tencent.mm]
MONITOR ON
SANDBOX OFF
```

> 注：`FUSE_EXTRA_ARGS` 的值是 `=` 后行尾原样内容（含内部空格），解析器不剥离行内注释——如 `FUSE_EXTRA_ARGS --foo # bar` 的值是 `--foo # bar`。

---

## 4. 四类规则

| 规则 | 语法 | 语义 |
|------|------|------|
| 隐藏 | `HIDE <path>` | 应用看不到该路径（返回 ENOENT） |
| 只读 | `RO <path>` | 该路径对应用只读（写操作返回 EROFS） |
| 放行 | `ALLOW <path>` | 显式放行：等价于"重定向回自身真实存储"，parse 阶段生成 `?<path>` 内部前缀 |
| 重定向 | `REDIRECT <vpath> <target>` | 应用访问 `<vpath>` 实际落到 `<target>` |

> 内置隐藏：`CONFIG_DIR`（`/data/Namespace-Proxy`）下所有访问无条件返回 ENOENT；应用访问 `/Android/data/<其他包>/`、`/Android/obb/<其他包>/` 自动判为其他应用并隐藏（跨应用隔离）。

### 路径前缀约定

底层真实物理存储固定为 `/data/media/<user_id>`（`STORAGE_BASE` 常量）。配置中的路径前缀按下表归一：

| 写法 | 归入 |
|------|------|
| `Android/data/foo`（相对，无前导 `/`） | 当前用户存储 `/data/media/<user_id>/Android/data/foo` |
| `/storage/emulated/0/xxx` | 归一为当前用户存储（剥离 `/storage/emulated/<N>` 前缀） |
| `/sdcard/xxx` | 当前用户存储（`strip_storage_prefix` 仅处理 `/storage/emulated/`，`/sdcard` 走相对路径分类） |
| `/data/...`、`/mnt/...`、`/storage/...`（含根目录本身） | 绝对路径原样（`is_system_abs_path`） |
| `?/xxx` | 当前用户存储（项目内部前缀，由 parse 阶段对 ALLOW/相对路径自动生成，一般不需手写） |

- 路径若不以 `/` 或 `*` 开头，会自动补前导 `/`。
- 不含通配符的路径会自动去掉尾部 `/`。
- `REDIRECT` 的真实目标含变量时原样存入，路径分类延迟到运行时 `build_real_base_from_target`。

示例：

```
HIDE /Android/data/com.secret/cache
RO   /system/fonts
REDIRECT /sdcard/MyApp   /storage/emulated/0/MyApp
ALLOW /system/fonts
```

---

## 5. 路径变量

### 系统变量

| 变量 | 含义 |
|------|------|
| `$package` | 当前命中应用包名（运行时按 uid 解析，已去掉 `:process` 后缀） |

### 自定义变量

在段内用 `NAME=VALUE` 定义（**紧凑形式，`=` 两侧无空格**）：

```
[GLOBAL]
DATA_BASE=/sdcard/Android/data/$package
MNT_BASE=/mnt/sdcard/$package
```

- 值可引用其他变量（含 `$package`），运行时递归展开。
- 循环引用（`A=$B` + `B=$A`）自动检测，保留字面不展开。
- **保留名 `package` 禁止覆盖**，违反时告警并忽略。

### 引用语法

| 写法 | 含义 |
|------|------|
| `$name` | 常规引用，如 `$package`、`$DATA_BASE` |
| `${name}` | 边界明确，如 `${package}_suffix` |

- 变量名规则：`[A-Za-z_][A-Za-z0-9_]*`，大小写敏感。
- 未定义变量保留字面 `$name` 不替换。

### 作用域与限制

- 写在 `[GLOBAL]` 段为全局共享；写在应用段为该应用专属，**覆盖全局同名变量**。
- **虚拟前缀侧（REDIRECT/HIDE/RO/ALLOW 匹配路径的那一侧）不支持 `$package`**——含变量的规则无法写入 Trie（仅存线性数组），匹配效率低于纯路径规则。
- `$uid` / `$user_id` 等其他系统变量**暂未实现**，禁止使用。
- 含 `$package` 的规则在包名不可解析时（`pkg_resolvable` 返回 false：包名为 `system`/`unknown`、长度<3、含 `zygote`/`<pre-`）**自动失效**（跳过），走默认 fallback。

示例：

```
[GLOBAL]
DATA_BASE=/sdcard/Android/data/$package

REDIRECT /files   $DATA_BASE/files
HIDE     $DATA_BASE/private
RO       $DATA_BASE/cache
```

---

## 6. 通配符

- 支持 `*` `?` `[` `]`（POSIX fnmatch 语义）。
- **虚拟前缀侧（REDIRECT 的第一参数、HIDE/RO/ALLOW 的路径）不限制通配符**，但含通配符的规则匹配效率低于纯路径规则。
- `[` `]` 亦作 fnmatch 字符类，需匹配字面方括号时暂无转义机制，避免在路径中使用。

示例：

```
HIDE /Android/data/com.foo/*
HIDE /sdcard/DCIM/[Pp]hotos
```

---

## 7. 注释规则

- `#` 只能在**行首**作整行注释，行首可有空格。
- **行内 `#` 不是注释**，会被当作规则的一部分处理。

```
# 这是整行注释
HIDE /secret   # 这不是注释，会被并入规则
```

---

## 8. 禁忌清单

| ❌ 错误写法 | ✅ 正确写法 | 原因 |
|------------|-----------|------|
| `$package` 出现在 REDIRECT 虚拟前缀侧 | 虚拟前缀用纯静态路径，`$package` 只放 target 侧 | 虚拟前缀侧不支持 `$package`，含变量无法入 Trie |
| `package=xxx` | 避免覆盖，用其他变量名 | `package` 是保留名，禁止覆盖 |
| `$uid`、`$user_id` | 无替代，按当前用户存储约定写路径 | 这些系统变量未实现 |
| `VAR = /x`（带空格） | `VAR=/x` | 变量定义必须紧凑形式，`=` 两侧无空格（`parse_var_assignment`） |
| 路径含行内 `#` 当注释 | 行内 `#` 不是注释，需另起一行 `#` 注释 | 解析器不剥离行内 `#` |
| 单行超过 2048 字节 | 拆成多行 | 解析缓冲区上限 2048 |
| 路径超过 255 字符 | 缩短路径 | `MAX_PATH_LEN=256` |
| 包名超过 127 字符 | 校验包名长度 | 结构体上限 128 |
| `SANDBOX_TARGET` / 自定义沙箱目录 | 仅用 `SANDBOX ON` | 自定义沙箱目录未实现，路径固定为 `/Android/data/<pkg>/sandbox` |
| 应用段写 `MONITOR OFF` 期望继承全局 | 全局段写 `MONITOR OFF`，或应用段显式写所需值 | 应用段显式写即覆盖全局（`*_explicit` 标记），不会"继承后再覆盖" |
| `FUSE_EXTRA_ARGS` 写在应用段 | 仅写在 `[GLOBAL]` 段 | 应用段无 `fuse_extra_args` 字段，仅全局生效 |
| 期望 `/sdcard` 在配置里原样保留 | 知悉 `/sdcard/xxx` 走相对路径分类，会落到当前用户存储 | `strip_storage_prefix` 不处理 `/sdcard`，归 `build_real_base_from_target` 的"其他以 `/` 开头"分支 |

---

## 9. 快速配置（仅用 injector.conf）

不想分多文件时，**所有功能都可写在单一 `injector.conf` 内**：全局段 + 各应用段 + 多用户段并列，无需创建任何 `App-rules*/<pkg>.conf`。

适用场景：规则总量少、应用数不多、不追求按应用拆文件维护。

```
# /data/Namespace-Proxy/injector.conf  —— 单文件全量配置

[GLOBAL]
GLOBAL_INJECT ON
SKIP_SYSTEM_APPS ON
DATA_BASE=/sdcard/Android/data/$package

REDIRECT /files   $DATA_BASE/files
HIDE     $DATA_BASE/private
RO       $DATA_BASE/cache

[com.tencent.mm] ON
MONITOR ON
HIDE /sdcard/Tencent/MicroMsg/*/credential

[com.tencent.mm:999] ON
# 仅对多开实例 999 生效
SANDBOX ON
HIDE /sdcard/Tencent/MicroMsg/999/private

[USER_APPS:0] ON
# user 0 全部用户应用：隐藏各应用私有目录（类别变量 target 侧可用 $package）
HIDE $DATA_BASE/private

[SYSTEM_APPS] ON
# 全部系统应用：只读保护系统字体
RO /system/fonts

[com.termux] OFF
# 已声明关闭注入，下列规则不会生效
```

约定：

- 单文件内段顺序不限，但 `[GLOBAL]` 通常置首以利阅读。
- 同一包可多次出现段头（含不同 `:uid`），规则在各自作用域内累积。
- 若日后规则膨胀，可平滑迁移到 `App-rules*/<pkg>.conf` 拆文件，解析语义一致。

---

## 10. 完整示例

```
# /data/Namespace-Proxy/injector.conf

[GLOBAL]
GLOBAL_INJECT ON
SKIP_SYSTEM_APPS ON

DATA_BASE=/sdcard/Android/data/$package
MNT_BASE=/mnt/sdcard/$package

REDIRECT /files   $DATA_BASE/files
HIDE     $DATA_BASE/private
RO       $DATA_BASE/cache
ALLOW    /system/fonts

[com.tencent.mm]
MONITOR ON
SANDBOX OFF
HIDE /sdcard/Tencent/MicroMsg/*/credential
RO   /system/fonts
```

---

## 11. 自检清单

写完配置后逐条核对：

- [ ] 段头格式正确：`[GLOBAL]` / `[<pkg>]` / `[<pkg>:<uid>]` / `[USER_APPS:<uid>]` / `[SYSTEM_APPS]`，段头缺省 ON/OFF 时默认 ON
- [ ] 开关值只用 `ON` / `1`（开）或省略/其他（关）
- [ ] `FUSE_EXTRA_ARGS` 仅写在 `[GLOBAL]` 段
- [ ] `HIDE` / `RO` / `ALLOW` / `REDIRECT` 关键字拼写无误
- [ ] `REDIRECT` 第二参数含 `$package` 时，第一参数（虚拟前缀）不含 `$package`
- [ ] 变量定义紧凑：`NAME=VALUE`，`=` 两侧无空格（`parse_var_assignment`）
- [ ] 未覆盖保留名 `package`
- [ ] 未使用未实现的 `$uid` / `$user_id` / `SANDBOX_TARGET`
- [ ] 所有路径 ≤ 255 字符，单行 ≤ 2048 字节
- [ ] 行内无 `#` 当注释；整行注释 `#` 在行首
- [ ] 多用户段 `[<pkg>:<uid>]` 的 `uid` 与目标用户一致（`pm list users` 输出的活跃用户）
- [ ] 沙箱路径勿手写——`SANDBOX ON` 自动重定向到 `/Android/data/<pkg>/sandbox`
