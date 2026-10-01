# 配置规范

`injector.conf` 的完整语法：段头、开关、规则、路径变量、禁忌。

## 1. 文件位置

| 用途 | 路径 |
|------|------|
| 主规则文件 | `<CONFIG_DIR>/injector.conf` |
| 应用规则（uid 0） | `<CONFIG_DIR>/App-rules/<pkg>.conf` |
| 应用规则（其他用户） | `<CONFIG_DIR>/App-rules-<uid>/<pkg>.conf` |

`CONFIG_DIR` Android 为 `/data/Namespace-Proxy`、GNU 为 `/var/fuse-proxy`（见 `include/nsp_constants.h`，`common.h` 以别名暴露）。目录名约定：**uid 0 用 `App-rules`，uid 非 0 用 `App-rules-<uid>`**（由 `nsp_app_rule_dir` 合成）。主文件先加载，再扫描各 `App-rules*/` 目录；一个 `<pkg>.conf` 对应一个应用；目录缺失时仅 injector 会创建（只读加载方不 mkdir）。

**所有功能都可只写在单一 `injector.conf` 内**（全局段 + 各应用段并列），规则膨胀后再平滑迁移到分文件，解析语义一致。

## 2. 段头

| 写法 | 含义 |
|------|------|
| `[GLOBAL]` | 全局段，对所有应用生效 |
| `[<pkg>]` | 应用段，如 `[com.tencent.mm]`（省略 `:uid` 记为 **user_id=-1**，跨用户 fallback，见下） |
| `[<pkg>:<uid>]` | 指定用户的应用段，如 `[com.tencent.mm:999]`（多开/分身常用） |
| `[USER_APPS:<uid>]` | 类别段：该用户全部**用户应用**；裸 `[USER_APPS]` 对所有用户生效 |
| `[SYSTEM_APPS]` | 类别段：全部**系统应用**（忽略 uid；带 `:uid` 会被归一并告警） |

- 段头后可加 `ON` / `OFF` 控制该段是否注入使能，缺省为 **ON**。解析器只识别紧跟 `]` 后（忽略空格）的 `ON` / `OFF`，其他字符按默认 ON。
- **优先级：应用专属 > 类别 > GLOBAL**。REDIRECT/FTP 取首命中；HIDE/RO 取并集；MONITOR/SANDBOX 显式覆盖按同序（应用段 `SANDBOX OFF` 显式否决类别+全局）。
- **裸 `[<pkg>]` 是跨用户 fallback（user_id=-1），不是 user 0**：查找同名包时先精确匹配 `[<pkg>:<uid>]`，未命中再回退到 `[<pkg>]`。因此 `[com.tencent.mm]` 对 0/999 等所有用户生效，而 `[com.tencent.mm:999]` 只对 999 生效。注意这与 App-rules **文件目录**不同：uid 0 的规则文件放在 `App-rules/`（`0` 是目录默认值），不要据此把裸段头的 user_id 当成 0。
- 类别判定复用 `SKIP_SYSTEM_APPS` 逻辑：`pm list packages -s` 缓存（injector 落盘 `sys_pkgs.cache` 供 FUSE 侧只读），失败回退 `uid < 10000`。
- 包名不可解析时（`system`/`unknown`/过短/`zygote`）类别段不生效，仅 GLOBAL 适用。
- 类别段有实质规则（REDIRECT/HIDE/RO/SANDBOX）即视为点名注入（跳过 `SKIP_SYSTEM_APPS` 过滤）；段头 `OFF` 显式否决该类别注入。
- 类别段只写主文件；`GLOBAL_INJECT` / `SKIP_SYSTEM_APPS` / `FUSE_EXTRA_ARGS` 仅 `[GLOBAL]` 段有效，写在别处忽略并告警。
- 活跃用户列表由 `scan_active_users` 经 `pm list users` 获取（失败回退 `/data/media` 扫描，再兜底 user 0）。

## 3. 开关项

取 `ON` 或 `1` 为开，其他值（含省略）为关。

| 开关 | 范围 | 说明 |
|------|------|------|
| `MONITOR` | 应用段 | 监控该应用的文件访问 |
| `SANDBOX` | 应用段 | 启用独立沙箱（隔离 `/Android/data`、`/Android/obb`） |
| `GLOBAL_INJECT` | 全局段 | 全局注入开关 |
| `SKIP_SYSTEM_APPS` | 全局段 | 跳过系统应用，默认 **ON** |
| `FUSE_EXTRA_ARGS` | 全局段 | 透传给 `fuse_daemon` 的额外参数（行尾原样，不分词，上限 512 字节） |

`MONITOR` / `SANDBOX` 在应用段**显式写一次即覆盖全局**（`*_explicit` 标记），不存在"继承全局后再覆盖"的中间态。开关词法唯一出处 `nsp_switch_on()`（`ON`/`1` 为开）。

`MONITOR` 的三层合并（应用显式 > 类别显式 > `[GLOBAL]`；`[USER_APPS[:uid]]` / `[SYSTEM_APPS]` 均参与）由**框架**统一计算，与规则模块是否加载无关：模块未加载/被 ban、路径无 `<uid>/` 用户层、模块未命中规则时同样算得对。若把开关绑在"模块是否给出有效决策"上，这些情形下文件读写一切正常、IO 监控日志却静默消失且无任何提示（历史缺陷）。框架为此自建一份配置索引并自行解析 uid→包名（`uid.map` → `/proc` 回退，见 `architecture.md` §2.2）；包名不可解析（`system`/`unknown`/过短/`zygote`）时只认 `[GLOBAL]`，与模块侧同一 fail-safe 口径。

注入方法为 `v3` 时（`injector --inject-method=v3`，见 `architecture.md` §5.1），`GLOBAL_INJECT` / `SKIP_SYSTEM_APPS` **不参与目标判定**——含系统应用在内一律经项目 FUSE；应用段与类别段头的 `OFF` 仍然生效。

## 4. 四类规则

| 规则 | 语法 | 语义 |
|------|------|------|
| 隐藏 | `HIDE <path>` | 应用看不到该路径（返回 ENOENT） |
| 只读 | `RO <path>` | 该路径对应用只读（写操作返回 EROFS） |
| 放行 | `ALLOW <path>` | 显式放行：等价"重定向回自身真实存储"（parse 生成 `?<path>` 内部前缀） |
| 重定向 | `REDIRECT <vpath> <target>` | 应用访问 `<vpath>` 实际落到 `<target>` |

> 内置隐藏：`CONFIG_DIR` 下所有访问无条件返回 ENOENT；应用访问 `/Android/data/<其他包>/`、`/Android/obb/<其他包>/` 自动判为其他应用（跨应用隔离，仅作用于列举）。

> **`HIDE` 的 errno 在所有操作上统一为 `ENOENT`**（含 `mkdir`/`create`/`unlink`/`chmod` 等写类操作）。早期版本写类操作用 `EACCES`，同一条 `HIDE` 声明会因操作类别不同而产生两种 errno；自 ABI V3 起由框架单点强制（`fw_route`）统一为 `ENOENT`，与「存在变不存在」的语义一致。若前端曾按 `EACCES` 判定隐藏路径，需改为按 `ENOENT` 判定。

后端模块可追加规则类型（如 FTP 模块的 `FTP <虚拟前缀> <段名>`），见 `modules.md` §2.1。

### 路径前缀归一

底层真实物理存储固定为 `/data/media/<user_id>`（`STORAGE_BASE`）。配置中的路径按下表归一：

| 写法 | 归入 |
|------|------|
| `Android/data/foo`（相对，无前导 `/`） | 当前用户存储 `/data/media/<user_id>/Android/data/foo` |
| `/storage/emulated/0/xxx` | 归一为当前用户存储（剥离 `/storage/emulated/<N>`） |
| `/sdcard/xxx` | 当前用户存储（走"其他以 `/` 开头"分支，非前缀剥离） |
| `/data/...`、`/mnt/...`、`/storage/...` | 绝对路径原样（`is_system_abs_path`） |
| `?/xxx` | 当前用户存储（内部前缀，parse 阶段自动生成，无需手写） |

- 路径不以 `/` 或 `*` 开头时自动补前导 `/`；不含通配符的路径自动去尾部 `/`。
- `REDIRECT` 的真实目标含变量时原样存入，分类延迟到运行时 `build_real_base_from_target`。

## 5. 路径变量

### 系统变量

`$package`：当前命中 uid 对应的包名（已去掉 `:process` 后缀）。解析顺序：`uid.map` 二分查询 → `/proc/<tid>/status` 的 `Tgid` → `cmdline`；uid<10000 直接判为 `system`。

含 `$package` 的规则在包名不可解析时（为 `system`/`unknown`/空、长度<3、含 `zygote`/`<pre-`）**自动失效**（跳过），走默认 fallback。

`$uid` / `$user_id` 等其他系统变量**未实现**，禁止使用。

### 自定义变量

段内用 `NAME=VALUE` 定义（**紧凑形式，`=` 两侧无空格**，由 `parse_var_assignment` 识别）：

```
[GLOBAL]
DATA_BASE=/sdcard/Android/data/$package
MNT_BASE=/mnt/sdcard/$package
```

- **作用域**：`[GLOBAL]` 段为全局共享，应用段为该应用专属并覆盖全局同名变量（`lookup_var` 先查应用、再查全局）。
- **值引用**：可引用其他变量（含 `$package`），运行时递归展开（`expand_into`，最大 32 层）。循环引用（`A=$B` + `B=$A`）自动检测，保留字面不展开。
- **保留名**：`package` 禁止覆盖（告警并忽略）。
- **VALUE 语义**：取 `=` 后行尾原样内容（含空格），不剥离行内注释——`VAR=/x # 备注` 的值是 `/x # 备注`。

### 引用语法

- `$name`：常规引用，如 `$package`、`$DATA_BASE`。
- `${name}`：边界明确，如 `${package}_suffix`。
- 变量名 `[A-Za-z_][A-Za-z0-9_]*`，大小写敏感；未定义变量与未闭合 `${name` 均保留字面。

### 限制与自动优化

- **虚拟前缀侧（REDIRECT 第一参数、HIDE/RO/ALLOW 的路径）不支持 `$package`**——含变量的规则无法写入 Trie，仅存线性数组，匹配效率低于纯路径规则。
- 加载时 `analyze_var_staticness` 自动分析：静态变量（值与传递闭包均不含 `$package`）预计算缓存到 `var_resolved[]`；动态变量每次请求展开。迭代收敛，用户无需关心。

## 6. 通配符与注释

- 支持 `*` `?` `[` `]`（POSIX fnmatch），仅虚拟前缀侧可用。`[` `]` 无转义机制，需匹配字面方括号时避免使用。
- `#` **只能在行首**作整行注释（行首可有空格）。**行内 `#` 不是注释**，会被并入规则。

```
HIDE /Android/data/com.foo/*
HIDE /sdcard/DCIM/[Pp]hotos
# 这是整行注释
HIDE /secret   # 这不是注释，会被并入规则
```

## 7. 禁忌清单

| ❌ 错误写法 | ✅ 正确写法 | 原因 |
|------------|-----------|------|
| `$package` 出现在 REDIRECT 虚拟前缀侧 | 虚拟前缀用纯静态路径，`$package` 只放 target 侧 | 含变量无法入 Trie |
| `package=xxx` | 换其他变量名 | `package` 是保留名 |
| `$uid`、`$user_id` | 按当前用户存储约定写路径 | 未实现 |
| `VAR = /x`（带空格） | `VAR=/x` | 变量定义必须紧凑形式 |
| 路径含行内 `#` 当注释 | 另起一行 `#` 注释 | 解析器不剥离行内 `#` |
| 单行超 2048 字节 | 整行删除或缩短后重载 | 超长行整行跳过（告警），不参与匹配 |
| 路径超 255 字符 | 缩短路径 | `MAX_PATH_LEN=256` |
| 包名超 127 字符 | 校验包名长度 | 结构体上限 128 |
| `SANDBOX_TARGET` / 自定义沙箱目录 | 仅用 `SANDBOX ON` | 未实现，路径固定 `/Android/data/<pkg>/sandbox` |
| 应用段写 `MONITOR OFF` 期望继承全局 | 全局段写 `MONITOR OFF`，或应用段显式写所需值 | 应用段显式写即覆盖全局 |
| `FUSE_EXTRA_ARGS` 写在应用段 | 仅写 `[GLOBAL]` 段 | 应用段无该字段 |
| 期望 `/sdcard` 原样保留 | 知悉其归一到当前用户存储 | `strip_storage_prefix` 不处理 `/sdcard` |

## 8. 完整示例

```ini
# <CONFIG_DIR>/injector.conf —— 单文件全量配置

[GLOBAL]
GLOBAL_INJECT ON
SKIP_SYSTEM_APPS ON
FUSE_EXTRA_ARGS --strip-o-direct

DATA_BASE=/sdcard/Android/data/$package

REDIRECT /files   $DATA_BASE/files
HIDE     $DATA_BASE/private
RO       $DATA_BASE/cache
ALLOW    /system/fonts

[com.tencent.mm] ON
MONITOR ON
SANDBOX OFF
HIDE /sdcard/Tencent/MicroMsg/*/credential

[com.tencent.mm:999] ON
# 仅对多开实例 999 生效
SANDBOX ON

[USER_APPS:0] ON
# user 0 全部用户应用（类别段 target 侧可用 $package）
HIDE $DATA_BASE/private

[SYSTEM_APPS] ON
RO /system/fonts

[com.termux] OFF
# 已声明关闭注入，下列规则不会生效
```

同一包可多次出现段头（含不同 `:uid`），规则在各自作用域内累积；段顺序不限，`[GLOBAL]` 通常置首。

## 9. 参考

- 实现：`src/config/config_parser.c`、`src/config/path_vars.c`
- 测试：`tests/test_rules.py`、`tests/test_path_vars.py`
- 规则匹配与真实目标分类的运行时行为：`architecture.md` §4
