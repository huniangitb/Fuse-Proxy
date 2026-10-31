# 配置规范

`injector.conf` 的完整语法：段头、开关、规则、路径变量、禁忌。

## 1. 文件位置

| 用途 | 路径 |
|------|------|
| 主规则文件 | `<CONFIG_DIR>/injector.conf` |
| 远程存储服务器（FTP/SFTP） | `<CONFIG_DIR>/modules/ftp_module/ftp_module.conf`（语法见 `modules.md` §7.1） |
| 应用规则（uid 0） | `<CONFIG_DIR>/App-rules/<pkg>.conf` |
| 应用规则（其他用户） | `<CONFIG_DIR>/App-rules-<uid>/<pkg>.conf` |

**模块自有配置在模块目录下**（`<CONFIG_DIR>/modules/<模块名>/<模块名>.conf`）：
配置的**读取**由框架完成，读后经扁平视图下发给模块——模块不读文件、不跑 inotify
（见 `modules.md` §6.1.1）。写到别处不会被读取；模块会 loud 报出它期望的确切路径。
随包分发的 `ftp_module.conf` 是**空模板**：没有服务器条目，也没有注释示例——表单由
`MODULE_CONF_SCHEMA` 渲染、条目由 `MODULE_CONF_ADD/SET` 落盘，文件里的示例反而会被
解析器/前端当成真条目或已停用规则。

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
- **优先级：应用专属 > 类别 > GLOBAL**。REDIRECT/FTP 取首命中；HIDE/RO 取并集；MONITOR/SANDBOX 显式覆盖按同序（应用段 `SANDBOX OFF` 显式否决类别+全局）。同一作用域内**静态路径规则先于含通配/变量的规则**（Trie 命中即取，Trie 只是静态规则的加速索引）；跨作用域一律按上面的作用域顺序，**下层作用域的静态规则不得压过上层作用域的通配/变量规则**。
- **裸 `[<pkg>]` 是跨用户 fallback（user_id=-1），不是 user 0**：查找同名包时先精确匹配 `[<pkg>:<uid>]`，未命中再回退到 `[<pkg>]`。因此 `[com.tencent.mm]` 对 0/999 等所有用户生效，而 `[com.tencent.mm:999]` 只对 999 生效。注意这与 App-rules **文件目录**不同：uid 0 的规则文件放在 `App-rules/`（`0` 是目录默认值），不要据此把裸段头的 user_id 当成 0。
- 类别判定复用 `SKIP_SYSTEM_APPS` 逻辑：`pm list packages -s` 缓存（injector 落盘 `sys_pkgs.cache` 供 FUSE 侧只读），失败回退 `uid < 10000`。
- 包名不可解析时（`system`/`unknown`/过短/`zygote`）类别段不生效，仅 GLOBAL 适用。
- 类别段有实质规则（REDIRECT/HIDE/RO/SANDBOX）即视为点名注入（跳过 `SKIP_SYSTEM_APPS` 过滤）；段头 `OFF` 显式否决该类别注入。
- 类别段只写主文件；`GLOBAL_INJECT` / `SKIP_SYSTEM_APPS` / `FUSE_EXTRA_ARGS` / `SANDBOX_DIR` 仅 `[GLOBAL]` 段有效，写在别处忽略并告警。
- 活跃用户列表由 `scan_active_users` 经 `pm list users` 获取（失败回退 `/data/media` 扫描，再兜底 user 0）。

## 3. 开关项

取 `ON` 或 `1` 为开，其他值（含省略）为关。

| 开关 | 范围 | 说明 |
|------|------|------|
| `MONITOR` | 应用段 | 监控该应用的文件访问 |
| `SANDBOX` | 应用段 | 启用独立沙箱（隔离 `/Android/data`、`/Android/obb`） |
| `GLOBAL_INJECT` | 全局段 | 全局注入开关 |
| `SKIP_SYSTEM_APPS` | 全局段 | 跳过系统应用，默认 **ON**。zygisk 模块**不**再按 uid 硬编码过滤：除 `uid 0` 与 isolated 区（90000–99999）外一律上报，是否注入完全由本开关裁决——写成 OFF 时系统应用（如 uid 1000 的 Settings）才会被注入/还原 |
| `FUSE_EXTRA_ARGS` | 全局段 | 透传给 `fuse_daemon` 的额外参数（行尾原样，不分词，上限 512 字节）；其中 `-o negative_timeout[=N]` 会被单点剥离（恒为 libfuse 默认 0.0，非 0 负缓存以 ino=0 回包会触发内核 nodeid=0 崩溃） |
| `SANDBOX_DIR` | 全局段 | 沙盒落点目录名（覆盖默认 `sandbox`） |
| `ALLOW_CROSS_APP_DATA` | 全局段 | 跨应用隔离放宽开关，默认 **OFF**（=隔离生效：`/Android/data|obb/<他包>` 既**不可列举也不可打开**）。写 `ON` 恢复旧行为（只过滤列举、不限制打开），是跨应用隔离的**唯一逃生阀**，见 §4.1 |

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

> 内置隐藏：`CONFIG_DIR` 下所有访问无条件返回 ENOENT；应用访问 `/Android/data/<其他包>/`、`/Android/obb/<其他包>/` 自动判为其他应用（跨应用隔离，**列举与打开同口径**，见 §4.1）。

### 4.1 跨应用隔离

生效范围只有 `Android/data` 与 `Android/obb`（`media`/`obj` 不在其中——历史就没有隔离，扩范围会改变既有行为）。隔离与 `HIDE` **同口径**：`resolve`（getattr/open）与 `probe`（readdir 条目过滤）走同一个隐藏判定出口，所以「看不见 = 打不开」；旧实现只在列举侧过滤，任何按名打开的命令都能读到内容。

- **放行**：目标目录名等于调用方**基础包名**（`com.x:push` 与 `com.x` 同包）时放行；调用方包名不可解析（`system`/`unknown`，即 root 与系统工具）不隔离；`[GLOBAL] ALLOW_CROSS_APP_DATA ON` 全局放行。
- **与 `SANDBOX ON` 的关系**：沙盒生效的调用方被豁免——它的 `Android/data|obb` 访问本就会被 `SANDBOX` 重定向进**自己的**沙盒镜像（读不到他包内容），判成 ENOENT 只会让镜像路径整体不可用；列举侧仍按隔离过滤（保持既有行为）。
- **边界（共享 uid）**：`uid.map` 是「uid → 单个包名」，若两个非系统应用共享 uid（旧 `sharedUserId`，API 29 起废弃），A 进程访问 `/Android/data/B` 会被判成「他包」而返回 ENOENT。这类设备很少见，逃生阀同上（写 `ALLOW_CROSS_APP_DATA ON`；或用 `ALLOW /Android/data/B` 类规则——规则放行的是**路径**，与调用方身份无关）。
- **代价**：隔离开启时 `Android/data|obb` 子树不做 backing 直通（该子树必须由 daemon 按调用方裁决），即这部分 I/O 回到全量仲裁路径；`ALLOW_CROSS_APP_DATA ON` 后恢复按规则细分的 backing 直通。

> **`REDIRECT <vpath> <target>` 的 `<vpath>` 会遮蔽同名的真实条目**：该名字在列举里由虚拟目录提供（内容取 `<target>`），底层若存在同名文件/目录则不再单独列出——否则会出现「列表里是真实目录、`stat` 却落到重定向目标」的不一致；虚拟前缀的父目录在底层缺失时也会被合成为目录。`<target>`（真实目标）**不受影响**，仍是普通路径，照常列举与访问。

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
- **可见性（三层作用域 × 变量段，**此前未文档化的实际语义**）**：`fw_rules.c` 在三个求值入口传给 `expand_path_vars` 的「应用段」参数各不相同，故同一变量在不同规则来源下是否可见并不一致：
  - **应用段规则**（`[<pkg>]`）→ 传该应用自己的 `AppConfig`，故**能**看到自己的应用变量与 GLOBAL 变量。
  - **类别段规则**（`[USER_APPS]` / `[USER_APPS:<uid>]` / `[SYSTEM_APPS]`）→ **同样传类别段自己的 `AppConfig`**；类别段内定义的变量属类别私有，**应用变量对类别规则不可见**（类别规则不能用「当前应用」的变量）。
  - **全局段规则**（`[GLOBAL]`）→ 传全局 `AppConfig`，故只能看到 GLOBAL 变量，**看不到任何应用变量**。
  - 变量查找顺序恒为「传入的段 `AppConfig` → `global_cfg`」（`lookup_var`），`$package` 单独走 `current_pkg`（不经变量表，故在上述三层都可用）。
  - 因此：**应用变量只能被该应用自己的段规则看到**；类别/GLOBAL 规则写 `$APP_VAR` 时若该变量未在对应段定义，将保留字面（未定义变量语义）而非展开成当前应用的值。需要「随应用变化」的规则请写在**应用段**或用 `$package`。
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
- **注释掉的规则行不是「隐形」的**：rule_server 的 `classify_line` 会剥掉行首 `#` 再
  按已注册类型匹配，`#` 后紧跟规则关键字（如 `# HIDE /sdcard/x`）的行会作为
  **已停用规则**（`enabled:false`）出现在 `GET` 应答里、由前端列出。所以**不要**把示例
  规则以注释形式留在配置文件里——随包分发的 `injector.conf` 因此只留开关行。

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
| `SANDBOX_DIR` 写在应用段/类别段 | 只写 `[GLOBAL]` 段 | 仅全局段有效，写在别处忽略并告警（`config_parser.c` 的 `SANDBOX_DIR` 分支）；目录名须单级、不含 `/`、上限 63 字节 |
| `SANDBOX_TARGET = <路径>` | 用 `[GLOBAL]` 段的 `SANDBOX_DIR` 改目录名 | 无此配置项；沙盒落点固定为 `<STORAGE_BASE>/<uid>/Android/data/<pkg>/<SANDBOX_DIR 或 sandbox>`，不能改成任意路径 |
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
