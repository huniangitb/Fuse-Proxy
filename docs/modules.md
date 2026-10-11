# 热插拔模块架构与开发

`fuse_daemon` 是框架：FUSE 回调骨架 + 路径清洗 + **规则决策（内建 `fw_rules.c`）** + 后端分派 + 本地存储原语。**V4 起模块只有一种形态——后端存储提供者**（如 FTP）：规则决策、uid→包名、MONITOR 开关都是框架能力（放进模块会让"模块缺席 ⇒ 规则与监控一起失效"）。第三方模块**只以 `include/nsp_module.h` 为唯一入口**（该头代含 `nsp_log.h` / `nsp_constants.h` / `nsp_cfg_view.h`，见 §6.1），可在独立仓库独立编译。

## 1. 设计要点

- **规则内建**：REDIRECT/SANDBOX/HIDE/ALLOW/RO 与 FTP 前缀归属由框架解释（`fw_rules_resolve`），与模块无关；无后端模块时框架直接操作本地文件系统（`module_backend_active()` 快速路径，零函数指针调用）。
- **只有后端形态**：模块声明 `backend_match` 即被认作后端；不再有能力位图/模块类型需要与实现保持一致的冗余声明。
- **热插拔**：`.so` 放入模块目录即加载，删除即卸载，覆盖即重载，不中断已挂载的 FUSE。
- **内存副本加载**：模块经 `memfd_create` + `/proc/self/fd/N` dlopen，映像只属于本进程（`/proc/<pid>/maps` 显示为 `memfd:nsp_module_<名>`）。因此磁盘上那份 `.so` 无论**原子替换**（tmp+rename）还是**就地覆盖**（truncate + 重写）都不会破坏运行中的模块——后者曾是崩溃源：ELF 按文件 mmap，truncate 会连已重定位的私有页一起丢弃，再次缺页读到的是未重定位的链接期值（函数指针变垃圾），连 `dlclose`/进程退出的析构调用都会野指针跳转。检测到文件变化后按新内容重载（旧映像 `dlclose`）。
- **后端不实现 FUSE**：模块只提供 `backend_*` 操作方法，FUSE 由框架统一实现。

## 2. 模块目录约定

```
<MODULES_DIR>/<模块名>/<模块名>.so      # 模块本体（dlopen 进 fuse_daemon）
<MODULES_DIR>/<模块名>/<模块名>.rules   # 可选：模块声明（rule_server 读取）
                                        #   [TYPE] 段 = 规则类型注册
                                        #   [conf] 段 = 模块配置 schema（见 §2.2）
<MODULES_DIR>/<模块名>/<模块名>.conf    # 可选：模块自有配置（框架读取后下发）

- Android：`/data/Namespace-Proxy/modules`；GNU：`/var/fuse-proxy/modules`（`--modules-dir=` 可覆盖）。
- 模块名仅含 `[a-z0-9_-]`，**目录名 = 模块名 = `.so` 文件名 = `NspModuleInfo.name`**，不一致拒绝加载。

### 2.1 规则类型注册（`.rules`）

模块可放置 `<模块名>.rules` 向 **rule_server** 声明自己支持的规则类型，实现「前端可操作的规则随模块动态追加」。conf 段格式（推荐）：

```ini
[FTP]
format = pair
argc = 2
desc = 存储映射：<虚拟前缀>|<段名>
desc.en = Storage mapping: <virtual prefix>|<section>
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
- **内置类型随 rule_server 二进制内嵌**（`rule_server.c` 的 `BUILTIN_RULE_TYPES`，即原 `basic_rules.rules` 的内容）：HIDE/RO/REDIRECT/ALLOW/MONITOR/SANDBOX/GLOBAL_INJECT/SKIP_SYSTEM_APPS 的 format/argc/global-only/多语言 desc 都在那里声明，走**与模块 `.rules` 完全相同的解析器**——规则引擎已内建进框架，模块目录里不再有 `basic_rules.rules`，若改成在 C 里裸注册类型名，内建类型的 `desc` 会全空（前端按 desc 渲染类型说明）。改内建类型说明即改该处。未注册的类型前端无法 ADD/REMOVE/ENABLE/DISABLE；无 `.rules` 的模块正常加载，仅跳过类型注册。
### 2.2 模块配置 schema（`.rules` 的 `[conf]` 段）

模块用同一个 `.rules` 文件的 `[conf]` 段声明**自己配置文件的字段契约**，语法与
`[TYPE]` 段同一解析器（`conf.<字段>.<属性>=值`）：

```ini
[conf]
conf.host.type = string          # string / int / bool / path
conf.host.maxlen = 255           # 字节上限（string/path 用；缺省不限制）
conf.host.required = true        # 新建条目时必填（控制面强制，不只是前端提示）
conf.host.desc = 服务器地址       # 中文标签（默认语言）
conf.host.desc.en = Host         # 指定语言标签
conf.port.type = int
conf.port.range = 1:65535        # int 值域闭区间（min:max）
conf.port.default = 21           # 缺省值（LIST/GET 回填生效值并记入 derived）
conf.port.default.proto.sftp = 22  # 条件缺省：依赖字段 proto=sftp 时缺省 22
conf.proto.enum = ftp|sftp       # 可选值（竖线分隔），越界即拒
conf.password.sensitive = true   # 敏感：只写不读，仅回 has_password
conf.key_file.order = 7          # 前端显示顺序
```

- `default.<依赖字段>.<取值>` 声明**条件缺省**（缺省随另一字段取值而变），命中时覆盖
  `default`。依赖字段自身也可缺省（取其 `default`），且与两者在文件里的书写顺序无关。
  它必须与模块自己的推导一致——这是同一发布物内的两处声明（例：`ftp_module` 的
  `port` 在 `proto=sftp` 时缺省 22，与 `ftp_conf.c` 的 `ftp_conf_parse_end` 同口径）。
- `max` 是旧写法（按已声明的 `type` 解释：`string/path` = 字节上限、`int` = 值域上界），
  新声明请用 `maxlen` / `range`——两者不混用，前端按 `type` 取对应键。

由此得到两条能力：

- **新增配置项不必改 C**：控制面按 schema 校验 `MODULE_CONF_ADD/SET`（键白名单、
  长度上限、类型、值域、枚举都来自声明），不必重新编译发布。声明文件撤掉即回退编译期
  默认表；**未声明任何字段的模块不放行写入**（fail-closed）。
- **前端自动渲染**：`MODULE_CONF_SCHEMA` 回传 `{file, module,
  fields:[{key, type, maxlen|min+max, required, sensitive, default, default_if?,
  enum?, order, desc, desc_map}]}`，前端据此渲染数字框 / 开关 / 密码框（带脱敏）/
  下拉，并自动带上 `maxlength`——**不必另维护中文标签与顺序**。`default` 按 `type`
  给 JSON 型别（`int`→数字、`bool`→布尔、其余→字符串），与 LIST/GET 里的实际值同型。

### 2.3 控制面命令（通用 + FTP 别名）

`MODULE_CONF_*` 按 `module` 参数寻址**任意模块**的配置；`FTP_*` 是向后兼容别名
（等价 `module=ftp_module`），既有前端/脚本零改动继续可用。

| 通用命令 | 别名 | 参数 | 说明 |
|---|---|---|---|
| `MODULE_CONF_SCHEMA` | `MODULE_SCHEMA` | `module`、`lang` | 取该模块的字段契约（前端渲染用，含 `default_if` 条件缺省） |
| `MODULE_CONF_LIST` | `FTP_LIST` | `module` | 列出配置里的条目（段名即条目名，跳过 `[GLOBAL]`；每条含 `derived`） |
| `MODULE_CONF_GET` | `FTP_GET` | `module`、`name` | 读单个条目（含 `derived`） |
| `MODULE_CONF_ADD` | `FTP_ADD` | `module`、`name`、`fields` | 新建/更新条目（空值 = 不写该键；新建须给齐 `required`；幂等：同值 → `duplicate:true` 免写） |
| `MODULE_CONF_SET` | `FTP_SET` | `module`、`name`，加 `key`+`value` **或** `fields` | 改字段：空值/纯空白 = 删键回缺省（`int` 同样可删）；`fields` 形态可**一次请求内既写字段又删键**，原子落盘 |
| `MODULE_CONF_REMOVE` | `FTP_REMOVE` | `module`、`name` | 删条目 |

**应答信封（rule_server 全部命令，含规则 `ADD`/`SET`/`REMOVE`/…）**：统一回
`{status, command, data|error, timestamp}`，其中 `command` **必须等于本次请求的 `cmd`**
（不是相近命令的名字——`SET` 曾因内部转发而复用 `ADD` 的应答串，客户端只校验 `status`
才没暴露；契约上按「同名回显」判）。

约束：

- **`module` 必填校验**：只接受 `[A-Za-z0-9_-]`、长度 <64。模块名直接参与
  `<CONFIG_DIR>/modules/<名>/<名>.conf` 路径拼接，故 fail-closed 拒绝 `..` 与路径
  分隔符，防止越出模块目录。缺省为 `ftp_module`（使通用命令与别名行为一致）。
- **字段一律经 schema 校验**，与 `MODULE_CONF_SET` 共用同一校验函数：未知键、
  超长、类型不符、值域越界、枚举越界即整体拒绝，不部分写入。**`int` 字段写规范十进制**
  （`"007"` → `7`），ADD 与 SET 同口径——不再按字段名特判 `port`。
- **空值语义（ADD 与 SET 不同，别记反）**：
  - `MODULE_CONF_SET` 传空值（含纯空白）= **删键回缺省**。该分支在值校验**之前**，
    故 `int` 字段同样删得掉（否则会被判「须为整数」而永远删不掉，缺省也就永远回不去）。
  - `MODULE_CONF_ADD` 传空值 = **不写该键**（走模块缺省），不落 `key = ` 空行——模块
    读侧对空值多判非法而**整段作废**。要清掉已有的键请用 SET，不要用 ADD 传空。
- **`MODULE_CONF_SET` 支持 `fields` 形态（一次请求既写又删）**：
  `{"cmd":"MODULE_CONF_SET","name":N,"fields":{"host":"h","user":"","port":""}}`
  —— 非空值写、空值删，正是**表单整体保存**需要的语义（改了的写、清空的删），
  不必拆成 N 个请求，也不会有「先写后删」的中途状态：全部先解析校验，再统一落盘
  一次；任何一个键非法即整条请求拒绝，文件逐字不动。应答
  `{file, name, keys:[本次写入的键], deleted:[本次删除的键], changed}`；单字段形态
  另回 `key`（既有前端契约不变）。`fields` 为空对象 → 明确拒绝（不静默回 `ok`）。
- **`required` 由控制面强制**：新建条目缺 `required` 字段即拒。模块侧对缺必填字段的段
  整段作废，落一个「看不见的坏段」不如当场拒绝。
- **条目回读形状**：`{name, <各字段生效值>, has_<敏感字段>, derived:[…]}`。`derived`
  列出**文件里没有、值来自 schema 缺省**的键（含条件缺省），前端据此区分「已显式配置」
  与「缺省生效」。字段有键则原样回读（含空值/越界值——那是文件的真实内容，前端凭
  `min`/`max` 自行标记，控制面不替模块「修正」值）。
- **敏感字段**（`sensitive`）在应答里**键本身不出现**，只给 `has_<键名>` 布尔；
  写入时按 `password` 归一并清 `pass` 别名。
- **散字段形态仍兼容但已通用化**：`{"cmd":"MODULE_CONF_ADD","name":N,"host":…,"port":…}`
  按 schema **逐字段拾取**（不再硬编码 5 个字段名），声明了的新字段（`proto`/`key_file`
  …）照样能写。请求信封自带的键（`cmd`/`module`/`name`/`lang`/`key`/`value`/`fields`）
  不参与拾取——模块若真有同名字段，用 `fields` 对象给值。

前端适配：

- 用 `MODULE_CONF_SCHEMA` 拿字段契约（不要硬编码字段名/上限/顺序），按 `order`
  排序渲染，`type` 决定控件（`int`→数字框并带 `min`/`max`、`enum`→下拉、`sensitive`→
  密码框且只提交不读回、`bool`→开关），`maxlength` 取 `maxlen`，标签取 `desc`
  （可带 `lang`）。`desc_map` 给全语言切换，`default_if` 给条件缺省的 placeholder。
- 写操作改用 `MODULE_CONF_ADD`（`fields` 对象）与 `MODULE_CONF_SET`；`FTP_*`
  继续可用，建议新前端直接用通用命令，未来新模块无需改前端。
- **整体回写必须按 `derived` 过滤**：只提交不在 `derived` 里的键（或只提交用户改动过的
  字段）。把缺省值一并写回会把「缺省生效」物化成显式键——例如 `proto=sftp` 的段被写上
  `port = 22`，此后再改 `proto=ftp` 仍连 22 端口。这是「读回再整体回写」写坏 SFTP
  配置的根因。
- **表单保存用一次 `MODULE_CONF_SET` + `fields`**：用户清空的字段传空串（= 删键），
  改动的传新值；新建条目走 `MODULE_CONF_ADD`（`fields`，空值 = 不写）。这样一次请求
  就表达了「写哪些 + 删哪些」，落盘一次完成。

三条边界（不得越界）：

1. schema **只服务控制面校验与前端渲染**，不改变配置读取归属：框架依旧把原始行
   原样下发、模块自己解析（§6.1.1）。别让 schema 变成「框架替模块解析配置」。
2. 敏感字段沿用并升级既有「密码只写不读」：此前只有 `password` 一个键享受特判，
   现按 `sensitive` 判定，新增敏感字段自动脱敏；敏感字段的**键本身不出现在应答里**，
   只给 `has_<key>` 布尔。
3. schema 随 `.rules` 的 mtime 缓存一同失效重建：**撤掉 `[conf]` 段即回退默认表**，
   绝不沿用上次扫描残留的字段声明（声明始终是唯一来源）。

- **`log_ctl` 与 `rule_server` 的类型集合刻意不同**：`rule_server` 是权威控制面，内置类型内嵌 + 读取 `.rules` 合并模块动态类型；`log_ctl` 的 `set-rule`/`remove-rule` 只认内置类型（HIDE/RO/REDIRECT/ALLOW/MONITOR/SANDBOX/GLOBAL_INJECT，不含 SKIP_SYSTEM_APPS），不扫描模块目录。两者对同一内置类型的编辑语义一致（行级实现共享，见 §6.1）。

## 3. 模块 ABI（`include/nsp_module.h`）

当前 `NSP_MODULE_ABI_VERSION = 5`、`NSP_FRAMEWORK_API_VERSION = 4`。

**V3 是决策结果的不兼容重构**：`NspResolveResult` 被声明式的 `NspPathDecision` 取代，模块只声明「这个路径该怎么表现」，errno 映射与权限策略全部收归框架单点（`fw_route` 强制 appear_missing/read_only，只读判定统一走 `vfs_check_read_only`；V3 时代另有属性覆盖的落实函数，已随 V4 删除）。字段变化：

| 删除 | 新增/替换 | 理由 |
|---|---|---|
| `hidden` | `appear_missing` | 语义不变，但强制统一为 ENOENT（见下） |
| `ro` | `read_only` | 语义不变，强制统一为 EROFS |
| `is_virtual_ancestor` + `is_redirect_target` | `virtual_kind`（`NSP_VK_NONE/ANCESTOR/TARGET`） | 两个并列 bool 合并为单枚举，合并策略明确（ANCESTOR 优先）。命名沿用历史：`TARGET` 指该路径**本身是重定向的虚拟前缀**，与"重定向的真实目标"无关（见 `architecture.md` §4.6） |
| `is_redir` | `is_redirect` | 仅改名 |
| `user_id` / `sub_path` | —（框架自算） | 框架的 `fw_parse_path` 与模块侧剥离逻辑逐行等价，无需跨 ABI 传递；结果结构由 8336 降到约 4.2KB |
| — | `attr_override` + `mode`/`uid`/`gid`（V4 已删，理由见 `src/daemon/fw_rules.h` 的 `NspPathDecision` 注释） | 模块可覆盖权限位与属主（见 §3.3 历史记录） |

**V4 删除了 `pkg` / `monitor_on` / `get_pkg`**：包名与 `MONITOR` 都是配置语义的输入，模块缺席时必须仍有正确值，故早已归框架——包名由 `fw_pkg.c` 自算（`uid.map` → `/proc` 回退），`MONITOR` 由 `fw_config_monitor_for` 自算三层合并（应用 > 类别 > 全局）。`monitor_on` 也不再由决策结构承载（`fw_route` 经出参单独给出，它本就不是路径决策）。

**V3 的行为变更（有意）**：`appear_missing` 在**所有**回调统一返回 `ENOENT`。V2 时代读类回调是 `ENOENT`、写类回调是 `EACCES`，同一声明产生两种结果；统一后与「存在变不存在」的语义一致。若前端曾依赖写类路径的 `EACCES`，需按 `ENOENT` 调整。

**注意两个版本号是不同的命名空间**：`NSP_MODULE_ABI_VERSION`（本次 4→5，破坏性，须重编译）与 `NSP_FRAMEWORK_API_VERSION`（`NspFrameworkApi` 的版本，尾部兼容演进，自身不要求重编译）互不相干。**框架 API V4 是尾部兼容新增**（`subscribe_rules` / `set_config_listener`），故框架 API 这一侧不要求重编译。`NspFrameworkApi` 只保留框架真正消费的字段（`api_version` / `get_rules_path` / `subscribe_rules` / `set_config_listener`）；日志由 `nsp_log.h` 的 `log_internal(LogLevel)` 统一提供。V2 删除了中间字段（`log` / `get_real_root`、`NspResolveResult` 的 `allow`/`has_redir`/`redir_target`/`has_sandbox`/`sandbox_target`/`is_other_app_pkg`/`ftp_backend`、`ops` 的 `get_vars`/`reload` 等）。**按新版头重编译是硬要求**：加载器按 `abi_version` 精确匹配，V1/V2/V3/V4 一律拒载（见下方加载校验顺序、§6.5）。

加载校验顺序（`module_prepare`）：稳定性校验 → 读入内存副本 → `dlopen` → `dlsym(nsp_module_info)` → 魔数/ABI 版本 → 名字一致 → `init`。框架只校验"模块是否可用"，不做内容哈希。**ABI 校验发生在 `dlopen` 之后**：`RTLD_NOW` 会立即解析模块的全部符号，V1 模块引用已删除的导出符号时可能在 ABI 检查之前就解析失败；模块的构造器也已在 `dlopen` 期间运行。因此"拒绝旧 ABI"是加载失败，不是加载前拦截。

### 3.1 类型与能力位（V4 已删，历史保留）

> V4 起 `NspModuleInfo` 已无 `type`/`caps` 字段：现行模块形态只由 `ops` 决定（声明了 `backend_match` 即后端模块），见 `include/nsp_module.h` 的 `NspModuleInfo` 定义。下表仅为 V3 及以前的历史记录，重编译须删掉这两处赋值。

<!-- history:begin V3 及以前的 type/caps 位图，仅作迁移参照，勿照此写新模块 -->

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

<!-- history:end -->

### 3.2 框架服务表 `NspFrameworkApi`（框架 → 模块）

`init` 时注入，模块**仅经它取用框架参数**（版本化，兼容新增字段追加尾部）：

```c
typedef struct NspFrameworkApi {
    uint32_t api_version;                       /* NSP_FRAMEWORK_API_VERSION */
    const char* (*get_rules_path)(void);        /* 规则配置路径（--rules） */
    /* ---- API V4 追加（尾部新增，旧模块按 api_version 决定是否使用）---- */
    void (*subscribe_rules)(const char* const* types, int count);   /* 声明申请的规则类型 */
    void (*set_config_listener)(void (*cb)(const NspModuleConfig*)); /* 配置下发回调 */
} NspFrameworkApi;
```

现行字段仅 `get_rules_path` / `subscribe_rules` / `set_config_listener`（对照 `include/nsp_module.h:90-108`）：`get_flags` 随 V4 与规则模块一起删除（唯一消费者是规则决策，框架不再提供）。

- `api_version` 是模块 `init` 的第一道自检（如 `ftp_module` 在 `api->api_version < NSP_FRAMEWORK_API_VERSION` 时拒绝初始化）。
- 日志**不再经服务表**：`nsp_module.h` 代含 `nsp_log.h`，模块直接调用 `log_internal(LogLevel, ...)` / `LOG`/`LOG_WRN`/`LOG_ERR`/`LOG_DBG` 宏，与框架同一套 `LogLevel`（0=DEBUG 1=INFO 2=WARN 3=ERROR）。真实存储根不再经服务表暴露——路径合成用导出表里的 `common_default_real_path` / `common_sandbox_path`（见 §6.1）。

### 3.3 接口表 `NspModuleOps`（模块 → 框架）

所有字段可选，未实现置 NULL。返回 `0` 成功 / **负值 errno** 失败。

> V4 起只剩 `backend_*`（历史记录）：`resolve` / `probe` / `readdir_extra` 随规则引擎内建一起删除，决策结构 `NspQueryCtx` / `NspPathDecision` / `NspProbeResult` 已搬进 `src/daemon/fw_rules.h`，不再是 ABI。以下 `resolve` / `probe` / 属性覆盖段落仅为 V3 及以前的历史语义，现行模块不要实现它们。

<!-- history:begin V3 规则模块的 resolve/probe/属性覆盖语义，仅作迁移参照 -->

规则模块（V4 已删，历史保留）：

```c
int (*resolve)(const NspQueryCtx* q, NspPathDecision* out);  /* 路径决策，一次调用返回全部声明式决策 */
int (*probe)(const NspQueryCtx* q, NspProbeResult* out);      /* readdir 逐条目轻量过滤 */
int (*readdir_extra)(const NspQueryCtx*, const char* sub_path, int user_id,
                     const char* pkg, bool is_root, NspDirEntry* out, int max);
```

`resolve` 输入 FUSE 原始路径 + uid/pid/gid，输出**声明式决策**：`valid` / `appear_missing` / `read_only` / `attr_override`+`mode`/`uid`/`gid` / `virtual_kind` / `real_path` / `is_redirect` / `is_ftp`——**一次调用返回全部决策**，保住「一次查询多路复用」的性能语义。ALLOW 与 SANDBOX 不单独回传：模块已把它们落实进 `real_path`。`probe` 只判 `valid`/`appear_missing`/`virtual_kind`/`is_other_app_pkg`，不构建真实路径、不触发 sandbox 目录创建。

**强制由框架单点完成**（`src/daemon/fuse_daemon.c` 的 `fw_route`），模块不参与 errno 决策：

| 声明 | 框架行为 |
|---|---|
| `appear_missing` | 所有回调统一 `ENOENT`（含写类；V2 写类为 `EACCES`） |
| `read_only` | 变更操作统一 `EROFS`；root 豁免由框架持有。`open`/`access` 是否算"写"由 `flags`/`mask` 判定（`O_RDONLY` 打开只读路径必须放行） |
| `attr_override` | 位图（`NSP_OV_MODE`/`NSP_OV_UID`/`NSP_OV_GID`），默认 0 = 不改——故 `memset(out, 0, sizeof *out)` 这类零初始化是安全的。在框架既有属性来源**之后**应用，模块的显式声明优先于框架默认（底层真实属性、虚拟目录继承上级、FTP 继承用户存储根）。`mode` 只取 `07777`，`S_IFMT` 类型位一律忽略 |

> **属性覆盖为何用位图而非"特殊值哨兵"**：若用 `mode == UNSET`/`uid == -1` 表示"不改"，模块惯用的 `memset` 零初始化会静默变成"权限清 0 + 属主 root"。位图让"零初始化 = 什么都不改"成立。

> **初始化不变量**：`resolve` 输出必须**逐字段**重置，不能只置 `valid=false`。FUSE 回调在模块未命中时仍会读 `read_only`/`is_ftp`/`virtual_kind` 等标志；历史上"未命中只置 valid + 固定栈填充恰好稳定"曾把不存在的路径合成为目录，逐字段初始化是回归防线。（规则内建后此事归 `fw_rules_resolve` 单点，见 `architecture.md` §7。）

<!-- history:end -->

后端模块（现行唯一形态——声明了 `backend_match` 即后端模块，无需任何类型/能力位声明）：

```c
int (*backend_match)(const char* path);        /* 1=管理该路径（前缀匹配） 0=否 */
int (*backend_getattr)(const char* path, struct stat* st);
/* V5 分页：跳过前 offset 条，填 ≤max 条；0=到末尾，<0 errno。
   超长名（≥256）整条跳过，禁止截断安装。 */
int (*backend_readdir)(const char* path, NspDirEntry* entries, int max, uint64_t offset);
int (*backend_open)(const char* path, int flags, uint64_t* h);
int (*backend_create)(const char* path, mode_t mode, uint64_t* h);
int (*backend_read)(uint64_t h, char* buf, size_t size, off_t off, size_t* got);
int (*backend_write)(uint64_t h, const char* buf, size_t size, off_t off, size_t* wrote);
int (*backend_flush)(uint64_t h);              /* 收尾数据但保留句柄 */
int (*backend_release)(uint64_t h);            /* 句柄销毁唯一入口 */
int (*backend_unlink/mkdir/rmdir/rename/truncate)(...);
```

`backend_flush` 与 `backend_release` 的分工是易错点：FLUSH 可因 dup/fork **多次调用**，只能收尾数据（如上传完成），销毁必须等 RELEASE。**FLUSH 之后句柄仍可写**——第一次 FLUSH 把当前数据同步到后端，之后从存活的 fd 继续写入的数据必须由后续 FLUSH/RELEASE 继续同步；把「已同步」写成一次性开关（置位后写路径或补传路径早退）会让后半段数据静默丢失（FTP 后端 `uploaded` 曾如此：`tests/test_ftp.py` 的 dup/close 用例守护）。

**列目录分页（V5）**：框架按 256 条/页、`offset` 累加逐页拉取，直到短页/0 页或 filler 满——FTP 大目录无条数上限（V4 的 512 整批上限会静默丢尾）。FTP 后端以单条目 LIST 缓存服务后续页（同目录翻页零额外 LIST；变更成功后失效）；`VFS_READDIR_MAX_TOTAL=65536` 是恶意后端无限产条目的 DoS 熔断（超限 `E2BIG` loud 报错，正常走不到）。

**内核断点续扫**：单目录一次列不完时内核带 `offset`（上次收到的条目 `off`）再次调用；所有发射经 `vfs_emit` 单点编号（`off` 从 1 起），`offset>0` 时跳过去重后的前 `offset` 个条目（后端路径含点条目，后端分页起点同步对齐，免空翻页）。旧实现忽略 `offset` 且 `filler off` 全 0，大目录尾部丢失/重复。

### 3.4 后端分派与句柄编码

框架 vfs 回调解析出 real_path 后，若规则模块 resolve 命中 FTP 规则（`rr.is_ftp`）且 `backend_match(path)==1`，则改调模块方法；否则本地文件系统直通（`module_backend_active()` 保证零开销）。路径参数为框架解析后的真实路径（如 `/mnt/nsp_ftp/云盘/xxx`），模块自行剥离前缀。

模块返回的句柄 `h` 被框架编码进 FUSE `fi->fh`，供 read/write/release 无锁快速分派：

| 位段 | 含义 |
|------|------|
| `bit40` | 后端句柄标志 `NSP_FH_BACKEND_FLAG`（与本地 fd 区分） |
| `bit41-50` | 模块槽位（V5 注册表动态化，硬上限 1024，10 位） |
| `bit0-39` | 后端句柄 ID（`NSP_FH_HANDLE_MASK` 还原） |

**模块侧须保证句柄 ID 落在 bit0-39 内**——Android tagged-pointer 对 top byte 会 SIGABRT，高位一律保留给框架。bit51-55 空闲。

## 4. 加载与热插拔

1. `module_system_init(rules_path, modules_dir)`：mkdir 模块目录 → 全量扫描 → 启动 inotify 监控线程。
2. 每个 `<name>/<name>.so`：0.5s 文件稳定性校验（防加载半写入的 .so）→ **读入内存副本**（`memfd_create` + 写入）→ 再校验文件未在读取期间变化 → `dlopen("/proc/self/fd/<fd>", RTLD_NOW|RTLD_LOCAL)` → `dlsym(nsp_module_info)` → 校验魔数/ABI 版本/名字一致 → `init(api)`（经围栏）→ 登记注册表（**该 memfd 保持打开到模块卸载**：它是模块唯一可执行映像的 `memfd:nsp_module_<名>` 可观测证据）。顺序见 §3：ABI 校验在 `dlopen` 之后、`init`/`ops` 之前。内容哈希校验（含旧"模块自哈希"与框架侧 memfd 复验）已整体弃用：相对热加载收益是无效工作，版本区分由 ban 记录的 mtime 承担；`.banned` 里残留的旧哈希格式行会在命中时视为 stale 自动清除。
3. 两层 inotify 监听：顶层管子目录增删（+ `.banned` 等顶层文件），每个合法模块子目录各一个 watch 管各自 `.so` 变更（inotify 不递归，子目录 watch 补上这一层）。任何变更必有事件，扫描只由事件触发（1s 归并窗口合并一次拷贝的多个事件），**稳态零唤醒、无周期扫描**；仅当上次扫描留下延迟工作（quiescence 推迟的卸载/重载、拷贝中途的瞬时失败）或 watch 建不全时，才按 5s 间隔定时重试回到稳态。
4. 模块变更**不再经 IPC 上报 injector**：`fuse_daemon` 的规则/后端分派走槽位原子快照，热插拔即时生效，无需 injector 重挂。`LIST_MODULES` 仍可查询当前模块列表（由 injector 扫描模块目录应答，与 fuse_daemon 的加载约定一致）。

## 5. 故障隔离（框架层防护）

框架对全部模块调用（`backend_*`/`init`/`exit`）做三层防护，**模块错误不会带崩 fuse_daemon**：

1. **调用围栏**（`src/module/fault_fence.c`）：每 worker 线程一套 TLS `sigsetjmp` 围栏；`sigaltstack` 是 **per-thread** 的——`fault_fence_init` 设置的全局 altstack 只覆盖主线程，每个首次调用围栏的线程还会为自己设置独立 TLS altstack（worker 不继承主线程的 altstack）。调用窗口内崩溃（SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT）→ 归因到肇事模块槽位 → `siglongjmp` 恢复，daemon 存活、该请求按 `-EIO` 失败。归因失败（如堆损坏延迟到框架代码爆发）走原 `crash_dump` 链路。
2. **输出校验**（`src/module/module_guard.c`）：跨 ABI 的字符串只剩后端 `readdir` 的条目名，故校验面也只剩两个——`nsp_guard_str_ok`（字符串 NUL 终止）与 `nsp_guard_dir_entry_ok`（readdir 单条目）。规则决策不再跨 ABI（引擎已内建），**决策结构的 canary 哨兵与值域校验随之删除**（见 `include/module_guard.h` 顶部说明）。
3. **熔断器**：每模块滑动窗口（默认 10 秒 5 次错误，env `NSP_GUARD_WINDOW_SEC` / `NSP_GUARD_ERR_MAX` 可覆盖）触发即 `module_fault_poison`——槽位置空（该模块规则立即全部失效，走直通回退）+ 卸载 + ban 落盘。崩溃单次即置毒。**`backend_*` 的 errno 风格返回码（`-1..-4095`）不计入**：后端模块以返回码回传业务失败（`-ENOENT` 路径不存在、`-EPERM` 命令被拒、`-ENOTEMPTY` 目录非空、`-EIO` 后端暂不可达）是其唯一通道；若计入，应用扫描缺失路径（`os.path.exists`、文件管理器存在性探测）十秒内即可打满阈值，把健康模块置毒 + ban（文件不变则不再重载）。豁免判定见 `fuse_daemon.c` 的 `backend_rc_is_business()`，回归用例见 `test_module_circuit.py` §9。V4 起规则引擎内建，`resolve`/`probe` 已不在 ABI 中——熔断只对后端模块生效。

**ban 机制**：记录写 `<MODULES_DIR>/.banned`（每行 `模块名|mtime|原因|时间戳`）。扫描线程或热重载前先按文件 mtime 查 ban（`module_ban_blocks`）：一致即跳过（加载与重载都不做），mtime 变化（发布新版本）记录失效，**版本更新自愈**；daemon 重启后 ban 仍有效。

**加载前就被拒的情形同样落 ban**（`module_prepare` 内）：`abi_version` 不匹配、内部 `name` 与目录名不一致——这两种都发生在 `dlopen` 之后、`commit` 之前，槽位从未建立，若只报错不落 ban，每次事件扫描就重试一轮（0.5s 稳定性等待 + 整份 `.so` 复制进新 memfd），并**每次泄漏一个内存副本 fd**（实测残留旧 ABI 模块时每次扫描漏 1 个，累积到 nofile 上限后 socket/open 全面 EMFILE）。现落 ban 后只报一次（`检测到新模块` + 具体原因 ERROR + 一次 `ban 名单命中` WARN），之后静默跳过；日志按 `(模块名, 文件 mtime)` 去重，文件一变重新提示一次（`sys.log` 里 DEBUG 不受最小级别过滤，靠降级日志级别解决不了刷屏）。`module_prepare` 的所有失败路径经 `module_prepare_reject()` 统一回收 memfd。ban 记录**含框架 ABI 字段**（见 §3 末）：**框架升级到新 ABI 后这些 ban 自动失效**，用户不必手工删 `.banned`。

**旧模块残留**：框架内建规则引擎后 `basic_rules` 已退役，而 `CONFIG_DIR/modules/` 不在 Magisk 模块目录内，卸载/更新都不会清它，安装脚本此前只 `cp` 不删 → 旧 `.so` 会永久留在设备上（症状就是启动后反复出现 `模块 basic_rules ABI 不匹配`）。现两条一起处理：**打包时**由 `scripts/pack-module.sh` 按本次构建的模块清单（`KNOWN_MODULES`，源自 `MODULE_PAIRS`）清掉骨架 `bin/modules/` 下不在清单内的目录，使发布包里不含退役模块；框架侧按上面的 ban 机制兜底（用户手动放进设备的坏模块同理）。注意两者作用域不同：脚本只管**发布包内容**，设备上 `CONFIG_DIR/modules/` 里用户自放的模块由 ban 机制处理，脚本不会去删。回归用例见 `test_modules.py` §5。

**排障入口**：`log_ctl search-sys --level 2 MOD_ERR <模块名>` 按模块过滤结构化错误行（`module=/op=/rc=/path=/detail=`）。窗口内前 5 条明细全打、之后每 100 条打 1 条汇总，坏模块不会淹没日志环；熔断与崩溃恢复两类高危事件无条件追加到 `<LOG_DIR>/module_errors.log`；崩溃转储附 `Crash attribution: module=<名> slot=<N> op=<op>` 归因行。`module_health_snapshot()` 输出每模块 `err_count`/`err_total`/`banned`/`ban_reason`/`last_err_time` 供前端展示。

## 6. 开发第三方模块

### 6.1 依赖与前置

- **唯一接口头**：`include/nsp_module.h`，源码只依赖本头 + 标准库。该头**代含** `nsp_log.h`（`LogLevel` 与 `log_internal`）、`nsp_constants.h`（`NSP_CONFIG_DIR`/`NSP_STORAGE_BASE`/`NSP_LOG_DIR` 等共享常量）与 `nsp_cfg_view.h`（配置下发视图 `NspCfgRec`/`NspModuleConfig`）；分发 SDK 时必须把这三个代含头一并给出，否则模块无法编译。
- **许可证**：框架以 GPL-3.0-or-later 发布，但**对模块 ABI 授予链接例外**——仅通过本头文件公开 ABI 结合的独立模块，可按任意条款发布（含闭源），不因此受 GPL 约束。前提是不编入框架源码、不依赖本头以外的内部头、不引用未声明的内部符号。**代含的 `nsp_log.h` / `nsp_constants.h` / `nsp_cfg_view.h` 同属公开 ABI 头**，链接例外同样覆盖。完整条款见 `LICENSE.module-exception`。
- **编译宏**：必须定义 `-DNSP_MODULE_BUILD`，激活头内「模块公共运行时 ABI」段（`LogLevel`/日志宏、平台常量、框架导出符号声明）。框架自身 TU 不定义该宏，声明与宏以 `common.h` 为准。
- **运行时符号**：日志/路径等框架符号经 fuse_daemon 的 `-Wl,--export-dynamic` 导出表在 dlopen 时解析，模块无需链接框架，**不得把 `src/core/common.c` 等框架源编入自身**。模块也**不链接 `nsp_comm`**——统一通讯线程是框架各进程的内部设施，不属于模块 ABI。
- **公开 ABI 只有 `nsp_module.h` 及其代含头**，不包含任何 `src/` 下的项目工具。`nsp_util`（`nsp_mkdir_p`、`nsp_set_thread_name`、App-rules 路径合成等）**不是 SDK 公共 ABI**：树内以 GPL 发布的模块可以链接它，但**第三方模块若要保留链接例外，就不能因此 include `nsp_util.h` 或编入任何项目源码**——例外只覆盖 `nsp_module.h` 声明的接口（含代含的 `nsp_log.h`/`nsp_constants.h`/`nsp_cfg_view.h`），越界即落入 GPL（见 `LICENSE.module-exception` 的「独立模块」定义）。通用 INI 段式存储（`nsp_ini_open/...`）与规则文件行级读写（`nsp_rule_file.h`）同样**不在模块 ABI 内**：`nsp_ini_store` 是 rule_server 的私有静态库（log_ctl 不使用），`nsp_rule_file` 是 rule_server/log_ctl 的控制面共享实现，两者都不经 `nsp_module.h` 暴露。

### 6.1.1 配置读取归属（V4）

**读取完全由框架完成**：框架读 `injector.conf`、`App-rules*`，以及各模块的
自有配置 `<modules_dir>/<模块名>/<模块名>.conf`，完成行级词法
（去注释/首尾空白）与段头识别（`[段]` / `ON|OFF` / `:uid`），产出扁平记录视图
（`NspCfgRec`：段头、规则行、App-rules 文件归属、**模块配置文件标记与行**）。
**模块不读文件、不跑 inotify**——包括它自己的配置：`ftp.conf` 的读取与热重载
都由框架负责，模块只在 `set_config_listener` 回调里消费下发的行。

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

**模块自有配置的记录与过滤**（视图版本 2 追加）：

- `NSP_CFG_REC_MODULE_FILE`：`text` = 模块名，`file` = 该模块配置文件的**确切
  路径**。**无条件下发**——文件不存在时也发，故模块总能报出它期望的路径而不是
  猜一个。随后的 `NSP_CFG_REC_MODULE_LINE` 是框架读出的原始行（只去 `\r\n` 与
  首尾空白，**不剥注释、不切键值**：注释边界与键值语法是模块的配置语法）。
- 这两类记录**按 owner 过滤**：只下发给同名模块，其他模块看不到（配置隔离与
  规则隔离同等要求）。`subscribe_rules` 只作用于 RULE 记录，不影响模块拿回自己的配置。
- 配置内容逐字未变时模块可自行跳过重建（如 `ftp_module` 按行取指纹）——他人配置
  变化同样会触发回调，无谓重建会波及在途句柄。

> 注意：`uid.map`（uid→包名）与 `sys_pkgs.cache`（系统应用表）**框架与模块各自读取**
> （它们不是规则配置而是数据表，故不经视图下发）：框架侧用于日志标签与 `MONITOR`
> 的三层合并（`fw_pkg.c`），模块侧用于 `$package` 变量展开与沙箱隔离。两侧都只读
> 文件、都不写，故无冲突。

### 6.2 最小骨架（V5 后端形态，照抄编译通过为准）

```c
#include "nsp_module.h"   /* 编译须带 -DNSP_MODULE_BUILD */

static int my_match(const char* path) { (void)path; return 0; }  /* 1=管理该路径 */
static const NspModuleOps g_my_ops = { .backend_match = my_match };

static int my_init(const NspFrameworkApi* api) {
    (void)api;                    /* 按需取用 get_rules_path / subscribe_rules / set_config_listener */
    return 0;                     /* 非 0 拒绝加载 */
}
static void my_exit(void) { /* 清理（可为 NULL） */ }

const NspModuleInfo nsp_module_info = {
    .magic       = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,    /* 必须匹配，否则拒绝加载 */
    .name        = "my_module",               /* 须与 .so 文件名/目录名一致 */
    .version     = "1.0.0",
    .init        = my_init,
    .exit        = my_exit,
    .ops         = &g_my_ops,                 /* 声明 backend_match 即后端模块，无 type/caps */
};
```

> V4 起 `NspModuleInfo` 已无 `.type` / `.caps`（见 `include/nsp_module.h` 的 `NspModuleInfo` 定义）：旧骨架照抄必编译失败，以本节为准。

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
- 输出字符串字段**必须 NUL 终止**：框架按 `nsp_guard_str_ok` / `nsp_guard_dir_entry_ok` 校验，不合法即计一次契约违规（累计触发熔断置毒）。
- 回调内**不得阻塞**：围栏窗口内不可恢复地持锁会破坏 longjmp 安全性（框架侧已保证分派路径不持锁）。
- 置毒时框架**仍会调用 `exit()`**（经围栏，崩溃会被 longjmp 收敛）——模块可能持有自己的 pthread，`exit` 是停掉它们的唯一途径，不调就 `dlclose` 会让残留线程踩空带崩 daemon。仅当 `exit` 自身崩溃（无法确认线程已停）才保留 `.so` 映射不 `dlclose`。因此模块 `exit` 必须幂等、且负责 join 自己创建的线程。

### 6.5 ABI 演进

| 场景 | 机制 |
|------|------|
| 不兼容变更（改表结构/删字段） | `NSP_MODULE_ABI_VERSION` 递增 → 旧模块被校验拒绝，须重编译 |
| 兼容新增框架能力 | `NspFrameworkApi` 尾部追加字段 + `NSP_FRAMEWORK_API_VERSION` 递增 |
| 新增模块方法 | `NspModuleOps` 尾部追加字段（模块未实现置 NULL，框架调用前判空）；改变既有方法签名属第一类 |
| 模块自身版本 | `NspModuleInfo.version` 字符串（不影响加载兼容性） |

ABI 从 1 到 2 的变更属于第一类：`NspFrameworkApi` 删除了中间的 `log`/`get_real_root` 字段，`NspModuleOps` 也删除了字段——**不是**仅尾部兼容扩展，故必须递增 ABI 版本并要求 V1 模块重编译（`NspResolveResult` 由 V1 的 16596 字节降到 V2 的 8336 字节）；V3 把 `NspResolveResult` 换成声明式的 `NspPathDecision`（结构降到约 4.2KB）并要求 V1/V2 重编译。校验拒绝发生在 `dlopen` 之后（见 §3），旧模块的构造器与 `RTLD_NOW` 符号解析会先于 ABI 检查执行。V4 属同类的**不兼容变更**（删 `NspPathDecision` 的 `pkg`/`monitor_on` 与 `NspModuleOps.get_pkg`），故递增到 4 并拒绝 V1/V2/V3。V5 同理（`backend_readdir` 加 `offset` 分页 + 超长名跳过语义），递增到 5 并拒绝 V1/V2/V3/V4——V4 模块无分页，大目录静默丢尾。

**注册表容量（V5）**：加载器注册表动态翻倍（初容 16，硬上限 1024，由 fh 槽位 10 位编码决定），无 16 上限静默拒载；静态快照数组（槽位原子快照/围栏/guard）按硬上限分配；无锁扫描只扫到高水位（`g_backend_hwm`，单调只增）。模块版本区分按 `.so` 文件 mtime 秒粒度（`st.st_mtime`）：同秒内替换不放行 ban、不触发重载，需 `touch` 续秒或等下次变化。**ban 记录还带框架 ABI 维度**（行末第 5 字段 = 落 ban 时的 `NSP_MODULE_ABI_VERSION`）：框架 ABI 与记录不同（或记录为无该字段的旧格式）即视为 stale 丢弃并放行——否则「旧框架因 ABI 不匹配落 ban → 用户升级框架到新 ABI」后，模块 mtime 未变、旧 ban 永久命中，**新框架明明支持该模块却再也加载不回来**（升级框架通常不会重装/触碰 `.so`）。`LIST_MODULES` 应答与模块配置里的服务器表、FTP 后端表同理动态化。模块配置失败闭合：段名≥64 字节或任一字段（`host`/`user`/`pass`/`remote_dir`）超长即整段作废，绝不带截断值连接；目录 `mtime` 回查的父级 `LIST` URL 组装失败亦直接返回失败，不拿截断 URL 列错目录。

## 7. 参考实现

| 模块 | 源码 | 说明 |
|------|------|------|
| 规则引擎（**非模块**） | `src/daemon/fw_rules.c` | V4 起规则决策内建进 fuse_daemon：Trie + 线性通道 / sandbox / 虚拟目录 / uid→AppConfig 缓存；配置由 `fw_config` 换入，引擎的派生缓存在发布临界区（旧读者排空、新读者封锁）内经 `config_set_publish_invalidate_hook` 作废（见 §6.1.1）。**它不是可插拔模块**——规则语义属于框架 |
| `ftp_module.so` | `src/modules/ftp/` | 远程存储后端（FTP 与 SFTP，libcurl，**不依赖 libfuse3**）：`ftp_mux.c` 是控制面「epoll + curl_multi」复用器（见下），`ftp_backend_libcurl.c` 是路径映射与读写实现（含协议分派、`backend_flush` 两阶段收尾与弱网重试）；写路径为本地临时文件缓存 + 流式 STOR/APPE（SFTP 下同为 `CURLOPT_UPLOAD`+`APPEND`）上传 |

**FTP 控制面并发模型（`src/modules/ftp/ftp_mux.c`）**：`getattr`/`readdir`/`DELE`/`MKD`/`RMD`/`RNFR`/空文件 `STOR`/`TRUNCATE` 等控制操作交给每后端一个 `CURLM` 句柄，由**一个 epoll 事件线程**驱动（`curl_multi_socket_action` + `CURLMOPT_SOCKET/TIMERFUNCTION` 接入 epoll；提交线程只入队 + eventfd 唤醒，绝不触碰 multi——libcurl 多接口非线程安全）。收益：控制连接在 multi 的连接缓存里长期复用（免重复 USER/PASS 登录），多个 FUSE 线程的控制操作并行在飞（同服务器并发控制连接上限 `CURLMOPT_MAX_HOST_CONNECTIONS`，默认 4），且**业务失败不再重建连接**——旧实现在任何失败（含 550 不存在）都 `curl_easy_cleanup` 重建共享句柄，让下一次操作白付一次 TCP + 登录往返。数据面（读下载线程 / 写流式上传）仍用每文件独立句柄 + 阻塞 `curl_easy_perform`：它们本就互不竞争，且背压模型是「缓冲满即中止传输」（`write_cb` 返回 0 → `CURLE_WRITE_ERROR`），与事件循环驱动不兼容。回归用例 `test_ftp_parallel.py`（并发正确性 / 连接数 / 延迟收敛 / 热重载竞态）。

FTP 映射由 `injector.conf` 的 `FTP <虚拟前缀> <段名>` 规则决定（如 `FTP /云盘 云盘`），作用域按规则所在段——`[GLOBAL]` 全局、`[应用包名]` 仅该应用，与 REDIRECT 一致。规则由内建引擎解释并置 `is_ftp`，框架据此把该路径分派给后端模块（不再有 `FTP_<段名>` 变量注册机制）。**协议（FTP/SFTP）由模块配置的 `proto` 决定，框架侧零改动**（规则类型、`is_ftp` 分派、模块 ABI 都不变）。

### 7.1 SFTP（`proto = sftp`）

SFTP 复用同一个模块与同一套线程/缓存/句柄/熔断基础设施，由 libcurl 的 SSH 后端（libssh2）承载；模块配置段增加：

```ini
[备份]
proto = sftp              # ftp（默认）| sftp；非法值整段作废
host = nas.local
port = 22                 # 未显式配置时按 proto 补默认（ftp 21 / sftp 22）
user = backup
key_file = /data/Namespace-Proxy/keys/backup.key   # 空 = 密码 / ssh-agent
key_pass = <私钥口令>      # 可选
known_hosts = /data/Namespace-Proxy/known_hosts    # 空 = <CONFIG_DIR>/known_hosts
host_key_check = on       # 默认 on：主机密钥不匹配即拒连（fail-closed）
remote_dir = /srv/backup
```

协议分派只落在六处（其余代码协议无关）：URL scheme（`ftp://`/`sftp://`）、失败分类（见下）、`getattr` 探针顺序、LIST 时间口径、quote 命令字（`DELE/MKD/RMD` ↔ `rm/mkdir/rmdir`、`RNFR/RNTO` ↔ 单条 `rename`）、`ftp_easy_new` 的 SSH 选项。四条**与 FTP 不同、改错就出错**的语义：

1. **`CURLINFO_RESPONSE_CODE` 在 SFTP 下恒为 0**（libcurl 只给 FTP/SMTP 填 `info.httpcode`）。照抄 FTP 的 `resp==0 ⇒ 后端不可达` 判据会把每个业务失败（不存在/无权限/认证失败）都计进熔断窗口 → 应用探测若干缺失路径（`os.path.exists`）就把健康后端置静默、完好文件被误报 EIO。故 `res_is_unavailable()` 按协议分支：SFTP 只把连接/协议层 `CURLE` 计入。
2. **目录探针必须排在文件探针之前**：OpenSSH 的 sftp-server 允许以只读方式 `open` 一个目录，libcurl 的下载路径对目录同样返回 `CURLE_OK`，文件探针会把目录报成 `S_IFREG`（size=目录自身大小）。判据是「URL 加尾斜杠 + `NOBODY` + `FILETIME`」：`NOBODY` 让 readdir 短路（不真列目录），存在的唯一证据是 GETINFO 那次 stat 的 `FILETIME`（不存在 → 保持 -1）。**不能**给目录探针加 `NOBODY` 后依赖 `CURLE_OK`——那样不存在的路径也会被当成目录。
3. **空文件大小**：libssh2 对 0 字节文件把 `CONTENT_LENGTH` 报成 -1（`sftp_download_stat` 在 `filesize==0` 时置未知）。那是「0 字节」不是「未知」，必须归一为 0，否则空文件 `st_size=-1`。
4. **quote 命令的参数是远程路径本身**，libcurl 不会像 FTP 那样先 CWD 到 URL 目录；且参数由客户端 `Curl_get_pathname` 解析，含空白必须加引号（引号内 `\`/`"` 转义）。路径还要先做百分号解码——POSTQUOTE 串不是 URL，带 `%20` 的命令会让服务器去找字面量名字。失败 errno 细化见 `ftp_quote_errno()`（libcurl 把 SFTP quote 失败一律折叠成 `CURLE_QUOTE_ERROR`，只能用 `CURLOPT_ERRORBUFFER` 的文案保守细化，认不出就退回 FTP 的历史粗口径）。

构建：GNU 上 `-Dsftp=auto`（默认）在系统 libcurl 无 SFTP 时自动改用子模块 curl 并编入 libssh2；Android 的 NDK 不带 libssh2/密码学库，需 `scripts/build-libssh2-android.sh` 产出预构建后 `-Dsftp=enabled -Dlibssh2_dir=<根>`。**`-Dsftp=disabled` 与历史构建逐字节一致**（不引入任何新依赖）。运行期还有一道能力自检：`curl_version_info()->protocols` 里没有 `sftp` 时，`proto=sftp` 的段整段跳过并 loud 报错（fail-closed，绝不静默退回明文 FTP）。

内建引擎的关键语义（修改时必须保持）：appear_missing/read_only 取 app + global **并集**；redirect/sandbox 取 app 优先、global 兜底，sandbox 仅在无 redir 命中时生效；`fw_rules_resolve`/`fw_rules_probe` 走 `config_read_begin`/`config_read_end` 无锁快照（不持 `config_lock_read()` rwlock，见 `architecture.md` §6）。

## 8. 相关文档

- 进程架构与规则引擎：`architecture.md`
- 配置语法：`config.md`
- 构建与测试：`README.md`、`AGENTS.md`
