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

**注入方法（v1/v2/v3）是运行期控制项，不写在配置里**：文件 `<CONFIG_DIR>/inject_method` 写一行 `v1`/`v2`/`v3`，再 `kill -HUP <injector pid>` 即生效，不用重启设备。切换是一次显式迁移：切到 v1 先把三族族根从备份还原成系统视图（失败则保持原方法不动），切到 v2/v3 立刻对账一次全局替换；随后应用对账按新方法执行。启动时该文件优先于 `--inject-method=` 参数，缺失或写错保持当前方法。

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
- **优先级：应用专属 > 类别 > GLOBAL，四类路径规则同一套「作用域优先」**：同一条路径先问应用段**是否发了话**，发了就用应用段的声明（HIDE / ALLOW / RO / REDIRECT 任一个），否则问类别段，最后问 `[GLOBAL]`。所以应用段 `HIDE /Download` 能压过 `[GLOBAL] ALLOW /Download`，应用段 `ALLOW /Download` 也能取消 `[GLOBAL] HIDE /Download`（旧实现把 HIDE/RO 做三层并集，于是 GLOBAL 恒赢、应用段 ALLOW 永远无效——用户报障「单应用规则优先级没全局高」即此，已修）。跨作用域**不再有并集语义**；FTP 取首命中。同一作用域内**静态路径规则先于含通配/变量的规则**（Trie 命中即取，Trie 只是静态规则的加速索引）；跨作用域一律按上面的作用域顺序，**下层作用域的静态规则不得压过上层作用域的通配/变量规则**。同一段内对**同一虚拟前缀**同时写了 `ALLOW` 与 `REDIRECT` 时 **`REDIRECT` 胜**（`ALLOW` 的语义是"不重定向/放行到自身"，显式改写目标更具体；旧实现靠 Trie 同一节点后写覆盖先写，观测结果一致）。
- **沙盒的作用域**：沙盒"从哪里来的"由最高优先级的声明决定（应用段显式 > 应用段继承 > 类别段 > `[GLOBAL]`），见 §3 `SANDBOX`。**低作用域的 `ALLOW` 不得豁免高作用域声明的沙盒**：`[GLOBAL] SANDBOX ON` + `[GLOBAL] ALLOW /Pictures` 时 `/Pictures` 对普通应用放行（不沙盒）；但某应用段一旦写了 `SANDBOX ON`，该应用下 `/Pictures` 同样进沙盒——要豁免就在**同一应用段**写 `ALLOW /Pictures`。这条是「全局开沙盒时单应用不能继承/不能覆盖」报障的修复口径。
- **裸 `[<pkg>]` 是跨用户 fallback（user_id=-1），不是 user 0**：查找同名包时先精确匹配 `[<pkg>:<uid>]`，未命中再回退到 `[<pkg>]`。因此 `[com.tencent.mm]` 对 0/999 等所有用户生效，而 `[com.tencent.mm:999]` 只对 999 生效。注意这与 App-rules **文件目录**不同：uid 0 的规则文件放在 `App-rules/`（`0` 是目录默认值），不要据此把裸段头的 user_id 当成 0。
- 类别判定复用 `SKIP_SYSTEM_APPS` 逻辑：`pm list packages -s` 缓存（injector 落盘 `sys_pkgs.cache` 供 FUSE 侧只读），失败回退 `uid < 10000`。
- 包名不可解析时（`system`/`unknown`/过短/`zygote`）类别段不生效，仅 GLOBAL 适用。
- **系统应用的应用段**（如 `[com.android.settings]`，uid < 10000）在 FUSE 侧可命中：`fw_pkg_resolve_exact` 先查 `uid.map`（格式 `uid pkg`，共享 uid 可手工加一行），无条目时读 `/data/system/packages.list` 按 uid 取包名兜底；命中应用段才替换伪包口径，解析不出或未命中仍按 `system` 伪包参与 SYSTEM_APPS 类别层。注意两点：① 系统应用进程要能把 `POST` 发回 injector，SELinux 需放行其域对 `zygote` 的 `unix_stream_socket` 写权限（模块 `sepolicy.rule` 已含 `system_app`/`platform_app`/`priv_app`；缺失时 pre DEFER 后 POST 静默丢失、永不挂载，logcat 可见 `avc: denied { write } ... tclass=unix_stream_socket`）；② 排查/验证规则效果须以应用自身身份访问（`setpriv --reuid <uid>` 进其 mount ns），root 经 `/proc/<pid>/root` 穿透的请求以 uid 0 发出，解析不出应用段属预期 fail-safe。
- 类别段有实质规则（REDIRECT/HIDE/RO/SANDBOX）即视为点名注入（跳过 `SKIP_SYSTEM_APPS` 过滤）；段头 `OFF` 显式否决该类别注入。
- 类别段只写主文件；`GLOBAL_INJECT` / `SKIP_SYSTEM_APPS` / `FUSE_EXTRA_ARGS` / `SANDBOX_DIR` 仅 `[GLOBAL]` 段有效，写在别处忽略并告警。
- 活跃用户列表由 `scan_active_users` 经 `pm list users` 获取（失败回退 `/data/media` 扫描，再兜底 user 0）。

## 3. 开关项

取 `ON` 或 `1` 为开，其他值（含省略）为关。

| 开关 | 范围 | 说明 |
|------|------|------|
| `MONITOR` | 应用段 | 监控该应用的文件访问 |
| `SANDBOX` | 应用段 / 全局段 | 启用独立沙箱：该应用对存储的访问**整树重定向**到沙盒落点（`<storage>/Android/data/<pkg>/<SANDBOX_DIR>`，见 `architecture.md` §存储视图），`/Android` 是否也在整树之内由 `SANDBOX_ANDROID_TREE` 决定：默认 **OFF** 时 `/Android` 下除 `Android/data|obb` 容器里的条目外一律让位真实目录（应用新建的 `/Android/123.txt` 落真实目录），写 `ON` 才整树进镜像（落 `<storage>/Android/data/<pkg>/sandbox/Android/123.txt`，真实目录不落盘），`/Android/data`、`/Android/obb` 的跨应用骨架另按 §4.1 隔离。**应用段不写 = 继承 `[GLOBAL]`**；应用段 `ON` = 该应用一律沙箱（连 `[GLOBAL] ALLOW` 的目录也进沙箱，要豁免须写在同一应用段）；应用段 `OFF` = 显式不沙箱。**媒体提供者（`com.android.providers.media*`，含 `.module`）不参与沙盒**：它在 FUSE 视图里是第三方应用取字节的通道（Photo Picker、缩略图、转码），重定向进空沙盒目录会让所有未被 `ALLOW` 覆盖的媒体 ENOENT；应用段/类别段对它显式写 `SANDBOX ON` 会被忽略并告警（v1 按应用挂载时本就不给它挂 FUSE 实例，口径一致）。命中 `ALLOW` 的路径不再进沙盒（`ALLOW` = 不重定向），除非沙盒的声明作用域高于该 `ALLOW`。`/Android` 下只有四处让位到真实目录：三个容器本身 `/Android/data`、`/Android/obb`、`/Android/media`（ACL 骨架目录，容器里每个包单独裁决），以及该应用自己在三者中的私有目录 `/Android/{data,obb,media}/<pkg>`（原生在这里提供挂载点、引用、媒体扫描）。**他包 `Android/data|obb` 子树同样不归沙盒改写**（让位给 §4.1 的隔离判据：原生在这里按调用方能力裁决，镜像改写会掩盖那个裁决）；他包的 `Android/media/<他包>` 不在这四处之内，照整树进镜像（media 不在 §4.1 隔离范围）。语义见 §2「沙盒的作用域」 |
| `GLOBAL_INJECT` | 全局段 | 全局注入开关 |
| `SKIP_SYSTEM_APPS` | 全局段 | 跳过系统应用，默认 **ON**；它是 `GLOBAL_INJECT` 的**作用域收窄项**，`GLOBAL_INJECT` 为 OFF 时它不单独生效（两种取值都不影响显式点名的应用段/类别段/`[*]` 段——那三处各有自己的使能位，见 §2）。zygisk 模块**不**再按 uid 硬编码过滤：除 `uid 0` 与 isolated 区（90000–99999）外一律上报，是否注入完全由本开关裁决——写成 OFF 时系统应用（如 uid 1000 的 Settings）才会被注入/还原 |
| `FUSE_EXTRA_ARGS` | 全局段 | 透传给 `fuse_daemon` 的额外参数（行尾原样，不分词，上限 512 字节）；其中 `-o negative_timeout[=N]` 会被单点剥离（恒为 libfuse 默认 0.0，非 0 负缓存以 ino=0 回包会触发内核 nodeid=0 崩溃） |
| `SANDBOX_DIR` | 全局段 | 沙盒落点目录名（覆盖默认 `sandbox`） |
| `SANDBOX_ANDROID_TREE` | 全局段 | 沙盒里 `/Android` 的口径开关，默认 **OFF**。`OFF` = `/Android` 下除三个容器本身与该应用自己的私有目录外的条目一律让位真实目录、不进镜像（旧口径）；`ON` = `/Android` 本身与其下其它条目整树进镜像，应用新建的 `/Android/123.txt` 落沙盒、真实 `/Android` 不落盘。`ON` 下 `/Android` 读的是镜像，镜像里没有真实的容器目录，故读侧的 `data`、`obb`、`media` 三条容器条目由框架合成（`OFF` 读真实目录，不合成）。见 §4.1「与 `SANDBOX ON` 的关系」 |
| `FUSE_EVENTS` | 全局段 | FUSE 事件通道总开关，默认 **OFF**。开启后 daemon 暴露两条抽象命名空间 UDS：`nsp_fs_events`（订阅后推 NDJSON 事件）与 `nsp_fs_query`（一次性查询），供扫描侧按增量扫描而非整树重扫；关闭时零线程、零 socket，IO 路径只多一次原子读。通道白名单默认含 root(0)/system(1000)/media_rw(1023) + **自动解析的 MediaProvider 进程 uid**（包名 `com.google.android.providers.media.module`、`com.android.providers.media.module` 与 `com.android.providers.media`，启动时从 `/data/system/packages.list` 取 uid 并按相同 uid 去重——消费方跑在该进程内，它既不是 1000 也不是 1023；解析失败只少这一条，通道其余照旧）+ `[GLOBAL] FUSE_EVENTS_UIDS` 追加项。见 `architecture.md` §4.7 |
| `FUSE_EVENTS_UIDS` | 全局段 | 事件通道**追加**白名单 uid（逗号分隔，上限 8 项；默认已含 root(0)/system(1000)/media_rw(1023) 与自动解析出的 MediaProvider 进程 uid，见上行）。它只决定谁能连这两条 socket，与事件里的 `uid`/`pkg`（被代理的应用）无关 |
| `FUSE_THREADS` | 全局段 | FUSE worker 线程数上限。`0`（默认）= 自动，按宿主 CPU 核数取 `min(max(2, ncpu/2), 8)`（4 核 → 2、6 核 → 3、8 核 → 4、16 核及以上 → 8）；`1`–`32` 显式指定；`-1` 交回 libfuse 默认（10）。启动期参数：改它需要重启 daemon。worker 太少时单个应用冷启动会把同一条 FUSE 连接排满，太多只是让线程互抢 CPU |
| `ZYGISK_POST_WAIT_MS` | 全局段 | zygisk 模块在 `postAppSpecialize` 等自己命名空间出现代理视图的**墙钟**预算（毫秒，`0`–`1000`，默认 **`0` = 不等**），随 pre 的 `DEFER <ms>` 应答下发给 proto>=4 的模块。`0` 时模块**一次 `/proc/self/mountinfo` 都不读**：合并挂载交 injector 后台盯梢（`ns/mnt` 切换 + 250ms 就绪预算）与重试队列收敛，应用首个 `open()` 看到的可能是原生视图；`>0` 时模块在预算内等**挂载表变化事件**（`poll(/proc/self/mountinfo, events=0)`）再复探，超预算立刻放行。读取整份挂载表的成本与条目数成正比（本机 0.39ms、大表机型 54–136ms），旧实现按步进计数会在大表机型上固定做 11 次整表扫描（0.7–1.5s，全落在冷启动热路径上），所以默认必须是 0；想恢复「首写前就绪」的老语义写 `150`。改它**不需要重启 daemon**（判决时读取，`log_ctl reload-config` 后对新判决生效） |
| `HIDE_ERRNO` | 全局段 | 隐藏规则命中时对外返回的 errno：`ENOENT`（默认）/ `EACCES` / `EPERM`；缺省是 `ENOENT`（= 文件不存在）。应用对「不存在」和「不许访问」的处理常常不同：把 HIDE 当「尚未生成」反复重试的应用（先 probe 再写、自建缓存目录）会在 `ENOENT` 下形成重试风暴，把同类访问放大成百上千次，`EACCES` 通常一次就放弃。只对用户规则命中生效，骨架/CONFIG_DIR 等内部隐藏恒为 `ENOENT`。启动期参数：改它需要重启 daemon |
| `ALLOW_CROSS_APP_DATA` | 全局段 | 跨应用隔离放宽开关，默认 **OFF**（=隔离生效：`/Android/data|obb/<他包>` 既**不可列举也不可打开**）。写 `ON` 恢复旧行为（只过滤列举、不限制打开），是跨应用隔离的**唯一逃生阀**，见 §4.1 |
| `ALLOW_CROSS_APP_PKGS` | 全局段 | 跨应用放行白名单（可写多次，累积）。列出的**调用方**包名可以访问他包 `/Android/data|obb`，未列出的照常隔离；按调用方**自身**包名精确匹配（不做 uid 兜底，同 uid 的兄弟包不会被顺带放行），独立于 appops 授权。见 §4.1 |
| `ALLOW_CROSS_APP_BY_CAPABILITY` | 全局段 | 是否按调用方能力放行跨应用访问，默认 **ON**（与原生一致）。开着时按 uid 查一次 appops：持 `MANAGE_EXTERNAL_STORAGE`（All files access）的调用方放行他包 `Android/data|obb`；持 `INSTALL_PACKAGES` / `REQUEST_INSTALL_PACKAGES`（能装包）的只放行 `Android/obb`——对应原生 `PASS_THROUGH` 与 `INSTALLER` 两档挂载模式。写 `OFF` = 主动选择「比原生更严」：能力不再豁免，只有白名单与 platform 签名能跨应用读。见 §4.1 |

`MONITOR` 在应用段**显式写一次即覆盖全局**（`*_explicit` 标记）。`SANDBOX` 是**分层声明**而不是「写了才生效」的开关：不写 = 继承全局；`ON` = 该应用一律沙箱（含全局 `ALLOW` 的目录）；`OFF` = 显式不沙箱（见 §2「沙盒的作用域」）。开关词法唯一出处 `nsp_switch_on()`（`ON`/`1` 为开）。

`MONITOR` 的三层合并（应用显式 > 类别显式 > `[GLOBAL]`；`[USER_APPS[:uid]]` / `[SYSTEM_APPS]` 均参与）由**框架**统一计算，与规则模块是否加载无关：模块未加载/被 ban、路径无 `<uid>/` 用户层、模块未命中规则时同样算得对。若把开关绑在"模块是否给出有效决策"上，这些情形下文件读写一切正常、IO 监控日志却静默消失且无任何提示（历史缺陷）。框架为此自建一份配置索引并自行解析 uid→包名（`uid.map` → `/proc` 回退，见 `architecture.md` §2.2）；包名不可解析（`system`/`unknown`/过短/`zygote`）时只认 `[GLOBAL]`，与模块侧同一 fail-safe 口径。

`io.log` 的行数完全由 `MONITOR` 决定：**三层合并后未生效的调用方一行都不记**（默认 `OFF`，空白配置下该文件不增长）。正常行 `时间|LEVEL|[pkg(uid)] [OP] <虚拟路径>`，命中 `REDIRECT` 时尾部追加 ` -> <target>`；**正常行不带 errno**，失败另起 `[pkg] [ERR] <OP> <路径> errno=…`。排查「文件明明在却打不开」要的是拒绝原因，那条在 `sys.log`（`隐藏规则命中`/`访问控制拒绝`/`跨应用隔离`/存储根守卫，都带 `errno=`）——按 `io.log` 里同一个路径、同一个时间窗去对 `sys.log`，别在 `io.log` 里找错误码。

注入方法为 `v3` 时（`injector --inject-method=v3`，见 `architecture.md` §5.1），`GLOBAL_INJECT` / `SKIP_SYSTEM_APPS` **不参与目标判定**——含系统应用在内一律经项目 FUSE。应用段与类别段头的 `OFF` 只表示「该应用不被注入」：v1 / v2 下该应用根本不进项目 FUSE（v1 不挂、v2 还原成原生视图），段内**规则不会被评估**；v3 下非目标应用不还原、仍走全局 FUSE，段内规则**照旧参与裁决**——在 v3 下写 `[pkg] OFF` 再配 `HIDE /` 会真的把该应用的存储根隐藏掉。

## 4. 四类规则

| 规则 | 语法 | 语义 |
|------|------|------|
| 隐藏 | `HIDE <path>` | 应用看不到该路径（返回 ENOENT） |
| 只读 | `RO <path>` | 该路径对应用只读（写操作返回 EROFS） |
| 放行 | `ALLOW <path>` | 显式放行：等价"重定向回自身真实存储"（parse 生成 `?<path>` 内部前缀）。命中后该路径**不参与沙盒重定向**，且不继承低作用域的 `HIDE`/`RO`/`REDIRECT`（作用域优先，见 §2）。**IO 仍由 daemon 代理**（不挂 backing 直达下层）——否则内核会按应用自身凭证对 `/data/media` 做 DAC，放行路径反而写不进去 |
| 重定向 | `REDIRECT <vpath> <target>` | 应用访问 `<vpath>` 实际落到 `<target>` |

> **v3 下的连带影响**：`v3` 全局替换后媒体提供者（`com.android.providers.media*`）也经本项目 FUSE（见 `architecture.md` §5.1），故 `[GLOBAL] HIDE` 对它的中转路径同样生效。隐藏 `/.picker_transcoded`、`/.transforms` 会让系统相册选择器（Photo Picker）取字节失败（ENOENT），表现为「选完图读不出来」——这是配置后果，不是模块缺陷。命中 HIDE 规则时 daemon 打限频 WARN `隐藏规则命中: uid=… 包名=… <路径>`（首个命中与每 1024 次各一条），排查「文件明明在却打不开」先看这条。

> 内置隐藏：`CONFIG_DIR` 下所有访问无条件返回 ENOENT；应用访问 `/Android/data/<其他包>/`、`/Android/obb/<其他包>/` 自动判为其他应用（跨应用隔离，**列举与打开同口径**，见 §4.1）。

### 4.1 跨应用隔离

生效范围只有 `Android/data` 与 `Android/obb`（`media`/`obj` 不在其中——历史就没有隔离，扩范围会改变既有行为）。隔离与 `HIDE` **同口径**：`resolve`（getattr/open）与 `probe`（readdir 条目过滤）走同一个隐藏判定出口，所以「看不见 = 打不开」；旧实现只在列举侧过滤，任何按名打开的命令都能读到内容。

**优先级：显式规则 > 隔离（默认边界）**。这条路径上任何作用域写了 `ALLOW`/`HIDE`/`RO`/`REDIRECT`，隔离就让位、交规则层裁决——隔离是「用户没有表态时的默认边界」，不是能压过配置的硬墙。

- **放行**：目标目录名等于调用方**基础包名**（`com.x:push` 与 `com.x` 同包）时放行；调用方包名不可解析（`system`/`unknown`，即 root 与系统工具）不隔离；`[GLOBAL] ALLOW_CROSS_APP_DATA ON` 全局放行；调用方命中白名单 / platform 签名 / 能力档（下两条）时放行。
- **同 uid 视为同一应用**：目标目录的**属主 uid** 等于调用方 uid 时放行（判据取自 `/data/system/packages.list` 的「包名 uid」行，查不到则维持隔离）。Linux DAC 只认 uid，同一 uid 下的多个包（旧 `sharedUserId`，或系统里共用进程的两个 provider，例如 `android.process.media` 宿主同时提供 MediaProvider 与 DownloadsProvider）本就是同一个 app 身份；只按包名比较会把它们误判成「他应用」，在 v3 全局挂载下表现为下载器读不到 Downloads 的私有目录（ENOENT）。解析/目录属主 uid 失败时不额外放行。
- **与 `SANDBOX ON` 的关系**：沙盒只对四处让位、其余进镜像。让位的是：他包 `Android/data|obb` 子树（本节判据）、三个容器本身 `/Android/data`、`/Android/obb`、`/Android/media`（ACL 骨架目录，容器里每个包单独裁决）、应用自己的私有目录 `/Android/{data,obb,media}/<pkg>`——这些路径不做镜像改写，落回真实路径交本节判据裁决（原生在这里按调用方能力/挂载模式放行或 ENOENT，改写会把那个裁决整个掩盖掉：能力放行者读到空目录，非放行者拿到的 ENOENT 也不是原生那个原因）。其余路径（`/Download`、`/Pictures`、他包 `/Android/media/<他包>`，以及 `SANDBOX_ANDROID_TREE ON` 时的 `/Android` 本身与应用在它下面新建的条目）照旧整树进镜像。`SANDBOX_ANDROID_TREE` 默认 **OFF**：`/Android` 本身与其下非 `data`/`obb` 容器里的条目一律按「让位真实目录」处理、不进镜像（旧口径），两个口径下 `/Android/data|obb` 的容器裁决不变。**`ON` 下 `/Android` 读的是镜像，镜像里没有真实的容器目录**，故读侧的三个容器条目要由框架补齐：`readdir` 对镜像里缺失的 `/Android/data`、`/Android/obb`、`/Android/media` 合成 `0755` 目录条目（时间取最近存在的祖先，不是 1970），按名 `getattr`/`access`/`opendir` 对同三条给一样的兜底；`/Android/media/<pkg>` 不在兜底范围——容器里每个包仍按本节判据单独裁决，镜像里没列举过的子路径照旧 ENOENT。因此**开关与白名单在沙盒生效时同样有效**，不会因为应用开了沙盒而失效。媒体提供者不参与沙盒，也不参与隔离：它读 `/Android/data` 里的媒体内容不该因为「不再沙盒」而新被拦（v1 不挂载即无此判定）。
- **特权应用自动豁免**：调用方是 **platform 签名**应用（`/data/system/packages.list` 的 seinfo 字段以 `platform` 开头，含 `platform:privapp` 与纯 `platform` 共享签名；DocumentsUI / Settings 等系统中介均为 priv-app）时自动放行——文件中介（如 DocumentsUI）的本职就是访问他包 `Android/data`，逐包手工写规则不可维护，按 Android 自己的权限体系判定。普通应用（seinfo `default`）与 `packages.list` 不可读/无该 uid（fail-safe）照常隔离。此豁免与 `ALLOW_CROSS_APP_DATA` 无关、无需配置。
- **按包名白名单**：`[GLOBAL] ALLOW_CROSS_APP_PKGS com.a,com.b` 列出的**调用方**包名可以访问他包 `Android/data|obb`（完整放行，等同能力档的 `FULL`），与 appops 授权无关，用于「不想给全盘权限、又确实要读某个他包目录」的场合（迁移工具、备份应用）。匹配用调用方自身包名精确比较，**不做 uid 兜底**：同 uid 的兄弟包要访问也各自写一行——`uid.map` 是 uid→单包名，按 uid 放行等于让共享 uid 的所有包互相看光。未列出的应用照常隔离；白名单只解除隔离，`HIDE`/`RO`/`REDIRECT` 规则照旧生效，沙盒生效时同样有效（沙盒对他包路径让位，见上一条）。
- **能力档（默认开）**：`[GLOBAL] ALLOW_CROSS_APP_BY_CAPABILITY` 默认 **ON**，按调用方能力分两档，对应原生挂载模式的两档：持 **MANAGE_EXTERNAL_STORAGE**（All files access）的放行他包 `Android/data` 与 `Android/obb`（原生 `MOUNT_MODE_EXTERNAL_PASS_THROUGH`：lowerfs 直通，结构规则与私有目录判定都绕过）；持 **INSTALL_PACKAGES** / **REQUEST_INSTALL_PACKAGES**（能装包）的只放行 `Android/obb`（原生 `MOUNT_MODE_EXTERNAL_INSTALLER`：额外拿 `EXT_OBB_RW_GID`，装应用时要读他包 obb）。开着时按 uid 查一次 appops，两个结论同一次查询取得，结果按 uid 缓存、配置重载后失效重查，另设 30s 有效期——运行期新授予的权限最多 30s 内生效，不必重启 daemon。写 `OFF` 时能力不再参与跨应用裁决（只剩白名单与 platform 签名），这是「比原生更严」的显式选择；顶层目录创建（`NSP_ACL_OP_MKDIR`）的能力旁路不受本开关约束（AOSP `shouldBypassFuseRestrictions` 等价物，见 `architecture.md` §4.5.1）。`legacy storage` 不参与：Android 16 已无 legacy 挂载模式。边界与白名单一致：只解除隔离，`HIDE`/`RO` 等显式规则照旧生效。
- **边界（共享 uid）**：`uid.map` 是「uid → 单个包名」，所以**调用方身份**只能按包名展示；但「是否他应用」看的是 uid（见上一条），同 uid 多包互访不再被拦。仍然拦的情形：两个不同 uid 的应用互读对方私有目录（正常跨应用隔离）、目标包在 `packages.list` 里查不到 uid（无法证明同 uid，维持隔离）。逃生阀不变（`ALLOW_CROSS_APP_DATA ON`，或 `ALLOW /Android/data/B` 这类按路径放行的规则）。
- **代价**：全局实例（服务所有被注入应用的那个 daemon）**不做任何 backing 直通**，全部 I/O 由 daemon 代理——隔离需要 per-caller 裁决只是原因之一，更硬的原因是下层 DAC：backing 之后内核按**调用方凭证**访问 `/data/media`（归 MediaProvider `10277:1023`、顶层目录 `0770`、属组 `media_rw`），应用通常不在该属组里（补充组不含 `media_rw`），一律 EACCES。加速只在 media 实例（调用方恒为 MediaProvider 自身）保留，见 `architecture.md` §跨应用隔离。

> **`REDIRECT <vpath> <target>` 的 `<vpath>` 会遮蔽同名的真实条目**：该名字在列举里由虚拟目录提供（内容取 `<target>`），底层若存在同名文件/目录则不再单独列出——否则会出现「列表里是真实目录、`stat` 却落到重定向目标」的不一致；虚拟前缀的父目录在底层缺失时也会被合成为目录。`<target>`（真实目标）**不受影响**，仍是普通路径，照常列举与访问。

> **`HIDE` 的 errno 在所有操作上统一为 `ENOENT`**（含 `mkdir`/`create`/`unlink`/`chmod` 等写类操作）。早期版本写类操作用 `EACCES`，同一条 `HIDE` 声明会因操作类别不同而产生两种 errno；自 ABI V3 起由框架单点强制（`fw_route`）统一为 `ENOENT`，与「存在变不存在」的语义一致。若前端曾按 `EACCES` 判定隐藏路径，需改为按 `ENOENT` 判定。

后端模块可追加规则类型（如 FTP 模块的 `FTP <虚拟前缀> <段名>`），见 `modules.md` §2.1。

### RO 的可见副作用：媒体索引不会自己刷新

Android 11+ 的 `/storage/emulated` 由 **MediaProvider 自己**当 FUSE 服务端。应用的写一旦经本项目 FUSE 落地（`REDIRECT` 落点、或直写 backing），MediaProvider 那一层就**没有见过这次写**——它把新文件收进媒体库只有两条路：① 应用保存后显式请求扫描该路径；② MediaProvider 自身的 idle 维护扫描（分钟到小时级）。

`RO` 掐断的正是 ①：应用照旧对 `RO` 的那条路径请求扫描，而文件因为 `EROFS` 根本没建，MediaProvider 扫出空结果，相册要等 ② 才出现条目。现象是「加了 `RO` 之后相册刷新巨慢」，同时磁盘上另一份（`REDIRECT` 落点）其实是好的；应用若等扫描回调，还会表现为「保存超时」。注意这与单次 I/O 快慢无关：`RO` 拒绝比放行更快（宿主实测 create 被拒 25.9µs vs 放行 62.7µs，p50），`read`/`write` 更不经过规则判定。

- **想让相册立刻看到落地文件**，必须由某一方显式触发一次扫描（命令在 Android 13 实测可用）：
  `content call --uri content://media/ --method scan_file --arg /storage/emulated/0/DCIM/xxx.jpg`
  返回 `Bundle[android.intent.extra.STREAM=<生成的媒体 Uri>]`；文件不存在或不是媒体时该值为 `null`。应用侧等价 API 是 `MediaScannerConnection.scanFile(...)` 与 @hide 的 `MediaStore.scanFile(resolver, volume, path)`，都落到同一个 `scan_file`。`android.intent.action.MEDIA_SCANNER_SCAN_FILE` 广播自 API 29 弃用，Android 13 上不可依赖；`--method scan_volume` 是整卷重扫，代价大且部分 ROM 对 volume 参数挑剔。
- **触发方只能来自知道真实落点的一方**：daemon（重定向目标写入成功/close 之后，按路径去抖、异步执行，禁止占用 I/O 路径等 `fork+exec`）或外部 hook（hook MediaProvider 的 `call`/扫描入口）。
- **只想「不产生重复文件」而不想改动扫描可见性时，优先用 `REDIRECT`** 让两次保存落到**同一个**真实目标，而不是用 `RO` 把其中一次变成 `EROFS`。

### 路径前缀归一

底层真实物理存储固定为 `/data/media/<user_id>`（`STORAGE_BASE`）。配置中的路径按下表归一：

| 写法 | 归入 |
|------|------|
| `Android/data/foo`（相对，无前导 `/`） | 当前用户存储 `/data/media/<user_id>/Android/data/foo` |
| `/storage/emulated/0/xxx` | 归一为当前用户存储（剥离 `/storage/emulated/<N>`） |
| `/sdcard/xxx`、`/mnt/sdcard/xxx`、`/storage/self/primary/xxx` | 当前用户存储（存储根别名，与 `/storage/emulated/<N>` 同口径剥离，见 `nsp_strip_storage_prefix`） |
| `/data/...`、`/mnt/...`、`/storage/...` | 绝对路径原样（`is_system_abs_path`） |
| `?/xxx` | 当前用户存储（内部前缀，parse 阶段自动生成，无需手写） |

- 路径不以 `/` 或 `*` 开头时自动补前导 `/`；不含通配符的路径自动去尾部 `/`。
- **变量展开的结果按同一套口径再归一一次**（`normalize_expanded_rule_path`）：折叠开头重复的 `/`、剥离存储根别名（`/storage/emulated/<N>`、`/sdcard`、`/mnt/sdcard`、`/storage/self/primary`）、必要时补前导 `/`、无通配符时去尾 `/`。原因：以变量开头的规则在解析期已被补上前导 `/`，而变量值可能自带 `/` 或使用别名，不归一会拼出 `//storage/...` 而永不命中。故 `HIDE $DATA_BASE/files` 与 `HIDE /storage/emulated/0/.../files` 等价，变量值写 `/sdcard/...`、`/mnt/sdcard/...` 或不带前导 `/` 均可。只折叠**开头**的重复斜杠，路径内部的 `//` 不予改动；展开结果放不进缓冲时该规则按不命中丢弃（fail-closed）。
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
- **值里的存储路径**：可写 `/sdcard/...`、`/mnt/sdcard/...`、`/storage/self/primary/...`、`/storage/emulated/<N>/...` 或相对形式；规则引用变量时，展开结果会按「路径前缀归一」一节的同一套口径归一再匹配（见该节说明）。
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
| 开了沙盒后 `/Android` 里新建的文件没进沙盒 | `[GLOBAL]` 段加 `SANDBOX_ANDROID_TREE ON` | 默认 OFF 是旧口径：`/Android` 下非 `data`/`obb` 容器里的条目让位真实目录、不进镜像（§4.1） |
| `SANDBOX_ANDROID_TREE ON` 后应用在 `/Android` 下只看到 `data`、`obb`，没有 `media` | 升级到补齐该条目的版本；`OFF` 口径不受影响 | `ON` 下 `/Android` 读的是镜像，容器条目要框架合成；`media` 与 `data`/`obb` 的 ACL 分类不同（容器里每个包单独裁决），漏补就少一条（§4.1） |
| 应用段写 `MONITOR OFF` 期望继承全局 | 全局段写 `MONITOR OFF`，或应用段显式写所需值 | 应用段显式写即覆盖全局 |
| `[GLOBAL] ALLOW /Pictures` 后应用段 `SANDBOX ON`，期望 `/Pictures` 仍放行 | 在同一应用段写 `ALLOW /Pictures` | 低作用域 `ALLOW` 不豁免高作用域声明的沙盒（§2） |
| `FUSE_EXTRA_ARGS` 写在应用段 | 仅写 `[GLOBAL]` 段 | 应用段无该字段 |
| `HIDE /.picker_transcoded`（或 `/.transforms`）后期望系统相册选择器照常取图 | 不要隐藏系统 picker 的转码/临时目录 | v3 下媒体提供者也在 FUSE 视图内，隐藏这些目录会让 Photo Picker 取字节 ENOENT |
| 期望 `/sdcard` 原样保留 | 知悉其归一到当前用户存储 | `/sdcard`、`/mnt/sdcard`、`/storage/self/primary` 是存储根别名，规则路径与变量值都按别名剥离 |

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
