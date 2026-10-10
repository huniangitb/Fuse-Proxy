# 贡献与维护规范

Android 13+ 用户态 FUSE 存储代理，C23 + Meson/Ninja。仓库文档与提交信息**用中文**。

本文是**流程**的权威出处：怎么开工、代码放哪、什么不能碰、提交前要过哪些门。
技术细节在 `docs/`（见 `docs/README.md` 的归属表），构建陷阱与逐套件判别性细节
在 `AGENTS.md`。

## 1. 开发流程

1. **先读对应文档**：架构 `docs/architecture.md`、模块 `docs/modules.md`、
   配置语法 `docs/config.md`、测试 `docs/testing.md`。
2. **按归属写代码**（见 §2）。
3. **同步测试**：改了行为就地补用例，并按 `docs/testing.md` 的映射表跑全绿。
   新套件按 `docs/testing.md` §9 的清单登记。
4. **自测验收门**：`python3 tests/run.py`（日常）/ `scripts/acceptance.sh`（提交前）。
5. **提交**：标题说清「做了什么更改」，正文按需直接描述改动（见 §5）。

## 2. 代码归属

同一能力只能有一份实现，放错位置就会出现「各文件私刻副本」然后缓慢分叉。

| 代码性质 | 去处 |
|---|---|
| 纯 libc、无全局依赖的公共工具 | `src/core/nsp_util.c`（**禁止各文件私刻副本**） |
| 依赖项目全局（`g_real_root`、日志、SELinux） | `src/core/common.c` |
| 跨进程/跨模块常量 | `include/nsp_constants.h`（唯一出处） |
| 日志级别与宏 | `include/nsp_log.h`（唯一出处） |
| 规则决策、uid→包名、MONITOR 合并 | 框架侧 `src/daemon/fw_rules.c` / `fw_pkg.c` / `fw_config.c`——**不要放进模块** |
| 后端存储能力（FTP 等） | `src/modules/<名>/`，只实现 `backend_*` |

两条配套约定：

- **新增跨文件函数必须带域前缀**（`fw_*`/`vfs_*`/`nsp_*`/`common_*`/`fdq_*`/`cfg_*`/
  `ns_*`… 完整清单见 `docs/architecture.md` §7）。
- **`nsp_util` 是树内共享实现，不是模块 SDK 的公开 ABI**：第三方模块只能依赖
  `include/nsp_module.h`（及其代含的公开头），否则 ABI 链接例外保不住。

## 3. 红线（破坏即回滚）

1. **同一模块 ABI 版本内不改 `fuse_daemon` 导出表公共符号签名**——已编译模块靠
   `b_lundef=false` + `--export-dynamic` 解析它们。授权升 ABI 时允许破坏签名/删字段，
   但必须递增 `NSP_MODULE_ABI_VERSION` 让加载器拒绝旧版本
   （见 `docs/modules.md` §3/§6.5），**不得静默改变既有版本的语义**。
2. **不破坏「REDIRECT 虚拟前缀不含 user_id，FUSE 层剥离 `/0/` 后再匹配」约定。**
3. **路径合成走 `common_*` 唯一出口**：禁止裸拼 `STORAGE_BASE "/%d…"`；
   `MAX_PATH_LEN` 放不下时**返回 -1 而非截断**。截断会**放大** HIDE/RO 的命中范围
   （更短的前缀匹配更多路径），属安全缺陷而非显示问题。
4. **决策强制只在 `fw_route` 单点**：新增回调必须走
   `VFS_SETUP_CORE(path, VFS_OP_READ|VFS_OP_MUTATE)`，不得自行手写 hidden/ro 判定
   ——那正是 V3 收敛掉的漂移来源。
5. **YAGNI**：不留无调用者的预留实现。
6. **文档即契约**：文档与实现冲突时按文档改实现；文档没写清的决策列为待裁决，
   不臆断。

## 4. 提交前验收门

完整定义与证据要求见 `docs/testing.md` §4。一条命令跑完：

```bash
scripts/acceptance.sh
```

最低要求（全绿方可提交）：

| | 门 | 判据 |
|---|---|---|
| G1 | GNU 构建 | 零**新增**代码告警（基线见 `docs/testing.md` §4） |
| G2 | Android 交叉构建 | 产物齐全；`src/zygisk/*.so` 的 `readelf -d` 无 `libc++_shared.so` |
| G3 | 文档/台账一致性 | `python3 tests/test_docs_sync.py` 通过 |
| G4 | 全量测试 | `python3 tests/run.py --all --strict` 退出码 0，gap 为 0 或逐条记录原因并确认非产品缺陷 |
| G7 | **判别性** | 新增回归用例**在旧实现上失败**（见下） |
| G8 | 层级诚实 | 结论写清覆盖到哪层；L3/L4 未做就写未做 |

G5（ASan+UBSan）与 G6（宿主隔离）较重，按改动面酌情跑——碰内存/并发/挂载的改动
必跑。

### 判别性：本仓库最重要的一条

**新增回归用例必须能在旧实现上失败**，否则它只是「跑了一遍」而没有验证力。
本仓库的套路是把旧实现副本编进测试：

```bash
FTP_BACKEND_SRC=<git show HEAD:旧副本>   # FTP 后端
FW_CONFIG_SRC=<旧源码>                   # fw_config
FDQ_SRC=<旧实现>                         # 延迟 close 队列
PROBE_VARIANT=old                        # 透传探测
```

或直接 `cc` 编译旧源码副本 + `-Wl,--wrap=<函数>` 注入失败。写完用例请**实测它在旧
实现上失败**，并在提交信息或 `AGENTS.md` 映射表里写明判别信号是什么
（看 errno 还是看记账？看日志还是看标记文件？）。

两个常见陷阱：

- **别靠 grep daemon 日志判别**：daemon 日志走 UDS 交给 `log_monitor`，测试进程拿到的
  `daemon.log` 恒为空，靠它判别会把真缺陷误报成环境问题。用模块侧标记文件或套件自记
  的事件文件。
- **两侧 errno 相同不等于没区别**：例如后端越界回包被内核拒收时，新旧实现都返回
  EIO；判别要看**记账**（模块是否被熔断、`module_errors.log` 有无记录）。

## 5. 提交规范

**标题回答「做了什么更改」，正文按需直接描述改动（可选）。** 本节是规则的权威
出处，`scripts/commit_msg.py lint` 是它**唯一**的可执行形式——改规则要同时改两边，
`tests/test_commit_msg_lint.py` 会拦住漂移。

每个 clone 装配一次（写进 `.git/config`，不随 clone 传播）：

```bash
scripts/setup-hooks.sh     # core.hooksPath=.githooks + commit.template=.gitmessage
```

- `.githooks/commit-msg` 在每次提交时校验，不合规**当场拒收**并逐条给出原因
  （`git commit --no-verify` 可绕过，评审可见，别默认用）。
- `.gitmessage` 在编辑器里预填骨架。注意 `git commit -m` **不加载模板**——模板只是
  效率优化，钩子才是约束。

### 5.1 标题

`<type>(<scope>)!: <做了什么更改>`

- **type**：`feat` / `fix` / `docs` / `refactor` / `perf` / `test` / `build` / `chore`。
- **scope 从下表选，不得自造**；同一个文件只允许一个 scope，无明确归属可省略。
  省略或写错时，校验器会按**本次改动的文件**给出建议（如 `src/modules/ftp/…` → `ftp`）。
- 一句话说清改了什么，**目标 ≤ 50、硬上限 72 显示列**（中文按 2 列计，约 36 个汉字），
  句末不加句号。口径是**显示宽度**不是字符数：40 个汉字是 40 字符却占 80 列，终端
  必然折行——按字符数计的校验器（如 commitlint 的默认口径）会把它放行。
- **不把内部计划/评审编号（`B1`/`C9`/`A26`…）写进标题**——仓库外无人知道它指什么，
  需要追溯就写进正文。
- 标题里出现 `+` / `；`，说明一个提交塞了多件事，**新提交**应按 §5.3 拆开。

| scope | 覆盖范围 |
|---|---|
| `fw` | 规则决策、uid→包名、MONITOR 合并（`src/daemon/fw_rules.c`、`fw_pkg.c`、`fw_config.c`） |
| `fuse` | `fuse_daemon.c` 与 FUSE 回调、虚拟路径、backing |
| `module` | 加载器 / ABI / 围栏 / 熔断（`src/module/`） |
| `ftp` | FTP 后端与 mux（`src/modules/ftp/`） |
| `injector` | 注入主控、挂载序列、zygote 追踪 |
| `zygisk` | Zygisk 通知模块（`src/zygisk/`，Android 双 ABI） |
| `log` | 日志链路（`src/log/`、`log_ctl`、`log_monitor`） |
| `rule` | 规则文件编辑与 `rule_server` 协议 |
| `config` | 配置解析、段头、路径变量 |
| `core` | `nsp_util` / `common` 等公共实现（`src/core/`） |
| `build` | Meson、交叉构建、打包 |
| `scripts` | `scripts/` 下的运维与验收脚本 |
| `test` | 测试夹具与驱动本身 |
| `docs` | 仅文档 |

### 5.2 正文（中文，可选）

**直接描述这次提交改了什么**：不写固定标签（「以实现：」「凭什么对：」已废除），
不写取舍论证与取证细节（那些放 `docs/testing.md` 或 PR 描述）。标题已说清改动的，
正文可省。

正文每行 **≤ 72 显示列**（含 URL 的行与 4 空格缩进的代码块豁免）——`git log` 缩进 4 列
后仍不折行。正文用真换行，**不要写字面 `\n`**（shell 里漏写 `$'…'` 就会这样，GitHub
上会渲染成一整行）。示例：

    fix(fuse): readdir 的 probe 入参补上 <uid>/ 层

    probe 与 getattr 现在走同一套前缀剥离，HIDE 条目不再出现在父目录的列举结果里。

### 5.3 粒度

- 多个功能拆多个提交，每段**逐段可编译**，被依赖的修复排在前面。不要攒一个大提交。
- 纯格式化 / 纯机械改动单独成提交，并把哈希加进 `.git-blame-ignore-revs`。

### 5.4 校验清单

`scripts/commit_msg.py lint` 逐条实现下表；任一「拒绝」项命中即退出码 1，提交被拒。

| # | 规则 | 判据 |
|---|---|---|
| 1 | 标题 ≤ 72 显示列 | 目标 50，超出仅提示；> 72 拒绝 |
| 2 | type / scope 取自词表 | scope 只能一个；`B1` 这类内部编号单独报错 |
| 3 | 标题无句号、无 `+` / `；`、无内部编号 | 三者任一即拒 |
| 4 | 标题与正文之间空一行 | 否则拒 |
| 5 | 正文可选，直接描述改动 | 不写「以实现：」这类固定标签 |
| 6 | 正文每行 ≤ 72 显示列 | 含 URL 的行与缩进代码块豁免 |
| 7 | `!` 与 `BREAKING CHANGE:` 成对；trailer 在正文末尾且空一行 | 否则拒 |
| 8 | 不得引用未入库的本地材料 | 黑名单：`.workbuddy-ai`、`review-findings-*`、`review-todo-*`、`.zcode` |
| — | `Merge` / `Revert "` / `fixup!` / `squash!` | git 生成，整体跳过 |

### 5.5 CHANGELOG（让规范有回报）

CHANGELOG 由提交历史生成，复用同一份 conventional 解析，不必手工整理发布说明：

```bash
python3 scripts/commit_msg.py changelog                        # 最近 tag..HEAD → stdout
python3 scripts/commit_msg.py changelog --output CHANGELOG.md  # 已存在则在首个标题后插入
```

### 5.6 正文超宽了怎么办

钩子拒收时不必手工数格子，让工具折：

```bash
python3 scripts/commit_msg.py lint --fix .git/COMMIT_EDITMSG   # 先折行，再校验
python3 scripts/commit_msg.py wrap .git/COMMIT_EDITMSG         # 只折行，不校验
```

`--fix` / `wrap` 只折**正文**（标题超宽是「该重写」而不是「该折行」），并且：列表项保持
结构、URL 不拆断、4 空格缩进的代码块原样保留、结果**幂等**（再跑一次不会变）。

## 6. 设备操作（生产级隔离）

**真机视为生产环境。** 一切设备命令经 `scripts/adb-sh.sh` 执行，
**禁止裸 `adb shell` 做变更**。动手前完整读 `AGENTS.md`「设备操作」一节。

核心纪律（内核强制，非约定）：

- 测试 I/O 一律 `su shell` 降级执行（uid=gid=2000、`CapEff=0`），
  `assert_downgraded()` 每次先验。
- root 只用于建/卸挂载（`/dev/fuse` 0600 只能 root 开），且 `need_root()` 留痕。
- backing 只用 `SAFE_ROOT` 合成 fixture——**生产 backing 永不进测试挂载**；
  需要真实下层行为时 `cp -a` 快照到沙盒。
- 设备侧脚本 source harness 即自动影子危险命令（`rm`/`umount`/`mv`/`cp`/`dd`/`tee`/
  `chcon`/`chmod`/`chown`/`restorecon`/`setenforce`/`kill`），绕过须用 `command` 或
  绝对路径（评审可见）。
- `set -u` 常开；umount 循环卸直到消失，失败即 die 且**错误禁止重定向吞掉**。

## 7. 相关文档

- `docs/README.md` — 文档索引与各文档权威范围
- `docs/testing.md` — 测试分层、验收门、环境坑
- `docs/architecture.md` §7 — 维护规范（命名、归属、不变量）
- `AGENTS.md` — 构建陷阱、逐套件判别性细节、设备操作
