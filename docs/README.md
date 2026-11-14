# 文档索引

每份文档有**明确的归属范围**：同一事实只在一处写权威版本，别处引用而不复述。
这样修改时只需改一处，也便于机器校验（`tests/test_docs_sync.py`）。

## 按角色选起点

| 你要做的事 | 读这个 |
|---|---|
| 第一次接触本项目 | `../README.md` → 本页 → `architecture.md` §1-2 |
| 改框架代码（daemon / injector / 日志） | `architecture.md`（尤其 §7 维护规范）→ `testing.md` |
| 写或移植第三方模块 | `modules.md`（§3 ABI 契约、§6 开发指南） |
| 写规则 / 排查规则不生效 | `config.md`（§7 禁忌清单先看） |
| 跑测试 / 做验收 | `testing.md` |
| 提交代码、开分支、合并 | `../CONTRIBUTING.md`——§1.1 分支模型：默认 `dev`，功能开 `feature/*` 再合回 |
| 构建失败、交叉编译、打包 | `../AGENTS.md`「构建」 |
| 操作真机 | `../AGENTS.md`「设备操作」——**先读完再动手** |

## 各文档的权威范围

| 文档 | 权威内容（唯一出处） | 不在这里写 |
|---|---|---|
| `architecture.md` | 进程架构、规则引擎双通道、热路径、全局状态与并发、源码布局、命名前缀与维护红线 | 模块 ABI 细节、配置语法 |
| `modules.md` | 模块 ABI（`NspModuleInfo`/`NspModuleOps`/`NspFrameworkApi`）、加载与热插拔、故障隔离三层、ABI 演进规则、第三方模块开发 | 框架内部实现、规则语法 |
| `config.md` | 配置文件语法、段与作用域、路径变量、开关语义、禁忌清单 | 规则引擎实现、ABI |
| `testing.md` | 测试分层（L0-L4）、套件映射、退出码约定、验收门、ASan 复跑、隔离跑、环境坑、逐套件判别性细节（§附录） | 构建选项细节 |
| `../AGENTS.md` | 构建陷阱、设备操作纪律、AI 协作约定 | 对外架构说明、逐套件判别性细节（在 `testing.md` §附录） |
| `../CONTRIBUTING.md` | 开发流程、**分支模型**（默认 `dev`、`feature/*`、`main` 只接 `dev` 合并）、代码归属规则、红线、提交与验收规范 | 技术细节本身 |
| `../README.md` | 项目定位、构建入口、产物表、结构总览、许可证 | 任何细节 |

## 代码里的权威出处

文档描述的若干「唯一出处」在代码中的位置，改动时以代码为准、文档随之更新：

| 事实 | 代码出处 |
|---|---|
| 模块 ABI / 框架 API 版本号 | `include/nsp_module.h` 的 `NSP_MODULE_ABI_VERSION` / `NSP_FRAMEWORK_API_VERSION` |
| 跨进程/跨模块常量（`CONFIG_DIR`、`STORAGE_BASE`、uid 布局、行缓冲上限） | `include/nsp_constants.h` |
| 日志级别与宏 | `include/nsp_log.h` |
| 决策结构与虚拟目录种类 | `src/daemon/fw_rules.h` |
| 测试套件映射 / 分层 / 并行白名单 | `tests/run.py` 的 `SUITE_MAP` / `LAYERS` / `PARALLEL_SAFE` |
| 退出码约定 | `tests/run.py` 的 `SKIP_RC` / `GAP_RC` / `MISSING_RC` |

## 文档即契约

文档与实现冲突时**按文档改实现**（已有裁定），而不是把文档改成跟现状一致——
除非确认文档描述的行为本身是错的，此时先在提交信息里说明理由。

文档没写清的决策不要臆断，列为待裁决项。

### 机器校验的部分

`tests/test_docs_sync.py`（L0 层，恒跑）校验这些可证伪的点：

1. 套件台账闭合：`tests/*.py`（`run.py` 与 `_*.py` 助手除外）⊆ `SUITE_MAP` ∪ `ON_DEMAND`，且登记的文件存在
2. 分层完整：`SUITE_MAP` 里每个套件恰好属于一层
3. Tier 自洽：并行白名单与独占 Tier 不指向未知套件、互不重叠
4. 版本号：文档写出的 ABI/API 版本等于 `include/nsp_module.h` 的实际值
5. 路径引用：文档里的 `src/…`、`tests/…` 等路径真实存在
6. 退出码：`testing.md` 写出的 77/78/127 与 `run.py` 常量一致
7. 已删标识符不以「现行机制」口吻出现（V3/V4 删除物）
8. 源码树覆盖：每个 `src/**/*.c` 与 `include/*.h` 都被某条 `SUITE_MAP` 路径谓词命中
   （或登记进 `SOURCE_COVER_EXEMPT` 并写明理由）——否则改它只会跑恒跑基线

第 7 条有意只做**行级**判断。成段的历史记录用显式区域标记圈起来，整段豁免：

```markdown
<!-- history:begin 为什么保留这段历史 -->
…（V3 的旧 ABI 语义等）…
<!-- history:end -->
```

用显式标记而不是「按标题猜」，因为同一节里常把历史与现行混排（`modules.md` §3.3
上半段讲 V3 的 `resolve`、下半段讲现行后端方法）。标记本身也是给读者的提示：
**这段别照着写新代码**。

校验不了的部分（叙述是否准确、例子是否可跑）仍靠评审——所以新增文档段落要带
可验证的锚点（符号名、文件路径、用例名），别只写抽象描述。
