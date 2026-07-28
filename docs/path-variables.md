# 路径变量配置语法

Fuse-Proxy 的 `REDIRECT` / `HIDE` / `RO` / `ALLOW` 规则路径支持变量，按当前命中应用动态展开。

## 系统变量

- `$package`：当前命中 uid 对应的包名（运行时由 `vfs_get_app_cfg` 按 uid 解析，已去掉 `:process` 后缀）。
  - uid<10000 直接判为 `system`，不解析。
  - 解析顺序：`uid.map` 二分查询 → `/proc/<tid>/status` 的 `Tgid`（取主进程 PID）→ `proc_get_cmdline` 读 `cmdline` 去掉 `:` 后缀。
  - 解析出 `zygote`、`<pre-`、长度<3 的进程名视为不可解析，缓存为 `unknown`。

## 用户变量

在配置里用 `NAME=VALUE` 定义（紧凑形式，`=` 两侧无空格，由 `parse_var_assignment` 识别）：

```
[GLOBAL]
DATA_BASE=/sdcard/Android/data/$package
STATIC_BASE=/sdcard/myapp
```

- **作用域**：写在 `[GLOBAL]` 段为全局（所有应用共享）；写在 `[com.xxx:0]` 段为该应用专属，覆盖全局同名变量。运行时 `lookup_var` 先查应用配置、再查全局。
- **值引用**：值可引用其他变量（含 `$package`），运行时递归展开（`expand_into`，最大递归栈 32 层）。循环引用（`A=$B` + `B=$A`）自动检测，保留字面不展开。
- **保留名**：`package` 禁止覆盖（违反时 `LOG_WRN` 告警并忽略该定义）。
- **VALUE 语义**：取 `=` 后行尾原样内容（含内部空格与变量引用），不剥离行内注释——如 `VAR=/x # 备注` 的值是 `/x # 备注`。

## 引用语法

- `$name`：常规引用，如 `$package`、`$DATA_BASE`。
- `${name}`：边界明确，如 `${package}_suffix` 不会把 `_suffix` 当成变量名一部分。
- 变量名规则：`[A-Za-z_][A-Za-z0-9_]*`，大小写敏感。
- 未定义变量保留字面 `$name` 不替换（`parse_dollar` 返回 `ok=false` 时按原字面输出）。
- 未闭合的 `${name`（缺 `}`）按原字面输出。

## 规则示例

```
[GLOBAL]
DATA_BASE=/sdcard/Android/data/$package
MNT_BASE=/mnt/sdcard/$package

REDIRECT /files   $DATA_BASE/files
HIDE     $DATA_BASE/private
RO       $DATA_BASE/cache
REDIRECT /ext     $MNT_BASE
```

不同应用命中同一条规则时，`$package` 替换为各自包名，从而落到各自目录。

## ALLOW 的 `?` 内部前缀

`ALLOW <path>` 在 parse 阶段被等价转换为一条 redirect：虚拟前缀 `<path>`、真实目标 `?<path>`。`?` 是项目内部标记，表示"相对当前用户存储"，运行时由 `vfs_to_real_path` / `build_real_base_from_target` 还原为 `STORAGE_BASE/<user_id><后缀>`。配置文件中一般无需手写 `?`。

同样地，REDIRECT 的相对路径 target（不以 `/` 开头、非系统绝对路径）也会在 parse 阶段被转换为 `?/<原值>` 形式，统一走运行时分类。

## REDIRECT 真实目标的路径分类

`build_real_base_from_target` 对变量展开后的真实目标按以下顺序分类：

| 真实目标形式 | 分类结果 |
|------------|---------|
| `?` 前缀（如 `?/Android/data`） | 当前用户存储：`STORAGE_BASE/<user_id><后缀>`（`?` 后必跟 `/`） |
| `/storage/emulated/X/...` | 归一为当前用户存储：剥离 `/storage/emulated/<N>` 前缀，落到 `STORAGE_BASE/<user_id>/<后缀>` |
| `/data`、`/mnt`、`/storage`（含根目录本身与带子路径形式） | 绝对路径原样（`is_system_abs_path`） |
| 其他以 `/` 开头（如 `/sdcard/...`）或相对路径 | 相对当前用户存储：`STORAGE_BASE/<user_id>/<后缀>` |

> 注：`strip_storage_prefix`（parse 阶段）只处理 `/storage/emulated/<N>` 前缀；`/sdcard` 不被其剥离，而是落到本表最后一行"其他以 `/` 开头"分支，最终归一到当前用户存储。

## 未命中包名

当无法解析真实包名时（`pkg_resolvable` 返回 false），含 `$package` 的规则**失效**（跳过），走默认 fallback。`pkg_resolvable` 判定不可解析的三种场景：

- 包名为 `system`（uid<10000）或 `unknown`（cmdline 解析失败）。
- 包名为空。

> 注：`vfs_get_app_cfg` 解析出含 `zygote`、`<pre-`、长度<3 的进程名时会直接缓存为 nullptr 并返回，此时 `current_pkg` 被填为该字面值（如 `unknown`），后续 `pkg_resolvable` 判为不可解析。

## 静态/动态自动优化

配置加载时 `analyze_var_staticness` 自动分析每个用户变量：

- **静态变量**（值不含 `$package`，传递闭包也无动态因素）：预计算展开值并缓存到 `var_resolved[]`，运行时 `lookup_var` 直接返回缓存值。
- **动态变量**（含 `$package` 或引用动态变量）：每次请求运行时递归展开。

分析采用迭代收敛（最多 `var_count` 轮），收敛后仍未定的循环引用变量视为动态。用户无需关心，自动优化。

## 不支持（YAGNI）

- 虚拟前缀侧（REDIRECT/HIDE/RO/ALLOW 匹配路径的那一侧）不支持 `$package`——含变量的规则无法写入 Trie，仅存线性数组，匹配效率低于纯路径规则。
- `$uid` / `$user_id` 等其他系统变量暂未实现（预留框架）。
- SANDBOX 自定义目录（`SANDBOX_TARGET`）未实现，路径固定为 `/Android/data/<pkg>/sandbox`。

## 参考

- 设计文档：`docs/superpowers/specs/2026-07-05-package-variable-design.md`
