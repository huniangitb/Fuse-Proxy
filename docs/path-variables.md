# 路径变量配置语法

Fuse-Proxy 的 `REDIRECT` / `HIDE` / `RO` / `ALLOW` 规则路径支持变量，按当前命中应用动态展开。

## 系统变量

- `$package`：当前命中 uid 对应的包名（运行时按 uid 解析，已去掉 `:process` 后缀）。

## 用户变量

在配置里用 `NAME=VALUE` 定义（紧凑形式，`=` 两侧无空格）：

```
[GLOBAL]
DATA_BASE=/sdcard/Android/data/$package
STATIC_BASE=/sdcard/myapp
```

- **作用域**：写在 `[GLOBAL]` 段为全局（所有应用共享）；写在 `[com.xxx:0]` 段为该应用专属，覆盖全局同名变量。
- **值引用**：值可引用其他变量（含 `$package`），运行时递归展开。循环引用（`A=$B` + `B=$A`）自动检测，保留字面不展开。
- **保留名**：`package` 禁止覆盖（违反时告警并忽略）。
- **VALUE 语义**：取 `=` 后行尾原样内容（含内部空格与变量引用），不剥离行内注释——如 `VAR=/x # 备注` 的值是 `/x # 备注`。

## 引用语法

- `$name`：常规引用，如 `$package`、`$DATA_BASE`。
- `${name}`：边界明确，如 `${package}_suffix` 不会把 `_suffix` 当成变量名一部分。
- 变量名规则：`[A-Za-z_][A-Za-z0-9_]*`，大小写敏感。
- 未定义变量保留字面 `$name` 不替换。

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

## REDIRECT 真实目标的路径分类

REDIRECT 的真实目标（变量展开后）按以下顺序分类：

- `?` 前缀 / 无前导 `/` 的相对路径（如 `Android/data`）→ 相对当前用户存储（`/data/media/<user_id>/...`）。
- `/storage/emulated/X/...` → 归一为当前用户存储。
- `/data`、`/mnt`、`/storage`（含根目录本身与带子路径形式）→ 绝对路径原样。
- 其他以 `/` 开头（如 `/sdcard/...`）→ 相对当前用户存储。

## 未命中包名

当无法解析真实包名（uid<10000 为 `system`，或查不到包名为 `unknown`）时，含 `$package` 的规则**失效**（跳过），走默认 fallback。

## 静态/动态自动优化

配置加载时自动分析每个用户变量：

- **静态变量**（值不含 `$package`，传递闭包也无动态因素）：预计算展开值并缓存，运行时直接替换。
- **动态变量**（含 `$package`）：每次请求运行时展开。

用户无需关心，自动优化。

## 不支持（YAGNI）

- 虚拟前缀侧（REDIRECT/HIDE/RO 匹配路径的那一侧）不支持 `$package`。
- `$uid` / `$user_id` 等其他系统变量暂未实现（预留框架）。
- SANDBOX 自定义目录（`SANDBOX_TARGET`）未实现。

## 参考

- 设计文档：`docs/superpowers/specs/2026-07-05-package-variable-design.md`
