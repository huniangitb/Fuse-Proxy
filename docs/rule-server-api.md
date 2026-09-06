# rule_server —— 规则控制守护进程 API 文档

## 概述

`rule_server` 是 Fuse-Proxy 的**规则控制守护进程**：前端（Android 应用 / GNU 管理界面）
通过**抽象命名空间 Unix Domain Socket** 以**单行 JSON 协议**与其通信，实现对项目全部规则文件的动态管理。

- **Socket 类型**: `AF_UNIX` / `SOCK_STREAM`（抽象命名空间）
- **Socket 路径**: `nsp_rule_socket`（抽象地址，无文件残留；可用 `--socket` 覆盖）
- **权限要求**: 拥有 `AF_UNIX` 通信权限即可（root / system_app / 同 UID）
- **双平台适配**: Android（`/data/Namespace-Proxy`）与 GNU（`/var/fuse-proxy`）
  均构建运行，路径经 `CONFIG_DIR` 宏 / `--config-dir` 参数适配
- **依赖**: 仅 json-c，无 libfuse3；纯文件级操作，经 injector / fuse_daemon 的
  inotify 热重载联动生效

安装路径：Android `/data/Namespace-Proxy/bin/rule_server`，GNU 见 meson install 输出。

---

## 启动方式

```bash
# 守护进程模式（默认，前台运行）
rule_server
# 指定配置目录与套接字名（测试/多实例）
rule_server --config-dir /var/fuse-proxy --socket nsp_rule_socket
# 客户端模式：发送单条 JSON 命令并打印响应
rule_server -c '{"cmd":"LIST"}'
```

参数：

| 参数 | 说明 |
|------|------|
| （无） | 守护进程模式，监听抽象套接字 `nsp_rule_socket` |
| `-c, --cmd <JSON>` | 客户端模式，连接服务发送一条命令 |
| `--config-dir <dir>` | 覆盖配置根目录（默认 `CONFIG_DIR`） |
| `--socket <name>` | 覆盖抽象套接字名 |
| `-h, --help` | 帮助 |

---

## 协议

客户端连接后发送**一行紧凑 JSON**（末尾 `\n`），服务端处理完成后关闭连接，返回**一行 JSON**。

### 通用响应格式

成功：

```json
{"status":"ok","command":"<CMD>","data":{...},"timestamp":1718000000}
```

失败：

```json
{"status":"error","command":"<CMD>","error":"错误描述","timestamp":1718000000}
```

### 命令速查

| 命令 | 用途 |
|------|------|
| `PING` | 存活探测 |
| `UPTIME` | 查询本守护进程运行时长（单调时钟） |
| `LIST` | 全量规则（全局 + 所有用户空间的应用） |
| `USERS` | 列出全部已配置用户（uid + 目录 + 应用数） |
| `GET` | 查询全局 / 单个应用 / 按 uid 过滤的用户应用 |
| `ADD` | 动态新增规则 / 开关 / 应用注入开关 |
| `REMOVE` | 按 (类型, 索引) 删除规则 |
| `ENABLE` / `DISABLE` | 启用 / 停用规则（`#` 注释切换） |
| `SET` | 设置开关（MONITOR/SANDBOX/GLOBAL_INJECT/INJECT_ENABLE） |
| `FTP_LIST` / `FTP_GET` | 查询 ftp.conf 服务器账号（密码脱敏，只回 `has_password`） |
| `FTP_ADD` / `FTP_SET` / `FTP_REMOVE` | 增改删 ftp.conf 服务器段（原子落盘，ftp_module 经 inotify 自动热重载） |
| `RELOAD` | 向 injector 发送 SIGHUP 触发配置重载 |
| `STOP` | 向 injector 发送 SIGTERM 停止注入服务 |
| `SERVICE` | 服务状态查询与启停控制（log_monitor/injector/fuse_daemon） |
| `STATUS` | 系统状态概览 |
| `QUIT` | 退出本守护进程 |

---

## 命令详解

### 1. PING

```json
{"cmd":"PING"}
{"cmd":"PING","lang":"en"}      // 可选：描述语言，默认中文（zh）
```

响应 `data`：`pong`、`version`、`config_dir`、`socket`、`rule_types`。

`lang` 请求参数（PING/LIST/STATUS 均支持）：控制 `rule_types` 中 `desc`
字段的语言。不传或传未知语言时回退中文；`desc_map` 始终返回该类型的
**全语言描述映射**，前端可据此渲染语言切换。

`rule_types`：当前**全部可用规则类型**（内置 + 已加载模块动态注册），
每项含：

| 字段 | 说明 |
|------|------|
| `type` | 类型名（如 HIDE / FTP） |
| `format` | 值格式：`path`/`pair`/`switch`/`tokens` |
| `builtin` | 是否内置类型 |
| `module` | 来源模块名（内置为 `builtin`） |
| `global_only` | 是否仅全局作用域可用（如 GLOBAL_INJECT/SKIP_SYSTEM_APPS） |
| `argc_min` / `argc_max` | 参数数量约束（`-1`=不限制；pair 默认 2:2、tokens 默认 2:∞），由 `.rules` 声明 `argc=` 覆盖 |
| `desc` | 按请求 `lang` 选取的描述文本（默认中文，未匹配回退 zh） |
| `desc_map` | 全语言描述映射（如 `{"zh":"...","en":"..."}`），仅当模块声明多语言时存在 |

```json
[
  {"type":"HIDE","format":"path","builtin":true,"module":"builtin",
   "global_only":false,"argc_min":1,"argc_max":1,"desc":"隐藏路径","desc_map":{"zh":"隐藏路径"}},
  {"type":"REDIRECT","format":"pair","builtin":true,"module":"builtin",
   "global_only":false,"argc_min":2,"argc_max":2,"desc":"路径重定向","desc_map":{"zh":"路径重定向"}},
  {"type":"FTP","format":"pair","builtin":false,"module":"ftp_module",
   "global_only":false,"argc_min":2,"argc_max":2,
   "desc":"FTP 存储映射：<虚拟前缀>|<段名>",
   "desc_map":{"zh":"FTP 存储映射：<虚拟前缀>|<段名>","en":"FTP storage mapping: <virtual prefix>|<section>"}}
]
```

### 1.1 UPTIME —— 运行时长查询

```json
{"cmd":"UPTIME"}
```

响应 `data`（基于 `CLOCK_MONOTONIC` 单调时钟，系统改时间不影响）：

```json
{
  "uptime_seconds": 3600,
  "uptime": "1小时0分0秒",
  "started_at": 1718000000
}
```

| 字段 | 说明 |
|------|------|
| `uptime_seconds` | 自守护进程启动起的整数秒数 |
| `uptime` | 人类可读时长（X天X小时X分X秒，按需省略高位） |
| `started_at` | 启动时刻墙钟时间戳（epoch 秒） |

### 2. LIST —— 全量规则

```json
{"cmd":"LIST"}
{"cmd":"LIST","lang":"en"}      // 可选：描述语言，默认中文（zh）
```

响应 `data`：

```json
{
  "rule_types": [
    {"type":"HIDE","format":"path","builtin":true,"module":"builtin",
     "global_only":false,"argc_min":1,"argc_max":1,"desc":"隐藏路径"},
    {"type":"FTP","format":"pair","builtin":false,"module":"ftp_module",
     "global_only":false,"argc_min":2,"argc_max":2,
     "desc":"FTP 存储映射：<虚拟前缀>|<段名>"}
  ],
  "global": {
    "file": "/var/fuse-proxy/injector.conf",
    "switches": {"MONITOR": true, "SANDBOX": false, "GLOBAL_INJECT": false},
    "rules": [
      {"index": 0, "type": "HIDE", "value": "/sdcard/secret", "enabled": true},
      {"index": 0, "type": "REDIRECT", "value": "/sdcard/a /sdcard/b", "enabled": true}
    ]
  },
  "apps": [
    {
      "pkg": "com.example.app", "uid": 0,
      "file": "/var/fuse-proxy/App-rules/com.example.app.conf",
      "inject_enable": true,
      "switches": {"MONITOR": true, "SANDBOX": false, "GLOBAL_INJECT": false},
      "rules": [{"index": 0, "type": "HIDE", "value": "/sdcard/app_secret", "enabled": false}]
    }
  ]
}
```

- `global.switches` / `apps[].switches`：开关状态（布尔）
- `rules[].index`：**该类型内**的从 0 起始索引（含已停用行），供 REMOVE/ENABLE/DISABLE 使用
- `rules[].enabled`：是否启用（`false` = 文件中被 `#` 注释，解析器跳过）
- `rules[].module`：该规则类型的来源（`builtin` 或模块名）
- `apps[].inject_enable`：应用规则启用状态——存在 `<pkg>.conf`（未被重命名为 `.disabled`）即启用；仅存在 `.conf.disabled` 或两者皆无视为停用（不再读取 injector.conf 段头）

### 3. GET —— 查询单作用域

```json
{"cmd":"GET","pkg":"GLOBAL"}
{"cmd":"GET","pkg":"com.example.app","uid":0}
{"cmd":"GET","uid":10}
```

- `pkg` 省略或为 `GLOBAL` 时返回全局段；`pkg` 为 `USER_APPS`/`SYSTEM_APPS`
  时返回类别段视图（`data.category`：主文件内精确段头切片，含 `section` 段头名；
  其中 `rules[].index` 为**段内局部序号**，仅展示用）；否则返回该应用。
- `uid` 默认 `0`（多用户场景指定用户，见下；类别段 `USER_APPS` 按 `uid` 选段）。
- **uid 过滤**：`GET {"uid":10}` 返回全局快照 + uid 10 用户空间的全部应用；
  `GET {"pkg":"GLOBAL","uid":10}` 同理。

响应 `data`：`global`、`app` 或 `category` 对象（`global`/`app` 结构与 LIST 内对应项一致）。

```json
{"cmd":"GET","pkg":"USER_APPS","uid":10}
{"cmd":"GET","pkg":"SYSTEM_APPS"}
```

### 3.1 USERS —— 多用户列表

```json
{"cmd":"USERS"}
```

响应 `data.users`：全部已配置用户空间（`App-rules` = uid 0，
`App-rules-<uid>` = uid > 0），每项含 `uid`、`dir`、`app_count`：

```json
[
  {"uid": 0,  "dir": "/var/fuse-proxy/App-rules",     "app_count": 3},
  {"uid": 10, "dir": "/var/fuse-proxy/App-rules-10",  "app_count": 2}
]
```

前端可先 `USERS` 枚举用户，再以 `uid` 参数操作各用户空间的规则
（ADD/REMOVE/ENABLE/DISABLE/SET/INJECT_ENABLE 均支持 `uid`）。
uid 合法范围 0~100000，超范围返回错误。

### 3.2 多用户规则存储

- **uid 0**（主用户）：`App-rules/<pkg>.conf`
- **uid > 0**（副用户/工作空间）：`App-rules-<uid>/<pkg>.conf`

各用户空间相互隔离：同名包可在不同 uid 下配置不同规则；
应用规则停用/启用（`.disabled` 重命名）只在对应用户目录内生效。

### 4. ADD —— 动态新增

```json
{"cmd":"ADD","pkg":"GLOBAL","type":"HIDE","value":"/sdcard/secret"}
{"cmd":"ADD","pkg":"GLOBAL","type":"REDIRECT","value":"/sdcard/a|/sdcard/b"}
{"cmd":"ADD","pkg":"com.example.app","type":"RO","value":"/sdcard/protected","uid":0}
```

| type | value 格式 | 说明 |
|------|-----------|------|
| `REDIRECT` | `src\|dst` | 虚拟路径\|真实路径（与 log_ctl set-rule 一致） |
| `ALLOW` | 路径 | 放行规则 |
| `HIDE` | 路径 | 隐藏规则 |
| `RO` | 路径 | 只读规则 |
| `MONITOR`/`SANDBOX` | `ON`/`OFF` | 开关（GLOBAL 段替换，应用段写应用文件） |
| `INJECT_ENABLE` | `ON`/`OFF` | 仅应用作用域：启用/停用应用规则（见下） |
| 模块注册类型 | 依 `rule_types[].format` + `argc_min/argc_max` | 动态追加：`path`=路径、`pair`=`\|` 分隔**恰好 2 值**（如 `FTP /云盘\|云盘`）、`tokens`=`\|` 分隔多值；参数数量按类型声明的 `argc=` 约束校验（模块 `.rules` 可自定义，如 `argc=3` / `argc=2:4`），不满足返回错误 |

模块类型由 `<模块名>.rules` 文件动态注册（详见 `docs/modules.md`），
声明的属性（argc 参数约束、global-only 作用域、多语言 desc）全部由
rule_server 在运行时解析并体现在 `rule_types` 中，前端无需硬编码任何模块类型。

### INJECT_ENABLE —— 应用规则启用/停用（`.disabled` 文件重命名）

应用规则的启用/停用**不接触 injector.conf**（其 `[pkg:uid]` 段头仅控制注入挂载），
通过重命名 `App-rules/<pkg>.conf` 文件实现：

- `OFF`（停用）→ 重命名为 `<pkg>.conf.disabled`，配置解析器只加载 `.conf` 后缀，
  该应用的规则即不生效
- `ON`（启用）→ 去掉 `.disabled` 后缀，规则重新生效；无规则文件时创建空配置文件
- LIST 返回的 `apps[]` 仍包含已停用应用（`inject_enable:false` + `disabled_file:true`），
  前端可据此展示并重新启用

### 全局专属类型（仅 `[GLOBAL]` 段可用）

以下类型**只能在全局规则中使用**，配置到应用作用域时 ADD/SET 返回错误：

- `GLOBAL_INJECT`（全局注入）
- `SKIP_SYSTEM_APPS`（跳过系统应用）

应用配置文件（`App-rules/<pkg>.conf`）中不允许出现上述类型。

- `pkg=GLOBAL` 写入 `injector.conf` 的 `[GLOBAL]` 段（开关替换、规则去重插入）。
- `pkg=<应用>` 写入 `App-rules/<pkg>.conf`（uid>0 时 `App-rules-<uid>/`），目录不存在自动创建。
- `pkg=USER_APPS`/`SYSTEM_APPS` 写入 `injector.conf` 的精确类别段头
  （`[USER_APPS:<uid>]`，`uid` 默认 0；`[SYSTEM_APPS]`），开关替换、规则去重插入；
  控制面恒写显式 `:uid`，裸 `[USER_APPS]`（跨用户 fallback）仅支持手写配置；
  `INJECT_ENABLE` 不适用于类别段（启停请直接编辑段头 `ON`/`OFF`），
  `GLOBAL_INJECT`/`SKIP_SYSTEM_APPS` 仍仅 `[GLOBAL]` 可用。
- 重复规则幂等（去重，返回 `duplicate:true`）。

```json
{"cmd":"ADD","pkg":"USER_APPS","uid":10,"type":"HIDE","value":"/sdcard/secret"}
{"cmd":"ADD","pkg":"SYSTEM_APPS","type":"REDIRECT","value":"/sdcard/a|/sdcard/b"}
```

### 5. REMOVE —— 删除规则

```json
{"cmd":"REMOVE","pkg":"GLOBAL","type":"RO","index":0}
{"cmd":"REMOVE","pkg":"com.example.app","type":"HIDE","index":1,"uid":0}
```

按 `type` 内第 `index` 条（含已停用行）删除，索引与 LIST 输出一致。
类别段（`pkg=USER_APPS`/`SYSTEM_APPS`）路由到主文件，用**主文件全局索引**
（与 `pkg=GLOBAL` 语义一致；`GET category` 返回的是段内局部序号，仅展示用）。

### 6. ENABLE / DISABLE —— 启用 / 停用规则

```json
{"cmd":"DISABLE","pkg":"GLOBAL","type":"HIDE","index":0}
{"cmd":"ENABLE","pkg":"com.example.app","type":"HIDE","index":1,"uid":0}
```

- 停用 = 行首加 `#`（配置解析器自动跳过注释行），启用 = 去除 `#`。
- 开关类型（MONITOR 等）请用 `SET` 设置 ON/OFF。

### 7. SET —— 设置开关

```json
{"cmd":"SET","pkg":"GLOBAL","type":"SANDBOX","value":"ON"}
{"cmd":"SET","pkg":"com.example.app","type":"INJECT_ENABLE","value":"OFF","uid":0}
```

复用 ADD 的写入逻辑（INJECT_ENABLE 仅应用作用域有效）。

### 7.1 FTP —— 服务器账号管理（ftp.conf）

基于公共 `nsp_ini_store` 抽象（`include/nsp_ini_store.h`，第三方模块可借用）：
注释保留的行级读写 + 临时文件 rename 原子落盘；`ftp_module` 经 inotify
监听目录自动热重载，改完即生效，无需 RELOAD。

安全：`password` 只写不读——`FTP_LIST`/`FTP_GET` 绝不回传密码明文，
仅回 `has_password` 布尔。`ftp.conf` 本身明文落盘（与模块解析现状一致，
备份/分享配置目录时注意脱敏）。

段名允许中文（如`云盘`，不用包名字符集校验），仅禁 `\n\r[]`；
`[GLOBAL]` 非服务器段，控制面拒绝写入该名。字段上限与 `FtpServerCfg`
对应：段名≤63、`host`≤255、`user`≤63、`password`≤127、`remote_dir`≤511；
`port` 1~65535（缺省 21）；`user` 缺省 `anonymous`、`remote_dir` 缺省 `/`
（LIST/GET 回填生效值，与模块行为一致）。
字段值禁 `\n\r#`（`#` 为行内注释起点，放行会导致读回截断）；落盘文件
权限收紧为 0600（含已存在文件的旧权限一并收紧）。

```json
{"cmd":"FTP_LIST"}
{"cmd":"FTP_GET","name":"云盘"}
{"cmd":"FTP_ADD","name":"云盘","host":"192.168.1.100","port":21,
 "user":"myuser","password":"mypass","remote_dir":"/"}
{"cmd":"FTP_SET","name":"云盘","key":"host","value":"10.0.0.1"}
{"cmd":"FTP_REMOVE","name":"云盘"}
```

- `FTP_LIST` → `data{file, servers[]}`，每项
  `{name,host,port,user,remote_dir,has_password}`。
- `FTP_GET` → 同形状单对象（+ `file`）；段不存在返回 error。
- `FTP_ADD`：段不存在时 `host` 必填；同名且所给字段与现状一致返回
  `duplicate:true, changed:false` 免写；空字符串的可选字段视为"不写该键"
  （走模块缺省；清空请用 `FTP_SET` 传空值删键）；`password` 统一写
  `password` 键并清理旧 `pass` 别名。
- `FTP_SET`：`key` 限 `host/port/user/password/remote_dir`（`pass` 归一
  `password`）；空值 = 删键回缺省；段不存在报错（新建请用 `FTP_ADD`）；
  同值免写（`changed:false`）。
- `FTP_REMOVE`：整段删除；段不存在返回 error。

### 8. RELOAD / STOP

```json
{"cmd":"RELOAD"}
{"cmd":"STOP"}
```

- `RELOAD`：向 injector（`injector.pid`）发送 `SIGHUP` 触发配置重载。
- `STOP`：向 injector 发送 `SIGTERM` 停止注入服务（injector 会清理其 FUSE 守护进程）。
- 正常情况下无需手动 RELOAD：规则文件变更由 injector / fuse_daemon 的 inotify 自动热重载。

### 8.1 SERVICE —— 服务状态查询与启停控制

查询/控制常驻服务（`log_monitor`、`injector`、`fuse_daemon`），
能力等价于模块的 `service.sh`（可远程拉起/停止/重启服务）：

```json
{"cmd":"SERVICE"}                              // 默认 status
{"cmd":"SERVICE","action":"status"}            // 查询全部服务状态
{"cmd":"SERVICE","action":"start"}             // 启动 log_monitor + injector（fuse_daemon 由 injector 拉起）
{"cmd":"SERVICE","action":"stop"}              // 停止 injector/fuse_daemon/log_monitor
{"cmd":"SERVICE","action":"restart"}           // 先停全部再启动
```

`status` 响应 `data`：

```json
{
  "rule_server": {"pid": 1234, "alive": true},
  "injector":    {"pid": 1230, "alive": true},
  "fuse_daemon": {"pid": 1232, "alive": true},
  "log_monitor": {"pid": 1228, "alive": true},
  "ready": true
}
```

- 各进程对象均含 `pid` 与 `alive`；`ready` = 三个常驻服务（injector/fuse_daemon/log_monitor）全部存活。
- 进程检测：injector 优先 `injector.pid` 文件，回退 `/proc` 按名匹配；fuse_daemon/log_monitor 按 `/proc` comm 匹配，**自动跳过僵尸进程**。
- `start`/`stop`/`restart` 响应 `data` 含 `started`/`stopped`/`failed` 计数（restart 合并 stop+start）。
- 启动依赖二进制与本程序同目录（`bin_dir`）；`start` 会先清理残留进程再拉起，避免重复实例。

### 9. STATUS

```json
{"cmd":"STATUS"}
```

响应 `data`：`version`、`config_dir`、`socket`、`injector{pid,alive}`、`global`（结构同 LIST 的 global）。

### 10. QUIT

```json
{"cmd":"QUIT"}
```

令守护进程优雅退出（测试/管理用），随后服务端关闭监听。

---

## 安全校验

- 包名仅允许 `[A-Za-z0-9._-]`，禁止 `/` 与 `..`（防路径穿越）。
- 规则值禁止换行/回车，长度上限 `MAX_LINE-64`。
- 未知命令、未知类型、非法索引均返回 `error` 状态，不修改任何文件。

---

## Android 接入要点

Android Java 层标准 `LocalSocket` 不支持抽象命名空间地址，推荐两种方式：

1. **进程调用**（与 log_ctl 方案一致）：通过 `ProcessBuilder` 调用
   `rule_server -c '<JSON>'`，解析 stdout 的 JSON 响应。
2. **原生接入**：JNI 中直接 `socket(AF_UNIX)` + `connect("\0nsp_rule_socket")`，
   写入一行 JSON，读取一行响应。

## 文件清单

| 文件 | 说明 |
|------|------|
| `src/rule/rule_server.c` | 守护进程 + 客户端模式实现（单文件） |
| `include/common.h` | `RULE_SOCKET_NAME` 常量 |
| `meson.build` | `rule_server` 构建目标（Android/GNU 均构建） |
| `tests/test_rule_server.py` | 端到端测试（PING/LIST/ADD/REMOVE/ENABLE/DISABLE/SET/STATUS/QUIT + 模块动态类型、多语言 desc、argc 约束、顺序任意与畸形声明） |
