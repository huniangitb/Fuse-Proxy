# log_ctl 前端 API 接入文档

## 概述

`log_ctl` 是 Fuse-Proxy 的命令行工具，提供日志查询、配置管理、规则编辑等功能。前端应用可通过 `api` 参数获得**结构化 JSON 输出**，方便程序化调用。

> 安装路径：`/data/Namespace-Proxy/bin/log_ctl`

---

## 配置文件结构

理解配置结构是正确使用 API 的前提。

### 主配置文件 `injector.conf`

三段式 INI 风格：

```
[GLOBAL]
GLOBAL_INJECT OFF
MONITOR ON
SANDBOX OFF
RO /123云盘/Cache/
RO /HyperOS_Sandbox/

[com.termux:0] OFF
[com.tencent.mobileqq:0] ON
[com.dragon.read:0] OFF
[com.android.providers.media.module:0] ON
```

- `[GLOBAL]` 段：全局开关（`GLOBAL_INJECT`、`MONITOR`、`SANDBOX`）及全局规则（`RO`、`HIDE`、`REDIRECT`）
- `[pkg:user_id]` 段：应用注入开关，`ON` = 启用注入，`OFF` = 禁用

### 应用规则文件 `App-rules/<pkg>.conf`

存放具体规则，每行一条：

```
HIDE /sdcard/secret
RO /sdcard/protected
REDIRECT /sdcard/A /sdcard/B
MONITOR ON
```

> **`:0` 默认**：未指定 user_id 的包名默认附加 `:0`

### 配置重载机制

Injector 通过 `inotify` 监听配置文件变更，修改文件后**自动重载**，无需手动触发。

---

## 通用响应格式

### ✅ 成功响应

```json
{"status":"ok","command":"<command-name>","data":{...},"timestamp":1719523200}
```

### ❌ 错误响应

```json
{"status":"error","command":"<command-name>","error":"错误描述信息","timestamp":1719523200}
```

> `data` 字段的内容因命令而异（详见各命令说明）。
> **注意**：所有 JSON 输出均为紧凑单行格式（无多余换行和缩进），`data` 字段内部的结构化 JSON 亦然。文档中为便于阅读使用格式化展示。

---

## 全局选项

所有命令均支持以下全局选项，可放在任意位置：

| 选项 | 说明 | 默认 |
|------|------|------|
| `api` | 启用 JSON 结构化输出（所有命令都支持） | 关闭（纯文本） |
| `--uid <uid>` | 指定用户 ID（多用户场景） | `0` |
| `-u` | 日志输出强制显示 UID | 关闭 |
| `--level <level>` | 日志级别过滤（search/stream 类命令） | 见各命令 |
| `--static` | 搭配 `get-config` 使用，从磁盘读取原始文件 | 从内存读取 |

### 日志级别

| 值 | 级别 |
|----|------|
| `0` | DEBUG |
| `1` | INFO |
| `2` | WARN |
| `3` | ERROR |
| `-1` | 全部（仅 search 有效） |

`--level` 除数字外也支持级别名（大小写不敏感，映射到对应数字）：
`debug`→`0`、`info`→`1`、`warn`/`warning`→`2`、`error`/`err`→`3`。
示例：`log_ctl search-sys --level error '' 10 0` 等价于
`log_ctl search-sys --level 3 '' 10 0`。

### 调用建议

通过 `ProcessBuilder` 或 `Runtime.exec()` 调用，直接在命令行末尾添加 `api`：

```kotlin
// Kotlin 示例
fun logCtl(vararg args: String): String {
    val proc = ProcessBuilder()
        .command("/data/Namespace-Proxy/bin/log_ctl", *args, "api")
        .redirectErrorStream(false)
        .start()
    val stdout = proc.inputStream.readBytes().decodeToString()
    val exitCode = proc.waitFor(5, TimeUnit.SECONDS)
    if (exitCode != 0 || !proc.isAlive) throw IOException("log_ctl 失败: $stdout")
    return stdout.trim()
}
```

---

## 命令速查表

| 类别 | 命令 | 用途 |
|------|------|------|
| **系统状态** | [`status`](#1-status--系统状态概览) | 全面系统状态概览 |
| **配置查看** | [`get-config`](#2-get-config--获取内存中配置) | 获取注入器内存中的解析后配置（紧凑 JSON） |
| | [`get-config --static`](#3-get-config---static--从磁盘读取完整配置) | 从磁盘读取 `injector.conf` 解析为结构化 JSON |
| | [`stream-config`](#4-stream-config--订阅配置变更) | 订阅实时配置变更推送 |
| **规则解析** | [`parse-rules`](#5-parse-rules--本地解析规则) | 本地重新解析规则文件，输出结构化 JSON |
| | [`get-global-rules`](#6-get-global-rules--查看全局规则) | 查看本地 `[GLOBAL]` 段全部规则（开关+路径） |
| | [`get-app-rules`](#7-get-app-rules--查看指定应用规则) | 根据包名查看指定应用的配置和规则 |
| | [`validate-rules`](#8-validate-rules--验证规则) | 验证规则文件语法正确性 |
| **规则编辑** | [`set-rule`](#9-set-rule--添加规则) | 向 `App-rules/<pkg>.conf` 追加规则 |
| | [`remove-rule`](#10-remove-rule--删除规则) | 从 `App-rules/<pkg>.conf` 删除指定规则 |
| | [`reload-config`](#11-reload-config--重载配置) | 向注入器发送 SIGHUP 显式触发重载 |
| **注入状态** | [`list-injected`](#14-list-injected--已注入列表) | 查看已注入应用列表 |
| | [`list-users`](#15-list-users--活跃用户列表) | 查看当前活跃用户及对应应用数 |
| **日志查询** | [`search-io / search-sys`](#16-search-io--search-sys--查询日志) | 查询 I/O 或系统日志 |
| | [`clear-io / clear-sys`](#13-clear-io--clear-sys--清除日志) | 清除 I/O 或系统日志 |
| | [`log-count`](#17-log-count--日志统计) | 获取各日志缓冲区总计条数 |
| **流式日志** | [`stream-io / stream-sys / stream-logcat / stream-all`](#18-流式日志命令) | 实时流式输出日志 |
| **前端接入** | [日志格式与前端展示规范](#日志格式与前端展示规范) | 日志格式解析规则、前端格式化显示建议 |

> ⚠️ **重要**：`stream-*` 和 `stream-config` 是长连接命令，会持续输出直到进程被终止。前端调用时应当**异步启动进程**，逐行读取 stdout。

---

## 1. `status` — 系统状态概览

获取注入器、FUSE 守护进程的运行状态及配置统计。

### 调用

```bash
log_ctl status api
```

### 响应 (data)

```json
{
  "timestamp": 1719523200,
  "time": "2024-06-28T00:20:00",
  "injector": {
    "pid": 1234,
    "alive": true
  },
  "fuse": {
    "pid": 5678,
    "alive": true
  },
  "config": {
    "main_conf_path": "/data/Namespace-Proxy/injector.conf",
    "main_conf_size": 2048,
    "app_rule_files": 12,
    "parsed_apps_in_memory": 8
  },
  "system": {
    "config_dir": "/data/Namespace-Proxy",
    "pid_file": "/data/Namespace-Proxy/injector.pid"
  }
}
```

### 字段说明

| 路径 | 类型 | 说明 |
|------|------|------|
| `injector.pid` | int | 注入器进程 PID |
| `injector.alive` | bool | 注入器是否存活 |
| `fuse.pid` | int | FUSE 守护进程 PID（从 mountinfo 解析） |
| `fuse.alive` | bool | FUSE 是否存活 |
| `config.main_conf_size` | int | `injector.conf` 字节数 |
| `config.app_rule_files` | int | `App-rules` 目录中的 `.conf` 文件数 |
| `config.parsed_apps_in_memory` | int | 内存中已解析的应用配置数 |

---

## 2. `get-config` — 获取内存中配置

向注入器广播服务请求当前内存中的已解析配置 JSON。

### 调用

```bash
log_ctl get-config api
```

### 响应 (data)

返回注入器 `config_publisher` 推送的完整配置 JSON（紧凑单行格式，最大 256KB）。前端直接访问 `data` 字段（已为 JSON 对象）即可。

返回结构（格式化展示）：

```json
{"timestamp":1719523200,"injector":{"pid":1234,"passive":false,"mode":"active"},"global_fuse":{"fuse_pid":5678,"disabled":false},"templates":[{"template_name":"GLOBAL","hook_operation":["query","insert"],"apply_to_app":["*"],"enable_sandbox":false,"global_inject":true,"fuse_direct":false,"hide_paths":["/sdcard/secret"],"read_only_path":[],"redirect_rules":[]}]}
```

---

## 3. `get-config --static` — 从磁盘读取完整配置

从磁盘读取 `injector.conf` 并解析为结构化 JSON，按规则类型拆分输出。

### 调用

```bash
log_ctl get-config --static api
```

### 响应 (data)

```json
{"timestamp":1719523200,"type":"static","global":{"switches":{"global_inject":"OFF","monitor":"ON","sandbox":"OFF","fuse_direct":"OFF"},"ro_rules":["/123 云盘/Cache/","/HyperOS_Sandbox/"],"hide_rules":[],"redirect_rules":["/sdcard/src /sdcard/dst"],"allow_rules":[]},"apps":[{"pkg":"com.termux","user_id":0,"inject_enable":"OFF"},{"pkg":"com.tencent.mobileqq","user_id":0,"inject_enable":"ON"}],"app_rules":[{"file":"com.tencent.mobileqq.conf","user_dir":"App-rules","content":"SANDBOX ON\n"}]}
```

### 字段说明

| 路径 | 类型 | 说明 |
|------|------|------|
| `global.switches` | object | 全局开关值：`global_inject`、`monitor`、`sandbox`、`fuse_direct`（`"ON"` / `"OFF"`） |
| `global.ro_rules` | string[] | 全局 RO 规则路径列表 |
| `global.hide_rules` | string[] | 全局 HIDE 规则路径列表 |
| `global.redirect_rules` | string[] | 全局 REDIRECT 规则列表 |
| `global.allow_rules` | string[] | 全局 ALLOW 规则路径列表 |
| `apps` | object[] | `injector.conf` 中 `[pkg:uid]` 段解析出的应用开关列表 |
| `apps[].pkg` | string | 包名 |
| `apps[].user_id` | int | 用户 ID |
| `apps[].inject_enable` | string | `"ON"` 或 `"OFF"` |
| `app_rules` | object[] | `App-rules/` 目录下的每个应用规则文件 |
| `app_rules[].file` | string | 文件名（如 `com.tencent.mobileqq.conf`） |
| `app_rules[].user_dir` | string | 所在用户目录（如 `App-rules`、`App-rules-10`） |
| `app_rules[].content` | string | 文件原始内容（转义字符串） |

---

## 4. `stream-config` — 订阅配置变更

订阅注入器的实时配置变更推送。**长连接命令**，需要异步处理。

### 调用

```bash
log_ctl stream-config api
```

### 输出格式

每收到一次配置变更，输出一行 JSON：

```json
{"status":"ok","command":"stream-config","data":{"timestamp":1719523200,"injector":{"pid":1234,"passive":false,"mode":"active"},"global_fuse":{"fuse_pid":5678,"disabled":false},"templates":[...]},"timestamp":1719523200}
```

### 前端处理方式

```kotlin
// Kotlin 示例 — 异步流式读取
fun streamConfig(callback: (String) -> Unit): Process {
    val proc = ProcessBuilder()
        .command("/data/Namespace-Proxy/bin/log_ctl", "stream-config", "api")
        .start()

    thread {
        proc.inputStream.bufferedReader().use { reader ->
            var line = reader.readLine()
            while (line != null) {
                callback(line)
                line = reader.readLine()
            }
        }
    }
    return proc // 外部可通过 proc.destroy() 停止
}
```

---

## 5. `parse-rules` — 本地解析规则

直接从磁盘加载并解析全部规则文件（`injector.conf` + `App-rules/*.conf`），输出结构化 JSON（不依赖注入器内存）。

### 调用

```bash
log_ctl parse-rules api
```

### 响应 (data)

```json
{
  "global": {
    "sandbox": false,
    "global_inject": true,
    "fuse_direct": false,
    "monitor": false,
    "inject_enable": true,
    "hide_count": 3,
    "ro_count": 1,
    "redir_count": 5
  },
  "apps": [
    {
      "pkg": "com.tencent.mobileqq",
      "user_id": 0,
      "inject_enable": true,
      "monitor": false,
      "sandbox": true,
      "fuse_direct": false,
      "hide_count": 2,
      "ro_count": 0,
      "redir_count": 1
    }
  ]
}
```

`apps[].inject_enable` 对应 `injector.conf` 中 `[pkg:uid] ON/OFF` 开关。

---

## 6. `get-global-rules` — 查看全局规则

本地解析 `injector.conf` 并查看 `[GLOBAL]` 段全部规则（开关 + 路径列表）。

### 调用

```bash
log_ctl get-global-rules api
```

### 响应 (data)

```json
{"switches":{"global_inject":false,"monitor":true,"sandbox":true,"fuse_direct":false},"hide_rules":["/sdcard/secret"],"ro_rules":["/123 云盘/Cache/","/HyperOS_Sandbox/"],"redirect_rules":[{"virtual_prefix":"/sdcard/A","real_target":"/data/B"}],"allow_rules":[],"fuse_extra_args":"","counts":{"hide":1,"ro":2,"redirect":1,"allow":0}}
```

### 字段说明

| 路径 | 类型 | 说明 |
|------|------|------|
| `switches` | object | 全局开关：`global_inject`、`monitor`、`sandbox`、`fuse_direct` |
| `hide_rules` | string[] | HIDE 路径列表 |
| `ro_rules` | string[] | RO 路径列表 |
| `redirect_rules` | object[] | REDIRECT 规则列表（含 `virtual_prefix` 和 `real_target`） |
| `allow_rules` | object[] | ALLOW 规则列表（含 `virtual_prefix` 和 `real_target`） |
| `counts` | object | 各规则数量统计 |
| `counts.hide` | int | HIDE 规则数量 |
| `counts.ro` | int | RO 规则数量 |
| `counts.redirect` | int | REDIRECT 规则数量 |
| `counts.allow` | int | ALLOW 规则数量 |

---

## 7. `get-app-rules` — 查看指定应用规则

根据包名查看指定应用的配置和规则。本地解析磁盘文件，不依赖注入器。

### 调用

```bash
log_ctl get-app-rules <pkg> [--uid uid] [api]
```

| 参数 | 说明 |
|------|------|
| `pkg` | 包名 |
| `--uid` | 可选，用户 ID（默认 0） |

### 示例

```bash
log_ctl get-app-rules com.tencent.mobileqq api
log_ctl get-app-rules com.example.app --uid 10
log_ctl get-app-rules com.tencent.mobileqq   # 纯文本模式
```

### 响应 (data) — api 模式

```json
{"pkg":"com.tencent.mobileqq","user_id":0,"switches":{"inject_enable":true,"monitor":false,"sandbox":true,"fuse_direct":false},"hide_rules":["/sdcard/secret"],"ro_rules":[],"redirect_rules":[],"allow_rules":[],"counts":{"hide":1,"ro":0,"redirect":0,"allow":0}}
```

### 响应 (data) — 文本模式

```
===== 应用规则: com.tencent.mobileqq (UID 0) =====

--- Switch 开关 ---
  INJECT_ENABLE ON
  MONITOR       OFF
  SANDBOX       ON
  FUSE_DIRECT   OFF

--- HIDE 规则 (1 条) ---
  [0] HIDE /sdcard/secret
```

### 字段说明

| 路径 | 类型 | 说明 |
|------|------|------|
| `pkg` | string | 包名 |
| `user_id` | int | 用户 ID |
| `switches` | object | 应用级开关 |
| `switches.inject_enable` | bool | 是否启用注入 |
| `switches.monitor` | bool | 是否启用监控 |
| `switches.sandbox` | bool | 是否启用沙箱 |
| `switches.fuse_direct` | bool | 是否启用 FUSE 直通 |
| `hide_rules` | string[] | HIDE 路径列表 |
| `ro_rules` | string[] | RO 路径列表 |
| `redirect_rules` | object[] | REDIRECT 规则列表 |
| `allow_rules` | object[] | ALLOW 规则列表 |
| `counts` | object | 各规则数量统计 |
| `counts.hide` | int | HIDE 规则数量 |
| `counts.ro` | int | RO 规则数量 |
| `counts.redirect` | int | REDIRECT 规则数量 |
| `counts.allow` | int | ALLOW 规则数量 |

---

## 8. `validate-rules` — 验证规则

验证磁盘上全部规则文件的语法正确性。

### 调用

```bash
log_ctl validate-rules api
```

### 响应 (data)

```json
{
  "valid": true,
  "app_count": 8,
  "global_hide_rules": 3,
  "global_ro_rules": 1,
  "global_redir_rules": 5
}
```

---

## 9. `set-rule` — 添加规则

向指定应用的 `App-rules/<pkg>.conf` 文件中**追加**一条规则。

> ⚠️ 如需修改 `injector.conf` 中的 `[pkg:uid] ON/OFF` 开关，请直接编辑 `injector.conf` 文件。`set-rule` 仅操作 `App-rules/` 目录下的应用规则文件。

### 调用

```bash
log_ctl set-rule <pkg> <type> <value> [--uid uid] [api]
```

### 参数

| 参数 | 说明 |
|------|------|
| `pkg` | 包名。使用 `GLOBAL` 操作 `injector.conf` 中的 `[GLOBAL]` 段 |
| `type` | 规则类型（见下表） |
| `value` | 规则值。`REDIRECT` 类型格式为 `src\|dst` |
| `--uid` | 可选，用户 ID（默认 0，即包名后附加 `:0`） |

### 规则类型

| type | value 格式 | 写入目标文件 |
|------|-----------|-------------|
| `HIDE` | `<路径>` | `App-rules/<pkg>.conf` |
| `RO` | `<路径>` | `App-rules/<pkg>.conf` |
| `REDIRECT` | `<源路径\|目标路径>` | `App-rules/<pkg>.conf` |
| `ALLOW` | `<路径>` | `App-rules/<pkg>.conf` |
| `MONITOR` | `ON` 或 `OFF` | `App-rules/<pkg>.conf` |
| `SANDBOX` | `ON` 或 `OFF` | `App-rules/<pkg>.conf` |
| `GLOBAL_INJECT` | `ON` 或 `OFF` | 仅 `pkg=GLOBAL` 时写入 `injector.conf` `[GLOBAL]` 段 |
| `FUSE_DIRECT` | `ON` 或 `OFF` | 仅 `pkg=GLOBAL` 时写入 `injector.conf` `[GLOBAL]` 段 |

### 示例

```bash
# 为 com.tencent.mobileqq 添加一条 HIDE 规则
log_ctl set-rule com.tencent.mobileqq HIDE /data/local/tmp/secret api

# 添加 REDIRECT 规则
log_ctl set-rule com.tencent.mobileqq REDIRECT "/sdcard/A|/sdcard/B" api

# 为 用户 10 的 com.example.app 添加规则
log_ctl set-rule com.example.app HIDE /data/local/tmp/secret --uid 10 api

# 全局 [GLOBAL] 段追加 GLOBAL_INJECT ON
log_ctl set-rule GLOBAL GLOBAL_INJECT ON api

# 全局 [GLOBAL] 段追加 RO 规则
log_ctl set-rule GLOBAL RO /data/media/0/secret api
```

### 响应 (data)

```json
{
  "file": "/data/Namespace-Proxy/App-rules/com.tencent.mobileqq.conf",
  "line": "HIDE /data/local/tmp/secret\n",
  "pkg": "com.tencent.mobileqq",
  "type": "HIDE",
  "value": "/data/local/tmp/secret"
}
```

> ⚠️ `set-rule` 写入文件后，Injector 会通过 `inotify` 自动感知文件变更并重载（非 api 模式下还会额外发送 SIGHUP 信号确保即时生效）。

---

## 10. `remove-rule` — 删除规则

从 `App-rules/<pkg>.conf` 文件中删除指定索引的规则。

### 调用

```bash
log_ctl remove-rule <pkg> <type> <index> [--uid uid] [api]
```

### 参数

| 参数 | 说明 |
|------|------|
| `pkg` | 包名。使用 `GLOBAL` 操作 `injector.conf` 中的 `[GLOBAL]` 段 |
| `type` | 规则类型 |
| `index` | 要删除的规则索引，从 0 开始计数（仅统计该 type 的规则） |
| `--uid` | 可选，用户 ID（默认 0） |

### 示例

```bash
# 删除 com.tencent.mobileqq 的第 2 条 HIDE 规则
log_ctl remove-rule com.tencent.mobileqq HIDE 2 api

# 删除 [GLOBAL] 段的第 0 条 REDIRECT 规则
log_ctl remove-rule GLOBAL REDIRECT 0 api
```

### 响应 (data)

```json
{
  "file": "/data/Namespace-Proxy/App-rules/com.tencent.mobileqq.conf",
  "pkg": "com.tencent.mobileqq",
  "type": "HIDE",
  "index": 2
}
```

> 同 `set-rule`，Injector 通过 `inotify` 自动感知文件变化并重载。

---

## 11. `reload-config` — 重载配置

向注入器进程发送 `SIGHUP` 信号，显式触发配置重载。

> 🔔 Injector 已内置 `inotify` 文件监听，磁盘文件修改后会**自动重载**。`reload-config` 仅作为手动即时触发手段。

### 调用

```bash
log_ctl reload-config api
```

### 响应 (data)

```json
{
  "pid": 1234,
  "signal": "SIGHUP"
}
```

---

## 12. `search-io` / `search-sys` — 查询日志

查询历史日志。通过抽象 Unix Socket(`nsp_log_socket`，AF_UNIX SOCK_STREAM)连接日志服务。

### 调用

```bash
log_ctl search-io [--level level] [key] [limit] [offset] [api]
log_ctl search-sys [--level level] [key] [limit] [offset] [api]
```

| 参数 | 说明 | 默认 |
|------|------|------|
| `--level` | 日志级别过滤（仅 search-sys 生效） | `-1`（全部） |
| `key` | 搜索关键词 | `""`（全部） |
| `limit` | 返回条数上限 | `100` |
| `offset` | 偏移量 | `0` |

### 示例

```bash
log_ctl search-sys --level 1 error 100 0 api
log_ctl search-io com.tencent 50 0 api
```

### 响应 (data)

```json
{
  "raw": "2024-06-28 00:20:00 [injector(1234)] INFO: 注入成功\n2024-06-28 00:20:01 [fuse_daemon(5678)] WARN: 路径拒绝",
  "done": {
    "total": 10,
    "remaining": 5
  }
}
```

`raw` 字段包含原始日志文本（不含 DONE 行），逐行解析即可。`done` 字段包含统计信息：`total` 为匹配总数，`remaining` 为剩余条数（用于分页）。

---

## 13. `clear-io` / `clear-sys` — 清除日志

清除服务端内存中的日志缓冲区。

### 调用

```bash
log_ctl clear-io api
log_ctl clear-sys api
```

### 响应 (data)

```json
{
  "raw": "OK",
  "done": {
    "total": 0,
    "remaining": 0
  }
}
```

---

## 14. `list-injected` — 已注入列表

通过抽象 Unix Socket 连接注入器 IPC 服务，查询已注入的应用列表。

### 调用

```bash
log_ctl list-injected api
```

### 响应 (data)

```json
{
  "raw": "APP|com.tencent.mobileqq|1234|10123|3|2|1\nAPP|com.example.app2|1235|10124|1|0|0",
  "done": {
    "total": 2
  }
}
```

`raw` 中每行 `APP|pkg|pid|uid|redir_count|hide_count|ro_count`，不包含 DONE 行。`done.total` 为已注入应用总数。

---

## 15. `list-users` — 活跃用户列表

列出当前系统活跃用户及每个用户下的应用配置数。数据来源于 `/data/media/` 下的 UID 目录扫描。

### 调用

```bash
log_ctl list-users api
```

### 响应 (data)

```json
{
  "count": 2,
  "users": [
    {"uid": 0, "app_count": 5},
    {"uid": 10, "app_count": 3}
  ]
}
```

### 字段说明

| 路径 | 类型 | 说明 |
|------|------|------|
| `count` | int | 活跃用户总数 |
| `users[].uid` | int | 用户 ID |
| `users[].app_count` | int | 该用户下已解析的应用配置数量 |

---

## 16. `log-count` — 日志统计

获取当前日志服务器中各缓冲区（IO / SYS / Logcat）的日志总条数，便于前端计算分页。

### 调用

```bash
log_ctl log-count api
```

### 响应 (data)

```json
{
  "io": 262144,
  "sys": 50000,
  "logcat": 100000
}
```

### 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `io` | int | I/O 日志缓冲区当前条数 |
| `sys` | int | 系统日志缓冲区当前条数 |
| `logcat` | int | Logcat 日志缓冲区当前条数 |

### 分页使用示例

结合 `search-io` / `search-sys` 的 `limit` 和 `offset` 参数实现前端分页：

```kotlin
// 获取总条数
val countJson = logCtl("log-count", "api")
val totalSys = countJson.getJSONObject("data").getInt("sys")

// 计算总页数
val pageSize = 50
val totalPages = (totalSys + pageSize - 1) / pageSize

// 翻页查询
fun searchPage(page: Int) {
    val offset = (page - 1) * pageSize
    logCtl("search-sys", "", pageSize.toString(), offset.toString(), "api")
}
```

---

## 17. 流式日志命令

实时流式输出日志。**长连接命令**，需要异步处理。

### 调用

```bash
log_ctl stream-io [--level level] [api]
log_ctl stream-sys [--level level] [api]
log_ctl stream-logcat [--level level] [api]
log_ctl stream-all [--level level] [api]
```

| 子命令 | 说明 |
|--------|------|
| `stream-io` | 流式 I/O 日志 |
| `stream-sys` | 流式系统日志 |
| `stream-logcat` | 流式 Logcat 日志 |
| `stream-all` | 流式所有日志 |

### 输出格式

`stream-sys` 在 `api` 模式下输出纯文本（每行一个），格式为 `<级别数字>|<原始消息>`：

```
1|[injector(1234)] 注入成功
2|[fuse_daemon(5678)] 路径拒绝
```

> `stream-io` / `stream-logcat` / `stream-all` 的 api 模式同样输出纯文本（每行一条日志记录）。

### 前端处理方式

参考 [`stream-config` 的前端处理](#4-stream-config--订阅配置变更)。

---

## 日志格式与前端展示规范

本章节为前端应用提供日志数据的格式解析规则和格式化显示建议。

### 日志格式规范

#### 三种日志类型总览

| 类型 | 说明 | 缓冲区容量 | 级别过滤 | 写入来源 |
|------|------|-----------|---------|---------|
| SYS | 系统日志（注入器、FUSE 等组件运行日志） | 50,000 条 | 支持 (`--level`) | 各组件通过抽象 Unix Socket 发送 |
| IO | I/O 操作日志（FUSE 文件操作记录） | 262,144 条 | 不支持 | FUSE 守护进程 |
| Logcat | Android Logcat 日志 | 100,000 条 | 不支持 | 系统 logcat |

#### SYS 系统日志行格式

search 查询结果中，SYS 日志的 message 部分有两种格式：

**格式 A**（无级别前缀）：

```
[进程名] 消息内容
```

**格式 B**（带 `LOG_SYS:` 级别前缀）：

```
LOG_SYS:<级别数字>:[进程名] 消息内容
```

实际输出示例：

```
[fuse_daemon] 已接收通知，重新加载配置
LOG_SYS:1:[fuse_daemon] FUSE Passthrough: 🟢 启用成功
LOG_SYS:0:[injector] IPC 服务已启动
```

> **注意**：PID 不一定出现，格式取决于日志来源。前端解析时应兼容两种格式。

SYS 日志级别定义：

| 值 | 级别 | 建议前景色 |
|----|------|-----------|
| 0 | DEBUG | #9E9E9E（灰色） |
| 1 | INFO | #2196F3（蓝色） |
| 2 | WARN | #FF9800（橙色） |
| 3 | ERROR | #F44336（红色） |

#### IO 日志行格式

```
[操作类型] /路径
```

带重定向时：

```
[操作类型] /源路径 -> /目标路径
```

IO 操作类型一览：

| 操作类型 | 说明 | 建议颜色 |
|---------|------|---------|
| OPEN | 打开文件 | #4CAF50（绿色） |
| CREATE | 创建文件 | #4CAF50（绿色） |
| READ | 读取文件 | #2196F3（蓝色） |
| WRITE | 写入文件 | #FF9800（橙色） |
| UNLINK | 删除文件 | #F44336（红色） |
| MKDIR | 创建目录 | #4CAF50（绿色） |
| RMDIR | 删除目录 | #F44336（红色） |
| RENAME | 重命名 | #9C27B0（紫色） |
| GETATTR | 获取属性 | #9E9E9E（灰色） |
| ACCESS | 访问检查 | #9E9E9E（灰色） |
| TRUNCATE | 截断文件 | #FF9800（橙色） |
| UTIMENS | 修改时间 | #9E9E9E（灰色） |
| CHMOD | 修改权限 | #9C27B0（紫色） |
| CHOWN | 修改所有者 | #9C27B0（紫色） |
| READLINK | 读取链接 | #2196F3（蓝色） |
| STATFS | 文件系统信息 | #9E9E9E（灰色） |
| OPENDIR | 打开目录 | #4CAF50（绿色） |
| READDIR | 读取目录 | #2196F3（蓝色） |

#### Logcat 日志行格式

直接为 Android logcat 原始文本，无固定结构。

---

### search 查询结果解析

#### API 响应结构

```json
{
  "status": "ok",
  "command": "search",
  "data": {
    "raw": "2024-06-28 00:20:00 [injector(1234)] 注入成功\n2024-06-28 00:20:01 [fuse_daemon(5678)] 路径拒绝",
    "done": {
      "total": 10,
      "remaining": 5
    }
  }
}
```

#### raw 字段逐行解析

`raw` 字段为多行文本，每行格式：

```
YYYY-MM-DD HH:MM:SS | 消息内容
```

**分隔规则**：

1. 按 `\n` 分割得到每一行
2. 每行按**第一个** `|` 分割为 **时间戳** 和 **消息体**
3. 消息体的格式取决于日志类型（SYS 为 `[进程名] 内容` 或 `LOG_SYS:级别:[进程名] 内容`，IO 为 `[操作类型] /路径`，Logcat 为原始文本）

> **注意**：`|` 字符在消息体中可能出现（如 IO 日志的重定向路径），但时间戳与消息体之间的分隔符始终是**第一个** `|`。

#### 分页计算

```kotlin
// 获取总条数
val countJson = logCtl("log-count", "api")
val totalCount = countJson.getJSONObject("data").getInt("sys") // 或 "io" / "logcat"

// 分页查询
val pageSize = 50
val totalPages = (totalCount + pageSize - 1) / pageSize

// 第 N 页（从 1 开始）
val offset = (page - 1) * pageSize
logCtl("search-sys", "", pageSize.toString(), offset.toString(), "api")
```

#### Kotlin 解析示例

```kotlin
data class LogEntry(
    val timestamp: String,    // "2026-07-04 11:41:03"
    val message: String,      // "[fuse_daemon] 已接收通知" 或 "LOG_SYS:1:[fuse_daemon] FUSE 启用成功"
    val level: Int? = null,   // SYS 日志：0-3（从 LOG_SYS 前缀提取）；IO/Logcat：null
    val processName: String? = null  // "fuse_daemon"
)

fun parseSearchResult(jsonStr: String): List<LogEntry> {
    val json = JSONObject(jsonStr)
    val data = json.getJSONObject("data")
    val raw = data.getString("raw")
    val entries = mutableListOf<LogEntry>()

    // 兼容两种 SYS 日志格式的正则
    val logSysRegex = Regex("""LOG_SYS:(\d+):\[(\w+)\]""")  // 格式 B: LOG_SYS:级别:[进程名]
    val bracketRegex = Regex("""\[(\w+)\]""")                // 格式 A: [进程名]

    for (line in raw.split("\n")) {
        if (line.isBlank()) continue
        val pipeIdx = line.indexOf('|')
        if (pipeIdx < 0) continue

        val timestamp = line.substring(0, pipeIdx).trim()
        val message = line.substring(pipeIdx + 1).trim()

        var level: Int? = null
        var processName: String? = null

        // 优先匹配格式 B（带 LOG_SYS 前缀）
        val logSysMatch = logSysRegex.find(message)
        if (logSysMatch != null) {
            level = logSysMatch.groupValues[1].toIntOrNull()
            processName = logSysMatch.groupValues[2]
        } else {
            // 匹配格式 A（仅 [进程名]）
            val bracketMatch = bracketRegex.find(message)
            if (bracketMatch != null) {
                processName = bracketMatch.groupValues[1]
            }
        }

        entries.add(LogEntry(
            timestamp = timestamp,
            message = message,
            level = level,
            processName = processName
        ))
    }
    return entries
}
```

---

### stream 流式日志解析

#### 各子命令输出格式对照

| 子命令 | api 模式输出 | 非 api 模式输出 |
|--------|-------------|---------------|
| `stream-sys` | 逐行纯文本（带级别前缀） | 逐行原始文本 |
| `stream-io` | 逐行原始文本 | 逐行原始文本 |
| `stream-logcat` | 逐行原始文本 | 逐行原始文本 |
| `stream-all` | 逐行原始文本（混合） | 逐行原始文本 |

> **重要**：所有 stream 命令在 api 模式下均输出纯文本行（无 JSON 包装）。`stream-sys` 的 api 模式会在每行前添加级别数字前缀。

#### stream-sys API 模式详解

调用命令：

```bash
log_ctl stream-sys --level 1 api
```

log_monitor 收到 `STREAM_SYS_API:1` 命令后，会为每条 SYS 日志前插级别标签：

```
<级别数字>|<原始消息>
```

示例输出：

```
1|[injector(1234)] 注入成功
2|[fuse_daemon(5678)] 路径拒绝
3|[injector(1234)] 注入失败: 权限不足
```

**解析规则**：

1. 按行读取
2. 每行按第一个 `|` 分割
3. 左侧为级别数字（0=DEBUG, 1=INFO, 2=WARN, 3=ERROR）
4. 右侧为消息体，格式为 `[进程名(PID)] 内容`

#### stream-sys 非 API 模式

调用命令：

```bash
log_ctl stream-sys --level 1
```

log_monitor 收到 `STREAM_SYS:1` 命令后，**不添加**级别标签，直接输出原始消息：

```
[injector(1234)] 注入成功
[fuse_daemon(5678)] 路径拒绝
```

#### stream-io / stream-logcat / stream-all

所有模式均输出原始文本行，无 JSON 包装，无级别标签。

`stream-all` 混合输出三种日志，前端可通过消息格式初步区分：

- 含 `[操作类型] /path` 格式的为 IO 日志
- 含 `[进程名(PID)]` 格式的为 SYS 日志
- 其余为 Logcat 日志

#### Kotlin 流式处理示例

```kotlin
fun streamSysLogs(minLevel: Int = 0, callback: (LogEntry) -> Unit): Process {
    val proc = ProcessBuilder()
        .command("/data/Namespace-Proxy/bin/log_ctl", "stream-sys",
                 "--level", minLevel.toString(), "api")
        .start()

    thread {
        proc.inputStream.bufferedReader().use { reader ->
            var line = reader.readLine()
            while (line != null) {
                // stream-sys API 模式：格式为 "级别|消息"
                val pipeIdx = line.indexOf('|')
                if (pipeIdx > 0) {
                    val level = line.substring(0, pipeIdx).toIntOrNull()
                    val message = line.substring(pipeIdx + 1)
                    // 兼容两种格式：LOG_SYS:级别:[进程名] 或 [进程名]
                    val logSysRegex = Regex("""LOG_SYS:\d+:\[(\w+)\]""")
                    val bracketRegex = Regex("""\[(\w+)\]""")
                    val match = logSysRegex.find(message) ?: bracketRegex.find(message)
                    callback(LogEntry(
                        timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date()),
                        message = message,
                        level = level,
                        processName = match?.groupValues?.get(1)
                    ))
                }
                line = reader.readLine()
            }
        }
    }
    return proc
}
```

---

### 前端格式化显示规范

#### 日志级别着色方案

| 级别 | 值 | 推荐文字色 | 推荐背景色 | 说明 |
|------|---|-----------|-----------|------|
| DEBUG | 0 | #9E9E9E | 透明 | 低优先级调试信息 |
| INFO | 1 | #2196F3 | 透明 | 常规运行信息 |
| WARN | 2 | #FF9800 | #FFF3E0 | 警告信息 |
| ERROR | 3 | #F44336 | #FFEBEE | 错误信息 |

#### 日志类型分Tab建议

建议前端提供三个 Tab 页签：

| Tab | 标签 | 数据源 | 特殊处理 |
|-----|------|--------|---------|
| 系统日志 | SYS | `search-sys` / `stream-sys` | 支持级别过滤，显示进程名 |
| I/O 日志 | IO | `search-io` / `stream-io` | 操作类型图标，路径截断显示 |
| Logcat | Logcat | `stream-logcat` | 保留原始格式 |

#### 进程名提取与高亮

从消息体中提取进程名（兼容两种格式）：

```kotlin
// 格式 B: LOG_SYS:级别:[进程名] 消息
val logSysRegex = Regex("""LOG_SYS:\d+:\[(\w+)\]""")
// 格式 A: [进程名] 消息
val bracketRegex = Regex("""\[(\w+)\]""")

val match = logSysRegex.find(message) ?: bracketRegex.find(message)
val processName = match?.groupValues?.get(1)  // "fuse_daemon"
```

显示建议：

- 进程名用**加粗**或**不同颜色**突出显示
- 格式 B 中的 `LOG_SYS:级别:` 前缀可选择隐藏，仅显示 `[进程名] 消息` 部分

#### 时间戳处理

原始格式：`2024-06-28 00:20:00`

显示建议：

- **详细模式**：显示完整时间戳
- **简洁模式**：显示相对时间（如 "3分钟前"、"昨天 00:20"）
- **排序**：按时间戳降序排列（最新在前）

#### IO 路径显示优化

对于长路径，建议：

- 显示最后两级目录 + 文件名
- 完整路径显示在 Tooltip 中
- 例：`/data/media/0/Android/data/com.tencent.mobileqq/files/secret.txt` → `.../files/secret.txt`

#### 搜索关键词高亮

在消息体中高亮搜索关键词：

```kotlin
fun highlightKeyword(text: String, keyword: String): SpannableString {
    val spannable = SpannableString(text)
    var start = 0
    while (true) {
        val idx = text.indexOf(keyword, start, ignoreCase = true)
        if (idx < 0) break
        spannable.setSpan(
            BackgroundColorSpan(Color.YELLOW),
            idx, idx + keyword.length,
            Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
        )
        start = idx + keyword.length
    }
    return spannable
}
```

---

## 错误处理

所有命令在 api 模式下，错误时返回统一格式：

```json
{
  "status": "error",
  "command": "<command-name>",
  "error": "错误描述",
  "timestamp": 1719523200
}
```

常见错误场景：

| 错误信息 | 可能原因 |
|----------|---------|
| `无法读取注入器 PID 文件` | 注入器未运行 |
| `发送 SIGHUP 到 PID %d 失败` | 注入器已退出 |
| `无法打开规则文件 %s` | 权限不足或路径错误 |
| `未获取到配置信息（超时）` | 注入器广播服务未响应 |
| `连接注入器 IPC 服务失败` | 注入器未运行 |
| `连接日志服务失败` | 日志监控服务未运行 |

---

## 附录：关键路径常量

| 常量 | 值 |
|------|-----|
| `log_ctl` 路径 | `/data/Namespace-Proxy/bin/log_ctl` |
| 配置目录 | `/data/Namespace-Proxy` |
| 主配置文件 | `/data/Namespace-Proxy/injector.conf` |
| 应用规则目录 | `/data/Namespace-Proxy/App-rules` |
| PID 文件 | `/data/Namespace-Proxy/injector.pid` |
| 日志 Socket | `nsp_log_socket`（抽象 UDS，AF_UNIX SOCK_STREAM） |
| 配置广播 Socket | `nsp_config_broadcast`（抽象 UDS） |
| IPC Socket | `nsp_ipc_socket`（抽象 UDS） |
