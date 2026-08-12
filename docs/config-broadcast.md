# 配置广播服务 —— Android 接入文档

## 概述

**injector** 通过 **Unix Domain Socket (SOCK_DGRAM)** + **epoll** 以 JSON 格式实时公布当前加载的配置规则（injector.conf + App-rules）。

- **Socket 类型**: `AF_UNIX` / `SOCK_DGRAM`（抽象命名空间）
- **Socket 路径**: `nsp_config_broadcast`（抽象地址，无文件残留）
- **权限要求**: 拥有 `AF_UNIX` 通信权限即可（root / system_app / 同 UID）
- **JSON 上限**: 256KB

---

## 命令接口

| 命令 | 说明 |
|------|------|
| `GET` | 获取当前**内存解析后**的全量配置 JSON |
| `STATIC` | 从磁盘读取**原始规则文件**内容，以 JSON 返回 |
| `SUBSCRIBE` | 注册为订阅者，立即推送一次；后续配置变更自动推送 |
| `UNSUBSCRIBE` | 取消订阅 |
| 空/未知 | 等同于 `GET` |

---

## Android 接入 —— 必备知识

### 抽象命名空间 UDS 连接要点

Android Java 层可通过 `LocalSocket` 连接**文件系统路径**的 Unix Socket，但**标准 `LocalSocket` 不支持抽象命名空间**（`sun_path[0] = '\0'`）。

**解决方案**: 通过 JNI 或 `Runtime.exec()` 调用 `socat`/`log_ctl` 获取输出，或直接编写 Native 代码。

> **推荐方案**: 应用内集成 `log_ctl` 二进制，通过 `ProcessBuilder` 调用，解析 stdout。

---

## 方案一：通过 log_ctl 获取（推荐）

### 1. 一键拉取配置

```kotlin
// ConfigFetcher.kt
object ConfigFetcher {

    private val json = Json { ignoreUnknownKeys = true }

    /** 获取内存解析后的规则 */
    suspend fun getRuntimeConfig(): Result<ConfigResponse> = runCatching {
        val output = runLogCtl("get-config", "api")
        json.decodeFromString<ConfigResponse>(output)
    }

    /** 获取磁盘原始规则文件 */
    suspend fun getStaticConfig(): Result<StaticResponse> = runCatching {
        val output = runLogCtl("get-config", "--static", "api")
        json.decodeFromString<StaticResponse>(output)
    }

    /** 订阅配置变更（返回 Flow） */
    fun streamConfig(scope: CoroutineScope): Flow<TemplatesUpdate> = callbackFlow {
        val process = runLogCtlStream("stream-config", "api")
        val reader = BufferedReader(InputStreamReader(process.inputStream))

        scope.launch(Dispatchers.IO) {
            var buffer = StringBuilder()
            while (true) {
                val line = reader.readLine() ?: break
                buffer.append(line)
                // JSON 对象以 }\n 结尾时尝试解析
                if (line.trimEnd() == "}") {
                    trySend(json.decodeFromString<TemplatesUpdate>(buffer.toString()))
                    buffer = StringBuilder()
                }
            }
        }

        awaitClose { process.destroy() }
    }

    // ---------- 底层调用 ----------

    private fun runLogCtl(vararg args: String): String {
        val proc = ProcessBuilder()
            .command("/data/Namespace-Proxy/bin/log_ctl", *args)
            .redirectErrorStream(false)
            .start()
        val stdout = proc.inputStream.readBytes().decodeToString()
        val stderr = proc.errorStream.readBytes().decodeToString()
        val exit = proc.waitFor(5, TimeUnit.SECONDS)
        if (exit != 0 || !proc.isAlive) throw IOException("log_ctl 失败: $stderr")
        return stdout.trim()
    }

    private fun runLogCtlStream(vararg args: String): Process {
        val pb = ProcessBuilder()
            .command("/data/Namespace-Proxy/bin/log_ctl", *args)
            .redirectErrorStream(true)
        return pb.start()
    }
}
```

### 2. 数据模型

```kotlin
// Model.kt
@Serializable
data class ConfigResponse(
    val timestamp: Long = 0,
    val injector: InjectorInfo? = null,
    @SerialName("global_fuse") val globalFuse: FuseInfo? = null,
    val templates: List<Template> = emptyList()
)

@Serializable
data class InjectorInfo(
    val pid: Int = 0,
    val passive: Boolean = false,
    val mode: String = ""
)

@Serializable
data class FuseInfo(
    @SerialName("fuse_pid") val fusePid: Int = 0,
    val disabled: Boolean = false
)

@Serializable
data class Template(
    @SerialName("template_name") val templateName: String = "",
    @SerialName("hook_operation") val hookOperation: List<String> = listOf("query", "insert"),
    @SerialName("apply_to_app") val applyToApp: List<String> = emptyList(),
    @SerialName("enable_sandbox") val enableSandbox: Boolean = false,
    val monitor: Boolean? = null,
    @SerialName("inject_enable") val injectEnable: Boolean? = null,
    @SerialName("global_inject") val globalInject: Boolean? = null,
    @SerialName("hide_paths") val hidePaths: List<String> = emptyList(),
    @SerialName("read_only_path") val readOnlyPath: List<String> = emptyList(),
    @SerialName("redirect_rules") val redirectRules: List<RedirectRule> = emptyList()
)

@Serializable
data class RedirectRule(
    val source: String = "",
    val target: String = ""
)

@Serializable
data class UidEntry(
    val uid: Int = 0,
    val pkg: String = ""
)

// STATIC 响应
@Serializable
data class StaticResponse(
    val timestamp: Long = 0,
    val type: String = "static",
    val global: GlobalRules? = null,
    val apps: List<AppEntry> = emptyList(),
    @SerialName("app_rules") val appRules: List<StaticRuleFile> = emptyList()
)

@Serializable
data class GlobalRules(
    val switches: Switches? = null,
    @SerialName("ro_rules") val roRules: List<String> = emptyList(),
    @SerialName("hide_rules") val hideRules: List<String> = emptyList(),
    @SerialName("redirect_rules") val redirectRules: List<String> = emptyList(),
    @SerialName("allow_rules") val allowRules: List<String> = emptyList()
)

@Serializable
data class Switches(
    @SerialName("global_inject") val globalInject: String = "OFF",
    val monitor: String = "ON",
    val sandbox: String = "OFF",
    @SerialName("fuse_direct") val fuseDirect: String = "OFF"
)

@Serializable
data class AppEntry(
    val pkg: String = "",
    @SerialName("user_id") val userId: Int = 0,
    @SerialName("inject_enable") val injectEnable: String = "OFF"
)

@Serializable
data class StaticRuleFile(
    val file: String = "",
    @SerialName("user_dir") val userDir: String = "",
    val content: String? = null
)
```

### 3. 在 Activity / ViewModel 中使用

```kotlin
// MainViewModel.kt
class MainViewModel : ViewModel() {

    private val _templates = MutableStateFlow<List<Template>>(emptyList())
    val templates: StateFlow<List<Template>> = _templates.asStateFlow()

    private val _fuseStatus = MutableStateFlow<FuseInfo?>(null)
    val fuseStatus: StateFlow<FuseInfo?> = _fuseStatus.asStateFlow()

    init {
        refreshConfig()
    }

    fun refreshConfig() {
        viewModelScope.launch {
            ConfigFetcher.getRuntimeConfig().onSuccess { resp ->
                _templates.value = resp.templates
                _fuseStatus.value = resp.globalFuse
            }
        }
    }

    /** 对接到订阅推送 */
    fun startStreaming() {
        ConfigFetcher.streamConfig(viewModelScope).collect { update ->
            _templates.value = update.templates
        }
    }

    /** 查找匹配当前应用的模板 */
    fun getTemplatesForApp(packageName: String): List<Template> {
        return _templates.value.filter { t ->
            t.templateName == packageName ||
            t.applyToApp.any { it == packageName || it == "*" }
        }
    }
}
```

---

## 方案二：JNI 直连 UDS（低延迟）

对于**不允许生成子进程**的场景（如 system_server 插件），可通过 JNI 直连抽象 UDS。

### C/JNI 层

```c
// ndk_bridge.c
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#define SOCKET_PATH "nsp_config_broadcast"

/**
 * 连接 injector 配置广播并执行命令
 * @param cmd  "GET" / "STATIC" / "SUBSCRIBE"
 * @param out  输出缓冲区 (至少 65536 字节)
 * @param size 缓冲区大小
 * @return 接收到的字节数，失败返回 -1
 */
int fetch_config(const char *cmd, char *out, int size) {
    // 1. 创建 DGRAM socket
    int sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return -1;

    // 2. 绑定本地 ephemeral 抽象地址
    struct sockaddr_un local = { .sun_family = AF_UNIX };
    local.sun_path[0] = '\0';
    snprintf(local.sun_path + 1, sizeof(local.sun_path) - 2,
             "nsp_client_%d", getpid());
    socklen_t local_len = offsetof(struct sockaddr_un, sun_path) + 1 +
                          strlen(local.sun_path + 1);
    if (bind(sock, (struct sockaddr *)&local, local_len) < 0) {
        close(sock);
        return -1;
    }

    // 3. 发送命令到广播地址
    struct sockaddr_un dest = { .sun_family = AF_UNIX };
    dest.sun_path[0] = '\0';
    strncpy(dest.sun_path + 1, SOCKET_PATH, sizeof(dest.sun_path) - 2);
    socklen_t dest_len = offsetof(struct sockaddr_un, sun_path) + 1 +
                         strlen(SOCKET_PATH);

    if (sendto(sock, cmd, strlen(cmd), 0,
               (struct sockaddr *)&dest, dest_len) < 0) {
        close(sock);
        return -1;
    }

    // 4. 接收响应（带 3 秒超时）
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int n = (int)recv(sock, out, size - 1, 0);
    close(sock);

    if (n > 0) out[n] = '\0';
    return n;
}
```

### JNI 注册

```kotlin
// ConfigBridge.kt
object ConfigBridge {
    init { System.loadLibrary("nsp_bridge") }

    /** @return JSON 字符串，失败返回空 */
    external fun nativeFetchConfig(cmd: String): String?
}

// 使用
lifecycleScope.launch(Dispatchers.IO) {
    val json = ConfigBridge.nativeFetchConfig("GET")
    if (json != null) {
        val resp = Json.decodeFromString<ConfigResponse>(json)
        withContext(Dispatchers.Main) {
            viewModel.onConfigLoaded(resp)
        }
    }
}
```

---

## 方案三：SUBSCRIBE 长连接模式

适合**实时同步配置变更**的场景（如后台 Service 持续监听）：

```kotlin
// ConfigSubscriptionService.kt
class ConfigSubscriptionService : Service() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        scope.launch {
            ConfigFetcher.streamConfig(this).collect { update ->
                // 配置变了 → 通知前台 UI 或重新挂载
                val intent = Intent("com.nsp.CONFIG_UPDATED").apply {
                    putExtra("templates", Json.encodeToString(update.templates))
                }
                sendBroadcast(intent)
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?) = null
}
```

---

## 响应格式参考

### GET 响应（内存解析后配置）

```json
{
  "timestamp": 1718000000,
  "injector": {
    "pid": 1234,
    "passive": false,
    "mode": "active"
  },
  "global_fuse": {
    "fuse_pid": 5678,
    "disabled": false
  },
  "templates": [
    {
      "template_name": "GLOBAL",
      "hook_operation": ["query", "insert"],
      "apply_to_app": ["*"],
      "enable_sandbox": false,
      "global_inject": true,
      "fuse_direct": false,
      "hide_paths": [],
      "read_only_path": [],
      "redirect_rules": [
        { "source": "/sdcard", "target": "/data/media/0" }
      ]
    },
    {
      "template_name": "com.alibaba.android.rimet",
      "hook_operation": ["query", "insert"],
      "apply_to_app": ["com.alibaba.android.rimet"],
      "enable_sandbox": true,
      "monitor": false,
      "inject_enable": true,
      "hide_paths": ["/system/fonts"],
      "read_only_path": ["/storage/emulated/0/HarmonyOS_Sans_SC_Regular.ttf/"],
      "redirect_rules": []
    }
  ]
}
```

### 字段映射表

| JSON 字段 | Kotlin 类型 | 解释 |
|-----------|-------------|------|
| `templates[].template_name` | String | `"GLOBAL"`=全局规则，其余为包名 |
| `templates[].hook_operation` | List\<String\> | 固定 `["query","insert"]`，直接透传 |
| `templates[].apply_to_app` | List\<String\> | 该模板作用的应用列表 |
| `templates[].enable_sandbox` | Boolean | 沙盒模式开关 |
| `templates[].global_inject` | Boolean | 全局注入开关（仅 GLOBAL 模板） |
| `templates[].fuse_direct` | Boolean | FUSE 直通开关（仅 GLOBAL 模板） |
| `templates[].monitor` | Boolean | 监控开关（仅应用模板） |
| `templates[].inject_enable` | Boolean | 注入使能（仅应用模板） |
| `templates[].hide_paths` | List\<String\> | 隐藏路径列表 |
| `templates[].read_only_path` | List\<String\> | 只读路径列表 |
| `templates[].redirect_rules` | List\<RedirectRule\> | 重定向规则 |
| `redirect_rules[].source` | String | 虚拟路径 |
| `redirect_rules[].target` | String | 实际目标路径 |

### STATIC 响应（磁盘原始规则文件解析结果）

```json
{
  "timestamp": 1718000000,
  "type": "static",
  "global": {
    "switches": {
      "global_inject": "OFF",
      "monitor": "ON",
      "sandbox": "OFF",
      "fuse_direct": "OFF"
    },
    "ro_rules": ["/123 云盘/Cache/", "/HyperOS_Sandbox/"],
    "hide_rules": [],
    "redirect_rules": ["/sdcard/src /sdcard/dst"],
    "allow_rules": []
  },
  "apps": [
    {"pkg": "com.termux", "user_id": 0, "inject_enable": "OFF"},
    {"pkg": "com.tencent.mobileqq", "user_id": 0, "inject_enable": "ON"}
  ],
  "app_rules": [
    {
      "file": "com.tencent.mobileqq.conf",
      "user_dir": "App-rules",
      "content": "SANDBOX ON\n"
    }
  ]
}
```

- `global.switches`：全局开关（`global_inject`、`monitor`、`sandbox`、`fuse_direct`，值为 `"ON"` / `"OFF"`）
- `global.ro_rules` / `hide_rules` / `redirect_rules` / `allow_rules`：各类型规则列表
- `apps[].inject_enable`：应用注入开关（`"ON"` / `"OFF"`）
- `app_rules[].content`：规则文件原始内容（JSON 转义字符串）


## Android 端常见问题

### Q: `Permission denied` 怎么办？
A: 连接抽象 UDS 需要 root 权限，或应用与 injector 运行在同一 UID 下。如果使用 `log_ctl` 方案，`log_ctl` 需要有执行权限。

### Q: DGRAM 丢包了怎么办？
A: `SOCK_DGRAM` 不保证送达。关键场景使用 `SUBSCRIBE` + 超时重试策略，或多次调用 `GET` 轮询。

### Q: 应用被杀后订阅还在吗？
A: 订阅基于客户端 socket 地址。客户端进程死亡后，socket 自动关闭，下次 `sendto` 到该地址会 `ECONNREFUSED`，服务端会自动移除该订阅者。

### Q: SELinux 阻止了通信？
A: 如果应用在沙盒中运行，`AF_UNIX` 对抽象命名空间的访问可能受限。确保 sepolicy 允许：
```
allow <app_domain> nsp_config_broadcast_socket:sock_file { write read };
```
或直接通过有权限的守护进程转发。

---

## 触发广播的时机

| 事件 | 说明 |
|------|------|
| 配置重载 | inotify 检测到 `injector.conf`/`App-rules/*.conf` 变更，或 SIGHUP 信号 |
| `GET` 请求 | 单次查询，即收即回 |
| `SUBSCRIBE` | 加入订阅列表 + 立即推送一次全量 |
| 后续变更 | 自动推送给所有活跃订阅者 |

---

## 文件清单

| 文件 | 说明 |
|------|------|
| `include/config_publisher.h` | 广播服务 API 声明 |
| `src/injector/config_publisher.c` | 核心实现（~543 行） |
| `src/injector/injector.c` | 集成：初始化、epoll 处理、重载广播、清理 |
| `src/log/log_ctl.c` | CLI 客户端：`get-config` / `get-config --static` / `stream-config` |
| `include/common.h` | `CONFIG_BROADCAST_SOCKET` 常量 |
| `include/inject_target.h` | `get_injected_snapshot()` / `get_uid_map_snapshot()` |
| `src/injector/inject_target.c` | 快照访问器实现 |
| `docs/config-broadcast.md` | 本文档 |
