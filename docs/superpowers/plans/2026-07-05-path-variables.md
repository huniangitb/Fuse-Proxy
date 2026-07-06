# 路径变量支持（`$package` + 用户变量 + 静态/动态优化） 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 fuse 的 REDIRECT/HIDE/RO/ALLOW 规则路径支持 `$package`（按命中 uid 动态）与 `NAME=VALUE` 用户自定义变量（递归展开、静态/动态分类优化），并修正 `/mnt`、`/data` 等系统根目录的识别。

**Architecture:** 新增纯函数模块 `src/config/path_vars.c`（不依赖 fuse、不依赖 `g_global_cfg` 全局，通过参数接收 `global_cfg`，可独立单测）；配置解析侧 `config_parser.c` 增加赋值分支与静态分析；运行时侧 `vfs_core.c` 在 4 个规则匹配点调用 `expand_path_vars` / `build_real_base_from_target`。

**Tech Stack:** C23 / meson / clang（aarch64-linux-android35）/ libfuse3。测试用 meson `test()` + assert 风格的可执行文件（无外部框架）。

**对设计文档的一处细化：** `expand_path_vars` 与 `build_real_base_from_target` 增加 `global_cfg` 显式参数（替代直接访问 `g_global_cfg`），使 path_vars.c 成为纯函数模块、支持独立单测。调用方传 `&g_global_cfg`。

**参考设计：** `docs/superpowers/specs/2026-07-05-package-variable-design.md`

---

## 文件结构

| 文件 | 责任 | 动作 |
|---|---|---|
| `include/path_vars.h` | 类型与函数声明 | 新建 |
| `src/config/path_vars.c` | 纯函数实现：变量判定、解析、展开、静态分析、real_base 构造 | 新建 |
| `tests/test_path_vars.c` | 纯函数单元测试 | 新建 |
| `include/config_parser.h` | `AppConfig` 增加 `var_*` 字段 | 修改 |
| `src/config/config_parser.c` | 赋值分支、`var_*` 生命周期、`analyze` 调用、trie 收紧、REDIRECT 延迟归一、根目录判定 | 修改 |
| `src/daemon/vfs_core.c` | 4 处规则匹配点接入 expand/build_real_base；`vfs_fill_virtual_dirs` 签名加 `current_pkg` | 修改 |
| `src/daemon/fuse_daemon.c` | `vfs_fill_virtual_dirs` 调用处补传 `current_pkg` | 修改 |
| `meson.build` | `common_sources` 加 `path_vars.c`；新增 test 目标 | 修改 |

---

## Task 1: 创建 path_vars 模块骨架 + meson test 目标 + has_path_var

**Files:**
- Create: `include/path_vars.h`
- Create: `src/config/path_vars.c`
- Create: `tests/test_path_vars.c`
- Modify: `meson.build`

- [ ] **Step 1: 写 path_vars.h**

```c
#ifndef PATH_VARS_H
#define PATH_VARS_H
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include "config_parser.h"

/* 含变量占位符（有 '$' 即视为含变量） */
bool has_path_var(const char* s);

/* current_pkg 是否可解析为真实包名（非空、非 system、非 unknown） */
bool pkg_resolvable(const char* pkg);

/* 判定系统绝对根目录路径：/data | /data/... | /mnt | /mnt/... | /storage | /storage/...
   注：/storage/emulated/... 也以 /storage 开头，调用方应先判 emulated 分支 */
bool is_system_abs_path(const char* path);

/* 判断一行是否为 NAME=VALUE 赋值。命中则拆出 name/value 并返回 true。
   NAME=[A-Za-z_][A-Za-z0-9_]*；VALUE 取 '=' 后行尾剩余原样（允许含空格/变量） */
bool parse_var_assignment(const char* line, char* name, size_t nname, char* value, size_t nval);

/* 展开路径变量 $name / ${name}。
   app_cfg / global_cfg 可为 NULL。memchr('$') 短路；未知变量保留字面；
   静态变量走 var_resolved 缓存，动态变量递归展开；循环检测深度上限 32。
   返回写入长度（不含 null）。 */
size_t expand_path_vars(const char* in, char* out, size_t outsz,
                        const AppConfig* app_cfg, const AppConfig* global_cfg,
                        const char* current_pkg);

/* 静态/动态分析 + 静态变量预计算 var_resolved。在某段所有赋值解析完后调用。
   global_cfg 用于 app 段引用全局变量（分析 [GLOBAL] 段时传 NULL） */
void analyze_var_staticness(AppConfig* cfg, const AppConfig* global_cfg);

/* 由 real_target 构造 real_base（合并现有 :457-468 分类 + :271-276 ?前缀构造）。
   含 '$' 则先展开再按统一规则分类。返回 false=规则应失效（含 $ 但包名不可解析）。 */
bool build_real_base_from_target(const char* target, int user_id, char* real_base, size_t sz,
                                 const AppConfig* app_cfg, const AppConfig* global_cfg,
                                 const char* current_pkg);

#endif
```

- [ ] **Step 2: 写 path_vars.c 骨架（仅 has_path_var + pkg_resolvable）**

```c
#include "path_vars.h"
#include "common.h"
#include <ctype.h>
#include <string.h>

bool has_path_var(const char* s) {
    if (!s) return false;
    return strchr(s, '$') != NULL;
}

bool pkg_resolvable(const char* pkg) {
    if (!pkg || !pkg[0]) return false;
    if (strcmp(pkg, "system") == 0) return false;
    if (strcmp(pkg, "unknown") == 0) return false;
    return true;
}
```

- [ ] **Step 3: 写 test_path_vars.c（has_path_var 用例）**

```c
#include "path_vars.h"
#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\n", __LINE__, #cond); g_fail++; } } while(0)

static void test_has_path_var(void) {
    CHECK(has_path_var("/sdcard/$package/files") == true);
    CHECK(has_path_var("${base}/x") == true);
    CHECK(has_path_var("/sdcard/Android/data") == false);
    CHECK(has_path_var("") == false);
    CHECK(has_path_var(NULL) == false);
    CHECK(has_path_var("price=10") == false);  /* $ 不存在 */
}

int main(void) {
    test_has_path_var();
    if (g_fail) { printf("FAILED %d\n", g_fail); return 1; }
    printf("all passed\n");
    return 0;
}
```

- [ ] **Step 4: 修改 meson.build — common_sources 加 path_vars.c**

在 `common_sources` 数组里追加 `'src/config/path_vars.c'`：

```meson
common_sources = [
    'src/core/common.c',
    'src/config/config_parser.c',
    'src/config/path_vars.c',
    'src/core/fast_search.c',
    'src/core/uid_map.c'
]
```

- [ ] **Step 5: 在 meson.build 末尾追加 test 目标**

在最后那个 `message(...)` 块**之前**插入：

```meson
# ================= 单元测试 =================
test_path_vars_exe = executable('test_path_vars',
  ['tests/test_path_vars.c', 'src/config/path_vars.c'],
  include_directories: inc_dir)
test('path_vars', test_path_vars_exe)
```

- [ ] **Step 6: 编译并运行测试**

Run: `meson setup build && ninja -C build test_path_vars && ./build/test_path_vars`
Expected: 输出 `all passed`，退出码 0。

- [ ] **Step 7: Commit**

```bash
git add include/path_vars.h src/config/path_vars.c tests/test_path_vars.c meson.build
git commit -m "feat(path_vars): 新增 path_vars 模块骨架与 has_path_var 单测"
```

---

## Task 2: is_system_abs_path

**Files:**
- Modify: `src/config/path_vars.c`（追加实现）
- Modify: `tests/test_path_vars.c`（追加用例）

- [ ] **Step 1: 追加测试用例到 test_path_vars.c**

在 `test_has_path_var` 之后新增，并在 `main` 里调用：

```c
static void test_is_system_abs_path(void) {
    /* 根目录本身（无尾部斜杠） */
    CHECK(is_system_abs_path("/data") == true);
    CHECK(is_system_abs_path("/mnt") == true);
    CHECK(is_system_abs_path("/storage") == true);
    /* 带子路径 */
    CHECK(is_system_abs_path("/data/...") == true);  /* 仅占位，实际用 /data/foo */
    CHECK(is_system_abs_path("/data/foo/bar") == true);
    CHECK(is_system_abs_path("/mnt/sdcard") == true);
    CHECK(is_system_abs_path("/storage/self") == true);
    /* 非系统根目录：/sdcard（通常为 user 存储 symlink）、相对路径、/ */
    CHECK(is_system_abs_path("/sdcard") == false);
    CHECK(is_system_abs_path("/sdcard/foo") == false);
    CHECK(is_system_abs_path("/Android/data") == false);
    CHECK(is_system_abs_path("Android/data") == false);
    CHECK(is_system_abs_path("/") == false);
    CHECK(is_system_abs_path(NULL) == false);
    /* /datafoo 不应识别为 /data 根 */
    CHECK(is_system_abs_path("/datafoo") == false);
}
```

> 注意：上面 `/data/...` 这一行只是占位写法，实际写入文件时用真实路径 `/data/foo`。把它改写为：`CHECK(is_system_abs_path("/data/foo/bar") == true);`（删除 `/data/...` 占位行，下面已有）。

在 `main` 的 `test_has_path_var();` 之后加 `test_is_system_abs_path();`。

- [ ] **Step 2: 运行测试验证失败**

Run: `ninja -C build test_path_vars && ./build/test_path_vars`
Expected: FAIL（`is_system_abs_path` 未定义，链接错误）。

- [ ] **Step 3: 在 path_vars.c 追加实现**

在文件末尾追加：

```c
static bool starts_with_root(const char* path, const char* root) {
    size_t rl = strlen(root);
    if (strncmp(path, root, rl) != 0) return false;
    char c = path[rl];  /* strncmp 已保证 strlen(path) >= rl，此处不越界 */
    return c == '\0' || c == '/';
}

bool is_system_abs_path(const char* path) {
    if (!path || path[0] != '/') return false;
    return starts_with_root(path, "/data") ||
           starts_with_root(path, "/mnt") ||
           starts_with_root(path, "/storage");
}
```

- [ ] **Step 4: 运行测试验证通过**

Run: `ninja -C build test_path_vars && ./build/test_path_vars`
Expected: `all passed`。

- [ ] **Step 5: Commit**

```bash
git add src/config/path_vars.c tests/test_path_vars.c
git commit -m "feat(path_vars): 实现 is_system_abs_path 支持系统根目录判定"
```

---

## Task 3: parse_var_assignment

**Files:**
- Modify: `src/config/path_vars.c`
- Modify: `tests/test_path_vars.c`

- [ ] **Step 1: 追加测试用例**

```c
static void test_parse_var_assignment(void) {
    char name[128], val[256];
    /* 合法紧凑形式 */
    CHECK(parse_var_assignment("MY_DIR=/sdcard/x", name, sizeof name, val, sizeof val) == true);
    CHECK(strcmp(name, "MY_DIR") == 0);
    CHECK(strcmp(val, "/sdcard/x") == 0);
    /* VALUE 含空格与变量 */
    CHECK(parse_var_assignment("BASE=/sdcard/$package/files", name, sizeof name, val, sizeof val) == true);
    CHECK(strcmp(name, "BASE") == 0);
    CHECK(strcmp(val, "/sdcard/$package/files") == 0);
    /* 带前导空白 */
    CHECK(parse_var_assignment("  FOO=bar", name, sizeof name, val, sizeof val) == true);
    CHECK(strcmp(name, "FOO") == 0 && strcmp(val, "bar") == 0);
    /* 下划线/数字 */
    CHECK(parse_var_assignment("A_1=v", name, sizeof name, val, sizeof val) == true);
    CHECK(strcmp(name, "A_1") == 0);
    /* 非法：数字开头 */
    CHECK(parse_var_assignment("1ABC=v", name, sizeof name, val, sizeof val) == false);
    /* 非法：无 = */
    CHECK(parse_var_assignment("REDIRECT /a /b", name, sizeof name, val, sizeof val) == false);
    /* 非法：关键字 HIDE 后跟路径（首 token 无 =） */
    CHECK(parse_var_assignment("HIDE /x", name, sizeof name, val, sizeof val) == false);
    /* 带空格围绕 = 不识别（NAME 后是空格非 =） */
    CHECK(parse_var_assignment("X = y", name, sizeof name, val, sizeof val) == false);
}
```

在 `main` 加 `test_parse_var_assignment();`。

- [ ] **Step 2: 运行验证失败**

Run: `ninja -C build test_path_vars && ./build/test_path_vars`
Expected: FAIL（链接错误）。

- [ ] **Step 3: 在 path_vars.c 追加实现**

```c
bool parse_var_assignment(const char* line, char* name, size_t nname, char* value, size_t nval) {
    if (!line || !name || !value || nname == 0 || nval == 0) return false;
    const char* p = line;
    while (isspace((unsigned char)*p)) p++;
    if (!isalpha((unsigned char)*p) && *p != '_') return false;
    const char* name_start = p;
    while (isalnum((unsigned char)*p) || *p == '_') p++;
    if (*p != '=') return false;
    size_t name_len = (size_t)(p - name_start);
    if (name_len == 0 || name_len >= nname) return false;
    memcpy(name, name_start, name_len);
    name[name_len] = '\0';
    p++;  /* 跳过 '=' */
    strncpy(value, p, nval - 1);
    value[nval - 1] = '\0';
    return true;
}
```

- [ ] **Step 4: 运行验证通过**

Run: `ninja -C build test_path_vars && ./build/test_path_vars`
Expected: `all passed`。

- [ ] **Step 5: Commit**

```bash
git add src/config/path_vars.c tests/test_path_vars.c
git commit -m "feat(path_vars): 实现 parse_var_assignment 解析 NAME=VALUE 赋值"
```

---

## Task 4: AppConfig var_* 字段 + free 释放 + parse 赋值分支

**Files:**
- Modify: `include/config_parser.h:41-43`（AppConfig 加字段）
- Modify: `src/config/config_parser.c`（free_app_config_rules + parse_config_line）
- Test: 集成靠 Task 13 运行时验证；本任务用编译验证

- [ ] **Step 1: AppConfig 增加 var_* 字段**

在 `include/config_parser.h` 的 `AppConfig` 结构体里，`char fuse_extra_args[512];` 这一行**之前**插入：

```c
    char** var_names;
    char** var_values;      /* 原始值（含 $ 占位），动态变量运行时展开用 */
    char** var_resolved;    /* 静态变量的预计算展开值；动态变量为 NULL */
    bool*  var_is_static;   /* 静态/动态标记 */
    int    var_count;
    int    var_capacity;
```

- [ ] **Step 2: free_app_config_rules 增加 var_* 释放**

在 `src/config/config_parser.c` 的 `free_app_config_rules`（:210-236）里，`redir_*` 释放块**之后**、函数末尾 `}` 之前 插入：

```c
    if (cfg->var_names) {
        for (int i = 0; i < cfg->var_count; i++) free(cfg->var_names[i]);
        free(cfg->var_names);
        cfg->var_names = nullptr;
    }
    if (cfg->var_values) {
        for (int i = 0; i < cfg->var_count; i++) free(cfg->var_values[i]);
        free(cfg->var_values);
        cfg->var_values = nullptr;
    }
    if (cfg->var_resolved) {
        for (int i = 0; i < cfg->var_count; i++) free(cfg->var_resolved[i]);
        free(cfg->var_resolved);
        cfg->var_resolved = nullptr;
    }
    if (cfg->var_is_static) {
        free(cfg->var_is_static);
        cfg->var_is_static = nullptr;
    }
    cfg->var_count = 0;
    cfg->var_capacity = 0;
```

- [ ] **Step 3: 在 parse_config_line 开头插入赋值分支**

在 `src/config/config_parser.c:339` 的 `parse_config_line` 函数体最开头，`char* tok = get_next_token(&p_ptr);` **之前**插入：

```c
    /* 先尝试 NAME=VALUE 赋值（紧凑形式，无空格围绕 =） */
    {
        char vname[128], vvalue[MAX_PATH_LEN];
        if (parse_var_assignment(line, vname, sizeof vname, vvalue, sizeof vvalue)) {
            if (strcmp(vname, "package") == 0) {
                LOG_WRN("不允许覆盖系统保留变量 package (行 %d, 文件 %s)", line_num, file_path);
            } else {
                if (cur->var_count >= cur->var_capacity) {
                    int newcap = cur->var_capacity == 0 ? 8 : cur->var_capacity * 2;
                    cur->var_names   = realloc(cur->var_names,   newcap * sizeof(char*));
                    cur->var_values  = realloc(cur->var_values,  newcap * sizeof(char*));
                    cur->var_resolved= realloc(cur->var_resolved,newcap * sizeof(char*));
                    cur->var_is_static = realloc(cur->var_is_static, newcap * sizeof(bool));
                    cur->var_capacity = newcap;
                }
                cur->var_names[cur->var_count] = strdup(vname);
                cur->var_values[cur->var_count] = strdup(vvalue);
                cur->var_resolved[cur->var_count] = NULL;
                if (cur->var_is_static) cur->var_is_static[cur->var_count] = false;
                cur->var_count++;
            }
            return;
        }
    }
```

- [ ] **Step 4: 确认 config_parser.c 已 include path_vars.h**

检查 `src/config/config_parser.c` 顶部 include 区。若无 `#include "path_vars.h"`，在 `#include "common.h"` 之后追加：

```c
#include "path_vars.h"
```

- [ ] **Step 5: 编译验证（含全项目）**

Run: `ninja -C build`
Expected: 全部目标编译通过，无错误。

- [ ] **Step 6: Commit**

```bash
git add include/config_parser.h src/config/config_parser.c
git commit -m "feat(config): AppConfig 增加 var_* 字段、parse_config_line 支持 NAME=VALUE 赋值"
```

---

## Task 5: expand_path_vars（核心展开，含静态/动态分支与循环检测）

**Files:**
- Modify: `src/config/path_vars.c`
- Modify: `tests/test_path_vars.c`

- [ ] **Step 1: 追加测试用例**

```c
static void test_expand_path_vars(void) {
    char out[1024];
    /* 无 $：原样 */
    expand_path_vars("/sdcard/x", out, sizeof out, NULL, NULL, "com.a");
    CHECK(strcmp(out, "/sdcard/x") == 0);
    /* $package */
    expand_path_vars("/sdcard/Android/data/$package/files", out, sizeof out, NULL, NULL, "com.a");
    CHECK(strcmp(out, "/sdcard/Android/data/com.a/files") == 0);
    /* ${package} */
    expand_path_vars("${package}/cache", out, sizeof out, NULL, NULL, "com.b");
    CHECK(strcmp(out, "com.b/cache") == 0);
    /* 未知变量保留字面 */
    expand_path_vars("/x/$foo/y", out, sizeof out, NULL, NULL, "com.a");
    CHECK(strcmp(out, "/x/$foo/y") == 0);
    /* 未闭合 ${ 保留字面 */
    expand_path_vars("/x/${pkg/y", out, sizeof out, NULL, NULL, "com.a");
    CHECK(strcmp(out, "/x/${pkg/y") == 0);
    /* $ 后非变量名字符，保留 $ */
    expand_path_vars("cost$5", out, sizeof out, NULL, NULL, "com.a");
    CHECK(strcmp(out, "cost$5") == 0);
    /* 多次出现 */
    expand_path_vars("$package/$package", out, sizeof out, NULL, NULL, "com.a");
    CHECK(strcmp(out, "com.a/com.a") == 0);

    /* 用户变量（构造 AppConfig） */
    AppConfig cfg = {0};
    char* n1 = strdup("BASE"); char* v1 = strdup("/sdcard/$package");
    cfg.var_names = &n1; cfg.var_values = &v1;
    cfg.var_resolved = (char*[]){NULL};  /* 动态，未预计算 */
    bool st[] = {false};
    cfg.var_is_static = st;
    cfg.var_count = 1;
    expand_path_vars("$BASE/files", out, sizeof out, &cfg, NULL, "com.a");
    CHECK(strcmp(out, "/sdcard/com.a/files") == 0);
    /* app 覆盖 global */
    AppConfig g = {0};
    char* gn = strdup("V"); char* gv = strdup("/global");
    g.var_names = &gn; g.var_values = &gv; g.var_resolved = (char*[]){NULL};
    bool gst[] = {false}; g.var_is_static = gst; g.var_count = 1;
    AppConfig a = {0};
    char* an = strdup("V"); char* av = strdup("/app");
    a.var_names = &an; a.var_values = &av; a.var_resolved = (char*[]){NULL};
    bool ast[] = {false}; a.var_is_static = ast; a.var_count = 1;
    expand_path_vars("$V/x", out, sizeof out, &a, &g, "com.a");
    CHECK(strcmp(out, "/app/x") == 0);
    /* 循环引用：A=$B, B=$A（不展开为静态，运行时遇循环保留字面） */
    AppConfig c2 = {0};
    char* c2n[] = {"A", "B"};
    char* c2v[] = {"$B", "$A"};
    c2.var_names = c2n; c2.var_values = c2v;
    c2.var_resolved = (char*[]){NULL, NULL};
    bool c2st[] = {false, false}; c2.var_is_static = c2st; c2.var_count = 2;
    expand_path_vars("$A", out, sizeof out, &c2, NULL, "com.a");
    CHECK(strcmp(out, "$A") == 0);  /* 循环→保留字面 */
    /* 缓冲区截断：输出超长不越界，结果以 null 结尾 */
    char small[4];
    expand_path_vars("/sdcard/Android/data/$package", small, sizeof small, NULL, NULL, "com.a");
    CHECK(small[3] == '\0' && strncmp(small, "/sd", 3) == 0);
}
```

在 `main` 加 `test_expand_path_vars();`。

- [ ] **Step 2: 运行验证失败**

Run: `ninja -C build test_path_vars && ./build/test_path_vars`
Expected: FAIL（链接错误）。

- [ ] **Step 3: 在 path_vars.c 追加完整实现**

```c
typedef struct {
    char* out;
    size_t outsz;
    size_t pos;
    const AppConfig* app_cfg;
    const AppConfig* global_cfg;
    const char* current_pkg;
    char stack[32][64];   /* 展开栈，循环检测 */
    int stack_n;
} expand_ctx;

static void out_ch(expand_ctx* c, char ch) {
    if (c->pos + 1 < c->outsz) c->out[c->pos++] = ch;
}

static void out_raw(expand_ctx* c, const char* s, size_t n) {
    for (size_t i = 0; i < n; i++) out_ch(c, s[i]);
}

/* 解析 $name 或 ${name}。返回消费后的指针；*ok=false 表示非合法引用（保留原字面） */
static const char* parse_dollar(const char* p, char* buf, size_t bufsz, bool* ok) {
    *ok = false;
    if (*p != '$') return p;
    p++;
    if (*p == '{') {
        p++;
        size_t k = 0;
        while (*p && *p != '}' && k + 1 < bufsz) buf[k++] = *p++;
        buf[k] = '\0';
        if (*p == '}') { p++; *ok = (k > 0); }
        else *ok = false;   /* 未闭合 */
    } else if (isalpha((unsigned char)*p) || *p == '_') {
        size_t k = 0;
        while ((isalnum((unsigned char)*p) || *p == '_') && k + 1 < bufsz) buf[k++] = *p++;
        buf[k] = '\0';
        *ok = true;
    } else {
        buf[0] = '\0';
        *ok = false;
    }
    return p;
}

/* 查变量。返回值指针与是否已 resolve（静态）。未找到返回 NULL */
static const char* lookup_var(expand_ctx* c, const char* name, bool* is_resolved) {
    *is_resolved = false;
    if (strcmp(name, "package") == 0) return c->current_pkg;
    const AppConfig* arrs[2] = { c->app_cfg, c->global_cfg };
    for (int a = 0; a < 2; a++) {
        const AppConfig* cfg = arrs[a];
        if (!cfg || !cfg->var_names) continue;
        for (int i = 0; i < cfg->var_count; i++) {
            if (cfg->var_names[i] && strcmp(cfg->var_names[i], name) == 0) {
                if (cfg->var_is_static && cfg->var_is_static[i] &&
                    cfg->var_resolved && cfg->var_resolved[i]) {
                    *is_resolved = true;
                    return cfg->var_resolved[i];
                }
                return cfg->var_values[i];
            }
        }
    }
    return NULL;
}

static void expand_into(expand_ctx* c, const char* in) {
    if (!in) return;
    const char* p = in;
    while (*p) {
        if (*p == '$') {
            const char* before = p;
            char name[128];
            bool ok;
            p = parse_dollar(p, name, sizeof name, &ok);
            if (!ok || name[0] == '\0') {
                out_raw(c, before, (size_t)(p - before));   /* 保留原字面 */
                continue;
            }
            bool is_resolved;
            const char* val = lookup_var(c, name, &is_resolved);
            if (!val) {
                out_raw(c, before, (size_t)(p - before));   /* 未知变量保留字面 */
                continue;
            }
            if (is_resolved) {
                out_raw(c, val, strlen(val));   /* 静态变量，直接拷入 */
                continue;
            }
            /* 动态变量：递归展开，带循环检测 */
            if (c->stack_n >= 32) {
                out_raw(c, before, (size_t)(p - before));
                continue;
            }
            bool loop = false;
            for (int i = 0; i < c->stack_n; i++) {
                if (strcmp(c->stack[i], name) == 0) { loop = true; break; }
            }
            if (loop) {
                out_raw(c, before, (size_t)(p - before));
                continue;
            }
            size_t nl = strlen(name);
            if (nl > 63) nl = 63;
            memcpy(c->stack[c->stack_n], name, nl);
            c->stack[c->stack_n][nl] = '\0';
            c->stack_n++;
            expand_into(c, val);
            c->stack_n--;
        } else {
            out_ch(c, *p);
            p++;
        }
    }
}

size_t expand_path_vars(const char* in, char* out, size_t outsz,
                        const AppConfig* app_cfg, const AppConfig* global_cfg,
                        const char* current_pkg) {
    if (!in || !out || outsz == 0) return 0;
    if (!strchr(in, '$')) {   /* memchr 短路 */
        size_t n = strlen(in);
        if (n >= outsz) n = outsz - 1;
        memcpy(out, in, n);
        out[n] = '\0';
        return n;
    }
    expand_ctx c;
    memset(&c, 0, sizeof c);
    c.out = out; c.outsz = outsz;
    c.app_cfg = app_cfg; c.global_cfg = global_cfg;
    c.current_pkg = current_pkg;
    expand_into(&c, in);
    if (c.pos >= outsz) c.pos = outsz - 1;
    out[c.pos] = '\0';
    return c.pos;
}
```

- [ ] **Step 4: 运行验证通过**

Run: `ninja -C build test_path_vars && ./build/test_path_vars`
Expected: `all passed`。

- [ ] **Step 5: Commit**

```bash
git add src/config/path_vars.c tests/test_path_vars.c
git commit -m "feat(path_vars): 实现 expand_path_vars 递归展开与循环检测"
```

---

## Task 6: analyze_var_staticness + load 末尾调用 + 静态集成测试

**Files:**
- Modify: `src/config/path_vars.c`
- Modify: `src/config/config_parser.c`（load_config_rules 末尾调用）
- Modify: `tests/test_path_vars.c`

- [ ] **Step 1: 追加测试用例**

```c
static void test_analyze_var_staticness(void) {
    /* 全局：STATIC=/sdcard/m（字面量）, DYN=/x/$package（动态）, NEST=$STATIC/c（静态） */
    AppConfig g = {0};
    char* gn[] = {"STATIC", "DYN", "NEST"};
    char* gv[] = {"/sdcard/m", "/x/$package", "$STATIC/c"};
    g.var_names = gn; g.var_values = gv;
    char* gr[] = {NULL, NULL, NULL};
    g.var_resolved = gr;
    bool gst[] = {false, false, false};
    g.var_is_static = gst; g.var_count = 3;
    analyze_var_staticness(&g, NULL);
    CHECK(g.var_is_static[0] == true);   /* STATIC 静态 */
    CHECK(g.var_is_static[1] == false);  /* DYN 动态 */
    CHECK(g.var_is_static[2] == true);   /* NEST 传递闭包仍静态 */
    CHECK(g.var_resolved[0] != NULL && strcmp(g.var_resolved[0], "/sdcard/m") == 0);
    CHECK(g.var_resolved[2] != NULL && strcmp(g.var_resolved[2], "/sdcard/m/c") == 0);
    CHECK(g.var_resolved[1] == NULL);    /* 动态不预计算 */
    /* 循环引用 → 动态 */
    AppConfig c2 = {0};
    char* cn[] = {"A", "B"};
    char* cv[] = {"$B", "$A"};
    c2.var_names = cn; c2.var_values = cv;
    char* cr[] = {NULL, NULL};
    c2.var_resolved = cr;
    bool cst[] = {false, false};
    c2.var_is_static = cst; c2.var_count = 2;
    analyze_var_staticness(&c2, NULL);
    CHECK(c2.var_is_static[0] == false && c2.var_is_static[1] == false);
    /* 展开后静态变量走 resolved（与递归展开结果一致） */
    char out[256];
    expand_path_vars("$NEST/files", out, sizeof out, &g, NULL, "com.a");
    CHECK(strcmp(out, "/sdcard/m/c/files") == 0);
}
```

在 `main` 加 `test_analyze_var_staticness();`。

- [ ] **Step 2: 运行验证失败**

Run: `ninja -C build test_path_vars && ./build/test_path_vars`
Expected: FAIL（链接错误）。

- [ ] **Step 3: 在 path_vars.c 追加实现**

```c
static int find_var_index(const AppConfig* cfg, const char* name) {
    if (!cfg || !cfg->var_names) return -1;
    for (int i = 0; i < cfg->var_count; i++) {
        if (cfg->var_names[i] && strcmp(cfg->var_names[i], name) == 0) return i;
    }
    return -1;
}

/* 扫描某变量值，判定其状态：
   返回 1=静态（无动态因素），2=动态（含 $package 或引用动态变量），0=未定（引用未定变量）。
   pending 标记是否含未定引用。 */
static int scan_value_state(const char* val, const AppConfig* cfg, const int* state,
                            const AppConfig* global, bool* pending) {
    *pending = false;
    if (!val) return 1;
    for (const char* p = val; *p; ) {
        if (*p == '$') {
            char name[128]; bool ok;
            const char* after = parse_dollar(p, name, sizeof name, &ok);
            if (ok && name[0]) {
                if (strcmp(name, "package") == 0) return 2;   /* 系统动态变量 */
                int idx = find_var_index(cfg, name);
                if (idx >= 0) {
                    if (state[idx] == 2) return 2;
                    if (state[idx] == 0) *pending = true;
                    /* state==1 静态，继续 */
                } else if (global) {
                    int gi = find_var_index(global, name);
                    if (gi >= 0) {
                        if (!global->var_is_static || !global->var_is_static[gi]) return 2;
                        /* global 静态，继续 */
                    }
                    /* else 未知变量，当字面 */
                }
                p = after;
            } else {
                p = after;   /* 非合法引用，按字面处理 */
            }
        } else {
            p++;
        }
    }
    return *pending ? 0 : 1;   /* 无动态因素：无 pending 则静态 */
}

void analyze_var_staticness(AppConfig* cfg, const AppConfig* global_cfg) {
    int n = cfg->var_count;
    if (n <= 0) return;
    int* state = calloc((size_t)n, sizeof(int));   /* 0=unknown */
    if (!state) return;
    bool changed = true;
    int rounds = 0;
    while (changed && rounds <= n) {
        changed = false; rounds++;
        for (int i = 0; i < n; i++) {
            if (state[i] != 0) continue;
            bool pending = false;
            int st = scan_value_state(cfg->var_values[i], cfg, state, global_cfg, &pending);
            if (st == 2) { state[i] = 2; changed = true; }
            else if (st == 1) { state[i] = 1; changed = true; }
            /* st==0 保持未定 */
        }
    }
    /* 收敛后仍未定（循环）→ 动态 */
    /* 预计算静态变量 resolved：先全置 var_is_static=false，使 expand 用纯递归 */
    for (int i = 0; i < n; i++) cfg->var_is_static[i] = false;
    for (int i = 0; i < n; i++) {
        if (state[i] == 1) {
            cfg->var_resolved[i] = malloc(PATH_MAX);
            if (cfg->var_resolved[i]) {
                expand_path_vars(cfg->var_values[i], cfg->var_resolved[i], PATH_MAX, cfg, global_cfg, "pkg");
            }
        }
    }
    for (int i = 0; i < n; i++) cfg->var_is_static[i] = (state[i] == 1);
    free(state);
}
```

> 注：`PATH_MAX` 来自 `common.h`（含 `<limits.h>`）。预计算时 `current_pkg` 传占位 `"pkg"`，因为静态变量值不含 `$package`（已判定），pkg 不影响结果。

- [ ] **Step 4: 运行验证通过**

Run: `ninja -C build test_path_vars && ./build/test_path_vars`
Expected: `all passed`。

- [ ] **Step 5: 在 load_config_rules 末尾调用 analyze**

在 `src/config/config_parser.c` 的 `load_config_rules`（:636-643 的 qsort 块）**之后**、函数结束 `}` 之前 插入：

```c
    analyze_var_staticness(&g_global_cfg, NULL);
    for (int i = 0; i < g_app_cfg_count; i++) {
        analyze_var_staticness(g_app_cfgs[i], &g_global_cfg);
    }
```

- [ ] **Step 6: 全量编译验证**

Run: `ninja -C build`
Expected: 通过。

- [ ] **Step 7: Commit**

```bash
git add src/config/path_vars.c src/config/config_parser.c tests/test_path_vars.c
git commit -m "feat(path_vars): 实现 analyze_var_staticness 静态分析与预计算，并在配置加载后调用"
```

---

## Task 7: build_real_base_from_target

**Files:**
- Modify: `src/config/path_vars.c`
- Modify: `tests/test_path_vars.c`

- [ ] **Step 1: 追加测试用例**

```c
static void test_build_real_base(void) {
    char base[PATH_MAX];
    /* 不含 $：emulated 归一 */
    CHECK(build_real_base_from_target("?/Android/data", 0, base, sizeof base, NULL, NULL, "com.a") == true);
    CHECK(strcmp(base, "/data/media/0/Android/data") == 0);
    /* 不含 $：系统绝对 */
    CHECK(build_real_base_from_target("/data/foo", 10, base, sizeof base, NULL, NULL, "com.a") == true);
    CHECK(strcmp(base, "/data/foo") == 0);
    CHECK(build_real_base_from_target("/mnt", 10, base, sizeof base, NULL, NULL, "com.a") == true);
    CHECK(strcmp(base, "/mnt") == 0);
    /* 不含 $：相对 */
    CHECK(build_real_base_from_target("Android/data", 10, base, sizeof base, NULL, NULL, "com.a") == true);
    CHECK(strcmp(base, "/data/media/10/Android/data") == 0);
    /* 含 $：展开后系统绝对（/mnt/sdcard/com.a） */
    CHECK(build_real_base_from_target("/mnt/sdcard/$package", 10, base, sizeof base, NULL, NULL, "com.a") == true);
    CHECK(strcmp(base, "/mnt/sdcard/com.a") == 0);
    /* 含 $：展开后 /data 根目录 */
    CHECK(build_real_base_from_target("$P", 10, base, sizeof base,
          &(AppConfig){0}, NULL, "com.a") == true);  /* $P 未知→保留字面→相对 */
    /* 含 $ 但包名不可解析 → 失效 */
    CHECK(build_real_base_from_target("/x/$package", 10, base, sizeof base, NULL, NULL, "system") == false);
    CHECK(build_real_base_from_target("/x/$package", 10, base, sizeof base, NULL, NULL, "unknown") == false);
}
```

> 注：上面含复合字面量 `(AppConfig){0}` 的行用于未知变量 `$P` 场景——展开后保留字面 `$P`（不以 `/` 开头）→ 相对，结果 `/data/media/10/$P`。可单独断言该结果。若编译器对复合字面量报警告，可改为先定义 `AppConfig empty = {0};` 再传入。

在 `main` 加 `test_build_real_base();`。

- [ ] **Step 2: 运行验证失败**

Run: `ninja -C build test_path_vars && ./build/test_path_vars`
Expected: FAIL（链接错误）。

- [ ] **Step 3: 在 path_vars.c 追加实现**

```c
bool build_real_base_from_target(const char* target, int user_id, char* real_base, size_t sz,
                                 const AppConfig* app_cfg, const AppConfig* global_cfg,
                                 const char* current_pkg) {
    if (!target || !real_base || sz == 0) return false;
    char expanded[PATH_MAX];
    const char* t = target;
    if (has_path_var(target)) {
        if (!pkg_resolvable(current_pkg)) return false;   /* 规则失效 */
        expand_path_vars(target, expanded, sizeof expanded, app_cfg, global_cfg, current_pkg);
        t = expanded;
    }
    if (t[0] == '?') {
        /* 相对当前 user 存储（ALLOW/相对路径在 parse 阶段转成的 ? 前缀，等价原 :271-274）。
           注意 t+1 以 '/' 开头，格式串用 "/%d%s"（%s 前无 '/'），否则产生双斜杠 */
        snprintf(real_base, sz, STORAGE_BASE "/%d%s", user_id, t + 1);
    } else if (strncmp(t, "/storage/emulated/", 18) == 0) {
        const char* rest = t + 18;
        while (*rest && isdigit((unsigned char)*rest)) rest++;
        if (*rest == '/') rest++;
        snprintf(real_base, sz, STORAGE_BASE "/%d/%s", user_id, rest);
    } else if (is_system_abs_path(t)) {
        strncpy(real_base, t, sz - 1);
        real_base[sz - 1] = '\0';
    } else {
        const char* rest = (t[0] == '/') ? t + 1 : t;
        snprintf(real_base, sz, STORAGE_BASE "/%d/%s", user_id, rest);
    }
    return true;
}
```

- [ ] **Step 4: 运行验证通过**

Run: `ninja -C build test_path_vars && ./build/test_path_vars`
Expected: `all passed`。

- [ ] **Step 5: Commit**

```bash
git add src/config/path_vars.c tests/test_path_vars.c
git commit -m "feat(path_vars): 实现 build_real_base_from_target 统一路径分类构造"
```

---

## Task 8: 集成 #1 — check_redir_rule 改用 build_real_base_from_target

**Files:**
- Modify: `src/daemon/vfs_core.c:259-291`（check_redir_rule 的 real_base 构造段）
- Test: 编译 + Task 13 运行时验证

- [ ] **Step 1: 修改 check_redir_rule 的 real_base 构造**

定位 `src/daemon/vfs_core.c` 的 `check_redir_rule`（:259）中，从 `const char* target = c->redir_rules[i].real_target;`（:270）到 `matched = true;`（:286）这段 real_base 构造逻辑。

把现有的：
```c
                char real_base[MAX_PATH_LEN];
                const char* target = c->redir_rules[i].real_target;
                if (target[0] == '?') {
                    int effective_uid = user_id >= 0 ? user_id : 0;
                    snprintf(real_base, sizeof(real_base), STORAGE_BASE "/%d%s", effective_uid, target + 1);
                } else {
                    strncpy(real_base, target, sizeof(real_base) - 1); 
                    real_base[sizeof(real_base) - 1] = '\0';
                }
```

替换为：
```c
                char real_base[PATH_MAX];
                const char* target = c->redir_rules[i].real_target;
                if (!build_real_base_from_target(target, (user_id >= 0 ? user_id : 0),
                                                 real_base, sizeof real_base,
                                                 c, &g_global_cfg, current_pkg)) {
                    continue;   /* 含 $ 但包名不可解析 → 本条 redir 不命中 */
                }
```

> 注意：`build_real_base_from_target` 内部已统一处理 `?` 前缀、emulated、系统绝对、相对四类，且对含 `$` 的 target 先展开。`current_pkg` 是 `check_redir_rule` 的现有参数（:259 签名）。

- [ ] **Step 2: 确认 vfs_core.c 已 include path_vars.h**

在 `src/daemon/vfs_core.c` 顶部 include 区，若无则追加：
```c
#include "path_vars.h"
```

- [ ] **Step 3: 全量编译验证**

Run: `ninja -C build`
Expected: 通过。

- [ ] **Step 4: Commit**

```bash
git add src/daemon/vfs_core.c
git commit -m "feat(vfs): check_redir_rule 改用 build_real_base_from_target 统一路径构造"
```

---

## Task 9: 集成 #2 — vfs_fill_virtual_dirs 改用 build_real_base_from_target + 签名加 current_pkg

**Files:**
- Modify: `src/daemon/vfs_core.c:601`（vfs_fill_virtual_dirs 签名）+ `:602-624`（PROCESS_CFG_DIRS 宏）
- Modify: `src/daemon/fuse_daemon.c`（vfs_fill_virtual_dirs 调用处）

- [ ] **Step 1: 给 vfs_fill_virtual_dirs 增加 current_pkg 参数**

在 `src/daemon/vfs_core.c:601` 函数签名末尾加 `const char* current_pkg`：

```c
bool vfs_fill_virtual_dirs(AppConfig* cfg, const char* sub_path, int path_user_id, void* buf, fuse_fill_dir_t filler, uid_t uid, gid_t gid, DirHashTable* ht, bool is_root, const char* current_pkg) {
```

- [ ] **Step 2: 修改 PROCESS_CFG_DIRS 宏里的 dummy 构造**

定位 `:611-616` 的：
```c
                if (strcmp(full_vpath, (c)->redir_rules[i].virtual_prefix) == 0) { \
                     char dummy[1024]; const char* target = (c)->redir_rules[i].real_target; \
                     if (target[0] == '?') { int effective_uid = path_user_id >= 0 ? path_user_id : 0; snprintf(dummy, sizeof(dummy), STORAGE_BASE "/%d%s", effective_uid, target + 1); } \
                     else { strncpy(dummy, target, sizeof(dummy)-1); dummy[sizeof(dummy)-1] = '\0'; } \
                     if (access(dummy, F_OK) != 0) continue; \
                } \
```

替换为：
```c
                if (strcmp(full_vpath, (c)->redir_rules[i].virtual_prefix) == 0) { \
                     char dummy[PATH_MAX]; \
                     if (!build_real_base_from_target((c)->redir_rules[i].real_target, (path_user_id >= 0 ? path_user_id : 0), dummy, sizeof dummy, (c), &g_global_cfg, current_pkg)) continue; \
                     if (access(dummy, F_OK) != 0) continue; \
                } \
```

- [ ] **Step 3: 更新 fuse_daemon.c 的调用处**

在 `src/daemon/fuse_daemon.c` 里 `vfs_readdir`（:175 附近）调用 `vfs_fill_virtual_dirs(...)` 处，末尾补传 `current_pkg`（该 handler 经 `VFS_SETUP_CORE` 宏已有 `current_pkg` 变量）。

用 grep 定位调用点：`grep -n "vfs_fill_virtual_dirs" src/daemon/fuse_daemon.c`，在该调用的参数列表末尾加 `, current_pkg`。

- [ ] **Step 4: 全量编译验证**

Run: `ninja -C build`
Expected: 通过（无 "too few arguments" 错误）。

- [ ] **Step 5: Commit**

```bash
git add src/daemon/vfs_core.c src/daemon/fuse_daemon.c
git commit -m "feat(vfs): vfs_fill_virtual_dirs 改用 build_real_base_from_target 并接收 current_pkg"
```

---

## Task 10: 集成 #3 — is_path_hidden_internal 对 hide 规则展开

**Files:**
- Modify: `src/daemon/vfs_core.c:219-236`（is_path_hidden_internal 的 hide_rules 遍历段）

- [ ] **Step 1: 修改 app cfg 的 hide_rules 遍历**

定位 `:219-227`：
```c
    if (cfg && cfg->hide_rules) {
        for (int i = 0; i < cfg->hide_count; i++) {
            if (cfg->hide_rules[i]) {
                if (fnmatch(cfg->hide_rules[i], sub_path, 0) == 0) { return true; }
                size_t len = strlen(cfg->hide_rules[i]);
                if (strncmp(sub_path, cfg->hide_rules[i], len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { return true; }
            }
        }
    }
```

替换为：
```c
    if (cfg && cfg->hide_rules) {
        for (int i = 0; i < cfg->hide_count; i++) {
            if (cfg->hide_rules[i]) {
                const char* rule = cfg->hide_rules[i];
                char expanded[PATH_MAX];
                const char* match_str = rule;
                if (has_path_var(rule)) {
                    if (!pkg_resolvable(current_pkg)) continue;   /* 规则失效 */
                    expand_path_vars(rule, expanded, sizeof expanded, cfg, &g_global_cfg, current_pkg);
                    match_str = expanded;
                }
                if (fnmatch(match_str, sub_path, 0) == 0) { return true; }
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { return true; }
            }
        }
    }
```

- [ ] **Step 2: 同样修改 g_global_cfg 的 hide_rules 遍历**

定位 `:228-236` 同结构的 `g_global_cfg.hide_rules` 遍历段，同样替换为展开版（`app_cfg` 参数用 `cfg`、`global_cfg` 用 `&g_global_cfg`）：

```c
    if (g_global_cfg.hide_rules) {
        for (int i = 0; i < g_global_cfg.hide_count; i++) {
            if (g_global_cfg.hide_rules[i]) {
                const char* rule = g_global_cfg.hide_rules[i];
                char expanded[PATH_MAX];
                const char* match_str = rule;
                if (has_path_var(rule)) {
                    if (!pkg_resolvable(current_pkg)) continue;
                    expand_path_vars(rule, expanded, sizeof expanded, cfg, &g_global_cfg, current_pkg);
                    match_str = expanded;
                }
                if (fnmatch(match_str, sub_path, 0) == 0) { return true; }
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { return true; }
            }
        }
    }
```

- [ ] **Step 3: 全量编译验证**

Run: `ninja -C build`
Expected: 通过。

- [ ] **Step 4: Commit**

```bash
git add src/daemon/vfs_core.c
git commit -m "feat(vfs): is_path_hidden_internal 支持 hide 规则变量展开"
```

---

## Task 11: 集成 #4 — RO 段对 ro 规则展开

**Files:**
- Modify: `src/daemon/vfs_core.c:388-403`（vfs_to_real_path 内 RO 段）

- [ ] **Step 1: 修改 app cfg 的 ro_rules 遍历**

定位 `:388-395`：
```c
    if (cfg && cfg->ro_rules) {
        for (int i = 0; i < cfg->ro_count; i++) {
            if (cfg->ro_rules[i]) {
                if (fnmatch(cfg->ro_rules[i], sub_path, 0) == 0) { return true; }
                size_t len = strlen(cfg->ro_rules[i]);
                if (strncmp(sub_path, cfg->ro_rules[i], len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { return true; }
            }
        }
    }
```

替换为：
```c
    if (cfg && cfg->ro_rules) {
        for (int i = 0; i < cfg->ro_count; i++) {
            if (cfg->ro_rules[i]) {
                const char* rule = cfg->ro_rules[i];
                char expanded[PATH_MAX];
                const char* match_str = rule;
                if (has_path_var(rule)) {
                    if (!pkg_resolvable(current_pkg)) continue;
                    expand_path_vars(rule, expanded, sizeof expanded, cfg, &g_global_cfg, current_pkg);
                    match_str = expanded;
                }
                if (fnmatch(match_str, sub_path, 0) == 0) { return true; }
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { return true; }
            }
        }
    }
```

- [ ] **Step 2: 同样修改 g_global_cfg 的 ro_rules 遍历（:397-403）**

同结构替换（`app_cfg`=`cfg`、`global_cfg`=`&g_global_cfg`）：
```c
    if (g_global_cfg.ro_rules) {
        for (int i = 0; i < g_global_cfg.ro_count; i++) {
            if (g_global_cfg.ro_rules[i]) {
                const char* rule = g_global_cfg.ro_rules[i];
                char expanded[PATH_MAX];
                const char* match_str = rule;
                if (has_path_var(rule)) {
                    if (!pkg_resolvable(current_pkg)) continue;
                    expand_path_vars(rule, expanded, sizeof expanded, cfg, &g_global_cfg, current_pkg);
                    match_str = expanded;
                }
                if (fnmatch(match_str, sub_path, 0) == 0) { return true; }
                size_t len = strlen(match_str);
                if (strncmp(sub_path, match_str, len) == 0 && (sub_path[len] == '\0' || sub_path[len] == '/')) { return true; }
            }
        }
    }
```

- [ ] **Step 3: 全量编译验证**

Run: `ninja -C build`
Expected: 通过。

- [ ] **Step 4: Commit**

```bash
git add src/daemon/vfs_core.c
git commit -m "feat(vfs): RO 段支持 ro 规则变量展开"
```

---

## Task 12: trie 判定收紧 + REDIRECT 含 `$` 延迟归一 + :463 用 is_system_abs_path

**Files:**
- Modify: `src/config/config_parser.c`

- [ ] **Step 1: trie 判定收紧（hide/ro/redirect 含 `$` 不进 trie）**

- `:388` hide：`if (!is_wildcard_string(clean_rule))` → `if (!is_wildcard_string(clean_rule) && !has_path_var(clean_rule))`
- `:409` ro：同上
- `:437` redirect virtual_prefix：`if (!is_wildcard_string(virtual_prefix))` → `if (!is_wildcard_string(virtual_prefix) && !has_path_var(virtual_prefix))`
- `:477` redirect：`if (!is_wildcard_string(virtual_prefix) && !is_wildcard_string(real_target))` → `if (!is_wildcard_string(virtual_prefix) && !is_wildcard_string(real_target) && !has_path_var(real_target))`

- [ ] **Step 2: REDIRECT real_target 含 `$` 时延迟归一**

定位 `:456-469` 的 real_target 构造段：
```c
            char real_target[MAX_PATH_LEN];
            if (strncmp(v2, "/storage/emulated/", 18) == 0) {
                char* p = v2 + 18;
                while (*p && isdigit((unsigned char)*p)) p++;
                if (*p == '/') p++;
                snprintf(real_target, MAX_PATH_LEN - 1, "?/%s", p);
            }
            else if (strncmp(v2, "/data/", 6) == 0 || strncmp(v2, "/mnt/", 5) == 0 || strncmp(v2, "/storage/", 9) == 0) {
                strncpy(real_target, v2, MAX_PATH_LEN - 1);
            }
            else {
                snprintf(real_target, MAX_PATH_LEN - 1, "?/%s", v2[0] == '/' ? v2 + 1 : v2);
            }
            strip_trailing_slash(real_target);
```

在 `char real_target[MAX_PATH_LEN];` 之后、`if (strncmp(v2, "/storage/emulated/"...` 之前，插入含 `$` 的短路分支：
```c
            char real_target[MAX_PATH_LEN];
            if (has_path_var(v2)) {
                /* 含变量：原样存入，路径分类延迟到运行时 build_real_base_from_target */
                strncpy(real_target, v2, MAX_PATH_LEN - 1);
                real_target[MAX_PATH_LEN - 1] = '\0';
            }
            else if (strncmp(v2, "/storage/emulated/", 18) == 0) {
                char* p = v2 + 18;
                while (*p && isdigit((unsigned char)*p)) p++;
                if (*p == '/') p++;
                snprintf(real_target, MAX_PATH_LEN - 1, "?/%s", p);
            }
            else if (is_system_abs_path(v2)) {   /* 替换原 strncmp /data/ /mnt/ /storage/ 判定，支持根目录本身 */
                strncpy(real_target, v2, MAX_PATH_LEN - 1);
                real_target[MAX_PATH_LEN - 1] = '\0';
            }
            else {
                snprintf(real_target, MAX_PATH_LEN - 1, "?/%s", v2[0] == '/' ? v2 + 1 : v2);
            }
            strip_trailing_slash(real_target);
```

> 注：原 `else if (strncmp(v2,"/data/",6)==0 || strncmp(v2,"/mnt/",5)==0 || strncmp(v2,"/storage/",9)==0)` 被 `is_system_abs_path(v2)` 替代，从而支持 `/data`、`/mnt`、`/storage` 根目录本身（无尾部斜杠）。

- [ ] **Step 3: 全量编译验证**

Run: `ninja -C build`
Expected: 通过。

- [ ] **Step 4: 运行单元测试确认无回归**

Run: `ninja -C build test_path_vars && ./build/test_path_vars`
Expected: `all passed`。

- [ ] **Step 5: Commit**

```bash
git add src/config/config_parser.c
git commit -m "feat(config): 含 $ 规则不进 trie、REDIRECT 延迟归一、:463 改用 is_system_abs_path 支持根目录"
```

---

## Task 13: 端到端运行时验证 + 配置文档

**Files:**
- Verify: 运行时行为（按设计 7.2）
- Modify: `docs/`（若有配置说明文档）

- [ ] **Step 1: 重新构建并部署**

Run: `ninja -C build && cp build/fuse_daemon <部署路径>/`（按项目实际部署方式）
Expected: 成功启动 fuse_daemon，无崩溃。

- [ ] **Step 2: 运行时验证 — 系统根目录（不含变量）**

配置：
```
REDIRECT /test_data /data
REDIRECT /test_mnt /mnt
```
从任意应用访问 `/test_data`、`/test_mnt`，验证落到真实 `/data`、`/mnt`（非 `/data/media/<uid>/data`）。
检查 `[MAP]` 调试日志：`g_min_log_level=LOG_DEBUG` 时 `vfs_log_io` 打印 `sub_path -> real_path`。

- [ ] **Step 3: 运行时验证 — 静态用户变量**

配置：
```
[GLOBAL]
STATIC_BASE=/sdcard/myapp
REDIRECT /x $STATIC_BASE/files
```
从应用 A/B 访问 `/x`，验证都落到 `/sdcard/myapp/files`。

- [ ] **Step 4: 运行时验证 — 动态用户变量（含 $package 递归）**

配置：
```
[GLOBAL]
DATA_BASE=/sdcard/Android/data/$package
REDIRECT /files $DATA_BASE/files
HIDE $DATA_BASE/private
```
应用 A 访问 `/files` 落到 `/sdcard/Android/data/<A>/files`；应用 B 落到各自目录。
应用 A 访问 `/sdcard/Android/data/<A>/private` 返回 ENOENT（隐藏），应用 B 访问各自 private 也 ENOENT，但应用 A 访问 `<B>/private` 可见（非本包隐藏）。

- [ ] **Step 5: 运行时验证 — 系统根目录变量**

配置：
```
[GLOBAL]
MNT=/mnt/sdcard/$package
REDIRECT /ext $MNT
```
应用 A 访问 `/ext` → `/mnt/sdcard/<A>`（绝对路径，不拼 user_id）。

- [ ] **Step 6: 运行时验证 — app 覆盖 global**

配置：
```
[GLOBAL]
VAR=/global
[com.x:0]
VAR=/appx
REDIRECT /v $VAR
```
com.x 访问 `/v` → `/global`？应→`/appx`（app 覆盖）；其他应用 → `/global`。

- [ ] **Step 7: 运行时验证 — 未命中失效**

以 system uid 进程访问含 `$package` 的规则路径，验证规则失效走默认（非崩溃）。

- [ ] **Step 8: 更新配置文档**

若 `docs/` 下有配置说明文件，补充 `NAME=VALUE` 赋值语法、`$name`/`${name}` 引用、静态/动态行为、系统根目录说明。引用设计文档 `docs/superpowers/specs/2026-07-05-package-variable-design.md`。

- [ ] **Step 9: Commit**

```bash
git add docs/
git commit -m "docs: 补充路径变量与 NAME=VALUE 配置语法说明"
```

---

## Self-Review 结果

**1. Spec 覆盖：**
- `$package` 系统变量 → Task 5（expand）+ Task 8-11（集成）
- `NAME=VALUE` 用户变量 → Task 3（parse）+ Task 4（赋值分支）+ Task 5（查找）
- 全局+应用级作用域 → Task 5 测试（app 覆盖 global）+ Task 4（存入 cur）
- 递归展开 → Task 5（expand_into 递归）
- 静态/动态优化 → Task 6（analyze）+ Task 5（lookup_var 静态分支）
- REDIRECT 路径延迟归一 → Task 7（build_real_base）+ Task 8/#1 + Task 12
- 系统根目录 /mnt /data → Task 2（is_system_abs_path）+ Task 7 + Task 12
- 未命中失效 → Task 7（返回 false）+ Task 8-11（调用方 continue）
- 循环检测 → Task 5（stack + depth 32）
- 保留名 package 禁止覆盖 → Task 4（LOG_WRN）

**2. 占位符扫描：** 无 TBD/TODO；Task 2 中的 `/data/...` 占位行已注明改写为真实路径。

**3. 类型一致性：** `expand_path_vars` / `build_real_base_from_target` 签名（含 `global_cfg` 参数）在 Task 1（声明）、Task 5/7（实现）、Task 8-11（调用 `&g_global_cfg`）一致；`var_*` 字段在 Task 4（定义）、Task 5/6（使用）、Task 4 free（释放）一致；`vfs_fill_virtual_dirs` 签名变更在 Task 9（定义）与 fuse_daemon.c（调用）一致。
