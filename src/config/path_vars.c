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

static bool starts_with_root(const char* path, const char* root) {
    size_t rl = strlen(root);
    if (strncmp(path, root, rl) != 0) return false;
    char c = path[rl]; /* strncmp 已保证 strlen(path) >= rl，此处不越界 */
    return c == '\0' || c == '/';
}

bool is_system_abs_path(const char* path) {
    if (!path || path[0] != '/') return false;
    return starts_with_root(path, "/data") || starts_with_root(path, "/mnt") ||
           starts_with_root(path, "/storage");
}

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
    p++; /* 跳过 '=' */
    strncpy(value, p, nval - 1);
    value[nval - 1] = '\0';
    return true;
}

typedef struct {
    char* out;
    size_t outsz;
    size_t pos;
    const AppConfig* app_cfg;
    const AppConfig* global_cfg;
    const char* current_pkg;
    char stack[32][64]; /* 展开栈，循环检测 */
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
        if (*p == '}') {
            p++;
            *ok = (k > 0);
        } else
            *ok = false; /* 未闭合 */
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
    const AppConfig* arrs[2] = {c->app_cfg, c->global_cfg};
    for (int a = 0; a < 2; a++) {
        const AppConfig* cfg = arrs[a];
        if (!cfg || !cfg->var_names) continue;
        for (int i = 0; i < cfg->var_count; i++) {
            if (cfg->var_names[i] && strcmp(cfg->var_names[i], name) == 0) {
                if (cfg->var_is_static && cfg->var_is_static[i] && cfg->var_resolved &&
                    cfg->var_resolved[i]) {
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
                out_raw(c, before, (size_t)(p - before)); /* 保留原字面 */
                continue;
            }
            bool is_resolved;
            const char* val = lookup_var(c, name, &is_resolved);
            if (!val) {
                out_raw(c, before, (size_t)(p - before)); /* 未知变量保留字面 */
                continue;
            }
            if (is_resolved) {
                out_raw(c, val, strlen(val)); /* 静态变量，直接拷入 */
                continue;
            }
            /* 动态变量：递归展开，带循环检测 */
            if (c->stack_n >= 32) {
                out_raw(c, before, (size_t)(p - before));
                continue;
            }
            bool loop = false;
            for (int i = 0; i < c->stack_n; i++) {
                if (strcmp(c->stack[i], name) == 0) {
                    loop = true;
                    break;
                }
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

size_t expand_path_vars(const char* in, char* out, size_t outsz, const AppConfig* app_cfg,
                        const AppConfig* global_cfg, const char* current_pkg) {
    if (!in || !out || outsz == 0) return 0;
    if (!strchr(in, '$')) { /* memchr 短路 */
        size_t n = strlen(in);
        if (n >= outsz) n = outsz - 1;
        memcpy(out, in, n);
        out[n] = '\0';
        return n;
    }
    expand_ctx c;
    memset(&c, 0, sizeof c);
    c.out = out;
    c.outsz = outsz;
    c.app_cfg = app_cfg;
    c.global_cfg = global_cfg;
    c.current_pkg = current_pkg;
    expand_into(&c, in);
    if (c.pos >= outsz) c.pos = outsz - 1;
    out[c.pos] = '\0';
    return c.pos;
}

static int find_var_index(const AppConfig* cfg, const char* name) {
    if (!cfg || !cfg->var_names) return -1;
    for (int i = 0; i < cfg->var_count; i++) {
        if (cfg->var_names[i] && strcmp(cfg->var_names[i], name) == 0) return i;
    }
    return -1;
}

/* 扫描某变量值，判定其状态：
   返回 1=静态（无动态因素），2=动态（含 $package 或引用动态变量），0=未定（引用未定变量） */
static int scan_value_state(const char* val, const AppConfig* cfg, const int* state,
                            const AppConfig* global, bool* pending) {
    *pending = false;
    if (!val) return 1;
    for (const char* p = val; *p;) {
        if (*p == '$') {
            char name[128];
            bool ok;
            const char* after = parse_dollar(p, name, sizeof name, &ok);
            if (ok && name[0]) {
                if (strcmp(name, "package") == 0) return 2; /* 系统动态变量 */
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
                p = after; /* 非合法引用，按字面处理 */
            }
        } else {
            p++;
        }
    }
    return *pending ? 0 : 1; /* 无动态因素：无 pending 则静态 */
}

void analyze_var_staticness(AppConfig* cfg, const AppConfig* global_cfg) {
    int n = cfg->var_count;
    if (n <= 0) return;
    int* state = calloc((size_t)n, sizeof(int)); /* 0=unknown */
    if (!state) return;
    bool changed = true;
    int rounds = 0;
    while (changed && rounds <= n) {
        changed = false;
        rounds++;
        for (int i = 0; i < n; i++) {
            if (state[i] != 0) continue;
            bool pending = false;
            int st = scan_value_state(cfg->var_values[i], cfg, state, global_cfg, &pending);
            if (st == 2) {
                state[i] = 2;
                changed = true;
            } else if (st == 1) {
                state[i] = 1;
                changed = true;
            }
            /* st==0 保持未定 */
        }
    }
    /* 收敛后仍未定（循环）→ 动态（state 保持 0，下面 var_is_static=false） */
    /* 预计算静态变量 resolved：先全置 var_is_static=false，使 expand 用纯递归 */
    for (int i = 0; i < n; i++) cfg->var_is_static[i] = false;
    for (int i = 0; i < n; i++) {
        if (state[i] == 1) {
            cfg->var_resolved[i] = malloc(PATH_MAX);
            if (cfg->var_resolved[i]) {
                expand_path_vars(cfg->var_values[i], cfg->var_resolved[i], PATH_MAX, cfg,
                                 global_cfg, "pkg");
            }
        }
    }
    for (int i = 0; i < n; i++) cfg->var_is_static[i] = (state[i] == 1);
    free(state);
}

/* 目标展开是否**依赖 $package**：直接引用 `$package`，或引用了非静态（值里含
   $package 或引用动态变量）的自定义变量。判定复用 analyze_var_staticness 预计算
   的 var_is_static——不必自己重跑静态度分析（那会与扫描逻辑各写一份）。 */
static bool target_needs_pkg(const char* target, const AppConfig* app, const AppConfig* global) {
    for (const char* p = target; p && *p;) {
        if (*p != '$') {
            p++;
            continue;
        }
        char name[128];
        bool ok;
        p = parse_dollar(p, name, sizeof name, &ok);
        if (!ok || !name[0]) continue;
        if (strcmp(name, "package") == 0) return true;
        for (int a = 0; a < 2; a++) {
            const AppConfig* cfg = (a == 0) ? app : global;
            int idx = find_var_index(cfg, name);
            if (idx < 0) continue;
            if (!cfg->var_is_static || !cfg->var_is_static[idx]) return true;
            break; /* 静态变量：var_resolved 已是展开结果，不含 $package */
        }
    }
    return false;
}

bool build_real_base_from_target(const char* target, int user_id, char* real_base, size_t sz,
                                 const AppConfig* app_cfg, const AppConfig* global_cfg,
                                 const char* current_pkg) {
    if (!target || !real_base || sz == 0) return false;
    char expanded[PATH_MAX * 4];
    const char* t = target;
    if (has_path_var(target)) {
        /* 只有**真正依赖 $package** 的目标才在包名不可解析时失效（config.md §5）。
           旧实现一见目标含变量就要求 pkg_resolvable，把自定义变量（DEST=/Pics/ 这类
           与包名无关）的规则也从 system/unknown 访问者身上一并否掉了。 */
        if (target_needs_pkg(target, app_cfg, global_cfg) && !pkg_resolvable(current_pkg))
            return false; /* 规则失效 */
        expand_path_vars(target, expanded, sizeof expanded, app_cfg, global_cfg, current_pkg);
        t = expanded;
    }
    /* ===== 前缀剥离：统一得到"相对 user 存储"的剩余路径 =====
       根目录（剥离后剩余为空，如 ? 后无路径 / 仅 user_id 层）
       不允许任何规则插入——FUSE 挂载点根下不得出现额外虚拟目录
       （由框架 loader.c 的 path_has_uid_layer 拦截兜底）；
       仅允许 <uid>/ 之后的路径（与其他目录合成逻辑分开，避免混淆） */
    const char* rest = nullptr;
    /* "/storage/emulated/" 前缀长度（含尾斜杠 = 18），剥离与比较共用。
       必须用 "ROOT \"/\"" 的字面量：ROOT 本身 17 字符，sizeof-1 会少 1 */
    const size_t emu_prefix_len = sizeof(NSP_ANDROID_EMULATED_ROOT "/") - 1;
    if (t[0] == '?') {
        /* 相对当前 user 存储（ALLOW/相对路径在 parse 阶段转成的 ? 前缀，
           等价原 vfs_core.c:271-274）。t+1 以 '/' 开头，剥离后即剩余 */
        rest = t + 1;
        if (*rest == '/') rest++;
    } else if (strncmp(t, NSP_ANDROID_EMULATED_ROOT "/", emu_prefix_len) == 0) {
        rest = t + emu_prefix_len;
        while (*rest && isdigit((unsigned char)*rest)) rest++;
        if (*rest == '/') rest++;
    } else if (is_system_abs_path(t)) {
        /* 系统绝对路径（/data、/mnt、/storage 开头，非挂载镜像）：原样使用 */
        strncpy(real_base, t, sz - 1);
        real_base[sz - 1] = '\0';
        return true;
    } else {
        rest = (t[0] == '/') ? t + 1 : t;
    }
    /* ===== 根目录判定（独立于目录合成）=====
       剩余为空（如 ?/、挂载点本身、仅 /storage/emulated/0/ 用户层）：
       指向 FUSE 根目录，不允许任何规则插入，仅 <uid>/ 之后允许 */
    if (!rest || rest[0] == '\0') return false;
    /* ===== 目录合成：<uid>/ 之后的路径 =====
       经 common_default_real_path 统一合成（禁裸拼 STORAGE_BASE）：
       rest 无前导 '/'，补 '/' 后语义与原 "%s/%d/%s" 分支逐字节一致 */
    char with_slash[PATH_MAX];
    with_slash[0] = '/';
    strncpy(with_slash + 1, rest, sizeof(with_slash) - 2);
    with_slash[sizeof(with_slash) - 1] = '\0';
    common_default_real_path(user_id, with_slash, real_base, sz);
    return true;
}
