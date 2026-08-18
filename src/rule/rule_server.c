/*
 * rule_server —— 规则控制守护进程
 *
 * 前端（Android 应用 / GNU 管理界面）通过抽象命名空间 Unix Domain Socket
 * （默认 nsp_rule_socket）发送单行 JSON 命令，实现对项目全部规则文件的动态管理：
 *
 *   PING / LIST / GET             查询（全局 + 各应用规则，含启用状态）
 *   ADD                           动态新增规则（REDIRECT/ALLOW/HIDE/RO/开关）
 *   REMOVE                        按 (类型, 索引) 删除规则
 *   ENABLE / DISABLE              启用/停用规则（# 注释切换，解析器自动跳过）
 *   SET                           设置开关（MONITOR/SANDBOX/GLOBAL_INJECT/INJECT_ENABLE）
 *   RELOAD                        向 injector 发送 SIGHUP 触发配置重载
 *   STOP                          向 injector 发送 SIGTERM 停止注入服务
 *   STATUS                        系统状态概览
 *   QUIT                          退出本守护进程（测试/管理用）
 *
 * 双平台适配：路径全部基于 CONFIG_DIR（Android=/data/Namespace-Proxy，
 * GNU=/var/fuse-proxy），抽象套接字在 Linux 内核（含 Android）上语义一致；
 * 无 Android 专有 API，GNU/Android 均可构建运行。
 *
 * 依赖：仅 json-c（无 libfuse、无 config_parser，纯文件级操作，
 * 与 injector/fuse_daemon 通过 inotify 热重载联动，无需内存规则状态）。
 */

#include "common.h"
#include <json-c/json.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stddef.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <poll.h>

#define RULE_VERSION "1.0.0"
#define MAX_REQ_LEN 8192
#define MAX_LINE 2048

/* 可被命令行覆盖的运行参数（--config-dir / --socket） */
static char g_config_dir[PATH_MAX] = CONFIG_DIR;
static char g_socket_name[64] = RULE_SOCKET_NAME;
static volatile sig_atomic_t g_should_exit = 0;
static bool g_foreground = false;   /* --foreground：前台运行（测试/调试用） */
static struct timespec g_start_mono;  /* 启动时刻（CLOCK_MONOTONIC，运行时长基准） */
static time_t g_start_wall = 0;       /* 启动时刻（墙钟，started_at 展示） */

/* 日志开关：DEBUG 构建输出到 stderr（Android 由 logcat 捕获） */
#ifdef DEBUG
#define RLOG(...) fprintf(stderr, "[rule_server] " __VA_ARGS__)
#else
#define RLOG(...) do { } while (0)
#endif

/* ==================== 规则类型（动态注册表） ====================
   类型来源两类：
   1. 内置类型（rule_types_init 填充）：HIDE/RO/REDIRECT/ALLOW/MONITOR/
      SANDBOX/GLOBAL_INJECT，与 basic_rules 模块能力对应；
   2. 模块类型（rule_types_refresh 扫描）：加载模块目录下 <模块名>.rules
      声明的类型（如 ftp_module 的 FTP），实现「支持的规则随加载模块动态追加」。
   值格式决定 ADD 时如何解析 value、写入文件时如何拼行：
     path   — 单值路径（HIDE /x）
     pair   — src|dst 双值（REDIRECT /a|/b → REDIRECT /a /b）
     switch — ON/OFF 开关（MONITOR ON）
     tokens — 空格分隔多 token（ADD 时 value 用 | 分隔） */
typedef enum {
    RFT_PATH = 0,   /* 单值路径 */
    RFT_PAIR,       /* src|dst */
    RFT_SWITCH,     /* ON/OFF */
    RFT_TOKENS      /* 多 token（| 分隔） */
} RuleFmt;

#define MAX_RULE_TYPES 64
/* 多语言描述槽：<lang, text> 对；lang 为语言代码（zh/en/ja/...，默认 zh） */
#define MAX_DESC_LANGS 8
typedef struct {
    char lang[8];
    char text[160];
} DescEntry;
typedef struct {
    char name[64];        /* 类型名（大写，如 HIDE / FTP） */
    RuleFmt fmt;          /* 值格式 */
    bool builtin;         /* 内置类型（不可随模块卸载移除） */
    bool global_only;     /* 仅全局作用域可用（如 GLOBAL_INJECT/SKIP_SYSTEM_APPS） */
    char module[64];      /* 来源模块名（内置为 "builtin"） */
    /* 动态适配扩展：.rules 可选属性（argc=N / argc=N:M / global-only / desc[.lang]="..."）
       argc_min/argc_max：pair/tokens 的参数数量约束（-1=不限制，默认：
       pair=2:2、path=1:1、tokens=2:-1、switch=1:1），ADD 时按此校验 */
    int argc_min;
    int argc_max;
    DescEntry descs[MAX_DESC_LANGS];  /* 多语言描述（desc=→zh，desc.en=→en，...） */
    int desc_count;
} RuleTypeDef;

typedef int RuleType;     /* 动态表索引；RT_UNKNOWN 表示未知 */
#define RT_UNKNOWN (-1)

static RuleTypeDef g_rule_types[MAX_RULE_TYPES];
static int g_rule_type_count = 0;

/* 按格式取默认参数数量约束：path=1、pair=2、tokens=2+（上限不限）、switch=1 */
static void rule_fmt_default_argc(RuleFmt fmt, int *minp, int *maxp) {
    switch (fmt) {
        case RFT_PATH:   *minp = 1; *maxp = 1; break;
        case RFT_PAIR:   *minp = 2; *maxp = 2; break;
        case RFT_SWITCH: *minp = 1; *maxp = 1; break;
        case RFT_TOKENS: *minp = 2; *maxp = -1; break;
        default:         *minp = 1; *maxp = -1; break;
    }
}

/* 内置类型初始化（与 basic_rules 能力一一对应） */
static void rule_types_add_ex(const char *name, RuleFmt fmt, bool builtin, bool global_only,
                              const char *module, int argc_min, int argc_max,
                              const DescEntry *descs, int desc_count) {
    if (g_rule_type_count >= MAX_RULE_TYPES) return;
    RuleTypeDef *t = &g_rule_types[g_rule_type_count];
    strncpy(t->name, name, sizeof(t->name) - 1);
    t->fmt = fmt;
    t->builtin = builtin;
    t->global_only = global_only;
    strncpy(t->module, module ? module : "builtin", sizeof(t->module) - 1);
    if (argc_min < 0 && argc_max < 0) rule_fmt_default_argc(fmt, &argc_min, &argc_max);
    t->argc_min = argc_min;
    t->argc_max = argc_max;
    /* 多语言描述：逐个槽复制（默认 zh 在前），多余截断 */
    t->desc_count = 0;
    for (int i = 0; i < desc_count && t->desc_count < MAX_DESC_LANGS; i++) {
        if (!descs[i].text[0]) continue;
        strncpy(t->descs[t->desc_count].lang, descs[i].lang, sizeof(t->descs[t->desc_count].lang) - 1);
        strncpy(t->descs[t->desc_count].text, descs[i].text, sizeof(t->descs[t->desc_count].text) - 1);
        t->desc_count++;
    }
    g_rule_type_count++;
}

/* 兼容旧签名：argc/desc 取默认 */
static void rule_types_add(const char *name, RuleFmt fmt, bool builtin, bool global_only, const char *module) {
    rule_types_add_ex(name, fmt, builtin, global_only, module, -1, -1, nullptr, 0);
}

static void rule_types_init(void) {
    g_rule_type_count = 0;
    rule_types_add("HIDE", RFT_PATH, true, false, "builtin");
    rule_types_add("RO", RFT_PATH, true, false, "builtin");
    rule_types_add("REDIRECT", RFT_PAIR, true, false, "builtin");
    rule_types_add("ALLOW", RFT_PATH, true, false, "builtin");
    rule_types_add("MONITOR", RFT_SWITCH, true, false, "builtin");
    rule_types_add("SANDBOX", RFT_SWITCH, true, false, "builtin");
    /* 全局专属：仅 [GLOBAL] 段可用，应用配置中不允许出现 */
    rule_types_add("GLOBAL_INJECT", RFT_SWITCH, true, true, "builtin");
    rule_types_add("SKIP_SYSTEM_APPS", RFT_SWITCH, true, true, "builtin");
}

/* 按名查找类型（大小写不敏感），返回索引；未找到返回 RT_UNKNOWN */
static RuleType rule_type_of(const char *name);

/* 合并属性到已存在的类型（定义见 conf 解析段）：前向声明供旧行格式
   rule_types_parse_line 使用（两种格式共用同一合并语义） */
static void rule_types_merge(RuleType idx, RuleFmt fmt, bool fmt_set,
                             int argc_min, int argc_max, bool argc_set,
                             bool global_only, bool global_only_set,
                             const DescEntry *descs, int desc_count);

static RuleType rule_type_of(const char *name) {
    if (!name) return RT_UNKNOWN;
    for (int i = 0; i < g_rule_type_count; i++) {
        if (strcasecmp(name, g_rule_types[i].name) == 0) return i;
    }
    return RT_UNKNOWN;
}

static const char *rule_type_name(RuleType t) {
    if (t < 0 || t >= g_rule_type_count) return NULL;
    return g_rule_types[t].name;
}

static bool is_switch_type(RuleType t) {
    if (t < 0 || t >= g_rule_type_count) return false;
    return g_rule_types[t].fmt == RFT_SWITCH;
}

/* 识别一行是否为规则/开关行（忽略行首空白与可选的 # 注释前缀）；
   返回类型索引；非规则行（空行/段头/未知关键字）返回 RT_UNKNOWN */
static RuleType classify_line(const char *line) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#') {
        p++;
        while (*p == ' ' || *p == '\t') p++;
    }
    if (*p == '[' || *p == '\0' || *p == '\n') return RT_UNKNOWN;
    for (int i = 0; i < g_rule_type_count; i++) {
        const char *name = g_rule_types[i].name;
        size_t nlen = strlen(name);
        if (strncasecmp(p, name, nlen) == 0 &&
            (p[nlen] == ' ' || p[nlen] == '\t' || p[nlen] == '\n' || p[nlen] == '\0'))
            return i;
    }
    return RT_UNKNOWN;
}

/* 解析一行 .rules 声明："<TYPE> <FORMAT>"，追加进类型表（去重）。
   FORMAT: path|pair|switch|tokens，缺省为 path */
static void rule_types_parse_line(char *line, const char *module) {
    char *p = line;
    while (isspace((unsigned char)*p)) p++;
    if (!*p || *p == '#') return;
    char type[64];
    int i = 0;
    while (*p && !isspace((unsigned char)*p) && i < (int)sizeof(type) - 1)
        type[i++] = *p++;
    type[i] = '\0';
    if (!type[0]) return;
    while (isspace((unsigned char)*p)) p++;
    RuleFmt fmt = RFT_PATH;
    if (strncasecmp(p, "pair", 4) == 0)      { fmt = RFT_PAIR;   p += 4; }
    else if (strncasecmp(p, "switch", 6) == 0) { fmt = RFT_SWITCH; p += 6; }
    else if (strncasecmp(p, "tokens", 6) == 0) { fmt = RFT_TOKENS; p += 6; }
    else if (strncasecmp(p, "path", 4) == 0)  { fmt = RFT_PATH;   p += 4; }
    else return;                              /* 未知 FORMAT：跳过 */
    /* 可选属性列（以空格分隔，顺序任意）：
         argc=N          — 恰好 N 个参数
         argc=N:M        — N~M 个参数（M 省略或 * 表示不限上界）
         global-only     — 仅全局作用域可用
         desc="..."      — 类型描述（中文，默认语言；引号内可含空格，最长 159 字符）
         desc.xx="..."   — 指定语言的描述（xx=语言代码，如 desc.en="..."） */
    int argc_min = -1, argc_max = -1;
    bool global_only = false;
    DescEntry descs[MAX_DESC_LANGS];
    int desc_count = 0;
    /* desc 语言代码缓冲：必须在循环外（函数作用域），否则 lang 指针在
       if 块结束后悬垂，语言变体（desc.en=）会被覆盖为空 */
    char langbuf[8] = "zh";
    while (*p) {
        while (isspace((unsigned char)*p)) p++;
        if (!*p) break;
        if (strncasecmp(p, "argc=", 5) == 0) {
            /* 用 strtol 校验数字：atoi 无法区分解析失败与合法 0，
               畸形声明（argc=abc / argc=2:abc）会静默生成 0:0 / N:0 约束，
               使该类型所有 ADD 被拒且错误信息误导调用方。
               畸形时跳过该属性（保持向前兼容），不注册错误约束 */
            p += 5;
            char *end = nullptr;
            errno = 0;
            long v1 = strtol(p, &end, 10);
            if (end == p || errno == ERANGE) {   /* 非数字：跳过属性 */
                while (*p && !isspace((unsigned char)*p)) p++;
                continue;
            }
            /* 先完整解析 N 或 N:M（含畸形上界），全部成功后才提交：
               argc=2:abc 的畸形上界使整个属性被跳过，不注册 2:∞ */
            int new_min = (int)v1;
            int new_max = new_min;
            p = end;
            if (*p == ':') {
                p++;
                if (*p == '*' || *p == '\0' || isspace((unsigned char)*p)) {
                    new_max = -1;   /* 不限上界 */
                    if (*p == '*') p++;
                } else {
                    char *end2 = nullptr;
                    errno = 0;
                    long v2 = strtol(p, &end2, 10);
                    if (end2 == p || errno == ERANGE) {   /* 畸形上界：整体跳过属性 */
                        while (*p && !isspace((unsigned char)*p)) p++;
                        continue;
                    }
                    new_max = (int)v2;
                    p = end2;
                }
            }
            argc_min = new_min;
            argc_max = new_max;
            continue;
        }
        if (strncasecmp(p, "global-only", 11) == 0) {
            global_only = true;
            p += 11;
            continue;
        }
        if (strncasecmp(p, "desc", 4) == 0) {
            /* 每个 desc= 前重置为默认中文：保证属性顺序任意（文档约定
               "顺序任意"）——desc.en= 出现在 desc= 之前时，默认描述
               不会被错误标记为上一变体的语言 */
            strncpy(langbuf, "zh", sizeof(langbuf) - 1);
            const char *lang = langbuf;   /* 默认中文 */
            p += 4;
            if (*p == '.') {           /* desc.xx= 语言变体 */
                p++;
                size_t li = 0;
                while (*p && *p != '=' && li < sizeof(langbuf) - 1) langbuf[li++] = *p++;
                langbuf[li] = '\0';
                if (li > 0) lang = langbuf;
            }
            if (*p == '=') p++;
            char dtext[160] = {0};
            if (*p == '"') {
                p++;
                size_t di = 0;
                while (*p && *p != '"' && di < sizeof(dtext) - 1) dtext[di++] = *p++;
                dtext[di] = '\0';
                if (*p == '"') p++;
            } else {
                size_t di = 0;
                while (*p && !isspace((unsigned char)*p) && di < sizeof(dtext) - 1)
                    dtext[di++] = *p++;
                dtext[di] = '\0';
            }
            if (dtext[0] && desc_count < MAX_DESC_LANGS) {
                strncpy(descs[desc_count].lang, lang, sizeof(descs[desc_count].lang) - 1);
                strncpy(descs[desc_count].text, dtext, sizeof(descs[desc_count].text) - 1);
                desc_count++;
            }
            continue;
        }
        /* 未知属性：跳过该 token，保持向前兼容 */
        while (*p && !isspace((unsigned char)*p)) p++;
    }
    /* 已注册（内置或他模块）的同名类型：合并补充属性（多语言 desc 等），
       不覆盖类型名与 module 来源；否则作为新模块类型注册 */
    RuleType existing = rule_type_of(type);
    if (existing != RT_UNKNOWN) {
        rule_types_merge(existing, fmt, true,
                         argc_min, argc_max, (argc_min >= 0),
                         global_only, global_only,
                         descs, desc_count);
    } else {
        rule_types_add_ex(type, fmt, false, global_only, module,
                          argc_min, argc_max, descs, desc_count);
    }
}

/* ============ conf 格式解析（.rules 支持两种书写格式） ============
   conf 段格式（推荐，易于编写）：
     [FTP]
     format = pair
     argc = 2
     global-only = false
     desc = FTP 存储映射：<虚拟前缀>|<段名>
     desc.en = FTP storage mapping: <virtual prefix>|<section>
   旧行格式（兼容）：FTP pair argc=2 desc="..." desc.en="..."
   解析器为状态机：遇到 [TYPE] 段头进入段模式收集 key=value 属性，
   段内无 '=' 的行或段外行按旧行格式处理；文件尾刷新未结束的段。 */

/* conf 段属性收集状态 */
typedef struct {
    char type[64];
    bool active;          /* 是否处于 [TYPE] 段内 */
    RuleFmt fmt;
    bool fmt_set;         /* format 键是否显式声明（未声明不覆盖已有类型） */
    int argc_min, argc_max;
    bool argc_set;        /* argc 键是否显式声明 */
    bool global_only;
    bool global_only_set; /* global-only 键是否显式声明 */
    DescEntry descs[MAX_DESC_LANGS];
    int desc_count;
    char langbuf[8];      /* desc 语言缓冲（函数级作用域防悬垂） */
} ConfSection;

static void conf_section_reset(ConfSection *cs) {
    cs->active = false;
    cs->type[0] = '\0';
    cs->fmt = RFT_PATH;
    cs->fmt_set = false;
    cs->argc_min = -1;
    cs->argc_max = -1;
    cs->argc_set = false;
    cs->global_only = false;
    cs->global_only_set = false;
    cs->desc_count = 0;
}

/* 合并属性到已存在的类型（内置或他模块注册的同名类型）：
   .rules 中的补充声明（desc 多语言/argc/global-only 等）生效，
   不覆盖内置类型名与 module 来源；显式声明的字段（*_set）才覆盖。 */
static void rule_types_merge(RuleType idx, RuleFmt fmt, bool fmt_set,
                             int argc_min, int argc_max, bool argc_set,
                             bool global_only, bool global_only_set,
                             const DescEntry *descs, int desc_count) {
    if (idx < 0 || idx >= g_rule_type_count) return;
    RuleTypeDef *t = &g_rule_types[idx];
    if (fmt_set) t->fmt = fmt;
    if (argc_set) {
        t->argc_min = argc_min;
        t->argc_max = argc_max;
    }
    if (global_only_set) t->global_only = global_only;
    /* desc 槽合并：已有同语言则覆盖文本，否则追加 */
    for (int i = 0; i < desc_count; i++) {
        bool replaced = false;
        for (int d = 0; d < t->desc_count; d++) {
            if (strcasecmp(t->descs[d].lang, descs[i].lang) == 0) {
                strncpy(t->descs[d].text, descs[i].text, sizeof(t->descs[d].text) - 1);
                replaced = true;
                break;
            }
        }
        if (!replaced && t->desc_count < MAX_DESC_LANGS) {
            strncpy(t->descs[t->desc_count].lang, descs[i].lang,
                    sizeof(t->descs[t->desc_count].lang) - 1);
            strncpy(t->descs[t->desc_count].text, descs[i].text,
                    sizeof(t->descs[t->desc_count].text) - 1);
            t->desc_count++;
        }
    }
}

/* 段结束时把收集的属性注册进类型表（同名内置类型改为合并补充） */
static void conf_section_flush(ConfSection *cs, const char *module) {
    if (cs->active && cs->type[0]) {
        RuleType existing = rule_type_of(cs->type);
        if (existing == RT_UNKNOWN) {
            rule_types_add_ex(cs->type, cs->fmt, false, cs->global_only, module,
                              cs->argc_min, cs->argc_max, cs->descs, cs->desc_count);
        } else {
            rule_types_merge(existing, cs->fmt, cs->fmt_set,
                             cs->argc_min, cs->argc_max, cs->argc_set,
                             cs->global_only, cs->global_only_set,
                             cs->descs, cs->desc_count);
        }
    }
    conf_section_reset(cs);
}

/* 解析 conf 键值属性（format/argc/global-only/desc[.lang]），写入段状态 */
static void conf_section_apply_key(ConfSection *cs, const char *key, const char *val) {
    if (strcasecmp(key, "format") == 0) {
        if (strcasecmp(val, "pair") == 0) cs->fmt = RFT_PAIR;
        else if (strcasecmp(val, "switch") == 0) cs->fmt = RFT_SWITCH;
        else if (strcasecmp(val, "tokens") == 0) cs->fmt = RFT_TOKENS;
        else cs->fmt = RFT_PATH;
        cs->fmt_set = true;
        return;
    }
    if (strcasecmp(key, "argc") == 0) {
        /* 先完整解析 N 或 N:M（含畸形上界），全部成功后才提交到段状态：
           argc=2:abc 的畸形上界会使整个属性被跳过，而不是注册 2:∞
           错误约束（与文档"畸形声明被跳过"语义一致） */
        char *end = nullptr;
        errno = 0;
        long v1 = strtol(val, &end, 10);
        if (end == val || errno == ERANGE) return;   /* 畸形：跳过 */
        int new_min = (int)v1;
        int new_max = new_min;
        if (*end == ':') {
            const char *up = end + 1;
            if (*up == '*' || *up == '\0' || isspace((unsigned char)*up)) {
                new_max = -1;                        /* 不限上界 */
            } else {
                char *end2 = nullptr;
                errno = 0;
                long v2 = strtol(up, &end2, 10);
                if (end2 == up || errno == ERANGE) return;   /* 畸形上界：整体跳过 */
                new_max = (int)v2;
            }
        }
        cs->argc_min = new_min;
        cs->argc_max = new_max;
        cs->argc_set = true;
        return;
    }
    if (strcasecmp(key, "global-only") == 0) {
        cs->global_only = (strcasecmp(val, "true") == 0 || strcasecmp(val, "1") == 0 ||
                           strcasecmp(val, "yes") == 0 || strcasecmp(val, "on") == 0);
        cs->global_only_set = true;
        return;
    }
    if (strncasecmp(key, "desc", 4) == 0) {
        /* 每个 desc= 前重置默认中文（属性顺序任意） */
        strncpy(cs->langbuf, "zh", sizeof(cs->langbuf) - 1);
        const char *lang = cs->langbuf;
        const char *dot = key + 4;
        if (*dot == '.') {                           /* desc.xx= 语言变体 */
            dot++;
            size_t li = 0;
            while (*dot && li < sizeof(cs->langbuf) - 1) cs->langbuf[li++] = *dot++;
            cs->langbuf[li] = '\0';
            if (li > 0) lang = cs->langbuf;
        }
        const char *v = val;
        char dtext[160] = {0};
        if (*v == '"') {                             /* 引号包裹（可含空格） */
            v++;
            size_t di = 0;
            while (*v && *v != '"' && di < sizeof(dtext) - 1) dtext[di++] = *v++;
        } else {
            size_t di = 0;
            while (*v && di < sizeof(dtext) - 1) dtext[di++] = *v++;
        }
        if (dtext[0] && cs->desc_count < MAX_DESC_LANGS) {
            strncpy(cs->descs[cs->desc_count].lang, lang, sizeof(cs->descs[cs->desc_count].lang) - 1);
            strncpy(cs->descs[cs->desc_count].text, dtext, sizeof(cs->descs[cs->desc_count].text) - 1);
            cs->desc_count++;
        }
        return;
    }
    /* 未知键：忽略（向前兼容） */
}

/* 解析整个 .rules 文件（conf 段 + 旧行格式混合） */
static void rule_types_parse_conf(FILE *fp, const char *module) {
    char line[256];
    ConfSection cs;
    conf_section_reset(&cs);
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (!*p || *p == '#') continue;              /* 空行/注释 */
        if (*p == '[') {                             /* 段头：[TYPE] */
            conf_section_flush(&cs, module);
            p++;
            size_t ti = 0;
            while (*p && *p != ']' && ti < sizeof(cs.type) - 1) cs.type[ti++] = *p++;
            cs.type[ti] = '\0';
            cs.active = (ti > 0);
            continue;
        }
        char *eq = strchr(p, '=');
        if (cs.active && eq) {                       /* 段内 key=value */
            *eq = '\0';
            char *key = p;
            while (key < eq && isspace((unsigned char)key[0])) key++;
            char *kend = eq - 1;
            while (kend >= key && isspace((unsigned char)*kend)) { *kend = '\0'; kend--; }
            char *val = eq + 1;
            while (isspace((unsigned char)*val)) val++;
            conf_section_apply_key(&cs, key, val);
            continue;
        }
        /* 旧行格式（兼容）：FTP pair argc=2 ... */
        rule_types_parse_line(line, module);
    }
    conf_section_flush(&cs, module);                 /* 文件尾刷新未结束段 */
}

/* ==================== 模块规则类型缓存（避免每次命令全量扫描） ====================
   dispatch 每次命令前调用 rule_types_refresh：快速路径仅 stat 模块目录与各
   .rules 文件的 mtime，全部未变则直接复用当前类型表；仅当目录/文件 mtime
   变化（模块增删或 .rules 内容修改）才全量重建。 */

#define MAX_CACHED_MODULES 32
typedef struct {
    char name[64];        /* 模块名（目录名 = <name>.rules 前缀） */
    long long mtime_ns;   /* 上次扫描时 <name>.rules 的 mtime（纳秒精度，
                             避免同秒内写入被快速路径误判为未变化） */
    bool present;         /* 上次扫描时 .rules 是否存在 */
} ModuleTypeCache;

static ModuleTypeCache g_module_cache[MAX_CACHED_MODULES];
static int g_module_cache_count = 0;
static long long g_modules_dir_mtime_ns = 0;
static bool g_module_cache_valid = false;

/* 取文件/目录 mtime（纳秒）：不存在返回 0 */
static long long file_mtime_ns(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return (long long)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
}

/* 扫描模块目录 <config_dir>/modules/<名>/<名>.rules，动态追加模块规则类型。
   与 fuse_daemon 加载约定一致（目录名=模块名）；模块卸载后其类型随扫描消失。 */
static void rule_types_refresh(void) {
    char modules_dir[PATH_MAX];
    snprintf(modules_dir, sizeof(modules_dir), "%s/modules", g_config_dir);

    long long cur_dir_mtime = file_mtime_ns(modules_dir);

    /* 快速路径：目录 mtime 未变 + 各 .rules 文件 mtime 未变 → 类型表无需重建 */
    if (g_module_cache_valid && cur_dir_mtime == g_modules_dir_mtime_ns) {
        bool unchanged = true;
        for (int i = 0; i < g_module_cache_count; i++) {
            char rules_path[PATH_MAX];
            snprintf(rules_path, sizeof(rules_path), "%s/%s/%s.rules",
                     modules_dir, g_module_cache[i].name, g_module_cache[i].name);
            long long cur = file_mtime_ns(rules_path);
            bool present = (cur != 0);
            if (present != g_module_cache[i].present ||
                (present && cur != g_module_cache[i].mtime_ns)) {
                unchanged = false;
                break;
            }
        }
        if (unchanged) return;   /* 全部未变：跳过全量扫描 */
    }

    /* 慢路径：全量重建类型表与缓存 */
    g_rule_type_count = 0;
    rule_types_init();
    g_module_cache_count = 0;
    g_modules_dir_mtime_ns = cur_dir_mtime;
    g_module_cache_valid = true;

    if (cur_dir_mtime == 0) return;   /* 模块目录不存在 */
    DIR *d = opendir(modules_dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *mname = de->d_name;
        if (mname[0] == '.') continue;
        if (strchr(mname, '/')) continue;
        char rules_path[PATH_MAX];
        snprintf(rules_path, sizeof(rules_path), "%s/%s/%s.rules", modules_dir, mname, mname);
        long long r_mtime = file_mtime_ns(rules_path);
        bool present = (r_mtime != 0);
        if (g_module_cache_count < MAX_CACHED_MODULES) {
            ModuleTypeCache *c = &g_module_cache[g_module_cache_count];
            strncpy(c->name, mname, sizeof(c->name) - 1);
            c->present = present;
            c->mtime_ns = r_mtime;
            g_module_cache_count++;
        }
        if (!present) continue;
        FILE *fp = fopen(rules_path, "r");
        if (!fp) continue;
        /* 支持 conf 段格式（[TYPE] + key=value）与旧行格式（TYPE FORMAT ...）混合 */
        rule_types_parse_conf(fp, mname);
        fclose(fp);
    }
    closedir(d);
    RLOG("规则类型表: %d 项（含模块动态类型，缓存 %d 个模块）\n",
         g_rule_type_count, g_module_cache_count);
}

/* 该行是否为已注释（停用）状态 */
static bool line_is_disabled(const char *line) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    return *p == '#';
}

/* 提取规则行的"值"部分：关键字后的原始内容（REDIRECT 为 "src dst"） */
static const char *rule_line_value(const char *line, char *out, size_t sz) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#') {
        p++;
        while (*p == ' ' || *p == '\t') p++;
    }
    while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
    while (*p == ' ' || *p == '\t') p++;
    size_t len = 0;
    while (p[len] && p[len] != '\n') {
        if (len + 1 < sz) {
            out[len] = p[len];
            len++;
        } else {
            break;
        }
    }
    while (len > 0 && (out[len - 1] == ' ' || out[len - 1] == '\t')) len--;
    out[len] = '\0';
    return out;
}

/* ==================== 文件行级工具 ==================== */
static char **read_file_lines(const char *path, int *out_count, int *out_cap) {
    FILE *fp = fopen(path, "r");
    if (!fp) { *out_count = 0; *out_cap = 0; return NULL; }
    char **lines = NULL;
    int count = 0, cap = 0;
    char buf[MAX_LINE];
    while (fgets(buf, sizeof(buf), fp)) {
        if (count >= cap) {
            cap = cap == 0 ? 64 : cap * 2;
            char **new_lines = realloc(lines, cap * sizeof(char *));
            if (!new_lines) {
                for (int j = 0; j < count; j++) free(lines[j]);
                free(lines);
                fclose(fp);
                *out_count = 0; *out_cap = 0;
                return NULL;
            }
            lines = new_lines;
        }
        lines[count] = strdup(buf);
        if (!lines[count]) {
            for (int j = 0; j < count; j++) free(lines[j]);
            free(lines);
            fclose(fp);
            *out_count = 0; *out_cap = 0;
            return NULL;
        }
        count++;
    }
    fclose(fp);
    *out_count = count; *out_cap = cap;
    return lines;
}

/* 原子写入：先写临时文件再 rename，避免 inotify 读到半截配置 */
static bool write_file_lines_atomic(const char *path, char **lines, int count) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *fp = fopen(tmp, "w");
    if (!fp) return false;
    for (int i = 0; i < count; i++) {
        if (fputs(lines[i], fp) < 0) { fclose(fp); unlink(tmp); return false; }
    }
    if (fclose(fp) != 0) { unlink(tmp); return false; }
    if (rename(tmp, path) != 0) { unlink(tmp); return false; }
    return true;
}

static void free_file_lines(char **lines, int count) {
    for (int i = 0; i < count; i++) free(lines[i]);
    free(lines);
}

static int insert_line_at(char ***lines, int *cap, int count, int pos, const char *text) {
    if (pos < 0 || pos > count) return -1;
    if (count >= *cap) {
        int new_cap = *cap == 0 ? 64 : *cap * 2;
        if (new_cap > 65536) return -1;   /* 防止无界 realloc */
        char **new_lines = realloc(*lines, (size_t)new_cap * sizeof(char *));
        if (!new_lines) return -1;
        *lines = new_lines;
        *cap = new_cap;
    }
    memmove(&(*lines)[pos + 1], &(*lines)[pos], (count - pos) * sizeof(char *));
    (*lines)[pos] = strdup(text);
    return (*lines)[pos] ? count + 1 : -1;
}

static void remove_line_at(char **lines, int *count, int pos) {
    if (pos < 0 || pos >= *count) return;
    free(lines[pos]);
    memmove(&lines[pos], &lines[pos + 1], (*count - pos - 1) * sizeof(char *));
    (*count)--;
}

static int append_line(char ***lines, int *cap, int count, const char *text) {
    return insert_line_at(lines, cap, count, count, text);
}

/* 查找段头 [name]（或 [name:uid]），返回行号，未找到返回 -1 */
static int find_section_header(char **lines, int count, const char *name) {
    size_t nlen = strlen(name);
    for (int i = 0; i < count; i++) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (p[0] == '[' && strncmp(p + 1, name, nlen) == 0) {
            char after = p[1 + nlen];
            if (after == ']' || after == ':') return i;
        }
    }
    return -1;
}

/* 在段头之后查找指定开关行（MONITOR 等），返回行号，未找到返回 -1 */
static int find_switch_in_section(char **lines, int count, int header_idx, const char *type) {
    size_t tlen = strlen(type);
    for (int i = header_idx + 1; i < count; i++) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (p[0] == '[') break;
        if (strncasecmp(p, type, tlen) == 0 &&
            (p[tlen] == ' ' || p[tlen] == '\t' || p[tlen] == '\n')) {
            return i;
        }
    }
    return -1;
}

/* ==================== 路径工具 ==================== */
static void main_conf_path(char *out, size_t sz) {
    snprintf(out, sz, "%s/injector.conf", g_config_dir);
}

static void app_rule_path(char *out, size_t sz, const char *pkg, int uid) {
    if (uid == 0)
        snprintf(out, sz, "%s/App-rules/%s.conf", g_config_dir, pkg);
    else
        snprintf(out, sz, "%s/App-rules-%d/%s.conf", g_config_dir, uid, pkg);
}

static void app_rule_dir(char *out, size_t sz, int uid) {
    if (uid == 0)
        snprintf(out, sz, "%s/App-rules", g_config_dir);
    else
        snprintf(out, sz, "%s/App-rules-%d", g_config_dir, uid);
}

/* 返回应用规则当前生效文件：.conf 存在（启用）→ .conf；否则 .conf.disabled 存在
   （停用）→ .disabled；两者皆无 → .conf（新建时使用）。
   保证停用状态下 ADD/SET/REMOVE/TOGGLE 继续操作 .disabled 文件，
   不会新建残缺 .conf 导致规则丢失或注入状态异常开启。 */
static void resolve_app_rule_active_path(const char *pkg, int uid, char *out, size_t sz) {
    char path[PATH_MAX];
    app_rule_path(path, sizeof(path), pkg, uid);
    if (access(path, F_OK) == 0) {
        snprintf(out, sz, "%s", path);
        return;
    }
    char dis[PATH_MAX];
    snprintf(dis, sizeof(dis), "%s.disabled", path);
    if (access(dis, F_OK) == 0)
        snprintf(out, sz, "%s", dis);
    else
        snprintf(out, sz, "%s", path);
}

/* 应用规则状态：true=启用（.conf 存在），false=停用（仅 .conf.disabled） */
static bool app_rule_is_enabled(const char *pkg, int uid) {
    char path[PATH_MAX];
    app_rule_path(path, sizeof(path), pkg, uid);
    return (access(path, F_OK) == 0);
}

static void injector_pid_path(char *out, size_t sz) {
    snprintf(out, sz, "%s/injector.pid", g_config_dir);
}

/* 递归建目录（最小实现，避免依赖 common.c） */
static int mkdir_p(const char *path) {
    if (!path || !*path) return -1;
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) { *p = '/'; return -1; }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* ==================== JSON 应答 ==================== */
static void send_all(int fd, const char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n <= 0) return;
        buf += n;
        len -= (size_t)n;
    }
}

static void reply_json(int fd, const char *status, const char *cmd, json_object *data, const char *err) {
    json_object *root = json_object_new_object();
    json_object_object_add(root, "status", json_object_new_string(status));
    json_object_object_add(root, "command", json_object_new_string(cmd));
    if (data) json_object_object_add(root, "data", data);
    if (err) json_object_object_add(root, "error", json_object_new_string(err));
    json_object_object_add(root, "timestamp", json_object_new_int64(time(NULL)));
    const char *s = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    send_all(fd, s, strlen(s));
    send_all(fd, "\n", 1);
    json_object_put(root);
}

static void reply_ok(int fd, const char *cmd, json_object *data) {
    reply_json(fd, "ok", cmd, data, NULL);
}

static void reply_error(int fd, const char *cmd, const char *fmt, ...) {
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    reply_json(fd, "error", cmd, NULL, msg);
}

/* ==================== 输入校验 ==================== */
/* 包名只能含 [A-Za-z0-9._-]，禁止 / 与 ..，防路径穿越 */
static bool valid_pkg(const char *pkg) {
    if (!pkg || !*pkg || strlen(pkg) > 127) return false;
    if (strchr(pkg, '/') || strstr(pkg, "..")) return false;
    for (const char *p = pkg; *p; p++) {
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '_' || *p == '-'))
            return false;
    }
    return true;
}

static bool valid_value(const char *v) {
    if (!v || !*v || strchr(v, '\n')) return false;
    if (strlen(v) >= MAX_LINE - 64) return false;
    for (const char *p = v; *p; p++) {
        if (*p == '\r' || *p == '\0') return false;
    }
    return true;
}

/* ==================== 规则列表构建 ==================== */
/* 构建单个规则文件的 rules 数组 + switches 对象 */
static void build_file_rules(const char *path, json_object *rules, json_object *switches) {
    int count = 0, cap = 0;
    char **lines = read_file_lines(path, &count, &cap);
    if (!lines) return;
    int type_index[MAX_RULE_TYPES] = {0};
    char valbuf[MAX_LINE];
    for (int i = 0; i < count; i++) {
        RuleType t = classify_line(lines[i]);
        if (t == RT_UNKNOWN) continue;
        const char *name = rule_type_name(t);
        bool disabled = line_is_disabled(lines[i]);
        if (is_switch_type(t)) {
            /* 开关：switches.{name} = "ON"/"OFF"（以值行为准，默认 OFF） */
            rule_line_value(lines[i], valbuf, sizeof(valbuf));
            bool on = (strcasecmp(valbuf, "ON") == 0) || (strcasecmp(valbuf, "1") == 0);
            json_object_object_add(switches, name, json_object_new_boolean(on));
        } else {
            json_object *r = json_object_new_object();
            json_object_object_add(r, "index", json_object_new_int(type_index[t]));
            json_object_object_add(r, "type", json_object_new_string(name));
            rule_line_value(lines[i], valbuf, sizeof(valbuf));
            json_object_object_add(r, "value", json_object_new_string(valbuf));
            json_object_object_add(r, "enabled", json_object_new_boolean(!disabled));
            json_object_object_add(r, "module", json_object_new_string(g_rule_types[t].module));
            json_object_array_add(rules, r);
            type_index[t]++;
        }
    }
    free_file_lines(lines, count);
}

static json_object *build_global_json(void) {
    char path[PATH_MAX];
    main_conf_path(path, sizeof(path));
    json_object *global = json_object_new_object();
    json_object *switches = json_object_new_object();
    json_object *rules = json_object_new_array();
    build_file_rules(path, rules, switches);
    json_object_object_add(global, "file", json_object_new_string(path));
    json_object_object_add(global, "switches", switches);
    json_object_object_add(global, "rules", rules);
    return global;
}

static json_object *build_app_json(const char *pkg, int uid) {
    char read_path[PATH_MAX];
    resolve_app_rule_active_path(pkg, uid, read_path, sizeof(read_path));
    bool disabled = !app_rule_is_enabled(pkg, uid);
    json_object *app = json_object_new_object();
    json_object *switches = json_object_new_object();
    json_object *rules = json_object_new_array();
    build_file_rules(read_path, rules, switches);
    json_object_object_add(app, "pkg", json_object_new_string(pkg));
    json_object_object_add(app, "uid", json_object_new_int(uid));
    json_object_object_add(app, "file", json_object_new_string(read_path));
    json_object_object_add(app, "inject_enable", json_object_new_boolean(!disabled));
    if (disabled) json_object_object_add(app, "disabled_file", json_object_new_boolean(true));
    json_object_object_add(app, "switches", switches);
    json_object_object_add(app, "rules", rules);
    return app;
}

/* 扫描 App-rules 与 App-rules-<uid> 目录，列出全部应用规则
   （含已停用 <pkg>.conf.disabled 文件——前端需可见以便重新启用）
   uid_filter >= 0 时仅返回该用户的应用（GET ?uid= 场景） */
static json_object *build_apps_json_filtered(int uid_filter) {
    json_object *apps = json_object_new_array();
    DIR *d = opendir(g_config_dir);
    if (!d) return apps;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *name = de->d_name;
        int uid = 0;
        if (strcmp(name, "App-rules") == 0) {
            uid = 0;
        } else if (strncmp(name, "App-rules-", 10) == 0) {
            uid = atoi(name + 10);
        } else {
            continue;
        }
        if (uid_filter >= 0 && uid != uid_filter) continue;
        char dir[PATH_MAX];
        app_rule_dir(dir, sizeof(dir), uid);
        DIR *ad = opendir(dir);
        if (!ad) continue;
        struct dirent *ae;
        while ((ae = readdir(ad)) != NULL) {
            const char *fn = ae->d_name;
            size_t flen = strlen(fn);
            /* 匹配 <pkg>.conf 与 <pkg>.conf.disabled 两种形态 */
            bool disabled = false;
            size_t suffix = 5;   /* ".conf" */
            if (flen > 14 && strcmp(fn + flen - 14, ".conf.disabled") == 0) {
                disabled = true;
                suffix = 14;     /* ".conf.disabled" */
            } else if (flen <= 5 || strcmp(fn + flen - 5, ".conf") != 0) {
                continue;
            }
            char pkg[128];
            size_t plen = flen - suffix;
            if (plen >= sizeof(pkg)) plen = sizeof(pkg) - 1;
            memcpy(pkg, fn, plen);
            pkg[plen] = '\0';
            if (!valid_pkg(pkg)) continue;
            /* 去重：.conf 存在（启用）时跳过同名 .disabled，避免同一应用输出两个条目；
               状态（inject_enable/disabled_file）由 build_app_json 统一判定 */
            if (disabled && app_rule_is_enabled(pkg, uid)) continue;
            json_object_array_add(apps, build_app_json(pkg, uid));
        }
        closedir(ad);
    }
    closedir(d);
    return apps;
}

static json_object *build_apps_json(void) {
    return build_apps_json_filtered(-1);
}

/* 扫描 config_dir 下全部用户目录（App-rules=uid 0、App-rules-<uid>=uid>0），
   返回用户列表 [{uid, dir, app_count}] */
static json_object *build_users_json(void) {
    json_object *users = json_object_new_array();
    DIR *d = opendir(g_config_dir);
    if (!d) return users;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *name = de->d_name;
        int uid = -1;
        if (strcmp(name, "App-rules") == 0) {
            uid = 0;
        } else if (strncmp(name, "App-rules-", 10) == 0) {
            char *end = NULL;
            long v = strtol(name + 10, &end, 10);
            if (end && *end == '\0' && v >= 0 && v <= 100000)
                uid = (int)v;
        }
        if (uid < 0) continue;
        char dir[PATH_MAX];
        app_rule_dir(dir, sizeof(dir), uid);
        int app_cnt = 0;
        DIR *ad = opendir(dir);
        if (ad) {
            struct dirent *ae;
            while ((ae = readdir(ad)) != NULL) {
                const char *fn = ae->d_name;
                size_t flen = strlen(fn);
                if ((flen > 5 && strcmp(fn + flen - 5, ".conf") == 0) ||
                    (flen > 14 && strcmp(fn + flen - 14, ".conf.disabled") == 0))
                    app_cnt++;
            }
            closedir(ad);
        }
        json_object *u = json_object_new_object();
        json_object_object_add(u, "uid", json_object_new_int(uid));
        json_object_object_add(u, "dir", json_object_new_string(dir));
        json_object_object_add(u, "app_count", json_object_new_int(app_cnt));
        json_object_array_add(users, u);
    }
    closedir(d);
    return users;
}

/* uid 参数校验：JSON 中的 uid 需在合法范围（Android user_id 0~100000） */
static bool valid_uid(int uid) {
    return uid >= 0 && uid <= 100000;
}

/* ==================== 规则定位（按类型+索引） ==================== */
/* 在**已读取**的 lines 中定位第 index 条 type 规则（含已停用行，与 LIST 索引一致），
   返回行号；未找到返回 -1。调用方已持有 lines（避免重复读文件）。 */
static int find_rule_line(char **lines, int count, RuleType type, int index) {
    if (!lines) return -1;
    int seen = 0;
    for (int i = 0; i < count; i++) {
        if (classify_line(lines[i]) == type) {
            if (seen == index) return i;
            seen++;
        }
    }
    return -1;
}

/* ==================== 命令处理 ==================== */
/* 构建当前支持规则类型列表（含动态模块类型），供 PING/LIST/STATUS 返回。
   lang：前端请求的语言（如 "en"），为空默认 "zh"；
   每个类型回传匹配语言的 desc（找不到回退 zh），并附 desc_map 全语言映射
   与 argc_min/argc_max 参数约束，供前端动态渲染任意模块的规则输入框 */
static json_object *build_rule_types_json(const char *lang) {
    if (!lang || !*lang) lang = "zh";
    json_object *arr = json_object_new_array();
    for (int i = 0; i < g_rule_type_count; i++) {
        json_object *t = json_object_new_object();
        json_object_object_add(t, "type", json_object_new_string(g_rule_types[i].name));
        const char *fmt_s = "path";
        if (g_rule_types[i].fmt == RFT_PAIR) fmt_s = "pair";
        else if (g_rule_types[i].fmt == RFT_SWITCH) fmt_s = "switch";
        else if (g_rule_types[i].fmt == RFT_TOKENS) fmt_s = "tokens";
        json_object_object_add(t, "format", json_object_new_string(fmt_s));
        json_object_object_add(t, "builtin", json_object_new_boolean(g_rule_types[i].builtin));
        json_object_object_add(t, "module", json_object_new_string(g_rule_types[i].module));
        json_object_object_add(t, "global_only", json_object_new_boolean(g_rule_types[i].global_only));
        json_object_object_add(t, "argc_min", json_object_new_int(g_rule_types[i].argc_min));
        json_object_object_add(t, "argc_max", json_object_new_int(g_rule_types[i].argc_max));
        /* 多语言描述：按请求语言选取（回退 zh），并附全语言 desc_map */
        const char *match = nullptr;
        for (int d = 0; d < g_rule_types[i].desc_count; d++) {
            if (strcasecmp(g_rule_types[i].descs[d].lang, lang) == 0)
                match = g_rule_types[i].descs[d].text;
        }
        if (!match) {
            for (int d = 0; d < g_rule_types[i].desc_count; d++) {
                if (strcasecmp(g_rule_types[i].descs[d].lang, "zh") == 0)
                    match = g_rule_types[i].descs[d].text;
            }
        }
        if (!match && g_rule_types[i].desc_count > 0) match = g_rule_types[i].descs[0].text;
        json_object_object_add(t, "desc", json_object_new_string(match ? match : ""));
        if (g_rule_types[i].desc_count > 0) {
            json_object *dmap = json_object_new_object();
            for (int d = 0; d < g_rule_types[i].desc_count; d++)
                json_object_object_add(dmap, g_rule_types[i].descs[d].lang,
                                       json_object_new_string(g_rule_types[i].descs[d].text));
            json_object_object_add(t, "desc_map", dmap);
        }
        json_object_array_add(arr, t);
    }
    return arr;
}

static void handle_ping(int fd, json_object *req) {
    (void)req;
    json_object *data = json_object_new_object();
    json_object_object_add(data, "pong", json_object_new_boolean(true));
    json_object_object_add(data, "version", json_object_new_string(RULE_VERSION));
    json_object_object_add(data, "config_dir", json_object_new_string(g_config_dir));
    json_object_object_add(data, "socket", json_object_new_string(g_socket_name));
    const char *lang = json_object_get_string(json_object_object_get(req, "lang"));
    json_object_object_add(data, "rule_types", build_rule_types_json(lang));
    reply_ok(fd, "PING", data);
}

/* UPTIME：查询本守护进程运行时长（CLOCK_MONOTONIC 单调时钟，不受系统
   改时间影响）。data：uptime_seconds（整数秒）、uptime（人类可读时长）、
   started_at（启动墙钟时间戳，epoch 秒） */
static void handle_uptime(int fd, json_object *req) {
    (void)req;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long long secs = (long long)(now.tv_sec - g_start_mono.tv_sec);
    if (secs < 0) secs = 0;   /* 时钟异常兜底 */
    json_object *data = json_object_new_object();
    json_object_object_add(data, "uptime_seconds", json_object_new_int64(secs));
    char human[64];
    long long d = secs / 86400, h = (secs % 86400) / 3600,
              m = (secs % 3600) / 60, s = secs % 60;
    if (d > 0)      snprintf(human, sizeof human, "%lld天%lld小时%lld分%lld秒", d, h, m, s);
    else if (h > 0) snprintf(human, sizeof human, "%lld小时%lld分%lld秒", h, m, s);
    else            snprintf(human, sizeof human, "%lld分%lld秒", m, s);
    json_object_object_add(data, "uptime", json_object_new_string(human));
    json_object_object_add(data, "started_at", json_object_new_int64((int64_t)g_start_wall));
    reply_ok(fd, "UPTIME", data);
}

static void handle_list(int fd, json_object *req) {
    (void)req;
    json_object *data = json_object_new_object();
    const char *lang = json_object_get_string(json_object_object_get(req, "lang"));
    json_object_object_add(data, "rule_types", build_rule_types_json(lang));
    json_object_object_add(data, "global", build_global_json());
    json_object_object_add(data, "apps", build_apps_json());
    reply_ok(fd, "LIST", data);
}

static void handle_get(int fd, json_object *req) {
    const char *pkg = json_object_get_string(json_object_object_get(req, "pkg"));
    int uid = json_object_get_int(json_object_object_get(req, "uid"));
    if (uid < 0) uid = 0;
    /* GET 不带 pkg 时：返回全局 + 指定用户（uid 参数）的全部应用；
       前端可用 GET {"uid":10} 只取某个用户空间的配置 */
    if (!pkg || strcasecmp(pkg, "GLOBAL") == 0) {
        json_object *data = json_object_new_object();
        json_object_object_add(data, "global", build_global_json());
        if (pkg && strcasecmp(pkg, "GLOBAL") != 0) {
            /* 形如 GET {"pkg":"GLOBAL","uid":10}：全局 + 该用户应用 */
            json_object_object_add(data, "apps", build_apps_json_filtered(uid));
        } else if (json_object_object_get(req, "uid") != NULL) {
            /* GET {"uid":10}：只返回该用户应用（含全局快照） */
            json_object_object_add(data, "apps", build_apps_json_filtered(uid));
        }
        reply_ok(fd, "GET", data);
        return;
    }
    if (!valid_uid(uid)) {
        reply_error(fd, "GET", "非法 uid: %d", uid);
        return;
    }
    if (!valid_pkg(pkg)) {
        reply_error(fd, "GET", "非法包名: %s", pkg ? pkg : "(null)");
        return;
    }
    json_object *data = json_object_new_object();
    json_object_object_add(data, "app", build_app_json(pkg, uid));
    reply_ok(fd, "GET", data);
}

/* USERS：列出全部已配置用户（App-rules 与 App-rules-<uid> 目录），
   前端可据此遍历多用户空间 */
static void handle_users(int fd, json_object *req) {
    (void)req;
    json_object *data = json_object_new_object();
    json_object_object_add(data, "users", build_users_json());
    reply_ok(fd, "USERS", data);
}

/* 依据类型构建规则行文本；返回 0 成功，-1 参数错误 */
static int build_rule_line(RuleType t, const char *value, char *line, size_t sz) {
    if (t < 0 || t >= g_rule_type_count) return -1;
    const char *name = rule_type_name(t);
    RuleFmt fmt = g_rule_types[t].fmt;
    if (fmt == RFT_SWITCH) {
        if (!value || (strcasecmp(value, "ON") != 0 && strcasecmp(value, "OFF") != 0))
            return -1;
        snprintf(line, sz, "%s %s\n", name, value);
        return 0;
    }
    if (fmt == RFT_PAIR || fmt == RFT_TOKENS) {
        /* pair/tokens：value 用 | 分隔多 token，写入时以空格拼行
           （REDIRECT /a|/b → "REDIRECT /a /b"；FTP /云盘|云盘 → "FTP /云盘 云盘"）。
           参数数量按类型声明约束（argc=N / argc=N:M，见 rule_types_parse_line）：
           pair 默认恰好 2 个 token，tokens 默认 2 个以上任意数量；
           模块可在 .rules 中自定义（如 argc=3 / argc=2:4）。 */
        if (!value || !*value) return -1;
        char out[MAX_LINE];
        size_t olen = 0;
        const char *p = value;
        bool first = true;
        int tok_count = 0;
        while (*p) {
            char tok[MAX_LINE];
            size_t tlen = 0;
            while (*p && *p != '|' && tlen < sizeof(tok) - 1)
                tok[tlen++] = *p++;
            tok[tlen] = '\0';
            if (tlen == 0) return -1;   /* 空 token（如 /a||/b）非法 */
            tok_count++;
            /* 单次 snprintf 写入并检测溢出（返回应写入长度，>= 剩余空间即截断） */
            int w = snprintf(out + olen, sizeof(out) - olen, "%s%s", first ? "" : " ", tok);
            if (w < 0 || (size_t)w >= sizeof(out) - olen) return -1;
            olen += (size_t)w;
            first = false;
            if (*p == '|') p++;
        }
        if (first) return -1;
        /* 按类型声明的 argc 约束校验（-1 表示不限制对应边界） */
        if (g_rule_types[t].argc_min >= 0 && tok_count < g_rule_types[t].argc_min) return -1;
        if (g_rule_types[t].argc_max >= 0 && tok_count > g_rule_types[t].argc_max) return -1;
        snprintf(line, sz, "%s %s\n", name, out);
        return 0;
    }
    /* RFT_PATH：单值路径 */
    if (!value || !*value) return -1;
    snprintf(line, sz, "%s %s\n", name, value);
    return 0;
}

/* ADD：动态新增规则。
   scope=GLOBAL 时写入 injector.conf 的 [GLOBAL] 段；
   scope=APP 时写入 App-rules/<pkg>.conf（uid>0 时 App-rules-<uid>/）。
   type=INJECT_ENABLE 仅 APP 有效，改写 injector.conf 的 [pkg:uid] ON/OFF 头。 */
static void handle_add(int fd, json_object *req) {
    const char *pkg = json_object_get_string(json_object_object_get(req, "pkg"));
    const char *type_s = json_object_get_string(json_object_object_get(req, "type"));
    const char *value = json_object_get_string(json_object_object_get(req, "value"));
    int uid = json_object_get_int(json_object_object_get(req, "uid"));
    if (uid < 0) uid = 0;

    if (!pkg || !type_s) {
        reply_error(fd, "ADD", "缺少参数: pkg/type");
        return;
    }
    if (!valid_uid(uid)) {
        reply_error(fd, "ADD", "非法 uid: %d", uid);
        return;
    }
    if (value && !valid_value(value)) {
        reply_error(fd, "ADD", "规则值包含非法字符或过长");
        return;
    }
    bool is_global = (strcasecmp(pkg, "GLOBAL") == 0);

    /* INJECT_ENABLE：应用规则启用/停用总开关。
       通过重命名 App-rules/<pkg>.conf ↔ <pkg>.conf.disabled 实现：
       OFF（停用）→ 加 .disabled 后缀，解析器跳过该文件（规则不生效）；
       ON（启用） → 去掉 .disabled 后缀，规则重新生效。
       全程不接触 injector.conf（其 [pkg:uid] 段头仅控制注入挂载）。 */
    if (strcasecmp(type_s, "INJECT_ENABLE") == 0) {
        if (is_global) {
            reply_error(fd, "ADD", "INJECT_ENABLE 仅适用于应用作用域");
            return;
        }
        if (!valid_pkg(pkg)) {
            reply_error(fd, "ADD", "非法包名: %s", pkg);
            return;
        }
        bool on = (value && strcasecmp(value, "ON") == 0);
        char dir[PATH_MAX], path[PATH_MAX], dis_path[PATH_MAX];
        app_rule_dir(dir, sizeof(dir), uid);
        app_rule_path(path, sizeof(path), pkg, uid);
        snprintf(dis_path, sizeof(dis_path), "%s.disabled", path);
        bool active_exists = (access(path, F_OK) == 0);
        bool disabled_exists = (access(dis_path, F_OK) == 0);
        if (on) {
            if (disabled_exists && !active_exists) {
                if (rename(dis_path, path) != 0) {
                    reply_error(fd, "ADD", "启用应用规则失败: %s", strerror(errno));
                    return;
                }
            } else if (!active_exists) {
                /* 无任何规则文件：创建空配置文件（应用已配置但无规则） */
                if (mkdir_p(dir) != 0) {
                    reply_error(fd, "ADD", "无法创建目录 %s: %s", dir, strerror(errno));
                    return;
                }
                FILE *fp = fopen(path, "w");
                if (!fp) {
                    reply_error(fd, "ADD", "创建 %s 失败: %s", path, strerror(errno));
                    return;
                }
                fclose(fp);
            }
        } else {
            if (active_exists) {
                if (mkdir_p(dir) != 0) {
                    reply_error(fd, "ADD", "无法创建目录 %s: %s", dir, strerror(errno));
                    return;
                }
                if (rename(path, dis_path) != 0) {
                    reply_error(fd, "ADD", "停用应用规则失败: %s", strerror(errno));
                    return;
                }
            } else if (!disabled_exists) {
                reply_error(fd, "ADD", "应用 %s 无规则文件可停用", pkg);
                return;
            }
        }
        json_object *data = json_object_new_object();
        json_object_object_add(data, "dir", json_object_new_string(dir));
        json_object_object_add(data, "file", json_object_new_string(on ? path : dis_path));
        json_object_object_add(data, "enabled", json_object_new_boolean(on));
        reply_ok(fd, "ADD", data);
        return;
    }

    /* 普通规则 / 开关 */
    RuleType t = rule_type_of(type_s);
    if (t == RT_UNKNOWN) {
        reply_error(fd, "ADD", "未知规则类型: %s", type_s);
        return;
    }
    /* 全局专属类型（GLOBAL_INJECT/SKIP_SYSTEM_APPS）：仅 [GLOBAL] 段可用 */
    if (!is_global && g_rule_types[t].global_only) {
        reply_error(fd, "ADD", "规则类型 %s 仅可在全局规则中使用，不能配置到应用 %s",
                    type_s, pkg);
        return;
    }
    char line[MAX_LINE];
    if (build_rule_line(t, value, line, sizeof(line)) != 0) {
        reply_error(fd, "ADD", "规则值不合法: %s", value ? value : "(null)");
        return;
    }

    if (is_global) {
        /* GLOBAL：写入 injector.conf 的 [GLOBAL] 段（开关替换/规则去重插入） */
        char conf[PATH_MAX];
        main_conf_path(conf, sizeof(conf));
        int count = 0, cap = 0;
        char **lines = read_file_lines(conf, &count, &cap);
        if (!lines) {
            if (mkdir_p(g_config_dir) != 0) {
                reply_error(fd, "ADD", "无法创建配置目录 %s: %s", g_config_dir, strerror(errno));
                return;
            }
            if (append_line(&lines, &cap, 0, "[GLOBAL]\n") < 0 ||
                append_line(&lines, &cap, 1, line) < 0) {
                free_file_lines(lines, count);
                reply_error(fd, "ADD", "内存不足");
                return;
            }
            count = 2;
            if (!write_file_lines_atomic(conf, lines, count)) {
                reply_error(fd, "ADD", "写入 %s 失败: %s", conf, strerror(errno));
                free_file_lines(lines, count);
                return;
            }
            free_file_lines(lines, count);
            json_object *data = json_object_new_object();
            json_object_object_add(data, "file", json_object_new_string(conf));
            json_object_object_add(data, "line", json_object_new_string(line));
            reply_ok(fd, "ADD", data);
            return;
        }
        int hdr = find_section_header(lines, count, "GLOBAL");
        bool changed = false;
        if (is_switch_type(t)) {
            const char *tname = rule_type_name(t);
            if (hdr >= 0) {
                int old = find_switch_in_section(lines, count, hdr, tname);
                if (old >= 0) {
                    if (strcmp(lines[old], line) != 0) {
                        free(lines[old]);
                        lines[old] = strdup(line);
                        if (!lines[old]) {
                            free_file_lines(lines, count);
                            reply_error(fd, "ADD", "内存不足");
                            return;
                        }
                        changed = true;
                    }
                } else {
                    int nc = insert_line_at(&lines, &cap, count, hdr + 1, line);
                    if (nc < 0) {
                        free_file_lines(lines, count);
                        reply_error(fd, "ADD", "内存不足");
                        return;
                    }
                    count = nc;
                    changed = true;
                }
            } else {
                if (append_line(&lines, &cap, count, "[GLOBAL]\n") < 0 ||
                    append_line(&lines, &cap, count + 1, line) < 0) {
                    free_file_lines(lines, count);
                    reply_error(fd, "ADD", "内存不足");
                    return;
                }
                count += 2;
                changed = true;
            }
        } else {
            /* 规则行：去重后插入 [GLOBAL] 段头之后 */
            bool dup = false;
            for (int i = 0; i < count; i++) {
                if (strcmp(lines[i], line) == 0) { dup = true; break; }
            }
            if (!dup) {
                int pos = hdr >= 0 ? hdr + 1 : count;
                if (hdr < 0) {
                    if (append_line(&lines, &cap, count, "[GLOBAL]\n") < 0) {
                        free_file_lines(lines, count);
                        reply_error(fd, "ADD", "内存不足");
                        return;
                    }
                    count++;
                    pos = count;
                }
                int nc = insert_line_at(&lines, &cap, count, pos, line);
                if (nc < 0) {
                    free_file_lines(lines, count);
                    reply_error(fd, "ADD", "内存不足");
                    return;
                }
                count = nc;
                changed = true;
            }
        }
        if (changed) {
            if (!write_file_lines_atomic(conf, lines, count)) {
                reply_error(fd, "ADD", "写入 %s 失败: %s", conf, strerror(errno));
                free_file_lines(lines, count);
                return;
            }
        }
        free_file_lines(lines, count);
        json_object *data = json_object_new_object();
        json_object_object_add(data, "file", json_object_new_string(conf));
        json_object_object_add(data, "line", json_object_new_string(line));
        json_object_object_add(data, "changed", json_object_new_boolean(changed));
        reply_ok(fd, "ADD", data);
        return;
    }

    /* APP 作用域：追加到 App-rules/<pkg>.conf（uid>0 时 App-rules-<uid>/）。
       停用状态下路由到 <pkg>.conf.disabled——保持停用，不新建残缺 .conf 丢规则 */
    if (!valid_pkg(pkg)) {
        reply_error(fd, "ADD", "非法包名: %s", pkg);
        return;
    }
    char dir[PATH_MAX], path[PATH_MAX];
    app_rule_dir(dir, sizeof(dir), uid);
    resolve_app_rule_active_path(pkg, uid, path, sizeof(path));
    if (mkdir_p(dir) != 0) {
        reply_error(fd, "ADD", "无法创建目录 %s: %s", dir, strerror(errno));
        return;
    }
    {
        int count = 0, cap = 0;
        char **lines = read_file_lines(path, &count, &cap);
        bool changed = false;
        if (is_switch_type(t)) {
            /* 开关类型：替换文件中已存在的同类型开关行（保持唯一，后写覆盖），
               无则追加——与 GLOBAL 段语义一致，避免 MONITOR ON/OFF 并存 */
            int old = -1;
            for (int i = 0; i < count; i++) {
                if (classify_line(lines[i]) == t) { old = i; break; }
            }
            if (old >= 0) {
                if (strcmp(lines[old], line) != 0) {
                    free(lines[old]);
                    lines[old] = strdup(line);
                    if (!lines[old]) {
                        free_file_lines(lines, count);
                        reply_error(fd, "ADD", "内存不足");
                        return;
                    }
                    changed = true;
                }
            } else {
                int nc = append_line(&lines, &cap, count, line);
                if (nc < 0) {
                    free_file_lines(lines, count);
                    reply_error(fd, "ADD", "内存不足");
                    return;
                }
                count = nc;
                changed = true;
            }
        } else {
            /* 规则行：去重后追加 */
            bool dup = false;
            if (lines) {
                for (int i = 0; i < count; i++) {
                    if (strcmp(lines[i], line) == 0) { dup = true; break; }
                }
            }
            if (!dup) {
                int nc = append_line(&lines, &cap, count, line);
                if (nc < 0) {
                    free_file_lines(lines, count);
                    reply_error(fd, "ADD", "内存不足");
                    return;
                }
                count = nc;
                changed = true;
            }
        }
        if (changed) {
            if (!write_file_lines_atomic(path, lines, count)) {
                reply_error(fd, "ADD", "写入 %s 失败: %s", path, strerror(errno));
                free_file_lines(lines, count);
                return;
            }
        }
        free_file_lines(lines, count);
        json_object *data = json_object_new_object();
        json_object_object_add(data, "file", json_object_new_string(path));
        json_object_object_add(data, "line", json_object_new_string(line));
        json_object_object_add(data, "changed", json_object_new_boolean(changed));
        reply_ok(fd, "ADD", data);
    }
}

/* 定位规则所在文件路径；scope=GLOBAL 返回主配置文件，否则返回应用规则**当前生效**文件
   （停用状态返回 .conf.disabled，保证后续操作写入同一文件、不丢规则） */
static void resolve_rule_path(const char *pkg, int uid, bool *is_global, char *out, size_t sz) {
    if (!pkg || strcasecmp(pkg, "GLOBAL") == 0) {
        *is_global = true;
        main_conf_path(out, sz);
    } else {
        *is_global = false;
        resolve_app_rule_active_path(pkg, uid, out, sz);
    }
}

/* REMOVE：按 (类型, 索引) 删除规则行（索引与 LIST 输出一致，含已停用行） */
static void handle_remove(int fd, json_object *req) {
    const char *pkg = json_object_get_string(json_object_object_get(req, "pkg"));
    const char *type_s = json_object_get_string(json_object_object_get(req, "type"));
    int index = json_object_get_int(json_object_object_get(req, "index"));
    int uid = json_object_get_int(json_object_object_get(req, "uid"));
    if (uid < 0) uid = 0;
    if (!pkg || !type_s) {
        reply_error(fd, "REMOVE", "缺少参数: pkg/type/index");
        return;
    }
    if (!valid_uid(uid)) {
        reply_error(fd, "REMOVE", "非法 uid: %d", uid);
        return;
    }
    RuleType t = rule_type_of(type_s);
    if (t == RT_UNKNOWN) {
        reply_error(fd, "REMOVE", "未知规则类型: %s", type_s);
        return;
    }
    if (index < 0) {
        reply_error(fd, "REMOVE", "索引必须 >= 0");
        return;
    }
    if (!is_switch_type(t) && strcmp(pkg, "GLOBAL") != 0 && !valid_pkg(pkg)) {
        reply_error(fd, "REMOVE", "非法包名: %s", pkg);
        return;
    }
    bool is_global = false;
    char path[PATH_MAX];
    resolve_rule_path(pkg, uid, &is_global, path, sizeof(path));
    int count = 0, cap = 0;
    char **lines = read_file_lines(path, &count, &cap);
    if (!lines) {
        reply_error(fd, "REMOVE", "无法打开规则文件 %s", path);
        return;
    }
    int found = find_rule_line(lines, count, t, index);
    if (found < 0) {
        free_file_lines(lines, count);
        reply_error(fd, "REMOVE", "未找到 %s 类型的第 %d 条规则", type_s, index);
        return;
    }
    char removed[MAX_LINE];
    snprintf(removed, sizeof(removed), "%s", lines[found]);
    remove_line_at(lines, &count, found);
    if (!write_file_lines_atomic(path, lines, count)) {
        reply_error(fd, "REMOVE", "写入 %s 失败: %s", path, strerror(errno));
        free_file_lines(lines, count);
        return;
    }
    free_file_lines(lines, count);
    json_object *data = json_object_new_object();
    json_object_object_add(data, "file", json_object_new_string(path));
    json_object_object_add(data, "removed", json_object_new_string(removed));
    reply_ok(fd, "REMOVE", data);
}

/* ENABLE / DISABLE：切换规则行的 # 注释状态（停用行被解析器跳过） */
static void handle_toggle(int fd, json_object *req, bool enable) {
    const char *cmd = enable ? "ENABLE" : "DISABLE";
    const char *pkg = json_object_get_string(json_object_object_get(req, "pkg"));
    const char *type_s = json_object_get_string(json_object_object_get(req, "type"));
    int index = json_object_get_int(json_object_object_get(req, "index"));
    int uid = json_object_get_int(json_object_object_get(req, "uid"));
    if (uid < 0) uid = 0;
    if (!pkg || !type_s) {
        reply_error(fd, cmd, "缺少参数: pkg/type/index");
        return;
    }
    if (!valid_uid(uid)) {
        reply_error(fd, cmd, "非法 uid: %d", uid);
        return;
    }
    RuleType t = rule_type_of(type_s);
    if (t == RT_UNKNOWN) {
        reply_error(fd, cmd, "未知规则类型: %s", type_s);
        return;
    }
    if (is_switch_type(t)) {
        reply_error(fd, cmd, "开关类型 %s 请使用 SET 命令设置 ON/OFF", type_s);
        return;
    }
    if (index < 0) {
        reply_error(fd, cmd, "索引必须 >= 0");
        return;
    }
    if (strcmp(pkg, "GLOBAL") != 0 && !valid_pkg(pkg)) {
        reply_error(fd, cmd, "非法包名: %s", pkg);
        return;
    }
    bool is_global = false;
    char path[PATH_MAX];
    resolve_rule_path(pkg, uid, &is_global, path, sizeof(path));
    int count = 0, cap = 0;
    char **lines = read_file_lines(path, &count, &cap);
    if (!lines) {
        reply_error(fd, cmd, "无法打开规则文件 %s", path);
        return;
    }
    int found = find_rule_line(lines, count, t, index);
    if (found < 0) {
        free_file_lines(lines, count);
        reply_error(fd, cmd, "未找到 %s 类型的第 %d 条规则", type_s, index);
        return;
    }
    char *p = lines[found];
    while (*p == ' ' || *p == '\t') p++;
    bool already = (enable ? !line_is_disabled(lines[found]) : line_is_disabled(lines[found]));
    if (!already) {
        if (enable) {
            /* 去掉行首 #（及紧随其后的空白）——向前移动，长度缩小，安全 */
            if (*p == '#') {
                char *q = p + 1;
                while (*q == ' ' || *q == '\t') q++;
                memmove(p, q, strlen(q) + 1);
            }
        } else {
            /* 行首插入 #：行变长，必须重建缓冲，禁止原地 memmove 越界
               （strdup 分配 len+1 字节，插入后需 len+2 字节） */
            size_t prefix = (size_t)(p - lines[found]);
            size_t len = strlen(lines[found]);
            if (len + 2 >= MAX_LINE) {
                free_file_lines(lines, count);
                reply_error(fd, cmd, "规则行过长，无法停用");
                return;
            }
            char *nl = malloc(len + 2);
            if (!nl) {
                free_file_lines(lines, count);
                reply_error(fd, cmd, "内存不足");
                return;
            }
            memcpy(nl, lines[found], prefix);
            nl[prefix] = '#';
            strcpy(nl + prefix + 1, p);
            free(lines[found]);
            lines[found] = nl;
        }
        if (!write_file_lines_atomic(path, lines, count)) {
            reply_error(fd, cmd, "写入 %s 失败: %s", path, strerror(errno));
            free_file_lines(lines, count);
            return;
        }
    }
    char updated[MAX_LINE];
    snprintf(updated, sizeof(updated), "%s", lines[found]);
    free_file_lines(lines, count);
    json_object *data = json_object_new_object();
    json_object_object_add(data, "file", json_object_new_string(path));
    json_object_object_add(data, "line", json_object_new_string(updated));
    json_object_object_add(data, "enabled", json_object_new_boolean(enable));
    json_object_object_add(data, "changed", json_object_new_boolean(!already));
    reply_ok(fd, cmd, data);
}

/* SET：设置开关（MONITOR/SANDBOX/GLOBAL_INJECT）或应用注入开关，
   复用 ADD 的写入逻辑 */
static void handle_set(int fd, json_object *req) {
    handle_add(fd, req);
}

/* 向 injector 发送信号（SIGHUP 重载 / SIGTERM 停止） */
static void signal_injector(int fd, const char *cmd, int sig) {
    char path[PATH_MAX];
    injector_pid_path(path, sizeof(path));
    FILE *fp = fopen(path, "r");
    if (!fp) {
        reply_error(fd, cmd, "无法读取注入器 PID 文件 %s: %s", path, strerror(errno));
        return;
    }
    int pid = -1;
    if (fscanf(fp, "%d", &pid) != 1) pid = -1;
    fclose(fp);
    if (pid <= 0) {
        reply_error(fd, cmd, "PID 文件 %s 内容无效", path);
        return;
    }
    if (kill(pid, sig) != 0) {
        reply_error(fd, cmd, "向 PID %d 发送信号 %d 失败: %s", pid, sig, strerror(errno));
        return;
    }
    json_object *data = json_object_new_object();
    json_object_object_add(data, "pid", json_object_new_int(pid));
    json_object_object_add(data, "signal", json_object_new_int(sig));
    json_object_object_add(data, "action", json_object_new_string(sig == SIGHUP ? "reload" : "stop"));
    reply_ok(fd, cmd, data);
}

/* ==================== 服务状态查询（SERVICE API） ==================== */

static bool proc_alive(int pid) {
    if (pid <= 0) return false;
    /* 僵尸进程（kill(pid,0) 仍成功但已退出）：读 /proc/<pid>/stat 的 state
       字段（pid (comm) state ...，state 在最后一个 ')' 之后）判别 */
    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    FILE *fp = fopen(stat_path, "r");
    if (fp) {
        char buf[256] = {0};
        if (fgets(buf, sizeof(buf), fp)) {
            char *rp = strrchr(buf, ')');
            if (rp && rp[1] == ' ' && (rp[2] == 'Z' || rp[2] == 'z')) {
                fclose(fp);
                return false;   /* 僵尸视为已退出 */
            }
        }
        fclose(fp);
    }
    return (kill(pid, 0) == 0 || errno == EPERM);
}

/* 扫描 /proc/<pid>/comm 匹配进程名，返回第一个**存活**匹配 pid（跳过僵尸）；
   未找到返回 0 */
static int find_proc_pid(const char *name) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *de;
    int found = 0;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        int pid = atoi(de->d_name);
        if (pid <= 0 || pid == (int)getpid()) continue;   /* 排除自身 */
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        FILE *fp = fopen(comm_path, "r");
        if (!fp) continue;
        char buf[64] = {0};
        if (fgets(buf, sizeof(buf), fp)) {
            buf[strcspn(buf, "\n")] = '\0';
            if (strcmp(buf, name) == 0) {
                fclose(fp);
                if (proc_alive(pid)) { found = pid; break; }   /* 跳过僵尸，取存活实例 */
                continue;
            }
        }
        fclose(fp);
    }
    closedir(d);
    return found;
}

/* injector PID：优先 PID 文件（精确），失效则回退 /proc 按名匹配 */
static int read_injector_pid(void) {
    char path[PATH_MAX];
    injector_pid_path(path, sizeof(path));
    FILE *fp = fopen(path, "r");
    if (fp) {
        int pid = -1;
        if (fscanf(fp, "%d", &pid) == 1 && pid > 0 && proc_alive(pid)) {
            fclose(fp);
            return pid;
        }
        fclose(fp);
    }
    return find_proc_pid("injector");
}

/* 构建单个进程状态对象 {pid, alive} */
static json_object *build_proc_json(int pid) {
    json_object *o = json_object_new_object();
    json_object_object_add(o, "pid", json_object_new_int(pid));
    json_object_object_add(o, "alive", json_object_new_boolean(proc_alive(pid)));
    return o;
}

/* SERVICE status：查询 log_monitor / injector / fuse_daemon / rule_server 状态 */
static void handle_service_status(int fd, json_object *req) {
    (void)req;
    int injector_pid = read_injector_pid();
    int fuse_pid = find_proc_pid("fuse_daemon");
    int log_pid = find_proc_pid("log_monitor");
    json_object *data = json_object_new_object();
    json_object_object_add(data, "rule_server", build_proc_json((int)getpid()));
    json_object_object_add(data, "injector", build_proc_json(injector_pid));
    json_object_object_add(data, "fuse_daemon", build_proc_json(fuse_pid));
    json_object_object_add(data, "log_monitor", build_proc_json(log_pid));
    /* 汇总：全部常驻服务就绪 = ready */
    bool ready = proc_alive(injector_pid) && proc_alive(fuse_pid) && proc_alive(log_pid);
    json_object_object_add(data, "ready", json_object_new_boolean(ready));
    reply_ok(fd, "SERVICE", data);
}

/* ==================== SERVICE 启停控制（等价 service.sh） ==================== */

/* 本进程所在目录（/proc/self/exe 解析），用于定位同目录的 injector/log_monitor/fuse_daemon */
static void self_bin_dir(char *out, size_t sz) {
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) { snprintf(out, sz, "."); return; }
    exe[n] = '\0';
    char *slash = strrchr(exe, '/');
    if (slash) *slash = '\0';
    snprintf(out, sz, "%s", exe[0] ? exe : ".");
}

/* 向 pid 发送信号并等待其退出（stop 场景）；返回 0 表示已停止/不存在。
   SIGTERM 宽限 500ms 后仍存活则升级 SIGKILL 兜底（部分守护进程 epoll 无限
   等待，SIGTERM 置位后无事件不会退出，如 log_monitor）。 */
static int stop_proc(int pid, int sig) {
    if (pid <= 0) return 0;
    if (!proc_alive(pid)) return 0;
    kill(pid, sig);
    for (int i = 0; i < 50 && proc_alive(pid); i++)
        usleep(10000);   /* 宽限 500ms */
    if (proc_alive(pid)) {
        kill(pid, SIGKILL);   /* 兜底强杀 */
        for (int i = 0; i < 50 && proc_alive(pid); i++)
            usleep(10000);
    }
    return proc_alive(pid) ? -1 : 0;
}

/* 启动一个守护进程：fork+exec（setsid 脱离会话，防 shell 退出连带 kill）。
   argv 以 NULL 结尾；返回子进程 pid，失败返回 -1 */
static int spawn_daemon(const char *path, char *const argv[]) {
    if (!path || access(path, X_OK) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        setsid();
        int nullfd = open("/dev/null", O_RDWR);
        if (nullfd >= 0) {
            dup2(nullfd, 0);
            dup2(nullfd, 1);
            dup2(nullfd, 2);
            if (nullfd > 2) close(nullfd);
        }
        execv(path, argv);
        _exit(127);
    }
    return (int)pid;
}

/* 停止全部服务：injector（SIGTERM，其自行清理 fuse_daemon）、log_monitor、fuse_daemon。
   执行层：不发送响应，统计结果写入 out_stopped / out_failed */
static void service_stop_all_exec(int *out_stopped, int *out_failed) {
    int injector_pid = read_injector_pid();
    int log_pid = find_proc_pid("log_monitor");
    int fuse_pid = find_proc_pid("fuse_daemon");
    int stopped = 0, failed = 0;
    if (injector_pid > 0 && proc_alive(injector_pid)) {
        if (stop_proc(injector_pid, SIGTERM) == 0) stopped++;
        else failed++;
    }
    if (fuse_pid > 0 && proc_alive(fuse_pid)) {
        if (stop_proc(fuse_pid, SIGTERM) == 0) stopped++;
        else failed++;
    }
    if (log_pid > 0 && proc_alive(log_pid)) {
        if (stop_proc(log_pid, SIGTERM) == 0) stopped++;
        else failed++;
    }
    if (out_stopped) *out_stopped = stopped;
    if (out_failed) *out_failed = failed;
}

static void service_stop_all(int fd, const char *cmd) {
    int stopped = 0, failed = 0;
    service_stop_all_exec(&stopped, &failed);
    json_object *data = json_object_new_object();
    json_object_object_add(data, "action", json_object_new_string("stop"));
    json_object_object_add(data, "stopped", json_object_new_int(stopped));
    json_object_object_add(data, "failed", json_object_new_int(failed));
    reply_ok(fd, cmd, data);
}

/* 启动全部服务（等价 service.sh 的拉起逻辑）：
   先清理残留进程，再按 log_monitor → injector 顺序启动（fuse_daemon 由 injector 拉取）。
   执行层：不发送响应，统计结果写入 out_started / out_failed */
static void service_start_all_exec(int *out_started, int *out_failed) {
    char bin_dir[PATH_MAX];
    self_bin_dir(bin_dir, sizeof(bin_dir));
    char log_path[PATH_MAX], inj_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/log_monitor", bin_dir);
    snprintf(inj_path, sizeof(inj_path), "%s/injector", bin_dir);

    /* 清理残留：killall -9 等价（fuse_daemon 残留由 stop 兜底） */
    int old_inj = read_injector_pid();
    int old_fuse = find_proc_pid("fuse_daemon");
    int old_log = find_proc_pid("log_monitor");
    if (old_inj > 0) kill(old_inj, SIGKILL);
    if (old_fuse > 0) kill(old_fuse, SIGKILL);
    if (old_log > 0) kill(old_log, SIGKILL);
    usleep(50000);

    int started = 0, failed = 0;
    /* log_monitor：先起（日志服务） */
    if (access(log_path, X_OK) == 0) {
        char *argv_log[] = { "log_monitor", NULL };
        if (spawn_daemon(log_path, argv_log) > 0) started++;
        else failed++;
    }
    /* injector：主控（--passive 与 service.sh 一致），其内部拉起 fuse_daemon */
    if (access(inj_path, X_OK) == 0) {
        char *argv_inj[] = { "injector", "--passive", NULL };
        if (spawn_daemon(inj_path, argv_inj) > 0) started++;
        else failed++;
    }
    if (out_started) *out_started = started;
    if (out_failed) *out_failed = failed;
}

static void service_start_all(int fd, const char *cmd) {
    int started = 0, failed = 0;
    service_start_all_exec(&started, &failed);
    char bin_dir[PATH_MAX];
    self_bin_dir(bin_dir, sizeof(bin_dir));
    json_object *data = json_object_new_object();
    json_object_object_add(data, "action", json_object_new_string("start"));
    json_object_object_add(data, "started", json_object_new_int(started));
    json_object_object_add(data, "failed", json_object_new_int(failed));
    json_object_object_add(data, "bin_dir", json_object_new_string(bin_dir));
    reply_ok(fd, cmd, data);
}

/* SERVICE 命令分发：status / start / stop / restart */
static void handle_service(int fd, json_object *req) {
    const char *action = json_object_get_string(json_object_object_get(req, "action"));
    if (!action || strcasecmp(action, "status") == 0) {
        handle_service_status(fd, req);
        return;
    }
    if (strcasecmp(action, "start") == 0) {
        service_start_all(fd, "SERVICE");
        return;
    }
    if (strcasecmp(action, "stop") == 0) {
        service_stop_all(fd, "SERVICE");
        return;
    }
    if (strcasecmp(action, "restart") == 0) {
        /* restart = stop + start（同一响应内完成） */
        int stopped = 0, failed_stop = 0, started = 0, failed_start = 0;
        service_stop_all_exec(&stopped, &failed_stop);
        service_start_all_exec(&started, &failed_start);
        json_object *data = json_object_new_object();
        json_object_object_add(data, "action", json_object_new_string("restart"));
        json_object_object_add(data, "stopped", json_object_new_int(stopped));
        json_object_object_add(data, "started", json_object_new_int(started));
        json_object_object_add(data, "failed", json_object_new_int(failed_stop + failed_start));
        reply_ok(fd, "SERVICE", data);
        return;
    }
    reply_error(fd, "SERVICE", "未知 action: %s（支持 status/start/stop/restart）", action);
}

static void handle_reload(int fd, json_object *req) {
    (void)req;
    signal_injector(fd, "RELOAD", SIGHUP);
}

static void handle_stop(int fd, json_object *req) {
    (void)req;
    signal_injector(fd, "STOP", SIGTERM);
}

static void handle_status(int fd, json_object *req) {
    (void)req;
    int injector_pid = -1;
    bool injector_alive = false;
    char path[PATH_MAX];
    injector_pid_path(path, sizeof(path));
    FILE *fp = fopen(path, "r");
    if (fp) {
        if (fscanf(fp, "%d", &injector_pid) == 1 && injector_pid > 0) {
            injector_alive = (kill(injector_pid, 0) == 0 || errno == EPERM);
        }
        fclose(fp);
    }
    json_object *data = json_object_new_object();
    json_object_object_add(data, "version", json_object_new_string(RULE_VERSION));
    json_object_object_add(data, "config_dir", json_object_new_string(g_config_dir));
    json_object_object_add(data, "socket", json_object_new_string(g_socket_name));
    json_object *inj = json_object_new_object();
    json_object_object_add(inj, "pid", json_object_new_int(injector_pid));
    json_object_object_add(inj, "alive", json_object_new_boolean(injector_alive));
    json_object_object_add(data, "injector", inj);
    json_object_object_add(data, "global", build_global_json());
    reply_ok(fd, "STATUS", data);
}

static void handle_quit(int fd, json_object *req) {
    (void)req;
    g_should_exit = 1;
    reply_ok(fd, "QUIT", NULL);
}

/* ==================== 命令分发 ==================== */
static void dispatch(int fd, json_object *req) {
    const char *cmd = json_object_get_string(json_object_object_get(req, "cmd"));
    if (!cmd) {
        reply_error(fd, "?", "缺少 cmd 字段");
        return;
    }
    /* 每次命令前刷新规则类型表：模块 .rules 增删即动态追加/回收类型（热更新） */
    rule_types_refresh();
    if (strcasecmp(cmd, "PING") == 0)             handle_ping(fd, req);
    else if (strcasecmp(cmd, "UPTIME") == 0)      handle_uptime(fd, req);
    else if (strcasecmp(cmd, "LIST") == 0)        handle_list(fd, req);
    else if (strcasecmp(cmd, "USERS") == 0)       handle_users(fd, req);
    else if (strcasecmp(cmd, "GET") == 0)         handle_get(fd, req);
    else if (strcasecmp(cmd, "ADD") == 0)         handle_add(fd, req);
    else if (strcasecmp(cmd, "REMOVE") == 0)      handle_remove(fd, req);
    else if (strcasecmp(cmd, "ENABLE") == 0)      handle_toggle(fd, req, true);
    else if (strcasecmp(cmd, "DISABLE") == 0)     handle_toggle(fd, req, false);
    else if (strcasecmp(cmd, "SET") == 0)         handle_set(fd, req);
    else if (strcasecmp(cmd, "RELOAD") == 0)      handle_reload(fd, req);
    else if (strcasecmp(cmd, "STOP") == 0)        handle_stop(fd, req);
    else if (strcasecmp(cmd, "SERVICE") == 0)     handle_service(fd, req);
    else if (strcasecmp(cmd, "STATUS") == 0)      handle_status(fd, req);
    else if (strcasecmp(cmd, "QUIT") == 0)        handle_quit(fd, req);
    else reply_error(fd, cmd, "未知命令: %s", cmd);
}

/* ==================== 服务端 ==================== */
static void handle_client(int client_fd) {
    /* 500ms 读写超时，防止异常客户端挂起 */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* 循环读取完整请求行（至换行 / EOF / 缓冲上限），防止单次 read 截断；
       请求超过 MAX_REQ_LEN 仍未结束 → 明确拒绝，不截断后误解析 */
    char buf[MAX_REQ_LEN + 1] = {0};
    size_t total = 0;
    bool too_long = false;
    while (total < MAX_REQ_LEN) {
        ssize_t n = read(client_fd, buf + total, MAX_REQ_LEN - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;   /* 超时 / 错误 */
        }
        if (n == 0) break;   /* EOF（客户端 shutdown 写端） */
        total += (size_t)n;
        if (memchr(buf + total - (size_t)n, '\n', (size_t)n) != NULL)
            break;   /* 已含行尾 */
    }
    if (total == 0) {
        close(client_fd);
        return;
    }
    /* 缓冲已满仍无行尾：请求超长，拒绝（防止截断出残缺 JSON） */
    if (total >= MAX_REQ_LEN && memchr(buf, '\n', total) == NULL) {
        too_long = true;
    }
    /* 去掉尾部换行 */
    while (total > 0 && (buf[total - 1] == '\n' || buf[total - 1] == '\r')) buf[--total] = '\0';
    if (too_long) {
        reply_error(client_fd, "?", "请求超过 %d 字节上限", MAX_REQ_LEN);
        close(client_fd);
        return;
    }
    json_object *req = json_tokener_parse(buf);
    if (!req || !json_object_is_type(req, json_type_object)) {
        if (req) json_object_put(req);
        reply_error(client_fd, "?", "请求必须是 JSON 对象: %.80s", buf);
        close(client_fd);
        return;
    }
    dispatch(client_fd, req);
    json_object_put(req);
    close(client_fd);
}

static void sig_handler(int sig) {
    (void)sig;
    g_should_exit = 1;
}

static int run_server(void) {
    /* 记录启动时刻：UPTIME 查询基准（单调时钟，不受系统改时间影响） */
    clock_gettime(CLOCK_MONOTONIC, &g_start_mono);
    g_start_wall = time(NULL);

    struct sigaction sa = { .sa_handler = sig_handler };
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        fprintf(stderr, "[rule_server] 创建 socket 失败: %s\n", strerror(errno));
        return 1;
    }
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, g_socket_name, sizeof(addr.sun_path) - 2);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(g_socket_name);
    if (bind(sock, (struct sockaddr *)&addr, addr_len) < 0) {
        fprintf(stderr, "[rule_server] 绑定 %s 失败: %s\n", g_socket_name, strerror(errno));
        close(sock);
        return 1;
    }
    if (listen(sock, 16) < 0) {
        fprintf(stderr, "[rule_server] listen 失败: %s\n", strerror(errno));
        close(sock);
        return 1;
    }
    RLOG("服务已启动 socket=%s config_dir=%s\n", g_socket_name, g_config_dir);

    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) {
        close(sock);
        return 1;
    }
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = sock };
    epoll_ctl(ep, EPOLL_CTL_ADD, sock, &ev);

    while (!g_should_exit) {
        struct epoll_event events[16];
        int n = epoll_wait(ep, events, 16, 500);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == sock) {
                while (1) {
                    int cfd = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
                    if (cfd < 0) break;
                    handle_client(cfd);
                }
            }
        }
    }
    close(ep);
    close(sock);
    RLOG("服务退出\n");
    return 0;
}

/* ==================== 客户端模式 ==================== */
static int run_client(const char *cmd_json) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "创建 socket 失败: %s\n", strerror(errno));
        return 1;
    }
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, g_socket_name, sizeof(addr.sun_path) - 2);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(g_socket_name);
    if (connect(sock, (struct sockaddr *)&addr, addr_len) < 0) {
        fprintf(stderr, "连接 %s 失败: %s（服务未启动？）\n", g_socket_name, strerror(errno));
        close(sock);
        return 1;
    }
    char req[MAX_REQ_LEN];
    snprintf(req, sizeof(req), "%s\n", cmd_json);
    send_all(sock, req, strlen(req));
    shutdown(sock, SHUT_WR);

    /* 响应动态扩容读取（LIST/GET 全量规则可能远超 8KB），杜绝静默截断 */
    size_t cap = MAX_REQ_LEN;
    char *resp = malloc(cap);
    if (!resp) {
        close(sock);
        return 1;
    }
    size_t total = 0;
    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    while (poll(&pfd, 1, 3000) > 0) {
        if (total >= cap - 1) {
            size_t new_cap = cap * 2;
            char *tmp = realloc(resp, new_cap);
            if (!tmp) break;
            resp = tmp;
            cap = new_cap;
        }
        ssize_t n = read(sock, resp + total, cap - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    if (total > 0) {
        resp[total] = '\0';
        fwrite(resp, 1, total, stdout);
        if (resp[total - 1] != '\n') fputc('\n', stdout);
    }
    free(resp);
    close(sock);
    return 0;
}

/* ==================== 后台化（daemonize + cgroup 逃脱） ====================
   与 injector 同策略：默认自动退入后台（service.sh 无需 &），双重 fork + setsid
   脱离会话与控制终端；并将进程写入 cgroup 根（v2 cgroup.procs / v1 tasks），
   逃出 Android 应用冻结/内存清理 cgroup，避免后台被系统误杀。
   --foreground 保留前台模式（测试/调试）。
   命名加 rs_ 前缀：common.h 已声明公共 escape_cgroup（injector 用），
   本文件独立实现避免符号冲突。 */

static void rs_escape_cgroup(void) {
    char pid_s[32];
    snprintf(pid_s, sizeof(pid_s), "%d", (int)getpid());
    const char *targets[] = {
        "/sys/fs/cgroup/cgroup.procs", /* v2 根 cgroup */
        "/dev/cpuctl/tasks",           /* v1 cpu */
        "/dev/cpuset/tasks",           /* v1 cpuset */
        "/dev/stune/tasks"             /* v1 stune */
    };
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        int fd = open(targets[i], O_WRONLY | O_CLOEXEC);
        if (fd >= 0) {
            /* 静默吞掉写入失败：cgroup 路径在不同 Android 版本与配置下可能不存在或无写权限 */
            if (write(fd, pid_s, strlen(pid_s)) < 0)
                RLOG("rs_escape_cgroup: 写入 %s 失败: %s\n", targets[i], strerror(errno));
            close(fd);
        }
    }
}

static void rs_daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);   /* 父进程退出，service.sh 无需 & 即返回 */
    setsid();
    pid = fork();           /* 二次 fork 确保不重新获得控制终端 */
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    /* 关闭全部 fd 并重定向标准流到 /dev/null */
    long max_fd_l = sysconf(_SC_OPEN_MAX);
    int max_fd = (max_fd_l <= 0 || max_fd_l > 4096) ? 4096 : (int)max_fd_l;
    for (int x = max_fd; x >= 0; x--) close(x);
    int dev_null = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (dev_null >= 0) {
        dup2(dev_null, 0);
        dup2(dev_null, 1);
        dup2(dev_null, 2);
        close(dev_null);
    }
}

static void usage(const char *prog) {
    fprintf(stderr,
        "用法: %s [选项]\n"
        "  （无参数）          守护进程模式：自动退入后台，监听抽象套接字 %s，提供规则控制 JSON API\n"
        "  -c, --cmd <JSON>    客户端模式：发送单条 JSON 命令并打印响应\n"
        "  --config-dir <dir>  覆盖配置根目录（默认 %s）\n"
        "  --socket <name>     覆盖抽象套接字名（默认 %s）\n"
        "  --foreground        前台运行（不后台化，测试/调试用）\n"
        "  -h, --help          显示本帮助\n",
        prog, RULE_SOCKET_NAME, CONFIG_DIR, RULE_SOCKET_NAME);
}

int main(int argc, char *argv[]) {
    const char *client_cmd = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cmd") == 0) {
            if (i + 1 >= argc) { usage(argv[0]); return 2; }
            client_cmd = argv[++i];
        } else if (strcmp(argv[i], "--config-dir") == 0) {
            if (i + 1 >= argc) { usage(argv[0]); return 2; }
            strncpy(g_config_dir, argv[++i], sizeof(g_config_dir) - 1);
        } else if (strcmp(argv[i], "--socket") == 0) {
            if (i + 1 >= argc) { usage(argv[0]); return 2; }
            strncpy(g_socket_name, argv[++i], sizeof(g_socket_name) - 1);
        } else if (strcmp(argv[i], "--foreground") == 0) {
            g_foreground = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (client_cmd) return run_client(client_cmd);
    /* 守护进程模式：默认自动退入后台并逃脱 cgroup（service.sh 无需 & 即可拉起） */
    if (!g_foreground) {
        rs_daemonize();
        rs_escape_cgroup();
    }
    return run_server();
}