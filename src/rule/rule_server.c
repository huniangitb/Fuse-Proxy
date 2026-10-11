/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
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
 *   FTP_LIST / FTP_GET              查询模块配置里的服务器账号（密码脱敏，只回 has_password）
 *   FTP_ADD / FTP_SET / FTP_REMOVE  增改删模块配置里的服务器段（原子落盘，
 *                                   ftp_module 经 inotify 自动热重载）
 *   RELOAD                        向 injector 发送 SIGHUP 触发配置重载
 *   STOP                          向 injector 发送 SIGTERM 停止注入服务
 *   STATUS                        系统状态概览
 *   EXPORT_LOGS                   把 <CONFIG_DIR>/log 打包到 <CONFIG_DIR>/export/
 *                                 （root 私有，只保留最新一份；见函数头安全说明）
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
#include "nsp_util.h"
#include "nsp_rule_file.h"
#include "nsp_ini_store.h"
#include <json-c/json.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stddef.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <poll.h>

#define RULE_VERSION "1.0.0"
#define MAX_REQ_LEN  8192
#define MAX_LINE     2048

/* 可被命令行覆盖的运行参数（--config-dir / --socket） */
static char g_config_dir[PATH_MAX] = CONFIG_DIR;
static char g_socket_name[64] = RULE_SOCKET_NAME;
static volatile sig_atomic_t g_should_exit = 0;
static bool g_foreground = false;    /* --foreground：前台运行（测试/调试用） */
static struct timespec g_start_mono; /* 启动时刻（CLOCK_MONOTONIC，运行时长基准） */
static time_t g_start_wall = 0;      /* 启动时刻（墙钟，started_at 展示） */

/* 统一日志：经 comm 线程进 sys.log（[rule_server] 前缀由 log_frame_packet
 * 按 g_proc_name 自动添加，调用方不再手写）。日志走 common.h 的 LOG 宏。 */

/* ==================== 规则类型（动态注册表） ====================
   类型来源两类：
   1. 内建类型：**随二进制内嵌**（BUILTIN_RULE_TYPES，即原 basic_rules.rules
      的内容）——规则引擎已内建进框架（fw_rules.c），其类型元数据也必须随
      框架走：模块目录里不再有 basic_rules.rules，若改成在 C 里裸注册类型名，
      desc/argc 这些展示与校验元数据会永久丢失；
   2. 模块类型（rule_types_refresh 扫描）：加载模块目录下 <模块名>.rules
      声明的类型（如 ftp_module 的 FTP），实现「支持的规则随加载模块动态追加」。
   值格式决定 ADD 时如何解析 value、写入文件时如何拼行：
     path   — 单值路径（HIDE /x）
     pair   — src|dst 双值（REDIRECT /a|/b → REDIRECT /a /b）
     switch — ON/OFF 开关（MONITOR ON）
     tokens — 空格分隔多 token（ADD 时 value 用 | 分隔） */
typedef enum {
    RFT_PATH = 0, /* 单值路径 */
    RFT_PAIR,     /* src|dst */
    RFT_SWITCH,   /* ON/OFF */
    RFT_TOKENS    /* 多 token（| 分隔） */
} RuleFmt;

#define MAX_RULE_TYPES 64
/* 多语言描述槽：<lang, text> 对；lang 为语言代码（zh/en/ja/...，默认 zh） */
#define MAX_DESC_LANGS 8
typedef struct {
    char lang[8];
    char text[160];
} DescEntry;
typedef struct {
    char name[64];    /* 类型名（大写，如 HIDE / FTP） */
    RuleFmt fmt;      /* 值格式 */
    bool builtin;     /* 内置类型（不可随模块卸载移除） */
    bool global_only; /* 仅全局作用域可用（如 GLOBAL_INJECT/SKIP_SYSTEM_APPS） */
    char module[64];  /* 来源模块名（内置为 "builtin"） */
    /* 动态适配扩展：.rules 可选属性（argc=N / argc=N:M / global-only / desc[.lang]="..."）
       argc_min/argc_max：pair/tokens 的参数数量约束（-1=不限制，默认：
       pair=2:2、path=1:1、tokens=2:-1、switch=1:1），ADD 时按此校验 */
    int argc_min;
    int argc_max;
    DescEntry descs[MAX_DESC_LANGS]; /* 多语言描述（desc=→zh，desc.en=→en，...） */
    int desc_count;
} RuleTypeDef;

typedef int RuleType; /* 动态表索引；RT_UNKNOWN 表示未知 */
#define RT_UNKNOWN (-1)

static RuleTypeDef g_rule_types[MAX_RULE_TYPES];
static int g_rule_type_count = 0;

/* 按格式取默认参数数量约束：path=1、pair=2、tokens=2+（上限不限）、switch=1 */
static void rule_fmt_default_argc(RuleFmt fmt, int* minp, int* maxp) {
    switch (fmt) {
        case RFT_PATH:
            *minp = 1;
            *maxp = 1;
            break;
        case RFT_PAIR:
            *minp = 2;
            *maxp = 2;
            break;
        case RFT_SWITCH:
            *minp = 1;
            *maxp = 1;
            break;
        case RFT_TOKENS:
            *minp = 2;
            *maxp = -1;
            break;
        default:
            *minp = 1;
            *maxp = -1;
            break;
    }
}

/* 注册一个类型（新类型）：argc 未显式声明（-1）时取格式默认约束；
   descs 为多语言描述槽（默认 zh 在前），多余截断 */
static void rule_types_add_ex(const char* name, RuleFmt fmt, bool builtin, bool global_only,
                              const char* module, int argc_min, int argc_max,
                              const DescEntry* descs, int desc_count) {
    if (g_rule_type_count >= MAX_RULE_TYPES) return;
    RuleTypeDef* t = &g_rule_types[g_rule_type_count];
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
        strncpy(t->descs[t->desc_count].lang, descs[i].lang,
                sizeof(t->descs[t->desc_count].lang) - 1);
        strncpy(t->descs[t->desc_count].text, descs[i].text,
                sizeof(t->descs[t->desc_count].text) - 1);
        t->desc_count++;
    }
    g_rule_type_count++;
}

/* 内建规则类型声明 —— 原 basic_rules.rules 的内容，规则引擎内建后随二进制分发。
   刻意用与模块 .rules **同一个解析器**（多语言 desc / argc 约束 / global-only
   全部支持），而不是在 C 里裸注册类型名：后者会让内建类型的 desc 全空（前端
   按 desc 渲染类型说明），argc/global-only 也只能靠格式默认值兜着。
   改这里即改前端可见的类型说明；新增内建规则类型须与 fw_rules.c 的解析同步。 */
static const char BUILTIN_RULE_TYPES[] =
    "# 段格式：[类型名] 段 + key=value 属性行\n"
    "#   format       — path（单值路径）/ pair（src|dst）/ switch（ON/OFF）/ tokens（多 token）\n"
    "#   argc=N / argc=N:M — 参数个数约束（M 用 * 或不写表示不限上界）\n"
    "#   global-only  — true/false：仅全局作用域可用\n"
    "#   desc / desc.xx — 类型描述（默认中文；desc.en 等为指定语言）\n"
    "\n"
    "[HIDE]\n"
    "format = path\n"
    "argc = 1\n"
    "desc = 隐藏路径\n"
    "desc.en = Hide path\n"
    "\n"
    "[RO]\n"
    "format = path\n"
    "argc = 1\n"
    "desc = 只读路径\n"
    "desc.en = Read-only path\n"
    "\n"
    "[REDIRECT]\n"
    "format = pair\n"
    "argc = 2\n"
    "desc = 路径重定向\n"
    "desc.en = Path redirect\n"
    "\n"
    "[ALLOW]\n"
    "format = path\n"
    "argc = 1\n"
    "desc = 放行路径\n"
    "desc.en = Allow path\n"
    "\n"
    "[MONITOR]\n"
    "format = switch\n"
    "desc = 监控\n"
    "desc.en = Monitor switch\n"
    "\n"
    "[SANDBOX]\n"
    "format = switch\n"
    "desc = 沙盒\n"
    "desc.en = Sandbox switch\n"
    "\n"
    "[GLOBAL_INJECT]\n"
    "format = switch\n"
    "global-only = true\n"
    "desc = 全局注入\n"
    "desc.en = Global injection switch\n"
    "\n"
    "[SKIP_SYSTEM_APPS]\n"
    "format = switch\n"
    "global-only = true\n"
    "desc = 跳过系统应用\n"
    "desc.en = Skip system apps switch\n"
    "\n"
    "[SANDBOX_DIR]\n"
    "format = path\n"
    "argc = 1\n"
    "global-only = true\n"
    "desc = 沙盒目录名（单级目录名，覆盖默认 sandbox）\n"
    "desc.en = Sandbox dir name (overrides default \"sandbox\")\n";

/* 解析内嵌声明文本（定义见 conf 解析段）：前向声明供 rule_types_init 使用，
   与模块 .rules 文件走同一套行解析与合并语义 */
static void rule_types_parse_text(const char* text, const char* module, bool builtin);

/* 内建类型初始化（与内建规则引擎一一对应；模块自带 .rules 只补充新增类型） */
static void rule_types_init(void) {
    g_rule_type_count = 0;
    rule_types_parse_text(BUILTIN_RULE_TYPES, "builtin", true);
}

/* 按名查找类型（大小写不敏感），返回索引；未找到返回 RT_UNKNOWN */
static RuleType rule_type_of(const char* name);

/* 合并属性到已存在的类型（定义见 conf 解析段）：前向声明供旧行格式
   rule_types_parse_line 使用（两种格式共用同一合并语义） */
static void rule_types_merge(RuleType idx, RuleFmt fmt, bool fmt_set, int argc_min, int argc_max,
                             bool argc_set, bool global_only, bool global_only_set,
                             const DescEntry* descs, int desc_count);

static RuleType rule_type_of(const char* name) {
    if (!name) return RT_UNKNOWN;
    for (int i = 0; i < g_rule_type_count; i++) {
        if (strcasecmp(name, g_rule_types[i].name) == 0) return i;
    }
    return RT_UNKNOWN;
}

static const char* rule_type_name(RuleType t) {
    if (t < 0 || t >= g_rule_type_count) return NULL;
    return g_rule_types[t].name;
}

static bool is_switch_type(RuleType t) {
    if (t < 0 || t >= g_rule_type_count) return false;
    return g_rule_types[t].fmt == RFT_SWITCH;
}

/* 识别一行是否为规则/开关行（忽略行首空白与可选的 # 注释前缀）；
   返回类型索引；非规则行（空行/段头/未知关键字）返回 RT_UNKNOWN */
static RuleType classify_line(const char* line) {
    const char* p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#') {
        p++;
        while (*p == ' ' || *p == '\t') p++;
    }
    if (*p == '[' || *p == '\0' || *p == '\n') return RT_UNKNOWN;
    for (int i = 0; i < g_rule_type_count; i++) {
        const char* name = g_rule_types[i].name;
        size_t nlen = strlen(name);
        if (strncasecmp(p, name, nlen) == 0 &&
            (p[nlen] == ' ' || p[nlen] == '\t' || p[nlen] == '\n' || p[nlen] == '\0'))
            return i;
    }
    return RT_UNKNOWN;
}

/* 解析一行 .rules 声明："<TYPE> <FORMAT>"，追加进类型表（去重）。
   FORMAT: path|pair|switch|tokens，缺省为 path。
   builtin：声明来源是否内建（内嵌声明为 true，模块 .rules 为 false） */
static void rule_types_parse_line(char* line, const char* module, bool builtin) {
    char* p = line;
    while (isspace((unsigned char)*p)) p++;
    if (!*p || *p == '#') return;
    char type[64];
    int i = 0;
    while (*p && !isspace((unsigned char)*p) && i < (int)sizeof(type) - 1) type[i++] = *p++;
    type[i] = '\0';
    if (!type[0]) return;
    while (isspace((unsigned char)*p)) p++;
    RuleFmt fmt = RFT_PATH;
    if (strncasecmp(p, "pair", 4) == 0) {
        fmt = RFT_PAIR;
        p += 4;
    } else if (strncasecmp(p, "switch", 6) == 0) {
        fmt = RFT_SWITCH;
        p += 6;
    } else if (strncasecmp(p, "tokens", 6) == 0) {
        fmt = RFT_TOKENS;
        p += 6;
    } else if (strncasecmp(p, "path", 4) == 0) {
        fmt = RFT_PATH;
        p += 4;
    } else
        return; /* 未知 FORMAT：跳过 */
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
            char* end = nullptr;
            errno = 0;
            long v1 = strtol(p, &end, 10);
            if (end == p || errno == ERANGE) { /* 非数字：跳过属性 */
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
                    new_max = -1; /* 不限上界 */
                    if (*p == '*') p++;
                } else {
                    char* end2 = nullptr;
                    errno = 0;
                    long v2 = strtol(p, &end2, 10);
                    if (end2 == p || errno == ERANGE) { /* 畸形上界：整体跳过属性 */
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
            const char* lang = langbuf; /* 默认中文 */
            p += 4;
            if (*p == '.') { /* desc.xx= 语言变体 */
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
    /* 已注册（内建或他模块）的同名类型：合并补充属性（多语言 desc 等），
       不覆盖类型名与 module 来源；否则按声明来源注册为新类型 */
    RuleType existing = rule_type_of(type);
    if (existing != RT_UNKNOWN) {
        rule_types_merge(existing, fmt, true, argc_min, argc_max, (argc_min >= 0), global_only,
                         global_only, descs, desc_count);
    } else {
        rule_types_add_ex(type, fmt, builtin, global_only, module, argc_min, argc_max, descs,
                          desc_count);
    }
}

/* ============ conf 格式解析（.rules 支持两种书写格式） ============
   conf 段格式（推荐，易于编写）：
     [FTP]
     format = pair
     argc = 2
     global-only = false
     desc = 存储映射：<虚拟前缀>|<段名>
     desc.en = Storage mapping: <virtual prefix>|<section>
   旧行格式（兼容）：FTP pair argc=2 desc="..." desc.en="..."
   解析器为状态机：遇到 [TYPE] 段头进入段模式收集 key=value 属性，
   段内无 '=' 的行或段外行按旧行格式处理；文件尾刷新未结束的段。 */

/* conf 段属性收集状态 */
#define MODCONF_MAX_FIELDS 16
#define MODCONF_MAX_ENUM 4

typedef struct {
    char type[64];
    bool active; /* 是否处于 [TYPE] 段内 */
    RuleFmt fmt;
    bool fmt_set; /* format 键是否显式声明（未声明不覆盖已有类型） */
    int argc_min, argc_max;
    bool argc_set; /* argc 键是否显式声明 */
    bool global_only;
    bool global_only_set; /* global-only 键是否显式声明 */
    DescEntry descs[MAX_DESC_LANGS];
    int desc_count;
    char langbuf[8]; /* desc 语言缓冲（函数级作用域防悬垂） */
    /* ---- [conf] 段专用：conf.<字段>.<属性> 累积槽（不参与规则类型） ---- */
    char cf_key[32];     /* 当前 conf.<字段>（空 = 未进入某字段） */
    char cf_type[8];
    size_t cf_maxlen;
    int cf_min, cf_max;
    bool cf_has_range;
    bool cf_required;
    bool cf_sensitive;
    char cf_defval[64];
    char cf_cond_dep[32];    /* 条件缺省：依赖字段名（default.<dep>.<val>） */
    char cf_cond_val[32];    /* 依赖字段取值 */
    char cf_cond_defval[64]; /* 命中时的缺省值（覆盖 cf_defval） */
    bool cf_has_cond;
    char cf_enum[MODCONF_MAX_ENUM][24];
    int cf_enum_count;
    int cf_order;
    DescEntry cf_descs[MAX_DESC_LANGS];
    int cf_desc_count;
    char cf_module[64];  /* [conf] 段所属模块（段头绑定；字段级提交不得复位） */
    bool cf_started;     /* 本段已初始化：清表只做一次 */
} ConfSection;

/* [conf] 段（模块配置 schema）解析：定义在 FTP 配置段之前，此处前向声明供
   conf_section_apply_key / conf_section_flush 在前面调用 */
static void modconf_apply(ConfSection* cs, const char* rest, const char* val);
static void modconf_field_commit(ConfSection* cs);
static void modconf_flush(ConfSection* cs, const char* module);


typedef struct {
    char key[32];                    /* 字段名（INI 键名） */
    char type[8];                    /* string / int / bool / path */
    size_t maxlen;                   /* string/path 的字节上限（0 = 不限制） */
    int min, max;                    /* int 取值闭区间；has_range=false 时无意义 */
    bool has_range;                  /* 是否声明了 int 值域 */
    bool required;                   /* 新建条目时必填 */
    bool sensitive;                  /* 敏感：只写不读，LIST/GET 仅回 has_<key> */
    char defval[64];                 /* 缺省值（LIST/GET 回填生效值） */
    /* 条件缺省：当 cond_dep 字段的生效值等于 cond_val 时，缺省取 cond_defval。
       用于「缺省随另一字段取值而变」的字段（如 port 在 proto=sftp 时缺省 22）——
       模块侧的推导规则必须与这里一致（同一发布物内的两处声明）。 */
    char cond_dep[32];
    char cond_val[32];
    char cond_defval[64];
    bool has_cond;
    char enumvals[MODCONF_MAX_ENUM][24];
    int enum_count;
    int order;                       /* 前端显示顺序（0 = 未指定，按声明序） */
    DescEntry descs[MAX_DESC_LANGS]; /* 多语言标签（desc= → zh，desc.en= → en） */
    int desc_count;
} ModConfField;

typedef struct {
    char module[64];               /* 所属模块名 */
    ModConfField fields[MODCONF_MAX_FIELDS];
    int count;
    bool loaded;                   /* 已由 [conf] 段填入（否则用默认表） */
} ModConfSchema;

static ModConfSchema* modconf_for(const char* module); /* 定义见 modconf_load_defaults 附近 */

#define MODCONF_MAX_MODULES 8
static ModConfSchema g_modconf[MODCONF_MAX_MODULES] = {0};
static int g_modconf_count = 0;


static void conf_section_reset(ConfSection* cs) {
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
    /* [conf] 段槽位一并复位（逐字段赋值，与上面同风格；勿改整体 memset） */
    cs->cf_key[0] = '\0';
    cs->cf_module[0] = '\0';
    cs->cf_started = false;
    cs->cf_type[0] = '\0';
    cs->cf_maxlen = 0;
    cs->cf_min = 0;
    cs->cf_max = 0;
    cs->cf_has_range = false;
    cs->cf_required = false;
    cs->cf_sensitive = false;
    cs->cf_defval[0] = '\0';
    cs->cf_cond_dep[0] = '\0';
    cs->cf_cond_val[0] = '\0';
    cs->cf_cond_defval[0] = '\0';
    cs->cf_has_cond = false;
    cs->cf_enum_count = 0;
    cs->cf_order = 0;
    cs->cf_desc_count = 0;
}

/* 合并属性到已存在的类型（内置或他模块注册的同名类型）：
   .rules 中的补充声明（desc 多语言/argc/global-only 等）生效，
   不覆盖内置类型名与 module 来源；显式声明的字段（*_set）才覆盖。 */
static void rule_types_merge(RuleType idx, RuleFmt fmt, bool fmt_set, int argc_min, int argc_max,
                             bool argc_set, bool global_only, bool global_only_set,
                             const DescEntry* descs, int desc_count) {
    if (idx < 0 || idx >= g_rule_type_count) return;
    RuleTypeDef* t = &g_rule_types[idx];
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

/* 段结束时把收集的属性注册进类型表（同名内建类型改为合并补充） */
static void conf_section_flush(ConfSection* cs, const char* module, bool builtin) {
    /* [conf] 段不是规则类型：它是模块配置 schema，转交 schema 解析，不进类型表 */
    if (cs->active && strcasecmp(cs->type, "conf") == 0) {
        modconf_flush(cs, module);
        conf_section_reset(cs);
        return;
    }
    if (cs->active && cs->type[0]) {
        RuleType existing = rule_type_of(cs->type);
        if (existing == RT_UNKNOWN) {
            rule_types_add_ex(cs->type, cs->fmt, builtin, cs->global_only, module, cs->argc_min,
                              cs->argc_max, cs->descs, cs->desc_count);
        } else {
            rule_types_merge(existing, cs->fmt, cs->fmt_set, cs->argc_min, cs->argc_max,
                             cs->argc_set, cs->global_only, cs->global_only_set, cs->descs,
                             cs->desc_count);
        }
    }
    conf_section_reset(cs);
}

/* 解析 conf 键值属性（format/argc/global-only/desc[.lang]），写入段状态 */
static void conf_section_apply_key(ConfSection* cs, const char* key, const char* val) {
    /* [conf] 段的 conf.<字段>.<属性> 键：交给 schema 解析器，不走规则类型属性 */
    if (strncasecmp(key, "conf.", 5) == 0) {
        modconf_apply(cs, key + 5, val);
        return;
    }
    if (strcasecmp(key, "format") == 0) {
        if (strcasecmp(val, "pair") == 0)
            cs->fmt = RFT_PAIR;
        else if (strcasecmp(val, "switch") == 0)
            cs->fmt = RFT_SWITCH;
        else if (strcasecmp(val, "tokens") == 0)
            cs->fmt = RFT_TOKENS;
        else
            cs->fmt = RFT_PATH;
        cs->fmt_set = true;
        return;
    }
    if (strcasecmp(key, "argc") == 0) {
        /* 先完整解析 N 或 N:M（含畸形上界），全部成功后才提交到段状态：
           argc=2:abc 的畸形上界会使整个属性被跳过，而不是注册 2:∞
           错误约束（与文档"畸形声明被跳过"语义一致） */
        char* end = nullptr;
        errno = 0;
        long v1 = strtol(val, &end, 10);
        if (end == val || errno == ERANGE) return; /* 畸形：跳过 */
        int new_min = (int)v1;
        int new_max = new_min;
        if (*end == ':') {
            const char* up = end + 1;
            if (*up == '*' || *up == '\0' || isspace((unsigned char)*up)) {
                new_max = -1; /* 不限上界 */
            } else {
                char* end2 = nullptr;
                errno = 0;
                long v2 = strtol(up, &end2, 10);
                if (end2 == up || errno == ERANGE) return; /* 畸形上界：整体跳过 */
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
        const char* lang = cs->langbuf;
        const char* dot = key + 4;
        if (*dot == '.') { /* desc.xx= 语言变体 */
            dot++;
            size_t li = 0;
            while (*dot && li < sizeof(cs->langbuf) - 1) cs->langbuf[li++] = *dot++;
            cs->langbuf[li] = '\0';
            if (li > 0) lang = cs->langbuf;
        }
        const char* v = val;
        char dtext[160] = {0};
        if (*v == '"') { /* 引号包裹（可含空格） */
            v++;
            size_t di = 0;
            while (*v && *v != '"' && di < sizeof(dtext) - 1) dtext[di++] = *v++;
        } else {
            size_t di = 0;
            while (*v && di < sizeof(dtext) - 1) dtext[di++] = *v++;
        }
        if (dtext[0] && cs->desc_count < MAX_DESC_LANGS) {
            strncpy(cs->descs[cs->desc_count].lang, lang,
                    sizeof(cs->descs[cs->desc_count].lang) - 1);
            strncpy(cs->descs[cs->desc_count].text, dtext,
                    sizeof(cs->descs[cs->desc_count].text) - 1);
            cs->desc_count++;
        }
        return;
    }
    /* 未知键：忽略（向前兼容） */
}

/* 处理一行 .rules 声明（段头 / 段内 key=value / 旧行格式），就地修改 line。
   文件与内嵌文本两个入口共用，避免两套行语义漂移。 */
static void rule_types_parse_one_line(char* line, ConfSection* cs, const char* module,
                                      bool builtin) {
    char* p = line;
    while (isspace((unsigned char)*p)) p++;
    if (!*p || *p == '#') return; /* 空行/注释 */
    if (*p == '[') {              /* 段头：[TYPE] */
        conf_section_flush(cs, module, builtin);
        p++;
        size_t ti = 0;
        while (*p && *p != ']' && ti < sizeof(cs->type) - 1) cs->type[ti++] = *p++;
        cs->type[ti] = '\0';
        cs->active = (ti > 0);
        /* [conf] 段：**立刻**绑定所属模块，使段内 conf.<字段>.<属性> 能写进该模块的
           schema 表。推迟到段尾绑定会让「换字段时的中间提交」拿不到模块名而丢弃，
           结果整段只剩最后一个字段、且属性串成最后字段的那一份。 */
        if (cs->active && strcasecmp(cs->type, "conf") == 0) {
            snprintf(cs->cf_module, sizeof cs->cf_module, "%s", module);
            cs->cf_started = false;
        }
        return;
    }
    char* eq = strchr(p, '=');
    if (cs->active && eq) { /* 段内 key=value */
        *eq = '\0';
        char* key = p;
        while (key < eq && isspace((unsigned char)key[0])) key++;
        char* kend = eq - 1;
        while (kend >= key && isspace((unsigned char)*kend)) {
            *kend = '\0';
            kend--;
        }
        char* val = eq + 1;
        while (isspace((unsigned char)*val)) val++;
        conf_section_apply_key(cs, key, val);
        return;
    }
    /* 旧行格式（兼容）：FTP pair argc=2 ... */
    rule_types_parse_line(line, module, builtin);
}

/* 解析整个 .rules 文件（conf 段 + 旧行格式混合） */
static void rule_types_parse_conf(FILE* fp, const char* module, bool builtin) {
    char line[256];
    ConfSection cs;
    conf_section_reset(&cs);
    while (fgets(line, sizeof(line), fp)) {
        char* nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        rule_types_parse_one_line(line, &cs, module, builtin);
    }
    conf_section_flush(&cs, module, builtin); /* 文件尾刷新未结束段 */
}

/* 解析内嵌声明文本（同 conf 解析器，含多语言 desc 与 argc 约束）：
   rule_types_init 用它加载 BUILTIN_RULE_TYPES，不引入临时文件/流依赖 */
static void rule_types_parse_text(const char* text, const char* module, bool builtin) {
    char line[256];
    ConfSection cs;
    conf_section_reset(&cs);
    const char* p = text;
    while (*p) {
        const char* nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, p, len);
        line[len] = '\0';
        rule_types_parse_one_line(line, &cs, module, builtin);
        if (!nl) break;
        p = nl + 1;
    }
    conf_section_flush(&cs, module, builtin); /* 文本尾刷新未结束段 */
}

/* ==================== 模块规则类型缓存（避免每次命令全量扫描） ====================
   dispatch 每次命令前调用 rule_types_refresh：快速路径仅 stat 模块目录与各
   .rules 文件的 mtime，全部未变则直接复用当前类型表；仅当目录/文件 mtime
   变化（模块增删或 .rules 内容修改）才全量重建。 */

#define MAX_CACHED_MODULES 32
typedef struct {
    char name[64];      /* 模块名（目录名 = <name>.rules 前缀） */
    long long mtime_ns; /* 上次扫描时 <name>.rules 的 mtime（纳秒精度，
                             避免同秒内写入被快速路径误判为未变化） */
    bool present;       /* 上次扫描时 .rules 是否存在 */
} ModuleTypeCache;

static ModuleTypeCache g_module_cache[MAX_CACHED_MODULES];
static int g_module_cache_count = 0;
static long long g_modules_dir_mtime_ns = 0;
static bool g_module_cache_valid = false;

/* 取文件/目录 mtime（纳秒）：不存在返回 0 */
static long long file_mtime_ns(const char* path) {
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
            snprintf(rules_path, sizeof(rules_path), "%s/%s/%s.rules", modules_dir,
                     g_module_cache[i].name, g_module_cache[i].name);
            long long cur = file_mtime_ns(rules_path);
            bool present = (cur != 0);
            if (present != g_module_cache[i].present ||
                (present && cur != g_module_cache[i].mtime_ns)) {
                unchanged = false;
                break;
            }
        }
        if (unchanged) return; /* 全部未变：跳过全量扫描 */
    }

    /* 慢路径：全量重建类型表与缓存。
       schema 一并失效：若模块撤掉了 [conf] 段，必须回退默认表，绝不沿用上一次
       扫描残留的字段声明（否则删声明后旧字段仍可写，声明就不再是唯一来源）。 */
    for (int i = 0; i < MODCONF_MAX_MODULES; i++) {
        g_modconf[i].count = 0;
        g_modconf[i].loaded = false;
        g_modconf[i].module[0] = '\0';
    }
    g_modconf_count = 0;
    g_rule_type_count = 0;
    rule_types_init();
    g_module_cache_count = 0;
    g_modules_dir_mtime_ns = cur_dir_mtime;
    g_module_cache_valid = true;

    if (cur_dir_mtime == 0) return; /* 模块目录不存在 */
    DIR* d = opendir(modules_dir);
    if (!d) return;
    struct dirent* de;
    while ((de = readdir(d)) != NULL) {
        const char* mname = de->d_name;
        if (mname[0] == '.') continue;
        if (strchr(mname, '/')) continue;
        char rules_path[PATH_MAX];
        snprintf(rules_path, sizeof(rules_path), "%s/%s/%s.rules", modules_dir, mname, mname);
        long long r_mtime = file_mtime_ns(rules_path);
        bool present = (r_mtime != 0);
        if (g_module_cache_count < MAX_CACHED_MODULES) {
            ModuleTypeCache* c = &g_module_cache[g_module_cache_count];
            strncpy(c->name, mname, sizeof(c->name) - 1);
            c->present = present;
            c->mtime_ns = r_mtime;
            g_module_cache_count++;
        }
        if (!present) continue;
        FILE* fp = fopen(rules_path, "r");
        if (!fp) continue;
        /* 支持 conf 段格式（[TYPE] + key=value）与旧行格式（TYPE FORMAT ...）混合 */
        rule_types_parse_conf(fp, mname, false);
        fclose(fp);
    }
    closedir(d);
    LOG("规则类型表: %d 项（含模块动态类型，缓存 %d 个模块）", g_rule_type_count,
        g_module_cache_count);
}

/* 该行是否为已注释（停用）状态 */
static bool line_is_disabled(const char* line) {
    const char* p = line;
    while (*p == ' ' || *p == '\t') p++;
    return *p == '#';
}

/* 提取规则行的"值"部分：关键字后的原始内容（REDIRECT 为 "src dst"） */
static const char* rule_line_value(const char* line, char* out, size_t sz) {
    const char* p = line;
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

/* 行级读写与段编辑统一走 nsp_rule_file（与 log_ctl 共享同一实现；
   语义基准即本文件既有语义：开关在作用域内唯一、规则行全文件去重、
   按 (类型,索引) 删除时索引计入已停用行、落盘原子写）。 */

/* ==================== 路径工具 ==================== */
static void main_conf_path(char* out, size_t sz) {
    snprintf(out, sz, "%s/injector.conf", g_config_dir);
}

/* 应用规则状态：true=启用（.conf 存在），false=停用（仅 .conf.disabled） */
static bool app_rule_is_enabled(const char* pkg, int uid) {
    char path[PATH_MAX];
    nsp_app_rule_path(g_config_dir, uid, pkg, path, sizeof(path));
    return (access(path, F_OK) == 0);
}

static void injector_pid_path(char* out, size_t sz) {
    snprintf(out, sz, "%s/injector.pid", g_config_dir);
}

/* ==================== JSON 应答 ====================
   mkdir/send 全量发送经 nsp_util 公共库复用（nsp_mkdir_p / nsp_send_all，
   见 nsp_util.h），禁私刻副本（旧 mkdir_p/send_all 已删除） */
static void reply_json(int fd, const char* status, const char* cmd, json_object* data,
                       const char* err) {
    json_object* root = json_object_new_object();
    json_object_object_add(root, "status", json_object_new_string(status));
    json_object_object_add(root, "command", json_object_new_string(cmd));
    if (data) json_object_object_add(root, "data", data);
    if (err) json_object_object_add(root, "error", json_object_new_string(err));
    json_object_object_add(root, "timestamp", json_object_new_int64(time(NULL)));
    const char* s = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    nsp_send_all(fd, s, strlen(s));
    nsp_send_all(fd, "\n", 1);
    json_object_put(root);
}

static void reply_ok(int fd, const char* cmd, json_object* data) {
    reply_json(fd, "ok", cmd, data, NULL);
}

/* 拒绝日志限频：同一 cmd 每秒最多一条（防日志洪泛），被抑制条数并入下一条。
   服务端单线程串行处理请求，故无需加锁。 */
#define REPLY_RL_SLOTS 16
static struct {
    char cmd[32];
    time_t last;
    unsigned suppressed;
} g_reply_rl[REPLY_RL_SLOTS];

/* 返回 true 表示本条应当落日志；*out_suppressed 给出上次落日志至今被抑制的条数 */
static bool reply_log_gate(const char* cmd, unsigned* out_suppressed) {
    time_t now = time(NULL);
    int free_i = -1, oldest_i = 0;
    for (int i = 0; i < REPLY_RL_SLOTS; i++) {
        if (g_reply_rl[i].cmd[0] && strcmp(g_reply_rl[i].cmd, cmd) == 0) {
            if (now - g_reply_rl[i].last >= 1) {
                g_reply_rl[i].last = now;
                *out_suppressed = g_reply_rl[i].suppressed;
                g_reply_rl[i].suppressed = 0;
                return true;
            }
            g_reply_rl[i].suppressed++;
            return false;
        }
        if (!g_reply_rl[i].cmd[0]) {
            if (free_i < 0) free_i = i;
        } else if (g_reply_rl[i].last < g_reply_rl[oldest_i].last) {
            oldest_i = i;
        }
    }
    int slot = (free_i >= 0) ? free_i : oldest_i;
    snprintf(g_reply_rl[slot].cmd, sizeof g_reply_rl[slot].cmd, "%s", cmd);
    g_reply_rl[slot].last = now;
    g_reply_rl[slot].suppressed = 0;
    *out_suppressed = 0;
    return true;
}

static void reply_error(int fd, const char* cmd, const char* fmt, ...) {
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    /* 错误应答单点留痕：前端发来无法接受的参数 / 规则写入失败等均经此应答，
       以警告级别落日志（含命令与原因），便于从 sys.log 侧审计前端误用。

       cmd 与 msg 都可能含**客户端可控文本**（请求原文、包名等），落日志前必须
       清洗成单行：log_monitor 按 '\n' 拆行、按行首 "<数字>:" 取等级，未清洗时
       一次 `garbage\n3:伪造` 即可向 sys.log 注入伪造的 ERROR 行（且每条坏请求
       落一行 = 日志洪泛面）。故清洗 + 同 cmd 限频。 */
    char safe_cmd[48], safe_msg[512];
    nsp_log_line_sanitize(cmd ? cmd : "?", safe_cmd, sizeof safe_cmd);
    nsp_log_line_sanitize(msg, safe_msg, sizeof safe_msg);
    unsigned suppressed = 0;
    if (reply_log_gate(safe_cmd, &suppressed)) {
        if (suppressed)
            LOG_WRN("规则请求被拒绝: cmd=%s 原因=%s（另有 %u 条同类被抑制）", safe_cmd, safe_msg,
                    suppressed);
        else
            LOG_WRN("规则请求被拒绝: cmd=%s 原因=%s", safe_cmd, safe_msg);
    }
    reply_json(fd, "error", cmd, NULL, msg);
}

/* ==================== 输入校验 ==================== */
/* 包名只能含 [A-Za-z0-9._-]，禁止 / 与 ..，防路径穿越 */
static bool valid_pkg(const char* pkg) {
    if (!pkg || !*pkg || strlen(pkg) > 127) return false;
    if (strchr(pkg, '/') || strstr(pkg, "..")) return false;
    for (const char* p = pkg; *p; p++) {
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '_' || *p == '-')) return false;
    }
    return true;
}

static bool valid_value(const char* v) {
    if (!v || !*v || strchr(v, '\n')) return false;
    if (strlen(v) >= MAX_LINE - 64) return false;
    for (const char* p = v; *p; p++) {
        if (*p == '\r' || *p == '\0') return false;
    }
    return true;
}

/* ==================== 规则列表构建 ==================== */
/* 构建已读取行数组的 rules 数组 + switches 对象（索引与 REMOVE/TOGGLE 一致） */
static void build_lines_rules(char** lines, int count, json_object* rules, json_object* switches) {
    if (!lines) return;
    int type_index[MAX_RULE_TYPES] = {0};
    char valbuf[MAX_LINE];
    for (int i = 0; i < count; i++) {
        RuleType t = classify_line(lines[i]);
        if (t == RT_UNKNOWN) continue;
        const char* name = rule_type_name(t);
        bool disabled = line_is_disabled(lines[i]);
        if (is_switch_type(t)) {
            /* 开关：switches.{name} = "ON"/"OFF"（以值行为准，默认 OFF） */
            rule_line_value(lines[i], valbuf, sizeof(valbuf));
            bool on = (strcasecmp(valbuf, "ON") == 0) || (strcasecmp(valbuf, "1") == 0);
            json_object_object_add(switches, name, json_object_new_boolean(on));
        } else {
            json_object* r = json_object_new_object();
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
}

/* 构建单个规则文件的 rules 数组 + switches 对象 */
static void build_file_rules(const char* path, json_object* rules, json_object* switches) {
    int count = 0, cap = 0;
    char** lines = nsp_rule_file_read(path, &count, &cap);
    if (!lines) return;
    build_lines_rules(lines, count, rules, switches);
    nsp_rule_file_free(lines, count);
}

/* 类别段 JSON：只取主文件内精确段头（[USER_APPS:<uid>]/[SYSTEM_APPS]）
   覆盖的行区间（段不存在则空规则，file 照样回主文件路径）。
   索引为**段内**局部序号——与 REMOVE/TOGGLE 的 scope 口径同源（§A5）。 */
static json_object* build_category_json(const char* pkg, int uid) {
    char path[PATH_MAX];
    char sec_name[64], hdr[72];
    main_conf_path(path, sizeof(path));
    nsp_rule_file_category_name(pkg, uid, sec_name, sizeof sec_name);
    snprintf(hdr, sizeof hdr, "[%s]", sec_name);
    json_object* cat = json_object_new_object();
    json_object* switches = json_object_new_object();
    json_object* rules = json_object_new_array();
    int count = 0, cap = 0;
    char** lines = nsp_rule_file_read(path, &count, &cap);
    if (lines) {
        NspRuleScope scope = {sec_name, NSP_RULE_SEC_EXACT};
        int beg = 0, end = 0;
        if (nsp_rule_file_scope_range(lines, count, &scope, &beg, &end))
            build_lines_rules(lines + beg, end - beg, rules, switches);
        nsp_rule_file_free(lines, count);
    }
    json_object_object_add(cat, "pkg", json_object_new_string(pkg));
    json_object_object_add(cat, "uid", json_object_new_int(uid));
    json_object_object_add(cat, "section", json_object_new_string(hdr));
    json_object_object_add(cat, "file", json_object_new_string(path));
    json_object_object_add(cat, "switches", switches);
    json_object_object_add(cat, "rules", rules);
    return cat;
}

/* 全局视图：只取 [GLOBAL] 段（含文件起始到首个非 GLOBAL 段头之间的行，与解析器
   的全局作用域一致）。此前扫整份主文件，会把类别段（[USER_APPS:<uid>]/
   [SYSTEM_APPS]）的规则与开关一并混进 GLOBAL 视图（§A5）。 */
static json_object* build_global_json(void) {
    char path[PATH_MAX];
    main_conf_path(path, sizeof(path));
    json_object* global = json_object_new_object();
    json_object* switches = json_object_new_object();
    json_object* rules = json_object_new_array();
    int count = 0, cap = 0;
    char** lines = nsp_rule_file_read(path, &count, &cap);
    if (lines) {
        NspRuleScope scope = {"GLOBAL", NSP_RULE_SEC_PREFIX};
        int beg = 0, end = count;
        if (nsp_rule_file_scope_range(lines, count, &scope, &beg, &end))
            build_lines_rules(lines + beg, end - beg, rules, switches);
        nsp_rule_file_free(lines, count);
    }
    json_object_object_add(global, "file", json_object_new_string(path));
    json_object_object_add(global, "switches", switches);
    json_object_object_add(global, "rules", rules);
    return global;
}

static json_object* build_app_json(const char* pkg, int uid) {
    char read_path[PATH_MAX];
    nsp_rule_file_app_active_path(g_config_dir, uid, pkg, read_path, sizeof(read_path));
    bool disabled = !app_rule_is_enabled(pkg, uid);
    json_object* app = json_object_new_object();
    json_object* switches = json_object_new_object();
    json_object* rules = json_object_new_array();
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
static json_object* build_apps_json_filtered(int uid_filter) {
    json_object* apps = json_object_new_array();
    DIR* d = opendir(g_config_dir);
    if (!d) return apps;
    struct dirent* de;
    while ((de = readdir(d)) != NULL) {
        const char* name = de->d_name;
        int uid = 0;
        if (strcmp(name, NSP_APP_RULES_DIRNAME) == 0) {
            uid = 0;
        } else if (strncmp(name, NSP_APP_RULES_DIRNAME "-",
                           sizeof(NSP_APP_RULES_DIRNAME "-") - 1) == 0) {
            uid = atoi(name + sizeof(NSP_APP_RULES_DIRNAME "-") - 1);
        } else {
            continue;
        }
        if (uid_filter >= 0 && uid != uid_filter) continue;
        char dir[PATH_MAX];
        nsp_app_rule_dir(g_config_dir, uid, dir, sizeof(dir));
        DIR* ad = opendir(dir);
        if (!ad) continue;
        struct dirent* ae;
        while ((ae = readdir(ad)) != NULL) {
            const char* fn = ae->d_name;
            size_t flen = strlen(fn);
            /* 匹配 <pkg>.conf 与 <pkg>.conf.disabled 两种形态 */
            bool disabled = false;
            size_t suffix = 5; /* ".conf" */
            if (flen > 14 && strcmp(fn + flen - 14, ".conf.disabled") == 0) {
                disabled = true;
                suffix = 14; /* ".conf.disabled" */
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

static json_object* build_apps_json(void) {
    return build_apps_json_filtered(-1);
}

/* 扫描 config_dir 下全部用户目录（App-rules=uid 0、App-rules-<uid>=uid>0），
   返回用户列表 [{uid, dir, app_count}] */
static json_object* build_users_json(void) {
    json_object* users = json_object_new_array();
    DIR* d = opendir(g_config_dir);
    if (!d) return users;
    struct dirent* de;
    while ((de = readdir(d)) != NULL) {
        const char* name = de->d_name;
        int uid = -1;
        if (strcmp(name, NSP_APP_RULES_DIRNAME) == 0) {
            uid = 0;
        } else if (strncmp(name, NSP_APP_RULES_DIRNAME "-",
                           sizeof(NSP_APP_RULES_DIRNAME "-") - 1) == 0) {
            char* end = NULL;
            long v = strtol(name + sizeof(NSP_APP_RULES_DIRNAME "-") - 1, &end, 10);
            if (end && *end == '\0' && v >= 0 && v <= 100000) uid = (int)v;
        }
        if (uid < 0) continue;
        char dir[PATH_MAX];
        nsp_app_rule_dir(g_config_dir, uid, dir, sizeof(dir));
        int app_cnt = 0;
        DIR* ad = opendir(dir);
        if (ad) {
            struct dirent* ae;
            while ((ae = readdir(ad)) != NULL) {
                const char* fn = ae->d_name;
                size_t flen = strlen(fn);
                if ((flen > 5 && strcmp(fn + flen - 5, ".conf") == 0) ||
                    (flen > 14 && strcmp(fn + flen - 14, ".conf.disabled") == 0))
                    app_cnt++;
            }
            closedir(ad);
        }
        json_object* u = json_object_new_object();
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

/* ==================== 命令处理 ==================== */
/* 构建当前支持规则类型列表（含动态模块类型），供 PING/LIST/STATUS 返回。
   lang：前端请求的语言（如 "en"），为空默认 "zh"；
   每个类型回传匹配语言的 desc（找不到回退 zh），并附 desc_map 全语言映射
   与 argc_min/argc_max 参数约束，供前端动态渲染任意模块的规则输入框 */
static json_object* build_rule_types_json(const char* lang) {
    if (!lang || !*lang) lang = "zh";
    json_object* arr = json_object_new_array();
    for (int i = 0; i < g_rule_type_count; i++) {
        json_object* t = json_object_new_object();
        json_object_object_add(t, "type", json_object_new_string(g_rule_types[i].name));
        const char* fmt_s = "path";
        if (g_rule_types[i].fmt == RFT_PAIR)
            fmt_s = "pair";
        else if (g_rule_types[i].fmt == RFT_SWITCH)
            fmt_s = "switch";
        else if (g_rule_types[i].fmt == RFT_TOKENS)
            fmt_s = "tokens";
        json_object_object_add(t, "format", json_object_new_string(fmt_s));
        json_object_object_add(t, "builtin", json_object_new_boolean(g_rule_types[i].builtin));
        json_object_object_add(t, "module", json_object_new_string(g_rule_types[i].module));
        json_object_object_add(t, "global_only",
                               json_object_new_boolean(g_rule_types[i].global_only));
        json_object_object_add(t, "argc_min", json_object_new_int(g_rule_types[i].argc_min));
        json_object_object_add(t, "argc_max", json_object_new_int(g_rule_types[i].argc_max));
        /* 多语言描述：按请求语言选取（回退 zh），并附全语言 desc_map */
        const char* match = nullptr;
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
            json_object* dmap = json_object_new_object();
            for (int d = 0; d < g_rule_types[i].desc_count; d++)
                json_object_object_add(dmap, g_rule_types[i].descs[d].lang,
                                       json_object_new_string(g_rule_types[i].descs[d].text));
            json_object_object_add(t, "desc_map", dmap);
        }
        json_object_array_add(arr, t);
    }
    return arr;
}

static void handle_ping(int fd, json_object* req) {
    (void)req;
    json_object* data = json_object_new_object();
    json_object_object_add(data, "pong", json_object_new_boolean(true));
    json_object_object_add(data, "version", json_object_new_string(RULE_VERSION));
    json_object_object_add(data, "config_dir", json_object_new_string(g_config_dir));
    json_object_object_add(data, "socket", json_object_new_string(g_socket_name));
    const char* lang = json_object_get_string(json_object_object_get(req, "lang"));
    json_object_object_add(data, "rule_types", build_rule_types_json(lang));
    reply_ok(fd, "PING", data);
}

/* UPTIME：查询本守护进程运行时长（CLOCK_MONOTONIC 单调时钟，不受系统
   改时间影响）。data：uptime_seconds（整数秒）、uptime（人类可读时长）、
   started_at（启动墙钟时间戳，epoch 秒） */
static void handle_uptime(int fd, json_object* req) {
    (void)req;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long long secs = (long long)(now.tv_sec - g_start_mono.tv_sec);
    if (secs < 0) secs = 0; /* 时钟异常兜底 */
    json_object* data = json_object_new_object();
    json_object_object_add(data, "uptime_seconds", json_object_new_int64(secs));
    char human[64];
    long long d = secs / 86400, h = (secs % 86400) / 3600, m = (secs % 3600) / 60, s = secs % 60;
    if (d > 0)
        snprintf(human, sizeof human, "%lld天%lld小时%lld分%lld秒", d, h, m, s);
    else if (h > 0)
        snprintf(human, sizeof human, "%lld小时%lld分%lld秒", h, m, s);
    else
        snprintf(human, sizeof human, "%lld分%lld秒", m, s);
    json_object_object_add(data, "uptime", json_object_new_string(human));
    json_object_object_add(data, "started_at", json_object_new_int64((int64_t)g_start_wall));
    reply_ok(fd, "UPTIME", data);
}

static void handle_list(int fd, json_object* req) {
    (void)req;
    json_object* data = json_object_new_object();
    const char* lang = json_object_get_string(json_object_object_get(req, "lang"));
    json_object_object_add(data, "rule_types", build_rule_types_json(lang));
    json_object_object_add(data, "global", build_global_json());
    json_object_object_add(data, "apps", build_apps_json());
    reply_ok(fd, "LIST", data);
}

static void handle_get(int fd, json_object* req) {
    const char* pkg = json_object_get_string(json_object_object_get(req, "pkg"));
    int uid = json_object_get_int(json_object_object_get(req, "uid"));
    if (uid < 0) uid = 0;
    /* GET 不带 pkg 时：返回全局 + 指定用户（uid 参数）的全部应用；
       前端可用 GET {"uid":10} 只取某个用户空间的配置 */
    if (!pkg || strcasecmp(pkg, "GLOBAL") == 0) {
        json_object* data = json_object_new_object();
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
    /* 类别段视图：主文件内精确段头切片；索引为**段内**局部序号，
       与 REMOVE/TOGGLE 的 scope 口径同源（§A5） */
    if (nsp_rule_file_is_category_pkg(pkg)) {
        json_object* data = json_object_new_object();
        json_object_object_add(data, "category", build_category_json(pkg, uid));
        reply_ok(fd, "GET", data);
        return;
    }
    if (!valid_pkg(pkg)) {
        reply_error(fd, "GET", "非法包名: %s", pkg ? pkg : "(null)");
        return;
    }
    json_object* data = json_object_new_object();
    json_object_object_add(data, "app", build_app_json(pkg, uid));
    reply_ok(fd, "GET", data);
}

/* USERS：列出全部已配置用户（App-rules 与 App-rules-<uid> 目录），
   前端可据此遍历多用户空间 */
static void handle_users(int fd, json_object* req) {
    (void)req;
    json_object* data = json_object_new_object();
    json_object_object_add(data, "users", build_users_json());
    reply_ok(fd, "USERS", data);
}

/* 依据类型构建规则行文本；返回 0 成功，-1 参数错误 */
static int build_rule_line(RuleType t, const char* value, char* line, size_t sz) {
    if (t < 0 || t >= g_rule_type_count) return -1;
    const char* name = rule_type_name(t);
    RuleFmt fmt = g_rule_types[t].fmt;
    if (fmt == RFT_SWITCH) {
        if (!value || (strcasecmp(value, "ON") != 0 && strcasecmp(value, "OFF") != 0)) return -1;
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
        const char* p = value;
        bool first = true;
        int tok_count = 0;
        while (*p) {
            char tok[MAX_LINE];
            size_t tlen = 0;
            while (*p && *p != '|' && tlen < sizeof(tok) - 1) tok[tlen++] = *p++;
            tok[tlen] = '\0';
            if (tlen == 0) return -1; /* 空 token（如 /a||/b）非法 */
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
static void handle_add(int fd, json_object* req) {
    const char* pkg = json_object_get_string(json_object_object_get(req, "pkg"));
    const char* type_s = json_object_get_string(json_object_object_get(req, "type"));
    const char* value = json_object_get_string(json_object_object_get(req, "value"));
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
    /* 类别段（[USER_APPS:<uid>]/[SYSTEM_APPS]）：写主文件精确段头 */
    bool is_category = (!is_global && nsp_rule_file_is_category_pkg(pkg));

    /* INJECT_ENABLE：应用规则启用/停用总开关。
       通过重命名 App-rules/<pkg>.conf ↔ <pkg>.conf.disabled 实现：
       OFF（停用）→ 加 .disabled 后缀，解析器跳过该文件（规则不生效）；
       ON（启用） → 去掉 .disabled 后缀，规则重新生效。
       全程不接触 injector.conf（其 [pkg:uid] 段头仅控制注入挂载）。
       类别段无分文件：启停请直接编辑主文件段头 ON/OFF。 */
    if (strcasecmp(type_s, "INJECT_ENABLE") == 0) {
        if (is_global || is_category) {
            reply_error(fd, "ADD", "INJECT_ENABLE 仅适用于应用作用域");
            return;
        }
        if (!valid_pkg(pkg)) {
            reply_error(fd, "ADD", "非法包名: %s", pkg);
            return;
        }
        bool on = (value && strcasecmp(value, "ON") == 0);
        char dir[PATH_MAX], path[PATH_MAX], dis_path[PATH_MAX];
        nsp_app_rule_dir(g_config_dir, uid, dir, sizeof(dir));
        nsp_app_rule_path(g_config_dir, uid, pkg, path, sizeof(path));
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
                if (nsp_mkdir_p(dir, 0755) != 0) {
                    reply_error(fd, "ADD", "无法创建目录 %s: %s", dir, strerror(errno));
                    return;
                }
                FILE* fp = fopen(path, "w");
                if (!fp) {
                    reply_error(fd, "ADD", "创建 %s 失败: %s", path, strerror(errno));
                    return;
                }
                fclose(fp);
            }
        } else {
            if (active_exists) {
                if (nsp_mkdir_p(dir, 0755) != 0) {
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
        json_object* data = json_object_new_object();
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
    /* 全局专属类型（GLOBAL_INJECT/SKIP_SYSTEM_APPS）：仅 [GLOBAL] 段可用
       （类别段同样拒绝，is_category 非全局） */
    if (!is_global && g_rule_types[t].global_only) {
        reply_error(fd, "ADD", "规则类型 %s 仅可在全局规则中使用，不能配置到应用 %s", type_s, pkg);
        return;
    }
    char line[MAX_LINE];
    if (build_rule_line(t, value, line, sizeof(line)) != 0) {
        reply_error(fd, "ADD", "规则值不合法: %s", value ? value : "(null)");
        return;
    }

    if (is_global || is_category) {
        /* GLOBAL/类别段：写入 injector.conf 的对应段（开关段内替换/规则去重插入）。
           段名不含方括号（段头由共享实现构造）：GLOBAL 用前缀匹配以兼容
           [GLOBAL:...]；类别段用精确段头（[USER_APPS:<uid>]/[SYSTEM_APPS]），
           避免与裸 [USER_APPS] 混淆；USER_APPS 按请求 uid 落段（默认 0）。 */
        char sec_name[64];
        NspRuleSectionMatch sec_match;
        if (is_category) {
            nsp_rule_file_category_name(pkg, uid, sec_name, sizeof sec_name);
            sec_match = NSP_RULE_SEC_EXACT;
        } else {
            snprintf(sec_name, sizeof sec_name, "GLOBAL");
            sec_match = NSP_RULE_SEC_PREFIX;
        }
        char conf[PATH_MAX];
        main_conf_path(conf, sizeof(conf));
        if (nsp_mkdir_p(g_config_dir, 0755) != 0) {
            reply_error(fd, "ADD", "无法创建配置目录 %s: %s", g_config_dir, strerror(errno));
            return;
        }
        bool changed = false;
        int rc = nsp_rule_file_upsert_in_section(conf, sec_name, sec_match, is_switch_type(t),
                                                 rule_type_name(t), line, &changed);
        if (rc != NSP_RULE_FILE_OK) {
            reply_error(fd, "ADD", "写入 %s 失败: %s", conf, strerror(errno));
            return;
        }
        json_object* data = json_object_new_object();
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
    nsp_app_rule_dir(g_config_dir, uid, dir, sizeof(dir));
    nsp_rule_file_app_active_path(g_config_dir, uid, pkg, path, sizeof(path));
    if (nsp_mkdir_p(dir, 0755) != 0) {
        reply_error(fd, "ADD", "无法创建目录 %s: %s", dir, strerror(errno));
        return;
    }
    {
        /* 无段结构文件：开关就地替换（保持唯一），规则行全文件去重后追加 */
        bool changed = false;
        int rc =
            nsp_rule_file_upsert_line(path, is_switch_type(t), rule_type_name(t), line, &changed);
        if (rc != NSP_RULE_FILE_OK) {
            reply_error(fd, "ADD", "写入 %s 失败: %s", path, strerror(errno));
            return;
        }
        json_object* data = json_object_new_object();
        json_object_object_add(data, "file", json_object_new_string(path));
        json_object_object_add(data, "line", json_object_new_string(line));
        json_object_object_add(data, "changed", json_object_new_boolean(changed));
        reply_ok(fd, "ADD", data);
    }
}

/* 定位规则所在文件与**作用域**（索引口径）。
 *   GLOBAL / 类别段 → 主配置文件，作用域限定在该段（段内索引）；
 *   应用            → 应用规则**当前生效**文件（停用状态为 .conf.disabled，
 *                     保证后续操作写同一文件、不丢规则），作用域为整文件。
 * 作用域必须与 GET 输出一致：GET 类别段只回段内切片、GET GLOBAL 只回 [GLOBAL]
 * 段；若删除/切换仍按整文件全局序号计数，就会删错规则（§A5）。 */
typedef struct {
    char path[PATH_MAX];
    char sec[64];        /* scope.sec_name 的存储（NULL 时不用） */
    NspRuleScope scope;  /* sec_name == NULL 表示整文件 */
} RuleTarget;

static void resolve_rule_target(const char* pkg, int uid, RuleTarget* t) {
    memset(t, 0, sizeof *t);
    t->scope.sec_match = NSP_RULE_SEC_EXACT;
    if (!pkg || strcasecmp(pkg, "GLOBAL") == 0) {
        main_conf_path(t->path, sizeof(t->path));
        snprintf(t->sec, sizeof(t->sec), "GLOBAL");
        t->scope.sec_name = t->sec;
        t->scope.sec_match = NSP_RULE_SEC_PREFIX;
        return;
    }
    if (nsp_rule_file_is_category_pkg(pkg)) {
        main_conf_path(t->path, sizeof(t->path));
        nsp_rule_file_category_name(pkg, uid, t->sec, sizeof(t->sec));
        t->scope.sec_name = t->sec;
        return;
    }
    nsp_rule_file_app_active_path(g_config_dir, uid, pkg, t->path, sizeof(t->path));
    t->scope.sec_name = NULL;
}

/* REMOVE：按 (类型, 索引) 删除规则行（索引与 LIST 输出一致，含已停用行） */
static void handle_remove(int fd, json_object* req) {
    const char* pkg = json_object_get_string(json_object_object_get(req, "pkg"));
    const char* type_s = json_object_get_string(json_object_object_get(req, "type"));
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
    if (!is_switch_type(t) && strcmp(pkg, "GLOBAL") != 0 && !nsp_rule_file_is_category_pkg(pkg) &&
        !valid_pkg(pkg)) {
        reply_error(fd, "REMOVE", "非法包名: %s", pkg);
        return;
    }
    RuleTarget tgt;
    resolve_rule_target(pkg, uid, &tgt);
    /* 索引计入已停用行，且限定在该段内（与 GET 展示索引一致） */
    char removed[MAX_LINE];
    int rc = nsp_rule_file_remove_nth_scoped(tgt.path, &tgt.scope, rule_type_name(t), index, removed,
                                             sizeof removed);
    if (rc == NSP_RULE_FILE_ENOTFND) {
        reply_error(fd, "REMOVE", "未找到 %s 类型的第 %d 条规则", type_s, index);
        return;
    }
    if (rc != NSP_RULE_FILE_OK) {
        reply_error(fd, "REMOVE", "写入 %s 失败: %s", tgt.path, strerror(errno));
        return;
    }
    json_object* data = json_object_new_object();
    json_object_object_add(data, "file", json_object_new_string(tgt.path));
    json_object_object_add(data, "removed", json_object_new_string(removed));
    reply_ok(fd, "REMOVE", data);
}

/* ENABLE / DISABLE：切换规则行的 # 注释状态（停用行被解析器跳过） */
static void handle_toggle(int fd, json_object* req, bool enable) {
    const char* cmd = enable ? "ENABLE" : "DISABLE";
    const char* pkg = json_object_get_string(json_object_object_get(req, "pkg"));
    const char* type_s = json_object_get_string(json_object_object_get(req, "type"));
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
    if (strcmp(pkg, "GLOBAL") != 0 && !nsp_rule_file_is_category_pkg(pkg) && !valid_pkg(pkg)) {
        reply_error(fd, cmd, "非法包名: %s", pkg);
        return;
    }
    RuleTarget tgt;
    resolve_rule_target(pkg, uid, &tgt);
    /* 加锁事务：读-改-写全程持目录 flock，且在**段内**按索引定位（与 GET 一致）。
       此前在调用侧自行「读全文→改一行→覆盖写」既不持锁（并发 ADD 会被旧快照
       覆盖，§A6），索引又是整文件全局序号（会改错类别段的行，§A5）。 */
    char updated[MAX_LINE];
    bool changed = false;
    int rc = nsp_rule_file_toggle_nth_scoped(tgt.path, &tgt.scope, rule_type_name(t), index, enable,
                                             updated, sizeof updated, &changed);
    if (rc == NSP_RULE_FILE_ENOTFND) {
        reply_error(fd, cmd, "未找到 %s 类型的第 %d 条规则", type_s, index);
        return;
    }
    if (rc != NSP_RULE_FILE_OK) {
        reply_error(fd, cmd, "写入 %s 失败: %s", tgt.path, strerror(errno));
        return;
    }
    json_object* data = json_object_new_object();
    json_object_object_add(data, "file", json_object_new_string(tgt.path));
    json_object_object_add(data, "line", json_object_new_string(updated));
    json_object_object_add(data, "enabled", json_object_new_boolean(enable));
    json_object_object_add(data, "changed", json_object_new_boolean(changed));
    reply_ok(fd, cmd, data);
}

/* SET：设置开关（MONITOR/SANDBOX/GLOBAL_INJECT）或应用注入开关，
   复用 ADD 的写入逻辑 */
static void handle_set(int fd, json_object* req) {
    handle_add(fd, req);
}

/* 向 injector 发送信号（SIGHUP 重载 / SIGTERM 停止） */
static void signal_injector(int fd, const char* cmd, int sig) {
    char path[PATH_MAX];
    injector_pid_path(path, sizeof(path));
    FILE* fp = fopen(path, "r");
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
    json_object* data = json_object_new_object();
    json_object_object_add(data, "pid", json_object_new_int(pid));
    json_object_object_add(data, "signal", json_object_new_int(sig));
    json_object_object_add(data, "action",
                           json_object_new_string(sig == SIGHUP ? "reload" : "stop"));
    reply_ok(fd, cmd, data);
}

/* ==================== 服务状态查询（SERVICE API） ==================== */

static bool proc_alive(int pid) {
    if (pid <= 0) return false;
    /* 僵尸进程（kill(pid,0) 仍成功但已退出）：读 /proc/<pid>/stat 的 state
       字段（pid (comm) state ...，state 在最后一个 ')' 之后）判别 */
    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    FILE* fp = fopen(stat_path, "r");
    if (fp) {
        char buf[256] = {0};
        if (fgets(buf, sizeof(buf), fp)) {
            char* rp = strrchr(buf, ')');
            if (rp && rp[1] == ' ' && (rp[2] == 'Z' || rp[2] == 'z')) {
                fclose(fp);
                return false; /* 僵尸视为已退出 */
            }
        }
        fclose(fp);
    }
    return (kill(pid, 0) == 0 || errno == EPERM);
}

/* 扫描 /proc/<pid>/comm 匹配进程名，返回第一个**存活**匹配 pid（跳过僵尸）；
   未找到返回 0 */
static int find_proc_pid(const char* name) {
    DIR* d = opendir("/proc");
    if (!d) return 0;
    struct dirent* de;
    int found = 0;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        int pid = atoi(de->d_name);
        if (pid <= 0 || pid == (int)getpid()) continue; /* 排除自身 */
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        FILE* fp = fopen(comm_path, "r");
        if (!fp) continue;
        char buf[64] = {0};
        if (fgets(buf, sizeof(buf), fp)) {
            buf[strcspn(buf, "\n")] = '\0';
            if (strcmp(buf, name) == 0) {
                fclose(fp);
                if (proc_alive(pid)) {
                    found = pid;
                    break;
                } /* 跳过僵尸，取存活实例 */
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
    FILE* fp = fopen(path, "r");
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
static json_object* build_proc_json(int pid) {
    json_object* o = json_object_new_object();
    json_object_object_add(o, "pid", json_object_new_int(pid));
    json_object_object_add(o, "alive", json_object_new_boolean(proc_alive(pid)));
    return o;
}

/* SERVICE status：查询 log_monitor / injector / fuse_daemon / rule_server 状态 */
static void handle_service_status(int fd, json_object* req) {
    (void)req;
    int injector_pid = read_injector_pid();
    int fuse_pid = find_proc_pid("fuse_daemon");
    int log_pid = find_proc_pid("log_monitor");
    json_object* data = json_object_new_object();
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
static void self_bin_dir(char* out, size_t sz) {
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) {
        snprintf(out, sz, ".");
        return;
    }
    exe[n] = '\0';
    char* slash = strrchr(exe, '/');
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
    for (int i = 0; i < 50 && proc_alive(pid); i++) usleep(10000); /* 宽限 500ms */
    if (proc_alive(pid)) {
        kill(pid, SIGKILL); /* 兜底强杀 */
        for (int i = 0; i < 50 && proc_alive(pid); i++) usleep(10000);
    }
    return proc_alive(pid) ? -1 : 0;
}

/* 启动一个守护进程：双 fork + exec（setsid 脱离会话，防 shell 退出连带 kill）。
   双 fork 让实际守护进程被 init 收养，rule_server 只回收中间子进程——避免
   守护进程退出后在其下留僵尸（§A7-1）。
   argv 以 NULL 结尾；成功返回 >0，失败返回 -1 */
static int spawn_daemon(const char* path, char* const argv[]) {
    if (!path || access(path, X_OK) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        setsid();
        pid_t pid2 = fork();
        if (pid2 < 0) _exit(127);
        if (pid2 > 0) _exit(0); /* 中间子进程退出，孙进程由 init 收养 */
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
    /* 回收中间子进程（不阻塞：其 setsid+fork 后立即退出） */
    int st;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return (int)pid;
}

/* 停止全部服务：injector（SIGTERM，其自行清理 fuse_daemon）、log_monitor、fuse_daemon。
   执行层：不发送响应，统计结果写入 out_stopped / out_failed */
static void service_stop_all_exec(int* out_stopped, int* out_failed) {
    int injector_pid = read_injector_pid();
    int log_pid = find_proc_pid("log_monitor");
    int fuse_pid = find_proc_pid("fuse_daemon");
    int stopped = 0, failed = 0;
    if (injector_pid > 0 && proc_alive(injector_pid)) {
        if (stop_proc(injector_pid, SIGTERM) == 0)
            stopped++;
        else
            failed++;
    }
    if (fuse_pid > 0 && proc_alive(fuse_pid)) {
        if (stop_proc(fuse_pid, SIGTERM) == 0)
            stopped++;
        else
            failed++;
    }
    if (log_pid > 0 && proc_alive(log_pid)) {
        if (stop_proc(log_pid, SIGTERM) == 0)
            stopped++;
        else
            failed++;
    }
    if (out_stopped) *out_stopped = stopped;
    if (out_failed) *out_failed = failed;
}

static void service_stop_all(int fd, const char* cmd) {
    int stopped = 0, failed = 0;
    service_stop_all_exec(&stopped, &failed);
    json_object* data = json_object_new_object();
    json_object_object_add(data, "action", json_object_new_string("stop"));
    json_object_object_add(data, "stopped", json_object_new_int(stopped));
    json_object_object_add(data, "failed", json_object_new_int(failed));
    reply_ok(fd, cmd, data);
}

/* 启动全部服务（等价 service.sh 的拉起逻辑）：
   先清理残留进程，再按 log_monitor → injector 顺序启动（fuse_daemon 由 injector 拉取）。
   执行层：不发送响应，统计结果写入 out_started / out_failed */
static void service_start_all_exec(int* out_started, int* out_failed) {
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
        char* argv_log[] = {"log_monitor", NULL};
        if (spawn_daemon(log_path, argv_log) > 0)
            started++;
        else
            failed++;
    }
    /* injector：主控（--passive 与 service.sh 一致），其内部拉起 fuse_daemon */
    if (access(inj_path, X_OK) == 0) {
        char* argv_inj[] = {"injector", "--passive", NULL};
        if (spawn_daemon(inj_path, argv_inj) > 0)
            started++;
        else
            failed++;
    }
    if (out_started) *out_started = started;
    if (out_failed) *out_failed = failed;
}

static void service_start_all(int fd, const char* cmd) {
    int started = 0, failed = 0;
    service_start_all_exec(&started, &failed);
    char bin_dir[PATH_MAX];
    self_bin_dir(bin_dir, sizeof(bin_dir));
    json_object* data = json_object_new_object();
    json_object_object_add(data, "action", json_object_new_string("start"));
    json_object_object_add(data, "started", json_object_new_int(started));
    json_object_object_add(data, "failed", json_object_new_int(failed));
    json_object_object_add(data, "bin_dir", json_object_new_string(bin_dir));
    reply_ok(fd, cmd, data);
}

/* SERVICE 命令分发：status / start / stop / restart */
static void handle_service(int fd, json_object* req) {
    const char* action = json_object_get_string(json_object_object_get(req, "action"));
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
        json_object* data = json_object_new_object();
        json_object_object_add(data, "action", json_object_new_string("restart"));
        json_object_object_add(data, "stopped", json_object_new_int(stopped));
        json_object_object_add(data, "started", json_object_new_int(started));
        json_object_object_add(data, "failed", json_object_new_int(failed_stop + failed_start));
        reply_ok(fd, "SERVICE", data);
        return;
    }
    reply_error(fd, "SERVICE", "未知 action: %s（支持 status/start/stop/restart）", action);
}

static void handle_reload(int fd, json_object* req) {
    (void)req;
    signal_injector(fd, "RELOAD", SIGHUP);
}

static void handle_stop(int fd, json_object* req) {
    (void)req;
    signal_injector(fd, "STOP", SIGTERM);
}

static void handle_status(int fd, json_object* req) {
    (void)req;
    int injector_pid = -1;
    bool injector_alive = false;
    char path[PATH_MAX];
    injector_pid_path(path, sizeof(path));
    FILE* fp = fopen(path, "r");
    if (fp) {
        if (fscanf(fp, "%d", &injector_pid) == 1 && injector_pid > 0) {
            injector_alive = (kill(injector_pid, 0) == 0 || errno == EPERM);
        }
        fclose(fp);
    }
    json_object* data = json_object_new_object();
    json_object_object_add(data, "version", json_object_new_string(RULE_VERSION));
    json_object_object_add(data, "config_dir", json_object_new_string(g_config_dir));
    json_object_object_add(data, "socket", json_object_new_string(g_socket_name));
    json_object* inj = json_object_new_object();
    json_object_object_add(inj, "pid", json_object_new_int(injector_pid));
    json_object_object_add(inj, "alive", json_object_new_boolean(injector_alive));
    json_object_object_add(data, "injector", inj);
    json_object_object_add(data, "global", build_global_json());
    reply_ok(fd, "STATUS", data);
}

/* ==================== EXPORT_LOGS：一键导出日志 ====================
   把 <CONFIG_DIR>/log 整目录 tar.gz 到 <CONFIG_DIR>/export/（root 私有 0700），
   只保留最新 LOG_EXPORT_KEEP 份；供前端经 UDS 取回或 root 侧显式 copy-out。

   落点为何**不在**共享存储（review-findings §A7-0 / §A7-4）：
   1. io.log 记录全部应用的文件访问路径，投递到 /sdcard 等于对所有有存储权限的
      应用公开，与本栈既有脱敏姿态（模块配置密码只写不读、nsp_ini_save 收紧
      0600）方向相反；
   2. /sdcard 由本 FUSE 承载、任意应用可写，且旧实现的文件名只含 time(NULL)
      完全可预测，root 身份的 tar/chmod 会跟随应用预置的软链覆盖 injector.conf
      或模块 .so 并放宽其权限——在本栈上是**确定的提权原语**。
   故落点搬到 root 私有目录，创建带 O_CREAT|O_EXCL|O_NOFOLLOW，权限经 fchmod 施加。

   执行模型：同步等待但**有界**——WNOHANG 轮询 + 硬超时 SIGKILL，避免 tar 卡在
   慢存储时唯一 epoll 事件循环无限停摆（SIGTERM 亦可在轮询间隙生效）。 */
#define LOG_EXPORT_KEEP       1
#define LOG_EXPORT_TIMEOUT_MS 10000

/* 在候选路径中挑第一个可执行的 tar（Android /system/bin、通用 /bin、/usr/bin）。
   绝对路径直接 execl，不依赖继承 PATH（与旧实现的口径差异见 §A7-6）。 */
static const char* export_logs_tar_path(void) {
    static const char* const cands[] = {"/system/bin/tar", "/bin/tar", "/usr/bin/tar"};
    for (size_t i = 0; i < sizeof(cands) / sizeof(cands[0]); i++) {
        if (access(cands[i], X_OK) == 0) return cands[i];
    }
    return NULL;
}

/* 导出包所在目录：<CONFIG_DIR>/export（root 私有；随 --config-dir 走，GNU 可测） */
static void export_logs_dir(char* out, size_t sz) {
    snprintf(out, sz, "%s/export", g_config_dir);
}

/* 是否为导出包名（宽前缀 + 后缀） */
static bool export_logs_is_pkg(const char* name) {
    static const char* const prefix = "log_export_";
    static const char* const suffix = ".tar.gz";
    size_t plen = strlen(prefix), slen = strlen(suffix), nlen = strlen(name);
    return nlen >= plen + slen && strncmp(name, prefix, plen) == 0 &&
           strcmp(name + nlen - slen, suffix) == 0;
}

/* 按宽前缀扫描，删除最旧的使剩余 ≤ keep 份；返回实际删除数。
   循环删除而非只删一份：目录里堆积 N 份时一次调用即收敛（§A7-2）。 */
static int export_logs_prune(const char* dir, int keep) {
    int removed = 0;
    for (;;) {
        DIR* d = opendir(dir);
        if (!d) break;
        char oldest[PATH_MAX] = {0};
        time_t oldest_mtime = 0;
        int count = 0;
        struct dirent* de;
        while ((de = readdir(d))) {
            if (!export_logs_is_pkg(de->d_name)) continue;
            char p[PATH_MAX];
            snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
            struct stat st;
            if (lstat(p, &st) != 0) continue; /* 不跟随软链 */
            count++;
            if (!oldest[0] || st.st_mtime < oldest_mtime ||
                (st.st_mtime == oldest_mtime && strcmp(p, oldest) < 0)) {
                oldest_mtime = st.st_mtime;
                snprintf(oldest, sizeof(oldest), "%s", p);
            }
        }
        closedir(d);
        if (count <= keep || !oldest[0]) break;
        if (unlink(oldest) != 0) break;
        removed++;
    }
    return removed;
}

static void handle_export_logs(int fd, json_object* req) {
    (void)req;
    char log_dir[PATH_MAX], exp_dir[PATH_MAX], out[PATH_MAX];
    snprintf(log_dir, sizeof(log_dir), "%s/log", g_config_dir);

    const char* tar_bin = export_logs_tar_path();
    if (!tar_bin) {
        reply_error(fd, "EXPORT_LOGS", "未找到 tar 可执行文件");
        return;
    }
    struct stat st;
    if (stat(log_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        reply_error(fd, "EXPORT_LOGS", "日志目录不存在: %s", log_dir);
        return;
    }
    /* 导出目录：root 私有 0700（幂等收紧，已存在时也保证私有） */
    export_logs_dir(exp_dir, sizeof(exp_dir));
    if (nsp_mkdir_p(exp_dir, 0700) != 0) {
        reply_error(fd, "EXPORT_LOGS", "创建导出目录失败: %s: %s", exp_dir, strerror(errno));
        return;
    }
    (void)chmod(exp_dir, 0700);

    /* 唯一包名：时间 + pid + 递增序号，避免同秒多次导出互相覆盖（§A7-2） */
    static unsigned s_export_seq = 0;
    snprintf(out, sizeof(out), "%s/log_export_%ld_%d_%u.tar.gz", exp_dir, (long)time(NULL),
             (int)getpid(), s_export_seq++);

    /* 以 O_EXCL|O_NOFOLLOW 占名：不覆盖既有文件、不跟随软链（§A7-0） */
    int ofd = open(out, O_CREAT | O_EXCL | O_NOFOLLOW | O_WRONLY | O_CLOEXEC, 0600);
    if (ofd < 0) {
        reply_error(fd, "EXPORT_LOGS", "创建导出文件失败: %s: %s", out, strerror(errno));
        return;
    }
    close(ofd); /* 名字已安全占位；tar 随后 O_TRUNC 复用（目录私有，无软链窗口） */

    pid_t pid = fork();
    if (pid < 0) {
        int e = errno;
        unlink(out);
        reply_error(fd, "EXPORT_LOGS", "fork 失败: %s", strerror(e));
        return;
    }
    if (pid == 0) {
        int nullfd = open("/dev/null", O_RDWR);
        if (nullfd >= 0) {
            dup2(nullfd, 0);
            dup2(nullfd, 1);
            dup2(nullfd, 2);
            if (nullfd > 2) close(nullfd);
        }
        execl(tar_bin, "tar", "-czf", out, "-C", log_dir, ".", (char*)NULL);
        _exit(127);
    }

    /* 有界等待：WNOHANG 轮询 + 硬超时 kill，避免慢存储把唯一事件循环卡死（§A7-1） */
    int status = 0;
    bool reaped = false, timed_out = false, wait_err = false;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            reaped = true;
            break;
        }
        if (w < 0) {
            if (errno == EINTR) continue;
            wait_err = true;
            break;
        }
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long ms = (long)(now.tv_sec - t0.tv_sec) * 1000 + (now.tv_nsec - t0.tv_nsec) / 1000000;
        if (ms >= LOG_EXPORT_TIMEOUT_MS || g_should_exit) {
            timed_out = true;
            kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            break;
        }
        usleep(20000);
    }
    if (timed_out) {
        unlink(out);
        reply_error(fd, "EXPORT_LOGS", "导出超时（>%d ms），已终止", LOG_EXPORT_TIMEOUT_MS);
        return;
    }
    if (wait_err) {
        int e = errno;
        unlink(out);
        reply_error(fd, "EXPORT_LOGS", "等待 tar 失败: %s", strerror(e));
        return;
    }
    /* 失败应答据实：区分信号死亡 / 非零退出，不再用残留 errno 冒充原因（§A7-3） */
    if (reaped && WIFSIGNALED(status)) {
        unlink(out);
        reply_error(fd, "EXPORT_LOGS", "tar 被信号 %d 终止", WTERMSIG(status));
        return;
    }
    if (!reaped || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        int code = (reaped && WIFEXITED(status)) ? WEXITSTATUS(status) : -1;
        unlink(out);
        reply_error(fd, "EXPORT_LOGS", "tar 打包失败（exit=%d）", code);
        return;
    }

    /* 收紧权限并取大小：经 fd（O_NOFOLLOW）施加，不跟随软链（§A7-0） */
    int rfd = open(out, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (rfd < 0) {
        unlink(out);
        reply_error(fd, "EXPORT_LOGS", "导出产物缺失: %s", out);
        return;
    }
    fchmod(rfd, 0600);
    struct stat stf;
    if (fstat(rfd, &stf) != 0) {
        int e = errno;
        close(rfd);
        unlink(out);
        reply_error(fd, "EXPORT_LOGS", "读取导出产物失败: %s", strerror(e));
        return;
    }
    close(rfd);

    /* 成功发布后按宽前缀收敛到 LOG_EXPORT_KEEP 份（含本次） */
    int pruned = export_logs_prune(exp_dir, LOG_EXPORT_KEEP);

    json_object* data = json_object_new_object();
    json_object_object_add(data, "file", json_object_new_string(out));
    json_object_object_add(data, "dir", json_object_new_string(exp_dir));
    json_object_object_add(data, "size_bytes", json_object_new_int64((long long)stf.st_size));
    json_object_object_add(data, "generated_at", json_object_new_int64((long long)time(NULL)));
    json_object_object_add(data, "pruned", json_object_new_int(pruned));
    reply_ok(fd, "EXPORT_LOGS", data);
}

static void handle_quit(int fd, json_object* req) {
    (void)req;
    g_should_exit = 1;
    reply_ok(fd, "QUIT", NULL);
}

/* ==================== 模块配置 schema（<模块名>.conf 的字段声明） ====================
 * 目的：把「模块配置有哪些字段、各字段的类型/上限/是否敏感/缺省/可选值/显示顺序」
 * 从 C 代码搬到模块自带的声明文件（`<模块名>.rules` 的 `[conf]` 段），与 .rules 的
 * 规则类型声明**同一解析器、同一扫描路径**，于是新增一个配置项不必改 C、不必
 * 重新编译发布——模块自带的声明文件即契约。
 *
 * 边界（重要，不得越界）：
 *   - schema **只服务控制面校验与前端渲染**，不改变配置读取归属：框架依旧把
 *     原始行原样下发给模块、模块自己解析（docs/modules.md §6.1.1）。
 *   - 敏感字段（`sensitive`）沿用并**升级**既有「密码只写不读」：此前只有
 *     password 一个键享受特判，现按 schema 判定，新增敏感字段自动脱敏。
 *   - 未声明 [conf] 段时回退编译期默认表（见 modconf_load_defaults），旧包照旧。
 */


/* 取字段（按 key 精确匹配；未命中返回 NULL） */
static const ModConfField* modconf_find(const ModConfSchema* sc, const char* key) {
    if (!sc || !key) return NULL;
    for (int i = 0; i < sc->count; i++)
        if (strcasecmp(sc->fields[i].key, key) == 0) return &sc->fields[i];
    return NULL;
}

/* 值是否命中该字段的可选值集合（enum 未声明时恒真） */
static bool modconf_enum_hit(const ModConfField* f, const char* val) {
    if (f->enum_count <= 0) return true;
    for (int i = 0; i < f->enum_count; i++)
        if (strcasecmp(f->enumvals[i], val) == 0) return true;
    return false;
}

/* 按请求语言取标签：命中对应 lang 槽 → 回退 zh → 再回退键名本身。
   MODULE_SCHEMA 用它输出 desc（前端直接显示，无需自维护中文标签）。 */
static const char* modconf_label(const ModConfField* f, const char* lang) {
    if (lang && lang[0]) {
        for (int i = 0; i < f->desc_count; i++)
            if (strcasecmp(f->descs[i].lang, lang) == 0) return f->descs[i].text;
    }
    for (int i = 0; i < f->desc_count; i++)
        if (strcasecmp(f->descs[i].lang, "zh") == 0) return f->descs[i].text;
    return f->key;
}

#define FTP_NAME_MAX 63
#define FTP_HOST_MAX 255
#define FTP_USER_MAX 63
#define FTP_PASS_MAX 127
#define FTP_RDIR_MAX 511

/* 取（必要时创建）某模块的 schema 槽；表满返回 NULL（调用方判空） */
static ModConfSchema* modconf_for(const char* module) {
    if (!module || !module[0]) return NULL;
    for (int i = 0; i < g_modconf_count; i++)
        if (strcasecmp(g_modconf[i].module, module) == 0) return &g_modconf[i];
    for (int i = 0; i < MODCONF_MAX_MODULES; i++) {
        if (g_modconf[i].module[0] == '\0') {
            if (i >= g_modconf_count) g_modconf_count = i + 1;
            snprintf(g_modconf[i].module, sizeof g_modconf[i].module, "%s", module);
            return &g_modconf[i];
        }
    }
    LOG("模块配置 schema 模块数超上限 %d，忽略 %s", MODCONF_MAX_MODULES, module);
    return NULL;
}

/* 编译期默认表：与旧 FTP_* 白名单逐字等价，仅在模块未声明 [conf] 段时使用 */
static void modconf_load_defaults(ModConfSchema* sc) {
    sc->count = 0;
    sc->loaded = false;
    /* name(host/user≤63、pass≤127、remote_dir≤511、host≤255) 与旧常量一致 */
    struct {
        const char* key;
        const char* type;
        size_t maxlen;
        bool sensitive;
        const char* def;
        int order;
        int min, max;
        bool has_range;
        bool required;
    } d[] = {
        {"host", "string", FTP_HOST_MAX, false, NULL, 1, 0, 0, false, true},
        {"port", "int", 0, false, "21", 0, 1, 65535, true, false},
        {"user", "string", FTP_USER_MAX, false, "anonymous", 0, 0, 0, false, false},
        {"password", "string", FTP_PASS_MAX, true, NULL, 0, 0, 0, false, false},
        {"remote_dir", "string", FTP_RDIR_MAX, false, "/", 0, 0, 0, false, false},
    };
    for (size_t i = 0; i < sizeof(d) / sizeof(d[0]); i++) {
        ModConfField* f = &sc->fields[sc->count++];
        memset(f, 0, sizeof *f);
        snprintf(f->key, sizeof f->key, "%s", d[i].key);
        snprintf(f->type, sizeof f->type, "%s", d[i].type);
        f->maxlen = d[i].maxlen;
        f->sensitive = d[i].sensitive;
        if (d[i].def) snprintf(f->defval, sizeof f->defval, "%s", d[i].def);
        f->order = d[i].order;
        f->min = d[i].min;
        f->max = d[i].max;
        f->has_range = d[i].has_range;
        f->required = d[i].required;
    }
}

/* 累积 `conf.<字段>.<属性>`：同名字段继续累积，换字段先把上一个落表（CS 无 realloc，
   用固定数组 + 溢出即忽略并告警，避免动态分配失败路径） */
static void modconf_apply(ConfSection* cs, const char* rest, const char* val) {
    /* rest = "<字段>.<属性>"，切出字段名与属性名 */
    const char* dot = strchr(rest, '.');
    if (!dot) return;
    size_t klen = (size_t)(dot - rest);
    if (klen == 0 || klen >= sizeof(cs->cf_key)) return;
    if (cs->cf_key[0] && strncasecmp(cs->cf_key, rest, klen) != 0) modconf_field_commit(cs);
    if (!cs->cf_key[0]) {
        memcpy(cs->cf_key, rest, klen);
        cs->cf_key[klen] = '\0';
    }
    const char* attr = dot + 1;
    if (strcasecmp(attr, "type") == 0) {
        snprintf(cs->cf_type, sizeof cs->cf_type, "%s", val);
    } else if (strcasecmp(attr, "maxlen") == 0) {
        long v = atol(val);
        cs->cf_maxlen = v > 0 ? (size_t)v : 0;
    } else if (strcasecmp(attr, "range") == 0) {
        /* int 值域：range = 1:65535。val 是只读（视图行属框架），拷贝后切分 */
        char buf[64];
        snprintf(buf, sizeof buf, "%s", val);
        char* colon = strchr(buf, ':');
        if (colon) {
            *colon = '\0';
            cs->cf_min = atoi(buf);
            cs->cf_max = atoi(colon + 1);
            cs->cf_has_range = true;
        }
    } else if (strcasecmp(attr, "required") == 0) {
        cs->cf_required = (strcasecmp(val, "true") == 0 || strcasecmp(val, "on") == 0 ||
                           strcmp(val, "1") == 0);
    } else if (strcasecmp(attr, "max") == 0) {
        /* 兼容旧写法：按已声明的 type 解释（string/path=字节上限，int=值域上界） */
        long v = atol(val);
        if (strcasecmp(cs->cf_type, "int") == 0) {
            cs->cf_max = (int)v;
            cs->cf_has_range = true;
        } else {
            cs->cf_maxlen = v > 0 ? (size_t)v : 0;
        }
    } else if (strcasecmp(attr, "sensitive") == 0) {
        cs->cf_sensitive = (strcasecmp(val, "true") == 0 || strcasecmp(val, "on") == 0 ||
                            strcmp(val, "1") == 0);
    } else if (strncasecmp(attr, "default.", 8) == 0) {
        /* 条件缺省：default.<依赖字段>.<依赖取值> = 缺省值（如 default.proto.sftp = 22）。
           命中时覆盖 default；未命中仍用 default。依赖字段自身也可缺省（取其 default）。 */
        const char* d1 = attr + 8;
        const char* d2 = strchr(d1, '.');
        if (d2 && d2 != d1 && d2[1] && (size_t)(d2 - d1) < sizeof cs->cf_cond_dep) {
            snprintf(cs->cf_cond_dep, sizeof cs->cf_cond_dep, "%.*s", (int)(d2 - d1), d1);
            snprintf(cs->cf_cond_val, sizeof cs->cf_cond_val, "%s", d2 + 1);
            snprintf(cs->cf_cond_defval, sizeof cs->cf_cond_defval, "%s", val);
            cs->cf_has_cond = true;
        }
    } else if (strcasecmp(attr, "default") == 0) {
        snprintf(cs->cf_defval, sizeof cs->cf_defval, "%s", val);
    } else if (strcasecmp(attr, "enum") == 0) {
        /* 竖线分隔：enum = ftp|sftp */
        cs->cf_enum_count = 0;
        const char* p = val;
        while (*p && cs->cf_enum_count < MODCONF_MAX_ENUM) {
            const char* e = strchr(p, '|');
            size_t n = e ? (size_t)(e - p) : strlen(p);
            if (n >= sizeof(cs->cf_enum[0])) n = sizeof(cs->cf_enum[0]) - 1;
            memcpy(cs->cf_enum[cs->cf_enum_count], p, n);
            cs->cf_enum[cs->cf_enum_count][n] = '\0';
            cs->cf_enum_count++;
            if (!e) break;
            p = e + 1;
        }
    } else if (strcasecmp(attr, "order") == 0) {
        cs->cf_order = atoi(val);
    } else if (strncasecmp(attr, "desc", 4) == 0) {
        const char* lang = "zh";
        const char* d = attr + 4;
        if (*d == '.') lang = d + 1;
        if (cs->cf_desc_count < MAX_DESC_LANGS) {
            snprintf(cs->cf_descs[cs->cf_desc_count].lang, 8, "%s", lang);
            snprintf(cs->cf_descs[cs->cf_desc_count].text, 160, "%s", val);
            cs->cf_desc_count++;
        }
    }
    /* 未知属性忽略（向前兼容） */
}

/* 把一个累完整的字段落进全局 schema 表 */
static void modconf_field_commit(ConfSection* cs) {
    if (!cs->cf_key[0]) return;
    ModConfSchema* sc = modconf_for(cs->cf_module);
    if (!sc) return;
    if (sc->count >= MODCONF_MAX_FIELDS) {
        LOG("模块配置 schema 字段超上限 %d，忽略 %s", MODCONF_MAX_FIELDS, cs->cf_key);
        cs->cf_key[0] = '\0';
        return;
    }
    ModConfField* f = &sc->fields[sc->count++];
    memset(f, 0, sizeof *f);
    snprintf(f->key, sizeof f->key, "%s", cs->cf_key);
    snprintf(f->type, sizeof f->type, "%s", cs->cf_type[0] ? cs->cf_type : "string");
    f->maxlen = cs->cf_maxlen;
    f->min = cs->cf_min;
    f->max = cs->cf_max;
    f->has_range = cs->cf_has_range;
    f->required = cs->cf_required;
    f->sensitive = cs->cf_sensitive;
    snprintf(f->defval, sizeof f->defval, "%s", cs->cf_defval);
    snprintf(f->cond_dep, sizeof f->cond_dep, "%s", cs->cf_cond_dep);
    snprintf(f->cond_val, sizeof f->cond_val, "%s", cs->cf_cond_val);
    snprintf(f->cond_defval, sizeof f->cond_defval, "%s", cs->cf_cond_defval);
    f->has_cond = cs->cf_has_cond;
    memcpy(f->enumvals, cs->cf_enum, sizeof cs->cf_enum);
    f->enum_count = cs->cf_enum_count;
    f->order = cs->cf_order;
    memcpy(f->descs, cs->cf_descs, sizeof cs->cf_descs);
    f->desc_count = cs->cf_desc_count;
    /* 复位全部累积槽：不复位会让 type/max/sensitive/default/enum/desc 串到下一个
       字段（表现：key_file 继承 proto 的 enum、password 的 sensitive 等） */
    cs->cf_key[0] = '\0';
    cs->cf_type[0] = '\0';
    cs->cf_maxlen = 0;
    cs->cf_min = 0;
    cs->cf_max = 0;
    cs->cf_has_range = false;
    cs->cf_required = false;
    cs->cf_sensitive = false;
    cs->cf_defval[0] = '\0';
    cs->cf_cond_dep[0] = '\0';
    cs->cf_cond_val[0] = '\0';
    cs->cf_cond_defval[0] = '\0';
    cs->cf_has_cond = false;
    cs->cf_enum_count = 0;
    cs->cf_order = 0;
    cs->cf_desc_count = 0;
}

/* [conf] 段结束：提交最后一个字段并标记已加载 */
static void modconf_flush(ConfSection* cs, const char* module) {
    snprintf(cs->cf_module, sizeof cs->cf_module, "%s", module);
    modconf_field_commit(cs);
    ModConfSchema* sc = modconf_for(module);
    if (sc) sc->loaded = (sc->count > 0);
}

#define FTP_MODULE_NAME "ftp_module"

/* 取当前生效 schema：未由 [conf] 段加载过则给编译期默认表（旧包行为不变） */
/* 取某模块 schema：无 [conf] 声明则回退默认表（当前仅 ftp_module 有；其余模块
   拿到空表——它们的配置项本就必须先声明，见 docs/modules.md §2.2） */
static const ModConfSchema* modconf_get(const char* module) {
    ModConfSchema* sc = modconf_for(module);
    if (!sc) return NULL;
    if (!sc->loaded) {
        sc->count = 0;
        if (strcasecmp(module, FTP_MODULE_NAME) == 0) modconf_load_defaults(sc);
        snprintf(sc->module, sizeof sc->module, "%s", module);
    }
    return sc;
}

/* ==================== FTP 服务器账号管理（模块配置文件） ====================
 * 基于 nsp_ini_store 抽象（rule_server 私有静态库，已退出模块 ABI——见
 * nsp_ini_store.h）：注释保留的行级读写 + 临时文件 rename 原子落盘；框架侧
 * fw_config 监听模块目录自动热重载并下发（模块不读文件、不跑 inotify），无需 RELOAD。
 * 落点即框架读取的**同一路径**：`<CONFIG_DIR>/modules/<模块名>/<模块名>.conf`
 * （见 docs/modules.md §6.1.1）——写到这里才会被下发，写到别处等于没配。
 * 安全：password 只写不读——LIST/GET 仅回 has_password 布尔；该文件
 * 本身明文落盘（与模块解析现状一致），文档中明确提示。
 * 段名允许中文（如 [云盘]，不用 valid_pkg），仅禁 \n\r[]（nsp_ini_valid_section）；
 * [GLOBAL] 段非服务器（ftp_conf 跳过），控制面拒绝写入该名。
 * 字段上限与 FtpServerCfg 对应：name≤63、host≤255、user≤63、pass≤127、
 * remote_dir≤511；port 1~65535（缺省 21）；user 缺省 anonymous、
 * remote_dir 缺省 /（LIST/GET 回填生效值，与模块行为一致）。 */


/* 模块配置文件名 = 模块名（框架按 <modules_dir>/<名>/<名>.conf 读取）。
   模块目录取自 g_config_dir（rule_server 的配置根，可经 --config-dir 覆盖），
   与 LIST_MODULES 的目录推导同一口径——**不得**用编译期 MODULES_DIR 宏，
   否则覆盖了配置根的部署会写到一个框架根本不读的位置。 */

/* 通用版：<CONFIG_DIR>/modules/<模块名>/<模块名>.conf（框架读取下发的同一路径） */
static void module_conf_path(char* out, size_t sz, const char* module) {
    snprintf(out, sz, "%s/modules/%s/%s.conf", g_config_dir, module, module);
}

static int module_conf_ensure_dir(const char* module) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s/modules/%s", g_config_dir, module);
    return mkdir_recursive(dir);
}

/* 写前确保模块目录存在（模块可能尚未部署，首次 FTP_ADD 时目录还不存在）。
   目录 0755：里面只有 .so 与 .conf，无敏感目录遍历面。 */
/* 去首尾空白拷入定长缓冲；超长返回 -1 */
static int ftp_trim_copy(const char* src, char* dst, size_t sz) {
    if (!src) {
        dst[0] = '\0';
        return 0;
    }
    while (isspace((unsigned char)*src)) src++;
    size_t n = strlen(src);
    while (n > 0 && isspace((unsigned char)src[n - 1])) n--;
    if (n >= sz) return -1;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return 0;
}

static bool ftp_valid_name(const char* name) {
    if (!nsp_ini_valid_section(name)) return false;
    char tmp[256];
    if (ftp_trim_copy(name, tmp, sizeof tmp) != 0) return false;
    if (tmp[0] == '\0' || strlen(tmp) > FTP_NAME_MAX) return false;
    if (strcmp(tmp, "GLOBAL") == 0) return false; /* [GLOBAL] 非服务器段 */
    return true;
}

static bool ftp_valid_field(const char* v, size_t max) {
    if (!v) return true; /* 缺省 = 不写该键 */
    size_t n = strlen(v);
    if (n > max) return false;
    for (size_t i = 0; i < n; i++) {
        /* `#` 禁止：store/ftp_conf 读侧以首个 `#` 为注释起点剥除，
           放行会导致写入值被截断（如密码 "a#b" 读回成 "a"） */
        if (v[i] == '\n' || v[i] == '\r' || v[i] == '\0' || v[i] == '#') return false;
    }
    return true;
}

static bool modconf_enum_hit(const ModConfField* f, const char* val);
static bool modconf_enum_hit(const ModConfField* f, const char* val); /* 定义在下方 */

/* bool 取值归一：接受 on/off/true/false/1/0（写入侧同一口径） */
static bool modconf_enum_hit_bool(const char* v) {
    return !(strcasecmp(v, "off") == 0 || strcasecmp(v, "false") == 0 || strcmp(v, "0") == 0);
}

/* 解析键名：查 schema 并把**规范化后的键名**（`pass` → `password`）写入 out_key。
 * 未知键 fail-closed（未声明即不可写）。**不含值校验**——SET 的「空值删键」分支
 * 必须在值校验之前，否则 int 字段的删键请求会被判「须为整数」而永远删不掉。 */
static const ModConfField* module_conf_resolve(const ModConfSchema* sc, const char* key,
                                               char* out_key, size_t out_key_sz, char* err,
                                               size_t err_sz) {
    const ModConfField* f = modconf_find(sc, strcasecmp(key, "pass") == 0 ? "password" : key);
    if (!f) {
        char known[256] = {0};
        for (int i = 0; i < sc->count; i++) {
            if (i) strncat(known, "/", sizeof(known) - strlen(known) - 1);
            strncat(known, sc->fields[i].key, sizeof(known) - strlen(known) - 1);
        }
        snprintf(err, err_sz, "未知字段: %s（限 %s）", key, known);
        return NULL;
    }
    snprintf(out_key, out_key_sz, "%s", f->key);
    return f;
}

/* 校验一个**非空**值：类型 / 长度上限 / 枚举，全部以 schema 为准。
 * 失败时返回 false 并把可直接回给调用方的人类可读原因写入 err。 */
static bool module_conf_validate_value(const ModConfField* f, const char* key, const char* value,
                                       char* err, size_t err_sz) {
    if (strcasecmp(f->type, "int") == 0) {
        char* endp = NULL;
        long v = strtol(value, &endp, 10);
        int lo = f->has_range ? f->min : 1;
        int hi = f->has_range ? f->max : 65535;
        if (endp == value || *nsp_str_trim(endp) != '\0' || v < lo || v > hi) {
            if (f->has_range)
                snprintf(err, err_sz, "字段值越界（须为整数 %d~%d）: %s", lo, hi, key);
            else
                snprintf(err, err_sz, "字段值非法（须为整数）: %s", key);
            return false;
        }
        return true;
    }
    if (!ftp_valid_field(value, f->maxlen ? f->maxlen : FTP_RDIR_MAX)) {
        snprintf(err, err_sz, "字段值非法或超长: %s", key);
        return false;
    }
    if (f->enum_count > 0 && !modconf_enum_hit(f, value)) {
        char opts[128] = {0};
        for (int i = 0; i < f->enum_count; i++) {
            if (i) strncat(opts, "|", sizeof(opts) - strlen(opts) - 1);
            strncat(opts, f->enumvals[i], sizeof(opts) - strlen(opts) - 1);
        }
        snprintf(err, err_sz, "字段值不在可选范围内: %s（限 %s）", value, opts);
        return false;
    }
    return true;
}

/* 值归一：int 写规范十进制（"021" → "21"），其余原样——ADD 与 SET 共用，
   免得同一个值经两条路径落盘成两种写法。 */
static void modconf_canon_value(const ModConfField* f, const char* in, char* out, size_t sz) {
    if (strcasecmp(f->type, "int") == 0) snprintf(out, sz, "%d", atoi(in));
    else snprintf(out, sz, "%s", in);
}

/* 取某字段在某段里的**生效缺省**：命中条件缺省则用它，否则用 defval。
 * 依赖字段的取值同样按「文件里有则用文件的，否则用其 defval」解析——故 proto
 * 写在 port 之后也正确，与模块侧 ftp_conf_parse_end 的推导同口径。 */
static void modconf_effective_default(const ModConfSchema* sc, NspIniStore* s, const char* sec,
                                      const ModConfField* f, char* out, size_t sz) {
    snprintf(out, sz, "%s", f->defval);
    if (!f->has_cond || !f->cond_dep[0]) return;
    char dep_val[FTP_RDIR_MAX + 1];
    bool hit = (nsp_ini_get(s, sec, f->cond_dep, dep_val, sizeof dep_val) == 0);
    if (!hit) {
        const ModConfField* dep = modconf_find(sc, f->cond_dep);
        if (dep && dep->defval[0]) snprintf(dep_val, sizeof dep_val, "%s", dep->defval);
        else dep_val[0] = '\0';
    }
    if (strcasecmp(dep_val, f->cond_val) == 0) snprintf(out, sz, "%s", f->cond_defval);
}

/* 缺省值按字段类型给 JSON 型别（int → 数字、bool → 布尔、其余 → 字符串），
 * 与实际值的型别一致——前端不必为某几个字段做「字符串转数字/布尔」的特殊处理。 */
static json_object* modconf_default_json(const ModConfField* f, const char* raw) {
    if (strcasecmp(f->type, "int") == 0) return json_object_new_int(atoi(raw));
    if (strcasecmp(f->type, "bool") == 0) return json_object_new_boolean(modconf_enum_hit_bool(raw));
    return json_object_new_string(raw);
}

/* 单服务器 JSON：按模块配置 schema 输出**全部**字段的生效值。
 * 敏感字段（schema 的 sensitive）绝不回传明文，只给 has_<key> 布尔——
 * 此前仅 password 一个键享受特判，现按 schema 判定，新增敏感字段自动脱敏。
 * `derived` 列出**不在文件里、值来自 schema 缺省**的键：前端据此区分「已显式
 * 配置」与「缺省生效」，做整体回写时可只提交前者（配置逐字节保持，不会把缺省
 * 物化成显式键——如 sftp 段的 port 22）。 */
static json_object* build_ftp_server_json(NspIniStore* s, const char* module,
                                           const char* name) {
    const ModConfSchema* sc = modconf_get(module);
    if (!sc) sc = modconf_get(FTP_MODULE_NAME);
    json_object* o = json_object_new_object();
    json_object* derived = json_object_new_array();
    json_object_object_add(o, "name", json_object_new_string(name));
    char val[FTP_RDIR_MAX + 1];
    for (int i = 0; i < sc->count; i++) {
        const ModConfField* f = &sc->fields[i];
        val[0] = '\0';
        /* pass 是 password 的历史别名：两处都查，与写入侧归一一致 */
        bool hit = (nsp_ini_get(s, name, f->key, val, sizeof val) == 0);
        if (!hit && strcasecmp(f->key, "password") == 0)
            hit = (nsp_ini_get(s, name, "pass", val, sizeof val) == 0);
        if (f->sensitive) {
            /* 保持既有契约：敏感字段的**键本身不出现**（不是回空串），只给
               has_<key> 布尔。前端据此判断"是否已设置"，且永远不会拿到明文。 */
            char hk[40];
            snprintf(hk, sizeof hk, "has_%s", f->key);
            json_object_object_add(o, hk, json_object_new_boolean(hit));
            continue;
        }
        /* 文件里没有该键 → 回 schema 的生效缺省（条件缺省优先）并记入 derived。
           有键则原样回读（含空值/越界值——那是文件的真实内容，前端凭 min/max
           自行标记；控制面不再按字段名特判、不再替模块"修正"值）。 */
        if (!hit) {
            modconf_effective_default(sc, s, name, f, val, sizeof val);
            json_object_array_add(derived, json_object_new_string(f->key));
        }
        if (strcasecmp(f->type, "int") == 0) {
            json_object_object_add(o, f->key, json_object_new_int(atoi(val)));
        } else if (strcasecmp(f->type, "bool") == 0) {
            json_object_object_add(o, f->key,
                                   json_object_new_boolean(modconf_enum_hit_bool(val)));
        } else {
            json_object_object_add(o, f->key, json_object_new_string(val));
        }
    }
    json_object_object_add(o, "derived", derived);
    return o;
}

/* MODULE_SCHEMA：把模块配置的字段契约交给前端（自动渲染表单）。
 * 形状：{file, module, fields:[{key, type, maxlen|min+max, required, sensitive,
 * default, default_if?, enum?, order, desc, desc_map}]}。只读，与 FTP_LIST 同级。 */
static void module_conf_schema(int fd, json_object* req, const char* module, const char* cmd) {
    const ModConfSchema* sc = modconf_get(module);
    if (!sc || sc->count == 0) {
        reply_error(fd, cmd, "模块未声明配置 schema（无法渲染）");
        return;
    }
    char path[PATH_MAX];
    module_conf_path(path, sizeof(path), module);
    json_object* data = json_object_new_object();
    json_object_object_add(data, "file", json_object_new_string(path));
    json_object_object_add(data, "module", json_object_new_string(sc->module));
    json_object* arr = json_object_new_array();
    for (int i = 0; i < sc->count; i++) {
        const ModConfField* f = &sc->fields[i];
        json_object* o = json_object_new_object();
        json_object_object_add(o, "key", json_object_new_string(f->key));
        json_object_object_add(o, "type", json_object_new_string(f->type));
        if (strcasecmp(f->type, "int") == 0) {
            /* int 给值域（min/max），前端据此校验与提示；不给 maxlen（长度语义只属字符串） */
            if (f->has_range) {
                json_object_object_add(o, "min", json_object_new_int(f->min));
                json_object_object_add(o, "max", json_object_new_int(f->max));
            }
        } else if (strcasecmp(f->type, "bool") != 0) {
            json_object_object_add(o, "maxlen", json_object_new_int((int)f->maxlen));
        }
        /* default 按字段类型给 JSON 型别（int → 数字、bool → 布尔、其余 → 字符串），
           与 LIST/GET 里的实际值同型——前端不必为某些类型做"字符串转换"的特殊处理 */
        json_object_object_add(o, "required", json_object_new_boolean(f->required));
        json_object_object_add(o, "sensitive", json_object_new_boolean(f->sensitive));
        json_object_object_add(o, "default", modconf_default_json(f, f->defval));
        /* 条件缺省（如 port 在 proto=sftp 时缺省 22）：前端按当前条目里依赖字段的
           取值挑 placeholder，与 LIST/GET 的 derived 值同口径 */
        if (f->has_cond) {
            json_object* di = json_object_new_object();
            json_object_object_add(di, "key", json_object_new_string(f->cond_dep));
            json_object_object_add(di, "value", json_object_new_string(f->cond_val));
            json_object_object_add(di, "default", modconf_default_json(f, f->cond_defval));
            json_object_object_add(o, "default_if", di);
        }
        if (f->enum_count > 0) {
            json_object* ev = json_object_new_array();
            for (int k = 0; k < f->enum_count; k++)
                json_object_array_add(ev, json_object_new_string(f->enumvals[k]));
            json_object_object_add(o, "enum", ev);
        }
        json_object_object_add(o, "order", json_object_new_int(f->order));
        const char* lang = json_object_get_string(json_object_object_get(req, "lang"));
        json_object_object_add(o, "desc",
                               json_object_new_string(modconf_label(f, lang ? lang : "zh")));
        json_object* dm = json_object_new_object();
        for (int k = 0; k < f->desc_count; k++)
            json_object_object_add(dm, f->descs[k].lang, json_object_new_string(f->descs[k].text));
        json_object_object_add(o, "desc_map", dm);
        json_object_array_add(arr, o);
    }
    json_object_object_add(data, "fields", arr);
    reply_ok(fd, cmd, data);
}

static void module_conf_list(int fd, const char* module, const char* cmd) {
    char path[PATH_MAX];
    module_conf_path(path, sizeof(path), module);
    NspIniStore* s = nsp_ini_open(path);
    if (!s) {
        reply_error(fd, cmd, "内存不足");
        return;
    }
    json_object* data = json_object_new_object();
    json_object* arr = json_object_new_array();
    int n = nsp_ini_section_count(s);
    for (int i = 0; i < n; i++) {
        const char* sec = nsp_ini_section_name(s, i);
        if (!sec || strcmp(sec, "GLOBAL") == 0) continue;
        json_object_array_add(arr, build_ftp_server_json(s, module, sec));
    }
    nsp_ini_close(s);
    json_object_object_add(data, "file", json_object_new_string(path));
    json_object_object_add(data, "module", json_object_new_string(module));
    json_object_object_add(data, "servers", arr);
    reply_ok(fd, cmd, data);
}

static void module_conf_get(int fd, json_object* req, const char* module, const char* cmd) {
    const char* name = json_object_get_string(json_object_object_get(req, "name"));
    if (!name || !ftp_valid_name(name)) {
        reply_error(fd, cmd, "缺少或非法参数: name");
        return;
    }
    char path[PATH_MAX];
    module_conf_path(path, sizeof(path), module);
    NspIniStore* s = nsp_ini_open(path);
    if (!s) {
        reply_error(fd, cmd, "内存不足");
        return;
    }
    char trimmed[FTP_NAME_MAX + 1];
    ftp_trim_copy(name, trimmed, sizeof trimmed);
    if (nsp_ini_find_section(s, trimmed) < 0) {
        nsp_ini_close(s);
        reply_error(fd, cmd, "条目不存在: %s", trimmed);
        return;
    }
    json_object* data = build_ftp_server_json(s, module, trimmed);
    nsp_ini_close(s);
    json_object_object_add(data, "file", json_object_new_string(path));
    json_object_object_add(data, "module", json_object_new_string(module));
    reply_ok(fd, cmd, data);
}

/* 请求信封自带的键（非配置字段）：散字段拾取时跳过，免得把条目名当配置项写进去。
   模块若真需要同名字段，用 `fields` 对象给值（那条路径不做信封过滤）。 */
static bool modconf_is_envelope_key(const char* key) {
    static const char* env[] = {"cmd", "module", "name", "lang", "key", "value", "fields"};
    for (size_t i = 0; i < sizeof(env) / sizeof(env[0]); i++)
        if (strcasecmp(key, env[i]) == 0) return true;
    return false;
}

/* 收集一个待写字段：先解析键名（未知键 fail-closed，**空值也不例外**——未声明即
 * 不可写），再去首尾空白：为空 → 不写该键（返回 0）；按 schema 校验通过 → 落进
 * out_key/out_val（返回 1）；非法 → 返回 -1 并把原因写进 err。
 * ADD 的两条取值路径（fields 对象 / 散字段）共用，避免两套收集逻辑漂移。 */
static int modconf_collect(const ModConfSchema* sc, const char* key, const char* raw,
                           char* out_key, size_t out_key_sz, char* out_val, size_t out_val_sz,
                           char* err, size_t err_sz) {
    const ModConfField* f = module_conf_resolve(sc, key, out_key, out_key_sz, err, err_sz);
    if (!f) return -1;
    char tv[FTP_RDIR_MAX + 1];
    if (!raw || ftp_trim_copy(raw, tv, sizeof tv) != 0) {
        snprintf(err, err_sz, "字段值非法或超长: %s", key);
        return -1;
    }
    if (!tv[0]) return 0;
    if (!module_conf_validate_value(f, key, tv, err, err_sz)) return -1;
    modconf_canon_value(f, tv, out_val, out_val_sz);
    return 1;
}

/* MODULE_CONF_ADD：新建或更新某模块配置里的一个段（段名 = 条目名）。
 * 字段一律按该模块的 [conf] schema 校验（未知键/类型/上限/值域/枚举），与 SET 共用
 * 同一套键名解析与值校验（module_conf_resolve + module_conf_validate_value）——
 * 不接受 schema 之外的键（fail-closed：未声明即不可写）。
 * 值有两种给法，语义等价：
 *   - 通用：{"cmd":"MODULE_CONF_ADD","module":X,"name":N,"fields":{键:值,…}}
 *   - 兼容：散字段 {"host":…,"port":…,…}（FTP_* 前端的既有形态）——按 schema
 *     逐字段拾取（不再硬编码字段名，新增声明字段自动可写）
 * 空值（含纯空白）一律视为"不写该键"（走模块缺省；清空请用 SET 传空值删键）——
 * 不落 `key = ` 空行：模块读侧对空值多判非法而整段作废。
 * 幂等：所给字段与现状逐项一致 → duplicate=true 免写；否则更新并原子落盘。 */
static void module_conf_add(int fd, json_object* req, const char* module, const char* cmd) {
    const char* name = json_object_get_string(json_object_object_get(req, "name"));
    if (!name || !ftp_valid_name(name)) {
        reply_error(fd, cmd, "缺少或非法参数: name");
        return;
    }
    const ModConfSchema* sc = modconf_get(module);
    if (!sc || sc->count == 0) {
        reply_error(fd, cmd, "模块未声明配置 schema（无法校验字段）");
        return;
    }
    /* 收集待写字段：优先 fields 对象，否则按 schema 从散字段里拾取（兼容既有
     * FTP_* 形态）。收集阶段即按 schema 校验，任何一个不合法就整体拒绝（不部分写入）。 */
    char keys[MODCONF_MAX_FIELDS][32];
    char vals[MODCONF_MAX_FIELDS][FTP_RDIR_MAX + 1];
    int nf = 0;
    char verr[256];
    json_object* fobj = json_object_object_get(req, "fields");
    if (fobj) {
        json_object_object_foreach(fobj, fk, fv) {
            if (nf >= MODCONF_MAX_FIELDS) {
                reply_error(fd, cmd, "字段数超上限 %d", MODCONF_MAX_FIELDS);
                return;
            }
            int rc = modconf_collect(sc, fk, json_object_get_string(fv), keys[nf],
                                     sizeof keys[nf], vals[nf], sizeof vals[nf], verr,
                                     sizeof verr);
            if (rc < 0) {
                reply_error(fd, cmd, "%s", verr);
                return;
            }
            if (rc > 0) nf++;
        }
    } else {
        for (int i = 0; i < sc->count && nf < MODCONF_MAX_FIELDS; i++) {
            const char* fk = sc->fields[i].key;
            if (modconf_is_envelope_key(fk)) continue;
            json_object* v = json_object_object_get(req, fk);
            if (!v && strcasecmp(fk, "password") == 0) v = json_object_object_get(req, "pass");
            if (!v) continue;
            int rc = modconf_collect(sc, fk, json_object_get_string(v), keys[nf],
                                     sizeof keys[nf], vals[nf], sizeof vals[nf], verr,
                                     sizeof verr);
            if (rc < 0) {
                reply_error(fd, cmd, "%s", verr);
                return;
            }
            if (rc > 0) nf++;
        }
    }
    /* 新建段必须给出内容（否则创建一个空段毫无意义），且 schema 标 required 的字段
       必须给全——缺了模块侧必填字段的段会被模块整段作废，当场拒绝好过落一个坏段。 */
    char path[PATH_MAX];
    module_conf_path(path, sizeof(path), module);
    if (module_conf_ensure_dir(module) != 0) {
        reply_error(fd, cmd, "无法创建模块配置目录");
        return;
    }
    NspIniStore* s = nsp_ini_open(path);
    if (!s) {
        reply_error(fd, cmd, "内存不足");
        return;
    }
    char trimmed[FTP_NAME_MAX + 1];
    ftp_trim_copy(name, trimmed, sizeof trimmed);
    bool exists = (nsp_ini_find_section(s, trimmed) >= 0);
    if (!exists && nf == 0) {
        nsp_ini_close(s);
        reply_error(fd, cmd, "新建条目需至少提供一个字段");
        return;
    }
    if (!exists) {
        for (int i = 0; i < sc->count; i++) {
            if (!sc->fields[i].required) continue;
            bool got = false;
            for (int k = 0; k < nf; k++)
                if (strcasecmp(keys[k], sc->fields[i].key) == 0) got = true;
            if (!got) {
                nsp_ini_close(s);
                reply_error(fd, cmd, "新建条目缺少必填字段: %s", sc->fields[i].key);
                return;
            }
        }
    }
    /* 幂等：所给字段与现状逐项一致 → duplicate。密码可明文比对（配置本就明文），
       否则轮换密码会被误判 duplicate 静默吞掉。 */
    bool same = exists;
    char cur[FTP_RDIR_MAX + 1];
    for (int i = 0; same && i < nf; i++) {
        same = (nsp_ini_get(s, trimmed, keys[i], cur, sizeof cur) == 0 &&
                strcmp(cur, vals[i]) == 0);
    }
    json_object* data = json_object_new_object();
    json_object_object_add(data, "file", json_object_new_string(path));
    json_object_object_add(data, "module", json_object_new_string(module));
    json_object_object_add(data, "name", json_object_new_string(trimmed));
    if (same) {
        nsp_ini_close(s);
        json_object_object_add(data, "duplicate", json_object_new_boolean(true));
        json_object_object_add(data, "changed", json_object_new_boolean(false));
        reply_ok(fd, cmd, data);
        return;
    }
    for (int i = 0; i < nf; i++) {
        if (strcasecmp(keys[i], "password") == 0) nsp_ini_del_key(s, trimmed, "pass");
        if (nsp_ini_set(s, trimmed, keys[i], vals[i]) != 0) goto ftp_add_fail;
    }
    if (nsp_ini_save(s) != 0) goto ftp_add_fail;
    nsp_ini_close(s);
    json_object_object_add(data, "duplicate", json_object_new_boolean(false));
    json_object_object_add(data, "changed", json_object_new_boolean(true));
    reply_ok(fd, cmd, data);
    return;
ftp_add_fail:
    nsp_ini_close(s);
    reply_error(fd, cmd, "写入 %s 失败", path);
}

/* MODULE_CONF_SET：修改单个字段（键按模块 [conf] schema，pass 归一 password）。
 * 空值（含纯空白）= 删键回缺省；段不存在报错（新建请用 ADD）。
 * 注意顺序：**先归一/校验键名，再判空删键，最后才校验值**——删键请求带的是空值，
 * 若先走类型校验，int 字段会被判"须为整数"而永远删不掉（缺省也就永远回不去）。 */
static void module_conf_set(int fd, json_object* req, const char* module, const char* cmd) {
    const char* name = json_object_get_string(json_object_object_get(req, "name"));
    const char* key = json_object_get_string(json_object_object_get(req, "key"));
    const char* value = json_object_get_string(json_object_object_get(req, "value"));
    if (!name || !ftp_valid_name(name) || !key) {
        reply_error(fd, cmd, "缺少或非法参数: name/key");
        return;
    }
    /* 字段白名单不再硬编码：查模块配置 schema（[conf] 段声明，未声明走默认表）。
       `pass` 仍归一为 `password`（别名），schema 里只声明其一。 */
    const ModConfSchema* sc = modconf_get(module);
    if (!sc || sc->count == 0) {
        reply_error(fd, cmd, "模块未声明配置 schema（无法校验字段）");
        return;
    }
    char norm_key[32], verr[256];
    const ModConfField* field =
        module_conf_resolve(sc, key, norm_key, sizeof norm_key, verr, sizeof verr);
    if (!field) {
        reply_error(fd, cmd, "%s", verr);
        return;
    }
    /* 值先去首尾空白：空白串与空串同义（= 删键回缺省）。否则 `value="  "` 会
       把键写成空值，而模块读侧对空值多判非法、整段作废。 */
    char tbuf[FTP_RDIR_MAX + 1];
    if (value && ftp_trim_copy(value, tbuf, sizeof tbuf) != 0) {
        reply_error(fd, cmd, "字段值非法或超长: %s", key);
        return;
    }
    bool del = (!value || !tbuf[0]);
    if (!del && !module_conf_validate_value(field, key, tbuf, verr, sizeof verr)) {
        reply_error(fd, cmd, "%s", verr);
        return;
    }
    char path[PATH_MAX];
    module_conf_path(path, sizeof(path), module);
    if (module_conf_ensure_dir(module) != 0) {
        reply_error(fd, cmd, "无法创建模块配置目录");
        return;
    }
    NspIniStore* s = nsp_ini_open(path);
    if (!s) {
        reply_error(fd, cmd, "内存不足");
        return;
    }
    char trimmed[FTP_NAME_MAX + 1];
    ftp_trim_copy(name, trimmed, sizeof trimmed);
    if (nsp_ini_find_section(s, trimmed) < 0) {
        nsp_ini_close(s);
        reply_error(fd, cmd, "条目不存在: %s（新建请用 MODULE_CONF_ADD）", trimmed);
        return;
    }
    bool changed = false;
    if (del) {
        /* 空值 = 删键回缺省；password 一并清 pass 别名 */
        if (nsp_ini_del_key(s, trimmed, norm_key) == 0) changed = true;
        if (strcmp(norm_key, "password") == 0 && nsp_ini_del_key(s, trimmed, "pass") == 0)
            changed = true;
    } else {
        /* int 一律写规范十进制（"021" → "21"）；其余类型写去空白后的原值。
           类型/上限/枚举已在上面统一校验过。 */
        char canon[FTP_RDIR_MAX + 1];
        modconf_canon_value(field, tbuf, canon, sizeof canon);
        char cur[FTP_RDIR_MAX + 1] = {0};
        bool cur_hit = (nsp_ini_get(s, trimmed, norm_key, cur, sizeof cur) == 0);
        if (!cur_hit || strcmp(cur, canon) != 0) {
            if (strcmp(norm_key, "password") == 0) nsp_ini_del_key(s, trimmed, "pass");
            if (nsp_ini_set(s, trimmed, norm_key, canon) != 0) goto ftp_set_fail;
            changed = true;
        }
    }
    if (changed && nsp_ini_save(s) != 0) goto ftp_set_fail;
    nsp_ini_close(s);
    json_object* data = json_object_new_object();
    json_object_object_add(data, "file", json_object_new_string(path));
    json_object_object_add(data, "name", json_object_new_string(trimmed));
    json_object_object_add(data, "key", json_object_new_string(norm_key));
    json_object_object_add(data, "changed", json_object_new_boolean(changed));
    reply_ok(fd, cmd, data);
    return;
ftp_set_fail:
    nsp_ini_close(s);
    reply_error(fd, cmd, "写入 %s 失败", path);
}

static void module_conf_remove(int fd, json_object* req, const char* module, const char* cmd) {
    const char* name = json_object_get_string(json_object_object_get(req, "name"));
    if (!name || !ftp_valid_name(name)) {
        reply_error(fd, cmd, "缺少或非法参数: name");
        return;
    }
    char path[PATH_MAX];
    module_conf_path(path, sizeof(path), module);
    if (module_conf_ensure_dir(module) != 0) {
        reply_error(fd, cmd, "无法创建模块配置目录");
        return;
    }
    NspIniStore* s = nsp_ini_open(path);
    if (!s) {
        reply_error(fd, cmd, "内存不足");
        return;
    }
    char trimmed[FTP_NAME_MAX + 1];
    ftp_trim_copy(name, trimmed, sizeof trimmed);
    if (nsp_ini_del_section(s, trimmed) != 0) {
        nsp_ini_close(s);
        reply_error(fd, cmd, "条目不存在: %s", trimmed);
        return;
    }
    if (nsp_ini_save(s) != 0) {
        nsp_ini_close(s);
        reply_error(fd, cmd, "写入 %s 失败", path);
        return;
    }
    nsp_ini_close(s);
    json_object* data = json_object_new_object();
    json_object_object_add(data, "file", json_object_new_string(path));
    json_object_object_add(data, "name", json_object_new_string(trimmed));
    reply_ok(fd, cmd, data);
}

/* ==================== 模块配置控制面（通用命令 + FTP_* 别名） ====================
 * `MODULE_CONF_*` 按 `module` 参数寻址**任意模块**的配置；`FTP_*` 是它的向后兼容
 * 别名（等价于 module=ftp_module），既有前端/脚本零改动继续可用。
 * 校验规则一律取自该模块的 [conf] schema（见 docs/modules.md §2.2），故新增模块
 * 只需放一份声明文件，不必改本文件。 */

/* 模块名直接参与 <config-dir>/modules/<名>/<名>.conf 路径拼接，必须 fail-closed：
 * 只放 [A-Za-z0-9_-]，杜绝 `..` 与路径分隔符越出模块目录。 */
static bool module_conf_valid(const char* m) {
    if (!m || !m[0] || strlen(m) >= 64) return false;
    for (const char* p = m; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '-')) return false;
    return true;
}

/* 取 module 参数；缺省 ftp_module（使 MODULE_CONF_* 与 FTP_* 行为一致） */
static const char* module_conf_arg(json_object* req, char* buf, size_t sz) {
    const char* m = json_object_get_string(json_object_object_get(req, "module"));
    snprintf(buf, sz, "%s", (m && m[0]) ? m : FTP_MODULE_NAME);
    return buf;
}

/* 通用入口：解析并校验 module 后转交实现；非法 module 直接拒（不落盘） */
static void mc_schema(int fd, json_object* req) {
    char m[64];
    module_conf_arg(req, m, sizeof m);
    if (!module_conf_valid(m)) {
        reply_error(fd, "MODULE_CONF_SCHEMA", "非法或缺失的 module 参数");
        return;
    }
    module_conf_schema(fd, req, m, "MODULE_CONF_SCHEMA");
}

static void mc_list(int fd, json_object* req) {
    char m[64];
    module_conf_arg(req, m, sizeof m);
    if (!module_conf_valid(m)) {
        reply_error(fd, "MODULE_CONF_LIST", "非法或缺失的 module 参数");
        return;
    }
    module_conf_list(fd, m, "MODULE_CONF_LIST");
}

static void mc_get(int fd, json_object* req) {
    char m[64];
    module_conf_arg(req, m, sizeof m);
    if (!module_conf_valid(m)) {
        reply_error(fd, "MODULE_CONF_GET", "非法或缺失的 module 参数");
        return;
    }
    module_conf_get(fd, req, m, "MODULE_CONF_GET");
}

static void mc_add(int fd, json_object* req) {
    char m[64];
    module_conf_arg(req, m, sizeof m);
    if (!module_conf_valid(m)) {
        reply_error(fd, "MODULE_CONF_ADD", "非法或缺失的 module 参数");
        return;
    }
    module_conf_add(fd, req, m, "MODULE_CONF_ADD");
}

static void mc_set(int fd, json_object* req) {
    char m[64];
    module_conf_arg(req, m, sizeof m);
    if (!module_conf_valid(m)) {
        reply_error(fd, "MODULE_CONF_SET", "非法或缺失的 module 参数");
        return;
    }
    module_conf_set(fd, req, m, "MODULE_CONF_SET");
}

static void mc_remove(int fd, json_object* req) {
    char m[64];
    module_conf_arg(req, m, sizeof m);
    if (!module_conf_valid(m)) {
        reply_error(fd, "MODULE_CONF_REMOVE", "非法或缺失的 module 参数");
        return;
    }
    module_conf_remove(fd, req, m, "MODULE_CONF_REMOVE");
}

/* FTP_* 别名：等价 module=ftp_module（保留供既有调用方零改动迁移） */
static void handle_module_schema(int fd, json_object* req) {
    module_conf_schema(fd, req, FTP_MODULE_NAME, "MODULE_SCHEMA");
}
static void handle_ftp_list(int fd, json_object* req) {
    (void)req;
    module_conf_list(fd, FTP_MODULE_NAME, "FTP_LIST");
}
static void handle_ftp_get(int fd, json_object* req) {
    module_conf_get(fd, req, FTP_MODULE_NAME, "FTP_GET");
}
static void handle_ftp_add(int fd, json_object* req) {
    module_conf_add(fd, req, FTP_MODULE_NAME, "FTP_ADD");
}
static void handle_ftp_set(int fd, json_object* req) {
    module_conf_set(fd, req, FTP_MODULE_NAME, "FTP_SET");
}
static void handle_ftp_remove(int fd, json_object* req) {
    module_conf_remove(fd, req, FTP_MODULE_NAME, "FTP_REMOVE");
}

/* 受信任调用者 uid 白名单（root 之外的额外放行项）：由环境变量
 * NSP_TRUSTED_UIDS 给出（逗号分隔，最多 8 项），启动时读一次。生产由模块的
 * service.sh 设为管理器 App 的 uid；**未设置时只有 root** 能执行高危命令。 */
static uid_t g_trusted_uids[8];
static int g_trusted_uid_count;

static void load_trusted_uids(void) {
    g_trusted_uid_count = 0;
    const char* env = getenv("NSP_TRUSTED_UIDS");
    if (!env) return;
    const char* p = env;
    while (*p && g_trusted_uid_count < (int)(sizeof g_trusted_uids / sizeof g_trusted_uids[0])) {
        char* end = NULL;
        unsigned long v = strtoul(p, &end, 10);
        if (end == p) break; /* 非数字：停止（不猜测） */
        if (v <= 0xFFFFFFFFul) g_trusted_uids[g_trusted_uid_count++] = (uid_t)v;
        p = end;
        while (*p == ',' || *p == ' ' || *p == '\t') p++;
    }
}

static bool peer_is_privileged(uid_t uid) {
    if (uid == 0) return true;
    for (int i = 0; i < g_trusted_uid_count; i++)
        if (g_trusted_uids[i] == uid) return true;
    return false;
}

/* 高危命令：能停服（STOP/QUIT）、把全机访问日志导出到落点（EXPORT_LOGS），
 * 或经 SERVICE 启停常驻服务（start/stop/restart 与 STOP 同等能力——都会
 * 杀/拉起 injector、fuse_daemon、log_monitor）。
 * 其余命令（查询/规则编辑、SERVICE status）保持开放——控制面可用性优先，
 * 且它们不越权。
 *
 * 注意 SERVICE 必须在这里按 action 判定：它是最外层 cmd，若只看顶层 cmd，
 * `{"cmd":"SERVICE","action":"stop"}` 会绕过 STOP 的白名单检查直接停服
 * （SERVICE 与 STOP 的差别只是命令名）。 */
static bool cmd_is_privileged(json_object* req) {
    const char* cmd = json_object_get_string(json_object_object_get(req, "cmd"));
    if (!cmd) return false;
    if (strcasecmp(cmd, "STOP") == 0 || strcasecmp(cmd, "QUIT") == 0 ||
        strcasecmp(cmd, "EXPORT_LOGS") == 0)
        return true;
    if (strcasecmp(cmd, "SERVICE") == 0) {
        const char* action = json_object_get_string(json_object_object_get(req, "action"));
        /* 缺 action 等价 status（见 handle_service），保持开放 */
        if (!action || strcasecmp(action, "status") == 0) return false;
        return true;
    }
    return false;
}

/* ==================== 命令分发 ==================== */
static void dispatch(int fd, json_object* req, uid_t peer_uid) {
    const char* cmd = json_object_get_string(json_object_object_get(req, "cmd"));
    if (!cmd) {
        reply_error(fd, "?", "缺少 cmd 字段");
        return;
    }
    /* 高危命令（停服 / 启停服务 / 导出全机日志）仅 root 或白名单 uid 可执行
       （B2：对端鉴权） */
    if (cmd_is_privileged(req) && !peer_is_privileged(peer_uid)) {
        char clean[128];
        nsp_log_line_sanitize(cmd, clean, sizeof clean);
        LOG_WRN("拒绝高危命令 %s：对端 uid=%u 不在白名单（仅 root / NSP_TRUSTED_UIDS）", clean,
                (unsigned)peer_uid);
        reply_error(fd, cmd, "权限不足：该命令仅限 root 或受信任 uid");
        return;
    }
    /* 每次命令前刷新规则类型表：模块 .rules 增删即动态追加/回收类型（热更新） */
    rule_types_refresh();
    if (strcasecmp(cmd, "PING") == 0)
        handle_ping(fd, req);
    else if (strcasecmp(cmd, "UPTIME") == 0)
        handle_uptime(fd, req);
    else if (strcasecmp(cmd, "LIST") == 0)
        handle_list(fd, req);
    else if (strcasecmp(cmd, "USERS") == 0)
        handle_users(fd, req);
    else if (strcasecmp(cmd, "GET") == 0)
        handle_get(fd, req);
    else if (strcasecmp(cmd, "ADD") == 0)
        handle_add(fd, req);
    else if (strcasecmp(cmd, "REMOVE") == 0)
        handle_remove(fd, req);
    else if (strcasecmp(cmd, "ENABLE") == 0)
        handle_toggle(fd, req, true);
    else if (strcasecmp(cmd, "DISABLE") == 0)
        handle_toggle(fd, req, false);
    else if (strcasecmp(cmd, "SET") == 0)
        handle_set(fd, req);
    else if (strcasecmp(cmd, "MODULE_CONF_SCHEMA") == 0)
        mc_schema(fd, req);
    else if (strcasecmp(cmd, "MODULE_CONF_LIST") == 0)
        mc_list(fd, req);
    else if (strcasecmp(cmd, "MODULE_CONF_GET") == 0)
        mc_get(fd, req);
    else if (strcasecmp(cmd, "MODULE_CONF_ADD") == 0)
        mc_add(fd, req);
    else if (strcasecmp(cmd, "MODULE_CONF_SET") == 0)
        mc_set(fd, req);
    else if (strcasecmp(cmd, "MODULE_CONF_REMOVE") == 0)
        mc_remove(fd, req);
    else if (strcasecmp(cmd, "MODULE_SCHEMA") == 0) /* 旧名 = MODULE_CONF_SCHEMA */
        handle_module_schema(fd, req);
    else if (strcasecmp(cmd, "FTP_LIST") == 0)
        handle_ftp_list(fd, req);
    else if (strcasecmp(cmd, "FTP_GET") == 0)
        handle_ftp_get(fd, req);
    else if (strcasecmp(cmd, "FTP_ADD") == 0)
        handle_ftp_add(fd, req);
    else if (strcasecmp(cmd, "FTP_SET") == 0)
        handle_ftp_set(fd, req);
    else if (strcasecmp(cmd, "FTP_REMOVE") == 0)
        handle_ftp_remove(fd, req);
    else if (strcasecmp(cmd, "RELOAD") == 0)
        handle_reload(fd, req);
    else if (strcasecmp(cmd, "STOP") == 0)
        handle_stop(fd, req);
    else if (strcasecmp(cmd, "SERVICE") == 0)
        handle_service(fd, req);
    else if (strcasecmp(cmd, "STATUS") == 0)
        handle_status(fd, req);
    else if (strcasecmp(cmd, "EXPORT_LOGS") == 0)
        handle_export_logs(fd, req);
    else if (strcasecmp(cmd, "QUIT") == 0)
        handle_quit(fd, req);
    else
        reply_error(fd, cmd, "未知命令: %s", cmd);
}

/* ==================== 服务端 ==================== */
static void handle_client(int client_fd) {
    /* 对端鉴权：取 SO_PEERCRED 的 uid。失败（非 UDS/异常）按最不可信处理，
       高危命令随即被拒——仅靠 SELinux 域兜底不足（见 nsp_peer_cred 注释）。 */
    uid_t peer_uid = (uid_t)-1;
    if (nsp_peer_cred(client_fd, NULL, &peer_uid, NULL) != 0) peer_uid = (uid_t)-1;

    /* 500ms 读写超时，防止异常客户端挂起 */
    struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
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
            break; /* 超时 / 错误 */
        }
        if (n == 0) break; /* EOF（客户端 shutdown 写端） */
        total += (size_t)n;
        if (memchr(buf + total - (size_t)n, '\n', (size_t)n) != NULL) break; /* 已含行尾 */
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
    json_object* req = json_tokener_parse(buf);
    if (!req || !json_object_is_type(req, json_type_object)) {
        if (req) json_object_put(req);
        reply_error(client_fd, "?", "请求必须是 JSON 对象: %.80s", buf);
        close(client_fd);
        return;
    }
    dispatch(client_fd, req, peer_uid);
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
    load_trusted_uids();

    /* 统一日志：daemonize 之后建链（comm 线程不跨 fork），此后 LOG_*
     * 经 comm 线程进 sys.log；启动失败同时保留 stderr，service.sh 仍可见 */
    log_init("rule_server");
    /* 环境信息仅 injector 输出一次（崩溃归因走 crash_dump 的 Build 行），此处不重复 */

    struct sigaction sa = {.sa_handler = sig_handler};
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        LOG_ERR("创建 socket 失败: %s", strerror(errno));
        fprintf(stderr, "[rule_server] 创建 socket 失败: %s\n", strerror(errno));
        log_close();
        return 1;
    }
    struct sockaddr_un addr;
    socklen_t addr_len = nsp_uds_abstract_addr(&addr, g_socket_name);
    if (bind(sock, (struct sockaddr*)&addr, addr_len) < 0) {
        LOG_ERR("绑定 %s 失败: %s", g_socket_name, strerror(errno));
        fprintf(stderr, "[rule_server] 绑定 %s 失败: %s\n", g_socket_name, strerror(errno));
        close(sock);
        log_close();
        return 1;
    }
    if (listen(sock, 16) < 0) {
        LOG_ERR("listen 失败: %s", strerror(errno));
        fprintf(stderr, "[rule_server] listen 失败: %s\n", strerror(errno));
        close(sock);
        log_close();
        return 1;
    }
    LOG("服务已启动 socket=%s config_dir=%s", g_socket_name, g_config_dir);

    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) {
        LOG_ERR("创建 epoll 失败: %s", strerror(errno));
        close(sock);
        log_close();
        return 1;
    }
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = sock};
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
    LOG("服务退出");
    log_close();
    return 0;
}

/* ==================== 客户端模式 ==================== */
static int run_client(const char* cmd_json) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "创建 socket 失败: %s\n", strerror(errno));
        return 1;
    }
    struct sockaddr_un addr;
    socklen_t addr_len = nsp_uds_abstract_addr(&addr, g_socket_name);
    if (connect(sock, (struct sockaddr*)&addr, addr_len) < 0) {
        fprintf(stderr, "连接 %s 失败: %s（服务未启动？）\n", g_socket_name, strerror(errno));
        close(sock);
        return 1;
    }
    char req[MAX_REQ_LEN];
    snprintf(req, sizeof(req), "%s\n", cmd_json);
    nsp_send_all(sock, req, strlen(req));
    shutdown(sock, SHUT_WR);

    /* 响应动态扩容读取（LIST/GET 全量规则可能远超 8KB），杜绝静默截断 */
    size_t cap = MAX_REQ_LEN;
    char* resp = malloc(cap);
    if (!resp) {
        close(sock);
        return 1;
    }
    size_t total = 0;
    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    while (poll(&pfd, 1, 3000) > 0) {
        if (total >= cap - 1) {
            size_t new_cap = cap * 2;
            char* tmp = realloc(resp, new_cap);
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
   脱离会话与控制终端；并将进程写入 cgroup 根，逃出 Android 应用冻结/内存清理
   cgroup，避免后台被系统误杀。--foreground 保留前台模式（测试/调试）。
   实现经 nsp_util 公共库复用（nsp_daemonize / nsp_escape_cgroup），禁私刻副本。 */
static void rs_escape_cgroup(void) {
    nsp_escape_cgroup();
}

static void rs_daemonize(void) {
    nsp_daemonize(-1);
}

static void usage(const char* prog) {
    fprintf(
        stderr,
        "用法: %s [选项]\n"
        "  （无参数）          守护进程模式：自动退入后台，监听抽象套接字 %s，提供规则控制 JSON API\n"
        "  -c, --cmd <JSON>    客户端模式：发送单条 JSON 命令并打印响应\n"
        "  --config-dir <dir>  覆盖配置根目录（默认 %s）\n"
        "  --socket <name>     覆盖抽象套接字名（默认 %s）\n"
        "  --foreground        前台运行（不后台化，测试/调试用）\n"
        "  -h, --help          显示本帮助\n",
        prog, RULE_SOCKET_NAME, CONFIG_DIR, RULE_SOCKET_NAME);
}

int main(int argc, char* argv[]) {
    const char* client_cmd = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cmd") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return 2;
            }
            client_cmd = argv[++i];
        } else if (strcmp(argv[i], "--config-dir") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return 2;
            }
            strncpy(g_config_dir, argv[++i], sizeof(g_config_dir) - 1);
        } else if (strcmp(argv[i], "--socket") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return 2;
            }
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