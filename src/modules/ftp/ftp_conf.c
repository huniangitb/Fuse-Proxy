#define _GNU_SOURCE
#include "ftp_conf.h"
#include "nsp_module.h" /* LOG_WRN（模块 ABI，经主程序导出表解析，与同目录后端一致） */
#include "nsp_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* 去首尾空白经 nsp_util 公共库复用（nsp_str_trim），禁私刻 trim 副本 */

/* 去掉行内注释（'#' 前导）与尾部空白 */
static void strip_comment(char* line) {
    char* hash = strchr(line, '#');
    if (hash) *hash = '\0';
}

/* 失败闭合拷贝：放得下返回 true；放不下返回 false 且 dst 置空
   （调用方将整段标 bad，绝不带着截断的 host/remote_dir 去连接错地方）。 */
static bool set_str_checked(char* dst, size_t sz, const char* v) {
    size_t vl = strlen(v);
    if (vl >= sz) {
        dst[0] = '\0';
        return false;
    }
    memcpy(dst, v, vl + 1);
    return true;
}

#define FTP_CONF_LINE_MAX 1024

/* 新段槽位：动态翻倍（初容 FTP_CONF_MAX_SERVERS），OOM 返回 NULL
   （调用方将后续键值静默丢弃——整段失效但不断解析；OOM 极罕见）。 */
static FtpServerCfg* ftp_conf_new_server(FtpServerList* out) {
    if (out->count >= out->cap) {
        int ncap = out->cap > 0 ? out->cap * 2 : FTP_CONF_MAX_SERVERS;
        FtpServerCfg* grown = realloc(out->servers, (size_t)ncap * sizeof *grown);
        if (!grown) return NULL;
        out->servers = grown;
        out->cap = ncap;
    }
    FtpServerCfg* cur = &out->servers[out->count];
    memset(cur, 0, sizeof *cur);
    cur->port = 21;
    cur->bad = false;
    if (!set_str_checked(cur->remote_dir, sizeof cur->remote_dir, "/")) cur->bad = true;
    if (!set_str_checked(cur->user, sizeof cur->user, "anonymous")) cur->bad = true;
    out->count++;
    return cur;
}

int ftp_conf_load(const char* path, FtpServerList* out) {
    memset(out, 0, sizeof *out);
    FILE* fp = fopen(path, "r");
    if (!fp) return -1;

    char* line = nullptr;
    size_t line_cap = 0;
    char cur_section[128] = {0};
    bool cur_section_bad = false; /* 段名超长：整段跳过（不建 server，不消费键） */
    FtpServerCfg* cur = NULL;
    int lineno = 0;

    /* 有界动态行读取：超长行整行丢弃（长行永不裂成“段头碎片 + 键值碎片”） */
    for (;;) {
        int r = nsp_getline_capped(fp, &line, &line_cap, FTP_CONF_LINE_MAX, NULL);
        if (r == 0) break;
        lineno++;
        if (r == -2) {
            LOG_WRN("ftp.conf %s 第 %d 行超长（>%d 字节），整行跳过", path, lineno,
                    FTP_CONF_LINE_MAX);
            /* 超长值行被整行丢弃：字段会静默回默认（fail-open 缝隙），故整段作废
               fail-closed。长注释行亦毒化段落——可接受，配合本日志可查。 */
            if (cur) cur->bad = true;
            continue; /* 超长整行跳过（段声明亦不生效） */
        }
        if (r < 0) break;
        strip_comment(line);
        char* s = nsp_str_trim(line);
        if (!s[0]) continue;

        if (s[0] == '[') {
            char* close = strchr(s, ']');
            if (!close) continue;
            *close = '\0';
            const char* sec = nsp_str_trim(s + 1);
            /* 段名超长（≥64，含中文段名按字节计）：整段跳过，不建 server。
               截断段名会造成虚拟前缀碰撞（/云盘… 截成 /云盘），失败闭合。 */
            if (strlen(sec) >= sizeof(((FtpServerCfg*)0)->name)) {
                cur_section[0] = '\0';
                cur_section_bad = true;
                cur = NULL;
                continue;
            }
            if (!set_str_checked(cur_section, sizeof cur_section, sec)) {
                cur_section[0] = '\0';
                cur_section_bad = true;
                cur = NULL;
                continue;
            }
            cur_section_bad = false;
            if (strcmp(cur_section, "GLOBAL") == 0) {
                cur = NULL;
                continue;
            }
            cur = ftp_conf_new_server(out);
            if (cur) {
                /* 段名长度已校验，必成功；失败亦标 bad（纵深防御） */
                if (!set_str_checked(cur->name, sizeof cur->name, cur_section))
                    cur->bad = true;
            }
            continue;
        }

        char* eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char* key = nsp_str_trim(s);
        char* val = nsp_str_trim(eq + 1);
        if (!key[0]) continue;

        if (!cur || cur_section_bad) {
            /* [GLOBAL] 段键（虚拟前缀 = /段名，不再有 mount_base 语义）；
               超长段名后的键一律丢弃（cur==NULL 已保证） */
            continue;
        }

        if (strcmp(key, "host") == 0) {
            if (!set_str_checked(cur->host, sizeof cur->host, val)) cur->bad = true;
        } else if (strcmp(key, "port") == 0) {
            cur->port = atoi(val);
        } else if (strcmp(key, "user") == 0) {
            if (!set_str_checked(cur->user, sizeof cur->user, val)) cur->bad = true;
        } else if (strcmp(key, "password") == 0 || strcmp(key, "pass") == 0) {
            if (!set_str_checked(cur->pass, sizeof cur->pass, val)) cur->bad = true;
        } else if (strcmp(key, "remote_dir") == 0) {
            if (!set_str_checked(cur->remote_dir, sizeof cur->remote_dir, val)) cur->bad = true;
        }
        /* 其他键忽略（passive/encoding 等预留） */
    }
    free(line);
    fclose(fp);

    /* 清理无效段：无 host 的段无效；任一字段超长（bad）整段作废——
       绝不带着截断的 host/remote_dir 去连接或映射错地方 */
    int n = 0;
    for (int i = 0; i < out->count; i++) {
        if (out->servers[i].bad) {
            LOG_WRN("ftp.conf [%s] 字段超长，整段作废", out->servers[i].name);
            continue;
        }
        if (out->servers[i].host[0]) {
            if (n != i) out->servers[n] = out->servers[i];
            n++;
        }
    }
    out->count = n;
    return out->count > 0 ? 0 : -1;
}

void ftp_conf_free(FtpServerList* list) {
    if (!list) return;
    free(list->servers);
    list->servers = NULL;
    list->count = 0;
    list->cap = 0;
}

FtpServerCfg* ftp_conf_find(FtpServerList* list, const char* name) {
    if (!list || !name) return NULL;
    for (int i = 0; i < list->count; i++) {
        if (strcmp(list->servers[i].name, name) == 0) return &list->servers[i];
    }
    return NULL;
}
