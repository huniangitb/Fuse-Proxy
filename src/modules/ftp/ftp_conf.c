#define _GNU_SOURCE
#include "ftp_conf.h"
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

static void set_str(char* dst, size_t sz, const char* v) {
    strncpy(dst, v, sz - 1);
    dst[sz - 1] = '\0';
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
    set_str(cur->remote_dir, sizeof cur->remote_dir, "/");
    set_str(cur->user, sizeof cur->user, "anonymous");
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
    FtpServerCfg* cur = NULL;

    /* 有界动态行读取：超长行整行丢弃（长行永不裂成“段头碎片 + 键值碎片”） */
    for (;;) {
        int r = nsp_getline_capped(fp, &line, &line_cap, FTP_CONF_LINE_MAX, NULL);
        if (r == 0) break;
        if (r == -2) continue; /* 超长整行跳过（段声明亦不生效） */
        if (r < 0) break;
        strip_comment(line);
        char* s = nsp_str_trim(line);
        if (!s[0]) continue;

        if (s[0] == '[') {
            char* close = strchr(s, ']');
            if (!close) continue;
            *close = '\0';
            set_str(cur_section, sizeof cur_section, nsp_str_trim(s + 1));
            if (strcmp(cur_section, "GLOBAL") == 0) {
                cur = NULL;
                continue;
            }
            cur = ftp_conf_new_server(out);
            if (cur) set_str(cur->name, sizeof cur->name, cur_section); /* 段名 = 服务器名 */
            continue;
        }

        char* eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char* key = nsp_str_trim(s);
        char* val = nsp_str_trim(eq + 1);
        if (!key[0]) continue;

        if (!cur) {
            /* [GLOBAL] 段键（虚拟前缀 = /段名，不再有 mount_base 语义） */
            continue;
        }

        if (strcmp(key, "host") == 0) {
            set_str(cur->host, sizeof cur->host, val);
        } else if (strcmp(key, "port") == 0) {
            cur->port = atoi(val);
        } else if (strcmp(key, "user") == 0) {
            set_str(cur->user, sizeof cur->user, val);
        } else if (strcmp(key, "password") == 0 || strcmp(key, "pass") == 0) {
            set_str(cur->pass, sizeof cur->pass, val);
        } else if (strcmp(key, "remote_dir") == 0) {
            set_str(cur->remote_dir, sizeof cur->remote_dir, val);
        }
        /* 其他键忽略（passive/encoding 等预留） */
    }
    free(line);
    fclose(fp);

    /* 清理无 host 的 server 段（未配置 host= 的段无效） */
    int n = 0;
    for (int i = 0; i < out->count; i++) {
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
