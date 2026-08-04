#define _GNU_SOURCE
#include "ftp_conf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* 去首尾空白 */
static char* trim(char* s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char* end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = '\0';
    return s;
}

/* 去掉行内注释（'#' 前导）与尾部空白 */
static void strip_comment(char* line) {
    char* hash = strchr(line, '#');
    if (hash) *hash = '\0';
}

static void set_str(char* dst, size_t sz, const char* v) {
    strncpy(dst, v, sz - 1);
    dst[sz - 1] = '\0';
}

int ftp_conf_load(const char* path, FtpServerList* out) {
    memset(out, 0, sizeof *out);
    FILE* fp = fopen(path, "r");
    if (!fp) return -1;

    char line[1024];
    char cur_section[128] = {0};
    FtpServerCfg* cur = NULL;

    while (fgets(line, sizeof line, fp)) {
        strip_comment(line);
        char* s = trim(line);
        if (!s[0]) continue;

        if (s[0] == '[') {
            char* close = strchr(s, ']');
            if (!close) continue;
            *close = '\0';
            set_str(cur_section, sizeof cur_section, trim(s + 1));
            if (strcmp(cur_section, "GLOBAL") == 0) {
                cur = NULL;
                continue;
            }
            if (out->count < FTP_CONF_MAX_SERVERS) {
                cur = &out->servers[out->count];
                memset(cur, 0, sizeof *cur);
                cur->port = 21;
                set_str(cur->remote_dir, sizeof cur->remote_dir, "/");
                set_str(cur->user, sizeof cur->user, "anonymous");
                set_str(cur->name, sizeof cur->name, cur_section);   /* 段名 = 服务器名 */
                out->count++;
            } else {
                cur = NULL;
            }
            continue;
        }

        char* eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char* key = trim(s);
        char* val = trim(eq + 1);
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

FtpServerCfg* ftp_conf_find(FtpServerList* list, const char* name) {
    if (!list || !name) return NULL;
    for (int i = 0; i < list->count; i++) {
        if (strcmp(list->servers[i].name, name) == 0)
            return &list->servers[i];
    }
    return NULL;
}
