#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ftp_conf.h"
#include "nsp_module.h" /* LOG_WRN（模块 ABI，经主程序导出表解析，与同目录后端一致） */
#include "nsp_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp（proto / host_key_check 解析） */
#include <ctype.h>

/* 去首尾空白经 nsp_util 公共库复用（nsp_str_trim），禁私刻 trim 副本 */

/* 去掉行内注释与尾部空白。
   `#` 仅在**行首或前面是空白**时才起注释——此前无条件截断，含 '#' 的密码
   （如 `pass = p#ssw0rd`）被静默改成 `p`，服务器按 530 拒绝，而 530 被判为
   业务失败不熔断 → 永久静默失败且配置看不出问题。
   与「shell/INI 惯例一致」：`#` 作注释符需在行首或空白之后；词中间视作普通
   字符（与同样在本栈的 nsp_ini_store 取值语义对齐）。 */
static void strip_comment(char* line) {
    for (char* p = line; *p; p++) {
        if (*p == '#' && (p == line || isspace((unsigned char)p[-1]))) {
            *p = '\0'; /* 行首整行注释，或空白后的行内注释 */
            return;
        }
    }
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
    /* port 0 = 未显式配置：载入结束时按 proto 补默认（ftp 21 / sftp 22），
       故配置项顺序无关（proto 写在 port 之后也正确） */
    cur->port = 0;
    cur->host_key_check = true; /* 主机密钥校验默认开启（fail-closed） */
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
            /* 端口范围校验：此前 atoi 直取，0/负数/超 65535/非数字（atoi→0）
               全被照收，最终以 "ftp://host:0/" 形式交给 libcurl，报错信息
               完全指不到配置行。非法值整段作废（同字段超长的失败闭合姿态），
               并 loud 告警指出段名与原始值。 */
            char* endp = NULL;
            long v = strtol(val, &endp, 10);
            if (endp == val || *nsp_str_trim(endp) != '\0' || v < 1 || v > 65535) {
                LOG_WRN("ftp.conf [%s] port 非法（\"%s\"，须 1..65535），整段作废", cur->name, val);
                cur->bad = true;
            } else {
                cur->port = (int)v;
            }
        } else if (strcmp(key, "user") == 0) {
            if (!set_str_checked(cur->user, sizeof cur->user, val)) cur->bad = true;
        } else if (strcmp(key, "password") == 0 || strcmp(key, "pass") == 0) {
            if (!set_str_checked(cur->pass, sizeof cur->pass, val)) cur->bad = true;
        } else if (strcmp(key, "remote_dir") == 0) {
            if (!set_str_checked(cur->remote_dir, sizeof cur->remote_dir, val)) cur->bad = true;
        } else if (strcmp(key, "proto") == 0 || strcmp(key, "protocol") == 0) {
            /* 协议：ftp（默认）/ sftp。拼错即整段作废——静默回退 ftp 会让
               用户以为连的是 SFTP，实际把账号密码发到明文 FTP 上 */
            if (strcasecmp(val, "ftp") == 0) {
                cur->sftp = false;
            } else if (strcasecmp(val, "sftp") == 0) {
                cur->sftp = true;
            } else {
                LOG_WRN("ftp.conf [%s] proto 非法（\"%s\"，须 ftp|sftp），整段作废", cur->name, val);
                cur->bad = true;
            }
        } else if (strcmp(key, "key_file") == 0 || strcmp(key, "identity_file") == 0) {
            if (!set_str_checked(cur->key_file, sizeof cur->key_file, val)) cur->bad = true;
        } else if (strcmp(key, "key_pass") == 0 || strcmp(key, "key_passphrase") == 0) {
            if (!set_str_checked(cur->key_pass, sizeof cur->key_pass, val)) cur->bad = true;
        } else if (strcmp(key, "known_hosts") == 0) {
            if (!set_str_checked(cur->known_hosts, sizeof cur->known_hosts, val)) cur->bad = true;
        } else if (strcmp(key, "host_key_check") == 0) {
            /* 三态解析：只认明确的开关词，其余整段作废（同 port 的失败闭合姿态） */
            if (strcasecmp(val, "on") == 0 || strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0) {
                cur->host_key_check = true;
            } else if (strcasecmp(val, "off") == 0 || strcasecmp(val, "false") == 0 ||
                       strcmp(val, "0") == 0) {
                cur->host_key_check = false;
            } else {
                LOG_WRN("ftp.conf [%s] host_key_check 非法（\"%s\"，须 on|off），整段作废",
                        cur->name, val);
                cur->bad = true;
            }
        }
        /* 其他键忽略（passive/encoding 等预留） */
    }
    free(line);
    fclose(fp);

    /* 未显式配置端口：按协议补默认（ftp 21 / sftp 22）。放在段作废过滤之前，
       与配置项书写顺序无关（proto 可出现在 port 之后） */
    for (int i = 0; i < out->count; i++)
        if (out->servers[i].port == 0) out->servers[i].port = out->servers[i].sftp ? 22 : 21;

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

