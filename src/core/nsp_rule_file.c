/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#define _GNU_SOURCE
/*
 * nsp_rule_file.c — 规则配置文件行级读写实现（语义见 nsp_rule_file.h）
 *
 * 纯 libc，零项目全局依赖：不引用 common.h 的日志/配置状态，故 rule_server
 * （未链接 common.c 的既有路径）与 log_ctl 均可直接链接复用。
 *
 * 本文件由 log_ctl.c 与 rule_server.c 中两份逐字同构的私有实现合并而来，
 * 合并基准取 rule_server（权威控制面，索引语义与 LIST 输出一致）。合并顺带
 * 修掉 log_ctl 侧的非原子写：两处编辑同一个 injector.conf，而非原子写会让
 * injector 的 inotify 监听读到半截配置。
 */
#include "nsp_rule_file.h"
#include "nsp_util.h" /* nsp_getline_capped（编辑器回写路径的有界行读取） */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strncasecmp */
#include <unistd.h>

/* 行数组初始容量与扩容因子（与合并前两份实现一致） */
#define NSP_RULE_LINES_INIT_CAP 64

/* ==================== 行数组原语 ==================== */

char** nsp_rule_file_read(const char* path, int* out_count, int* out_cap) {
    if (out_count) *out_count = 0;
    if (out_cap) *out_cap = 0;
    if (!path) return NULL;

    FILE* fp = fopen(path, "r");
    if (!fp) return NULL;

    char** lines = NULL;
    int count = 0, cap = 0;
    /* 有界动态行读取（1MB 熔断，NSP_DYN_FORMAT_MAX）：超长整行丢弃，长行永不
       裂成多条“碎片规则”——旧 fgets 固定缓冲（2048B）会把超长行切成多段，
       下次编辑回写时碎片间被插入换行复活为多条畸形规则。 */
    char* line = NULL;
    size_t line_cap = 0;
    for (;;) {
        int r = nsp_getline_capped(fp, &line, &line_cap, NSP_DYN_FORMAT_MAX, NULL);
        if (r == 0) break;
        if (r == -2) continue; /* 超长整行丢弃，不参与匹配（与配置语义对齐） */
        if (r < 0) break;
        if (count >= cap) {
            int ncap = cap == 0 ? NSP_RULE_LINES_INIT_CAP : cap * 2;
            char** grown = realloc(lines, (size_t)ncap * sizeof(char*));
            if (!grown) {
                nsp_rule_file_free(lines, count);
                free(line);
                fclose(fp);
                return NULL;
            }
            lines = grown;
            cap = ncap;
        }
        /* 行尾换行归一：getline 已剥换行（含末行无换行与 \r\n），此处统一补齐，
           使写入路径面对的行数组恒满足"行尾带 \n"——任何"插到该行之后"的写入
           都不会与之粘连成同一行（如 "[USER_APPS:0]REDIRECT ..." 畸形配置）。
           写入本就会重写整个文件，补一个缺失的收尾换行无副作用。 */
        size_t llen = strlen(line);
        char* dup = malloc(llen + 2);
        if (dup) {
            memcpy(dup, line, llen);
            dup[llen] = '\n';
            dup[llen + 1] = '\0';
        }
        lines[count] = dup;
        if (!lines[count]) {
            nsp_rule_file_free(lines, count);
            free(line);
            fclose(fp);
            return NULL;
        }
        count++;
    }
    free(line);
    fclose(fp);
    if (out_count) *out_count = count;
    if (out_cap) *out_cap = cap;
    return lines;
}

bool nsp_rule_file_write(const char* path, char** lines, int count) {
    if (!path || count < 0) return false;
    char tmp[PATH_MAX];
    int n = snprintf(tmp, sizeof tmp, "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof tmp) {
        errno = ENAMETOOLONG;
        return false;
    }
    FILE* fp = fopen(tmp, "w");
    if (!fp) return false;
    for (int i = 0; i < count; i++) {
        if (fputs(lines[i], fp) < 0) {
            fclose(fp);
            unlink(tmp);
            return false;
        }
    }
    if (fclose(fp) != 0) {
        unlink(tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return false;
    }
    return true;
}

void nsp_rule_file_free(char** lines, int count) {
    if (!lines) return;
    for (int i = 0; i < count; i++) free(lines[i]);
    free(lines);
}

int nsp_rule_file_insert(char*** lines, int* cap, int count, int pos, const char* text) {
    if (!lines || !cap || !text || pos < 0 || pos > count) return NSP_RULE_FILE_EINVAL;
    if (count >= *cap) {
        int ncap = *cap == 0 ? NSP_RULE_LINES_INIT_CAP : *cap * 2;
        char** grown = realloc(*lines, (size_t)ncap * sizeof(char*));
        if (!grown) return NSP_RULE_FILE_EINVAL;
        *lines = grown;
        *cap = ncap;
    }
    memmove(&(*lines)[pos + 1], &(*lines)[pos], (size_t)(count - pos) * sizeof(char*));
    (*lines)[pos] = strdup(text);
    return (*lines)[pos] ? count + 1 : NSP_RULE_FILE_EINVAL;
}

void nsp_rule_file_remove(char** lines, int* count, int pos) {
    if (!lines || !count || pos < 0 || pos >= *count) return;
    free(lines[pos]);
    memmove(&lines[pos], &lines[pos + 1], (size_t)(*count - pos - 1) * sizeof(char*));
    (*count)--;
}

int nsp_rule_file_append(char*** lines, int* cap, int count, const char* text) {
    return nsp_rule_file_insert(lines, cap, count, count, text);
}

/* ==================== 段与类型匹配 ==================== */

int nsp_rule_file_find_section(char** lines, int count, const char* name) {
    if (!lines || !name) return NSP_RULE_FILE_ENOTFND;
    size_t nlen = strlen(name);
    for (int i = 0; i < count; i++) {
        char* p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (p[0] == '[' && strncmp(p + 1, name, nlen) == 0) {
            char after = p[1 + nlen];
            if (after == ']' || after == ':') return i;
        }
    }
    return NSP_RULE_FILE_ENOTFND;
}

int nsp_rule_file_find_header(char** lines, int count, const char* hdr_text) {
    if (!lines || !hdr_text) return NSP_RULE_FILE_ENOTFND;
    size_t hlen = strlen(hdr_text);
    for (int i = 0; i < count; i++) {
        char* p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (strncmp(p, hdr_text, hlen) != 0) continue;
        char* rest = p + hlen;
        while (isspace((unsigned char)*rest)) rest++;
        /* ON/OFF 须有边界（空白/NUL/换行），[USER_APPS:0]OFFX 之类不算段头 */
        if (*rest == '\0' || *rest == '\n') return i;
        if (strncmp(rest, "ON", 2) == 0 &&
            (rest[2] == '\0' || rest[2] == '\n' || isspace((unsigned char)rest[2])))
            return i;
        if (strncmp(rest, "OFF", 3) == 0 &&
            (rest[3] == '\0' || rest[3] == '\n' || isspace((unsigned char)rest[3])))
            return i;
    }
    return NSP_RULE_FILE_ENOTFND;
}

int nsp_rule_file_find_switch(char** lines, int count, int header_idx, const char* type) {
    if (!lines || !type || header_idx < 0) return NSP_RULE_FILE_ENOTFND;
    size_t tlen = strlen(type);
    for (int i = header_idx + 1; i < count; i++) {
        char* p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (p[0] == '[') break;
        if (strncasecmp(p, type, tlen) == 0 &&
            (p[tlen] == ' ' || p[tlen] == '\t' || p[tlen] == '\n'))
            return i;
    }
    return NSP_RULE_FILE_ENOTFND;
}

bool nsp_rule_file_is_category_pkg(const char* pkg) {
    /* 大小写敏感，与 config_parser 及 GLOBAL 段一致：控制面不得把
       [user_apps:0] 当类别写入（parser 会将其按普通应用加载） */
    return pkg && (strcmp(pkg, "USER_APPS") == 0 || strcmp(pkg, "SYSTEM_APPS") == 0);
}

void nsp_rule_file_category_name(const char* pkg, int uid, char* out, size_t sz) {
    if (!out || sz == 0) return;
    if (pkg && strcmp(pkg, "SYSTEM_APPS") == 0)
        snprintf(out, sz, "SYSTEM_APPS");
    else
        snprintf(out, sz, "USER_APPS:%d", uid < 0 ? 0 : uid);
}

bool nsp_rule_file_line_is_type(const char* line, const char* type_name) {
    if (!line || !type_name) return false;
    const char* p = line;
    /* 只跳空格与制表符（不跳换行）：空行不应被误判为规则行 */
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#') { /* 已停用行（# 前缀）仍算该类型规则，与 LIST 索引一致 */
        p++;
        while (*p == ' ' || *p == '\t') p++;
    }
    if (*p == '[' || *p == '\0' || *p == '\n') return false;
    size_t nlen = strlen(type_name);
    if (strncasecmp(p, type_name, nlen) != 0) return false;
    char after = p[nlen];
    return after == ' ' || after == '\t' || after == '\n' || after == '\0';
}

int nsp_rule_file_find_nth(char** lines, int count, const char* type_name, int index) {
    if (!lines || !type_name || index < 0) return NSP_RULE_FILE_ENOTFND;
    int seen = 0;
    for (int i = 0; i < count; i++) {
        if (nsp_rule_file_line_is_type(lines[i], type_name)) {
            if (seen == index) return i;
            seen++;
        }
    }
    return NSP_RULE_FILE_ENOTFND;
}

/* ==================== 段式文件写入 ==================== */

int nsp_rule_file_upsert_in_section(const char* path, const char* sec_name,
                                    NspRuleSectionMatch sec_match, bool is_switch,
                                    const char* type_name, const char* line, bool* out_changed) {
    if (!path || !sec_name || !line) return NSP_RULE_FILE_EINVAL;
    if (is_switch && !type_name) return NSP_RULE_FILE_EINVAL;
    if (out_changed) *out_changed = false;

    /* 匹配文本与写入文本必须分开：find_header 靠"段头之后为空白或 ON/OFF"
       来容忍 [X] OFF / [X]␠␠ / 末行无换行，传入带 \n 的文本会让这些形态全部
       失配（\n 与行内的空白/ON/OFF 首字符不等），误判段头缺失后追加重复段 ——
       而重复段的段头是默认 ON，会把显式 [X] OFF 的类别悄悄重新使能 */
    char sec_match_hdr[128];
    int mn = snprintf(sec_match_hdr, sizeof sec_match_hdr, "[%s]", sec_name);
    if (mn < 0 || (size_t)mn >= sizeof sec_match_hdr) return NSP_RULE_FILE_EINVAL;
    char sec_hdr[132];
    int hn = snprintf(sec_hdr, sizeof sec_hdr, "%s\n", sec_match_hdr);
    if (hn < 0 || (size_t)hn >= sizeof sec_hdr) return NSP_RULE_FILE_EINVAL;

    int count = 0, cap = 0;
    char** lines = nsp_rule_file_read(path, &count, &cap);
    bool changed = false;

    int hdr = (sec_match == NSP_RULE_SEC_PREFIX)
                  ? nsp_rule_file_find_section(lines, count, sec_name)
                  : nsp_rule_file_find_header(lines, count, sec_match_hdr);

    if (is_switch) {
        /* 开关：段内就地替换（保持唯一），无则插段头后；段头缺失则新建段 */
        if (hdr >= 0) {
            int old = nsp_rule_file_find_switch(lines, count, hdr, type_name);
            if (old >= 0) {
                if (strcmp(lines[old], line) != 0) {
                    char* dup = strdup(line);
                    if (!dup) {
                        nsp_rule_file_free(lines, count);
                        return NSP_RULE_FILE_EINVAL;
                    }
                    free(lines[old]);
                    lines[old] = dup;
                    changed = true;
                }
            } else {
                int nc = nsp_rule_file_insert(&lines, &cap, count, hdr + 1, line);
                if (nc < 0) {
                    nsp_rule_file_free(lines, count);
                    return NSP_RULE_FILE_EINVAL;
                }
                count = nc;
                changed = true;
            }
        } else {
            if (nsp_rule_file_append(&lines, &cap, count, sec_hdr) < 0 ||
                nsp_rule_file_append(&lines, &cap, count + 1, line) < 0) {
                nsp_rule_file_free(lines, count);
                return NSP_RULE_FILE_EINVAL;
            }
            count += 2;
            changed = true;
        }
    } else {
        /* 规则行：全文件去重后插段头之后；段头缺失则新建段 */
        bool dup = false;
        for (int i = 0; i < count; i++) {
            if (strcmp(lines[i], line) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            int pos = (hdr >= 0) ? hdr + 1 : count;
            if (hdr < 0) {
                if (nsp_rule_file_append(&lines, &cap, count, sec_hdr) < 0) {
                    nsp_rule_file_free(lines, count);
                    return NSP_RULE_FILE_EINVAL;
                }
                count++;
                pos = count;
            }
            int nc = nsp_rule_file_insert(&lines, &cap, count, pos, line);
            if (nc < 0) {
                nsp_rule_file_free(lines, count);
                return NSP_RULE_FILE_EINVAL;
            }
            count = nc;
            changed = true;
        }
    }

    if (changed && !nsp_rule_file_write(path, lines, count)) {
        nsp_rule_file_free(lines, count);
        return NSP_RULE_FILE_EIO;
    }
    nsp_rule_file_free(lines, count);
    if (out_changed) *out_changed = changed;
    return NSP_RULE_FILE_OK;
}

/* ==================== 无段文件写入 ==================== */

int nsp_rule_file_upsert_line(const char* path, bool is_switch, const char* type_name,
                              const char* line, bool* out_changed) {
    if (!path || !line) return NSP_RULE_FILE_EINVAL;
    if (is_switch && !type_name) return NSP_RULE_FILE_EINVAL;
    if (out_changed) *out_changed = false;

    int count = 0, cap = 0;
    char** lines = nsp_rule_file_read(path, &count, &cap);
    bool changed = false;

    if (is_switch) {
        /* 开关：替换文件中首个同类型开关行（保持唯一，后写覆盖），无则追加 */
        int old = -1;
        for (int i = 0; i < count; i++) {
            if (nsp_rule_file_line_is_type(lines[i], type_name)) {
                old = i;
                break;
            }
        }
        if (old >= 0) {
            if (strcmp(lines[old], line) != 0) {
                char* dup = strdup(line);
                if (!dup) {
                    nsp_rule_file_free(lines, count);
                    return NSP_RULE_FILE_EINVAL;
                }
                free(lines[old]);
                lines[old] = dup;
                changed = true;
            }
        } else {
            int nc = nsp_rule_file_append(&lines, &cap, count, line);
            if (nc < 0) {
                nsp_rule_file_free(lines, count);
                return NSP_RULE_FILE_EINVAL;
            }
            count = nc;
            changed = true;
        }
    } else {
        /* 规则行：全文件去重后追加 */
        bool dup = false;
        for (int i = 0; i < count; i++) {
            if (strcmp(lines[i], line) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            int nc = nsp_rule_file_append(&lines, &cap, count, line);
            if (nc < 0) {
                nsp_rule_file_free(lines, count);
                return NSP_RULE_FILE_EINVAL;
            }
            count = nc;
            changed = true;
        }
    }

    if (changed && !nsp_rule_file_write(path, lines, count)) {
        nsp_rule_file_free(lines, count);
        return NSP_RULE_FILE_EIO;
    }
    nsp_rule_file_free(lines, count);
    if (out_changed) *out_changed = changed;
    return NSP_RULE_FILE_OK;
}

/* ==================== 按 (类型, 索引) 删除 ==================== */

int nsp_rule_file_remove_nth(const char* path, const char* type_name, int index, char* out_removed,
                             size_t removed_sz) {
    if (!path || !type_name || index < 0) return NSP_RULE_FILE_EINVAL;

    int count = 0, cap = 0;
    char** lines = nsp_rule_file_read(path, &count, &cap);
    if (!lines) return NSP_RULE_FILE_EIO;

    int found = nsp_rule_file_find_nth(lines, count, type_name, index);
    if (found < 0) {
        nsp_rule_file_free(lines, count);
        return NSP_RULE_FILE_ENOTFND;
    }
    if (out_removed && removed_sz) snprintf(out_removed, removed_sz, "%s", lines[found]);

    nsp_rule_file_remove(lines, &count, found);
    if (!nsp_rule_file_write(path, lines, count)) {
        nsp_rule_file_free(lines, count);
        return NSP_RULE_FILE_EIO;
    }
    nsp_rule_file_free(lines, count);
    return NSP_RULE_FILE_OK;
}
