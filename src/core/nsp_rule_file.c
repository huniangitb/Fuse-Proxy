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
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strncasecmp */
#include <sys/file.h> /* flock：跨进程串行化读改写 */
#include <sys/stat.h>
#include <unistd.h>

/* 行数组初始容量与扩容因子（与合并前两份实现一致） */
#define NSP_RULE_LINES_INIT_CAP 64

/* ==================== 行数组原语 ==================== */

char** nsp_rule_file_read_ex(const char* path, int* out_count, int* out_cap, int* out_err) {
    if (out_count) *out_count = 0;
    if (out_cap) *out_cap = 0;
    if (out_err) *out_err = 0;
    if (!path) {
        if (out_err) *out_err = EINVAL;
        return NULL;
    }

    FILE* fp = fopen(path, "r");
    if (!fp) {
        if (out_err) *out_err = errno ? errno : EIO;
        return NULL;
    }

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
                if (out_err) *out_err = ENOMEM;
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
            if (out_err) *out_err = ENOMEM;
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

char** nsp_rule_file_read(const char* path, int* out_count, int* out_cap) {
    return nsp_rule_file_read_ex(path, out_count, out_cap, NULL);
}

/* 目录 fsync（rename 的持久化点）：失败不致命，仅尽力而为 */
static void rule_file_fsync_dir(const char* path) {
    char dir[PATH_MAX];
    int n = snprintf(dir, sizeof dir, "%s", path ? path : "");
    if (n < 0 || (size_t)n >= sizeof dir) return;
    char* slash = strrchr(dir, '/');
    if (!slash) return;
    if (slash == dir)
        dir[1] = '\0';
    else
        *slash = '\0';
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return;
    fsync(fd);
    close(fd);
}

/* 原子落盘（内部独占）：对外唯一的写入路径是 nsp_rule_file_edit，见文件末尾。
 * 本函数刻意不进入公共头文件——调用方拿不到无锁写入口，也就无法自行拼出
 * 「读全文 → 改一行 → 覆盖写」而绕过目录 flock（§C6）。 */
static bool rule_file_write(const char* path, char** lines, int count) {
    if (!path || count < 0) return false;
    /* 临时名带 pid：同一目录可能被多个进程（rule_server 与多个 log_ctl）同时编辑，
       固定 <path>.tmp 会让两个写者互相 rename 掉对方尚未写完的临时文件 */
    char tmp[PATH_MAX];
    int n = snprintf(tmp, sizeof tmp, "%s.tmp.%ld", path, (long)getpid());
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
    /* 持久性：fclose 只把数据交给内核，掉电时可能"rename 已生效、内容还是旧的"。
       先 fsync 文件内容，再 rename，最后 fsync 目录让 rename 本身持久化 */
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        fclose(fp);
        unlink(tmp);
        return false;
    }
    if (fclose(fp) != 0) {
        unlink(tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return false;
    }
    rule_file_fsync_dir(path);
    return true;
}

/* 跨进程串行化「读-改-写」：flock 于规则文件所在目录（目录 fd 上 flock 合法，
   也不必额外维护锁文件）。不取锁时两边仍各自原子落盘，但两个编辑者读到同一份
   内容再各自写回，后写者会吃掉前者的修改。取锁失败按 fail-open 继续（绝不因
   锁不可用而拒绝编辑）。 */
static int rule_file_lock_dir(const char* path) {
    char dir[PATH_MAX];
    int n = snprintf(dir, sizeof dir, "%s", path ? path : "");
    if (n < 0 || (size_t)n >= sizeof dir) return -1;
    char* slash = strrchr(dir, '/');
    if (!slash) return -1;
    if (slash == dir)
        dir[1] = '\0';
    else
        *slash = '\0';
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    while (flock(fd, LOCK_EX) != 0) {
        if (errno == EINTR) continue;
        close(fd);
        return -1;
    }
    return fd;
}

static void rule_file_unlock_dir(int fd) {
    if (fd < 0) return;
    flock(fd, LOCK_UN);
    close(fd);
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

void nsp_rule_file_app_active_path(const char* config_dir, int uid, const char* pkg, char* out,
                                   size_t sz) {
    if (!out || sz == 0) return;
    char path[PATH_MAX];
    nsp_app_rule_path(config_dir, uid, pkg, path, sizeof(path));
    if (access(path, F_OK) == 0) {
        snprintf(out, sz, "%s", path);
        return;
    }
    char dis[PATH_MAX];
    int dn = snprintf(dis, sizeof(dis), "%s.disabled", path);
    if (dn > 0 && (size_t)dn < sizeof(dis) && access(dis, F_OK) == 0) {
        snprintf(out, sz, "%s", dis);
        return;
    }
    snprintf(out, sz, "%s", path); /* 两者皆无（或路径过长表达不出 .disabled）→ base */
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
    return nsp_rule_file_find_nth_scoped(lines, count, NULL, type_name, index);
}

/* 该行是否为名为 name 的段头（match 决定精确/前缀匹配）。
 * 与 find_section/find_header 的判定逐条对齐：PREFIX 接受 [name] / [name:...]；
 * EXACT 要求 [name] 且其后为空白/ON/OFF/行尾。 */
static bool line_is_section_named(const char* line, const char* name, NspRuleSectionMatch match) {
    if (!line || !name) return false;
    const char* p = line;
    while (isspace((unsigned char)*p)) p++;
    if (*p != '[') return false;
    size_t nlen = strlen(name);
    if (strncmp(p + 1, name, nlen) != 0) return false;
    char after = p[1 + nlen];
    if (match == NSP_RULE_SEC_PREFIX) return after == ']' || after == ':';
    if (after != ']') return false;
    const char* rest = p + 2 + nlen;
    while (isspace((unsigned char)*rest)) rest++;
    if (*rest == '\0' || *rest == '\n') return true;
    if (strncmp(rest, "ON", 2) == 0 &&
        (rest[2] == '\0' || rest[2] == '\n' || isspace((unsigned char)rest[2])))
        return true;
    if (strncmp(rest, "OFF", 3) == 0 &&
        (rest[3] == '\0' || rest[3] == '\n' || isspace((unsigned char)rest[3])))
        return true;
    return false;
}

bool nsp_rule_file_scope_range(char** lines, int count, const NspRuleScope* scope, int* out_beg,
                               int* out_end) {
    int beg = 0, end = count;
    if (scope && scope->sec_name) {
        if (scope->sec_match == NSP_RULE_SEC_PREFIX) {
            /* GLOBAL：文件起始到首个非本段段头（本段段头透明）。首个段头之前
               的规则归属全局，与解析器 cur 初值一致。 */
            for (int i = 0; i < count; i++) {
                const char* p = lines[i];
                while (isspace((unsigned char)*p)) p++;
                if (*p != '[') continue;
                if (line_is_section_named(lines[i], scope->sec_name, NSP_RULE_SEC_PREFIX)) continue;
                end = i;
                break;
            }
        } else {
            char hdr[128];
            int n = snprintf(hdr, sizeof hdr, "[%s]", scope->sec_name);
            if (n < 0 || (size_t)n >= sizeof hdr) return false;
            int h = nsp_rule_file_find_header(lines, count, hdr);
            if (h < 0) return false;
            beg = h + 1;
            for (int i = beg; i < count; i++) {
                const char* p = lines[i];
                while (isspace((unsigned char)*p)) p++;
                if (*p == '[') {
                    end = i;
                    break;
                }
            }
        }
    }
    if (out_beg) *out_beg = beg;
    if (out_end) *out_end = end;
    return true;
}

int nsp_rule_file_find_nth_scoped(char** lines, int count, const NspRuleScope* scope,
                                  const char* type_name, int index) {
    if (!lines || !type_name || index < 0) return NSP_RULE_FILE_ENOTFND;
    int beg = 0, end = count;
    if (scope && scope->sec_name &&
        !nsp_rule_file_scope_range(lines, count, scope, &beg, &end))
        return NSP_RULE_FILE_ENOTFND;
    int seen = 0;
    for (int i = beg; i < end; i++) {
        if (nsp_rule_file_line_is_type(lines[i], type_name)) {
            if (seen == index) return i;
            seen++;
        }
    }
    return NSP_RULE_FILE_ENOTFND;
}

/* ==================== 段式文件写入 ==================== */

typedef struct {
    const char* sec_name;
    NspRuleSectionMatch sec_match;
    bool is_switch;
    const char* type_name;
    const char* line;
} EditUpsertSectionCtx;

/* 段式 upsert 的编辑体（在 nsp_rule_file_edit 事务内改行数组；不读写文件、不取锁）。
 * 出错时直接返回错误码——行数组所有权归事务，本函数不得释放它。 */
static int edit_upsert_in_section(char*** lines_p, int* count_p, int* cap_p, void* vctx,
                                  bool* out_changed) {
    const EditUpsertSectionCtx* c = vctx;
    char** lines = *lines_p;
    int count = *count_p;
    int cap = *cap_p;

    /* 匹配文本与写入文本必须分开：find_header 靠"段头之后为空白或 ON/OFF"
       来容忍 [X] OFF / [X] 带尾随空白 / 末行无换行，传入带 \n 的文本会让这些
       形态全部失配（\n 与行内的空白/ON/OFF 首字符不等），误判段头缺失后追加
       重复段 —— 而重复段的段头是默认 ON，会把显式 [X] OFF 的类别悄悄重新使能 */
    char sec_match_hdr[128];
    int mn = snprintf(sec_match_hdr, sizeof sec_match_hdr, "[%s]", c->sec_name);
    if (mn < 0 || (size_t)mn >= sizeof sec_match_hdr) return NSP_RULE_FILE_EINVAL;
    char sec_hdr[132];
    int hn = snprintf(sec_hdr, sizeof sec_hdr, "%s\n", sec_match_hdr);
    if (hn < 0 || (size_t)hn >= sizeof sec_hdr) return NSP_RULE_FILE_EINVAL;

    bool changed = false;

    int hdr = (c->sec_match == NSP_RULE_SEC_PREFIX)
                  ? nsp_rule_file_find_section(lines, count, c->sec_name)
                  : nsp_rule_file_find_header(lines, count, sec_match_hdr);

    if (c->is_switch) {
        /* 开关：段内就地替换（保持唯一），无则插段头后；段头缺失则新建段 */
        if (hdr >= 0) {
            int old = nsp_rule_file_find_switch(lines, count, hdr, c->type_name);
            if (old >= 0) {
                if (strcmp(lines[old], c->line) != 0) {
                    char* dup = strdup(c->line);
                    if (!dup) return NSP_RULE_FILE_EINVAL;
                    free(lines[old]);
                    lines[old] = dup;
                    changed = true;
                }
            } else {
                int nc = nsp_rule_file_insert(&lines, &cap, count, hdr + 1, c->line);
                if (nc < 0) return NSP_RULE_FILE_EINVAL;
                count = nc;
                changed = true;
            }
        } else {
            if (nsp_rule_file_append(&lines, &cap, count, sec_hdr) < 0)
                return NSP_RULE_FILE_EINVAL;
            count++;
            if (nsp_rule_file_append(&lines, &cap, count, c->line) < 0)
                return NSP_RULE_FILE_EINVAL;
            count++;
            changed = true;
        }
    } else {
        /* 规则行：全文件去重后插段头之后；段头缺失则新建段 */
        bool dup = false;
        for (int i = 0; i < count; i++) {
            if (strcmp(lines[i], c->line) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            int pos = (hdr >= 0) ? hdr + 1 : count;
            if (hdr < 0) {
                if (nsp_rule_file_append(&lines, &cap, count, sec_hdr) < 0)
                    return NSP_RULE_FILE_EINVAL;
                count++;
                pos = count;
            }
            int nc = nsp_rule_file_insert(&lines, &cap, count, pos, c->line);
            if (nc < 0) return NSP_RULE_FILE_EINVAL;
            count = nc;
            changed = true;
        }
    }

    *lines_p = lines;
    *count_p = count;
    *cap_p = cap;
    *out_changed = changed;
    return NSP_RULE_FILE_OK;
}

/* ==================== 无段文件写入 ==================== */

typedef struct {
    bool is_switch;
    const char* type_name;
    const char* line;
} EditUpsertLineCtx;

/* 无段文件 upsert 的编辑体（在事务内改行数组）。 */
static int edit_upsert_line(char*** lines_p, int* count_p, int* cap_p, void* vctx,
                            bool* out_changed) {
    const EditUpsertLineCtx* c = vctx;
    char** lines = *lines_p;
    int count = *count_p;
    int cap = *cap_p;
    bool changed = false;

    if (c->is_switch) {
        /* 开关：替换文件中首个同类型开关行（保持唯一，后写覆盖），无则追加 */
        int old = -1;
        for (int i = 0; i < count; i++) {
            if (nsp_rule_file_line_is_type(lines[i], c->type_name)) {
                old = i;
                break;
            }
        }
        if (old >= 0) {
            if (strcmp(lines[old], c->line) != 0) {
                char* dup = strdup(c->line);
                if (!dup) return NSP_RULE_FILE_EINVAL;
                free(lines[old]);
                lines[old] = dup;
                changed = true;
            }
        } else {
            int nc = nsp_rule_file_append(&lines, &cap, count, c->line);
            if (nc < 0) return NSP_RULE_FILE_EINVAL;
            count = nc;
            changed = true;
        }
    } else {
        /* 规则行：全文件去重后追加 */
        bool dup = false;
        for (int i = 0; i < count; i++) {
            if (strcmp(lines[i], c->line) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            int nc = nsp_rule_file_append(&lines, &cap, count, c->line);
            if (nc < 0) return NSP_RULE_FILE_EINVAL;
            count = nc;
            changed = true;
        }
    }

    *lines_p = lines;
    *count_p = count;
    *cap_p = cap;
    *out_changed = changed;
    return NSP_RULE_FILE_OK;
}

/* ==================== 按 (类型, 索引) 删除 / 切换启用状态 ==================== */

/* 行首（跳过空格/制表符）是否为 '#'——即该规则行处于停用态 */
static bool rule_line_is_disabled(const char* line) {
    if (!line) return false;
    const char* p = line;
    while (*p == ' ' || *p == '\t') p++;
    return *p == '#';
}

typedef struct {
    const NspRuleScope* scope;
    const char* type_name;
    int index;
    char* out_removed;
    size_t removed_sz;
} EditRemoveNthCtx;

/* 删除编辑体：未找到返回 ENOTFND（事务据此放弃落盘）。 */
static int edit_remove_nth(char*** lines_p, int* count_p, int* cap_p, void* vctx,
                           bool* out_changed) {
    (void)cap_p; /* 删除不扩容 */
    const EditRemoveNthCtx* c = vctx;
    char** lines = *lines_p;
    int count = *count_p;

    int found = nsp_rule_file_find_nth_scoped(lines, count, c->scope, c->type_name, c->index);
    if (found < 0) return NSP_RULE_FILE_ENOTFND;
    if (c->out_removed && c->removed_sz)
        snprintf(c->out_removed, c->removed_sz, "%s", lines[found]);

    nsp_rule_file_remove(lines, &count, found);
    *lines_p = lines;
    *count_p = count;
    *out_changed = true;
    return NSP_RULE_FILE_OK;
}

typedef struct {
    const NspRuleScope* scope;
    const char* type_name;
    int index;
    bool enable;
    char* out_line;
    size_t out_sz;
} EditToggleNthCtx;

/* 启用/停用编辑体：已处于目标状态时不改动（out_changed=false，事务跳过落盘）。 */
static int edit_toggle_nth(char*** lines_p, int* count_p, int* cap_p, void* vctx,
                           bool* out_changed) {
    (void)cap_p; /* 切换不扩容 */
    const EditToggleNthCtx* c = vctx;
    char** lines = *lines_p;
    int count = *count_p;

    int found = nsp_rule_file_find_nth_scoped(lines, count, c->scope, c->type_name, c->index);
    if (found < 0) return NSP_RULE_FILE_ENOTFND;
    bool disabled = rule_line_is_disabled(lines[found]);
    bool already = c->enable ? !disabled : disabled;
    bool changed = false;
    if (!already) {
        char* p = lines[found];
        while (*p == ' ' || *p == '\t') p++;
        if (c->enable) {
            /* 去掉行首 #（及紧随其后的空白）——向前移动，长度缩小，安全 */
            if (*p == '#') {
                char* q = p + 1;
                while (*q == ' ' || *q == '\t') q++;
                memmove(p, q, strlen(q) + 1);
            }
        } else {
            /* 行首插入 #：行变长，必须重建缓冲，禁止原地 memmove 越界
               （strdup 分配 len+1 字节，插入后需 len+2 字节） */
            size_t prefix = (size_t)(p - lines[found]);
            size_t len = strlen(lines[found]);
            if (len + 2 > (size_t)NSP_DYN_FORMAT_MAX) { /* 与读入上限同界，防御性 */
                return NSP_RULE_FILE_EINVAL;
            }
            char* nl = malloc(len + 2);
            if (!nl) return NSP_RULE_FILE_EINVAL;
            memcpy(nl, lines[found], prefix);
            nl[prefix] = '#';
            strcpy(nl + prefix + 1, p);
            free(lines[found]);
            lines[found] = nl;
        }
        changed = true;
    }
    if (c->out_line && c->out_sz) snprintf(c->out_line, c->out_sz, "%s", lines[found]);
    *lines_p = lines;
    *count_p = count;
    *out_changed = changed;
    return NSP_RULE_FILE_OK;
}

/* ==================== 唯一编辑入口（持锁读-改-写事务） ====================
   库对外的写入路径只有这一条：取目录 flock → 读全文 → 调编辑体 → 原子写回 → 放锁。
   四个编辑语义（段式/无段 upsert、按索引删除、启用切换）都是本原语的回调实现，
   故「读-改-写却没取锁」在结构上不可能出现（§C6）；原子落盘函数 rule_file_write
   亦不进入公共头文件，调用方无从自行拼出无锁写路径。
   锁不可用时按 fail-open 继续（绝不因锁不可用而拒绝编辑）。 */

int nsp_rule_file_edit(const char* path, NspRuleFileEditFn fn, void* ctx, bool* out_changed) {
    if (!path || !fn) return NSP_RULE_FILE_EINVAL;
    if (out_changed) *out_changed = false;

    int lk = rule_file_lock_dir(path);
    int count = 0, cap = 0, rerr = 0;
    char** lines = nsp_rule_file_read_ex(path, &count, &cap, &rerr);
    /* 读失败（非 ENOENT）绝不当空文件：否则会以「段头 + 本次 1 条」覆盖整份
       规则文件（EMFILE/EACCES/EIO/OOM 时静默丢全部既有规则，§A10） */
    if (!lines && rerr != 0 && rerr != ENOENT) {
        rule_file_unlock_dir(lk);
        errno = rerr;
        return NSP_RULE_FILE_EIO;
    }

    bool changed = false;
    int rc = fn(&lines, &count, &cap, ctx, &changed);
    if (rc == NSP_RULE_FILE_OK && changed && !rule_file_write(path, lines, count))
        rc = NSP_RULE_FILE_EIO;
    if (rc != NSP_RULE_FILE_OK) changed = false; /* 未落盘即不算改动 */
    nsp_rule_file_free(lines, count);
    rule_file_unlock_dir(lk);
    if (out_changed) *out_changed = changed;
    return rc;
}

int nsp_rule_file_upsert_in_section(const char* path, const char* sec_name,
                                    NspRuleSectionMatch sec_match, bool is_switch,
                                    const char* type_name, const char* line, bool* out_changed) {
    if (!path || !sec_name || !line) return NSP_RULE_FILE_EINVAL;
    if (is_switch && !type_name) return NSP_RULE_FILE_EINVAL;
    EditUpsertSectionCtx ctx = {.sec_name = sec_name, .sec_match = sec_match,
                                .is_switch = is_switch, .type_name = type_name, .line = line};
    return nsp_rule_file_edit(path, edit_upsert_in_section, &ctx, out_changed);
}

int nsp_rule_file_upsert_line(const char* path, bool is_switch, const char* type_name,
                              const char* line, bool* out_changed) {
    if (!path || !line) return NSP_RULE_FILE_EINVAL;
    if (is_switch && !type_name) return NSP_RULE_FILE_EINVAL;
    EditUpsertLineCtx ctx = {.is_switch = is_switch, .type_name = type_name, .line = line};
    return nsp_rule_file_edit(path, edit_upsert_line, &ctx, out_changed);
}

int nsp_rule_file_remove_nth(const char* path, const char* type_name, int index, char* out_removed,
                             size_t removed_sz) {
    return nsp_rule_file_remove_nth_scoped(path, NULL, type_name, index, out_removed, removed_sz);
}

int nsp_rule_file_remove_nth_scoped(const char* path, const NspRuleScope* scope,
                                    const char* type_name, int index, char* out_removed,
                                    size_t removed_sz) {
    if (!path || !type_name || index < 0) return NSP_RULE_FILE_EINVAL;
    EditRemoveNthCtx ctx = {.scope = scope, .type_name = type_name, .index = index,
                            .out_removed = out_removed, .removed_sz = removed_sz};
    return nsp_rule_file_edit(path, edit_remove_nth, &ctx, NULL);
}

int nsp_rule_file_toggle_nth_scoped(const char* path, const NspRuleScope* scope,
                                    const char* type_name, int index, bool enable, char* out_line,
                                    size_t out_sz, bool* out_changed) {
    if (!path || !type_name || index < 0) return NSP_RULE_FILE_EINVAL;
    EditToggleNthCtx ctx = {.scope = scope, .type_name = type_name, .index = index,
                            .enable = enable, .out_line = out_line, .out_sz = out_sz};
    return nsp_rule_file_edit(path, edit_toggle_nth, &ctx, out_changed);
}
