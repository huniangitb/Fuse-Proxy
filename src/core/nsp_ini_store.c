/* nsp_ini_store.c — 通用 INI 段式配置文件行级存储实现（纯 libc） */
#include "nsp_ini_store.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

struct NspIniStore {
    char* path;   /* 文件路径（strdup） */
    char** lines; /* 行数组（已去结尾 \n，超长行亦原样保留） */
    size_t count;
    size_t cap;
};

/* ---- 行内工具（本文件自包含，不依赖 nsp_util：模块经导出表解析时
 * 仅需本 TU 符号，避免跨公共库的隐式依赖） ---- */
static char* ini_trim(char* s) {
    while (isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    return s;
}

/* 段头解析：去空白后形如 [name]（name 去空白，非空）则返回 true 并填 name */
static bool parse_header(const char* line, char* name_out, size_t name_sz) {
    if (!line || line[0] != '[') return false;
    const char* close = strchr(line, ']');
    if (!close || close[1] != '\0') return false; /* 余部必须为空（ON/OFF 后缀不归通用管） */
    size_t n = (size_t)(close - line - 1);
    if (n == 0 || n >= name_sz) return false;
    memcpy(name_out, line + 1, n);
    name_out[n] = '\0';
    char* t = ini_trim(name_out);
    if (t != name_out) memmove(name_out, t, strlen(t) + 1);
    return name_out[0] != '\0';
}

/* 键行解析：含 `=` 则拆 key（去空白，非空）与 value（剥行内 `#` 后去空白） */
static bool parse_kv(char* line, char** key_out, char** val_out) {
    char* eq = strchr(line, '=');
    if (!eq) return false;
    *eq = '\0';
    char* k = ini_trim(line);
    if (!k[0]) return false;
    char* v = eq + 1;
    char* hash = strchr(v, '#'); /* 与 ftp_conf 一致：首个 `#` 起皆为注释 */
    if (hash) *hash = '\0';
    v = ini_trim(v);
    *key_out = k;
    *val_out = v;
    return true;
}

static bool store_append(NspIniStore* s, const char* line) {
    if (s->count >= s->cap) {
        size_t ncap = s->cap == 0 ? 64 : s->cap * 2;
        if (ncap > 65536) return false;
        char** nl = realloc(s->lines, ncap * sizeof *nl);
        if (!nl) return false;
        s->lines = nl;
        s->cap = ncap;
    }
    s->lines[s->count] = strdup(line);
    if (!s->lines[s->count]) return false;
    s->count++;
    return true;
}

NspIniStore* nsp_ini_open(const char* path) {
    if (!path || !path[0]) return NULL;
    NspIniStore* s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->path = strdup(path);
    if (!s->path) {
        free(s);
        return NULL;
    }
    FILE* fp = fopen(path, "r");
    if (!fp) return s; /* 文件不存在 = 空存储 */
    char* line = NULL;
    size_t llen = 0;
    ssize_t n;
    bool ok = true;
    while ((n = getline(&line, &llen, fp)) >= 0) {
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (!store_append(s, line)) {
            ok = false;
            break;
        }
    }
    free(line);
    fclose(fp);
    if (!ok) {
        nsp_ini_close(s);
        return NULL;
    }
    return s;
}

void nsp_ini_close(NspIniStore* s) {
    if (!s) return;
    for (size_t i = 0; i < s->count; i++) free(s->lines[i]);
    free(s->lines);
    free(s->path);
    free(s);
}

const char* nsp_ini_path(const NspIniStore* s) {
    return s ? s->path : NULL;
}

/* 段块边界：hdr_idx 为段头行，*end_out 为下一段头行号（或 count） */
static bool section_block(const NspIniStore* s, int hdr_idx, size_t* end_out) {
    char name[256];
    char* t = s->lines[hdr_idx];
    while (isspace((unsigned char)*t)) t++;
    if (!parse_header(t, name, sizeof name)) return false;
    size_t end = (size_t)hdr_idx + 1;
    while (end < s->count) {
        char* p = s->lines[end];
        while (isspace((unsigned char)*p)) p++;
        if (p[0] == '[') {
            char probe[256];
            if (parse_header(p, probe, sizeof probe)) break;
            /* 形如 “[” 开头但非合法段头（如注释/脏行）：视为段内普通行 */
        }
        end++;
    }
    *end_out = end;
    return true;
}

int nsp_ini_section_count(const NspIniStore* s) {
    if (!s) return 0;
    int n = 0;
    char name[256];
    for (size_t i = 0; i < s->count; i++) {
        char* p = s->lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (p[0] == '[' && parse_header(p, name, sizeof name)) n++;
    }
    return n;
}

const char* nsp_ini_section_name(const NspIniStore* s, int idx) {
    /* 非常量返回：调用方不得修改/释放；store 变更后指针可能失效 */
    static _Thread_local char namebuf[256];
    if (!s || idx < 0) return NULL;
    int n = 0;
    for (size_t i = 0; i < s->count; i++) {
        char* p = s->lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (p[0] != '[' || !parse_header(p, namebuf, sizeof namebuf)) continue;
        if (n++ == idx) return namebuf;
    }
    return NULL;
}

int nsp_ini_find_section(const NspIniStore* s, const char* name) {
    if (!s || !name) return -1;
    char hdr[256];
    for (size_t i = 0; i < s->count; i++) {
        char* p = s->lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (p[0] != '[' || !parse_header(p, hdr, sizeof hdr)) continue;
        if (strcmp(hdr, name) == 0) return (int)i;
    }
    return -1;
}

int nsp_ini_key_count(const NspIniStore* s, int sec_idx) {
    if (!s || sec_idx < 0 || (size_t)sec_idx >= s->count) return 0;
    size_t end = 0;
    if (!section_block(s, sec_idx, &end)) return 0;
    int n = 0;
    for (size_t i = (size_t)sec_idx + 1; i < end; i++) {
        char* tmp = strdup(s->lines[i]);
        if (!tmp) break;
        char *k = NULL, *v = NULL;
        if (parse_kv(tmp, &k, &v)) n++;
        free(tmp);
    }
    return n;
}

const char* nsp_ini_key_name(const NspIniStore* s, int sec_idx, int key_idx) {
    static _Thread_local char keybuf[256];
    if (!s || sec_idx < 0 || (size_t)sec_idx >= s->count || key_idx < 0) return NULL;
    size_t end = 0;
    if (!section_block(s, sec_idx, &end)) return NULL;
    int n = 0;
    for (size_t i = (size_t)sec_idx + 1; i < end; i++) {
        char* tmp = strdup(s->lines[i]);
        if (!tmp) break;
        char *k = NULL, *v = NULL;
        bool hit = parse_kv(tmp, &k, &v);
        if (hit && (int)strlen(k) < (int)sizeof keybuf) {
            if (n++ == key_idx) {
                memcpy(keybuf, k, strlen(k) + 1);
                free(tmp);
                return keybuf;
            }
        } else if (hit) {
            n++;
        }
        free(tmp);
    }
    return NULL;
}

int nsp_ini_get(const NspIniStore* s, const char* section, const char* key, char* out, size_t sz) {
    if (!s || !section || !key) return -1;
    int hdr = nsp_ini_find_section(s, section);
    if (hdr < 0) return -1;
    size_t end = 0;
    if (!section_block(s, hdr, &end)) return -1;
    for (size_t i = (size_t)hdr + 1; i < end; i++) {
        char* tmp = strdup(s->lines[i]);
        if (!tmp) return -1;
        char *k = NULL, *v = NULL;
        bool hit = parse_kv(tmp, &k, &v) && strcmp(k, key) == 0;
        if (hit) {
            if (out && sz > 0) {
                strncpy(out, v, sz - 1);
                out[sz - 1] = '\0';
            }
            free(tmp);
            return 0;
        }
        free(tmp);
    }
    return -1;
}

int nsp_ini_set(NspIniStore* s, const char* section, const char* key, const char* value) {
    if (!s || !nsp_ini_valid_section(section) || !nsp_ini_valid_key(key) ||
        !nsp_ini_valid_value(value))
        return -1;
    /* 去首尾空白后操作：避免 " name " 与 "[name]" 互相找不到 */
    char sec[256], kbuf[256];
    {
        const char* a = section;
        while (isspace((unsigned char)*a)) a++;
        size_t n = strlen(a);
        while (n > 0 && isspace((unsigned char)a[n - 1])) n--;
        if (n >= sizeof sec) return -1;
        memcpy(sec, a, n);
        sec[n] = '\0';
        a = key;
        while (isspace((unsigned char)*a)) a++;
        n = strlen(a);
        while (n > 0 && isspace((unsigned char)a[n - 1])) n--;
        if (n >= sizeof kbuf) return -1;
        memcpy(kbuf, a, n);
        kbuf[n] = '\0';
    }
    section = sec;
    key = kbuf;
    int hdr = nsp_ini_find_section(s, section);
    if (hdr < 0) {
        /* 追段到文件尾（与前文用空行分隔，保持可读） */
        char hdrline[512];
        snprintf(hdrline, sizeof hdrline, "[%s]", section);
        if (s->count > 0) {
            char* last = s->lines[s->count - 1];
            char* t = last;
            while (isspace((unsigned char)*t)) t++;
            if (*t) {
                if (!store_append(s, "")) return -1;
            }
        }
        if (!store_append(s, hdrline)) return -1;
        hdr = (int)s->count - 1;
    }
    size_t end = 0;
    if (!section_block(s, hdr, &end)) return -1;
    char newline[NSP_INI_MAX_LINE];
    int w = snprintf(newline, sizeof newline, "%s = %s", key, value);
    if (w < 0 || (size_t)w >= sizeof newline) return -1; /* 组合超长：拒写，防静默截断 */
    for (size_t i = (size_t)hdr + 1; i < end; i++) {
        char* tmp = strdup(s->lines[i]);
        if (!tmp) return -1;
        char *k = NULL, *v = NULL;
        bool hit = parse_kv(tmp, &k, &v) && strcmp(k, key) == 0;
        free(tmp);
        if (hit) {
            char* repl = strdup(newline);
            if (!repl) return -1;
            free(s->lines[i]);
            s->lines[i] = repl;
            return 0;
        }
    }
    /* 键不存在：追段尾（插入到下一段头之前） */
    if (s->count >= s->cap) {
        size_t ncap = s->cap == 0 ? 64 : s->cap * 2;
        if (ncap > 65536) return -1;
        char** nl = realloc(s->lines, ncap * sizeof *nl);
        if (!nl) return -1;
        s->lines = nl;
        s->cap = ncap;
    }
    memmove(&s->lines[end + 1], &s->lines[end], (s->count - end) * sizeof *s->lines);
    s->lines[end] = strdup(newline);
    if (!s->lines[end]) return -1;
    s->count++;
    return 0;
}

int nsp_ini_del_key(NspIniStore* s, const char* section, const char* key) {
    if (!s || !section || !key) return -1;
    int hdr = nsp_ini_find_section(s, section);
    if (hdr < 0) return -1;
    size_t end = 0;
    if (!section_block(s, hdr, &end)) return -1;
    for (size_t i = (size_t)hdr + 1; i < end; i++) {
        char* tmp = strdup(s->lines[i]);
        if (!tmp) return -1;
        char *k = NULL, *v = NULL;
        bool hit = parse_kv(tmp, &k, &v) && strcmp(k, key) == 0;
        free(tmp);
        if (hit) {
            free(s->lines[i]);
            memmove(&s->lines[i], &s->lines[i + 1], (s->count - i - 1) * sizeof *s->lines);
            s->count--;
            return 0;
        }
    }
    return -1;
}

int nsp_ini_del_section(NspIniStore* s, const char* section) {
    if (!s || !section) return -1;
    int hdr = nsp_ini_find_section(s, section);
    if (hdr < 0) return -1;
    size_t end = 0;
    if (!section_block(s, hdr, &end)) return -1;
    for (size_t i = (size_t)hdr; i < end; i++) free(s->lines[i]);
    memmove(&s->lines[hdr], &s->lines[end], (s->count - end) * sizeof *s->lines);
    s->count -= (end - (size_t)hdr);
    return 0;
}

int nsp_ini_save(const NspIniStore* s) {
    if (!s || !s->path[0]) return -1;
    char tmp[4096];
    snprintf(tmp, sizeof tmp, "%s.tmp", s->path);
    FILE* fp = fopen(tmp, "w");
    if (!fp) return -1;
    /* 0600：经本接口落盘的文件可能含明文密码（如 ftp.conf），与读侧
       "密码只写不读"的脱敏姿态一致；已存在文件的旧权限一并收紧 */
    fchmod(fileno(fp), S_IRUSR | S_IWUSR);
    for (size_t i = 0; i < s->count; i++) {
        if (fputs(s->lines[i], fp) < 0 || fputc('\n', fp) < 0) {
            fclose(fp);
            unlink(tmp);
            return -1;
        }
    }
    if (fclose(fp) != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, s->path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

bool nsp_ini_valid_section(const char* name) {
    if (!name) return false;
    while (isspace((unsigned char)*name)) name++;
    size_t n = strlen(name);
    while (n > 0 && isspace((unsigned char)name[n - 1])) n--;
    if (n == 0 || n > 255) return false;
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        if (c == '\n' || c == '\r' || c == '[' || c == ']') return false;
    }
    return true;
}

bool nsp_ini_valid_key(const char* key) {
    if (!key) return false;
    while (isspace((unsigned char)*key)) key++;
    size_t n = strlen(key);
    while (n > 0 && isspace((unsigned char)key[n - 1])) n--;
    if (n == 0 || n > 255) return false;
    for (size_t i = 0; i < n; i++) {
        char c = key[i];
        if (c == '\n' || c == '\r' || c == '[' || c == ']' || c == '=') return false;
    }
    return true;
}

bool nsp_ini_valid_value(const char* value) {
    if (!value) return false;
    size_t n = strlen(value);
    if (n > NSP_INI_MAX_LINE - 1) return false;
    for (size_t i = 0; i < n; i++) {
        if (value[i] == '\n' || value[i] == '\r') return false;
    }
    return true;
}
