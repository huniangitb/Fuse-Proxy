#define _GNU_SOURCE
#include "ftp_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <ctype.h>

/* ================= 基础网络 IO ================= */

static int sock_connect_timeout(const char* host, int port, int timeout_s) {
    struct addrinfo hints, *res = NULL;
    char port_str[16];
    snprintf(port_str, sizeof port_str, "%d", port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) return -1;
    int fd = -1;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        /* 纯阻塞 connect：connect 前勿设 SO_SNDTIMEO——Linux 上阻塞 connect
           带发送超时可能返回 EINPROGRESS 被误判失败；IO 超时由 ftp_connect
           的 SO_RCVTIMEO/SO_SNDTIMEO 承担 */
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* 读一行（到 '\n'，含末尾换行），返回行长度（不含 NUL）或 -1 */
static int ftp_read_line(FtpConn* c, char* buf, size_t bufsz) {
    size_t pos = 0;
    while (pos + 1 < bufsz) {
        ssize_t n = read(c->ctrl_fd, buf + pos, 1);
        if (n == 1) {
            if (buf[pos] == '\n') { pos++; break; }
            pos++;
        } else if (n == 0) {
            return pos > 0 ? (int)pos : -1;
        } else {
            if (errno == EINTR) continue;
            return -1;
        }
    }
    buf[pos] = '\0';
    return (int)pos;
}

/* 读完整响应（含多行 "NNN-...NNN "），返回响应码 */
static int ftp_read_reply(FtpConn* c) {
    c->last_reply[0] = '\0';
    c->last_code = -1;
    char line[1024];
    int n = ftp_read_line(c, line, sizeof line);
    if (n < 3) return -1;
    int code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
    size_t off = strlen(c->last_reply);
    size_t llen = strlen(line);
    if (off + llen < sizeof c->last_reply - 1) {
        memcpy(c->last_reply + off, line, llen);
        c->last_reply[off + llen] = '\0';
    }
    /* 多行响应：NNN- ... NNN <space> */
    if (n >= 4 && line[3] == '-') {
        while (1) {
            int n2 = ftp_read_line(c, line, sizeof line);
            if (n2 < 3) return -1;
            off = strlen(c->last_reply);
            llen = strlen(line);
            if (off + llen < sizeof c->last_reply - 1) {
                memcpy(c->last_reply + off, line, llen);
                c->last_reply[off + llen] = '\0';
            }
            if (line[0] == '0' + (code / 100) && line[1] == '0' + ((code / 10) % 10) &&
                line[2] == '0' + (code % 10) && line[3] == ' ') break;
        }
    }
    c->last_code = code;
    return code;
}

int ftp_cmd(FtpConn* c, const char* cmd, const char* arg) {
    char buf[2048];
    if (arg && arg[0])
        snprintf(buf, sizeof buf, "%s %s\r\n", cmd, arg);
    else
        snprintf(buf, sizeof buf, "%s\r\n", cmd);
    size_t len = strlen(buf);
    ssize_t w = write(c->ctrl_fd, buf, len);
    if (w != (ssize_t)len) return -1;
    return ftp_read_reply(c);
}

/* ================= 连接 / 关闭 ================= */

int ftp_connect(FtpConn* c, const char* host, int port,
                const char* user, const char* pass, int timeout_s) {
    memset(c, 0, sizeof *c);
    c->ctrl_fd = -1;
    c->timeout_s = timeout_s > 0 ? timeout_s : 30;
    int fd = sock_connect_timeout(host, port, c->timeout_s);
    if (fd < 0) return -1;
    c->ctrl_fd = fd;
    struct timeval tv = { .tv_sec = c->timeout_s, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int code = ftp_read_reply(c);
    if (code != 220) { ftp_close(c); return -1; }
    code = ftp_cmd(c, "USER", user && user[0] ? user : "anonymous");
    if (code != 230 && code != 331) { ftp_close(c); return -1; }
    if (code == 331) {
        code = ftp_cmd(c, "PASS", pass ? pass : "anonymous@");
        if (code != 230 && code != 202) { ftp_close(c); return -1; }
    }
    /* 二进制传输 */
    ftp_cmd(c, "TYPE", "I");
    return 0;
}

void ftp_close(FtpConn* c) {
    if (!c) return;
    if (c->ctrl_fd >= 0) {
        ftp_cmd(c, "QUIT", NULL);   /* 尽力而为 */
        close(c->ctrl_fd);
    }
    c->ctrl_fd = -1;
}

/* ================= 被动模式数据连接 ================= */

static int ftp_pasv_data_fd(FtpConn* c) {
    int code = ftp_cmd(c, "PASV", NULL);
    if (code != 227) return -1;
    /* 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2) */
    const char* p = strchr(c->last_reply, '(');
    if (!p) return -1;
    int h1, h2, h3, h4, p1, p2;
    if (sscanf(p, "(%d,%d,%d,%d,%d,%d)", &h1, &h2, &h3, &h4, &p1, &p2) != 6) return -1;
    char host[64];
    snprintf(host, sizeof host, "%d.%d.%d.%d", h1, h2, h3, h4);
    int port = p1 * 256 + p2;
    return sock_connect_timeout(host, port, c->timeout_s);
}

int ftp_data_open(FtpConn* c, const char* cmd, const char* path, long long rest_off) {
    int dfd = ftp_pasv_data_fd(c);
    if (dfd < 0) return -1;
    if (rest_off >= 0) {
        char offbuf[32];
        snprintf(offbuf, sizeof offbuf, "%lld", rest_off);
        int code = ftp_cmd(c, "REST", offbuf);
        if (code != 350) { close(dfd); return -1; }
    }
    int code = ftp_cmd(c, cmd, path);
    if (code != 150 && code != 125) {
        close(dfd);
        return -1;
    }
    return dfd;
}

int ftp_data_finish(FtpConn* c) {
    int code = ftp_read_reply(c);
    return (code == 226 || code == 250) ? 0 : -1;
}

/* ================= 高层操作 ================= */

int ftp_list(FtpConn* c, const char* path, char** out, size_t* out_len) {
    int dfd = ftp_data_open(c, "LIST", path, -1);
    if (dfd < 0) return -1;
    size_t cap = 16384, len = 0;
    char* buf = malloc(cap);
    if (!buf) { close(dfd); return -1; }
    for (;;) {
        if (len + 4096 > cap) {
            cap *= 2;
            char* nb = realloc(buf, cap);
            if (!nb) { free(buf); close(dfd); return -1; }
            buf = nb;
        }
        ssize_t n = read(dfd, buf + len, cap - len - 1);
        if (n > 0) len += (size_t)n;
        else break;
    }
    buf[len] = '\0';
    close(dfd);
    if (ftp_data_finish(c) != 0) { free(buf); return -1; }
    *out = buf;
    if (out_len) *out_len = len;
    return 0;
}

int ftp_retr(FtpConn* c, const char* path, long long off, char* buf, size_t size, size_t* got) {
    int dfd = ftp_data_open(c, "RETR", path, off);
    if (dfd < 0) return -1;
    size_t total = 0;
    while (total < size) {
        ssize_t n = read(dfd, buf + total, size - total);
        if (n > 0) total += (size_t)n;
        else break;
    }
    close(dfd);
    if (ftp_data_finish(c) != 0) return -1;
    if (got) *got = total;
    return 0;
}

int ftp_stor(FtpConn* c, const char* path, const char* buf, size_t size) {
    int dfd = ftp_data_open(c, "STOR", path, -1);
    if (dfd < 0) return -1;
    size_t off = 0;
    while (off < size) {
        ssize_t n = write(dfd, buf + off, size - off);
        if (n > 0) off += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else break;
    }
    close(dfd);
    if (ftp_data_finish(c) != 0) return -1;
    return off == size ? 0 : -1;
}

int ftp_size(FtpConn* c, const char* path, long long* size_out) {
    int code = ftp_cmd(c, "SIZE", path);
    if (code != 213) return -1;
    /* 213 <size> */
    const char* p = strchr(c->last_reply, ' ');
    if (!p) return -1;
    if (size_out) *size_out = atoll(p + 1);
    return 0;
}

int ftp_mdtm(FtpConn* c, const char* path, time_t* out) {
    int code = ftp_cmd(c, "MDTM", path);
    if (code != 213) return -1;
    /* 213 YYYYMMDDHHMMSS */
    const char* p = strchr(c->last_reply, ' ');
    if (!p) return -1;
    p++;
    int y, mo, d, h, mi, s;
    if (sscanf(p, "%4d%2d%2d%2d%2d%2d", &y, &mo, &d, &h, &mi, &s) != 6) return -1;
    struct tm tm = { .tm_year = y - 1900, .tm_mon = mo - 1, .tm_mday = d,
                     .tm_hour = h, .tm_min = mi, .tm_sec = s };
    if (out) *out = timegm(&tm);
    return 0;
}

int ftp_dele(FtpConn* c, const char* path) {
    int code = ftp_cmd(c, "DELE", path);
    return (code == 250) ? 0 : -1;
}

int ftp_mkd(FtpConn* c, const char* path) {
    int code = ftp_cmd(c, "MKD", path);
    return (code == 257 || code == 250) ? 0 : -1;
}

int ftp_rmd(FtpConn* c, const char* path) {
    int code = ftp_cmd(c, "RMD", path);
    return (code == 250) ? 0 : -1;
}

int ftp_rename(FtpConn* c, const char* from, const char* to) {
    int code = ftp_cmd(c, "RNFR", from);
    if (code != 350) return -1;
    code = ftp_cmd(c, "RNTO", to);
    return (code == 250) ? 0 : -1;
}

/* ================= LIST 解析（Unix 风格） ================= */

static int month_to_int(const char* m) {
    static const char* months[] = {"Jan","Feb","Mar","Apr","May","Jun",
                                   "Jul","Aug","Sep","Oct","Nov","Dec"};
    for (int i = 0; i < 12; i++)
        if (strncmp(m, months[i], 3) == 0) return i;
    return -1;
}

int ftp_parse_list(const char* text, FtpEntry* entries, int max) {
    int n = 0;
    const char* line = text;
    while (*line && n < max) {
        const char* eol = strchr(line, '\n');
        size_t linelen = eol ? (size_t)(eol - line) : strlen(line);
        char* buf = malloc(linelen + 1);
        if (!buf) break;
        memcpy(buf, line, linelen);
        buf[linelen] = '\0';
        line = eol ? eol + 1 : line + linelen;

        /* Unix 风格：-rw-r--r-- 1 user group size Mon dd HH:MM name */
        if (linelen > 0 && (buf[0] == '-' || buf[0] == 'd' || buf[0] == 'l')) {
            char* save = NULL;
            char* tok = strtok_r(buf, " \t", &save);   /* 权限位 */
            char* links = strtok_r(NULL, " \t", &save);
            char* owner = strtok_r(NULL, " \t", &save);
            char* group = strtok_r(NULL, " \t", &save);
            char* size_s = strtok_r(NULL, " \t", &save);
            char* month = strtok_r(NULL, " \t", &save);
            char* day = strtok_r(NULL, " \t", &save);
            char* time_s = strtok_r(NULL, " \t", &save);
            char* name = strtok_r(NULL, "", &save);
            (void)links; (void)owner; (void)group;
            if (tok && size_s && month && day && time_s && name) {
                while (*name == ' ' || *name == '\t') name++;
                char* name_end = name + strlen(name);
                while (name_end > name && (name_end[-1] == '\r' || name_end[-1] == '\n'))
                    *--name_end = '\0';
                if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                    free(buf);
                    continue;
                }
                FtpEntry* e = &entries[n];
                memset(e, 0, sizeof *e);
                e->is_dir = (buf[0] == 'd');
                e->size = atoll(size_s);
                int mo = month_to_int(month);
                struct tm tm = { .tm_year = 0, .tm_mon = mo >= 0 ? mo : 0,
                                 .tm_mday = atoi(day), .tm_hour = 0, .tm_min = 0, .tm_sec = 0 };
                if (strchr(time_s, ':')) {
                    int h, mi;
                    if (sscanf(time_s, "%d:%d", &h, &mi) == 2) { tm.tm_hour = h; tm.tm_min = mi; }
                } else {
                    tm.tm_year = atoi(time_s) - 1900;
                }
                e->mtime = timegm(&tm);
                strncpy(e->name, name, sizeof e->name - 1);
                n++;
            }
        }
        free(buf);
    }
    return n;
}
