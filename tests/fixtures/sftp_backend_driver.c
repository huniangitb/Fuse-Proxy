/*
 * tests/fixtures/sftp_backend_driver.c — SFTP 后端确定性驱动
 * （tests/test_sftp.py 的 C 侧夹具；真实 libcurl + libssh2 + 真实 sshd，不经 FUSE）
 *
 * 为什么不用端到端 FUSE 用例：FUSE 侧要 /dev/fuse，且框架的 backend_* 分派与
 * 协议无关（FTP 已由 test_ftp.py 端到端覆盖）。本驱动直接编入**实际后端源码**
 * （-DFTP_BACKEND_SRC）并链接**实际** ftp_mux.c，用真实 libcurl 连本机 sshd，
 * 故 SFTP 的 URL 组装/错误分类/getattr 探测/quote 命令映射/数据面读写全部走
 * 真实代码路径——正是本套件要判别的那几处。
 *
 * 用法：sftp_backend_driver <ftp.conf> -        # 从 stdin 读命令（同一进程 = 同一
 *                                               # 后端实例，故熔断/缓存等状态连续）
 *       sftp_backend_driver <ftp.conf> <op> [args...]
 * 命令（参数含空格用双引号）：
 *   getattr  <vpath>                       → rc=<n> mode=<o> size=<n> mtime=<n>
 *   readdir  <vpath>                       → rc=<n> n=<k> names=a,b,c
 *   pread    <vpath> <off> <len> [rdwr]    → rc=<n> got=<k> data=<...>
 *   write    <vpath> <content> [verify <localfile>]
 *                                          → rc=<n> [remote=<...>]（verify 在**释放
 *                                            句柄之前**读远端，判别 FLUSH/fsync 语义）
 *   unlink|mkdir|rmdir <vpath>             → rc=<n>
 *   rename   <from> <to>                   → rc=<n>
 *   truncate <vpath> <size>                → rc=<n>
 *   match    <vpath>                       → rc=<n>
 *   echo     <text>                        → text（Python 侧对齐用）
 * 退出码：0=命令已执行（业务结果用 rc 表达）；2=用法/配置错误；3=本 libcurl 无 SFTP。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "nsp_module.h"
#include "ftp_conf.h"
#include "ftp_backend.h"

#ifndef FTP_BACKEND_SRC
#define FTP_BACKEND_SRC "ftp_backend_libcurl.c"
#endif

/* ============ 框架运行时桩（模块在 fuse_daemon 里由 --export-dynamic 解析） ============ */
LogLevel g_min_log_level = LOG_WARN;
void log_internal(LogLevel level, const char* format, ...) {
    va_list ap;
    va_start(ap, format);
    fprintf(stderr, "[lvl%d] ", (int)level);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

#include FTP_BACKEND_SRC

/* 运行期能力探测（与 ftp_module.c 同判据：curl 8.x 已删 CURL_VERSION_LIBSSH2） */
static bool curl_supports_sftp(void) {
    curl_version_info_data* vi = curl_version_info(CURLVERSION_NOW);
    if (!vi || !vi->protocols) return false;
    for (const char* const* p = vi->protocols; *p; p++)
        if (strcmp(*p, "sftp") == 0) return true;
    return false;
}

static void print_rc(int rc) { printf("rc=%d", rc); }

/* ============ 命令实现 ============ */

static int op_getattr(const char* p) {
    struct stat st;
    memset(&st, 0, sizeof st);
    int rc = ftp_backend_getattr(p, &st);
    print_rc(rc);
    if (rc == 0)
        printf(" mode=%o size=%lld mtime=%lld", (unsigned)st.st_mode, (long long)st.st_size,
               (long long)st.st_mtime);
    printf("\n");
    return 0;
}

static int op_readdir(const char* p) {
    NspDirEntry e[600];
    memset(e, 0, sizeof e);
    int n = ftp_backend_readdir(p, e, 600, 0);
    print_rc(n);
    if (n > 0) {
        printf(" n=%d names=", n);
        for (int i = 0; i < n; i++) printf("%s%s", i ? "," : "", e[i].name);
    }
    printf("\n");
    return 0;
}

static int op_pread(const char* p, long off, long len, bool rdwr) {
    uint64_t h = 0;
    int rc = ftp_backend_open(p, rdwr ? O_RDWR : O_RDONLY, &h);
    if (rc != 0) {
        print_rc(rc);
        printf("\n");
        return 0;
    }
    char* buf = calloc(1, (size_t)len + 1);
    size_t got = 0;
    rc = ftp_backend_read(h, buf, (size_t)len, (off_t)off, &got);
    print_rc(rc);
    if (rc == 0) printf(" got=%zu data=%s", got, buf);
    printf("\n");
    free(buf);
    ftp_backend_release(h);
    return 0;
}

static int op_write(const char* p, const char* content, const char* verify_local) {
    uint64_t h = 0;
    int rc = ftp_backend_open(p, O_WRONLY | O_CREAT | O_TRUNC, &h);
    if (rc != 0) {
        print_rc(rc);
        printf("\n");
        return 0;
    }
    size_t wrote = 0;
    rc = ftp_backend_write(h, content, strlen(content), 0, &wrote);
    if (rc == 0) rc = ftp_backend_flush(h); /* 收尾上传；句柄保留到 RELEASE */
    print_rc(rc);
    if (rc == 0 && verify_local) {
        FILE* fp = fopen(verify_local, "r");
        printf(" remote=");
        if (fp) {
            char b[512];
            size_t k = fread(b, 1, sizeof b - 1, fp);
            b[k] = '\0';
            printf("%s", b);
            fclose(fp);
        } else {
            printf("<unreadable:%s>", strerror(errno));
        }
    }
    printf("\n");
    ftp_backend_release(h);
    return 0;
}

/* 单条命令派发：argv[0] = op */
static int run_cmd(int argc, char** argv) {
    const char* op = argv[0];
    if (!strcmp(op, "echo")) {
        for (int i = 1; i < argc; i++) printf("%s%s", i > 1 ? " " : "", argv[i]);
        printf("\n");
        return 0;
    }
    if (!strcmp(op, "getattr") && argc >= 2) return op_getattr(argv[1]);
    if (!strcmp(op, "readdir") && argc >= 2) return op_readdir(argv[1]);
    if (!strcmp(op, "pread") && argc >= 4)
        return op_pread(argv[1], atol(argv[2]), atol(argv[3]),
                        argc >= 5 && !strcmp(argv[4], "rdwr"));
    if (!strcmp(op, "write") && argc >= 3) {
        const char* vl = (argc >= 5 && !strcmp(argv[3], "verify")) ? argv[4] : NULL;
        return op_write(argv[1], argv[2], vl);
    }
    if (!strcmp(op, "unlink") && argc >= 2) { print_rc(ftp_backend_unlink(argv[1])); printf("\n"); return 0; }
    if (!strcmp(op, "mkdir") && argc >= 2) { print_rc(ftp_backend_mkdir(argv[1], 0755)); printf("\n"); return 0; }
    if (!strcmp(op, "rmdir") && argc >= 2) { print_rc(ftp_backend_rmdir(argv[1])); printf("\n"); return 0; }
    if (!strcmp(op, "rename") && argc >= 3) { print_rc(ftp_backend_rename(argv[1], argv[2])); printf("\n"); return 0; }
    if (!strcmp(op, "truncate") && argc >= 3) {
        print_rc(ftp_backend_truncate(argv[1], (off_t)atoll(argv[2])));
        printf("\n");
        return 0;
    }
    if (!strcmp(op, "match") && argc >= 2) { print_rc(ftp_backend_match(argv[1])); printf("\n"); return 0; }
    fprintf(stderr, "未知或不完整命令: %s\n", op);
    return 2;
}

/* 极简分词：空白分隔，双引号内保留空白（支持 \" 与 \\ 转义） */
#define MAX_TOK 16
static int tokenize(char* line, char** toks) {
    int n = 0;
    char* p = line;
    while (*p && n < MAX_TOK) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        char* out = p;
        char* w = p;
        bool quoted = (*p == '"');
        if (quoted) {
            out = ++p;
            w = out;
            while (*p && *p != '"') {
                if (*p == '\\' && (p[1] == '"' || p[1] == '\\')) p++;
                *w++ = *p++;
            }
            if (*p == '"') p++;
            *w = '\0';
        } else {
            while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
            if (*p) *p++ = '\0';
        }
        toks[n++] = out;
    }
    return n;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "用法: %s <ftp.conf> -|<op> [args...]\n", argv[0]);
        return 2;
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
    FtpServerList list;
    if (ftp_conf_load(argv[1], &list) != 0) {
        fprintf(stderr, "配置加载失败: %s\n", argv[1]);
        return 2;
    }
    bool have_sftp = curl_supports_sftp();
    int added = 0;
    for (int i = 0; i < list.count; i++) {
        if (list.servers[i].sftp && !have_sftp) {
            fprintf(stderr, "libcurl 未编入 SFTP（libssh2），段 [%s] 跳过\n", list.servers[i].name);
            continue;
        }
        if (ftp_backend_add(&list.servers[i]) == 0) added++;
    }
    if (added == 0) {
        printf("no_backend\n");
        return have_sftp ? 2 : 3;
    }

    int rc = 0;
    if (!strcmp(argv[2], "-")) {
        char* line = NULL;
        size_t cap = 0;
        while (getline(&line, &cap, stdin) > 0) {
            char* toks[MAX_TOK];
            char* tmp = strdup(line);
            int n = tokenize(tmp, toks);
            if (n == 0) { free(tmp); continue; }
            if (run_cmd(n, toks) != 0) rc = 1;
            free(tmp);
        }
        free(line);
    } else {
        rc = run_cmd(argc - 2, argv + 2);
    }

    fflush(stdout);
    ftp_backend_clear(); /* 停 mux 事件线程，避免进程退出时线程仍在飞 */
    ftp_conf_free(&list);
    return rc;
}
