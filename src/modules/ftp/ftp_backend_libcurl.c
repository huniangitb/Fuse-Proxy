/* ftp_backend_libcurl.c — 基于 libcurl 的 FTP 后端模块
 *
 * 使用 libcurl 的 easy 接口进行 FTP 操作，单连接复用 + 自动重连。
 * 替换自研 ftp_client.c，利用 libcurl 成熟的网络栈解决：
 *   - 连接复用（keep-alive）
 *   - PASV IP 正确处理（防安卓 NAT/防火墙 → EIO）
 *   - 超时与错误处理
 *   - 随机读支持（CURLOPT_RESUME_FROM）
 */

#include "nsp_module.h"
#include "common.h"
#include "ftp_backend.h"
#include <curl/curl.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

/* ================= 配置 ================= */

#define FTP_BACKEND_MAX 16
#define FTP_HANDLE_MAX 256
#define FTP_STREAM_BUF_SIZE (64 * 1024)  /* 流式读缓冲 64KB */

/* ================= 后端（每个 FTP 服务器一个） ================= */

typedef struct FtpBackend {
    FtpServerCfg cfg;
    char prefix[PATH_MAX];   /* 虚拟前缀 = "/" + 段名 */
    CURL* curl;              /* 复用连接（libcurl easy handle） */
    pthread_mutex_t lock;    /* 连接锁 */
    pthread_mutex_t op_lock; /* 操作锁：串行化 curl_easy_perform（句柄非线程安全） */
    bool connected;          /* 连接是否有效 */
    time_t last_used;        /* 最后使用时间（保活） */
} FtpBackend;

static FtpBackend g_backends[FTP_BACKEND_MAX];
static int g_backend_count = 0;

/* ================= 文件句柄（每个打开的文件一个） ================= */

typedef struct FtpBackendFile {
    FtpBackend* bk;
    char ftp_path[PATH_MAX]; /* 远程路径 */
    int  tmp_fd;             /* 写模式本地缓存 fd */
    bool writing;            /* true=写模式（release 上传）；false=读模式 */
    size_t file_size;        /* 文件大小（用于读模式边界检查） */
} FtpBackendFile;

static FtpBackendFile* g_handles[FTP_HANDLE_MAX];
static pthread_mutex_t g_handles_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ================= 写缓冲回调 ================= */

struct WriteBuf {
    char* buf;
    size_t len;
    size_t cap;
    bool auto_grow;   /* 自动扩容（下载/LIST 用），false 时容量满即停 */
};

static size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    struct WriteBuf* wb = (struct WriteBuf*)userdata;
    size_t total = size * nmemb;
    if (wb->len + total > wb->cap) {
        if (wb->auto_grow || !wb->buf) {
            // 自动扩容（buf 为 NULL 或 auto_grow 开启）
            size_t ncap = wb->len + total + 4096;
            char* nbuf = realloc(wb->buf, ncap);
            if (!nbuf) return 0;
            wb->buf = nbuf;
            wb->cap = ncap;
        } else {
            // buf 由调用者提供且不允许扩容：超出容量即停止
            return 0;
        }
    }
    memcpy(wb->buf + wb->len, ptr, total);
    wb->len += total;
    return total;
}

/* ================= 读缓冲回调 ================= */

struct ReadBuf {
    const char* data;
    size_t len;
    size_t pos;
};

static size_t read_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    struct ReadBuf* rb = (struct ReadBuf*)userdata;
    size_t avail = rb->len - rb->pos;
    size_t want = size * nmemb;
    if (want > avail) want = avail;
    if (want > 0) {
        memcpy(ptr, rb->data + rb->pos, want);
        rb->pos += want;
    }
    return want;
}

/* ================= 后端管理 ================= */

int ftp_backend_add(const FtpServerCfg* cfg) {
    if (!cfg || !cfg->name[0] || g_backend_count >= FTP_BACKEND_MAX) return -1;
    FtpBackend* bk = &g_backends[g_backend_count];
    memset(bk, 0, sizeof *bk);
    bk->cfg = *cfg;
    snprintf(bk->prefix, sizeof bk->prefix, "/%s", cfg->name);
    pthread_mutex_init(&bk->lock, NULL);
    pthread_mutex_init(&bk->op_lock, NULL);
    bk->curl = curl_easy_init();
    g_backend_count++;
    return 0;
}

void ftp_backend_clear(void) {
    for (int i = 0; i < g_backend_count; i++) {
        FtpBackend* bk = &g_backends[i];
        if (bk->curl) {
            curl_easy_cleanup(bk->curl);
            bk->curl = NULL;
        }
        pthread_mutex_destroy(&bk->lock);
        pthread_mutex_destroy(&bk->op_lock);
    }
    g_backend_count = 0;
}

int ftp_backend_count(void) { return g_backend_count; }

/* 找 path 命中的后端 */
static FtpBackend* ftp_backend_find(const char* path) {
    for (int i = 0; i < g_backend_count; i++) {
        size_t plen = strlen(g_backends[i].prefix);
        if (strncmp(g_backends[i].prefix, path, plen) == 0 &&
            (path[plen] == '\0' || path[plen] == '/'))
            return &g_backends[i];
    }
    return NULL;
}

/* 构建 FTP URL（不编码 /，FTP 协议路径直接使用） */
static void build_url(const FtpBackend* bk, const char* path, char* url, size_t sz) {
    char rel[1024];
    const char* p = path + strlen(bk->prefix);
    while (*p == '/') p++;
    if (p[0] == '\0') {
        snprintf(rel, sizeof rel, "%s", bk->cfg.remote_dir);
    } else {
        snprintf(rel, sizeof rel, "%s/%s", bk->cfg.remote_dir, p);
    }
    // 对路径中的特殊字符（空格等）编码，但保留 /
    char* enc = curl_easy_escape(NULL, rel, 0);
    if (enc) {
        // 将 %2F 还原为 /（FTP 路径中的 / 是目录分隔符，不应编码）
        char* s = enc;
        char* d = enc;
        while (*s) {
            if (s[0] == '%' && s[1] == '2' && s[2] == 'F') {
                *d++ = '/';
                s += 3;
            } else {
                *d++ = *s++;
            }
        }
        *d = '\0';
        snprintf(url, sz, "ftp://%s:%d%s", bk->cfg.host, bk->cfg.port, enc);
        curl_free(enc);
    } else {
        snprintf(url, sz, "ftp://%s:%d%s", bk->cfg.host, bk->cfg.port, rel);
    }
}

/* 确保连接有效（失败时重建）。仅设置持久选项，不重置操作选项 */
static int ensure_curl(FtpBackend* bk) {
    pthread_mutex_lock(&bk->lock);
    if (!bk->curl) {
        bk->curl = curl_easy_init();
        if (!bk->curl) { pthread_mutex_unlock(&bk->lock); return -1; }
        // 持久选项：一次性设置，各操作函数负责设置自己的选项
        curl_easy_setopt(bk->curl, CURLOPT_USERNAME, bk->cfg.user);
        curl_easy_setopt(bk->curl, CURLOPT_PASSWORD, bk->cfg.pass);
        curl_easy_setopt(bk->curl, CURLOPT_CONNECTTIMEOUT, 30L);
        curl_easy_setopt(bk->curl, CURLOPT_TIMEOUT, 60L);
        curl_easy_setopt(bk->curl, CURLOPT_FTP_RESPONSE_TIMEOUT, 30L);
        curl_easy_setopt(bk->curl, CURLOPT_FTP_SKIP_PASV_IP, 1L);
        curl_easy_setopt(bk->curl, CURLOPT_USE_SSL, CURLUSESSL_NONE);
        curl_easy_setopt(bk->curl, CURLOPT_FOLLOWLOCATION, 0L);
    }
    bk->connected = true;
    bk->last_used = time(NULL);
    pthread_mutex_unlock(&bk->lock);
    return 0;
}

/* 重置 curl 句柄（断开后重建） */
static void reset_curl(FtpBackend* bk) {
    pthread_mutex_lock(&bk->lock);
    if (bk->curl) {
        curl_easy_cleanup(bk->curl);
        bk->curl = NULL;
    }
    bk->connected = false;
    pthread_mutex_unlock(&bk->lock);
}

/* 重置共享句柄的操作级选项（防跨操作残留：NOBODY 残留会吞掉 STOR 上传、
   WRITEDATA 残留指向已失效的栈缓冲）。各操作在 setopt 前调用，然后设置自己所需选项。 */
static void ftp_reset_opts(FtpBackend* bk) {
    curl_easy_setopt(bk->curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_UPLOAD, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_CUSTOMREQUEST, NULL);
    curl_easy_setopt(bk->curl, CURLOPT_RESUME_FROM, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_FILETIME, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_HEADER, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_POSTQUOTE, NULL);
    curl_easy_setopt(bk->curl, CURLOPT_QUOTE, NULL);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEDATA, NULL);
    curl_easy_setopt(bk->curl, CURLOPT_READFUNCTION, NULL);
    curl_easy_setopt(bk->curl, CURLOPT_READDATA, NULL);
}

/* ================= 文件句柄管理 ================= */

static uint64_t ftp_handle_alloc(FtpBackendFile* f) {
    pthread_mutex_lock(&g_handles_mutex);
    for (int i = 1; i < FTP_HANDLE_MAX; i++) {
        if (!g_handles[i]) {
            g_handles[i] = f;
            pthread_mutex_unlock(&g_handles_mutex);
            return (uint64_t)i;
        }
    }
    pthread_mutex_unlock(&g_handles_mutex);
    return 0;
}

static FtpBackendFile* ftp_handle_get(uint64_t id) {
    if (id <= 0 || id >= FTP_HANDLE_MAX) return NULL;
    pthread_mutex_lock(&g_handles_mutex);
    FtpBackendFile* f = g_handles[id];
    pthread_mutex_unlock(&g_handles_mutex);
    return f;
}

static void ftp_handle_free(uint64_t id) {
    if (id <= 0 || id >= FTP_HANDLE_MAX) return;
    pthread_mutex_lock(&g_handles_mutex);
    g_handles[id] = NULL;
    pthread_mutex_unlock(&g_handles_mutex);
}

/* ================= 后端操作 ================= */

int ftp_backend_match(const char* path) {
    return ftp_backend_find(path) != NULL ? 1 : 0;
}

int ftp_backend_getattr(const char* path, struct stat* st) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk) return -ENOENT;
    memset(st, 0, sizeof *st);

    if (ensure_curl(bk) != 0) return -EIO;

    char url[2048];
    build_url(bk, path, url, sizeof url);

    // 先尝试作为文件（SIZE + MDTM）
    struct WriteBuf wb = {0};
    wb.auto_grow = true;
    pthread_mutex_lock(&bk->op_lock);
    ftp_reset_opts(bk);
    curl_easy_setopt(bk->curl, CURLOPT_URL, url);
    curl_easy_setopt(bk->curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(bk->curl, CURLOPT_FILETIME, 1L);
    curl_easy_setopt(bk->curl, CURLOPT_HEADER, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEDATA, &wb);

    CURLcode res = curl_easy_perform(bk->curl);
    pthread_mutex_unlock(&bk->op_lock);
    if (res == CURLE_OK) {
        long resp_code = 0;
        curl_easy_getinfo(bk->curl, CURLINFO_RESPONSE_CODE, &resp_code);
        if (resp_code == 213 || resp_code == 350) {
            // 文件存在
            curl_off_t cl = 0;
                    curl_easy_getinfo(bk->curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl);
            st->st_mode = S_IFREG | 0644;
            st->st_size = (off_t)cl;
            st->st_nlink = 1;
            long ft = 0;
            curl_easy_getinfo(bk->curl, CURLINFO_FILETIME, &ft);
            if (ft >= 0) st->st_mtime = (time_t)ft;
            free(wb.buf);
            return 0;
        }
    }
    free(wb.buf);

    // 作为目录（LIST）- URL 末尾加 / 即可触发 libcurl 自动 LIST
    char dir_url[2048];
    size_t ulen = strlen(url);
    if (ulen > 0 && url[ulen-1] != '/')
        snprintf(dir_url, sizeof dir_url, "%s/", url);
    else
        snprintf(dir_url, sizeof dir_url, "%s", url);

    struct WriteBuf dir_wb = {0};
    dir_wb.auto_grow = true;
    pthread_mutex_lock(&bk->op_lock);
    ftp_reset_opts(bk);
    curl_easy_setopt(bk->curl, CURLOPT_URL, dir_url);
    curl_easy_setopt(bk->curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_CUSTOMREQUEST, NULL);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEDATA, &dir_wb);

    res = curl_easy_perform(bk->curl);
    pthread_mutex_unlock(&bk->op_lock);
    curl_easy_setopt(bk->curl, CURLOPT_CUSTOMREQUEST, NULL); // 重置
    if (res == CURLE_OK) {
        // LIST 成功即视为目录（空目录返回 0 字节，不能用 len>0 判断）
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        free(dir_wb.buf);
        return 0;
    }
    free(dir_wb.buf);

    // 都不是
    reset_curl(bk);
    return -ENOENT;
}

int ftp_backend_readdir(const char* path, NspDirEntry* entries, int max) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk) return -ENOENT;
    if (!entries || max <= 0) return 0;

    if (ensure_curl(bk) != 0) return -EIO;

    char url[2048], dir_url[2048];
    build_url(bk, path, url, sizeof url);
    size_t ulen = strlen(url);
    if (ulen > 0 && url[ulen-1] != '/')
        snprintf(dir_url, sizeof dir_url, "%s/", url);
    else
        snprintf(dir_url, sizeof dir_url, "%s", url);

    struct WriteBuf wb = {0};
    wb.auto_grow = true;
    pthread_mutex_lock(&bk->op_lock);
    ftp_reset_opts(bk);
    curl_easy_setopt(bk->curl, CURLOPT_URL, dir_url);
    curl_easy_setopt(bk->curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_CUSTOMREQUEST, NULL);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEDATA, &wb);

    CURLcode res = curl_easy_perform(bk->curl);
    pthread_mutex_unlock(&bk->op_lock);
    if (res != CURLE_OK) {
        free(wb.buf);
        reset_curl(bk);
        return -ENOENT;
    }

    // 解析 LIST 输出
    int out_n = 0;
    char* line = wb.buf;
    char* end = wb.buf + wb.len;
    while (line < end && out_n < max) {
        // 跳过空行
        while (line < end && (*line == '\n' || *line == '\r')) line++;
        if (line >= end) break;
        char* nl = memchr(line, '\n', end - line);
        if (!nl) nl = end;
        // 简单解析：跳过日期/权限字段，取最后一列作为文件名
        char* name = NULL;
        char* p = line;
        // 跳过类似 "drwxr-xr-x 1 user group 0 Jan 1 00:00 name" 的前 8 列
        int col = 0;
        while (p < nl && col < 8) {
            if (*p == ' ' || *p == '\t') { p++; continue; }
            col++;
            while (p < nl && *p != ' ' && *p != '\t') p++;
        }
        // 跳过空格
        while (p < nl && (*p == ' ' || *p == '\t')) p++;
        // 剩余部分为文件名
        if (p < nl) {
            name = p;
            // 去掉末尾的 \r
            char* e = nl;
            if (e > name && *(e-1) == '\r') e--;
            size_t nlen = e - name;
            if (nlen > 0 && name[0] != '.') {
                strncpy(entries[out_n].name, name, nlen < sizeof(entries[out_n].name) ? nlen : sizeof(entries[out_n].name) - 1);
                entries[out_n].name[sizeof(entries[out_n].name) - 1] = '\0';
                entries[out_n].is_dir = (line[0] == 'd');
                out_n++;
            }
        }
        line = nl + 1;
    }
    free(wb.buf);
    return out_n;
}

int ftp_backend_open(const char* path, int flags, uint64_t* h) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk || !h) return -ENOENT;

    if (ensure_curl(bk) != 0) return -EIO;

    FtpBackendFile* f = calloc(1, sizeof *f);
    if (!f) return -ENOMEM;
    f->bk = bk;
    f->tmp_fd = -1;
    build_url(bk, path, f->ftp_path, sizeof f->ftp_path);

    int accmode = flags & O_ACCMODE;
    bool writing = (accmode != O_RDONLY || (flags & O_CREAT) || (flags & O_TRUNC));

    // 创建本地临时文件（读写模式共用）
    char tpath[128];
    snprintf(tpath, sizeof tpath, "/tmp/nsp_ftp_XXXXXX");
    int tfd = mkstemp(tpath);
    if (tfd < 0) { free(f); return -EIO; }
    unlink(tpath);

    if (writing) {
        // 写模式：本地临时文件，release 时上传
        f->tmp_fd = tfd;
        f->writing = true;
        *h = ftp_handle_alloc(f);
        if (*h == 0) { close(tfd); free(f); return -EIO; }
        return 0;
    }

    // 读模式：下载整个文件到临时文件，read 从本地 pread（规避 REST 连接问题）
    // 用独立 curl 句柄下载（不碰 bk->curl），避免与 STOR 上传等操作并发竞争
    CURL* dl = curl_easy_init();
    if (!dl) { close(tfd); free(f); return -EIO; }
    curl_easy_setopt(dl, CURLOPT_USERNAME, bk->cfg.user);
    curl_easy_setopt(dl, CURLOPT_PASSWORD, bk->cfg.pass);
    curl_easy_setopt(dl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(dl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(dl, CURLOPT_FTP_RESPONSE_TIMEOUT, 5L);
    curl_easy_setopt(dl, CURLOPT_FTP_SKIP_PASV_IP, 1L);
    curl_easy_setopt(dl, CURLOPT_USE_SSL, CURLUSESSL_NONE);
    curl_easy_setopt(dl, CURLOPT_FOLLOWLOCATION, 0L);
    struct WriteBuf wb = {0};
    wb.auto_grow = true;
    curl_easy_setopt(dl, CURLOPT_URL, f->ftp_path);
    curl_easy_setopt(dl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(dl, CURLOPT_UPLOAD, 0L);
    curl_easy_setopt(dl, CURLOPT_CUSTOMREQUEST, NULL);
    curl_easy_setopt(dl, CURLOPT_RESUME_FROM, 0L);
    curl_easy_setopt(dl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(dl, CURLOPT_WRITEDATA, &wb);
    CURLcode res = curl_easy_perform(dl);
    curl_easy_cleanup(dl);
    if (res != CURLE_OK) {
        free(wb.buf);
        close(tfd);
        free(f);
        return -ENOENT;
    }
    // 下载成功，写入临时文件
    if (wb.len > 0) {
        ssize_t w = write(tfd, wb.buf, wb.len);
        if (w != (ssize_t)wb.len) { free(wb.buf); close(tfd); free(f); return -EIO; }
    }
    free(wb.buf);
    lseek(tfd, 0, SEEK_SET);

    f->tmp_fd = tfd;
    f->writing = false;
    *h = ftp_handle_alloc(f);
    if (*h == 0) { close(tfd); free(f); return -EIO; }
    return 0;
}

int ftp_backend_create(const char* path, mode_t mode, uint64_t* h) {
    (void)mode;
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk || !h) return -ENOENT;

    if (ensure_curl(bk) != 0) return -EIO;

    char url[2048];
    build_url(bk, path, url, sizeof url);

    // STOR 上传空文件
    struct ReadBuf rb = {"", 0, 0};
    pthread_mutex_lock(&bk->op_lock);
    ftp_reset_opts(bk);
    curl_easy_setopt(bk->curl, CURLOPT_URL, url);
    curl_easy_setopt(bk->curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(bk->curl, CURLOPT_INFILESIZE, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_READFUNCTION, read_cb);
    curl_easy_setopt(bk->curl, CURLOPT_READDATA, &rb);

    CURLcode res = curl_easy_perform(bk->curl);
    pthread_mutex_unlock(&bk->op_lock);
    curl_easy_setopt(bk->curl, CURLOPT_UPLOAD, 0L);
    if (res != CURLE_OK) {
        reset_curl(bk);
        return -EIO;
    }
    return ftp_backend_open(path, O_WRONLY | O_CREAT | O_TRUNC, h);
}

int ftp_backend_read(uint64_t h, char* buf, size_t size, off_t off, size_t* got) {
    FtpBackendFile* f = ftp_handle_get(h);
    if (!f || !buf || !got) return -EINVAL;

    if (f->tmp_fd >= 0) {
        // 写模式 / 读缓存模式：本地临时文件（读模式 open 时已下载全文件）
        ssize_t n = pread(f->tmp_fd, buf, size, off);
        if (n < 0) return -errno;
        *got = (size_t)n;
        return 0;
    }

    return -EIO;
}

int ftp_backend_write(uint64_t h, const char* buf, size_t size, off_t off, size_t* wrote) {
    FtpBackendFile* f = ftp_handle_get(h);
    if (!f || !buf || !wrote) return -EINVAL;
    if (f->tmp_fd < 0) return -EBADF;
    ssize_t n = pwrite(f->tmp_fd, buf, size, off);
    if (n < 0) return -errno;
    *wrote = (size_t)n;
    return 0;
}

int ftp_backend_release(uint64_t h) {
    FtpBackendFile* f = ftp_handle_get(h);
    if (!f) return -EINVAL;
    int rc = 0;

    if (f->writing) {
        // 写模式：读临时文件 → STOR 上传
        off_t sz = lseek(f->tmp_fd, 0, SEEK_END);
        if (sz < 0) { close(f->tmp_fd); f->tmp_fd = -1; ftp_handle_free(h); free(f); return -EIO; }
        lseek(f->tmp_fd, 0, SEEK_SET);

        char* data = sz > 0 ? malloc((size_t)sz) : NULL;
        if (sz > 0 && !data) { close(f->tmp_fd); f->tmp_fd = -1; ftp_handle_free(h); free(f); return -ENOMEM; }

        size_t got = 0;
        if (sz > 0) {
            ssize_t n = read(f->tmp_fd, data, (size_t)sz);
            if (n > 0) got = (size_t)n;
        }
        close(f->tmp_fd);
        f->tmp_fd = -1;

        if (ensure_curl(f->bk) == 0) {
            struct ReadBuf rb = {data ? data : "", got, 0};
            pthread_mutex_lock(&f->bk->op_lock);
            ftp_reset_opts(f->bk);
            curl_easy_setopt(f->bk->curl, CURLOPT_URL, f->ftp_path);
            curl_easy_setopt(f->bk->curl, CURLOPT_UPLOAD, 1L);
            curl_easy_setopt(f->bk->curl, CURLOPT_INFILESIZE, (long)got);
            curl_easy_setopt(f->bk->curl, CURLOPT_READFUNCTION, read_cb);
            curl_easy_setopt(f->bk->curl, CURLOPT_READDATA, &rb);

            CURLcode res = curl_easy_perform(f->bk->curl);
            pthread_mutex_unlock(&f->bk->op_lock);
            curl_easy_setopt(f->bk->curl, CURLOPT_UPLOAD, 0L);
            if (res != CURLE_OK) {
                reset_curl(f->bk);
                rc = -EIO;
            }
        } else {
            rc = -EIO;
        }
        free(data);
    }

    // 读模式：关闭临时文件（写模式已 close 并置 -1）
    if (f->tmp_fd >= 0) close(f->tmp_fd);

    ftp_handle_free(h);
    free(f);
    return rc;
}

/* curlftpfs 方式：提取文件名 + 提取全远程路径 */
static const char* ftp_filename(const char* url) {
    const char* s = strrchr(url, '/');
    return s ? s + 1 : url;
}
static void ftp_remote_path(const char* url, char* path, size_t sz) {
    const char* s = strstr(url, "://");
    if (s) {
        s = strchr(s + 3, '/');
        if (s) { strncpy(path, s, sz - 1); path[sz - 1] = '\0'; return; }
    }
    snprintf(path, sz, "/");
}
static void ftp_parent_url(const char* url, char* parent, size_t sz) {
    const char* s = strrchr(url, '/');
    if (s && s > url + 7) {
        size_t len = (size_t)(s - url);
        if (len >= sz) len = sz - 1;
        memcpy(parent, url, len); parent[len] = '\0';
        if (len > 0 && parent[len-1] != '/') {
            if (len + 1 < sz) { parent[len] = '/'; parent[len+1] = '\0'; }
        }
    } else { snprintf(parent, sz, "%s/", url); }
}

/* curlftpfs 方式：POSTQUOTE + 父目录 URL + 仅文件名，NOBODY 避免数据连接 */
static int ftp_quote_cmd(FtpBackend* bk, const char* path, const char* fmt, int ok_code) {
    if (!bk) return -ENOENT;
    if (ensure_curl(bk) != 0) return -EIO;
    curl_easy_setopt(bk->curl, CURLOPT_RESUME_FROM, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_FILETIME, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_CUSTOMREQUEST, NULL);
    curl_easy_setopt(bk->curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_UPLOAD, 0L);
    char url[2048], parent[2048], cmd[4096];
    build_url(bk, path, url, sizeof url);
    ftp_parent_url(url, parent, sizeof parent);
    snprintf(cmd, sizeof cmd, fmt, ftp_filename(url));
    struct curl_slist* slist = curl_slist_append(NULL, cmd);
    struct WriteBuf wb = {0};
    wb.auto_grow = true;
    pthread_mutex_lock(&bk->op_lock);
    ftp_reset_opts(bk);
    curl_easy_setopt(bk->curl, CURLOPT_POSTQUOTE, slist);
    curl_easy_setopt(bk->curl, CURLOPT_URL, parent);
    curl_easy_setopt(bk->curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEDATA, &wb);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(bk->curl, CURLOPT_UPLOAD, 0L);
    CURLcode res = curl_easy_perform(bk->curl);
    pthread_mutex_unlock(&bk->op_lock);
    curl_easy_setopt(bk->curl, CURLOPT_POSTQUOTE, NULL);
    curl_slist_free_all(slist);
    free(wb.buf);
    /* 失败：按 ok_code 映射预期错误（rmdir 非空目录 → -ENOTEMPTY），
       未指定（unlink/mkdir）则统一 -EPERM（curlftpfs 方式） */
    if (res != CURLE_OK) {
        reset_curl(bk);
        return ok_code ? -ok_code : -EPERM;
    }
    return 0;
}

int ftp_backend_unlink(const char* path) {
    return ftp_quote_cmd(ftp_backend_find(path), path, "DELE %s", 0);
}

int ftp_backend_mkdir(const char* path, mode_t mode) {
    (void)mode;
    return ftp_quote_cmd(ftp_backend_find(path), path, "MKD %s", 0);
}

int ftp_backend_rmdir(const char* path) {
    return ftp_quote_cmd(ftp_backend_find(path), path, "RMD %s", ENOTEMPTY);
}

int ftp_backend_rename(const char* from, const char* to) {
    FtpBackend* bk = ftp_backend_find(from);
    if (!bk) return -ENOENT;
    if (ensure_curl(bk) != 0) return -EIO;
    char from_url[2048], to_url[2048], from_path[2048], to_path[2048], parent[2048], cmd1[4096], cmd2[4096];
    build_url(bk, from, from_url, sizeof from_url);
    build_url(bk, to, to_url, sizeof to_url);
    /* RNFR/RNTO 用完整远程路径（跨目录 rename 时目标目录才正确），
       不能只用 basename——RNTO 会在源 CWD 内改名导致文件放错目录 */
    ftp_remote_path(from_url, from_path, sizeof from_path);
    ftp_remote_path(to_url, to_path, sizeof to_path);
    ftp_parent_url(from_url, parent, sizeof parent);
    snprintf(cmd1, sizeof cmd1, "RNFR %s", from_path);
    snprintf(cmd2, sizeof cmd2, "RNTO %s", to_path);
    struct curl_slist* slist = NULL;
    slist = curl_slist_append(slist, cmd1);
    slist = curl_slist_append(slist, cmd2);
    pthread_mutex_lock(&bk->op_lock);
    ftp_reset_opts(bk);
    curl_easy_setopt(bk->curl, CURLOPT_POSTQUOTE, slist);
    curl_easy_setopt(bk->curl, CURLOPT_URL, parent);
    curl_easy_setopt(bk->curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(bk->curl, CURLOPT_UPLOAD, 0L);
    CURLcode res = curl_easy_perform(bk->curl);
    pthread_mutex_unlock(&bk->op_lock);
    curl_easy_setopt(bk->curl, CURLOPT_POSTQUOTE, NULL);
    curl_slist_free_all(slist);
    if (res != CURLE_OK) { reset_curl(bk); return -EIO; }
    return 0;
}

int ftp_backend_truncate(const char* path, off_t size) {
    (void)path;
    (void)size;
    // libcurl 不支持直接 TRUNCATE
    // 简单实现：下载原始文件，截断后重新上传
    // 暂时用 STOR 空文件模拟 size=0
    if (size == 0) {
        FtpBackend* bk = ftp_backend_find(path);
        if (!bk) return -ENOENT;
        if (ensure_curl(bk) != 0) return -EIO;

        char url[2048];
        build_url(bk, path, url, sizeof url);

        struct ReadBuf rb = {"", 0, 0};
        pthread_mutex_lock(&bk->op_lock);
        ftp_reset_opts(bk);
        curl_easy_setopt(bk->curl, CURLOPT_URL, url);
        curl_easy_setopt(bk->curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(bk->curl, CURLOPT_INFILESIZE, 0L);
        curl_easy_setopt(bk->curl, CURLOPT_READFUNCTION, read_cb);
        curl_easy_setopt(bk->curl, CURLOPT_READDATA, &rb);

        CURLcode res = curl_easy_perform(bk->curl);
        pthread_mutex_unlock(&bk->op_lock);
        curl_easy_setopt(bk->curl, CURLOPT_UPLOAD, 0L);
        if (res != CURLE_OK) { reset_curl(bk); return -EIO; }
        return 0;
    }
    return -EIO;  // 非零截断暂不支持
}

/* ================= 模块注册接口 =================

libcurl 后端函数通过 ftp_backend.h 暴露给 ftp_module.c，
由 ftp_module.c 注册到 NspModuleOps 中。无需单独注册函数。 */