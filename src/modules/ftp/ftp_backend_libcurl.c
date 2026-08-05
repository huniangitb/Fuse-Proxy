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
#define FTP_RBUF_MIN (64 * 1024)         /* 预取缓冲最小容量（随机读/初始） */
#define FTP_RBUF_MAX (8 * 1024 * 1024)   /* 预取缓冲最大容量（顺序读 8MB，减少 REST 往返） */

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
    CURL* read_curl;         /* 读模式独立句柄（下载线程专用，不复用共享 bk->curl） */
    /* 滑动读缓冲（下载线程持续填充，read 实时取，避免"等缓冲满一段才回传"） */
    char* rbuf;              /* 滑动缓冲 */
    off_t rbuf_off;          /* 缓冲中首个有效字节的文件偏移 */
    off_t rbuf_base;         /* rbuf[0] 对应的文件偏移（尾部追加/压缩用） */
    size_t rbuf_len;         /* 缓冲有效字节数 */
    size_t rbuf_cap;         /* 当前容量（64KB~8MB 自适应） */
    bool rbuf_eof;           /* 已读到文件尾 */
    pthread_mutex_t f_lock;  /* 保护本文件缓冲状态（下载线程与 read 并发） */
    pthread_cond_t dl_cond;  /* 下载线程：数据到达/空间释放通知 */
    pthread_t dl_tid;        /* 下载线程 */
    bool dl_started;         /* 下载线程已启动 */
    bool dl_stop;            /* 请求下载线程停止（release/跳变） */
    bool dl_restart;         /* 随机跳变：需要重启下载（清空缓冲重新拉） */
    bool dl_error;           /* 最近一次下载出错（open/read 超时兜底判断） */
    bool dl_released;        /* release 已置位：read 应立即退出，不再 cond_wait */
    int  n_readers;          /* 在途 read 计数（f_lock 保护，release 等待归零） */
    off_t dl_grow_off;       /* 上次扩容时的 rbuf_off（验证读侧消费后才扩容） */
} FtpBackendFile;

static FtpBackendFile* g_handles[FTP_HANDLE_MAX];
static pthread_mutex_t g_handles_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ================= 写缓冲回调 ================= */

struct WriteBuf {
    char* buf;
    size_t len;
    size_t cap;
    bool auto_grow;   /* 自动扩容（下载/LIST 用），false 时容量满即停 */
    pthread_mutex_t* lock;  /* 非 NULL：写入/更新 len 时加锁（下载线程与 read 共享缓冲） */
    void* owner;            /* 非 NULL：滑动缓冲下载模式——实时写 owner->rbuf 尾部并广播 */
};

static size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    struct WriteBuf* wb = (struct WriteBuf*)userdata;
    size_t total = size * nmemb;
    size_t ret = 0;
    if (wb->lock) pthread_mutex_lock(wb->lock);   /* 下载线程与 read 共享缓冲：写入加锁 */
    if (wb->owner) {
        /* 滑动缓冲下载模式：写入 rbuf 尾部，实时通知 read 取走。
           缓冲仅作滑动粘合（慢速消费/写盘场景背压）；数据到达立即广播，
           高吞吐消费端（快盘）无需等待缓冲填满 */
        FtpBackendFile* f = (FtpBackendFile*)wb->owner;
        if (f->dl_restart) {
            /* 随机跳变重启中：返回 0 → CURLE_WRITE_ERROR 立即中止旧 RANGE 下载 */
            ret = 0;
            goto out;
        }
        if (f->dl_stop) {
            /* release 已请求停止：返回 0 立即中止在途传输，
               否则 pthread_join 要等缓冲填满或 60s curl 超时才返回 */
            ret = 0;
            goto out;
        }
        /* 滑窗压缩：头部已消费空洞移到缓冲头部，腾出尾部空间继续追加。
           有效数据物理在 [head, head+rbuf_len)，memmove 移动 rbuf_len 字节
           （rbuf_len 是剩余有效字节数，head 是空洞——两者无可比性，
           绝不能写 head>=rbuf_len 时置 0，那会丢失剩余数据导致错位）；
           rbuf_len=0 时 memmove 0 字节无操作 */
        if (f->rbuf_off > f->rbuf_base) {
            size_t head = (size_t)(f->rbuf_off - f->rbuf_base);
            memmove(f->rbuf, f->rbuf + head, f->rbuf_len);
            f->rbuf_base = f->rbuf_off;
        }
        if (f->rbuf_len >= f->rbuf_cap) {
            ret = 0;   /* 缓冲满：返回 0 → CURLE_WRITE_ERROR 背压，等 read 消费后续传 */
            goto out;
        }
        size_t wpos = (size_t)(f->rbuf_off + (off_t)f->rbuf_len - f->rbuf_base);
        size_t remain = f->rbuf_cap - wpos;
        size_t n = total < remain ? total : remain;
        memcpy(f->rbuf + wpos, ptr, n);
        f->rbuf_len += n;
        pthread_cond_broadcast(&f->dl_cond);   /* 数据到达：read 可实时取 */
        ret = n;
        goto out;
    }
    if (wb->len + total > wb->cap) {
        if (wb->auto_grow || !wb->buf) {
            // 自动扩容（buf 为 NULL 或 auto_grow 开启）
            size_t ncap = wb->len + total + 4096;
            char* nbuf = realloc(wb->buf, ncap);
            if (!nbuf) goto out;
            wb->buf = nbuf;
            wb->cap = ncap;
            memcpy(wb->buf + wb->len, ptr, total);
            wb->len += total;
            ret = total;
        } else {
            // buf 由调用者提供且不允许扩容：只写入剩余容量，
            // 返回实际写入字节数（< 请求数 → curl 以 WRITE_ERROR 中止，
            // 由调用方视为"读够即停"）。不能整块返回 0，否则丢失已收数据
            size_t remain = wb->cap - wb->len;
            if (remain > 0) {
                memcpy(wb->buf + wb->len, ptr, remain);
                wb->len += remain;
            }
            ret = remain;
        }
    } else {
        memcpy(wb->buf + wb->len, ptr, total);
        wb->len += total;
        ret = total;
    }
out:
    if (wb->lock) pthread_mutex_unlock(wb->lock);
    return ret;
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
    /* 必须先持 op_lock 再清理：各操作在 op_lock 内 setopt/perform 共享
       bk->curl，若此处只持 bk->lock 清理，并发线程可能正用已 cleanup 的
       句柄 → UAF（0x18 NULL 解引用崩溃）。所有调用点均在 op_lock 释放后，
       锁序（op_lock → bk->lock）与使用路径无嵌套冲突，不会死锁 */
    pthread_mutex_lock(&bk->op_lock);
    pthread_mutex_lock(&bk->lock);
    if (bk->curl) {
        curl_easy_cleanup(bk->curl);
        bk->curl = NULL;
    }
    bk->connected = false;
    pthread_mutex_unlock(&bk->lock);
    pthread_mutex_unlock(&bk->op_lock);
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

/* 前置声明：读下载线程（定义在 ftp_backend_read 前，open 读模式启动） */
static void* ftp_dl_thread(void* arg);

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
    long resp_code = 0;
    curl_off_t cl = 0;
    long ft = -1;
    CURLcode res;
    pthread_mutex_lock(&bk->op_lock);
    ftp_reset_opts(bk);
    curl_easy_setopt(bk->curl, CURLOPT_URL, url);
    curl_easy_setopt(bk->curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(bk->curl, CURLOPT_FILETIME, 1L);
    curl_easy_setopt(bk->curl, CURLOPT_HEADER, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEDATA, &wb);

    res = curl_easy_perform(bk->curl);
    // getinfo 必须在 op_lock 内：句柄状态由本操作独占，避免并发 perform
    // 覆盖后读到污染值（如 cl=0）
    if (res == CURLE_OK) {
        curl_easy_getinfo(bk->curl, CURLINFO_RESPONSE_CODE, &resp_code);
        if (resp_code == 213 || resp_code == 350) {
            curl_easy_getinfo(bk->curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl);
            curl_easy_getinfo(bk->curl, CURLINFO_FILETIME, &ft);
        }
    }
    pthread_mutex_unlock(&bk->op_lock);
    if (res == CURLE_OK && (resp_code == 213 || resp_code == 350)) {
        // 文件存在
        st->st_mode = S_IFREG | 0644;
        st->st_size = (off_t)cl;
        st->st_nlink = 1;
        if (ft >= 0) st->st_mtime = (time_t)ft;
        free(wb.buf);
        return 0;
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
    curl_easy_setopt(bk->curl, CURLOPT_CUSTOMREQUEST, NULL); // 锁内重置，防并发竞争
    pthread_mutex_unlock(&bk->op_lock);
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
                /* 拷贝文件名并显式补 NUL：strncpy 在 nlen < 容量时不补 NUL，
                   会残留栈垃圾字节导致条目名拼接/乱码（根目录短名最明显） */
                size_t cap = sizeof(entries[out_n].name) - 1;
                size_t cp = nlen < cap ? nlen : cap;
                memcpy(entries[out_n].name, name, cp);
                entries[out_n].name[cp] = '\0';
                entries[out_n].is_dir = (line[0] == 'd');
                out_n++;
            }
        }
        line = nl + 1;
    }
    free(wb.buf);
    return out_n;
}

/* 创建读模式独立句柄（open 与 read 错误重建共用）：
   不复用共享 bk->curl，避免与 STOR 上传并发竞争 */
static CURL* ftp_read_curl_new(const FtpBackend* bk) {
    CURL* rc = curl_easy_init();
    if (!rc) return NULL;
    curl_easy_setopt(rc, CURLOPT_USERNAME, bk->cfg.user);
    curl_easy_setopt(rc, CURLOPT_PASSWORD, bk->cfg.pass);
    curl_easy_setopt(rc, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(rc, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(rc, CURLOPT_FTP_RESPONSE_TIMEOUT, 30L);
    curl_easy_setopt(rc, CURLOPT_FTP_SKIP_PASV_IP, 1L);
    curl_easy_setopt(rc, CURLOPT_USE_SSL, CURLUSESSL_NONE);
    curl_easy_setopt(rc, CURLOPT_FOLLOWLOCATION, 0L);
    return rc;
}

int ftp_backend_open(const char* path, int flags, uint64_t* h) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk || !h) return -ENOENT;

    if (ensure_curl(bk) != 0) return -EIO;

    FtpBackendFile* f = calloc(1, sizeof *f);
    if (!f) return -ENOMEM;
    f->bk = bk;
    f->tmp_fd = -1;
    pthread_mutex_init(&f->f_lock, NULL);   /* 保护读缓冲状态 */
    build_url(bk, path, f->ftp_path, sizeof f->ftp_path);

    int accmode = flags & O_ACCMODE;
    bool writing = (accmode != O_RDONLY || (flags & O_CREAT) || (flags & O_TRUNC));

    if (writing) {
        // 写模式：本地临时文件，release 时上传
        char tpath[128];
        snprintf(tpath, sizeof tpath, "/tmp/nsp_ftp_XXXXXX");
        int tfd = mkstemp(tpath);
        if (tfd < 0) { pthread_mutex_destroy(&f->f_lock); free(f); return -EIO; }
        unlink(tpath);
        f->tmp_fd = tfd;
        f->writing = true;
        *h = ftp_handle_alloc(f);
        if (*h == 0) { close(tfd); pthread_mutex_destroy(&f->f_lock); free(f); return -EIO; }
        return 0;
    }

    // 读模式：滑动缓冲 + 下载线程——FTP 数据持续拉取写入缓冲并实时广播，
    // read 拿到覆盖数据立即回传（不等缓冲满）；缓冲仅作慢速消费端背压粘合
    struct stat st;
    if (ftp_backend_getattr(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        pthread_mutex_destroy(&f->f_lock);
        free(f);
        return -ENOENT;
    }
    f->file_size = (size_t)st.st_size;
    f->writing = false;

    // 每文件独立读句柄（下载线程专用，不复用共享 bk->curl，避免与 STOR 上传并发竞争）
    CURL* rc = ftp_read_curl_new(bk);
    if (!rc) { pthread_mutex_destroy(&f->f_lock); free(f); return -EIO; }
    f->read_curl = rc;

    // 初始化滑动缓冲并启动下载线程
    f->rbuf_cap = FTP_RBUF_MIN;
    f->rbuf = malloc(f->rbuf_cap);
    if (!f->rbuf) { curl_easy_cleanup(f->read_curl); pthread_mutex_destroy(&f->f_lock); free(f); return -ENOMEM; }
    pthread_cond_init(&f->dl_cond, NULL);
    f->dl_stop = false;
    f->dl_restart = false;
    f->dl_error = false;
    if (pthread_create(&f->dl_tid, NULL, ftp_dl_thread, f) != 0) {
        curl_easy_cleanup(f->read_curl);
        free(f->rbuf);
        pthread_cond_destroy(&f->dl_cond);
        pthread_mutex_destroy(&f->f_lock);
        free(f);
        return -EIO;
    }
    f->dl_started = true;

    *h = ftp_handle_alloc(f);
    if (*h == 0) {
        /* 句柄表满：必须停止并 join 已启动的下载线程后再销毁资源，
           否则线程在已释放的 f 上运行（UAF：锁已销毁的 f_lock、
           对已 cleanup 的 curl 句柄 perform、触碰已 free 的 rbuf） */
        pthread_mutex_lock(&f->f_lock);
        f->dl_stop = true;
        pthread_cond_broadcast(&f->dl_cond);
        pthread_mutex_unlock(&f->f_lock);
        pthread_join(f->dl_tid, NULL);
        curl_easy_cleanup(rc);
        free(f->rbuf);
        pthread_cond_destroy(&f->dl_cond);
        pthread_mutex_destroy(&f->f_lock);
        free(f);
        return -EIO;
    }
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
    curl_easy_setopt(bk->curl, CURLOPT_UPLOAD, 0L);   /* 锁内清理，防并发竞争句柄 */
    pthread_mutex_unlock(&bk->op_lock);
    if (res != CURLE_OK) {
        reset_curl(bk);
        return -EIO;
    }
    return ftp_backend_open(path, O_WRONLY | O_CREAT | O_TRUNC, h);
}

/* 预取：确保 rbuf 覆盖 [off, off+size)。顺序续读保持连接、缓冲翻倍至 1MB；
   随机跳变清空缓冲并缩容到 64KB；write_cb 写满缓冲返回 0（CURLE_WRITE_ERROR）
   实现"缓冲满即阻塞下载"（背压），read 消费后再续传。
   调用方须持有 f->f_lock。返回 0 成功（缓冲尽量覆盖），-errno 失败。 */
/* 下载线程：持续从 FTP 拉取数据写入滑动缓冲（write_cb owner 模式实时写 rbuf 尾部），
   read 实时取走。缓冲满时 write_cb 返回 0（CURLE_WRITE_ERROR 背压），线程等待
   read 消费腾出空间后继续；随机跳变由 read 置 dl_restart 清空缓冲从新偏移重启。
   仅顺序读场景需要（读模式 open 时启动）；写模式/释放时 dl_stop 退出。
   调用方须确保 read_curl 有效（错误时线程内销毁，read 层重建）。 */
static void* ftp_dl_thread(void* arg) {
    FtpBackendFile* f = arg;
    while (!f->dl_stop) {
        pthread_mutex_lock(&f->f_lock);
        /* 等待：未停止 且 未 restart，且（已 EOF 或 缓冲满不可扩）时挂起。
           EOF 后线程必须存活——read 可能随机跳变回读（restart 唤醒），
           若线程 break 退出则 read 永久 cond_wait（死锁根因） */
        while (!f->dl_stop && !f->dl_restart &&
               (f->rbuf_eof ||
                (f->rbuf_len >= f->rbuf_cap && f->rbuf_cap >= FTP_RBUF_MAX)))
            pthread_cond_wait(&f->dl_cond, &f->f_lock);
        if (f->dl_stop) { pthread_mutex_unlock(&f->f_lock); break; }
        if (f->dl_restart) {
            /* 随机跳变：清空缓冲，从 read 设置的新 rbuf_off 重新拉 */
            f->dl_restart = false;
            f->rbuf_len = 0;
            f->rbuf_base = f->rbuf_off;
            f->rbuf_eof = false;
            f->dl_error = false;
        }
        if (f->rbuf_eof) {
            /* EOF 且无 restart：回到等待（release 置 dl_stop 或 read 置 restart 唤醒） */
            pthread_mutex_unlock(&f->f_lock);
            continue;
        }
        if (!f->read_curl) { pthread_mutex_unlock(&f->f_lock); break; }
        /* 顺序读扩容：仅当读侧已实际消费（rbuf_off 前进）才扩容翻倍至 8MB。
           不验证消费会让 open 后从不读取的文件也急切下载至 8MB
           （慢链路网络流量/延迟回归）；dl_grow_off 记录上次扩容时的消费位置 */
        if (f->rbuf_len >= f->rbuf_cap && f->rbuf_cap < FTP_RBUF_MAX &&
            f->rbuf_off > f->dl_grow_off) {
            size_t nc = f->rbuf_cap * 2;
            f->rbuf_cap = nc > FTP_RBUF_MAX ? FTP_RBUF_MAX : nc;
            char* nb = realloc(f->rbuf, f->rbuf_cap);
            if (nb) f->rbuf = nb;
            else f->rbuf_cap = FTP_RBUF_MIN;   /* 分配失败：回退最小容量 */
            f->dl_grow_off = f->rbuf_off;
        }
        off_t dl_off = f->rbuf_off + (off_t)f->rbuf_len;
        struct WriteBuf wb = {0};
        wb.owner = f;              /* 滑动缓冲模式：write_cb 加锁写 rbuf 尾部并广播 */
        wb.lock = &f->f_lock;
        pthread_mutex_unlock(&f->f_lock);

        char range[32];
        snprintf(range, sizeof range, "%lld-", (long long)dl_off);
        curl_easy_setopt(f->read_curl, CURLOPT_URL, f->ftp_path);
        curl_easy_setopt(f->read_curl, CURLOPT_NOBODY, 0L);
        curl_easy_setopt(f->read_curl, CURLOPT_UPLOAD, 0L);
        curl_easy_setopt(f->read_curl, CURLOPT_CUSTOMREQUEST, NULL);
        curl_easy_setopt(f->read_curl, CURLOPT_RESUME_FROM, 0L);
        curl_easy_setopt(f->read_curl, CURLOPT_RANGE, range);
        curl_easy_setopt(f->read_curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(f->read_curl, CURLOPT_WRITEDATA, &wb);

        CURLcode res = curl_easy_perform(f->read_curl);
        // 重置选项，防残留影响下次续传
        curl_easy_setopt(f->read_curl, CURLOPT_RANGE, NULL);
        curl_easy_setopt(f->read_curl, CURLOPT_CUSTOMREQUEST, NULL);
        curl_easy_setopt(f->read_curl, CURLOPT_RESUME_FROM, 0L);

        pthread_mutex_lock(&f->f_lock);
        if (res == CURLE_OK || res == CURLE_REMOTE_FILE_NOT_FOUND) {
            f->rbuf_eof = true;   /* 读到文件尾 */
        } else if (res != CURLE_WRITE_ERROR) {
            /* 真错误：保留句柄（curl 自动重连），短暂退避后重试，
               避免忙循环；open/read 的等待由 cond_timedwait 超时兜底 */
            f->dl_error = true;
            pthread_cond_broadcast(&f->dl_cond);
            pthread_mutex_unlock(&f->f_lock);
            usleep(100000);
            continue;
        }
        pthread_cond_broadcast(&f->dl_cond);
        pthread_mutex_unlock(&f->f_lock);
    }
    return NULL;
}

int ftp_backend_read(uint64_t h, char* buf, size_t size, off_t off, size_t* got) {
    FtpBackendFile* f = ftp_handle_get(h);
    if (!f || !buf || !got) return -EINVAL;

    if (f->tmp_fd >= 0) {
        // 写模式：本地临时文件
        ssize_t n = pread(f->tmp_fd, buf, size, off);
        if (n < 0) return -errno;
        *got = (size_t)n;
        return 0;
    }
    if (size == 0) { *got = 0; return 0; }

    pthread_mutex_lock(&f->f_lock);
    /* 在途 read 计数：release 需等待 n_readers 归零后才销毁 cond/锁/f，
       否则 read 可能 cond_wait 在已销毁对象上（UAF/永久挂起） */
    f->n_readers++;
    /* 等待缓冲覆盖 [off, off+size)：下载线程持续填充并广播，
       数据到达立即累积（滑动缓冲实时性），读满 size 或 EOF 才返回——
       绝不短读（FUSE 内核会续读，但 os.pread 等单次调用拿不到短读数据）。
       命中采用"部分命中累积"：off 在缓冲内就 memcpy 可读部分并继续等，
       避免缓冲满时 read 等续传、下载线程等空间的死锁 */
    size_t done = 0;
    int rc = 0;
    for (;;) {
        off_t cur = off + (off_t)done;
        /* 部分命中：cur 落在缓冲内，memcpy 可读部分累积 */
        if (f->rbuf_len > 0 && cur >= f->rbuf_off &&
            cur < f->rbuf_off + (off_t)f->rbuf_len) {
            size_t avail = (size_t)(f->rbuf_off + (off_t)f->rbuf_len - cur);
            size_t cp = avail < (size - done) ? avail : (size - done);
            memcpy(buf + done, f->rbuf + (size_t)(cur - f->rbuf_base), cp);
            done += cp;
            /* 消费：跳过的空洞（cur 之前的未读部分）+ 本次 cp 都必须从
               rbuf_len 扣除——否则 rbuf_off 前进后逻辑可读上限
               (rbuf_off+rbuf_len) 超出物理缓冲末尾 → 越界读（数据错乱/崩溃） */
            size_t skip = (size_t)(cur - f->rbuf_off);
            f->rbuf_off = cur + (off_t)cp;
            f->rbuf_len -= (skip + cp);
            pthread_cond_broadcast(&f->dl_cond);   /* 通知下载线程有空间续传 */
            if (done == size || f->rbuf_eof) {
                *got = done;
                goto out;
            }
            continue;   /* 数据未满：继续等下载线程填充 */
        }
        /* 随机跳变（重启下载）判定：
           - off 在缓冲范围之外（回退或前跳）
           - off 恰好等于缓冲尾 且 缓冲已满（无空间续传，只能从 off 重新拉）
           off == rbuf_off+rbuf_len 且缓冲未满 → 等待续传（下载线程有空间填充），
           绝不置 restart——否则 rbuf_len=0 初始态（off==rbuf_off）恒触发 restart，
           下载线程下载前被 write_cb 的 dl_restart 检查中止 → 无限互相打断死锁 */
        if (cur < f->rbuf_off || cur > f->rbuf_off + (off_t)f->rbuf_len ||
            (cur == f->rbuf_off + (off_t)f->rbuf_len &&
             f->rbuf_len >= f->rbuf_cap)) {
            f->rbuf_off = cur;
            f->rbuf_len = 0;
            f->rbuf_base = cur;
            f->rbuf_eof = false;
            f->dl_restart = true;
            pthread_cond_broadcast(&f->dl_cond);
        }
        /* EOF：返回已累积部分（可能 < size）或 0 */
        if (f->rbuf_eof) {
            *got = done;
            goto out;
        }
        if (f->dl_error) {
            /* 下载出错（且未到 EOF）：返回 EIO，避免无限等待 */
            f->dl_error = false;
            rc = -EIO;
            goto out;
        }
        /* release 已置位：立即退出，不再 cond_wait（条件变量可能被销毁） */
        if (f->dl_released) {
            *got = done;
            goto out;
        }
        /* 数据未到：等待下载线程广播（数据到达/EOF/重启） */
        pthread_cond_wait(&f->dl_cond, &f->f_lock);
    }
out:
    f->n_readers--;
    if (f->dl_released)
        pthread_cond_broadcast(&f->dl_cond);   /* 通知 release 等待循环可继续 */
    pthread_mutex_unlock(&f->f_lock);
    return rc;
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
            /* 单次 read() 对 32MB 级大文件可能读不满（内核限制单次返回量），
               必须循环读满——否则 got < sz，STOR 上传长度不匹配/失败，
               FTP 服务器留下 0 字节文件（大文件写入静默丢失） */
            while (got < (size_t)sz) {
                ssize_t n = read(f->tmp_fd, data + got, (size_t)sz - got);
                if (n <= 0) break;
                got += (size_t)n;
            }
        }
        close(f->tmp_fd);
        f->tmp_fd = -1;

        if (ensure_curl(f->bk) == 0) {
            struct ReadBuf rb = {data ? data : "", got, 0};
            CURLcode res = CURLE_OK;
            /* 上传失败自动重试：并发 STOR（多进程同时 close）或网络瞬态
               会让共享句柄的 perform 返回 CURLE_BAD_FUNCTION_ARGUMENT 等
               瞬时错误（已实测 res=43）；重试吸收竞争窗口，避免上传静默丢失
               （FLUSH 错误会传播给 close() → 应用读到 EIO） */
            for (int attempt = 0; attempt < 3; attempt++) {
                if (attempt > 0) usleep(50000);
                if (ensure_curl(f->bk) != 0) { res = CURLE_FAILED_INIT; break; }
                rb.pos = 0;
                pthread_mutex_lock(&f->bk->op_lock);
                ftp_reset_opts(f->bk);
                curl_easy_setopt(f->bk->curl, CURLOPT_URL, f->ftp_path);
                curl_easy_setopt(f->bk->curl, CURLOPT_UPLOAD, 1L);
                curl_easy_setopt(f->bk->curl, CURLOPT_INFILESIZE, (long)got);
                curl_easy_setopt(f->bk->curl, CURLOPT_READFUNCTION, read_cb);
                curl_easy_setopt(f->bk->curl, CURLOPT_READDATA, &rb);
                res = curl_easy_perform(f->bk->curl);
                curl_easy_setopt(f->bk->curl, CURLOPT_UPLOAD, 0L);   /* 锁内清理，防并发竞争句柄 */
                pthread_mutex_unlock(&f->bk->op_lock);
                if (res == CURLE_OK) break;
            }
            if (res != CURLE_OK) {
                reset_curl(f->bk);
                rc = -EIO;
            }
        } else {
            rc = -EIO;
        }
        free(data);
    }

    // 读模式：停止并 join 下载线程 + 等待在途 read 完成 + 释放滑动缓冲 + 销毁独立读句柄
    if (f->dl_started) {
        pthread_mutex_lock(&f->f_lock);
        f->dl_stop = true;         /* write_cb 检测后立即中止在途传输（join 快速返回） */
        f->dl_released = true;     /* read 检测后立即退出，不再 cond_wait */
        pthread_cond_broadcast(&f->dl_cond);   /* 唤醒下载线程与在途 read */
        pthread_mutex_unlock(&f->f_lock);
        pthread_join(f->dl_tid, NULL);
        f->dl_started = false;
        /* 等待在途 read 全部退出后再销毁条件变量/锁/f——
           否则 read 可能 cond_wait 在已销毁对象上（UAF/永久挂起） */
        pthread_mutex_lock(&f->f_lock);
        while (f->n_readers > 0)
            pthread_cond_wait(&f->dl_cond, &f->f_lock);
        pthread_mutex_unlock(&f->f_lock);
        pthread_cond_destroy(&f->dl_cond);
    }
    if (f->tmp_fd >= 0) close(f->tmp_fd);
    if (f->read_curl) {
        curl_easy_cleanup(f->read_curl);
        f->read_curl = NULL;
    }
    free(f->rbuf);
    f->rbuf = NULL;
    pthread_mutex_destroy(&f->f_lock);

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
    curl_easy_setopt(bk->curl, CURLOPT_POSTQUOTE, NULL);  /* 锁内清理，防并发竞争句柄 */
    pthread_mutex_unlock(&bk->op_lock);
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
    curl_easy_setopt(bk->curl, CURLOPT_POSTQUOTE, NULL);  /* 锁内清理，防并发竞争句柄 */
    pthread_mutex_unlock(&bk->op_lock);
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
        curl_easy_setopt(bk->curl, CURLOPT_UPLOAD, 0L);   /* 锁内清理，防并发竞争句柄 */
        pthread_mutex_unlock(&bk->op_lock);
        if (res != CURLE_OK) { reset_curl(bk); return -EIO; }
        return 0;
    }
    return -EIO;  // 非零截断暂不支持
}

/* ================= 模块注册接口 =================

libcurl 后端函数通过 ftp_backend.h 暴露给 ftp_module.c，
由 ftp_module.c 注册到 NspModuleOps 中。无需单独注册函数。 */