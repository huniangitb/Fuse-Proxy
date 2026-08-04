#define _GNU_SOURCE
#include "ftp_backend.h"
#include "ftp_client.h"
#include "common.h"   /* CONFIG_DIR 与 mkdir_recursive */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>

/* ================= 后端注册表（挂载前缀 → FTP 配置） ================= */

typedef struct FtpBackend {
    FtpServerCfg cfg;
    char prefix[PATH_MAX];   /* 虚拟前缀 = "/" + 段名（如 /云盘），backend_match 依据 */
} FtpBackend;

#define FTP_BACKEND_MAX 16
static FtpBackend g_backends[FTP_BACKEND_MAX];
static int g_backend_count = 0;

int ftp_backend_add(const FtpServerCfg* cfg) {
    if (!cfg || !cfg->name[0] || g_backend_count >= FTP_BACKEND_MAX) return -1;
    FtpBackend* bk = &g_backends[g_backend_count];
    memset(bk, 0, sizeof *bk);
    bk->cfg = *cfg;
    /* 虚拟前缀 = /段名：FUSE 剥离 /0/ 后的原始路径（/云盘/xxx）直接命中，
       无需 REDIRECT 规则与变量 */
    snprintf(bk->prefix, sizeof bk->prefix, "/%s", cfg->name);
    g_backend_count++;
    return 0;
}

void ftp_backend_clear(void) { g_backend_count = 0; }
int  ftp_backend_count(void) { return g_backend_count; }

/* 每分钟重连探活：对每个后端尝试 FTP 连接并登出。
   FTP 每次操作新建连接，此函数用于服务器故障恢复后自动恢复可用性
   （配合模块后台线程每 60s 调用），无需重启 fuse_daemon/模块。 */
static int ftp_conn_open(FtpBackend* bk, FtpConn* c);   /* 定义见下（连接段） */
void ftp_backend_retry_all(void) {
    for (int i = 0; i < g_backend_count; i++) {
        FtpConn c;
        if (ftp_conn_open(&g_backends[i], &c) == 0) {
            LOG("ftp_module: FTP %s:%d 连接恢复（server=%s）",
                g_backends[i].cfg.host, g_backends[i].cfg.port, g_backends[i].cfg.name);
            ftp_close(&c);
        }
    }
}

/* 找 path 命中的后端（前缀 + '/' 或精确相等） */
static FtpBackend* ftp_backend_find(const char* path) {
    for (int i = 0; i < g_backend_count; i++) {
        size_t plen = strlen(g_backends[i].prefix);
        if (strncmp(g_backends[i].prefix, path, plen) == 0 &&
            (path[plen] == '\0' || path[plen] == '/'))
            return &g_backends[i];
    }
    return NULL;
}

/* real_path（/mnt/nsp_ftp/云盘/x）→ FTP 远程路径（/upload/x） */
static void ftp_remote_path(FtpBackend* bk, const char* path, char* out, size_t sz) {
    const char* rel = path + strlen(bk->prefix);   /* 剥离前缀 */
    while (*rel == '/') rel++;
    const char* base = bk->cfg.remote_dir;
    size_t blen = strlen(base);
    if (rel[0] == '\0') {
        /* 后端根：remote_dir 去尾斜杠（部分 FTP 服务器对带斜杠路径的
           LIST/文件操作返回 550，与 getattr 的 CWD 兜底行为不一致） */
        size_t n = blen;
        while (n > 1 && base[n - 1] == '/') n--;
        snprintf(out, sz, "%.*s", (int)n, base);
    } else if (blen > 1 && base[blen - 1] == '/') {
        snprintf(out, sz, "%s%s", base, rel);
    } else if (blen == 1 && base[0] == '/') {
        snprintf(out, sz, "/%s", rel);
    } else {
        snprintf(out, sz, "%s/%s", base, rel);
    }
}

/* ================= 路径信息缓存（TTL 最长 1 分钟） =================
   getattr/readdir 结果缓存，减少 FTP 往返；创建/删除/重命名等路径变更
   后由 ftp_cache_invalidate 立即失效 */

#define FTP_CACHE_MAX 64
#define FTP_CACHE_TTL_NS (60LL * 1000000000LL)

typedef struct FtpPathCache {
    char path[PATH_MAX];      /* 虚拟路径（sub_path，如 /云盘/xxx） */
    struct stat st;           /* getattr 缓存 */
    bool has_st;
    NspDirEntry entries[256]; /* readdir 缓存 */
    int entry_count;
    struct timespec ts;       /* 缓存时间（CLOCK_MONOTONIC） */
} FtpPathCache;

static FtpPathCache g_path_cache[FTP_CACHE_MAX];
static pthread_mutex_t g_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool ftp_cache_get(const char* path, struct stat* st, NspDirEntry* entries, int max, int* count) {
    pthread_mutex_lock(&g_cache_mutex);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    for (int i = 0; i < FTP_CACHE_MAX; i++) {
        FtpPathCache* c = &g_path_cache[i];
        if (c->path[0] && strcmp(c->path, path) == 0) {
            if (now.tv_sec - c->ts.tv_sec > FTP_CACHE_TTL_NS / 1000000000LL) {
                c->path[0] = '\0';   /* 过期 */
                pthread_mutex_unlock(&g_cache_mutex);
                return false;
            }
            /* 区分命中类型：getattr 请求须 has_st，readdir 请求须有条目
               （否则 getattr 先缓存会令 readdir 误命中返回空） */
            if (st && !c->has_st) { pthread_mutex_unlock(&g_cache_mutex); return false; }
            if (entries && c->entry_count <= 0) { pthread_mutex_unlock(&g_cache_mutex); return false; }
            if (st && c->has_st) *st = c->st;
            if (entries && c->entry_count > 0) {
                int n = c->entry_count < max ? c->entry_count : max;
                memcpy(entries, c->entries, (size_t)n * sizeof(NspDirEntry));
                if (count) *count = n;
            } else if (count) *count = 0;
            pthread_mutex_unlock(&g_cache_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&g_cache_mutex);
    return false;
}

static void ftp_cache_put(const char* path, const struct stat* st, const NspDirEntry* entries, int count) {
    pthread_mutex_lock(&g_cache_mutex);
    int slot = -1;
    for (int i = 0; i < FTP_CACHE_MAX; i++) {
        if (g_path_cache[i].path[0] && strcmp(g_path_cache[i].path, path) == 0) { slot = i; break; }
    }
    if (slot < 0) {
        for (int i = 0; i < FTP_CACHE_MAX; i++) {
            if (!g_path_cache[i].path[0]) { slot = i; break; }
        }
    }
    if (slot < 0) slot = 0;   /* 满：覆盖第一个 */
    FtpPathCache* c = &g_path_cache[slot];
    memset(c, 0, sizeof *c);
    strncpy(c->path, path, sizeof c->path - 1);
    if (st) { c->st = *st; c->has_st = true; }
    if (entries && count > 0) {
        int n = count < 256 ? count : 256;
        memcpy(c->entries, entries, (size_t)n * sizeof(NspDirEntry));
        c->entry_count = n;
    }
    clock_gettime(CLOCK_MONOTONIC, &c->ts);
    pthread_mutex_unlock(&g_cache_mutex);
}

/* 路径变更后立即失效（unlink/mkdir/rmdir/rename/create/truncate 成功后调用） */
void ftp_cache_invalidate(void) {
    pthread_mutex_lock(&g_cache_mutex);
    for (int i = 0; i < FTP_CACHE_MAX; i++) g_path_cache[i].path[0] = '\0';
    pthread_mutex_unlock(&g_cache_mutex);
}

/* ================= 连接 ================= */

static int ftp_conn_open(FtpBackend* bk, FtpConn* c) {
    return ftp_connect(c, bk->cfg.host, bk->cfg.port, bk->cfg.user, bk->cfg.pass, 15);
}

/* ================= 工具（迁移自 ftp_fuse） ================= */

static void split_parent_base(const char* path, char* parent, size_t ps, char* base, size_t bs) {
    const char* slash = strrchr(path, '/');
    if (!slash || slash == path) {
        strncpy(parent, "/", ps - 1); parent[ps - 1] = '\0';
        strncpy(base, slash ? path + 1 : path, bs - 1); base[bs - 1] = '\0';
    } else {
        size_t plen = (size_t)(slash - path);
        if (plen >= ps) plen = ps - 1;
        memcpy(parent, path, plen); parent[plen] = '\0';
        strncpy(base, slash + 1, bs - 1); base[bs - 1] = '\0';
    }
}

static int find_entry_in_list(const char* list, const char* base, FtpEntry* out) {
    FtpEntry entries[512];
    int n = ftp_parse_list(list, entries, 512);
    for (int i = 0; i < n; i++) {
        if (strcmp(entries[i].name, base) == 0) {
            if (out) *out = entries[i];
            return 1;
        }
    }
    return 0;
}

/* 临时目录由编译时目标决定：Android → CONFIG_DIR/ftp-tmp；GNU → /tmp */
static int temp_path(char* out, size_t sz) {
#ifdef TARGET_ANDROID
    static const char* dirs[] = { CONFIG_DIR "/ftp-tmp" };
#else
    static const char* dirs[] = { "/tmp" };
#endif
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        if (mkdir_recursive((char*)dirs[i]) != 0) return -1;
        snprintf(out, sz, "%s/ftp_fuse_XXXXXX", dirs[i]);
        int fd = mkstemp(out);
        if (fd >= 0) return fd;
    }
    return -1;
}

/* ================= NspModuleOps.backend_* 实现 ================= */

int ftp_backend_match(const char* path) {
    return ftp_backend_find(path) ? 1 : 0;
}

int ftp_backend_getattr(const char* path, struct stat* st) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk) return -ENOENT;
    if (ftp_cache_get(path, st, NULL, 0, NULL)) { FTP_DBG("getattr: 缓存命中 path=%s\n", path); return 0; }
    FTP_DBG("getattr: 缓存未命中 path=%s\n", path);
    memset(st, 0, sizeof *st);

    FtpConn c;
    if (ftp_conn_open(bk, &c) != 0) return -EIO;
    char rpath[1024];
    ftp_remote_path(bk, path, rpath, sizeof rpath);
    int rc = -ENOENT;

    /* 1. SIZE 判定文件 */
    long long size;
    if (ftp_size(&c, rpath, &size) == 0) {
        st->st_mode = S_IFREG | 0644;
        st->st_size = size;
        st->st_nlink = 1;
        time_t mt = 0;
        if (ftp_mdtm(&c, rpath, &mt) == 0) st->st_mtime = mt;
        rc = 0;
        goto done;
    }
    /* 2. LIST 父目录查条目 */
    {
        char rparent[1024], local_base[256];
        split_parent_base(rpath, rparent, sizeof rparent, local_base, sizeof local_base);
        char* list = NULL;
        if (ftp_list(&c, rparent, &list, NULL) == 0 && list) {
            FtpEntry e;
            if (find_entry_in_list(list, local_base, &e)) {
                st->st_mode = e.is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644);
                st->st_size = e.size;
                st->st_mtime = e.mtime;
                st->st_nlink = e.is_dir ? 2 : 1;
                rc = 0;
            }
            free(list);
        }
        /* 3. 目录判定用 CWD（LIST 对不存在路径可能返回空成功）；
           判定后恢复回后端根目录：用 prefix 自身计算（不能传 "/"，
           "/" 短于前缀会导致 ftp_remote_path 越界读） */
        if (rc != 0) {
            if (ftp_cmd(&c, "CWD", rpath) == 250) {
                st->st_mode = S_IFDIR | 0755;
                st->st_nlink = 2;
                rc = 0;
                char rroot[1024];
                ftp_remote_path(bk, bk->prefix, rroot, sizeof rroot);
                ftp_cmd(&c, "CWD", rroot);
            }
        }
    }
done:
    ftp_close(&c);
    if (rc == 0) ftp_cache_put(path, st, NULL, 0);
    return rc;
}

int ftp_backend_readdir(const char* path, NspDirEntry* entries, int max) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk) return -ENOENT;
    if (!entries || max <= 0) return 0;
    int cached = 0;
    if (ftp_cache_get(path, NULL, entries, max, &cached)) return cached;   /* 命中缓存 */
    FtpConn c;
    if (ftp_conn_open(bk, &c) != 0) return -EIO;
    char rpath[1024];
    ftp_remote_path(bk, path, rpath, sizeof rpath);
    char* list = NULL;
    if (ftp_list(&c, rpath, &list, NULL) != 0) {
        ftp_close(&c);
        return -ENOENT;
    }
    FtpEntry fe[1024];
    int n = ftp_parse_list(list, fe, 1024);
    free(list);
    int out_n = 0;
    for (int i = 0; i < n && out_n < max; i++) {
        strncpy(entries[out_n].name, fe[i].name, sizeof entries[out_n].name - 1);
        entries[out_n].name[sizeof entries[out_n].name - 1] = '\0';
        entries[out_n].is_dir = fe[i].is_dir;
        out_n++;
    }
    ftp_close(&c);
    if (out_n > 0) ftp_cache_put(path, NULL, entries, out_n);
    return out_n;
}

/* ================= 文件句柄（写模式：临时文件缓存 + release STOR） ================= */

typedef struct FtpBackendFile {
    FtpBackend* bk;
    char ftp_path[PATH_MAX];   /* 远程路径（release 上传目标） */
    int  tmp_fd;               /* 写模式上传缓存 fd；-1=未建 */
    bool writing;              /* true=写模式（release STOR 上传）；false=读模式（内存分段流式） */
    /* 读模式：内存分段下载——每段 = read count，分配 → 下载 → 传给应用 → 释放；
       复用连接 + 失败重试，传完一段销毁一段（无缓冲上限，防爆内存） */
    FtpConn* conn;             /* 复用连接；NULL=未打开 */
} FtpBackendFile;

/* 句柄为小整数 ID（非指针）：Android tagged-pointer 检测会因 fi->fh 存
   堆指针（MTE tag 非零）触发 "Pointer tag truncated" SIGABRT（用户指示：
   FTP 路径不做 FD 透传等本地优化），故后端句柄一律用非指针 ID */
#define FTP_HANDLE_MAX 256
static FtpBackendFile* g_handles[FTP_HANDLE_MAX];
static pthread_mutex_t g_handles_mutex = PTHREAD_MUTEX_INITIALIZER;

/* 分配句柄 ID（1..FTP_HANDLE_MAX-1），失败返回 0 */
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

int ftp_backend_open(const char* path, int flags, uint64_t* h) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk || !h) return -ENOENT;
    FtpBackendFile* f = calloc(1, sizeof *f);
    if (!f) return -ENOMEM;
    f->bk = bk;
    ftp_remote_path(bk, path, f->ftp_path, sizeof f->ftp_path);
    f->tmp_fd = -1;

    int accmode = flags & O_ACCMODE;
    bool writing = (accmode != O_RDONLY || (flags & O_CREAT) || (flags & O_TRUNC));
    if (!writing) {
        /* 读模式：内存分段流式——open 仅验证存在，
           read 时按 count 分配 → RETR 下载 → 传给应用 → 释放 */
        FtpConn c;
        if (ftp_conn_open(bk, &c) != 0) { free(f); return -EIO; }
        long long size;
        if (ftp_size(&c, f->ftp_path, &size) != 0 || size < 0) {
            ftp_close(&c); free(f); return -ENOENT;
        }
        ftp_close(&c);
        f->writing = false;
        FTP_DBG("open-read: 内存分段 path=%s ftp=%s size=%lld\n", path, f->ftp_path, size);
        *h = ftp_handle_alloc(f);
        if (*h == 0) { free(f); return -EIO; }
        return 0;
    }

    /* 写模式：建本地临时文件；非 O_TRUNC 且已存在则先拉取 */
    char tpath[128];
    int tfd = temp_path(tpath, sizeof tpath);
    if (tfd < 0) { free(f); return -EIO; }
    bool need_fetch = !(flags & O_TRUNC) && !(flags & O_CREAT);
    if (need_fetch) {
        FtpConn c;
        if (ftp_conn_open(bk, &c) == 0) {
            long long size;
            if (ftp_size(&c, f->ftp_path, &size) == 0 && size > 0) {
                char* data = malloc((size_t)size);
                if (data) {
                    size_t got = 0;
                    if (ftp_retr(&c, f->ftp_path, 0, data, (size_t)size, &got) == 0 && got > 0) {
                        ssize_t w = write(tfd, data, got);
                        (void)w;
                        lseek(tfd, 0, SEEK_SET);
                    }
                    free(data);
                }
            }
            ftp_close(&c);
        }
    }
    f->tmp_fd = tfd;
    f->writing = true;
    unlink(tpath);
    *h = ftp_handle_alloc(f);
        if (*h == 0) { free(f); return -EIO; }
    return 0;
}



int ftp_backend_create(const char* path, mode_t mode, uint64_t* h) {
    (void)mode;
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk || !h) return -ENOENT;
    /* 先立即创建空文件：框架在 create 后会 getattr 验证新节点 */
    FtpConn c;
    if (ftp_conn_open(bk, &c) != 0) return -EIO;
    char rpath[1024];
    ftp_remote_path(bk, path, rpath, sizeof rpath);
    int rc = ftp_stor(&c, rpath, "", 0);
    ftp_close(&c);
    if (rc != 0) return -EIO;
    ftp_cache_invalidate();   /* 创建文件后立即失效缓存 */
    return ftp_backend_open(path, O_WRONLY | O_CREAT | O_TRUNC, h);
}

int ftp_backend_read(uint64_t h, char* buf, size_t size, off_t off, size_t* got) {
    FtpBackendFile* f = ftp_handle_get(h);
    if (!f || !buf || !got) return -EINVAL;
    if (f->writing) {
        /* 写模式：本地临时文件读改写 */
        ssize_t n = pread(f->tmp_fd, buf, size, off);
        if (n < 0) return -errno;
        *got = (size_t)n;
        return 0;
    }
    /* 读模式：内存分段——分配 → 下载 → 传应用 → 释放（传完一段销毁一段） */
    if (f->writing) {
        ssize_t n = pread(f->tmp_fd, buf, size, off);
        if (n < 0) return -errno;
        *got = (size_t)n;
        return 0;
    }
    /* 读模式：复用连接，失败重试 */
    if (!f->conn) {
        f->conn = malloc(sizeof(FtpConn));
        if (!f->conn) return -ENOMEM;
        if (ftp_conn_open(f->bk, f->conn) != 0) { free(f->conn); f->conn = NULL; return -EIO; }
    }
    char* dbuf = malloc(size);
    if (!dbuf) return -ENOMEM;
    size_t dn = 0;
    int rc = ftp_retr(f->conn, f->ftp_path, off, dbuf, size, &dn);
    if (rc != 0) {
        ftp_close(f->conn); free(f->conn); f->conn = NULL;
        f->conn = malloc(sizeof(FtpConn));
        if (f->conn && ftp_conn_open(f->bk, f->conn) == 0) {
            dn = 0; rc = ftp_retr(f->conn, f->ftp_path, off, dbuf, size, &dn);
        }
        if (rc != 0) {
            if (f->conn) { ftp_close(f->conn); free(f->conn); f->conn = NULL; }
            free(dbuf); return -EIO;
        }
    }
    if (dn > 0) memcpy(buf, dbuf, dn);
    free(dbuf);  /* 传完一段，销毁一段 */
    *got = dn;
    FTP_DBG("read: 内存分段 off=%lld req=%zu got=%zu\n", (long long)off, size, dn);
    return 0;
}

int ftp_backend_write(uint64_t h, const char* buf, size_t size, off_t off, size_t* wrote) {
    FtpBackendFile* f = ftp_handle_get(h);
    if (!f || !buf || !wrote) return -EINVAL;
    if (f->tmp_fd < 0) return -EBADF;   /* 只读句柄不可写 */
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
        /* 写模式：读临时文件 → STOR 全量上传 */
        off_t sz = lseek(f->tmp_fd, 0, SEEK_END);
        if (sz < 0) { close(f->tmp_fd); ftp_handle_free(h); free(f); return -EIO; }
        lseek(f->tmp_fd, 0, SEEK_SET);
        char* data = sz > 0 ? malloc((size_t)sz) : NULL;
        if (sz > 0 && !data) { close(f->tmp_fd); ftp_handle_free(h); free(f); return -ENOMEM; }
        size_t got = 0;
        if (sz > 0) {
            ssize_t n = read(f->tmp_fd, data, (size_t)sz);
            if (n > 0) got = (size_t)n;
        }
        close(f->tmp_fd);
        if (got > 0 || sz == 0) {
            FtpConn c;
            if (ftp_conn_open(f->bk, &c) == 0) {
                if (ftp_stor(&c, f->ftp_path, data ? data : "", got) != 0) rc = -EIO;
                ftp_close(&c);
            } else rc = -EIO;
        }
        free(data);
    } else {
        /* 读模式：关闭复用连接 */
        if (f->conn) { ftp_close(f->conn); free(f->conn); f->conn = NULL; }
    }
    ftp_handle_free(h);
    free(f);
    return rc;
}

int ftp_backend_unlink(const char* path) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk) return -ENOENT;
    FtpConn c;
    if (ftp_conn_open(bk, &c) != 0) return -EIO;
    char rpath[1024];
    ftp_remote_path(bk, path, rpath, sizeof rpath);
    int rc = (ftp_dele(&c, rpath) == 0) ? 0 : -ENOENT;
    ftp_close(&c);
    if (rc == 0) ftp_cache_invalidate();   /* 删除路径后立即失效缓存 */
    return rc;
}

int ftp_backend_mkdir(const char* path, mode_t mode) {
    (void)mode;
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk) return -ENOENT;
    FtpConn c;
    if (ftp_conn_open(bk, &c) != 0) return -EIO;
    char rpath[1024];
    ftp_remote_path(bk, path, rpath, sizeof rpath);
    int rc = (ftp_mkd(&c, rpath) == 0) ? 0 : -EIO;
    ftp_close(&c);
    if (rc == 0) ftp_cache_invalidate();   /* 创建目录后立即失效缓存 */
    return rc;
}

int ftp_backend_rmdir(const char* path) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk) return -ENOENT;
    FtpConn c;
    if (ftp_conn_open(bk, &c) != 0) return -EIO;
    char rpath[1024];
    ftp_remote_path(bk, path, rpath, sizeof rpath);
    int rc = (ftp_rmd(&c, rpath) == 0) ? 0 : -ENOTEMPTY;
    ftp_close(&c);
    if (rc == 0) ftp_cache_invalidate();   /* 删除目录后立即失效缓存 */
    return rc;
}

int ftp_backend_rename(const char* from, const char* to) {
    FtpBackend* bk = ftp_backend_find(from);
    if (!bk) return -ENOENT;
    FtpConn c;
    if (ftp_conn_open(bk, &c) != 0) return -EIO;
    char rfrom[1024], rto[1024];
    ftp_remote_path(bk, from, rfrom, sizeof rfrom);
    ftp_remote_path(bk, to, rto, sizeof rto);
    int rc = (ftp_rename(&c, rfrom, rto) == 0) ? 0 : -EIO;
    ftp_close(&c);
    if (rc == 0) ftp_cache_invalidate();   /* 重命名后立即失效缓存 */
    return rc;
}

int ftp_backend_truncate(const char* path, off_t size) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk) return -ENOENT;
    FtpConn c;
    if (ftp_conn_open(bk, &c) != 0) return -EIO;
    char rpath[1024];
    ftp_remote_path(bk, path, rpath, sizeof rpath);
    int rc = -EIO;
    if (size == 0) {
        rc = (ftp_stor(&c, rpath, "", 0) == 0) ? 0 : -EIO;
    } else {
        long long cur = 0;
        if (ftp_size(&c, rpath, &cur) == 0) {
            size_t readn = cur < size ? (size_t)cur : (size_t)size;
            char* data = readn > 0 ? malloc(readn) : NULL;
            if (readn == 0 || data) {
                size_t got = 0;
                if (ftp_retr(&c, rpath, 0, data ? data : "", readn, &got) == 0) {
                    if (ftp_stor(&c, rpath, data ? data : "", got) == 0) rc = 0;
                }
                free(data);
            }
        }
        if (rc == 0) ftp_cache_invalidate();   /* 截断后立即失效缓存 */
    }
    ftp_close(&c);
    return rc;
}
