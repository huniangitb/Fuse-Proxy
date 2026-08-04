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

/* ================= 后端注册表（挂载前缀 → FTP 配置） ================= */

typedef struct FtpBackend {
    FtpServerCfg cfg;
    char prefix[PATH_MAX];   /* 挂载前缀 = <mount_base>/<段名>（backend_match 依据） */
} FtpBackend;

#define FTP_BACKEND_MAX 16
static FtpBackend g_backends[FTP_BACKEND_MAX];
static int g_backend_count = 0;

int ftp_backend_add(const FtpServerCfg* cfg, const char* mount_base) {
    if (!cfg || !mount_base || g_backend_count >= FTP_BACKEND_MAX) return -1;
    FtpBackend* bk = &g_backends[g_backend_count];
    memset(bk, 0, sizeof *bk);
    bk->cfg = *cfg;
    snprintf(bk->prefix, sizeof bk->prefix, "%s/%s", mount_base, cfg->name);
    g_backend_count++;
    return 0;
}

void ftp_backend_clear(void) { g_backend_count = 0; }
int  ftp_backend_count(void) { return g_backend_count; }

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
    if (blen > 1 && base[blen - 1] == '/') {
        snprintf(out, sz, "%s%s", base, rel);
    } else if (blen == 1 && base[0] == '/') {
        snprintf(out, sz, "/%s", rel);
    } else {
        snprintf(out, sz, "%s/%s", base, rel);
    }
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
        char rparent[1024], rbase[256];
        char local_parent[1024], local_base[256];
        split_parent_base(rpath, rparent, sizeof rparent, local_base, sizeof local_base);
        (void)local_parent;
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
        /* 3. 目录判定用 CWD（LIST 对不存在路径可能返回空成功） */
        if (rc != 0) {
            if (ftp_cmd(&c, "CWD", rpath) == 250) {
                st->st_mode = S_IFDIR | 0755;
                st->st_nlink = 2;
                rc = 0;
                char rroot[1024];
                ftp_remote_path(bk, path, rroot, sizeof rroot);
                char rroot2[1024];
                ftp_remote_path(bk, "/", rroot2, sizeof rroot2);
                (void)rroot;
                ftp_cmd(&c, "CWD", rroot2);
            }
        }
    }
done:
    ftp_close(&c);
    return rc;
}

int ftp_backend_readdir(const char* path, NspDirEntry* entries, int max) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk) return -ENOENT;
    if (!entries || max <= 0) return 0;
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
    return out_n;
}

/* ================= 文件句柄（写模式：临时文件缓存 + release STOR） ================= */

typedef struct FtpBackendFile {
    FtpBackend* bk;
    char ftp_path[PATH_MAX];   /* 远程路径（release 上传目标） */
    int  tmp_fd;               /* 写模式临时文件 fd；读模式 -1 */
} FtpBackendFile;

static uint64_t ftp_h_to_u64(FtpBackendFile* f) { return (uint64_t)(uintptr_t)f; }
static FtpBackendFile* ftp_u64_to_h(uint64_t h) { return (FtpBackendFile*)(uintptr_t)h; }

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
        /* 读模式：验证存在，read 时直接 RETR */
        FtpConn c;
        if (ftp_conn_open(bk, &c) != 0) { free(f); return -EIO; }
        long long size;
        int rc = ftp_size(&c, f->ftp_path, &size);
        ftp_close(&c);
        if (rc != 0) { free(f); return -ENOENT; }
        *h = ftp_h_to_u64(f);
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
    unlink(tpath);   /* 句柄持有，路径立即释放 */
    *h = ftp_h_to_u64(f);
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
    return ftp_backend_open(path, O_WRONLY | O_CREAT | O_TRUNC, h);
}

int ftp_backend_read(uint64_t h, char* buf, size_t size, off_t off, size_t* got) {
    FtpBackendFile* f = ftp_u64_to_h(h);
    if (!f || !buf || !got) return -EINVAL;
    if (f->tmp_fd >= 0) {
        /* 读改写：从本地临时文件读 */
        ssize_t n = pread(f->tmp_fd, buf, size, off);
        if (n < 0) return -errno;
        *got = (size_t)n;
        return 0;
    }
    FtpConn c;
    if (ftp_conn_open(f->bk, &c) != 0) return -EIO;
    int rc = ftp_retr(&c, f->ftp_path, off, buf, size, got);
    ftp_close(&c);
    return rc == 0 ? 0 : -EIO;
}

int ftp_backend_write(uint64_t h, const char* buf, size_t size, off_t off, size_t* wrote) {
    FtpBackendFile* f = ftp_u64_to_h(h);
    if (!f || !buf || !wrote) return -EINVAL;
    if (f->tmp_fd < 0) return -EBADF;   /* 只读句柄不可写 */
    ssize_t n = pwrite(f->tmp_fd, buf, size, off);
    if (n < 0) return -errno;
    *wrote = (size_t)n;
    return 0;
}

int ftp_backend_release(uint64_t h) {
    FtpBackendFile* f = ftp_u64_to_h(h);
    if (!f) return -EINVAL;
    int rc = 0;
    if (f->tmp_fd >= 0) {
        /* 读临时文件 → STOR 全量上传 */
        off_t sz = lseek(f->tmp_fd, 0, SEEK_END);
        if (sz < 0) { close(f->tmp_fd); free(f); return -EIO; }
        lseek(f->tmp_fd, 0, SEEK_SET);
        char* data = sz > 0 ? malloc((size_t)sz) : NULL;
        if (sz > 0 && !data) { close(f->tmp_fd); free(f); return -ENOMEM; }
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
    }
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
    }
    ftp_close(&c);
    return rc;
}
