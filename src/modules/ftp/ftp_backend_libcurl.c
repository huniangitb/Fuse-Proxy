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
#include "nsp_module.h"
#include "nsp_util.h" /* nsp_set_thread_name（线程语义化命名） */
#include "ftp_backend.h"
#include <curl/curl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

/* ================= 配置 ================= */

#define FTP_BACKEND_MAX     16
#define FTP_HANDLE_MAX      256
#define FTP_STREAM_BUF_SIZE (64 * 1024)       /* 流式读缓冲 64KB */
#define FTP_RBUF_MIN        (64 * 1024)       /* 预取缓冲最小容量（随机读/初始） */
#define FTP_RBUF_MAX        (8 * 1024 * 1024) /* 预取缓冲最大容量（顺序读 8MB，减少 REST 往返） */
#define FTP_READ_POOL_MAX   4                 /* 每后端空闲读句柄池上限（S3：open 复用连接） */
#define FTP_UP_CHUNK        (1 * 1024 * 1024) /* 流式上传每块 1MB（读 tmp → STOR/APPE） */
#define FTP_UP_WINDOW       (8 * 1024 * 1024) /* 背压：未上传窗口上限（限 tmp 膨胀 + close 快速） */

/* ================= 后端（每个 FTP 服务器一个） ================= */
typedef struct FtpBackendFile FtpBackendFile; /* 前向声明：线程池槽引用 */

/* ================= stat 缓存（FUSE getattr 高频路径） =================
   目录/文件 stat 在 FTP 上需 2~3 次网络往返（SIZE+MDTM → LIST → 父 LIST），
   FUSE 对 getattr 极频繁；缓存命中（TTL 内）零网络直出。
   一致性：任何写操作（STOR 上传/DELE/MKD/RMD/RNFR/RNTO/TRUNCATE）成功后
   整表失效——写操作低频（相对 getattr），全清成本可忽略且杜绝
   "close 后立即 stat 命中旧值"的 close-to-open 窗口错误。 */
#define FTP_STAT_CACHE_SLOTS 16
#define FTP_STAT_CACHE_TTL   30
#define FTP_STAT_PATH_MAX    512 /* 超长虚拟路径不缓存（罕见） */

typedef struct {
    bool valid;
    time_t ts;
    char path[FTP_STAT_PATH_MAX];
    int err; /* 0=存在；-ENOENT=缓存不存在 */
    bool is_dir;
    off_t size;
    time_t mtime;
} FtpStatCacheEntry;

typedef struct FtpBackend {
    FtpServerCfg cfg;
    char prefix[PATH_MAX];   /* 虚拟前缀 = "/" + 段名 */
    CURL* curl;              /* 复用连接（libcurl easy handle） */
    pthread_mutex_t lock;    /* 连接锁 */
    pthread_mutex_t op_lock; /* 操作锁：串行化 curl_easy_perform（句柄非线程安全） */
    bool connected;          /* 连接是否有效 */
    time_t last_used;        /* 最后使用时间（保活） */
    int fail_count;          /* 连续失败计数（熔断：无网络自动静默） */
    bool silent;             /* 静默模式：熔断生效，操作快速失败、停止重试 */
    time_t silent_at;        /* 进入静默的时间（探活恢复节奏参考） */
    /* 目录 mtime TTL 缓存：FTP 无目录 MDTM，需父目录 LIST 解析（一次网络
       往返 + 全量列表）；FUSE 对目录 getattr 极频繁，缓存避免每次 stat
       都触发一次额外 LIST。路径匹配 + TTL 内直接返回缓存值 */
    char mtime_cache_path[PATH_MAX];
    time_t mtime_cache_val;
    time_t mtime_cache_ts;
    /* 完整 stat 缓存（文件/目录/不存在，TTL 内零网络直出）：
       getattr 命中免 SIZE+MDTM→LIST 的 2~3 次网络往返 */
    FtpStatCacheEntry stat_cache[FTP_STAT_CACHE_SLOTS];
    pthread_mutex_t stat_lock; /* stat 缓存锁（P2#3：多 FUSE 线程并发
                                    getattr/readdir 读写同一数组，无锁会撕裂
                                    条目 → 错误 st_size/陈旧 ENOENT） */
    /* S3 读句柄池：读模式 open 复用空闲句柄（FTP 控制连接保持，免每次
       open 新建连接 + USER/PASS 登录）；release 归还，池满才销毁。
       bk->curl 为共享控制句柄（op_lock 串行化），读句柄为每文件独立
       （下载线程专用），二者互不干扰 */
    CURL* read_pool[FTP_READ_POOL_MAX];
    int read_pool_count;
    pthread_mutex_t pool_lock; /* 读句柄池锁（仅 open/release/clear 触碰） */
    bool mutex_inited;         /* 每后端互斥锁是否已初始化（槽位复用：clear
                                    不再 destroy，add 仅首次 init，杜绝在途
                                    操作使用已销毁锁 → SIGSEGV） */
} FtpBackend;

/* 目录 mtime 缓存 TTL：目录时间变化不频繁，30s 内复用缓存足够 */
#define FTP_MTIME_CACHE_TTL 30

static unsigned ftp_stat_cache_hash(const char* path) {
    unsigned h = 5381;
    for (const unsigned char* p = (const unsigned char*)path; *p; p++) h = h * 33 + *p;
    return h;
}

/* 开放寻址槽位：同 path 命中或首个空槽；表满且无匹配返回 NULL */
static FtpStatCacheEntry* ftp_stat_cache_slot(FtpBackend* bk, const char* path) {
    unsigned start = ftp_stat_cache_hash(path) % FTP_STAT_CACHE_SLOTS;
    unsigned i = start;
    do {
        FtpStatCacheEntry* e = &bk->stat_cache[i];
        if (!e->valid || strcmp(e->path, path) == 0) return e;
        i = (i + 1) % FTP_STAT_CACHE_SLOTS;
    } while (i != start);
    return NULL;
}

static void ftp_stat_cache_clear(FtpBackend* bk) {
    pthread_mutex_lock(&bk->stat_lock);
    for (int i = 0; i < FTP_STAT_CACHE_SLOTS; i++) bk->stat_cache[i].valid = false;
    pthread_mutex_unlock(&bk->stat_lock);
}

static void ftp_stat_cache_fill(FtpBackend* bk, const char* path, int err, bool is_dir, off_t size,
                                time_t mtime) {
    size_t plen = strlen(path);
    if (plen == 0 || plen >= FTP_STAT_PATH_MAX) return; /* 超长不缓存 */
    pthread_mutex_lock(&bk->stat_lock);
    FtpStatCacheEntry* e = ftp_stat_cache_slot(bk, path);
    if (!e) {
        /* 表满无匹配：覆盖哈希起始槽（简单淘汰，写操作低频影响可忽略） */
        e = &bk->stat_cache[ftp_stat_cache_hash(path) % FTP_STAT_CACHE_SLOTS];
    }
    memcpy(e->path, path, plen + 1);
    e->valid = true;
    e->ts = time(NULL);
    e->err = err;
    e->is_dir = is_dir;
    e->size = size;
    e->mtime = mtime;
    pthread_mutex_unlock(&bk->stat_lock);
}

/* stat 缓存查找：命中返回 0 并填充输出；未命中返回 1（调用方走网络）。
   超长路径不查（与 fill 的拒绝条件一致）。 */
static int ftp_stat_cache_lookup(FtpBackend* bk, const char* path, int* err_out, bool* is_dir_out,
                                 off_t* size_out, time_t* mtime_out) {
    if (strlen(path) >= FTP_STAT_PATH_MAX) return 1;
    pthread_mutex_lock(&bk->stat_lock);
    FtpStatCacheEntry* e = ftp_stat_cache_slot(bk, path);
    int hit =
        (e && e->valid && strcmp(e->path, path) == 0 && time(NULL) - e->ts < FTP_STAT_CACHE_TTL);
    if (hit) {
        if (err_out) *err_out = e->err;
        if (is_dir_out) *is_dir_out = e->is_dir;
        if (size_out) *size_out = e->size;
        if (mtime_out) *mtime_out = e->mtime;
    }
    pthread_mutex_unlock(&bk->stat_lock);
    return hit ? 0 : 1;
}

/* 熔断阈值：连续失败达此值进入静默。8 次可在容忍正常偶发失败（连接抖动）
   的同时，无网络时（connect 立即失败）毫秒级进入静默——过低（如 3）会
   把正常瞬时失败误判为断网。 */
#define FTP_SILENT_THRESHOLD 8
static void mark_failure(FtpBackend* bk) {
    pthread_mutex_lock(&bk->lock);
    bk->fail_count++;
    if (bk->fail_count >= FTP_SILENT_THRESHOLD && !bk->silent) {
        bk->silent = true;
        bk->silent_at = time(NULL);
    }
    pthread_mutex_unlock(&bk->lock);
}
static void mark_success(FtpBackend* bk) {
    pthread_mutex_lock(&bk->lock);
    bk->fail_count = 0;
    bk->silent = false;
    pthread_mutex_unlock(&bk->lock);
}
/* 静默熔断探测节奏：silent 时快速失败；每 FTP_SILENT_PROBE_INTERVAL 秒
   放行一次真实连接尝试（探测）——网络恢复后由成功操作 mark_success 退出
   静默（自动恢复，延迟 ≤ 探测间隔）。返回 true=应快速失败（不发起连接）。 */
#define FTP_SILENT_PROBE_INTERVAL 2
static bool silent_fast_fail(FtpBackend* bk) {
    if (!bk->silent) return false;
    time_t now = time(NULL);
    if (now - bk->silent_at < FTP_SILENT_PROBE_INTERVAL) return true;
    bk->silent_at = now; /* 放行一次连接尝试（探测窗口） */
    return false;
}

static FtpBackend g_backends[FTP_BACKEND_MAX];
static int g_backend_count = 0;
/* 后端数组全局锁 + 热重载标志：
   - g_backend_glock：保护 g_backend_count 与 g_backends 数组的增删扫描
     （find/add/clear/retry_all），杜绝热重载清表与在途查找的数组撕裂
   - g_backend_clearing：ftp.conf 热重载（ftp_backend_clear）期间置位，
     find 立即拒绝新调用，保证 clear 之后不会有新操作触碰已清理的后端 */
static pthread_mutex_t g_backend_glock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic bool g_backend_clearing = false;

/* ================= 文件句柄（每个打开的文件一个） ================= */

typedef struct FtpBackendFile {
    FtpBackend* bk;
    char ftp_path[PATH_MAX]; /* 远程路径 */
    int tmp_fd;              /* 写模式本地缓存 fd */
    bool writing;            /* true=写模式（release 上传）；false=读模式 */
    bool uploaded;           /* 写模式数据已 STOR 上传（FLUSH 置位，release 补传判定） */
    size_t file_size;        /* 文件大小（用于读模式边界检查） */
    CURL* read_curl;         /* 读模式独立句柄（下载线程专用，不复用共享 bk->curl） */
    CURL* write_curl;        /* 写模式独立句柄（upload 专用，不复用共享 bk->curl，
                                避免并发 STOR 竞争共享句柄 → 消除 op_lock 串行） */
    /* 滑动读缓冲（下载线程持续填充，read 实时取，避免"等缓冲满一段才回传"） */
    char* rbuf;             /* 滑动缓冲 */
    off_t rbuf_off;         /* 缓冲中首个有效字节的文件偏移 */
    off_t rbuf_base;        /* rbuf[0] 对应的文件偏移（尾部追加/压缩用） */
    size_t rbuf_len;        /* 缓冲有效字节数 */
    size_t rbuf_cap;        /* 当前容量（64KB~8MB 自适应） */
    bool rbuf_eof;          /* 已读到文件尾 */
    pthread_mutex_t f_lock; /* 保护本文件缓冲状态（下载线程与 read 并发） */
    pthread_cond_t dl_cond; /* 下载线程：数据到达/空间释放通知 */
    pthread_t dl_tid;       /* 下载线程 */
    bool dl_started;        /* 下载线程已启动 */
    bool dl_stop;           /* 请求下载线程停止（release/跳变） */
    bool dl_restart;        /* 随机跳变：需要重启下载（清空缓冲重新拉） */
    bool dl_error;          /* 最近一次下载出错（open/read 超时兜底判断） */
    bool dl_released;       /* release 已置位：read 应立即退出，不再 cond_wait */
    int n_readers;          /* 在途 read 计数（f_lock 保护，release 等待归零） */
    off_t dl_grow_off;      /* 上次扩容时的 rbuf_off（验证读侧消费后才扩容） */
    /* ---- S4 流式上传（写模式）----
       写数据先落数据分区 tmp 文件（免 tmpfs ENOSPC），后台上传线程
       增量 STOR/APPE 推送（write 期间即上传，close 只等尾部追平）；
       背压限制未上传窗口，乱序改写已上传前缀时置 retransmit 转全量重传。 */
    pthread_t up_tid;       /* 上传线程 */
    pthread_cond_t up_cond; /* 上传线程：新数据/停止通知（f_lock 保护） */
    bool up_started;        /* 上传线程已启动 */
    bool up_stop;           /* flush/release 请求停止并追平 */
    bool up_error;          /* 流式上传出错（转全量重传兜底） */
    bool retransmit;        /* 乱序改写已上传前缀：全量重传 */
    bool up_first;          /* 下一块用 STOR（首块截断）而非 APPE（追加） */
    off_t up_upto;          /* 已流式上传字节数（f_lock 保护） */
    off_t file_end;         /* 已写最大偏移（写模式跟踪，f_lock 保护） */
} FtpBackendFile;

static FtpBackendFile* g_handles[FTP_HANDLE_MAX];
/* 活跃文件句柄计数：热重载 quiescence 门控用——框架在卸载/重载模块前
   查询（nsp_module_active_handles），确保没有任何应用仍持有本模块的
   open 文件时才执行热重载（避免热重载竞态崩溃） */
static _Atomic int g_active_handles = 0;
static pthread_mutex_t g_handles_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ================= 写缓冲回调 ================= */

struct WriteBuf {
    char* buf;
    size_t len;
    size_t cap;
    bool auto_grow;        /* 自动扩容（下载/LIST 用），false 时容量满即停 */
    pthread_mutex_t* lock; /* 非 NULL：写入/更新 len 时加锁（下载线程与 read 共享缓冲） */
    void* owner;           /* 非 NULL：滑动缓冲下载模式——实时写 owner->rbuf 尾部并广播 */
};

static size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    struct WriteBuf* wb = (struct WriteBuf*)userdata;
    size_t total = size * nmemb;
    size_t ret = 0;
    if (wb->lock) pthread_mutex_lock(wb->lock); /* 下载线程与 read 共享缓冲：写入加锁 */
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
            ret = 0; /* 缓冲满：返回 0 → CURLE_WRITE_ERROR 背压，等 read 消费后续传 */
            goto out;
        }
        size_t wpos = (size_t)(f->rbuf_off + (off_t)f->rbuf_len - f->rbuf_base);
        size_t remain = f->rbuf_cap - wpos;
        size_t n = total < remain ? total : remain;
        memcpy(f->rbuf + wpos, ptr, n);
        f->rbuf_len += n;
        pthread_cond_broadcast(&f->dl_cond); /* 数据到达：read 可实时取 */
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
    if (!cfg || !cfg->name[0]) return -1;
    pthread_mutex_lock(&g_backend_glock);
    if (g_backend_count >= FTP_BACKEND_MAX) {
        pthread_mutex_unlock(&g_backend_glock);
        return -1;
    }
    FtpBackend* bk = &g_backends[g_backend_count];
    memset(bk, 0, sizeof *bk);
    bk->cfg = *cfg;
    snprintf(bk->prefix, sizeof bk->prefix, "/%s", cfg->name);
    /* 互斥锁仅首次初始化：clear 不再 destroy，槽位复用不重复 init
       （对已初始化 mutex 重复 pthread_mutex_init 属未定义行为） */
    if (!bk->mutex_inited) {
        pthread_mutex_init(&bk->lock, NULL);
        pthread_mutex_init(&bk->op_lock, NULL);
        pthread_mutex_init(&bk->pool_lock, NULL);
        pthread_mutex_init(&bk->stat_lock, NULL);
        bk->mutex_inited = true;
    }
    bk->curl = curl_easy_init();
    g_backend_count++;
    pthread_mutex_unlock(&g_backend_glock);
    return 0;
}

void ftp_backend_clear(void) {
    atomic_store_explicit(&g_backend_clearing, true, memory_order_release);
    pthread_mutex_lock(&g_backend_glock);
    for (int i = 0; i < g_backend_count; i++) {
        FtpBackend* bk = &g_backends[i];
        /* 在途 curl 操作持 op_lock：先取锁再清理，串行化 curl_easy_cleanup，
           避免与在途 curl_easy_perform 竞态（句柄 UAF → SIGSEGV） */
        pthread_mutex_lock(&bk->op_lock);
        if (bk->curl) {
            curl_easy_cleanup(bk->curl);
            bk->curl = NULL;
        }
        /* 释放池中空闲读句柄（在途句柄由各自 release 归还/销毁） */
        for (int p = 0; p < bk->read_pool_count; p++) {
            if (bk->read_pool[p]) curl_easy_cleanup(bk->read_pool[p]);
        }
        bk->read_pool_count = 0;
        pthread_mutex_unlock(&bk->op_lock);
        /* 不再 pthread_mutex_destroy：槽位复用，互斥锁生命周期与模块一致，
           杜绝在途操作 pthread_mutex_lock 已销毁锁 → UB/SIGSEGV */
    }
    g_backend_count = 0;
    pthread_mutex_unlock(&g_backend_glock);
    atomic_store_explicit(&g_backend_clearing, false, memory_order_release);
}

int ftp_backend_count(void) {
    return g_backend_count;
}

/* 找 path 命中的后端 */
static FtpBackend* ftp_backend_find(const char* path) {
    if (atomic_load_explicit(&g_backend_clearing, memory_order_acquire)) return NULL;
    pthread_mutex_lock(&g_backend_glock);
    FtpBackend* r = NULL;
    for (int i = 0; i < g_backend_count; i++) {
        size_t plen = strlen(g_backends[i].prefix);
        if (strncmp(g_backends[i].prefix, path, plen) == 0 &&
            (path[plen] == '\0' || path[plen] == '/')) {
            r = &g_backends[i];
            break;
        }
    }
    pthread_mutex_unlock(&g_backend_glock);
    return r;
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
        if (!bk->curl) {
            pthread_mutex_unlock(&bk->lock);
            return -1;
        }
        // 持久选项：一次性设置，各操作函数负责设置自己的选项
        curl_easy_setopt(bk->curl, CURLOPT_USERNAME, bk->cfg.user);
        curl_easy_setopt(bk->curl, CURLOPT_PASSWORD, bk->cfg.pass);
        curl_easy_setopt(bk->curl, CURLOPT_CONNECTTIMEOUT, 30L);
        /* 弱网适配：不用 CURLOPT_TIMEOUT 总超时（慢速大文件传输会被误杀），
           改低速率判定——持续 30s 低于 1KB/s 才算卡死，数据在流动就不超时 */
        curl_easy_setopt(bk->curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);
        curl_easy_setopt(bk->curl, CURLOPT_LOW_SPEED_TIME, 30L);
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

/* 重置 curl 句柄（断开后重建）。
   count_failure=false 表示本次失败是正常业务结果（如文件/目录不存在，
   FTP 550 → CURLE_REMOTE_FILE_NOT_FOUND），不计入熔断——否则应用对缺失
   路径的存在性检查（os.path.exists / readdir 多个缺失条目）会连续计数，
   把健康连接误判为断网进入静默 */
static void reset_curl(FtpBackend* bk, bool count_failure) {
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
    /* 连接失败清理（各操作失败统一入口）：熔断计数，达阈值进入静默 */
    if (count_failure) mark_failure(bk);
}

/* 重置共享句柄的操作级选项（防跨操作残留：NOBODY 残留会吞掉 STOR 上传、
   WRITEDATA 残留指向已失效的栈缓冲）。各操作在 setopt 前调用，然后设置自己所需选项。 */
static void ftp_reset_opts_curl(CURL* c) {
    curl_easy_setopt(c, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(c, CURLOPT_UPLOAD, 0L);
    curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, NULL);
    curl_easy_setopt(c, CURLOPT_RESUME_FROM, 0L);
    curl_easy_setopt(c, CURLOPT_FILETIME, 0L);
    curl_easy_setopt(c, CURLOPT_HEADER, 0L);
    curl_easy_setopt(c, CURLOPT_POSTQUOTE, NULL);
    curl_easy_setopt(c, CURLOPT_QUOTE, NULL);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, NULL);
    curl_easy_setopt(c, CURLOPT_READFUNCTION, NULL);
    curl_easy_setopt(c, CURLOPT_READDATA, NULL);
}

static void ftp_reset_opts(FtpBackend* bk) {
    ftp_reset_opts_curl(bk->curl);
}

/* ================= 文件句柄管理 ================= */

static uint64_t ftp_handle_alloc(FtpBackendFile* f) {
    pthread_mutex_lock(&g_handles_mutex);
    for (int i = 1; i < FTP_HANDLE_MAX; i++) {
        if (!g_handles[i]) {
            g_handles[i] = f;
            atomic_fetch_add_explicit(&g_active_handles, 1, memory_order_release);
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
    if (g_handles[id]) {
        g_handles[id] = NULL;
        atomic_fetch_sub_explicit(&g_active_handles, 1, memory_order_acq_rel);
    }
    pthread_mutex_unlock(&g_handles_mutex);
}

/* 框架热重载 quiescence 查询：当前活跃 open 句柄数（0 = 无应用持有文件） */
int nsp_module_active_handles(void) {
    return atomic_load_explicit(&g_active_handles, memory_order_acquire);
}

/* ================= 后端操作 ================= */

int ftp_backend_match(const char* path) {
    return ftp_backend_find(path) != NULL ? 1 : 0;
}

/* 前置声明：读下载线程（定义在 ftp_backend_read 前，open 读模式启动） */
static void* ftp_dl_thread(void* arg);

/* 解析 Unix-style LIST 行的时间列并转 time_t：
   行格式：`drwxr-xr-x 1 user group 4096 Mon DD HH:MM name`（当年）
   或      `drwxr-xr-x 1 user group 4096 Mon DD  YYYY name`（往年）。
   FTP 协议规定服务器 LIST 时间为 GMT/UTC（vsftpd 默认 use_localtime=NO
   即输出 GMT），故用 timegm 按 UTC 解释，避免本地时区偏移。
   返回 0 成功、-1 解析失败（保持调用方默认 mtime）。 */
static int ftp_parse_list_time(const char* line, const char* nl, time_t* out) {
    /* 跳过前 5 列（权限/链接/属主/组/大小） */
    const char* p = line;
    int col = 0;
    while (p < nl && col < 5) {
        if (*p == ' ' || *p == '\t') {
            p++;
            continue;
        }
        col++;
        while (p < nl && *p != ' ' && *p != '\t') p++;
    }
    while (p < nl && (*p == ' ' || *p == '\t')) p++;
    if (p >= nl) return -1;
    /* 第 6 列：月份缩写 */
    char mon[8];
    int mi = 0;
    while (p < nl && *p != ' ' && *p != '\t' && mi < 7) mon[mi++] = *p++;
    mon[mi] = '\0';
    while (p < nl && (*p == ' ' || *p == '\t')) p++;
    if (mi == 0) return -1;
    /* 第 7 列：日 */
    int day = 0;
    while (p < nl && *p >= '0' && *p <= '9') {
        day = day * 10 + (*p - '0');
        p++;
    }
    while (p < nl && (*p == ' ' || *p == '\t')) p++;
    if (day <= 0 || day > 31) return -1;
    /* 第 8 列：HH:MM 或 YYYY */
    char tok[16];
    int ti = 0;
    while (p < nl && *p != ' ' && *p != '\t' && ti < 15) tok[ti++] = *p++;
    tok[ti] = '\0';
    if (ti == 0) return -1;
    struct tm tmv;
    memset(&tmv, 0, sizeof tmv);
    tmv.tm_mday = day;
    tmv.tm_isdst = -1;
    /* 月名映射（Jan..Dec） */
    static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    int found = -1;
    for (int i = 0; i < 12; i++) {
        if (strncasecmp(mon, months[i], 3) == 0) {
            found = i;
            break;
        }
    }
    if (found < 0) return -1;
    tmv.tm_mon = found;
    if (strchr(tok, ':') != NULL) {
        /* 当年时间 HH:MM */
        int hh = 0, mm = 0, i = 0;
        while (tok[i] >= '0' && tok[i] <= '9') {
            hh = hh * 10 + (tok[i] - '0');
            i++;
        }
        if (tok[i] != ':') return -1;
        i++;
        while (tok[i] >= '0' && tok[i] <= '9') {
            mm = mm * 10 + (tok[i] - '0');
            i++;
        }
        if (hh > 23 || mm > 59) return -1;
        tmv.tm_hour = hh;
        tmv.tm_min = mm;
        time_t now = time(NULL);
        struct tm* nt = localtime(&now);
        if (nt) tmv.tm_year = nt->tm_year;
    } else {
        /* 往年 YYYY */
        long yr = strtol(tok, NULL, 10);
        if (yr < 1970 || yr > 2100) return -1;
        tmv.tm_year = (int)yr - 1900;
    }
    time_t mt = timegm(&tmv);
    if (mt < 0) return -1;
    *out = mt;
    return 0;
}

/* 获取 FTP 目录自身 mtime：FTP 无目录 MDTM 标准命令（vsftpd 不支持），
   通过对父目录 LIST 并解析目标目录行的时间列实现。
   返回 0 成功、-1 失败（调用方保持默认 mtime）。 */
static int ftp_dir_mtime(FtpBackend* bk, const char* path, time_t* out) {
    if (!bk || !path || !out) return -1;
    /* TTL 缓存命中：同路径 + 缓存新鲜（30s）直接返回，避免每次 FUSE
       getattr 都触发一次父目录 LIST 网络往返 */
    pthread_mutex_lock(&bk->lock);
    if (bk->mtime_cache_path[0] && strcmp(bk->mtime_cache_path, path) == 0 &&
        time(NULL) - bk->mtime_cache_ts < FTP_MTIME_CACHE_TTL && bk->mtime_cache_val > 0) {
        *out = bk->mtime_cache_val;
        pthread_mutex_unlock(&bk->lock);
        return 0;
    }
    pthread_mutex_unlock(&bk->lock);
    if (ensure_curl(bk) != 0) return -EIO;
    /* 用 build_url 得到 FTP 端完整 URL（含 remote_dir 映射），
       从 URL 路径部分取父路径与目标目录名——不能按虚拟 path 切分，
       否则 remote_dir（如 /upload）映射后父路径会算错 */
    char url[2048];
    build_url(bk, path, url, sizeof url);
    char* pathpart = strchr(url + strlen("ftp://"), '/');
    if (!pathpart) return -1;
    /* 去尾斜杠（FTP 目录 URL 常以 / 结尾） */
    size_t pplen = strlen(pathpart);
    while (pplen > 1 && pathpart[pplen - 1] == '/') pathpart[--pplen] = '\0';
    if (pplen == 0) return -1; /* 根目录自身：无父级可 LIST 解析 */
    /* 目标目录名 = 最后一段（URL 路径部分经 curl_easy_escape 百分号编码，
       如空格/中文 → my%20dir / %E4%BA%91，须解码后才能与 LIST 响应的
       真实名匹配） */
    const char* slash = strrchr(pathpart, '/');
    const char* enc_target = slash ? slash + 1 : pathpart;
    if (!enc_target[0]) return -1;
    char target[PATH_MAX];
    char* dec = curl_easy_unescape(NULL, enc_target, 0, NULL);
    if (dec) {
        strncpy(target, dec, sizeof(target) - 1);
        target[sizeof(target) - 1] = '\0';
        curl_free(dec);
    } else {
        strncpy(target, enc_target, sizeof(target) - 1);
        target[sizeof(target) - 1] = '\0';
    }
    /* 父路径 = 去掉最后一段；根时父为空 → LIST "/" */
    char parent[2048];
    if (slash) {
        size_t plen = (size_t)(slash - pathpart);
        memcpy(parent, pathpart, plen);
        parent[plen] = '\0';
        if (plen == 0) strcpy(parent, "/");
    } else {
        strcpy(parent, "/");
    }
    /* 拼接父路径 FTP URL（同一 bk 的 host/port/remote_dir 已含在 pathpart 计算中，
       这里直接基于原 url 前缀重建） */
    size_t urllen = strlen(url);
    char list_url[2048];
    if (strcmp(parent, "/") == 0) {
        /* 父为 FTP 根：remote_dir 的父级 = remote_dir 去掉最后一段或空 */
        const char* rd = bk->cfg.remote_dir;
        size_t rdl = strlen(rd);
        while (rdl > 1 && rd[rdl - 1] == '/') rdl--;
        const char* rdslash = NULL;
        for (size_t i = 0; i < rdl; i++)
            if (rd[i] == '/') rdslash = rd + i;
        if (rdslash && rdslash > rd) {
            size_t plen2 = (size_t)(rdslash - rd);
            snprintf(list_url, sizeof list_url, "ftp://%s:%d%.*s/", bk->cfg.host, bk->cfg.port,
                     (int)plen2, rd);
        } else {
            snprintf(list_url, sizeof list_url, "ftp://%s:%d/", bk->cfg.host, bk->cfg.port);
        }
    } else {
        /* 父路径在 remote_dir 之下：url 前缀（host:port）+ parent */
        snprintf(list_url, sizeof list_url, "%.*s%s/", (int)(urllen - pplen), url, parent);
    }

    struct WriteBuf wb = {0};
    /* 只需匹配目标目录行：限制 LIST 缓冲容量（256KB 固定、不自动扩容），
       避免大父目录全量列表导致内存随条目数无界增长 */
    wb.cap = 256 * 1024;
    wb.buf = malloc(wb.cap);
    if (!wb.buf) return -1;
    wb.auto_grow = false;
    pthread_mutex_lock(&bk->op_lock);
    ftp_reset_opts(bk);
    curl_easy_setopt(bk->curl, CURLOPT_URL, list_url);
    curl_easy_setopt(bk->curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(bk->curl, CURLOPT_CUSTOMREQUEST, NULL);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(bk->curl, CURLOPT_WRITEDATA, &wb);
    CURLcode res = curl_easy_perform(bk->curl);
    pthread_mutex_unlock(&bk->op_lock);
    if (res != CURLE_OK && res != CURLE_WRITE_ERROR) {
        free(wb.buf);
        return -1;
    }

    /* 逐行匹配目标目录名，取时间列 */
    int rc = -1;
    char* line = wb.buf;
    char* end = wb.buf + wb.len;
    while (line < end) {
        while (line < end && (*line == '\n' || *line == '\r')) line++;
        if (line >= end) break;
        char* nl = memchr(line, '\n', end - line);
        if (!nl) nl = end;
        /* 跳过前 8 列取文件名（与 readdir 解析一致） */
        char* p = line;
        int col = 0;
        while (p < nl && col < 8) {
            if (*p == ' ' || *p == '\t') {
                p++;
                continue;
            }
            col++;
            while (p < nl && *p != ' ' && *p != '\t') p++;
        }
        while (p < nl && (*p == ' ' || *p == '\t')) p++;
        char* nm = p;
        char* ne = nl;
        if (ne > nm && *(ne - 1) == '\r') ne--;
        size_t nlen = (size_t)(ne - nm);
        if (nlen == strlen(target) && memcmp(nm, target, nlen) == 0) {
            if (ftp_parse_list_time(line, nl, out) == 0) {
                rc = 0;
                /* 写入 TTL 缓存：后续 getattr 直接命中，免父目录 LIST */
                pthread_mutex_lock(&bk->lock);
                strncpy(bk->mtime_cache_path, path, sizeof(bk->mtime_cache_path) - 1);
                bk->mtime_cache_path[sizeof(bk->mtime_cache_path) - 1] = '\0';
                bk->mtime_cache_val = *out;
                bk->mtime_cache_ts = time(NULL);
                pthread_mutex_unlock(&bk->lock);
            }
            break;
        }
        line = nl + 1;
    }
    free(wb.buf);
    return rc;
}

int ftp_backend_getattr(const char* path, struct stat* st) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk) return -ENOENT;
    /* stat 缓存优先：TTL 内零网络直出（含"不存在"负缓存，exists 检查高频；
       写操作成功后整表失效，故不会命中写后旧值）。命中不发起网络，
       静默熔断/弱网下已缓存路径仍可快速响应 */
    int c_err = 0;
    bool c_dir = false;
    off_t c_size = 0;
    time_t c_mtime = 0;
    if (ftp_stat_cache_lookup(bk, path, &c_err, &c_dir, &c_size, &c_mtime) == 0) {
        if (c_err != 0) return c_err;
        memset(st, 0, sizeof *st);
        st->st_mode = c_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644);
        st->st_size = c_size;
        st->st_nlink = c_dir ? 2 : 1;
        st->st_mtime = c_mtime;
        return 0;
    }
    if (silent_fast_fail(bk)) return -ENOENT; /* 静默熔断：快速失败（每 2s 放行一次探测） */
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
        ftp_stat_cache_fill(bk, path, 0, false, (off_t)cl, ft >= 0 ? (time_t)ft : 0);
        mark_success(bk); /* 操作成功：清零熔断计数 */
        return 0;
    }
    free(wb.buf);

    // 作为目录（LIST）- URL 末尾加 / 即可触发 libcurl 自动 LIST
    char dir_url[2048];
    size_t ulen = strlen(url);
    if (ulen > 0 && url[ulen - 1] != '/')
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
        /* 同步服务器目录时间：FTP 无目录 MDTM 标准命令（vsftpd 不支持），
           通过父目录 LIST 解析目标目录行的时间列；解析失败保持默认 */
        time_t dmtime = 0;
        if (ftp_dir_mtime(bk, path, &dmtime) == 0 && dmtime > 0) st->st_mtime = dmtime;
        free(dir_wb.buf);
        ftp_stat_cache_fill(bk, path, 0, true, 0, st->st_mtime);
        return 0;
    }
    free(dir_wb.buf);

    // 都不是
    /* 文件与目录均不存在（FTP 550 → CURLE_REMOTE_FILE_NOT_FOUND）是正常
       业务结果，不计入熔断；连接/传输类错误才累计（避免 exists 检查
       连续命中缺失路径把健康连接误判为断网） */
    reset_curl(bk, res != CURLE_REMOTE_FILE_NOT_FOUND);
    /* 负缓存：exists 检查（os.path.exists）高频，TTL 内免 2~3 次网络往返；
       写操作成功后整表失效，不会命中写后旧 ENOENT */
    if (res == CURLE_REMOTE_FILE_NOT_FOUND) ftp_stat_cache_fill(bk, path, -ENOENT, false, 0, 0);
    return -ENOENT;
}

int ftp_backend_readdir(const char* path, NspDirEntry* entries, int max) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk) return -ENOENT;
    if (!entries || max <= 0) return 0;
    if (silent_fast_fail(bk)) return -ENOENT; /* 静默熔断：快速失败（每 2s 放行一次探测） */

    if (ensure_curl(bk) != 0) return -EIO;

    char url[2048], dir_url[2048];
    build_url(bk, path, url, sizeof url);
    size_t ulen = strlen(url);
    if (ulen > 0 && url[ulen - 1] != '/')
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
        /* 目录不存在（FTP 550 → CURLE_REMOTE_FILE_NOT_FOUND）是正常业务
           结果，不计入熔断；连接/传输类错误才累计 */
        reset_curl(bk, res != CURLE_REMOTE_FILE_NOT_FOUND);
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
        // 简单解析：跳过日期/权限字段，取最后一列作为文件名；
        // 同时捕获第 5 列（size）用于子项 stat 缓存预取
        //（优化 3：readdir 后 getattr 子项零网络；时间列由
        //  ftp_parse_list_time 对整行解析，此处不重复捕获）
        char* name = NULL;
        char* p = line;
        char size_str[32] = {0};
        // 跳过类似 "drwxr-xr-x 1 user group 0 Jan 1 00:00 name" 的前 8 列
        int col = 0;
        while (p < nl && col < 8) {
            if (*p == ' ' || *p == '\t') {
                p++;
                continue;
            }
            col++;
            char* cstart = p;
            while (p < nl && *p != ' ' && *p != '\t') p++;
            size_t clen = (size_t)(p - cstart);
            if (col == 5) {
                size_t n = clen < sizeof size_str - 1 ? clen : sizeof size_str - 1;
                memcpy(size_str, cstart, n);
                size_str[n] = '\0';
            }
        }
        // 跳过空格
        while (p < nl && (*p == ' ' || *p == '\t')) p++;
        // 剩余部分为文件名
        if (p < nl) {
            name = p;
            // 去掉末尾的 \r
            char* e = nl;
            if (e > name && *(e - 1) == '\r') e--;
            size_t nlen = e - name;
            if (nlen > 0 && name[0] != '.') {
                /* 拷贝文件名并显式补 NUL：strncpy 在 nlen < 容量时不补 NUL，
                   会残留栈垃圾字节导致条目名拼接/乱码（根目录短名最明显） */
                size_t cap = sizeof(entries[out_n].name) - 1;
                size_t cp = nlen < cap ? nlen : cap;
                memcpy(entries[out_n].name, name, cp);
                entries[out_n].name[cp] = '\0';
                entries[out_n].is_dir = (line[0] == 'd');
                /* 优化 3：预取填充子项 stat 缓存（getattr 命中免 SIZE+MDTM→LIST
                   网络往返）。key 为虚拟路径（path + "/" + name），与
                   getattr 查询一致；mtime 由整行解析，失败兜底 0 */
                size_t plen = strlen(path);
                if (plen > 0 && plen + 1 + cp < FTP_STAT_PATH_MAX) {
                    char child[FTP_STAT_PATH_MAX];
                    memcpy(child, path, plen);
                    child[plen] = '/';
                    memcpy(child + plen + 1, entries[out_n].name, cp + 1);
                    time_t mt = 0;
                    if (ftp_parse_list_time(line, nl, &mt) != 0) mt = 0;
                    ftp_stat_cache_fill(bk, child, 0, entries[out_n].is_dir,
                                        size_str[0] ? (off_t)atoll(size_str) : 0, mt);
                }
                out_n++;
            }
        }
        line = nl + 1;
    }
    free(wb.buf);
    mark_success(bk); /* 操作成功：清零熔断计数 */
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
    /* 弱网适配：不用 CURLOPT_TIMEOUT 总超时（慢速大文件传输会被误杀），
       改低速率判定——持续 30s 低于 1KB/s 才算卡死，数据在流动就不超时 */
    curl_easy_setopt(rc, CURLOPT_LOW_SPEED_LIMIT, 1024L);
    curl_easy_setopt(rc, CURLOPT_LOW_SPEED_TIME, 30L);
    curl_easy_setopt(rc, CURLOPT_FTP_RESPONSE_TIMEOUT, 30L);
    curl_easy_setopt(rc, CURLOPT_FTP_SKIP_PASV_IP, 1L);
    curl_easy_setopt(rc, CURLOPT_USE_SSL, CURLUSESSL_NONE);
    curl_easy_setopt(rc, CURLOPT_FOLLOWLOCATION, 0L);
    return rc;
}

/* S3 读句柄池：获取读模式句柄——优先复用池中空闲句柄（libcurl 句柄保留
   FTP 控制连接，open-close 循环免重建连接 + USER/PASS 登录），池空才新建。
   返回的句柄已重置操作选项（下载线程 perform 前也会自设），可直接使用。 */
static CURL* ftp_read_curl_acquire(FtpBackend* bk) {
    pthread_mutex_lock(&bk->pool_lock);
    if (bk->read_pool_count > 0) {
        CURL* c = bk->read_pool[--bk->read_pool_count];
        pthread_mutex_unlock(&bk->pool_lock);
        ftp_reset_opts_curl(c); /* 清残留操作选项，防 RANGE/WRITEDATA 泄漏 */
        return c;
    }
    pthread_mutex_unlock(&bk->pool_lock);
    return ftp_read_curl_new(bk);
}

/* S3 读句柄池：归还空闲句柄（release/错误路径调用）。句柄须已无在途
   perform（下载线程已 join/未启动）。池满则直接销毁。 */
static void ftp_read_curl_release(FtpBackend* bk, CURL* c) {
    if (!c) return;
    ftp_reset_opts_curl(c); /* 清残留，防下次 acquire 拿到脏选项 */
    pthread_mutex_lock(&bk->pool_lock);
    if (bk->read_pool_count < FTP_READ_POOL_MAX) {
        bk->read_pool[bk->read_pool_count++] = c;
        pthread_mutex_unlock(&bk->pool_lock);
        return;
    }
    pthread_mutex_unlock(&bk->pool_lock);
    curl_easy_cleanup(c);
}

int ftp_backend_open(const char* path, int flags, uint64_t* h) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk || !h) return -ENOENT;
    if (silent_fast_fail(bk)) return -ENOENT; /* 静默熔断：快速失败（每 2s 放行一次探测） */

    if (ensure_curl(bk) != 0) return -EIO;

    FtpBackendFile* f = calloc(1, sizeof *f);
    if (!f) return -ENOMEM;
    f->bk = bk;
    f->tmp_fd = -1;
    pthread_mutex_init(&f->f_lock, NULL); /* 保护读缓冲状态 */
    build_url(bk, path, f->ftp_path, sizeof f->ftp_path);

    int accmode = flags & O_ACCMODE;
    bool writing = (accmode != O_RDONLY || (flags & O_CREAT) || (flags & O_TRUNC));

    if (writing) {
        // 写模式：数据分区 tmp 文件（S4 流式上传：边写边传，release 追平尾部）
        // tmpfs（/tmp）容量小，大文件（视频）会 ENOSPC——mkstemp 优先走
        // TMPDIR（Android 常为数据分区 /data/local/tmp），失败回退 /tmp
        char tpath[PATH_MAX];
        const char* td = getenv("TMPDIR");
        if (td && td[0] && strlen(td) + 32 < sizeof tpath)
            snprintf(tpath, sizeof tpath, "%s/nsp_ftp_XXXXXX", td);
        else
            snprintf(tpath, sizeof tpath, "/tmp/nsp_ftp_XXXXXX");
        int tfd = mkstemp(tpath);
        if (tfd < 0 && strncmp(tpath, "/tmp/", 5) != 0) {
            /* TMPDIR 不可写回退 /tmp */
            snprintf(tpath, sizeof tpath, "/tmp/nsp_ftp_XXXXXX");
            tfd = mkstemp(tpath);
        }
        if (tfd < 0) {
            pthread_mutex_destroy(&f->f_lock);
            free(f);
            return -EIO;
        }
        unlink(tpath);
        f->tmp_fd = tfd;
        f->writing = true;
        f->up_first = true;
        pthread_cond_init(&f->up_cond, NULL);
        *h = ftp_handle_alloc(f);
        if (*h == 0) {
            close(tfd);
            pthread_cond_destroy(&f->up_cond);
            pthread_mutex_destroy(&f->f_lock);
            free(f);
            return -EIO;
        }
        mark_success(bk); /* 连接建立成功：清零熔断计数 */
        return 0;
    }

    // 读模式：滑动缓冲 + 下载线程——FTP 数据持续拉取写入缓冲并实时广播，
    // read 拿到覆盖数据立即回传（不等缓冲满）；缓冲仅作慢速消费端背压粘合
    struct stat st;
    int grc = ftp_backend_getattr(path, &st);
    /* 写后立即读：FLUSH 的 fuse_invalidate_path 是异步通知，close() 返回后
       立即 open 可能短暂命中内核 negative 缓存（并发多 FLUSH 时处理延迟），
       导致刚上传成功的文件 ENOENT——短重试覆盖该 close-to-open 窗口；
       文件真不存在时 2×10ms 后仍 ENOENT，正确性不变（重试降频：原 5×20ms
       =100ms 同步阻塞 FUSE open 线程，对缺失路径的存在性检查是热路径） */
    if (grc != 0 || !S_ISREG(st.st_mode)) {
        for (int retry = 0; retry < 2; retry++) {
            usleep(10000);
            grc = ftp_backend_getattr(path, &st);
            if (grc == 0 && S_ISREG(st.st_mode)) break;
        }
    }
    if (grc != 0 || !S_ISREG(st.st_mode)) {
        pthread_mutex_destroy(&f->f_lock);
        free(f);
        return -ENOENT;
    }
    f->file_size = (size_t)st.st_size;
    f->writing = false;

    // 每文件独立读句柄（下载线程专用，不复用共享 bk->curl，避免与 STOR 上传并发竞争）
    CURL* rc = ftp_read_curl_acquire(bk); /* S3：优先复用池中句柄（连接保持） */
    if (!rc) {
        pthread_mutex_destroy(&f->f_lock);
        free(f);
        return -EIO;
    }
    f->read_curl = rc;

    // 初始化滑动缓冲并启动下载线程
    f->rbuf_cap = FTP_RBUF_MIN;
    f->rbuf = malloc(f->rbuf_cap);
    if (!f->rbuf) {
        ftp_read_curl_release(bk, f->read_curl);
        pthread_mutex_destroy(&f->f_lock);
        free(f);
        return -ENOMEM;
    }
    pthread_cond_init(&f->dl_cond, NULL);
    f->dl_stop = false;
    f->dl_restart = false;
    f->dl_error = false;
    if (pthread_create(&f->dl_tid, NULL, ftp_dl_thread, f) != 0) {
        ftp_read_curl_release(bk, f->read_curl);
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
        ftp_read_curl_release(bk, rc);
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
    curl_easy_setopt(bk->curl, CURLOPT_UPLOAD, 0L); /* 锁内清理，防并发竞争句柄 */
    pthread_mutex_unlock(&bk->op_lock);
    if (res != CURLE_OK) {
        reset_curl(bk, true); /* 传输失败：计入熔断 */
        return -EIO;
    }
    ftp_stat_cache_clear(bk); /* 空文件已创建：整表失效 */
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
    nsp_set_thread_name("nsp_ftpdl");
    int dl_backoff_ms = 500; /* 弱网适配：错误退避指数增长（500ms→8s 封顶） */
    while (!f->dl_stop) {
        pthread_mutex_lock(&f->f_lock);
        /* 等待：未停止 且 未 restart，且（已 EOF 或 缓冲满不可扩）时挂起。
           EOF 后线程必须存活——read 可能随机跳变回读（restart 唤醒），
           若线程 break 退出则 read 永久 cond_wait（死锁根因） */
        while (!f->dl_stop && !f->dl_restart &&
               (f->rbuf_eof || (f->rbuf_len >= f->rbuf_cap && f->rbuf_cap >= FTP_RBUF_MAX)))
            pthread_cond_wait(&f->dl_cond, &f->f_lock);
        if (f->dl_stop) {
            pthread_mutex_unlock(&f->f_lock);
            break;
        }
        if (f->dl_restart) {
            /* 随机跳变：清空缓冲，从 read 设置的新 rbuf_off 重新拉 */
            f->dl_restart = false;
            f->rbuf_len = 0;
            f->rbuf_base = f->rbuf_off;
            f->rbuf_eof = false;
            f->dl_error = false;
            dl_backoff_ms = 500; /* 恢复信号：重置退避 */
        }
        if (f->rbuf_eof) {
            /* EOF 且无 restart：回到等待（release 置 dl_stop 或 read 置 restart 唤醒） */
            pthread_mutex_unlock(&f->f_lock);
            continue;
        }
        if (!f->read_curl) {
            pthread_mutex_unlock(&f->f_lock);
            break;
        }
        /* 顺序读扩容：仅当读侧已实际消费（rbuf_off 前进）才扩容翻倍至 8MB。
           不验证消费会让 open 后从不读取的文件也急切下载至 8MB
           （慢链路网络流量/延迟回归）；dl_grow_off 记录上次扩容时的消费位置 */
        if (f->rbuf_len >= f->rbuf_cap && f->rbuf_cap < FTP_RBUF_MAX &&
            f->rbuf_off > f->dl_grow_off) {
            size_t nc = f->rbuf_cap * 2;
            f->rbuf_cap = nc > FTP_RBUF_MAX ? FTP_RBUF_MAX : nc;
            char* nb = realloc(f->rbuf, f->rbuf_cap);
            if (nb)
                f->rbuf = nb;
            else
                f->rbuf_cap = FTP_RBUF_MIN; /* 分配失败：回退最小容量 */
            f->dl_grow_off = f->rbuf_off;
        }
        off_t dl_off = f->rbuf_off + (off_t)f->rbuf_len;
        struct WriteBuf wb = {0};
        wb.owner = f; /* 滑动缓冲模式：write_cb 加锁写 rbuf 尾部并广播 */
        wb.lock = &f->f_lock;
        pthread_mutex_unlock(&f->f_lock);

        if (silent_fast_fail(f->bk)) {
            /* 静默模式（无网络熔断）：空转等待，每 2s 放行一次连接探测，
               网络恢复后 perform 成功 → mark_success 退出静默继续下载 */
            usleep(500000);
            continue;
        }

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
            f->rbuf_eof = true;  /* 读到文件尾 */
            mark_success(f->bk); /* 连接成功：清零熔断计数（网络恢复退出静默） */
        } else if (res != CURLE_WRITE_ERROR) {
            /* 真错误：保留句柄（curl 自动重连），指数退避后重试——弱网下
               瞬时失败（断连/超时）可能持续，固定 100ms 会忙循环且网络
               未恢复时反复失败；500ms 起 ×2 封顶 8s，恢复后 restart 重置。
               open/read 的等待由 cond_timedwait 超时兜底 */
            f->dl_error = true;
            pthread_cond_broadcast(&f->dl_cond);
            pthread_mutex_unlock(&f->f_lock);
            usleep((useconds_t)dl_backoff_ms * 1000);
            if (dl_backoff_ms < 8000) dl_backoff_ms *= 2;
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
    if (size == 0) {
        *got = 0;
        return 0;
    }

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
        if (f->rbuf_len > 0 && cur >= f->rbuf_off && cur < f->rbuf_off + (off_t)f->rbuf_len) {
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
            pthread_cond_broadcast(&f->dl_cond); /* 通知下载线程有空间续传 */
            if (done == size || f->rbuf_eof) {
                *got = done;
                goto out;
            }
            continue; /* 数据未满：继续等下载线程填充 */
        }
        /* 随机跳变（重启下载）判定：
           - off 在缓冲范围之外（回退或前跳）
           - off 恰好等于缓冲尾 且 缓冲已满（无空间续传，只能从 off 重新拉）
           off == rbuf_off+rbuf_len 且缓冲未满 → 等待续传（下载线程有空间填充），
           绝不置 restart——否则 rbuf_len=0 初始态（off==rbuf_off）恒触发 restart，
           下载线程下载前被 write_cb 的 dl_restart 检查中止 → 无限互相打断死锁 */
        if (cur < f->rbuf_off || cur > f->rbuf_off + (off_t)f->rbuf_len ||
            (cur == f->rbuf_off + (off_t)f->rbuf_len && f->rbuf_len >= f->rbuf_cap)) {
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
    if (f->dl_released) pthread_cond_broadcast(&f->dl_cond); /* 通知 release 等待循环可继续 */
    pthread_mutex_unlock(&f->f_lock);
    return rc;
}

/* S4 流式上传前向声明（实现位于 ftp_backend_upload 之前，write 先于其调用） */
static int ftp_stream_chunk(FtpBackendFile* f, const char* data, size_t len, bool append);
static void* ftp_up_thread(void* arg);

int ftp_backend_write(uint64_t h, const char* buf, size_t size, off_t off, size_t* wrote) {
    FtpBackendFile* f = ftp_handle_get(h);
    if (!f || !buf || !wrote) return -EINVAL;
    if (f->tmp_fd < 0) return -EBADF;
    pthread_mutex_lock(&f->f_lock);
    /* S4 乱序检测：改写已流式上传的前缀（off < up_upto）→ 已传字节作废，
       流式无法覆盖，置 retransmit 转全量重传（flush STOR 覆盖）；
       off >= up_upto 的随机写仍由 tmp_fd 兜底（未上传区域可继续 APPE） */
    if (off < f->up_upto) f->retransmit = true;
    /* 懒启动上传线程（首个写才建线程；失败退化为全量上传兜底） */
    if (!f->up_started && !f->retransmit && !f->up_stop) {
        if (pthread_create(&f->up_tid, NULL, ftp_up_thread, f) == 0) f->up_started = true;
    }
    pthread_mutex_unlock(&f->f_lock);

    ssize_t n = pwrite(f->tmp_fd, buf, size, off);
    if (n < 0) return -errno;
    *wrote = (size_t)n;

    pthread_mutex_lock(&f->f_lock);
    off_t end = off + (off_t)n;
    if (end > f->file_end) f->file_end = end;
    pthread_cond_broadcast(&f->up_cond); /* 唤醒上传线程推新数据 */
    /* 背压：顺序写快于网络时，未上传窗口超过 FTP_UP_WINDOW 则等待上传
       线程追平（限 tmp 膨胀 + close 时尾部小）；retransmit/error 不等待
       （走全量重传兜底，等也无意义） */
    if (f->up_started && !f->retransmit && !f->up_error) {
        while (f->file_end - f->up_upto > (off_t)FTP_UP_WINDOW && !f->retransmit && !f->up_error)
            pthread_cond_wait(&f->up_cond, &f->f_lock);
    }
    pthread_mutex_unlock(&f->f_lock);
    return 0;
}

/* ============ S4 流式上传（写模式） ============
   写数据先落数据分区 tmp 文件（mkstemp 走 TMPDIR，免 tmpfs ENOSPC），
   后台上传线程把已写内容增量推送（首块 STOR 截断、后续 APPE 追加），
   write 期间即上传——close/FLUSH 只等尾部追平，不再全量同步 STOR。
   背压：write 侧未上传窗口超过 FTP_UP_WINDOW 时阻塞等待，限 tmp 膨胀。
   乱序（改写已上传前缀 off < up_upto）置 retransmit：流式无法覆盖已传
   字节，转全量重传（ftp_backend_upload STOR 覆盖）；FUSE 顺序写（视频/
   大文件）为常态，乱序（sqlite 随机页/原地改写）为少数回退路径。 */

/* 单块上传：append=false 用 STOR（首块，截断创建），true 用 APPE（追加）。
   独立 write_curl 句柄（不复用共享 bk->curl，避免并发 STOR 竞争 op_lock）；
   失败指数退避重试（吸收网络瞬态），仍失败置 up_error 转全量重传兜底。
   调用方不持 f_lock（curl perform 可能长时间阻塞）。 */
static int ftp_stream_chunk(FtpBackendFile* f, const char* data, size_t len, bool append) {
    if (!f->write_curl) f->write_curl = ftp_read_curl_new(f->bk);
    if (!f->write_curl) return -EIO;
    struct ReadBuf rb = {data, len, 0};
    CURLcode res = CURLE_OK;
    int backoff_ms = 200;
    for (int attempt = 0; attempt < 5; attempt++) {
        if (attempt > 0) {
            usleep((useconds_t)backoff_ms * 1000);
            if (backoff_ms < 3200) backoff_ms *= 2;
        }
        rb.pos = 0;
        ftp_reset_opts_curl(f->write_curl);
        curl_easy_setopt(f->write_curl, CURLOPT_URL, f->ftp_path);
        curl_easy_setopt(f->write_curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(f->write_curl, CURLOPT_APPEND, append ? 1L : 0L);
        curl_easy_setopt(f->write_curl, CURLOPT_INFILESIZE, (long)len);
        curl_easy_setopt(f->write_curl, CURLOPT_READFUNCTION, read_cb);
        curl_easy_setopt(f->write_curl, CURLOPT_READDATA, &rb);
        res = curl_easy_perform(f->write_curl);
        curl_easy_setopt(f->write_curl, CURLOPT_UPLOAD, 0L);
        curl_easy_setopt(f->write_curl, CURLOPT_APPEND, 0L);
        if (res == CURLE_OK) return 0;
        if (f->bk->silent) break; /* 静默模式：无网络空转，不再重试 */
    }
    curl_easy_cleanup(f->write_curl); /* 失败句柄可能已半损坏，重建 */
    f->write_curl = NULL;
    mark_failure(f->bk);
    return -EIO;
}

/* 上传线程：追平已写内容（tmp_fd 读 → STOR/APPE 推送到 up_upto == file_end）。
   up_stop 置位后追平剩余尾部即退出（flush/release 等待 join）；
   retransmit/up_error 时立即退出（flush 转全量重传兜底）。 */
static void* ftp_up_thread(void* arg) {
    FtpBackendFile* f = arg;
    nsp_set_thread_name("nsp_ftpup");
    char* buf = malloc(FTP_UP_CHUNK);
    if (!buf) {
        pthread_mutex_lock(&f->f_lock);
        f->up_error = true;
        pthread_cond_broadcast(&f->up_cond);
        pthread_mutex_unlock(&f->f_lock);
        return NULL;
    }
    bool first = true; /* 首块 STOR（截断），后续 APPE（追加） */
    for (;;) {
        pthread_mutex_lock(&f->f_lock);
        /* 等待：有未上传数据（up_upto < file_end）或停止/回退信号 */
        while (!f->up_stop && !f->retransmit && !f->up_error && f->up_upto >= f->file_end)
            pthread_cond_wait(&f->up_cond, &f->f_lock);
        if (f->retransmit || f->up_error) {
            pthread_mutex_unlock(&f->f_lock);
            break;
        }
        if (f->up_upto >= f->file_end) {
            pthread_mutex_unlock(&f->f_lock);
            break;
        } /* 追平（含 up_stop） */
        off_t off = f->up_upto;
        size_t want = (size_t)(f->file_end - off);
        if (want > FTP_UP_CHUNK) want = FTP_UP_CHUNK;
        pthread_mutex_unlock(&f->f_lock);

        ssize_t got = pread(f->tmp_fd, buf, want, off);
        if (got <= 0) {
            pthread_mutex_lock(&f->f_lock);
            f->up_error = true;
            pthread_cond_broadcast(&f->up_cond);
            pthread_mutex_unlock(&f->f_lock);
            break;
        }
        if (ftp_stream_chunk(f, buf, (size_t)got, !first) != 0) {
            pthread_mutex_lock(&f->f_lock);
            f->up_error = true;
            pthread_cond_broadcast(&f->up_cond);
            pthread_mutex_unlock(&f->f_lock);
            break;
        }
        first = false;
        pthread_mutex_lock(&f->f_lock);
        f->up_upto = off + (off_t)got;
        pthread_cond_broadcast(&f->up_cond); /* 背压解除 / flush 追平通知 */
        pthread_mutex_unlock(&f->f_lock);
    }
    free(buf);
    return NULL;
}

/* 写模式上传：读本地临时文件 → STOR 全量上传（带并发重试）。
   成功置 uploaded；FLUSH（同步收尾）与 RELEASE（防御补传）共用。
   f_lock 互斥：FLUSH 与延迟 RELEASE 可能并发进入（两阶段拆除后句柄
   存活到 RELEASE），无锁会让两个线程同时 lseek/read/close(tmp_fd)
   → 上传失败（写模式场景 f_lock 无其他竞争，read 只用于读模式）。
   返回 0 成功，负值 errno 风格。 */
static int ftp_backend_upload(FtpBackendFile* f) {
    pthread_mutex_lock(&f->f_lock);
    if (!f->writing || f->uploaded) {
        pthread_mutex_unlock(&f->f_lock);
        return 0;
    }
    off_t sz = lseek(f->tmp_fd, 0, SEEK_END);
    if (sz < 0) {
        pthread_mutex_unlock(&f->f_lock);
        return -EIO;
    }
    lseek(f->tmp_fd, 0, SEEK_SET);

    char* data = sz > 0 ? malloc((size_t)sz) : NULL;
    if (sz > 0 && !data) {
        pthread_mutex_unlock(&f->f_lock);
        return -ENOMEM;
    }

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

    int rc = 0;
    /* 独立写句柄（选项同读句柄：用户名/密码/弱网超时）：不复用共享 bk->curl，
       并发多文件 STOR 不再竞争 op_lock（此前 res=43 的竞争窗口由此根除）；
       句柄缓存在文件上，同文件多次 FLUSH/补传复用连接池 */
    if (!f->write_curl) f->write_curl = ftp_read_curl_new(f->bk);
    if (f->write_curl) {
        struct ReadBuf rb = {data ? data : "", got, 0};
        CURLcode res = CURLE_OK;
        /* 上传失败自动重试：网络瞬态让 perform 返回 CURLE_BAD_FUNCTION_ARGUMENT
           等瞬时错误（已实测 res=43）；重试吸收竞争窗口，避免上传静默丢失
           （FLUSH 错误会传播给 close() → 应用读到 EIO） */
        int backoff_ms = 200; /* 弱网适配：上传失败指数退避 200ms→3.2s 封顶 */
        for (int attempt = 0; attempt < 5; attempt++) {
            if (attempt > 0) {
                usleep((useconds_t)backoff_ms * 1000);
                if (backoff_ms < 3200) backoff_ms *= 2;
            }
            rb.pos = 0;
            ftp_reset_opts_curl(f->write_curl);
            curl_easy_setopt(f->write_curl, CURLOPT_URL, f->ftp_path);
            curl_easy_setopt(f->write_curl, CURLOPT_UPLOAD, 1L);
            curl_easy_setopt(f->write_curl, CURLOPT_INFILESIZE, (long)got);
            curl_easy_setopt(f->write_curl, CURLOPT_READFUNCTION, read_cb);
            curl_easy_setopt(f->write_curl, CURLOPT_READDATA, &rb);
            res = curl_easy_perform(f->write_curl);
            curl_easy_setopt(f->write_curl, CURLOPT_UPLOAD, 0L);
            if (res == CURLE_OK) break;
            if (f->bk->silent) break; /* 静默模式：失败后不再重试（无网络空转） */
        }
        if (res != CURLE_OK) {
            curl_easy_cleanup(f->write_curl); /* 失败句柄可能已半损坏，重建 */
            f->write_curl = NULL;
            mark_failure(f->bk); /* 计入熔断 */
            rc = -EIO;
        }
    } else {
        rc = -EIO;
    }
    free(data);
    if (rc == 0) {
        f->uploaded = true;
        mark_success(f->bk);         /* 上传成功：清零熔断计数（网络恢复退出静默） */
        ftp_stat_cache_clear(f->bk); /* STOR 完成：整表失效，杜绝写后旧 stat */
    }
    return rc;
}

/* FLUSH 数据收尾：写模式完成上传但**保留句柄**——FUSE 的 FLUSH 在
   每次 close() 调用（dup/fork 可多次），句柄销毁必须等 RELEASE（最后一个
   引用关闭后），否则存活 fd 的后续读写会命中已销毁句柄（-EINVAL）；
   读模式无操作。返回 0 成功。 */
int ftp_backend_flush(uint64_t h) {
    FtpBackendFile* f = ftp_handle_get(h);
    if (!f) return -EINVAL;
    if (!f->writing) return 0;
    /* S4 流式收尾：请求上传线程追平并等待其完成；
       乱序/出错时线程已退出，走全量重传兜底 */
    if (f->up_started) {
        pthread_mutex_lock(&f->f_lock);
        f->up_stop = true; /* 追平剩余尾部后退出 */
        pthread_cond_broadcast(&f->up_cond);
        while (f->up_upto < f->file_end && !f->retransmit && !f->up_error)
            pthread_cond_wait(&f->up_cond, &f->f_lock);
        pthread_mutex_unlock(&f->f_lock);
        pthread_join(f->up_tid, NULL);
        pthread_mutex_lock(&f->f_lock);
        f->up_started = false;
        pthread_mutex_unlock(&f->f_lock);
    }
    if (f->retransmit || f->up_error || f->up_upto < f->file_end)
        return ftp_backend_upload(f); /* 乱序/出错/未追平：全量重传覆盖 */
    f->uploaded = true;
    mark_success(f->bk);
    ftp_stat_cache_clear(f->bk); /* 流式 STOR/APPE 完成：整表失效 */
    return 0;
}

int ftp_backend_release(uint64_t h) {
    FtpBackendFile* f = ftp_handle_get(h);
    if (!f) return -EINVAL;
    int rc = 0;

    /* S4：写模式先停止并 join 流式上传线程（追平尾部或线程已因
       retransmit/error 退出），确保后续 upload 兜底不再有并发读 tmp_fd */
    if (f->up_started) {
        pthread_mutex_lock(&f->f_lock);
        f->up_stop = true;
        pthread_cond_broadcast(&f->up_cond);
        pthread_mutex_unlock(&f->f_lock);
        pthread_join(f->up_tid, NULL);
        f->up_started = false;
    }

    if (f->writing && !f->uploaded) {
        /* FLUSH 未完成上传（未调用/失败/乱序重传）时补传，随后统一销毁句柄 */
        if (ftp_backend_upload(f) != 0) rc = -EIO;
    }

    // 读模式：停止并 join 下载线程 + 等待在途 read 完成 + 释放滑动缓冲 + 销毁独立读句柄
    if (f->dl_started) {
        pthread_mutex_lock(&f->f_lock);
        f->dl_stop = true;                   /* write_cb 检测后立即中止在途传输（join 快速返回） */
        f->dl_released = true;               /* read 检测后立即退出，不再 cond_wait */
        pthread_cond_broadcast(&f->dl_cond); /* 唤醒下载线程与在途 read */
        pthread_mutex_unlock(&f->f_lock);
        pthread_join(f->dl_tid, NULL);
        f->dl_started = false;
        /* 等待在途 read 全部退出后再销毁条件变量/锁/f——
           否则 read 可能 cond_wait 在已销毁对象上（UAF/永久挂起） */
        pthread_mutex_lock(&f->f_lock);
        while (f->n_readers > 0) pthread_cond_wait(&f->dl_cond, &f->f_lock);
        pthread_mutex_unlock(&f->f_lock);
        pthread_cond_destroy(&f->dl_cond);
    }
    if (f->tmp_fd >= 0) close(f->tmp_fd);
    if (f->read_curl) {
        /* S3：归还句柄池（FTP 控制连接保持，供下次 open 复用） */
        ftp_read_curl_release(f->bk, f->read_curl);
        f->read_curl = NULL;
    }
    if (f->write_curl) {
        curl_easy_cleanup(f->write_curl);
        f->write_curl = NULL;
    }
    free(f->rbuf);
    f->rbuf = NULL;
    if (f->writing) pthread_cond_destroy(&f->up_cond); /* 写模式 open 时 init */
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
        if (s) {
            strncpy(path, s, sz - 1);
            path[sz - 1] = '\0';
            return;
        }
    }
    snprintf(path, sz, "/");
}
static void ftp_parent_url(const char* url, char* parent, size_t sz) {
    const char* s = strrchr(url, '/');
    if (s && s > url + 7) {
        size_t len = (size_t)(s - url);
        if (len >= sz) len = sz - 1;
        memcpy(parent, url, len);
        parent[len] = '\0';
        if (len > 0 && parent[len - 1] != '/') {
            if (len + 1 < sz) {
                parent[len] = '/';
                parent[len + 1] = '\0';
            }
        }
    } else {
        snprintf(parent, sz, "%s/", url);
    }
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
    curl_easy_setopt(bk->curl, CURLOPT_POSTQUOTE, NULL); /* 锁内清理，防并发竞争句柄 */
    pthread_mutex_unlock(&bk->op_lock);
    curl_slist_free_all(slist);
    free(wb.buf);
    /* 失败：按 ok_code 映射预期错误（rmdir 非空目录 → -ENOTEMPTY），
       未指定（unlink/mkdir）则统一 -EPERM（curlftpfs 方式） */
    if (res != CURLE_OK) {
        reset_curl(bk, true); /* 命令失败：计入熔断 */
        return ok_code ? -ok_code : -EPERM;
    }
    ftp_stat_cache_clear(bk); /* DELE/MKD/RMD 成功：整表失效 */
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
    char from_url[2048], to_url[2048], from_path[2048], to_path[2048], parent[2048], cmd1[4096],
        cmd2[4096];
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
    curl_easy_setopt(bk->curl, CURLOPT_POSTQUOTE, NULL); /* 锁内清理，防并发竞争句柄 */
    pthread_mutex_unlock(&bk->op_lock);
    curl_slist_free_all(slist);
    if (res != CURLE_OK) {
        reset_curl(bk, true);
        return -EIO;
    }                         /* 重命名失败：计入熔断 */
    ftp_stat_cache_clear(bk); /* RNFR/RNTO 成功：整表失效（from/to 均可能被缓存） */
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
        curl_easy_setopt(bk->curl, CURLOPT_UPLOAD, 0L); /* 锁内清理，防并发竞争句柄 */
        pthread_mutex_unlock(&bk->op_lock);
        if (res != CURLE_OK) {
            reset_curl(bk, true);
            return -EIO;
        }                         /* 截断失败：计入熔断 */
        ftp_stat_cache_clear(bk); /* STOR 空文件截断成功：整表失效 */
        return 0;
    }
    return -EIO; // 非零截断暂不支持
}

/* ================= 模块注册接口 =================

libcurl 后端函数通过 ftp_backend.h 暴露给 ftp_module.c，
由 ftp_module.c 注册到 NspModuleOps 中。无需单独注册函数。 */