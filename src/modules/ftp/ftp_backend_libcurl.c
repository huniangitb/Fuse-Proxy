/* ftp_backend_libcurl.c — 基于 libcurl 的 FTP 后端模块
 *
 * 替换自研 ftp_client.c，利用 libcurl 成熟的网络栈解决：
 *   - 连接复用（keep-alive）
 *   - PASV IP 正确处理（防安卓 NAT/防火墙 → EIO）
 *   - 超时与错误处理
 *   - 随机读支持（CURLOPT_RESUME_FROM）
 *
 * 两条通道的连接模型不同，刻意分开：
 *   - **控制面**（getattr/readdir/DELE/MKD/RMD/RNFR/STOR 空文件/TRUNCATE）：
 *     交给 ftp_mux（epoll + curl_multi，见 ftp_mux.h）驱动。多个 FUSE 线程
 *     的 stat/readdir 因此并行在飞、互不排队，控制连接在 multi 的连接缓存里
 *     长期复用，业务失败（550）也不再丢弃健康连接。
 *   - **数据面**（读下载线程 / 写流式上传）：每文件独立句柄 + 独立线程，
 *     阻塞式 perform。它们本就互不竞争，且背压模型是"缓冲满即中止传输"
 *     （write_cb 返回 0 → CURLE_WRITE_ERROR），与事件循环驱动不兼容，故保留。
 */

#include "nsp_module.h"
#include "nsp_util.h" /* nsp_set_thread_name（线程语义化命名） */
#include "ftp_backend.h"
#include "ftp_mux.h"
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

#define FTP_BACKEND_MAX     16 /* 初容（动态翻倍起点），不再是硬上限 */
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
    FtpMux* mux;             /* 控制面复用器（epoll + curl_multi）：连接缓存 +
                                并发在飞，取代旧的共享 easy 句柄 + op_lock */
    pthread_mutex_t lock;    /* 连接锁 */
    int fail_count;          /* 窗口内失败计数（熔断：后端不可达自动静默） */
    time_t fail_last;        /* 上次计入熔断的失败时间（滑动窗口计数用） */
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
       读句柄为每文件独立（下载线程专用），与 mux 驱动的控制面互不干扰 */
    CURL* read_pool[FTP_READ_POOL_MAX];
    int read_pool_count;
    pthread_mutex_t pool_lock; /* 读句柄池锁（仅 open/release/clear 触碰） */
    bool mutex_inited;         /* 互斥锁已初始化（对象在 add 内一次性建好；clear
                                    不 destroy——对象可能仍被在途操作持有，销毁
                                    会让它们撞上已销毁锁 → SIGSEGV） */
    bool in_use;               /* 注册表槽位占用（clear 后复用，不 free——在途
                                    操作可能仍持 bk 指针，内存 immortal） */
    /* ---- V5 分页 LIST 缓存（单条目：最近列过的目录全量条目） ----
       框架顺序翻页（offset 0→N）时后续页零网络；并发交错列多目录时颠簸重取
       （正确，仅多一次 LIST）。bk->lock 保护（复用连接锁，短临界区）；
       变更操作成功后失效（与 stat 缓存同策略，见各 ftp_stat_cache_clear 点）。
       常驻内存上限 ≈ FTP_LIST_CACHE_MAX 条名字（仅巨型目录可达，典型 KB 级）。 */
    char* list_path;           /* 目录虚拟路径（malloc） */
    struct FtpListEntry* list_entries; /* 全量条目数组（malloc） */
    size_t list_count;
    bool list_truncated;       /* 解析超上限，尾部未知（见 FTP_LIST_CACHE_MAX） */
    time_t list_ts;            /* 上次使用时间：跨**次**列举的缓存有界 TTL，
                                  在用的（连续翻页）不失效——见 FTP_LIST_CACHE_TTL */
} FtpBackend;

/* 跨次列举的 LIST 缓存存活期（秒），**滑动**刷新：每次命中续期。
   为什么滑动而不是绝对 TTL：框架翻页靠 offset，缓存若在翻页中途失效，条目序列
   会平移——同一次 readdir 出现重复/漏项。滑动续期保证"正在被列举的目录"序列稳定；
   空闲超过该时长后再列则重新 LIST，外部客户端在服务器上的增删因此有界可见
   （此前永久复用：只改动的同一目录长期看不到变化）。 */
#define FTP_LIST_CACHE_TTL 5

/* V5 分页缓存上限 = 框架页循环总数上限(VFS_READDIR_MAX_TOTAL=65536)+1 哨兵：
   解析到此数后仍有行即 truncated，服务到缓存末尾时报 E2BIG（fail-closed，
   与框架侧总数上限对齐，>64K 条的 FTP 目录**拒绝服务残页**而非静默丢尾）。

   注意（C3）：此处回传的 -E2BIG 落在框架 `backend_rc_is_business` 区间
   （-4095..0），被框架当作**业务 errno** 原样回给 readdir 调用者——**不会**
   触发 module_guard_error，故**没有**框架 loud 日志、也不计模块错误。这与
   框架自身在 `vfs_readdir_ctx` 里对"无限产条目"的防御（那一路会
   `module_guard_error` 后 loud 报错）是两回事：本模块是**如实上报**一个
   业务失败（远端条目数超出可服务范围），契约上就该走业务通道。 */
#define FTP_LIST_CACHE_MAX 65537u

typedef struct FtpListEntry {
    char name[256]; /* 单名 ≤255（ABI 约束），超长名解析时整条跳过 */
    bool is_dir;
    off_t size;   /* LIST 第 5 列（stat 预取用） */
    time_t mtime; /* 整行时间解析（失败 0） */
} FtpListEntry;

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

/* ============ 失败分类：熔断计数的唯一判定入口 ============
   熔断的意义是发现「后端不可达」（断网/服务挂了）从而快速失败、停止无谓
   等待——不是惩罚应用的正常业务请求。故仅两类计入：
     ① resp==0：服务器从未给出应答（connect 失败/DNS 失败/超时/连接重置）
     ② resp==421：服务器主动声明暂不可用
   其余**服务器已应答**的情形（550 路径缺失/访问拒绝、530 认证失败、450 无
   匹配……）都是「后端活着」的证据：业务结果，一律不计入（避免误杀）。
   热重载/下线归位（CURLE_ABORTED_BY_CALLBACK，resp 恒为 0）同样豁免。
   调用方须在 curl_easy_cleanup 之前取到 CURLINFO_RESPONSE_CODE 传入。 */
static bool res_is_unavailable(CURLcode res, long resp) {
    if (res == CURLE_OK) return false;
    if (res == CURLE_ABORTED_BY_CALLBACK) return false;
    return resp == 0 || resp == 421;
}

/* 「路径不存在」业务判定：服务器明确应答 550（不可用/不存在），或 curl 已
   映射为 not-found。注意 550 在不同命令上对应的 CURLE 码不同（RETR/SIZE →
   CURLE_REMOTE_FILE_NOT_FOUND，CWD/LIST → CURLE_REMOTE_ACCESS_DENIED），故
   必须看响应码、不能只看 CURLE——历史 bug：目录探针返回 9 未被识别，缺失
   路径被误计入熔断、负缓存填充条件从不生效。 */
static bool res_is_not_found(CURLcode res, long resp) {
    return resp == 550 || res == CURLE_REMOTE_FILE_NOT_FOUND;
}

/* 熔断阈值：滑动窗口内失败达此值进入静默。8 次可在容忍正常偶发失败（连接
   抖动）的同时，无网络时（connect 立即失败）毫秒级进入静默——过低（如 3）
   会把正常瞬时失败误判为断网。计入什么由 res_is_unavailable 统一判定。 */
#define FTP_SILENT_THRESHOLD 8
/* 计数窗口：距上次计入的失败超过此秒数即归零重开——零星失败不再终身累积，
   杜绝「慢性累积误杀」健康后端（真断网时失败是密集爆发，不受窗口影响）。 */
#define FTP_FAIL_WINDOW_SEC 30
static void mark_failure(FtpBackend* bk) {
    pthread_mutex_lock(&bk->lock);
    time_t now = time(NULL);
    if (now - bk->fail_last > FTP_FAIL_WINDOW_SEC) bk->fail_count = 0; /* 窗口外旧失败归零 */
    bk->fail_last = now;
    bk->fail_count++;
    if (bk->fail_count >= FTP_SILENT_THRESHOLD && !bk->silent) {
        bk->silent = true;
        bk->silent_at = now;
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

/* 后端注册表：指针数组动态翻倍（初容 FTP_BACKEND_MAX），条目 immortal——
   find 返回的 bk 指针在 glock 解锁后仍被在途操作使用，故条目内存永不 free
   （clear 只关停 mux/标记空闲，add 复用空闲槽）。数组本身的 realloc 只在
   glock 内发生，逃逸的 bk 指针不受影响。 */
static FtpBackend** g_backends = NULL;
static int g_backend_count = 0; /* 活跃条目数（in_use；ftp_backend_count 上报值） */
static int g_backend_slots = 0; /* 已分配槽位数（每次 add 一个新对象，只增不减） */
static int g_backend_cap = 0;   /* 指针数组容量 */
/* 后端数组全局锁 + 热重载标志：
   - g_backend_glock：保护 g_backend_count/cap 与 g_backends 数组的增删扫描
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
    bool uploaded;           /* 本地内容已与远端同步（up_upto == file_end，且此后无新写入）；
                                write 追加/改写后清除，FLUSH 与 RELEASE 据此判定是否需要再同步 */
    size_t file_size;        /* 文件大小（用于读模式边界检查） */
    CURL* read_curl;         /* 读模式独立句柄（下载线程专用，不走控制面 mux） */
    CURL* write_curl;        /* 写模式独立句柄（upload 专用，不走控制面 mux，
                                故并发多文件 STOR 天然互不竞争） */
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
    /* ---- 句柄生命周期（见 ftp_handle_get/put）----
       框架保证 FLUSH 与 RELEASE 不会对同一 h 并发（见 fuse_daemon 的
       "FLUSH 必须早于 RELEASE 且不并发"契约），但防御性地支持乱序/重入：
       refs 计数让"release 拆除"与"在途 flush/write"互不 UAF。 */
    _Atomic int refs;       /* 在途用户计数（0 = 可拆除）；拆除责任只在最后一个 put */
    bool dead;              /* release 已从表中摘除：新 get 一律拒绝 */
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

/* LIST 缓存释放（调用方须持 bk->lock；clear/替换/模块清表路径用） */
static void ftp_list_cache_free_locked(FtpBackend* bk) {
    free(bk->list_path);
    free(bk->list_entries);
    bk->list_path = NULL;
    bk->list_entries = NULL;
    bk->list_count = 0;
    bk->list_truncated = false;
    bk->list_ts = 0;
}

/* 变更操作成功后失效 LIST 缓存（与 ftp_stat_cache_clear 同点调用，
   同策略：写低频，全清成本可忽略）。bk->lock 内执行。 */
static void ftp_list_cache_clear(FtpBackend* bk) {
    pthread_mutex_lock(&bk->lock);
    ftp_list_cache_free_locked(bk);
    pthread_mutex_unlock(&bk->lock);
}

int ftp_backend_add(const FtpServerCfg* cfg) {
    if (!cfg || !cfg->name[0]) return -1;
    pthread_mutex_lock(&g_backend_glock);
    /* **每次 add 都新建后端对象**，不复用已 clear 槽位的内存：旧对象可能仍被
       在途操作或已打开文件持有（它们缓存了 bk 指针，文件句柄还靠 bk->cfg 拼
       URL/取凭据），原位 memset 会把在用的 pthread mutex 一起清零（UB：持有者
       与新进入者同时进临界区），并把 cfg 换成新服务器——热重载与 serving 并发
       时的跨代串用正源于此。对象内存依旧 immortal（既有设计：条目永不 free），
       只是从注册表摘除（in_use=false，find 不再命中），新对象接管。
       指针数组翻倍：realloc 只在 glock 内发生；已逃逸的 bk 指针指向对象本身，
       不受数组搬移影响。 */
    if (g_backend_slots >= g_backend_cap) {
        int ncap = g_backend_cap > 0 ? g_backend_cap * 2 : FTP_BACKEND_MAX;
        FtpBackend** grown = realloc(g_backends, (size_t)ncap * sizeof *grown);
        if (!grown) {
            pthread_mutex_unlock(&g_backend_glock);
            return -1;
        }
        for (int i = g_backend_cap; i < ncap; i++) grown[i] = NULL;
        g_backends = grown;
        g_backend_cap = ncap;
    }
    FtpBackend* bk = calloc(1, sizeof *bk);
    if (!bk) {
        pthread_mutex_unlock(&g_backend_glock);
        return -1;
    }
    g_backends[g_backend_slots++] = bk;
    pthread_mutex_init(&bk->lock, NULL);
    pthread_mutex_init(&bk->pool_lock, NULL);
    pthread_mutex_init(&bk->stat_lock, NULL);
    bk->mutex_inited = true;
    bk->in_use = true;
    bk->cfg = *cfg;
    snprintf(bk->prefix, sizeof bk->prefix, "/%s", cfg->name);
    /* 控制面复用器（epoll 事件线程 + CURLM 连接缓存） */
    FtpMux* mux = ftp_mux_new();
    if (!mux) {
        pthread_mutex_unlock(&g_backend_glock);
        return -1;
    }
    /* 在 bk->lock 内发布指针：backend_mux_ref 在同一锁内取引用，
       两者互斥，故不存在"取到引用却已被释放"的窗口 */
    pthread_mutex_lock(&bk->lock);
    bk->mux = mux;
    pthread_mutex_unlock(&bk->lock);
    g_backend_count++;
    pthread_mutex_unlock(&g_backend_glock);
    return 0;
}

void ftp_backend_clear(void) {
    atomic_store_explicit(&g_backend_clearing, true, memory_order_release);
    pthread_mutex_lock(&g_backend_glock);
    for (int i = 0; i < g_backend_slots; i++) {
        FtpBackend* bk = g_backends[i];
        if (!bk || !bk->in_use) continue;
        /* 先摘指针再关停：摘指针与 backend_mux_ref 的取引用互斥（同锁），
           摘除后新操作拿不到旧 mux；关停会把在途任务归位（提交者拿到
           失败码而非悬挂），并等其全部离开后才销毁 multi */
        pthread_mutex_lock(&bk->lock);
        FtpMux* mux = bk->mux;
        bk->mux = NULL;
        ftp_list_cache_free_locked(bk); /* LIST 缓存同清（锁内） */
        pthread_mutex_unlock(&bk->lock);
        if (mux) {
            ftp_mux_shutdown(mux);
            ftp_mux_unref(mux);
        }
        /* 释放池中空闲读句柄（在途句柄由各自 release 归还/销毁） */
        pthread_mutex_lock(&bk->pool_lock);
        for (int p = 0; p < bk->read_pool_count; p++) {
            if (bk->read_pool[p]) curl_easy_cleanup(bk->read_pool[p]);
        }
        bk->read_pool_count = 0;
        pthread_mutex_unlock(&bk->pool_lock);
        /* 不再 pthread_mutex_destroy：槽位复用，互斥锁生命周期与模块一致，
           杜绝在途操作 pthread_mutex_lock 已销毁锁 → UB/SIGSEGV。
           条目内存 immortal（不 free）：在途操作仍可能持 bk 指针。 */
        bk->in_use = false;
    }
    g_backend_count = 0;
    pthread_mutex_unlock(&g_backend_glock);
    atomic_store_explicit(&g_backend_clearing, false, memory_order_release);
}

int ftp_backend_count(void) {
    return g_backend_count;
}

/* 找 path 命中的后端（仅活跃条目；返回指针在 glock 外仍有效，
   条目内存 immortal） */
static FtpBackend* ftp_backend_find(const char* path) {
    if (atomic_load_explicit(&g_backend_clearing, memory_order_acquire)) return NULL;
    pthread_mutex_lock(&g_backend_glock);
    FtpBackend* r = NULL;
    for (int i = 0; i < g_backend_slots; i++) {
        FtpBackend* bk = g_backends[i];
        if (!bk || !bk->in_use) continue;
        size_t plen = strlen(bk->prefix);
        if (strncmp(bk->prefix, path, plen) == 0 &&
            (path[plen] == '\0' || path[plen] == '/')) {
            r = bk;
            break;
        }
    }
    pthread_mutex_unlock(&g_backend_glock);
    return r;
}

/* 构建 FTP URL（不编码 /，FTP 协议路径直接使用）。
   失败闭合：保持 void 签名（9 处调用方不动），任何一步放不下都写空串——
   调用方 curl 以空 URL 失败（EIO），永不读写截断出的错误远端文件。
   动态扩充：rel 经 nsp_snprintf_dyn 堆溢出（URL 编码可膨胀 3 倍，固定 1024
   栈缓冲在深路径 + 中文名下必截断）；终 URL 同理。常见短路径零 malloc。 */
static void build_url(const FtpBackend* bk, const char* path, char* url, size_t sz) {
    if (!url || sz == 0) return;
    url[0] = '\0'; /* 先置空：任何失败路径都不外流截断串 */
    if (!bk || !path) return;
    /* 前缀前置校验（与 ftp_backend_find 同一判据）：不匹配即保持空串，由调用方
       按「空 URL」闭合（EIO/ENAMETOOLONG）。此前无条件 `path + strlen(prefix)`：
       ① path 比 prefix 短时越过 NUL 读未初始化栈字节拼进 URL；② 把**别的
       server** 的路径拼到本 server 的 URL 上——跨 server rename 因此静默写错
       服务器（§A13）。 */
    size_t plen = strlen(bk->prefix);
    if (strncmp(bk->prefix, path, plen) != 0) return;
    if (path[plen] != '\0' && path[plen] != '/') return;
    const char* p = path + plen;
    while (*p == '/') p++;
    char rel_fixed[1024];
    char* rel_heap = NULL;
    int rn = (p[0] == '\0')
                 ? nsp_snprintf_dyn(rel_fixed, sizeof rel_fixed, &rel_heap, 65536, "%s",
                                    bk->cfg.remote_dir)
                 : nsp_snprintf_dyn(rel_fixed, sizeof rel_fixed, &rel_heap, 65536, "%s/%s",
                                    bk->cfg.remote_dir, p);
    if (rn < 0) {
        free(rel_heap);
        return;
    }
    const char* rel = rel_heap ? rel_heap : rel_fixed;
    // 对路径中的特殊字符（空格等）编码，但保留 /
    char* enc = curl_easy_escape(NULL, rel, 0);
    char* url_heap = NULL;
    int un;
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
        un = nsp_snprintf_dyn(url, sz, &url_heap, 65536, "ftp://%s:%d%s", bk->cfg.host,
                              bk->cfg.port, enc);
        curl_free(enc);
    } else {
        un = nsp_snprintf_dyn(url, sz, &url_heap, 65536, "ftp://%s:%d%s", bk->cfg.host,
                              bk->cfg.port, rel);
    }
    free(rel_heap);
    if (un < 0 || url_heap) {
        /* 终 URL 放不进调用方缓冲（或超限）：置空失败 */
        free(url_heap);
        url[0] = '\0';
    }
}

/* 后端就绪检查（mux 未建/已 clear）。仅作快速失败——真正的竞态（取指针到
   使用之间被 clear 摘除）由 backend_mux_ref 的引用计数兜底。指针读取在
   bk->lock 内：与 clear 的「锁内摘指针」互斥，消除与 ftp_backend_clear 的
   无同步数据竞争 */
static int backend_ready(FtpBackend* bk) {
    pthread_mutex_lock(&bk->lock);
    bool ready = (bk->mux != NULL);
    pthread_mutex_unlock(&bk->lock);
    return ready ? 0 : -1;
}

/* 取当前 mux 并持引用。热重载（ftp_backend_clear）会把 bk->mux 置 NULL 并
   shutdown/unref；取指针与 perform 之间必须持引用，否则可能与 unref 释放
   竞态（UAF）。返回 NULL 表示后端已下线，调用方按失败处理。 */
static FtpMux* backend_mux_ref(FtpBackend* bk) {
    pthread_mutex_lock(&bk->lock);
    FtpMux* m = ftp_mux_ref(bk->mux);
    pthread_mutex_unlock(&bk->lock);
    return m;
}

/* 控制面执行入口：驱动一个 easy 任务直到完成（epoll 事件线程内部驱动），
   返回 curl 结果码。CURLE_ABORTED_BY_CALLBACK = 后端已下线（热重载/未就绪）。
   easy 由调用方创建并独占，返回后调用方负责 cleanup。 */
static CURLcode backend_perform(FtpBackend* bk, CURL* easy) {
    FtpMux* m = backend_mux_ref(bk);
    if (!m) return CURLE_ABORTED_BY_CALLBACK;
    CURLcode res = ftp_mux_perform(m, easy);
    ftp_mux_unref(m);
    return res;
}

/* 失败后的连接处置（控制面统一出口）。backend_unavailable=true（且仅此时）：
   标记缓存连接可疑（下次操作以全新连接 + 重新登录执行）并计入熔断。
   false 表示**业务失败**（550 文件/目录不存在、非空目录、认证被拒……，或
   热重载归位）：控制连接完全健康、响应已消费完——既不重建（重建等于让下一次
   操作白付一次 TCP + USER/PASS 登录往返）也不计数。
   分类判定统一走 res_is_unavailable（调用方传入前先取好响应码）：
   服务器应答过的业务失败与热重载归位码一律 false，避免误杀。
   置位经 backend_mux_ref 锁内取引用：直接读 bk->mux 与 ftp_backend_clear 的
   「锁内摘指针 → shutdown → unref → free」构成 UAF 数据竞争。 */
static void reset_curl(FtpBackend* bk, bool backend_unavailable) {
    if (!backend_unavailable) return;
    FtpMux* m = backend_mux_ref(bk);
    if (m) {
        ftp_mux_invalidate(m);
        ftp_mux_unref(m);
    }
    mark_failure(bk);
}

/* 重置 easy 句柄的操作级选项（防跨操作残留：NOBODY 残留会吞掉 STOR 上传、
   WRITEDATA 残留指向已失效的栈缓冲）。控制面每次操作都用全新句柄
   （ftp_easy_new），无需重置；此处仅供数据面**池化复用**的读写句柄使用。 */
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

/* 最终拆除：仅在「已 dead（release 摘表）且 refs 归零」时执行。
   调用者持有最后一个引用（ftp_handle_put 内调用）或 release 自身即最后一个。
   注意本函数不碰 g_handles（摘表已由 release 完成）。 */
static void ftp_handle_destroy_final(FtpBackendFile* f);

/* 取句柄并**在表锁内**增加在途引用（见 FtpBackendFile.refs 注释）。
   返回 NULL 表示 id 非法或已被 RELEASE 摘除。
   调用方**必须**在结束使用后调用 ftp_handle_put()（不区分成功/失败路径）。
   这样"release 查表 → 释放 f"与"flush/write 查表 → 用 f"之间不再有
   无保护窗口：release 只有在 refs 归零时才真正 free。 */
static FtpBackendFile* ftp_handle_get(uint64_t id) {
    if (id <= 0 || id >= FTP_HANDLE_MAX) return NULL;
    pthread_mutex_lock(&g_handles_mutex);
    FtpBackendFile* f = g_handles[id];
    if (f) atomic_fetch_add_explicit(&f->refs, 1, memory_order_acq_rel);
    pthread_mutex_unlock(&g_handles_mutex);
    return f;
}

/* 归还一次在途引用。refs 归零且 release 已置 dead → 由本调用执行最终拆除
   （此前 release 把拆除推迟到这里，避免与在途使用者竞态）。 */
static void ftp_handle_put(uint64_t id, FtpBackendFile* f) {
    if (!f) return;
    if (atomic_fetch_sub_explicit(&f->refs, 1, memory_order_acq_rel) == 1) {
        /* 最后一个引用：仅当 release 已置 dead（拆表）才真正拆除；
           否则句柄仍在使用中（无人 release），保留。
           表锁内复核 dead，与 release 的"摘表后置 dead"形成单点同步：
           要么本线程看到 dead 并拆，要么 release 稍后自己看到 refs==0 并拆。 */
        bool do_destroy = false;
        pthread_mutex_lock(&g_handles_mutex);
        do_destroy = f->dead;
        pthread_mutex_unlock(&g_handles_mutex);
        if (do_destroy) ftp_handle_destroy_final(f);
    }
    (void)id;
}

/* 仅从注册表摘除（不改 dead / refs / 不 free）：供 ftp_backend_clear 与单元
   驱动在"绕过 release"的受控场景下注销句柄用。
   正常路径请走 ftp_backend_release（含 refs 归零后的最终拆除）。 */
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
    if (backend_ready(bk) != 0) return -EIO;
    /* 用 build_url 得到 FTP 端完整 URL（含 remote_dir 映射），
       从 URL 路径部分取父路径与目标目录名——不能按虚拟 path 切分，
       否则 remote_dir（如 /upload）映射后父路径会算错 */
    char url[2048];
    build_url(bk, path, url, sizeof url);
    if (url[0] == '\0') return -1; /* build_url 已失败闭合（超长置空）：不拿截断串继续 */
    if (strlen(url) < strlen("ftp://") + 1) return -1;
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
        size_t dl = strlen(dec);
        /* 超长名无法精确匹配：失败闭合（不截断后模糊匹配错目录） */
        if (dl == 0 || dl >= sizeof(target)) {
            curl_free(dec);
            return -1;
        }
        memcpy(target, dec, dl + 1);
        curl_free(dec);
    } else {
        size_t el = strlen(enc_target);
        if (el == 0 || el >= sizeof(target)) return -1;
        memcpy(target, enc_target, el + 1);
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
       这里直接基于原 url 前缀重建）。失败闭合：nsp_snprintf_dyn 放不下
       （堆溢出）即返回 -1，绝不拿截断 URL 去 LIST 错目录。 */
    size_t urllen = strlen(url);
    char list_url[2048];
    char* list_heap = NULL;
    const char* list_use = list_url;
    int lr = -1;
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
            lr = nsp_snprintf_dyn(list_url, sizeof list_url, &list_heap, 65536,
                                  "ftp://%s:%d%.*s/", bk->cfg.host, bk->cfg.port,
                                  (int)plen2, rd);
        } else {
            lr = nsp_snprintf_dyn(list_url, sizeof list_url, &list_heap, 65536,
                                  "ftp://%s:%d/", bk->cfg.host, bk->cfg.port);
        }
    } else {
        /* 父路径在 remote_dir 之下：url 前缀（host:port）+ parent */
        lr = nsp_snprintf_dyn(list_url, sizeof list_url, &list_heap, 65536, "%.*s%s/",
                              (int)(urllen - pplen), url, parent);
    }
    if (lr < 0 || list_heap) {
        free(list_heap);
        return -1;
    }
    list_use = list_url;

    struct WriteBuf wb = {0};
    /* 只需匹配目标目录行：限制 LIST 缓冲容量（256KB 固定、不自动扩容），
       避免大父目录全量列表导致内存随条目数无界增长 */
    wb.cap = 256 * 1024;
    wb.buf = malloc(wb.cap);
    if (!wb.buf) return -1;
    wb.auto_grow = false;
    CURL* c = ftp_easy_new(&bk->cfg);
    if (!c) {
        free(wb.buf);
        return -1;
    }
    curl_easy_setopt(c, CURLOPT_URL, list_use);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &wb);
    CURLcode res = backend_perform(bk, c);
    curl_easy_cleanup(c);
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
                /* 写入 TTL 缓存：后续 getattr 直接命中，免父目录 LIST。
                   键超长不缓存（不写截断键，防键碰撞污染），本次结果照常返回。 */
                pthread_mutex_lock(&bk->lock);
                if (strlen(path) < sizeof(bk->mtime_cache_path)) {
                    memcpy(bk->mtime_cache_path, path, strlen(path) + 1);
                    bk->mtime_cache_val = *out;
                    bk->mtime_cache_ts = time(NULL);
                }
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
    if (silent_fast_fail(bk))
        return -EIO; /* 静默=后端不可达：EIO 如实上报（报 ENOENT 会把完好
                        文件说成消失，属误杀）；每 2s 放行一次探测 */
    memset(st, 0, sizeof *st);

    if (backend_ready(bk) != 0) return -EIO;

    char url[2048];
    build_url(bk, path, url, sizeof url);
    if (url[0] == '\0') return -ENAMETOOLONG; /* 路径过长组不出 URL（业务 errno，不熔断） */

    // 先尝试作为文件（SIZE + MDTM）
    struct WriteBuf wb = {0};
    wb.auto_grow = true;
    long resp_code = 0;
    curl_off_t cl = 0;
    long ft = -1;
    CURLcode res;
    CURL* fc = ftp_easy_new(&bk->cfg);
    if (!fc) return -EIO;
    curl_easy_setopt(fc, CURLOPT_URL, url);
    curl_easy_setopt(fc, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(fc, CURLOPT_FILETIME, 1L);
    curl_easy_setopt(fc, CURLOPT_HEADER, 0L);
    curl_easy_setopt(fc, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(fc, CURLOPT_WRITEDATA, &wb);

    res = backend_perform(bk, fc);
    /* getinfo 在句柄独占期内读：任务完成后 mux 已摘除该句柄，
       不会再有并发传输覆盖其状态（如 cl=0）。响应码无论成败都取——
       失败分类（res_is_unavailable/res_is_not_found）依赖它 */
    curl_easy_getinfo(fc, CURLINFO_RESPONSE_CODE, &resp_code);
    if (res == CURLE_OK && (resp_code == 213 || resp_code == 350)) {
        curl_easy_getinfo(fc, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl);
        curl_easy_getinfo(fc, CURLINFO_FILETIME, &ft);
    }
    curl_easy_cleanup(fc);
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
    /* 保留文件探针结论（res/resp_code 随后被目录探针复用）：两探针各自分类，
       任一判定「后端不可达」才计熔断——服务器应答过的（550 等）绝不计入 */
    CURLcode file_res = res;
    long file_resp = resp_code;

    // 作为目录（LIST）- URL 末尾加 / 即可触发 libcurl 自动 LIST
    char dir_url[2048];
    size_t ulen = strlen(url);
    if (ulen > 0 && url[ulen - 1] != '/')
        snprintf(dir_url, sizeof dir_url, "%s/", url);
    else
        snprintf(dir_url, sizeof dir_url, "%s", url);

    struct WriteBuf dir_wb = {0};
    dir_wb.auto_grow = true;
    CURL* dc = ftp_easy_new(&bk->cfg);
    if (!dc) {
        reset_curl(bk, true); /* 句柄分配失败：计入熔断 */
        return -EIO;
    }
    curl_easy_setopt(dc, CURLOPT_URL, dir_url);
    curl_easy_setopt(dc, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(dc, CURLOPT_WRITEDATA, &dir_wb);

    res = backend_perform(bk, dc);
    long dir_resp = 0;
    curl_easy_getinfo(dc, CURLINFO_RESPONSE_CODE, &dir_resp); /* 须在 cleanup 前取 */
    curl_easy_cleanup(dc);
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
        mark_success(bk); /* 操作成功：清零熔断计数（此前目录成功不清零，
                            零星失败会跨操作累积 → 慢性误杀） */
        return 0;
    }
    free(dir_wb.buf);

    // 都不是
    /* 两探针各自分类：任一「后端不可达」（无应答/421/归位码豁免见
       res_is_unavailable）才重建连接 + 计熔断；服务器应答过的业务失败不计 */
    reset_curl(bk, res_is_unavailable(file_res, file_resp) ||
                       res_is_unavailable(res, dir_resp));
    if (res_is_not_found(file_res, file_resp) && res_is_not_found(res, dir_resp)) {
        /* 双探针均应答 550：确实不存在——正常业务结果，返回 ENOENT 并入负缓存
           （exists 检查高频，TTL 内免 2~3 次网络往返；写操作成功后整表失效，
           不会命中写后旧 ENOENT） */
        ftp_stat_cache_fill(bk, path, -ENOENT, false, 0, 0);
        return -ENOENT;
    }
    /* 未双确认缺失（无应答/传输失败/服务器其它应答）：如实报 EIO——把后端
       故障谎报成 ENOENT 会让应用把完好的文件当消失（误杀） */
    return -EIO;
}

/* 从已缓存数组服务一页（纯函数，无锁，调用方持 bk->lock）：
   返回填充数；页尾恰为缓存末尾但远端还有未知条目（truncated）→ -E2BIG
   fail-closed（拒给残页，由调用方回给框架；见 FTP_LIST_CACHE_MAX 处关于
   "走业务通道、无 loud" 的说明）；offset 越界时同理，
   否则（确到末尾）返回 0。 */
static int ftp_list_serve_page(const FtpListEntry* arr, size_t count, bool truncated,
                               NspDirEntry* out, int max, uint64_t offset) {
    if (max <= 0) return 0;
    if (offset >= (uint64_t)count) return truncated ? -E2BIG : 0;
    size_t avail = count - (size_t)offset;
    size_t n = avail < (size_t)max ? avail : (size_t)max;
    for (size_t i = 0; i < n; i++) {
        memcpy(out[i].name, arr[(size_t)offset + i].name, sizeof out[i].name);
        out[i].is_dir = arr[(size_t)offset + i].is_dir;
    }
    /* 页尾恰达缓存末尾但远端还有未知条目：宁可报错不给残页（fail-closed，
       调用方回 -E2BIG 给框架；该值走业务 errno 通道，非框架 loud 路径） */
    if ((uint64_t)offset + n == (uint64_t)count && truncated) return -E2BIG;
    return (int)n;
}

/* 已服务页的子项 stat 预取（优化 3：readdir 后 getattr 子项零网络）。
   调用方持 bk->lock；key 为虚拟路径（path + "/" + name），与 getattr 一致。 */
static void ftp_list_prefetch(FtpBackend* bk, const char* path, const FtpListEntry* arr,
                              size_t base, int n) {
    size_t plen = strlen(path);
    if (plen == 0) return;
    for (int i = 0; i < n; i++) {
        const FtpListEntry* e = &arr[base + (size_t)i];
        size_t nlen = strlen(e->name);
        if (plen + 1 + nlen >= FTP_STAT_PATH_MAX) continue; /* 超长不缓存 */
        char child[FTP_STAT_PATH_MAX];
        memcpy(child, path, plen);
        child[plen] = '/';
        memcpy(child + plen + 1, e->name, nlen + 1);
        ftp_stat_cache_fill(bk, child, 0, e->is_dir, e->size, e->mtime);
    }
}

int ftp_backend_readdir(const char* path, NspDirEntry* entries, int max, uint64_t offset) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk) return -ENOENT;
    if (!entries || max <= 0) return 0;
    if (silent_fast_fail(bk))
        return -EIO; /* 静默=后端不可达：EIO 如实上报（报 ENOENT 会把完好
                        文件说成消失，属误杀）；每 2s 放行一次探测 */

    if (backend_ready(bk) != 0) return -EIO;

    /* 缓存命中：同目录后续页零网络（框架顺序翻页，命中率 100%）。
       空目录也缓存（entries NULL + count 0）：到末尾直接回 0，免重复 LIST。 */
    pthread_mutex_lock(&bk->lock);
    if (bk->list_path && strcmp(bk->list_path, path) == 0 &&
        time(nullptr) - bk->list_ts <= FTP_LIST_CACHE_TTL) {
        bk->list_ts = time(nullptr); /* 滑动续期：连续翻页期间不失效（序列稳定） */
        int n = ftp_list_serve_page(bk->list_entries, bk->list_count, bk->list_truncated,
                                    entries, max, offset);
        if (n > 0)
            ftp_list_prefetch(bk, path, bk->list_entries, (size_t)offset, n);
        pthread_mutex_unlock(&bk->lock);
        return n;
    }
    pthread_mutex_unlock(&bk->lock);

    /* 未命中：一次 LIST 全量拉取（wb auto_grow，大小不限——解析侧按
       FTP_LIST_CACHE_MAX 封顶，网络侧全收保证解析完整） */
    char url[2048], dir_url[2048];
    build_url(bk, path, url, sizeof url);
    if (url[0] == '\0') return -ENAMETOOLONG; /* 路径过长组不出 URL（业务 errno，不熔断） */
    size_t ulen = strlen(url);
    if (ulen + 2 > sizeof dir_url) return -ENAMETOOLONG;
    if (ulen > 0 && url[ulen - 1] != '/')
        snprintf(dir_url, sizeof dir_url, "%s/", url);
    else
        snprintf(dir_url, sizeof dir_url, "%s", url);

    struct WriteBuf wb = {0};
    wb.auto_grow = true;
    CURL* c = ftp_easy_new(&bk->cfg);
    if (!c) return -EIO;
    curl_easy_setopt(c, CURLOPT_URL, dir_url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &wb);

    CURLcode res = backend_perform(bk, c);
    long resp = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &resp); /* 须在 cleanup 前取 */
    curl_easy_cleanup(c);
    if (res != CURLE_OK) {
        free(wb.buf);
        /* 分类见 res_is_unavailable/res_is_not_found：服务器应答 550 是
           「目录不存在」的正常业务结果（ENOENT、不计熔断）；后端不可达
           如实报 EIO——谎报 ENOENT 会让应用以为目录消失了（误杀） */
        reset_curl(bk, res_is_unavailable(res, resp));
        return res_is_not_found(res, resp) ? -ENOENT : -EIO;
    }

    // 解析 LIST 输出 → 新缓存数组（动态翻倍，上限 FTP_LIST_CACHE_MAX）
    FtpListEntry* arr = NULL;
    size_t count = 0, arr_cap = 0;
    bool truncated = false;
    size_t skipped_long = 0;
    char* line = wb.buf;
    char* end = wb.buf + wb.len;
    while (line < end) {
        // 跳过空行
        while (line < end && (*line == '\n' || *line == '\r')) line++;
        if (line >= end) break;
        if (count >= FTP_LIST_CACHE_MAX) {
            truncated = true; /* 尾部未知：服务到末尾时 E2BIG（fail-closed） */
            break;
        }
        char* nl = memchr(line, '\n', (size_t)(end - line));
        if (!nl) nl = end;
        // 简单解析：跳过日期/权限字段，取最后一列作为文件名；
        // 同时捕获第 5 列（size）与时间列用于子项 stat 缓存预取
        //（优化 3：readdir 后 getattr 子项零网络）
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
            size_t nlen = (size_t)(e - name);
            /* 只跳过真正的点条目 "." / ".."（A15）：旧写法 `name[0] != '.'`
               会把**所有**点开头文件一起丢掉，于是 .nomedia/.git 等完全不可见，
               而 backend_getattr 对它们返回成功 → ls -a 空、rsync/rm -r 漏删、
               只含点文件的目录 rmdir 报 ENOTEMPTY 却列不出内容。 */
            bool dot_entry = (nlen == 1 && name[0] == '.') ||
                             (nlen == 2 && name[0] == '.' && name[1] == '.');
            if (nlen > 0 && !dot_entry) {
                /* V5：超长名整条跳过（ABI 约束：禁止截断安装，同前缀长名
                   截断后会互相覆盖；且内核 NAME_MAX=255 本就装不下）。 */
                if (nlen >= sizeof arr[0].name) {
                    skipped_long++;
                } else {
                    if (count >= arr_cap) {
                        size_t ncap = arr_cap > 0 ? arr_cap * 2 : 256;
                        if (ncap > FTP_LIST_CACHE_MAX) ncap = FTP_LIST_CACHE_MAX;
                        FtpListEntry* grown = realloc(arr, ncap * sizeof *grown);
                        if (!grown) {
                            /* OOM：已有条目照常服务，但尾部未知 → 置 truncated，
                               服务到末尾时 E2BIG（fail-closed，不谎报“到末尾”） */
                            truncated = true;
                            break;
                        }
                        arr = grown;
                        arr_cap = ncap;
                    }
                    if (count < arr_cap) {
                        memcpy(arr[count].name, name, nlen);
                        arr[count].name[nlen] = '\0';
                        arr[count].is_dir = (line[0] == 'd');
                        arr[count].size = size_str[0] ? (off_t)atoll(size_str) : 0;
                        arr[count].mtime = 0;
                        if (ftp_parse_list_time(line, nl, &arr[count].mtime) != 0)
                            arr[count].mtime = 0;
                        count++;
                    }
                }
            }
        }
        line = nl + 1;
    }
    free(wb.buf);

    /* 安装：锁内复核。命中"TTL 内的同路径缓存"说明是并发另一线程刚装好同目录
       （本次是重复拉取）→ 复用已装、丢本次结果。注意判据必须带 TTL：只比路径的话，
       本次因**过期**而重取的数据也会被这里丢掉、旧缓存原样留着，于是每次列举都白拉
       一遍且永远看不到外部改动（TTL 形同虚设）。 */
    pthread_mutex_lock(&bk->lock);
    int n;
    const FtpListEntry* use_arr;
    size_t use_count;
    bool use_trunc;
    if (bk->list_path && strcmp(bk->list_path, path) == 0 &&
        time(nullptr) - bk->list_ts <= FTP_LIST_CACHE_TTL) {
        free(arr);
        use_arr = bk->list_entries;
        use_count = bk->list_count;
        use_trunc = bk->list_truncated;
    } else {
        char* np = strdup(path);
        if (!np) {
            pthread_mutex_unlock(&bk->lock);
            free(arr);
            return -ENOMEM;
        }
        ftp_list_cache_free_locked(bk);
        bk->list_path = np;
        bk->list_entries = arr;
        bk->list_count = count;
        bk->list_truncated = truncated;
        bk->list_ts = time(nullptr);
        use_arr = arr;
        use_count = count;
        use_trunc = truncated;
    }
    n = ftp_list_serve_page(use_arr, use_count, use_trunc, entries, max, offset);
    if (n > 0) ftp_list_prefetch(bk, path, use_arr, (size_t)offset, n);
    pthread_mutex_unlock(&bk->lock);
    if (skipped_long > 0)
        LOG_WRN("ftp_module: 目录 %s 有 %zu 个超长文件名（≥255 字节）已跳过", path, skipped_long);
    mark_success(bk); /* 操作成功：清零熔断计数 */
    return n;
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
    return ftp_easy_new(&bk->cfg);
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

/* ============ 写模式 open 的回灌（A8） ============
   open(O_RDWR) / open(O_WRONLY|O_APPEND) 等「就地改写」语义下，远端已有内容
   必须先灌进本地 tmp，否则后续 pwrite 只写命中区域、上传时按 tmp 长度全量
   STOR——远端被替换成「空洞(读作 0) + 新数据」，原内容全丢（SQLite
   synchronous=FULL 就地写、编辑器保存必现）。 */

/* curl 写回调：把 RETR 数据顺序落盘到 tmp_fd（不占内存，支持大文件） */
struct FdWriteCtx {
    int fd;
    off_t pos;
};

static size_t write_fd_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    struct FdWriteCtx* c = (struct FdWriteCtx*)userdata;
    size_t total = size * nmemb;
    size_t done = 0;
    while (done < total) {
        ssize_t w = pwrite(c->fd, ptr + done, total - done, c->pos + (off_t)done);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return done; /* 短写 → curl 以 CURLE_WRITE_ERROR 中止 */
        }
        done += (size_t)w;
    }
    return total;
}

/* 把远端内容整体下载进 f->tmp_fd（复用池化读句柄，选项集与下载线程一致）。
   返回 0 成功；负 errno 失败。调用方须在 open 的写模式分支内、上传线程启动前调用。 */
static int ftp_write_backfill(FtpBackend* bk, FtpBackendFile* f) {
    CURL* c = ftp_read_curl_acquire(bk);
    if (!c) return -EIO;
    struct FdWriteCtx ctx = {.fd = f->tmp_fd, .pos = 0};
    char range[32];
    snprintf(range, sizeof range, "0-");
    curl_easy_setopt(c, CURLOPT_URL, f->ftp_path);
    curl_easy_setopt(c, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(c, CURLOPT_UPLOAD, 0L);
    curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, NULL);
    curl_easy_setopt(c, CURLOPT_RESUME_FROM, 0L);
    curl_easy_setopt(c, CURLOPT_RANGE, range);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_fd_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &ctx);
    CURLcode res = curl_easy_perform(c);
    ftp_read_curl_release(bk, c); /* 内部已重置操作选项，防 RANGE/WRITEDATA 残留 */
    if (res != CURLE_OK) return -EIO;
    return 0;
}

int ftp_backend_open(const char* path, int flags, uint64_t* h) {
    FtpBackend* bk = ftp_backend_find(path);
    if (!bk || !h) return -ENOENT;
    if (silent_fast_fail(bk))
        return -EIO; /* 静默=后端不可达：EIO 如实上报（报 ENOENT 会把完好
                        文件说成消失，属误杀）；每 2s 放行一次探测 */

    if (backend_ready(bk) != 0) return -EIO;

    FtpBackendFile* f = calloc(1, sizeof *f);
    if (!f) return -ENOMEM;
    f->bk = bk;
    f->tmp_fd = -1;
    atomic_store_explicit(&f->refs, 0, memory_order_relaxed); /* 表内登记后才可能被 get */
    f->dead = false;
    pthread_mutex_init(&f->f_lock, NULL); /* 保护读缓冲状态 */
    build_url(bk, path, f->ftp_path, sizeof f->ftp_path);
    if (f->ftp_path[0] == '\0') { /* 路径过长组不出 URL（业务 errno，不熔断），不进 curl */
        pthread_mutex_destroy(&f->f_lock);
        free(f);
        return -ENAMETOOLONG;
    }

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

        /* A8 回灌：目标已存在且非 O_TRUNC → 先把远端内容下载进 tmp。
           - 远端不存在（ENOENT）：按新建处理，零下载（避免 open 期多一次往返）；
           - getattr 真失败：放弃 open（fail-closed）——不知远端内容就改写等于
             赌「原内容会被静默丢弃」；
           - 回灌后把 file_end/up_upto 都设为远端长度、up_first=false：
             内容与远端一致，视作「已上传」，后续增量走 APPE 而非 STOR 截断；
             若应用改写前缀（off < up_upto）则由 write 置 retransmit 转全量重传。 */
        if (!(flags & O_TRUNC)) {
            struct stat rst;
            int grc = ftp_backend_getattr(path, &rst);
            if (grc == -ENOENT) {
                /* 新文件：保持零下载 */
            } else if (grc != 0) {
                close(tfd);
                f->tmp_fd = -1;
                pthread_cond_destroy(&f->up_cond);
                pthread_mutex_destroy(&f->f_lock);
                free(f);
                return grc;
            } else if (S_ISREG(rst.st_mode) && rst.st_size > 0) {
                int brc = ftp_write_backfill(bk, f);
                if (brc != 0) {
                    close(tfd);
                    f->tmp_fd = -1;
                    pthread_cond_destroy(&f->up_cond);
                    pthread_mutex_destroy(&f->f_lock);
                    free(f);
                    return brc;
                }
                f->file_end = rst.st_size;
                f->up_upto = rst.st_size;
                f->up_first = false;
            }
        }

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
    /* 曾在此处做 2×10ms 重试，覆盖"上传成功后立即 open 命中内核 negative 缓存
       报 ENOENT"的 close-to-open 窗口。该竞态的根因是框架把 libfuse 默认的
       negative_timeout=0.0 抬到了 0.5，已由框架侧修正（见 vfs_init），
       ENOENT 不再被内核缓存，故重试去除——缺失路径的存在性检查恢复为
       单次查询（此前重试会让每次缺失查询同步阻塞 FUSE open 线程 ≥20ms） */
    if (grc != 0) {
        /* getattr 结果如实透传（EIO/ENOENT）——此前一律改写成 ENOENT，
           后端故障时「打开完好文件」会被谎报成文件不存在（误杀） */
        pthread_mutex_destroy(&f->f_lock);
        free(f);
        return grc;
    }
    if (!S_ISREG(st.st_mode)) {
        pthread_mutex_destroy(&f->f_lock);
        free(f);
        return -ENOENT;
    }
    f->file_size = (size_t)st.st_size;
    f->writing = false;

    // 每文件独立读句柄（下载线程专用，与 mux 驱动的控制面互不干扰）
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

    if (backend_ready(bk) != 0) return -EIO;

    char url[2048];
    build_url(bk, path, url, sizeof url);
    if (url[0] == '\0') return -ENAMETOOLONG; /* 路径过长组不出 URL（业务 errno，不熔断） */

    // STOR 上传空文件
    struct ReadBuf rb = {"", 0, 0};
    CURL* c = ftp_easy_new(&bk->cfg);
    if (!c) return -EIO;
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(c, CURLOPT_INFILESIZE, 0L);
    curl_easy_setopt(c, CURLOPT_READFUNCTION, read_cb);
    curl_easy_setopt(c, CURLOPT_READDATA, &rb);

    CURLcode res = backend_perform(bk, c);
    long resp = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &resp); /* 须在 cleanup 前取 */
    curl_easy_cleanup(c);
    if (res != CURLE_OK) {
        /* 创建失败：服务器应答过的（550 已存在/无权限等）是业务失败，不计
           熔断不重建；仅后端不可达计入（分类见 res_is_unavailable） */
        reset_curl(bk, res_is_unavailable(res, resp));
        return -EIO;
    }
    ftp_stat_cache_clear(bk); /* 空文件已创建：整表失效 */
    ftp_list_cache_clear(bk); /* 新条目出现：LIST 缓存失效 */
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
        /* 随机跳变竞态：perform 期间 read 可能已把缓冲重置到新偏移（置
           dl_restart），本次传输的 EOF/错误结论对应的是已作废的旧偏移，
           必须整体丢弃——否则陈旧 rbuf_eof 会被套到新偏移上，read 直接
           走 EOF 分支静默返回 0 字节（随机 pread 假短读）。丢弃后由循环
           顶部的 restart 分支按新偏移重建缓冲并重新下载。 */
        if (f->dl_restart) {
            pthread_cond_broadcast(&f->dl_cond);
            pthread_mutex_unlock(&f->f_lock);
            continue;
        }
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
        int r = (n < 0) ? -errno : 0;
        if (n >= 0) *got = (size_t)n;
        ftp_handle_put(h, f);
        return r;
    }
    if (size == 0) {
        *got = 0;
        ftp_handle_put(h, f);
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
    ftp_handle_put(h, f);
    return rc;
}

/* S4 流式上传前向声明（实现位于 ftp_backend_upload 之前，write 先于其调用） */
static int ftp_stream_chunk(FtpBackendFile* f, const char* data, size_t len, bool append);
static void* ftp_up_thread(void* arg);

int ftp_backend_write(uint64_t h, const char* buf, size_t size, off_t off, size_t* wrote) {
    FtpBackendFile* f = ftp_handle_get(h);
    if (!f || !buf || !wrote) return -EINVAL;
    if (f->tmp_fd < 0) {
        ftp_handle_put(h, f);
        return -EBADF;
    }
    pthread_mutex_lock(&f->f_lock);
    /* S4 乱序检测：改写已流式上传的前缀（off < up_upto）→ 已传字节作废，
       流式无法覆盖，置 retransmit 转全量重传（flush STOR 覆盖）；
       off >= up_upto 的随机写仍由 tmp_fd 兜底（未上传区域可继续 APPE） */
    if (off < f->up_upto) f->retransmit = true;
    /* 本轮写使本地内容再次领先远端：清除同步标记。FLUSH 在 dup/fork 下会被
       多次调用（每次 close 一次），FLUSH 之后仍可从存活的 fd 继续写，那些
       数据同样必须上传——旧实现只置位不清除，第二次 FLUSH 会被全量补传的
       uploaded 早退挡掉，数据静默丢失 */
    f->uploaded = false;
    /* 懒启动上传线程（首个写才建线程；失败退化为全量上传兜底）。
       up_stop 在此清零：上一轮 FLUSH 已让线程退出，新数据到来须重新起一轮
       流式同步；up_error/retransmit 时不起（等收尾同步做全量重传） */
    if (!f->up_started && !f->retransmit && !f->up_error) {
        f->up_stop = false;
        if (pthread_create(&f->up_tid, NULL, ftp_up_thread, f) == 0) f->up_started = true;
    }
    pthread_mutex_unlock(&f->f_lock);

    ssize_t n = pwrite(f->tmp_fd, buf, size, off);
    if (n < 0) {
        int e = errno;
        ftp_handle_put(h, f);
        return -e;
    }
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
    ftp_handle_put(h, f);
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
   独立 write_curl 句柄（不走控制面 mux，故与其他 STOR 天然互不竞争）；
   失败指数退避重试（吸收网络瞬态），仍失败置 up_error 转全量重传兜底。
   调用方不持 f_lock（curl perform 可能长时间阻塞）。 */
static int ftp_stream_chunk(FtpBackendFile* f, const char* data, size_t len, bool append) {
    if (!f->write_curl) f->write_curl = ftp_easy_new(&f->bk->cfg);
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
    long resp = 0;
    curl_easy_getinfo(f->write_curl, CURLINFO_RESPONSE_CODE, &resp); /* 须在 cleanup 前取 */
    curl_easy_cleanup(f->write_curl); /* 失败句柄可能已半损坏，重建 */
    f->write_curl = NULL;
    /* 分类见 res_is_unavailable：仅后端不可达计熔断——STOR 550（配额/权限
       等服务器已应答）是业务失败，不计（避免误杀） */
    if (res_is_unavailable(res, resp)) mark_failure(f->bk);
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
        /* 首块 STOR（截断创建）、其后 APPE：标记存在句柄上而非线程局部量。
           线程在 FLUSH 后退出、后续写入再起新一轮，若用局部量会把尾块当首块
           STOR——服务器文件被截成只剩尾块，已上传的前缀丢失 */
        bool append = !f->up_first;
        pthread_mutex_unlock(&f->f_lock);

        ssize_t got = pread(f->tmp_fd, buf, want, off);
        if (got <= 0) {
            pthread_mutex_lock(&f->f_lock);
            f->up_error = true;
            pthread_cond_broadcast(&f->up_cond);
            pthread_mutex_unlock(&f->f_lock);
            break;
        }
        if (ftp_stream_chunk(f, buf, (size_t)got, append) != 0) {
            pthread_mutex_lock(&f->f_lock);
            f->up_error = true;
            pthread_cond_broadcast(&f->up_cond);
            pthread_mutex_unlock(&f->f_lock);
            break;
        }
        pthread_mutex_lock(&f->f_lock);
        f->up_first = false; /* 首块已推：后续增量一律 APPE */
        f->up_upto = off + (off_t)got;
        pthread_cond_broadcast(&f->up_cond); /* 背压解除 / flush 追平通知 */
        pthread_mutex_unlock(&f->f_lock);
    }
    free(buf);
    return NULL;
}

/* 写模式上传：把本地临时文件全量推送到远端，**内存恒定、不持 f_lock 做网络 I/O**。
   成功置 uploaded；FLUSH（同步收尾）与 RELEASE（防御补传）共用。

   旧实现的两个缺陷（review A26-④）：
   ① 全程持 f_lock 做网络 I/O（最多 5 次重试 + 指数退避，单次可长达数秒），
      同一句柄的 read/write 在此期间全部阻塞——FUSE worker 被长时间占用；
   ② `malloc((size_t)sz)` 把整个文件读进内存（2GB 改写 = 2GB 常驻），
      OOM 时直接 -ENOMEM 返回，数据既不落远端也无重试。

   新做法：**锁内只取快照**（大小、tmp_fd、write_curl），随后释放 f_lock，
   在锁外按 FTP_UP_CHUNK 分块 pread + STOR/APPE 推送（复用 ftp_stream_chunk
   的重试与熔断分类），最后再短暂持锁发布结果。
   半写语义：中途失败时远端留下已推前缀（部分文件），此时置 up_error 且
   uploaded=false，由下一次 FLUSH/RELEASE 重试全量——绝不谎报成功。
   返回 0 成功，负值 errno 风格。 */
static int ftp_backend_upload(FtpBackendFile* f) {
    pthread_mutex_lock(&f->f_lock);
    /* 是否需要上传由调用方（ftp_write_sync）判定，此处只挡「非写模式」与
       「本地缓存已被 RELEASE 回收」两态。用 uploaded 早退会让「FLUSH 置位后
       又写入」的补传被静默跳过——数据不落远端（dup/fork 下的数据丢失根因） */
    if (!f->writing || f->tmp_fd < 0) {
        pthread_mutex_unlock(&f->f_lock);
        return 0; /* 无需上传 */
    }
    off_t sz = lseek(f->tmp_fd, 0, SEEK_END);
    if (sz < 0 || lseek(f->tmp_fd, 0, SEEK_SET) < 0) {
        pthread_mutex_unlock(&f->f_lock);
        return -EIO;
    }
    /* 句柄缓存到文件上（同文件多次 FLUSH/补传复用连接池） */
    if (!f->write_curl) f->write_curl = ftp_easy_new(&f->bk->cfg);
    bool have_curl = (f->write_curl != NULL);
    int tmp_fd = f->tmp_fd; /* 句柄在本函数结束前不会被 RELEASE 拆除（调用方持引用） */
    pthread_mutex_unlock(&f->f_lock);

    if (!have_curl) return -EIO;
    if (sz == 0) {
        /* 空文件：仍须发一次 STOR 截断（否则 TRUNC 到 0 的远端仍保留旧内容） */
        int r0 = ftp_stream_chunk(f, "", 0, false);
        pthread_mutex_lock(&f->f_lock);
        if (r0 == 0) {
            f->uploaded = true;
            f->up_upto = f->file_end = 0;
            f->up_first = false;
            f->retransmit = f->up_error = false;
        } else {
            f->uploaded = false;
            f->up_error = f->retransmit = true;
        }
        pthread_mutex_unlock(&f->f_lock);
        if (r0 == 0) {
            mark_success(f->bk);
            ftp_stat_cache_clear(f->bk);
            ftp_list_cache_clear(f->bk);
        }
        return r0;
    }

    char* buf = malloc(FTP_UP_CHUNK);
    if (!buf) return -ENOMEM;
    int rc = 0;
    off_t off = 0;
    bool first = true; /* 首块 STOR（截断创建），其后 APPE（追加） */
    while (off < sz) {
        size_t want = (size_t)(sz - off);
        if (want > FTP_UP_CHUNK) want = FTP_UP_CHUNK;
        size_t got = 0;
        /* 单次 pread 可能读不满（内核单次返回量上限/信号中断）：循环补齐 */
        while (got < want) {
            ssize_t n = pread(tmp_fd, buf + got, want - got, off + (off_t)got);
            if (n < 0) {
                if (errno == EINTR) continue;
                rc = -EIO;
                break;
            }
            if (n == 0) break; /* 文件被截短：按已得部分继续（尾部会由下一轮同步补齐） */
            got += (size_t)n;
        }
        if (rc != 0) break;
        if (got == 0) break;
        if (ftp_stream_chunk(f, buf, got, !first) != 0) {
            rc = -EIO;
            break;
        }
        first = false;
        off += (off_t)got;
    }
    free(buf);

    pthread_mutex_lock(&f->f_lock);
    if (rc == 0 && off == sz) {
        /* 全量覆盖成功：远端内容 == 本地内容，流式状态复位（此后增量走 APPE，
           乱序/出错标记清除，流式上传可恢复） */
        f->uploaded = true;
        f->up_upto = off;
        f->up_first = false;
        f->retransmit = false;
        f->up_error = false;
    } else {
        /* 中途失败（或未推完）：远端可能留下部分前缀。标记重传，让下一次
           同步再试；uploaded 保持 false，不谎报成功（否则收尾路径会走
           「零开销」早退，残缺文件被当成已同步） */
        f->uploaded = false;
        f->up_error = true;
        f->retransmit = true;
        if (rc == 0) rc = -EIO; /* 未推完同样算失败 */
    }
    pthread_mutex_unlock(&f->f_lock);

    if (rc == 0) {
        mark_success(f->bk);         /* 上传成功：清零熔断计数（网络恢复退出静默） */
        ftp_stat_cache_clear(f->bk); /* STOR 完成：整表失效，杜绝写后旧 stat */
        ftp_list_cache_clear(f->bk); /* 新条目出现：LIST 缓存失效 */
    }
    return rc;
}

/* 写模式收尾同步（FLUSH 与 RELEASE 共用）：
   ① 流式上传线程在跑 → 请求追平并 join（乱序/出错时线程已自行退出）；
   ② 仍未追平（乱序改写 / 流式出错 / 线程未起就跑完）→ 全量 STOR 重传覆盖；
   ③ 已追平 → 标记「本地与远端同步」并清 stat/LIST 缓存。
   tmp_fd 保留到 RELEASE：FLUSH 之后仍可从存活的 fd 继续写（dup/fork 场景），
   那些数据由下一次同步（通常是 RELEASE）续传。返回 0 成功，负值 errno 风格。 */
static int ftp_write_sync(FtpBackendFile* f) {
    if (f->up_started) {
        pthread_mutex_lock(&f->f_lock);
        /* 复查 up_started：两个 FLUSH 并发（vfs_fsync 与 vfs_flush 同时到达，
           或 dup/fork 下多个 close）时，先到者已 join 并把 up_started 清 false；
           后到者若不再复查就会对同一 tid 再次 pthread_join → UB（tid 可能已
           被复用，join 到无关线程或永久挂起）。
           复查与 up_tid 捕获同临界区：要么本线程拿到 up_started==true 并成为
           唯一的 join 者，要么直接跳过。 */
        if (!f->up_started) {
            pthread_mutex_unlock(&f->f_lock);
        } else {
            f->up_stop = true; /* 追平剩余尾部后退出 */
            pthread_cond_broadcast(&f->up_cond);
            while (f->up_upto < f->file_end && !f->retransmit && !f->up_error)
                pthread_cond_wait(&f->up_cond, &f->f_lock);
            f->up_started = false; /* 先清标志再放锁：另一个 join 者立即看到并跳过 */
            pthread_t tid = f->up_tid;
            pthread_mutex_unlock(&f->f_lock);
            pthread_join(tid, NULL);
        }
    }
    /* 尾部判定读 up_upto/file_end 等状态：释放 f_lock 前后保持一致快照——
       撕裂读会跳过最后一次全量重传，尾部数据不落远端。故在同一临界区内取快照 */
    pthread_mutex_lock(&f->f_lock);
    bool need_full = f->retransmit || f->up_error || f->up_upto < f->file_end;
    bool already = f->uploaded;
    if (!need_full && !already) {
        f->uploaded = true;
    }
    pthread_mutex_unlock(&f->f_lock);
    if (need_full) return ftp_backend_upload(f); /* 乱序/出错/未追平：全量重传覆盖 */
    if (!already) {
        mark_success(f->bk);
        ftp_stat_cache_clear(f->bk); /* 流式 STOR/APPE 完成：整表失效 */
        ftp_list_cache_clear(f->bk); /* 新条目出现：LIST 缓存失效 */
    }
    return 0;
}

/* FLUSH 数据收尾：写模式同步尾部上传但**保留句柄**——FUSE 的 FLUSH 在
   每次 close() 调用（dup/fork 可多次），句柄销毁必须等 RELEASE（最后一个
   引用关闭后），否则存活 fd 的后续读写会命中已销毁句柄（-EINVAL）；
   读模式无操作。返回 0 成功。
   可重入：多线程同时 FLUSH（fsync+flush 并发 / dup 多份 close）不会 double
   join——见 ftp_write_sync 内的 up_started 复查。 */
int ftp_backend_flush(uint64_t h) {
    FtpBackendFile* f = ftp_handle_get(h);
    if (!f) return -EINVAL;
    int rc = 0;
    if (f->writing) rc = ftp_write_sync(f);
    ftp_handle_put(h, f);
    return rc;
}

/* 句柄最终拆除（release 与最后一个在途一起走到才执行；见 .refs 注释）。
   内含：停止/join 读写线程、归还 curl 句柄、销毁同步原语、free(f)。 */
static void ftp_handle_destroy_final(FtpBackendFile* f) {
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
    free(f);
}

/* 释放句柄（最后一个 close/RELEASE）。
   两阶段拆除（修 A26-④⑥）：先把句柄从表内摘除并置 dead（此后新 get 一律
   拒绝——新 open 拿不到旧句柄），再把自己的引用还掉；**真正 free 由
   "refs 归零的那个线程"执行**。这样在途 write/flush 不会执行到已 free 的句柄，
   也不存在"两个 FLUSH 对同一 tid 双 join"（join 与 free 只在最后一次性做）。 */
int ftp_backend_release(uint64_t h) {
    FtpBackendFile* f = ftp_handle_get(h);
    if (!f) return -EINVAL;
    int rc = 0;

    /* S4：写模式最后同步一次（内部先停止并 join 流式上传线程，确保随后的
       全量补传不再有并发读 tmp_fd）。FLUSH 之后仍可能从存活的 dup fd 写入
       （每次 close 触发一次 FLUSH），那些数据必须在这里补传；已同步且无新
       写入时该调用零网络开销 */
    if (f->writing && (f->up_started || !f->uploaded || f->up_upto < f->file_end)) {
        if (ftp_write_sync(f) != 0) rc = -EIO;
    }

    /* 摘表 + 置 dead：此后没有任何新使用者能拿到本句柄 */
    pthread_mutex_lock(&g_handles_mutex);
    if (g_handles[h] == f) {
        g_handles[h] = NULL;
        atomic_fetch_sub_explicit(&g_active_handles, 1, memory_order_acq_rel);
    }
    f->dead = true;
    pthread_mutex_unlock(&g_handles_mutex);

    /* 归还自己的引用；若此时仍无其他在途者，本调用即执行最终拆除 */
    ftp_handle_put(h, f);
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
    if (backend_ready(bk) != 0) return -EIO;
    char url[2048], parent[2048], cmd[4096];
    build_url(bk, path, url, sizeof url);
    if (url[0] == '\0') return -ENAMETOOLONG; /* 路径过长组不出 URL（业务 errno，不熔断） */
    ftp_parent_url(url, parent, sizeof parent);
    snprintf(cmd, sizeof cmd, fmt, ftp_filename(url));
    struct curl_slist* slist = curl_slist_append(NULL, cmd);
    struct WriteBuf wb = {0};
    wb.auto_grow = true;
    CURL* c = ftp_easy_new(&bk->cfg);
    if (!c) {
        curl_slist_free_all(slist);
        return -EIO;
    }
    curl_easy_setopt(c, CURLOPT_POSTQUOTE, slist);
    curl_easy_setopt(c, CURLOPT_URL, parent);
    curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &wb);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    CURLcode res = backend_perform(bk, c);
    long resp = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &resp); /* 须在 cleanup 前取 */
    curl_easy_cleanup(c);
    curl_slist_free_all(slist);
    free(wb.buf);
    /* 失败：按 ok_code 映射预期错误（rmdir 非空目录 → -ENOTEMPTY），
       未指定（unlink/mkdir）则统一 -EPERM（curlftpfs 方式） */
    if (res != CURLE_OK) {
        /* 服务器应答过的（550 路径不存在/非空等）是业务失败：不计熔断不
           重建；仅后端不可达计入（分类见 res_is_unavailable） */
        reset_curl(bk, res_is_unavailable(res, resp));
        return ok_code ? -ok_code : -EPERM;
    }
    ftp_stat_cache_clear(bk); /* DELE/MKD/RMD 成功：整表失效 */
    ftp_list_cache_clear(bk); /* 条目增删：LIST 缓存失效 */
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
    if (backend_ready(bk) != 0) return -EIO;
    /* 跨 server rename：一个 ftp_module 可注册多个 server，框架侧只校验
       「同一模块」（bf_ops == bt_ops），到不了 server 粒度。RNFR/RNTO 只能落在
       同一条控制连接上，若 to 属于另一个 server，旧实现会把文件留在 from 的
       server 上、改名为 to 的**远程路径**——应用以为搬到了另一个挂载点，两边
       都不对。此处显式拒绝：EXDEV 是「跨设备搬移」的既有语义，与应用可见的
       真实语义一致（不是同一存储，无法原地改名）。 */
    if (ftp_backend_find(to) != bk) return -EXDEV;
    char from_url[2048], to_url[2048], from_path[2048], to_path[2048], parent[2048], cmd1[4096],
        cmd2[4096];
    build_url(bk, from, from_url, sizeof from_url);
    build_url(bk, to, to_url, sizeof to_url);
    if (from_url[0] == '\0' || to_url[0] == '\0')
        return -ENAMETOOLONG; /* 路径过长组不出 URL（业务 errno，不熔断） */
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
    CURL* c = ftp_easy_new(&bk->cfg);
    if (!c) {
        curl_slist_free_all(slist);
        return -EIO;
    }
    curl_easy_setopt(c, CURLOPT_POSTQUOTE, slist);
    curl_easy_setopt(c, CURLOPT_URL, parent);
    curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
    CURLcode res = backend_perform(bk, c);
    long resp = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &resp); /* 须在 cleanup 前取 */
    curl_easy_cleanup(c);
    curl_slist_free_all(slist);
    if (res != CURLE_OK) {
        /* 服务器应答过的（550 目标已存在/RNFR 无效等）是业务失败：不计
           熔断不重建；仅后端不可达计入（分类见 res_is_unavailable） */
        reset_curl(bk, res_is_unavailable(res, resp));
        return -EIO;
    }
    ftp_stat_cache_clear(bk); /* RNFR/RNTO 成功：整表失效（from/to 均可能被缓存） */
    ftp_list_cache_clear(bk); /* 条目改名：LIST 缓存失效 */
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
        if (backend_ready(bk) != 0) return -EIO;

        char url[2048];
        build_url(bk, path, url, sizeof url);
        if (url[0] == '\0') return -ENAMETOOLONG; /* 路径过长组不出 URL（业务 errno，不熔断） */

        struct ReadBuf rb = {"", 0, 0};
        CURL* c = ftp_easy_new(&bk->cfg);
        if (!c) return -EIO;
        curl_easy_setopt(c, CURLOPT_URL, url);
        curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(c, CURLOPT_INFILESIZE, 0L);
        curl_easy_setopt(c, CURLOPT_READFUNCTION, read_cb);
        curl_easy_setopt(c, CURLOPT_READDATA, &rb);

        CURLcode res = backend_perform(bk, c);
        long resp = 0;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &resp); /* 须在 cleanup 前取 */
        curl_easy_cleanup(c);
        if (res != CURLE_OK) {
            /* 服务器应答过的（550 等）是业务失败：不计熔断不重建；仅后端
               不可达计入（分类见 res_is_unavailable） */
            reset_curl(bk, res_is_unavailable(res, resp));
            return -EIO;
        }
        ftp_stat_cache_clear(bk); /* STOR 空文件截断成功：整表失效 */
        ftp_list_cache_clear(bk); /* 目录条目大小随之变化：LIST 缓存一并失效，
                                     否则后续列举会把旧 size 回灌进 stat 缓存 */
        return 0;
    }
    return -EIO; // 非零截断暂不支持
}

/* ================= 模块注册接口 =================

libcurl 后端函数通过 ftp_backend.h 暴露给 ftp_module.c，
由 ftp_module.c 注册到 NspModuleOps 中。无需单独注册函数。 */
