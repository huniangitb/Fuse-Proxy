#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <sys/epoll.h>
#include <stddef.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/inotify.h>
#include <sys/timerfd.h>
#include <fnmatch.h>
#include <sys/uio.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include "common.h"
#include "nsp_comm.h"
#include "nsp_util.h"
#define MAX_MSG_LEN 4096
/* 滑动日志缓冲：按字节上限控制（超出丢弃最旧日志）。
   IO 日志最大 128MB，普通日志（sys/logcat）各 16MB。
   条数上限 = 字节上限 / 单条固定大小（LogEntry ≈ MAX_MSG_LEN+16），
   数组内存 ≈ 字节上限（取代旧版 52 万/20 万条 ≈ 2.1GB/800MB 的预分配）。 */
#define MAX_IO_LOG_BYTES     (128u * 1024u * 1024u)
#define MAX_SYS_LOG_BYTES    (16u * 1024u * 1024u)
#define MAX_LOGCAT_LOG_BYTES (16u * 1024u * 1024u)
#define MAX_IO_LOGS     (MAX_IO_LOG_BYTES / (MAX_MSG_LEN + 16))
#define MAX_SYS_LOGS    (MAX_SYS_LOG_BYTES / (MAX_MSG_LEN + 16))
#define MAX_LOGCAT_LOGS (MAX_LOGCAT_LOG_BYTES / (MAX_MSG_LEN + 16))
#define DEFAULT_LIMIT 500
#define MAX_EVENTS 256
#define RING_CAP 16384
typedef struct AsyncCtx {
    int fd;
    int type;               /* 0=undef, 1=IO, 2=SYS, 3=LOGCAT */
    pthread_t tid;
    volatile bool disconnected;
    struct { char msg[512]; int level; int type; } entries[RING_CAP];
    volatile int head;
    volatile int tail;
    int notify_fd;
    /* 粘包移交缓冲：主循环一次 read 读到首行 LOG_SYS 转 async 后，buf 中
       剩余字节（如紧跟的 LOG_BATCH 帧）移交至此，async_log_thread 先处理。
       在 process_line 内、pthread_create 之前填充，避免线程先跑读空 */
    char pending[4096];
    int pending_len;
    /* 合并日志多槽队列：LOG_BATCH 合并内容可超过 entries.msg 的 512 上限，
       且连续多个合并周期（背靠背 LOG_BATCH 帧）不能互相覆盖。
       head 仅 async_log_thread 写、tail 仅主循环 drain_async 读（无锁环形）。
       drain_async 将每槽 push 入 g_sys_buf（MAX_MSG_LEN=4096），
       避免 UTF-8 截断乱码 */
#define BATCH_Q_CAP 4
    struct { char msg[MAX_MSG_LEN]; int len; } batch_q[BATCH_Q_CAP];
    volatile int batch_q_head;
    volatile int batch_q_tail;
    struct AsyncCtx *next;
} AsyncCtx;

static int set_nonblock(int fd);
static int set_block(int fd);
typedef enum {
    OP_NONE     = 0,
    OP_OPEN     = 1 << 0,
    OP_CREATE   = 1 << 1,
    OP_WRITE    = 1 << 2,
    OP_READ     = 1 << 3,
    OP_UNLINK   = 1 << 4,
    OP_MKDIR    = 1 << 5,
    OP_RMDIR    = 1 << 6,
    OP_RENAME   = 1 << 7,
    OP_GETATTR  = 1 << 8,
    OP_ACCESS   = 1 << 9,
    OP_TRUNCATE = 1 << 10,
    OP_UTIMENS  = 1 << 11,
    OP_CHMOD    = 1 << 12,
    OP_CHOWN    = 1 << 13,
    OP_READLINK = 1 << 14,
    OP_STATFS   = 1 << 15,
    OP_OPENDIR  = 1 << 16,
    OP_READDIR  = 1 << 17,
} IoOpMask;
typedef struct ClientCtx {
    int fd;
    char line[1536];
    size_t pos;
    struct timespec start_time;
    bool is_streaming;
    bool stream_del_posted;   /* STOP 路径已投递 DEL，外层关闭路径不再重复投递 */
    struct ClientCtx *next;
    struct ClientCtx *prev;
} ClientCtx;
typedef struct IgnoreRule {
    int op_mask;
    char *path_prefix;
    bool is_wildcard;
    struct IgnoreRule *next;
} IgnoreRule;
typedef struct {
    time_t t;
    int level;
    char msg[MAX_MSG_LEN];
} LogEntry;
typedef struct {
    LogEntry* data;
    int head, tail;
    bool full;
    int max;
} LogBuffer;
typedef struct StreamClient {
    int fd;
    int type;       /* 0=ALL, 1=IO, 2=SYS, 3=LOGCAT */
    int min_level;
    bool level_tag; /* true = SYS 消息前插 LEVEL| 标签（api 模式） */
    bool with_ts;   /* true = 推送行前缀时间戳（STREAM_*:<level>:1 启用） */
    struct StreamClient *next;
} StreamClient;
static LogBuffer g_io_buf, g_sys_buf, g_logcat_buf;
static bool should_ignore_io(const char *line);
static volatile sig_atomic_t g_should_exit = 0;
static int g_server_sock = -1;
static IgnoreRule *g_ignore_rules = nullptr;
static StreamClient *g_stream_clients = nullptr;
static ClientCtx *g_active_clients = nullptr;
static AsyncCtx *g_async_clients = nullptr;
static int g_epoll_fd = -1;
static void init_buf(LogBuffer* buf, int max) {
    buf->data = calloc(max, sizeof(LogEntry));
    buf->head = buf->tail = 0;
    buf->full = false;
    buf->max = max;
}
static void destroy_buf(LogBuffer* buf) {
    if (buf->data) { free(buf->data); buf->data = nullptr; }
}
/* 订阅集合仅 comm 线程触碰（主线程一律 post 'A'/'D'）：'D' 在此同步 close，
   主线程只 shutdown，不断号故无 fd 复用竞态 */
static void remove_stream_client(int fd) {
    StreamClient **pp = &g_stream_clients;
    while (*pp) {
        if ((*pp)->fd == fd) {
            StreamClient *tmp = *pp; *pp = (*pp)->next;
            close(tmp->fd);
            free(tmp);
            break;
        }
        pp = &(*pp)->next;
    }
}
/* 解析 STREAM_* 可选参数 "<level>[:<with_ts>]"：返回 level，with_ts 出参（1=附带时间戳） */
static int parse_stream_args(const char *p, bool *with_ts) {
    *with_ts = false;
    int level = atoi(p);
    const char *ts_p = strchr(p, ':');
    if (ts_p) *with_ts = (atoi(ts_p + 1) > 0);
    return level;
}

/* BCAST 通道载荷（客户端集合归 comm 线程所有，主线程只 post）：
   'L' + type:1 + level:4 + t:8 + 行字节 —— 实时推送（过滤/组帧在 comm 侧）
   'A' + type:1 + min_level:4 + level_tag:1 + with_ts:1 + fd:4 —— 订阅加入
   'D' + fd:4 —— 订阅移除并由 comm 线程 close（主线程仅 shutdown，不断号防复用） */
static void stream_post_add(int fd, int type, int min_level, bool level_tag, bool with_ts) {
    uint8_t buf[1 + 1 + 4 + 1 + 1 + 4];
    buf[0] = 'A';
    buf[1] = (uint8_t)type;
    memcpy(buf + 2, &min_level, 4);
    buf[6] = level_tag ? 1 : 0;
    buf[7] = with_ts ? 1 : 0;
    memcpy(buf + 8, &fd, 4);
    nsp_comm_post(NSP_CH_BCAST, buf, sizeof(buf));
}

static void stream_post_del(int fd) {
    uint8_t buf[1 + 4];
    buf[0] = 'D';
    memcpy(buf + 1, &fd, 4);
    nsp_comm_post(NSP_CH_BCAST, buf, sizeof(buf));
}

static void broadcast_log(int type, const char *line, int level, time_t t) {
    size_t len = strlen(line);
    size_t total = 1 + 1 + 4 + 8 + len + 1;
    uint8_t *buf = malloc(total);
    if (!buf) return;
    buf[0] = 'L';
    buf[1] = (uint8_t)type;
    memcpy(buf + 2, &level, 4);
    memcpy(buf + 6, &t, 8);
    memcpy(buf + 14, line, len + 1);
    nsp_comm_post(NSP_CH_BCAST, buf, total);
    free(buf);
}

/* 后端（comm 线程）：STREAM 客户端集合的唯一读写者 */
static int stream_emit(void *ctx, const void *data, size_t len) {
    (void)ctx;
    if (len < 1) return 0;
    const uint8_t *p = data;
    if (p[0] == 'A') {
        if (len < 12) return 0;
        int fd;
        int min_level;
        memcpy(&min_level, p + 2, 4);
        memcpy(&fd, p + 8, 4);
        for (StreamClient *e = g_stream_clients; e; e = e->next) {
            if (e->fd == fd) { /* 重复加入：更新属性（幂等） */
                e->type = p[1]; e->min_level = min_level;
                e->level_tag = p[6] ? true : false;
                e->with_ts = p[7] ? true : false;
                return 0;
            }
        }
        StreamClient *c = malloc(sizeof(StreamClient));
        if (!c) return 0;
        c->fd = fd; c->type = p[1]; c->min_level = min_level;
        c->level_tag = p[6] ? true : false;
        c->with_ts = p[7] ? true : false;
        c->next = g_stream_clients; g_stream_clients = c;
        return 0;
    }
    if (p[0] == 'D') {
        if (len < 5) return 0;
        int fd;
        memcpy(&fd, p + 1, 4);
        remove_stream_client(fd);   /* comm 线程内同步 close（不断号，无复用竞态） */
        return 0;
    }
    if (p[0] != 'L' || len < 15) return 0;
    int type = p[1];
    int level;
    time_t t;
    memcpy(&level, p + 2, 4);
    memcpy(&t, p + 6, 8);
    const char *line = (const char *)(p + 14);
    size_t llen = len - 15;
    char nl = '\n';
    char level_pref[4]; /* "0|", "1|", "2|", "3|" */
    char ts_buf[32] = {0};
    if (t > 0) {
        struct tm tm_buf;
        localtime_r(&t, &tm_buf);
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    }
    StreamClient *c = g_stream_clients;
    while (c) {
        if (c->fd > 0 && (c->type == 0 || c->type == type)) {
            if (level >= c->min_level) {
                struct iovec iov[5];
                int iovlen = 0;
                if (c->with_ts && ts_buf[0]) {
                    iov[iovlen].iov_base = ts_buf;
                    iov[iovlen].iov_len = 19; /* "YYYY-MM-DD HH:MM:SS" */
                    iovlen++;
                    iov[iovlen].iov_base = (void *)"|";
                    iov[iovlen].iov_len = 1;
                    iovlen++;
                }
                if (type == 2 && c->level_tag) {  /* SYS + api: 前插等级标签 */
                    level_pref[0] = '0' + (level % 10);
                    level_pref[1] = '|';
                    iov[iovlen].iov_base = level_pref;
                    iov[iovlen].iov_len = 2;
                    iovlen++;
                }
                iov[iovlen].iov_base = (void *)line;
                iov[iovlen].iov_len = llen;
                iovlen++;
                iov[iovlen].iov_base = &nl;
                iov[iovlen].iov_len = 1;
                iovlen++;
                struct msghdr msg = { .msg_iov = iov, .msg_iovlen = iovlen };
                ssize_t ret = sendmsg(c->fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
                if (ret <= 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) { close(c->fd); c->fd = -1; }
            }
        }
        c = c->next;
    }
    StreamClient **pp = &g_stream_clients;
    while (*pp) {
        if ((*pp)->fd == -1) { StreamClient *tmp = *pp; *pp = (*pp)->next; free(tmp); }
        else { pp = &(*pp)->next; }
    }
    return 0;
}
/* overflow 应急落盘机制已移除：producer 环满时直接丢弃（见 async 线程注释）；
   持久化统一走 io/sys 自动落盘（persist_*，单文件 2MB 轮转） */
/* ===== io/sys 自动落盘（懒写入 + 单文件 2MB 轮转） =====
   写入路径：push_log（主线程单漏斗）→ 行暂存 64KB stage → 刷盘时机：
   stage 满 / 500ms tick（脏超 1s） / 进程退出。刷盘 open-fstat-rotate-
   write-close 一次批量写完，杜绝逐条 open/write/close。轮转：cur+本批超
   2MB → cur 改名 .1（删旧 .1），每类最多保留 cur + .1（≤4MB），单文件
   严格 ≤2MB。logcat 不落盘。 */
#define PERSIST_FILE_MAX (2u * 1024u * 1024u)
#define PERSIST_STAGE_CAP (64u * 1024u)
#define PERSIST_LAZY_MS 1000
#define PERSIST_FAIL_BACKOFF_MS 5000
typedef struct {
    char path[PATH_MAX];    /* LOG_DIR/io.log */
    char rot[PATH_MAX];     /* LOG_DIR/io.log.1（单备份轮转） */
    char *stage;
    size_t staged;
    uint64_t last_flush_ms;
    uint64_t fail_until_ms; /* 磁盘失败退避：到期前跳过 open 尝试 */
    uint64_t dropped;       /* 磁盘不可写时丢弃批次数 */
} PersistWriter;
static PersistWriter g_persist_io;
static PersistWriter g_persist_sys;

static uint64_t persist_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void persist_init_writer(PersistWriter *w, const char *name) {
    snprintf(w->path, sizeof(w->path), "%s/%s.log", LOG_DIR, name);
    snprintf(w->rot, sizeof(w->rot), "%s/%s.log.1", LOG_DIR, name);
    w->stage = malloc(PERSIST_STAGE_CAP);
    w->staged = 0;
    w->last_flush_ms = persist_now_ms();
    w->fail_until_ms = 0;
    w->dropped = 0;
}

/* 刷盘：open → fstat 校准 → 超限轮转 → 全量写出 → close。失败退避，下轮
   重试；磁盘不可写时丢弃本批（内存链路不受影响，dropped 计数）。 */
static void persist_flush(PersistWriter *w) {
    if (!w->stage || w->staged == 0) return;
    uint64_t now = persist_now_ms();
    if (now < w->fail_until_ms) { w->staged = 0; w->dropped++; return; }
    int fd = open(w->path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) { w->fail_until_ms = now + PERSIST_FAIL_BACKOFF_MS; w->staged = 0; w->dropped++; return; }
    struct stat st;
    uint64_t cur = (fstat(fd, &st) == 0 && st.st_size > 0) ? (uint64_t)st.st_size : 0;
    if (cur + w->staged > PERSIST_FILE_MAX) {
        close(fd);
        unlink(w->rot);
        rename(w->path, w->rot);
        fd = open(w->path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (fd < 0) { w->fail_until_ms = now + PERSIST_FAIL_BACKOFF_MS; w->staged = 0; w->dropped++; return; }
    }
    size_t off = 0;
    while (off < w->staged) {
        ssize_t n = write(fd, w->stage + off, w->staged - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        off += (size_t)n;
    }
    close(fd);
    if (off < w->staged) { w->fail_until_ms = now + PERSIST_FAIL_BACKOFF_MS; w->dropped++; }
    w->staged = 0;
    w->last_flush_ms = now;
}

static void persist_stage(PersistWriter *w, const char *msg, int level, time_t t) {
    if (!w->stage) return;
    struct tm tm_buf;
    localtime_r(&t, &tm_buf);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);
    char line[MAX_MSG_LEN + 128];
    int len = snprintf(line, sizeof(line), "%s|%d|%s\n", ts, level, msg);
    if (len <= 0) return;
    /* 截断时强制尾部换行，避免与下一行拼接成无换行超长行 */
    if ((size_t)len >= sizeof(line)) {
        len = sizeof(line) - 1;
        line[len - 1] = '\n';
    }
    if (w->staged + (size_t)len > PERSIST_STAGE_CAP) persist_flush(w);
    if (w->staged + (size_t)len > PERSIST_STAGE_CAP) { w->dropped++; return; }
    memcpy(w->stage + w->staged, line, (size_t)len);
    w->staged += (size_t)len;
}

/* 懒刷盘：500ms tick 调用，脏数据超 1s 未刷则写出（低频场景最多延迟 1s+） */
static void persist_lazy_tick(void) {
    uint64_t now = persist_now_ms();
    if (g_persist_io.staged > 0 && now - g_persist_io.last_flush_ms >= PERSIST_LAZY_MS)
        persist_flush(&g_persist_io);
    if (g_persist_sys.staged > 0 && now - g_persist_sys.last_flush_ms >= PERSIST_LAZY_MS)
        persist_flush(&g_persist_sys);
}

/* ===== 启动时加载落盘快照（只读独立缓冲） =====
   io.log.1 → io.log（先旧后新）解析为线性数组（oldest→newest），上限
   DISK_LOAD_MAX 条/类（滑动保留最新，超限丢弃最旧）。与内存环无重叠
   （内存启动时为空），客户端获取时拼接：磁盘在前、内存在后。
   行格式 ts|level|msg（与落盘格式一致），解析失败跳过。 */
#define DISK_LOAD_MAX 2048
typedef struct {
    LogEntry *data;   /* oldest→newest 线性数组，启动后只读 */
    int count;
} DiskLogBuf;
static DiskLogBuf g_io_disk = {0};
static DiskLogBuf g_sys_disk = {0};

static time_t parse_log_ts(const char *ts) {
    int Y, M, D, h, m, s;
    if (sscanf(ts, "%d-%d-%d %d:%d:%d", &Y, &M, &D, &h, &m, &s) != 6) return (time_t)0;
    if (Y < 1970 || M < 1 || M > 12 || D < 1 || D > 31 || h > 23 || m > 59 || s > 61)
        return (time_t)0;
    struct tm tm = {0};
    tm.tm_year = Y - 1900; tm.tm_mon = M - 1; tm.tm_mday = D;
    tm.tm_hour = h; tm.tm_min = m; tm.tm_sec = s;
    tm.tm_isdst = -1;
    time_t t = mktime(&tm);
    return t < 0 ? (time_t)0 : t;
}

static void disk_load_file(LogEntry *ring, int *total, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char line[MAX_MSG_LEN + 128];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;
        char *p1 = strchr(line, '|');
        if (!p1) continue;
        char *p2 = strchr(p1 + 1, '|');
        if (!p2) continue;
        *p1 = '\0';                                   /* ts 段 */
        int level = atoi(p1 + 1);
        const char *msg = p2 + 1;
        time_t t = parse_log_ts(line);
        if (t == 0 || !msg[0]) continue;
        LogEntry *e = &ring[(*total) % DISK_LOAD_MAX];
        e->t = t;
        e->level = level;
        strncpy(e->msg, msg, MAX_MSG_LEN - 1);
        e->msg[MAX_MSG_LEN - 1] = '\0';
        (*total)++;
    }
    fclose(fp);
}

static void disk_load(DiskLogBuf *d, const char *rot_path, const char *cur_path) {
    LogEntry *ring = calloc(DISK_LOAD_MAX, sizeof(LogEntry));
    if (!ring) return;
    int total = 0;
    disk_load_file(ring, &total, rot_path);   /* 先旧（.1） */
    disk_load_file(ring, &total, cur_path);   /* 后新 */
    int n = total < DISK_LOAD_MAX ? total : DISK_LOAD_MAX;
    d->data = malloc((size_t)n * sizeof(LogEntry));
    if (!d->data) { free(ring); d->count = 0; return; }
    int start = total < DISK_LOAD_MAX ? 0 : total % DISK_LOAD_MAX;
    for (int i = 0; i < n; i++)
        d->data[i] = ring[(start + i) % DISK_LOAD_MAX];
    d->count = n;
    free(ring);
}

static void push_log(LogBuffer* buf, const char* msg, int type, int level) {
    time_t now = time(nullptr);
    broadcast_log(type, msg, level, now);
    if (buf->full) {
        /* 滑动缓冲：已满（达到字节/条数上限）时覆盖最旧——丢弃最旧日志，
           tail 前进腾位，新条目覆盖原 head 位置（不再写溢出文件） */
        buf->tail = (buf->tail + 1) % buf->max;
    }
    buf->data[buf->head].t = now;
    buf->data[buf->head].level = level;
    strncpy(buf->data[buf->head].msg, msg, MAX_MSG_LEN - 1);
    buf->data[buf->head].msg[MAX_MSG_LEN - 1] = '\0';
    buf->head = (buf->head + 1) % buf->max;
    if (buf->head == buf->tail) buf->full = true;
    /* io/sys 自动落盘（logcat 除外）：只暂存，刷盘时机见 persist_lazy_tick */
    if (type == 1) persist_stage(&g_persist_io, msg, level, now);
    else if (type == 2) persist_stage(&g_persist_sys, msg, level, now);
}
static void drain_async(AsyncCtx *ctx) {
    /* 合并日志多槽队列：逐槽 push 入 g_sys_buf（整块可超过 entries.msg
       512 上限，背靠背 LOG_BATCH 帧互不覆盖） */
    while (ctx->batch_q_tail != ctx->batch_q_head) {
        int slot = ctx->batch_q_tail % BATCH_Q_CAP;
        if (ctx->batch_q[slot].len > 0) {
            push_log(&g_sys_buf, ctx->batch_q[slot].msg, 2, LOG_DEBUG);
        }
        ctx->batch_q[slot].len = 0;
        ctx->batch_q_tail++;
    }
    while (ctx->tail != ctx->head) {
        char *msg = ctx->entries[ctx->tail].msg;
        int level = ctx->entries[ctx->tail].level;
        int entry_type = ctx->entries[ctx->tail].type;
        if (entry_type == 1) {
            if (!should_ignore_io(msg))
                push_log(&g_io_buf, msg, 1, LOG_INFO);
        } else if (entry_type == 2) {
            push_log(&g_sys_buf, msg, 2, level);
        } else if (entry_type == 3) {
            push_log(&g_logcat_buf, msg, 3, LOG_INFO);
        }
        ctx->tail = (ctx->tail + 1) & (RING_CAP - 1);
    }
}
static void cleanup_async(AsyncCtx *ctx) {
    AsyncCtx **pp = &g_async_clients;
    while (*pp) {
        if (*pp == ctx) { *pp = ctx->next; break; }
        pp = &(*pp)->next;
    }
    if (ctx->fd >= 0) close(ctx->fd);
    if (ctx->notify_fd >= 0) close(ctx->notify_fd);
    free(ctx);
}
static void *async_log_thread(void *arg) {
    AsyncCtx *ctx = arg;
    char buf[4096];
    char line[MAX_MSG_LEN + 128];   /* 行缓冲须容纳完整合并日志（单行制表符），
                                       否则 511 截断会切坏 UTF-8 中文产生乱码 */
    int pos = 0;
    /* LOG_BATCH 合并包：整块（含多行）合并为一条日志入库，前端只显示一条 */
    int batch_collect = 0;
    char batch_msg[4096] = {0};
    size_t batch_len = 0;
    /* 先处理主循环移交的粘包剩余字节（如 LOG_BATCH 帧），再进入 read 循环 */
    size_t pidx = 0;
    while (pidx < (size_t)ctx->pending_len) {
        char c = ctx->pending[pidx++];
        if (c == '\n') {
            line[pos] = '\0';
            if (pos > 0) {
                char *msg = line;
                if (batch_collect && strncmp(msg, "LOG_BATCH_END", 13) == 0) {
                    batch_collect = 0;
                    if (batch_len > 0) {
                        /* 合并日志入多槽队列（可超过 entries.msg 的 512 上限），
                           背靠背帧互不覆盖，由主循环 drain_async 逐槽 push 入 g_sys_buf */
                        int slot = ctx->batch_q_head % BATCH_Q_CAP;
                        if ((ctx->batch_q_head - ctx->batch_q_tail) < BATCH_Q_CAP) {
                            size_t copy = (batch_len < (int)sizeof(ctx->batch_q[slot].msg))
                                        ? (size_t)batch_len : sizeof(ctx->batch_q[slot].msg) - 1;
                            memcpy(ctx->batch_q[slot].msg, batch_msg, copy);
                            ctx->batch_q[slot].msg[copy] = '\0';
                            ctx->batch_q[slot].len = (int)copy;
                            ctx->batch_q_head++;
                            uint64_t val = 1;
                            write(ctx->notify_fd, &val, sizeof(val));
                        }
                        /* batch_q 满：丢弃本合并包（overflow 机制已移除） */
                    }
                    pos = 0;
                    continue;
                }
                if (!batch_collect && strncmp(msg, "LOG_BATCH", 9) == 0 &&
                    msg[9] == '\0') {
                    batch_collect = 1;
                    batch_len = 0;
                    batch_msg[0] = '\0';
                    pos = 0;
                    continue;
                }
                if (batch_collect) {
                    size_t add = strlen(msg);
                    if (batch_len + add + 2 < sizeof(batch_msg)) {
                        memcpy(batch_msg + batch_len, msg, add);
                        batch_len += add;
                        batch_msg[batch_len++] = '\n';
                        batch_msg[batch_len] = '\0';
                    }
                    pos = 0;
                    continue;
                }
                int level = LOG_INFO;
                if (strncmp(msg, "LOG_IO:", 7) == 0) {
                    ctx->type = 1; msg += 7;
                } else if (strncmp(msg, "LOG_SYS:", 8) == 0) {
                    ctx->type = 2; msg += 8;
                } else if (strncmp(msg, "LOG_LOGCAT:", 11) == 0) {
                    ctx->type = 3; msg += 11;
                }
                if (ctx->type == 2 && msg[0] >= '0' && msg[0] <= '9') {
                    level = msg[0] - '0';
                    char *colon = strchr(msg, ':');
                    if (colon) msg = colon + 1;
                }
                int next = (ctx->head + 1) & (RING_CAP - 1);
                if (next != ctx->tail) {
                    strncpy(ctx->entries[ctx->head].msg, msg, 511);
                    ctx->entries[ctx->head].msg[511] = '\0';
                    ctx->entries[ctx->head].level = level;
                    ctx->entries[ctx->head].type = ctx->type;
                    ctx->head = next;
                    uint64_t val = 1;
                    write(ctx->notify_fd, &val, sizeof(val));
                }
                /* entries 环满：丢弃本条（overflow 机制已移除） */
            }
            pos = 0;
        } else if (pos < (int)sizeof(line) - 1) {
            line[pos++] = c;
        }
    }
    ctx->pending_len = 0;
    while (!ctx->disconnected) {
        ssize_t n = read(ctx->fd, buf, sizeof(buf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                line[pos] = '\0';
                if (pos > 0) {
                    char *msg = line;
                    /* 合并包尾优先判断：LOG_BATCH_END 以 LOG_BATCH 开头，
                       必须先匹配 END，否则会被头判断误吞导致内容永不入库 */
                    if (batch_collect && strncmp(msg, "LOG_BATCH_END", 13) == 0) {
                        batch_collect = 0;
                        if (batch_len > 0) {
                            /* 合并日志入多槽队列（可超过 entries.msg 的 512 上限），
                               背靠背帧互不覆盖，由主循环 drain_async 逐槽 push 入 g_sys_buf */
                            int slot = ctx->batch_q_head % BATCH_Q_CAP;
                            if ((ctx->batch_q_head - ctx->batch_q_tail) < BATCH_Q_CAP) {
                                size_t copy = (batch_len < (int)sizeof(ctx->batch_q[slot].msg))
                                            ? (size_t)batch_len : sizeof(ctx->batch_q[slot].msg) - 1;
                                memcpy(ctx->batch_q[slot].msg, batch_msg, copy);
                                ctx->batch_q[slot].msg[copy] = '\0';
                                ctx->batch_q[slot].len = (int)copy;
                                ctx->batch_q_head++;
                                uint64_t val = 1;
                                write(ctx->notify_fd, &val, sizeof(val));
                            }
                            /* batch_q 满：丢弃本合并包（overflow 机制已移除） */
                        }
                        pos = 0;
                        continue;
                    }
                    /* 合并包头：进入收集模式（要求第 10 字符为行尾，避免
                       误匹配 LOG_BATCH_END） */
                    if (!batch_collect && strncmp(msg, "LOG_BATCH", 9) == 0 &&
                        msg[9] == '\0') {
                        batch_collect = 1;
                        batch_len = 0;
                        batch_msg[0] = '\0';
                        pos = 0;
                        continue;
                    }
                    if (batch_collect) {
                        /* 收集内容行（保留换行） */
                        size_t add = strlen(msg);
                        if (batch_len + add + 2 < sizeof(batch_msg)) {
                            memcpy(batch_msg + batch_len, msg, add);
                            batch_len += add;
                            batch_msg[batch_len++] = '\n';
                            batch_msg[batch_len] = '\0';
                        }
                        pos = 0;
                        continue;
                    }
                    int level = LOG_INFO;
                    if (strncmp(msg, "LOG_IO:", 7) == 0) {
                        ctx->type = 1; msg += 7;
                    } else if (strncmp(msg, "LOG_SYS:", 8) == 0) {
                        ctx->type = 2; msg += 8;
                    } else if (strncmp(msg, "LOG_LOGCAT:", 11) == 0) {
                        ctx->type = 3; msg += 11;
                    }
                    if (ctx->type == 2 && msg[0] >= '0' && msg[0] <= '9') {
                        level = msg[0] - '0';
                        char *colon = strchr(msg, ':');
                        if (colon) msg = colon + 1;
                    }
                    int next = (ctx->head + 1) & (RING_CAP - 1);
                    if (next != ctx->tail) {
                        strncpy(ctx->entries[ctx->head].msg, msg, 511);
                        ctx->entries[ctx->head].msg[511] = '\0';
                        ctx->entries[ctx->head].level = level;
                        ctx->entries[ctx->head].type = ctx->type;
                        ctx->head = next;
                        uint64_t val = 1;
                        write(ctx->notify_fd, &val, sizeof(val));
                    }
                    /* entries 环满：丢弃本条（overflow 机制已移除） */
                }
                pos = 0;
            } else if (pos < (int)sizeof(line) - 1) {
                line[pos++] = buf[i];
            }
        }
    }
    uint64_t val = 1;
    write(ctx->notify_fd, &val, sizeof(val));
    ctx->disconnected = true;
    return nullptr;
}
static int parse_op_string(const char *op_str) {
    if (strcmp(op_str, "OPEN") == 0) return OP_OPEN;
    if (strcmp(op_str, "CREATE") == 0) return OP_CREATE;
    if (strcmp(op_str, "WRITE") == 0) return OP_WRITE;
    if (strcmp(op_str, "READ") == 0) return OP_READ;
    if (strcmp(op_str, "UNLINK") == 0) return OP_UNLINK;
    if (strcmp(op_str, "MKDIR") == 0) return OP_MKDIR;
    if (strcmp(op_str, "RMDIR") == 0) return OP_RMDIR;
    if (strcmp(op_str, "RENAME") == 0) return OP_RENAME;
    if (strcmp(op_str, "GETATTR") == 0) return OP_GETATTR;
    if (strcmp(op_str, "ACCESS") == 0) return OP_ACCESS;
    if (strcmp(op_str, "TRUNCATE") == 0) return OP_TRUNCATE;
    if (strcmp(op_str, "UTIMENS") == 0) return OP_UTIMENS;
    if (strcmp(op_str, "CHMOD") == 0) return OP_CHMOD;
    if (strcmp(op_str, "CHOWN") == 0) return OP_CHOWN;
    if (strcmp(op_str, "READLINK") == 0) return OP_READLINK;
    if (strcmp(op_str, "STATFS") == 0) return OP_STATFS;
    if (strcmp(op_str, "OPENDIR") == 0) return OP_OPENDIR;
    if (strcmp(op_str, "READDIR") == 0) return OP_READDIR;
    return 0;
}
static void load_ignore_rules() {
    FILE *fp = fopen(MONITOR_IGNORE_PATH, "re");
    IgnoreRule *cur = g_ignore_rules;
    while (cur) {
        IgnoreRule *next = cur->next;
        free(cur->path_prefix); free(cur); cur = next;
    }
    g_ignore_rules = nullptr;
    int count = 0;
    if (fp) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            char *p = line;
            if (strncmp(p, "\xEF\xBB\xBF", 3) == 0) p += 3;
            while (isspace((unsigned char)*p)) p++;
            if (*p == '#' || *p == '\0') continue;
            char *end = p + strlen(p) - 1;
            while (end > p && isspace((unsigned char)*end)) end--;
            *(end+1) = '\0';
            int op_mask = 0; char *path = p;
            if (*p == '[') {
                char *close_ptr = strchr(p, ']');
                if (close_ptr) {
                    *close_ptr = '\0'; char *ops = p+1;
                    char *saveptr = nullptr;
                    char *token = strtok_r(ops, ",", &saveptr);
                    while (token) {
                        int op = parse_op_string(token);
                        if (op) op_mask |= op;
                        token = strtok_r(nullptr, ",", &saveptr);
                    }
                    path = close_ptr+1; while (isspace((unsigned char)*path)) path++;
                }
            }
            if (op_mask == 0) op_mask = ~0;
            if (path[0] != '/' && path[0] != '*') continue;
            IgnoreRule *rule = malloc(sizeof(IgnoreRule));
            rule->op_mask = op_mask; rule->path_prefix = strdup(path);
            rule->is_wildcard = (strpbrk(path, "*?[]") != nullptr);
            rule->next = g_ignore_rules; g_ignore_rules = rule; count++;
        }
        fclose(fp);
    }
    char msg[256];
    snprintf(msg, sizeof(msg), "[log_monitor] 加载监控忽略规则完成，共 %d 条", count);
    push_log(&g_sys_buf, msg, 2, LOG_DEBUG);
}
static bool should_ignore_io(const char *line) {
    char *op_bracket = strchr(line, '[');
    if (!op_bracket) return false;
    op_bracket = strchr(op_bracket + 1, '[');
    if (!op_bracket) return false;
    char *op_end = strchr(op_bracket, ']');
    if (!op_end) return false;
    char op_buf[32];
    size_t op_len = op_end - (op_bracket + 1);
    if (op_len >= sizeof(op_buf)) op_len = sizeof(op_buf)-1;
    strncpy(op_buf, op_bracket + 1, op_len); op_buf[op_len] = '\0';
    int op_mask = parse_op_string(op_buf);
    if (op_mask == 0) return false;
    char *path_start = op_end + 1;
    while (isspace((unsigned char)*path_start)) path_start++;
    if (*path_start == '\0') return false;
    char *path_end = strstr(path_start, " -> ");
    if (!path_end) path_end = path_start + strlen(path_start);
    char path_buf[PATH_MAX];
    size_t path_len = path_end - path_start;
    if (path_len >= sizeof(path_buf)) path_len = sizeof(path_buf)-1;
    strncpy(path_buf, path_start, path_len); path_buf[path_len] = '\0';
    IgnoreRule *rule = g_ignore_rules;
    bool ignore = false;
    while (rule) {
        if (rule->op_mask & op_mask) {
            if (rule->is_wildcard) {
                if (fnmatch(rule->path_prefix, path_buf, 0) == 0) { ignore = true; break; }
            } else {
                if (strncmp(path_buf, rule->path_prefix, strlen(rule->path_prefix)) == 0) { ignore = true; break; }
            }
        }
        rule = rule->next;
    }
    return ignore;
}
static bool search_hit(int level, const char *msg, const char *key, int level_filter) {
    return (level_filter < 0 || level >= level_filter) &&
           (!key || key[0] == '\0' || strstr(msg, key));
}

static void search_emit_line(int fd, time_t t, int level, const char *msg, const char *log_type) {
    char line[MAX_MSG_LEN + 128];
    struct tm tm_info; localtime_r(&t, &tm_info);
    char time_buf[32]; strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    int len;
    if (log_type && strcmp(log_type, "sys") == 0) {
        /* SYS 查询行附带等级（与落盘行/STREAM_SYS_API 格式一致）：
           客户端据此执行等级阈值过滤 */
        len = snprintf(line, sizeof(line), "%s|%d|%s\n", time_buf, level % 10, msg);
    } else {
        len = snprintf(line, sizeof(line), "%s|%s\n", time_buf, msg);
    }
    write(fd, line, len);
}

/* 分页查询：内存环（newest→oldest）在前、落盘快照（newest→oldest）在后，
   offset/limit 跨段共享计数 */
static void search_log_paged(int fd, LogBuffer* buf, const DiskLogBuf *disk,
                             const char* key, int limit, int offset, int level_filter,
                             const char *log_type) {
    int total_in_buf = buf->full ? buf->max : (buf->head - buf->tail + buf->max) % buf->max;
    int total_matched = 0; int idx = buf->tail;
    for (int i = 0; i < total_in_buf; i++) {
        if (search_hit(buf->data[idx].level, buf->data[idx].msg, key, level_filter)) total_matched++;
        idx = (idx + 1) % buf->max;
    }
    if (disk) {
        for (int i = 0; i < disk->count; i++) {
            if (search_hit(disk->data[i].level, disk->data[i].msg, key, level_filter)) total_matched++;
        }
    }
    int sent_count = 0; int skip_count = 0;
    char line[MAX_MSG_LEN + 128];
    idx = (buf->head - 1 + buf->max) % buf->max;
    for (int i = 0; i < total_in_buf && sent_count < limit; i++) {
        if (search_hit(buf->data[idx].level, buf->data[idx].msg, key, level_filter)) {
            if (skip_count < offset) skip_count++;
            else { search_emit_line(fd, buf->data[idx].t, buf->data[idx].level, buf->data[idx].msg, log_type); sent_count++; }
        }
        idx = (idx - 1 + buf->max) % buf->max;
    }
    if (disk) {
        for (int i = disk->count - 1; i >= 0 && sent_count < limit; i--) {
            if (search_hit(disk->data[i].level, disk->data[i].msg, key, level_filter)) {
                if (skip_count < offset) skip_count++;
                else { search_emit_line(fd, disk->data[i].t, disk->data[i].level, disk->data[i].msg, log_type); sent_count++; }
            }
        }
    }
    (void)log_type; /* 保留参数供行格式分支使用；overflow 查询已移除 */
    int remaining = total_matched - (offset + sent_count);
    if (remaining < 0) remaining = 0;
    snprintf(line, sizeof(line), "DONE|%d|%d\n", total_matched, remaining);
    write(fd, line, strlen(line));
}
static void add_active_client(ClientCtx *ctx) {
    ctx->next = g_active_clients;
    ctx->prev = nullptr;
    if (g_active_clients) {
        g_active_clients->prev = ctx;
    }
    g_active_clients = ctx;
}
static void remove_active_client(ClientCtx *ctx) {
    if (ctx->prev) {
        ctx->prev->next = ctx->next;
    } else {
        g_active_clients = ctx->next;
    }
    if (ctx->next) {
        ctx->next->prev = ctx->prev;
    }
}
/* 单条历史输出（dump/search 共用格式）：false=对端硬错，调用方停止 */
static bool dump_one_entry(int fd, time_t t, int level, const char *msg,
                           int type, int min_level, bool with_ts, bool with_level) {
    if (level < min_level) return true;
    char line_buf[MAX_MSG_LEN + 64]; /* ts(20) + msg + \n */
    size_t msg_len = strnlen(msg, MAX_MSG_LEN);
    if (msg_len > MAX_MSG_LEN - 1) msg_len = MAX_MSG_LEN - 1;
    int off = 0;
    if (with_ts && t > 0) {
        struct tm tm_info;
        localtime_r(&t, &tm_info);
        char time_buf[32];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
        off = snprintf(line_buf, sizeof(line_buf), "%s|", time_buf);
    }
    if (with_level && type == 2) {
        line_buf[off++] = (char)('0' + (level % 10));
        line_buf[off++] = '|';
    }
    memcpy(line_buf + off, msg, msg_len);
    line_buf[off + msg_len] = '\n';
    line_buf[off + msg_len + 1] = '\0';
    ssize_t ret = send(fd, line_buf, off + msg_len + 1, MSG_NOSIGNAL | MSG_DONTWAIT);
    return !(ret <= 0 && (errno != EAGAIN && errno != EWOULDBLOCK));
}

/* 历史转储：落盘快照（oldest→newest）在前、内存环在后拼接。
 * with_level 时为 SYS 条目附加 "<level>|" 等级前缀（与 STREAM_SYS_API
 * 实时推送行格式一致：ts|<lvl>|msg），客户端据此做等级阈值过滤 */
static void dump_buf_to_client(int fd, LogBuffer* buf, const DiskLogBuf *disk,
                               int type, int min_level, bool with_ts, bool with_level) {
    if (disk) {
        for (int i = 0; i < disk->count; i++) {
            if (!dump_one_entry(fd, disk->data[i].t, disk->data[i].level, disk->data[i].msg,
                                type, min_level, with_ts, with_level))
                return;
        }
    }
    int total_in_buf = buf->full ? buf->max : (buf->head - buf->tail + buf->max) % buf->max;
    int idx = buf->tail;
    for (int i = 0; i < total_in_buf; i++) {
        if (!dump_one_entry(fd, buf->data[idx].t, buf->data[idx].level, buf->data[idx].msg,
                            type, min_level, with_ts, with_level))
            break;
        idx = (idx + 1) % buf->max;
    }
}
static int process_line(ClientCtx* ctx, char* line, const char* leftover, int leftover_len) {
    int fd = ctx->fd;
    if (strncmp(line, "LOG_IO:", 7) == 0 ||
        strncmp(line, "LOG_SYS:", 8) == 0 ||
        strncmp(line, "LOG_LOGCAT:", 11) == 0) {
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, ctx->fd, nullptr);
        AsyncCtx *actx = calloc(1, sizeof(AsyncCtx));
        actx->fd = ctx->fd;
        /* async 线程以阻塞方式 read：accept 时该 fd 被设为非阻塞，若保持非阻塞，
           无数据时 read 返回 EAGAIN 会被误判为对端断开而退出，进而拆除连接、反向触发生产者忙等 */
        set_block(actx->fd);
        actx->notify_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        actx->disconnected = false;
        /* 粘包剩余字节（如紧跟的 LOG_BATCH 帧）在创建线程前移交 pending，
           避免 async_log_thread 先跑读到 pending_len==0 导致帧丢失 */
        if (leftover && leftover_len > 0) {
            int copy = leftover_len;
            if (copy > (int)sizeof(actx->pending)) copy = (int)sizeof(actx->pending);
            memcpy(actx->pending, leftover, (size_t)copy);
            actx->pending_len = copy;
        }
        char *msg = line;
        int level = LOG_INFO;
        int entry_type = 0;
        if (strncmp(msg, "LOG_IO:", 7) == 0)
            { entry_type = 1; msg += 7; }
        else if (strncmp(msg, "LOG_SYS:", 8) == 0)
            { entry_type = 2; msg += 8;
              if (msg[0] >= '0' && msg[0] <= '9') {
                  level = msg[0] - '0';
                  char *colon = strchr(msg, ':');
                  if (colon) msg = colon + 1;
              }
            }
        else if (strncmp(msg, "LOG_LOGCAT:", 11) == 0)
            { entry_type = 3; msg += 11; }
        actx->type = entry_type;
        strncpy(actx->entries[0].msg, msg, 511);
        actx->entries[0].msg[511] = '\0';
        actx->entries[0].level = level;
        actx->entries[0].type = entry_type;
        actx->head = 1; actx->tail = 0;
        actx->next = g_async_clients;
        g_async_clients = actx;
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = actx->notify_fd };
        epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, actx->notify_fd, &ev);
        pthread_create(&actx->tid, nullptr, async_log_thread, actx);
        pthread_detach(actx->tid);
        ctx->fd = -1;
        return 1;
    } else if (strncmp(line, "LOG_BATCH", 9) == 0 && line[9] == '\0') {
        /* LOG_BATCH 合并帧作为连接首个数据包（重连/重启后稳态、全局替换
           模式下环形缓冲首条即合并摘要）：不能像普通日志行解析入 entries
           （无级别/类型前缀），整帧（头行 + 粘包剩余字节）移交给 async
           线程按帧协议收集——否则主循环逐行处理时每行返回 0，帧被丢弃 */
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, ctx->fd, nullptr);
        AsyncCtx *actx = calloc(1, sizeof(AsyncCtx));
        if (!actx) {
            /* OOM：无法移交 async 线程，丢弃该连接（帧数据不可恢复，
               至少不崩溃、不泄漏 fd） */
            close(ctx->fd);
            ctx->fd = -1;
            return 1;
        }
        actx->fd = ctx->fd;
        set_block(actx->fd);
        actx->notify_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (actx->notify_fd < 0) {
            close(ctx->fd);
            ctx->fd = -1;
            free(actx);
            return 1;
        }
        actx->disconnected = false;
        /* pending：LOG_BATCH 头行 + 剩余字节（可能含帧内容/END/后续 LOG_* 行） */
        int plen = 0;
        static const char head[] = "LOG_BATCH\n";
        memcpy(actx->pending + plen, head, sizeof(head) - 1);
        plen += (int)sizeof(head) - 1;
        if (leftover && leftover_len > 0) {
            int copy = leftover_len;
            if (copy > (int)sizeof(actx->pending) - plen) copy = (int)sizeof(actx->pending) - plen;
            memcpy(actx->pending + plen, leftover, (size_t)copy);
            plen += copy;
        }
        actx->pending_len = plen;
        actx->type = 2;
        actx->head = 0; actx->tail = 0;
        actx->next = g_async_clients;
        g_async_clients = actx;
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = actx->notify_fd };
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, actx->notify_fd, &ev) != 0) {
            /* notify_fd 注册失败：drain_async 永不触发，帧静默丢弃；
               cleanup_async 从链表移除并关闭 fd/释放 actx */
            ctx->fd = -1;   /* 防止主循环 close 已接管 fd */
            cleanup_async(actx);
            return 1;
        }
        if (pthread_create(&actx->tid, nullptr, async_log_thread, actx) != 0) {
            /* 线程创建失败：actx 留在链表但无消费者，阻塞 fd 泄漏；
               移除并清理 */
            ctx->fd = -1;
            cleanup_async(actx);
            return 1;
        }
        pthread_detach(actx->tid);
        ctx->fd = -1;
        return 1;
    } else if (strncmp(line, "QUERY_IO:", 9) == 0 || strncmp(line, "QUERY_SYS:", 10) == 0 ||
               strncmp(line, "QUERY_LOGCAT:", 13) == 0) {
        bool is_io = (strstr(line, "IO") != nullptr);
        bool is_logcat = (strstr(line, "LOGCAT") != nullptr);
        char *rest = line + (is_io ? 9 : (is_logcat ? 13 : 10));
        int limit = DEFAULT_LIMIT, offset = 0, level_filter = -1;
        char *key = rest;
        char *level_s = strchr(rest, ':');
        if (level_s) {
            *level_s = 0; level_s++;
            level_filter = atoi(rest);
            key = level_s;
            char *limit_s = strchr(key, ':');
            if (limit_s) {
                *limit_s = 0; limit_s++;
                char *offset_s = strchr(limit_s, ':');
                if (offset_s) {
                    *offset_s = 0; offset_s++;
                    offset = atoi(offset_s);
                }
                limit = atoi(limit_s);
            }
        }
        search_log_paged(fd, is_io ? &g_io_buf : (is_logcat ? &g_logcat_buf : &g_sys_buf),
                         is_io ? &g_io_disk : (is_logcat ? nullptr : &g_sys_disk),
                         key, limit, offset, level_filter, is_io ? "io" : (is_logcat ? "logcat" : "sys"));
        return 1; 
    } else if (strcmp(line, "CLEAR_IO") == 0) {
        g_io_buf.head = g_io_buf.tail = 0; g_io_buf.full = false;
        /* 同步清启动快照、暂存与落盘文件（暂存不清会与 tick 刷盘竞态复活文件） */
        free(g_io_disk.data); g_io_disk.data = nullptr; g_io_disk.count = 0;
        g_persist_io.staged = 0;
        unlink(g_persist_io.path); unlink(g_persist_io.rot);
        write(fd, "OK\n", 3);
        return 1;
    } else if (strcmp(line, "CLEAR_SYS") == 0) {
        g_sys_buf.head = g_sys_buf.tail = 0; g_sys_buf.full = false;
        free(g_sys_disk.data); g_sys_disk.data = nullptr; g_sys_disk.count = 0;
        g_persist_sys.staged = 0;
        unlink(g_persist_sys.path); unlink(g_persist_sys.rot);
        write(fd, "OK\n", 3);
        return 1;
    } else if (strcmp(line, "CLEAR_LOGCAT") == 0) {
        g_logcat_buf.head = g_logcat_buf.tail = 0; g_logcat_buf.full = false;
        write(fd, "OK\n", 3);
        return 1;
    } else if (strncmp(line, "STREAM_IO", 9) == 0) {
        bool with_ts = false;
        int min_level = 0;
        if (line[9] == ':') min_level = parse_stream_args(line + 10, &with_ts);
        write(fd, "OK\n", 3);
        dump_buf_to_client(fd, &g_io_buf, &g_io_disk, 1, min_level, with_ts, false);
        stream_post_add(fd, 1, min_level, false, with_ts);
        ctx->is_streaming = true;
        return 0;
    } else if (strncmp(line, "STREAM_SYS_API", 14) == 0) {
        bool with_ts = false;
        int min_level = 0;
        if (line[14] == ':') min_level = parse_stream_args(line + 15, &with_ts);
        write(fd, "OK\n", 3);
        /* API 模式：历史转储附带等级前缀，与其自身实时推送行格式一致 */
        dump_buf_to_client(fd, &g_sys_buf, &g_sys_disk, 2, min_level, with_ts, true);
        stream_post_add(fd, 2, min_level, true, with_ts);
        ctx->is_streaming = true;
        return 0;
    } else if (strncmp(line, "STREAM_SYS", 10) == 0) {
        bool with_ts = false;
        int min_level = 0;
        if (line[10] == ':') min_level = parse_stream_args(line + 11, &with_ts);
        write(fd, "OK\n", 3);
        dump_buf_to_client(fd, &g_sys_buf, &g_sys_disk, 2, min_level, with_ts, false);
        stream_post_add(fd, 2, min_level, false, with_ts);
        ctx->is_streaming = true;
        return 0;
    } else if (strncmp(line, "STREAM_LOGCAT", 13) == 0) {
        bool with_ts = false;
        int min_level = 0;
        if (line[13] == ':') min_level = parse_stream_args(line + 14, &with_ts);
        write(fd, "OK\n", 3);
        dump_buf_to_client(fd, &g_logcat_buf, nullptr, 3, min_level, with_ts, false);
        stream_post_add(fd, 3, min_level, false, with_ts);
        ctx->is_streaming = true;
        return 0;
    } else if (strncmp(line, "STREAM_ALL", 10) == 0) {
        bool with_ts = false;
        int min_level = 0;
        if (line[10] == ':') min_level = parse_stream_args(line + 11, &with_ts);
        write(fd, "OK\n", 3);
        dump_buf_to_client(fd, &g_io_buf, &g_io_disk, 1, min_level, with_ts, false);
        dump_buf_to_client(fd, &g_sys_buf, &g_sys_disk, 2, min_level, with_ts, false);
        dump_buf_to_client(fd, &g_logcat_buf, nullptr, 3, min_level, with_ts, false);
        stream_post_add(fd, 0, min_level, false, with_ts);
        ctx->is_streaming = true;
        return 0;
    } else if (strncmp(line, "STOP_STREAM", 11) == 0) {
        /* 订阅集合归 comm 线程：先同步回 OK（shutdown 后不可再写），再 shutdown
           并投递 DEL（comm 侧 close）；is_streaming 保持 true，使公共关闭路径
           走 shutdown+DEL 而非直接 close */
        write(fd, "OK\n", 3);
        shutdown(fd, SHUT_RDWR);
        stream_post_del(fd);
        ctx->stream_del_posted = true;
        return 1;
    } else if (strcmp(line, "COUNT") == 0) {
        int io_total = g_io_disk.count +
            (g_io_buf.full ? g_io_buf.max : (g_io_buf.head - g_io_buf.tail + g_io_buf.max) % g_io_buf.max);
        int sys_total = g_sys_disk.count +
            (g_sys_buf.full ? g_sys_buf.max : (g_sys_buf.head - g_sys_buf.tail + g_sys_buf.max) % g_sys_buf.max);
        int logcat_total = g_logcat_buf.full ? g_logcat_buf.max : (g_logcat_buf.head - g_logcat_buf.tail + g_logcat_buf.max) % g_logcat_buf.max;
        char resp[128];
        int len = snprintf(resp, sizeof(resp), "COUNT|%d|%d|%d\n", io_total, sys_total, logcat_total);
        write(fd, resp, len);
        return 1;
    }
    return 0; 
}
static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
static int set_block(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}
void handle_signal(int sig) { if (sig == SIGINT || sig == SIGTERM) g_should_exit = 1; }
/* 核心优化：合并异步定时器超时回调 */
static int setup_client_timeout_timer(int epoll_fd) {
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd < 0) return -1;
    struct itimerspec ts = {
        .it_interval = { .tv_sec = 0, .tv_nsec = 500000000 }, 
        .it_value    = { .tv_sec = 0, .tv_nsec = 500000000 }
    };
    timerfd_settime(timer_fd, 0, &ts, nullptr);
    struct epoll_event ev_t = { .events = EPOLLIN, .data.fd = timer_fd };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev_t);
    return timer_fd;
}
static void handle_client_timeout_tick(int timer_fd) {
    uint64_t expirations;
    ssize_t r = read(timer_fd, &expirations, sizeof(expirations));
    (void)r;
    persist_lazy_tick();   /* 落盘懒刷盘（500ms tick 驱动） */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    ClientCtx *curr_chk = g_active_clients;
    while (curr_chk) {
        ClientCtx *next_chk = curr_chk->next;
        if (!curr_chk->is_streaming) {
            long elapsed_ms = (now.tv_sec - curr_chk->start_time.tv_sec) * 1000 +
                              (now.tv_nsec - curr_chk->start_time.tv_nsec) / 1000000;
                if (elapsed_ms >= 500) {
                    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, curr_chk->fd, nullptr);
                    close(curr_chk->fd);
                    /* 超时清理仅针对非订阅连接（订阅连接 is_streaming=true，不会走到这里），
                       故不在订阅集合中，无需投递 DEL */
                    remove_active_client(curr_chk);
                    free(curr_chk);
                }
        }
        curr_chk = next_chk;
    }
    AsyncCtx **app = &g_async_clients;
    while (*app) {
        AsyncCtx *a = *app;
        if (a->disconnected) {
            *app = a->next;
            epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, a->notify_fd, nullptr);
            if (a->fd >= 0) close(a->fd);
            if (a->notify_fd >= 0) close(a->notify_fd);
            free(a);
        } else {
            app = &(*app)->next;
        }
    }
}
int main(int argc, char *argv[]) {
    escape_cgroup();
    init_timezone();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    bool verbose = false;
    int opt;
    static struct option long_options[] = {
        {"persist-all", no_argument, nullptr, 'p'},
        {"help", no_argument, nullptr, 'h'},
        {"verbose", no_argument, nullptr, 'v'},
        {nullptr, 0, nullptr, 0}
    };
    while ((opt = getopt_long(argc, argv, "phv", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'p': g_persist_all_logs = 1; break;
            case 'v': verbose = true; break;
            default: break;
        }
    }
    (void)verbose;
    init_buf(&g_io_buf, MAX_IO_LOGS); init_buf(&g_sys_buf, MAX_SYS_LOGS); init_buf(&g_logcat_buf, MAX_LOGCAT_LOGS);
    /* io/sys 自动落盘常开：建目录 + 初始化暂存器（先于首条 push_log） */
    mkdir(LOG_DIR, 0755);
    persist_init_writer(&g_persist_io, "io");
    persist_init_writer(&g_persist_sys, "sys");
    /* 启动加载落盘快照到只读独立缓冲（与内存拼接，客户端获取时合并） */
    disk_load(&g_io_disk, g_persist_io.rot, g_persist_io.path);
    disk_load(&g_sys_disk, g_persist_sys.rot, g_persist_sys.path);
    load_ignore_rules();
    g_server_sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un addr;
    socklen_t addr_len = nsp_uds_abstract_addr(&addr, LOG_SOCKET_NAME);
    unlink(LOG_SOCKET_NAME);
    bind(g_server_sock, (struct sockaddr*)&addr, addr_len);
    listen(g_server_sock, 128);
    g_epoll_fd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN; ev.data.fd = g_server_sock; epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_server_sock, &ev);
    int inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd >= 0) {
        inotify_add_watch(inotify_fd, CONFIG_DIR, IN_MODIFY | IN_MOVED_TO | IN_CREATE | IN_CLOSE_WRITE | IN_DELETE);
        ev.events = EPOLLIN; ev.data.fd = inotify_fd; epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, inotify_fd, &ev);
    }
    /* 启动 client 超时异步定时器并注册至 epoll */
    int timer_fd = setup_client_timeout_timer(g_epoll_fd);
    /* 统一通讯线程：STREAM 实时推送扇出改由 comm 线程驱动，主线程只 post */
    nsp_comm_init();
    nsp_comm_backend_t stream_be = {
        .ctx = NULL, .ensure_link = NULL, .emit = stream_emit,
        .fini = NULL, .report = nsp_log_report,
    };
    nsp_comm_register(NSP_CH_BCAST, &stream_be);
    while (!g_should_exit) {
        int nfds = epoll_wait(g_epoll_fd, events, MAX_EVENTS, -1); /* 取消同步 100ms 超时，转为无限等待 */
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            if (fd == g_server_sock) {
                int client = accept(g_server_sock, nullptr, nullptr);
                if (client >= 0) {
                    set_nonblock(client);
                    ClientCtx* ctx = calloc(1, sizeof(ClientCtx));
                    ctx->fd = client;
                    clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);
                    ctx->is_streaming = false;
                    add_active_client(ctx);
                    ev.events = EPOLLIN | EPOLLET; ev.data.ptr = ctx;
                    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, client, &ev);
                }
            } else if (inotify_fd >= 0 && fd == inotify_fd) {
                char inotify_buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
                ssize_t len;
                while ((len = read(inotify_fd, inotify_buf, sizeof(inotify_buf))) > 0) {
                    bool need_reload = false;
                    for (char *ptr = inotify_buf; ptr < inotify_buf + len; ) {
                        struct inotify_event *ev_inotify = (struct inotify_event *) ptr;
                        if (ev_inotify->len && strstr(ev_inotify->name, "monitor_ignore.conf")) need_reload = true;
                        ptr += sizeof(struct inotify_event) + ev_inotify->len;
                    }
                    if (need_reload) load_ignore_rules();
                }
            } else if (fd == timer_fd) {
                /* 处理异步定时器事件 */
                handle_client_timeout_tick(timer_fd);
            } else {
                int event_fd = events[i].data.fd;
                AsyncCtx *actx = nullptr;
                for (AsyncCtx *a = g_async_clients; a; a = a->next) {
                    if (a->notify_fd == event_fd) { actx = a; break; }
                }
                if (actx) {
                    uint64_t val;
                    read(actx->notify_fd, &val, sizeof(val));
                    drain_async(actx);
                    if (actx->disconnected) {
                        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, actx->notify_fd, nullptr);
                        cleanup_async(actx);
                    }
                } else {
                ClientCtx* ctx = (ClientCtx*)events[i].data.ptr;
                char buf[4096]; bool consumed = false;
                while (!consumed) {
                    ssize_t n = read(ctx->fd, buf, sizeof(buf));
                    if (n > 0) {
                        for (ssize_t j = 0; j < n; j++) {
                            if (buf[j] == '\n') {
                                ctx->line[ctx->pos] = '\0';
                                if (ctx->pos > 0) {
                                    if (process_line(ctx, ctx->line, buf + j + 1, (int)(n - (j + 1)))) {
                                        consumed = true; break;
                                    }
                                }
                                ctx->pos = 0;
                            } else if (ctx->pos < sizeof(ctx->line) - 1) ctx->line[ctx->pos++] = buf[j];
                        }
                    } else if (n == -1 && errno == EAGAIN) break;
                    else { consumed = true; break; }
                }
                if (consumed) {
                    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, ctx->fd, nullptr);
                    if (ctx->is_streaming && !ctx->stream_del_posted) {
                        /* 订阅连接：shutdown + 投递 DEL，close 由 comm 线程执行
                           （不断号，无 fd 复用竞态；STOP 路径已投递则跳过） */
                        shutdown(ctx->fd, SHUT_RDWR);
                        stream_post_del(ctx->fd);
                    } else if (!ctx->is_streaming) {
                        close(ctx->fd);
                    }
                    remove_active_client(ctx);
                    free(ctx);
                }
                }
            }
        }
    }
    /* 先 join comm 线程（含订阅集合收尾），再直接关闭全部 fd（无竞态） */
    nsp_comm_fini();
    /* P3：fini 后投递的 DEL 只计 dropped（comm 已 join 无人 close），订阅 fd
       仅 shutdown 未 close——退出前统一关闭（comm 线程已结束，无竞态） */
    while (g_stream_clients) {
        StreamClient *tmp = g_stream_clients;
        g_stream_clients = tmp->next;
        close(tmp->fd);
        free(tmp);
    }
    close(g_server_sock);
    if (inotify_fd >= 0) close(inotify_fd);
    if (timer_fd >= 0) close(timer_fd);
    close(g_epoll_fd);
    ClientCtx* curr_free = g_active_clients;
    while (curr_free) {
        ClientCtx* next_free = curr_free->next;
        close(curr_free->fd);
        free(curr_free);
        curr_free = next_free;
    }
    g_active_clients = nullptr;
    AsyncCtx *a_curr = g_async_clients;
    while (a_curr) {
        AsyncCtx *a_next = a_curr->next;
        a_curr->disconnected = true;
        if (a_curr->fd >= 0) close(a_curr->fd);
        if (a_curr->notify_fd >= 0) close(a_curr->notify_fd);
        free(a_curr);
        a_curr = a_next;
    }
    g_async_clients = nullptr;
    /* 退出前刷盘残余暂存并释放 */
    persist_flush(&g_persist_io);
    persist_flush(&g_persist_sys);
    free(g_persist_io.stage); g_persist_io.stage = nullptr;
    free(g_persist_sys.stage); g_persist_sys.stage = nullptr;
    free(g_io_disk.data); g_io_disk.data = nullptr; g_io_disk.count = 0;
    free(g_sys_disk.data); g_sys_disk.data = nullptr; g_sys_disk.count = 0;
    destroy_buf(&g_io_buf); destroy_buf(&g_sys_buf); destroy_buf(&g_logcat_buf);
    return 0;
}