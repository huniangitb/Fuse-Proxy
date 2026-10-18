/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <stdatomic.h>
#include <sys/eventfd.h>
#include "common.h"
#include "nsp_comm.h"
#include "nsp_util.h"
#include "nsp_log.h"
#define MAX_MSG_LEN NSP_LOG_MSG_MAX /* 单条日志上限，与 common.c 组帧同源（nsp_constants.h） */
/* 滑动日志缓冲：按字节上限控制（超出丢弃最旧日志）。
   IO 日志最大 128MB，普通日志（sys/logcat）各 16MB。
   条数上限 = 字节上限 / 单条固定大小（LogEntry ≈ MAX_MSG_LEN+16），
   数组内存 ≈ 字节上限（取代旧版 52 万/20 万条 ≈ 2.1GB/800MB 的预分配）。 */
#define MAX_IO_LOG_BYTES     (128u * 1024u * 1024u)
#define MAX_SYS_LOG_BYTES    (16u * 1024u * 1024u)
#define MAX_LOGCAT_LOG_BYTES (16u * 1024u * 1024u)
#define MAX_IO_LOGS          (MAX_IO_LOG_BYTES / (MAX_MSG_LEN + 16))
#define MAX_SYS_LOGS         (MAX_SYS_LOG_BYTES / (MAX_MSG_LEN + 16))
#define MAX_LOGCAT_LOGS      (MAX_LOGCAT_LOG_BYTES / (MAX_MSG_LEN + 16))
#define DEFAULT_LIMIT        500
#define MAX_EVENTS           256
#define RING_CAP             16384
typedef struct AsyncCtx {
    int fd;
    int type; /* 0=undef, 1=IO, 2=SYS, 3=LOGCAT */
    pthread_t tid;
    /* 线程已创建且未被 join（线程非 detached，收尸责任在 cleanup_async）。
       free 之前必须 join 出「线程已退出」的同步证据：仅置 disconnected 只让线程
       在下次循环检查后退出，主线程随即 close/free 会让它醒来在已释放对象上写
       notify_fd（ASan heap-use-after-free，退出期 SIGTERM 路径可复现）。 */
    bool thread_started;
    /* 断开标记用原子而非 volatile：async 线程在**最后一批 entries/batch_q 写入之后**
       才置位，主循环回收前置 acquire 读取——release/acquire 配对让那些 volatile
       写对接收方可见。用 volatile 只保证不被优化掉，不保证跨线程可见性，线程
       末尾刚入环的日志会在回收方读 head 之前就被 free 掉而永久丢失。 */
    _Atomic bool disconnected;
    struct {
        /* 短消息内联（512，常见路径零 malloc）；超长经 big 堆溢出
           （malloc 精确大小，上限行缓冲 4224）——此前一律截断到 511，
           长路径 IO 行的路径尾部在内存与 io.log 里永久丢失。 */
        char msg[512];
        char* big;
        int level;
        int type;
    } entries[RING_CAP];
    volatile int head;
    volatile int tail;
    int notify_fd;
    /* 粘包移交缓冲：主循环一次 read 读到首行 LOG_SYS 转 async 后，buf 中
       剩余字节（如紧跟的 LOG_BATCH 帧）移交至此，async_log_thread 先处理。
       在 process_line 内、pthread_create 之前填充，避免线程先跑读空 */
    char pending[4096];
    int pending_len;
    /* 合并日志多槽队列：LOG_BATCH 整块内容经此入 g_sys_buf，
       背靠背 LOG_BATCH 帧互不覆盖。
       head 仅 async_log_thread 写、tail 仅主循环 drain_async 读（无锁环形）。
       drain_async 将每槽 push 入 g_sys_buf（MAX_MSG_LEN=4096），
       避免 UTF-8 截断乱码 */
#define BATCH_Q_CAP 4
    struct {
        char msg[MAX_MSG_LEN];
        int len;
    } batch_q[BATCH_Q_CAP];
    volatile int batch_q_head;
    volatile int batch_q_tail;
    struct AsyncCtx* next;
} AsyncCtx;

static int set_nonblock(int fd);
static int set_block(int fd);
typedef enum {
    OP_NONE = 0,
    OP_OPEN = 1 << 0,
    OP_CREATE = 1 << 1,
    OP_WRITE = 1 << 2,
    OP_READ = 1 << 3,
    OP_UNLINK = 1 << 4,
    OP_MKDIR = 1 << 5,
    OP_RMDIR = 1 << 6,
    OP_RENAME = 1 << 7,
    OP_GETATTR = 1 << 8,
    OP_ACCESS = 1 << 9,
    OP_TRUNCATE = 1 << 10,
    OP_UTIMENS = 1 << 11,
    OP_CHMOD = 1 << 12,
    OP_CHOWN = 1 << 13,
    OP_READLINK = 1 << 14,
    OP_STATFS = 1 << 15,
    OP_OPENDIR = 1 << 16,
    OP_READDIR = 1 << 17,
} IoOpMask;
typedef struct ClientCtx {
    int fd;
    char line[1536];
    size_t pos;
    struct timespec start_time;
    bool is_streaming;
    bool stream_del_posted; /* STOP 路径已投递 DEL，外层关闭路径不再重复投递 */
    struct ClientCtx* next;
    struct ClientCtx* prev;
} ClientCtx;
typedef struct IgnoreRule {
    int op_mask;
    char* path_prefix;
    bool is_wildcard;
    struct IgnoreRule* next;
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
    int type; /* 0=ALL, 1=IO, 2=SYS, 3=LOGCAT */
    int min_level;
    bool level_tag; /* true = SYS 消息前插 LEVEL| 标签（api 模式） */
    bool with_ts;   /* true = 推送行前缀时间戳（STREAM_*:<level>:1 启用） */
    struct StreamClient* next;
} StreamClient;
static LogBuffer g_io_buf, g_sys_buf, g_logcat_buf;
static bool should_ignore_io(const char* line);
static volatile sig_atomic_t g_should_exit = 0;
static int g_server_sock = -1;
static IgnoreRule* g_ignore_rules = nullptr;
static StreamClient* g_stream_clients = nullptr;
static ClientCtx* g_active_clients = nullptr;
static AsyncCtx* g_async_clients = nullptr;
static int g_epoll_fd = -1;
static void init_buf(LogBuffer* buf, int max) {
    buf->data = calloc(max, sizeof(LogEntry));
    buf->head = buf->tail = 0;
    buf->full = false;
    buf->max = max;
}
static void destroy_buf(LogBuffer* buf) {
    if (buf->data) {
        free(buf->data);
        buf->data = nullptr;
    }
}
/* 订阅集合仅 comm 线程触碰（主线程一律 post 'A'/'D'）：'D' 在此同步 close，
   主线程只 shutdown，不断号故无 fd 复用竞态 */
static void remove_stream_client(int fd) {
    StreamClient** pp = &g_stream_clients;
    while (*pp) {
        if ((*pp)->fd == fd) {
            StreamClient* tmp = *pp;
            *pp = (*pp)->next;
            close(tmp->fd);
            free(tmp);
            break;
        }
        pp = &(*pp)->next;
    }
}
/* 解析 STREAM_* 可选参数 "<level>[:<with_ts>]"：返回 level，with_ts 出参（1=附带时间戳） */
static int parse_stream_args(const char* p, bool* with_ts) {
    *with_ts = false;
    int level = atoi(p);
    const char* ts_p = strchr(p, ':');
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

static void broadcast_log(int type, const char* line, int level, time_t t) {
    size_t len = strlen(line);
    size_t total = 1 + 1 + 4 + 8 + len + 1;
    uint8_t* buf = malloc(total);
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
static int stream_emit(void* ctx, const void* data, size_t len) {
    (void)ctx;
    if (len < 1) return 0;
    const uint8_t* p = data;
    if (p[0] == 'A') {
        if (len < 12) return 0;
        int fd;
        int min_level;
        memcpy(&min_level, p + 2, 4);
        memcpy(&fd, p + 8, 4);
        for (StreamClient* e = g_stream_clients; e; e = e->next) {
            if (e->fd == fd) { /* 重复加入：更新属性（幂等） */
                e->type = p[1];
                e->min_level = min_level;
                e->level_tag = p[6] ? true : false;
                e->with_ts = p[7] ? true : false;
                return 0;
            }
        }
        StreamClient* c = malloc(sizeof(StreamClient));
        if (!c) return 0;
        c->fd = fd;
        c->type = p[1];
        c->min_level = min_level;
        c->level_tag = p[6] ? true : false;
        c->with_ts = p[7] ? true : false;
        c->next = g_stream_clients;
        g_stream_clients = c;
        return 0;
    }
    if (p[0] == 'D') {
        if (len < 5) return 0;
        int fd;
        memcpy(&fd, p + 1, 4);
        remove_stream_client(fd); /* comm 线程内同步 close（不断号，无复用竞态） */
        return 0;
    }
    if (p[0] != 'L' || len < 15) return 0;
    int type = p[1];
    int level;
    time_t t;
    memcpy(&level, p + 2, 4);
    memcpy(&t, p + 6, 8);
    const char* line = (const char*)(p + 14);
    size_t llen = len - 15;
    char nl = '\n';
    const char* level_name = nsp_log_level_name(level);
    size_t level_name_len = strlen(level_name);
    char ts_buf[32] = {0};
    if (t > 0) {
        struct tm tm_buf;
        localtime_r(&t, &tm_buf);
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    }
    StreamClient* c = g_stream_clients;
    while (c) {
        if (c->fd > 0 && (c->type == 0 || c->type == type)) {
            if (level >= c->min_level) {
                struct iovec iov[6];
                int iovlen = 0;
                if (c->with_ts && ts_buf[0]) {
                    iov[iovlen].iov_base = ts_buf;
                    iov[iovlen].iov_len = 19; /* "YYYY-MM-DD HH:MM:SS" */
                    iovlen++;
                    iov[iovlen].iov_base = (void*)"|";
                    iov[iovlen].iov_len = 1;
                    iovlen++;
                }
                if (type == 2 && c->level_tag) { /* SYS + api: 前插等级名 */
                    iov[iovlen].iov_base = (void*)level_name;
                    iov[iovlen].iov_len = level_name_len;
                    iovlen++;
                    iov[iovlen].iov_base = (void*)"|";
                    iov[iovlen].iov_len = 1;
                    iovlen++;
                }
                iov[iovlen].iov_base = (void*)line;
                iov[iovlen].iov_len = llen;
                iovlen++;
                iov[iovlen].iov_base = &nl;
                iov[iovlen].iov_len = 1;
                iovlen++;
                struct msghdr msg = {.msg_iov = iov, .msg_iovlen = iovlen};
                ssize_t ret = sendmsg(c->fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
                if (ret <= 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                    close(c->fd);
                    c->fd = -1;
                }
            }
        }
        c = c->next;
    }
    StreamClient** pp = &g_stream_clients;
    while (*pp) {
        if ((*pp)->fd == -1) {
            StreamClient* tmp = *pp;
            *pp = (*pp)->next;
            free(tmp);
        } else {
            pp = &(*pp)->next;
        }
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
#define PERSIST_FILE_MAX        (2u * 1024u * 1024u)
#define PERSIST_STAGE_CAP       (64u * 1024u)
#define PERSIST_LAZY_MS         1000
#define PERSIST_FAIL_BACKOFF_MS 5000
typedef struct {
    char path[PATH_MAX]; /* LOG_DIR/io.log */
    char rot[PATH_MAX];  /* LOG_DIR/io.log.1（单备份轮转） */
    char* stage;
    size_t staged;
    uint64_t last_flush_ms;
    uint64_t fail_until_ms; /* 磁盘失败退避：到期前跳过 open 尝试 */
    uint64_t dropped;       /* stage 满且刷盘不可用时被拒收的日志行数 */
} PersistWriter;
static PersistWriter g_persist_io;
static PersistWriter g_persist_sys;

/* 链路丢弃累计（跨连接/跨 async 线程）：这些是**唯一**会静默吃掉日志的点，
   不计数就等于"日志凭空消失且无从查起"。由 report_drops_once() 限频上报到
   sys 缓冲（search-sys / sys.log 可见），稳态计数不变则零噪音。 */
static _Atomic uint64_t g_drop_entries = 0; /* 接收环（entries）满丢弃的行数 */
static _Atomic uint64_t g_drop_batch = 0;   /* 合并队列（batch_q）满丢弃的包数 */

/* 接收槽存储（含堆溢出）：短消息内联，超长 malloc 精确大小。
   低内存：常见短日志零堆分配；堆路径上限行缓冲（约 4KB），随槽释放即 free。
   OOM 回退截断内联并计入 g_drop_entries（可观测，不静默）。 */
static void async_slot_store(AsyncCtx* ctx, int idx, const char* msg) {
    size_t len = strlen(msg);
    if (len < sizeof(ctx->entries[idx].msg)) {
        memcpy(ctx->entries[idx].msg, msg, len + 1);
        ctx->entries[idx].big = NULL;
    } else {
        char* h = malloc(len + 1);
        if (!h) {
            memcpy(ctx->entries[idx].msg, msg, sizeof(ctx->entries[idx].msg) - 1);
            ctx->entries[idx].msg[sizeof(ctx->entries[idx].msg) - 1] = '\0';
            ctx->entries[idx].big = NULL;
            atomic_fetch_add_explicit(&g_drop_entries, 1, memory_order_relaxed);
        } else {
            memcpy(h, msg, len + 1);
            ctx->entries[idx].msg[0] = '\0';
            ctx->entries[idx].big = h;
        }
    }
}

static char* async_slot_msg(AsyncCtx* ctx, int idx) {
    return ctx->entries[idx].big ? ctx->entries[idx].big : ctx->entries[idx].msg;
}

static void async_slot_release(AsyncCtx* ctx, int idx) {
    free(ctx->entries[idx].big);
    ctx->entries[idx].big = NULL;
}

static uint64_t persist_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void persist_init_writer(PersistWriter* w, const char* name) {
    snprintf(w->path, sizeof(w->path), "%s/%s.log", LOG_DIR, name);
    snprintf(w->rot, sizeof(w->rot), "%s/%s.log.1", LOG_DIR, name);
    w->stage = malloc(PERSIST_STAGE_CAP);
    w->staged = 0;
    w->last_flush_ms = persist_now_ms();
    w->fail_until_ms = 0;
    w->dropped = 0;
}

/* 刷盘：open → fstat 校准 → 超限轮转 → 全量写出 → close。失败进入退避后重试。
   **任何失败路径都不清空 stage**：暂存区是这批日志的唯一副本，清掉等于把
   退避期（默认 5s，磁盘故障期间更久）内累积的最多 64KB 无声丢弃；只有真正
   写出的数据才从 stage 移除（部分写出时保留未写出的尾部）。容量耗尽由
   persist_stage 收口——它在 flush 后仍放不下时按行拒收并计数（dropped）。 */
static void persist_flush(PersistWriter* w) {
    if (!w->stage || w->staged == 0) return;
    uint64_t now = persist_now_ms();
    if (now < w->fail_until_ms) return;
    int fd = open(w->path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) {
        w->fail_until_ms = now + PERSIST_FAIL_BACKOFF_MS;
        return;
    }
    struct stat st;
    uint64_t cur = (fstat(fd, &st) == 0 && st.st_size > 0) ? (uint64_t)st.st_size : 0;
    if (cur + w->staged > PERSIST_FILE_MAX) {
        close(fd);
        unlink(w->rot);
        rename(w->path, w->rot);
        fd = open(w->path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (fd < 0) {
            w->fail_until_ms = now + PERSIST_FAIL_BACKOFF_MS;
            return;
        }
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
    if (off < w->staged) {
        /* 部分写出：移除已落盘的前缀，未写出的尾部留到退避结束后重试 */
        if (off > 0) {
            memmove(w->stage, w->stage + off, w->staged - off);
            w->staged -= off;
        }
        w->fail_until_ms = now + PERSIST_FAIL_BACKOFF_MS;
        return;
    }
    w->staged = 0;
    w->last_flush_ms = now;
}

static void persist_stage(PersistWriter* w, const char* msg, int level, time_t t) {
    if (!w->stage) return;
    struct tm tm_buf;
    localtime_r(&t, &tm_buf);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);
    char line[MAX_MSG_LEN + 128];
    int len = snprintf(line, sizeof(line), "%s|%s|%s\n", ts, nsp_log_level_name(level), msg);
    if (len <= 0) return;
    /* 截断时强制尾部换行，避免与下一行拼接成无换行超长行 */
    if ((size_t)len >= sizeof(line)) {
        len = sizeof(line) - 1;
        line[len - 1] = '\n';
    }
    if (w->staged + (size_t)len > PERSIST_STAGE_CAP) persist_flush(w);
    if (w->staged + (size_t)len > PERSIST_STAGE_CAP) {
        w->dropped++;
        return;
    }
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
   io.log.1 → io.log（先旧后新）解析为线性数组（oldest→newest）。与内存环无
   重叠（内存启动时为空），客户端获取时拼接：磁盘在前、内存在后。
   行格式 ts|LEVEL|msg（LEVEL 为 DEBUG/INFO/WARN/ERROR 名称，见 nsp_log.h；
   2026-09 之前的旧文件为纯数字等级，仍可解析），解析失败跳过。

   磁盘历史可查性：旧实现按固定条数上限 DISK_LOAD_MAX=2048 截断，且每条固定
   占 MAX_MSG_LEN(4096) 字节——2×2MB 落盘里只有最新 2048 条能被 count/search
   翻到，更早的记录明明躺在文件里却"查不到"（重启即只剩两千余条）。现改为
   **紧凑存储**：条目只存 t/level + 指向字符串池的指针，字符串按实际行长排布，
   同样的内存量级即可全量载入（2×2MB ≈ 5MB）。DISK_READ_MAX 是防异常大文件的
   硬上界：超出时只取末尾并跳过残缺首行（轮转本身把文件约束在 2MB 内）。 */
#define DISK_READ_MAX (8u * 1024u * 1024u)
typedef struct {
    time_t t;
    int level;
    const char* msg; /* 指向 strings 池（NUL 结尾），池释放前有效 */
} DiskEntry;
typedef struct {
    DiskEntry* data; /* oldest→newest 线性数组，启动后只读 */
    char* strings;   /* 全部条目字符串的单块池 */
    int count;
} DiskLogBuf;
static DiskLogBuf g_io_disk = {0};
static DiskLogBuf g_sys_disk = {0};

static time_t parse_log_ts(const char* ts) {
    int Y, M, D, h, m, s;
    if (sscanf(ts, "%d-%d-%d %d:%d:%d", &Y, &M, &D, &h, &m, &s) != 6) return (time_t)0;
    if (Y < 1970 || M < 1 || M > 12 || D < 1 || D > 31 || h > 23 || m > 59 || s > 61)
        return (time_t)0;
    struct tm tm = {0};
    tm.tm_year = Y - 1900;
    tm.tm_mon = M - 1;
    tm.tm_mday = D;
    tm.tm_hour = h;
    tm.tm_min = m;
    tm.tm_sec = s;
    tm.tm_isdst = -1;
    time_t t = mktime(&tm);
    return t < 0 ? (time_t)0 : t;
}

/* 解析一行落盘记录 "ts|LEVEL|msg"：成功填充并返回 true。
   等级字段自 2026-09 起渲染为名称（DEBUG/INFO/WARN/ERROR），旧文件仍是
   纯数字——两者都接受；**未知等级一律判为无效行跳过**，不能退化成 atoi
   （"INFO" 会被静默当成 0=DEBUG，等级过滤与展示一起失真）。
   **不改写 line**——同一份缓冲要先后被「统计」「填充」两遍扫描，
   就地切断分隔符会让第二遍再也找不到原始分段。 */
static bool disk_parse_line(const char* line, size_t len, time_t* out_t, int* out_level,
                            const char** out_msg, size_t* out_msg_len) {
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) len--;
    if (len == 0) return false;
    const char* p1 = memchr(line, '|', len);
    if (!p1) return false;
    const char* lvl = p1 + 1;
    size_t lvl_len = len - (size_t)(lvl - line);
    const char* p2 = memchr(lvl, '|', lvl_len);
    if (!p2) return false;
    char ts[32];
    size_t tlen = (size_t)(p1 - line);
    if (tlen >= sizeof(ts)) return false;
    memcpy(ts, line, tlen);
    ts[tlen] = '\0';
    time_t t = parse_log_ts(ts);
    if (t == 0) return false;
    char lvl_buf[16];
    size_t lvlen = (size_t)(p2 - lvl);
    if (lvlen == 0 || lvlen >= sizeof(lvl_buf)) return false;
    memcpy(lvl_buf, lvl, lvlen);
    lvl_buf[lvlen] = '\0';
    int level = nsp_log_level_parse(lvl_buf);
    if (level < 0) return false;
    const char* msg = p2 + 1;
    size_t mlen = len - (size_t)(msg - line);
    if (mlen == 0) return false;
    *out_t = t;
    *out_level = level;
    *out_msg = msg;
    *out_msg_len = mlen;
    return true;
}

/* 读文件末尾至多 DISK_READ_MAX 字节。*out_partial=true 表示从中间截断
 （首行残缺，统计/填充两遍都要跳过首行）。返回 NUL 结尾的 malloc 缓冲，失败 NULL。 */
static char* disk_read_tail(const char* path, size_t* out_len, bool* out_partial) {
    *out_len = 0;
    *out_partial = false;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return nullptr;
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        close(fd);
        return nullptr;
    }
    size_t size = (size_t)st.st_size;
    size_t off = 0;
    if (size > DISK_READ_MAX) {
        off = size - DISK_READ_MAX;
        *out_partial = true;
    }
    size_t len = size - off;
    char* buf = (char*)malloc(len + 1);
    if (!buf) {
        close(fd);
        return nullptr;
    }
    if (off > 0 && lseek(fd, (off_t)off, SEEK_SET) < 0) {
        free(buf);
        close(fd);
        return nullptr;
    }
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        got += (size_t)n;
    }
    close(fd);
    buf[got] = '\0';
    *out_len = got;
    return buf;
}

/* 第一遍：只累计有效条数与字符串总字节数（用于一次性分配，避免反复 realloc） */
static void disk_count_lines(const char* text, size_t len, bool skip_first, int* cnt,
                             size_t* bytes) {
    size_t pos = 0;
    bool first = skip_first;
    while (pos < len) {
        const char* nl = memchr(text + pos, '\n', len - pos);
        size_t line_len = nl ? (size_t)(nl - (text + pos)) : len - pos;
        if (!first) {
            time_t t;
            int level;
            const char* msg;
            size_t mlen;
            if (disk_parse_line(text + pos, line_len, &t, &level, &msg, &mlen)) {
                (*cnt)++;
                *bytes += mlen + 1;
            }
        }
        first = false;
        pos += line_len + (nl ? 1 : 0);
    }
}

/* 第二遍：写入预分配好的条目数组与字符串池（游标由调用方跨文件累计，
   保证 .1 → io.log 的旧新顺序） */
static void disk_fill_lines(const char* text, size_t len, bool skip_first, DiskEntry* entries,
                            char* strings, int* cursor, size_t* str_off) {
    size_t pos = 0;
    bool first = skip_first;
    while (pos < len) {
        const char* nl = memchr(text + pos, '\n', len - pos);
        size_t line_len = nl ? (size_t)(nl - (text + pos)) : len - pos;
        if (!first) {
            time_t t;
            int level;
            const char* msg;
            size_t mlen;
            if (disk_parse_line(text + pos, line_len, &t, &level, &msg, &mlen)) {
                DiskEntry* e = &entries[*cursor];
                e->t = t;
                e->level = level;
                e->msg = strings + *str_off;
                memcpy(strings + *str_off, msg, mlen);
                strings[*str_off + mlen] = '\0';
                *str_off += mlen + 1;
                (*cursor)++;
            }
        }
        first = false;
        pos += line_len + (nl ? 1 : 0);
    }
}

static void disk_free(DiskLogBuf* d) {
    if (!d) return;
    free(d->data);
    free(d->strings);
    d->data = nullptr;
    d->strings = nullptr;
    d->count = 0;
}

static void disk_load(DiskLogBuf* d, const char* rot_path, const char* cur_path) {
    size_t len1 = 0, len2 = 0;
    bool part1 = false, part2 = false;
    char* text1 = disk_read_tail(rot_path, &len1, &part1);
    char* text2 = disk_read_tail(cur_path, &len2, &part2);
    int cnt = 0;
    size_t bytes = 0;
    if (text1) disk_count_lines(text1, len1, part1, &cnt, &bytes);
    if (text2) disk_count_lines(text2, len2, part2, &cnt, &bytes);
    DiskEntry* entries = cnt > 0 ? (DiskEntry*)malloc((size_t)cnt * sizeof(DiskEntry)) : nullptr;
    char* strings = bytes > 0 ? (char*)malloc(bytes) : nullptr;
    if (cnt > 0 && (!entries || !strings)) {
        free(entries);
        free(strings);
        free(text1);
        free(text2);
        d->data = nullptr;
        d->strings = nullptr;
        d->count = 0;
        LOG_ERR("磁盘历史快照分配失败: %d 条 / %zu 字节", cnt, bytes);
        return;
    }
    int cursor = 0;
    size_t str_off = 0;
    if (text1) disk_fill_lines(text1, len1, part1, entries, strings, &cursor, &str_off);
    if (text2) disk_fill_lines(text2, len2, part2, entries, strings, &cursor, &str_off);
    free(text1);
    free(text2);
    d->data = entries;
    d->strings = strings;
    d->count = cursor;
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
    if (type == 1)
        persist_stage(&g_persist_io, msg, level, now);
    else if (type == 2)
        persist_stage(&g_persist_sys, msg, level, now);
}
static void drain_async(AsyncCtx* ctx) {
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
        char* msg = async_slot_msg(ctx, ctx->tail);
        int level = ctx->entries[ctx->tail].level;
        int entry_type = ctx->entries[ctx->tail].type;
        if (entry_type == 1) {
            if (!should_ignore_io(msg)) push_log(&g_io_buf, msg, 1, LOG_INFO);
        } else if (entry_type == 2) {
            push_log(&g_sys_buf, msg, 2, level);
        } else if (entry_type == 3) {
            push_log(&g_logcat_buf, msg, 3, LOG_INFO);
        }
        async_slot_release(ctx, ctx->tail);
        ctx->tail = (ctx->tail + 1) & (RING_CAP - 1);
    }
}

/* 丢弃告警：计数有变化时至多每 DROP_REPORT_INTERVAL_MS 上报一行到 sys 缓冲。
   由 500ms 定时 tick 驱动，不占用任何查询协议（不动 COUNT 响应格式）。 */
#define DROP_REPORT_INTERVAL_MS 10000
static uint64_t g_drop_reported = 0;
static uint64_t g_drop_report_ms = 0;

static void report_drops_once(void) {
    uint64_t ring_drop = atomic_load_explicit(&g_drop_entries, memory_order_relaxed);
    uint64_t batch_drop = atomic_load_explicit(&g_drop_batch, memory_order_relaxed);
    uint64_t drops = ring_drop + batch_drop + g_persist_io.dropped + g_persist_sys.dropped;
    if (drops == g_drop_reported) return;
    uint64_t now = persist_now_ms();
    if (g_drop_report_ms != 0 && now - g_drop_report_ms < DROP_REPORT_INTERVAL_MS) return;
    g_drop_reported = drops;
    g_drop_report_ms = now;
    char msg[256];
    snprintf(msg, sizeof(msg),
             "日志链路丢弃累计: 接收环满 %llu 条, 合并队列满 %llu 包, "
             "落盘拒收 IO %llu / SYS %llu 行（限频告警，每 %d s 至多一次）",
             (unsigned long long)ring_drop, (unsigned long long)batch_drop,
             (unsigned long long)g_persist_io.dropped, (unsigned long long)g_persist_sys.dropped,
             (unsigned)(DROP_REPORT_INTERVAL_MS / 1000));
    push_log(&g_sys_buf, msg, 2, LOG_WARN);
}
/* 停 async 线程并等它**真正退出**——free 前的同步证据。
   ctx->fd 是已接管的对端 socket：shutdown 唤醒阻塞在 read 的线程（否则它永远
   停在 read 里），线程走完当前缓冲后在循环顶看到 disconnected 退出；join 保证
   其后的 notify_fd / 环写入都已结束。只看 disconnected 不行：那是线程写的
   单向标记，主线程在它置位前 free 就是 UAF。 */
static void async_ctx_stop_thread(AsyncCtx* ctx) {
    if (!ctx->thread_started) return;
    if (ctx->fd >= 0) shutdown(ctx->fd, SHUT_RDWR);
    ctx->disconnected = true;
    pthread_join(ctx->tid, nullptr);
    ctx->thread_started = false;
}
static void cleanup_async(AsyncCtx* ctx) {
    async_ctx_stop_thread(ctx);
    AsyncCtx** pp = &g_async_clients;
    while (*pp) {
        if (*pp == ctx) {
            *pp = ctx->next;
            break;
        }
        pp = &(*pp)->next;
    }
    /* 释放环内未消费的堆溢出消息（断开时在途条目） */
    while (ctx->tail != ctx->head) {
        async_slot_release(ctx, ctx->tail);
        ctx->tail = (ctx->tail + 1) & (RING_CAP - 1);
    }
    if (ctx->fd >= 0) close(ctx->fd);
    if (ctx->notify_fd >= 0) close(ctx->notify_fd);
    free(ctx);
}
static void* async_log_thread(void* arg) {
    AsyncCtx* ctx = arg;
    nsp_set_thread_name("nsp_logasy");
    char buf[4096];
    char line[MAX_MSG_LEN + 128]; /* 行缓冲须容纳完整合并日志（单行制表符），
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
                char* msg = line;
                if (batch_collect && strncmp(msg, "LOG_BATCH_END", 13) == 0) {
                    batch_collect = 0;
                    if (batch_len > 0) {
                        /* 合并日志入多槽队列（整块入库，背靠背帧互不覆盖，
                           由主循环 drain_async 逐槽 push 入 g_sys_buf） */
                        int slot = ctx->batch_q_head % BATCH_Q_CAP;
                        if ((ctx->batch_q_head - ctx->batch_q_tail) < BATCH_Q_CAP) {
                            size_t copy = (batch_len < (int)sizeof(ctx->batch_q[slot].msg))
                                              ? (size_t)batch_len
                                              : sizeof(ctx->batch_q[slot].msg) - 1;
                            memcpy(ctx->batch_q[slot].msg, batch_msg, copy);
                            ctx->batch_q[slot].msg[copy] = '\0';
                            ctx->batch_q[slot].len = (int)copy;
                            ctx->batch_q_head++;
                            uint64_t val = 1;
                            write(ctx->notify_fd, &val, sizeof(val));
                        } else {
                            /* 合并队列满：丢弃本包并计数（见 report_drops_once） */
                            atomic_fetch_add_explicit(&g_drop_batch, 1, memory_order_relaxed);
                        }
                    }
                    pos = 0;
                    continue;
                }
                if (!batch_collect && strncmp(msg, "LOG_BATCH", 9) == 0 && msg[9] == '\0') {
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
                    ctx->type = 1;
                    msg += 7;
                } else if (strncmp(msg, "LOG_SYS:", 8) == 0) {
                    ctx->type = 2;
                    msg += 8;
                } else if (strncmp(msg, "LOG_LOGCAT:", 11) == 0) {
                    ctx->type = 3;
                    msg += 11;
                }
                if (ctx->type == 2 && msg[0] >= '0' && msg[0] <= '9') {
                    level = msg[0] - '0';
                    char* colon = strchr(msg, ':');
                    if (colon) msg = colon + 1;
                }
                int next = (ctx->head + 1) & (RING_CAP - 1);
                if (next != ctx->tail) {
                    async_slot_store(ctx, ctx->head, msg);
                    ctx->entries[ctx->head].level = level;
                    ctx->entries[ctx->head].type = ctx->type;
                    ctx->head = next;
                    uint64_t val = 1;
                    write(ctx->notify_fd, &val, sizeof(val));
                } else {
                    /* 接收环满：丢弃本条并计数（overflow 应急落盘已移除），
                       计数由 report_drops_once 限频上报，不再是无痕丢失 */
                    atomic_fetch_add_explicit(&g_drop_entries, 1, memory_order_relaxed);
                }
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
                    char* msg = line;
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
                                                  ? (size_t)batch_len
                                                  : sizeof(ctx->batch_q[slot].msg) - 1;
                                memcpy(ctx->batch_q[slot].msg, batch_msg, copy);
                                ctx->batch_q[slot].msg[copy] = '\0';
                                ctx->batch_q[slot].len = (int)copy;
                                ctx->batch_q_head++;
                                uint64_t val = 1;
                                write(ctx->notify_fd, &val, sizeof(val));
                            } else {
                                /* 合并队列满：丢弃本包并计数（见 report_drops_once） */
                                atomic_fetch_add_explicit(&g_drop_batch, 1, memory_order_relaxed);
                            }
                        }
                        pos = 0;
                        continue;
                    }
                    /* 合并包头：进入收集模式（要求第 10 字符为行尾，避免
                       误匹配 LOG_BATCH_END） */
                    if (!batch_collect && strncmp(msg, "LOG_BATCH", 9) == 0 && msg[9] == '\0') {
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
                        ctx->type = 1;
                        msg += 7;
                    } else if (strncmp(msg, "LOG_SYS:", 8) == 0) {
                        ctx->type = 2;
                        msg += 8;
                    } else if (strncmp(msg, "LOG_LOGCAT:", 11) == 0) {
                        ctx->type = 3;
                        msg += 11;
                    }
                    if (ctx->type == 2 && msg[0] >= '0' && msg[0] <= '9') {
                        level = msg[0] - '0';
                        char* colon = strchr(msg, ':');
                        if (colon) msg = colon + 1;
                    }
                    int next = (ctx->head + 1) & (RING_CAP - 1);
                    if (next != ctx->tail) {
                        async_slot_store(ctx, ctx->head, msg);
                        ctx->entries[ctx->head].level = level;
                        ctx->entries[ctx->head].type = ctx->type;
                        ctx->head = next;
                        uint64_t val = 1;
                        write(ctx->notify_fd, &val, sizeof(val));
                    } else {
                        /* 接收环满：丢弃本条并计数（见 report_drops_once） */
                        atomic_fetch_add_explicit(&g_drop_entries, 1, memory_order_relaxed);
                    }
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
static int parse_op_string(const char* op_str) {
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
    FILE* fp = fopen(MONITOR_IGNORE_PATH, "re");
    IgnoreRule* cur = g_ignore_rules;
    while (cur) {
        IgnoreRule* next = cur->next;
        free(cur->path_prefix);
        free(cur);
        cur = next;
    }
    g_ignore_rules = nullptr;
    int count = 0;
    if (fp) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            char* p = line;
            if (strncmp(p, "\xEF\xBB\xBF", 3) == 0) p += 3;
            p = nsp_str_trim(p);
            if (*p == '#' || *p == '\0') continue;
            int op_mask = 0;
            char* path = p;
            if (*p == '[') {
                char* close_ptr = strchr(p, ']');
                if (close_ptr) {
                    *close_ptr = '\0';
                    char* ops = p + 1;
                    char* saveptr = nullptr;
                    char* token = strtok_r(ops, ",", &saveptr);
                    while (token) {
                        int op = parse_op_string(token);
                        if (op) op_mask |= op;
                        token = strtok_r(nullptr, ",", &saveptr);
                    }
                    path = close_ptr + 1;
                    while (isspace((unsigned char)*path)) path++;
                }
            }
            if (op_mask == 0) op_mask = ~0;
            if (path[0] != '/' && path[0] != '*') continue;
            IgnoreRule* rule = malloc(sizeof(IgnoreRule));
            rule->op_mask = op_mask;
            rule->path_prefix = strdup(path);
            rule->is_wildcard = (strpbrk(path, "*?[]") != nullptr);
            rule->next = g_ignore_rules;
            g_ignore_rules = rule;
            count++;
        }
        fclose(fp);
    }
    char msg[256];
    snprintf(msg, sizeof(msg), "[log_monitor] 加载监控忽略规则完成，共 %d 条", count);
    push_log(&g_sys_buf, msg, 2, LOG_DEBUG);
}
static bool should_ignore_io(const char* line) {
    const char* op_bracket = strchr(line, '[');
    if (!op_bracket) return false;
    op_bracket = strchr(op_bracket + 1, '[');
    if (!op_bracket) return false;
    const char* op_end = strchr(op_bracket, ']');
    if (!op_end) return false;
    char op_buf[32];
    size_t op_len = op_end - (op_bracket + 1);
    if (op_len >= sizeof(op_buf)) op_len = sizeof(op_buf) - 1;
    strncpy(op_buf, op_bracket + 1, op_len);
    op_buf[op_len] = '\0';
    int op_mask = parse_op_string(op_buf);
    if (op_mask == 0) return false;
    const char* path_start = op_end + 1;
    while (isspace((unsigned char)*path_start)) path_start++;
    if (*path_start == '\0') return false;
    const char* path_end = strstr(path_start, " -> ");
    if (!path_end) path_end = path_start + strlen(path_start);
    char path_buf[PATH_MAX];
    size_t path_len = path_end - path_start;
    if (path_len >= sizeof(path_buf)) path_len = sizeof(path_buf) - 1;
    strncpy(path_buf, path_start, path_len);
    path_buf[path_len] = '\0';
    IgnoreRule* rule = g_ignore_rules;
    bool ignore = false;
    while (rule) {
        if (rule->op_mask & op_mask) {
            if (rule->is_wildcard) {
                if (fnmatch(rule->path_prefix, path_buf, 0) == 0) {
                    ignore = true;
                    break;
                }
            } else {
                if (strncmp(path_buf, rule->path_prefix, strlen(rule->path_prefix)) == 0) {
                    ignore = true;
                    break;
                }
            }
        }
        rule = rule->next;
    }
    return ignore;
}
static bool search_hit(int level, const char* msg, const char* key, int level_filter) {
    return (level_filter < 0 || level >= level_filter) &&
           (!key || key[0] == '\0' || strstr(msg, key));
}

static void search_emit_line(int fd, time_t t, int level, const char* msg, const char* log_type) {
    char line[MAX_MSG_LEN + 128];
    struct tm tm_info;
    localtime_r(&t, &tm_info);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    int len;
    if (log_type && strcmp(log_type, "sys") == 0) {
        /* SYS 查询行附带等级名（与落盘行/STREAM_SYS_API 格式一致）：
           客户端据此执行等级阈值过滤 */
        len = snprintf(line, sizeof(line), "%s|%s|%s\n", time_buf, nsp_log_level_name(level), msg);
    } else {
        len = snprintf(line, sizeof(line), "%s|%s\n", time_buf, msg);
    }
    write(fd, line, len);
}

/* 分页查询：内存环（newest→oldest）在前、落盘快照（newest→oldest）在后，
   offset/limit 跨段共享计数 */
static void search_log_paged(int fd, LogBuffer* buf, const DiskLogBuf* disk, const char* key,
                             int limit, int offset, int level_filter, const char* log_type) {
    int total_in_buf = buf->full ? buf->max : (buf->head - buf->tail + buf->max) % buf->max;
    int total_matched = 0;
    int idx = buf->tail;
    for (int i = 0; i < total_in_buf; i++) {
        if (search_hit(buf->data[idx].level, buf->data[idx].msg, key, level_filter))
            total_matched++;
        idx = (idx + 1) % buf->max;
    }
    if (disk) {
        for (int i = 0; i < disk->count; i++) {
            if (search_hit(disk->data[i].level, disk->data[i].msg, key, level_filter))
                total_matched++;
        }
    }
    int sent_count = 0;
    int skip_count = 0;
    char line[MAX_MSG_LEN + 128];
    idx = (buf->head - 1 + buf->max) % buf->max;
    for (int i = 0; i < total_in_buf && sent_count < limit; i++) {
        if (search_hit(buf->data[idx].level, buf->data[idx].msg, key, level_filter)) {
            if (skip_count < offset)
                skip_count++;
            else {
                search_emit_line(fd, buf->data[idx].t, buf->data[idx].level, buf->data[idx].msg,
                                 log_type);
                sent_count++;
            }
        }
        idx = (idx - 1 + buf->max) % buf->max;
    }
    if (disk) {
        for (int i = disk->count - 1; i >= 0 && sent_count < limit; i--) {
            if (search_hit(disk->data[i].level, disk->data[i].msg, key, level_filter)) {
                if (skip_count < offset)
                    skip_count++;
                else {
                    search_emit_line(fd, disk->data[i].t, disk->data[i].level, disk->data[i].msg,
                                     log_type);
                    sent_count++;
                }
            }
        }
    }
    (void)log_type; /* 保留参数供行格式分支使用；overflow 查询已移除 */
    int remaining = total_matched - (offset + sent_count);
    if (remaining < 0) remaining = 0;
    snprintf(line, sizeof(line), "DONE|%d|%d\n", total_matched, remaining);
    write(fd, line, strlen(line));
}
static void add_active_client(ClientCtx* ctx) {
    ctx->next = g_active_clients;
    ctx->prev = nullptr;
    if (g_active_clients) {
        g_active_clients->prev = ctx;
    }
    g_active_clients = ctx;
}
static void remove_active_client(ClientCtx* ctx) {
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
static bool dump_one_entry(int fd, time_t t, int level, const char* msg, int type, int min_level,
                           bool with_ts, bool with_level) {
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
        const char* lvl_name = nsp_log_level_name(level);
        size_t lvl_len = strlen(lvl_name);
        memcpy(line_buf + off, lvl_name, lvl_len);
        off += (int)lvl_len;
        line_buf[off++] = '|';
    }
    memcpy(line_buf + off, msg, msg_len);
    line_buf[off + msg_len] = '\n';
    line_buf[off + msg_len + 1] = '\0';
    ssize_t ret = send(fd, line_buf, off + msg_len + 1, MSG_NOSIGNAL | MSG_DONTWAIT);
    return !(ret <= 0 && (errno != EAGAIN && errno != EWOULDBLOCK));
}

/* 历史转储：落盘快照（oldest→newest）在前、内存环在后拼接。
 * with_level 时为 SYS 条目附加 "<LEVEL>|" 等级名前缀（与 STREAM_SYS_API
 * 实时推送行格式一致：ts|LEVEL|msg，LEVEL ∈ DEBUG/INFO/WARN/ERROR），
 * 客户端据此做等级阈值过滤 */
static void dump_buf_to_client(int fd, LogBuffer* buf, const DiskLogBuf* disk, int type,
                               int min_level, bool with_ts, bool with_level) {
    if (disk) {
        for (int i = 0; i < disk->count; i++) {
            if (!dump_one_entry(fd, disk->data[i].t, disk->data[i].level, disk->data[i].msg, type,
                                min_level, with_ts, with_level))
                return;
        }
    }
    int total_in_buf = buf->full ? buf->max : (buf->head - buf->tail + buf->max) % buf->max;
    int idx = buf->tail;
    for (int i = 0; i < total_in_buf; i++) {
        if (!dump_one_entry(fd, buf->data[idx].t, buf->data[idx].level, buf->data[idx].msg, type,
                            min_level, with_ts, with_level))
            break;
        idx = (idx + 1) % buf->max;
    }
}
static int process_line(ClientCtx* ctx, char* line, const char* leftover, int leftover_len) {
    int fd = ctx->fd;
    if (strncmp(line, "LOG_IO:", 7) == 0 || strncmp(line, "LOG_SYS:", 8) == 0 ||
        strncmp(line, "LOG_LOGCAT:", 11) == 0) {
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, ctx->fd, nullptr);
        AsyncCtx* actx = calloc(1, sizeof(AsyncCtx));
        if (!actx) {
            /* OOM：与 LOG_BATCH 分支同一处理——无法移交 async 线程，丢弃该
               连接（至少不崩溃、不泄漏 fd）。此前缺这一步，OOM 即 NULL
               解引用崩掉整个日志服务 */
            LOG_ERR("AsyncCtx 分配失败，丢弃连接 fd=%d", ctx->fd);
            close(ctx->fd);
            ctx->fd = -1;
            return 1;
        }
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
        char* msg = line;
        int level = LOG_INFO;
        int entry_type = 0;
        if (strncmp(msg, "LOG_IO:", 7) == 0) {
            entry_type = 1;
            msg += 7;
        } else if (strncmp(msg, "LOG_SYS:", 8) == 0) {
            entry_type = 2;
            msg += 8;
            if (msg[0] >= '0' && msg[0] <= '9') {
                level = msg[0] - '0';
                char* colon = strchr(msg, ':');
                if (colon) msg = colon + 1;
            }
        } else if (strncmp(msg, "LOG_LOGCAT:", 11) == 0) {
            entry_type = 3;
            msg += 11;
        }
        actx->type = entry_type;
        async_slot_store(actx, 0, msg);
        actx->entries[0].level = level;
        actx->entries[0].type = entry_type;
        actx->head = 1;
        actx->tail = 0;
        actx->next = g_async_clients;
        g_async_clients = actx;
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = actx->notify_fd};
        epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, actx->notify_fd, &ev);
        if (pthread_create(&actx->tid, nullptr, async_log_thread, actx) != 0) {
            /* 线程创建失败：actx 留在链表但无消费者，阻塞 fd 泄漏；移除并清理
               （thread_started 仍为 false，cleanup_async 不会去 join 不存在的线程） */
            LOG_ERR("async 日志线程创建失败，丢弃连接 fd=%d", actx->fd);
            epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, actx->notify_fd, nullptr);
            cleanup_async(actx);
            ctx->fd = -1;
            return 1;
        }
        actx->thread_started = true;
        ctx->fd = -1;
        return 1;
    } else if (strncmp(line, "LOG_BATCH", 9) == 0 && line[9] == '\0') {
        /* LOG_BATCH 合并帧作为连接首个数据包（重连/重启后稳态、全局替换
           模式下环形缓冲首条即合并摘要）：不能像普通日志行解析入 entries
           （无级别/类型前缀），整帧（头行 + 粘包剩余字节）移交给 async
           线程按帧协议收集——否则主循环逐行处理时每行返回 0，帧被丢弃 */
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, ctx->fd, nullptr);
        AsyncCtx* actx = calloc(1, sizeof(AsyncCtx));
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
        actx->head = 0;
        actx->tail = 0;
        actx->next = g_async_clients;
        g_async_clients = actx;
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = actx->notify_fd};
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, actx->notify_fd, &ev) != 0) {
            /* notify_fd 注册失败：drain_async 永不触发，帧静默丢弃；
               cleanup_async 从链表移除并关闭 fd/释放 actx */
            ctx->fd = -1; /* 防止主循环 close 已接管 fd */
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
        actx->thread_started = true;
        ctx->fd = -1;
        return 1;
    } else if (strncmp(line, "QUERY_IO:", 9) == 0 || strncmp(line, "QUERY_SYS:", 10) == 0 ||
               strncmp(line, "QUERY_LOGCAT:", 13) == 0) {
        /* 通道由**已匹配的固定前缀**三选一决定，偏移取定值。旧实现在**整行**
           （含搜索关键字）上 strstr("IO")/strstr("LOGCAT")：`log_ctl search-sys IO`
           拼出的 `QUERY_SYS:-1:IO:100:0` 会被判成 io 通道，且 rest 错位到前缀中间
           → 静默返回另一个环的数据（关键字含 "IO"/"LOGCAT" 即触发）。 */
        enum { CH_IO, CH_SYS, CH_LOGCAT } ch;
        size_t skip;
        if (strncmp(line, "QUERY_IO:", 9) == 0) {
            ch = CH_IO;
            skip = 9;
        } else if (strncmp(line, "QUERY_LOGCAT:", 13) == 0) {
            ch = CH_LOGCAT;
            skip = 13;
        } else {
            ch = CH_SYS;
            skip = 10;
        }
        char* rest = line + skip;
        int limit = DEFAULT_LIMIT, offset = 0, level_filter = -1;
        char* key = rest;
        char* level_s = strchr(rest, ':');
        if (level_s) {
            *level_s = 0;
            level_s++;
            level_filter = atoi(rest);
            key = level_s;
            char* limit_s = strchr(key, ':');
            if (limit_s) {
                *limit_s = 0;
                limit_s++;
                char* offset_s = strchr(limit_s, ':');
                if (offset_s) {
                    *offset_s = 0;
                    offset_s++;
                    offset = atoi(offset_s);
                }
                limit = atoi(limit_s);
            }
        }
        search_log_paged(fd,
                         ch == CH_IO ? &g_io_buf
                                     : (ch == CH_LOGCAT ? &g_logcat_buf : &g_sys_buf),
                         ch == CH_IO ? &g_io_disk
                                     : (ch == CH_LOGCAT ? nullptr : &g_sys_disk),
                         key, limit, offset, level_filter,
                         ch == CH_IO ? "io" : (ch == CH_LOGCAT ? "logcat" : "sys"));
        return 1;
    } else if (strcmp(line, "CLEAR_IO") == 0) {
        g_io_buf.head = g_io_buf.tail = 0;
        g_io_buf.full = false;
        /* 同步清启动快照、暂存与落盘文件（暂存不清会与 tick 刷盘竞态复活文件） */
        disk_free(&g_io_disk);
        g_persist_io.staged = 0;
        unlink(g_persist_io.path);
        unlink(g_persist_io.rot);
        write(fd, "OK\n", 3);
        return 1;
    } else if (strcmp(line, "CLEAR_SYS") == 0) {
        g_sys_buf.head = g_sys_buf.tail = 0;
        g_sys_buf.full = false;
        disk_free(&g_sys_disk);
        g_persist_sys.staged = 0;
        unlink(g_persist_sys.path);
        unlink(g_persist_sys.rot);
        write(fd, "OK\n", 3);
        return 1;
    } else if (strcmp(line, "CLEAR_LOGCAT") == 0) {
        g_logcat_buf.head = g_logcat_buf.tail = 0;
        g_logcat_buf.full = false;
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
        int io_total =
            g_io_disk.count + (g_io_buf.full
                                   ? g_io_buf.max
                                   : (g_io_buf.head - g_io_buf.tail + g_io_buf.max) % g_io_buf.max);
        int sys_total =
            g_sys_disk.count +
            (g_sys_buf.full ? g_sys_buf.max
                            : (g_sys_buf.head - g_sys_buf.tail + g_sys_buf.max) % g_sys_buf.max);
        int logcat_total =
            g_logcat_buf.full
                ? g_logcat_buf.max
                : (g_logcat_buf.head - g_logcat_buf.tail + g_logcat_buf.max) % g_logcat_buf.max;
        char resp[128];
        int len =
            snprintf(resp, sizeof(resp), "COUNT|%d|%d|%d\n", io_total, sys_total, logcat_total);
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
void handle_signal(int sig) {
    if (sig == SIGINT || sig == SIGTERM) g_should_exit = 1;
}
/* 核心优化：合并异步定时器超时回调 */
static int setup_client_timeout_timer(int epoll_fd) {
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd < 0) return -1;
    struct itimerspec ts = {.it_interval = {.tv_sec = 0, .tv_nsec = 500000000},
                            .it_value = {.tv_sec = 0, .tv_nsec = 500000000}};
    timerfd_settime(timer_fd, 0, &ts, nullptr);
    struct epoll_event ev_t = {.events = EPOLLIN, .data.fd = timer_fd};
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev_t);
    return timer_fd;
}
static void handle_client_timeout_tick(int timer_fd) {
    uint64_t expirations;
    ssize_t r = read(timer_fd, &expirations, sizeof(expirations));
    (void)r;
    persist_lazy_tick(); /* 落盘懒刷盘（500ms tick 驱动） */
    report_drops_once(); /* 链路丢弃限频告警（500ms tick 限频到 10s 一条） */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    ClientCtx* curr_chk = g_active_clients;
    while (curr_chk) {
        ClientCtx* next_chk = curr_chk->next;
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
    AsyncCtx** app = &g_async_clients;
    while (*app) {
        AsyncCtx* a = *app;
        if (a->disconnected) {
            /* async 线程已置位并返回（acquire 读取，见 AsyncCtx::disconnected
               注释）：cleanup_async 先 join 收尸，再把环内尚未移交的条目/合并包
               入库后回收。漏掉 drain，线程末尾写入、但 notify 事件与置位错峰
               未再触发 epoll 的那批日志会随 free 一起静默消失——生产者侧日志
               "只发不收"的第二个丢失点。cleanup_async 已把 *app 指向下一个，
               故本层不推进 app。 */
            epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, a->notify_fd, nullptr);
            cleanup_async(a);
        } else {
            app = &(*app)->next;
        }
    }
}
int main(int argc, char* argv[]) {
    escape_cgroup();
    init_timezone();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    bool verbose = false;
    int opt;
    static struct option long_options[] = {{"persist-all", no_argument, nullptr, 'p'},
                                           {"help", no_argument, nullptr, 'h'},
                                           {"verbose", no_argument, nullptr, 'v'},
                                           {nullptr, 0, nullptr, 0}};
    while ((opt = getopt_long(argc, argv, "phv", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'p': g_persist_all_logs = 1; break;
            case 'v': verbose = true; break;
            default: break;
        }
    }
    (void)verbose;
    init_buf(&g_io_buf, MAX_IO_LOGS);
    init_buf(&g_sys_buf, MAX_SYS_LOGS);
    init_buf(&g_logcat_buf, MAX_LOGCAT_LOGS);
    /* io/sys 自动落盘常开：建目录 + 初始化暂存器（先于首条 push_log） */
    mkdir(LOG_DIR, 0755);
    persist_init_writer(&g_persist_io, "io");
    persist_init_writer(&g_persist_sys, "sys");
    /* 启动加载落盘快照到只读独立缓冲（与内存拼接，客户端获取时合并） */
    disk_load(&g_io_disk, g_persist_io.rot, g_persist_io.path);
    disk_load(&g_sys_disk, g_persist_sys.rot, g_persist_sys.path);
    load_ignore_rules();
    /* 环境信息仅 injector 输出一次（崩溃归因走 crash_dump 的 Build 行），此处不重复 */
    g_server_sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un addr;
    socklen_t addr_len = nsp_uds_abstract_addr(&addr, LOG_SOCKET_NAME);
    unlink(LOG_SOCKET_NAME);
    bind(g_server_sock, (struct sockaddr*)&addr, addr_len);
    listen(g_server_sock, 128);
    g_epoll_fd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = g_server_sock;
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_server_sock, &ev);
    int inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd >= 0) {
        inotify_add_watch(inotify_fd, CONFIG_DIR,
                          IN_MODIFY | IN_MOVED_TO | IN_CREATE | IN_CLOSE_WRITE | IN_DELETE);
        ev.events = EPOLLIN;
        ev.data.fd = inotify_fd;
        epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, inotify_fd, &ev);
    }
    /* 启动 client 超时异步定时器并注册至 epoll */
    int timer_fd = setup_client_timeout_timer(g_epoll_fd);
    /* 统一通讯线程：STREAM 实时推送扇出改由 comm 线程驱动，主线程只 post */
    nsp_comm_init();
    nsp_comm_backend_t stream_be = {
        .ctx = NULL,
        .ensure_link = NULL,
        .emit = stream_emit,
        .fini = NULL,
        .report = nsp_log_report,
    };
    nsp_comm_register(NSP_CH_BCAST, &stream_be);
    while (!g_should_exit) {
        int nfds =
            epoll_wait(g_epoll_fd, events, MAX_EVENTS, -1); /* 取消同步 100ms 超时，转为无限等待 */
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            if (fd == g_server_sock) {
                int client = accept(g_server_sock, nullptr, nullptr);
                if (client >= 0) {
                    set_nonblock(client);
                    ClientCtx* ctx = calloc(1, sizeof(ClientCtx));
                    if (!ctx) {
                        /* OOM：拒绝该连接，而不是解引用 NULL 崩掉整个日志服务。
                           本循环还要处理同批次其它事件，故用 else 分支而非 continue */
                        LOG_ERR("ClientCtx 分配失败，拒绝连接 fd=%d", client);
                        close(client);
                    } else {
                        ctx->fd = client;
                        clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);
                        ctx->is_streaming = false;
                        add_active_client(ctx);
                        ev.events = EPOLLIN | EPOLLET;
                        ev.data.ptr = ctx;
                        epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, client, &ev);
                    }
                }
            } else if (inotify_fd >= 0 && fd == inotify_fd) {
                char inotify_buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
                ssize_t len;
                while ((len = read(inotify_fd, inotify_buf, sizeof(inotify_buf))) > 0) {
                    bool need_reload = false;
                    for (char* ptr = inotify_buf; ptr < inotify_buf + len;) {
                        struct inotify_event* ev_inotify = (struct inotify_event*)ptr;
                        if (ev_inotify->len && strstr(ev_inotify->name, "monitor_ignore.conf"))
                            need_reload = true;
                        ptr += sizeof(struct inotify_event) + ev_inotify->len;
                    }
                    if (need_reload) load_ignore_rules();
                }
            } else if (fd == timer_fd) {
                /* 处理异步定时器事件 */
                handle_client_timeout_tick(timer_fd);
            } else {
                int event_fd = events[i].data.fd;
                AsyncCtx* actx = nullptr;
                for (AsyncCtx* a = g_async_clients; a; a = a->next) {
                    if (a->notify_fd == event_fd) {
                        actx = a;
                        break;
                    }
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
                    char buf[4096];
                    bool consumed = false;
                    while (!consumed) {
                        ssize_t n = read(ctx->fd, buf, sizeof(buf));
                        if (n > 0) {
                            for (ssize_t j = 0; j < n; j++) {
                                if (buf[j] == '\n') {
                                    ctx->line[ctx->pos] = '\0';
                                    if (ctx->pos > 0) {
                                        if (process_line(ctx, ctx->line, buf + j + 1,
                                                         (int)(n - (j + 1)))) {
                                            consumed = true;
                                            break;
                                        }
                                    }
                                    ctx->pos = 0;
                                } else if (ctx->pos < sizeof(ctx->line) - 1)
                                    ctx->line[ctx->pos++] = buf[j];
                            }
                        } else if (n == -1 && errno == EAGAIN)
                            break;
                        else {
                            consumed = true;
                            break;
                        }
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
        StreamClient* tmp = g_stream_clients;
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
    /* 逐个 shutdown→join→drain→close→free（cleanup_async 的唯一出口）。
       join 必须在 drain 之前：线程还活着时 drain 完的环仍可能被它继续写，
       那些条目会随 free 一起静默丢失。 */
    while (g_async_clients) cleanup_async(g_async_clients);
    /* 退出前刷盘残余暂存并释放 */
    persist_flush(&g_persist_io);
    persist_flush(&g_persist_sys);
    free(g_persist_io.stage);
    g_persist_io.stage = nullptr;
    free(g_persist_sys.stage);
    g_persist_sys.stage = nullptr;
    disk_free(&g_io_disk);
    disk_free(&g_sys_disk);
    destroy_buf(&g_io_buf);
    destroy_buf(&g_sys_buf);
    destroy_buf(&g_logcat_buf);
    return 0;
}