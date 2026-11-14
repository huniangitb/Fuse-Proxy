#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* SO_PASSCRED/SCM_CREDENTIALS、SOCK_CLOEXEC、struct ucred：GNU 分支已定义 */
#endif
#include "fw_events.h"

#include "common.h"
#include "config_parser.h"
#include "fw_pkg.h"
#include "fw_rules.h"
#include "nsp_constants.h"
#include "nsp_log.h"
#include "nsp_util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/*
 * fw_events.c — FUSE 事件通道生产侧（契约：FUSE-EVENTS.md v5 冻结版）
 *
 * ================== 为什么要"另一条"路径 ==================
 * MediaProvider 扫描靠的是"知道哪个路径刚变过"。AOSP 的做法是让 MediaProvider
 * 自己挂 FUSE 当裁判（我们的架构里裁判是 fuse_daemon），所以变更事实必须由
 * **我们**广播出去，扫描侧才能只扫被点名的路径而不是整树重扫（MPM 的
 * 全量扫描代价是分钟级）。契约把"谁是裁判"与"谁去扫"切开：我们不扫描媒体、
 * 不碰 MediaStore，只回答两件事——「谁变了」（事件）与「这条路此刻是什么」
 * （查询）。
 *
 * ================== 三条硬承诺怎么兑现 ==================
 * 1) 默认 OFF / 零开销
 *    [GLOBAL] FUSE_EVENTS 默认 OFF，fw_events_start 直接返回：不建 socket、不
 *    建线程、不分配内存。埋点处只有 fw_events_active() 的一次 relaxed atomic
 *    读（内联，无调用、无分支预测失败）。
 *
 * 2) IO 路径绝不阻塞
 *    埋点只做 memcpy 进**有界环形队列**（4096 槽，满则丢最旧并 dropped++），
 *    临界区仅一次结构体拷贝、无 syscall、无分配、无日志。排空、200ms 合并、
 *    路径解析（fw_rules_resolve）、JSON 渲染、socket 发送全部在事件线程里做。
 *    对外发送一律 MSG_DONTWAIT：订阅者自己塞满队列时我们丢帧计数，不反压 IO。
 *
 * 3) 判定复用单点
 *    QUERY 的规则决策只调 fw_rules_resolve、访问控制只调 fw_acl_check；本文件
 *    不出现任何 hidden/ro/重定向的路径判断（静态契约测试守着这条）。事件里的
 *    rpath 同样由 fw_rules_resolve 现算，不自己拼。
 *
 * ================== 线程模型 ==================
 *   nsp_fs_events  事件线程：poll(事件 socket, eventfd) → 排空环 → 合并 → 发送
 *                  → 心跳（5s）。单实例。
 *   nsp_fs_query   查询 accept 线程 + 每连接一条 detached 线程（上限 8）。
 * 事件线程与查询线程完全分离：查询慢（lstat、规则解析）不拖住事件广播，
 * 事件风暴不饿死查询。
 */

/* ================== 常量 ================== */

/* 名字的字面量集中在 nsp_constants.h：log_ctl 的归属诊断按同一个常量查
   /proc/net/unix，两处各写一份会静默查空。 */
#define FW_EVENTS_SOCK_NAME NSP_EVENTS_SOCK_NAME
#define FW_QUERY_SOCK_NAME NSP_EVENTS_QUERY_SOCK_NAME

#define FW_EVENTS_RING_CAP 4096
#define FW_EVENTS_PATH_MAX 256       /* fuse 视角路径 */
#define FW_EVENTS_SPATH_MAX (MAX_PATH_LEN + 64) /* 视图绝对路径 */
#define FW_EVENTS_RPATH_MAX 1024     /* 真实落盘路径（刷新事件的回退落点） */
#define FW_EVENTS_FRAME_MAX 1024     /* 契约：单帧 ≤1KB */
#define FW_EVENTS_MAX_REQ 512        /* 订阅帧上限（超长直接忽略） */

#define FW_EVENTS_COALESCE_SLOTS 64
#define FW_EVENTS_COALESCE_MS 200
#define FW_EVENTS_MAX_SUBS 8
#define FW_EVENTS_SUB_TTL_MS 60000
#define FW_EVENTS_SUB_MAX_FAILS 16
#define FW_EVENTS_PING_MS 5000
#define FW_EVENTS_POLL_MAX_MS 1000

#define FW_EVENTS_MAX_EXTRA_UIDS 8
#define FW_EVENTS_MAX_AUTO_UIDS 3 /* 自动解析的 MediaProvider 包名个数（见下） */
/* 白名单容量：默认三项（root/system/media_rw）+ 自动解析项 + 配置追加项 */
#define FW_EVENTS_MAX_ALLOW (3 + FW_EVENTS_MAX_AUTO_UIDS + FW_EVENTS_MAX_EXTRA_UIDS)

#define FW_QUERY_MAX_CONNS 8
#define FW_QUERY_MAX_INFLIGHT 8
#define FW_QUERY_REQ_MAX 1024
#define FW_QUERY_RESP_MAX 1024
#define FW_QUERY_IDLE_MS 5000

#define FW_EXISTS_SLOTS 128
#define FW_EXISTS_TTL_MS 200

#define FW_EV_MASK_DONE 0x1u
#define FW_EV_MASK_DENIED 0x2u
#define FW_EV_MASK_PING 0x4u
#define FW_EV_MASK_REFRESH 0x8u

#define FW_JPUT_FAIL ((size_t)-1)

/* ================== 状态 ================== */

_Atomic bool g_fw_events_hot = false;

static _Atomic bool g_events_on = false; /* 模块已启动（[GLOBAL] FUSE_EVENTS ON） */
static _Atomic bool g_quit = false;
static _Atomic uint64_t g_seq = 0;
static _Atomic int g_query_conns = 0;
static _Atomic int g_query_inflight = 0;

static int g_evsock = -1;
static int g_qsock = -1;
static int g_evfd = -1;
static pthread_t g_ev_thread;
static pthread_t g_accept_thread;
static bool g_threads_up = false;

static uid_t g_allow_uids[FW_EVENTS_MAX_ALLOW];
static int g_allow_count = 0;

static int64_t g_test_now_ms = -1;

/* ================== 时间（可被测试钉住） ================== */

void fw_events_set_test_now_ms(int64_t ms) {
    g_test_now_ms = ms;
}

static int64_t fw_now_ms(void) {
    if (g_test_now_ms >= 0) return g_test_now_ms;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
}

static int64_t fw_wall_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
}

/* ================== JSON 输出（定长、失败即整帧放弃） ================== */

static size_t fw_putf(char* out, size_t cap, size_t len, const char* fmt, ...) {
    if (!out || cap == 0 || len >= cap) return FW_JPUT_FAIL;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + len, cap - len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - len) return FW_JPUT_FAIL;
    return len + (size_t)n;
}

/* 追加带引号的 JSON 字符串（转义 " \ 与控制字符；其余按字节原样拷贝，
   路径是 UTF-8，不能按 \u 重编码）。 */
static size_t fw_put_str(char* out, size_t cap, size_t len, const char* s) {
    if (!out || cap == 0) return FW_JPUT_FAIL;
    if (!s) s = "";
    len = fw_putf(out, cap, len, "\"");
    if (len == FW_JPUT_FAIL) return len;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        if (*p == '"' || *p == '\\') {
            len = fw_putf(out, cap, len, "\\%c", *p);
            if (len == FW_JPUT_FAIL) return len;
        } else if (*p < 0x20) {
            len = fw_putf(out, cap, len, "\\u%04x", (unsigned)*p);
            if (len == FW_JPUT_FAIL) return len;
        } else {
            if (len + 1 >= cap) return FW_JPUT_FAIL;
            out[len++] = (char)*p;
            out[len] = '\0';
        }
    }
    return fw_putf(out, cap, len, "\"");
}

static const char* fw_op_name(unsigned op) {
    switch (op) {
        case FW_EV_OP_CREATE: return "create";
        case FW_EV_OP_MKDIR: return "mkdir";
        case FW_EV_OP_RENAME: return "rename";
        case FW_EV_OP_CLOSE_WRITE: return "close_write";
        default: return "close_write";
    }
}

static const char* fw_errno_name(int e) {
    switch (e) {
        case EROFS: return "EROFS";
        case ENOENT: return "ENOENT";
        case EACCES: return "EACCES";
        case EPERM: return "EPERM";
        case ENAMETOOLONG: return "ENAMETOOLONG";
        case ENOSPC: return "ENOSPC";
        case EDQUOT: return "EDQUOT";
        default: return "EIO";
    }
}

static const char* fw_event_type_name(unsigned kind) {
    switch (kind) {
        case FW_EV_WRITE_DENIED: return "write_denied";
        case FW_EV_PING: return "ping";
        case FW_EV_MEDIA_REFRESH: return "media_refresh";
        default: return "write_done";
    }
}

static const char* fw_refresh_reason_name(unsigned reason) {
    switch (reason) {
        case FW_REFRESH_FTP_UPLOAD: return "ftp_upload";
        default: return "redirect_write";
    }
}

static const char* fw_media_kind_name(unsigned kind) {
    switch (kind) {
        case FW_MEDIA_IMAGE: return "image";
        case FW_MEDIA_AUDIO: return "audio";
        case FW_MEDIA_VIDEO: return "video";
        default: return "other";
    }
}

/* 按落点扩展名判媒体类别。判不出就返回 NONE，调用方据此不发刷新事件——宁可少
   一次扫描，也不把非媒体文件推进对端的扫描队列。 */
static uint8_t fw_media_kind_of(const char* path) {
    static const struct {
        const char* ext;
        uint8_t kind;
    } k_ext[] = {
        {"jpg", FW_MEDIA_IMAGE},  {"jpeg", FW_MEDIA_IMAGE}, {"png", FW_MEDIA_IMAGE},
        {"gif", FW_MEDIA_IMAGE},  {"webp", FW_MEDIA_IMAGE}, {"bmp", FW_MEDIA_IMAGE},
        {"heic", FW_MEDIA_IMAGE}, {"heif", FW_MEDIA_IMAGE}, {"dng", FW_MEDIA_IMAGE},
        {"avif", FW_MEDIA_IMAGE}, {"mp3", FW_MEDIA_AUDIO},  {"m4a", FW_MEDIA_AUDIO},
        {"aac", FW_MEDIA_AUDIO},  {"flac", FW_MEDIA_AUDIO}, {"ogg", FW_MEDIA_AUDIO},
        {"wav", FW_MEDIA_AUDIO},  {"opus", FW_MEDIA_AUDIO}, {"amr", FW_MEDIA_AUDIO},
        {"awb", FW_MEDIA_AUDIO},  {"mp4", FW_MEDIA_VIDEO},  {"mkv", FW_MEDIA_VIDEO},
        {"mov", FW_MEDIA_VIDEO},  {"3gp", FW_MEDIA_VIDEO},  {"webm", FW_MEDIA_VIDEO},
        {"m4v", FW_MEDIA_VIDEO},  {"ts", FW_MEDIA_VIDEO},
    };
    if (!path) return FW_MEDIA_NONE;
    const char* dot = strrchr(path, '.');
    if (!dot || dot[1] == '\0') return FW_MEDIA_NONE;
    /* 点必须落在最后一个路径分隔符之后：目录名里的点不算扩展名 */
    if (strchr(dot, '/')) return FW_MEDIA_NONE;
    const char* ext = dot + 1;
    for (size_t i = 0; i < sizeof k_ext / sizeof k_ext[0]; i++) {
        if (strcasecmp(ext, k_ext[i].ext) == 0) return k_ext[i].kind;
    }
    return FW_MEDIA_NONE;
}

/* ================== 事件记录与渲染 ================== */

typedef struct {
    uint8_t kind;   /* FwEventKind */
    uint8_t op;     /* FwEventOp */
    uint8_t reason; /* FwRefreshReason（仅 media_refresh） */
    int32_t err;    /* 正 errno（仅 write_denied） */
    uint64_t seq;
    int64_t ts;
    uid_t uid;
    pid_t pid;
    char fuse_path[FW_EVENTS_PATH_MAX];
    char src_fuse[FW_EVENTS_PATH_MAX];
} FwEventRec;

typedef struct {
    FwEventKind kind;
    FwEventOp op;
    uint64_t seq;
    int64_t ts;
    uid_t uid;
    int err;
    uint32_t dropped;
    uint8_t reason;     /* FwRefreshReason（仅 media_refresh） */
    uint8_t media_kind; /* FwMediaKind（仅 media_refresh，按落点扩展名判定） */
    char pkg[128];
    char vpath[FW_EVENTS_PATH_MAX];
    char spath[FW_EVENTS_SPATH_MAX];
    char rpath[FW_EVENTS_RPATH_MAX];
    char src_vpath[FW_EVENTS_PATH_MAX];
    char src_spath[FW_EVENTS_SPATH_MAX];
} FwEvent;

/* 渲染一帧（不含换行；发送方按需追加 '\n'）。放不下返回 0（调用方丢帧并计数）。 */
static size_t fw_format_event(const FwEvent* ev, char* out, size_t cap) {
    if (!ev || !out || cap < 2) return 0;
    out[0] = '\0';
    size_t n;
    const char* type = fw_event_type_name(ev->kind);
    n = fw_putf(out, cap, 0, "{\"v\":1,\"seq\":%llu,\"ts\":%lld,\"type\":\"%s\"",
                (unsigned long long)ev->seq, (long long)ev->ts, type);
    if (n == FW_JPUT_FAIL) return 0;
    if (ev->kind == FW_EV_PING) {
        n = fw_putf(out, cap, n, ",\"dropped\":%u}", ev->dropped);
        return n == FW_JPUT_FAIL ? 0 : n;
    }
    n = fw_putf(out, cap, n, ",\"vol\":\"external_primary\",\"uid\":%u,\"pkg\":", (unsigned)ev->uid);
    if (n == FW_JPUT_FAIL) return 0;
    n = fw_put_str(out, cap, n, ev->pkg);
    if (n == FW_JPUT_FAIL) return 0;
    if (ev->kind == FW_EV_MEDIA_REFRESH) {
        /* 媒体刷新只带"扫哪里、哪一类、为什么"：op 是变更操作的口径，对刷新无意义 */
        n = fw_putf(out, cap, n, ",\"reason\":\"%s\",\"media\":\"%s\"",
                    fw_refresh_reason_name(ev->reason), fw_media_kind_name(ev->media_kind));
        if (n == FW_JPUT_FAIL) return 0;
        n = fw_putf(out, cap, n, ",\"vpath\":");
        if (n == FW_JPUT_FAIL) return 0;
        n = fw_put_str(out, cap, n, ev->vpath);
        if (n == FW_JPUT_FAIL) return 0;
        n = fw_putf(out, cap, n, ",\"spath\":");
        if (n == FW_JPUT_FAIL) return 0;
        n = fw_put_str(out, cap, n, ev->spath);
        if (n == FW_JPUT_FAIL) return 0;
        n = fw_putf(out, cap, n, ",\"rpath\":");
        if (n == FW_JPUT_FAIL) return 0;
        n = fw_put_str(out, cap, n, ev->rpath);
        if (n == FW_JPUT_FAIL) return 0;
        n = fw_putf(out, cap, n, "}");
        return n == FW_JPUT_FAIL ? 0 : n;
    }
    n = fw_putf(out, cap, n, ",\"op\":\"%s\"", fw_op_name(ev->op));
    if (n == FW_JPUT_FAIL) return 0;
    n = fw_putf(out, cap, n, ",\"vpath\":");
    if (n == FW_JPUT_FAIL) return 0;
    n = fw_put_str(out, cap, n, ev->vpath);
    if (n == FW_JPUT_FAIL) return 0;
    n = fw_putf(out, cap, n, ",\"spath\":");
    if (n == FW_JPUT_FAIL) return 0;
    n = fw_put_str(out, cap, n, ev->spath);
    if (n == FW_JPUT_FAIL) return 0;
    if (ev->kind == FW_EV_WRITE_DONE) {
        n = fw_putf(out, cap, n, ",\"rpath\":");
        if (n == FW_JPUT_FAIL) return 0;
        n = fw_put_str(out, cap, n, ev->rpath);
        if (n == FW_JPUT_FAIL) return 0;
        if (ev->src_vpath[0]) {
            n = fw_putf(out, cap, n, ",\"src_vpath\":");
            if (n == FW_JPUT_FAIL) return 0;
            n = fw_put_str(out, cap, n, ev->src_vpath);
            if (n == FW_JPUT_FAIL) return 0;
            n = fw_putf(out, cap, n, ",\"src_spath\":");
            if (n == FW_JPUT_FAIL) return 0;
            n = fw_put_str(out, cap, n, ev->src_spath);
            if (n == FW_JPUT_FAIL) return 0;
        }
    } else {
        /* write_denied：写没落盘，没有 rpath；但必须带 spath（本应落到的视图位置） */
        n = fw_putf(out, cap, n, ",\"errno\":\"%s\"", fw_errno_name(ev->err));
        if (n == FW_JPUT_FAIL) return 0;
    }
    n = fw_putf(out, cap, n, "}");
    return n == FW_JPUT_FAIL ? 0 : n;
}

/* ================== 环形队列（有界、满丢最旧、独立 drain） ================== */

static FwEventRec* g_ring = NULL;
static int g_ring_head = 0;
static int g_ring_tail = 0;
static int g_ring_count = 0;
static uint32_t g_ring_dropped = 0;      /* 累计丢弃（进程生命周期内） */
static uint32_t g_ping_last_dropped = 0; /* 上次心跳时的累计值 */
/* 超长路径丢弃：入队时 fuse_path 装不下就整条不发。截断后的路径仍能解析出
   sub/vpath/spath，但对端拿去扫描的是**另一个**路径（漏原文件、还查错文件），
   所以宁可丢这条并计入 dropped——它和环满一样是"订阅者漏了事件"。 */
static _Atomic uint32_t g_ev_oversize_dropped = 0;
static pthread_mutex_t g_ring_mu = PTHREAD_MUTEX_INITIALIZER;

static void fw_ring_push(const FwEventRec* rec) {
    if (!g_ring) return;
    pthread_mutex_lock(&g_ring_mu);
    if (g_ring_count == FW_EVENTS_RING_CAP) {
        g_ring_tail = (g_ring_tail + 1) % FW_EVENTS_RING_CAP;
        g_ring_count--;
        g_ring_dropped++;
    }
    g_ring[g_ring_head] = *rec;
    g_ring_head = (g_ring_head + 1) % FW_EVENTS_RING_CAP;
    g_ring_count++;
    pthread_mutex_unlock(&g_ring_mu);
}

/* 批量出队（drain 线程专用）。返回条数（0 = 空）。 */
static int fw_ring_pop(FwEventRec* out, int max) {
    if (!g_ring || max <= 0) return 0;
    int n = 0;
    pthread_mutex_lock(&g_ring_mu);
    while (n < max && g_ring_count > 0) {
        out[n++] = g_ring[g_ring_tail];
        g_ring_tail = (g_ring_tail + 1) % FW_EVENTS_RING_CAP;
        g_ring_count--;
    }
    pthread_mutex_unlock(&g_ring_mu);
    return n;
}

/* 唤醒 drain（事件线程 poll 的 eventfd）。失败无副作用：drain 有兜底超时。 */
static void fw_ring_wake(void) {
    if (g_evfd < 0) return;
    uint64_t one = 1;
    ssize_t w = write(g_evfd, &one, sizeof one);
    (void)w; /* EAGAIN = 计数已满，drain 必然已被唤醒 */
}

/* ================== exists 缓存（lstat + ≤200ms TTL，写事件失效） ================== */

typedef struct {
    _Atomic unsigned ver; /* 偶=有效帧，奇=作废/写入中（seqlock） */
    char path[FW_EVENTS_PATH_MAX];
    int64_t ts;
    unsigned char exists;
} FwExistsSlot;

static FwExistsSlot g_exists[FW_EXISTS_SLOTS];

static unsigned fw_hash_path(const char* s) {
    unsigned h = 2166136261u;
    for (; s && *s; s++) {
        h ^= (unsigned char)*s;
        h *= 16777619u;
    }
    return h;
}

/* 写事件到达 → 失效对应槽（O(1)、无锁、不分配）。命中才置奇位，避免误伤同名
   之外的槽（误伤只是让下次查询多做一次 lstat，不影响正确性）。 */
static void fw_exists_invalidate(const char* fuse_path) {
    if (!fuse_path || !fuse_path[0]) return;
    FwExistsSlot* s = &g_exists[fw_hash_path(fuse_path) & (FW_EXISTS_SLOTS - 1)];
    unsigned v = atomic_load_explicit(&s->ver, memory_order_relaxed);
    if (v == 0 || (v & 1u)) return;
    if (strcmp(s->path, fuse_path) != 0) return;
    atomic_fetch_or(&s->ver, 1u);
}

/* exists 查询：命中且未过期直接返回；否则 lstat 落盘并回填。
   real_path 由调用方（QUERY）按 fw_rules_resolve 的结果给出。 */
static int fw_exists_lookup(const char* fuse_path, const char* real_path) {
    FwExistsSlot* s = &g_exists[fw_hash_path(fuse_path) & (FW_EXISTS_SLOTS - 1)];
    int64_t now = fw_now_ms();
    unsigned v1 = atomic_load_explicit(&s->ver, memory_order_acquire);
    if (v1 && !(v1 & 1u) && s->path[0] && strcmp(s->path, fuse_path) == 0 &&
        now - s->ts <= FW_EXISTS_TTL_MS) {
        unsigned v2 = atomic_load_explicit(&s->ver, memory_order_acquire);
        if (v1 == v2) return s->exists ? 1 : 0;
    }
    int ex = 0;
    if (real_path && real_path[0]) {
        struct stat st;
        ex = (lstat(real_path, &st) == 0) ? 1 : 0;
    }
    unsigned v = atomic_load_explicit(&s->ver, memory_order_relaxed);
    atomic_store_explicit(&s->ver, v | 1u, memory_order_relaxed);
    snprintf(s->path, sizeof s->path, "%s", fuse_path);
    s->ts = now;
    s->exists = (unsigned char)ex;
    atomic_store_explicit(&s->ver, (v | 1u) + 1u, memory_order_release);
    return ex;
}

/* 路径整串入缓存；放不下返回 false（调用方丢事件并计数）。
   不用 snprintf 的静默截断：FUSE 视角 /0/Pictures/<244B>.jpg 截成 255 字节后，
   后缀已经变成 .jp，派生出的 spath 指向一个不存在或别的文件。 */
static bool fw_copy_path(char* dst, size_t cap, const char* src) {
    if (!dst || cap == 0 || !src) return false;
    size_t n = strlen(src);
    if (n == 0 || n >= cap) return false;
    memcpy(dst, src, n + 1);
    return true;
}

/* ================== 埋点（IO 热路径） ================== */

void fw_events_note_write_done(uid_t uid, pid_t pid, const char* fuse_path, FwEventOp op,
                               const char* src_fuse) {
    /* 关闭时：唯一开销就是这一次 relaxed 读 */
    if (!atomic_load_explicit(&g_events_on, memory_order_relaxed)) return;
    if (!fuse_path || !fuse_path[0]) return;
    /* exists 缓存与订阅者无关（QUERY 也用它）：先按写事件失效 */
    fw_exists_invalidate(fuse_path);
    if (!fw_events_active()) return;
    FwEventRec rec;
    memset(&rec, 0, sizeof rec);
    rec.kind = (uint8_t)FW_EV_WRITE_DONE;
    rec.op = (uint8_t)op;
    rec.seq = atomic_fetch_add(&g_seq, 1) + 1;
    rec.ts = fw_wall_ms();
    rec.uid = uid;
    rec.pid = pid;
    if (!fw_copy_path(rec.fuse_path, sizeof rec.fuse_path, fuse_path)) {
        atomic_fetch_add(&g_ev_oversize_dropped, 1);
        return;
    }
    if (src_fuse && !fw_copy_path(rec.src_fuse, sizeof rec.src_fuse, src_fuse)) {
        atomic_fetch_add(&g_ev_oversize_dropped, 1);
        return;
    }
    fw_ring_push(&rec);
    fw_ring_wake();
}

void fw_events_note_write_denied(uid_t uid, pid_t pid, const char* fuse_path, NspAclOp acl_op,
                                 int err) {
    if (!fw_events_active()) return;
    if (!fuse_path || !fuse_path[0]) return;
    int e = err < 0 ? -err : err;
    /* 只发布扫描侧能据此下结论的 errno：永久性拒绝（EROFS/HIDE→ENOENT/ACL→
       EACCES|EPERM/超长）与**容量不足**（ENOSPC/磁盘满、EDQUOT/配额）——后者是
       相册保存失败的高频可解释原因，扫描侧看到就知道"不是没写，是没地方写"。
       EIO 一类瞬态/内部错误不发：那是噪声，只会让对端误判路径状态。 */
    if (e != EROFS && e != ENOENT && e != EACCES && e != EPERM && e != ENAMETOOLONG &&
        e != ENOSPC && e != EDQUOT)
        return;
    FwEventOp op;
    switch (acl_op) {
        case NSP_ACL_OP_CREATE: op = FW_EV_OP_CREATE; break;
        case NSP_ACL_OP_MKDIR: op = FW_EV_OP_MKDIR; break;
        case NSP_ACL_OP_RENAME_SRC:
        case NSP_ACL_OP_RENAME_DST: op = FW_EV_OP_RENAME; break;
        default: return; /* 契约只定义 create/mkdir/rename/close_write */
    }
    FwEventRec rec;
    memset(&rec, 0, sizeof rec);
    rec.kind = (uint8_t)FW_EV_WRITE_DENIED;
    rec.op = (uint8_t)op;
    rec.err = e;
    rec.seq = atomic_fetch_add(&g_seq, 1) + 1;
    rec.ts = fw_wall_ms();
    rec.uid = uid;
    rec.pid = pid;
    if (!fw_copy_path(rec.fuse_path, sizeof rec.fuse_path, fuse_path)) {
        atomic_fetch_add(&g_ev_oversize_dropped, 1);
        return;
    }
    fw_ring_push(&rec);
    fw_ring_wake();
}

void fw_events_note_media_refresh(uid_t uid, pid_t pid, const char* fuse_path, uint8_t reason) {
    /* 与 write_done 同一道上限：关着通道时只花一次 relaxed 读；开着也要先看有没有
       活订阅者，没有就不进队列（媒体扫描请求没有"事后补发"的意义） */
    if (!atomic_load_explicit(&g_events_on, memory_order_relaxed)) return;
    if (!fuse_path || !fuse_path[0]) return;
    fw_exists_invalidate(fuse_path);
    if (!fw_events_active()) return;
    FwEventRec rec;
    memset(&rec, 0, sizeof rec);
    rec.kind = (uint8_t)FW_EV_MEDIA_REFRESH;
    rec.reason = reason;
    rec.seq = atomic_fetch_add(&g_seq, 1) + 1;
    rec.ts = fw_wall_ms();
    rec.uid = uid;
    rec.pid = pid;
    if (!fw_copy_path(rec.fuse_path, sizeof rec.fuse_path, fuse_path)) {
        atomic_fetch_add(&g_ev_oversize_dropped, 1);
        return;
    }
    fw_ring_push(&rec);
    fw_ring_wake();
}

/* ================== 订阅者 ================== */

typedef struct {
    bool used;
    struct sockaddr_un addr;
    socklen_t addrlen;
    uid_t uid;
    unsigned mask;
    int64_t last_ms;
    unsigned fails;
} FwSub;

static FwSub g_subs[FW_EVENTS_MAX_SUBS];
static int g_sub_count = 0;

static bool fw_uid_allowed(uid_t uid) {
    for (int i = 0; i < g_allow_count; i++) {
        if (g_allow_uids[i] == uid) return true;
    }
    return false;
}

/* hot 标志 = 有活订阅者：驱动 IO 路径是否入队。只在事件线程改动。 */
static void fw_update_hot(void) {
    atomic_store_explicit(&g_fw_events_hot, g_sub_count > 0, memory_order_relaxed);
}

/* ================== 路径合成（唯一出口在 common_*） ================== */

/* FUSE 视角路径 → 真实落盘路径：**只经 fw_rules_resolve**（决策单点）。
   解析失败（无用户层）时退回默认存储路径，仍走 common_default_real_path。 */
static void fw_resolve_real(uid_t uid, pid_t pid, const char* fuse_path, char* out, size_t sz) {
    if (!out || sz == 0) return;
    out[0] = '\0';
    NspQueryCtx q;
    memset(&q, 0, sizeof q);
    q.uid = uid;
    q.pid = pid;
    q.path = fuse_path;
    NspPathDecision d;
    fw_rules_resolve(&q, &d);
    if (d.valid && d.real_path[0]) {
        snprintf(out, sz, "%s", d.real_path);
        return;
    }
    int user_id = -1;
    const char* sub = NULL;
    if (common_parse_user_layer(fuse_path, &user_id, &sub) == 1 && user_id >= 0 && sub) {
        common_default_real_path(user_id, sub, out, sz);
    }
}

/* ================== 事件渲染 + 发送 ================== */

static void fw_send_to_subs(const char* frame, size_t len, unsigned mask_bit) {
    for (int i = 0; i < FW_EVENTS_MAX_SUBS; i++) {
        FwSub* s = &g_subs[i];
        if (!s->used || (s->mask & mask_bit) == 0) continue;
        ssize_t w = sendto(g_evsock, frame, len, MSG_NOSIGNAL | MSG_DONTWAIT,
                           (struct sockaddr*)&s->addr, s->addrlen);
        if (w < 0) {
            /* 订阅者队列满（EAGAIN）或已消失（ECONNREFUSED）：计数并最终摘除，
               绝不在这里等——IO 路径的正确性不依赖订阅者是否在线 */
            if (++s->fails >= FW_EVENTS_SUB_MAX_FAILS) {
                s->used = false;
                if (g_sub_count > 0) g_sub_count--;
                LOG_DBG("事件订阅者失联，已摘除 (uid=%u, 连续失败 %u)", (unsigned)s->uid,
                        s->fails);
            }
        } else {
            s->fails = 0;
        }
    }
    fw_update_hot();
}

/* 渲染 + 发送一帧。装不下返回 false（调用方决定丢帧还是裁字段重试）：
   半截 JSON 会被对端当坏帧丢掉，还占着订阅者队列——所以绝不发半帧。 */
static bool fw_emit_frame(const FwEvent* ev, unsigned mask_bit) {
    char frame[FW_EVENTS_FRAME_MAX];
    size_t n = fw_format_event(ev, frame, sizeof frame - 2);
    if (n == 0 || n + 1 >= sizeof frame) return false;
    frame[n++] = '\n'; /* NDJSON：一帧一行 */
    frame[n] = '\0';
    fw_send_to_subs(frame, n, mask_bit);
    return true;
}

/* 在 base 的落点信息上补发一条 media_refresh。seq 单独取号：两条帧是两件事，
   共用序号会让按 seq 去重的对端吃掉后一条。 */
static void fw_emit_media_refresh(const FwEvent* base, uint8_t media_kind, uint8_t reason,
                                  const char* fuse_path) {
    FwEvent rev;
    memset(&rev, 0, sizeof rev);
    rev.kind = (FwEventKind)FW_EV_MEDIA_REFRESH;
    rev.reason = reason;
    rev.media_kind = media_kind;
    rev.seq = atomic_fetch_add(&g_seq, 1) + 1;
    rev.ts = fw_wall_ms();
    rev.uid = base->uid;
    snprintf(rev.pkg, sizeof rev.pkg, "%s", base->pkg);
    snprintf(rev.vpath, sizeof rev.vpath, "%s", base->vpath);
    snprintf(rev.spath, sizeof rev.spath, "%s", base->spath);
    snprintf(rev.rpath, sizeof rev.rpath, "%s", base->rpath);
    if (fw_emit_frame(&rev, FW_EV_MASK_REFRESH)) return;
    /* 装不下先去掉 rpath 重试：它只是"FUSE 未注入时"的回退落点，spath 才是扫描必需项 */
    if (rev.rpath[0]) {
        rev.rpath[0] = '\0';
        if (fw_emit_frame(&rev, FW_EV_MASK_REFRESH)) return;
    }
    atomic_fetch_add(&g_ev_oversize_dropped, 1);
    LOG_DBG("媒体刷新帧超长已丢弃 (seq=%llu, path=%s)", (unsigned long long)rev.seq, fuse_path);
}

static void fw_emit(const FwEventRec* rec) {
    if (g_sub_count == 0) return;
    int user_id = -1;
    const char* sub = NULL;
    if (common_parse_user_layer(rec->fuse_path, &user_id, &sub) != 1 || user_id < 0 || !sub) {
        /* 无 <user>/ 用户层（挂载点根、.fuse_hidden 等）：事件没有 vpath 语义 */
        return;
    }
    FwEvent ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = (FwEventKind)rec->kind;
    ev.op = (FwEventOp)rec->op;
    ev.reason = rec->reason;
    ev.seq = rec->seq;
    ev.ts = rec->ts;
    ev.uid = rec->uid;
    ev.err = rec->err;
    fw_pkg_resolve(rec->uid, rec->pid, ev.pkg, sizeof ev.pkg);
    if (!fw_copy_path(ev.vpath, sizeof ev.vpath, sub)) {
        atomic_fetch_add(&g_ev_oversize_dropped, 1);
        return;
    }
    common_view_path(user_id, sub, ev.spath, sizeof ev.spath);
    if (ev.spath[0] == '\0') {
        /* 视图路径放不下时 common_view_path 清空输出（失败闭合）——没有可信 spath 就不发 */
        atomic_fetch_add(&g_ev_oversize_dropped, 1);
        return;
    }
    if (rec->kind == FW_EV_WRITE_DONE || rec->kind == FW_EV_MEDIA_REFRESH) {
        fw_resolve_real(rec->uid, rec->pid, rec->fuse_path, ev.rpath, sizeof ev.rpath);
        ev.media_kind = fw_media_kind_of(ev.rpath);
    }
    /* 落点不是媒体（或根本解析不出落点）：刷新请求没有意义，整条不发——
       对端多一次扫描就是多一次 MediaProvider 唤醒，宁可漏也别误报 */
    if (rec->kind == FW_EV_MEDIA_REFRESH && ev.media_kind == FW_MEDIA_NONE) return;
    if (rec->kind == FW_EV_WRITE_DONE) {
        if (rec->src_fuse[0]) {
            int src_user = -1;
            const char* src_sub = NULL;
            if (common_parse_user_layer(rec->src_fuse, &src_user, &src_sub) == 1 && src_user >= 0 &&
                src_sub) {
                /* rename 的源只驱动"清旧行"：它放不下就整对 src_* 都不发，而不是发半个
                   路径让对端去清错行；目的端事件本身仍然有效 */
                if (fw_copy_path(ev.src_vpath, sizeof ev.src_vpath, src_sub)) {
                    common_view_path(src_user, src_sub, ev.src_spath, sizeof ev.src_spath);
                    if (ev.src_spath[0] == '\0') ev.src_vpath[0] = '\0';
                }
                if (!ev.src_vpath[0]) atomic_fetch_add(&g_ev_oversize_dropped, 1);
            }
        }
    }
    unsigned mask = FW_EV_MASK_DONE;
    if (rec->kind == FW_EV_WRITE_DENIED) mask = FW_EV_MASK_DENIED;
    else if (rec->kind == FW_EV_MEDIA_REFRESH) mask = FW_EV_MASK_REFRESH;
    if (!fw_emit_frame(&ev, mask)) {
        atomic_fetch_add(&g_ev_oversize_dropped, 1);
        LOG_DBG("事件帧超长已丢弃 (seq=%llu, path=%s)", (unsigned long long)ev.seq, rec->fuse_path);
        return;
    }

    /* 写落到"视图路径之外"才补一条 media_refresh：直通写在原地的文件本来就在扫描
       器眼里，只有改写落点（REDIRECT/沙盒）才会让媒体库漏掉它。落点与默认存储
       路径相同即未改写，此时 write_done 已经足够。 */
    if (rec->kind == FW_EV_WRITE_DONE && ev.rpath[0] && ev.media_kind != FW_MEDIA_NONE) {
        char def[FW_EVENTS_RPATH_MAX];
        def[0] = '\0';
        common_default_real_path(user_id, sub, def, sizeof def);
        if (def[0] && strcmp(def, ev.rpath) != 0) {
            fw_emit_media_refresh(&ev, ev.media_kind, (uint8_t)FW_REFRESH_REDIRECT_WRITE,
                                  rec->fuse_path);
        }
    }
}

/* ================== 200ms 合并（drain 侧） ================== */

typedef struct {
    bool used;
    int64_t deadline;
    FwEventRec rec;
} FwCoalesceSlot;

static FwCoalesceSlot g_coalesce[FW_EVENTS_COALESCE_SLOTS];

/* 同 fuse_path 在窗口内 last-wins；窗口自**首次**到达起算（不被后续事件续期，
   否则持续写同一文件会永远发不出去）。无空槽时立即发出——宁可少合并，不丢事件。 */
static void fw_coalesce_push(const FwEventRec* rec) {
    int64_t now = fw_now_ms();
    int free_slot = -1;
    for (int i = 0; i < FW_EVENTS_COALESCE_SLOTS; i++) {
        if (g_coalesce[i].used) {
            /* 同路径同类别才合并：write_done 与 media_refresh 对同一文件是两件事
               （一个说"写了"，一个说"现在必须进媒体库"），合并会吃掉后者 */
            if (g_coalesce[i].rec.kind == rec->kind &&
                strcmp(g_coalesce[i].rec.fuse_path, rec->fuse_path) == 0) {
                g_coalesce[i].rec = *rec;
                return;
            }
        } else if (free_slot < 0) {
            free_slot = i;
        }
    }
    if (free_slot < 0) {
        fw_emit(rec);
        return;
    }
    g_coalesce[free_slot].used = true;
    g_coalesce[free_slot].deadline = now + FW_EVENTS_COALESCE_MS;
    g_coalesce[free_slot].rec = *rec;
}

static void fw_coalesce_flush_due(void) {
    int64_t now = fw_now_ms();
    for (int i = 0; i < FW_EVENTS_COALESCE_SLOTS; i++) {
        if (!g_coalesce[i].used || now < g_coalesce[i].deadline) continue;
        FwEventRec rec = g_coalesce[i].rec;
        g_coalesce[i].used = false;
        fw_emit(&rec);
    }
}

/* 距最近一次到期的毫秒数（无待发 → FW_EVENTS_POLL_MAX_MS）
   无订阅者时直接按上限睡：此时没有任何发送机会，按槽到期时间返回 0 只会让
   事件线程 poll(0) 空转（合并槽要等订阅者回来才有人清）。 */
static int fw_coalesce_timeout(void) {
    if (g_sub_count == 0) return FW_EVENTS_POLL_MAX_MS;
    int64_t now = fw_now_ms();
    int64_t best = INT64_MAX;
    for (int i = 0; i < FW_EVENTS_COALESCE_SLOTS; i++) {
        if (!g_coalesce[i].used) continue;
        int64_t d = g_coalesce[i].deadline - now;
        if (d < best) best = d;
    }
    if (best == INT64_MAX) return FW_EVENTS_POLL_MAX_MS;
    if (best <= 0) return 0;
    return best > FW_EVENTS_POLL_MAX_MS ? FW_EVENTS_POLL_MAX_MS : (int)best;
}

static void fw_drain_ring(void) {
    FwEventRec batch[16];
    for (;;) {
        int n = fw_ring_pop(batch, 16);
        if (n <= 0) break;
        for (int i = 0; i < n; i++) fw_coalesce_push(&batch[i]);
    }
}

/* ================== 订阅帧解析 ================== */

/* 取 "key" 成员的值起始处（已跳过空白）；找不到返回 NULL。
   只走对象成员结构，字符串值整体跳过——键名出现在某个值里不会被误命中。 */
static const char* fw_json_value_of(const char* s, const char* key) {
    if (!s || !key) return NULL;
    size_t kl = strlen(key);
    const char* p = s;
    while (*p) {
        if (*p != '"') {
            p++;
            continue;
        }
        const char* k = p + 1;
        const char* e = k;
        while (*e && *e != '"') {
            if (*e == '\\' && e[1]) e++;
            e++;
        }
        if (!*e) return NULL;
        size_t klen = (size_t)(e - k);
        const char* v = e + 1;
        while (*v == ' ' || *v == '\t' || *v == '\r' || *v == '\n') v++;
        if (*v != ':') {
            p = e + 1;
            continue;
        }
        v++;
        while (*v == ' ' || *v == '\t' || *v == '\r' || *v == '\n') v++;
        if (klen == kl && strncmp(k, key, kl) == 0) return v;
        if (*v == '"') { /* 跳过字符串值，避免把值里的内容当键 */
            const char* ve = v + 1;
            while (*ve && *ve != '"') {
                if (*ve == '\\' && ve[1]) ve++;
                ve++;
            }
            p = *ve ? ve + 1 : ve;
            continue;
        }
        p = v;
    }
    return NULL;
}

static bool fw_json_find_str(const char* s, const char* key, char* out, size_t cap) {
    const char* v = fw_json_value_of(s, key);
    if (!v || *v != '"') return false;
    v++;
    size_t w = 0;
    while (*v && *v != '"') {
        char c = *v++;
        if (c == '\\' && *v) {
            char esc = *v++;
            c = (esc == 'n') ? '\n' : (esc == 't') ? '\t' : (esc == 'r') ? '\r' : esc;
        }
        if (w + 1 >= cap) return false;
        out[w++] = c;
    }
    if (*v != '"') return false;
    if (cap) out[w] = '\0';
    return true;
}

static bool fw_json_find_u64(const char* s, const char* key, unsigned long long* out) {
    const char* v = fw_json_value_of(s, key);
    if (!v) return false;
    if (*v == '"') v++;
    if (*v < '0' || *v > '9') return false;
    unsigned long long x = 0;
    while (*v >= '0' && *v <= '9') {
        x = x * 10u + (unsigned)(*v - '0');
        v++;
    }
    *out = x;
    return true;
}

/* 订阅：找空槽/同位槽登记；filter.types 决定收哪几类（心跳恒开——客户端靠它
   判丢帧与重订，不该被业务过滤关掉）。 */
static void fw_handle_subscribe(const char* buf, const struct sockaddr_un* from, socklen_t fromlen,
                                uid_t uid) {
    char cmd[32];
    char reply[sizeof(from->sun_path)];
    cmd[0] = '\0';
    reply[0] = '\0';
    if (!fw_json_find_str(buf, "cmd", cmd, sizeof cmd)) return;
    if (strcmp(cmd, "SUBSCRIBE") != 0) return;
    if (!fw_json_find_str(buf, "reply", reply, sizeof reply) || reply[0] != 'n') {
        /* reply 必须是客户端自己的抽象地址名（契约示例 nsp_fs_events.<pid>.<rand>）；
           以 'n' 开头是宽松校验，拦住明显非法的空/相对名字 */
        return;
    }
    unsigned mask = FW_EV_MASK_PING;
    if (strstr(buf, "\"write_done\"")) mask |= FW_EV_MASK_DONE;
    if (strstr(buf, "\"write_denied\"")) mask |= FW_EV_MASK_DENIED;
    if (strstr(buf, "\"media_refresh\"")) mask |= FW_EV_MASK_REFRESH;
    if (strstr(buf, "\"types\"")) {
        if ((mask & (FW_EV_MASK_DONE | FW_EV_MASK_DENIED | FW_EV_MASK_REFRESH)) == 0)
            return; /* 空过滤：不登记 */
    } else {
        mask |= FW_EV_MASK_DONE | FW_EV_MASK_DENIED | FW_EV_MASK_REFRESH; /* 无 filter = 全收 */
    }
    /* reply 是客户端的**抽象**地址名：必须经 nsp_uds_abstract_addr 合成
       （sun_path[0]='\0' 才是抽象命名空间；直接把名字拷到 sun_path[0] 会变成
       相对文件路径，sendto 一律 ENOENT/ECONNREFUSED，订阅者永远收不到事件） */
    struct sockaddr_un a;
    socklen_t alen = nsp_uds_abstract_addr(&a, reply);
    if (alen <= 0) return;

    int slot = -1;
    int oldest = 0;
    for (int i = 0; i < FW_EVENTS_MAX_SUBS; i++) {
        FwSub* s = &g_subs[i];
        if (s->used && s->addrlen == alen && memcmp(&s->addr, &a, alen) == 0) {
            slot = i;
            break;
        }
        if (!s->used && slot < 0) slot = i;
        if (s->used && s->last_ms < g_subs[oldest].last_ms) oldest = i;
    }
    if (slot < 0) { /* 满：挤掉最久没动静的订阅者 */
        slot = oldest;
        g_subs[slot].used = false;
        if (g_sub_count > 0) g_sub_count--;
    }
    FwSub* s = &g_subs[slot];
    if (!s->used) {
        s->used = true;
        g_sub_count++;
    }
    s->addr = a;
    s->addrlen = alen;
    s->uid = uid;
    s->mask = mask;
    s->last_ms = fw_now_ms();
    s->fails = 0;
    fw_update_hot();
    LOG("事件订阅已登记 (uid=%u, reply=%s, mask=0x%x, 共 %d 个)", (unsigned)uid, reply, mask,
        g_sub_count);
    (void)from;
    (void)fromlen;
}

/* 事件线程：接收所有待处理订阅帧（带 SCM_CREDENTIALS 做通道身份校验）。 */
static void fw_recv_subscribes(void) {
    char buf[FW_EVENTS_MAX_REQ + 1];
    for (;;) {
        char cbuf[CMSG_SPACE(sizeof(struct ucred))];
        struct iovec iov = {.iov_base = buf, .iov_len = sizeof buf - 1};
        struct msghdr mh;
        memset(&mh, 0, sizeof mh);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = cbuf;
        mh.msg_controllen = sizeof cbuf;
        struct sockaddr_un from;
        memset(&from, 0, sizeof from);
        mh.msg_name = &from;
        mh.msg_namelen = sizeof from;
        ssize_t n = recvmsg(g_evsock, &mh, MSG_DONTWAIT);
        if (n <= 0) break;
        buf[n] = '\0';
        bool have_cred = false;
        struct ucred cr;
        memset(&cr, 0, sizeof cr);
        for (struct cmsghdr* c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS &&
                c->cmsg_len >= CMSG_LEN(sizeof(struct ucred))) {
                memcpy(&cr, CMSG_DATA(c), sizeof cr);
                have_cred = true;
            }
        }
        if (!have_cred) continue; /* 没凭据（不可能，SO_PASSCRED 已开）：不采信 */
        if (!fw_uid_allowed(cr.uid)) {
            LOG_DBG("拒绝事件订阅：通道 uid=%u 不在白名单", (unsigned)cr.uid);
            continue;
        }
        fw_handle_subscribe(buf, &from, mh.msg_namelen, cr.uid);
    }
}

/* ================== 心跳 ================== */

static int64_t g_next_ping_ms = 0;

/* ping 带的是**自上次心跳以来**的环丢弃数：客户端据此判"我漏了事件"，
   累计值会让它在一次风暴后永远以为自己在丢。 */
static void fw_maybe_ping(void) {
    int64_t now = fw_now_ms();
    if (now < g_next_ping_ms) return;
    g_next_ping_ms = now + FW_EVENTS_PING_MS;
    if (g_sub_count == 0) return;
    uint32_t drop_now;
    pthread_mutex_lock(&g_ring_mu);
    drop_now = g_ring_dropped;
    pthread_mutex_unlock(&g_ring_mu);
    /* 超长路径/超长帧的丢弃与环满同口径计入本区间：对订阅者而言都是"你漏了这个事件" */
    uint32_t oversize = atomic_exchange(&g_ev_oversize_dropped, 0);
    uint32_t delta = drop_now - g_ping_last_dropped + oversize;
    g_ping_last_dropped = drop_now;
    FwEvent ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = FW_EV_PING;
    ev.seq = atomic_fetch_add(&g_seq, 1) + 1;
    ev.ts = fw_wall_ms();
    ev.dropped = delta;
    char frame[FW_EVENTS_FRAME_MAX];
    size_t n = fw_format_event(&ev, frame, sizeof frame - 2);
    if (n == 0) return;
    frame[n++] = '\n';
    frame[n] = '\0';
    fw_send_to_subs(frame, n, FW_EV_MASK_PING);
}

/* ================== 事件线程 ================== */

/* 单轮 poll 的超时：最近合并槽到期与下一次心跳取小；两者都远时封顶
   FW_EVENTS_POLL_MAX_MS（长睡也必须按时醒来发心跳）。 */
static int fw_poll_timeout_ms(void) {
    int timeout = fw_coalesce_timeout();
    int64_t until_ping = g_next_ping_ms - fw_now_ms();
    if (until_ping < timeout) timeout = until_ping > 0 ? (int)until_ping : 0;
    return timeout;
}

/* 单轮"排空 + 合并"：有订阅者时把环渲染进合并槽；无订阅者时环直接丢弃。
   合并槽必须**无条件** flush——槽只有 flush 才清，而在 g_sub_count 归零的分支
   里不清的话，遗留槽的 deadline 永远是过去时，poll 超时恒 0，事件线程空转烧满
   一核（最后一个订阅者被 sendto 失联摘除的那一刻就会进入这个状态）。 */
static void fw_events_maintain(void) {
    if (g_sub_count > 0) {
        fw_drain_ring();
    } else {
        FwEventRec junk[16];
        while (fw_ring_pop(junk, 16) > 0) {
        } /* 无订阅者：直接弃，不渲染 */
    }
    fw_coalesce_flush_due();
}

static void* fw_events_thread(void* arg) {
    (void)arg;
    nsp_set_thread_name("nsp_fs_events");
    g_next_ping_ms = fw_now_ms() + FW_EVENTS_PING_MS;
    struct pollfd pfd[2];
    pfd[0].fd = g_evsock;
    pfd[0].events = POLLIN;
    pfd[1].fd = g_evfd;
    pfd[1].events = POLLIN;
    while (!atomic_load_explicit(&g_quit, memory_order_relaxed)) {
        pfd[0].revents = 0;
        pfd[1].revents = 0;
        int r = poll(pfd, 2, fw_poll_timeout_ms());
        if (r < 0 && errno != EINTR) break;
        if (pfd[1].revents & POLLIN) {
            uint64_t v;
            ssize_t rd = read(g_evfd, &v, sizeof v);
            (void)rd;
        }
        if (pfd[0].revents & POLLIN) fw_recv_subscribes();
        fw_events_maintain();
        fw_maybe_ping();
    }
    return NULL;
}

/* ================== QUERY：请求 → 判定 → 响应 ================== */

/* 绝对 spath → (user_id, sub)。只认 /storage/emulated/<user>[/...]，
   且拒绝 ".."（防穿越：查询入参来自应用，不能让它借我们之眼看他人的存储）。 */
static bool fw_view_decode(const char* spath, int* user_id, char* sub, size_t sub_sz) {
    static const char* k_root = NSP_ANDROID_EMULATED_ROOT;
    size_t rl = strlen(k_root);
    if (!spath || strncmp(spath, k_root, rl) != 0 || spath[rl] != '/') return false;
    const char* p = spath + rl + 1;
    if (*p < '0' || *p > '9') return false;
    long v = 0;
    while (*p >= '0' && *p <= '9') {
        int dg = *p - '0';
        if (v > (INT_MAX - dg) / 10) return false; /* 溢出：非法 user_id，fail-closed */
        v = v * 10 + dg;
        p++;
    }
    if (*p == '\0') {
        snprintf(sub, sub_sz, "/");
    } else if (*p == '/') {
        if (strstr(p, "..")) return false;
        snprintf(sub, sub_sz, "%s", p);
    } else {
        return false;
    }
    *user_id = (int)v;
    return true;
}

/* 真实落盘路径 → 存储视图路径：落在 STORAGE_BASE/<user>/ 之下才映射，
   否则（重定向到别处/后端）回显请求里的 spath。 */
static void fw_real_to_view(const char* real, int user_id, const char* fallback, char* out,
                            size_t sz) {
    char base[PATH_MAX];
    common_storage_base(base, sizeof base);
    char prefix[PATH_MAX];
    snprintf(prefix, sizeof prefix, "%s/%d", base, user_id);
    size_t pl = strlen(prefix);
    if (real && real[0] && strncmp(real, prefix, pl) == 0 && (real[pl] == '/' || real[pl] == '\0')) {
        common_view_path(user_id, real[pl] ? real + pl : "/", out, sz);
        return;
    }
    snprintf(out, sz, "%s", fallback ? fallback : "");
}

static const char* fw_scope_name(uint8_t scope) {
    switch (scope) {
        case BR_SCOPE_APP: return "app";
        case BR_SCOPE_CAT: return "cat";
        case BR_SCOPE_GLOBAL: return "global";
        default: return "none";
    }
}

static const char* fw_rule_name(uint8_t kind) {
    switch (kind) {
        case NSP_RULE_ALLOW: return "allow";
        case NSP_RULE_HIDE: return "hide";
        case NSP_RULE_RO: return "ro";
        case NSP_RULE_REDIRECT: return "redirect";
        case NSP_RULE_SANDBOX: return "sandbox";
        case NSP_RULE_ISOLATION: return "isolation";
        default: return "none";
    }
}

typedef struct {
    bool busy;
    bool ok;
    bool exists;
    bool denied;
    const char* reason;
    /* 归因（引擎给的"谁说了算"）：reason 说明现象，scope/rule 说明来源。
       对端据此判断"这条结论来自 FUSE 的规则裁决"还是"只是默认边界"。 */
    const char* scope;
    const char* rule;
    uint64_t seq;
    char spath[FW_EVENTS_SPATH_MAX];
    char rpath[FW_EVENTS_RPATH_MAX];
} FwQueryResult;

static size_t fw_format_busy(char* out, size_t cap, uint64_t seq) {
    size_t n = fw_putf(out, cap, 0, "{\"v\":1,\"seq\":%llu,\"busy\":1}\n",
                       (unsigned long long)seq);
    return n == FW_JPUT_FAIL ? 0 : n;
}

static size_t fw_format_query(const FwQueryResult* r, char* out, size_t cap) {
    if (!out || cap < 2) return 0;
    out[0] = '\0';
    size_t n;
    if (!r->ok) {
        n = fw_putf(out, cap, 0, "{\"v\":1,\"seq\":%llu,\"ok\":0}\n", (unsigned long long)r->seq);
        return n == FW_JPUT_FAIL ? 0 : n;
    }
    n = fw_putf(out, cap, 0,
                "{\"v\":1,\"seq\":%llu,\"ok\":1,\"exists\":%d,\"denied\":%d,\"reason\":\"%s\"",
                (unsigned long long)r->seq, r->exists ? 1 : 0, r->denied ? 1 : 0, r->reason);
    if (n == FW_JPUT_FAIL) return 0;
    n = fw_putf(out, cap, n, ",\"scope\":\"%s\",\"rule\":\"%s\"", r->scope ? r->scope : "none",
                r->rule ? r->rule : "none");
    if (n == FW_JPUT_FAIL) return 0;
    n = fw_putf(out, cap, n, ",\"spath\":");
    if (n == FW_JPUT_FAIL) return 0;
    n = fw_put_str(out, cap, n, r->spath);
    if (n == FW_JPUT_FAIL) return 0;
    n = fw_putf(out, cap, n, ",\"rpath\":");
    if (n == FW_JPUT_FAIL) return 0;
    n = fw_put_str(out, cap, n, r->rpath);
    if (n == FW_JPUT_FAIL) return 0;
    n = fw_putf(out, cap, n, ",\"vol\":\"external_primary\"}\n");
    return n == FW_JPUT_FAIL ? 0 : n;
}

/* 请求处理（返回响应长度，0 = 连错误响应都放不下，调用方断开连接）。
   congested 由调用方判定（并发配额满）→ 只回 busy，绝不复用 ok=0：
   两者语义不同，客户端据此决定"重试"还是"降级到本地翻译"。 */
static size_t fw_query_handle(const char* req, char* out, size_t cap, bool congested) {
    char cmd[32];
    char spath[PATH_MAX];
    unsigned long long seq = 0;
    unsigned long long uid_v = 0;
    cmd[0] = '\0';
    spath[0] = '\0';
    bool has_seq = fw_json_find_u64(req, "seq", &seq);
    bool has_uid = fw_json_find_u64(req, "uid", &uid_v);
    bool has_cmd = fw_json_find_str(req, "cmd", cmd, sizeof cmd);
    bool has_spath = fw_json_find_str(req, "spath", spath, sizeof spath);

    if (congested) return fw_format_busy(out, cap, has_seq ? seq : 0);

    FwQueryResult r;
    memset(&r, 0, sizeof r);
    r.seq = has_seq ? seq : 0;
    r.reason = "none";
    r.scope = "none";
    r.rule = "none";
    if (!has_cmd || strcmp(cmd, "QUERY") != 0 || !has_spath || !has_uid) {
        /* 不认识的请求 / 缺字段：ok=0（与 denied 严格区分） */
        return fw_format_query(&r, out, cap);
    }
    int user_id = -1;
    char sub[PATH_MAX];
    if (!fw_view_decode(spath, &user_id, sub, sizeof sub)) return fw_format_query(&r, out, cap);

    char fuse_path[PATH_MAX];
    /* 换成 FUSE 视角层级再判定：放不下就 ok=0（绝不拿截断路径去问 ACL/规则，
       截断会把"他包 Android/data"变成别的目录，判定直接错位） */
    if (common_fuse_user_path(user_id, sub, fuse_path, sizeof fuse_path) != 0)
        return fw_format_query(&r, out, cap);

    /* 判定：访问控制走 fw_acl_check（单点），规则走 fw_rules_resolve（单点）。
       入参 uid 是**发起应用**（不是对端）：通道身份已由 SO_PEERCRED 白名单校验。 */
    int acl = fw_acl_check((uid_t)uid_v, 0, fuse_path, NSP_ACL_OP_GENERIC_READ, false, 0);
    NspQueryCtx q;
    memset(&q, 0, sizeof q);
    q.uid = (uid_t)uid_v;
    q.pid = 0;
    q.path = fuse_path;
    NspPathDecision d;
    fw_rules_resolve(&q, &d);
    if (!d.valid || d.is_ftp) return fw_format_query(&r, out, cap); /* 无规则 / 后端：ok=0 */

    r.ok = true;
    r.scope = fw_scope_name(d.rule_scope);
    r.rule = fw_rule_name(d.rule_kind);
    if (acl == -ENOENT) {
        r.denied = true;
        /* 跨应用隔离与 HIDE 在 ACL 侧同口径（都回 ENOENT），但成因不同：
           隔离的判据在引擎（is_other_app_pkg），这里据实报告——否则真机上
           「他包 Android/data」会被误报成 hide，扫描侧看不出是隔离。 */
        r.reason = d.is_other_app_pkg ? "isolation" : "hide";
        if (d.rule_kind == NSP_RULE_NONE) {
            /* ACL 先于规则拒绝（例如骨架路径）：成因不在规则表里，据实报 */
            r.rule = d.is_other_app_pkg ? "isolation" : "hide";
        }
    } else if (acl != 0) {
        r.denied = true;
        r.reason = "isolation"; /* 存在但不许 */
        r.scope = "none";       /* 访问控制是默认边界，不归任何规则作用域 */
        r.rule = "isolation";
    } else if (d.appear_missing) {
        r.denied = true;
        r.reason = "hide";
    } else if (d.read_only) {
        /* RO 优先于 REDIRECT：写被 RO 拒绝 ⇒ 没有文件可扫，扫描侧必须停手 */
        r.denied = true;
        r.reason = "ro";
    } else if (d.is_sandbox) {
        r.reason = "sandbox";
    } else if (d.is_redirect) {
        r.reason = "redirect";
    } else {
        r.reason = "none";
    }
    snprintf(r.rpath, sizeof r.rpath, "%s", d.real_path);
    fw_real_to_view(d.real_path, user_id, spath, r.spath, sizeof r.spath);
    r.exists = fw_exists_lookup(fuse_path, d.real_path) != 0;
    return fw_format_query(&r, out, cap);
}

/* ================== QUERY 连接线程 ================== */

static void fw_query_conns_release(void) {
    atomic_fetch_sub(&g_query_conns, 1);
}

static void* fw_query_conn_thread(void* arg) {
    int fd = (int)(intptr_t)arg;
    nsp_set_thread_name("nsp_fs_query");
    for (;;) {
        struct pollfd p;
        p.fd = fd;
        p.events = POLLIN;
        p.revents = 0;
        int r = poll(&p, 1, FW_QUERY_IDLE_MS);
        if (r == 0) break; /* 空闲超时：断开，客户端会退避重连 */
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        char buf[FW_QUERY_REQ_MAX + 1];
        ssize_t n = recv(fd, buf, sizeof buf - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';
        bool congested = atomic_load_explicit(&g_query_inflight, memory_order_relaxed) >=
                         FW_QUERY_MAX_INFLIGHT;
        atomic_fetch_add(&g_query_inflight, 1);
        char resp[FW_QUERY_RESP_MAX];
        size_t rl = fw_query_handle(buf, resp, sizeof resp, congested);
        atomic_fetch_sub(&g_query_inflight, 1);
        if (rl == 0 || !nsp_send_all(fd, resp, rl)) break;
    }
    close(fd);
    fw_query_conns_release();
    return NULL;
}

/* 超配额连接的处理：先读一帧（短超时）以便回显 seq，再回 busy=1。
   线程数因此恒 ≤ FW_QUERY_MAX_CONNS（不为超额连接开线程）。 */
static void fw_query_reject_busy(int fd) {
    struct pollfd p;
    p.fd = fd;
    p.events = POLLIN;
    p.revents = 0;
    char resp[FW_QUERY_RESP_MAX];
    size_t rl = 0;
    if (poll(&p, 1, 100) > 0) {
        char buf[FW_QUERY_REQ_MAX + 1];
        ssize_t n = recv(fd, buf, sizeof buf - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            rl = fw_query_handle(buf, resp, sizeof resp, true);
        }
    }
    if (rl == 0) rl = fw_format_busy(resp, sizeof resp, 0);
    if (rl) nsp_send_all(fd, resp, rl);
    close(fd);
}

static void* fw_query_accept_thread(void* arg) {
    (void)arg;
    nsp_set_thread_name("nsp_fs_query");
    while (!atomic_load_explicit(&g_quit, memory_order_relaxed)) {
        int fd = accept4(g_qsock, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (atomic_load_explicit(&g_quit, memory_order_relaxed)) break;
            LOG_DBG("QUERY accept 失败: %s", strerror(errno));
            break;
        }
        pid_t pid = 0;
        uid_t uid = 0;
        gid_t gid = 0;
        if (nsp_peer_cred(fd, &pid, &uid, &gid) != 0 || !fw_uid_allowed(uid)) {
            /* 通道身份不在白名单：直接断开（不回响应——它不该知道我们在这儿） */
            LOG_DBG("拒绝 QUERY 连接：通道 pid=%d uid=%u 不在白名单", (int)pid, (unsigned)uid);
            close(fd);
            continue;
        }
        if (atomic_load_explicit(&g_query_conns, memory_order_relaxed) >= FW_QUERY_MAX_CONNS) {
            fw_query_reject_busy(fd);
            continue;
        }
        atomic_fetch_add(&g_query_conns, 1);
        pthread_t th;
        if (pthread_create(&th, NULL, fw_query_conn_thread, (void*)(intptr_t)fd) != 0) {
            LOG_WRN("QUERY 连接线程创建失败，回 busy");
            fw_query_reject_busy(fd);
            fw_query_conns_release();
            continue;
        }
        pthread_detach(th);
    }
    return NULL;
}

/* ================== 生命周期 ================== */

static void fw_events_reset(void) {
    g_ring_head = 0;
    g_ring_tail = 0;
    g_ring_count = 0;
    atomic_store(&g_seq, 0);
    g_sub_count = 0;
    memset(g_subs, 0, sizeof g_subs);
    memset(g_coalesce, 0, sizeof g_coalesce);
    memset(g_exists, 0, sizeof g_exists);
    atomic_store(&g_query_conns, 0);
    atomic_store(&g_query_inflight, 0);
}

static void fw_events_close_fds(void) {
    if (g_evsock >= 0) close(g_evsock);
    if (g_qsock >= 0) close(g_qsock);
    if (g_evfd >= 0) close(g_evfd);
    g_evsock = -1;
    g_qsock = -1;
    g_evfd = -1;
}

/* 自动解析的两个 MediaProvider 包名：消费方（MPM）是跑在 MediaProvider 进程里的
   Xposed 模块，SO_PEERCRED 拿到的是**那个进程**的 uid——实测 10277
   （OPD2404/Android16，Android 11+ 为 .media.module），既不是 system(1000) 也不是
   media_rw(1023)：写死默认三项等于把通道唯一的消费方拒掉。uid 随 ROM/多用户变，
   包名才是稳定锚点，故按包名从 packages.list 解析。 */
static const char* const k_events_auto_pkg[] = {
    "com.google.android.providers.media.module", /* Google 版 Android 11+ */
    "com.android.providers.media.module",        /* AOSP/ROM 版 Android 11+：实测 OPD2404 就是它，
                                                    包名不带 google 前缀（漏了它 = 通道开着用不了） */
    "com.android.providers.media",               /* AOSP / 旧版（Android 10 及更早） */
};
#define FW_EVENTS_AUTO_PKG_COUNT (sizeof k_events_auto_pkg / sizeof k_events_auto_pkg[0])
_Static_assert(FW_EVENTS_AUTO_PKG_COUNT == FW_EVENTS_MAX_AUTO_UIDS,
               "FW_EVENTS_MAX_AUTO_UIDS 必须与 k_events_auto_pkg 的条目数一致");

/* 加入白名单（去重；满则只记 DEBUG——少一条白名单不影响通道本身）。 */
static void fw_allow_add(uid_t uid) {
    for (int i = 0; i < g_allow_count; i++) {
        if (g_allow_uids[i] == uid) return; /* 两个包名可能是同一 uid */
    }
    if (g_allow_count >= FW_EVENTS_MAX_ALLOW) {
        LOG_DBG("事件通道白名单已满（%d 项），uid=%u 未加入", FW_EVENTS_MAX_ALLOW,
                (unsigned)uid);
        return;
    }
    g_allow_uids[g_allow_count++] = uid;
}

/* 只把**解析出来的 uid**并进白名单：包名不可由请求方声明（那会让任意进程
   自称 MediaProvider 就拿到通道）。解析失败（packages.list 不可读 / 无该行）
   只少这一项，通道其余照旧。 */
static void fw_allow_add_mediaprovider(void) {
    for (size_t i = 0; i < FW_EVENTS_AUTO_PKG_COUNT; i++) {
        uid_t uid = 0;
        if (!fw_pkg_uid_for_package(k_events_auto_pkg[i], &uid)) {
            LOG_DBG("事件通道白名单：%s 的 uid 解析失败（packages.list 无该行），跳过",
                    k_events_auto_pkg[i]);
            continue;
        }
        fw_allow_add(uid);
    }
}

/* 通道身份白名单：root / system / media_rw + 自动解析的 MediaProvider 进程 uid
   + [GLOBAL] FUSE_EVENTS_UIDS 追加项。它只决定"谁有权连这两条 socket"，与事件
   里的 uid/pkg（被代理的应用）无关。只在 FUSE_EVENTS 打开时构造（fw_events_start
   的开关判断在前），关闭时零文件访问。 */
static void fw_build_allow_list(void) {
    g_allow_count = 0;
    fw_allow_add(0);    /* root */
    fw_allow_add(1000); /* system */
    fw_allow_add(1023); /* media_rw */
    fw_allow_add_mediaprovider();
    for (int i = 0; i < g_global_cfg.fuse_events_uid_count; i++) {
        if (g_global_cfg.fuse_events_uids[i] >= 0)
            fw_allow_add((uid_t)g_global_cfg.fuse_events_uids[i]);
    }
}

/* 通道起不来时把原因落到 LOG_DIR/events_socket.status：sys.log 里那条 ERR 会随日志
   滚动消失，而「事件通道哑了」本身没有任何外部表现（订阅者收不到事件，界面上也
   看不到异常），必须能从 log_ctl 反查到。成功启动或开关关闭时删掉该文件，避免旧
   失败残留被读成本次状态。 */
static void fw_events_record_result(bool ok, const char* stage, int err) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/events_socket.status", LOG_DIR);
    if (ok) {
        unlink(path);
        return;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return;
    char buf[256];
    int n = snprintf(buf, sizeof(buf), "time=%lld pid=%d stage=%s errno=%d msg=%s\n",
                     (long long)time(NULL), (int)getpid(), stage ? stage : "?", err,
                     strerror(err));
    if (n > 0) (void)write(fd, buf, (size_t)((n < (int)sizeof(buf)) ? n : (int)sizeof(buf) - 1));
    close(fd);
}

int fw_events_start(void) {
    if (atomic_load_explicit(&g_events_on, memory_order_relaxed)) return 0;
    if (!g_global_cfg.fuse_events) {
        LOG_DBG("FUSE 事件通道未启用（[GLOBAL] FUSE_EVENTS 默认 OFF）：零线程零 socket");
        fw_events_record_result(true, NULL, 0); /* 开关关闭不是故障，别留旧失败记录 */
        return 0;
    }
    const char* stage = "init";
    fw_build_allow_list();
    fw_events_reset();
    g_ring = calloc(FW_EVENTS_RING_CAP, sizeof *g_ring);
    if (!g_ring) {
        LOG_ERR("事件环分配失败（%d 槽）", FW_EVENTS_RING_CAP);
        fw_events_record_result(false, "ring-alloc", ENOMEM);
        return -1;
    }
    g_evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (g_evfd < 0) {
        LOG_ERR("eventfd 创建失败: %s", strerror(errno));
        stage = "eventfd";
        goto fail;
    }
    struct sockaddr_un addr;
    g_evsock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (g_evsock < 0) {
        LOG_ERR("事件 socket 创建失败: %s", strerror(errno));
        stage = "events-socket";
        goto fail;
    }
    socklen_t alen = nsp_uds_abstract_addr(&addr, FW_EVENTS_SOCK_NAME);
    if (bind(g_evsock, (struct sockaddr*)&addr, alen) != 0) {
        LOG_ERR("事件 socket 绑定 %s 失败: %s", FW_EVENTS_SOCK_NAME, strerror(errno));
        stage = "events-bind";
        goto fail;
    }
    int one = 1;
    /* DGRAM 无连接：SO_PEERCRED 在未连接 socket 上不可靠，订阅者身份靠
       SO_PASSCRED 的 SCM_CREDENTIALS 取（内核按发送者填，不可伪造）。 */
    if (setsockopt(g_evsock, SOL_SOCKET, SO_PASSCRED, &one, sizeof one) != 0) {
        LOG_ERR("事件 socket 开启 SO_PASSCRED 失败: %s", strerror(errno));
        stage = "events-passcred";
        goto fail;
    }
    g_qsock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (g_qsock < 0) {
        LOG_ERR("查询 socket 创建失败: %s", strerror(errno));
        stage = "query-socket";
        goto fail;
    }
    alen = nsp_uds_abstract_addr(&addr, FW_QUERY_SOCK_NAME);
    if (bind(g_qsock, (struct sockaddr*)&addr, alen) != 0) {
        LOG_ERR("查询 socket 绑定 %s 失败: %s", FW_QUERY_SOCK_NAME, strerror(errno));
        stage = "query-bind";
        goto fail;
    }
    if (listen(g_qsock, FW_QUERY_MAX_CONNS) != 0) {
        LOG_ERR("查询 socket listen 失败: %s", strerror(errno));
        stage = "query-listen";
        goto fail;
    }
    atomic_store_explicit(&g_quit, false, memory_order_relaxed);
    pthread_t th;
    if (pthread_create(&th, NULL, fw_query_accept_thread, NULL) != 0) {
        LOG_ERR("QUERY 线程创建失败");
        stage = "query-thread";
        goto fail;
    }
    g_accept_thread = th;
    if (pthread_create(&th, NULL, fw_events_thread, NULL) != 0) {
        LOG_ERR("事件线程创建失败");
        stage = "events-thread";
        atomic_store_explicit(&g_quit, true, memory_order_relaxed);
        shutdown(g_qsock, SHUT_RDWR);
        pthread_join(g_accept_thread, NULL);
        goto fail;
    }
    g_ev_thread = th;
    g_threads_up = true;
    atomic_store_explicit(&g_events_on, true, memory_order_relaxed);
    fw_events_record_result(true, NULL, 0);
    LOG("FUSE 事件通道已启动：%s（订阅者上限 %d，环 %d）、%s（并发上限 %d，白名单 %d 项）",
        FW_EVENTS_SOCK_NAME, FW_EVENTS_MAX_SUBS, FW_EVENTS_RING_CAP, FW_QUERY_SOCK_NAME,
        FW_QUERY_MAX_CONNS, g_allow_count);
    return 0;

fail: {
    int saved_errno = errno;
    fw_events_record_result(false, stage, saved_errno);
    fw_events_close_fds();
    free(g_ring);
    g_ring = NULL;
    errno = saved_errno;
    return -1;
}
}

void fw_events_stop(void) {
    if (!atomic_load_explicit(&g_events_on, memory_order_relaxed)) return;
    atomic_store_explicit(&g_quit, true, memory_order_relaxed);
    fw_ring_wake();
    if (g_qsock >= 0) shutdown(g_qsock, SHUT_RDWR);
    if (g_threads_up) {
        pthread_join(g_ev_thread, NULL);
        pthread_join(g_accept_thread, NULL);
        g_threads_up = false;
    }
    fw_events_close_fds();
    free(g_ring);
    g_ring = NULL;
    fw_events_reset();
    atomic_store_explicit(&g_fw_events_hot, false, memory_order_relaxed);
    atomic_store_explicit(&g_events_on, false, memory_order_relaxed);
    LOG("FUSE 事件通道已停止");
}
