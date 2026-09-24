#include "common.h"
#include "nsp_comm.h"
#include "nsp_util.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef TARGET_ANDROID
#include <sys/system_properties.h>
#endif
#include <stdatomic.h>
#ifdef TARGET_ANDROID
#include <sys/xattr.h>
#endif
#define FALLBACK_ERR_LOG ERROR_LOG_PATH

LogLevel g_min_log_level = LOG_INFO;
char g_real_root[PATH_MAX] = {0};
bool g_persist_all_logs = false;
bool g_strip_o_direct = false;
/* 日志合并周期：batch 期间 log_internal 将日志累积到批量缓冲（不逐条写
   环形缓冲），log_batch_end 时把整个周期合并为单条日志写入，前端最终只
   显示一条（多个发送请求并入一个日志）。原子嵌套计数 + 互斥锁保护缓冲 */
static volatile sig_atomic_t g_log_batch_depth = 0; /* >0 = 合并周期中 */
static pthread_mutex_t g_log_batch_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_log_batch_buf[65536];
static size_t g_log_batch_len = 0;

static char g_self_dir[PATH_MAX] = {0};
static char g_proc_name[64] = "unknown";
static bool g_log_inited = false;
static pthread_mutex_t g_persist_mutex = PTHREAD_MUTEX_INITIALIZER;

/* LOG 通道载荷组帧（与 log_monitor 行协议对齐，旧 log_entry_packet 语义）：
   kind=0 普通：level==LOG_IO → "LOG_IO:%s\n"；LOG_LOGCAT → "LOG_LOGCAT:%s\n"；
     否则 "LOG_SYS:<level>:[proc] <msg>\n"
   kind=1 合并： "LOG_BATCH\n<content>\nLOG_BATCH_END\n"（level 字节忽略） */
#define LOG_KIND_NORMAL 0
#define LOG_KIND_MERGED 1
static int log_frame_packet(uint8_t kind, uint8_t level, const char* msg, char* packet, size_t sz) {
    if (kind == LOG_KIND_MERGED) return snprintf(packet, sz, "LOG_BATCH\n%s\nLOG_BATCH_END\n", msg);
    if (level == LOG_IO) return snprintf(packet, sz, "LOG_IO:%s\n", msg);
    if (level == LOG_LOGCAT) return snprintf(packet, sz, "LOG_LOGCAT:%s\n", msg);
    return snprintf(packet, sz, "LOG_SYS:%d:[%s] %s\n", level, g_proc_name, msg);
}

/* 日志合并周期控制：原子嵌套计数（>0 = 周期中），支持并发/嵌套 begin/end，
   最后一个 end 把累积日志合并为单条写入环形缓冲 */
void log_batch_begin(void) {
    __sync_fetch_and_add(&g_log_batch_depth, 1);
}
void log_batch_end(void) {
    /* __sync_fetch_and_sub 返回旧值：旧值 == 1 说明这是最后一个周期，
       旧值 > 1 说明仍有外层周期（返回，不合并）。
       注意：原子减已把计数归零（旧值 1 → 0），不得再用普通赋值清零，
       否则会 clobber 并发线程的 log_batch_begin */
    if (__sync_fetch_and_sub(&g_log_batch_depth, 1) > 1) return;
    /* 取走累积内容 */
    pthread_mutex_lock(&g_log_batch_mutex);
    size_t n = g_log_batch_len;
    char merged[NSP_LOG_MSG_MAX];
    if (n >= sizeof(merged)) n = sizeof(merged) - 1;
    memcpy(merged, g_log_batch_buf, n);
    merged[n] = '\0';
    g_log_batch_len = 0;
    pthread_mutex_unlock(&g_log_batch_mutex);
    if (n == 0 || !g_log_inited) return;
    /* 合并为单条经 comm 线程发送（kind=MERGED，log_monitor 整块接收合并为
       一条入库，前端只显示一条）。单行输出：[proc] <条目1>\t<条目2>...
       （条目间以制表符连接，不用换行，避免前端按行拆分导致长内容截断/中文乱码） */
    char line[NSP_LOG_MSG_MAX];
    snprintf(line, sizeof(line), "[%s] %s", g_proc_name, merged);
    uint8_t buf[2 + NSP_LOG_MSG_MAX];
    buf[0] = LOG_KIND_MERGED;
    buf[1] = (uint8_t)LOG_DEBUG; /* 合并日志归为 debug 级别，--level>=1 不显示 */
    size_t llen = strlen(line);
    memcpy(buf + 2, line, llen + 1);
    nsp_comm_post(NSP_CH_LOG, buf, llen + 3);
}
/* 子进程日志转发 fd：run_in_mnt_ns_* fork 的子进程内 sender 线程不可达，
   子进程经此管道回传日志，父进程读取后统一写入环形缓冲（默认 -1=未启用） */
int g_log_forward_fd = -1;
_Atomic(bool) g_log_shutdown = false;
void init_timezone() {
    const char* tz = getenv("TZ");
    if (tz && tz[0] != '\0') {
        tzset();
        return;
    }
    char prop_buf[256];
#ifdef TARGET_ANDROID
    int len = __system_property_get("persist.sys.timezone", prop_buf);
    if (len > 0) {
        setenv("TZ", prop_buf, 1);
        tzset();
        return;
    }
    FILE* fp = fopen("/data/property/persist.sys.timezone", "re");
#else
    FILE* fp = fopen("/etc/timezone", "re");
#endif
    if (fp) {
        if (fgets(prop_buf, sizeof(prop_buf), fp)) {
            size_t plen = strlen(prop_buf);
            while (plen > 0 && (prop_buf[plen - 1] == '\n' || prop_buf[plen - 1] == '\r'))
                prop_buf[--plen] = '\0';
            if (plen > 0) {
                setenv("TZ", prop_buf, 1);
                tzset();
            }
        }
        fclose(fp);
    }
}
static const char* get_current_time_str(char* buf, size_t size) {
    time_t now = time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", &tm_buf);
    return buf;
}
void persist_log_to_disk(const char* log_type, const char* message, bool append_timestamp) {
    if (!g_persist_all_logs) return;
    pthread_mutex_lock(&g_persist_mutex);
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/persistent_%s.log", LOG_DIR, log_type);
    FILE* fp = fopen(path, "a");
    if (fp) {
        if (append_timestamp) {
            char time_buf[64];
            fprintf(fp, "[%s] ", get_current_time_str(time_buf, sizeof(time_buf)));
        }
        fprintf(fp, "%s\n", message);
        fclose(fp);
    }
    pthread_mutex_unlock(&g_persist_mutex);
}

/* 监控日志落盘（无条件，不依赖 g_persist_all_logs）：MONITOR ON 时保证
   应用操作路径始终可查（LOG_DIR/persistent_io.log），即使 log_ctl/UDS
   链路不可用也能从日志文件查看 */
void persist_io_log(const char* message) {
    if (!message) return;
    mkdir_recursive(LOG_DIR);
    pthread_mutex_lock(&g_persist_mutex);
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/persistent_io.log", LOG_DIR);
    FILE* fp = fopen(path, "a");
    if (fp) {
        char time_buf[64];
        fprintf(fp, "[%s] %s\n", get_current_time_str(time_buf, sizeof(time_buf)), message);
        fclose(fp);
    }
    pthread_mutex_unlock(&g_persist_mutex);
}
void escape_cgroup() {
    /* 实现与 cgroup 路径表统一在 nsp_util（唯一出口，避免两份路径表漂移）。
       行为差异：原先此处对写入失败打 LOG_DBG 明细，现与 nsp_util 版一致静默
       ——cgroup 路径在不同 Android 版本/配置下本就可能不存在或无写权限，
       属预期内失败；需要明细时可在 nsp_escape_cgroup 内单独加。 */
    nsp_escape_cgroup();
}
/* IPC 短连接 helper（500ms 收发超时 + abstract namespace）：
   仅 comm 线程的 IPC 后端使用，调用线程一律 nsp_comm_post(NSP_CH_IPC) */
static int connect_ipc(void) {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock_fd < 0) return -1;
    struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
    setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_un server_addr;
    socklen_t len = nsp_uds_abstract_addr(&server_addr, IPC_SOCKET_NAME);
    if (connect(sock_fd, (struct sockaddr*)&server_addr, len) < 0) {
        close(sock_fd);
        return -1;
    }
    return sock_fd;
}

/* IPC 后端（comm 线程）：每条消息独立短连接（与 injector ipc_server 短连接
   语义一致：send 后即关，不读回包） */
static int nsp_ipc_emit(void* ctx, const void* data, size_t len) {
    (void)ctx;
    int fd = connect_ipc();
    if (fd < 0) return -1;
    if (!nsp_send_all(fd, data, len)) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}
void set_self_dir(const char* path) {
    if (path && *path) strncpy(g_self_dir, path, sizeof(g_self_dir) - 1);
}
char* get_self_dir() {
    if (g_self_dir[0] != 0) return g_self_dir;
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        char* last_slash = strrchr(buf, '/');
        if (last_slash) *last_slash = '\0';
        strncpy(g_self_dir, buf, sizeof(g_self_dir) - 1);
    } else {
        strncpy(g_self_dir, "/data/local/tmp", sizeof(g_self_dir) - 1);
        g_self_dir[sizeof(g_self_dir) - 1] = '\0';
    }
    return g_self_dir;
}
/* 读取整个文件到堆内存（动态扩容，尾随 NUL）：injector 的 mount_manager
   与 ns_utils 原各自实现一份，现统一为公共工具（见 common.h 声明） */
char* read_file_dynamic(const char* path, size_t* out_size, size_t max_size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    size_t capacity = 65536;
    size_t size = 0;
    char* buf = malloc(capacity);
    if (!buf) {
        close(fd);
        return NULL;
    }
    while (1) {
        ssize_t r = read(fd, buf + size, capacity - size - 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return NULL;
        }
        if (r == 0) break;
        size += r;
        if (max_size > 0 && size > max_size) { /* 超上限：拒绝，防超大文件撑爆内存 */
            free(buf);
            close(fd);
            errno = EFBIG;
            return NULL;
        }
        if (size >= capacity - 1) {
            capacity *= 2;
            char* nb = realloc(buf, capacity);
            if (!nb) {
                free(buf);
                close(fd);
                return NULL;
            }
            buf = nb;
        }
    }
    close(fd);
    buf[size] = '\0';
    if (out_size) *out_size = size;
    return buf;
}

/* 递归创建目录（带父目录属性继承，原 config_parser.c 提供，迁至公共工具） */
static void sync_attributes(const char* source_parent, const char* target_path) {
    struct stat st;
    if (lstat(source_parent, &st) != 0) return;
    if (lchown(target_path, st.st_uid, st.st_gid) != 0) {
    }
    chmod(target_path, st.st_mode & 07777);
#ifdef TARGET_ANDROID
    char context[256];
    ssize_t ctx_len = lgetxattr(source_parent, "security.selinux", context, sizeof(context));
    if (ctx_len > 0) {
        lsetxattr(target_path, "security.selinux", context, (size_t)ctx_len, 0);
    } else if (strstr(target_path, STORAGE_BASE) == target_path) {
        const char* default_ctx = "u:object_r:media_rw_data_file:s0";
        lsetxattr(target_path, "security.selinux", default_ctx, strlen(default_ctx) + 1, 0);
    }
#endif
}

static void inherit_from_parent(const char* real_path) {
    char parent[PATH_MAX];
    strncpy(parent, real_path, PATH_MAX - 1);
    char* last = strrchr(parent, '/');
    if (last) {
        if (last == parent)
            strcpy(parent, "/");
        else
            *last = '\0';
        sync_attributes(parent, real_path);
    }
}

/* 递归建目录的唯一实现。inherit=true 时对新目录套用父目录的属主/模式
   （Android 另含 SELinux 上下文），供 mkdir_recursive_p；
   mkdir_recursive 保持历史语义（不继承属性、固定 0755）。
   两者语义确有差异故保留两个入口，但共用本实现——此前各写一份循环，
   且 mkdir_recursive 用 256 字节栈缓冲，超长路径会被静默拒绝。 */
static int mkdir_p_impl(const char* path, mode_t mode, bool inherit) {
    if (!path || !path[0]) return -1;
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) return -1;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (access(tmp, F_OK) != 0) {
                if (mkdir(tmp, mode) == 0) {
                    if (inherit) inherit_from_parent(tmp);
                } else if (errno != EEXIST) {
                    return -1;
                }
            }
            *p = '/';
        }
    }
    if (access(tmp, F_OK) != 0) {
        if (mkdir(tmp, mode) == 0) {
            if (inherit) inherit_from_parent(tmp);
        } else if (errno != EEXIST) {
            return -1;
        }
    }
    return 0;
}

int mkdir_recursive(const char* dir) {
    return mkdir_p_impl(dir, 0755, false);
}

int mkdir_recursive_p(const char* path, mode_t mode) {
    return mkdir_p_impl(path, mode, true);
}
/* 核心修复：共享的无效 Unicode/控制字符检测逻辑。
   增加全面的 Null 终止探测防御，绝不发生指针越过结束符 '\0' 的情况，阻断任何越界或野指针异常 */
static int path_char_is_invalid(const unsigned char* p) {
    if (*p == '\0') return 0;
    if (*p < 0x08) return 1;
    if (*p > 0x09 && *p < 0x20) return 1;
    if (*p == 0x7F) return 1;
    // 2 字节 UTF-8 校验，需确保 p[1] 并非终止符
    if (p[0] == 0xC2 && p[1] != '\0' && (p[1] == 0xA0 || p[1] == 0xAD)) return 2;
    // 3 字节 UTF-8 校验，需确保 p[1], p[2] 并非终止符
    if (p[0] == 0xE2 && p[1] != '\0' && p[2] != '\0') {
        if (p[1] == 0x80 && p[2] >= 0x80 && p[2] <= 0xAF) return 3;
        if (p[1] == 0x81 && p[2] >= 0xA0 && p[2] <= 0xAF) return 3;
    }
    if (p[0] == 0xE1 && p[1] != '\0' && p[2] != '\0') {
        if (p[1] == 0xA0 && p[2] == 0x8E) return 3;
    }
    if (p[0] == 0xEF && p[1] != '\0' && p[2] != '\0') {
        if (p[1] == 0xBB && p[2] == 0xBF) return 3;
    }
    // 4 字节 UTF-8 校验，需确保 p[1], p[2], p[3] 并非终止符
    if (p[0] == 0xF3 && p[1] != '\0' && p[2] != '\0' && p[3] != '\0') {
        if (p[1] == 0xA0 && p[2] == 0x80 && p[3] >= 0x80 && p[3] <= 0xBF) return 4;
        if (p[1] == 0xA0 && p[2] == 0x81 && p[3] >= 0x80 && p[3] <= 0xAF) return 4;
    }
    return 0;
}
bool path_contains_invalid_chars(const char* path) {
    if (!path) return false;
    const unsigned char* p = (const unsigned char*)path;
    while (*p) {
        int skip = path_char_is_invalid(p);
        if (skip > 0) return true;
        p++;
    }
    return false;
}
void path_sanitize(char* out, size_t size, const char* path) {
    if (!out || size == 0) return;
    if (!path) {
        out[0] = '\0';
        return;
    }
    const unsigned char* p = (const unsigned char*)path;
    size_t o = 0;
    size_t max = size - 1;
    while (*p && o < max) {
        int skip = path_char_is_invalid(p);
        if (skip > 0) {
            p += skip;
        } else {
            out[o++] = *p;
            p++;
        }
    }
    out[o] = '\0';
}
/* LOG 通道载荷：[kind:1][level:1][msg...]（调用线程组帧头，发送组包） */
typedef struct {
    int sock; /* -1=未建链（仅 comm 线程触碰） */
} log_be_ctx_t;
static log_be_ctx_t g_log_be = {.sock = -1};

static bool nsp_log_ensure_link(void* ctx) {
    log_be_ctx_t* c = ctx;
    if (c->sock >= 0) return true;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    struct timeval tv = {.tv_sec = 0, .tv_usec = 50000};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_un addr;
    socklen_t len = nsp_uds_abstract_addr(&addr, LOG_SOCKET_NAME);
    if (connect(fd, (struct sockaddr*)&addr, len) < 0) {
        close(fd);
        return false;
    }
    c->sock = fd;
    return true;
}

static int nsp_log_emit(void* ctx, const void* data, size_t len) {
    log_be_ctx_t* c = ctx;
    if (len < 2 || c->sock < 0) return -1;
    const uint8_t* p = data;
    char packet[NSP_LOG_MSG_MAX * 2 + 128];
    /* msg 段以 NUL 截断防越界（post 载荷恒以 NUL 结尾，见 log_internal） */
    size_t mlen = len - 2;
    if (mlen >= NSP_LOG_MSG_MAX) mlen = NSP_LOG_MSG_MAX - 1;
    char msg[NSP_LOG_MSG_MAX];
    memcpy(msg, p + 2, mlen);
    msg[mlen] = '\0';
    int plen = log_frame_packet(p[0], p[1], msg, packet, sizeof(packet));
    if (plen <= 0) return 0;
    if (!nsp_send_all(c->sock, packet, (size_t)plen)) {
        close(c->sock);
        c->sock = -1;
        return -1;
    }
    return 0;
}

static void nsp_log_fini(void* ctx) {
    log_be_ctx_t* c = ctx;
    if (c->sock >= 0) {
        close(c->sock);
        c->sock = -1;
    }
}

/* 拥塞上报：本 drain 轮有覆盖丢弃时经 LOG 通道发一行 SYS 可查
   （post 永不阻塞；LOG 自身拥塞时该行亦可能被覆盖，计数以 API 为准。
   若本进程未注册 LOG 后端（如 log_monitor），该行计 dropped，无限循环） */
void nsp_log_report(nsp_ch_t ch, uint64_t n, void* ctx) {
    (void)ctx;
    /* 限频 5s：LOG 自身拥塞时报告回注会加剧拥塞、下轮再报，限频后每轮
       最多一条；精确计数以 nsp_comm_dropped() 为准 */
    static uint64_t last_ms = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
    if (now - last_ms < 5000) return;
    last_ms = now;
    static const char* names[NSP_CH__N] = {"LOG", "IPC", "BCAST"};
    char msg[128];
    int mlen = snprintf(msg, sizeof(msg), "comm: %s 通道拥塞，覆盖旧数据 %llu 条", names[ch],
                        (unsigned long long)n);
    if (mlen <= 0) return;
    uint8_t buf[2 + 128];
    buf[0] = LOG_KIND_NORMAL;
    buf[1] = (uint8_t)LOG_WARN;
    memcpy(buf + 2, msg, (size_t)mlen + 1);
    nsp_comm_post(NSP_CH_LOG, buf, (size_t)mlen + 3);
}

void log_init(const char* process_name) {
    init_timezone();
    strncpy(g_proc_name, process_name, sizeof(g_proc_name) - 1);
    mkdir_recursive(LOG_DIR);
    atomic_store_explicit(&g_log_shutdown, false, memory_order_relaxed);
    /* 统一通讯线程：LOG + IPC 后端常驻（调用线程只 post，永不碰 socket） */
    if (nsp_comm_init() != 0) {
        g_log_inited = false;
        return;
    }
    nsp_comm_backend_t log_be = {
        .ctx = &g_log_be,
        .ensure_link = nsp_log_ensure_link,
        .emit = nsp_log_emit,
        .fini = nsp_log_fini,
        .report = nsp_log_report,
    };
    nsp_comm_register(NSP_CH_LOG, &log_be);
    nsp_comm_backend_t ipc_be = {
        .ctx = NULL,
        .ensure_link = NULL,
        .emit = nsp_ipc_emit,
        .fini = NULL,
        .report = nsp_log_report,
    };
    nsp_comm_register(NSP_CH_IPC, &ipc_be);
    g_log_inited = true;
}

void log_close(void) {
    if (!g_log_inited) return;
    nsp_comm_fini(); /* 最尽力 drain + join */
    g_log_inited = false;
}

void log_internal(LogLevel level, const char* format, ...) {
    if (level < g_min_log_level && level != LOG_DEBUG) return;
    char msg_buf[NSP_LOG_MSG_MAX];
    va_list args;
    va_start(args, format);
    vsnprintf(msg_buf, sizeof(msg_buf), format, args);
    va_end(args);
    size_t mlen = strlen(msg_buf);
    while (mlen > 0 && (msg_buf[mlen - 1] == '\n' || msg_buf[mlen - 1] == '\r'))
        msg_buf[--mlen] = '\0';
    /* 子进程日志转发：fork 后的子进程内 sender 线程不可达（fork 不复制线程），
       环形缓冲写了也没人消费；检测到 g_log_forward_fd 时把日志行写入管道，
       由父进程读取后统一写入环形缓冲（保持行格式 [时间]|[进程]|msg） */
    if (g_log_forward_fd >= 0) {
        char fwd_buf[NSP_LOG_MSG_MAX + 96];
        int flen = snprintf(fwd_buf, sizeof(fwd_buf), "%d|%s\n", (int)level, msg_buf);
        if (flen > 0) {
            ssize_t w = write(g_log_forward_fd, fwd_buf, (size_t)flen);
            (void)w;
        }
        return;
    }
    if (level == LOG_IO) {
#ifdef NSP_ENABLE_IO_LOG
        /* 监控日志落盘（LOG_DIR/persistent_io.log）：仅调试/监控构建
           （-DNSP_ENABLE_IO_LOG）启用——发布构建默认关闭该文件输出，
           避免弱网/低端设备上频繁 I/O 落盘；log_ctl/UDS 查询不受影响 */
        persist_io_log(msg_buf);
#endif
    } else if (g_persist_all_logs) {
        if (level == LOG_LOGCAT)
            persist_log_to_disk("logcat", msg_buf, true);
        else
            persist_log_to_disk("sys", msg_buf, true);
    }
    if (!g_log_inited) return;
    /* 合并周期内：累积到批量缓冲（不逐条写环形缓冲），由 log_batch_end
       合并为单条日志，前端最终只显示一条（多个发送请求并入一个日志）。
       只累积内容本身（不带 [proc] 前缀），条目间以制表符连接（不用换行，
       避免前端按行拆分导致长内容截断/中文乱码），标签由合并单条统一带。
       原子读 depth：log_batch_end 用 __sync_fetch_and_sub 归零，若此处
       用普通读可能看到陈旧值 1，在 batch 已结束归零后仍追加内容到已
       重置缓冲，造成消息丢失且残留字节并入下一周期 */
    if (__sync_fetch_and_add(&g_log_batch_depth, 0) > 0) {
        pthread_mutex_lock(&g_log_batch_mutex);
        int w = snprintf(g_log_batch_buf + g_log_batch_len,
                         sizeof(g_log_batch_buf) - g_log_batch_len, "%s\t", msg_buf);
        if (w > 0 && g_log_batch_len + (size_t)w < sizeof(g_log_batch_buf))
            g_log_batch_len += (size_t)w;
        pthread_mutex_unlock(&g_log_batch_mutex);
        return;
    }
    /* 调用线程仅组帧头 + post（永不碰 socket/mutex 长临界区/eventfd 细则） */
    uint8_t buf[2 + NSP_LOG_MSG_MAX];
    buf[0] = LOG_KIND_NORMAL;
    buf[1] = (uint8_t)level;
    size_t mlen2 = strlen(msg_buf);
    memcpy(buf + 2, msg_buf, mlen2 + 1);
    nsp_comm_post(NSP_CH_LOG, buf, mlen2 + 3);
}

bool is_media_provider(const char* pkg) {
    return (strstr(pkg, "com.android.providers.media") != nullptr);
}

/* 存储路径合成统一出口：fuse_daemon fw_default_real_path、br_rules 回退分支、
 * path_vars build_real_base 尾部分支原各写一份 STORAGE_BASE snprintf，现收敛至此。
 * 语义与原手写逻辑逐分支一致（g_real_root 非空则用测试/注入指定的真实根）。
 * 截断可观测：保持 void 签名（不断模块 ABI）。P3：每展开点独立计数、前 3 次
 * 带调用点告警（不同场景不再被一次性标志屏蔽），之后每 1024 次补一行抑制计数。
 * 输入恒受 MAX_PATH_LEN/PATH_MAX 约束，实际不可达；一旦出现即排查。 */
#define PATH_SNPRINTF(out, sz, ...)                                                                \
    do {                                                                                           \
        int _pn = snprintf(out, sz, __VA_ARGS__);                                                  \
        if (_pn < 0 || (size_t)_pn >= (sz)) {                                                      \
            static _Atomic unsigned _pwarn_n = 0;                                                  \
            unsigned _n0 = atomic_fetch_add(&_pwarn_n, 1);                                         \
            if (_n0 < 3)                                                                           \
                LOG_WRN("路径合成截断[%s:%d]（需 %d/限 %zu），请排查超长输入", __func__, __LINE__, \
                        _pn, (size_t)(sz));                                                        \
            else if (_n0 % 1024 == 0)                                                              \
                LOG_WRN("路径合成截断[%s:%d]已累计 %u 次（抑制中）", __func__, __LINE__, _n0);     \
        }                                                                                          \
    } while (0)

void common_default_real_path(int user_id, const char* sub_path, char* out, size_t sz) {
    if (!out || sz == 0) return;
    if (!sub_path) sub_path = "/";
    if (user_id >= 0) {
        if (g_real_root[0])
            PATH_SNPRINTF(out, sz, "%s/%d%s", g_real_root, user_id, sub_path);
        else
            PATH_SNPRINTF(out, sz, STORAGE_BASE "/%d%s", user_id, sub_path);
    } else {
        if (g_real_root[0])
            PATH_SNPRINTF(out, sz, "%s%s", g_real_root, sub_path);
        else
            PATH_SNPRINTF(out, sz, STORAGE_BASE "%s", sub_path);
    }
}

void common_storage_root(int user_id, char* out, size_t sz) {
    if (!out || sz == 0) return;
    if (user_id < 0) user_id = 0;
    if (g_real_root[0])
        PATH_SNPRINTF(out, sz, "%s/%d", g_real_root, user_id);
    else
        PATH_SNPRINTF(out, sz, STORAGE_BASE "/%d", user_id);
}

int common_sandbox_path(int uid, const char* pkg, char* out, size_t sz) {
    if (!pkg || !pkg[0] || !out || sz == 0) return -1;
    if (uid < 0) uid = 0;
    int need;
    if (g_real_root[0])
        need = snprintf(nullptr, 0, "%s/%d/Android/data/%s/sandbox", g_real_root, uid, pkg);
    else
        need = snprintf(nullptr, 0, STORAGE_BASE "/%d/Android/data/%s/sandbox", uid, pkg);
    if (need <= 0 || (size_t)need >= sz) return -1;
    if (g_real_root[0])
        snprintf(out, sz, "%s/%d/Android/data/%s/sandbox", g_real_root, uid, pkg);
    else
        snprintf(out, sz, STORAGE_BASE "/%d/Android/data/%s/sandbox", uid, pkg);
    return 0;
}
