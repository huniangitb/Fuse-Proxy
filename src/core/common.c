#include "common.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <sys/time.h>
#include <fcntl.h>
#ifdef TARGET_ANDROID
#include <sys/system_properties.h>
#endif
#include <stdatomic.h>
#include <sys/eventfd.h>
#include <poll.h>
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
static volatile sig_atomic_t g_log_batch_depth = 0;   /* >0 = 合并周期中 */
static pthread_mutex_t g_log_batch_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_log_batch_buf[65536];
static size_t g_log_batch_len = 0;
/* 合并日志标记：写入环形缓冲的合并单条以该前缀开头，sender 据此以
   LOG_BATCH 分帧协议发送，log_monitor 整块接收合并为一条入库 */
#define LOG_MERGED_MARK "\x01MERGED\x01"
static char g_self_dir[PATH_MAX] = {0};
static char g_proc_name[64] = "unknown";
static bool g_log_inited = false;
static pthread_mutex_t g_persist_mutex = PTHREAD_MUTEX_INITIALIZER;

#define LOG_BUF_CAPACITY 2048
#define LOG_BUF_MASK     (LOG_BUF_CAPACITY - 1)
/* 日志条目容量与 log_monitor 消费端（MAX_MSG_LEN=4096）对齐，
   避免合并日志在环形缓冲处被截断（总内存不变：2048×4096 ≈ 8192×1024） */
#define LOG_MSG_MAX_LEN  4096

typedef struct {
    char     msg[LOG_MSG_MAX_LEN];
    LogLevel level;
} LogEntry;

typedef struct {
    LogEntry      entries[LOG_BUF_CAPACITY];
    _Atomic(int)  head;
    int           tail;
    _Atomic(int)  dropped;
} LogRingBuffer;

static LogRingBuffer g_log_ring;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t     g_log_sender_tid;
static int           g_log_event_fd = -1;

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
    char merged[LOG_MSG_MAX_LEN];
    if (n >= sizeof(merged)) n = sizeof(merged) - 1;
    memcpy(merged, g_log_batch_buf, n);
    merged[n] = '\0';
    g_log_batch_len = 0;
    pthread_mutex_unlock(&g_log_batch_mutex);
    if (n == 0 || !g_log_inited) return;
    /* 合并为单条写入环形缓冲（带 LOG_MERGED_MARK 前缀）：sender 据此以
       LOG_BATCH 分帧协议发送，log_monitor 整块接收合并为一条入库，
       前端只显示一条（多个发送请求并入一个日志）。
       单行输出：[proc] <条目1>\t<条目2>...
       （条目间以制表符连接，不用换行，避免前端按行拆分导致截断/乱码） */
    pthread_mutex_lock(&g_log_mutex);
    int slot = atomic_fetch_add_explicit(&g_log_ring.head, 1, memory_order_relaxed) & LOG_BUF_MASK;
    snprintf(g_log_ring.entries[slot].msg, LOG_MSG_MAX_LEN,
             LOG_MERGED_MARK "[%s] %s", g_proc_name, merged);
    g_log_ring.entries[slot].level = LOG_DEBUG;   /* 合并日志归为 debug 级别，
                                                     --level >=1 查询时不显示 */
    pthread_mutex_unlock(&g_log_mutex);
    uint64_t val = 1;
    if (g_log_event_fd >= 0) write(g_log_event_fd, &val, sizeof(val));
}
/* 子进程日志转发 fd：run_in_mnt_ns_* fork 的子进程内 sender 线程不可达，
   子进程经此管道回传日志，父进程读取后统一写入环形缓冲（默认 -1=未启用） */
int g_log_forward_fd = -1;
_Atomic(bool) g_log_shutdown = false;
void init_timezone() {
    const char *tz = getenv("TZ");
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
    FILE *fp = fopen("/data/property/persist.sys.timezone", "re");
#else
    FILE *fp = fopen("/etc/timezone", "re");
#endif
    if (fp) {
        if (fgets(prop_buf, sizeof(prop_buf), fp)) {
            size_t plen = strlen(prop_buf);
            while (plen > 0 && (prop_buf[plen-1] == '\n' || prop_buf[plen-1] == '\r')) prop_buf[--plen] = '\0';
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
    int pid = getpid(); char pid_s[32]; snprintf(pid_s, sizeof(pid_s), "%d", pid);
    const char* targets[] = {
        "/sys/fs/cgroup/cgroup.procs", // v2
        "/dev/cpuctl/tasks",           // v1 cpu
        "/dev/cpuset/tasks",           // v1 cpuset
        "/dev/stune/tasks"             // v1 stune
    };
    for (int i = 0; i < 4; i++) {
        int fd = open(targets[i], O_WRONLY | O_CLOEXEC);
        if (fd >= 0) {
            /* 静默吞掉写入失败：cgroup 路径在不同 Android 版本与配置下可能不存在或无写权限 */
            if (write(fd, pid_s, strlen(pid_s)) < 0) {
                LOG_DBG("escape_cgroup: 写入 %s 失败: %s", targets[i], strerror(errno));
            }
            close(fd);
        }
    }
}
/* 抽取的 IPC 连接 helper：send_ipc_message / query_ipc_message 共用，
   统一 500ms 收发超时与 abstract namespace 绑定逻辑 */
static int connect_ipc() {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock_fd < 0) return -1;
    struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
    setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_un server_addr = {0};
    server_addr.sun_family = AF_UNIX;
    server_addr.sun_path[0] = '\0';
    strncpy(server_addr.sun_path + 1, IPC_SOCKET_NAME, sizeof(server_addr.sun_path) - 2);
    socklen_t len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(IPC_SOCKET_NAME);
    if (connect(sock_fd, (struct sockaddr*)&server_addr, len) < 0) {
        close(sock_fd); return -1;
    }
    return sock_fd;
}
int send_ipc_message(const char* message) {
    int sock_fd = connect_ipc();
    if (sock_fd < 0) return -1;
    send(sock_fd, message, strlen(message), MSG_NOSIGNAL);
    close(sock_fd);
    return 0;
}
int query_ipc_message(const char* command, char* out_buf, size_t buf_size) {
    int sock_fd = connect_ipc();
    if (sock_fd < 0) return -1;
    send(sock_fd, command, strlen(command), MSG_NOSIGNAL);
    shutdown(sock_fd, SHUT_WR);
    ssize_t total = 0;
    ssize_t n;
    while (buf_size > 0 && (n = read(sock_fd, out_buf, buf_size)) > 0) {
        out_buf += n;
        buf_size -= n;
        total += n;
    }
    close(sock_fd);
    return (int)total;
}
void set_self_dir(const char* path) { if (path && *path) strncpy(g_self_dir, path, sizeof(g_self_dir) - 1); }
char* get_self_dir() {
    if (g_self_dir[0] != 0) return g_self_dir;
    char buf[PATH_MAX]; ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0'; char* last_slash = strrchr(buf, '/');
        if (last_slash) *last_slash = '\0';
        strncpy(g_self_dir, buf, sizeof(g_self_dir) - 1);
    } else { strncpy(g_self_dir, "/data/local/tmp", sizeof(g_self_dir) - 1); g_self_dir[sizeof(g_self_dir) - 1] = '\0'; }
    return g_self_dir;
}
int mkdir_recursive(const char *dir) {
    if (!dir) return -1;
    size_t in_len = strlen(dir);
    if (in_len == 0 || in_len >= 256) return -1;   /* 拒绝空与超长输入，杜绝 snprintf 静默截断 */
    char tmp[256], *p = nullptr; snprintf(tmp, sizeof(tmp), "%s", dir);
    size_t len = strlen(tmp); if (tmp[len - 1] == '/') tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (access(tmp, F_OK) != 0 && mkdir(tmp, 0755) != 0) {
                *p = '/';
                return -1;
            }
            *p = '/';
        }
    }
    if (access(tmp, F_OK) != 0 && mkdir(tmp, 0755) != 0) return -1;
    return 0;
}

/* 递归创建目录（带父目录属性继承，原 config_parser.c 提供，迁至公共工具） */
static void sync_attributes(const char* source_parent, const char* target_path) {
    struct stat st;
    if (lstat(source_parent, &st) != 0) return;
    if (lchown(target_path, st.st_uid, st.st_gid) != 0) {}
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
    char parent[PATH_MAX]; strncpy(parent, real_path, PATH_MAX - 1);
    char* last = strrchr(parent, '/');
    if (last) {
        if (last == parent) strcpy(parent, "/");
        else *last = '\0';
        sync_attributes(parent, real_path);
    }
}

int mkdir_recursive_p(const char *path, mode_t mode) {
    if (!path || !path[0]) return -1;
    char tmp[PATH_MAX]; snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp); if (tmp[len - 1] == '/') tmp[len - 1] = 0;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (access(tmp, F_OK) != 0) {
                if (mkdir(tmp, mode) == 0) inherit_from_parent(tmp);
                else if (errno != EEXIST) return -1;
            }
            *p = '/';
        }
    }
    if (access(tmp, F_OK) != 0) {
        if (mkdir(tmp, mode) == 0) inherit_from_parent(tmp);
        else if (errno != EEXIST) return -1;
    }
    return 0;
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
    if (!path) { out[0] = '\0'; return; }
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
/* 日志条目 → 发送包格式（主 drain 与关闭 drain 共用，保证分帧协议一致）：
   - 合并单条（LOG_MERGED_MARK 前缀）：以 LOG_BATCH 分帧发送（头+内容+尾），
     log_monitor 整块接收合并为一条入库，前端只显示一条
   - 普通条目：LOG_IO:/LOG_LOGCAT:/LOG_SYS:<level>:[proc] 前缀 */
static int log_entry_packet(const LogEntry* e, char* packet, size_t sz) {
    if (strncmp(e->msg, LOG_MERGED_MARK, sizeof(LOG_MERGED_MARK) - 1) == 0) {
        const char* content = e->msg + sizeof(LOG_MERGED_MARK) - 1;
        return snprintf(packet, sz, "LOG_BATCH\n%s\nLOG_BATCH_END\n", content);
    }
    if (e->level == LOG_IO)
        return snprintf(packet, sz, "LOG_IO:%s\n", e->msg);
    if (e->level == LOG_LOGCAT)
        return snprintf(packet, sz, "LOG_LOGCAT:%s\n", e->msg);
    return snprintf(packet, sz, "LOG_SYS:%d:[%s] %s\n",
                    e->level, g_proc_name, e->msg);
}

static void *log_sender_thread(void *arg) {
    (void)arg;
    int sock = -1;
    struct timespec retry_after = {0, 0};

    while (!atomic_load_explicit(&g_log_shutdown, memory_order_relaxed)) {
        if (sock < 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > retry_after.tv_sec ||
                (now.tv_sec == retry_after.tv_sec && now.tv_nsec >= retry_after.tv_nsec)) {
                sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
                if (sock >= 0) {
                    struct sockaddr_un addr = { .sun_family = AF_UNIX };
                    strncpy(addr.sun_path + 1, LOG_SOCKET_NAME, sizeof(addr.sun_path) - 2);
                    socklen_t len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(LOG_SOCKET_NAME);
                    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
                    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                    if (connect(sock, (struct sockaddr*)&addr, len) < 0) {
                        close(sock); sock = -1;
                        clock_gettime(CLOCK_MONOTONIC, &retry_after);
                        retry_after.tv_nsec += 100000000;
                        if (retry_after.tv_nsec >= 1000000000) {
                            retry_after.tv_sec++;
                            retry_after.tv_nsec -= 1000000000;
                        }
                    }
                }
            }
        }

        int consumed = 0;
        while (g_log_ring.tail != atomic_load_explicit(&g_log_ring.head, memory_order_acquire)) {
            if (sock < 0) break;  /* 未连接：保留 ring 数据等待重连，避免丢弃式消耗（tail++/consumed++）导致空转 */
            /* 持锁读取并打包：与 log_internal 的写入互斥，杜绝 sender 读到撕裂的半写字符串 */
            pthread_mutex_lock(&g_log_mutex);
            LogEntry *e = &g_log_ring.entries[g_log_ring.tail & LOG_BUF_MASK];
            char packet[LOG_MSG_MAX_LEN * 2 + 128];
            int len = log_entry_packet(e, packet, sizeof(packet));
            pthread_mutex_unlock(&g_log_mutex);
            ssize_t sent = send(sock, packet, len, MSG_NOSIGNAL);
            if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                close(sock); sock = -1;
                clock_gettime(CLOCK_MONOTONIC, &retry_after);
                retry_after.tv_nsec += 100000000;
                if (retry_after.tv_nsec >= 1000000000) {
                    retry_after.tv_sec++;
                    retry_after.tv_nsec -= 1000000000;
                }
                break;
            }
            if (sent < 0) break;
            g_log_ring.tail++;
            consumed++;
        }

        if (!consumed) {
            /* sock 未就绪且 ring 非空时也等待 retry_after，避免紧密空转；
               ring 为空时靠 eventfd 唤醒，sock 未就绪时靠 retry_after 节流重连 */
            struct pollfd pfd = { .fd = g_log_event_fd, .events = POLLIN };
            int poll_ms = 100;
            if (sock < 0) {
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                int retry_ms = (int)(retry_after.tv_sec - now.tv_sec) * 1000
                            + (int)(retry_after.tv_nsec - now.tv_nsec) / 1000000;
                if (retry_ms > 0 && retry_ms < poll_ms) poll_ms = retry_ms;
            }
            poll(&pfd, 1, poll_ms);
            /* eventfd 为非 semaphore 模式：计数器只能靠 read 清零。poll 返回后必须读空，
               否则计数器永久 ≥1 → POLLIN 永久就绪 → poll 立即返回形成紧密空转（100% 单核） */
            if (pfd.revents & POLLIN) {
                uint64_t val;
                while (read(g_log_event_fd, &val, sizeof(val)) > 0) { }
            }
        }
    }

    while (g_log_ring.tail != atomic_load_explicit(&g_log_ring.head, memory_order_acquire)) {
        pthread_mutex_lock(&g_log_mutex);
        LogEntry *e = &g_log_ring.entries[g_log_ring.tail & LOG_BUF_MASK];
        char packet[LOG_MSG_MAX_LEN * 2 + 128];
        int len = log_entry_packet(e, packet, sizeof(packet));
        pthread_mutex_unlock(&g_log_mutex);
        if (sock >= 0) send(sock, packet, len, MSG_NOSIGNAL);
        g_log_ring.tail++;
    }
    if (sock >= 0) close(sock);
    return NULL;
}

void log_init(const char* process_name) {
    init_timezone();
    strncpy(g_proc_name, process_name, sizeof(g_proc_name) - 1);
    mkdir_recursive(LOG_DIR);
    atomic_store_explicit(&g_log_ring.head, 0, memory_order_relaxed);
    g_log_ring.tail = 0;
    atomic_store_explicit(&g_log_ring.dropped, 0, memory_order_relaxed);
    atomic_store_explicit(&g_log_shutdown, false, memory_order_relaxed);
    g_log_event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (g_log_event_fd < 0) {
        /* eventfd 失败：日志子系统降级为仅落盘模式，不派 sender 线程 */
        LOG_ERR("log_init: eventfd 创建失败: %s", strerror(errno));
        g_log_inited = false;
        return;
    }
    if (pthread_create(&g_log_sender_tid, NULL, log_sender_thread, NULL) != 0) {
        /* sender 线程派失败：日志将堆积于 ring buffer 但永不被发送，
           关闭 eventfd 避免后续无效写入 */
        LOG_ERR("log_init: sender 线程创建失败: %s", strerror(errno));
        close(g_log_event_fd);
        g_log_event_fd = -1;
        g_log_inited = false;
        return;
    }
    g_log_inited = true;
}

void log_close() {
    if (!g_log_inited) return;
    atomic_store_explicit(&g_log_shutdown, true, memory_order_release);
    uint64_t val = 1;
    if (g_log_event_fd >= 0) write(g_log_event_fd, &val, sizeof(val));
    pthread_join(g_log_sender_tid, NULL);
    if (g_log_event_fd >= 0) { close(g_log_event_fd); g_log_event_fd = -1; }
    g_log_inited = false;
}

void log_internal(LogLevel level, const char* format, ...) {
    if (level < g_min_log_level && level != LOG_DEBUG) return;
    char msg_buf[LOG_MSG_MAX_LEN];
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
        char fwd_buf[LOG_MSG_MAX_LEN + 96];
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
        if (level == LOG_LOGCAT) persist_log_to_disk("logcat", msg_buf, true);
        else persist_log_to_disk("sys", msg_buf, true);
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
                         sizeof(g_log_batch_buf) - g_log_batch_len,
                         "%s\t", msg_buf);
        if (w > 0 && g_log_batch_len + (size_t)w < sizeof(g_log_batch_buf))
            g_log_batch_len += (size_t)w;
        pthread_mutex_unlock(&g_log_batch_mutex);
        return;
    }
    pthread_mutex_lock(&g_log_mutex);
    int slot = atomic_fetch_add_explicit(&g_log_ring.head, 1, memory_order_relaxed) & LOG_BUF_MASK;
    strncpy(g_log_ring.entries[slot].msg, msg_buf, LOG_MSG_MAX_LEN - 1);
    g_log_ring.entries[slot].msg[LOG_MSG_MAX_LEN - 1] = '\0';
    g_log_ring.entries[slot].level = level;
    pthread_mutex_unlock(&g_log_mutex);
    uint64_t val = 1;
    if (g_log_event_fd >= 0) write(g_log_event_fd, &val, sizeof(val));
}

bool is_media_provider(const char* pkg) {
    return (strstr(pkg, "com.android.providers.media") != nullptr);
}
