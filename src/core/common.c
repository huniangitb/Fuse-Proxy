#include "common.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/system_properties.h>

#define FALLBACK_ERR_LOG ERROR_LOG_PATH

LogLevel g_min_log_level = LOG_INFO;
char g_real_root[PATH_MAX] = {0};
bool g_persist_all_logs = false;
bool g_strip_o_direct = false;  
static char g_self_dir[PATH_MAX] = {0};
static char g_proc_name[64] = "unknown"; 
static bool g_log_inited = false;

static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER; 
static pthread_mutex_t g_persist_mutex = PTHREAD_MUTEX_INITIALIZER; 
static int g_log_sock = -1; 

void init_timezone() {
    const char *tz = getenv("TZ");
    if (tz && tz[0] != '\0') {
        tzset();
        return;
    }
    char prop_buf[PROP_VALUE_MAX];
    int len = __system_property_get("persist.sys.timezone", prop_buf);
    if (len > 0) {
        setenv("TZ", prop_buf, 1);
        tzset();
        return;
    }
    FILE *fp = fopen("/data/property/persist.sys.timezone", "re");
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
        if (fd >= 0) { write(fd, pid_s, strlen(pid_s)); close(fd); }
    }
}

int send_ipc_message(const char* message) {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock_fd < 0) return -1;

    // 健壮性保障：设置严格的 500ms 超时，防止死锁的 FUSE / 注入器导致此接口挂死
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
    send(sock_fd, message, strlen(message), MSG_NOSIGNAL);
    close(sock_fd);
    return 0;
}

int query_ipc_message(const char* command, char* out_buf, size_t buf_size) {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock_fd < 0) return -1;

    // 健壮性保障：超时设定不高于 0.5 秒
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
    } else strcpy(g_self_dir, "/data/local/tmp");
    return g_self_dir;
}

int mkdir_recursive(const char *dir) {
    char tmp[256], *p = nullptr; snprintf(tmp, sizeof(tmp), "%s", dir);
    size_t len = strlen(tmp); if (tmp[len - 1] == '/') tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0; if (access(tmp, F_OK) != 0) mkdir(tmp, 0755);
            *p = '/';
        }
    }
    if (access(tmp, F_OK) != 0) mkdir(tmp, 0755);
    return 0;
}

bool path_contains_invalid_chars(const char* path) {
    const unsigned char* p = (const unsigned char*)path;
    while (*p) {
        if (*p < 0x08) return true;              
        if (*p > 0x09 && *p < 0x20) return true; 
        if (*p == 0x7F) return true;             

        // 检查 2 字节序列: C2 A0 或 C2 AD
        if (p[0] == 0xC2 && p[1] >= 0xA0 && p[1] <= 0xAD) {
            if (p[1] == 0xA0 || p[1] == 0xAD) return true;
        }

        // 检查 3 字节序列: E2 80 80-8A, etc.
        if (p[0] == 0xE2 && p[1] == 0x80 && p[2] >= 0x80 && p[2] <= 0xAF) return true;
        if (p[0] == 0xE2 && p[1] == 0x81 && p[2] >= 0xA0 && p[2] <= 0xAF) return true;
        if (p[0] == 0xE1 && p[1] == 0xA0 && p[2] == 0x8E) return true;
        if (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) return true;

        // 检查 4 字节序列: F3 A0 80 80-BF, etc.
        if (p[0] == 0xF3 && p[1] == 0xA0 && p[2] == 0x80 && p[3] >= 0x80 && p[3] <= 0xBF) return true;
        if (p[0] == 0xF3 && p[1] == 0xA0 && p[2] == 0x81 && p[3] >= 0x80 && p[3] <= 0xAF) return true;

        p++;
    }
    return false;
}

void path_sanitize(char* out, size_t size, const char* path) {
    if (!out || size == 0 || !path) return;
    const unsigned char* p = (const unsigned char*)path;
    size_t o = 0;
    size_t max = size - 1;

    while (*p && o < max) {
        int skip_bytes = 0;
        bool matched = false;

        if (*p < 0x08) { matched = true; skip_bytes = 1; }
        else if (*p > 0x09 && *p < 0x20) { matched = true; skip_bytes = 1; }
        else if (*p == 0x7F) { matched = true; skip_bytes = 1; }
        else if (p[0] == 0xC2 && (p[1] == 0xA0 || p[1] == 0xAD)) { matched = true; skip_bytes = 2; }
        else if (p[0] == 0xE2 && p[1] == 0x80 && p[2] >= 0x80 && p[2] <= 0xAF) { matched = true; skip_bytes = 3; }
        else if (p[0] == 0xE2 && p[1] == 0x81 && p[2] >= 0xA0 && p[2] <= 0xAF) { matched = true; skip_bytes = 3; }
        else if (p[0] == 0xE1 && p[1] == 0xA0 && p[2] == 0x8E) { matched = true; skip_bytes = 3; }
        else if (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) { matched = true; skip_bytes = 3; }
        else if (p[0] == 0xF3 && p[1] == 0xA0 && p[2] == 0x80 && p[3] >= 0x80 && p[3] <= 0xBF) { matched = true; skip_bytes = 4; }
        else if (p[0] == 0xF3 && p[1] == 0xA0 && p[2] == 0x81 && p[3] >= 0x80 && p[3] <= 0xAF) { matched = true; skip_bytes = 4; }

        if (matched) {
            p += skip_bytes;
        } else {
            out[o++] = *p;
            p++;
        }
    }
    out[o] = '\0';
}

void log_init(const char* process_name) {
    init_timezone();
    pthread_mutex_lock(&g_log_mutex);
    strncpy(g_proc_name, process_name, sizeof(g_proc_name) - 1);
    mkdir_recursive(LOG_DIR);
    g_log_inited = true;
    pthread_mutex_unlock(&g_log_mutex);
}

void log_close() {
    pthread_mutex_lock(&g_log_mutex);
    if (!g_log_inited) { 
        pthread_mutex_unlock(&g_log_mutex); 
        return; 
    }
    if (g_log_sock >= 0) { close(g_log_sock); g_log_sock = -1; }
    g_log_inited = false;
    pthread_mutex_unlock(&g_log_mutex);
}

void log_internal(LogLevel level, const char* format, ...) {
    if (level < g_min_log_level && level < LOG_MONITOR) return;
    
    char msg_buf[1024]; 
    va_list args; 
    va_start(args, format);
    vsnprintf(msg_buf, sizeof(msg_buf), format, args); 
    va_end(args);

    size_t mlen = strlen(msg_buf);
    while (mlen > 0 && (msg_buf[mlen - 1] == '\n' || msg_buf[mlen - 1] == '\r')) {
        msg_buf[--mlen] = '\0';
    }

    if (g_persist_all_logs) {
        if (level == LOG_LOGCAT) persist_log_to_disk("logcat", msg_buf, true);
        else if (level == LOG_IO) persist_log_to_disk("io", msg_buf, true);
        else persist_log_to_disk("sys", msg_buf, true);
    }

    if (pthread_mutex_trylock(&g_log_mutex) != 0) return;
    if (!g_log_inited) {
        pthread_mutex_unlock(&g_log_mutex);
        return;
    }
    
    if (g_log_sock < 0) {
        g_log_sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (g_log_sock >= 0) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(LOG_TCP_PORT);
            inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
            
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 20000; 
            setsockopt(g_log_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            
            if (connect(g_log_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                close(g_log_sock);
                g_log_sock = -1;
            } else {
                int flags = fcntl(g_log_sock, F_GETFL, 0);
                fcntl(g_log_sock, F_SETFL, flags | O_NONBLOCK);
            }
        }
    }
    
    if (g_log_sock >= 0) {
        char packet[1280];
        int len = 0;
        
        if (level == LOG_IO) {
            len = snprintf(packet, sizeof(packet), "LOG_IO:%s\n", msg_buf);
        } else if (level == LOG_LOGCAT) {
            len = snprintf(packet, sizeof(packet), "LOG_LOGCAT:%s\n", msg_buf);
        } else {
            len = snprintf(packet, sizeof(packet), "LOG_SYS:%d:[%s] %s\n", level, g_proc_name, msg_buf);
        }
        
        if (send(g_log_sock, packet, len, MSG_NOSIGNAL | MSG_DONTWAIT) < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINPROGRESS) {
                close(g_log_sock); g_log_sock = -1;
            }
        }
    }
    pthread_mutex_unlock(&g_log_mutex);
}