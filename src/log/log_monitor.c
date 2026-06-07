#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>
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
#include <fnmatch.h>

#include "common.h"

#define MAX_MSG_LEN 512
#define MAX_IO_LOGS 262144 
#define MAX_SYS_LOGS 50000  
#define MAX_LOGCAT_LOGS 100000
#define DEFAULT_LIMIT 500
#define MAX_EVENTS 256

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
    pthread_mutex_t lock; 
} LogBuffer;

typedef struct StreamClient {
    int fd;
    int type;       /* 0=ALL, 1=IO, 2=SYS, 3=LOGCAT */
    int min_level;  /* 最低日志级别过滤，仅 >= 此级别的日志会推送 */
    struct StreamClient *next;
} StreamClient;

static LogBuffer g_io_buf, g_sys_buf, g_logcat_buf;
static volatile sig_atomic_t g_should_exit = 0;
static int g_server_sock = -1;

static IgnoreRule *g_ignore_rules = nullptr;
static pthread_rwlock_t g_rules_lock = PTHREAD_RWLOCK_INITIALIZER;

static StreamClient *g_stream_clients = nullptr;
static pthread_mutex_t g_stream_lock = PTHREAD_MUTEX_INITIALIZER;

static ClientCtx *g_active_clients = nullptr;

static int g_epoll_fd = -1;

static void init_buf(LogBuffer* buf, int max) {
    buf->data = calloc(max, sizeof(LogEntry));
    buf->head = buf->tail = 0; 
    buf->full = false;
    buf->max = max;
    pthread_mutex_init(&buf->lock, nullptr);
}

static void destroy_buf(LogBuffer* buf) {
    if (buf->data) { free(buf->data); buf->data = nullptr; }
}

static void add_stream_client(int fd, int type, int min_level) {
    pthread_mutex_lock(&g_stream_lock);
    StreamClient *c = malloc(sizeof(StreamClient));
    c->fd = fd; c->type = type; c->min_level = min_level; c->next = g_stream_clients; g_stream_clients = c;
    pthread_mutex_unlock(&g_stream_lock);
}

static void remove_stream_client(int fd) {
    pthread_mutex_lock(&g_stream_lock);
    StreamClient **pp = &g_stream_clients;
    while (*pp) {
        if ((*pp)->fd == fd) {
            StreamClient *tmp = *pp; *pp = (*pp)->next; free(tmp); break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&g_stream_lock);
}

static void broadcast_log(int type, const char *line, int level) {
    pthread_mutex_lock(&g_stream_lock);
    StreamClient *c = g_stream_clients;
    while (c) {
        if (c->fd > 0 && (c->type == 0 || c->type == type)) {
            if (level >= c->min_level) {
                ssize_t ret = send(c->fd, line, strlen(line), MSG_NOSIGNAL | MSG_DONTWAIT);
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
    pthread_mutex_unlock(&g_stream_lock);
}

static void push_log(LogBuffer* buf, const char* msg, int type, int level) {
    broadcast_log(type, msg, level);
    pthread_mutex_lock(&buf->lock);
    buf->data[buf->head].t = time(nullptr);
    buf->data[buf->head].level = level;
    strncpy(buf->data[buf->head].msg, msg, MAX_MSG_LEN - 1);
    buf->head = (buf->head + 1) % buf->max;
    if (buf->full) buf->tail = (buf->tail + 1) % buf->max;
    else if (buf->head == buf->tail) buf->full = true;
    pthread_mutex_unlock(&buf->lock);
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
    pthread_rwlock_wrlock(&g_rules_lock);
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
                    *close_ptr = '\0'; char *ops = p+1; char *token = strtok(ops, ",");
                    while (token) { int op = parse_op_string(token); if (op) op_mask |= op; token = strtok(nullptr, ","); }
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
    pthread_rwlock_unlock(&g_rules_lock);
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
    pthread_rwlock_rdlock(&g_rules_lock);
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
    pthread_rwlock_unlock(&g_rules_lock);
    return ignore;
}

static void search_log_paged(int fd, LogBuffer* buf, const char* key, int limit, int offset, int level_filter) {
    pthread_mutex_lock(&buf->lock);
    int total_in_buf = buf->full ? buf->max : (buf->head - buf->tail + buf->max) % buf->max;
    int total_matched = 0; int idx = buf->tail;
    for (int i = 0; i < total_in_buf; i++) {
        bool level_match = (level_filter < 0 || buf->data[idx].level == level_filter);
        if (level_match && (!key || key[0] == '\0' || strstr(buf->data[idx].msg, key))) total_matched++;
        idx = (idx + 1) % buf->max;
    }
    int sent_count = 0; int skip_count = 0;
    idx = (buf->head - 1 + buf->max) % buf->max;
    char line[MAX_MSG_LEN + 128];
    for (int i = 0; i < total_in_buf && sent_count < limit; i++) {
        bool level_match = (level_filter < 0 || buf->data[idx].level == level_filter);
        if (level_match && (!key || key[0] == '\0' || strstr(buf->data[idx].msg, key))) {
            if (skip_count < offset) skip_count++;
            else {
                struct tm tm_info; localtime_r(&buf->data[idx].t, &tm_info);
                char time_buf[32]; strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
                int len = snprintf(line, sizeof(line), "%s|%s\n", time_buf, buf->data[idx].msg);
                write(fd, line, len); sent_count++;
            }
        }
        idx = (idx - 1 + buf->max) % buf->max;
    }
    int remaining = total_matched - (offset + sent_count);
    if (remaining < 0) remaining = 0;
    snprintf(line, sizeof(line), "DONE|%d|%d\n", total_matched, remaining);
    write(fd, line, strlen(line));
    pthread_mutex_unlock(&buf->lock);
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

static int process_line(ClientCtx* ctx, char* line) {
    int fd = ctx->fd;
    if (strncmp(line, "LOG_IO:", 7) == 0) {
        ctx->is_streaming = true; 
        if (should_ignore_io(line + 7)) return 0;
        push_log(&g_io_buf, line + 7, 1, LOG_INFO);
        return 0;
    } else if (strncmp(line, "LOG_SYS:", 8) == 0) {
        ctx->is_streaming = true; 
        char *msg = line + 8;
        int level = LOG_INFO;
        if (*msg >= '0' && *msg <= '9') {
            level = atoi(msg);
            char *colon = strchr(msg, ':');
            if (colon) msg = colon + 1;
        }
        push_log(&g_sys_buf, msg, 2, level);
        return 0;
    } else if (strncmp(line, "LOG_LOGCAT:", 11) == 0) {
        ctx->is_streaming = true; 
        push_log(&g_logcat_buf, line + 11, 3, LOG_INFO);
        return 0;
    } else if (strncmp(line, "QUERY_IO:", 9) == 0 || strncmp(line, "QUERY_SYS:", 10) == 0 ||
               strncmp(line, "QUERY_LOGCAT:", 13) == 0) {
        bool is_io = (strstr(line, "IO") != nullptr);
        bool is_logcat = (strstr(line, "LOGCAT") != nullptr);
        /* 新格式: {level}:{key}:{limit}:{offset} — level 移到最前面，避免 key 被误识别 */
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
        search_log_paged(fd, is_io ? &g_io_buf : (is_logcat ? &g_logcat_buf : &g_sys_buf), key, limit, offset, level_filter);
        return 1; 
    } else if (strcmp(line, "CLEAR_IO") == 0) {
        pthread_mutex_lock(&g_io_buf.lock); g_io_buf.head = g_io_buf.tail = 0; g_io_buf.full = false;
        pthread_mutex_unlock(&g_io_buf.lock);
        write(fd, "OK\n", 3); 
        return 1; 
    } else if (strcmp(line, "CLEAR_SYS") == 0) {
        pthread_mutex_lock(&g_sys_buf.lock); g_sys_buf.head = g_sys_buf.tail = 0; g_sys_buf.full = false;
        pthread_mutex_unlock(&g_sys_buf.lock);
        write(fd, "OK\n", 3); 
        return 1; 
    } else if (strcmp(line, "CLEAR_LOGCAT") == 0) {
        pthread_mutex_lock(&g_logcat_buf.lock); g_logcat_buf.head = g_logcat_buf.tail = 0; g_logcat_buf.full = false;
        pthread_mutex_unlock(&g_logcat_buf.lock);
        write(fd, "OK\n", 3); 
        return 1; 
    } else if (strncmp(line, "STREAM_IO", 9) == 0) {
        int min_level = 0;
        if (line[9] == ':') min_level = atoi(line + 10);
        add_stream_client(fd, 1, min_level);
        ctx->is_streaming = true;
        write(fd, "OK\n", 3);
        return 0;
    } else if (strncmp(line, "STREAM_SYS", 10) == 0) {
        int min_level = 0;
        if (line[10] == ':') min_level = atoi(line + 11);
        add_stream_client(fd, 2, min_level);
        ctx->is_streaming = true;
        write(fd, "OK\n", 3);
        return 0;
    } else if (strncmp(line, "STREAM_LOGCAT", 13) == 0) {
        int min_level = 0;
        if (line[13] == ':') min_level = atoi(line + 14);
        add_stream_client(fd, 3, min_level);
        ctx->is_streaming = true;
        write(fd, "OK\n", 3);
        return 0;
    } else if (strncmp(line, "STREAM_ALL", 10) == 0) {
        int min_level = 0;
        if (line[10] == ':') min_level = atoi(line + 11);
        add_stream_client(fd, 0, min_level);
        ctx->is_streaming = true;
        write(fd, "OK\n", 3);
        return 0;
    } else if (strncmp(line, "STOP_STREAM", 11) == 0) {
        remove_stream_client(fd); 
        ctx->is_streaming = false;
        write(fd, "OK\n", 3); 
        return 1; 
    }
    return 0; 
}

static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void handle_signal(int sig) { if (sig == SIGINT || sig == SIGTERM) g_should_exit = 1; }

int main(int argc, char *argv[]) {
    escape_cgroup();
    extern void init_timezone();
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
    if (g_persist_all_logs) mkdir("/data/Namespace-Proxy/log", 0755);
    load_ignore_rules();
    g_server_sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int optval = 1; setsockopt(g_server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LOG_TCP_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(g_server_sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(g_server_sock, 128);
    g_epoll_fd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN; ev.data.fd = g_server_sock; epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_server_sock, &ev);
    int inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd >= 0) {
        inotify_add_watch(inotify_fd, CONFIG_DIR, IN_MODIFY | IN_MOVED_TO | IN_CREATE | IN_CLOSE_WRITE | IN_DELETE);
        ev.events = EPOLLIN; ev.data.fd = inotify_fd; epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, inotify_fd, &ev);
    }
    while (!g_should_exit) {
        int nfds = epoll_wait(g_epoll_fd, events, MAX_EVENTS, 100);
        
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
                    remove_stream_client(curr_chk->fd);
                    remove_active_client(curr_chk);
                    free(curr_chk);
                }
            }
            curr_chk = next_chk;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == g_server_sock) {
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
            } else if (inotify_fd >= 0 && events[i].data.fd == inotify_fd) {
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
                                    if (process_line(ctx, ctx->line)) { consumed = true; break; }
                                }
                                ctx->pos = 0;
                            } else if (ctx->pos < sizeof(ctx->line) - 1) ctx->line[ctx->pos++] = buf[j];
                        }
                    } else if (n == -1 && errno == EAGAIN) break;
                    else { consumed = true; break; }
                }
                if (consumed) {
                    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, ctx->fd, nullptr);
                    close(ctx->fd); 
                    remove_stream_client(ctx->fd); 
                    remove_active_client(ctx);
                    free(ctx);
                }
            }
        }
    }
    close(g_server_sock); if (inotify_fd >= 0) close(inotify_fd); close(g_epoll_fd);
    
    ClientCtx* curr_free = g_active_clients;
    while (curr_free) {
        ClientCtx* next_free = curr_free->next;
        close(curr_free->fd);
        free(curr_free);
        curr_free = next_free;
    }
    g_active_clients = nullptr;

    destroy_buf(&g_io_buf); destroy_buf(&g_sys_buf); destroy_buf(&g_logcat_buf);
    return 0;
}