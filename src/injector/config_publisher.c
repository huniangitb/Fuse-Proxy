#define _GNU_SOURCE
#include "config_publisher.h"
#include "common.h"
#include "injector.h"
#include "config_parser.h"
#include "inject_target.h"
#include "uid_map.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#define PUBSUB_SOCKET_NAME    CONFIG_BROADCAST_SOCKET
#define MAX_SUBSCRIBERS       32
#define MAX_SNAPSHOT_APPS     256
#define MAX_SNAPSHOT_UIDMAP   1024
struct Subscriber {
    struct sockaddr_un addr;
    socklen_t addr_len;
    bool active;
};
static struct Subscriber g_subscribers[MAX_SUBSCRIBERS];
static int g_subscriber_count = 0;
typedef struct {
    char *buf;
    int len;
    int capacity;
} JsonBuf;
static void json_init(JsonBuf *jb, int initial_capacity) {
    jb->capacity = initial_capacity > 0 ? initial_capacity : 4096;
    jb->buf = malloc(jb->capacity);
    jb->len = 0;
    if (jb->buf) {
        jb->buf[0] = '\0';
    }
}
static void json_ensure_capacity(JsonBuf *jb, int need) {
    if (!jb->buf) return;
    /* 核心修复：确保判定中包含 + 1 的 Null 终止哨兵安全冗余。
     * 即使 need 的字节刚好填满可用空间，也仍有一字节的空闲存放末尾的 '\0'。 */
    if (jb->len + need + 1 > jb->capacity) {
        int new_capacity = jb->capacity * 2;
        while (new_capacity < jb->len + need + 1) {
            new_capacity *= 2;
        }
        char *new_buf = realloc(jb->buf, new_capacity);
        if (!new_buf) {
            return; 
        }
        jb->buf = new_buf;
        jb->capacity = new_capacity;
    }
}
__attribute__((format(printf, 2, 3)))
static void json_append(JsonBuf *jb, const char *fmt, ...) {
    if (!jb->buf) return;
    va_list ap;
    va_start(ap, fmt);
    va_list ap_copy;
    va_copy(ap_copy, ap);
    int remaining = jb->capacity - jb->len;
    int n = vsnprintf(jb->buf + jb->len, remaining, fmt, ap_copy);
    va_end(ap_copy);
    if (n >= remaining) {
        int new_capacity = jb->capacity * 2;
        while (new_capacity < jb->len + n + 1) {
            new_capacity *= 2;
        }
        char *new_buf = realloc(jb->buf, new_capacity);
        if (!new_buf) {
            va_end(ap);
            return; 
        }
        jb->buf = new_buf;
        jb->capacity = new_capacity;
        remaining = jb->capacity - jb->len;
        vsnprintf(jb->buf + jb->len, remaining, fmt, ap);
    }
    va_end(ap);
    if (n > 0) {
        jb->len += n;
    }
}
static void json_escape(JsonBuf *jb, const char *str, bool quoted) {
    if (!str) {
        json_append(jb, "null");
        return;
    }
    if (quoted) {
        json_ensure_capacity(jb, 1);
        jb->buf[jb->len++] = '"';
    }
    for (const char *p = str; *p; p++) {
        unsigned char c = (unsigned char)*p;
        json_ensure_capacity(jb, 6);
        switch (c) {
            case '"':  
                jb->buf[jb->len++] = '\\';
                jb->buf[jb->len++] = '"';
                break;
            case '\\': 
                jb->buf[jb->len++] = '\\';
                jb->buf[jb->len++] = '\\';
                break;
            case '\n': 
                jb->buf[jb->len++] = '\\';
                jb->buf[jb->len++] = 'n';
                break;
            case '\r': 
                jb->buf[jb->len++] = '\\';
                jb->buf[jb->len++] = 'r';
                break;
            case '\t': 
                jb->buf[jb->len++] = '\\';
                jb->buf[jb->len++] = 't';
                break;
            default:
                if (c < 0x20) {
                    int n = snprintf(jb->buf + jb->len, 7, "\\u%04x", c);
                    if (n > 0) jb->len += n;
                } else {
                    jb->buf[jb->len++] = (char)c;
                }
                break;
        }
    }
    if (quoted) {
        json_ensure_capacity(jb, 1);
        jb->buf[jb->len++] = '"';
    }
    jb->buf[jb->len] = '\0';
}
static void build_injector_json(JsonBuf *jb) {
    json_append(jb,
        "  \"injector\": {\n"
        "    \"pid\": %d,\n"
        "    \"passive\": %s,\n"
        "    \"mode\": ",
        getpid(),
        g_passive_mode ? "true" : "false");
    json_escape(jb, g_passive_mode ? "passive" : "active", true);
    json_append(jb, "\n  },\n");
}
static void build_global_fuse_json(JsonBuf *jb) {
    json_append(jb,
        "  \"global_fuse\": {\n"
        "    \"fuse_pid\": %d,\n"
        "    \"disabled\": %s\n"
        "  },\n",
        g_global_fuse.fuse_pid,
        g_global_fuse.disabled ? "true" : "false");
}
static void append_redir_rules_json(JsonBuf *jb, AppConfig *cfg) {
    for (int i = 0; i < cfg->redir_count; i++) {
        if (i > 0) json_append(jb, ",");
        json_append(jb, "\n          { \"source\": ");
        json_escape(jb, cfg->redir_rules[i].virtual_prefix, true);
        json_append(jb, ", \"target\": ");
        json_escape(jb, cfg->redir_rules[i].real_target, true);
        json_append(jb, " }");
    }
}
static void append_str_array_json(JsonBuf *jb, char **rules, int count) {
    for (int i = 0; i < count; i++) {
        if (i > 0) json_append(jb, ",");
        json_append(jb, "\n          ");
        json_escape(jb, rules[i], true);
    }
}
static void build_templates_json(JsonBuf *jb) {
    config_lock_read();
    json_append(jb, "  \"templates\": [\n");
    {
        json_append(jb, "    {\n");
        json_append(jb, "      \"template_name\": \"GLOBAL\",\n");
        json_append(jb, "      \"hook_operation\": [\"query\", \"insert\"],\n");
        json_append(jb, "      \"apply_to_app\": [\"*\"],\n");
        json_append(jb, "      \"enable_sandbox\": %s", g_global_cfg.sandbox ? "true" : "false");
        json_append(jb, ",\n      \"global_inject\": %s", g_global_cfg.global_inject ? "true" : "false");
        json_append(jb, ",\n      \"fuse_direct\": %s", g_global_cfg.fuse_direct ? "true" : "false");
        json_append(jb, ",\n      \"hide_paths\": [");
        append_str_array_json(jb, g_global_cfg.hide_rules, g_global_cfg.hide_count);
        json_append(jb, "\n      ],\n");
        json_append(jb, "      \"read_only_path\": [");
        append_str_array_json(jb, g_global_cfg.ro_rules, g_global_cfg.ro_count);
        json_append(jb, "\n      ],\n");
        json_append(jb, "      \"redirect_rules\": [");
        append_redir_rules_json(jb, &g_global_cfg);
        json_append(jb, "\n      ]\n");
        json_append(jb, "    }");
    }
    for (int i = 0; i < g_app_cfg_count; i++) {
        AppConfig *cfg = g_app_cfgs[i];
        json_append(jb, ",\n    {\n");
        json_append(jb, "      \"template_name\": ");
        json_escape(jb, cfg->pkg_name, true);
        json_append(jb, ",\n");
        json_append(jb, "      \"hook_operation\": [\"query\", \"insert\"],\n");
        json_append(jb, "      \"apply_to_app\": [");
        json_escape(jb, cfg->pkg_name, true);
        json_append(jb, "],\n");
        json_append(jb, "      \"enable_sandbox\": %s", cfg->sandbox ? "true" : "false");
        json_append(jb, ",\n      \"monitor\": %s", cfg->monitor ? "true" : "false");
        json_append(jb, ",\n      \"inject_enable\": %s", cfg->inject_enable ? "true" : "false");
        json_append(jb, ",\n      \"hide_paths\": [");
        append_str_array_json(jb, cfg->hide_rules, cfg->hide_count);
        json_append(jb, "\n      ],\n");
        json_append(jb, "      \"read_only_path\": [");
        append_str_array_json(jb, cfg->ro_rules, cfg->ro_count);
        json_append(jb, "\n      ],\n");
        json_append(jb, "      \"redirect_rules\": [");
        append_redir_rules_json(jb, cfg);
        json_append(jb, "\n      ]\n");
        json_append(jb, "    }");
    }
    json_append(jb, "\n  ],\n");
    config_unlock_read();
}
static void build_uidmap_json(JsonBuf *jb) {
    UidMapEntry entries[MAX_SNAPSHOT_UIDMAP];
    int count = get_uid_map_snapshot(entries, MAX_SNAPSHOT_UIDMAP);
    json_append(jb, "  \"uid_map\": [\n");
    for (int i = 0; i < count; i++) {
        json_append(jb, "    { \"uid\": %u, \"pkg\": ", entries[i].uid);
        json_escape(jb, entries[i].pkg, true);
        json_append(jb, " }%s\n", (i == count - 1) ? "" : ",");
    }
    json_append(jb, "  ]\n");
}
static char *build_config_json_payload(int *out_len) {
    JsonBuf jb;
    json_init(&jb, 16384); 
    if (!jb.buf) {
        *out_len = 0;
        return NULL;
    }
    json_append(&jb, "{\n");
    json_append(&jb, "  \"timestamp\": %lld,\n", (long long)time(NULL));
    build_injector_json(&jb);
    build_global_fuse_json(&jb);
    build_templates_json(&jb);
    build_uidmap_json(&jb);
    json_append(&jb, "}\n");
    *out_len = jb.len;
    return jb.buf;
}
static void broadcast_json(int sock_fd);
static int g_pub_fd = -1;
void config_publisher_broadcast(void) {
    if (g_pub_fd >= 0)
        broadcast_json(g_pub_fd);
}
static void broadcast_json(int sock_fd) {
    int len;
    char *json = build_config_json_payload(&len);
    if (!json) return;
    LOG_DBG("配置广播: %d 订阅者, JSON 大小 %d 字节", g_subscriber_count, len);
    for (int i = 0; i < MAX_SUBSCRIBERS && i < g_subscriber_count; i++) {
        if (!g_subscribers[i].active) continue;
        ssize_t ret = sendto(sock_fd, json, len, MSG_NOSIGNAL | MSG_DONTWAIT,
                             (struct sockaddr *)&g_subscribers[i].addr,
                             g_subscribers[i].addr_len);
        if (ret < 0) {
            if (errno == ECONNREFUSED || errno == ENOTCONN || errno == EPIPE) {
                LOG_DBG("配置广播: 订阅者 %d 已断开，移除", i);
                g_subscribers[i].active = false;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOG_DBG("配置广播: 发送给订阅者 %d 失败: %s", i, strerror(errno));
            }
        }
    }
    free(json);
}
#define MAX_FILE_SIZE (16 * 1024)  
#define MAX_STATIC_FILES 256
static int read_file_content(const char *path, char **out_buf) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    off_t fsize = 0;
    if (fstat(fd, &st) == 0) {
        fsize = st.st_size;
    }
    if (fsize > MAX_FILE_SIZE) fsize = MAX_FILE_SIZE;
    size_t alloc_size = (fsize > 0) ? (size_t)fsize : 4096;
    char *buf = malloc(alloc_size + 1);
    if (!buf) { close(fd); return -1; }
    size_t total_read = 0;
    while (total_read < alloc_size) {
        ssize_t n = read(fd, buf + total_read, alloc_size - total_read);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0) break;
        total_read += (size_t)n;
    }
    buf[total_read] = '\0';
    close(fd);
    *out_buf = buf;
    return (int)total_read;
}
static void handle_static_request(int sock_fd, struct sockaddr_un *cli_addr,
                                   socklen_t cli_len) {
    JsonBuf jb;
    json_init(&jb, 32768);
    if (!jb.buf) return;
    json_append(&jb, "{\n");
    json_append(&jb, "  \"timestamp\": %lld,\n", (long long)time(NULL));
    json_append(&jb, "  \"type\": \"static\",\n");
    json_append(&jb, "  \"injector_conf\": ");
    char *conf_content = NULL;
    int conf_len = read_file_content(INJECTOR_CONFIG_PATH, &conf_content);
    if (conf_len >= 0 && conf_content) {
        json_escape(&jb, conf_content, true);
        free(conf_content);
    } else {
        json_append(&jb, "null");
    }
    json_append(&jb, ",\n");
    json_append(&jb, "  \"app_rules\": [\n");
    bool first_rule = true;
    DIR *dir = opendir(CONFIG_DIR);
    if (dir) {
        struct dirent *de;
        while ((de = readdir(dir)) != nullptr) {
            if (de->d_type != DT_DIR) continue;
            if (strcmp(de->d_name, "App-rules") != 0 &&
                strncmp(de->d_name, "App-rules-", 10) != 0)
                continue;
            char rules_dir[PATH_MAX];
            snprintf(rules_dir, sizeof(rules_dir), "%s/%s", CONFIG_DIR, de->d_name);
            DIR *rdir = opendir(rules_dir);
            if (!rdir) continue;
            struct dirent *rde;
            while ((rde = readdir(rdir)) != nullptr) {
                if (rde->d_type != DT_REG && rde->d_type != DT_LNK) continue;
                char *dot = strrchr(rde->d_name, '.');
                if (!dot || strcmp(dot, ".conf") != 0) continue;
                if (!first_rule) json_append(&jb, ",");
                first_rule = false;
                char file_path[PATH_MAX];
                snprintf(file_path, sizeof(file_path), "%s/%s", rules_dir, rde->d_name);
                json_append(&jb, "\n    { \"file\": ");
                json_escape(&jb, rde->d_name, true);
                json_append(&jb, ", \"user_dir\": ");
                json_escape(&jb, de->d_name, true);
                json_append(&jb, ", \"content\": ");
                char *fc = NULL;
                int fc_len = read_file_content(file_path, &fc);
                if (fc_len >= 0 && fc) {
                    json_escape(&jb, fc, true);
                    free(fc);
                } else {
                    json_append(&jb, "null");
                }
                json_append(&jb, " }");
            }
            closedir(rdir);
        }
        closedir(dir);
    }
    json_append(&jb, "\n  ]\n");
    json_append(&jb, "}\n");
    sendto(sock_fd, jb.buf, jb.len, MSG_NOSIGNAL | MSG_DONTWAIT,
           (struct sockaddr *)cli_addr, cli_len);
    free(jb.buf);
}
static void handle_get_request(int sock_fd, struct sockaddr_un *cli_addr,
                                socklen_t cli_len) {
    int len;
    char *json = build_config_json_payload(&len);
    if (!json) return;
    sendto(sock_fd, json, len, MSG_NOSIGNAL | MSG_DONTWAIT,
           (struct sockaddr *)cli_addr, cli_len);
    free(json);
}
static void handle_subscribe(int sock_fd, struct sockaddr_un *cli_addr,
                              socklen_t cli_len) {
    for (int i = 0; i < MAX_SUBSCRIBERS && i < g_subscriber_count; i++) {
        if (g_subscribers[i].active && g_subscribers[i].addr_len == cli_len &&
            memcmp(&g_subscribers[i].addr, cli_addr, cli_len) == 0) {
            handle_get_request(sock_fd, cli_addr, cli_len);
            return;
        }
    }
    if (g_subscriber_count >= MAX_SUBSCRIBERS) {
        LOG_DBG("配置广播: 订阅者已满 (%d), 拒绝新订阅", MAX_SUBSCRIBERS);
        return;
    }
    int idx = -1;
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
        if (!g_subscribers[i].active) { idx = i; break; }
    }
    if (idx < 0) return;
    memcpy(&g_subscribers[idx].addr, cli_addr, cli_len);
    g_subscribers[idx].addr_len = cli_len;
    g_subscribers[idx].active = true;
    if (idx >= g_subscriber_count)
        g_subscriber_count = idx + 1;
    LOG("配置广播: 新订阅者 #%d 已注册, 当前 %d 个订阅者", idx, g_subscriber_count);
    handle_get_request(sock_fd, cli_addr, cli_len);
}
static void handle_unsubscribe(struct sockaddr_un *cli_addr, socklen_t cli_len) {
    for (int i = 0; i < MAX_SUBSCRIBERS && i < g_subscriber_count; i++) {
        if (g_subscribers[i].active && g_subscribers[i].addr_len == cli_len &&
            memcmp(&g_subscribers[i].addr, cli_addr, cli_len) == 0) {
            g_subscribers[i].active = false;
            LOG("配置广播: 订阅者 #%d 已取消订阅", i);
            return;
        }
    }
}
void config_publisher_handle_readable(int fd) {
    union {
        struct sockaddr_un un;
        struct sockaddr generic;
    } cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    char buf[256];
    ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, MSG_DONTWAIT,
                         &cli_addr.generic, &cli_len);
    if (n <= 0) {
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            LOG_ERR("配置广播: recvfrom 失败: %s", strerror(errno));
        return;
    }
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' '))
        buf[--n] = '\0';
    if (n == 0 || strcmp(buf, "GET") == 0 || strcmp(buf, "get") == 0) {
        handle_get_request(fd, &cli_addr.un, cli_len);
    } else if (strcmp(buf, "STATIC") == 0 || strcmp(buf, "static") == 0) {
        handle_static_request(fd, &cli_addr.un, cli_len);
    } else if (strcmp(buf, "SUBSCRIBE") == 0 || strcmp(buf, "subscribe") == 0) {
        handle_subscribe(fd, &cli_addr.un, cli_len);
    } else if (strcmp(buf, "UNSUBSCRIBE") == 0 || strcmp(buf, "unsubscribe") == 0) {
        handle_unsubscribe(&cli_addr.un, cli_len);
    } else {
        handle_get_request(fd, &cli_addr.un, cli_len);
    }
}
int config_publisher_init(void) {
    int sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (sock < 0) {
        LOG_ERR("配置广播: 创建 socket 失败: %s", strerror(errno));
        return -1;
    }
    int bufsize = 256 * 1024;  
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, PUBSUB_SOCKET_NAME, sizeof(addr.sun_path) - 2);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(PUBSUB_SOCKET_NAME);
    if (bind(sock, (struct sockaddr *)&addr, addr_len) < 0) {
        LOG_ERR("配置广播: bind 失败: %s", strerror(errno));
        close(sock);
        return -1;
    }
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = sock };
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        LOG_ERR("配置广播: epoll_ctl ADD 失败: %s", strerror(errno));
        close(sock);
        return -1;
    }
    g_pub_fd = sock;
    LOG("配置广播服务已启动 (DGRAM: %s)", PUBSUB_SOCKET_NAME);
    return sock;
}
void config_publisher_cleanup(int fd) {
    if (fd < 0) return;
    if (g_epoll_fd >= 0)
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    close(fd);
    if (g_pub_fd == fd)
        g_pub_fd = -1;
    for (int i = 0; i < MAX_SUBSCRIBERS; i++)
        g_subscribers[i].active = false;
    g_subscriber_count = 0;
    LOG("配置广播服务已关闭");
}