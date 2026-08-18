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
#include <json-c/json.h>
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
static void build_injector_json(json_object *root) {
    json_object *injector = json_object_new_object();
    json_object_object_add(injector, "pid", json_object_new_int(getpid()));
    json_object_object_add(injector, "passive", json_object_new_boolean(g_passive_mode));
    json_object_object_add(injector, "mode", json_object_new_string(g_passive_mode ? "passive" : "active"));
    json_object_object_add(root, "injector", injector);
}
static void build_global_fuse_json(json_object *root) {
    json_object *global_fuse = json_object_new_object();
    json_object_object_add(global_fuse, "fuse_pid", json_object_new_int(g_global_fuse.fuse_pid));
    json_object_object_add(global_fuse, "disabled", json_object_new_boolean(g_global_fuse.disabled));
    json_object_object_add(root, "global_fuse", global_fuse);
}
static void append_redir_rules_json(json_object *arr, AppConfig *cfg) {
    for (int i = 0; i < cfg->redir_count; i++) {
        if (cfg->redir_rules[i].is_allow) continue;  // ALLOW 规则单独输出
        json_object *rule = json_object_new_object();
        json_object_object_add(rule, "source", json_object_new_string(cfg->redir_rules[i].virtual_prefix));
        const char *raw_target = cfg->redir_rules[i].real_target;
        if (raw_target[0] == '?') {
            json_object_object_add(rule, "target", json_object_new_string(raw_target + 1));
        } else {
            json_object_object_add(rule, "target", json_object_new_string(raw_target));
        }
        json_object_array_add(arr, rule);
    }
}

static void append_allow_rules_json(json_object *arr, AppConfig *cfg) {
    for (int i = 0; i < cfg->redir_count; i++) {
        if (!cfg->redir_rules[i].is_allow) continue;  // 只输出 ALLOW 规则
        json_object_array_add(arr, json_object_new_string(cfg->redir_rules[i].virtual_prefix));
    }
}
static void append_str_array_json(json_object *arr, char **rules, int count) {
    for (int i = 0; i < count; i++) {
        json_object_array_add(arr, json_object_new_string(rules[i]));
    }
}
static void build_templates_json(json_object *root) {
    config_lock_read();
    json_object *templates = json_object_new_array();
    
    // GLOBAL 模板
    json_object *global = json_object_new_object();
    json_object_object_add(global, "template_name", json_object_new_string("GLOBAL"));
    
    json_object *hook_op = json_object_new_array();
    json_object_array_add(hook_op, json_object_new_string("query"));
    json_object_array_add(hook_op, json_object_new_string("insert"));
    json_object_object_add(global, "hook_operation", hook_op);
    
    json_object *apply_to = json_object_new_array();
    json_object_array_add(apply_to, json_object_new_string("*"));
    json_object_object_add(global, "apply_to_app", apply_to);
    
    json_object_object_add(global, "enable_sandbox", json_object_new_boolean(g_global_cfg.sandbox));
    /* 全局注入状态强制关闭，不再跟随 g_global_cfg.global_inject 规则改变 */
    json_object_object_add(global, "global_inject", json_object_new_boolean(false));
    
    json_object *hide_paths = json_object_new_array();
    append_str_array_json(hide_paths, g_global_cfg.hide_rules, g_global_cfg.hide_count);
    json_object_object_add(global, "hide_paths", hide_paths);
    
    json_object *read_only = json_object_new_array();
    append_str_array_json(read_only, g_global_cfg.ro_rules, g_global_cfg.ro_count);
    json_object_object_add(global, "read_only_path", read_only);
    
    json_object *redir_rules = json_object_new_array();
    append_redir_rules_json(redir_rules, &g_global_cfg);
    json_object_object_add(global, "redirect_rules", redir_rules);
    
    // 仅在存在 ALLOW 规则时才添加 allow_rules 字段，减少空数组输出
    if (g_global_cfg.redir_count > 0) {
        int allow_cnt = 0;
        for (int j = 0; j < g_global_cfg.redir_count; j++)
            if (g_global_cfg.redir_rules[j].is_allow) allow_cnt++;
        if (allow_cnt > 0) {
            json_object *allow_rules = json_object_new_array();
            append_allow_rules_json(allow_rules, &g_global_cfg);
            json_object_object_add(global, "allow_rules", allow_rules);
        }
    }
    
    json_object_array_add(templates, global);
    
    // 应用模板
    for (int i = 0; i < g_app_cfg_count; i++) {
        AppConfig *cfg = g_app_cfgs[i];
        json_object *app = json_object_new_object();
        json_object_object_add(app, "template_name", json_object_new_string(cfg->pkg_name));
        
        json_object *hook_op = json_object_new_array();
        json_object_array_add(hook_op, json_object_new_string("query"));
        json_object_array_add(hook_op, json_object_new_string("insert"));
        json_object_object_add(app, "hook_operation", hook_op);
        
        json_object *apply_to = json_object_new_array();
        json_object_array_add(apply_to, json_object_new_string(cfg->pkg_name));
        json_object_object_add(app, "apply_to_app", apply_to);
        
        json_object_object_add(app, "enable_sandbox", json_object_new_boolean(cfg->sandbox));
        json_object_object_add(app, "monitor", json_object_new_boolean(cfg->monitor));
        json_object_object_add(app, "inject_enable", json_object_new_boolean(cfg->inject_enable));
        
        json_object *hide_paths = json_object_new_array();
        append_str_array_json(hide_paths, cfg->hide_rules, cfg->hide_count);
        json_object_object_add(app, "hide_paths", hide_paths);
        
        json_object *read_only = json_object_new_array();
        append_str_array_json(read_only, cfg->ro_rules, cfg->ro_count);
        json_object_object_add(app, "read_only_path", read_only);
        
        json_object *redir_rules = json_object_new_array();
        append_redir_rules_json(redir_rules, cfg);
        json_object_object_add(app, "redirect_rules", redir_rules);
        
        // 仅在存在 ALLOW 规则时才添加 allow_rules 字段
        if (cfg->redir_count > 0) {
            int allow_cnt = 0;
            for (int j = 0; j < cfg->redir_count; j++)
                if (cfg->redir_rules[j].is_allow) allow_cnt++;
            if (allow_cnt > 0) {
                json_object *allow_rules = json_object_new_array();
                append_allow_rules_json(allow_rules, cfg);
                json_object_object_add(app, "allow_rules", allow_rules);
            }
        }
        
        json_object_array_add(templates, app);
    }
    
    json_object_object_add(root, "templates", templates);
    config_unlock_read();
}
#ifdef CONFIG_PUBLISHER_ENABLE_UIDMAP
static void build_uidmap_json(json_object *root) {
    UidMapEntry entries[MAX_SNAPSHOT_UIDMAP];
    int count = get_uid_map_snapshot(entries, MAX_SNAPSHOT_UIDMAP);
    json_object *uid_map = json_object_new_array();
    for (int i = 0; i < count; i++) {
        json_object *entry = json_object_new_object();
        json_object_object_add(entry, "uid", json_object_new_int(entries[i].uid));
        json_object_object_add(entry, "pkg", json_object_new_string(entries[i].pkg));
        json_object_array_add(uid_map, entry);
    }
    json_object_object_add(root, "uid_map", uid_map);
}
#endif /* CONFIG_PUBLISHER_ENABLE_UIDMAP */
static char *build_config_json_payload(int *out_len) {
    json_object *root = json_object_new_object();
    json_object_object_add(root, "timestamp", json_object_new_int64(time(NULL)));
    build_injector_json(root);
    build_global_fuse_json(root);
    build_templates_json(root);
    
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
    int len = strlen(json_str);
    char *result = strdup(json_str);
    json_object_put(root);
    
    *out_len = len;
    return result;
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
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
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
    /* 清理后重算真实活跃订阅数 */
    int alive = 0;
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
        if (g_subscribers[i].active) alive++;
    }
    g_subscriber_count = alive;
    free(json);
}
#define MAX_FILE_SIZE (256 * 1024)  
#define MAX_STATIC_FILES 256
static int read_file_content(const char *path, char **out_buf) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t cap = 4096;
    size_t total_read = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return -1; }
    while (1) {
        if (total_read >= cap) {
            cap *= 2;
            if (cap > MAX_FILE_SIZE) cap = MAX_FILE_SIZE;
            char *new_buf = realloc(buf, cap);
            if (!new_buf) { free(buf); close(fd); return -1; }
            buf = new_buf;
        }
        size_t remaining = cap - total_read;
        ssize_t n = read(fd, buf + total_read, remaining);
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
    json_object *root = json_object_new_object();
    json_object_object_add(root, "timestamp", json_object_new_int64(time(NULL)));
    json_object_object_add(root, "type", json_object_new_string("static"));

    /* 解析 injector.conf */
    char *conf_content = NULL;
    int conf_len = read_file_content(INJECTOR_CONFIG_PATH, &conf_content);
    if (conf_len >= 0 && conf_content) {
        json_object *global = json_object_new_object();
        json_object *switches = json_object_new_object();
        json_object *ro_rules = json_object_new_array();
        json_object *hide_rules = json_object_new_array();
        json_object *redirect_rules = json_object_new_array();
        json_object *allow_rules = json_object_new_array();
        json_object *apps = json_object_new_array();

        bool in_global = false;
        char *saveptr1 = NULL;
        char *tok = strtok_r(conf_content, "\n", &saveptr1);

        while (tok) {
            while (*tok == ' ' || *tok == '\t') tok++;
            if (*tok == '\0' || *tok == '#') { tok = strtok_r(nullptr, "\n", &saveptr1); continue; }

            if (tok[0] == '[') {
                in_global = (strcmp(tok, "[GLOBAL]") == 0);
                if (!in_global) {
                    /* 解析 [pkg:uid] ON/OFF */
                    char pkg[128] = {0};
                    int uid = 0;
                    char state[8] = {0};
                    char *end = strchr(tok + 1, ']');
                    if (end) {
                        size_t len = end - (tok + 1);
                        char inner[256];
                        snprintf(inner, sizeof(inner), "%.*s", (int)len, tok + 1);
                        char *colon = strrchr(inner, ':');
                        if (colon) { *colon = '\0'; uid = atoi(colon + 1); }
                        snprintf(pkg, sizeof(pkg), "%s", inner);
                        char *rest = end + 1;
                        while (*rest == ' ' || *rest == '\t') rest++;
                        sscanf(rest, "%7s", state);
                    }
                    if (pkg[0]) {
                        json_object *app = json_object_new_object();
                        json_object_object_add(app, "pkg", json_object_new_string(pkg));
                        json_object_object_add(app, "user_id", json_object_new_int(uid));
                        json_object_object_add(app, "inject_enable", json_object_new_string(state[0] ? state : "OFF"));
                        json_object_array_add(apps, app);
                    }
                }
                tok = strtok_r(nullptr, "\n", &saveptr1);
                continue;
            }

            if (in_global) {
                char val[4096];
                if (sscanf(tok, "GLOBAL_INJECT = %4095s", val) == 1 ||
                    sscanf(tok, "GLOBAL_INJECT %4095s", val) == 1)
                    json_object_object_add(switches, "global_inject", json_object_new_string(val));
                else if (sscanf(tok, "MONITOR = %4095s", val) == 1 ||
                         sscanf(tok, "MONITOR %4095s", val) == 1)
                    json_object_object_add(switches, "monitor", json_object_new_string(val));
                else if (sscanf(tok, "SANDBOX = %4095s", val) == 1 ||
                         sscanf(tok, "SANDBOX %4095s", val) == 1)
                    json_object_object_add(switches, "sandbox", json_object_new_string(val));
                else if (strncmp(tok, "RO ", 3) == 0 || strncmp(tok, "RO\t", 2) == 0) {
                    char *path = tok + 3;
                    while (*path == ' ' || *path == '\t') path++;
                    if (*path) json_object_array_add(ro_rules, json_object_new_string(path));
                } else if (strncmp(tok, "HIDE ", 5) == 0 || strncmp(tok, "HIDE\t", 5) == 0) {
                    char *path = tok + 5;
                    while (*path == ' ' || *path == '\t') path++;
                    if (*path) json_object_array_add(hide_rules, json_object_new_string(path));
                } else if (strncmp(tok, "REDIRECT ", 9) == 0 || strncmp(tok, "REDIRECT\t", 9) == 0) {
                    char *path = tok + 9;
                    while (*path == ' ' || *path == '\t') path++;
                    if (*path) json_object_array_add(redirect_rules, json_object_new_string(path));
                } else if (strncmp(tok, "ALLOW ", 6) == 0 || strncmp(tok, "ALLOW\t", 6) == 0) {
                    char *path = tok + 6;
                    while (*path == ' ' || *path == '\t') path++;
                    if (*path) json_object_array_add(allow_rules, json_object_new_string(path));
                }
            }
            tok = strtok_r(nullptr, "\n", &saveptr1);
        }

        json_object_object_add(global, "switches", switches);
        json_object_object_add(global, "ro_rules", ro_rules);
        json_object_object_add(global, "hide_rules", hide_rules);
        json_object_object_add(global, "redirect_rules", redirect_rules);
        json_object_object_add(global, "allow_rules", allow_rules);
        json_object_object_add(root, "global", global);
        json_object_object_add(root, "apps", apps);

        free(conf_content);
    } else {
        json_object_object_add(root, "global", NULL);
        json_object_object_add(root, "apps", json_object_new_array());
    }

    /* app_rules: 扫描文件系统读取每个应用规则文件内容 */
    json_object *app_rules = json_object_new_array();
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
                char file_path[PATH_MAX];
                snprintf(file_path, sizeof(file_path), "%s/%s", rules_dir, rde->d_name);
                json_object *rule = json_object_new_object();
                json_object_object_add(rule, "file", json_object_new_string(rde->d_name));
                json_object_object_add(rule, "user_dir", json_object_new_string(de->d_name));
                char *fc = NULL;
                int fc_len = read_file_content(file_path, &fc);
                if (fc_len >= 0 && fc) {
                    json_object_object_add(rule, "content", json_object_new_string(fc));
                    free(fc);
                } else {
                    json_object_object_add(rule, "content", NULL);
                }
                json_object_array_add(app_rules, rule);
            }
            closedir(rdir);
        }
        closedir(dir);
    }
    json_object_object_add(root, "app_rules", app_rules);

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
    sendto(sock_fd, json_str, strlen(json_str), MSG_NOSIGNAL | MSG_DONTWAIT,
           (struct sockaddr *)cli_addr, cli_len);
    json_object_put(root);
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
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
        if (g_subscribers[i].active && g_subscribers[i].addr_len == cli_len &&
            memcmp(&g_subscribers[i].addr, cli_addr, cli_len) == 0) {
            handle_get_request(sock_fd, cli_addr, cli_len);
            return;
        }
    }
    int idx = -1;
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
        if (!g_subscribers[i].active) { idx = i; break; }
    }
    if (idx < 0) {
        /* 所有 slot 都被占用，强制移除第一个旧订阅者腾出空间 */
        for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
            if (g_subscribers[i].active) {
                LOG("配置广播: 强制移除旧订阅者 #%d", i);
                g_subscribers[i].active = false;
                idx = i;
                break;
            }
        }
    }
    if (idx < 0) return;  /* 不应走到这里，但保留防御 */
    memcpy(&g_subscribers[idx].addr, cli_addr, cli_len);
    g_subscribers[idx].addr_len = cli_len;
    g_subscribers[idx].active = true;
    /* 重算真实活跃订阅数 */
    int alive = 0;
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
        if (g_subscribers[i].active) alive++;
    }
    g_subscriber_count = alive;
    LOG("配置广播: 新订阅者 #%d 已注册, 当前 %d 个订阅者", idx, g_subscriber_count);
    handle_get_request(sock_fd, cli_addr, cli_len);
}
static void handle_unsubscribe(struct sockaddr_un *cli_addr, socklen_t cli_len) {
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
        if (g_subscribers[i].active && g_subscribers[i].addr_len == cli_len &&
            memcmp(&g_subscribers[i].addr, cli_addr, cli_len) == 0) {
            g_subscribers[i].active = false;
            /* 重算真实活跃订阅数 */
            int alive = 0;
            for (int j = 0; j < MAX_SUBSCRIBERS; j++) {
                if (g_subscribers[j].active) alive++;
            }
            g_subscriber_count = alive;
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