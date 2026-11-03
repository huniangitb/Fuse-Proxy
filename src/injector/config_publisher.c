#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "config_publisher.h"
#include "common.h"
#include "nsp_comm.h"
#include "nsp_util.h"
#include <stdatomic.h>
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
#define PUBSUB_SOCKET_NAME CONFIG_BROADCAST_SOCKET
#define MAX_SUBSCRIBERS    32
#define MAX_SNAPSHOT_APPS  256
struct Subscriber {
    struct sockaddr_un addr;
    socklen_t addr_len;
    bool active;
};
static struct Subscriber g_subscribers[MAX_SUBSCRIBERS];
static int g_subscriber_count = 0;
static void build_injector_json(json_object* root) {
    json_object* injector = json_object_new_object();
    json_object_object_add(injector, "pid", json_object_new_int(getpid()));
    json_object_object_add(injector, "passive", json_object_new_boolean(g_passive_mode));
    json_object_object_add(injector, "mode",
                           json_object_new_string(g_passive_mode ? "passive" : "active"));
    json_object_object_add(root, "injector", injector);
}
static void build_global_fuse_json(json_object* root) {
    json_object* global_fuse = json_object_new_object();
    json_object_object_add(global_fuse, "fuse_pid", json_object_new_int(g_global_fuse.fuse_pid));
    json_object_object_add(global_fuse, "disabled",
                           json_object_new_boolean(g_global_fuse.disabled));
    json_object_object_add(root, "global_fuse", global_fuse);
}
static void append_redir_rules_json(json_object* arr, const AppConfig* cfg) {
    for (int i = 0; i < cfg->redir_count; i++) {
        if (cfg->redir_rules[i].is_allow) continue; // ALLOW 规则单独输出
        json_object* rule = json_object_new_object();
        json_object_object_add(rule, "source",
                               json_object_new_string(cfg->redir_rules[i].virtual_prefix));
        const char* raw_target = cfg->redir_rules[i].real_target;
        if (raw_target[0] == '?') {
            json_object_object_add(rule, "target", json_object_new_string(raw_target + 1));
        } else {
            json_object_object_add(rule, "target", json_object_new_string(raw_target));
        }
        json_object_array_add(arr, rule);
    }
}

static void append_allow_rules_json(json_object* arr, const AppConfig* cfg) {
    for (int i = 0; i < cfg->redir_count; i++) {
        if (!cfg->redir_rules[i].is_allow) continue; // 只输出 ALLOW 规则
        json_object_array_add(arr, json_object_new_string(cfg->redir_rules[i].virtual_prefix));
    }
}
static void append_str_array_json(json_object* arr, char* const* rules, int count) {
    for (int i = 0; i < count; i++) {
        json_object_array_add(arr, json_object_new_string(rules[i]));
    }
}
static void build_templates_json(json_object* root) {
    config_lock_read();
    json_object* templates = json_object_new_array();

    // GLOBAL 模板
    json_object* global = json_object_new_object();
    json_object_object_add(global, "template_name", json_object_new_string("GLOBAL"));

    json_object* hook_op = json_object_new_array();
    json_object_array_add(hook_op, json_object_new_string("query"));
    json_object_array_add(hook_op, json_object_new_string("insert"));
    json_object_object_add(global, "hook_operation", hook_op);

    json_object* apply_to = json_object_new_array();
    json_object_array_add(apply_to, json_object_new_string("*"));
    json_object_object_add(global, "apply_to_app", apply_to);

    json_object_object_add(global, "enable_sandbox", json_object_new_boolean(g_global_cfg.sandbox));
    /* 全局注入状态强制关闭，不再跟随 g_global_cfg.global_inject 规则改变 */
    json_object_object_add(global, "global_inject", json_object_new_boolean(false));

    json_object* hide_paths = json_object_new_array();
    append_str_array_json(hide_paths, g_global_cfg.hide_rules, g_global_cfg.hide_count);
    json_object_object_add(global, "hide_paths", hide_paths);

    json_object* read_only = json_object_new_array();
    append_str_array_json(read_only, g_global_cfg.ro_rules, g_global_cfg.ro_count);
    json_object_object_add(global, "read_only_path", read_only);

    json_object* redir_rules = json_object_new_array();
    append_redir_rules_json(redir_rules, &g_global_cfg);
    json_object_object_add(global, "redirect_rules", redir_rules);

    // 仅在存在 ALLOW 规则时才添加 allow_rules 字段，减少空数组输出
    if (g_global_cfg.redir_count > 0) {
        int allow_cnt = 0;
        for (int j = 0; j < g_global_cfg.redir_count; j++)
            if (g_global_cfg.redir_rules[j].is_allow) allow_cnt++;
        if (allow_cnt > 0) {
            json_object* allow_rules = json_object_new_array();
            append_allow_rules_json(allow_rules, &g_global_cfg);
            json_object_object_add(global, "allow_rules", allow_rules);
        }
    }

    json_object_array_add(templates, global);

    // 应用模板（含类别段：模板名 USER_APPS/SYSTEM_APPS，scope=category 标记，
    // 老消费端按 apply_to_app 精确匹配包名——类别名恒不等于真实包名，保持惰性）
    for (int i = 0; i < g_app_cfg_count; i++) {
        AppConfig* cfg = g_app_cfgs[i];
        json_object* app = json_object_new_object();
        json_object_object_add(app, "template_name", json_object_new_string(cfg->pkg_name));
        if (strcmp(cfg->pkg_name, "USER_APPS") == 0 || strcmp(cfg->pkg_name, "SYSTEM_APPS") == 0) {
            json_object_object_add(app, "scope", json_object_new_string("category"));
            json_object_object_add(app, "user_id", json_object_new_int(cfg->user_id));
        }

        json_object* hook_op = json_object_new_array();
        json_object_array_add(hook_op, json_object_new_string("query"));
        json_object_array_add(hook_op, json_object_new_string("insert"));
        json_object_object_add(app, "hook_operation", hook_op);

        json_object* apply_to = json_object_new_array();
        json_object_array_add(apply_to, json_object_new_string(cfg->pkg_name));
        json_object_object_add(app, "apply_to_app", apply_to);

        json_object_object_add(app, "enable_sandbox", json_object_new_boolean(cfg->sandbox));
        json_object_object_add(app, "monitor", json_object_new_boolean(cfg->monitor));
        json_object_object_add(app, "inject_enable", json_object_new_boolean(cfg->inject_enable));

        json_object* hide_paths = json_object_new_array();
        append_str_array_json(hide_paths, cfg->hide_rules, cfg->hide_count);
        json_object_object_add(app, "hide_paths", hide_paths);

        json_object* read_only = json_object_new_array();
        append_str_array_json(read_only, cfg->ro_rules, cfg->ro_count);
        json_object_object_add(app, "read_only_path", read_only);

        json_object* redir_rules = json_object_new_array();
        append_redir_rules_json(redir_rules, cfg);
        json_object_object_add(app, "redirect_rules", redir_rules);

        // 仅在存在 ALLOW 规则时才添加 allow_rules 字段
        if (cfg->redir_count > 0) {
            int allow_cnt = 0;
            for (int j = 0; j < cfg->redir_count; j++)
                if (cfg->redir_rules[j].is_allow) allow_cnt++;
            if (allow_cnt > 0) {
                json_object* allow_rules = json_object_new_array();
                append_allow_rules_json(allow_rules, cfg);
                json_object_object_add(app, "allow_rules", allow_rules);
            }
        }

        json_object_array_add(templates, app);
    }

    json_object_object_add(root, "templates", templates);
    config_unlock_read();
}
static char* build_config_json_payload(int* out_len) {
    json_object* root = json_object_new_object();
    json_object_object_add(root, "timestamp", json_object_new_int64(time(NULL)));
    build_injector_json(root);
    build_global_fuse_json(root);
    build_templates_json(root);

    const char* json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN |
                                                                    JSON_C_TO_STRING_NOSLASHESCAPE);
    int len = strlen(json_str);
    char* result = strdup(json_str);
    json_object_put(root);

    *out_len = len;
    return result;
}
/* BCAST 通道载荷（仅 comm 线程解释，订阅者集合归 comm 线程所有，
   主线程只 post，禁直接触碰 g_subscribers）：
   'J' + json 字节                    —— 扇出广播
   'A' + addrlen:1 + sockaddr 字节    —— 订阅注册（含去重 + 即时快照仍由主线程同步回复）
   'D' + addrlen:1 + sockaddr 字节    —— 取消订阅 */
/* 主线程写（init/cleanup）+ comm 线程读（ensure/emit），原子化防数据竞争；
   cleanup 只 shutdown 不断号 close，残余 sendto 至多 EBADF，不会误发复用 fd */
static _Atomic int g_pub_fd = -1;
static _Atomic bool g_pub_active = false;

static int sub_recount(void) {
    int alive = 0;
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
        if (g_subscribers[i].active) alive++;
    }
    g_subscriber_count = alive;
    return alive;
}

static void sub_add(const struct sockaddr_un* addr, socklen_t addr_len) {
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
        if (g_subscribers[i].active && g_subscribers[i].addr_len == addr_len &&
            memcmp(&g_subscribers[i].addr, addr, addr_len) == 0) {
            return; /* 重复订阅：幂等，主线程已同步回复快照 */
        }
    }
    int idx = -1;
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
        if (!g_subscribers[i].active) {
            idx = i;
            break;
        }
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
    if (idx < 0) return; /* 不应走到这里，但保留防御 */
    memcpy(&g_subscribers[idx].addr, addr, addr_len);
    g_subscribers[idx].addr_len = addr_len;
    g_subscribers[idx].active = true;
    LOG("配置广播: 新订阅者 #%d 已注册, 当前 %d 个订阅者", idx, sub_recount());
}

static void sub_del(const struct sockaddr_un* addr, socklen_t addr_len) {
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
        if (g_subscribers[i].active && g_subscribers[i].addr_len == addr_len &&
            memcmp(&g_subscribers[i].addr, addr, addr_len) == 0) {
            g_subscribers[i].active = false;
            LOG("配置广播: 订阅者 #%d 已取消订阅", i);
            sub_recount();
            return;
        }
    }
}

/* 后端（comm 线程）：DGRAM 无连接，ensure 以 active 标记为准 */
static bool cfgpub_ensure_link(void* ctx) {
    (void)ctx;
    return atomic_load(&g_pub_active) && atomic_load(&g_pub_fd) >= 0;
}

static int cfgpub_emit(void* ctx, const void* data, size_t len) {
    (void)ctx;
    int sock_fd = atomic_load(&g_pub_fd);
    if (len < 1 || sock_fd < 0) return -1;
    const uint8_t* p = data;
    if (p[0] == 'A' || p[0] == 'D') {
        if (len < 2) return 0;
        uint8_t alen = p[1];
        if (alen == 0 || alen > sizeof(struct sockaddr_un) || len < (size_t)2 + alen) return 0;
        struct sockaddr_un addr;
        memcpy(&addr, p + 2, alen);
        if (p[0] == 'A')
            sub_add(&addr, alen);
        else
            sub_del(&addr, alen);
        return 0;
    }
    if (p[0] != 'J') return 0;
    const char* json = (const char*)(p + 1);
    size_t jlen = len - 1;
    LOG_DBG("配置广播: %d 订阅者, JSON 大小 %zu 字节", g_subscriber_count, jlen);
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
        if (!g_subscribers[i].active) continue;
        ssize_t ret = sendto(sock_fd, json, jlen, MSG_NOSIGNAL | MSG_DONTWAIT,
                             (struct sockaddr*)&g_subscribers[i].addr, g_subscribers[i].addr_len);
        if (ret < 0) {
            if (errno == ECONNREFUSED || errno == ENOTCONN || errno == EPIPE) {
                LOG_DBG("配置广播: 订阅者 %d 已断开，移除", i);
                g_subscribers[i].active = false;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOG_DBG("配置广播: 发送给订阅者 %d 失败: %s", i, strerror(errno));
            }
        }
    }
    sub_recount();
    return 0;
}

void config_publisher_broadcast(void) {
    if (atomic_load(&g_pub_fd) < 0) return;
    int len;
    char* json = build_config_json_payload(&len);
    if (!json) return;
    /* JSON 拼装仍在调用方（沿用配置读锁上下文），扇出投递给 comm 线程 */
    size_t total = (size_t)len + 1;
    uint8_t* buf = malloc(total);
    if (buf) {
        buf[0] = 'J';
        memcpy(buf + 1, json, (size_t)len);
        nsp_comm_post(NSP_CH_BCAST, buf, total);
        free(buf);
    }
    free(json);
}
#define MAX_FILE_SIZE    (256 * 1024)
#define MAX_STATIC_FILES 256
/* 静态重定向规则字符串（"<虚拟前缀> <目标>"）：目标的 '?' 是 parse 阶段内部
   前缀（相对当前用户存储），对外展示时剥离；ALLOW 单独输出 */
static void append_static_redirect_json(json_object* arr, const AppConfig* cfg) {
    for (int i = 0; i < cfg->redir_count; i++) {
        if (cfg->redir_rules[i].is_allow) continue;
        const char* raw_target = cfg->redir_rules[i].real_target;
        char buf[2 * MAX_PATH_LEN];
        snprintf(buf, sizeof buf, "%s %s", cfg->redir_rules[i].virtual_prefix,
                 raw_target[0] == '?' ? raw_target + 1 : raw_target);
        json_object_array_add(arr, json_object_new_string(buf));
    }
}

/* STATIC 的 global 段：复用 config_parser 已加载的 AppConfig 快照（调用方须持
   读锁）。发布器禁止调用 load_config_rules——那会替换 injector 的 live 配置，
   破坏实时规则（对照 log_ctl 的查询路径，后者是独立进程可自行加载）。 */
static void build_static_global_json(json_object* root) {
    json_object* global = json_object_new_object();

    json_object* switches = json_object_new_object();
    json_object_object_add(switches, "global_inject",
                           json_object_new_string(g_global_cfg.global_inject ? "ON" : "OFF"));
    json_object_object_add(switches, "monitor",
                           json_object_new_string(g_global_cfg.monitor ? "ON" : "OFF"));
    json_object_object_add(switches, "sandbox",
                           json_object_new_string(g_global_cfg.sandbox ? "ON" : "OFF"));
    json_object_object_add(switches, "skip_system_apps",
                           json_object_new_string(g_global_cfg.skip_system_apps ? "ON" : "OFF"));
    json_object_object_add(global, "switches", switches);

    json_object* ro_rules = json_object_new_array();
    append_str_array_json(ro_rules, g_global_cfg.ro_rules, g_global_cfg.ro_count);
    json_object_object_add(global, "ro_rules", ro_rules);

    json_object* hide_rules = json_object_new_array();
    append_str_array_json(hide_rules, g_global_cfg.hide_rules, g_global_cfg.hide_count);
    json_object_object_add(global, "hide_rules", hide_rules);

    json_object* redirect_rules = json_object_new_array();
    append_static_redirect_json(redirect_rules, &g_global_cfg);
    json_object_object_add(global, "redirect_rules", redirect_rules);

    json_object* allow_rules = json_object_new_array();
    append_allow_rules_json(allow_rules, &g_global_cfg);
    json_object_object_add(global, "allow_rules", allow_rules);

    json_object_object_add(root, "global", global);
}

/* STATIC 的 apps 段：同样取已加载快照（含 App-rules 分文件与类别段），
   不再对 injector.conf 做 strtok_r + sscanf 旁路解析；类别段补 scope 标记，
   与 GET 模板的表示保持一致 */
static void build_static_apps_json(json_object* root) {
    json_object* apps = json_object_new_array();
    for (int i = 0; i < g_app_cfg_count; i++) {
        const AppConfig* cfg = g_app_cfgs[i];
        if (!cfg) continue;
        json_object* app = json_object_new_object();
        json_object_object_add(app, "pkg", json_object_new_string(cfg->pkg_name));
        json_object_object_add(app, "user_id", json_object_new_int(cfg->user_id));
        json_object_object_add(app, "inject_enable",
                               json_object_new_string(cfg->inject_enable ? "ON" : "OFF"));
        if (strcmp(cfg->pkg_name, "USER_APPS") == 0 || strcmp(cfg->pkg_name, "SYSTEM_APPS") == 0)
            json_object_object_add(app, "scope", json_object_new_string("category"));
        json_object_array_add(apps, app);
    }
    json_object_object_add(root, "apps", apps);
}

static void handle_static_request(int sock_fd, struct sockaddr_un* cli_addr, socklen_t cli_len) {
    json_object* root = json_object_new_object();
    json_object_object_add(root, "timestamp", json_object_new_int64(time(NULL)));
    json_object_object_add(root, "type", json_object_new_string("static"));

    /* global/apps 复用已加载快照（读锁下取一致视图）；app_rules 仍读磁盘原始
       文件内容——STATIC 的语义就是"原始规则文件" */
    config_lock_read();
    build_static_global_json(root);
    build_static_apps_json(root);
    config_unlock_read();

    /* app_rules: 扫描文件系统读取每个应用规则文件内容 */
    json_object* app_rules = json_object_new_array();
    DIR* dir = opendir(CONFIG_DIR);
    if (dir) {
        struct dirent* de;
        while ((de = readdir(dir)) != nullptr) {
            if (de->d_type != DT_DIR) continue;
            if (!nsp_is_app_rules_dirname(de->d_name)) continue;
            char rules_dir[PATH_MAX];
            snprintf(rules_dir, sizeof(rules_dir), "%s/%s", CONFIG_DIR, de->d_name);
            DIR* rdir = opendir(rules_dir);
            if (!rdir) continue;
            struct dirent* rde;
            while ((rde = readdir(rdir)) != nullptr) {
                if (rde->d_type != DT_REG && rde->d_type != DT_LNK) continue;
                char* dot = strrchr(rde->d_name, '.');
                if (!dot || strcmp(dot, ".conf") != 0) continue;
                char file_path[PATH_MAX];
                snprintf(file_path, sizeof(file_path), "%s/%s", rules_dir, rde->d_name);
                json_object* rule = json_object_new_object();
                json_object_object_add(rule, "file", json_object_new_string(rde->d_name));
                json_object_object_add(rule, "user_dir", json_object_new_string(de->d_name));
                size_t fc_len = 0;
                char* fc = read_file_dynamic(file_path, &fc_len, MAX_FILE_SIZE);
                if (fc) {
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

    const char* json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN |
                                                                    JSON_C_TO_STRING_NOSLASHESCAPE);
    sendto(sock_fd, json_str, strlen(json_str), MSG_NOSIGNAL | MSG_DONTWAIT,
           (struct sockaddr*)cli_addr, cli_len);
    json_object_put(root);
}
static void handle_get_request(int sock_fd, struct sockaddr_un* cli_addr, socklen_t cli_len) {
    int len;
    char* json = build_config_json_payload(&len);
    if (!json) return;
    sendto(sock_fd, json, len, MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr*)cli_addr, cli_len);
    free(json);
}
/* 订阅注册经 comm 线程（集合归 comm 所有，去重在 sub_add 内幂等）；
   快照回复仍由主线程同步发送（请求应答语义不变） */
static void post_sub_ctrl(char op, const struct sockaddr_un* cli_addr, socklen_t cli_len) {
    if (cli_len == 0 || cli_len > sizeof(struct sockaddr_un)) return;
    uint8_t buf[2 + sizeof(struct sockaddr_un)];
    buf[0] = (uint8_t)op;
    buf[1] = (uint8_t)cli_len;
    memcpy(buf + 2, cli_addr, cli_len);
    nsp_comm_post(NSP_CH_BCAST, buf, (size_t)2 + cli_len);
}

static void handle_subscribe(int sock_fd, struct sockaddr_un* cli_addr, socklen_t cli_len) {
    post_sub_ctrl('A', cli_addr, cli_len);
    handle_get_request(sock_fd, cli_addr, cli_len);
}
static void handle_unsubscribe(struct sockaddr_un* cli_addr, socklen_t cli_len) {
    post_sub_ctrl('D', cli_addr, cli_len);
}
void config_publisher_handle_readable(int fd) {
    union {
        struct sockaddr_un un;
        struct sockaddr generic;
    } cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    char buf[256];
    ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, MSG_DONTWAIT, &cli_addr.generic, &cli_len);
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
    struct sockaddr_un addr;
    socklen_t addr_len = nsp_uds_abstract_addr(&addr, PUBSUB_SOCKET_NAME);
    if (bind(sock, (struct sockaddr*)&addr, addr_len) < 0) {
        LOG_ERR("配置广播: bind 失败: %s", strerror(errno));
        close(sock);
        return -1;
    }
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = sock};
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        LOG_ERR("配置广播: epoll_ctl ADD 失败: %s", strerror(errno));
        close(sock);
        return -1;
    }
    atomic_store(&g_pub_fd, sock);
    atomic_store(&g_pub_active, true);
    /* BCAST 后端注册到统一 comm 线程：扇出 + 订阅集合改由 comm 线程驱动 */
    nsp_comm_backend_t be = {
        .ctx = NULL,
        .ensure_link = cfgpub_ensure_link,
        .emit = cfgpub_emit,
        .fini = NULL,
        .report = nsp_log_report,
    };
    nsp_comm_register(NSP_CH_BCAST, &be);
    LOG("配置广播服务已启动 (DGRAM: %s)", PUBSUB_SOCKET_NAME);
    return sock;
}
void config_publisher_cleanup(int fd) {
    if (fd < 0) return;
    if (g_epoll_fd >= 0) epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    /* 关闭期：先停扇出（comm 线程随后 join），fd 以 shutdown 失效不断号——
       comm 侧残余 sendto 至多 EBADF，不会因号段复用误发；集合内存随进程退出回收 */
    atomic_store(&g_pub_active, false);
    shutdown(fd, SHUT_RDWR);
    if (atomic_load(&g_pub_fd) == fd) atomic_store(&g_pub_fd, -1);
    LOG("配置广播服务已关闭");
}