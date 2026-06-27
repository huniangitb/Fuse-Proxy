#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/epoll.h>
#include <stddef.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include "common.h"
#include "config_parser.h"

static volatile sig_atomic_t g_running = 1;
void sigint_handler(int sig) {
    (void)sig;
    g_running = 0;
}

void usage(const char* prog) {
    printf("用法: %s <command> [--level level] [args]\n", prog);
    printf("\n日志查询命令:\n");
    printf("  search-io|search-sys [--level level] [key] [limit] [offset] [-u] [api]\n");
    printf("    --level level: 日志级别过滤（仅 search-sys 有效）\n");
    printf("           0=DEBUG 1=INFO 2=WARN 3=ERROR (-1=全部，默认-1)\n");
    printf("  clear-io|clear-sys\n");
    printf("\n日志统计命令:\n");
    printf("  log-count [api]            获取当前日志缓冲区总计条数（JSON）\n");
    printf("\n流式日志命令（实时输出，Ctrl+C 停止）:\n");
    printf("  stream-io|stream-sys|stream-logcat|stream-all [--level level] [-u]\n");
    printf("    --level level: 最低日志级别，仅显示 >= 此级别的日志\n");
    printf("           0=DEBUG 1=INFO 2=WARN 3=ERROR (默认0)\n");
    printf("\n注入状态命令:\n");
    printf("  list-injected [api]        列出已注入应用列表\n");
    printf("  list-users [api]           列出当前活跃用户及对应应用数\n");
    printf("\n配置查看命令:\n");
    printf("  get-config [api]           获取当前内存中的解析后配置（JSON）\n");
    printf("  get-config --static [api]  从磁盘读取原始规则文件内容（JSON）\n");
    printf("  stream-config [api]       订阅配置变更推送（Ctrl+C 停止）\n");
    printf("\n本地规则解析与配置命令 (API 友好):\n");
    printf("  parse-rules [api]          直接解析本地磁盘规则文件，输出结构化 JSON\n");
    printf("  get-global-rules [api]     查看本地 [GLOBAL] 段全部规则（开关+路径）\n");
    printf("  get-app-rules <pkg> [--uid uid] [api]\n");
    printf("                             查看指定应用的配置和规则\n");
    printf("  validate-rules [api]       验证本地规则语法正确性\n");
    printf("  reload-config [api]        重新加载配置（向注入器发送 SIGHUP）\n");
    printf("  status [api]               全面系统状态概览（JSON）\n");
    printf("  set-rule <pkg> <type> <value> [--uid uid] [api]\n");
    printf("                             添加/更新规则到文件\n");
    printf("                              type: HIDE|RO|REDIRECT|ALLOW|MONITOR|SANDBOX|GLOBAL_INJECT|FUSE_DIRECT\n");
    printf("  remove-rule <pkg> <type> <index> [--uid uid] [api]\n");
    printf("                             删除指定索引的规则\n");
    printf("\n选项:\n");
    printf("  -u               始终显示 UID\n");
    printf("  api              以 API 格式输出（供程序调用，结构化 JSON）\n");
    printf("  --subscribe      订阅模式，持续接收配置变更\n");
    printf("  --uid <uid>      指定用户 ID（默认 0）\n");
    exit(1);
}

/* ========== JSON API 结构化输出 ========== */

/* 返回结构化 JSON 响应，供前端 UI 解析
 * 格式: {"status":"ok","command":"cmd","data":...,"timestamp":ts}
 * 错误: {"status":"error","command":"cmd","error":"msg","timestamp":ts}
 */

static void json_api_start(bool api_mode) {
    if (!api_mode) return;
    /* 调用者在成功场景调用此函数开启 JSON 输出 */
    /* 实际输出由 json_api_finish / json_api_error 完成 */
}

static void json_api_finish(bool api_mode, const char *cmd, const char *json_data) {
    if (!api_mode) return;
    printf("{\"status\":\"ok\",\"command\":%s,\"data\":%s,\"timestamp\":%lld}\n",
           cmd ? cmd : "null",
           json_data ? json_data : "null",
           (long long)time(NULL));
}

static void json_api_error(bool api_mode, const char *cmd, const char *error_msg) {
    if (!api_mode) {
        fprintf(stderr, "错误: %s\n", error_msg ? error_msg : "未知错误");
        return;
    }
    printf("{\"status\":\"error\",\"command\":%s,\"error\":",
           cmd ? cmd : "null");
    /* 手动转义 error_msg 中的特殊字符 */
    if (error_msg) {
        putchar('"');
        for (const char *p = error_msg; *p; p++) {
            unsigned char c = (unsigned char)*p;
            switch (c) {
                case '"':  printf("\\\""); break;
                case '\\': printf("\\\\"); break;
                case '\n': printf("\\n"); break;
                case '\r': printf("\\r"); break;
                case '\t': printf("\\t"); break;
                default:
                    if (c < 0x20) printf("\\u%04x", c);
                    else putchar(c);
                    break;
            }
        }
        putchar('"');
    } else {
        printf("null");
    }
    printf(",\"timestamp\":%lld}\n", (long long)time(NULL));
}

/* 简单 JSON 转义辅助：将字符串写入缓冲区并转义，返回写入长度 */
static int json_escape_str(const char *src, char *dst, size_t dst_size) {
    if (!src || !dst || dst_size == 0) return 0;
    size_t pos = 0;
    for (const char *p = src; *p && pos < dst_size - 1; p++) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
            case '"':  if (pos + 2 < dst_size) { dst[pos++] = '\\'; dst[pos++] = '"'; } break;
            case '\\': if (pos + 2 < dst_size) { dst[pos++] = '\\'; dst[pos++] = '\\'; } break;
            case '\n': if (pos + 2 < dst_size) { dst[pos++] = '\\'; dst[pos++] = 'n'; } break;
            case '\r': if (pos + 2 < dst_size) { dst[pos++] = '\\'; dst[pos++] = 'r'; } break;
            case '\t': if (pos + 2 < dst_size) { dst[pos++] = '\\'; dst[pos++] = 't'; } break;
            default:
                if (c < 0x20) {
                    int n = snprintf(dst + pos, dst_size - pos, "\\u%04x", c);
                    if (n > 0) pos += (size_t)n;
                } else {
                    dst[pos++] = (char)c;
                }
                break;
        }
    }
    dst[pos] = '\0';
    return (int)pos;
}

/* ========== 配置文件读写辅助 ========== */

/* 读取 PID 文件，返回 PID 或 -1 */
static int read_pid_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    int pid = -1;
    if (fscanf(fp, "%d", &pid) != 1) pid = -1;
    fclose(fp);
    return pid;
}

/* 向注入器发送 SIGHUP 触发配置重载 */
static const char* send_reload_signal(void) {
    int pid = read_pid_file(INJECTOR_PID_PATH);
    if (pid <= 0) return "无法读取注入器 PID 文件";
    if (kill(pid, SIGHUP) != 0) {
        static char err_buf[128];
        snprintf(err_buf, sizeof(err_buf), "发送 SIGHUP 到 PID %d 失败: %s", pid, strerror(errno));
        return err_buf;
    }
    return NULL; /* 成功 */
}

/* 获取应用规则文件路径 */
static void get_app_rule_path(char *buf, size_t size, const char *pkg, int user_id) {
    if (user_id == 0)
        snprintf(buf, size, "%s/App-rules/%s.conf", CONFIG_DIR, pkg);
    else
        snprintf(buf, size, "%s/App-rules-%d/%s.conf", CONFIG_DIR, user_id, pkg);
}

/* 获取应用规则目录 */
static void get_app_rule_dir(char *buf, size_t size, int user_id) {
    if (user_id == 0)
        snprintf(buf, size, "%s/App-rules", CONFIG_DIR);
    else
        snprintf(buf, size, "%s/App-rules-%d", CONFIG_DIR, user_id);
}

/* ========== 解析本地规则 ========== */

/* 从内存解析后的结构中构建 JSON（类似 config_publisher 的 build_templates_json） */
static void build_parsed_rules_json(char *out, size_t out_size) {
    if (!out || out_size == 0) return;
    size_t pos = 0;
    pos += snprintf(out + pos, out_size - pos, "{");

    /* 全局配置 */
    config_lock_read();
    pos += snprintf(out + pos, out_size - pos,
        "\"global\":{\"sandbox\":%s,\"global_inject\":%s,\"fuse_direct\":%s,\"monitor\":%s,\"inject_enable\":true,\"hide_count\":%d,\"ro_count\":%d,\"redir_count\":%d},",
        g_global_cfg.sandbox ? "true" : "false",
        g_global_cfg.global_inject ? "true" : "false",
        g_global_cfg.fuse_direct ? "true" : "false",
        g_global_cfg.monitor ? "true" : "false",
        g_global_cfg.hide_count,
        g_global_cfg.ro_count,
        g_global_cfg.redir_count);

    /* 应用配置列表 */
    pos += snprintf(out + pos, out_size - pos, "\"apps\":[");
    for (int i = 0; i < g_app_cfg_count; i++) {
        AppConfig *cfg = g_app_cfgs[i];
        char esc_pkg[256];
        json_escape_str(cfg->pkg_name, esc_pkg, sizeof(esc_pkg));
        if (i > 0) pos += snprintf(out + pos, out_size - pos, ",");
        pos += snprintf(out + pos, out_size - pos,
            "{\"pkg\":\"%s\",\"user_id\":%d,\"inject_enable\":%s,\"monitor\":%s,\"sandbox\":%s,\"fuse_direct\":%s,\"hide_count\":%d,\"ro_count\":%d,\"redir_count\":%d}",
            esc_pkg,
            cfg->user_id,
            cfg->inject_enable ? "true" : "false",
            cfg->monitor ? "true" : "false",
            cfg->sandbox ? "true" : "false",
            cfg->fuse_direct ? "true" : "false",
            cfg->hide_count,
            cfg->ro_count,
            cfg->redir_count);
    }
    config_unlock_read();
    pos += snprintf(out + pos, out_size - pos, "]}");
}

/* 处理 parse-rules: 加载并解析本地磁盘规则，输出 JSON */
static void handle_parse_rules(bool api_mode) {
    /* 本地加载：使用 config_parser 的 load_config_rules */
    config_lock_write();
    load_config_rules(INJECTOR_CONFIG_PATH);
    config_unlock_write();

    char json_buf[65536];
    build_parsed_rules_json(json_buf, sizeof(json_buf));

    if (api_mode) {
        json_api_finish(true, "\"parse-rules\"", json_buf);
    } else {
        printf("===== 本地规则解析结果 =====\n%s\n", json_buf);
    }
}

/* 处理 validate-rules: 尝试加载，验证规则语法正确性 */
static void handle_validate_rules(bool api_mode) {
    /* 尝试加载，但不保留结果（重新加载一遍然后释放） */
    config_lock_write();
    load_config_rules(INJECTOR_CONFIG_PATH);
    int app_count = g_app_cfg_count;
    config_unlock_write();

    if (api_mode) {
        char data_buf[512];
        snprintf(data_buf, sizeof(data_buf),
            "{\"valid\":true,\"app_count\":%d,\"global_hide_rules\":%d,\"global_ro_rules\":%d,\"global_redir_rules\":%d}",
            app_count, g_global_cfg.hide_count, g_global_cfg.ro_count, g_global_cfg.redir_count);
        json_api_finish(true, "\"validate-rules\"", data_buf);
    } else {
        printf("规则验证通过。共解析 %d 个应用配置。\n", app_count);
        printf("全局: %d 条 HIDE, %d 条 RO, %d 条 REDIRECT\n",
               g_global_cfg.hide_count, g_global_cfg.ro_count, g_global_cfg.redir_count);
    }
}

/* 处理 get-global-rules: 本地解析并查看 [GLOBAL] 段全部规则 */
static void handle_get_global_rules(bool api_mode) {
    config_lock_write();
    load_config_rules(INJECTOR_CONFIG_PATH);
    config_unlock_write();

    config_lock_read();
    if (api_mode) {
        /* 构建 JSON 输出 */
        char data_buf[65536];
        size_t pos = 0;
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
            "{\"switches\":{\"global_inject\":%s,\"monitor\":%s,\"sandbox\":%s,\"fuse_direct\":%s},",
            g_global_cfg.global_inject ? "true" : "false",
            g_global_cfg.monitor ? "true" : "false",
            g_global_cfg.sandbox ? "true" : "false",
            g_global_cfg.fuse_direct ? "true" : "false");

        /* HIDE 规则 */
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"hide_rules\":[");
        for (int i = 0; i < g_global_cfg.hide_count; i++) {
            char esc[1024];
            json_escape_str(g_global_cfg.hide_rules[i], esc, sizeof(esc));
            if (i > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"%s\"", esc);
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");

        /* RO 规则 */
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"ro_rules\":[");
        for (int i = 0; i < g_global_cfg.ro_count; i++) {
            char esc[1024];
            json_escape_str(g_global_cfg.ro_rules[i], esc, sizeof(esc));
            if (i > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"%s\"", esc);
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");

        /* REDIRECT 规则 */
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"redirect_rules\":[");
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            char esc_v[1024], esc_r[1024];
            json_escape_str(g_global_cfg.redir_rules[i].virtual_prefix, esc_v, sizeof(esc_v));
            json_escape_str(g_global_cfg.redir_rules[i].real_target, esc_r, sizeof(esc_r));
            if (i > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
                "{\"virtual_prefix\":\"%s\",\"real_target\":\"%s\"}", esc_v, esc_r);
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");

        /* FUSE_EXTRA_ARGS */
        char esc_fuse[512];
        json_escape_str(g_global_cfg.fuse_extra_args, esc_fuse, sizeof(esc_fuse));
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
            "\"fuse_extra_args\":\"%s\",", esc_fuse);

        /* 统计计数 */
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
            "\"counts\":{\"hide\":%d,\"ro\":%d,\"redirect\":%d}}",
            g_global_cfg.hide_count,
            g_global_cfg.ro_count,
            g_global_cfg.redir_count);
        config_unlock_read();

        json_api_finish(true, "\"get-global-rules\"", data_buf);
    } else {
        printf("===== 全局规则 (GLOBAL) =====\n\n");
        printf("--- Switch 开关 ---\n");
        printf("  GLOBAL_INJECT %s\n", g_global_cfg.global_inject ? "ON" : "OFF");
        printf("  MONITOR       %s\n", g_global_cfg.monitor ? "ON" : "OFF");
        printf("  SANDBOX       %s\n", g_global_cfg.sandbox ? "ON" : "OFF");
        printf("  FUSE_DIRECT   %s\n", g_global_cfg.fuse_direct ? "ON" : "OFF");

        printf("\n--- HIDE 规则 (%d 条) ---\n", g_global_cfg.hide_count);
        for (int i = 0; i < g_global_cfg.hide_count; i++) {
            printf("  [%d] HIDE %s\n", i, g_global_cfg.hide_rules[i]);
        }

        printf("\n--- RO 规则 (%d 条) ---\n", g_global_cfg.ro_count);
        for (int i = 0; i < g_global_cfg.ro_count; i++) {
            printf("  [%d] RO %s\n", i, g_global_cfg.ro_rules[i]);
        }

        printf("\n--- REDIRECT 规则 (%d 条) ---\n", g_global_cfg.redir_count);
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            printf("  [%d] REDIRECT %s %s\n", i,
                   g_global_cfg.redir_rules[i].virtual_prefix,
                   g_global_cfg.redir_rules[i].real_target);
        }

        if (g_global_cfg.fuse_extra_args[0]) {
            printf("\n--- FUSE_EXTRA_ARGS ---\n");
            printf("  %s\n", g_global_cfg.fuse_extra_args);
        }
        config_unlock_read();
    }
}

/* 处理 get-app-rules: 根据包名查看指定应用的配置和规则 */
static void handle_get_app_rules(bool api_mode, const char *pkg, int user_id) {
    config_lock_write();
    load_config_rules(INJECTOR_CONFIG_PATH);
    config_unlock_write();

    config_lock_read();
    AppConfig *cfg = find_app_cfg_locked(pkg, user_id);
    if (!cfg) {
        config_unlock_read();
        char err[256];
        snprintf(err, sizeof(err), "未找到应用 \"%s\" (UID %d) 的配置", pkg, user_id);
        json_api_error(api_mode, "\"get-app-rules\"", err);
        return;
    }

    if (api_mode) {
        char data_buf[65536];
        size_t pos = 0;
        char esc_pkg[256];
        json_escape_str(cfg->pkg_name, esc_pkg, sizeof(esc_pkg));
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
            "{\"pkg\":\"%s\",\"user_id\":%d,"
            "\"switches\":{\"inject_enable\":%s,\"monitor\":%s,\"sandbox\":%s,\"fuse_direct\":%s},",
            esc_pkg, cfg->user_id,
            cfg->inject_enable ? "true" : "false",
            cfg->monitor ? "true" : "false",
            cfg->sandbox ? "true" : "false",
            cfg->fuse_direct ? "true" : "false");

        /* HIDE 规则 */
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"hide_rules\":[");
        for (int i = 0; i < cfg->hide_count; i++) {
            char esc[1024];
            json_escape_str(cfg->hide_rules[i], esc, sizeof(esc));
            if (i > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"%s\"", esc);
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");

        /* RO 规则 */
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"ro_rules\":[");
        for (int i = 0; i < cfg->ro_count; i++) {
            char esc[1024];
            json_escape_str(cfg->ro_rules[i], esc, sizeof(esc));
            if (i > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"%s\"", esc);
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");

        /* REDIRECT 规则 */
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"redirect_rules\":[");
        for (int i = 0; i < cfg->redir_count; i++) {
            char esc_v[1024], esc_r[1024];
            json_escape_str(cfg->redir_rules[i].virtual_prefix, esc_v, sizeof(esc_v));
            json_escape_str(cfg->redir_rules[i].real_target, esc_r, sizeof(esc_r));
            if (i > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
                "{\"virtual_prefix\":\"%s\",\"real_target\":\"%s\"}", esc_v, esc_r);
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");

        /* 统计计数 */
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
            "\"counts\":{\"hide\":%d,\"ro\":%d,\"redirect\":%d}}",
            cfg->hide_count,
            cfg->ro_count,
            cfg->redir_count);
        config_unlock_read();

        json_api_finish(true, "\"get-app-rules\"", data_buf);
    } else {
        printf("===== 应用规则: %s (UID %d) =====\n\n", cfg->pkg_name, cfg->user_id);
        printf("--- Switch 开关 ---\n");
        printf("  INJECT_ENABLE %s\n", cfg->inject_enable ? "ON" : "OFF");
        printf("  MONITOR       %s\n", cfg->monitor ? "ON" : "OFF");
        printf("  SANDBOX       %s\n", cfg->sandbox ? "ON" : "OFF");
        printf("  FUSE_DIRECT   %s\n", cfg->fuse_direct ? "ON" : "OFF");

        printf("\n--- HIDE 规则 (%d 条) ---\n", cfg->hide_count);
        for (int i = 0; i < cfg->hide_count; i++) {
            printf("  [%d] HIDE %s\n", i, cfg->hide_rules[i]);
        }

        printf("\n--- RO 规则 (%d 条) ---\n", cfg->ro_count);
        for (int i = 0; i < cfg->ro_count; i++) {
            printf("  [%d] RO %s\n", i, cfg->ro_rules[i]);
        }

        printf("\n--- REDIRECT 规则 (%d 条) ---\n", cfg->redir_count);
        for (int i = 0; i < cfg->redir_count; i++) {
            printf("  [%d] REDIRECT %s %s\n", i,
                   cfg->redir_rules[i].virtual_prefix,
                   cfg->redir_rules[i].real_target);
        }

        if (cfg->fuse_extra_args[0]) {
            printf("\n--- FUSE_EXTRA_ARGS ---\n");
            printf("  %s\n", cfg->fuse_extra_args);
        }
        config_unlock_read();
    }
}

/* ========== 配置管理命令 ========== */

/* 处理 reload-config: 向注入器发送 SIGHUP 信号 */
static void handle_reload_config(bool api_mode) {
    const char *err = send_reload_signal();
    if (err) {
        json_api_error(api_mode, "\"reload-config\"", err);
        return;
    }
    if (api_mode) {
        char data_buf[256];
        int pid = read_pid_file(INJECTOR_PID_PATH);
        snprintf(data_buf, sizeof(data_buf), "{\"pid\":%d,\"signal\":\"SIGHUP\"}", pid);
        json_api_finish(true, "\"reload-config\"", data_buf);
    } else {
        int pid = read_pid_file(INJECTOR_PID_PATH);
        printf("已向注入器 (PID %d) 发送 SIGHUP 信号，触发配置重载\n", pid);
    }
}

/* ========== 系统状态 ========== */

/* 处理 status: 全面系统状态 */
static void handle_status(bool api_mode) {
    /* 收集所有状态 */
    int injector_pid = read_pid_file(INJECTOR_PID_PATH);
    bool injector_alive = (injector_pid > 0 && kill(injector_pid, 0) == 0);

    int fuse_pid = 0;
    FILE *fp = fopen("/proc/self/mountinfo", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "fuse") && strstr(line, "nsp_global")) {
                char *tok = strtok(line, " ");
                for (int i = 0; tok && i < 4; i++) tok = strtok(NULL, " ");
                if (tok) fuse_pid = atoi(tok);
                break;
            }
        }
        fclose(fp);
    }

    bool fuse_alive = (fuse_pid > 0 && kill(fuse_pid, 0) == 0);
    int main_conf_size = 0;
    struct stat st;
    if (stat(INJECTOR_CONFIG_PATH, &st) == 0) main_conf_size = (int)st.st_size;

    /* 扫描 App-rules 目录 */
    int app_rule_files = 0;
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
            if (rdir) {
                struct dirent *rde;
                while ((rde = readdir(rdir)) != nullptr) {
                    if (rde->d_type == DT_REG || rde->d_type == DT_LNK) {
                        char *ext = strrchr(rde->d_name, '.');
                        if (ext && strcmp(ext, ".conf") == 0) app_rule_files++;
                    }
                }
                closedir(rdir);
            }
        }
        closedir(dir);
    }

    /* 统计当前内存中的配置 */
    config_lock_read();
    int mem_app_count = g_app_cfg_count;
    config_unlock_read();

    if (api_mode) {
        char data_buf[4096];
        char time_str[64];
        time_t now = time(NULL);
        struct tm tm_info;
        localtime_r(&now, &tm_info);
        strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", &tm_info);

        snprintf(data_buf, sizeof(data_buf),
            "{\"timestamp\":%lld,\"time\":\"%s\","
            "\"injector\":{\"pid\":%d,\"alive\":%s},"
            "\"fuse\":{\"pid\":%d,\"alive\":%s},"
            "\"config\":{\"main_conf_path\":\"%s\",\"main_conf_size\":%d,\"app_rule_files\":%d,\"parsed_apps_in_memory\":%d},"
            "\"system\":{\"config_dir\":\"%s\",\"pid_file\":\"%s\"}}",
            (long long)now, time_str,
            injector_pid, injector_alive ? "true" : "false",
            fuse_pid, fuse_alive ? "true" : "false",
            INJECTOR_CONFIG_PATH, main_conf_size,
            app_rule_files, mem_app_count,
            CONFIG_DIR, INJECTOR_PID_PATH);
        json_api_finish(true, "\"status\"", data_buf);
    } else {
        printf("===== 系统状态概览 =====\n");
        printf("时间: %lld\n", (long long)time(NULL));
        printf("注入器: PID %d [%s]\n", injector_pid, injector_alive ? "运行中" : "未运行");
        printf("FUSE 守护进程: PID %d [%s]\n", fuse_pid, fuse_alive ? "运行中" : "未运行");
        printf("主配置文件: %s (%d 字节)\n", INJECTOR_CONFIG_PATH, main_conf_size);
        printf("应用规则文件数: %d\n", app_rule_files);
        printf("内存中已解析应用: %d\n", mem_app_count);
    }
}

/* ========== set-rule / remove-rule 处理 ========== */

/*
 * set-rule 写入规则到应用配置文件
 * 格式: log_ctl set-rule <pkg> <type> <value> [--uid uid] [api]
 * type:
 *   HIDE <path>          - 添加隐藏路径
 *   RO <path>            - 添加只读路径
 *   REDIRECT <src> <dst> - 添加重定向规则 (value格式: "src|dst")
 *   ALLOW <path>         - 添加允许规则
 *   MONITOR ON|OFF       - 设置监控开关
 *   SANDBOX ON|OFF       - 设置沙盒开关
 *   GLOBAL_INJECT ON|OFF - 设置全局注入
 *   FUSE_DIRECT ON|OFF   - 设置FUSE直通
 */
static void handle_set_rule(bool api_mode, const char *pkg, const char *type,
                            const char *value, int user_id) {
    if (!pkg || !type || !value) {
        json_api_error(api_mode, "\"set-rule\"", "缺少必要参数: pkg type value");
        return;
    }

    char rule_path[PATH_MAX];
    if (strcmp(pkg, "GLOBAL") == 0) {
        snprintf(rule_path, sizeof(rule_path), "%s", INJECTOR_CONFIG_PATH);
    } else {
        get_app_rule_path(rule_path, sizeof(rule_path), pkg, user_id);
        /* 确保目录存在 */
        char rule_dir[PATH_MAX];
        get_app_rule_dir(rule_dir, sizeof(rule_dir), user_id);
        mkdir_recursive(rule_dir);
    }

    /* 以追加模式写入 */
    FILE *fp = fopen(rule_path, "a");
    if (!fp) {
        char err_buf[256];
        snprintf(err_buf, sizeof(err_buf), "无法打开规则文件 %s: %s", rule_path, strerror(errno));
        json_api_error(api_mode, "\"set-rule\"", err_buf);
        return;
    }

    char line[1024];
    if (strcmp(type, "REDIRECT") == 0) {
        /* value 格式: "source|target" */
        char src[512], dst[512];
        const char *sep = strchr(value, '|');
        if (sep) {
            size_t src_len = (size_t)(sep - value);
            if (src_len >= sizeof(src)) src_len = sizeof(src) - 1;
            memcpy(src, value, src_len);
            src[src_len] = '\0';
            strncpy(dst, sep + 1, sizeof(dst) - 1);
            dst[sizeof(dst) - 1] = '\0';
            snprintf(line, sizeof(line), "REDIRECT %s %s\n", src, dst);
        } else {
            snprintf(line, sizeof(line), "REDIRECT %s %s\n", value, value);
        }
    } else if (strcmp(type, "ALLOW") == 0) {
        snprintf(line, sizeof(line), "ALLOW %s\n", value);
    } else if (strcmp(type, "HIDE") == 0) {
        snprintf(line, sizeof(line), "HIDE %s\n", value);
    } else if (strcmp(type, "RO") == 0) {
        snprintf(line, sizeof(line), "RO %s\n", value);
    } else if (strcmp(type, "MONITOR") == 0 ||
               strcmp(type, "SANDBOX") == 0 ||
               strcmp(type, "GLOBAL_INJECT") == 0 ||
               strcmp(type, "FUSE_DIRECT") == 0) {
        snprintf(line, sizeof(line), "%s %s\n", type, value);
    } else {
        fclose(fp);
        char err_buf[128];
        snprintf(err_buf, sizeof(err_buf), "未知规则类型: %s (支持: HIDE, RO, REDIRECT, ALLOW, MONITOR, SANDBOX, GLOBAL_INJECT, FUSE_DIRECT)", type);
        json_api_error(api_mode, "\"set-rule\"", err_buf);
        return;
    }

    if (fputs(line, fp) < 0) {
        char err_buf[256];
        snprintf(err_buf, sizeof(err_buf), "写入规则文件失败: %s", strerror(errno));
        fclose(fp);
        json_api_error(api_mode, "\"set-rule\"", err_buf);
        return;
    }
    fclose(fp);

    if (api_mode) {
        char data_buf[1024];
        char esc_file[256], esc_line[256];
        json_escape_str(rule_path, esc_file, sizeof(esc_file));
        json_escape_str(line, esc_line, sizeof(esc_line));
        snprintf(data_buf, sizeof(data_buf),
            "{\"file\":\"%s\",\"line\":\"%s\",\"pkg\":\"%s\",\"type\":\"%s\",\"value\":\"%s\"}",
            esc_file, esc_line, pkg, type, value);
        json_api_finish(true, "\"set-rule\"", data_buf);
    } else {
        printf("已向 %s 追加规则: %s", rule_path, line);
    }
}

/* remove-rule: 从文件中删除指定索引的规则 */
static void handle_remove_rule(bool api_mode, const char *pkg, const char *type,
                               int index, int user_id) {
    if (!pkg || !type) {
        json_api_error(api_mode, "\"remove-rule\"", "缺少必要参数: pkg type index");
        return;
    }
    if (index < 0) {
        json_api_error(api_mode, "\"remove-rule\"", "索引必须 >= 0");
        return;
    }

    char rule_path[PATH_MAX];
    if (strcmp(pkg, "GLOBAL") == 0) {
        snprintf(rule_path, sizeof(rule_path), "%s", INJECTOR_CONFIG_PATH);
    } else {
        get_app_rule_path(rule_path, sizeof(rule_path), pkg, user_id);
    }

    /* 读取原文件，跳过匹配的第 index 条 type 规则 */
    FILE *fp = fopen(rule_path, "r");
    if (!fp) {
        char err_buf[256];
        snprintf(err_buf, sizeof(err_buf), "无法打开规则文件 %s: %s", rule_path, strerror(errno));
        json_api_error(api_mode, "\"remove-rule\"", err_buf);
        return;
    }

    /* 读取所有行到内存 */
    char **lines = NULL;
    int line_count = 0, line_cap = 0;
    char buf[2048];
    int skip_idx = 0;
    bool removed = false;

    while (fgets(buf, sizeof(buf), fp)) {
        /* 跳过空白行和注释 */
        char *trimmed = buf;
        while (isspace((unsigned char)*trimmed)) trimmed++;
        bool is_type_rule = (strncasecmp(trimmed, type, strlen(type)) == 0 &&
                            (trimmed[strlen(type)] == ' ' || trimmed[strlen(type)] == '\t'));

        if (is_type_rule && skip_idx == index) {
            removed = true;
            skip_idx++;
            continue;
        }
        if (is_type_rule) skip_idx++;

        /* 保留此行 */
        if (line_count >= line_cap) {
            line_cap = line_cap == 0 ? 64 : line_cap * 2;
            char **new_lines = realloc(lines, line_cap * sizeof(char *));
            if (!new_lines) {
                for (int j = 0; j < line_count; j++) free(lines[j]);
                free(lines);
                fclose(fp);
                json_api_error(api_mode, "\"remove-rule\"", "内存不足");
                return;
            }
            lines = new_lines;
        }
        lines[line_count] = strdup(buf);
        if (!lines[line_count]) {
            for (int j = 0; j < line_count; j++) free(lines[j]);
            free(lines);
            fclose(fp);
            json_api_error(api_mode, "\"remove-rule\"", "内存不足");
            return;
        }
        line_count++;
    }
    fclose(fp);

    if (!removed) {
        for (int j = 0; j < line_count; j++) free(lines[j]);
        free(lines);
        char err_buf[128];
        snprintf(err_buf, sizeof(err_buf), "未找到 %s 类型的第 %d 条规则", type, index);
        json_api_error(api_mode, "\"remove-rule\"", err_buf);
        return;
    }

    /* 写回文件 */
    fp = fopen(rule_path, "w");
    if (!fp) {
        for (int j = 0; j < line_count; j++) free(lines[j]);
        free(lines);
        char err_buf[256];
        snprintf(err_buf, sizeof(err_buf), "无法写入规则文件 %s: %s", rule_path, strerror(errno));
        json_api_error(api_mode, "\"remove-rule\"", err_buf);
        return;
    }

    for (int i = 0; i < line_count; i++) {
        fputs(lines[i], fp);
        free(lines[i]);
    }
    free(lines);
    fclose(fp);

    if (api_mode) {
        char esc_file[256];
        json_escape_str(rule_path, esc_file, sizeof(esc_file));
        char data_buf[512];
        snprintf(data_buf, sizeof(data_buf),
            "{\"file\":\"%s\",\"pkg\":\"%s\",\"type\":\"%s\",\"index\":%d}",
            esc_file, pkg, type, index);
        json_api_finish(true, "\"remove-rule\"", data_buf);
    } else {
        printf("已从 %s 删除第 %d 条 %s 规则\n", rule_path, index, type);
    }
}

/* ========== 配置广播接收（原有） ========== */
static int config_broadcast_connect(void) {
    int sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        perror("创建 DGRAM socket 失败");
        return -1;
    }
    struct sockaddr_un local = { .sun_family = AF_UNIX };
    local.sun_path[0] = '\0';
    snprintf(local.sun_path + 1, sizeof(local.sun_path) - 2, "nsp_ctl_%d", getpid());
    socklen_t local_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(local.sun_path + 1);
    if (bind(sock, (struct sockaddr *)&local, local_len) < 0) {
        perror("绑定本地 DGRAM 地址失败");
        close(sock);
        return -1;
    }
    return sock;
}
static int config_broadcast_send_cmd(int sock, const char *cmd) {
    struct sockaddr_un pub = { .sun_family = AF_UNIX };
    pub.sun_path[0] = '\0';
    strncpy(pub.sun_path + 1, CONFIG_BROADCAST_SOCKET, sizeof(pub.sun_path) - 2);
    socklen_t pub_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(CONFIG_BROADCAST_SOCKET);
    return sendto(sock, cmd, strlen(cmd), MSG_NOSIGNAL,
                  (struct sockaddr *)&pub, pub_len);
}
static ssize_t config_broadcast_recv(int sock, char *buf, size_t size, int timeout_ms) {
    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) return -1;
    if (ret == 0) return -2;
    ssize_t n = recv(sock, buf, size - 1, MSG_DONTWAIT);
    if (n > 0) buf[n] = '\0';
    return n;
}
#define BROADCAST_RECEIVE_MAX_SIZE (256 * 1024)
static void handle_get_config(bool api_mode, bool static_mode) {
    int sock = config_broadcast_connect();
    if (sock < 0) return;
    const char *cmd = static_mode ? "STATIC" : "GET";
    if (config_broadcast_send_cmd(sock, cmd) < 0) {
        perror("发送命令失败");
        close(sock);
        return;
    }
    char *resp = malloc(BROADCAST_RECEIVE_MAX_SIZE);
    if (!resp) {
        fprintf(stderr, "系统物理内存不足，无法分配接收缓冲区\n");
        close(sock);
        return;
    }
    ssize_t n = config_broadcast_recv(sock, resp, BROADCAST_RECEIVE_MAX_SIZE, 3000);
    close(sock);
    if (n < 0) {
        fprintf(stderr, "未获取到配置信息（%s）\n",
                (n == -2) ? "超时" : strerror(errno));
        free(resp);
        return;
    }
    if (api_mode) {
        json_api_finish(true, static_mode ? "\"get-config-static\"" : "\"get-config\"", resp);
    } else {
        printf("%s\n", resp);
    }
    free(resp);
}
static void handle_stream_config(bool api_mode) {
    int sock = config_broadcast_connect();
    if (sock < 0) return;
    if (config_broadcast_send_cmd(sock, "SUBSCRIBE") < 0) {
        perror("发送 SUBSCRIBE 命令失败");
        close(sock);
        return;
    }
    char *resp = malloc(BROADCAST_RECEIVE_MAX_SIZE);
    if (!resp) {
        fprintf(stderr, "系统物理内存不足，无法分配接收缓冲区\n");
        close(sock);
        return;
    }
    ssize_t n = config_broadcast_recv(sock, resp, BROADCAST_RECEIVE_MAX_SIZE, 3000);
    if (n > 0) {
        if (api_mode) {
            json_api_finish(true, "\"stream-config\"", resp);
        } else {
            printf("===== 当前配置 (首次推送) =====\n%s\n", resp);
        }
    }
    struct sigaction sa = { .sa_handler = sigint_handler };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    while (g_running) {
        n = config_broadcast_recv(sock, resp, BROADCAST_RECEIVE_MAX_SIZE, 60000);
        if (n > 0) {
            if (api_mode) {
                json_api_finish(true, "\"stream-config\"", resp);
            } else {
                printf("===== 配置变更推送 =====\n%s\n", resp);
            }
            fflush(stdout);
        } else if (n == -2) {
            continue;
        } else if (n < 0) {
            if (errno != EINTR) {
                perror("接收配置推送失败");
                break;
            }
        }
    }
    free(resp);
    close(sock);
}
void process_and_print(char* line, bool force_uid, [[maybe_unused]] bool api_mode) {
    char* open_b = strchr(line, '[');
    if (open_b && !force_uid) {
        char* open_p = strchr(open_b, '(');
        char* close_p = strchr(open_b, ')');
        if (open_p && close_p && open_p < close_p) {
            bool is_uid = true;
            for (char* c = open_p + 1; c < close_p; c++) if (!isdigit((unsigned char)*c)) is_uid = false;
            if (is_uid) memmove(open_p, close_p + 1, strlen(close_p + 1) + 1);
        }
    }
    printf("%s\n", line);
    fflush(stdout);
}
static void handle_list_injected(bool api_mode) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, IPC_SOCKET_NAME, sizeof(addr.sun_path) - 2);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(IPC_SOCKET_NAME);
    if (connect(sock, (struct sockaddr*)&addr, addr_len) < 0) {
        perror("连接注入器 IPC 服务失败");
        return;
    }
    write(sock, "LIST_INJECTED", 13);
    shutdown(sock, SHUT_WR);
    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    if (poll(&pfd, 1, 1000) <= 0) {
        if (!api_mode) fprintf(stderr, "未获取到响应\n");
        close(sock);
        return;
    }
    char resp[8192];
    ssize_t n = read(sock, resp, sizeof(resp) - 1);
    close(sock);
    if (n <= 0) {
        if (!api_mode) fprintf(stderr, "未获取到响应\n");
        return;
    }
    resp[n] = '\0';
    if (api_mode) {
        /* 将 DONE 行剥离出来作为单独字段，不混入 raw 内容 */
        char *done_line = NULL;
        int done_total = 0;
        bool has_done = false;

        done_line = strstr(resp, "\nDONE|");
        if (done_line) {
            *done_line = '\0';
            done_line++;
        } else if (strncmp(resp, "DONE|", 5) == 0) {
            done_line = resp;
            resp[0] = '\0';
        }

        if (done_line && sscanf(done_line + 5, "%d", &done_total) == 1) {
            has_done = true;
        }

        char esc[8192];
        json_escape_str(resp, esc, sizeof(esc));
        char data_buf[8192 + 128];
        if (has_done) {
            snprintf(data_buf, sizeof(data_buf),
                "{\"raw\":\"%s\",\"done\":{\"total\":%d}}", esc, done_total);
        } else {
            snprintf(data_buf, sizeof(data_buf), "{\"raw\":\"%s\"}", esc);
        }
        json_api_finish(true, "\"list-injected\"", data_buf);
        return;
    }
    int total = 0;
    char* line = strtok(resp, "\n");
    printf("\n已注入应用列表:\n");
    printf("%-4s %-40s %-7s %-8s %-5s %-5s %-5s\n",
           "序号", "包名", "PID", "UID", "重定向", "隐藏", "只读");
    printf("%s\n", "---- --------------------------------------- ------- -------- ----- ----- -----");
    int idx = 1;
    while (line) {
        if (strncmp(line, "APP|", 4) == 0) {
            char pkg[256]; int pid, uid, r, h, ro;
            if (sscanf(line, "APP|%255[^|]|%d|%d|%d|%d|%d", pkg, &pid, &uid, &r, &h, &ro) == 6) {
                printf("%-4d %-40s %-7d %-8d %-5d %-5d %-5d\n",
                       idx++, pkg, pid, uid, r, h, ro);
            }
        } else if (strncmp(line, "DONE|", 5) == 0) {
            sscanf(line + 5, "%d", &total);
        }
        line = strtok(nullptr, "\n");
    }
    printf("\n共计 %d 个应用已注入\n", total);
}

/* ========== 用户列表 ========== */

/* 处理 list-users: 列出当前活跃用户及每个用户下的应用配置数 */
static void handle_list_users(bool api_mode) {
    config_lock_read();
    int count = g_active_user_count;

    if (api_mode) {
        char data_buf[4096];
        size_t pos = 0;
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
            "{\"count\":%d,\"users\":[", count);
        for (int i = 0; i < count; i++) {
            int uid = g_active_users[i];
            /* 统计该用户下已解析的应用数 */
            int app_cnt = 0;
            for (int j = 0; j < g_app_cfg_count; j++) {
                if (g_app_cfgs[j]->user_id == uid) app_cnt++;
            }
            if (i > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
                "{\"uid\":%d,\"app_count\":%d}", uid, app_cnt);
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "]}");
        config_unlock_read();

        json_api_finish(true, "\"list-users\"", data_buf);
    } else {
        printf("===== 活跃用户列表 (%d) =====\n", count);
        for (int i = 0; i < count; i++) {
            int uid = g_active_users[i];
            int app_cnt = 0;
            for (int j = 0; j < g_app_cfg_count; j++) {
                if (g_app_cfgs[j]->user_id == uid) app_cnt++;
            }
            printf("  UID %-8d  %d 个应用配置\n", uid, app_cnt);
        }
    }
}

static void stream_logs(const char* stream_cmd) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LOG_TCP_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("连接日志服务失败");
        return;
    }
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "%s\n", stream_cmd);
    write(sock, cmd, strlen(cmd));
    char ack[16];
    ssize_t n = read(sock, ack, sizeof(ack) - 1);
    if (n <= 0 || strncmp(ack, "OK", 2) != 0) {
        fprintf(stderr, "服务端拒绝流式请求\n");
        close(sock);
        return;
    }
    struct sigaction sa = { .sa_handler = sigint_handler };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    char buf[8192];
    char line_buf[8192];
    size_t line_pos = 0;
    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); close(sock); return; }
    struct epoll_event ep_ev = { .events = EPOLLIN, .data.fd = sock };
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ep_ev);
    while (g_running) {
        struct epoll_event ev;
        int ret = epoll_wait(epfd, &ev, 1, 1000);
        if (!g_running) break;
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) continue;
        ssize_t n = read(sock, buf, sizeof(buf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                line_buf[line_pos] = '\0';
                process_and_print(line_buf, false, false);
                line_pos = 0;
            } else if (line_pos < sizeof(line_buf) - 1) {
                line_buf[line_pos++] = buf[i];
            } else {
                /* 行缓冲已满但还未遇到 \n：先刷出当前内容，继续接收续传 */
                line_buf[line_pos] = '\0';
                process_and_print(line_buf, false, false);
                line_pos = 0;
                line_buf[line_pos++] = buf[i];
            }
        }
    }
    close(epfd);
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc < 2) usage(argv[0]);

    /* 解析全局选项和位置参数 */
    bool api_mode = false;
    bool force_uid = false;
    bool static_mode = false;
    char *level_arg = NULL;
    char *pos_args[10] = {NULL};
    int pos_idx = 0;
    int user_id = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "api") == 0) {
            api_mode = true;
        } else if (strcmp(argv[i], "-u") == 0) {
            force_uid = true;
        } else if (strcmp(argv[i], "--static") == 0) {
            static_mode = true;
        } else if (strcmp(argv[i], "--level") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: --level 需要指定一个级别\n");
                usage(argv[0]);
            }
            level_arg = argv[++i];
        } else if (strcmp(argv[i], "--uid") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: --uid 需要指定用户 ID\n");
                usage(argv[0]);
            }
            user_id = atoi(argv[++i]);
        } else {
            if (pos_idx < 10) {
                pos_args[pos_idx++] = argv[i];
            } else {
                fprintf(stderr, "错误: 参数过多\n");
                usage(argv[0]);
            }
        }
    }
    if (pos_idx < 1) usage(argv[0]);

    /* 处理新的本地规则解析与配置命令 */
    if (strcmp(pos_args[0], "parse-rules") == 0) {
        handle_parse_rules(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "get-global-rules") == 0) {
        handle_get_global_rules(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "get-app-rules") == 0) {
        if (pos_idx < 2) {
            json_api_error(api_mode, "\"get-app-rules\"", "用法: log_ctl get-app-rules <pkg> [--uid uid] [api]");
            return 1;
        }
        handle_get_app_rules(api_mode, pos_args[1], user_id);
        return 0;
    }
    if (strcmp(pos_args[0], "validate-rules") == 0) {
        handle_validate_rules(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "reload-config") == 0) {
        handle_reload_config(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "status") == 0) {
        handle_status(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "set-rule") == 0) {
        if (pos_idx < 4) {
            json_api_error(api_mode, "\"set-rule\"", "用法: log_ctl set-rule <pkg> <type> <value> [--uid uid] [api]");
            return 1;
        }
        handle_set_rule(api_mode, pos_args[1], pos_args[2], pos_args[3], user_id);
        return 0;
    }
    if (strcmp(pos_args[0], "remove-rule") == 0) {
        if (pos_idx < 4) {
            json_api_error(api_mode, "\"remove-rule\"", "用法: log_ctl remove-rule <pkg> <type> <index> [--uid uid] [api]");
            return 1;
        }
        int index = atoi(pos_args[3]);
        handle_remove_rule(api_mode, pos_args[1], pos_args[2], index, user_id);
        return 0;
    }

    /* 处理流式命令 */
    if (strncmp(pos_args[0], "stream", 6) == 0) {
        const char *level = level_arg ? level_arg : "0";
        char stream_cmd[64] = {0};
        if (strcmp(pos_args[0], "stream-io") == 0) {
            snprintf(stream_cmd, sizeof(stream_cmd), "STREAM_IO:%s", level);
        } else if (strcmp(pos_args[0], "stream-sys") == 0) {
            snprintf(stream_cmd, sizeof(stream_cmd), api_mode ? "STREAM_SYS_API:%s" : "STREAM_SYS:%s", level);
        } else if (strcmp(pos_args[0], "stream-logcat") == 0) {
            snprintf(stream_cmd, sizeof(stream_cmd), "STREAM_LOGCAT:%s", level);
        } else if (strcmp(pos_args[0], "stream-all") == 0) {
            snprintf(stream_cmd, sizeof(stream_cmd), "STREAM_ALL:%s", level);
        } else {
            usage(argv[0]);
        }
        stream_logs(stream_cmd);
        return 0;
    }
    if (strcmp(pos_args[0], "list-injected") == 0) {
        handle_list_injected(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "list-users") == 0) {
        handle_list_users(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "get-config") == 0) {
        handle_get_config(api_mode, static_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "stream-config") == 0) {
        handle_stream_config(api_mode);
        return 0;
    }

    /* log-count 需要连接日志服务 */
    if (strcmp(pos_args[0], "log-count") == 0) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in log_addr;
        memset(&log_addr, 0, sizeof(log_addr));
        log_addr.sin_family = AF_INET;
        log_addr.sin_port = htons(LOG_TCP_PORT);
        inet_pton(AF_INET, "127.0.0.1", &log_addr.sin_addr);
        if (connect(sock, (struct sockaddr*)&log_addr, sizeof(log_addr)) < 0) {
            perror("连接日志服务失败");
            return 1;
        }
        write(sock, "COUNT\n", 6);
        shutdown(sock, SHUT_WR);
        char resp[256];
        ssize_t n = read(sock, resp, sizeof(resp) - 1);
        close(sock);
        if (n > 0) {
            resp[n] = '\0';
            int io_total = 0, sys_total = 0, logcat_total = 0;
            sscanf(resp, "COUNT|%d|%d|%d", &io_total, &sys_total, &logcat_total);
            if (api_mode) {
                char data_buf[256];
                snprintf(data_buf, sizeof(data_buf),
                    "{\"io\":%d,\"sys\":%d,\"logcat\":%d}", io_total, sys_total, logcat_total);
                json_api_finish(true, "\"log-count\"", data_buf);
            } else {
                printf("===== 日志统计 =====\n");
                printf("I/O 日志:     %d 条\n", io_total);
                printf("系统日志:     %d 条\n", sys_total);
                printf("Logcat 日志:  %d 条\n", logcat_total);
            }
        }
        return 0;
    }

    /* 其余命令（search / clear）需要连接日志服务 */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("创建 socket 失败");
        return 1;
    }
    struct sockaddr_in log_addr;
    memset(&log_addr, 0, sizeof(log_addr));
    log_addr.sin_family = AF_INET;
    log_addr.sin_port = htons(LOG_TCP_PORT);
    inet_pton(AF_INET, "127.0.0.1", &log_addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&log_addr, sizeof(log_addr)) < 0) {
        perror("连接日志服务失败");
        close(sock);
        return 1;
    }
    char cmd[128];
    if (strstr(pos_args[0], "search") != NULL) {
        const char *key = "";
        const char *limit = "100";
        const char *offset = "0";
        if (pos_idx > 1) key = pos_args[1];
        if (pos_idx > 2) limit = pos_args[2];
        if (pos_idx > 3) offset = pos_args[3];
        const char *level = level_arg ? level_arg : "-1";
        snprintf(cmd, sizeof(cmd), "QUERY_%s:%s:%s:%s:%s\n",
                 strstr(pos_args[0], "io") ? "IO" : "SYS",
                 level, key, limit, offset);
    } else if (strstr(pos_args[0], "clear") != NULL) {
        snprintf(cmd, sizeof(cmd), "CLEAR_%s\n", strstr(pos_args[0], "io") ? "IO" : "SYS");
    } else {
        close(sock);
        usage(argv[0]);
        return 1;
    }
    write(sock, cmd, strlen(cmd));
    shutdown(sock, SHUT_WR);
    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    if (poll(&pfd, 1, 1000) <= 0) {
        close(sock);
        return 1;
    }
    char resp[16384];
    size_t total = 0;
    while (total < sizeof(resp) - 1) {
        ssize_t n = read(sock, resp + total, sizeof(resp) - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    if (total > 0) {
        resp[total] = '\0';
        if (api_mode) {
            /* search/clear 的 API 模式：将 DONE 行剥离出来作为单独字段，不混入 raw 内容 */
            char *done_line = NULL;
            int done_total = 0, done_remaining = 0;
            bool has_done = false;

            done_line = strstr(resp, "\nDONE|");
            if (done_line) {
                *done_line = '\0';      /* 截断 resp，只保留 DONE 之前的内容作为 raw */
                done_line++;            /* 移到 "DONE|..." */
            } else if (strncmp(resp, "DONE|", 5) == 0) {
                done_line = resp;       /* 只有 DONE 行，raw 为空 */
                resp[0] = '\0';
            }

            if (done_line && sscanf(done_line + 5, "%d|%d", &done_total, &done_remaining) >= 1) {
                has_done = true;
            }

            char esc[16384];
            json_escape_str(resp, esc, sizeof(esc));
            char data_buf[16384 + 128];
            if (has_done) {
                snprintf(data_buf, sizeof(data_buf),
                    "{\"raw\":\"%s\",\"done\":{\"total\":%d,\"remaining\":%d}}",
                    esc, done_total, done_remaining);
            } else {
                snprintf(data_buf, sizeof(data_buf), "{\"raw\":\"%s\"}", esc);
            }
            json_api_finish(true, (strncmp(pos_args[0], "search", 6) == 0) ? "\"search\"" : "\"clear\"", data_buf);
        } else {
            char* line = strtok(resp, "\n");
            while (line) {
                if (strncmp(line, "DONE|", 5) == 0) {
                    if (!api_mode) {
                        int tot, remain;
                        if (sscanf(line + 5, "%d|%d", &tot, &remain) == 2)
                            fprintf(stderr, "\n[统计] 总数: %d | 剩余: %d\n", tot, remain);
                    }
                    break;
                } else if (strcmp(line, "OK") != 0) {
                    process_and_print(line, force_uid, api_mode);
                }
                line = strtok(nullptr, "\n");
            }
        }
    }
    close(sock);
    return 0;
}
